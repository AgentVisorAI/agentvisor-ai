//! AgentBridge server executable.

use ab_bridge::{BridgeManifest, EmbeddedBroker, EventBus};
use ab_harness::reconciler::spawn_reconciler;
use ab_harness::{build_router, AppState, HarnessConfig};
use ab_identity::{IdentityValidator, KeyMaterial};
use ab_loopdetect::{Embedder, HashEmbedder, NoopVectorSink, VectorSink};
use ab_receipts::{Ed25519Signer, Signer};
use ab_sandbox::{PolicyEngine, Sandbox, SandboxConfig, WasmPolicy};
use ab_state::{InMemoryStore, StateStore};
use anyhow::{Context, Result};
use futures::future::FutureExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing_subscriber::prelude::*;

#[tokio::main]
async fn main() -> Result<()> {
    #[cfg(feature = "otel")]
    let telemetry_provider = init_tracing()?;
    #[cfg(not(feature = "otel"))]
    init_tracing()?;

    let (config, config_source) = ab_harness::config::load_config().map_err(anyhow::Error::msg)?;
    let manifest = load_manifest(&config)?;
    let bridge = build_bridge(&config, &manifest)?;

    let sandbox = load_sandbox(&config)?;
    let store = build_store(&config)?;
    let embedder = build_embedder(&config)?;
    let vector_sink = build_vector_sink(&config, embedder.dim()).await?;
    // Build the metrics registry BEFORE `build_identity` so the JWKS
    // refresh loop can bump `ab_jwks_refresh_errors_total` on the same
    // registry that `AppState` will hand to `/metrics`. Otherwise the
    // JWKS counters would live on a phantom registry no scraper sees,
    // and a silently-stale key set (see F1/F3 in round-11 audit) would
    // remain unalertable.
    let metrics = Arc::new(ab_core::metrics::Registry::new());
    let (identity, jwks_refresh) = build_identity(&config, Arc::clone(&metrics)).await?;
    let signer_path = std::env::var_os("AB_SIGNING_SEED_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("config/signing.seed"));
    let signer: Arc<dyn Signer> = Arc::new(load_or_create_signer(&signer_path)?);
    bridge
        .set_control_key(ab_harness::control_key_from_signer(signer.as_ref()))
        .context("configure Bridge control authentication")?;
    let state = AppState::new_with_backends_and_metrics(
        config.clone(),
        store,
        Arc::new(sandbox),
        bridge,
        identity,
        signer,
        embedder,
        vector_sink,
        Arc::clone(&metrics),
    )
    .map_err(anyhow::Error::new)?;
    state
        .finalizer
        .recover_spooled_sessions(&state.sessions, &config.breaker)
        .await
        .context("recover ATIF spool")?;
    state
        .finalizer
        .retry_marked_promotions(&state.sessions)
        .await
        .context("retry durable promotions")?;
    let bridge_maintenance_shutdown = Arc::new(tokio::sync::Notify::new());
    let bridge_maintenance = spawn_bridge_maintenance(
        Arc::clone(&state.bridge),
        Arc::clone(&state.metrics),
        Arc::clone(&bridge_maintenance_shutdown),
    );
    let reconciler = spawn_reconciler(
        Arc::clone(&state.sessions),
        state.finalizer.clone(),
        config.session_idle_close_s,
        config.reconcile_tick_s,
        config.breaker.clone(),
        Arc::clone(&state.metrics),
    );
    let listener = tokio::net::TcpListener::bind(&config.listen)
        .await
        .with_context(|| format!("bind {}", config.listen))?;
    if let Some(segment) = config.duplicated_chat_path_segment() {
        tracing::warn!(
            upstream_url = %config.upstream_url,
            upstream_chat_path = %config.upstream_chat_path,
            "upstream_url already ends with \"/{segment}\" and upstream_chat_path repeats it; \
             the joined URL will contain \"/{segment}/{segment}/\" — most providers expect the \
             base URL without the \"/{segment}\" suffix"
        );
    }
    tracing::info!(
        listen = %config.listen,
        config = %config_source,
        upstream = %format!("{}{}", config.upstream_url.trim_end_matches('/'), config.upstream_chat_path),
        upstream_auth = %ab_harness::pipeline::describe_upstream_auth(&config),
        bridge = %config.bridge_backend,
        state = %config.state_backend,
        identity = if config.require_identity { "required" } else { "optional" },
        "AgentBridge started"
    );
    let (shutdown_started_tx, shutdown_started_rx) = tokio::sync::oneshot::channel();
    // Register the drain-timeout counter up front so alerts can wire
    // onto it at boot. This surfaces the round-11 F2 hazard: axum's
    // per-connection tasks are detached `tokio::spawn`s, so dropping
    // the `Serve` future does NOT cancel in-flight streams. If a
    // long-lived streaming client outlives the graceful drain budget,
    // the timeout fires, `state.worker.wait_idle()` also times out,
    // and any late-arriving job into `finalize_sessions` races the
    // stream's own drop-time finalizer. A non-zero counter is a
    // hard-page: it means shutdown ordering is unsafe and every
    // affected session needs receipt-verify on restart.
    let drain_timeouts = metrics.counter(
        "ab_http_shutdown_drain_timeouts_total",
        "HTTP graceful-drain phase exceeded budget; per-connection tasks may still be live",
    );
    let server = std::future::IntoFuture::into_future(
        axum::serve(listener, build_router(state.clone())).with_graceful_shutdown(async {
            shutdown_signal().await;
            let _ = shutdown_started_tx.send(());
        }),
    );
    tokio::pin!(server);
    let result = tokio::select! {
        result = &mut server => result.context("serve AgentBridge"),
        _ = shutdown_started_rx => {
            match tokio::time::timeout(std::time::Duration::from_secs(30), &mut server).await {
                Ok(result) => result.context("serve AgentBridge"),
                Err(_) => {
                    drain_timeouts.inc();
                    // Explicitly drop the pinned server future here to
                    // stop the accepting `TcpListener` from taking new
                    // connections while the later shutdown phases run.
                    // Detached per-connection tasks that Axum handed
                    // off via `tokio::spawn` still leak — a full fix
                    // requires a broadcast CancellationToken threaded
                    // through the streaming handlers, which is out of
                    // scope here. Until then, the counter above makes
                    // the failure mode observable.
                    Err(anyhow::anyhow!(
                        "timed out draining HTTP connections during shutdown"
                    ))
                }
            }
        }
    };
    reconciler.abort();
    // Round-24 F5: signal maintenance to stop instead of aborting.
    // JoinHandle::abort() only cancels the outer async task; a
    // spawn_blocking closure that's already running keeps rewriting
    // Bridge segments to completion and races the process exit.
    // Notify makes the loop return between ticks so the shutdown
    // .await below actually waits for the blocking work to finish.
    bridge_maintenance_shutdown.notify_one();
    // Round-12 F1: abort the JWKS refresh task on shutdown so the
    // infinite `loop { interval.tick() ... }` cannot outlive the
    // harness's outbound HTTP hygiene. Previously the JoinHandle was
    // dropped at spawn time, letting the refresher fire another
    // request during the shutdown window and race the finalizer for
    // IdentityValidator key state.
    if let Some(handle) = jwks_refresh.as_ref() {
        handle.abort();
    }
    // Silence the expected cancellation; log everything else (panic).
    if let Err(error) = reconciler.await {
        if !error.is_cancelled() {
            tracing::warn!(%error, "reconciler task exited with an error before shutdown abort");
        }
    }
    if let Err(error) = bridge_maintenance.await {
        if !error.is_cancelled() {
            tracing::warn!(%error, "bridge maintenance task exited with an error before shutdown abort");
        }
    }
    if let Some(handle) = jwks_refresh {
        if let Err(error) = handle.await {
            if !error.is_cancelled() {
                tracing::warn!(%error, "JWKS refresh task exited with an error before shutdown abort");
            }
        }
    }
    #[cfg(feature = "otel")]
    let flush_telemetry = move || {
        if let Some(provider) = telemetry_provider {
            provider
                .shutdown_with_timeout(std::time::Duration::from_secs(5))
                .map_err(|error| anyhow::anyhow!("flush OpenTelemetry: {error}"))?;
        }
        Ok(())
    };
    #[cfg(not(feature = "otel"))]
    let flush_telemetry = || Ok(());
    let open_sessions = state.sessions.open_sessions();
    let shutdown_finalizer = state.finalizer.clone();
    let finalize_sessions = async move {
        let mut failures = Vec::new();
        for session in open_sessions {
            if let Err(error) = shutdown_finalizer
                .close_session(session, ab_events::StopReason::SessionClosed)
                .await
            {
                failures.push(error.to_string());
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(anyhow::anyhow!(failures.join("; ")))
        }
    };
    finish_shutdown(
        result,
        std::time::Duration::from_secs(30),
        state.worker.wait_idle(),
        finalize_sessions,
        flush_telemetry,
    )
    .await
}

async fn finish_shutdown<F, G, T>(
    server_result: Result<()>,
    worker_timeout: std::time::Duration,
    worker_drain: F,
    finalize_sessions: G,
    flush_telemetry: T,
) -> Result<()>
where
    F: std::future::Future<Output = ()>,
    G: std::future::Future<Output = Result<()>>,
    T: FnOnce() -> Result<()>,
{
    let mut failures = Vec::new();
    if let Err(error) = server_result {
        failures.push(format!("server: {error:#}"));
    }
    if tokio::time::timeout(worker_timeout, worker_drain).await.is_err() {
        failures.push("timed out draining audit worker during shutdown".to_owned());
    }
    match tokio::time::timeout(worker_timeout, finalize_sessions).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => failures.push(format!("session finalization: {error:#}")),
        Err(_) => failures.push("timed out finalizing sessions during shutdown".to_owned()),
    }
    if let Err(error) = flush_telemetry() {
        failures.push(format!("telemetry: {error:#}"));
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(anyhow::anyhow!("shutdown failures: {}", failures.join("; ")))
    }
}

#[cfg(not(feature = "otel"))]
fn init_tracing() -> Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|error| {
                if std::env::var_os("RUST_LOG").is_some() {
                    eprintln!("warning: RUST_LOG parse failed ({error}); falling back to 'info'");
                }
                tracing_subscriber::EnvFilter::new("info")
            }),
        )
        .with(tracing_subscriber::fmt::layer().json())
        .try_init()
        .map_err(|error| anyhow::anyhow!("initialize tracing: {error}"))
}

#[cfg(feature = "otel")]
fn init_tracing() -> Result<Option<opentelemetry_sdk::trace::SdkTracerProvider>> {
    use opentelemetry::trace::TracerProvider as _;
    use opentelemetry_otlp::WithExportConfig as _;

    let provider = if std::env::var_os("OTEL_EXPORTER_OTLP_ENDPOINT").is_some()
        || std::env::var_os("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT").is_some()
    {
        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .with_protocol(opentelemetry_otlp::Protocol::HttpBinary)
            .build()
            .map_err(|error| anyhow::anyhow!("build OTLP exporter: {error}"))?;
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_resource(
                opentelemetry_sdk::Resource::builder()
                    .with_service_name("agent-bridge")
                    .build(),
            )
            .with_batch_exporter(exporter)
            .build();
        Some(provider)
    } else {
        None
    };
    let telemetry = provider
        .as_ref()
        .map(|provider| tracing_opentelemetry::layer().with_tracer(provider.tracer("agent-bridge")));
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|error| {
                if std::env::var_os("RUST_LOG").is_some() {
                    eprintln!("warning: RUST_LOG parse failed ({error}); falling back to 'info'");
                }
                tracing_subscriber::EnvFilter::new("info")
            }),
        )
        .with(tracing_subscriber::fmt::layer().json())
        .with(telemetry)
        .try_init()
        .map_err(|error| anyhow::anyhow!("initialize tracing: {error}"))?;
    Ok(provider)
}

fn load_sandbox(config: &HarnessConfig) -> Result<Sandbox> {
    let mut schemas = std::collections::HashMap::new();
    if let Some(directory) = config.tool_schema_dir.as_deref() {
        // Zero-config: the *default* schema directory may simply not exist
        // (fresh install, empty working dir). That is fine — the sandbox
        // stays fail-closed and rejects tool calls until schemas are added.
        // An explicitly configured directory must exist: a typo silently
        // disabling every schema would be a policy bypass.
        let is_default_dir = config.uses_default_tool_schema_dir();
        match std::fs::read_dir(directory) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && is_default_dir => {
                tracing::warn!(
                    directory,
                    "default tool schema directory not found; tool calls will be rejected until schemas are added"
                );
            }
            Err(error) => {
                return Err(error).with_context(|| format!("read tool schema directory {directory}"));
            }
            Ok(entries) => {
                for entry in entries {
                    let path = entry?.path();
                    if path.extension().and_then(std::ffi::OsStr::to_str) != Some("json") {
                        continue;
                    }
                    let tool = path
                        .file_stem()
                        .and_then(std::ffi::OsStr::to_str)
                        .filter(|name| !name.is_empty())
                        .ok_or_else(|| anyhow::anyhow!("invalid tool schema filename {}", path.display()))?;
                    let schema: serde_json::Value = serde_json::from_slice(
                        &std::fs::read(&path)
                            .with_context(|| format!("read tool schema {}", path.display()))?,
                    )
                    .with_context(|| format!("parse tool schema {}", path.display()))?;
                    schemas.insert(tool.to_owned(), schema);
                }
            }
        }
    }
    if config.require_tool_schema && schemas.is_empty() {
        // Only a hard error when tool forwarding is actually in use:
        // without a tool upstream no /v1/mcp call can be forwarded anyway,
        // and the sandbox rejects everything unmatched (fail-closed).
        if config.tool_upstream_url.is_some() {
            anyhow::bail!(
                "require_tool_schema=true and tool_upstream_url is set, but no tool schemas were loaded from {:?}",
                config.tool_schema_dir
            );
        }
        tracing::warn!("no tool schemas loaded; every tool call will be rejected (fail-closed)");
    }
    let mut policies: Vec<Box<dyn PolicyEngine>> = Vec::new();
    for path in &config.wasm_policy_paths {
        // Zero-config: fall back to the embedded copy of the default
        // payload-limit policy when the default path is absent on disk.
        // Explicitly configured paths must exist (typo = hard error).
        let is_default_policy = HarnessConfig::is_default_policy_path(path);
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && is_default_policy => {
                tracing::info!(path, "policy file not found; using embedded built-in copy");
                BUILTIN_POLICY_WAT.as_bytes().to_vec()
            }
            Err(error) => return Err(error).with_context(|| format!("read WASM policy {path}")),
        };
        policies.push(Box::new(
            WasmPolicy::from_bytes(path, &bytes).map_err(anyhow::Error::msg)?,
        ));
    }
    Sandbox::new(
        SandboxConfig {
            schemas,
            budget: config.budget.clone(),
            payout_field: "amount_usd".to_owned(),
            require_schema: config.require_tool_schema,
        },
        policies,
    )
    .map_err(anyhow::Error::msg)
}

/// Embedded copy of the default payload-limit policy, compiled into the
/// binary so `cargo install agent-bridge && agent-bridge` works from an
/// empty directory. Kept in sync with the repo file by `include_str!`.
const BUILTIN_POLICY_WAT: &str = include_str!("../../../config/policies/payload_limit.wat");

/// Built-in Bridge manifest for zero-config startup. Hot-only retention
/// (no `cold_uri`: cold export needs the `cold-store` feature and an
/// operator-chosen destination) and single-partition topics suitable for
/// a local trial. The OCSF schema reference resolves to the copy embedded
/// in `ab-bridge`, so no file is needed on disk.
const BUILTIN_MANIFEST_YAML: &str = r#"
manifest_version: 1
name: agent-bridge-builtin
replication_factor: 1
topics:
  - name: agent.tool_call
    partitions: 1
    retention: { hot_hours: 168 }
    schema_ref: schemas/ocsf-agent-event.schema.json
  - name: agent.stop_reason
    partitions: 1
    retention: { hot_hours: 168 }
    schema_ref: schemas/ocsf-agent-event.schema.json
  - name: agent.receipt
    partitions: 1
    retention: { hot_hours: 168 }
    schema_ref: schemas/ocsf-agent-event.schema.json
  - name: agent.compression
    partitions: 1
    retention: { hot_hours: 168 }
    schema_ref: schemas/ocsf-agent-event.schema.json
  - name: agent.identity
    partitions: 1
    retention: { hot_hours: 168 }
    schema_ref: schemas/ocsf-agent-event.schema.json
  - name: agent.session
    partitions: 1
    retention: { hot_hours: 168 }
    schema_ref: schemas/ocsf-agent-event.schema.json
"#;

/// Load the Bridge manifest, falling back to the embedded built-in when
/// the *default* path is absent (zero-config). An explicitly configured
/// path that is missing stays a hard error.
fn load_manifest(config: &HarnessConfig) -> Result<BridgeManifest> {
    match std::fs::read_to_string(&config.bridge_manifest_path) {
        Ok(text) => BridgeManifest::from_yaml(&text).map_err(anyhow::Error::new),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && config.uses_default_manifest_path() => {
            tracing::info!(
                path = %config.bridge_manifest_path,
                "Bridge manifest not found; using embedded built-in manifest"
            );
            BridgeManifest::from_yaml(BUILTIN_MANIFEST_YAML).map_err(anyhow::Error::new)
        }
        Err(error) => {
            Err(error).with_context(|| format!("read Bridge manifest {}", config.bridge_manifest_path))
        }
    }
}

fn spawn_bridge_maintenance(
    bridge: Arc<dyn EventBus>,
    metrics: Arc<ab_core::metrics::Registry>,
    shutdown: Arc<tokio::sync::Notify>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
        // Skip missed ticks under transient overload instead of the
        // default catch-up burst. Bridge maintenance is fine to run
        // once per hour even if the previous run took 30 minutes.
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            // Round-24 F5: previously `bridge_maintenance.abort()`
            // was used at shutdown, but JoinHandle::abort() cancels
            // only the outer async task — the `spawn_blocking`
            // closure below cannot be cancelled, so the OS thread
            // keeps rewriting bridge segments concurrently with
            // `flush_telemetry` and process exit. Race the shutdown
            // notify against the tick so the loop can exit cleanly
            // between ticks, and also skip a fresh spawn_blocking
            // if shutdown fired during the tick's own await.
            tokio::select! {
                biased;
                () = shutdown.notified() => return,
                _ = interval.tick() => {}
            }
            // Supervise the tick body: a panic inside the async wrapper
            // (e.g., an allocator failure in tracing::warn's Display
            // impl) would otherwise silently kill maintenance, and the
            // 1 h cadence hides the outage until Bridge hot retention
            // grows unbounded and fills the disk.
            let outcome = std::panic::AssertUnwindSafe(async {
                let maintenance_bridge = Arc::clone(&bridge);
                let result = tokio::task::spawn_blocking(move || {
                    maintenance_bridge.maintenance(ab_core::time::now_ms())
                })
                .await;
                match result {
                    Ok(Ok(actions)) => metrics
                        .counter(
                            "ab_bridge_maintenance_actions_total",
                            "Bridge retention expirations and cold-export retries",
                        )
                        .add(actions),
                    Ok(Err(error)) => {
                        // Round-12 F2: previously only tracing::warn.
                        // A silent 1-hour cadence made this class of
                        // failure invisible to alerts — Bridge hot
                        // retention could grow unbounded until disk
                        // fills. Bump a counter alongside the log.
                        metrics
                            .counter(
                                "ab_bridge_maintenance_errors_total",
                                "Bridge maintenance tick returned an error",
                            )
                            .inc();
                        tracing::warn!(%error, "Bridge maintenance failed");
                    }
                    Err(error) => {
                        metrics
                            .counter(
                                "ab_bridge_maintenance_join_errors_total",
                                "spawn_blocking JoinError from bridge maintenance tick",
                            )
                            .inc();
                        tracing::warn!(%error, "Bridge maintenance task failed");
                    }
                }
            })
            .catch_unwind()
            .await;
            if let Err(panic) = outcome {
                let msg = panic
                    .downcast_ref::<&'static str>()
                    .copied()
                    .or_else(|| panic.downcast_ref::<String>().map(String::as_str))
                    .unwrap_or("panic payload was not a string");
                metrics
                    .counter(
                        "ab_bridge_maintenance_panics_total",
                        "Bridge maintenance tick panicked; loop supervised via catch_unwind",
                    )
                    .inc();
                tracing::error!(panic = %msg, "Bridge maintenance tick panicked; continuing");
            }
        }
    })
}

async fn build_identity(
    config: &HarnessConfig,
    metrics: Arc<ab_core::metrics::Registry>,
) -> Result<(Option<Arc<IdentityValidator>>, Option<tokio::task::JoinHandle<()>>)> {
    let has_jwks = config
        .identity_jwks_url
        .as_deref()
        .is_some_and(|url| !url.is_empty());
    let has_hmac = config
        .identity_hmac_secret_file
        .as_deref()
        .is_some_and(|path| !path.is_empty());
    if !has_jwks && !has_hmac {
        return Ok((None, None));
    }

    let mut validator = IdentityValidator::new(&config.audience);
    if !config.identity_allowed_issuers.is_empty() {
        validator.allow_issuers(config.identity_allowed_issuers.clone());
    }
    if let Some(path) = config.identity_hmac_secret_file.as_deref() {
        require_owner_only_mode(Path::new(path))?;
        let secret = std::fs::read(path).with_context(|| format!("read identity HMAC secret {path}"))?;
        if secret.is_empty() {
            anyhow::bail!("identity HMAC secret file {path} is empty");
        }
        validator
            .add_key(&config.identity_hmac_kid, KeyMaterial::HmacSecret(secret))
            .context("install identity HMAC key")?;
    }

    let validator = Arc::new(validator);
    let mut refresh_handle: Option<tokio::task::JoinHandle<()>> = None;
    if let Some(url) = config.identity_jwks_url.as_deref() {
        // Disable redirects: an IdP that returns 302 to an internal URL would
        // let a compromised (or misconfigured) JWKS host pivot the harness
        // into an SSRF probe against private services.
        //
        // Total-request timeout of 10 s guards against slowloris IdPs
        // that accept the TCP handshake but never send response bytes
        // (or send them one byte per minute). Without it, a single
        // stuck fetch pins the refresh loop's `tick()` forever and
        // subsequent scheduled refreshes never fire (see round-11 F1).
        // Result: revoked keys stay honored until the next process
        // restart, with no scheduled recovery.
        let client = reqwest::Client::builder()
            .connect_timeout(ab_harness::pipeline::HTTP_CONNECT_TIMEOUT)
            .timeout(std::time::Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .context("build JWKS client")?;
        refresh_jwks(&client, url, validator.as_ref()).await?;
        let url = url.to_owned();
        let validator = Arc::clone(&validator);
        let refresh_s = config.identity_jwks_refresh_s;
        // Register both counters up-front so their TYPE lines are
        // present in `/metrics` even before the first failure — ops
        // alerts can wire onto them at boot.
        let refresh_errors = metrics.counter(
            "ab_jwks_refresh_errors_total",
            "JWKS refresh HTTP/parse/network failures (per attempt)",
        );
        let refresh_panics = metrics.counter(
            "ab_jwks_refresh_panics_total",
            "JWKS refresh task panicked; loop supervised via catch_unwind",
        );
        refresh_handle = Some(tokio::spawn(async move {
            // Wrap the whole loop in AssertUnwindSafe so an unexpected
            // panic (reqwest bug, malformed JWKS, allocator failure)
            // does not silently kill the refresher and leave the harness
            // running with a stale key set. If the loop *does* panic, we
            // log + count + rebuild the loop.
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(refresh_s));
            // Skip missed ticks instead of the default catch-up burst
            // — if a JWKS fetch takes longer than one interval (rare
            // but possible under IdP overload) we should not
            // immediately re-fire; another key rotation is minutes
            // away.
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            interval.tick().await;
            loop {
                interval.tick().await;
                // Wrap the WHOLE tick body — refresh + result handling
                // + tracing + counter — in catch_unwind, mirroring the
                // bridge maintenance pattern. Previously only the
                // refresh_jwks call itself was supervised, so a panic
                // in the match arm (e.g., allocator failure inside
                // tracing::warn's Display, or a refresh_panics.inc()
                // fault after the registry Arc has been dropped)
                // would silently kill the spawned task and leave keys
                // frozen until process restart — with no counter to
                // page on.
                let refresh_errors = Arc::clone(&refresh_errors);
                let refresh_panics_for_error = Arc::clone(&refresh_panics);
                let client = &client;
                let url = &url;
                let validator = validator.as_ref();
                let tick = std::panic::AssertUnwindSafe(async move {
                    match refresh_jwks(client, url, validator).await {
                        Ok(_) => {}
                        Err(error) => {
                            refresh_errors.inc();
                            // Round-35 F2: do NOT `%error` here. The
                            // anyhow chain in `refresh_jwks` used to
                            // embed the JWKS URL in every `.with_context`
                            // and every `anyhow::bail!` message; anyhow's
                            // Display walks the whole chain and prints
                            // it. The corp IdP hostname is enterprise-
                            // topology-sensitive (reveals SSO vendor,
                            // tenant, region) and does not belong in
                            // downstream OTLP sinks. `refresh_jwks` now
                            // returns URL-free error text; log the
                            // stable classifier only.
                            tracing::warn!(
                                category = %classify_jwks_error(&error),
                                "JWKS refresh failed; retaining previously loaded keys"
                            );
                        }
                    }
                });
                if let Err(panic) = tick.catch_unwind().await {
                    refresh_panics_for_error.inc();
                    let msg = panic
                        .downcast_ref::<&'static str>()
                        .copied()
                        .or_else(|| panic.downcast_ref::<String>().map(String::as_str))
                        .unwrap_or("panic payload was not a string");
                    tracing::error!(
                        panic = %msg,
                        "JWKS refresh task panicked; retaining previously loaded keys and continuing"
                    );
                }
            }
        }));
    }
    if validator.key_count() == 0 {
        anyhow::bail!("identity enforcement configured without any verification keys");
    }
    Ok((Some(validator), refresh_handle))
}

async fn refresh_jwks(client: &reqwest::Client, url: &str, validator: &IdentityValidator) -> Result<usize> {
    // A typical JWKS is < 10 KB (5–20 keys). Even the largest enterprise
    // IdPs stay under a few hundred KB. Cap at 4 MiB so a compromised or
    // misconfigured JWKS host cannot return a multi-GB payload and OOM
    // the harness before the 10 s request timeout fires: at a fast link
    // (1 Gbit/s) 1 second is enough to deliver >100 MB, so the timeout
    // alone is not a sufficient defense.
    //
    // Round-35 F2: every error return must be URL-free. Callers log
    // this fn's error via anyhow's Display, which walks the whole
    // context chain — embedding the URL in a `.with_context()` used
    // to leak the corp IdP hostname to downstream OTLP sinks.
    // Structured logs at the call site record the stable category.
    const MAX_JWKS_BYTES: usize = 4 * 1024 * 1024;
    let response = client
        .get(url)
        .send()
        .await
        .context("fetch JWKS")?
        .error_for_status()
        .context("JWKS endpoint returned an error")?;
    // Fast reject: if Content-Length is present and already exceeds the
    // cap, refuse without allocating anything for the body.
    if let Some(len) = response.content_length() {
        if len > MAX_JWKS_BYTES as u64 {
            anyhow::bail!(
                "JWKS declared Content-Length {len} bytes; cap is {MAX_JWKS_BYTES}"
            );
        }
    }
    use futures::StreamExt as _;
    let mut stream = response.bytes_stream();
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("read JWKS chunk")?;
        let next = body
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| anyhow::anyhow!("JWKS body size overflowed usize"))?;
        if next > MAX_JWKS_BYTES {
            anyhow::bail!(
                "JWKS exceeded {MAX_JWKS_BYTES} bytes (received at least {next})"
            );
        }
        body.extend_from_slice(&chunk);
    }
    let document: serde_json::Value =
        serde_json::from_slice(&body).context("parse JWKS JSON")?;
    validator.add_jwks(&document).map_err(anyhow::Error::new)
}

/// Round-35 F2: stable string classifier for JWKS refresh failures
/// suitable for structured logging without echoing the URL.
fn classify_jwks_error(error: &anyhow::Error) -> &'static str {
    if let Some(reqwest_err) = error.downcast_ref::<reqwest::Error>() {
        if reqwest_err.is_timeout() {
            "timeout"
        } else if reqwest_err.is_connect() {
            "connect"
        } else if reqwest_err.is_body() {
            "body"
        } else if reqwest_err.status().is_some() {
            "status"
        } else {
            "request"
        }
    } else if error.to_string().contains("exceeded") {
        "oversize"
    } else if error.to_string().contains("parse JWKS JSON") {
        "parse"
    } else {
        "other"
    }
}

fn build_bridge(config: &HarnessConfig, manifest: &BridgeManifest) -> Result<Arc<dyn EventBus>> {
    match config.bridge_backend.as_str() {
        "embedded" => {
            let path = PathBuf::from(&config.bridge_data_dir);
            let bridge = if path.join("manifest.yaml").exists() {
                EmbeddedBroker::open(&path)
            } else {
                EmbeddedBroker::provision(&path, manifest)
            }
            .context("initialize embedded Bridge")?;
            Ok(Arc::new(bridge))
        }
        "kafka" => {
            #[cfg(feature = "kafka")]
            {
                let endpoint = config
                    .bridge_endpoint
                    .as_deref()
                    .context("bridge_endpoint is required for kafka")?;
                let bus = tokio::task::block_in_place(|| {
                    ab_bridge::kafka_bus::KafkaBus::provision(endpoint, manifest)
                })
                .context("initialize Kafka/Redpanda Bridge")?;
                Ok(Arc::new(bus))
            }
            #[cfg(not(feature = "kafka"))]
            anyhow::bail!("kafka backend requested but agent-bridge was built without feature kafka")
        }
        "nats" => {
            #[cfg(feature = "nats")]
            {
                let endpoint = config
                    .bridge_endpoint
                    .as_deref()
                    .context("bridge_endpoint is required for nats")?;
                let bus = tokio::task::block_in_place(|| {
                    ab_bridge::nats_bus::NatsBus::provision(endpoint, manifest)
                })
                .context("initialize NATS JetStream Bridge")?;
                Ok(Arc::new(bus))
            }
            #[cfg(not(feature = "nats"))]
            anyhow::bail!("nats backend requested but agent-bridge was built without feature nats")
        }
        other => anyhow::bail!("unsupported bridge backend {other:?}"),
    }
}

fn build_store(config: &HarnessConfig) -> Result<Arc<dyn StateStore>> {
    match config.state_backend.as_str() {
        "memory" => Ok(Arc::new(InMemoryStore::new())),
        "redis" => {
            #[cfg(feature = "redis")]
            {
                let endpoint = config
                    .state_endpoint
                    .as_deref()
                    .context("state_endpoint is required for redis")?;
                let store =
                    ab_state::redis_store::RedisStore::connect(endpoint).map_err(anyhow::Error::new)?;
                Ok(Arc::new(store))
            }
            #[cfg(not(feature = "redis"))]
            anyhow::bail!("redis backend requested but agent-bridge was built without feature redis")
        }
        other => anyhow::bail!("unsupported state backend {other:?}"),
    }
}

fn build_embedder(config: &HarnessConfig) -> Result<Arc<dyn Embedder>> {
    match config.embedder_backend.as_str() {
        "hash" => Ok(Arc::new(HashEmbedder::default())),
        "onnx" => {
            #[cfg(feature = "onnx")]
            {
                let path = config
                    .onnx_model_path
                    .as_deref()
                    .context("onnx_model_path is required for onnx")?;
                let tokenizer_path = config
                    .onnx_tokenizer_path
                    .as_deref()
                    .context("onnx_tokenizer_path is required for onnx")?;
                let embedder = ab_loopdetect::OnnxEmbedder::load(
                    Path::new(path),
                    Path::new(tokenizer_path),
                    config.onnx_dimension,
                )
                .map_err(|error| anyhow::anyhow!("load ONNX model: {error}"))?;
                Ok(Arc::new(embedder))
            }
            #[cfg(not(feature = "onnx"))]
            anyhow::bail!("onnx backend requested but agent-bridge was built without feature onnx")
        }
        other => anyhow::bail!("unsupported embedder backend {other:?}"),
    }
}

async fn build_vector_sink(config: &HarnessConfig, _dimension: usize) -> Result<Arc<dyn VectorSink>> {
    match config.vector_backend.as_str() {
        "memory" => Ok(Arc::new(NoopVectorSink)),
        "qdrant" => {
            #[cfg(feature = "qdrant")]
            {
                let url = config
                    .qdrant_url
                    .as_deref()
                    .context("qdrant_url is required for qdrant")?;
                let sink = ab_loopdetect::QdrantVectorSink::new(url, &config.qdrant_collection)
                    .map_err(|error| anyhow::anyhow!("configure Qdrant client: {error}"))?;
                sink.ensure_collection(_dimension)
                    .await
                    .map_err(|error| anyhow::anyhow!("provision Qdrant collection: {error}"))?;
                Ok(Arc::new(sink))
            }
            #[cfg(not(feature = "qdrant"))]
            anyhow::bail!("qdrant backend requested but agent-bridge was built without feature qdrant")
        }
        other => anyhow::bail!("unsupported vector backend {other:?}"),
    }
}

fn load_or_create_signer(path: &Path) -> Result<Ed25519Signer> {
    match read_signer(path) {
        Ok(signer) => return Ok(signer),
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) => {}
        Err(error) => return Err(error),
    }
    let signer = Ed25519Signer::generate();
    // Round-18 F5 + round-19 F2/F3: `signer.seed()` now returns
    // `Zeroizing<[u8; 32]>` directly, so no temp slot lingers on
    // the caller's stack. The hex encoding is separately wrapped
    // in Zeroizing so its heap buffer is zeroed on drop too.
    let seed = signer.seed();
    // Round-19 F3: `&*seed` (not `*seed`) is required to avoid
    // copying the seed bytes onto a fresh un-zeroized temp slot
    // for hex::encode. clippy's `needless_borrows_for_generic_args`
    // lint is a false positive here — it would suggest `*seed`,
    // moving 32 bytes out of the Zeroizing wrapper.
    #[allow(clippy::needless_borrows_for_generic_args)]
    let encoded_seed = zeroize::Zeroizing::new(hex::encode(&*seed));
    if install_seed_exclusive(path, &encoded_seed)? {
        Ok(signer)
    } else {
        read_signer(path).context("load signing seed installed by another process")
    }
}

/// Reject a file whose mode is readable by group or other on Unix, and
/// refuse to follow a symbolic link at `path` — a pre-planted symlink to
/// an attacker-owned 0o600 hex file would otherwise fool the mode check
/// (`std::fs::metadata` follows symlinks and returns the *target*'s mode)
/// and let `read_to_string` load an attacker-chosen seed. Windows does
/// not model POSIX modes so this is a no-op there — deployments on
/// Windows must rely on ACLs set by the operator.
fn require_owner_only_mode(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        // `symlink_metadata` does NOT traverse a symbolic link, so the
        // file-type check below is applied to the link itself, not to
        // whatever the link happens to point at.
        let metadata = std::fs::symlink_metadata(path)
            .with_context(|| format!("stat secret file {}", path.display()))?;
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            anyhow::bail!(
                "secret file {} is a symbolic link; refusing to follow (remove the link and store the seed inline at this path)",
                path.display(),
            );
        }
        if !file_type.is_file() {
            anyhow::bail!(
                "secret file {} is not a regular file (type: {file_type:?})",
                path.display(),
            );
        }
        // Bottom 9 bits are rwxrwxrwx; any of the group/other read bits set is a leak.
        let mode = metadata.mode() & 0o777;
        if mode & 0o077 != 0 {
            anyhow::bail!(
                "secret file {} has mode 0o{mode:03o}; must be 0o600 (chmod 600 {})",
                path.display(),
                path.display(),
            );
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

fn read_signer(path: &Path) -> Result<Ed25519Signer> {
    require_owner_only_mode(path)?;
    // Round-18 F4: consistent posture with the CLI's round-17 F6
    // read_capped_str — the harness should not use uncapped
    // read_to_string on a security-sensitive file just because
    // require_owner_only_mode already refused the group/other-
    // readable case. A hex-encoded 32-byte seed is 65 bytes with
    // newline; MAX_CONTROL_BYTES (1 MiB) is a generous ceiling.
    // Round-18 F5: wrap the seed intermediates in `Zeroizing<...>`
    // so their memory is zeroed on drop rather than leaking a
    // recoverable copy in freed heap / stack slots (visible to a
    // core dump, minidump upload, or kdump crashkernel image).
    // ed25519-dalek 2.2+ with the `zeroize` feature also zeroes
    // SigningKey's internal buffer on drop.
    use zeroize::Zeroizing;
    let encoded = Zeroizing::new(
        ab_core::fsutil::read_capped_string(path, ab_core::fsutil::MAX_CONTROL_BYTES)
            .with_context(|| format!("read signing seed {}", path.display()))?,
    );
    let bytes = Zeroizing::new(
        hex::decode(encoded.trim()).context("decode signing seed as hex")?,
    );
    // Round-19 F1: copy directly from the Zeroizing<Vec<u8>> slice
    // into a fresh Zeroizing<[u8; 32]>. Historically we did
    // `(*bytes).clone().try_into()` which materialized a bare
    // `Vec<u8>` intermediate and (on `try_into` failure) an
    // `Err(Vec<u8>)` — both unzeroed. `<[u8;32]>::try_from(&[u8])`
    // takes only a slice reference and copies bytes straight into
    // the caller-supplied slot, so the intermediate is scoped to
    // the Zeroizing wrapper for its entire lifetime.
    let seed: Zeroizing<[u8; 32]> = Zeroizing::new(
        <[u8; 32]>::try_from(bytes.as_slice())
            .map_err(|_| anyhow::anyhow!("signing seed must contain exactly 32 bytes"))?,
    );
    // Round-14: refuse known-weak Ed25519 seeds. An all-zero seed
    // produces a valid keypair with a globally-known public key — any
    // attacker who knows we accepted `[0; 32]` can forge receipts
    // that verify against our key id. Same for the all-`0xFF` seed
    // (both are the "textbook wrong" values operators sometimes
    // paste in when troubleshooting). Fail fast at startup so the
    // hazard cannot ship silently.
    if *seed == [0u8; 32] {
        anyhow::bail!(
            "signing seed at {} is all zeros; refusing (this is a known-weak seed with a globally predictable public key)",
            path.display()
        );
    }
    if *seed == [0xFFu8; 32] {
        anyhow::bail!(
            "signing seed at {} is all 0xFF bytes; refusing (this is a known-weak seed with a globally predictable public key)",
            path.display()
        );
    }
    Ok(Ed25519Signer::from_seed(&seed))
}

fn install_seed_exclusive(path: &Path, encoded: &str) -> Result<bool> {
    use std::io::Write as _;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)
        .with_context(|| format!("create signing seed directory {}", parent.display()))?;
    let temporary = parent.join(format!(".signing-seed-{}.tmp", ab_core::new_event_uid()));
    // Round-12 F4: previously an early `?` return from write_all or
    // sync_all would orphan the temp file. The two `Err(...)` match
    // arms of `hard_link` explicitly removed it, but the earlier
    // failure paths did not. Use the same TempPathGuard RAII the
    // round-11 fix landed for `write_atomic` so every failure path
    // unlinks — this is a startup-only code path, but leaving an
    // orphan means every subsequent boot leaves another zero-byte
    // `.signing-seed-*.tmp` alongside the real seed, and a nervous
    // operator debugging a "signing seed exists twice" symptom is
    // easily led astray.
    let mut guard = ab_core::fsutil::TempPathGuard::new(temporary.clone());
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .with_context(|| format!("create signing seed temporary file {}", temporary.display()))?;
    file.write_all(encoded.as_bytes())
        .with_context(|| format!("write signing seed temporary file {}", temporary.display()))?;
    file.sync_all()
        .with_context(|| format!("sync signing seed temporary file {}", temporary.display()))?;
    match std::fs::hard_link(&temporary, path) {
        Ok(()) => {
            // Round-13 F4: the seed IS installed at `path` at this
            // point (hard_link committed). Degrade the remaining
            // best-effort ops (tmp unlink, parent fsync) to warn
            // rather than returning Err — otherwise a spurious EIO on
            // sync_directory made the harness fail startup even
            // though the seed was correctly installed, wasting one
            // boot cycle to a misleading error. On next boot,
            // hard_link → AlreadyExists → Ok(false) and the caller
            // reads back the seed — self-corrects, but the noisy
            // failure is now avoided at source.
            if let Err(error) = std::fs::remove_file(&temporary) {
                tracing::warn!(
                    path = %temporary.display(),
                    %error,
                    "signing seed installed, but removing tmp file failed; guard drop will retry"
                );
            }
            guard.disarm();
            if let Err(error) = ab_core::fsutil::sync_directory(parent) {
                tracing::warn!(
                    path = %parent.display(),
                    %error,
                    "signing seed installed, but parent directory fsync failed; dirent may not survive an immediate power loss"
                );
            }
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            // Guard drop below unlinks the tmp — no explicit remove
            // needed. Same for the generic Err arm.
            Ok(false)
        }
        Err(error) => {
            Err(error).with_context(|| format!("install signing seed {}", path.display()))
        }
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        // Install SIGTERM first: docker stop / kubectl delete pod send
        // SIGTERM (not SIGINT) and expect the process to shut down
        // cleanly within its grace period. If we cannot install a
        // SIGTERM handler, no orchestrator signal will trigger the
        // finalizer — the container silently ignores shutdown until
        // it gets SIGKILL, dropping in-flight receipts.
        //
        // This is a fatal environment misconfiguration (typically
        // over-restrictive seccomp), not something to paper over with
        // SIGINT-only fallback. Panic so the runtime exits with a
        // non-zero status the orchestrator can log.
        let mut terminate = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(signal) => signal,
            Err(error) => {
                tracing::error!(
                    %error,
                    "failed to install SIGTERM handler — orchestrator shutdowns will not be observed. \
                     This is a fatal environment misconfiguration (over-restrictive seccomp, missing \
                     signal syscalls). Aborting so the container is not silently unresponsive to \
                     `docker stop` / `kubectl delete pod`."
                );
                std::process::exit(2);
            }
        };
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                if let Err(error) = result {
                    tracing::error!(%error, "failed to listen for Ctrl-C");
                }
            }
            _ = terminate.recv() => {}
        }
        // Round-34 F2: force-exit on a second signal. Once the first
        // signal fires and this fn returns, the tokio handlers stay
        // registered process-wide — the OS default action never runs
        // and subsequent SIGTERM / SIGINT are silently consumed by
        // the still-armed receivers. An operator sending a second
        // Ctrl-C to force-abort a hung graceful shutdown (stuck
        // upstream connection preventing `wait_for_worker_jobs`
        // from returning, for instance) sees no effect until
        // Kubernetes' terminationGracePeriodSeconds elapses and
        // SIGKILL fires — the "docker stop; docker stop" pattern
        // is broken. Spawn a background task that races a second
        // signal to `std::process::exit(130)` (the conventional
        // Ctrl-C exit code). If a second signal arrives during
        // graceful shutdown, the process exits immediately with
        // a clear tracing line.
        tokio::spawn(async {
            let mut terminate = tokio::signal::unix::signal(
                tokio::signal::unix::SignalKind::terminate(),
            )
            .ok();
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = async {
                    if let Some(ref mut sig) = terminate {
                        sig.recv().await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                } => {}
            }
            tracing::warn!(
                "second shutdown signal received during graceful shutdown; forcing exit(130) \
                 — any in-flight receipt or ATIF write will be picked up by recovery on restart"
            );
            std::process::exit(130);
        });
    }
    #[cfg(not(unix))]
    if let Err(error) = tokio::signal::ctrl_c().await {
        tracing::error!(%error, "failed to listen for Ctrl-C");
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn signing_seed_is_persisted_and_reused() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("key.seed");
        let first = load_or_create_signer(&path).unwrap();
        let second = load_or_create_signer(&path).unwrap();
        assert_eq!(first.key_id(), second.key_id());
        assert_eq!(std::fs::read_to_string(path).unwrap().trim().len(), 64);
    }

    /// Round-14: a signing seed of all zeros produces a valid Ed25519
    /// keypair with a globally-known public key. Any attacker who
    /// realized we accepted `[0; 32]` could forge receipts that verify
    /// under the resulting key id. Fail closed at startup rather than
    /// let a copy-paste-from-test-vector operator error ship as
    /// production. Same for all-0xFF.
    #[cfg(unix)]
    #[test]
    fn refuses_known_weak_signing_seed_all_zeros() {
        use std::os::unix::fs::PermissionsExt as _;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("zeros.seed");
        std::fs::write(&path, "0".repeat(64)).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let err = read_signer(&path).unwrap_err().to_string();
        assert!(
            err.contains("all zeros"),
            "expected all-zeros rejection, got: {err}",
        );
    }

    #[cfg(unix)]
    #[test]
    fn refuses_known_weak_signing_seed_all_ff() {
        use std::os::unix::fs::PermissionsExt as _;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("ff.seed");
        std::fs::write(&path, "f".repeat(64)).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let err = read_signer(&path).unwrap_err().to_string();
        assert!(
            err.contains("0xFF"),
            "expected all-0xFF rejection, got: {err}",
        );
    }

    #[test]
    fn concurrent_signing_seed_creation_converges_on_one_key() {
        let directory = tempfile::tempdir().unwrap();
        let path = Arc::new(directory.path().join("shared.seed"));
        let barrier = Arc::new(std::sync::Barrier::new(8));
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let path = Arc::clone(&path);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    load_or_create_signer(&path).unwrap().key_id().to_owned()
                })
            })
            .collect();
        let key_ids: std::collections::HashSet<_> =
            handles.into_iter().map(|handle| handle.join().unwrap()).collect();
        assert_eq!(key_ids.len(), 1);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(path.as_ref()).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[tokio::test]
    async fn hmac_identity_file_enables_required_identity() {
        let directory = tempfile::tempdir().unwrap();
        let secret = directory.path().join("identity.secret");
        std::fs::write(&secret, b"development-secret").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let mut config = HarnessConfig::for_tests("http://upstream", "/tmp", "/tmp");
        config.require_identity = true;
        config.identity_hmac_secret_file = Some(secret.to_string_lossy().into_owned());
        let (validator, _refresh) = build_identity(&config, Arc::new(ab_core::metrics::Registry::new()))
            .await
            .unwrap();
        let validator = validator.unwrap();
        assert_eq!(validator.key_count(), 1);
    }

    /// A group- or world-readable signing seed must be refused rather than
    /// silently loaded — otherwise any other local user could steal the
    /// harness's private key by reading the seed file.
    #[cfg(unix)]
    #[test]
    fn refuses_to_load_group_readable_signing_seed() {
        use std::os::unix::fs::PermissionsExt as _;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("leaky.seed");
        let signer = Ed25519Signer::generate();
        std::fs::write(&path, hex::encode(signer.seed())).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let err = read_signer(&path).unwrap_err().to_string();
        assert!(err.contains("must be 0o600"), "got {err}");
    }

    #[cfg(unix)]
    #[test]
    fn refuses_to_load_world_readable_signing_seed() {
        use std::os::unix::fs::PermissionsExt as _;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("public.seed");
        let signer = Ed25519Signer::generate();
        std::fs::write(&path, hex::encode(signer.seed())).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_signer(&path).is_err());
    }

    /// Same guarantee for the identity HMAC secret file: refuse to load if
    /// group or other can read it.
    #[cfg(unix)]
    #[tokio::test]
    async fn refuses_to_load_group_readable_hmac_secret_file() {
        use std::os::unix::fs::PermissionsExt as _;
        let directory = tempfile::tempdir().unwrap();
        let secret = directory.path().join("leaky.hmac");
        std::fs::write(&secret, b"development-secret").unwrap();
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o644)).unwrap();
        let mut config = HarnessConfig::for_tests("http://upstream", "/tmp", "/tmp");
        config.require_identity = true;
        config.identity_hmac_secret_file = Some(secret.to_string_lossy().into_owned());
        assert!(build_identity(&config, Arc::new(ab_core::metrics::Registry::new())).await.is_err());
    }

    /// Vicious bug regression: `std::fs::metadata` follows symbolic links,
    /// so the historical `require_owner_only_mode` check returned the
    /// *target*'s mode. A pre-planted symlink pointing at an attacker-owned
    /// 0o600 hex file would therefore pass the mode check, and the
    /// subsequent `read_to_string` (which also follows symlinks) would load
    /// the attacker's chosen seed — replacing the harness's signing key.
    /// The fix uses `symlink_metadata` to reject symlinks up front, before
    /// any secret bytes are read.
    #[cfg(unix)]
    #[test]
    fn refuses_to_follow_signing_seed_symlink_to_attacker_owned_file() {
        use std::os::unix::fs::PermissionsExt as _;
        let directory = tempfile::tempdir().unwrap();
        // Attacker file: an ordinary 0o600 file owned by the same user.
        // In a shared-tenant deployment this could be any 32-byte hex blob
        // the attacker chose (e.g., their own keypair).
        let attacker_file = directory.path().join("attacker.hex");
        std::fs::write(
            &attacker_file,
            "0102030405060708091011121314151617181920212223242526272829303132\n",
        )
        .unwrap();
        std::fs::set_permissions(&attacker_file, std::fs::Permissions::from_mode(0o600)).unwrap();
        // Attacker plants a symlink at the seed path.
        let seed_path = directory.path().join("signing.seed");
        std::os::unix::fs::symlink(&attacker_file, &seed_path).unwrap();
        let err = read_signer(&seed_path).unwrap_err().to_string();
        assert!(
            err.contains("symbolic link"),
            "expected symlink rejection, got: {err}",
        );
    }

    /// Same guarantee for the identity HMAC secret file: a pre-planted
    /// symlink to an attacker-owned 0o600 file must be refused rather
    /// than followed to load an attacker-chosen HMAC key.
    #[cfg(unix)]
    #[tokio::test]
    async fn refuses_to_follow_hmac_secret_symlink_to_attacker_owned_file() {
        use std::os::unix::fs::PermissionsExt as _;
        let directory = tempfile::tempdir().unwrap();
        let attacker_file = directory.path().join("attacker.hmac");
        std::fs::write(&attacker_file, b"attacker-chosen-hmac-key").unwrap();
        std::fs::set_permissions(&attacker_file, std::fs::Permissions::from_mode(0o600)).unwrap();
        let secret = directory.path().join("identity.hmac");
        std::os::unix::fs::symlink(&attacker_file, &secret).unwrap();
        let mut config = HarnessConfig::for_tests("http://upstream", "/tmp", "/tmp");
        config.require_identity = true;
        config.identity_hmac_secret_file = Some(secret.to_string_lossy().into_owned());
        let result = build_identity(&config, Arc::new(ab_core::metrics::Registry::new())).await;
        let err = result.err().map(|error| error.to_string()).unwrap_or_default();
        assert!(
            err.contains("symbolic link"),
            "expected symlink rejection, got: {err}",
        );
    }

    /// Round-12: a compromised or misconfigured JWKS host that returns a
    /// gigantic body must not OOM the harness. Serve 8 MiB (double the
    /// 4 MiB cap) and assert the refresh returns an error whose text
    /// mentions the cap so ops can identify the failure mode.
    #[tokio::test]
    async fn refresh_jwks_rejects_bodies_over_the_cap() {
        use axum::routing::get;
        // 8 MiB of nonsense — well above the 4 MiB cap. We hand it out
        // in a single `[u8]` buffer wrapped in a `body::Body`, so the
        // Content-Length header is present. The response type doesn't
        // even need to be valid JSON: the size check triggers first.
        let big_body = vec![b'x'; 8 * 1024 * 1024];
        let router = axum::Router::new().route(
            "/jwks",
            get(move || {
                let body = big_body.clone();
                async move {
                    (
                        [(axum::http::header::CONTENT_TYPE, "application/json")],
                        body,
                    )
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();
        let validator = ab_identity::IdentityValidator::new("test-aud");
        let url = format!("http://{addr}/jwks");
        let err = refresh_jwks(&client, &url, &validator).await.unwrap_err();
        let text = format!("{err:#}");
        assert!(
            text.contains("Content-Length") || text.contains("exceeded"),
            "expected JWKS cap error, got: {text}"
        );
        assert!(text.contains("4194304"), "expected cap size in error, got: {text}");
        // Round-35 F2: the returned error MUST NOT contain the URL.
        // anyhow's Display walks the whole context chain; if any
        // `.with_context(|| format!("... {url}"))` or
        // `anyhow::bail!("... {url} ...")` slipped back into
        // refresh_jwks, this assertion fires. The URL character
        // sequence "://" is the tightest proxy for "any URL leaked".
        assert!(
            !text.contains("://"),
            "refresh_jwks error must be URL-free (JWKS URL is enterprise-topology-sensitive; \
             see round-35 F2). Got: {text}"
        );
        assert!(
            !text.contains(&addr.to_string()),
            "refresh_jwks error must not contain the host:port either. Got: {text}"
        );
        // classify_jwks_error must return a stable non-identifying
        // category — same URL-free posture on the log-side.
        let category = classify_jwks_error(&err);
        assert!(
            !category.contains("://") && !category.contains(&addr.to_string()),
            "classify_jwks_error must be URL-free. Got: {category}"
        );
        server.abort();
    }

    /// The same cap applies at the streamed-body level: a peer that
    /// omits Content-Length still cannot bypass the check because
    /// [`refresh_jwks`] counts bytes as they arrive. This test uses
    /// chunked transfer encoding via `axum::body::Body::from_stream`
    /// so no Content-Length is advertised.
    #[tokio::test]
    async fn refresh_jwks_rejects_streamed_bodies_over_the_cap() {
        use axum::routing::get;
        use futures::stream;
        let router = axum::Router::new().route(
            "/jwks",
            get(|| async {
                // Emit 128 chunks of 64 KiB each = 8 MiB, streamed
                // (no Content-Length).
                let chunks = (0..128).map(|_| {
                    Ok::<_, std::io::Error>(axum::body::Bytes::from(vec![b'x'; 64 * 1024]))
                });
                axum::body::Body::from_stream(stream::iter(chunks.collect::<Vec<_>>()))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();
        let validator = ab_identity::IdentityValidator::new("test-aud");
        let url = format!("http://{addr}/jwks");
        let err = refresh_jwks(&client, &url, &validator).await.unwrap_err();
        let text = format!("{err:#}");
        assert!(
            text.contains("exceeded"),
            "expected streamed-body cap error, got: {text}"
        );
        server.abort();
    }

    #[tokio::test]
    async fn shutdown_runs_later_phases_after_earlier_failures() {
        let telemetry_called = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let finalization_called = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let called = Arc::clone(&telemetry_called);
        let finalized = Arc::clone(&finalization_called);
        let error = finish_shutdown(
            Err(anyhow::anyhow!("server failed")),
            std::time::Duration::from_millis(1),
            std::future::pending(),
            async move {
                finalized.store(true, std::sync::atomic::Ordering::Release);
                Err(anyhow::anyhow!("finalize failed"))
            },
            move || {
                called.store(true, std::sync::atomic::Ordering::Release);
                Err(anyhow::anyhow!("flush failed"))
            },
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(telemetry_called.load(std::sync::atomic::Ordering::Acquire));
        assert!(finalization_called.load(std::sync::atomic::Ordering::Acquire));
        assert!(error.contains("server failed"));
        assert!(error.contains("timed out draining audit worker"));
        assert!(error.contains("finalize failed"));
        assert!(error.contains("flush failed"));
    }

    #[test]
    fn shipped_sandbox_artifacts_load_and_enforce() {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut config = HarnessConfig::for_tests("http://upstream", "/tmp", "/tmp");
        config.tool_schema_dir = Some(
            workspace
                .join("config/tool-schemas")
                .to_string_lossy()
                .into_owned(),
        );
        config.require_tool_schema = true;
        config.wasm_policy_paths = vec![workspace
            .join("config/policies/payload_limit.wat")
            .to_string_lossy()
            .into_owned()];
        let sandbox = load_sandbox(&config).unwrap();
        let store = InMemoryStore::new();
        let valid = serde_json::to_vec(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "db_write",
                "arguments": {"table": "items", "row": {"id": 1}}
            }
        }))
        .unwrap();
        assert!(sandbox.check(&store, "session", &valid).is_allowed());
        let unknown = serde_json::to_vec(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "unknown", "arguments": {}}
        }))
        .unwrap();
        assert!(!sandbox.check(&store, "session", &unknown).is_allowed());
        assert!(sandbox
            .sanitize(
                "chat/completions",
                &serde_json::json!({"content": "x".repeat(1_100_000)}),
            )
            .is_err());
    }
}
