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
    let identity = build_identity(&config).await?;
    let signer_path = std::env::var_os("AB_SIGNING_SEED_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("config/signing.seed"));
    let signer: Arc<dyn Signer> = Arc::new(load_or_create_signer(&signer_path)?);
    bridge
        .set_control_key(ab_harness::control_key_from_signer(signer.as_ref()))
        .context("configure Bridge control authentication")?;
    let state = AppState::new_with_backends(
        config.clone(),
        store,
        Arc::new(sandbox),
        bridge,
        identity,
        signer,
        embedder,
        vector_sink,
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
    let bridge_maintenance = spawn_bridge_maintenance(Arc::clone(&state.bridge), Arc::clone(&state.metrics));
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
                Err(_) => Err(anyhow::anyhow!(
                    "timed out draining HTTP connections during shutdown"
                )),
            }
        }
    };
    reconciler.abort();
    bridge_maintenance.abort();
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
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
        loop {
            interval.tick().await;
            let maintenance_bridge = Arc::clone(&bridge);
            let result =
                tokio::task::spawn_blocking(move || maintenance_bridge.maintenance(ab_core::time::now_ms()))
                    .await;
            match result {
                Ok(Ok(actions)) => metrics
                    .counter(
                        "ab_bridge_maintenance_actions_total",
                        "Bridge retention expirations and cold-export retries",
                    )
                    .add(actions),
                Ok(Err(error)) => tracing::warn!(%error, "Bridge maintenance failed"),
                Err(error) => tracing::warn!(%error, "Bridge maintenance task failed"),
            }
        }
    })
}

async fn build_identity(config: &HarnessConfig) -> Result<Option<Arc<IdentityValidator>>> {
    let has_jwks = config
        .identity_jwks_url
        .as_deref()
        .is_some_and(|url| !url.is_empty());
    let has_hmac = config
        .identity_hmac_secret_file
        .as_deref()
        .is_some_and(|path| !path.is_empty());
    if !has_jwks && !has_hmac {
        return Ok(None);
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
        validator.add_key(&config.identity_hmac_kid, KeyMaterial::HmacSecret(secret));
    }

    let validator = Arc::new(validator);
    if let Some(url) = config.identity_jwks_url.as_deref() {
        // Disable redirects: an IdP that returns 302 to an internal URL would
        // let a compromised (or misconfigured) JWKS host pivot the harness
        // into an SSRF probe against private services.
        let client = reqwest::Client::builder()
            .connect_timeout(ab_harness::pipeline::HTTP_CONNECT_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .context("build JWKS client")?;
        refresh_jwks(&client, url, validator.as_ref()).await?;
        let url = url.to_owned();
        let validator = Arc::clone(&validator);
        let refresh_s = config.identity_jwks_refresh_s;
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(refresh_s));
            interval.tick().await;
            loop {
                interval.tick().await;
                if let Err(error) = refresh_jwks(&client, &url, validator.as_ref()).await {
                    tracing::warn!(%error, "JWKS refresh failed; retaining previously loaded keys");
                }
            }
        });
    }
    if validator.key_count() == 0 {
        anyhow::bail!("identity enforcement configured without any verification keys");
    }
    Ok(Some(validator))
}

async fn refresh_jwks(client: &reqwest::Client, url: &str, validator: &IdentityValidator) -> Result<usize> {
    let response = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("fetch JWKS {url}"))?
        .error_for_status()
        .with_context(|| format!("JWKS endpoint {url} returned an error"))?;
    let document: serde_json::Value = response.json().await.context("parse JWKS JSON")?;
    validator.add_jwks(&document).map_err(anyhow::Error::new)
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
    if install_seed_exclusive(path, &hex::encode(signer.seed()))? {
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
    let encoded =
        std::fs::read_to_string(path).with_context(|| format!("read signing seed {}", path.display()))?;
    let bytes = hex::decode(encoded.trim()).context("decode signing seed as hex")?;
    let seed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("signing seed must contain exactly 32 bytes"))?;
    Ok(Ed25519Signer::from_seed(seed))
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
            std::fs::remove_file(&temporary)
                .with_context(|| format!("remove signing seed temporary file {}", temporary.display()))?;
            ab_core::fsutil::sync_directory(parent)
                .with_context(|| format!("sync signing seed directory {}", parent.display()))?;
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let _ = std::fs::remove_file(&temporary);
            Ok(false)
        }
        Err(error) => {
            let _ = std::fs::remove_file(&temporary);
            Err(error).with_context(|| format!("install signing seed {}", path.display()))
        }
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(signal) => signal,
            Err(error) => {
                tracing::error!(%error, "failed to install SIGTERM handler");
                let _ = tokio::signal::ctrl_c().await;
                return;
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
        let validator = build_identity(&config).await.unwrap().unwrap();
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
        assert!(build_identity(&config).await.is_err());
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
        let result = build_identity(&config).await;
        let err = result.err().map(|error| error.to_string()).unwrap_or_default();
        assert!(
            err.contains("symbolic link"),
            "expected symlink rejection, got: {err}",
        );
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
