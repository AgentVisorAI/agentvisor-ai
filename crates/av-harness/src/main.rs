//! AgentVisor AI server executable.

use anyhow::{Context, Result};
use av_bridge::{BridgeManifest, EmbeddedBroker, EventBus};
use av_harness::config::{BridgeBackend, EmbedderBackend, StateBackend, VectorBackend};
use av_harness::reconciler::spawn_reconciler;
use av_harness::{build_router, AppState, HarnessConfig};
use av_identity::{IdentityValidator, KeyMaterial};
use av_loopdetect::{Embedder, HashEmbedder, NoopVectorSink, VectorSink};
use av_receipts::{Ed25519Signer, Signer};
use av_sandbox::{PolicyEngine, Sandbox, SandboxConfig, WasmPolicy};
use av_state::{InMemoryStore, StateStore};
use axum::serve::ListenerExt as _;
use futures::future::FutureExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing_subscriber::prelude::*;

#[tokio::main]
async fn main() {
    // Fail-closed CLI contract: agentvisord historically ignored ALL
    // arguments, so `agentvisord --config /etc/prod.toml` silently booted
    // from the env/search-path config instead (possibly permissive
    // defaults), and `--help` started a server. For a security proxy,
    // unrecognized arguments must refuse to start. CLI/usage output is
    // deliberately plain text: it is for the human at the terminal and
    // happens before the structured logger exists.
    let config_override = match parse_cli_args(std::env::args().skip(1)) {
        Ok(CliAction::Run(config_override)) => config_override,
        Ok(CliAction::Help) => {
            println!("{USAGE}");
            return;
        }
        Ok(CliAction::Version) => {
            println!("agentvisord {}", env!("CARGO_PKG_VERSION"));
            return;
        }
        Err(error) => {
            eprintln!("{error}\n\n{USAGE}");
            std::process::exit(2);
        }
    };

    if let Err(error) = run(config_override).await {
        // The daemon logs structured JSON, but a fatal
        // startup/shutdown error used to return through anyhow and
        // print as a bare `Error:` line plus a backtrace — unparseable
        // to the log pipeline at exactly the moment it matters most.
        // Route the fatal reason through the structured logger when it
        // is up; fall back to stderr only when tracing itself never
        // initialized (the one failure that cannot be self-reported).
        if tracing::dispatcher::has_been_set() {
            tracing::error!(error = format!("{error:#}"), "agentvisord exiting on fatal error");
        } else {
            eprintln!("agentvisord exiting on fatal error: {error:#}");
        }
        std::process::exit(1);
    }
}

async fn run(config_override: Option<PathBuf>) -> Result<()> {
    #[cfg(feature = "otel")]
    let telemetry_provider = init_tracing()?;
    #[cfg(not(feature = "otel"))]
    init_tracing()?;

    let (config, config_source) =
        av_harness::config::load_config_with_override(config_override).map_err(anyhow::Error::msg)?;
    // Refuse the whole configuration up front, with the
    // complete list, when it selects backends this binary was compiled
    // without. The individual build_* sites keep their own bails as
    // defense in depth, but they fail one at a time and only when
    // reached — an operator fixing kafka would then discover onnx.
    let unsupported = config.unsupported_backend_requirements();
    if !unsupported.is_empty() {
        anyhow::bail!(
            "this build cannot run the resolved configuration: {}",
            unsupported.join("; ")
        );
    }
    let manifest = load_manifest(&config)?;
    let bridge = build_bridge(&config, &manifest)?;

    let sandbox = load_sandbox(&config)?;
    let store = build_store(&config)?;
    let embedder = build_embedder(&config)?;
    let vector_sink = build_vector_sink(&config, embedder.dim()).await?;
    // Build the metrics registry BEFORE `build_identity` so the JWKS
    // refresh loop can bump `av_jwks_refresh_errors_total` on the same
    // registry that `AppState` will hand to `/metrics`. Otherwise the
    // JWKS counters would live on a phantom registry no scraper sees,
    // and a silently-stale key set would
    // remain unalertable.
    let metrics = Arc::new(av_core::metrics::Registry::new());
    let (identity, jwks_refresh) = build_identity(&config, Arc::clone(&metrics)).await?;
    let signer_path = std::env::var_os("AV_SIGNING_SEED_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("config/signing.seed"));
    let (raw_signer, signer_newly_generated) = load_or_create_signer(&signer_path)?;
    // Capture the identifying material BEFORE moving into an `Arc<dyn Signer>`
    // so the startup banner can name the exact trust anchor the process
    // will sign under. Omitting this line is how a silent-new-anchor failure
    // (missing/emptied seed file → freshly generated seed → every receipt
    // signed by an untrusted key) can go undetected: without the id in the
    // log, only an external verifier days later notices, at which point the
    // audit chain for that window is unrecoverable.
    let signer_key_id = raw_signer.key_id().to_owned();
    let signer_public_key_hex = hex::encode(raw_signer.public_key_bytes());
    // Log the trust anchor UNCONDITIONALLY. The startup banner below is
    // info-level on the default target, so `RUST_LOG=warn` (the common
    // production setting — and what our own compose/K8s guidance quiets
    // logs with) silently drops the only steady-state record of which
    // key this process signs under. The `trust_anchor` target is pinned
    // to `info` inside init_tracing regardless of RUST_LOG, so this
    // line survives `warn`, `error`, and even `off`.
    tracing::info!(
        target: "trust_anchor",
        signer_key_id = %signer_key_id,
        signer_public_key_hex = %signer_public_key_hex,
        signer_seed_path = %signer_path.display(),
        freshly_generated = signer_newly_generated,
        "receipt-signing trust anchor for this process"
    );
    if signer_newly_generated {
        // A fresh anchor is only correct at genuine first boot. Every other
        // occurrence (Secret failed to mount, emptyDir vanished, seed file
        // deleted) is a compliance incident: audit consumers that trusted
        // the previous key will reject every receipt issued from here on.
        // Emit at WARN so the log pipeline surfaces it without needing a
        // Prometheus gauge (the metrics registry has no gauge type for
        // this yet). Uses the always-on `trust_anchor` target so even a
        // `RUST_LOG=error` deployment records the compliance incident.
        tracing::warn!(
            target: "trust_anchor",
            signer_key_id = %signer_key_id,
            signer_public_key_hex = %signer_public_key_hex,
            signer_seed_path = %signer_path.display(),
            "signing seed was freshly generated at startup — an operator that had trusted a previous key must re-pin this one before any receipt from this instance verifies"
        );
    }
    let signer: Arc<dyn Signer> = Arc::new(raw_signer);
    bridge
        .set_control_key(av_harness::control_key_from_signer(signer.as_ref()))
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
    // Two daemons on one spool silently split the audit
    // trail (interleaved journals, racing reconcilers, torn ATIF
    // artifacts). The README documents single-instance; nothing
    // enforced it. Hold an exclusive advisory lock on a well-known
    // spool file for the whole process lifetime — the OS releases it
    // on ANY exit including SIGKILL, so there is no stale-lock
    // recovery to get wrong. Everything below (orphaned-temp sweep,
    // spool recovery, the reconciler) assumes it is the only writer.
    let _spool_lock = acquire_spool_lock(std::path::Path::new(&config.atif_spool_dir))?;
    // Boot-time only (no concurrent writer exists yet): sweep temp
    // files orphaned by a SIGKILL between `create_new` and `rename` —
    // the RAII unlink cannot run across a crash, so crash loops
    // accumulate them linearly forever otherwise.
    match av_core::fsutil::sweep_orphaned_tmp(std::path::Path::new(&config.atif_spool_dir)) {
        Ok(0) => {}
        Ok(removed) => tracing::info!(removed, "removed crash-orphaned temp files from the spool"),
        Err(error) => tracing::warn!(%error, "orphaned-temp sweep failed; stale .tmp files may remain"),
    }
    // Fail-closed boot probe: an unwritable or full spool volume used
    // to boot silently — /health answered 200 while every chat 503'd
    // and nothing was capturable. Refuse to start instead: the spool
    // is the audit store; a server that cannot record must not serve.
    {
        let probe = std::path::Path::new(&config.atif_spool_dir)
            .join(format!(".writability-probe-{}.tmp", av_core::new_event_uid()));
        av_core::fsutil::write_atomic(&probe, b"probe")
            .and_then(|()| std::fs::remove_file(&probe))
            .with_context(|| {
                format!(
                    "spool directory {:?} is not writable; refusing to serve without a working audit store",
                    config.atif_spool_dir
                )
            })?;
    }
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
    // Retention: prune sealed ATIF trajectories + sidecars older than
    // `atif_retention_days` on an hourly cadence. Only sealed pairs are
    // touched; unpaired remnants stay for the reconciler quarantine
    // sweep. `None` (the ship default) preserves the historical
    // "manage-with-external-cron" behaviour.
    //
    // The tick body dispatches to `spawn_blocking` inside
    // `prune_sealed_atif`, and `JoinHandle::abort()` cancels only the
    // outer async task — a blocking `remove_file` sequence in flight
    // would keep running against the spool concurrently with process
    // exit and could leave orphan `.close-complete` markers on
    // abandonment. Mirror the bridge-maintenance discipline with a
    // dedicated Notify so shutdown returns the loop between ticks and
    // the outer `.await` below actually waits for the blocking work
    // to finish. Same rationale as `bridge_maintenance_shutdown`.
    let retention_shutdown = Arc::new(tokio::sync::Notify::new());
    let retention = config.atif_retention_days.map(|days| {
        let finalizer = state.finalizer.clone();
        let metrics = Arc::clone(&state.metrics);
        let shutdown = Arc::clone(&retention_shutdown);
        let pruned_total = metrics.counter(
            "av_atif_retention_pruned_total",
            "Sealed ATIF+sidecar pairs deleted by the retention sweep",
        );
        tokio::spawn(async move {
            let interval = std::time::Duration::from_secs(60 * 60);
            let max_age = std::time::Duration::from_secs(u64::from(days) * 24 * 60 * 60);
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                // Race the shutdown notify against the ticker so the
                // loop can exit between ticks and never launch a fresh
                // `spawn_blocking` if shutdown fired during the tick's
                // own await. Mirrors `spawn_bridge_maintenance`.
                tokio::select! {
                    biased;
                    () = shutdown.notified() => return,
                    _ = ticker.tick() => {}
                }
                // Supervise the tick body: a panic here (allocator OOM,
                // a Display panic on a non-UTF8 error chain, a
                // parking_lot poison-on-unwind) would otherwise silently
                // terminate the retention sweep under Tokio's default
                // UnhandledPanic::Ignore. The 1 h cadence means one
                // panic invisibly loses one hour of retention — a
                // persistent panic condition drops retention entirely
                // until the daemon restarts, and the spool grows
                // unbounded until it fills the disk. Mirrors the
                // bridge-maintenance and JWKS-refresh discipline.
                let pruned_total = pruned_total.clone();
                let metrics_tick = Arc::clone(&metrics);
                let finalizer_tick = finalizer.clone();
                let outcome = std::panic::AssertUnwindSafe(async move {
                    match finalizer_tick.prune_sealed_atif(max_age).await {
                        Ok(0) => {}
                        Ok(n) => {
                            pruned_total.add(n as u64);
                            tracing::info!(
                                pruned = n,
                                retention_days = days,
                                "ATIF retention sweep removed sealed evidence pairs"
                            );
                        }
                        Err(error) => {
                            metrics_tick
                                .counter(
                                    "av_atif_retention_errors_total",
                                    "ATIF retention sweep tick returned an error",
                                )
                                .inc();
                            tracing::warn!(
                                %error,
                                retention_days = days,
                                "ATIF retention sweep failed; will retry next hour"
                            );
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
                            "av_atif_retention_panics_total",
                            "ATIF retention sweep tick panicked; loop supervised via catch_unwind",
                        )
                        .inc();
                    tracing::error!(
                        panic = %msg,
                        "ATIF retention sweep tick panicked; continuing"
                    );
                }
            }
        })
    });
    let tcp_nodelay_failures = state.metrics.counter(
        "av_tcp_nodelay_failures_total",
        "TCP_NODELAY setsockopt failed on an accepted connection; the \
         suboptimal-latency connection still serves. Rate-limited to a \
         single tracing warn per process to avoid a per-accept log storm \
         under half-open flood / SYN flood.",
    );
    let listener = tokio::net::TcpListener::bind(&config.listen)
        .await
        .with_context(|| format!("bind {}", config.listen))?
        // Set TCP_NODELAY on every accepted socket. Nagle + delayed-
        // ACK together produce ~40 ms of avoidable per-frame stall
        // in the SSE relay: each streamed frame is 50-200 bytes
        // (one token or a small delta), so the second small frame
        // sits in the sender's kernel queue until the first is
        // ACK'd. Compounded across a 500-token stream that's tens
        // of seconds of inter-token latency the operator would
        // otherwise trace to "OpenAI feels slower behind the
        // proxy". The outbound-side reqwest client already sets
        // `.tcp_keepalive(30 s)` on the upstream direction
        // (`pipeline.rs`); this closes the reverse-facing hole.
        //
        // `tap_io` is axum 0.8's idiomatic hook for per-connection
        // socket-option tuning without swapping listener types.
        // Failure to set the option (embedded system without full
        // socket-option support, half-open flood socket teardown
        // between accept and setsockopt, ECONNRESET race) logs and
        // falls through — a suboptimal-latency connection is still
        // a working one.
        //
        // Wrap the warn in a `std::sync::Once`: a SYN-flood or
        // Slowloris-class probe against an unauthenticated endpoint
        // could otherwise fire this warn at accept-rate (~20 k/s on
        // a moderately-sized Linux node), saturating the log
        // pipeline and amplifying the very DoS the SSE latency
        // regression is a distant second to. Every occurrence is
        // still counted via `av_tcp_nodelay_failures_total` so
        // operators keep visibility of persistent failures without
        // the log storm. Same dampener discipline as R33's
        // identity_rejection_window sliding cap.
        .tap_io(move |tcp_stream| {
            if let Err(error) = tcp_stream.set_nodelay(true) {
                static WARNED: std::sync::Once = std::sync::Once::new();
                WARNED.call_once(|| {
                    tracing::warn!(
                        %error,
                        "failed to set TCP_NODELAY on incoming connection; SSE inter-token \
                         latency may regress by ~40 ms per frame. Subsequent failures logged \
                         only via av_tcp_nodelay_failures_total to avoid a per-accept log storm."
                    );
                });
                tcp_nodelay_failures.inc();
            }
        });
    if let Some(segment) = config.duplicated_chat_path_segment() {
        tracing::warn!(
            upstream_url = %av_core::url_redact::redact_userinfo(&config.upstream_url),
            upstream_chat_path = %config.upstream_chat_path,
            "upstream_url already ends with \"/{segment}\" and upstream_chat_path repeats it; \
             the joined URL will contain \"/{segment}/{segment}/\" — most providers expect the \
             base URL without the \"/{segment}\" suffix"
        );
    }
    tracing::info!(
        listen = %config.listen,
        config = %config_source,
        upstream = %av_core::url_redact::redact_userinfo(
            &format!("{}{}", config.upstream_url.trim_end_matches('/'), config.upstream_chat_path)
        ),
        upstream_auth = %av_harness::pipeline::describe_upstream_auth(&config),
        bridge = %config.bridge_backend,
        state = %config.state_backend,
        // Budget counters on an expiring backend
        // (Redis: 24 h) silently reset for sessions active past the
        // TTL; in-memory never expires. Surface the value so an
        // operator diagnosing "my week-long agent's budget reset"
        // can see the window without reading redis_store.rs.
        state_counter_ttl_s = ?state.store.counter_ttl_secs(),
        identity = if config.require_identity { "required" } else { "optional" },
        // Always surface the exact receipt-signing trust anchor. This is the
        // simplest observable signal that a Secret mount, an emptyDir volume,
        // or a hand-managed seed file survived the boot — an operator or an
        // audit-log consumer can compare it against the previously-published
        // public key without waiting for the first receipt to fail
        // downstream.
        signer_key_id = %signer_key_id,
        signer_public_key_hex = %signer_public_key_hex,
        "AgentVisor AI started"
    );
    // Publish the signing-key fingerprint as a labelled
    // gauge whose value is always 1 (Prometheus's convention for
    // `*_info` metrics). Downstream verifiers can alert on a
    // key-id change between scrapes even when nothing signed a
    // receipt in the window — the log-only signal above misses
    // that if operators only look at metrics dashboards. The
    // gauge is per-key-id (not just the fingerprint prefix) so a
    // key rotation shows up as a distinct series rather than a
    // silent value flip.
    state
        .metrics
        .gauge(
            &format!(
                "av_signing_key_info{{key_id=\"{signer_key_id}\",public_key_hex=\"{signer_public_key_hex}\"}}"
            ),
            "Signing-key fingerprint — 1 while the current process holds this key",
        )
        .set(1);
    let (shutdown_started_tx, shutdown_started_rx) = tokio::sync::oneshot::channel();
    // Register the drain-timeout counter up front so alerts can wire
    // onto it at boot. This surfaces a real hazard: axum's
    // per-connection tasks are detached `tokio::spawn`s, so dropping
    // the `Serve` future does NOT cancel in-flight streams. If a
    // long-lived streaming client outlives the graceful drain budget,
    // the timeout fires, `state.worker.wait_idle()` also times out,
    // and any late-arriving job into `finalize_sessions` races the
    // stream's own drop-time finalizer. A non-zero counter is a
    // hard-page: it means shutdown ordering is unsafe and every
    // affected session needs receipt-verify on restart.
    let drain_timeouts = metrics.counter(
        "av_http_shutdown_drain_timeouts_total",
        "HTTP graceful-drain phase exceeded budget; per-connection tasks may still be live",
    );
    let draining_flag = Arc::clone(&state.draining);
    let ready_drain_window = std::time::Duration::from_secs(config.shutdown_ready_drain_s);
    let server = std::future::IntoFuture::into_future(
        axum::serve(listener, build_router(state.clone())).with_graceful_shutdown(async move {
            shutdown_signal().await;
            // Flip the draining flag FIRST so `/readyz` reports 503 on
            // every connection accepted from here on. NOTE: axum stops
            // accepting the moment this future completes, so without
            // the pre-drain window below a fresh readiness probe sees
            // connection-refused (also a probe failure, but an LB that
            // distinguishes "degraded" from "gone" gets no 503, and
            // in-flight LB routing has zero grace). Every deployment
            // target uses `shutdown_ready_drain_s` for this window:
            // the shipped k8s manifest sets it to 5 because the
            // distroless runtime base has no shell for a preStop
            // `sleep` hook to run in; docker-compose, systemd, and
            // bare-VM LBs have no preStop equivalent at all.
            draining_flag.store(true, std::sync::atomic::Ordering::SeqCst);
            if ready_drain_window > std::time::Duration::ZERO {
                tracing::info!(
                    window_s = ready_drain_window.as_secs(),
                    "readiness-controlled pre-drain: /readyz now 503, still accepting"
                );
                tokio::time::sleep(ready_drain_window).await;
            }
            let _ = shutdown_started_tx.send(());
        }),
    );
    tokio::pin!(server);
    let result = tokio::select! {
        result = &mut server => result.context("serve AgentVisor AI"),
        _ = shutdown_started_rx => {
            match tokio::time::timeout(config.effective_drain_timeout(), &mut server).await {
                Ok(result) => result.context("serve AgentVisor AI"),
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
    // Signal retention to stop instead of aborting.
    // JoinHandle::abort() cancels only the outer async task, but the
    // retention tick body dispatches to spawn_blocking (each tick calls
    // Finalizer::prune_sealed_atif which is a spawn_blocking wrapper).
    // An abandoned blocking closure mid-remove_file sequence could leave
    // an orphan .close-complete marker on the spool. Notify makes the
    // loop return between ticks so the shutdown `.await` below actually
    // waits for the blocking work to finish — same rationale as the
    // bridge-maintenance loop below.
    retention_shutdown.notify_one();
    // Signal maintenance to stop instead of aborting.
    // JoinHandle::abort() only cancels the outer async task; a
    // spawn_blocking closure that's already running keeps rewriting
    // Bridge segments to completion and races the process exit.
    // Notify makes the loop return between ticks so the shutdown
    // .await below actually waits for the blocking work to finish.
    bridge_maintenance_shutdown.notify_one();
    // Abort the JWKS refresh task on shutdown so the
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
    if let Some(handle) = retention {
        if let Err(error) = handle.await {
            if !error.is_cancelled() {
                tracing::warn!(%error, "ATIF retention task exited with an error before shutdown abort");
            }
        }
    }
    #[cfg(feature = "otel")]
    let flush_telemetry = move || {
        if let Some(provider) = telemetry_provider {
            provider
                .shutdown_with_timeout(std::time::Duration::from_secs(
                    av_harness::config::OTEL_FLUSH_SECS,
                ))
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
        // Bound each per-session close so a stuck session (a leaked
        // SessionLease from an axum-cancelled handler, a worker permit
        // dropped without decrementing, an upstream half-closed after
        // TCP_KEEPALIVE-less client disconnect) does not starve the
        // remaining sessions' close budget. `close_session_locked`
        // internally calls `wait_for_streams` / `wait_for_worker_jobs`
        // which are unbounded loops on internal counters.
        //
        // The per-session deadline MUST be small relative to the outer
        // `WORKER_FINALIZE_PHASE_SECS` (30 s) budget — otherwise ONE
        // stuck session eats the whole outer window and every REMAINING
        // session is still skipped, which is the pathology this fix
        // exists to close. Set it to 3 s: healthy close_session
        // completes in < 100 ms so 3 s is 30× headroom for the healthy
        // path, and up to 10 stuck sessions can fire their per-session
        // deadline before the outer timer expires — giving the 11th
        // (and later) healthy sessions a chance to close cleanly.
        //
        // Contrast with the reconciler's `IDLE_CLOSE_DEADLINE = 90 s`
        // (R26): that path is NOT wrapped by an outer timeout so a
        // large per-session bound is fine there.
        //
        // On per-session timeout, bump a pre-registered metric so
        // operators tuning the deadline (or diagnosing why shutdown
        // leaves sessions for restart-time recovery) can see the class
        // separately from `av_http_shutdown_drain_timeouts_total`
        // (which fires on OUTER drain timeout, a distinct condition).
        const PER_SESSION_CLOSE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(3);
        let session_close_timeouts = shutdown_finalizer.metrics().counter(
            "av_shutdown_session_close_timeouts_total",
            "Per-session close hit the shutdown-time per-session deadline (3 s) and \
             was deferred to restart-time spool recovery. A sustained rate > 0 on \
             every rollout indicates a class of sessions that regularly hang their \
             close (leaked leases, dropped worker permits, unresponsive bridge \
             publish) — the coincident session id in the shutdown warn log is the \
             correlation key. Distinct from `av_http_shutdown_drain_timeouts_total` \
             which fires on the OUTER phase timeout.",
        );
        for session in open_sessions {
            let session_id = session.id.clone();
            let outcome = tokio::time::timeout(
                PER_SESSION_CLOSE_DEADLINE,
                shutdown_finalizer.close_session(session, av_events::StopReason::SessionClosed),
            )
            .await;
            match outcome {
                Ok(Ok(_)) => {}
                Ok(Err(error)) => failures.push(format!("session {session_id}: {error}")),
                Err(_elapsed) => {
                    session_close_timeouts.inc();
                    failures.push(format!(
                        "session {session_id}: per-session close deadline ({}s) exceeded — deferred to restart-time recovery",
                        PER_SESSION_CLOSE_DEADLINE.as_secs()
                    ));
                }
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(anyhow::anyhow!(failures.join("; ")))
        }
    };
    // Compose the worker drain with a pre-step that first drains
    // in-flight `mcp_call_inner` detached spawns (routes.rs). Axum's
    // graceful drain only awaits outer handlers; a client-disconnected
    // mcp_call whose spawned body is mid-execution outlives the drain.
    // If we skipped straight to `wait_idle`, that body could reach
    // `worker.try_submit` AFTER `wait_idle` returned, then race
    // `finalize_sessions` and trip `av_shutdown_session_close_
    // timeouts_total` on an otherwise-recoverable session.
    //
    // The 5 s inner budget is a small fraction of
    // `WORKER_FINALIZE_PHASE_SECS = 30 s`, leaving 25 s for
    // `wait_idle` to cover any worker jobs the drained bodies just
    // submitted. On timeout the `av_shutdown_mcp_drain_timeouts_total`
    // counter fires (pre-registered in `pipeline.rs`) so an operator
    // sees the drain miss on the coincident rollout, but shutdown
    // still proceeds (the affected session's post-drain worker
    // submission will trip the per-session close deadline and be
    // recovered on next boot).
    let mcp_drain_budget = std::time::Duration::from_secs(5);
    let mcp_inflight = Arc::clone(&state.mcp_inflight);
    let mcp_metrics = Arc::clone(&state.metrics);
    let worker_handle = state.worker.clone();
    let worker_drain = async move {
        if tokio::time::timeout(mcp_drain_budget, mcp_inflight.wait_drained())
            .await
            .is_err()
        {
            mcp_metrics
                .counter(
                    "av_shutdown_mcp_drain_timeouts_total",
                    "Shutdown MCP-inflight drain hit its 5 s deadline before every detached \
                     mcp_call_inner spawn completed",
                )
                .inc();
            tracing::warn!(
                inflight = mcp_inflight.count(),
                "timed out draining in-flight MCP tool calls (5 s); shutdown proceeding"
            );
        }
        worker_handle.wait_idle().await;
    };
    finish_shutdown(
        result,
        std::time::Duration::from_secs(av_harness::config::WORKER_FINALIZE_PHASE_SECS),
        worker_drain,
        finalize_sessions,
        flush_telemetry,
    )
    .await
}

const USAGE: &str = "Usage: agentvisord [--config <path>]\n\
\n\
Options:\n\
\x20 --config <path>  Load the harness config from <path> (overrides $AV_CONFIG\n\
\x20                  and the default search paths)\n\
\x20 -h, --help       Print this help and exit\n\
\x20 -V, --version    Print the version and exit\n\
\n\
Without --config, configuration is resolved from $AV_CONFIG, the default\n\
search paths, or built-in defaults (see the README).";

enum CliAction {
    Run(Option<PathBuf>),
    Help,
    Version,
}

/// Exclusive advisory lock proving this daemon is the
/// spool's only writer (see the call site in `run`). The returned
/// handle must stay alive for the process lifetime; dropping it — or
/// any process exit, including SIGKILL — releases the lock.
fn acquire_spool_lock(spool_dir: &Path) -> Result<std::fs::File> {
    // Use `create_dir_all_synced` (not bare `create_dir_all`) so the
    // spool ROOT is materialised at 0o700 on Unix. Every subsequent
    // path (`append_journal`, `write_atomic`, `claim_sync`) short-
    // circuits its own mkdir with an `is_dir()` fast path, so this
    // is the ONLY site that ever creates the root — leaving it at
    // the ambient umask (0o755 under the default 0022) would leak
    // enumeration of the deterministic `sha256(session-id)[..32]`
    // filename stems to any co-tenant with `execute` on the parent,
    // even though the individual spool files are now 0o600.
    av_core::fsutil::create_dir_all_synced(spool_dir)
        .with_context(|| format!("create spool directory {}", spool_dir.display()))?;
    let path = spool_dir.join(".agentvisord.lock");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .with_context(|| format!("open spool lock file {}", path.display()))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(std::fs::TryLockError::WouldBlock) => anyhow::bail!(
            "another agentvisord instance already holds the spool lock at {}; \
             two daemons sharing one spool would silently split the audit trail \
             (interleaved journals, racing reconcilers, torn artifacts). Run one \
             instance per spool directory",
            path.display()
        ),
        Err(std::fs::TryLockError::Error(error)) => {
            Err(anyhow::Error::new(error).context(format!("acquire exclusive spool lock {}", path.display())))
        }
    }
}

/// Fail-closed argument parsing: anything unrecognized refuses startup
/// rather than being silently ignored (a mistyped flag must never let a
/// security proxy boot with a different config than the operator intended).
fn parse_cli_args(args: impl Iterator<Item = String>) -> Result<CliAction, String> {
    let mut config: Option<PathBuf> = None;
    let mut args = args.peekable();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => return Ok(CliAction::Help),
            "-V" | "--version" => return Ok(CliAction::Version),
            "--config" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--config requires a path argument".to_owned())?;
                if config.replace(PathBuf::from(value)).is_some() {
                    return Err("--config may only be given once".to_owned());
                }
            }
            other => {
                if let Some(value) = other.strip_prefix("--config=") {
                    if value.is_empty() {
                        return Err("--config requires a non-empty path".to_owned());
                    }
                    if config.replace(PathBuf::from(value)).is_some() {
                        return Err("--config may only be given once".to_owned());
                    }
                } else {
                    return Err(format!("unrecognized argument {other:?}"));
                }
            }
        }
    }
    Ok(CliAction::Run(config))
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

/// Always-on filter directive for the `trust_anchor` target: the
/// receipt-signing key identity must reach the logs regardless of
/// RUST_LOG (a `warn`/`error` deployment otherwise never records which
/// key it signs under — the silent-new-anchor failure mode). A
/// target-specific directive outranks any global level directive, so
/// `RUST_LOG=error` still admits `trust_anchor` events at info.
fn trust_anchor_directive() -> tracing_subscriber::filter::Directive {
    // The literal is static and known-good; the fallback (global INFO)
    // is unreachable but avoids a panic path.
    "trust_anchor=info"
        .parse()
        .unwrap_or_else(|_| tracing_subscriber::filter::LevelFilter::INFO.into())
}

#[cfg(not(feature = "otel"))]
fn init_tracing() -> Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|error| {
                    if std::env::var_os("RUST_LOG").is_some() {
                        eprintln!("warning: RUST_LOG parse failed ({error}); falling back to 'info'");
                    }
                    tracing_subscriber::EnvFilter::new("info")
                })
                .add_directive(trust_anchor_directive()),
        )
        .with(tracing_subscriber::fmt::layer().json())
        .try_init()
        .map_err(|error| anyhow::anyhow!("initialize tracing: {error}"))?;
    // Every other feature-gated
    // capability refuses loudly when configured but compiled out; the
    // OTLP env vars were the one silent no-op. An operator pointing a
    // default-features binary at a collector got no traces and no
    // diagnostic.
    if std::env::var_os("OTEL_EXPORTER_OTLP_ENDPOINT").is_some()
        || std::env::var_os("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT").is_some()
    {
        tracing::warn!(
            "OTEL_EXPORTER_OTLP_* is set but this build has no OpenTelemetry support; \
             rebuild with `--features otel` (or `full`) to export traces"
        );
    }
    Ok(())
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
                    .with_service_name("agentvisor-ai")
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
        .map(|provider| tracing_opentelemetry::layer().with_tracer(provider.tracer("agentvisor-ai")));
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|error| {
                    if std::env::var_os("RUST_LOG").is_some() {
                        eprintln!("warning: RUST_LOG parse failed ({error}); falling back to 'info'");
                    }
                    tracing_subscriber::EnvFilter::new("info")
                })
                .add_directive(trust_anchor_directive()),
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
                        // Same MAX_CONTROL_BYTES cap and rationale as the
                        // bridge's `load_validators`: bound
                        // the allocation before the JSON parser can reject.
                        &av_core::fsutil::read_capped(&path, av_core::fsutil::MAX_CONTROL_BYTES)
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
        // Bounded read (same discipline as every other boot-time file):
        // real policies are tiny (the builtin is a few KiB of WAT), so
        // 16 MiB is generous for any legitimate compiled module while
        // bounding the allocation before wasmtime can reject the bytes.
        const MAX_WASM_POLICY_BYTES: u64 = 16 * 1024 * 1024;
        let bytes = match av_core::fsutil::read_capped(std::path::Path::new(path), MAX_WASM_POLICY_BYTES) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && is_default_policy => {
                tracing::info!(path, "policy file not found; using embedded built-in copy");
                BUILTIN_POLICY_WAT.as_bytes().to_vec()
            }
            Err(error) => return Err(error).with_context(|| format!("read WASM policy {path}")),
        };
        // The default payload-limit policy
        // denies bodies above 4 MiB. If the operator raised
        // `max_request_bytes` past that, chat requests the HTTP body
        // limit admits get 403 PolicyBlocked — misattributed as a
        // policy violation and invisible from the config file. Warn
        // loudly at boot so the mismatch is discoverable.
        const DEFAULT_POLICY_LIMIT_BYTES: usize = 4 * 1024 * 1024;
        if is_default_policy && config.max_request_bytes > DEFAULT_POLICY_LIMIT_BYTES {
            tracing::warn!(
                max_request_bytes = config.max_request_bytes,
                policy_limit = DEFAULT_POLICY_LIMIT_BYTES,
                "max_request_bytes exceeds the default payload-limit policy's 4 MiB threshold; \
                 chat requests between the two sizes will be refused as policy-blocked — raise \
                 the constant in the payload_limit.wat policy (or remove it from \
                 wasm_policy_paths) to match"
            );
        }
        policies.push(Box::new(
            WasmPolicy::from_bytes(path, &bytes).map_err(anyhow::Error::msg)?,
        ));
    }
    Sandbox::new(
        SandboxConfig {
            schemas,
            budget: config.budget.clone(),
            payout_field: config.payout_field.clone(),
            require_schema: config.require_tool_schema,
        },
        policies,
    )
    .map_err(anyhow::Error::msg)
}

/// Embedded copy of the default payload-limit policy, compiled into the
/// binary so `cargo install av-harness && agentvisord` works from an
/// empty directory. Deliberately located INSIDE the crate at
/// `crates/av-harness/policies/payload_limit.wat` so `cargo publish`
/// packages it — `include_str!` cannot reach outside the crate root on
/// a crates.io consumer build. The operator-facing copy at
/// `<repo>/config/policies/payload_limit.wat` is kept as a mirror for
/// deploy-time editing (Docker/systemd/k8s load that path); both files
/// MUST be kept in sync during development (there is intentionally no
/// build-time drift check to keep the compile fast).
const BUILTIN_POLICY_WAT: &str = include_str!("../policies/payload_limit.wat");

/// Built-in Bridge manifest for zero-config startup. Hot-only retention
/// (no `cold_uri`: cold export needs the `cold-store` feature and an
/// operator-chosen destination) and single-partition topics suitable for
/// a local trial. The OCSF schema reference resolves to the copy embedded
/// in `av-bridge`, so no file is needed on disk.
const BUILTIN_MANIFEST_YAML: &str = r#"
manifest_version: 1
name: agentvisor-ai-builtin
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
    // Capped read: `avctl manifest-validate` already refuses manifests
    // above MAX_CONTROL_BYTES, and `BridgeManifest::from_yaml` enforces
    // its own 256 KiB cap — an uncapped read here only buys the daemon
    // an unbounded allocation before that parse-side cap can reject.
    let manifest = match av_core::fsutil::read_capped_string(
        std::path::Path::new(&config.bridge_manifest_path),
        av_core::fsutil::MAX_CONTROL_BYTES,
    ) {
        Ok(text) => BridgeManifest::from_yaml(&text).map_err(anyhow::Error::new)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && config.uses_default_manifest_path() => {
            tracing::info!(
                path = %config.bridge_manifest_path,
                "Bridge manifest not found; using embedded built-in manifest"
            );
            BridgeManifest::from_yaml(BUILTIN_MANIFEST_YAML).map_err(anyhow::Error::new)?
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("read Bridge manifest {}", config.bridge_manifest_path));
        }
    };
    // A topic with no cold_uri DROPS records past
    // hot_hours — the audit stream half of the system of record
    // silently self-deletes (default 720 h = 30 days) while the ATIF
    // spool half retains forever. Surface the divergence at boot so
    // an operator who relies on broker replay for compliance knows
    // the clock is ticking.
    for topic in &manifest.topics {
        if topic.retention.cold_uri.is_none() {
            tracing::warn!(
                topic = %topic.name,
                hot_hours = topic.retention.hot_hours,
                "topic has no cold_uri: records older than hot_hours are DELETED, not archived — configure retention.cold_uri for a durable audit stream"
            );
        }
    }
    Ok(manifest)
}

fn spawn_bridge_maintenance(
    bridge: Arc<dyn EventBus>,
    metrics: Arc<av_core::metrics::Registry>,
    shutdown: Arc<tokio::sync::Notify>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
        // Skip missed ticks under transient overload instead of the
        // default catch-up burst. Bridge maintenance is fine to run
        // once per hour even if the previous run took 30 minutes.
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            // Previously `bridge_maintenance.abort()`
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
                    maintenance_bridge.maintenance(av_core::time::now_ms())
                })
                .await;
                match result {
                    Ok(Ok(actions)) => metrics
                        .counter(
                            "av_bridge_maintenance_actions_total",
                            "Bridge retention expirations and cold-export retries",
                        )
                        .add(actions),
                    Ok(Err(error)) => {
                        // Previously only tracing::warn.
                        // A silent 1-hour cadence made this class of
                        // failure invisible to alerts — Bridge hot
                        // retention could grow unbounded until disk
                        // fills. Bump a counter alongside the log.
                        metrics
                            .counter(
                                "av_bridge_maintenance_errors_total",
                                "Bridge maintenance tick returned an error",
                            )
                            .inc();
                        tracing::warn!(%error, "Bridge maintenance failed");
                    }
                    Err(error) => {
                        metrics
                            .counter(
                                "av_bridge_maintenance_join_errors_total",
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
                        "av_bridge_maintenance_panics_total",
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
    metrics: Arc<av_core::metrics::Registry>,
) -> Result<(
    Option<Arc<IdentityValidator>>,
    Option<tokio::task::JoinHandle<()>>,
)> {
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
    // Empty string means "unset" — the same posture `has_hmac` above and
    // the JWKS branch below already apply. Without the filter, a config
    // carrying a valid `identity_jwks_url` plus `identity_hmac_secret_file
    // = ""` passed the `has_hmac`-or-`has_jwks` gate and then died here
    // trying to stat "".
    if let Some(path) = config
        .identity_hmac_secret_file
        .as_deref()
        .filter(|path| !path.is_empty())
    {
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
    // Empty string means "unset" — same posture as `has_jwks` above.
    // Without the filter, `identity_jwks_url = ""` built a client and
    // fetched "" at boot, killing startup despite the HMAC path being
    // fully configured.
    if let Some(url) = config.identity_jwks_url.as_deref().filter(|url| !url.is_empty()) {
        // Disable redirects: an IdP that returns 302 to an internal URL would
        // let a compromised (or misconfigured) JWKS host pivot the harness
        // into an SSRF probe against private services.
        //
        // Total-request timeout of 10 s guards against slowloris IdPs
        // that accept the TCP handshake but never send response bytes
        // (or send them one byte per minute). Without it, a single
        // stuck fetch pins the refresh loop's `tick()` forever and
        // subsequent scheduled refreshes never fire.
        // Result: revoked keys stay honored until the next process
        // restart, with no scheduled recovery.
        let client = reqwest::Client::builder()
            .connect_timeout(av_harness::pipeline::HTTP_CONNECT_TIMEOUT)
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
            "av_jwks_refresh_errors_total",
            "JWKS refresh HTTP/parse/network failures (per attempt)",
        );
        let refresh_panics = metrics.counter(
            "av_jwks_refresh_panics_total",
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
                            // Do NOT `%error` here. The
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
    // Every error return must be URL-free.
    // An earlier fix removed the URL from `.with_context()` prepends,
    // but `.context("fetch JWKS")` still wraps a `reqwest::Error`
    // whose Display embeds the URL (`error sending request for url
    // (...)`) — anyhow's Display walks the whole chain and prints
    // the inner reqwest error verbatim. Convert the reqwest error
    // to a URL-free anyhow::Error using `reqwest::Error::without_url`
    // before the context wrap so no downstream `%error` on the boot
    // path or future logger can leak the IdP hostname. Keep the
    // stripped reqwest error as the anyhow *source* (not a
    // stringified message) so `classify_jwks_error`'s downcast can
    // still label timeout/connect/body/status failures.
    const MAX_JWKS_BYTES: usize = 4 * 1024 * 1024;
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|error| anyhow::Error::new(error.without_url()).context("fetch JWKS"))?
        .error_for_status()
        .map_err(|error| {
            let status = error
                .status()
                .map(|s| s.as_u16().to_string())
                .unwrap_or_else(|| "unknown".into());
            anyhow::Error::new(error.without_url()).context(format!("JWKS endpoint returned status {status}"))
        })?;
    // Fast reject: if Content-Length is present and already exceeds the
    // cap, refuse without allocating anything for the body.
    if let Some(len) = response.content_length() {
        if len > MAX_JWKS_BYTES as u64 {
            anyhow::bail!("JWKS declared Content-Length {len} bytes; cap is {MAX_JWKS_BYTES}");
        }
    }
    use futures::StreamExt as _;
    let mut stream = response.bytes_stream();
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk =
            chunk.map_err(|error| anyhow::Error::new(error.without_url()).context("read JWKS chunk"))?;
        let next = body
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| anyhow::anyhow!("JWKS body size overflowed usize"))?;
        if next > MAX_JWKS_BYTES {
            anyhow::bail!("JWKS exceeded {MAX_JWKS_BYTES} bytes (received at least {next})");
        }
        body.extend_from_slice(&chunk);
    }
    let document: serde_json::Value = serde_json::from_slice(&body).context("parse JWKS JSON")?;
    validator.add_jwks(&document).map_err(anyhow::Error::new)
}

/// Stable string classifier for JWKS refresh failures
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
    // `config.bridge()` is the same single parse site `validate()`
    // delegates to, so the factory can never disagree with pre-flight:
    // an unknown selector or a missing companion was already refused
    // at load, and the Kafka/Nats variants carry their endpoint by
    // construction.
    match config.bridge().map_err(anyhow::Error::msg)? {
        BridgeBackend::Embedded => {
            // An endpoint without the
            // backend that consumes it is a silent misconfiguration —
            // e.g. `docker run -e AV_BRIDGE_ENDPOINT=…` against the
            // shipped embedded-backend config does nothing. Warn so
            // 12-factor operators see why their override is inert.
            if config.bridge_endpoint.is_some() {
                tracing::warn!(
                    "bridge_endpoint (or AV_BRIDGE_ENDPOINT) is set but bridge_backend=\"embedded\" \
                     ignores it; set bridge_backend=\"kafka\" or \"nats\" to use the endpoint"
                );
            }
            let path = PathBuf::from(&config.bridge_data_dir);
            // Boot-time only, and only in the DAEMON (the single
            // writer): sweep temps orphaned by a crash between
            // `create_new` and `rename`. This must NOT live inside
            // `EmbeddedBroker::open` — `open()` itself is also
            // daemon-only now (`avctl event-tail` reads via the
            // mutation-free `fetch_read_only`), but keeping the sweep
            // here preserves the boot-once discipline.
            match av_core::fsutil::sweep_orphaned_tmp(&path) {
                Ok(0) => {}
                Ok(removed) => {
                    tracing::info!(
                        removed,
                        "removed crash-orphaned temp files from the bridge data dir"
                    );
                }
                Err(error) => {
                    tracing::warn!(%error, "bridge orphaned-temp sweep failed; stale .tmp files may remain");
                }
            }
            let bridge = if path.join("manifest.yaml").exists() {
                EmbeddedBroker::open(&path)
            } else {
                EmbeddedBroker::provision(&path, manifest)
            }
            .context("initialize embedded Bridge")?;
            Ok(Arc::new(bridge))
        }
        BridgeBackend::Kafka { endpoint } => {
            #[cfg(feature = "kafka")]
            {
                let bus = tokio::task::block_in_place(|| {
                    av_bridge::kafka_bus::KafkaBus::provision(&endpoint, manifest)
                })
                .context("initialize Kafka/Redpanda Bridge")?;
                Ok(Arc::new(bus))
            }
            #[cfg(not(feature = "kafka"))]
            {
                let _ = endpoint;
                anyhow::bail!(
                    "kafka backend requested but this agentvisord binary was built without the `kafka` feature (rebuild av-harness with --features kafka or full)"
                )
            }
        }
        BridgeBackend::Nats { endpoint } => {
            #[cfg(feature = "nats")]
            {
                let bus = tokio::task::block_in_place(|| {
                    av_bridge::nats_bus::NatsBus::provision(&endpoint, manifest)
                })
                .context("initialize NATS JetStream Bridge")?;
                Ok(Arc::new(bus))
            }
            #[cfg(not(feature = "nats"))]
            {
                let _ = endpoint;
                anyhow::bail!(
                    "nats backend requested but this agentvisord binary was built without the `nats` feature (rebuild av-harness with --features nats or full)"
                )
            }
        }
    }
}

fn build_store(config: &HarnessConfig) -> Result<Arc<dyn StateStore>> {
    match config.state().map_err(anyhow::Error::msg)? {
        StateBackend::Memory => {
            // Warn on an inert endpoint —
            // budget/velocity counters stay process-local (neither
            // shared nor durable), exactly what setting a Redis
            // endpoint was meant to fix.
            if config.state_endpoint.is_some() {
                tracing::warn!(
                    "state_endpoint (or AV_STATE_ENDPOINT) is set but state_backend=\"memory\" \
                     ignores it; set state_backend=\"redis\" to use the endpoint"
                );
            }
            Ok(Arc::new(InMemoryStore::new()))
        }
        StateBackend::Redis { endpoint } => {
            #[cfg(feature = "redis")]
            {
                let store =
                    av_state::redis_store::RedisStore::connect(&endpoint).map_err(anyhow::Error::new)?;
                Ok(Arc::new(store))
            }
            #[cfg(not(feature = "redis"))]
            {
                let _ = endpoint;
                anyhow::bail!(
                    "redis backend requested but this agentvisord binary was built without the `redis` feature (rebuild av-harness with --features redis or full)"
                )
            }
        }
    }
}

fn build_embedder(config: &HarnessConfig) -> Result<Arc<dyn Embedder>> {
    match config.embedder().map_err(anyhow::Error::msg)? {
        EmbedderBackend::Hash => Ok(Arc::new(HashEmbedder::default())),
        EmbedderBackend::Onnx {
            model_path,
            tokenizer_path,
        } => {
            #[cfg(feature = "onnx")]
            {
                let embedder = av_loopdetect::OnnxEmbedder::load(
                    Path::new(&model_path),
                    Path::new(&tokenizer_path),
                    config.onnx_dimension,
                )
                .map_err(|error| anyhow::anyhow!("load ONNX model: {error}"))?;
                Ok(Arc::new(embedder))
            }
            #[cfg(not(feature = "onnx"))]
            {
                let _ = (model_path, tokenizer_path);
                anyhow::bail!(
                    "onnx backend requested but this agentvisord binary was built without the `onnx` feature (rebuild av-harness with --features onnx or full)"
                )
            }
        }
    }
}

async fn build_vector_sink(config: &HarnessConfig, _dimension: usize) -> Result<Arc<dyn VectorSink>> {
    match config.vector().map_err(anyhow::Error::msg)? {
        VectorBackend::Memory => {
            // Warn on an inert Qdrant URL.
            if config.qdrant_url.is_some() {
                tracing::warn!(
                    "qdrant_url (or AV_QDRANT_URL) is set but vector_backend=\"memory\" ignores \
                     it; set vector_backend=\"qdrant\" to use the endpoint"
                );
            }
            Ok(Arc::new(NoopVectorSink))
        }
        VectorBackend::Qdrant { url } => {
            #[cfg(feature = "qdrant")]
            {
                let sink = av_loopdetect::QdrantVectorSink::new(&url, &config.qdrant_collection)
                    .map_err(|error| anyhow::anyhow!("configure Qdrant client: {error}"))?;
                sink.ensure_collection(_dimension)
                    .await
                    .map_err(|error| anyhow::anyhow!("provision Qdrant collection: {error}"))?;
                Ok(Arc::new(sink))
            }
            #[cfg(not(feature = "qdrant"))]
            {
                let _ = url;
                anyhow::bail!(
                    "qdrant backend requested but this agentvisord binary was built without the `qdrant` feature (rebuild av-harness with --features qdrant or full)"
                )
            }
        }
    }
}

fn load_or_create_signer(path: &Path) -> Result<(Ed25519Signer, bool)> {
    match read_signer(path) {
        Ok(signer) => return Ok((signer, false)),
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) => {}
        Err(error) => return Err(error),
    }
    let signer = Ed25519Signer::generate();
    // `signer.seed()` returns
    // `Zeroizing<[u8; 32]>` directly, so no temp slot lingers on
    // the caller's stack. The hex encoding is separately wrapped
    // in Zeroizing so its heap buffer is zeroed on drop too.
    let seed = signer.seed();
    // `&*seed` (not `*seed`) is required to avoid
    // copying the seed bytes onto a fresh un-zeroized temp slot
    // for hex::encode. clippy's `needless_borrows_for_generic_args`
    // lint is a false positive here — it would suggest `*seed`,
    // moving 32 bytes out of the Zeroizing wrapper.
    #[allow(clippy::needless_borrows_for_generic_args)]
    let encoded_seed = zeroize::Zeroizing::new(hex::encode(&*seed));
    if install_seed_exclusive(path, &encoded_seed)? {
        Ok((signer, true))
    } else {
        // A concurrent process installed a seed while we generated ours;
        // pick up its key — but this is NOT a fresh-anchor event from our
        // point of view, so mark newly_generated = false.
        let existing = read_signer(path).context("load signing seed installed by another process")?;
        Ok((existing, false))
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
        // Bottom 9 bits are rwxrwxrwx; any group/other bit set (not
        // just read — mode must be exactly owner-only) is refused.
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
    // Consistent posture with the CLI's
    // read_capped_str — the harness should not use uncapped
    // read_to_string on a security-sensitive file just because
    // require_owner_only_mode already refused the group/other-
    // readable case. A hex-encoded 32-byte seed is 65 bytes with
    // newline; MAX_CONTROL_BYTES (1 MiB) is a generous ceiling.
    // Wrap the seed intermediates in `Zeroizing<...>`
    // so their memory is zeroed on drop rather than leaking a
    // recoverable copy in freed heap / stack slots (visible to a
    // core dump, minidump upload, or kdump crashkernel image).
    // ed25519-dalek 2.2+ with the `zeroize` feature also zeroes
    // SigningKey's internal buffer on drop.
    use zeroize::Zeroizing;
    let encoded = Zeroizing::new(
        av_core::fsutil::read_capped_string(path, av_core::fsutil::MAX_CONTROL_BYTES)
            .with_context(|| format!("read signing seed {}", path.display()))?,
    );
    let bytes = Zeroizing::new(hex::decode(encoded.trim()).context("decode signing seed as hex")?);
    // Copy directly from the Zeroizing<Vec<u8>> slice
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
    // Refuse known-weak Ed25519 seeds. An all-zero seed
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
    // A bare `create_dir_all` fsyncs no dirent. If `parent` was newly
    // created (first-boot install), the ancestor dirents stay
    // volatile: the later `sync_directory(parent)` fsyncs the
    // CONTENTS of `parent`, not the `parent` dirent inside the
    // grandparent. A power loss immediately after install could drop
    // the whole `keys/` directory even though the seed file itself
    // was fsynced — the next boot would generate a fresh key with a
    // different public identity and every already-issued receipt
    // would fail signature verification. Route the mkdir through
    // `create_dir_all_synced` (which fsyncs every newly-created
    // ancestor and sets mode 0o700 atomically at mkdir on Unix,
    // closing the shared-tenant enumeration window until the
    // seed-file mode gets applied) — same posture as
    // `av_core::fsutil::write_atomic`.
    av_core::fsutil::create_dir_all_synced(parent)
        .with_context(|| format!("create signing seed directory {}", parent.display()))?;
    let temporary = parent.join(format!(".signing-seed-{}.tmp", av_core::new_event_uid()));
    // Previously an early `?` return from write_all or
    // sync_all would orphan the temp file. The two `Err(...)` match
    // arms of `hard_link` explicitly removed it, but the earlier
    // failure paths did not. Use the same TempPathGuard RAII
    // that `write_atomic` uses so every failure path
    // unlinks — this is a startup-only code path, but leaving an
    // orphan means every subsequent boot leaves another zero-byte
    // `.signing-seed-*.tmp` alongside the real seed, and a nervous
    // operator debugging a "signing seed exists twice" symptom is
    // easily led astray.
    let mut guard = av_core::fsutil::TempPathGuard::new(temporary.clone());
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
            // The seed IS installed at `path` at this
            // point (hard_link committed). Degrade the remaining
            // best-effort ops (tmp unlink, parent fsync) to warn
            // rather than returning Err — otherwise a spurious EIO on
            // sync_directory made the harness fail startup even
            // though the seed was correctly installed, wasting one
            // boot cycle to a misleading error. On next boot,
            // hard_link → AlreadyExists → Ok(false) and the caller
            // reads back the seed — self-corrects, but the noisy
            // failure is now avoided at source.
            match std::fs::remove_file(&temporary) {
                // Only a successful unlink may disarm the guard — an
                // unconditional disarm made "guard drop will retry" a
                // lie and orphaned a mode-0600 copy of the seed.
                Ok(()) => guard.disarm(),
                Err(error) => {
                    tracing::warn!(
                        path = %av_core::fsutil::basename(&temporary),
                        %error,
                        "signing seed installed, but removing tmp file failed; guard drop will retry"
                    );
                }
            }
            if let Err(error) = av_core::fsutil::sync_directory(parent) {
                tracing::warn!(
                    dir = %av_core::fsutil::basename(parent),
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
        Err(error) => Err(error).with_context(|| format!("install signing seed {}", path.display())),
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
        // Install SIGHUP as an explicitly-ignored signal. The default
        // action for SIGHUP on Unix is `Term` — the process gets
        // killed immediately, no finalize_sessions, no worker drain,
        // no receipt persistence. Real-world triggers that would
        // otherwise crash-terminate the daemon: `systemctl reload
        // agentvisord` (systemd's default `ExecReload` sends SIGHUP),
        // a lost controlling terminal in an interactive `docker exec`
        // session, or an operator's `pkill -HUP` muscle memory from
        // other daemons that reload on SIGHUP. The daemon does NOT
        // support config-reload on SIGHUP (see OPERATIONS.md); this
        // handler drains the signal into a no-op so that stance is
        // enforced by construction. Installation failure is
        // non-fatal (unlike SIGTERM) — the worst case is a returned
        // to pre-fix behavior on this ONE signal, and we log a warn.
        if let Ok(mut hup) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
            tokio::spawn(async move {
                while hup.recv().await.is_some() {
                    tracing::info!(
                        "SIGHUP received; ignored (this daemon does not reload config on SIGHUP — see OPERATIONS.md 'Shutdown' section)"
                    );
                }
            });
        } else {
            tracing::warn!(
                "failed to install SIGHUP handler; SIGHUP will kill the daemon per Unix default action \
                 (Term). Investigate seccomp / signal syscall restrictions if this appears."
            );
        }
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                if let Err(error) = result {
                    tracing::error!(%error, "failed to listen for Ctrl-C");
                }
            }
            _ = terminate.recv() => {}
        }
        // force-exit on a second signal. Once the first
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
            let mut terminate =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
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
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    /// The crate-local embedded default policy must stay byte-identical
    /// to the workspace-level copy operators deploy from `config/`
    /// (same discipline as av-bridge's vendored-OCSF-schema drift
    /// test). Reads the workspace copy at runtime so packaged-crate
    /// builds skip cleanly when it is absent.
    #[test]
    fn builtin_policy_matches_workspace_copy() {
        let workspace =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/policies/payload_limit.wat");
        let Ok(canonical) = std::fs::read_to_string(&workspace) else {
            return;
        };
        assert_eq!(
            BUILTIN_POLICY_WAT, canonical,
            "crates/av-harness/policies/payload_limit.wat has drifted from \
             config/policies/payload_limit.wat — copy the canonical file over"
        );
    }

    /// Fail-closed CLI contract: agentvisord used to ignore ALL arguments,
    /// so `agentvisord --config /etc/prod.toml` silently booted from the
    /// env/search-path config instead, and `--help` started a server.
    #[test]
    fn cli_args_are_parsed_fail_closed() {
        let parse = |args: &[&str]| parse_cli_args(args.iter().map(ToString::to_string));
        assert!(matches!(parse(&[]), Ok(CliAction::Run(None))));
        match parse(&["--config", "/tmp/h.toml"]) {
            Ok(CliAction::Run(Some(path))) => assert_eq!(path, PathBuf::from("/tmp/h.toml")),
            other => panic!("expected Run(Some(..)), got {:?}", other.is_ok()),
        }
        match parse(&["--config=/tmp/h.toml"]) {
            Ok(CliAction::Run(Some(path))) => assert_eq!(path, PathBuf::from("/tmp/h.toml")),
            other => panic!("expected Run(Some(..)), got {:?}", other.is_ok()),
        }
        assert!(matches!(parse(&["--help"]), Ok(CliAction::Help)));
        assert!(matches!(parse(&["-h"]), Ok(CliAction::Help)));
        assert!(matches!(parse(&["--version"]), Ok(CliAction::Version)));
        assert!(matches!(parse(&["-V"]), Ok(CliAction::Version)));
        // Everything unrecognized refuses startup.
        assert!(
            parse(&["--confg", "x"]).is_err(),
            "typos must not boot the server"
        );
        assert!(parse(&["start"]).is_err());
        assert!(parse(&["--config"]).is_err(), "missing value must error");
        assert!(parse(&["--config="]).is_err(), "empty value must error");
        assert!(
            parse(&["--config", "a", "--config", "b"]).is_err(),
            "duplicate --config must error"
        );
    }

    /// An explicit --config path that does not exist must be a hard error,
    /// never a silent fallback to $AV_CONFIG / search paths / defaults.
    #[test]
    fn explicit_config_path_must_exist() {
        let error = av_harness::config::load_config_with_override(Some(PathBuf::from(
            "/nonexistent/agentvisor-smoke.toml",
        )))
        .unwrap_err();
        assert!(error.contains("--config points to"), "got: {error}");
    }

    /// An explicit --config path takes precedence and actually loads.
    #[test]
    fn explicit_config_path_is_loaded() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("harness.toml");
        std::fs::write(
            &path,
            "config_version = 1\nupstream_url = \"http://127.0.0.1:1\"\nlisten = \"127.0.0.1:0\"\n",
        )
        .unwrap();
        let (config, source) = av_harness::config::load_config_with_override(Some(path.clone())).unwrap();
        assert_eq!(config.upstream_url, "http://127.0.0.1:1");
        assert!(format!("{source}").contains("harness.toml"), "{source}");
    }

    #[test]
    fn signing_seed_is_persisted_and_reused() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("key.seed");
        let (first, first_generated) = load_or_create_signer(&path).unwrap();
        let (second, second_generated) = load_or_create_signer(&path).unwrap();
        assert_eq!(first.key_id(), second.key_id());
        assert!(
            first_generated,
            "first call must report the seed was freshly generated"
        );
        assert!(!second_generated, "second call must observe the persisted seed");
        assert_eq!(std::fs::read_to_string(path).unwrap().trim().len(), 64);
    }

    /// A signing seed of all zeros produces a valid Ed25519
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
        assert!(err.contains("0xFF"), "expected all-0xFF rejection, got: {err}",);
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
                    load_or_create_signer(&path).unwrap().0.key_id().to_owned()
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
        let (validator, _refresh) = build_identity(&config, Arc::new(av_core::metrics::Registry::new()))
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
        // Pin the specific mode refusal (mirror the group-readable
        // sibling above): a permission-bit refactor that returned e.g.
        // "invalid seed length" for 0o644 still passed is_err() while
        // the mode gate this test names was gone.
        let err = read_signer(&path).unwrap_err().to_string();
        assert!(err.contains("must be 0o600"), "got {err}");
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
        assert!(
            build_identity(&config, Arc::new(av_core::metrics::Registry::new()))
                .await
                .is_err()
        );
    }

    /// Regression: `identity_hmac_secret_file = ""` means "unset" for the
    /// `has_hmac` gate, but the HMAC load branch used to match the bare
    /// `Some("")` and die at boot trying to stat `""` — even when a fully
    /// valid JWKS URL was configured. The empty string must be treated as
    /// unset everywhere, mirroring the `identity_jwks_url = ""` posture.
    #[tokio::test]
    async fn empty_hmac_secret_path_is_unset_alongside_valid_jwks() {
        use axum::routing::get;
        use base64::Engine as _;
        let key = Ed25519Signer::generate();
        let jwks = serde_json::json!({
            "keys": [{
                "kid": key.key_id(),
                "kty": "OKP",
                "crv": "Ed25519",
                "alg": "EdDSA",
                "x": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.public_key_bytes()),
            }]
        })
        .to_string();
        let router = axum::Router::new().route(
            "/jwks",
            get(move || {
                let body = jwks.clone();
                async move { ([(axum::http::header::CONTENT_TYPE, "application/json")], body) }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        let mut config = HarnessConfig::for_tests("http://upstream", "/tmp", "/tmp");
        config.identity_jwks_url = Some(format!("http://{addr}/jwks"));
        config.identity_hmac_secret_file = Some(String::new());
        let (validator, refresh) = build_identity(&config, Arc::new(av_core::metrics::Registry::new()))
            .await
            .expect("empty HMAC path must be treated as unset, not stat'ed");
        assert!(validator.is_some(), "JWKS-only identity must be enabled");
        if let Some(handle) = refresh {
            handle.abort();
        }
        server.abort();
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
        let result = build_identity(&config, Arc::new(av_core::metrics::Registry::new())).await;
        let err = result.err().map(|error| error.to_string()).unwrap_or_default();
        assert!(
            err.contains("symbolic link"),
            "expected symlink rejection, got: {err}",
        );
    }

    /// A compromised or misconfigured JWKS host that returns a
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
                async move { ([(axum::http::header::CONTENT_TYPE, "application/json")], body) }
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
        let validator = av_identity::IdentityValidator::new("test-aud");
        let url = format!("http://{addr}/jwks");
        let err = refresh_jwks(&client, &url, &validator).await.unwrap_err();
        let text = format!("{err:#}");
        assert!(
            text.contains("Content-Length") || text.contains("exceeded"),
            "expected JWKS cap error, got: {text}"
        );
        assert!(
            text.contains("4194304"),
            "expected cap size in error, got: {text}"
        );
        // The returned error MUST NOT contain the URL.
        // anyhow's Display walks the whole context chain; if any
        // `.with_context(|| format!("... {url}"))` or
        // `anyhow::bail!("... {url} ...")` slipped back into
        // refresh_jwks, this assertion fires. The URL character
        // sequence "://" is the tightest proxy for "any URL leaked".
        assert!(
            !text.contains("://"),
            "refresh_jwks error must be URL-free (JWKS URL is enterprise-topology-sensitive). Got: {text}"
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

    /// Assert the URL-free posture on the reqwest-error
    /// branches (`.send()` connect failure, `.error_for_status()`
    /// non-2xx). Earlier tests only covered
    /// `anyhow::bail!("... exceeded ...")` — the two paths above
    /// wrapped a `reqwest::Error` whose Display embeds the URL,
    /// and a `.context("...")` prepend did NOT strip it.
    /// The fix converts via `reqwest::Error::without_url`
    /// before the anyhow wrap; this test locks it in for both
    /// branches by pointing refresh_jwks at:
    ///   (a) a socket that immediately closes (send failure), and
    ///   (b) a server returning 500 (error_for_status failure).
    #[tokio::test]
    async fn refresh_jwks_send_failure_is_url_free() {
        // Bind a listener but immediately drop it so the request
        // hits a closed port — reqwest surfaces a connect error.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(2))
            .build()
            .unwrap();
        let validator = av_identity::IdentityValidator::new("test-aud");
        let url = format!("http://{addr}/jwks");
        let err = refresh_jwks(&client, &url, &validator).await.unwrap_err();
        let text = format!("{err:#}");
        assert!(
            !text.contains("://"),
            "send-failure error must be URL-free; got: {text}"
        );
        assert!(
            !text.contains(&addr.to_string()),
            "send-failure error must not contain host:port; got: {text}"
        );
        // The reqwest error is preserved as the anyhow source, so the
        // classifier's downcast labels the failure instead of "other".
        assert_eq!(classify_jwks_error(&err), "connect");
    }

    #[tokio::test]
    async fn refresh_jwks_non_2xx_is_url_free() {
        use axum::routing::get;
        let router = axum::Router::new().route(
            "/jwks",
            get(|| async { (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "server broke") }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(2))
            .build()
            .unwrap();
        let validator = av_identity::IdentityValidator::new("test-aud");
        let url = format!("http://{addr}/jwks");
        let err = refresh_jwks(&client, &url, &validator).await.unwrap_err();
        let text = format!("{err:#}");
        assert!(
            !text.contains("://"),
            "non-2xx error must be URL-free; got: {text}"
        );
        assert!(
            !text.contains(&addr.to_string()),
            "non-2xx error must not contain host:port; got: {text}"
        );
        // The stable status number is a legit signal for operators.
        assert!(
            text.contains("500"),
            "non-2xx error should carry the numeric status for triage; got: {text}"
        );
        // The status-carrying reqwest error survives as the anyhow
        // source, so the classifier labels it "status" (not "other").
        assert_eq!(classify_jwks_error(&err), "status");
        server.abort();
    }

    /// A peer that accepts the connection but never responds must
    /// classify as "timeout" — the downcast only works because
    /// `refresh_jwks` keeps the reqwest error as the anyhow source.
    #[tokio::test]
    async fn refresh_jwks_timeout_is_classified() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // Accept and hold connections open without sending any bytes.
        let server = tokio::spawn(async move {
            let mut held = Vec::new();
            loop {
                if let Ok((socket, _)) = listener.accept().await {
                    held.push(socket);
                }
            }
        });
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(200))
            .build()
            .unwrap();
        let validator = av_identity::IdentityValidator::new("test-aud");
        let url = format!("http://{addr}/jwks");
        let err = refresh_jwks(&client, &url, &validator).await.unwrap_err();
        assert_eq!(classify_jwks_error(&err), "timeout");
        let text = format!("{err:#}");
        assert!(
            !text.contains("://") && !text.contains(&addr.to_string()),
            "timeout error must be URL-free; got: {text}"
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
                let chunks =
                    (0..128).map(|_| Ok::<_, std::io::Error>(axum::body::Bytes::from(vec![b'x'; 64 * 1024])));
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
        let validator = av_identity::IdentityValidator::new("test-aud");
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
        // The default policy threshold now
        // matches the default max_request_bytes (4 MiB). A payload in
        // the 1–4 MiB band — which the HTTP body limit admits — must
        // NOT be policy-blocked anymore.
        assert!(sandbox
            .sanitize(
                "chat/completions",
                &serde_json::json!({"content": "x".repeat(1_100_000)}),
            )
            .is_ok());
        assert!(sandbox
            .sanitize(
                "chat/completions",
                &serde_json::json!({"content": "x".repeat(4_300_000)}),
            )
            .is_err());
    }
}
