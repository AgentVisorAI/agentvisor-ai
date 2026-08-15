//! Ordered hot-path middleware and upstream forwarding.

use crate::config::HarnessConfig;
use crate::reconciler::Finalizer;
use crate::session::{Session, SessionLease, SessionRegistry, Workflow};
use crate::worker::{AtifCapture, ResponsePermit, WorkerHandle, WorkerJob};
use ab_bridge::EventBus;
use ab_core::metrics::Registry;
use ab_core::time::elapsed_us;
use ab_events::{AgentIdentity, EventClass, EventMetrics, StatusId, StopReason};
use ab_identity::IdentityValidator;
use ab_loopdetect::{BreakerAction, BreakerState, Embedder, HashEmbedder, NoopVectorSink, VectorSink};
use ab_receipts::Signer;
use ab_sandbox::{Sandbox, ToolVerdict};
use ab_state::{ActionBudget, BudgetDecision, StateStore};
use axum::http::{HeaderMap, HeaderName, HeaderValue};
use serde_json::Value;
use std::sync::Arc;
use std::time::Instant;

pub(crate) const SESSION_HEADER: &str = "x-ab-session";
const WORKFLOW_HEADER: &str = "x-ab-workflow";
pub(crate) const MIDDLEWARE_US_HEADER: &str = "x-ab-middleware-us";

/// TCP connect timeout for every outbound HTTPS client the harness builds.
pub const HTTP_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// Fallback identity scope when the tool name cannot be parsed from the request.
pub(crate) const TOOL_INVOKE_SCOPE: &str = "tool:invoke";

/// Identity scope required to invoke a specific tool by name.
pub(crate) fn tool_scope(tool: &str) -> String {
    format!("tool:{tool}")
}

/// Shared application state passed through HTTP handlers and background tasks.
#[derive(Clone)]
pub struct AppState {
    /// Versioned harness configuration.
    pub config: Arc<HarnessConfig>,
    /// Atomic quota and action-budget state.
    pub store: Arc<dyn StateStore>,
    /// MCP schema, policy, and action-budget sandbox.
    pub sandbox: Arc<Sandbox>,
    /// Event Bridge backend used by asynchronous workers and by lifecycle
    /// finalization (close/promote publish through it inline).
    pub bridge: Arc<dyn EventBus>,
    /// Live session registry.
    pub sessions: Arc<SessionRegistry>,
    /// Bounded non-blocking worker queue.
    pub worker: WorkerHandle,
    /// Optional NHI validator. Required in production identity mode.
    pub identity: Option<Arc<IdentityValidator>>,
    /// Prometheus-compatible metrics registry.
    pub metrics: Arc<Registry>,
    /// Reused upstream HTTP client.
    pub client: reqwest::Client,
    /// Static credential injected into every chat-completions forward
    /// (resolved once at startup; value is marked sensitive).
    pub(crate) upstream_auth: Option<(HeaderName, HeaderValue)>,
    /// Bearer credential injected into every tool-upstream forward.
    pub(crate) tool_auth: Option<HeaderValue>,
    /// Asynchronous session close and promotion service.
    pub finalizer: Finalizer,
    pub(crate) journal_key: [u8; 32],
}

/// How the harness authenticates to the chat upstream, for startup logs
/// and `abctl doctor` — never contains key material.
pub fn describe_upstream_auth(config: &HarnessConfig) -> String {
    if config.upstream_authorization_passthrough {
        "passthrough(client Authorization)".to_owned()
    } else if let Some(env) = config.upstream_api_key_env.as_deref() {
        format!("api-key from ${env} in header {:?}", config.upstream_auth_header)
    } else if let Some(file) = config.upstream_api_key_file.as_deref() {
        format!(
            "api-key from file {file} in header {:?}",
            config.upstream_auth_header
        )
    } else {
        "none".to_owned()
    }
}

/// Resolve the configured upstream credential into a ready header pair.
///
/// Key material is accepted only from an environment variable or an
/// owner-only file — never from TOML or argv — and the resulting header
/// value is marked sensitive so `Debug` output redacts it.
pub(crate) fn resolve_upstream_auth(
    config: &HarnessConfig,
) -> Result<Option<(HeaderName, HeaderValue)>, PipelineError> {
    let key = match read_secret(
        config.upstream_api_key_env.as_deref(),
        config.upstream_api_key_file.as_deref(),
        "upstream API key",
    )? {
        Some(key) => key,
        None => return Ok(None),
    };
    let name = HeaderName::try_from(config.upstream_auth_header.as_str()).map_err(|_| {
        PipelineError::Upstream(format!(
            "upstream_auth_header {:?} is not a valid header name",
            config.upstream_auth_header
        ))
    })?;
    let rendered = if config.upstream_auth_scheme.is_empty() {
        key
    } else {
        format!("{} {key}", config.upstream_auth_scheme)
    };
    let mut value = HeaderValue::from_str(&rendered).map_err(|_| {
        PipelineError::Upstream(
            "upstream API key contains bytes that cannot appear in an HTTP header".to_owned(),
        )
    })?;
    value.set_sensitive(true);
    Ok(Some((name, value)))
}

/// Resolve the optional tool-upstream bearer token.
pub(crate) fn resolve_tool_auth(config: &HarnessConfig) -> Result<Option<HeaderValue>, PipelineError> {
    let token = match read_secret(
        config.tool_upstream_bearer_env.as_deref(),
        config.tool_upstream_bearer_file.as_deref(),
        "tool upstream bearer token",
    )? {
        Some(token) => token,
        None => return Ok(None),
    };
    let mut value = HeaderValue::from_str(&format!("Bearer {token}")).map_err(|_| {
        PipelineError::Upstream(
            "tool upstream bearer token contains bytes that cannot appear in an HTTP header".to_owned(),
        )
    })?;
    value.set_sensitive(true);
    Ok(Some(value))
}

/// Read a secret from an env var or an owner-only file, trimming trailing
/// whitespace. A configured-but-missing source is a loud startup error:
/// silently proxying unauthenticated would produce baffling upstream 401s.
fn read_secret(
    env_name: Option<&str>,
    file_path: Option<&str>,
    what: &str,
) -> Result<Option<String>, PipelineError> {
    read_secret_from(|name| std::env::var(name).ok(), env_name, file_path, what)
}

/// Testable core of [`read_secret`] with an injected environment.
fn read_secret_from(
    get_env: impl Fn(&str) -> Option<String>,
    env_name: Option<&str>,
    file_path: Option<&str>,
    what: &str,
) -> Result<Option<String>, PipelineError> {
    if let Some(name) = env_name {
        let value = get_env(name).ok_or_else(|| {
            PipelineError::Upstream(format!(
                "{what}: environment variable {name} is not set (export it or update the config)"
            ))
        })?;
        let value = value.trim().to_owned();
        if value.is_empty() {
            return Err(PipelineError::Upstream(format!(
                "{what}: environment variable {name} is set but empty"
            )));
        }
        return Ok(Some(value));
    }
    if let Some(path) = file_path {
        require_owner_only_secret(std::path::Path::new(path))
            .map_err(|error| PipelineError::Upstream(format!("{what}: {error}")))?;
        let value = std::fs::read_to_string(path)
            .map_err(|error| PipelineError::Upstream(format!("{what}: read {path}: {error}")))?;
        let value = value.trim().to_owned();
        if value.is_empty() {
            return Err(PipelineError::Upstream(format!("{what}: file {path} is empty")));
        }
        return Ok(Some(value));
    }
    Ok(None)
}

/// Same posture as the signing-seed loader: refuse symlinks (a pre-planted
/// link would fool the mode check, CWE-59) and group/other-readable modes
/// on Unix. Windows deployments rely on operator-set ACLs.
fn require_owner_only_secret(path: &std::path::Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|error| format!("stat secret file {}: {error}", path.display()))?;
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            return Err(format!(
                "secret file {} is a symbolic link; refusing to follow",
                path.display()
            ));
        }
        if !file_type.is_file() {
            return Err(format!("secret file {} is not a regular file", path.display()));
        }
        let mode = metadata.mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(format!(
                "secret file {} has mode 0o{mode:03o}; must be owner-only (chmod 600 {})",
                path.display(),
                path.display()
            ));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

/// A request after all local hot-path gates have passed.
pub struct PreparedRequest {
    /// Session bound to this request.
    pub session: Arc<Session>,
    /// Identity validated for this request.
    pub identity: AgentIdentity,
    /// Payload forwarded to the upstream provider after compression.
    pub payload: Value,
    /// Total local middleware time before upstream I/O.
    pub middleware_us: u64,
    lease: SessionLease,
    response_permit: Option<ResponsePermit>,
    response_attempt_id: String,
    /// Client `Authorization` header captured for passthrough mode only.
    client_authorization: Option<HeaderValue>,
}

/// Provider response paired with its active session lease.
pub struct ForwardedResponse {
    /// Provider HTTP response.
    pub response: reqwest::Response,
    pub(crate) lease: SessionLease,
    pub(crate) response_permit: Option<ResponsePermit>,
    pub(crate) response_marker: Option<String>,
    pub(crate) response_attempt_id: String,
}

/// Hot-path failures, each carrying an HTTP status mapping.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PipelineError {
    /// A request header was malformed or inconsistent.
    #[error("bad request: {0}")]
    BadRequest(String),
    /// Identity was missing or invalid.
    #[error("unauthorized: {0}")]
    Unauthorized(String),
    /// A stateful quota or loop breaker blocked execution.
    #[error("request blocked: {0}")]
    Blocked(String),
    /// The upstream provider request failed.
    #[error("upstream request failed: {0}")]
    Upstream(String),
    /// The breaker requested immediate connection closure.
    #[error("connection aborted: {0}")]
    Abort(String),
    /// Required audit capture infrastructure is unavailable.
    #[error("audit capture unavailable: {0}")]
    Unavailable(String),
}

impl PipelineError {
    /// HTTP status code corresponding to this failure.
    ///
    /// * `Blocked` / `Abort` are permanent policy verdicts for the current
    ///   session: 403 / 409 stop mainstream SDK auto-retry loops that
    ///   would otherwise interpret 429 as transient rate limiting and
    ///   burn budget re-hitting the same breaker.
    /// * `Unavailable` is transient: 503 is paired with `Retry-After` at
    ///   the response layer so intermediaries and clients back off in
    ///   bounded fashion (RFC 7231 §7.1.3).
    /// * `Unauthorized` is paired with `WWW-Authenticate` at the
    ///   response layer (RFC 7235 §3.1).
    pub fn status(&self) -> axum::http::StatusCode {
        match self {
            Self::BadRequest(_) => axum::http::StatusCode::BAD_REQUEST,
            Self::Unauthorized(_) => axum::http::StatusCode::UNAUTHORIZED,
            Self::Blocked(_) => axum::http::StatusCode::FORBIDDEN,
            Self::Upstream(_) => axum::http::StatusCode::BAD_GATEWAY,
            Self::Abort(_) => axum::http::StatusCode::CONFLICT,
            Self::Unavailable(_) => axum::http::StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

impl AppState {
    /// Build fully wired application state with a bounded worker and shared
    /// lifecycle services.
    pub fn new(
        config: HarnessConfig,
        store: Arc<dyn StateStore>,
        sandbox: Arc<Sandbox>,
        bridge: Arc<dyn EventBus>,
        identity: Option<Arc<IdentityValidator>>,
        signer: Arc<dyn Signer>,
    ) -> Result<Self, PipelineError> {
        Self::new_with_embedder(
            config,
            store,
            sandbox,
            bridge,
            identity,
            signer,
            Arc::new(HashEmbedder::default()),
        )
    }

    /// Build application state with an explicit embedding backend.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_embedder(
        config: HarnessConfig,
        store: Arc<dyn StateStore>,
        sandbox: Arc<Sandbox>,
        bridge: Arc<dyn EventBus>,
        identity: Option<Arc<IdentityValidator>>,
        signer: Arc<dyn Signer>,
        embedder: Arc<dyn Embedder>,
    ) -> Result<Self, PipelineError> {
        Self::new_with_backends(
            config,
            store,
            sandbox,
            bridge,
            identity,
            signer,
            embedder,
            Arc::new(NoopVectorSink),
        )
    }

    /// Build application state with explicit embedding and vector backends.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_backends(
        config: HarnessConfig,
        store: Arc<dyn StateStore>,
        sandbox: Arc<Sandbox>,
        bridge: Arc<dyn EventBus>,
        identity: Option<Arc<IdentityValidator>>,
        signer: Arc<dyn Signer>,
        embedder: Arc<dyn Embedder>,
        vector_sink: Arc<dyn VectorSink>,
    ) -> Result<Self, PipelineError> {
        Self::new_with_backends_and_metrics(
            config,
            store,
            sandbox,
            bridge,
            identity,
            signer,
            embedder,
            vector_sink,
            Arc::new(Registry::new()),
        )
    }

    /// Build application state reusing a pre-existing metrics registry.
    ///
    /// `main.rs` uses this so counters registered outside `AppState`
    /// (JWKS refresh errors, HTTP shutdown drain timeouts) live on the
    /// same registry that gets scraped at `/metrics` — otherwise their
    /// samples would be invisible to Prometheus.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_backends_and_metrics(
        config: HarnessConfig,
        store: Arc<dyn StateStore>,
        sandbox: Arc<Sandbox>,
        bridge: Arc<dyn EventBus>,
        identity: Option<Arc<IdentityValidator>>,
        signer: Arc<dyn Signer>,
        embedder: Arc<dyn Embedder>,
        vector_sink: Arc<dyn VectorSink>,
        metrics: Arc<Registry>,
    ) -> Result<Self, PipelineError> {
        let config = Arc::new(config);
        // Every stage of the `ab_stage_duration_seconds` series MUST
        // share the same bucket bounds, otherwise
        // `histogram_quantile(0.99, sum by(le) (rate(...[5m])))` in
        // Prometheus silently produces nonsense: the `le` values from
        // different label combinations do not align and the summation
        // is undefined. Use WIDE_LATENCY_BOUNDS_US for all stages
        // because `dispatch` (upstream streaming, 15-90 s) needs the
        // wide range — the fast stages just get more granular
        // low-end buckets they will never light up, which is fine.
        for stage in ["identity", "quota", "sanitize", "compression", "dispatch"] {
            metrics.histogram_with_bounds(
                &format!("ab_stage_duration_seconds{{stage=\"{stage}\"}}"),
                "Harness stage latency",
                ab_core::metrics::WIDE_LATENCY_BOUNDS_US,
            );
        }
        metrics.counter(
            "ab_events_dropped_total{stage=\"worker_queue\"}",
            "Worker jobs dropped",
        );
        metrics.counter(
            "ab_worker_panics_total",
            "Worker job panics isolated by supervisor",
        );
        metrics.counter("ab_worker_errors_total", "Worker jobs that failed");
        metrics.counter("ab_sessions_finalized_total", "Sessions finalized");
        metrics.counter("ab_sessions_promoted_total", "Unsigned sessions promoted");
        metrics.counter("ab_reconcile_errors_total", "Reconciliation errors");
        metrics.histogram("ab_receipt_sign_duration_seconds", "Receipt signing latency");
        // Reconciler ticks scan the ATIF spool dir, which can be large;
        // finalisation waits for worker drain + broker publish. Wide
        // bounds keep long-tail p99 useful under load.
        metrics.histogram_with_bounds(
            "ab_reconcile_duration_seconds",
            "Idle reconciliation duration",
            ab_core::metrics::WIDE_LATENCY_BOUNDS_US,
        );
        metrics.histogram_with_bounds(
            "ab_session_finalize_duration_seconds",
            "Session finalization latency",
            ab_core::metrics::WIDE_LATENCY_BOUNDS_US,
        );
        for endpoint in ["stats", "list", "detail"] {
            metrics.histogram(
                &format!("ab_dashboard_request_duration_seconds{{endpoint=\"{endpoint}\"}}"),
                "Dashboard endpoint latency",
            );
            metrics.counter(
                &format!("ab_dashboard_requests_total{{endpoint=\"{endpoint}\",status=\"ok\"}}"),
                "Dashboard endpoint requests served",
            );
            metrics.counter(
                &format!("ab_dashboard_requests_total{{endpoint=\"{endpoint}\",status=\"not_found\"}}"),
                "Dashboard endpoint requests that could not be served",
            );
        }
        let sessions = Arc::new(SessionRegistry::new());
        let journal_key = crate::journal::key_from_signer(signer.as_ref());
        let worker = crate::worker::spawn_worker_with_spool_authenticated(
            config.worker_channel_capacity,
            Arc::clone(&bridge),
            embedder,
            vector_sink,
            Some(std::path::PathBuf::from(&config.atif_spool_dir)),
            journal_key,
            Arc::clone(&metrics),
        );
        let finalizer = Finalizer::with_bridge(
            signer,
            std::path::PathBuf::from(&config.atif_spool_dir),
            Arc::clone(&metrics),
            Arc::clone(&bridge),
        )
        .with_state_store(Arc::clone(&store));
        let mut client_builder = reqwest::Client::builder()
            .connect_timeout(HTTP_CONNECT_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            // Providers (OpenAI, Anthropic, Azure, Bedrock fronting)
            // downgrade or block empty / generic UAs; identifying
            // ourselves also gives operators a stable string for
            // provider-side triage. Version is baked in at compile
            // time so a rolling deploy makes the change visible.
            .user_agent(concat!("AgentBridge/", env!("CARGO_PKG_VERSION")))
            // TCP keepalive so pooled connections behind NAT/L4 LBs
            // with short idle windows (AWS NLB 350 s, GCP TCP 600 s,
            // stateful FWs often 60-120 s) do not turn every first
            // request per pool cycle into a full TCP+TLS re-handshake
            // that manifests as a spurious 502/`connection reset`.
            .tcp_keepalive(std::time::Duration::from_secs(30))
            // Cap pool idle at 60 s: shorter than any realistic NAT
            // window, longer than any burst-of-requests batch. Bounds
            // the pool memory footprint and forces frequent-enough
            // TLS refresh under a rolling cert rotation.
            .pool_idle_timeout(std::time::Duration::from_secs(60));
        if let Some(seconds) = config.upstream_read_timeout_s {
            client_builder = client_builder.read_timeout(std::time::Duration::from_secs(seconds));
        }
        if config.upstream_http2_prior_knowledge {
            client_builder = client_builder.http2_prior_knowledge();
        }
        let client = client_builder
            .build()
            .map_err(|error| PipelineError::Upstream(error.to_string()))?;
        let upstream_auth = resolve_upstream_auth(&config)?;
        let tool_auth = resolve_tool_auth(&config)?;
        Ok(Self {
            config,
            store,
            sandbox,
            bridge,
            sessions,
            worker,
            identity,
            metrics,
            client,
            upstream_auth,
            tool_auth,
            finalizer,
            journal_key,
        })
    }

    /// Run identity, breaker, quota, sanitize, compression, and asynchronous
    /// dispatch in the mandated order without awaiting worker or upstream I/O.
    pub fn prepare_chat(
        &self,
        headers: &HeaderMap,
        mut payload: Value,
    ) -> Result<PreparedRequest, PipelineError> {
        let total_started = Instant::now();
        let session_id = session_id(headers)?;
        let workflow = workflow(headers, &self.config.default_workflow)?;

        let stage = Instant::now();
        let identity = match self.resolve_identity(headers, Some(&self.config.chat_scope)) {
            Ok(identity) => identity,
            Err(error) => {
                self.enqueue_transient_failure(&session_id, StopReason::IdentityRejected, error.to_string())?;
                return Err(error);
            }
        };
        self.observe_stage("identity", stage);

        let session = self
            .sessions
            .get_or_open(&session_id, workflow, &identity, &self.config.breaker);
        let admission = session.admission_guard();
        validate_session_binding(&session, workflow, &identity)?;
        session.refresh_identity(&identity);
        if session.is_closed() {
            return Err(PipelineError::BadRequest("session is already closed".to_owned()));
        }
        if session.capture_failed() {
            return Err(PipelineError::Unavailable(
                "session audit capture is incomplete".to_owned(),
            ));
        }
        session.touch();
        if session.loop_state.state() == BreakerState::Open {
            match session.loop_state.action() {
                BreakerAction::Reject => {
                    return Err(PipelineError::Blocked(
                        "semantic loop circuit breaker is open".to_owned(),
                    ));
                }
                BreakerAction::Abort => {
                    return Err(PipelineError::Abort(
                        "semantic loop circuit breaker requested connection close".to_owned(),
                    ));
                }
                BreakerAction::Inject => {
                    inject_corrective_message(&mut payload)?;
                    session.loop_state.reset();
                }
                _ => {
                    return Err(PipelineError::Blocked(
                        "unsupported semantic loop enforcement action".to_owned(),
                    ));
                }
            }
        }

        // Fused acquire: one worker slot + one response slot atomically.
        // If the worker slot succeeds and the response slot fails, the
        // worker permit drops via RAII (its OwnedSemaphorePermit and
        // mpsc reservation release cleanly), so the caller never sees
        // an orphaned half-reservation. Distinct
        // `ab_events_dropped_total{stage=worker_queue|response_slot}`
        // counters let operators tell which one exhausted.
        let permits = self
            .worker
            .try_reserve_pair(&session_id)
            .map_err(|error| PipelineError::Unavailable(error.to_string()))?;
        let worker_permit = permits.worker;
        let response_permit = permits.response;

        let stage = Instant::now();
        let prompt_tokens = ab_core::tokens::approx_tokens_json(&payload);
        let quota = match ActionBudget::new(self.store.as_ref(), &session_id, &self.config.budget)
            .try_tokens(prompt_tokens)
        {
            Ok(quota) => quota,
            Err(error) => {
                let error = PipelineError::Blocked(format!("quota backend failed closed: {error}"));
                worker_permit.submit(self.failure_job(
                    Arc::clone(&session),
                    identity.clone(),
                    StopReason::BudgetExceeded,
                    error.to_string(),
                ));
                return Err(error);
            }
        };
        if let BudgetDecision::Refused { limit, cap } = quota {
            let error = PipelineError::Blocked(format!("{limit} exceeded (cap {cap})"));
            worker_permit.submit(self.failure_job(
                Arc::clone(&session),
                identity.clone(),
                StopReason::BudgetExceeded,
                error.to_string(),
            ));
            return Err(error);
        }
        self.observe_stage("quota", stage);

        let stage = Instant::now();
        if let Err(reason) = self.sandbox.sanitize("chat/completions", &payload) {
            let error = PipelineError::Blocked(reason);
            worker_permit.submit(self.failure_job(
                Arc::clone(&session),
                identity.clone(),
                StopReason::PolicyBlocked,
                error.to_string(),
            ));
            return Err(error);
        }
        self.observe_stage("sanitize", stage);

        let stage = Instant::now();
        let compression = if self.config.compression_enabled {
            ab_compress::compress(&payload, &ab_compress::CompressionConfig::default())
        } else {
            ab_compress::CompressionOutcome {
                payload,
                tokens_before: prompt_tokens,
                tokens_after: prompt_tokens,
                changed: false,
            }
        };
        self.observe_stage("compression", stage);

        let stage = Instant::now();
        let text = last_message_text(&compression.payload);
        let atif = match atif_capture_from_request(&compression.payload) {
            Ok(atif) => atif,
            Err(error) => {
                worker_permit.submit(self.failure_job(
                    Arc::clone(&session),
                    identity.clone(),
                    StopReason::Other,
                    error.to_string(),
                ));
                return Err(error);
            }
        };
        let analyze_loop = atif.source == ab_atif::Source::Agent;
        let response_attempt_id = ab_core::new_event_uid();
        let job = WorkerJob {
            session: Arc::clone(&session),
            identity: identity.clone(),
            class: EventClass::Compression,
            payload: serde_json::json!({
                "changed": compression.changed,
                "tokens_before": compression.tokens_before,
                "tokens_after": compression.tokens_after,
            }),
            text,
            analyze_loop,
            status: StatusId::Success,
            stop_reason: None,
            native_stop_reason: None,
            metrics: EventMetrics {
                prompt_tokens: Some(compression.tokens_after),
                completion_tokens: Some(0),
                cached_tokens: Some(0),
                pruned_tokens: Some(compression.pruned_tokens()),
                pruning_ratio_millis: Some(compression.pruning_ratio_millis()),
            },
            cost_usd_micros: 0,
            atif: Some(atif),
            response_marker: None,
            response_attempt: Some(crate::worker::ResponseAttempt {
                id: response_attempt_id.clone(),
                terminal: false,
            }),
        };
        worker_permit.submit(job);
        self.observe_stage("dispatch", stage);
        let lease = SessionLease::new(Arc::clone(&session));
        drop(admission);

        Ok(PreparedRequest {
            session,
            identity,
            payload: compression.payload,
            middleware_us: elapsed_us(total_started),
            lease,
            response_permit: Some(response_permit),
            response_attempt_id,
            client_authorization: if self.config.upstream_authorization_passthrough {
                single_header(headers, "authorization")?.cloned()
            } else {
                None
            },
        })
    }

    /// Run synchronous local gates without waiting for off-path journal,
    /// embedding, or broker work. When a completion-token budget is
    /// configured (`budget.max_tokens`) the gates run on the blocking pool;
    /// otherwise they are cheap enough to run inline.
    pub async fn prepare_chat_nonblocking(
        &self,
        headers: &HeaderMap,
        payload: Value,
    ) -> Result<PreparedRequest, PipelineError> {
        if self.config.budget.max_tokens.is_none() {
            return self.prepare_chat(headers, payload);
        }
        let state = self.clone();
        let headers = headers.clone();
        tokio::task::spawn_blocking(move || state.prepare_chat(&headers, payload))
            .await
            .map_err(|error| PipelineError::Unavailable(error.to_string()))?
    }

    /// Prepare a request and wait until its audit record is durably captured
    /// before the provider can observe it.
    pub async fn prepare_chat_durable(
        &self,
        headers: &HeaderMap,
        payload: Value,
    ) -> Result<PreparedRequest, PipelineError> {
        if let Ok(id) = session_id(headers) {
            if let Some(session) = self.sessions.get(&id) {
                session.wait_for_worker_jobs().await;
                if session.capture_failed() {
                    return Err(PipelineError::Unavailable(
                        "session audit capture is incomplete".to_owned(),
                    ));
                }
            }
        }
        let state = self.clone();
        let headers = headers.clone();
        let mut prepared = tokio::task::spawn_blocking(move || state.prepare_chat(&headers, payload))
            .await
            .map_err(|error| PipelineError::Unavailable(error.to_string()))??;
        prepared.session.wait_for_worker_jobs().await;
        if prepared.session.capture_failed() {
            let error = PipelineError::Unavailable(
                "request audit capture failed before provider dispatch".to_owned(),
            );
            self.abandon_prepared(&mut prepared, StopReason::Other, &error.to_string());
            return Err(error);
        }
        if prepared.session.loop_state.state() == BreakerState::Open {
            let error = match prepared.session.loop_state.action() {
                BreakerAction::Abort => {
                    PipelineError::Abort("semantic loop circuit breaker opened during audit".to_owned())
                }
                _ => PipelineError::Blocked(
                    "semantic loop circuit breaker opened during audit; retry required".to_owned(),
                ),
            };
            self.abandon_prepared(&mut prepared, StopReason::LoopDetected, &error.to_string());
            return Err(error);
        }
        Ok(prepared)
    }

    /// Close out a prepared request that will never reach `forward_chat`.
    ///
    /// `prepare_chat` journals a non-terminal [`crate::worker::ResponseAttempt`]
    /// with its admission record; the matching terminal record normally comes
    /// from `forward_chat`'s failure path or the response relay. A caller that
    /// abandons the request after admission must submit the terminal failure
    /// record itself — otherwise the journal ends with a dangling non-terminal
    /// attempt and a later crash-recovery scan quarantines the whole session
    /// over a request the client already saw fail.
    fn abandon_prepared(&self, prepared: &mut PreparedRequest, stop_reason: StopReason, reason: &str) {
        let Some(permit) = prepared.response_permit.take() else {
            return;
        };
        let mut job = self.failure_job(
            Arc::clone(&prepared.session),
            prepared.identity.clone(),
            stop_reason,
            reason.to_owned(),
        );
        job.response_attempt = Some(crate::worker::ResponseAttempt {
            id: prepared.response_attempt_id.clone(),
            terminal: true,
        });
        // Best-effort submit: if the shard is momentarily full, the
        // response-slot counter has already been bumped inside submit
        // and the caller (this path) is already an abandon flow, so
        // there is nothing further to do.
        let _ = permit.submit(&self.worker, job);
    }

    /// Forward a prepared OpenAI-compatible request to the configured provider.
    pub async fn forward_chat(&self, request: PreparedRequest) -> Result<ForwardedResponse, PipelineError> {
        let PreparedRequest {
            session,
            identity,
            payload,
            lease,
            response_permit,
            response_attempt_id,
            client_authorization,
            ..
        } = request;
        let url = format!(
            "{}{}",
            self.config.upstream_url.trim_end_matches('/'),
            self.config.upstream_chat_path
        );
        // Digest the request payload so the in-flight marker can be
        // matched to the observed response bytes at recovery time.
        //
        // `serde_json::to_vec` on a `Value` is effectively infallible
        // (Value can only carry JSON-serialisable data), but we handle
        // the theoretical error path anyway: falling back to
        // `sha256(b"")` — the well-known empty digest — would make
        // every concurrent failed serialisation collide on the same
        // request_digest, silently violating the marker's
        // one-to-one-with-request invariant. Fall back to a
        // session-id-derived digest so a hypothetical failure at
        // least keeps distinct sessions distinct.
        let request_digest = match serde_json::to_vec(&payload) {
            Ok(bytes) => ab_core::digest::sha256_hex(&bytes),
            Err(error) => {
                tracing::error!(
                    %error,
                    session = %session.id,
                    "failed to serialise chat payload for request digest; falling back to session-derived digest"
                );
                ab_core::digest::sha256_hex(session.id.as_bytes())
            }
        };
        let response_marker = crate::worker::create_response_marker(
            std::path::Path::new(&self.config.atif_spool_dir),
            &self.journal_key,
            &session.id,
            request_digest,
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, session = %session.id, "could not write in-flight response marker");
        })
        .ok();
        let mut upstream_request = self.client.post(url).json(&payload);
        if let Some((name, value)) = &self.upstream_auth {
            upstream_request = upstream_request.header(name.clone(), value.clone());
        } else if let Some(authorization) = client_authorization {
            // Passthrough mode: the client's own credential travels to the
            // upstream. `validate()` guarantees this is mutually exclusive
            // with static keys and with NHI identity enforcement.
            upstream_request = upstream_request.header(reqwest::header::AUTHORIZATION, authorization);
        }
        match upstream_request.send().await {
            Ok(response) => Ok(ForwardedResponse {
                response,
                lease,
                response_permit,
                response_marker,
                response_attempt_id,
            }),
            Err(error) => {
                let internal_detail = error.to_string();
                tracing::warn!(
                    session = %session.id,
                    error = %internal_detail,
                    "upstream forwarding failed"
                );
                let client_reason = classify_upstream_error(&error);
                let client_error = PipelineError::Upstream(client_reason.to_owned());
                if let Some(permit) = response_permit {
                    let mut job = self.failure_job(session, identity, StopReason::Other, internal_detail);
                    job.response_marker = response_marker;
                    job.response_attempt = Some(crate::worker::ResponseAttempt {
                        id: response_attempt_id,
                        terminal: true,
                    });
                    // Best-effort: shard may be momentarily full, in
                    // which case the response-slot counter is bumped
                    // and the failure event falls back to the plain
                    // enqueue_failure path below on the next tick.
                    let _ = permit.submit(&self.worker, job);
                } else {
                    self.enqueue_failure(session, identity, StopReason::Other, error.to_string())?;
                }
                Err(client_error)
            }
        }
    }

    /// Intercept one MCP JSON-RPC tool call, emit its OCSF verdict
    /// asynchronously, and return the immediate authorization decision.
    pub fn intercept_tool(&self, headers: &HeaderMap, raw: &[u8]) -> Result<ToolVerdict, PipelineError> {
        self.intercept_tool_with_session(headers, raw)
            .map(|(verdict, _session)| verdict)
    }

    /// Core of [`Self::intercept_tool`] that also returns the bound session.
    ///
    /// Callers that must await audit durability need the same session the
    /// verdict was recorded under: re-deriving it from headers would mint a
    /// fresh random id for a header-less request (see [`session_id`]) and
    /// look up a session that does not exist.
    fn intercept_tool_with_session(
        &self,
        headers: &HeaderMap,
        raw: &[u8],
    ) -> Result<(ToolVerdict, Arc<Session>), PipelineError> {
        let session_id = session_id(headers)?;
        let workflow = workflow(headers, &self.config.default_workflow)?;
        let parsed_call = ab_sandbox::parse_tool_call(raw).ok();
        let required_scope = parsed_call
            .as_ref()
            .map(|request| tool_scope(&request.tool))
            .unwrap_or_else(|| TOOL_INVOKE_SCOPE.to_owned());
        let identity = match self.resolve_identity(headers, Some(&required_scope)) {
            Ok(identity) => identity,
            Err(error) => {
                self.enqueue_transient_failure(&session_id, StopReason::IdentityRejected, error.to_string())?;
                return Err(error);
            }
        };
        // Tool interception must NOT resurrect a closed session: a
        // tool call extends an in-progress conversation, so silently
        // opening a fresh session under the same id would let the
        // client accumulate tool calls past a signed receipt boundary
        // (chain-of-custody split). Chat requests use `get_or_open`
        // (recycles closed ids); the strict `_no_reopen` variant here
        // makes the `is_closed()` check below fire.
        let session =
            self.sessions
                .get_or_open_no_reopen(&session_id, workflow, &identity, &self.config.breaker);
        let admission = session.admission_guard();
        validate_session_binding(&session, workflow, &identity)?;
        session.refresh_identity(&identity);
        if session.is_closed() {
            return Err(PipelineError::BadRequest("session is already closed".to_owned()));
        }
        if session.capture_failed() {
            return Err(PipelineError::Unavailable(
                "session audit capture is incomplete".to_owned(),
            ));
        }
        session.touch();
        let worker_permit = self
            .worker
            .try_reserve(&session_id)
            .map_err(|error| PipelineError::Unavailable(error.to_string()))?;
        let verdict = match parsed_call.as_ref() {
            // `sandbox.check`'s budget gate spends before we return, so we must
            // veto workflow-mismatched consequential tools before it runs.
            Some(request)
                if workflow == Workflow::Unsigned
                    && self
                        .config
                        .consequential_tools
                        .iter()
                        .any(|required| required == &request.tool) =>
            {
                let reason = format!("tool {:?} requires a signed workflow", request.tool);
                ToolVerdict::Blocked {
                    tool: request.tool.clone(),
                    stage: "policy",
                    reason: reason.clone(),
                    response: ab_sandbox::rpc::authorization_error(request.id.as_ref(), &reason),
                    elapsed_us: 0,
                }
            }
            _ => self.sandbox.check(self.store.as_ref(), &session_id, raw),
        };
        let (status, payload) = match &verdict {
            ToolVerdict::Allowed {
                tool,
                budget_remaining,
                elapsed_us,
            } => (
                StatusId::Success,
                serde_json::json!({
                    "tool": tool,
                    "allowed": true,
                    "budget_remaining": (*budget_remaining != u64::MAX)
                        .then_some(*budget_remaining),
                    "budget_unlimited": *budget_remaining == u64::MAX,
                    "decision_us": elapsed_us,
                }),
            ),
            ToolVerdict::Blocked {
                tool,
                stage,
                reason,
                elapsed_us,
                ..
            } => (
                StatusId::Failure,
                serde_json::json!({
                    "tool": tool,
                    "allowed": false,
                    "stage": stage,
                    "reason": reason,
                    "decision_us": elapsed_us,
                }),
            ),
        };
        let tool_call_id = parsed_call
            .as_ref()
            .and_then(|request| request.id.as_ref())
            .map(|value| value.as_str().map_or_else(|| value.to_string(), str::to_owned))
            .unwrap_or_else(ab_core::new_event_uid);
        let tool_calls = parsed_call.as_ref().map(|request| {
            vec![ab_atif::ToolCall {
                tool_call_id: tool_call_id.clone(),
                function_name: request.tool.clone(),
                arguments: request.arguments.clone(),
                extra: None,
            }]
        });
        let observation = parsed_call.as_ref().map(|_| ab_atif::Observation {
            results: vec![ab_atif::ObservationResult {
                source_call_id: Some(tool_call_id),
                content: Some(Value::String(payload.to_string())),
                subagent_trajectory_ref: None,
                extra: None,
            }],
        });
        let stop_reason = match &verdict {
            ToolVerdict::Allowed { .. } => None,
            ToolVerdict::Blocked { stage: "budget", .. } => Some(StopReason::BudgetExceeded),
            ToolVerdict::Blocked { .. } => Some(StopReason::PolicyBlocked),
        };
        worker_permit.submit(WorkerJob {
            session: Arc::clone(&session),
            identity,
            class: EventClass::ToolCall,
            payload,
            text: String::from_utf8_lossy(raw).into_owned(),
            analyze_loop: false,
            status,
            stop_reason,
            native_stop_reason: None,
            metrics: EventMetrics::default(),
            cost_usd_micros: 0,
            atif: Some(AtifCapture {
                source: ab_atif::Source::Agent,
                message: Value::String("MCP tool authorization decision".to_owned()),
                reasoning_content: None,
                model_name: None,
                tool_calls,
                observation,
                llm_call_count: Some(0),
            }),
            response_marker: None,
            response_attempt: None,
        });
        drop(admission);
        Ok((verdict, session))
    }

    /// Authorize a tool call and wait for its verdict event to become durable.
    pub async fn intercept_tool_durable(
        &self,
        headers: &HeaderMap,
        raw: &[u8],
    ) -> Result<ToolVerdict, PipelineError> {
        let state = self.clone();
        let owned_headers = headers.clone();
        let raw = raw.to_vec();
        let (verdict, session) =
            tokio::task::spawn_blocking(move || state.intercept_tool_with_session(&owned_headers, &raw))
                .await
                .map_err(|error| PipelineError::Unavailable(error.to_string()))??;
        session.wait_for_worker_jobs().await;
        if session.capture_failed() {
            return Err(PipelineError::Unavailable(
                "tool authorization audit capture failed".to_owned(),
            ));
        }
        Ok(verdict)
    }

    /// Authorize a tool call on the blocking pool without waiting for the
    /// off-path event journal or broker publication.
    pub async fn intercept_tool_nonblocking(
        &self,
        headers: &HeaderMap,
        raw: &[u8],
    ) -> Result<ToolVerdict, PipelineError> {
        let state = self.clone();
        let owned_headers = headers.clone();
        let raw = raw.to_vec();
        tokio::task::spawn_blocking(move || state.intercept_tool(&owned_headers, &raw))
            .await
            .map_err(|error| PipelineError::Unavailable(error.to_string()))?
    }

    pub(crate) fn lease_session(&self, headers: &HeaderMap) -> Result<SessionLease, PipelineError> {
        let id = session_id(headers)?;
        let session = self
            .sessions
            .get(&id)
            .ok_or_else(|| PipelineError::BadRequest("unknown session".to_owned()))?;
        session
            .try_lease()
            .ok_or_else(|| PipelineError::BadRequest("session is already closed".to_owned()))
    }

    fn enqueue_transient_failure(
        &self,
        session_id: &str,
        stop_reason: StopReason,
        reason: String,
    ) -> Result<(), PipelineError> {
        let audit_session_id = format!("identity-rejected-{}", ab_core::new_event_uid());
        let identity = AgentIdentity {
            version: "unknown".to_owned(),
            charter: "identity-rejected".into(),
            instance_uid: audit_session_id.clone(),
            ttl_remaining_s: None,
        };
        let session = Arc::new(Session::new(
            audit_session_id,
            Workflow::Signed,
            identity.clone(),
            self.config.breaker.clone(),
        ));
        // Cap the attacker-controlled `session_id` echo so a
        // maliciously long header cannot bloat every audit record.
        // 64 bytes is enough to keep well-formed UUIDs and legitimate
        // client-chosen ids intact; anything larger is truncated with
        // a marker so operators can still tell what the caller sent.
        const MAX_ECHO: usize = 64;
        let mut boundary = MAX_ECHO.min(session_id.len());
        while boundary < session_id.len() && !session_id.is_char_boundary(boundary) {
            boundary -= 1;
        }
        let truncated = boundary < session_id.len();
        let echo = &session_id[..boundary];
        let echo_marker = if truncated { "…(truncated)" } else { "" };
        self.enqueue_failure(
            session,
            identity,
            stop_reason,
            format!("requested session {echo:?}{echo_marker}: {reason}"),
        )
    }

    fn enqueue_failure(
        &self,
        session: Arc<Session>,
        identity: AgentIdentity,
        stop_reason: StopReason,
        reason: String,
    ) -> Result<(), PipelineError> {
        self.worker
            .try_submit(self.failure_job(session, identity, stop_reason, reason))
            .map_err(|error| PipelineError::Unavailable(error.to_string()))
    }

    fn failure_job(
        &self,
        session: Arc<Session>,
        identity: AgentIdentity,
        stop_reason: StopReason,
        reason: String,
    ) -> WorkerJob {
        let atif = (session.workflow == Workflow::Unsigned).then(|| AtifCapture {
            source: ab_atif::Source::Agent,
            message: Value::String(reason.clone()),
            reasoning_content: None,
            model_name: None,
            tool_calls: None,
            observation: None,
            llm_call_count: Some(0),
        });
        WorkerJob {
            session,
            identity,
            class: EventClass::StopReason,
            payload: serde_json::json!({"reason": reason}),
            text: String::new(),
            analyze_loop: false,
            status: StatusId::Failure,
            stop_reason: Some(stop_reason),
            native_stop_reason: None,
            metrics: EventMetrics::default(),
            cost_usd_micros: 0,
            atif,
            response_marker: None,
            response_attempt: None,
        }
    }

    pub(crate) fn authorize_session(
        &self,
        headers: &HeaderMap,
        session: &Session,
        required_scope: &str,
    ) -> Result<(), PipelineError> {
        let identity = self.resolve_identity(headers, Some(required_scope))?;
        validate_session_binding(session, session.workflow, &identity)?;
        session.refresh_identity(&identity);
        Ok(())
    }

    pub(crate) fn resolve_identity(
        &self,
        headers: &HeaderMap,
        required_scope: Option<&str>,
    ) -> Result<AgentIdentity, PipelineError> {
        // Round-14 F1: reuse the round-13 duplicate-header refusal
        // pattern for `Authorization` on the identity hot path.
        // Previously `HeaderMap::get(AUTHORIZATION)` returned the
        // first value while `pipeline::client_authorization` capture
        // (line 695) and header-smuggling proxies could observe a
        // merged `A, B` form — auth split-brain: the harness
        // authenticates as A while log aggregators / WAFs / OTLP
        // exporters attribute the request to B. Refuse the multi-
        // value case at ingress, symmetric with the X-AB-Session /
        // X-AB-Workflow guards.
        let bearer = single_header(headers, "authorization")?
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "));
        match (bearer, &self.identity) {
            (Some(token), Some(validator)) => {
                let validated = validator.validate(token).map_err(|error| {
                    tracing::warn!(
                        error = %error,
                        "identity validation failed"
                    );
                    PipelineError::Unauthorized(classify_identity_error(&error).to_owned())
                })?;
                if self.config.enforce_identity_scopes {
                    if let Some(required) = required_scope {
                        if !scope_allows(&validated.claims.scopes, required) {
                            return Err(PipelineError::Unauthorized(format!(
                                "identity scope {required:?} is required"
                            )));
                        }
                    }
                }
                Ok(validated.agent_identity())
            }
            // Client presented a bearer but the validator is not
            // configured. Two legitimate cases and one attack surface:
            //  (a) `upstream_authorization_passthrough = true`: the
            //      client's bearer is the CREDENTIAL FOR THE UPSTREAM
            //      PROVIDER, not an identity claim for us. Accept
            //      anonymous locally so the request proceeds and the
            //      relay layer forwards the header. This is the
            //      documented dev-mode BYO-key posture.
            //  (b) Neither passthrough nor validator: the operator
            //      opted out of identity entirely. Any bearer is
            //      meaningless. Same accept-anonymous result — but
            //      warn once in tracing so the mismatch is visible.
            //  (c) A validator EXISTS but this arm ran because
            //      match fell through: unreachable because arm 1
            //      catches (Some, Some). No action.
            //
            // The attack case — a caller sends a scoped identity token
            // and we silently attribute the request as `anonymous`
            // producing a repudiation vector — was closed at commit
            // e56... by rejecting here. But that broke passthrough
            // mode. Restore acceptance when passthrough is on so the
            // BYO-key path works, and continue rejecting only when
            // NO passthrough is configured and identity was not
            // required (i.e. the client presenting a bearer to a
            // no-op harness).
            (Some(_), None) => {
                if self.config.upstream_authorization_passthrough {
                    Ok(AgentIdentity {
                        version: "dev".to_owned(),
                        charter: "anonymous".into(),
                        instance_uid: "anonymous".to_owned(),
                        ttl_remaining_s: None,
                    })
                } else {
                    Err(PipelineError::Unauthorized(
                        "bearer token presented but identity validator is not configured — \
                         refusing to silently record the request as anonymous (either \
                         configure identity_jwks_url / identity_hmac_secret_file, or set \
                         upstream_authorization_passthrough=true if the bearer is meant \
                         for the upstream provider)"
                            .to_owned(),
                    ))
                }
            }
            (None, _) if self.config.require_identity => {
                Err(PipelineError::Unauthorized("missing bearer token".to_owned()))
            }
            _ => Ok(AgentIdentity {
                version: "dev".to_owned(),
                charter: "anonymous".into(),
                instance_uid: "anonymous".to_owned(),
                ttl_remaining_s: None,
            }),
        }
    }

    fn observe_stage(&self, stage: &str, started: Instant) {
        let elapsed = elapsed_us(started);
        self.metrics
            .histogram(
                &format!("ab_stage_duration_seconds{{stage=\"{stage}\"}}"),
                "Harness stage latency",
            )
            .observe_us(elapsed);
        if (self.config.strict_stage_budget || truthy_env("AB_STRICT_BUDGET")) && elapsed > 2_000 {
            self.metrics
                .counter(
                    &format!("ab_strict_budget_breaches_total{{stage=\"{stage}\"}}"),
                    "Middleware stages that exceeded the strict per-stage budget",
                )
                .inc();
            tracing::warn!(stage, elapsed_us = elapsed, "strict stage budget exceeded");
        }
    }
}

fn truthy_env(name: &str) -> bool {
    match std::env::var(name) {
        Ok(value) => matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => false,
    }
}

/// Map a `reqwest::Error` to a client-safe reason (CWE-209): the raw
/// `Display` includes the request URL, which leaks the operator-configured
/// upstream URL — potentially an internal hostname — to the caller. Return a
/// stable, non-identifying category instead; the detailed message is logged
/// server-side by the caller.
pub(crate) fn classify_upstream_error(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "upstream timed out"
    } else if error.is_connect() {
        "upstream unreachable"
    } else if error.is_request() {
        "upstream request rejected"
    } else if error.is_body() || error.is_decode() {
        "upstream response malformed"
    } else if error.is_status() {
        "upstream returned error status"
    } else {
        "upstream forwarding failed"
    }
}

/// Map an [`IdentityError`] to a client-safe reason (CWE-209).
///
/// The `Display` impl on `IdentityError` embeds attacker-influenced strings
/// (the presented `kid`, `iss`, and structural detail from the underlying
/// JWT parser) and distinguishes between at least sixteen distinct failure
/// modes. Returning that verbatim to the client turns each 401 response
/// into an *enumeration oracle* for the validator's configured JWKS and
/// issuer allowlist: an attacker can iterate candidate `kid`s and issuers
/// and read the response body to discover which values are registered
/// (`UnknownKid` vs `AlgorithmRejected` vs `Verification` vs `BadIssuer`
/// all produce distinguishable text).
///
/// We collapse every attacker-reachable variant to a single stable string.
/// The detailed cause is preserved server-side by the caller via
/// `tracing::warn!` and the failure-job audit chain, so operators keep
/// full diagnostic detail without exposing it to the network.
fn classify_identity_error(error: &ab_identity::IdentityError) -> &'static str {
    match error {
        // Server-side misconfiguration is not attacker-reachable in the
        // normal request path (validator construction rejects a bad JWKS
        // at startup); report it distinctly so operator dashboards can
        // surface it if it ever appears.
        ab_identity::IdentityError::Jwks(_) => "identity validator misconfigured",
        // Every other variant is at least partially attacker-influenced —
        // collapse to one opaque message. Any finer distinction leaks
        // configured `kid`s, issuers, or acceptable algorithms.
        _ => "identity validation failed",
    }
}

/// Extract the single value for a control header, refusing duplicates.
///
/// `HeaderMap::get(name)` returns only the first entry when a header
/// appears multiple times. A client sending
/// `X-AB-Session: sessA` followed by `X-AB-Session: sessB` would then
/// have `sessA` used for state while an intermediary log-aggregator
/// might observe `sessA, sessB` (some proxies merge on the wire). The
/// resulting session-desync is hard to diagnose and is a header
/// smuggling primitive at boundaries where our proxy is behind
/// another one. Refuse the multi-value case at ingress rather than
/// silently accept the first.
pub(crate) fn single_header<'a>(
    headers: &'a HeaderMap,
    name: &'static str,
) -> Result<Option<&'a axum::http::HeaderValue>, PipelineError> {
    let mut iter = headers.get_all(name).into_iter();
    let first = iter.next();
    if iter.next().is_some() {
        return Err(PipelineError::BadRequest(format!(
            "request carries more than one {name} header; provide exactly one"
        )));
    }
    Ok(first)
}

fn session_id(headers: &HeaderMap) -> Result<String, PipelineError> {
    match single_header(headers, SESSION_HEADER)? {
        Some(value) => {
            let value = value
                .to_str()
                .map_err(|_| PipelineError::BadRequest("X-AB-Session is not valid text".to_owned()))?;
            ab_core::SessionId::parse(value)
                .map(|id| id.to_string())
                .map_err(|error| PipelineError::BadRequest(error.to_string()))
        }
        None => Ok(ab_core::new_session_id().to_string()),
    }
}

fn workflow(headers: &HeaderMap, default: &str) -> Result<Workflow, PipelineError> {
    let value = single_header(headers, WORKFLOW_HEADER)?
        .map(|header| {
            header
                .to_str()
                .map_err(|_| PipelineError::BadRequest("X-AB-Workflow is not valid text".to_owned()))
        })
        .transpose()?
        .unwrap_or(default);
    Workflow::parse(value).ok_or_else(|| {
        PipelineError::BadRequest(format!("X-AB-Workflow must be signed or unsigned, got {value:?}"))
    })
}

fn last_message_text(payload: &Value) -> String {
    payload
        .get("messages")
        .and_then(Value::as_array)
        .and_then(|messages| messages.last())
        .and_then(|message| message.get("content"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// Human-readable JSON type name for diagnostics — mirrors `typeof` in
/// JS. Used by [`atif_capture_from_request`] to say
/// `'messages' must be a JSON array, got object` rather than the
/// historical opaque `chat payload has no messages`.
fn json_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn atif_capture_from_request(payload: &Value) -> Result<AtifCapture, PipelineError> {
    // Split the two failure classes so support engineers can tell
    // "field missing" from "field is the wrong shape" — chasing a
    // phantom "no messages" ticket for a caller who typed
    // `"messages": {}` used to be the top diagnostic-quality complaint
    // (round-11 F7). The OpenAI Responses API also uses `input`
    // instead of `messages`; the missing-field message now points
    // directly at the correct fix.
    let messages_value = payload
        .get("messages")
        .ok_or_else(|| PipelineError::BadRequest("chat payload is missing 'messages'".to_owned()))?;
    let messages = messages_value.as_array().ok_or_else(|| {
        PipelineError::BadRequest(format!(
            "'messages' must be a JSON array, got {}",
            json_type_name(messages_value)
        ))
    })?;
    let message = messages
        .last()
        .ok_or_else(|| PipelineError::BadRequest("chat payload 'messages' is empty".to_owned()))?;
    let role = message.get("role").and_then(Value::as_str);
    let source = match role {
        Some("system" | "developer" | "tool") => ab_atif::Source::System,
        Some("user") => ab_atif::Source::User,
        Some("assistant") => ab_atif::Source::Agent,
        Some(other) => {
            return Err(PipelineError::BadRequest(format!(
                "unsupported chat role {other:?}"
            )))
        }
        None => return Err(PipelineError::BadRequest("chat message has no role".to_owned())),
    };
    let content = message
        .get("content")
        .filter(|value| value.is_string() || value.is_array())
        .cloned()
        .unwrap_or_else(|| Value::String(String::new()));
    let tool_calls = message.get("tool_calls").and_then(Value::as_array).map(|calls| {
        calls
            .iter()
            .filter_map(|call| {
                let function = call.get("function")?;
                let arguments = function
                    .get("arguments")
                    .cloned()
                    .unwrap_or(Value::Object(Default::default()));
                let arguments = arguments
                    .as_str()
                    .and_then(|raw| serde_json::from_str(raw).ok())
                    .unwrap_or(arguments);
                Some(ab_atif::ToolCall {
                    tool_call_id: call
                        .get("id")
                        .and_then(Value::as_str)
                        .map_or_else(ab_core::new_event_uid, str::to_owned),
                    function_name: function.get("name")?.as_str()?.to_owned(),
                    arguments,
                    extra: None,
                })
            })
            .collect()
    });
    let observation = (role == Some("tool")).then(|| ab_atif::Observation {
        results: vec![ab_atif::ObservationResult {
            source_call_id: None,
            content: Some(content.clone()),
            subagent_trajectory_ref: None,
            extra: message
                .get("tool_call_id")
                .cloned()
                .map(|tool_call_id| serde_json::json!({"tool_call_id": tool_call_id})),
        }],
    });
    Ok(AtifCapture {
        source,
        message: content,
        reasoning_content: if source == ab_atif::Source::Agent {
            message
                .get("reasoning_content")
                .and_then(Value::as_str)
                .map(str::to_owned)
        } else {
            None
        },
        model_name: if source == ab_atif::Source::Agent {
            payload.get("model").and_then(Value::as_str).map(str::to_owned)
        } else {
            None
        },
        tool_calls: if source == ab_atif::Source::Agent {
            tool_calls
        } else {
            None
        },
        observation,
        llm_call_count: (source == ab_atif::Source::Agent).then_some(1),
    })
}

fn validate_session_binding(
    session: &Session,
    workflow: Workflow,
    identity: &AgentIdentity,
) -> Result<(), PipelineError> {
    if session.workflow != workflow {
        return Err(PipelineError::BadRequest(
            "session workflow cannot change after open".to_owned(),
        ));
    }
    if session.identity.instance_uid != identity.instance_uid
        || session.identity.charter != identity.charter
        || session.identity.version != identity.version
    {
        return Err(PipelineError::Unauthorized(
            "session is bound to a different agent identity".to_owned(),
        ));
    }
    Ok(())
}

fn scope_allows(scopes: &[String], required: &str) -> bool {
    scopes.iter().any(|scope| {
        scope == "*"
            || scope == required
            || scope
                .strip_suffix(":*")
                .is_some_and(|prefix| required.starts_with(&format!("{prefix}:")))
    })
}

fn inject_corrective_message(payload: &mut Value) -> Result<(), PipelineError> {
    let messages = payload
        .get_mut("messages")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| PipelineError::BadRequest("chat payload has no messages array".to_owned()))?;
    messages.push(serde_json::json!({
        "role": "system",
        "content": "AgentBridge detected a semantic loop. Stop repeating the previous approach, identify new evidence, and choose a materially different next action."
    }));
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::unwrap_used
    )]

    use super::*;
    use ab_bridge::{BusError, PublishAck, StoredEvent};
    use ab_receipts::Ed25519Signer;
    use ab_sandbox::SandboxConfig;
    use ab_state::InMemoryStore;
    use axum::http::HeaderValue;
    use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};

    struct NullBus;

    struct BlockingSink {
        entered: AtomicBool,
        release: tokio::sync::Notify,
    }

    impl VectorSink for BlockingSink {
        fn record<'a>(
            &'a self,
            _session_id: &'a str,
            _vector: &'a [f32],
        ) -> ab_loopdetect::VectorSinkFuture<'a> {
            Box::pin(async move {
                self.entered.store(true, AtomicOrdering::Release);
                self.release.notified().await;
                Ok(())
            })
        }
    }

    impl EventBus for NullBus {
        fn publish(&self, topic: &str, _key: &str, _value: &Value) -> Result<PublishAck, BusError> {
            Ok(PublishAck {
                topic: topic.to_owned(),
                partition: 0,
                offset: 0,
            })
        }

        fn fetch(
            &self,
            _topic: &str,
            _partition: u32,
            _offset: u64,
            _max: usize,
        ) -> Result<Vec<StoredEvent>, BusError> {
            Ok(Vec::new())
        }

        fn partitions(&self, _topic: &str) -> Result<u32, BusError> {
            Ok(1)
        }

        fn topics(&self) -> Vec<String> {
            EventClass::all()
                .iter()
                .map(|class| class.topic().to_owned())
                .collect()
        }
    }

    fn state(mut config: HarnessConfig) -> AppState {
        config.atif_spool_dir = tempfile::tempdir().unwrap().keep().to_string_lossy().into_owned();
        AppState::new(
            config,
            Arc::new(InMemoryStore::new()),
            Arc::new(Sandbox::new(SandboxConfig::default(), Vec::new()).unwrap()),
            Arc::new(NullBus),
            None,
            Arc::new(Ed25519Signer::from_seed([9; 32])),
        )
        .unwrap()
    }

    fn payload() -> Value {
        serde_json::json!({
            "model": "test",
            "messages": [{"role": "user", "content": "hello"}],
        })
    }

    async fn trip_loop(state: &AppState, headers: &HeaderMap, repeated: &Value) {
        for expected in 1..=4u64 {
            state.prepare_chat(headers, repeated.clone()).unwrap();
            let session = state.sessions.get("loop-session").unwrap();
            // Generous budget: the chain append rides an async worker job and
            // must survive heavily loaded parallel test runs.
            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                while session.chain.lock().count() < expected {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
        }
    }

    #[tokio::test]
    async fn prepare_binds_session_and_stays_below_hot_path_budget() {
        let config = HarnessConfig::for_tests("http://127.0.0.1:9", "/tmp", "/tmp");
        let state = state(config);
        let mut headers = HeaderMap::new();
        headers.insert(SESSION_HEADER, HeaderValue::from_static("session-1"));

        let prepared = state.prepare_chat(&headers, payload()).unwrap();
        assert_eq!(prepared.session.id, "session-1");
        // Debug-build ceiling: 100ms is 3 orders of magnitude above the release
        // SLA (~33us p95); a regression an order of magnitude worse still trips
        // this. The strict perf gate lives in the SLA bench suite.
        assert!(
            prepared.middleware_us < 100_000,
            "middleware took {}us",
            prepared.middleware_us
        );
        assert!(state.metrics.render().contains("ab_stage_duration_seconds"));
    }

    #[tokio::test]
    async fn missing_identity_fails_closed_when_required() {
        let mut config = HarnessConfig::for_tests("http://127.0.0.1:9", "/tmp", "/tmp");
        config.require_identity = true;
        let error = match state(config).prepare_chat(&HeaderMap::new(), payload()) {
            Ok(_) => panic!("missing identity was accepted"),
            Err(error) => error,
        };
        assert!(matches!(error, PipelineError::Unauthorized(_)));
    }

    #[tokio::test]
    async fn token_quota_blocks_before_dispatch() {
        let mut config = HarnessConfig::for_tests("http://127.0.0.1:9", "/tmp", "/tmp");
        config.budget.max_tokens = Some(1);
        let state = state(config);
        let mut headers = HeaderMap::new();
        headers.insert(SESSION_HEADER, HeaderValue::from_static("quota-failure"));
        let error = match state.prepare_chat(&headers, payload()) {
            Ok(_) => panic!("over-budget request was accepted"),
            Err(error) => error,
        };
        assert!(matches!(error, PipelineError::Blocked(_)));
        assert_eq!(state.sessions.len(), 1);
        let session = state.sessions.get("quota-failure").unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while session.atif.lock().is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn invalid_workflow_is_rejected() {
        let config = HarnessConfig::for_tests("http://127.0.0.1:9", "/tmp", "/tmp");
        let state = state(config);
        let mut headers = HeaderMap::new();
        headers.insert(WORKFLOW_HEADER, HeaderValue::from_static("sometimes"));
        assert!(matches!(
            state.prepare_chat(&headers, payload()),
            Err(PipelineError::BadRequest(_))
        ));
    }

    #[tokio::test]
    async fn open_session_cannot_change_workflow() {
        let config = HarnessConfig::for_tests("http://127.0.0.1:9", "/tmp", "/tmp");
        let state = state(config);
        let mut headers = HeaderMap::new();
        headers.insert(SESSION_HEADER, HeaderValue::from_static("bound-session"));
        headers.insert(WORKFLOW_HEADER, HeaderValue::from_static("signed"));
        state.prepare_chat(&headers, payload()).unwrap();
        headers.insert(WORKFLOW_HEADER, HeaderValue::from_static("unsigned"));
        assert!(matches!(
            state.prepare_chat(&headers, payload()),
            Err(PipelineError::BadRequest(_))
        ));
    }

    #[tokio::test]
    async fn asynchronous_loop_verdict_blocks_the_next_request() {
        let mut config = HarnessConfig::for_tests("http://127.0.0.1:9", "/tmp", "/tmp");
        config.breaker.min_tokens = 0;
        let state = state(config);
        let mut headers = HeaderMap::new();
        headers.insert(SESSION_HEADER, HeaderValue::from_static("loop-session"));
        headers.insert(WORKFLOW_HEADER, HeaderValue::from_static("signed"));
        let repeated = serde_json::json!({
            "model": "test",
            "messages": [{
                "role": "assistant",
                "content": "I should check the database again for pending orders"
            }]
        });
        trip_loop(&state, &headers, &repeated).await;
        assert!(matches!(
            state.prepare_chat(&headers, repeated),
            Err(PipelineError::Blocked(_))
        ));
    }

    #[tokio::test]
    async fn loop_inject_action_adds_correction_and_resets_breaker() {
        let mut config = HarnessConfig::for_tests("http://127.0.0.1:9", "/tmp", "/tmp");
        config.breaker.min_tokens = 0;
        config.breaker.action = BreakerAction::Inject;
        let state = state(config);
        let mut headers = HeaderMap::new();
        headers.insert(SESSION_HEADER, HeaderValue::from_static("loop-session"));
        headers.insert(WORKFLOW_HEADER, HeaderValue::from_static("signed"));
        let repeated = serde_json::json!({
            "messages": [{"role": "assistant", "content": "repeat the database query"}]
        });
        trip_loop(&state, &headers, &repeated).await;
        let prepared = state.prepare_chat(&headers, repeated).unwrap();
        let correction = prepared
            .payload
            .get("messages")
            .and_then(Value::as_array)
            .and_then(|messages| messages.last())
            .and_then(|message| message.get("content"))
            .and_then(Value::as_str)
            .unwrap();
        assert!(correction.contains("semantic loop"));
        assert_eq!(prepared.session.loop_state.state(), BreakerState::Closed);
    }

    #[tokio::test]
    async fn loop_abort_action_returns_abort_error() {
        let mut config = HarnessConfig::for_tests("http://127.0.0.1:9", "/tmp", "/tmp");
        config.breaker.min_tokens = 0;
        config.breaker.action = BreakerAction::Abort;
        let state = state(config);
        let mut headers = HeaderMap::new();
        headers.insert(SESSION_HEADER, HeaderValue::from_static("loop-session"));
        headers.insert(WORKFLOW_HEADER, HeaderValue::from_static("signed"));
        let repeated = serde_json::json!({
            "messages": [{"role": "assistant", "content": "repeat the database query"}]
        });
        trip_loop(&state, &headers, &repeated).await;
        assert!(matches!(
            state.prepare_chat(&headers, repeated),
            Err(PipelineError::Abort(_))
        ));
    }

    /// A breaker trip used to replace the job's Compression class with
    /// StopReason *before* the accounting decisions ran, so the tripped
    /// admission's prompt tokens vanished from the session totals (and the
    /// journal record) — receipts undercounted exactly the runaway sessions
    /// the breaker exists to attest. Accounting must key on the submitted
    /// class, not the swapped one.
    #[tokio::test]
    async fn breaker_trip_does_not_drop_the_admissions_prompt_token_accounting() {
        let mut config = HarnessConfig::for_tests("http://127.0.0.1:9", "/tmp", "/tmp");
        config.breaker.min_tokens = 0;
        let state = state(config);
        let mut headers = HeaderMap::new();
        headers.insert(SESSION_HEADER, HeaderValue::from_static("loop-session"));
        headers.insert(WORKFLOW_HEADER, HeaderValue::from_static("signed"));
        let repeated = serde_json::json!({
            "model": "test",
            "messages": [{
                "role": "assistant",
                "content": "I should check the database again for pending orders"
            }]
        });
        // Four identical admissions, tracking chain growth like `trip_loop`;
        // the breaker trips on one of the later worker jobs. Capture the
        // per-admission token amount after the first job lands.
        let mut per_request = 0u64;
        for expected in 1..=4u64 {
            state.prepare_chat(&headers, repeated.clone()).unwrap();
            let session = state.sessions.get("loop-session").unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                while session.chain.lock().count() < expected {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            if expected == 1 {
                tokio::time::timeout(std::time::Duration::from_secs(10), session.wait_for_worker_jobs())
                    .await
                    .unwrap();
                per_request = session
                    .totals
                    .prompt_tokens
                    .load(std::sync::atomic::Ordering::Acquire);
                assert!(per_request > 0, "admission must account prompt tokens");
            }
        }
        let session = state.sessions.get("loop-session").unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(10), session.wait_for_worker_jobs())
            .await
            .unwrap();
        assert_eq!(
            session.loop_state.state(),
            BreakerState::Open,
            "precondition: the breaker must have tripped during the four admissions",
        );
        assert_eq!(
            session
                .totals
                .prompt_tokens
                .load(std::sync::atomic::Ordering::Acquire),
            per_request * 4,
            "every admission's prompt tokens must be accounted, including the one whose \
             worker job carried the breaker trip",
        );
    }

    /// Budget counters are dead weight once a session is sealed (admission
    /// rejects closed sessions before any quota check); finalization must
    /// clear them or the in-memory state store grows by a few cells per
    /// client-chosen session id forever.
    #[tokio::test]
    async fn finalization_clears_the_sessions_budget_counters() {
        let store: Arc<dyn StateStore> = Arc::new(InMemoryStore::new());
        let mut config = HarnessConfig::for_tests("http://127.0.0.1:9", "/tmp", "/tmp");
        config.budget.max_tokens = Some(1_000_000);
        config.atif_spool_dir = tempfile::tempdir().unwrap().keep().to_string_lossy().into_owned();
        let state = AppState::new(
            config,
            Arc::clone(&store),
            Arc::new(Sandbox::new(SandboxConfig::default(), Vec::new()).unwrap()),
            Arc::new(NullBus),
            None,
            Arc::new(Ed25519Signer::from_seed([9; 32])),
        )
        .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(SESSION_HEADER, HeaderValue::from_static("budget-cleanup"));
        state.prepare_chat(&headers, payload()).unwrap();
        let tokens_key = format!(
            "{}tokens",
            ab_state::ActionBudget::session_prefix("budget-cleanup")
        );
        assert!(
            store.get(&tokens_key).unwrap() > 0,
            "precondition: admission must have spent from the token budget",
        );
        let session = state.sessions.get("budget-cleanup").unwrap();
        session.wait_for_worker_jobs().await;
        state
            .finalizer
            .close_session(session, StopReason::SessionClosed)
            .await
            .unwrap();
        assert_eq!(
            store.get(&tokens_key).unwrap(),
            0,
            "finalization must remove the sealed session's budget counters",
        );
    }

    #[tokio::test]
    async fn consequential_tools_require_signed_workflows() {
        let config = HarnessConfig::for_tests("http://127.0.0.1:9", "/tmp", "/tmp");
        let state = state(config);
        let raw = serde_json::to_vec(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "db_write", "arguments": {}}
        }))
        .unwrap();
        let mut unsigned = HeaderMap::new();
        unsigned.insert(SESSION_HEADER, HeaderValue::from_static("unsigned-write"));
        assert!(matches!(
            state.intercept_tool(&unsigned, &raw).unwrap(),
            ToolVerdict::Blocked { stage: "policy", .. }
        ));

        let mut signed = HeaderMap::new();
        signed.insert(SESSION_HEADER, HeaderValue::from_static("signed-write"));
        signed.insert(WORKFLOW_HEADER, HeaderValue::from_static("signed"));
        assert!(state.intercept_tool(&signed, &raw).unwrap().is_allowed());
    }

    /// `intercept_tool_durable` used to re-derive the session id from headers
    /// AFTER the verdict. For a header-less request `session_id()` mints a
    /// fresh random id on every call, so the post-verdict lookup targeted a
    /// session that never existed and the call always failed with "tool
    /// session disappeared" — after the verdict had already been computed and
    /// audited under the real (generated) session.
    #[tokio::test]
    async fn intercept_tool_durable_works_without_a_session_header() {
        let config = HarnessConfig::for_tests("http://127.0.0.1:9", "/tmp", "/tmp");
        let state = state(config);
        let raw = serde_json::to_vec(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "safe_tool", "arguments": {}}
        }))
        .unwrap();
        let verdict = state
            .intercept_tool_durable(&HeaderMap::new(), &raw)
            .await
            .unwrap();
        assert!(
            verdict.is_allowed(),
            "durable interception must await the verdict's own session, not a re-derived id",
        );
    }

    /// When `prepare_chat_durable` refuses a request AFTER admission (the
    /// request's own loop analysis opened the breaker during the audit wait),
    /// it must submit the terminal failure record for the response attempt
    /// journaled at admission. Otherwise the active journal ends with a
    /// dangling non-terminal attempt and a later crash-recovery scan
    /// quarantines the session over a request the client already saw fail.
    #[tokio::test]
    async fn durable_breaker_refusal_journals_a_terminal_response_attempt() {
        let mut config = HarnessConfig::for_tests("http://127.0.0.1:9", "/tmp", "/tmp");
        config.breaker.min_tokens = 0;
        let state = state(config);
        let mut headers = HeaderMap::new();
        headers.insert(SESSION_HEADER, HeaderValue::from_static("durable-loop"));
        headers.insert(WORKFLOW_HEADER, HeaderValue::from_static("signed"));
        let repeated = serde_json::json!({
            "model": "test",
            "messages": [{
                "role": "assistant",
                "content": "I should check the database again for pending orders"
            }],
        });
        // Attempts the test itself abandons after a successful prepare: they
        // are expected to stay non-terminal because no forward happens here.
        let mut abandoned_by_test = std::collections::HashSet::new();
        let mut refusal = None;
        for _ in 0..8 {
            match state.prepare_chat_durable(&headers, repeated.clone()).await {
                Ok(prepared) => {
                    abandoned_by_test.insert(prepared.response_attempt_id.clone());
                }
                Err(error) => {
                    refusal = Some(error);
                    break;
                }
            }
        }
        assert!(
            matches!(refusal, Some(PipelineError::Blocked(_))),
            "the breaker must refuse during the audit wait, got {refusal:?}",
        );
        assert!(
            !abandoned_by_test.is_empty(),
            "at least one prepare must succeed first"
        );
        let session = state.sessions.get("durable-loop").unwrap();
        session.wait_for_worker_jobs().await;

        let digest = ab_core::digest::sha256_hex("durable-loop".as_bytes());
        let stem = digest.get(..32).unwrap();
        let journal_path =
            std::path::Path::new(&state.config.atif_spool_dir).join(format!("{stem}.events.ndjson"));
        let journal = std::fs::read_to_string(&journal_path).unwrap();
        let mut dangling = std::collections::HashSet::new();
        for (index, line) in journal.lines().enumerate() {
            let record: crate::worker::ActiveJournalRecord = crate::journal::open(
                &state.journal_key,
                "durable-loop:active",
                index as u64,
                line.as_bytes(),
            )
            .unwrap();
            if let Some(attempt) = record.response_attempt {
                if attempt.terminal {
                    assert!(
                        dangling.remove(&attempt.id),
                        "terminal record for attempt {} has no admission record",
                        attempt.id,
                    );
                } else {
                    dangling.insert(attempt.id);
                }
            }
        }
        assert_eq!(
            dangling, abandoned_by_test,
            "the refused request's response attempt must be terminated in the journal; \
             only attempts the test itself dropped may remain open",
        );
    }

    /// A session that only routes MCP tool calls (no chat completions) must
    /// still be considered active by `idle_sessions` — otherwise the
    /// reconciler tick force-closes tool-only sessions after
    /// `session_idle_close_s` and every subsequent tool call fails with
    /// "session is already closed". `prepare_chat` refreshes
    /// `last_activity_ms` via `touch()`; `intercept_tool` did not.
    #[tokio::test]
    async fn intercept_tool_refreshes_session_activity() {
        use std::sync::atomic::Ordering as AtomicOrdering;

        let config = HarnessConfig::for_tests("http://127.0.0.1:9", "/tmp", "/tmp");
        let state = state(config);
        let raw = serde_json::to_vec(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "safe_tool", "arguments": {}}
        }))
        .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(SESSION_HEADER, HeaderValue::from_static("tool-only-session"));
        headers.insert(WORKFLOW_HEADER, HeaderValue::from_static("signed"));

        state.intercept_tool(&headers, &raw).unwrap();
        let session = state.sessions.get("tool-only-session").unwrap();
        // Backdate the session to before the epoch's first second — this stands
        // in for a real session that has been quiet long enough to hit the
        // idle sweeper's cutoff.
        session.last_activity_ms.store(0, AtomicOrdering::Release);

        state.intercept_tool(&headers, &raw).unwrap();

        let refreshed = session.last_activity_ms.load(AtomicOrdering::Acquire);
        assert!(
            refreshed > 0,
            "intercept_tool must refresh last_activity_ms so a tool-only session is not force-closed by the idle sweeper — got {refreshed}",
        );
    }

    /// `intercept_tool` used to call `sandbox.check` unconditionally and then
    /// post-hoc override an `Allowed` verdict to `Blocked` when the workflow
    /// gate vetoes a consequential tool on an unsigned session. But
    /// `sandbox.check`'s budget gate (`try_spend_many`) spends before the
    /// override runs, so a legitimate client asking for a consequential tool
    /// on the wrong workflow got their `max_total_tool_calls` counter
    /// decremented for a call the sandbox never actually authorized. Once the
    /// client upgraded to a signed session to make the call for real, they
    /// hit the cap short of the number they were configured for.
    #[tokio::test]
    async fn unsigned_consequential_veto_does_not_spend_budget() {
        let store: Arc<dyn StateStore> = Arc::new(InMemoryStore::new());
        let sandbox_config = SandboxConfig {
            budget: ab_state::BudgetSpec {
                max_total_tool_calls: Some(5),
                ..ab_state::BudgetSpec::default()
            },
            ..SandboxConfig::default()
        };
        let sandbox = Arc::new(Sandbox::new(sandbox_config, Vec::new()).unwrap());
        let mut config = HarnessConfig::for_tests("http://127.0.0.1:9", "/tmp", "/tmp");
        config.atif_spool_dir = tempfile::tempdir().unwrap().keep().to_string_lossy().into_owned();
        let state = AppState::new(
            config,
            Arc::clone(&store),
            sandbox,
            Arc::new(NullBus),
            None,
            Arc::new(Ed25519Signer::from_seed([9; 32])),
        )
        .unwrap();

        let raw = serde_json::to_vec(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "db_write", "arguments": {}}
        }))
        .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(SESSION_HEADER, HeaderValue::from_static("unsigned-consequential"));
        // Default workflow is unsigned; no explicit x-ab-workflow header.

        let verdict = state.intercept_tool(&headers, &raw).unwrap();
        assert!(
            matches!(verdict, ToolVerdict::Blocked { stage: "policy", .. }),
            "consequential tool on unsigned workflow must block at the policy gate; got {verdict:?}",
        );

        let session_digest = ab_core::digest::sha256_hex("unsigned-consequential".as_bytes());
        let key = format!("budget:{{{}}}:total_calls", session_digest.get(..32).unwrap());
        let count = store.get(&key).unwrap();
        assert_eq!(
            count, 0,
            "sandbox.check must not spend the budget for a call the workflow gate vetoes — otherwise a legitimate client that upgrades to signed and retries hits the cap short of the configured limit",
        );
    }

    #[tokio::test]
    async fn full_capture_queue_fails_closed_before_upstream() {
        let mut config = HarnessConfig::for_tests("http://127.0.0.1:9", "/tmp", "/tmp");
        // The fused permit split (worker_capacity + response_capacity)
        // gives distinct exhaustion counters but keeps the *effective*
        // total admission the same as before, because response
        // capture doesn't hold an mpsc slot up front — only the
        // response semaphore. So with worker_channel_capacity=2 the
        // first request consumes 1 worker semaphore + 1 response
        // semaphore + 1 mpsc slot; the second request consumes the
        // remaining worker semaphore + response semaphore + mpsc slot;
        // the third would fail. Set to 1 for a clean single-request
        // saturation.
        config.worker_channel_capacity = 1;
        config.breaker.min_tokens = u64::MAX;
        let sink = Arc::new(BlockingSink {
            entered: AtomicBool::new(false),
            release: tokio::sync::Notify::new(),
        });
        let state = AppState::new_with_backends(
            config,
            Arc::new(InMemoryStore::new()),
            Arc::new(Sandbox::new(SandboxConfig::default(), Vec::new()).unwrap()),
            Arc::new(NullBus),
            None,
            Arc::new(Ed25519Signer::from_seed([10; 32])),
            Arc::new(HashEmbedder::default()),
            sink.clone(),
        )
        .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(SESSION_HEADER, HeaderValue::from_static("overload"));
        headers.insert(WORKFLOW_HEADER, HeaderValue::from_static("signed"));
        let mut agent_payload = payload();
        agent_payload["messages"][0]["role"] = Value::String("assistant".to_owned());
        state.prepare_chat(&headers, agent_payload.clone()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while !sink.entered.load(AtomicOrdering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(matches!(
            state.prepare_chat(&headers, agent_payload),
            Err(PipelineError::Unavailable(_))
        ));
        sink.release.notify_waiters();
    }

    #[test]
    fn identity_scope_matching_supports_exact_and_namespace_wildcards() {
        assert!(scope_allows(&["chat:write".into()], "chat:write"));
        assert!(scope_allows(&["tool:*".into()], "tool:db_write"));
        assert!(scope_allows(&["*".into()], "session:promote"));
        assert!(!scope_allows(&["chat:read".into()], "chat:write"));
        assert!(!scope_allows(&["tooling:*".into()], "tool:db_write"));
    }

    #[test]
    fn developer_and_tool_roles_map_to_valid_system_steps() {
        for (role, expects_observation) in [("developer", false), ("tool", true)] {
            let capture = atif_capture_from_request(&serde_json::json!({
                "messages": [{
                    "role": role,
                    "content": "context",
                    "tool_call_id": "call-1"
                }]
            }))
            .unwrap();
            assert_eq!(capture.source, ab_atif::Source::System);
            assert_eq!(capture.observation.is_some(), expects_observation);
            assert!(capture.model_name.is_none());
        }
    }

    /// Round-11 F7: `messages` field with the wrong type used to return
    /// the same "chat payload has no messages" as an absent field,
    /// steering support tickets at a phantom bug. Verify each class
    /// now returns a discriminating error message.
    #[test]
    fn atif_capture_rejects_non_array_messages_with_precise_diagnostics() {
        fn bad_request_message(payload: serde_json::Value) -> String {
            match atif_capture_from_request(&payload) {
                Ok(_) => panic!("expected BadRequest, got Ok"),
                Err(PipelineError::BadRequest(msg)) => msg,
                Err(other) => panic!("expected BadRequest, got {other:?}"),
            }
        }
        // (1) Field entirely missing (e.g., OpenAI Responses API caller
        //     who used `input` instead of `messages`).
        let msg = bad_request_message(serde_json::json!({
            "input": [{ "role": "user", "content": "hi" }]
        }));
        assert!(msg.contains("missing 'messages'"), "got {msg}");
        // (2) Field present but wrong JSON shape — object.
        let msg = bad_request_message(serde_json::json!({
            "messages": { "0": { "role": "user", "content": "hi" } }
        }));
        assert!(msg.contains("must be a JSON array"), "got {msg}");
        assert!(msg.contains("object"), "got {msg}");
        // (3) Field present, is an array, but empty.
        let msg = bad_request_message(serde_json::json!({ "messages": [] }));
        assert!(msg.contains("empty"), "got {msg}");
    }

    /// Round-13: multiple X-AB-Session (or X-AB-Workflow) headers on
    /// a single request must be refused. HeaderMap::get() returns
    /// only the first, so an intermediary that merges duplicates on
    /// the wire and downstream code that reads them separately can
    /// disagree on which session id was in effect — a header
    /// smuggling desync. Refuse loudly at ingress.
    #[test]
    fn duplicate_x_ab_session_header_is_refused() {
        let mut headers = HeaderMap::new();
        headers.append(SESSION_HEADER, HeaderValue::from_static("sessA"));
        headers.append(SESSION_HEADER, HeaderValue::from_static("sessB"));
        match session_id(&headers) {
            Ok(id) => panic!("expected duplicate-header refusal, got session_id {id:?}"),
            Err(PipelineError::BadRequest(msg)) => {
                assert!(msg.contains("more than one"), "got {msg}");
                assert!(msg.contains("x-ab-session"), "got {msg}");
            }
            Err(other) => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn duplicate_x_ab_workflow_header_is_refused() {
        let mut headers = HeaderMap::new();
        headers.append(WORKFLOW_HEADER, HeaderValue::from_static("signed"));
        headers.append(WORKFLOW_HEADER, HeaderValue::from_static("unsigned"));
        match workflow(&headers, "signed") {
            Ok(w) => panic!("expected duplicate-header refusal, got workflow {w:?}"),
            Err(PipelineError::BadRequest(msg)) => {
                assert!(msg.contains("more than one"), "got {msg}");
                assert!(msg.contains("x-ab-workflow"), "got {msg}");
            }
            Err(other) => panic!("expected BadRequest, got {other:?}"),
        }
    }

    /// Single X-AB-Session must continue to work — this is the
    /// happy-path regression guard for the duplicate-header refusal.
    #[test]
    fn single_x_ab_session_header_still_flows() {
        let mut headers = HeaderMap::new();
        headers.insert(SESSION_HEADER, HeaderValue::from_static("only-one"));
        assert_eq!(session_id(&headers).unwrap(), "only-one");
    }

    /// Round-14 F1: identity hot path (`resolve_identity`) must refuse
    /// duplicate `Authorization` headers, symmetric with X-AB-Session.
    /// Previously `HeaderMap::get(AUTHORIZATION)` returned the first
    /// value only — the harness would authenticate as `A` while
    /// log aggregators / WAFs seeing a merged `A, B` form would
    /// attribute the request to `B`. This is the identity split-brain
    /// round-13 tried to close for session headers.
    #[tokio::test]
    async fn resolve_identity_refuses_duplicate_authorization_header() {
        let state = null_state();
        let mut headers = HeaderMap::new();
        headers.append(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer aaaa"),
        );
        headers.append(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer bbbb"),
        );
        match state.resolve_identity(&headers, None) {
            Ok(_) => panic!("expected duplicate-header refusal, got Ok"),
            Err(PipelineError::BadRequest(msg)) => {
                assert!(msg.contains("more than one"), "got {msg}");
                assert!(msg.contains("authorization"), "got {msg}");
            }
            Err(other) => panic!("expected BadRequest, got {other:?}"),
        }
    }

    /// Single-value Authorization still flows through (happy-path
    /// regression guard for the dedup refusal).
    #[tokio::test]
    async fn resolve_identity_accepts_single_authorization_header() {
        let state = null_state();
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer aaaa"),
        );
        // No validator configured → refuse-401 fires per round-10 F3.
        // The important assertion is that we did NOT get a
        // BadRequest("more than one") on a single header.
        let outcome = state.resolve_identity(&headers, None);
        assert!(
            !matches!(&outcome, Err(PipelineError::BadRequest(msg)) if msg.contains("more than one")),
            "single Authorization header must not be refused as duplicate; got {outcome:?}"
        );
    }

    fn null_state() -> AppState {
        let mut config = HarnessConfig::for_tests("http://127.0.0.1:9", "/tmp", "/tmp");
        config.require_identity = false;
        let sandbox = Sandbox::new(SandboxConfig::default(), Vec::new()).unwrap();
        let store = Arc::new(InMemoryStore::new());
        let bridge: Arc<dyn EventBus> = Arc::new(NullBus);
        let signer: Arc<dyn Signer> = Arc::new(Ed25519Signer::generate());
        let embedder = Arc::new(HashEmbedder::default());
        let vector_sink: Arc<dyn VectorSink> = Arc::new(NoopVectorSink);
        AppState::new_with_backends(
            config,
            store,
            Arc::new(sandbox),
            bridge,
            None,
            signer,
            embedder,
            vector_sink,
        )
        .unwrap()
    }

    fn scoped_token(scopes: &[&str]) -> String {
        let now = ab_core::time::now_ms() / ab_core::units::MS_PER_SEC;
        let claims = ab_identity::NhiClaims {
            sub: "agent:test".into(),
            iss: "https://idp.example".into(),
            aud: "agent-bridge".into(),
            iat: now,
            nbf: None,
            exp: now + 600,
            jti: ab_core::new_event_uid(),
            instance_uid: "scoped-instance".into(),
            charter: "scoped-charter".into(),
            version: "1".into(),
            scopes: scopes.iter().map(|scope| (*scope).to_owned()).collect(),
            parent_token: None,
        };
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
        header.kid = Some("scope-key".into());
        jsonwebtoken::encode(
            &header,
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(b"scope-secret"),
        )
        .unwrap()
    }

    fn scoped_state() -> AppState {
        let mut config = HarnessConfig::for_tests("http://127.0.0.1:9", "/tmp", "/tmp");
        config.require_identity = true;
        config.enforce_identity_scopes = true;
        let validator = ab_identity::IdentityValidator::new("agent-bridge");
        validator.add_key(
            "scope-key",
            ab_identity::KeyMaterial::HmacSecret(b"scope-secret".to_vec()),
        );
        AppState::new(
            config,
            Arc::new(InMemoryStore::new()),
            Arc::new(Sandbox::new(SandboxConfig::default(), Vec::new()).unwrap()),
            Arc::new(NullBus),
            Some(Arc::new(validator)),
            Arc::new(Ed25519Signer::from_seed([12; 32])),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn real_jwt_scopes_gate_chat_and_lifecycle_operations() {
        let state = scoped_state();
        let mut headers = HeaderMap::new();
        headers.insert(SESSION_HEADER, HeaderValue::from_static("scoped-session"));
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", scoped_token(&["chat:write"]))).unwrap(),
        );
        let prepared = state.prepare_chat(&headers, payload()).unwrap();
        assert!(matches!(
            state.authorize_session(&headers, &prepared.session, "session:close"),
            Err(PipelineError::Unauthorized(_))
        ));
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_str(&format!(
                "Bearer {}",
                scoped_token(&["chat:write", "session:close"])
            ))
            .unwrap(),
        );
        state
            .authorize_session(&headers, &prepared.session, "session:close")
            .unwrap();
    }

    #[tokio::test]
    async fn upstream_failure_is_added_to_signed_chain() {
        let config = HarnessConfig::for_tests("http://127.0.0.1:9", "/tmp", "/tmp");
        let state = state(config);
        let mut headers = HeaderMap::new();
        headers.insert(SESSION_HEADER, HeaderValue::from_static("upstream-failure"));
        headers.insert(WORKFLOW_HEADER, HeaderValue::from_static("signed"));
        let prepared = state.prepare_chat(&headers, payload()).unwrap();
        let session = Arc::clone(&prepared.session);
        assert!(matches!(
            state.forward_chat(prepared).await,
            Err(PipelineError::Upstream(_))
        ));
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while session.chain.lock().count() < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    /// Regression lock for CWE-209 information exposure. Before the fix,
    /// `PipelineError::Upstream(reqwest_err.to_string())` embedded the
    /// operator-configured upstream URL in the JSON error body — any client
    /// that triggered an upstream failure could discover the URL, potentially
    /// leaking an internal hostname. The client-facing message must now be a
    /// stable category ("upstream unreachable", "upstream timed out", …) that
    /// does not depend on the URL.
    #[tokio::test]
    async fn upstream_failure_message_does_not_leak_configured_url() {
        // Use a distinctive private-network host so a regression is unmissable
        // in the assertion below.
        let sentinel_url = "http://internal-sentinel-host.corp.example:65001";
        let config = HarnessConfig::for_tests(sentinel_url, "/tmp", "/tmp");
        let state = state(config);
        let mut headers = HeaderMap::new();
        headers.insert(SESSION_HEADER, HeaderValue::from_static("cwe-209-check"));
        headers.insert(WORKFLOW_HEADER, HeaderValue::from_static("signed"));
        let prepared = state.prepare_chat(&headers, payload()).unwrap();
        let error = match state.forward_chat(prepared).await {
            Ok(_) => panic!("connect to unroutable host must fail"),
            Err(error) => error,
        };
        let message = error.to_string();
        assert!(
            !message.contains("internal-sentinel-host"),
            "upstream error message {message:?} leaks the configured URL"
        );
        assert!(
            !message.contains("65001"),
            "upstream error message {message:?} leaks the configured port"
        );
        assert!(
            !message.contains("corp.example"),
            "upstream error message {message:?} leaks the configured domain"
        );
    }

    /// Regression lock for CWE-209 information exposure. Before the fix,
    /// `PipelineError::Unauthorized(identity_err.to_string())` embedded the
    /// specific `IdentityError` variant's `Display` text in the JSON error
    /// body. Because that text distinguishes at least sixteen distinct
    /// failure modes — and echoes the attacker-supplied `kid`, `iss`, and
    /// `alg` values — each response became an enumeration oracle: an
    /// attacker could iterate candidate `kid`s and read the response body
    /// to discover which are configured on our validator. The client-facing
    /// message must now be a single stable string, and must never echo
    /// attacker-controlled token fields.
    #[test]
    fn identity_validation_failure_does_not_leak_kid_or_issuer() {
        // Every variant that an attacker can reach via a crafted token must
        // classify to exactly the same client-facing string. Any divergence
        // is an enumeration oracle for validator configuration.
        //
        // Sentinels that would appear in the raw `Display` output are
        // asserted absent — this catches accidental future variants that
        // slip through the `_` catch-all with a different classification.
        let sentinel_kid = "sentinel-attacker-kid";
        let sentinel_iss = "https://sentinel-attacker-iss.example.invalid";
        let sentinel_alg = "HS512";
        let cases: Vec<(&'static str, ab_identity::IdentityError)> = vec![
            (
                "Malformed",
                ab_identity::IdentityError::Malformed("jwt parse".into()),
            ),
            ("MissingKid", ab_identity::IdentityError::MissingKid),
            (
                "UnknownKid",
                ab_identity::IdentityError::UnknownKid(sentinel_kid.into()),
            ),
            (
                "AlgorithmRejected",
                ab_identity::IdentityError::AlgorithmRejected {
                    alg: sentinel_alg.into(),
                    kid: sentinel_kid.into(),
                },
            ),
            (
                "Verification",
                ab_identity::IdentityError::Verification("bad sig".into()),
            ),
            ("TtlTooLong", ab_identity::IdentityError::TtlTooLong(9999)),
            (
                "BadTimestamps",
                ab_identity::IdentityError::BadTimestamps { iat: 10, exp: 5 },
            ),
            (
                "FutureIat",
                ab_identity::IdentityError::FutureIat {
                    iat: 999_999_999,
                    now: 1,
                },
            ),
            ("EmptyField", ab_identity::IdentityError::EmptyField("charter")),
            (
                "SpoofingCharacter",
                ab_identity::IdentityError::SpoofingCharacter("charter"),
            ),
            (
                "BadIssuer",
                ab_identity::IdentityError::BadIssuer(sentinel_iss.into()),
            ),
            (
                "ScopeEscalation",
                ab_identity::IdentityError::ScopeEscalation {
                    scope: "chat:write".into(),
                },
            ),
            (
                "ExpEscalation",
                ab_identity::IdentityError::ExpEscalation {
                    child: 100,
                    parent: 50,
                },
            ),
            ("ChainTooDeep", ab_identity::IdentityError::ChainTooDeep(5)),
        ];

        let mut classifications: std::collections::BTreeSet<&'static str> = std::collections::BTreeSet::new();
        for (name, error) in &cases {
            let client_msg = super::classify_identity_error(error);
            classifications.insert(client_msg);
            assert!(
                !client_msg.contains(sentinel_kid),
                "{name}: client message {client_msg:?} echoes attacker kid"
            );
            assert!(
                !client_msg.contains(sentinel_iss),
                "{name}: client message {client_msg:?} echoes attacker iss"
            );
            assert!(
                !client_msg.contains(sentinel_alg),
                "{name}: client message {client_msg:?} echoes attacker alg"
            );
            // The full PipelineError as rendered to the client must also
            // not leak — this is what actually goes on the wire via
            // `pipeline_error()` -> `Json(json!({"error": err.to_string()}))`.
            let wire = PipelineError::Unauthorized(client_msg.to_owned()).to_string();
            assert!(
                !wire.contains(sentinel_kid),
                "{name}: wire error {wire:?} echoes attacker kid"
            );
            assert!(
                !wire.contains(sentinel_iss),
                "{name}: wire error {wire:?} echoes attacker iss"
            );
            assert!(
                !wire.contains(sentinel_alg),
                "{name}: wire error {wire:?} echoes attacker alg"
            );
        }
        // All attacker-reachable variants collapse to exactly one class —
        // the `Jwks` variant (server-side misconfig only, not on the
        // request path) may distinctly classify.
        assert_eq!(
            classifications.len(),
            1,
            "attacker-reachable IdentityError variants classify to multiple messages {classifications:?}: this is an enumeration oracle"
        );

        // And Jwks classifies distinctly (server-side, not attacker-reachable).
        let jwks_msg = super::classify_identity_error(&ab_identity::IdentityError::Jwks("bad jwks".into()));
        assert_ne!(
            jwks_msg,
            *classifications.iter().next().unwrap(),
            "server-side misconfig should classify distinctly for operator dashboards"
        );
    }

    /// The secret reader must fail loudly on missing/empty sources and
    /// trim whitespace — silent unauthenticated proxying is the worst
    /// failure mode because the operator sees only upstream 401s.
    #[test]
    fn read_secret_source_handling() {
        let env = |name: &str| -> Option<String> {
            match name {
                "GOOD_KEY" => Some("sk-live-123\n".into()),
                "EMPTY_KEY" => Some("   ".into()),
                _ => None,
            }
        };
        assert_eq!(
            super::read_secret_from(env, Some("GOOD_KEY"), None, "upstream API key")
                .unwrap()
                .as_deref(),
            Some("sk-live-123"),
            "value must be trimmed"
        );
        assert!(super::read_secret_from(env, Some("MISSING_KEY"), None, "upstream API key").is_err());
        assert!(super::read_secret_from(env, Some("EMPTY_KEY"), None, "upstream API key").is_err());
        assert!(super::read_secret_from(env, None, None, "upstream API key")
            .unwrap()
            .is_none());

        // File source: owner-only accepted (with trim), world-readable refused.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        std::fs::write(&path, "sk-file-456\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            let error = super::read_secret_from(env, None, path.to_str(), "upstream API key").unwrap_err();
            assert!(error.to_string().contains("must be owner-only"), "{error}");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert_eq!(
            super::read_secret_from(env, None, path.to_str(), "upstream API key")
                .unwrap()
                .as_deref(),
            Some("sk-file-456")
        );
        // Missing file is a hard error, not silent None.
        assert!(
            super::read_secret_from(env, None, dir.path().join("absent").to_str(), "upstream API key")
                .is_err()
        );
    }

    /// Auth resolution renders scheme-prefixed and raw header values,
    /// marks them sensitive, and never leaks the key through `describe`.
    #[test]
    fn upstream_auth_resolution_and_description() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("azure.key");
        std::fs::write(&key_path, "azure-raw-key").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        // Bearer scheme.
        let mut config = HarnessConfig::for_tests("http://up", "spool", "bridge");
        config.upstream_api_key_file = Some(key_path.to_string_lossy().into_owned());
        let (name, value) = super::resolve_upstream_auth(&config).unwrap().unwrap();
        assert_eq!(name.as_str(), "authorization");
        assert_eq!(value.to_str().unwrap(), "Bearer azure-raw-key");
        assert!(value.is_sensitive(), "credential must redact in Debug output");

        // Raw scheme (Azure api-key style).
        config.upstream_auth_header = "api-key".into();
        config.upstream_auth_scheme = String::new();
        let (name, value) = super::resolve_upstream_auth(&config).unwrap().unwrap();
        assert_eq!(name.as_str(), "api-key");
        assert_eq!(value.to_str().unwrap(), "azure-raw-key");

        // Description names the source but never the value.
        let described = super::describe_upstream_auth(&config);
        assert!(described.contains("api-key from file"), "{described}");
        assert!(!described.contains("azure-raw-key"), "{described}");

        // No auth configured resolves to None and describes as none.
        let bare = HarnessConfig::for_tests("http://up", "spool", "bridge");
        assert!(super::resolve_upstream_auth(&bare).unwrap().is_none());
        assert_eq!(super::describe_upstream_auth(&bare), "none");

        // Tool bearer renders Bearer form from a file source.
        let mut tooling = HarnessConfig::for_tests("http://up", "spool", "bridge");
        tooling.tool_upstream_url = Some("http://tools/mcp".into());
        tooling.tool_upstream_bearer_file = Some(key_path.to_string_lossy().into_owned());
        let bearer = super::resolve_tool_auth(&tooling).unwrap().unwrap();
        assert_eq!(bearer.to_str().unwrap(), "Bearer azure-raw-key");
        assert!(bearer.is_sensitive());
    }
}
