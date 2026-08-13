//! Ordered hot-path middleware and upstream forwarding.

use crate::config::HarnessConfig;
use crate::reconciler::Finalizer;
use crate::session::{Session, SessionLease, SessionRegistry, Workflow};
use crate::worker::{AtifCapture, WorkerHandle, WorkerJob, WorkerPermit};
use ab_bridge::EventBus;
use ab_core::metrics::Registry;
use ab_core::time::elapsed_us;
use ab_events::{AgentIdentity, EventClass, EventMetrics, StatusId, StopReason};
use ab_identity::IdentityValidator;
use ab_loopdetect::{BreakerAction, BreakerState, Embedder, HashEmbedder, NoopVectorSink, VectorSink};
use ab_receipts::Signer;
use ab_sandbox::{Sandbox, ToolVerdict};
use ab_state::{ActionBudget, BudgetDecision, StateStore};
use axum::http::HeaderMap;
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
    /// Asynchronous session close and promotion service.
    pub finalizer: Finalizer,
    pub(crate) journal_key: [u8; 32],
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
    response_permit: Option<WorkerPermit>,
    response_attempt_id: String,
}

/// Provider response paired with its active session lease.
pub struct ForwardedResponse {
    /// Provider HTTP response.
    pub response: reqwest::Response,
    pub(crate) lease: SessionLease,
    pub(crate) response_permit: Option<WorkerPermit>,
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
    pub fn status(&self) -> axum::http::StatusCode {
        match self {
            Self::BadRequest(_) => axum::http::StatusCode::BAD_REQUEST,
            Self::Unauthorized(_) => axum::http::StatusCode::UNAUTHORIZED,
            Self::Blocked(_) => axum::http::StatusCode::TOO_MANY_REQUESTS,
            Self::Upstream(_) => axum::http::StatusCode::BAD_GATEWAY,
            Self::Abort(_) => axum::http::StatusCode::TOO_MANY_REQUESTS,
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
        let config = Arc::new(config);
        let metrics = Arc::new(Registry::new());
        for stage in ["identity", "quota", "sanitize", "compression", "dispatch"] {
            metrics.histogram(
                &format!("ab_stage_duration_us{{stage=\"{stage}\"}}"),
                "Harness stage latency",
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
        metrics.histogram("ab_receipt_sign_duration_us", "Receipt signing latency");
        metrics.histogram("ab_reconcile_duration_us", "Idle reconciliation duration");
        metrics.histogram("ab_session_finalize_duration_us", "Session finalization latency");
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
        );
        let mut client_builder = reqwest::Client::builder()
            .connect_timeout(HTTP_CONNECT_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none());
        if let Some(seconds) = config.upstream_read_timeout_s {
            client_builder = client_builder.read_timeout(std::time::Duration::from_secs(seconds));
        }
        if config.upstream_http2_prior_knowledge {
            client_builder = client_builder.http2_prior_knowledge();
        }
        let client = client_builder
            .build()
            .map_err(|error| PipelineError::Upstream(error.to_string()))?;
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

        let worker_permit = self
            .worker
            .try_reserve(&session_id)
            .map_err(|error| PipelineError::Unavailable(error.to_string()))?;
        let response_permit = self
            .worker
            .try_reserve(&session_id)
            .map_err(|error| PipelineError::Unavailable(error.to_string()))?;

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
        self.observe_stage("dispatch", total_started);
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
        let prepared = tokio::task::spawn_blocking(move || state.prepare_chat(&headers, payload))
            .await
            .map_err(|error| PipelineError::Unavailable(error.to_string()))??;
        prepared.session.wait_for_worker_jobs().await;
        if prepared.session.capture_failed() {
            return Err(PipelineError::Unavailable(
                "request audit capture failed before provider dispatch".to_owned(),
            ));
        }
        if prepared.session.loop_state.state() == BreakerState::Open {
            return match prepared.session.loop_state.action() {
                BreakerAction::Abort => Err(PipelineError::Abort(
                    "semantic loop circuit breaker opened during audit".to_owned(),
                )),
                _ => Err(PipelineError::Blocked(
                    "semantic loop circuit breaker opened during audit; retry required".to_owned(),
                )),
            };
        }
        Ok(prepared)
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
            ..
        } = request;
        let url = format!(
            "{}/v1/chat/completions",
            self.config.upstream_url.trim_end_matches('/')
        );
        let request_digest =
            ab_core::digest::sha256_hex(serde_json::to_vec(&payload).unwrap_or_default().as_slice());
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
        match self.client.post(url).json(&payload).send().await {
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
                    permit.submit(job);
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
        Ok(verdict)
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
        let verdict = tokio::task::spawn_blocking(move || state.intercept_tool(&owned_headers, &raw))
            .await
            .map_err(|error| PipelineError::Unavailable(error.to_string()))??;
        let id = session_id(headers)?;
        let session = self
            .sessions
            .get(&id)
            .ok_or_else(|| PipelineError::Unavailable("tool session disappeared".to_owned()))?;
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
        self.enqueue_failure(
            session,
            identity,
            stop_reason,
            format!("requested session {session_id:?}: {reason}"),
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
        let bearer = headers
            .get(axum::http::header::AUTHORIZATION)
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
            (Some(_), None) if self.config.require_identity => Err(PipelineError::Unauthorized(
                "identity validator is not configured".to_owned(),
            )),
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
                &format!("ab_stage_duration_us{{stage=\"{stage}\"}}"),
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

fn session_id(headers: &HeaderMap) -> Result<String, PipelineError> {
    match headers.get(SESSION_HEADER) {
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
    let value = headers
        .get(WORKFLOW_HEADER)
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

fn atif_capture_from_request(payload: &Value) -> Result<AtifCapture, PipelineError> {
    let message = payload
        .get("messages")
        .and_then(Value::as_array)
        .and_then(|messages| messages.last())
        .ok_or_else(|| PipelineError::BadRequest("chat payload has no messages".to_owned()))?;
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
            tokio::time::timeout(std::time::Duration::from_secs(1), async {
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
        assert!(state.metrics.render().contains("ab_stage_duration_us"));
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
        config.worker_channel_capacity = 2;
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
}
