//! Axum HTTP routes for proxy, MCP interception, lifecycle, and operations.

use crate::pipeline::AppState;
use ab_core::time::elapsed_us;
use ab_events::StopReason;
use ab_sandbox::ToolVerdict;
use axum::body::{Body, Bytes};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures::stream::BoxStream;
use futures::{Stream, StreamExt};
use serde_json::{json, Value};
use std::future::Future as _;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tracing::Instrument as _;

/// Build the complete harness router.
pub fn build_router(state: AppState) -> Router {
    let max_body = state.config.max_request_bytes;
    let dashboard_enabled = state.config.dashboard_enabled;
    let mut router = Router::new()
        .route("/health", get(health))
        .route("/metrics", get(metrics))
        .route("/v1/chat/completions", post(chat_completions))
        .route("/v1/mcp", post(mcp_call))
        .route("/mcp", post(mcp_call))
        .route("/v1/sessions/{id}/close", post(close_session))
        .route("/v1/sessions/{id}/promote", post(promote_session));
    if dashboard_enabled {
        router = router
            .route("/dashboard", get(crate::dashboard::index))
            .route("/dashboard/", get(crate::dashboard::index))
            .route("/dashboard/style.css", get(crate::dashboard::style_css))
            .route("/dashboard/app.js", get(crate::dashboard::app_js))
            .route("/api/v1/dashboard/stats", get(crate::dashboard::stats))
            .route("/api/v1/dashboard/sessions", get(crate::dashboard::list_sessions))
            .route(
                "/api/v1/dashboard/sessions/{id}",
                get(crate::dashboard::session_detail),
            );
    }
    router
        .layer(axum::middleware::from_fn(trace_request))
        // axum's default body limit is 2 MiB, which silently rejects large
        // chat contexts (Claude 200k, GPT-4 128k) before the sandbox even
        // sees the payload. `max_request_bytes` (default 4 MiB, matching
        // the sandbox `MAX_PAYLOAD_BYTES`) is the single knob operators
        // control.
        .layer(axum::extract::DefaultBodyLimit::max(max_body))
        .with_state(state)
}

async fn trace_request(request: Request<Body>, next: Next) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let session_id = request
        .headers()
        .get(crate::pipeline::SESSION_HEADER)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("unbound")
        .to_owned();
    let span = tracing::info_span!(
        "agentbridge.request",
        otel.kind = "server",
        http.request.method = %method,
        url.path = %path,
        session.id = %session_id,
        http.response.status_code = tracing::field::Empty,
    );
    let response = next.run(request).instrument(span.clone()).await;
    span.record("http.response.status_code", response.status().as_u16());
    response
}

async fn health() -> impl IntoResponse {
    Json(json!({
        "status": "ok",
        // Product identifier so callers (abctl start) can tell a real
        // AgentBridge apart from an unrelated service squatting the port.
        "service": "agentbridge",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

async fn metrics(State(state): State<AppState>) -> Response {
    let mut response = Response::new(Body::from(state.metrics.render()));
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    response
}

async fn chat_completions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> Response {
    let admission_started = std::time::Instant::now();
    let mut prepared = match state.prepare_chat_nonblocking(&headers, payload).await {
        Ok(prepared) => prepared,
        Err(error) => return pipeline_error(error),
    };
    prepared.middleware_us = elapsed_us(admission_started);
    let session = Arc::clone(&prepared.session);
    let identity = prepared.identity.clone();
    let session_id = prepared.session.id.clone();
    let middleware_us = prepared.middleware_us;
    let forwarded = match state.forward_chat(prepared).await {
        Ok(response) => response,
        Err(error) => return pipeline_error(error),
    };
    let crate::pipeline::ForwardedResponse {
        response: upstream,
        lease,
        response_permit,
        response_marker,
        response_attempt_id,
    } = forwarded;
    let Some(response_permit) = response_permit else {
        return lifecycle_error("durable response capture permit is missing".to_owned());
    };

    let status = upstream.status();
    let upstream_headers = upstream.headers().clone();
    let is_sse = upstream_headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("text/event-stream"));
    let stream = upstream
        .bytes_stream()
        .map(|chunk| chunk.map_err(std::io::Error::other));
    let stream = AbortFinalizingStream {
        inner: stream.boxed(),
        session,
        identity,
        response_permit: Some(response_permit),
        store: Arc::clone(&state.store),
        budget: state.config.budget.clone(),
        finalizer: state.finalizer.clone(),
        _lease: lease,
        response_marker,
        response_attempt_id,
        response_message: String::new(),
        response_reasoning: String::new(),
        response_model: None,
        response_finish_reason: None,
        upstream_status: status,
        response_cost_usd_micros: 0,
        response_tool_calls: std::collections::BTreeMap::new(),
        response_metrics: ab_events::EventMetrics::default(),
        charged_completion_tokens: 0,
        last_reported_completion_tokens: None,
        last_reported_prompt_tokens: None,
        last_reported_cached_tokens: None,
        last_reported_cost_usd_micros: None,
        saw_chunk: false,
        capture_submitted: false,
        is_sse,
        protocol_buffer: Vec::new(),
        pending_output: std::collections::VecDeque::new(),
        pending_budget: None,
        captured_bytes: 0,
        completed: false,
    };
    let mut response = if is_sse {
        Response::new(Body::from_stream(stream))
    } else {
        // A non-SSE body is fully buffered inside the relay before any byte
        // is released: worker capture and the completion-token budget gate
        // run on the complete body. Handing axum a stream here would commit
        // the upstream status line before those gates run, so a budget
        // refusal degraded into a 200 head followed by an empty body with
        // no explanation. Drain the relay first (no extra buffering beyond
        // what the relay already does) and surface refusals as real errors.
        let mut relay = Box::pin(stream);
        let mut buffered: Vec<u8> = Vec::new();
        loop {
            match relay.next().await {
                Some(Ok(bytes)) => buffered.extend_from_slice(&bytes),
                Some(Err(error)) => {
                    let refusal_status = if error.kind() == std::io::ErrorKind::QuotaExceeded {
                        StatusCode::TOO_MANY_REQUESTS
                    } else {
                        StatusCode::BAD_GATEWAY
                    };
                    // Dropping the relay here runs its finalization Drop
                    // (evidence capture + session seal), same as when a
                    // client observed the severed stream.
                    return (refusal_status, Json(json!({"error": error.to_string()}))).into_response();
                }
                None => break,
            }
        }
        Response::new(Body::from(buffered))
    };
    *response.status_mut() = status;
    for (name, value) in &upstream_headers {
        if is_forwardable_upstream_header(name) {
            // `append`, not `insert`: iterating a HeaderMap repeats the name
            // for each value of a multi-valued header, and `insert` would
            // keep only the last one.
            response.headers_mut().append(name.clone(), value.clone());
        }
    }
    if let Ok(value) = HeaderValue::from_str(&session_id) {
        response
            .headers_mut()
            .insert(crate::pipeline::SESSION_HEADER, value);
    }
    if let Ok(value) = HeaderValue::from_str(&middleware_us.to_string()) {
        response
            .headers_mut()
            .insert(crate::pipeline::MIDDLEWARE_US_HEADER, value);
    }
    response
}

/// Decide whether an upstream response header may be forwarded to the client.
///
/// This is a *proxy* trust boundary: the upstream LLM provider is not on the
/// same trust domain as our client, so blindly forwarding response headers
/// would let the upstream (or an attacker who influences the upstream)
/// - set cookies in our domain (`Set-Cookie` — cookie injection),
/// - open CORS on our origin (`Access-Control-Allow-*`),
/// - inject invalid or contradictory framing/hop-by-hop metadata
///   (`Transfer-Encoding`, `Content-Length`, `Connection`, `Keep-Alive`,
///   `Trailer`, `TE`, `Upgrade`, `Proxy-Authenticate`, `Proxy-Authorization`),
/// - leak upstream implementation identity (`Server`, `X-Powered-By`,
///   `Via`, `X-Request-ID`).
///
/// Hyper computes framing metadata (`Content-Length`, `Transfer-Encoding`)
/// itself when we build the response; forwarding the upstream's copies risks
/// double-encoded or contradictory headers and — with `Transfer-Encoding` —
/// classical HTTP request smuggling. Hop-by-hop headers are forbidden by
/// RFC 7230 §6.1 from crossing a proxy.
fn is_forwardable_upstream_header(name: &axum::http::HeaderName) -> bool {
    use axum::http::header;
    let is_denied = *name == header::CONTENT_LENGTH
        || *name == header::TRANSFER_ENCODING
        || *name == header::CONNECTION
        || *name == header::UPGRADE
        || *name == header::TE
        || *name == header::TRAILER
        || *name == header::PROXY_AUTHENTICATE
        || *name == header::PROXY_AUTHORIZATION
        || *name == header::SET_COOKIE
        || *name == header::SERVER
        || *name == header::VIA
        || name.as_str().eq_ignore_ascii_case("keep-alive")
        || name.as_str().eq_ignore_ascii_case("x-powered-by")
        || name.as_str().eq_ignore_ascii_case("x-request-id")
        // Never let the upstream open CORS on our origin — if we want CORS
        // we set it deliberately in our own router.
        || name.as_str().to_ascii_lowercase().starts_with("access-control-");
    !is_denied
}

async fn mcp_call(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let (execution, unaudited_outcome) = if state.config.tool_upstream_url.is_some() {
        match ToolExecution::from_request(&state.config.atif_spool_dir, &headers, &body, state.journal_key) {
            Ok(mut execution) => {
                let required_scope = crate::pipeline::tool_scope(&execution.tool);
                let identity = match state.resolve_identity(&headers, Some(&required_scope)) {
                    Ok(identity) => identity,
                    Err(error) => return pipeline_error(error),
                };
                if let Err(error) = execution.bind_principal(&identity) {
                    return pipeline_error(error);
                }
                match execution.load().await {
                    Ok(ToolExecutionState::Completed(outcome)) => {
                        let Some(session) = state.sessions.get(&execution.session_id) else {
                            return pipeline_error(crate::pipeline::PipelineError::BadRequest(
                                "unknown session for cached tool result".to_owned(),
                            ));
                        };
                        if let Err(error) = state.authorize_session(
                            &headers,
                            &session,
                            &crate::pipeline::tool_scope(&execution.tool),
                        ) {
                            return pipeline_error(error);
                        }
                        return outcome.into_response();
                    }
                    Ok(ToolExecutionState::Unaudited(outcome)) => {
                        let Some(session) = state.sessions.get(&execution.session_id) else {
                            return pipeline_error(crate::pipeline::PipelineError::BadRequest(
                                "unknown session for pending tool audit".to_owned(),
                            ));
                        };
                        if let Err(error) = state.authorize_session(
                            &headers,
                            &session,
                            &crate::pipeline::tool_scope(&execution.tool),
                        ) {
                            return pipeline_error(error);
                        }
                        (Some(execution), Some(outcome))
                    }
                    Ok(ToolExecutionState::Pending) => {
                        let Some(session) = state.sessions.get(&execution.session_id) else {
                            return pipeline_error(crate::pipeline::PipelineError::BadRequest(
                                "unknown session for pending tool execution".to_owned(),
                            ));
                        };
                        if let Err(error) = state.authorize_session(
                            &headers,
                            &session,
                            &crate::pipeline::tool_scope(&execution.tool),
                        ) {
                            return pipeline_error(error);
                        }
                        return (
                            StatusCode::CONFLICT,
                            Json(json!({"error": TOOL_OUTCOME_UNCERTAIN})),
                        )
                            .into_response();
                    }
                    Ok(ToolExecutionState::Missing) => (Some(execution), None),
                    Err(error) if error == TOOL_REQUEST_MISMATCH => {
                        return (
                            StatusCode::CONFLICT,
                            Json(json!({"error": TOOL_REQUEST_MISMATCH})),
                        )
                            .into_response();
                    }
                    Err(error) => return lifecycle_error(error),
                }
            }
            Err(error) => return pipeline_error(error),
        }
    } else {
        (None, None)
    };
    if let (Some(execution), Some(outcome)) = (execution.as_ref(), unaudited_outcome) {
        let _lease = match state.lease_session(&headers) {
            Ok(lease) => lease,
            Err(error) => return pipeline_error(error),
        };
        let completion_permit = match state.worker.try_reserve(&execution.session_id) {
            Ok(permit) => permit,
            Err(error) => {
                return pipeline_error(crate::pipeline::PipelineError::Unavailable(error.to_string()));
            }
        };
        let Some(session) = state.sessions.get(&execution.session_id) else {
            return lifecycle_error("tool session disappeared".to_owned());
        };
        return complete_tool_audit(execution, outcome, completion_permit, session).await;
    }
    match state.intercept_tool_nonblocking(&headers, &body).await {
        Ok(ToolVerdict::Allowed {
            tool,
            budget_remaining,
            elapsed_us,
        }) => {
            if let Some(url) = state.config.tool_upstream_url.as_deref() {
                let _lease = match state.lease_session(&headers) {
                    Ok(lease) => lease,
                    Err(error) => return pipeline_error(error),
                };
                let execution = match execution {
                    Some(execution) => execution,
                    None => return lifecycle_error("tool execution state is missing".to_owned()),
                };
                let completion_permit = match state.worker.try_reserve(&execution.session_id) {
                    Ok(permit) => permit,
                    Err(error) => {
                        return pipeline_error(crate::pipeline::PipelineError::Unavailable(
                            error.to_string(),
                        ));
                    }
                };
                if let Err(error) = execution.claim().await {
                    // A lost claim race means another in-flight request owns
                    // this execution; answer exactly like the Pending state
                    // and keep the underlying io detail out of the wire.
                    tracing::warn!(
                        session = %execution.session_id,
                        error = %error,
                        "concurrent tool execution claim lost"
                    );
                    return (
                        StatusCode::CONFLICT,
                        Json(json!({"error": TOOL_OUTCOME_UNCERTAIN})),
                    )
                        .into_response();
                }
                let mut tool_request = state
                    .client
                    .post(url)
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(body);
                if let Some(bearer) = &state.tool_auth {
                    tool_request = tool_request.header(axum::http::header::AUTHORIZATION, bearer.clone());
                }
                match tool_request.send().await {
                    Ok(upstream) => {
                        let status = upstream.status();
                        match read_limited_tool_response(upstream).await {
                            Ok(bytes) => {
                                let outcome = ToolOutcome {
                                    status: status.as_u16(),
                                    body_hex: hex::encode(&bytes),
                                };
                                if let Err(error) = execution.persist(&outcome).await {
                                    return lifecycle_error(error);
                                }
                                let session = match state.sessions.get(&execution.session_id) {
                                    Some(session) => session,
                                    None => return lifecycle_error("tool session disappeared".to_owned()),
                                };
                                complete_tool_audit(&execution, outcome, completion_permit, session).await
                            }
                            Err(error) => pipeline_error(crate::pipeline::PipelineError::Upstream(format!(
                                "read tool response: {error}"
                            ))),
                        }
                    }
                    Err(error) => {
                        // CWE-209: `reqwest::Error::Display` embeds the request URL —
                        // returning it verbatim would leak the operator-configured
                        // tool-upstream URL (potentially an internal hostname) to
                        // whichever client called `/mcp`. Report a stable category
                        // and preserve the raw detail server-side for operators.
                        let category = crate::pipeline::classify_upstream_error(&error);
                        tracing::warn!(
                            error = %error,
                            category = category,
                            "tool upstream forwarding failed"
                        );
                        // Upstream faults must surface as 502 (as the chat
                        // relay does), not 500: a 500 blames the harness and
                        // misroutes operator alerting/retry policy.
                        pipeline_error(crate::pipeline::PipelineError::Upstream(format!(
                            "forward tool call: {category}"
                        )))
                    }
                }
            } else {
                (
                    StatusCode::OK,
                    Json(json!({
                        "allowed": true,
                        "tool": tool,
                        "budget_remaining": budget_remaining,
                        "decision_us": elapsed_us,
                    })),
                )
                    .into_response()
            }
        }
        Ok(ToolVerdict::Blocked { response, .. }) => (StatusCode::FORBIDDEN, Json(response)).into_response(),
        Err(error) => pipeline_error(error),
    }
}

const MAX_TOOL_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

async fn read_limited_tool_response(response: reqwest::Response) -> Result<Bytes, String> {
    let mut stream = response.bytes_stream();
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        // CWE-209: `reqwest::Error::Display` embeds the request URL — leaking
        // the operator-configured tool-upstream URL to the client if we
        // returned it verbatim. Use the stable classifier and log the raw
        // detail for operators.
        let chunk = chunk.map_err(|error| {
            let category = crate::pipeline::classify_upstream_error(&error);
            tracing::warn!(
                error = %error,
                category = category,
                "tool upstream stream chunk failed"
            );
            category.to_owned()
        })?;
        let next = body
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| "tool response size overflow".to_owned())?;
        if next > MAX_TOOL_RESPONSE_BYTES {
            return Err(format!("tool response exceeds {MAX_TOOL_RESPONSE_BYTES} bytes"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Bytes::from(body))
}

async fn complete_tool_audit(
    execution: &ToolExecution,
    outcome: ToolOutcome,
    completion_permit: crate::worker::WorkerPermit,
    session: Arc<crate::session::Session>,
) -> Response {
    let status = StatusCode::from_u16(outcome.status).unwrap_or(StatusCode::BAD_GATEWAY);
    let bytes = match hex::decode(&outcome.body_hex) {
        Ok(bytes) => Bytes::from(bytes),
        Err(error) => return lifecycle_error(format!("decode tool response: {error}")),
    };
    let success = status.is_success();
    completion_permit.submit(crate::worker::WorkerJob {
        session: Arc::clone(&session),
        identity: session.current_identity(),
        class: ab_events::EventClass::Session,
        payload: json!({
            "action": "tool_completed",
            "execution_key": &execution.key,
            "status": status.as_u16(),
            "response_sha256": ab_core::digest::sha256_hex(&bytes),
        }),
        text: String::new(),
        analyze_loop: false,
        status: if success {
            ab_events::StatusId::Success
        } else {
            ab_events::StatusId::Failure
        },
        stop_reason: (!success).then_some(StopReason::Other),
        native_stop_reason: None,
        metrics: ab_events::EventMetrics::default(),
        cost_usd_micros: 0,
        atif: Some(crate::worker::AtifCapture {
            source: ab_atif::Source::System,
            message: Value::String(String::from_utf8_lossy(&bytes).into_owned()),
            reasoning_content: None,
            model_name: None,
            tool_calls: None,
            observation: None,
            llm_call_count: None,
        }),
        response_marker: None,
        response_attempt: None,
    });
    session.wait_for_worker_jobs().await;
    if session.capture_failed() {
        return lifecycle_error("tool completed but completion audit failed".to_owned());
    }
    if let Err(error) = execution.mark_audited().await {
        return lifecycle_error(error);
    }
    (status, bytes).into_response()
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct ToolOutcome {
    status: u16,
    body_hex: String,
}

impl ToolOutcome {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.status).unwrap_or(StatusCode::BAD_GATEWAY);
        match hex::decode(self.body_hex) {
            Ok(body) => (status, Bytes::from(body)).into_response(),
            Err(error) => lifecycle_error(format!("decode cached tool response: {error}")),
        }
    }
}

enum ToolExecutionState {
    Missing,
    Pending,
    Unaudited(ToolOutcome),
    Completed(ToolOutcome),
}

const TOOL_REQUEST_MISMATCH: &str = "JSON-RPC id is already bound to a different tool request or principal";
/// Canonical duplicate-execution refusal, shared by the pre-flight Pending
/// state and a lost concurrent claim race so neither reveals more than the
/// other (a raw claim error would leak filesystem detail, CWE-209).
const TOOL_OUTCOME_UNCERTAIN: &str = "tool execution outcome is uncertain; refusing duplicate execution";

#[derive(PartialEq, serde::Serialize, serde::Deserialize)]
struct ToolIntent {
    pub(crate) execution_key: String,
    pub(crate) session_id: String,
    pub(crate) tool: String,
    pub(crate) request_digest: String,
    pub(crate) principal_digest: String,
}

#[cfg(test)]
pub(crate) async fn ensure_no_unresolved_tool_executions(
    spool: &std::path::Path,
    control_key: &[u8; 32],
) -> Result<(), String> {
    let sessions = unresolved_tool_sessions(spool, control_key).await?;
    if let Some(session_id) = sessions.into_iter().next() {
        Err(format!("session {session_id} has an unresolved tool execution"))
    } else {
        Ok(())
    }
}

pub(crate) async fn unresolved_tool_sessions(
    spool: &std::path::Path,
    control_key: &[u8; 32],
) -> Result<std::collections::HashSet<String>, String> {
    let directory = spool.join(crate::spool::TOOL_EXECUTIONS);
    let control_key = *control_key;
    tokio::task::spawn_blocking(move || {
        let entries = match std::fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(std::collections::HashSet::new());
            }
            Err(error) => return Err(error.to_string()),
        };
        let mut intent_keys = std::collections::HashSet::new();
        let mut unresolved_sessions = std::collections::HashSet::new();
        for entry in entries {
            let path = entry.map_err(|error| error.to_string())?.path();
            let Some(name) = path.file_name().and_then(std::ffi::OsStr::to_str) else {
                continue;
            };
            let Some(key) = name.strip_suffix(crate::spool::TOOL_INTENT_SUFFIX) else {
                continue;
            };
            intent_keys.insert(key.to_owned());
            let intent: ToolIntent = crate::journal::open(
                &control_key,
                &format!("{}:{key}", crate::journal::TOOL_INTENT_DOMAIN),
                0,
                &std::fs::read(&path).map_err(|error| error.to_string())?,
            )?;
            if intent.execution_key != key {
                return Err("tool intent path does not match authenticated execution key".to_owned());
            }
            let outcome_path = directory.join(format!("{key}{}", crate::spool::TOOL_OUTCOME_SUFFIX));
            if !outcome_path.exists() {
                unresolved_sessions.insert(intent.session_id);
                continue;
            }
            let _: ToolOutcome = crate::journal::open(
                &control_key,
                &format!("{}:{key}", crate::journal::TOOL_OUTCOME_DOMAIN),
                0,
                &std::fs::read(&outcome_path).map_err(|error| error.to_string())?,
            )?;
            let audited_path = directory.join(format!("{key}{}", crate::spool::TOOL_AUDITED_SUFFIX));
            if !audited_path.exists() {
                unresolved_sessions.insert(intent.session_id);
                continue;
            }
            let _: serde_json::Value = crate::journal::open(
                &control_key,
                &format!("{}:{key}", crate::journal::TOOL_AUDITED_DOMAIN),
                0,
                &std::fs::read(&audited_path).map_err(|error| error.to_string())?,
            )?;
        }
        for entry in std::fs::read_dir(&directory).map_err(|error| error.to_string())? {
            let path = entry.map_err(|error| error.to_string())?.path();
            let Some(name) = path.file_name().and_then(std::ffi::OsStr::to_str) else {
                continue;
            };
            if let Some(key) = name.strip_suffix(crate::spool::TOOL_OUTCOME_SUFFIX) {
                if !intent_keys.contains(key) {
                    return Err("tool outcome exists without an authenticated intent".to_owned());
                }
            }
        }
        Ok(unresolved_sessions)
    })
    .await
    .map_err(|error| error.to_string())?
}

#[derive(Clone)]
struct ToolExecution {
    key: String,
    session_id: String,
    tool: String,
    request_digest: String,
    principal_digest: String,
    control_key: [u8; 32],
    intent_path: std::path::PathBuf,
    outcome_path: std::path::PathBuf,
    audited_path: std::path::PathBuf,
}

impl ToolExecution {
    fn from_request(
        spool: &str,
        headers: &HeaderMap,
        body: &[u8],
        control_key: [u8; 32],
    ) -> Result<Self, crate::pipeline::PipelineError> {
        let session_id = headers
            .get(crate::pipeline::SESSION_HEADER)
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| crate::pipeline::PipelineError::BadRequest("missing x-ab-session".to_owned()))?;
        // Same validation as the pipeline's `session_id`: an id the intercept
        // path would reject must not key a tool-execution intent either.
        let session_id = ab_core::SessionId::parse(session_id)
            .map(|id| id.to_string())
            .map_err(|error| crate::pipeline::PipelineError::BadRequest(error.to_string()))?;
        let call = ab_sandbox::parse_tool_call(body)
            .map_err(|error| crate::pipeline::PipelineError::BadRequest(error.to_string()))?;
        let id = call.id.ok_or_else(|| {
            crate::pipeline::PipelineError::BadRequest(
                "forwarded tool calls require a JSON-RPC id for idempotency".to_owned(),
            )
        })?;
        let request: Value = serde_json::from_slice(body)
            .map_err(|error| crate::pipeline::PipelineError::BadRequest(error.to_string()))?;
        let canonical = ab_receipts::canonicalize(&request)
            .map_err(|error| crate::pipeline::PipelineError::BadRequest(error.to_string()))?;
        let request_digest = ab_core::digest::sha256_hex(canonical.as_bytes());
        let key_material = format!("{session_id}:{}", id);
        let key = ab_core::digest::sha256_hex(key_material.as_bytes());
        let directory = std::path::Path::new(spool).join(crate::spool::TOOL_EXECUTIONS);
        Ok(Self {
            intent_path: directory.join(format!("{key}{}", crate::spool::TOOL_INTENT_SUFFIX)),
            outcome_path: directory.join(format!("{key}{}", crate::spool::TOOL_OUTCOME_SUFFIX)),
            audited_path: directory.join(format!("{key}{}", crate::spool::TOOL_AUDITED_SUFFIX)),
            key,
            session_id,
            tool: call.tool,
            request_digest,
            principal_digest: String::new(),
            control_key,
        })
    }

    fn bind_principal(
        &mut self,
        identity: &ab_events::AgentIdentity,
    ) -> Result<(), crate::pipeline::PipelineError> {
        let stable_identity = json!({
            "version": identity.version,
            "charter": identity.charter,
            "instance_uid": identity.instance_uid,
        });
        let canonical = ab_receipts::canonicalize(&stable_identity)
            .map_err(|error| crate::pipeline::PipelineError::BadRequest(error.to_string()))?;
        self.principal_digest = ab_core::digest::sha256_hex(canonical.as_bytes());
        Ok(())
    }

    async fn load(&self) -> Result<ToolExecutionState, String> {
        let execution = self.clone();
        tokio::task::spawn_blocking(move || execution.load_sync())
            .await
            .map_err(|error| error.to_string())?
    }

    fn load_sync(&self) -> Result<ToolExecutionState, String> {
        if !self.intent_path.exists() {
            if self.outcome_path.exists() || self.audited_path.exists() {
                return Err("tool outcome exists without an authenticated intent".to_owned());
            }
            return Ok(ToolExecutionState::Missing);
        }
        let intent: ToolIntent = crate::journal::open(
            &self.control_key,
            &format!("{}:{}", crate::journal::TOOL_INTENT_DOMAIN, self.key),
            0,
            &std::fs::read(&self.intent_path).map_err(|error| error.to_string())?,
        )?;
        if intent != self.intent() {
            return Err(TOOL_REQUEST_MISMATCH.to_owned());
        }
        if self.outcome_path.exists() {
            let outcome: ToolOutcome = crate::journal::open(
                &self.control_key,
                &format!("{}:{}", crate::journal::TOOL_OUTCOME_DOMAIN, self.key),
                0,
                &std::fs::read(&self.outcome_path).map_err(|error| error.to_string())?,
            )?;
            return if self.audited_path.exists()
                && crate::journal::open::<serde_json::Value>(
                    &self.control_key,
                    &format!("{}:{}", crate::journal::TOOL_AUDITED_DOMAIN, self.key),
                    0,
                    &std::fs::read(&self.audited_path).map_err(|error| error.to_string())?,
                )
                .is_ok()
            {
                Ok(ToolExecutionState::Completed(outcome))
            } else {
                Ok(ToolExecutionState::Unaudited(outcome))
            };
        }
        Ok(ToolExecutionState::Pending)
    }

    async fn claim(&self) -> Result<(), String> {
        let execution = self.clone();
        tokio::task::spawn_blocking(move || execution.claim_sync())
            .await
            .map_err(|error| error.to_string())?
    }

    fn claim_sync(&self) -> Result<(), String> {
        use std::io::Write as _;
        let directory = self
            .intent_path
            .parent()
            .ok_or_else(|| "tool execution directory is missing".to_owned())?;
        std::fs::create_dir_all(directory).map_err(|error| error.to_string())?;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&self.intent_path)
            .map_err(|error| format!("tool execution already claimed or unavailable: {error}"))?;
        let intent = crate::journal::seal(
            &self.control_key,
            &format!("{}:{}", crate::journal::TOOL_INTENT_DOMAIN, self.key),
            0,
            &self.intent(),
        )?;
        file.write_all(&intent).map_err(|error| error.to_string())?;
        file.sync_all().map_err(|error| error.to_string())?;
        std::fs::File::open(directory)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| error.to_string())
    }

    async fn persist(&self, outcome: &ToolOutcome) -> Result<(), String> {
        let execution = self.clone();
        let outcome = outcome.clone();
        tokio::task::spawn_blocking(move || {
            let sealed = crate::journal::seal(
                &execution.control_key,
                &format!("{}:{}", crate::journal::TOOL_OUTCOME_DOMAIN, execution.key),
                0,
                &outcome,
            )?;
            write_atomic_bytes(&execution.outcome_path, &sealed)
        })
        .await
        .map_err(|error| error.to_string())?
    }

    async fn mark_audited(&self) -> Result<(), String> {
        let execution = self.clone();
        tokio::task::spawn_blocking(move || {
            let sealed = crate::journal::seal(
                &execution.control_key,
                &format!("{}:{}", crate::journal::TOOL_AUDITED_DOMAIN, execution.key),
                0,
                &json!({"audited": true}),
            )?;
            write_atomic_bytes(&execution.audited_path, &sealed)
        })
        .await
        .map_err(|error| error.to_string())?
    }

    fn intent(&self) -> ToolIntent {
        ToolIntent {
            execution_key: self.key.clone(),
            session_id: self.session_id.clone(),
            tool: self.tool.clone(),
            request_digest: self.request_digest.clone(),
            principal_digest: self.principal_digest.clone(),
        }
    }
}

fn write_atomic_bytes(path: &std::path::Path, bytes: &[u8]) -> Result<(), String> {
    ab_core::fsutil::write_atomic(path, bytes).map_err(|error| error.to_string())
}

async fn close_session(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(session) = state.sessions.get(&id) else {
        return (StatusCode::NOT_FOUND, Json(json!({"error": "unknown session"}))).into_response();
    };
    if let Err(error) = state.authorize_session(&headers, &session, &state.config.session_close_scope) {
        return pipeline_error(error);
    }
    match state
        .finalizer
        .close_session(session, StopReason::SessionClosed)
        .await
    {
        Ok(outcome) => Json(outcome).into_response(),
        Err(error) => lifecycle_error(error.to_string()),
    }
}

async fn promote_session(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(session) = state.sessions.get(&id) else {
        return (StatusCode::NOT_FOUND, Json(json!({"error": "unknown session"}))).into_response();
    };
    if let Err(error) = state.authorize_session(&headers, &session, &state.config.session_promote_scope) {
        return pipeline_error(error);
    }
    match state.finalizer.promote(session).await {
        Ok(receipt) => Json(receipt).into_response(),
        Err(error) => lifecycle_error(error.to_string()),
    }
}

fn pipeline_error(error: crate::pipeline::PipelineError) -> Response {
    let close = matches!(error, crate::pipeline::PipelineError::Abort(_));
    let mut response = (error.status(), Json(json!({"error": error.to_string()}))).into_response();
    if close {
        response
            .headers_mut()
            .insert(axum::http::header::CONNECTION, HeaderValue::from_static("close"));
    }
    response
}

fn lifecycle_error(error: String) -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": error}))).into_response()
}

struct AbortFinalizingStream {
    inner: BoxStream<'static, Result<Bytes, std::io::Error>>,
    session: Arc<crate::session::Session>,
    identity: ab_events::AgentIdentity,
    response_permit: Option<crate::worker::WorkerPermit>,
    store: Arc<dyn ab_state::StateStore>,
    budget: ab_state::BudgetSpec,
    finalizer: crate::reconciler::Finalizer,
    _lease: crate::session::SessionLease,
    response_marker: Option<String>,
    response_attempt_id: String,
    response_message: String,
    response_reasoning: String,
    response_model: Option<String>,
    response_finish_reason: Option<String>,
    upstream_status: StatusCode,
    response_cost_usd_micros: u64,
    response_tool_calls: std::collections::BTreeMap<u64, PartialToolCall>,
    response_metrics: ab_events::EventMetrics,
    charged_completion_tokens: u64,
    last_reported_completion_tokens: Option<u64>,
    last_reported_prompt_tokens: Option<u64>,
    last_reported_cached_tokens: Option<u64>,
    last_reported_cost_usd_micros: Option<u64>,
    saw_chunk: bool,
    capture_submitted: bool,
    is_sse: bool,
    protocol_buffer: Vec<u8>,
    pending_output: std::collections::VecDeque<Bytes>,
    pending_budget: Option<PendingBudget>,
    captured_bytes: usize,
    completed: bool,
}

const MAX_PROVIDER_CAPTURE_BYTES: usize = 16 * 1024 * 1024;
const MAX_PROVIDER_FIELD_BYTES: usize = 8 * 1024 * 1024;
const MAX_PROVIDER_TOOL_CALLS: usize = 128;

impl AbortFinalizingStream {
    fn absorb_network_chunk(&mut self, raw: &[u8]) -> Result<u64, String> {
        self.saw_chunk |= !raw.is_empty();
        self.captured_bytes = self
            .captured_bytes
            .checked_add(raw.len())
            .ok_or_else(|| "provider response size overflow".to_owned())?;
        if self.captured_bytes > MAX_PROVIDER_CAPTURE_BYTES {
            return Err(format!(
                "provider response exceeds {MAX_PROVIDER_CAPTURE_BYTES} capture bytes"
            ));
        }
        self.protocol_buffer.extend_from_slice(raw);
        if !self.is_sse {
            return Ok(0);
        }
        let mut budget_delta = 0u64;
        while let Some(end) = sse_frame_end(&self.protocol_buffer) {
            let frame: Vec<u8> = self.protocol_buffer.drain(..end).collect();
            let frame = std::str::from_utf8(&frame)
                .map_err(|error| format!("provider SSE frame is not UTF-8: {error}"))?;
            budget_delta = budget_delta
                .checked_add(self.absorb_frame(frame)?)
                .ok_or_else(|| "provider completion-token delta overflow".to_owned())?;
        }
        if self.protocol_buffer.len() > MAX_PROVIDER_FIELD_BYTES {
            return Err("unterminated provider SSE frame exceeds limit".to_owned());
        }
        Ok(budget_delta)
    }

    fn flush_protocol_buffer(&mut self) -> Result<u64, String> {
        if self.protocol_buffer.is_empty() {
            return Ok(0);
        }
        let frame = std::mem::take(&mut self.protocol_buffer);
        let frame = std::str::from_utf8(&frame)
            .map_err(|error| format!("provider response is not UTF-8: {error}"))?;
        self.absorb_frame(frame)
    }

    fn absorb_frame(&mut self, raw: &str) -> Result<u64, String> {
        let Some(parsed) = parse_provider_chunk(raw)? else {
            return Ok(0);
        };
        if self.upstream_status.is_success() && !parsed.has_choices {
            return Err("successful provider response has no choices array".to_owned());
        }
        push_bounded(&mut self.response_message, &parsed.message, "response message")?;
        if let Some(reasoning) = parsed.reasoning {
            push_bounded(&mut self.response_reasoning, &reasoning, "response reasoning")?;
        }
        if self.response_model.is_none() {
            self.response_model = parsed.model_name;
        }
        if parsed.finish_reason.is_some() {
            self.response_finish_reason = parsed.finish_reason;
        }
        self.response_cost_usd_micros = self.response_cost_usd_micros.max(parsed.cost_usd_micros);
        for delta in parsed.tool_call_deltas {
            if delta.index >= MAX_PROVIDER_TOOL_CALLS as u64 {
                return Err(format!(
                    "provider tool-call index {} is out of range",
                    delta.index
                ));
            }
            if !self.response_tool_calls.contains_key(&delta.index)
                && self.response_tool_calls.len() >= MAX_PROVIDER_TOOL_CALLS
            {
                return Err(format!(
                    "provider response exceeds {MAX_PROVIDER_TOOL_CALLS} tool calls"
                ));
            }
            let partial = self.response_tool_calls.entry(delta.index).or_default();
            if delta.id.is_some() {
                partial.id = delta.id;
            }
            if delta.name.is_some() {
                partial.name = delta.name;
            }
            push_bounded(&mut partial.arguments, &delta.arguments, "tool-call arguments")?;
        }
        if parsed.usage_reported {
            reject_metric_regression(
                "prompt tokens",
                &mut self.last_reported_prompt_tokens,
                parsed.metrics.prompt_tokens,
            )?;
            reject_metric_regression(
                "cached tokens",
                &mut self.last_reported_cached_tokens,
                parsed.metrics.cached_tokens,
            )?;
        }
        if parsed.cost_reported {
            reject_metric_regression(
                "cost",
                &mut self.last_reported_cost_usd_micros,
                Some(parsed.cost_usd_micros),
            )?;
        }
        if let Some(prompt) = parsed.metrics.prompt_tokens {
            self.response_metrics.prompt_tokens = Some(
                self.response_metrics
                    .prompt_tokens
                    .map_or(prompt, |current| current.max(prompt)),
            );
        }
        if let Some(cached) = parsed.metrics.cached_tokens {
            self.response_metrics.cached_tokens = Some(
                self.response_metrics
                    .cached_tokens
                    .map_or(cached, |current| current.max(cached)),
            );
        }
        let reported_completion = parsed.metrics.completion_tokens.unwrap_or(0);
        let delta = if parsed.usage_reported {
            let previous = self.last_reported_completion_tokens.unwrap_or(0);
            if reported_completion < previous {
                return Err("provider completion usage regressed".to_owned());
            }
            self.last_reported_completion_tokens = Some(reported_completion);
            let delta = reported_completion.saturating_sub(self.charged_completion_tokens);
            self.response_metrics.completion_tokens = Some(
                self.response_metrics
                    .completion_tokens
                    .map_or(reported_completion, |current| current.max(reported_completion)),
            );
            delta
        } else {
            let total = self
                .response_metrics
                .completion_tokens
                .unwrap_or(0)
                .checked_add(reported_completion)
                .filter(|total| *total <= ab_core::error::JCS_SAFE_MAX)
                .ok_or_else(|| "provider completion-token total exceeds JCS-safe bounds".to_owned())?;
            self.response_metrics.completion_tokens = Some(total);
            reported_completion
        };
        if delta == 0 {
            return Ok(0);
        }
        self.charged_completion_tokens = self
            .charged_completion_tokens
            .checked_add(delta)
            .ok_or_else(|| "charged completion-token counter overflow".to_owned())?;
        Ok(delta)
    }

    fn begin_budget_check(&mut self, delta: u64, continuation: BudgetContinuation) {
        let store = Arc::clone(&self.store);
        let session_id = self.session.id.clone();
        let budget = self.budget.clone();
        let task = tokio::task::spawn_blocking(move || {
            ab_state::ActionBudget::new(store.as_ref(), &session_id, &budget)
                .try_tokens(delta)
                .map_err(|error| format!("token budget backend failed closed: {error}"))
        });
        self.pending_budget = Some(PendingBudget { task, continuation });
    }

    fn submit_response_capture(&mut self, failure: Option<String>) -> Result<(), crate::worker::SubmitError> {
        if self.capture_submitted {
            return Ok(());
        }
        self.capture_submitted = true;
        let reasoning =
            (!self.response_reasoning.is_empty()).then(|| std::mem::take(&mut self.response_reasoning));
        let analysis_text = reasoning.clone().unwrap_or_else(|| self.response_message.clone());
        let native_finish_reason = self.response_finish_reason.clone();
        let (class, status, stop_reason, payload) = if let Some(reason) = failure {
            (
                ab_events::EventClass::StopReason,
                ab_events::StatusId::Failure,
                Some(ab_events::StopReason::BudgetExceeded),
                json!({"reason": reason, "direction": "upstream_response"}),
            )
        } else if !self.upstream_status.is_success() {
            (
                ab_events::EventClass::StopReason,
                ab_events::StatusId::Failure,
                Some(ab_events::StopReason::Other),
                json!({
                    "direction": "upstream_response",
                    "http_status": self.upstream_status.as_u16(),
                }),
            )
        } else if let Some(native) = &native_finish_reason {
            (
                ab_events::EventClass::StopReason,
                ab_events::StatusId::Success,
                Some(map_finish_reason(native)),
                json!({
                    "direction": "upstream_response",
                    "finish_reason": native,
                    "http_status": self.upstream_status.as_u16(),
                }),
            )
        } else {
            (
                ab_events::EventClass::Session,
                ab_events::StatusId::Success,
                None,
                json!({
                    "direction": "upstream_response",
                    "http_status": self.upstream_status.as_u16(),
                }),
            )
        };
        let tool_calls: Vec<ab_atif::ToolCall> = std::mem::take(&mut self.response_tool_calls)
            .into_values()
            .map(|partial| {
                let arguments = serde_json::from_str(&partial.arguments)
                    .unwrap_or_else(|_| json!({"raw": partial.arguments}));
                ab_atif::ToolCall {
                    tool_call_id: partial.id.unwrap_or_else(ab_core::new_event_uid),
                    function_name: partial.name.unwrap_or_else(|| "unknown".to_owned()),
                    arguments,
                    extra: None,
                }
            })
            .collect();
        let permit = self
            .response_permit
            .take()
            .ok_or(crate::worker::SubmitError::Closed)?;
        permit.submit(crate::worker::WorkerJob {
            session: Arc::clone(&self.session),
            identity: self.identity.clone(),
            class,
            payload,
            text: analysis_text,
            analyze_loop: true,
            status,
            stop_reason,
            native_stop_reason: native_finish_reason,
            metrics: self.response_metrics,
            cost_usd_micros: self.response_cost_usd_micros,
            atif: Some(crate::worker::AtifCapture {
                source: ab_atif::Source::Agent,
                message: Value::String(std::mem::take(&mut self.response_message)),
                reasoning_content: reasoning,
                model_name: self.response_model.take(),
                tool_calls: (!tool_calls.is_empty()).then_some(tool_calls),
                observation: None,
                llm_call_count: Some(1),
            }),
            response_marker: self.response_marker.take(),
            response_attempt: Some(crate::worker::ResponseAttempt {
                id: self.response_attempt_id.clone(),
                terminal: true,
            }),
        });
        Ok(())
    }
}

enum BudgetContinuation {
    Emit(Bytes),
    ContinueNonSse,
    FinishSse,
    FinishNonSse,
}

struct PendingBudget {
    task: tokio::task::JoinHandle<Result<ab_state::BudgetDecision, String>>,
    continuation: BudgetContinuation,
}

#[derive(Default)]
struct PartialToolCall {
    id: Option<String>,
    name: Option<String>,
    arguments: String,
}

struct ProviderToolCallDelta {
    index: u64,
    id: Option<String>,
    name: Option<String>,
    arguments: String,
}

struct ParsedProviderChunk {
    message: String,
    reasoning: Option<String>,
    model_name: Option<String>,
    metrics: ab_events::EventMetrics,
    usage_reported: bool,
    finish_reason: Option<String>,
    cost_usd_micros: u64,
    cost_reported: bool,
    has_choices: bool,
    tool_call_deltas: Vec<ProviderToolCallDelta>,
}

fn reject_metric_regression(
    field: &str,
    previous: &mut Option<u64>,
    current: Option<u64>,
) -> Result<(), String> {
    let Some(current) = current else {
        return Ok(());
    };
    if previous.is_some_and(|previous| current < previous) {
        return Err(format!("provider {field} regressed"));
    }
    *previous = Some(current);
    Ok(())
}

fn push_bounded(target: &mut String, value: &str, field: &str) -> Result<(), String> {
    let size = target
        .len()
        .checked_add(value.len())
        .ok_or_else(|| format!("{field} size overflow"))?;
    if size > MAX_PROVIDER_FIELD_BYTES {
        return Err(format!("{field} exceeds {MAX_PROVIDER_FIELD_BYTES} bytes"));
    }
    target.push_str(value);
    Ok(())
}

fn sse_frame_end(buffer: &[u8]) -> Option<usize> {
    let mut line_start = 0usize;
    let mut index = 0usize;
    while index < buffer.len() {
        let byte = buffer.get(index).copied()?;
        let newline = match byte {
            b'\r' if buffer.get(index + 1) == Some(&b'\n') => 2,
            b'\r' if buffer.get(index + 1).is_none() => return None,
            b'\r' | b'\n' => 1,
            _ => {
                index += 1;
                continue;
            }
        };
        if index == line_start {
            return Some(index + newline);
        }
        index += newline;
        line_start = index;
    }
    None
}

impl AbortFinalizingStream {
    /// Fail-closed relay abort: the client connection is severed (the
    /// status line already went out, so a clean error response is no
    /// longer possible). Without this log the reason would vanish into
    /// an io::Error that hyper discards — leaving "empty reply from
    /// server" as the only symptom of e.g. an upstream returning HTML.
    fn abort_error(&self, reason: String) -> std::io::Error {
        tracing::warn!(
            session = %self.session.id,
            %reason,
            "aborting client response; upstream reply could not be captured"
        );
        std::io::Error::other(reason)
    }
}

impl Stream for AbortFinalizingStream {
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.pending_budget.is_some() {
            let result = {
                let Some(pending) = self.pending_budget.as_mut() else {
                    self.session.mark_capture_failed();
                    return Poll::Ready(Some(Err(std::io::Error::other(
                        "pending completion budget state disappeared",
                    ))));
                };
                match Pin::new(&mut pending.task).poll(context) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(result) => result,
                }
            };
            let Some(pending) = self.pending_budget.take() else {
                self.session.mark_capture_failed();
                return Poll::Ready(Some(Err(std::io::Error::other(
                    "completed completion budget state disappeared",
                ))));
            };
            let failure = match result {
                Ok(Ok(ab_state::BudgetDecision::Allowed { .. })) => None,
                Ok(Ok(ab_state::BudgetDecision::Refused { limit, cap })) => {
                    Some(format!("{limit} exceeded (cap {cap})"))
                }
                Ok(Err(reason)) => Some(reason),
                Err(error) => {
                    self.session.mark_capture_failed();
                    self.pending_output.clear();
                    return Poll::Ready(Some(Err(std::io::Error::other(format!(
                        "completion budget task failed: {error}"
                    )))));
                }
            };
            if let Some(reason) = failure {
                if let Err(error) = self.submit_response_capture(Some(reason.clone())) {
                    self.session.mark_capture_failed();
                    self.pending_output.clear();
                    return Poll::Ready(Some(Err(std::io::Error::other(format!(
                        "response capture failed closed: {error}"
                    )))));
                }
                self.pending_output.clear();
                // QuotaExceeded is an in-process marker: the non-SSE drain in
                // `chat_completions` maps it to HTTP 429 so budget refusals
                // reach the client as a real error instead of a severed body.
                return Poll::Ready(Some(Err(std::io::Error::new(
                    std::io::ErrorKind::QuotaExceeded,
                    format!("response blocked by token budget: {reason}"),
                ))));
            }
            match pending.continuation {
                BudgetContinuation::Emit(bytes) => return Poll::Ready(Some(Ok(bytes))),
                BudgetContinuation::ContinueNonSse => {}
                BudgetContinuation::FinishSse => {
                    if let Err(error) = self.submit_response_capture(None) {
                        self.session.mark_capture_failed();
                        return Poll::Ready(Some(Err(std::io::Error::other(format!(
                            "response capture failed closed: {error}"
                        )))));
                    }
                    self.completed = true;
                    return Poll::Ready(None);
                }
                BudgetContinuation::FinishNonSse => {
                    if let Err(error) = self.submit_response_capture(None) {
                        self.session.mark_capture_failed();
                        self.pending_output.clear();
                        return Poll::Ready(Some(Err(std::io::Error::other(format!(
                            "response capture failed closed: {error}"
                        )))));
                    }
                    self.completed = true;
                    return Poll::Ready(self.pending_output.pop_front().map(Ok));
                }
            }
        }

        if !self.is_sse {
            if self.completed {
                return Poll::Ready(self.pending_output.pop_front().map(Ok));
            }
            loop {
                match self.inner.as_mut().poll_next(context) {
                    Poll::Ready(Some(Ok(bytes))) => {
                        let delta = match self.absorb_network_chunk(&bytes) {
                            Ok(delta) => delta,
                            Err(error) => {
                                self.session.mark_capture_failed();
                                self.pending_output.clear();
                                let error = self.abort_error(error);
                                return Poll::Ready(Some(Err(error)));
                            }
                        };
                        self.pending_output.push_back(bytes);
                        if delta > 0 {
                            self.begin_budget_check(delta, BudgetContinuation::ContinueNonSse);
                            context.waker().wake_by_ref();
                            return Poll::Pending;
                        }
                    }
                    Poll::Ready(Some(Err(error))) => {
                        self.session.mark_capture_failed();
                        self.pending_output.clear();
                        let error = self.abort_error(error.to_string());
                        return Poll::Ready(Some(Err(error)));
                    }
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(None) => {
                        let delta = match self.flush_protocol_buffer() {
                            Ok(delta) => delta,
                            Err(error) => {
                                self.session.mark_capture_failed();
                                self.pending_output.clear();
                                let error = self.abort_error(error);
                                return Poll::Ready(Some(Err(error)));
                            }
                        };
                        if delta > 0 {
                            self.begin_budget_check(delta, BudgetContinuation::FinishNonSse);
                            context.waker().wake_by_ref();
                            return Poll::Pending;
                        }
                        if let Err(error) = self.submit_response_capture(None) {
                            self.session.mark_capture_failed();
                            self.pending_output.clear();
                            return Poll::Ready(Some(Err(std::io::Error::other(format!(
                                "response capture failed closed: {error}"
                            )))));
                        }
                        self.completed = true;
                        return Poll::Ready(self.pending_output.pop_front().map(Ok));
                    }
                }
            }
        }

        match self.inner.as_mut().poll_next(context) {
            Poll::Ready(Some(Ok(bytes))) => match self.absorb_network_chunk(&bytes) {
                Ok(0) => Poll::Ready(Some(Ok(bytes))),
                Ok(delta) => {
                    self.begin_budget_check(delta, BudgetContinuation::Emit(bytes));
                    context.waker().wake_by_ref();
                    Poll::Pending
                }
                Err(error) => {
                    self.session.mark_capture_failed();
                    let error = self.abort_error(error);
                    Poll::Ready(Some(Err(error)))
                }
            },
            Poll::Ready(Some(Err(error))) => {
                self.session.mark_capture_failed();
                let error = self.abort_error(error.to_string());
                Poll::Ready(Some(Err(error)))
            }
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => {
                let delta = match self.flush_protocol_buffer() {
                    Ok(delta) => delta,
                    Err(error) => {
                        self.session.mark_capture_failed();
                        let error = self.abort_error(error);
                        return Poll::Ready(Some(Err(error)));
                    }
                };
                if delta > 0 {
                    self.begin_budget_check(delta, BudgetContinuation::FinishSse);
                    context.waker().wake_by_ref();
                    return Poll::Pending;
                }
                if let Err(error) = self.submit_response_capture(None) {
                    self.session.mark_capture_failed();
                    return Poll::Ready(Some(Err(std::io::Error::other(format!(
                        "response capture failed closed: {error}"
                    )))));
                }
                self.completed = true;
                Poll::Ready(None)
            }
        }
    }
}

fn parse_provider_chunk(raw: &str) -> Result<Option<ParsedProviderChunk>, String> {
    let mut message = String::new();
    let mut reasoning = String::new();
    let mut prompt_tokens = None;
    let mut completion_tokens = None;
    let mut cached_tokens = None;
    let mut usage_reported = false;
    let mut finish_reason = None;
    let mut cost_usd_micros = 0u64;
    let mut cost_reported = false;
    let mut tool_call_deltas = Vec::new();
    let mut is_sse = false;
    let mut data = Vec::new();
    for line in raw.split(['\r', '\n']) {
        if let Some(value) = line.strip_prefix("data:") {
            is_sse = true;
            data.push(value.trim_start());
        } else if line == "data"
            || line.starts_with("event:")
            || line.starts_with("id:")
            || line.starts_with("retry:")
            || line.starts_with(':')
        {
            is_sse = true;
        }
    }
    let candidate = if is_sse {
        if data.is_empty() {
            return Ok(None);
        }
        data.join("\n")
    } else {
        raw.trim().to_owned()
    };
    if candidate.is_empty() || candidate == "[DONE]" {
        return Ok(None);
    }
    let value = serde_json::from_str::<Value>(&candidate)
        .map_err(|error| format!("invalid provider JSON frame: {error}"))?;
    let model_name = value.get("model").and_then(Value::as_str).map(str::to_owned);
    if let Some(usage) = value.get("usage") {
        usage_reported = true;
        prompt_tokens = provider_u64(usage.get("prompt_tokens"), "prompt_tokens")?.or(prompt_tokens);
        completion_tokens =
            provider_u64(usage.get("completion_tokens"), "completion_tokens")?.or(completion_tokens);
        cached_tokens = provider_u64(
            usage.pointer("/prompt_tokens_details/cached_tokens"),
            "cached_tokens",
        )?
        .or(cached_tokens);
    }
    let cost_value = value.pointer("/usage/cost_usd").or_else(|| value.get("cost_usd"));
    if let Some(cost_value) = cost_value {
        let cost = cost_value
            .as_f64()
            .ok_or_else(|| "provider cost_usd is not a number".to_owned())?;
        if !cost.is_finite() || cost < 0.0 {
            return Err("provider cost_usd is not finite and nonnegative".to_owned());
        }
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        {
            let micros = (cost * ab_core::units::USD_MICROS_PER_DOLLAR as f64).round();
            if micros > ab_core::error::JCS_SAFE_MAX as f64 {
                return Err("provider cost exceeds JCS-safe receipt bounds".to_owned());
            }
            cost_usd_micros = micros as u64;
            cost_reported = true;
        }
    }
    let has_choices = value.get("choices").is_some();
    let choices = match value.get("choices") {
        Some(Value::Array(choices)) => Some(choices),
        Some(_) => return Err("provider choices is not an array".to_owned()),
        None => None,
    };
    if let Some(choices) = choices {
        for choice in choices {
            if let Some(reason) = choice.get("finish_reason").and_then(Value::as_str) {
                finish_reason = Some(reason.to_owned());
            }
            let content = choice
                .pointer("/delta/content")
                .or_else(|| choice.pointer("/message/content"))
                .and_then(Value::as_str);
            if let Some(content) = content {
                message.push_str(content);
            }
            let reasoning_content = choice
                .pointer("/delta/reasoning_content")
                .or_else(|| choice.pointer("/message/reasoning_content"))
                .and_then(Value::as_str);
            if let Some(content) = reasoning_content {
                reasoning.push_str(content);
            }
            let streaming_calls = choice.pointer("/delta/tool_calls");
            let calls = streaming_calls
                .or_else(|| choice.pointer("/message/tool_calls"))
                .map(|calls| {
                    calls
                        .as_array()
                        .ok_or_else(|| "provider tool_calls is not an array".to_owned())
                })
                .transpose()?;
            if let Some(calls) = calls {
                for (position, call) in calls.iter().enumerate() {
                    let index = match call.get("index").and_then(Value::as_u64) {
                        Some(index) => index,
                        None if streaming_calls.is_some() => {
                            return Err("streaming provider tool call has no index".to_owned());
                        }
                        None => u64::try_from(position)
                            .map_err(|_| "provider tool-call index overflow".to_owned())?,
                    };
                    tool_call_deltas.push(ProviderToolCallDelta {
                        index,
                        id: call.get("id").and_then(Value::as_str).map(str::to_owned),
                        name: call
                            .pointer("/function/name")
                            .and_then(Value::as_str)
                            .map(str::to_owned),
                        arguments: call
                            .pointer("/function/arguments")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned(),
                    });
                }
            }
        }
    }
    let completion_tokens = completion_tokens.unwrap_or_else(|| {
        let mut estimated = ab_core::tokens::approx_tokens(&message)
            .saturating_add(ab_core::tokens::approx_tokens(&reasoning));
        for call in &tool_call_deltas {
            estimated = estimated
                .saturating_add(call.name.as_deref().map_or(0, ab_core::tokens::approx_tokens))
                .saturating_add(ab_core::tokens::approx_tokens(&call.arguments));
        }
        estimated
    });
    Ok(Some(ParsedProviderChunk {
        message,
        reasoning: (!reasoning.is_empty()).then_some(reasoning),
        model_name,
        metrics: ab_events::EventMetrics {
            prompt_tokens,
            completion_tokens: Some(completion_tokens),
            cached_tokens,
            pruned_tokens: None,
            pruning_ratio_millis: None,
        },
        usage_reported,
        finish_reason,
        cost_usd_micros,
        cost_reported,
        has_choices,
        tool_call_deltas,
    }))
}

fn provider_u64(value: Option<&Value>, field: &str) -> Result<Option<u64>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value
        .as_u64()
        .ok_or_else(|| format!("provider {field} is not a nonnegative integer"))?;
    if value > ab_core::error::JCS_SAFE_MAX {
        return Err(format!("provider {field} exceeds JCS-safe bounds"));
    }
    Ok(Some(value))
}

fn map_finish_reason(native: &str) -> ab_events::StopReason {
    match native {
        "stop" | "stop_sequence" | "end_turn" => ab_events::StopReason::Stop,
        "length" | "max_tokens" => ab_events::StopReason::MaxTokens,
        "tool_calls" | "function_call" | "tool_use" => ab_events::StopReason::ToolUse,
        "content_filter" => ab_events::StopReason::ContentFilter,
        _ => ab_events::StopReason::Other,
    }
}

impl Drop for AbortFinalizingStream {
    fn drop(&mut self) {
        // Session-being-closed intentionally still captures: `wait_for_streams`
        // in `close_session_locked` is blocked on this stream's `SessionLease`,
        // so the response_capture we submit here will land before finalize
        // reads the chain / atif.
        if self.completed {
            return;
        }
        // Capture is_closed once so the fail-closed guards below agree on
        // the same view. When a concurrent close is already draining this
        // stream via `wait_for_streams`, the finalize path is imminent and
        // we must not `mark_capture_failed` on the last budget check /
        // trailing frame — otherwise `close_session_locked`'s post-drain
        // `capture_failed` guard seals the session (`mark_artifact_committed`
        // + committed claim) and returns `CaptureIncomplete`: the close is
        // never retried and the session finalizes with no artifact at all.
        // On a normal abort (no concurrent close) the fail-closed marks
        // still fire, so a mid-flight budget verdict or garbled trailing
        // frame still refuses the capture on the client's next request.
        let is_closed = self.session.is_closed();
        if !is_closed && self.pending_budget.is_some() {
            self.session.mark_capture_failed();
        }
        let budget_delta = match self.flush_protocol_buffer() {
            Ok(delta) => delta,
            Err(error) => {
                tracing::warn!(%error, "provider stream flush failed on drop");
                if !is_closed {
                    self.session.mark_capture_failed();
                }
                0
            }
        };
        if !is_closed && budget_delta > 0 {
            self.session.mark_capture_failed();
        }
        if !self.session.capture_failed() {
            if let Err(error) = self.submit_response_capture(None) {
                tracing::warn!(%error, "response-capture submit failed on drop");
                self.session.mark_capture_failed();
            }
        }
        if !is_closed {
            let session = Arc::clone(&self.session);
            let finalizer = self.finalizer.clone();
            let session_id = session.id.clone();
            match tokio::runtime::Handle::try_current() {
                Ok(runtime) => {
                    // Detach: the drop is sync and cannot await. The
                    // spawn is supervised only by the runtime's panic
                    // hook, so mirror the outcome to tracing + a metric
                    // instead of silently discarding the Result — a
                    // failed close would otherwise leave the session
                    // "open" until the idle sweeper reaps it, with zero
                    // operator signal.
                    runtime.spawn(async move {
                        if let Err(error) = finalizer.close_session(session, StopReason::Other).await {
                            tracing::warn!(
                                %error,
                                %session_id,
                                "background close on stream abort failed"
                            );
                        }
                    });
                }
                Err(error) => {
                    // Runtime is gone (shutdown, drop from a blocking
                    // thread) — there is no place to await the close.
                    // Mark capture failed so the reconciler retries on
                    // the next tick instead of finalising a session
                    // that never ran to completion.
                    tracing::warn!(
                        %error,
                        %session_id,
                        "no tokio runtime available for stream-abort close; marking capture failed for reconciler retry"
                    );
                    self.session.mark_capture_failed();
                }
            }
        }
    }
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
    use ab_bridge::{BusError, EventBus, PublishAck, StoredEvent};
    use ab_receipts::Ed25519Signer;
    use ab_sandbox::{Sandbox, SandboxConfig};
    use ab_state::{InMemoryStore, Spend, StateError, StateStore};
    use axum::http::Request;
    use std::time::Duration;
    use tower::ServiceExt;

    struct NullBus;

    struct SlowStore {
        inner: InMemoryStore,
        calls: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl StateStore for SlowStore {
        fn add(&self, key: &str, delta: u64) -> Result<u64, StateError> {
            self.inner.add(key, delta)
        }

        fn get(&self, key: &str) -> Result<u64, StateError> {
            self.inner.get(key)
        }

        fn try_spend(&self, key: &str, amount: u64, limit: u64) -> Result<bool, StateError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            std::thread::sleep(Duration::from_millis(100));
            self.inner.try_spend(key, amount, limit)
        }

        fn try_spend_many(&self, spends: &[Spend]) -> Result<Option<usize>, StateError> {
            self.inner.try_spend_many(spends)
        }

        fn remove(&self, key: &str) {
            self.inner.remove(key);
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
            ab_events::EventClass::all()
                .iter()
                .map(|class| class.topic().to_owned())
                .collect()
        }
    }

    async fn mock_chat(Json(payload): Json<Value>) -> Response {
        if payload.get("model").and_then(Value::as_str) == Some("empty-error") {
            let mut response = Response::new(Body::empty());
            *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            response.headers_mut().insert(
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            return response;
        }
        if payload.get("model").and_then(Value::as_str) == Some("json-error") {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({}))).into_response();
        }
        if payload.get("model").and_then(Value::as_str) == Some("empty-success") {
            return Json(json!({})).into_response();
        }
        if payload.get("model").and_then(Value::as_str) == Some("provisional-usage") {
            let chunks = vec![
                Ok::<_, std::convert::Infallible>(Bytes::from_static(
                    b"data: {\"choices\":[{\"delta\":{\"content\":\"hello\"}}]}\n\n",
                )),
                Ok(Bytes::from_static(
                    b"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":2}}\n\n",
                )),
            ];
            let mut response = Response::new(Body::from_stream(futures::stream::iter(chunks)));
            response.headers_mut().insert(
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_static("text/event-stream"),
            );
            return response;
        }
        if payload.get("model").and_then(Value::as_str) == Some("tool-no-usage") {
            let arguments = "x".repeat(4_096);
            let event = format!(
                "data: {{\"choices\":[{{\"delta\":{{\"tool_calls\":[{{\"index\":0,\"function\":{{\"name\":\"read\",\"arguments\":\"{arguments}\"}}}}]}}}}]}}\n\n"
            );
            let mut response = Response::new(Body::from(event));
            response.headers_mut().insert(
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_static("text/event-stream"),
            );
            return response;
        }
        if payload.get("model").and_then(Value::as_str) == Some("tool-oob-index") {
            let event = "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":18446744073709551615,\"function\":{\"name\":\"read\",\"arguments\":\"{}\"}}]}}]}\n\n";
            let mut response = Response::new(Body::from(event));
            response.headers_mut().insert(
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_static("text/event-stream"),
            );
            return response;
        }
        if payload.get("model").and_then(Value::as_str) == Some("regressive-usage") {
            let chunks = vec![
                Ok::<_, std::convert::Infallible>(Bytes::from_static(
                    b"data: {\"choices\":[{\"delta\":{\"content\":\"first\"}}],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":100,\"prompt_tokens_details\":{\"cached_tokens\":5}},\"cost_usd\":0.01}\n\n",
                )),
                Ok(Bytes::from_static(
                    b"data: {\"choices\":[{\"delta\":{\"content\":\"second\"}}],\"usage\":{\"prompt_tokens\":9,\"completion_tokens\":1,\"prompt_tokens_details\":{\"cached_tokens\":4}},\"cost_usd\":0.001}\n\n",
                )),
            ];
            let mut response = Response::new(Body::from_stream(futures::stream::iter(chunks)));
            response.headers_mut().insert(
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_static("text/event-stream"),
            );
            return response;
        }
        if payload.get("model").and_then(Value::as_str) == Some("split-json") {
            let body = serde_json::to_vec(&json!({
                "model": "split-json",
                "choices": [{"message": {"role": "assistant", "content": "héllo"}}],
                "usage": {"prompt_tokens": 5, "completion_tokens": 2}
            }))
            .unwrap();
            let split = body.iter().position(|byte| *byte == 0xc3).unwrap() + 1;
            let chunks = vec![
                Ok::<_, std::convert::Infallible>(Bytes::copy_from_slice(&body[..split])),
                Ok(Bytes::copy_from_slice(&body[split..])),
            ];
            let mut response = Response::new(Body::from_stream(futures::stream::iter(chunks)));
            response.headers_mut().insert(
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            return response;
        }
        if payload.get("model").and_then(Value::as_str) == Some("malformed-json") {
            let mut response = Response::new(Body::from("{\"choices\":["));
            response.headers_mut().insert(
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            return response;
        }
        if payload.get("stream").and_then(Value::as_bool).unwrap_or(false) {
            let event = "data: {\"choices\":[{\"delta\":{\"content\":\"hello\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":3,\"cost_usd\":0.00125,\"prompt_tokens_details\":{\"cached_tokens\":4}}}\n\ndata: [DONE]\n\n";
            let bytes = event.as_bytes();
            let chunks = vec![
                Ok::<_, std::convert::Infallible>(Bytes::copy_from_slice(&bytes[..19])),
                Ok(Bytes::copy_from_slice(&bytes[19..97])),
                Ok(Bytes::copy_from_slice(&bytes[97..])),
            ];
            let mut response = Response::new(Body::from_stream(futures::stream::iter(chunks)));
            response.headers_mut().insert(
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_static("text/event-stream"),
            );
            response
        } else {
            Json(json!({"choices": [{"message": {"role": "assistant", "content": "hello"}}]})).into_response()
        }
    }

    async fn counting_tool(
        State(calls): State<Arc<std::sync::atomic::AtomicUsize>>,
        body: Bytes,
    ) -> Response {
        calls.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        (StatusCode::OK, body).into_response()
    }

    async fn redirecting_tool(State(calls): State<Arc<std::sync::atomic::AtomicUsize>>) -> Response {
        calls.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        (
            StatusCode::TEMPORARY_REDIRECT,
            [(axum::http::header::LOCATION, "/effect")],
        )
            .into_response()
    }

    async fn redirected_effect(State(calls): State<Arc<std::sync::atomic::AtomicUsize>>) -> Response {
        calls.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        StatusCode::OK.into_response()
    }

    struct HeldToolState {
        arrived: std::sync::atomic::AtomicBool,
        release: tokio::sync::Notify,
    }

    async fn held_tool(State(state): State<Arc<HeldToolState>>, body: Bytes) -> Response {
        state.arrived.store(true, std::sync::atomic::Ordering::Release);
        state.release.notified().await;
        (StatusCode::OK, body).into_response()
    }

    async fn test_state(spool: &std::path::Path) -> (AppState, tokio::task::JoinHandle<()>) {
        test_state_with_token_cap(spool, None).await
    }

    async fn test_state_with_token_cap(
        spool: &std::path::Path,
        max_tokens: Option<u64>,
    ) -> (AppState, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let provider = Router::new().route("/v1/chat/completions", post(mock_chat));
        let server = tokio::spawn(async move {
            axum::serve(listener, provider).await.unwrap();
        });
        let mut config = crate::config::HarnessConfig::for_tests(
            &format!("http://{address}"),
            &spool.to_string_lossy(),
            &spool.to_string_lossy(),
        );
        config.budget.max_tokens = max_tokens;
        let state = AppState::new(
            config,
            Arc::new(InMemoryStore::new()),
            Arc::new(Sandbox::new(SandboxConfig::default(), Vec::new()).unwrap()),
            Arc::new(NullBus),
            None,
            Arc::new(Ed25519Signer::from_seed([11; 32])),
        )
        .unwrap();
        (state, server)
    }

    fn chat_request(session: &str) -> Request<Body> {
        chat_request_with_payload(session, chat_payload())
    }

    fn chat_request_with_payload(session: &str, payload: Value) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .header("x-ab-session", session)
            .header("x-ab-workflow", "unsigned")
            .body(Body::from(serde_json::to_vec(&payload).unwrap()))
            .unwrap()
    }

    fn chat_payload() -> Value {
        json!({
            "model": "mock",
            "stream": true,
            "messages": [{"role": "user", "content": "hello"}],
        })
    }

    fn active_records(
        directory: &std::path::Path,
        state: &AppState,
        session_id: &str,
    ) -> Vec<crate::worker::ActiveJournalRecord> {
        let digest = ab_core::digest::sha256_hex(session_id.as_bytes());
        let journal =
            std::fs::read_to_string(directory.join(format!("{}.events.ndjson", &digest[..32]))).unwrap();
        journal
            .lines()
            .enumerate()
            .map(|(index, line)| {
                crate::journal::open(
                    &state.journal_key,
                    &format!("{session_id}:active"),
                    index as u64,
                    line.as_bytes(),
                )
                .unwrap()
            })
            .collect()
    }

    #[tokio::test]
    async fn full_chat_close_and_promotion_flow() {
        let directory = tempfile::tempdir().unwrap();
        let (state, provider) = test_state(directory.path()).await;
        let app = build_router(state.clone());

        let response = app.clone().oneshot(chat_request("http-flow")).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers().get("x-ab-session").unwrap(), "http-flow");
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        assert!(String::from_utf8_lossy(&body).contains("[DONE]"));

        let close = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/sessions/http-flow/close")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let close_status = close.status();
        let close_bytes = axum::body::to_bytes(close.into_body(), 64 * 1024).await.unwrap();
        assert_eq!(
            close_status,
            StatusCode::OK,
            "{}",
            String::from_utf8_lossy(&close_bytes)
        );
        let close_body: Value = serde_json::from_slice(&close_bytes).unwrap();
        assert_eq!(close_body["kind"], "atif");
        let artifact = state
            .sessions
            .get("http-flow")
            .unwrap()
            .atif_path
            .lock()
            .clone()
            .unwrap();
        let trajectory: ab_atif::Trajectory =
            serde_json::from_slice(&tokio::fs::read(&artifact).await.unwrap()).unwrap();
        if let Some(destination) = std::env::var_os("AB_HARBOR_INTEROP_OUT") {
            std::fs::copy(&artifact, destination).unwrap();
        }
        assert_eq!(
            trajectory.steps.len(),
            2,
            "request and response must both be captured"
        );
        assert_eq!(trajectory.steps[0].source, ab_atif::Source::User);
        assert!(trajectory.steps[0].metrics.is_none());
        assert_eq!(trajectory.steps[1].source, ab_atif::Source::Agent);
        assert_eq!(trajectory.steps[1].message, Value::String("hello".to_owned()));
        assert_eq!(
            trajectory.steps[1].metrics.as_ref().unwrap().cached_tokens,
            Some(4)
        );

        let promoted = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/sessions/http-flow/promote")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(promoted.status(), StatusCode::OK);
        let receipt: ab_receipts::Receipt = serde_json::from_slice(
            &axum::body::to_bytes(promoted.into_body(), 64 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        receipt.verify_embedded().unwrap();
        assert_eq!(receipt.body.stop_reason_id, ab_events::StopReason::Stop.id());
        assert_eq!(receipt.body.cost.completion_tokens, 3);
        assert_eq!(receipt.body.cost.cached_tokens, 4);
        assert_eq!(receipt.body.cost.cost_usd_micros, 1_250);
        assert_eq!(
            receipt.body.cost.prompt_tokens,
            ab_core::tokens::approx_tokens(&chat_payload().to_string()),
            "provider prompt usage must not be added a second time"
        );
        provider.abort();
    }

    #[tokio::test]
    async fn mcp_metrics_and_abort_paths_are_enforced() {
        let directory = tempfile::tempdir().unwrap();
        let (state, provider) = test_state(directory.path()).await;
        let app = build_router(state.clone());
        let allowed = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/mcp")
                    .header("x-ab-session", "mcp-flow")
                    .body(Body::from(
                        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read","arguments":{}}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(allowed.status(), StatusCode::OK);
        let allowed_body: Value = serde_json::from_slice(
            &axum::body::to_bytes(allowed.into_body(), 64 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(allowed_body["decision_us"].as_u64().unwrap() < 5_000);

        let blocked = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/mcp")
                    .header("x-ab-session", "mcp-flow")
                    .body(Body::from("not-json"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(blocked.status(), StatusCode::FORBIDDEN);

        let metrics_response = app
            .clone()
            .oneshot(Request::builder().uri("/metrics").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let metrics = String::from_utf8_lossy(
            &axum::body::to_bytes(metrics_response.into_body(), 128 * 1024)
                .await
                .unwrap(),
        )
        .into_owned();
        assert!(metrics.contains("ab_stage_duration_seconds") || metrics.contains("ab_sessions"));

        let aborted = app.clone().oneshot(chat_request("abort-flow")).await.unwrap();
        drop(aborted);
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if state
                    .sessions
                    .get("abort-flow")
                    .is_some_and(|session| session.is_closed())
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("abort finalization timed out");
        provider.abort();
    }

    /// The response-body stream drops mid-flight while another task is
    /// closing the session (idle timeout or explicit close). Recorded
    /// scenario: `try_close` in `close_session_locked` transitions
    /// `closed` 0→1, then blocks in `wait_for_streams` because the
    /// client still holds the response body's `SessionLease`. When
    /// the client eventually drops the response, `AbortFinalizingStream::drop`
    /// used to see `session.is_closed() == true` and return early —
    /// silently skipping `submit_response_capture`. The reader's
    /// response bytes never reached the chain, but `wait_for_streams`
    /// then unblocked and the finalize path signed a receipt whose
    /// `subject.event_count` reflects only the compression event.
    #[tokio::test]
    async fn stream_drop_during_concurrent_close_still_captures_response() {
        let directory = tempfile::tempdir().unwrap();
        let (state, provider) = test_state(directory.path()).await;
        let app = build_router(state.clone());

        let request = Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .header("x-ab-session", "stream-close-race")
            .header("x-ab-workflow", "signed")
            .body(Body::from(serde_json::to_vec(&chat_payload()).unwrap()))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let session = state.sessions.get("stream-close-race").unwrap();

        let close_task = {
            let finalizer = state.finalizer.clone();
            let session = Arc::clone(&session);
            tokio::spawn(async move { finalizer.close_session(session, StopReason::SessionClosed).await })
        };

        tokio::time::timeout(Duration::from_secs(1), async {
            while !session.is_closed() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("concurrent close did not initiate before the response was dropped");

        drop(response);

        close_task
            .await
            .expect("close_session task panicked")
            .expect("close_session returned an error");

        let final_count = session.chain.lock().count();
        assert!(
            final_count >= 2,
            "AbortFinalizingStream::drop must submit the response capture even when the session is already being closed — otherwise a concurrent close during an active stream discards the response and the receipt attests to fewer events than actually flowed; got chain.count() = {final_count}",
        );

        provider.abort();
    }

    /// Regression for the follow-on to the concurrent-close capture bug. The
    /// original fix removed the `is_closed()` early-return from
    /// `AbortFinalizingStream::drop` so the response capture would still be
    /// submitted while another task drained the stream via
    /// `wait_for_streams`. But `drop` also carried a defensive
    /// `if self.pending_budget.is_some() { self.session.mark_capture_failed(); }`
    /// intended for genuine abort-mid-flight: an in-flight completion-token
    /// budget task means we don't yet know if the token spend would have been
    /// refused, so fail-closed is safe for a normal client disconnect. When
    /// composed with the removal of the `is_closed()` early-return, however,
    /// this fail-closed mark now fires during the concurrent-close scenario
    /// too — even though the concurrent close is imminent and skipping the
    /// last budget verdict is harmless (the response bytes are captured
    /// internally regardless of whether we would have emitted them to the
    /// client). The resulting `capture_failed = 1` then makes the concurrent
    /// close's post-`wait_for_worker_jobs` `if session.capture_failed()` guard
    /// seal the session (`mark_artifact_committed` + committed claim) and
    /// return `Err(FinalizeError::CaptureIncomplete)`: the close is not
    /// retried, and the session finalizes without any artifact — the
    /// capture is silently lost. The fix: gate the pending-budget mark
    /// (and the budget-delta > 0 mark and the flush-error mark) on
    /// `!is_closed`, so during a concurrent close the drop submits the
    /// response capture without fail-closing the session.
    #[tokio::test]
    async fn drop_with_pending_budget_during_concurrent_close_does_not_stick_session() {
        let directory = tempfile::tempdir().unwrap();
        let (state, provider) = test_state(directory.path()).await;

        let identity = ab_events::AgentIdentity {
            version: "1".into(),
            charter: "c".into(),
            instance_uid: "i".into(),
            ttl_remaining_s: None,
        };
        let session = state.sessions.get_or_open(
            "pending-budget-close",
            crate::session::Workflow::Signed,
            &identity,
            &state.config.breaker,
        );
        // Reserve a worker permit up front so `submit_response_capture` in
        // drop has somewhere to send the job.
        let permit = state
            .worker
            .try_reserve("pending-budget-close")
            .expect("test setup: worker permit");
        // Bump active_streams so a concurrent close would block in
        // `wait_for_streams`, mirroring the production scenario.
        let lease = crate::session::SessionLease::new(Arc::clone(&session));

        // Set up an in-flight budget task. Its result is irrelevant to drop —
        // drop only checks `pending_budget.is_some()` — but the JoinHandle
        // has to be a real one so the field type-checks.
        let budget_task =
            tokio::spawn(async { Ok::<_, String>(ab_state::BudgetDecision::Allowed { remaining: 100 }) });

        let stream = AbortFinalizingStream {
            inner: futures::stream::empty::<Result<Bytes, std::io::Error>>().boxed(),
            session: Arc::clone(&session),
            identity: identity.clone(),
            response_permit: Some(permit),
            store: Arc::clone(&state.store),
            budget: state.config.budget.clone(),
            finalizer: state.finalizer.clone(),
            _lease: lease,
            response_marker: None,
            response_attempt_id: "pending-budget-attempt".into(),
            response_message: "captured content".into(),
            response_reasoning: String::new(),
            response_model: None,
            response_finish_reason: Some("stop".into()),
            upstream_status: StatusCode::OK,
            response_cost_usd_micros: 0,
            response_tool_calls: std::collections::BTreeMap::new(),
            response_metrics: ab_events::EventMetrics::default(),
            charged_completion_tokens: 3,
            last_reported_completion_tokens: Some(3),
            last_reported_prompt_tokens: None,
            last_reported_cached_tokens: None,
            last_reported_cost_usd_micros: None,
            saw_chunk: true,
            capture_submitted: false,
            is_sse: true,
            protocol_buffer: Vec::new(),
            pending_output: std::collections::VecDeque::new(),
            pending_budget: Some(PendingBudget {
                task: budget_task,
                continuation: BudgetContinuation::FinishSse,
            }),
            captured_bytes: 100,
            completed: false,
        };

        // Simulate the concurrent close's `try_close` having already fired.
        assert!(session.try_close(), "test setup: try_close should have won");
        assert!(session.is_closed());

        // Drop the stream. This is what happens when the response body is
        // released while another task is blocked in `wait_for_streams`.
        drop(stream);

        assert!(
            !session.capture_failed(),
            "AbortFinalizingStream::drop must not fail the capture just because a completion-token budget check was still in flight while a concurrent close is already draining this stream via wait_for_streams — otherwise close_session_locked's capture_failed guard seals the session and returns CaptureIncomplete: the receipt is never signed and the capture is lost",
        );

        // Now run the concurrent close to completion. It must succeed —
        // wait_for_streams sees active=0 (lease dropped), wait_for_worker_jobs
        // drains the response job we just submitted, and the capture_failed
        // check must find `false` so the finalize path can proceed to
        // sign the receipt.
        let outcome = tokio::time::timeout(
            Duration::from_secs(3),
            state
                .finalizer
                .close_session(Arc::clone(&session), StopReason::SessionClosed),
        )
        .await
        .expect("close_session hung after drop released the stream");
        outcome.expect(
            "close_session must succeed after AbortFinalizingStream::drop submits the response capture — a session sealed without its artifact is worse than a marginally-over-budget response record, because the receipt is lost entirely",
        );

        provider.abort();
    }

    #[tokio::test]
    async fn duplicate_tool_id_replays_outcome_without_reexecution() {
        let tool_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tool_address = tool_listener.local_addr().unwrap();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let tool_router = Router::new()
            .route("/mcp", post(counting_tool))
            .with_state(Arc::clone(&calls));
        let tool_server = tokio::spawn(async move {
            axum::serve(tool_listener, tool_router).await.unwrap();
        });
        let directory = tempfile::tempdir().unwrap();
        let (mut state, provider) = test_state(directory.path()).await;
        Arc::get_mut(&mut state.config).unwrap().tool_upstream_url =
            Some(format!("http://{tool_address}/mcp"));
        let app = build_router(state.clone());
        let body = r#"{"jsonrpc":"2.0","id":"once","method":"tools/call","params":{"name":"read","arguments":{"id":7}}}"#;
        for _ in 0..2 {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/v1/mcp")
                        .header("x-ab-session", "tool-once")
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                axum::body::to_bytes(response.into_body(), 64 * 1024)
                    .await
                    .unwrap(),
                body
            );
        }
        assert_eq!(calls.load(std::sync::atomic::Ordering::Acquire), 1);
        let session = state.sessions.get("tool-once").unwrap();
        assert_eq!(
            session
                .totals
                .tool_calls
                .load(std::sync::atomic::Ordering::Acquire),
            1
        );
        let audited_path = std::fs::read_dir(directory.path().join(crate::spool::TOOL_EXECUTIONS))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| path.extension().is_some_and(|extension| extension == "audited"))
            .unwrap();
        std::fs::remove_file(audited_path).unwrap();
        let unaudited_replay = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/mcp")
                    .header("x-ab-session", "tool-once")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unaudited_replay.status(), StatusCode::OK);
        assert_eq!(calls.load(std::sync::atomic::Ordering::Acquire), 1);
        assert_eq!(
            session
                .totals
                .tool_calls
                .load(std::sync::atomic::Ordering::Acquire),
            1,
            "unaudited outcome recovery must not spend tool budget again"
        );

        let changed_request = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/mcp")
                    .header("x-ab-session", "tool-once")
                    .body(Body::from(
                        r#"{"jsonrpc":"2.0","id":"once","method":"tools/call","params":{"name":"read","arguments":{"id":8}}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(changed_request.status(), StatusCode::CONFLICT);
        assert_eq!(calls.load(std::sync::atomic::Ordering::Acquire), 1);
        tool_server.abort();
        provider.abort();
    }

    /// End-to-end proof that a configured upstream API key is injected on
    /// the upstream wire: a capturing mock provider records the header the
    /// harness actually sent for both Bearer and Azure raw-key styles, and
    /// the passthrough mode relays the client's own Authorization header.
    #[tokio::test]
    async fn upstream_auth_header_reaches_provider_wire() {
        type Captured = Arc<parking_lot::Mutex<Vec<(Option<String>, Option<String>)>>>;
        async fn capture_chat(
            State(captured): State<Captured>,
            headers: HeaderMap,
            Json(_): Json<Value>,
        ) -> Response {
            captured.lock().push((
                headers
                    .get(axum::http::header::AUTHORIZATION)
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned),
                headers
                    .get("api-key")
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned),
            ));
            Json(json!({"choices": [], "usage": {"prompt_tokens": 1, "completion_tokens": 1}}))
                .into_response()
        }
        let captured: Captured = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let provider_router = Router::new()
            .route("/v1/chat/completions", post(capture_chat))
            .route("/openai/deployments/d1/chat/completions", post(capture_chat))
            .with_state(Arc::clone(&captured));
        let provider = tokio::spawn(async move {
            axum::serve(listener, provider_router).await.unwrap();
        });
        let directory = tempfile::tempdir().unwrap();
        let key_path = directory.path().join("upstream.key");
        std::fs::write(&key_path, "sk-wire-test\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let spool = directory.path().to_string_lossy();
        let build_state = |config: crate::config::HarnessConfig| {
            AppState::new(
                config,
                Arc::new(InMemoryStore::new()),
                Arc::new(Sandbox::new(SandboxConfig::default(), Vec::new()).unwrap()),
                Arc::new(NullBus),
                None,
                Arc::new(Ed25519Signer::from_seed([12; 32])),
            )
            .unwrap()
        };
        let send_chat = |state: AppState, authorization: Option<&'static str>| async move {
            let mut request = Request::builder()
                .method("POST")
                .uri("/v1/chat/completions")
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .header("x-ab-session", "auth-wire");
            if let Some(value) = authorization {
                request = request.header(axum::http::header::AUTHORIZATION, value);
            }
            let response = build_router(state)
                .oneshot(request.body(Body::from(chat_payload().to_string())).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        };

        // 1) Bearer key from an owner-only file.
        let mut config =
            crate::config::HarnessConfig::for_tests(&format!("http://{address}"), &spool, &spool);
        config.upstream_api_key_file = Some(key_path.to_string_lossy().into_owned());
        send_chat(build_state(config), None).await;
        assert_eq!(
            captured.lock().pop().unwrap(),
            (Some("Bearer sk-wire-test".to_owned()), None),
            "Bearer credential must reach the provider"
        );

        // 2) Azure style: raw key in a custom header on a custom path.
        let mut config =
            crate::config::HarnessConfig::for_tests(&format!("http://{address}"), &spool, &spool);
        config.upstream_api_key_file = Some(key_path.to_string_lossy().into_owned());
        config.upstream_auth_header = "api-key".into();
        config.upstream_auth_scheme = String::new();
        config.upstream_chat_path = "/openai/deployments/d1/chat/completions".into();
        send_chat(build_state(config), None).await;
        assert_eq!(
            captured.lock().pop().unwrap(),
            (None, Some("sk-wire-test".to_owned())),
            "raw key must reach the provider on the configured path and header"
        );

        // 3) Passthrough: the client's own Authorization header is relayed.
        let mut config =
            crate::config::HarnessConfig::for_tests(&format!("http://{address}"), &spool, &spool);
        config.upstream_authorization_passthrough = true;
        send_chat(build_state(config), Some("Bearer client-owned-key")).await;
        assert_eq!(
            captured.lock().pop().unwrap(),
            (Some("Bearer client-owned-key".to_owned()), None),
            "passthrough must relay the client credential"
        );

        // 4) No auth configured: no Authorization header appears upstream.
        let config = crate::config::HarnessConfig::for_tests(&format!("http://{address}"), &spool, &spool);
        send_chat(build_state(config), Some("Bearer client-owned-key")).await;
        assert_eq!(
            captured.lock().pop().unwrap(),
            (None, None),
            "without passthrough the client credential must NOT leak upstream"
        );
        provider.abort();
    }

    /// The tool-upstream bearer token must be injected on forwarded MCP
    /// calls (and must not depend on the caller's own headers).
    #[tokio::test]
    async fn tool_upstream_bearer_reaches_tool_server() {
        type Captured = Arc<parking_lot::Mutex<Vec<Option<String>>>>;
        async fn capture_tool(State(captured): State<Captured>, headers: HeaderMap, body: Bytes) -> Response {
            captured.lock().push(
                headers
                    .get(axum::http::header::AUTHORIZATION)
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned),
            );
            (StatusCode::OK, body).into_response()
        }
        let captured: Captured = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let tool_router = Router::new()
            .route("/mcp", post(capture_tool))
            .with_state(Arc::clone(&captured));
        let tool_server = tokio::spawn(async move {
            axum::serve(listener, tool_router).await.unwrap();
        });
        let directory = tempfile::tempdir().unwrap();
        let token_path = directory.path().join("mcp.token");
        std::fs::write(&token_path, "tool-secret\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let (mut state, provider) = test_state(directory.path()).await;
        {
            let config = Arc::get_mut(&mut state.config).unwrap();
            config.tool_upstream_url = Some(format!("http://{address}/mcp"));
            config.tool_upstream_bearer_file = Some(token_path.to_string_lossy().into_owned());
        }
        // test_state resolved auth from the pre-mutation config; re-resolve.
        state.tool_auth = crate::pipeline::resolve_tool_auth(&state.config).unwrap();
        let response = build_router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/mcp")
                    .header("x-ab-session", "tool-auth")
                    .body(Body::from(
                        r#"{"jsonrpc":"2.0","id":"t1","method":"tools/call","params":{"name":"read","arguments":{}}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            captured.lock().pop().unwrap().as_deref(),
            Some("Bearer tool-secret"),
            "tool bearer must reach the tool server"
        );
        tool_server.abort();
        provider.abort();
    }

    #[tokio::test]
    async fn startup_refuses_pending_and_unaudited_tool_effects() {
        let directory = tempfile::tempdir().unwrap();
        let control_key = [31; 32];
        let mut headers = HeaderMap::new();
        headers.insert("x-ab-session", HeaderValue::from_static("tool-recovery"));
        let body = br#"{"jsonrpc":"2.0","id":"recover","method":"tools/call","params":{"name":"read","arguments":{}}}"#;
        let mut execution =
            ToolExecution::from_request(&directory.path().to_string_lossy(), &headers, body, control_key)
                .unwrap();
        execution
            .bind_principal(&ab_events::AgentIdentity {
                version: "dev".to_owned(),
                charter: "anonymous".into(),
                instance_uid: "anonymous".to_owned(),
                ttl_remaining_s: None,
            })
            .unwrap();
        execution.claim().await.unwrap();
        assert!(
            ensure_no_unresolved_tool_executions(directory.path(), &control_key)
                .await
                .is_err()
        );
        execution
            .persist(&ToolOutcome {
                status: 200,
                body_hex: hex::encode(body),
            })
            .await
            .unwrap();
        assert!(
            ensure_no_unresolved_tool_executions(directory.path(), &control_key)
                .await
                .is_err()
        );
        execution.mark_audited().await.unwrap();
        ensure_no_unresolved_tool_executions(directory.path(), &control_key)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn tool_redirect_is_terminal_and_never_replays_post() {
        let tool_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tool_address = tool_listener.local_addr().unwrap();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let tool_router = Router::new()
            .route("/redirect", post(redirecting_tool))
            .route("/effect", post(redirected_effect))
            .with_state(Arc::clone(&calls));
        let tool_server = tokio::spawn(async move {
            axum::serve(tool_listener, tool_router).await.unwrap();
        });
        let directory = tempfile::tempdir().unwrap();
        let (mut state, provider) = test_state(directory.path()).await;
        Arc::get_mut(&mut state.config).unwrap().tool_upstream_url =
            Some(format!("http://{tool_address}/redirect"));
        let response = build_router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/mcp")
                    .header("x-ab-session", "tool-redirect")
                    .body(Body::from(
                        r#"{"jsonrpc":"2.0","id":"redirect","method":"tools/call","params":{"name":"read","arguments":{}}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(calls.load(std::sync::atomic::Ordering::Acquire), 1);
        tool_server.abort();
        provider.abort();
    }

    #[tokio::test]
    async fn concurrent_duplicate_tool_claims_conflict_without_leaking_io_detail() {
        let tool_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tool_address = tool_listener.local_addr().unwrap();
        let held = Arc::new(HeldToolState {
            arrived: std::sync::atomic::AtomicBool::new(false),
            release: tokio::sync::Notify::new(),
        });
        let tool_router = Router::new()
            .route("/mcp", post(held_tool))
            .with_state(Arc::clone(&held));
        let tool_server = tokio::spawn(async move {
            axum::serve(tool_listener, tool_router).await.unwrap();
        });
        let directory = tempfile::tempdir().unwrap();
        let (mut state, provider) = test_state(directory.path()).await;
        Arc::get_mut(&mut state.config).unwrap().tool_upstream_url =
            Some(format!("http://{tool_address}/mcp"));
        let app = build_router(state);
        let request = || {
            Request::builder()
                .method("POST")
                .uri("/v1/mcp")
                .header("x-ab-session", "claim-race")
                .body(Body::from(
                    r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"read","arguments":{}}}"#,
                ))
                .unwrap()
        };
        let winner_app = app.clone();
        let winner = tokio::spawn(async move { winner_app.oneshot(request()).await.unwrap() });
        tokio::time::timeout(Duration::from_secs(1), async {
            while !held.arrived.load(std::sync::atomic::Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        // The winner holds the claim while its upstream call is in flight;
        // an identical duplicate must lose the race with the canonical
        // uncertainty message and no io/filesystem detail.
        let loser = app.oneshot(request()).await.unwrap();
        assert_eq!(loser.status(), StatusCode::CONFLICT);
        let body = axum::body::to_bytes(loser.into_body(), 64 * 1024).await.unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains(TOOL_OUTCOME_UNCERTAIN), "{text}");
        assert!(!text.contains("os error"), "leaked io detail: {text}");
        held.release.notify_one();
        assert_eq!(winner.await.unwrap().status(), StatusCode::OK);
        tool_server.abort();
        provider.abort();
    }

    #[tokio::test]
    async fn close_waits_for_tool_execution_and_completion_capture() {
        let tool_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tool_address = tool_listener.local_addr().unwrap();
        let held = Arc::new(HeldToolState {
            arrived: std::sync::atomic::AtomicBool::new(false),
            release: tokio::sync::Notify::new(),
        });
        let tool_router = Router::new()
            .route("/mcp", post(held_tool))
            .with_state(Arc::clone(&held));
        let tool_server = tokio::spawn(async move {
            axum::serve(tool_listener, tool_router).await.unwrap();
        });
        let directory = tempfile::tempdir().unwrap();
        let (mut state, provider) = test_state(directory.path()).await;
        Arc::get_mut(&mut state.config).unwrap().tool_upstream_url =
            Some(format!("http://{tool_address}/mcp"));
        let app = build_router(state);
        let tool_app = app.clone();
        let tool_task = tokio::spawn(async move {
            tool_app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/v1/mcp")
                        .header("x-ab-session", "held-tool")
                        .body(Body::from(
                            r#"{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"read","arguments":{}}}"#,
                        ))
                        .unwrap(),
                )
                .await
                .unwrap()
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            while !held.arrived.load(std::sync::atomic::Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let close_task = tokio::spawn(async move {
            app.oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/sessions/held-tool/close")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
        });
        tokio::task::yield_now().await;
        assert!(!close_task.is_finished(), "close overtook the executing tool");
        held.release.notify_one();
        assert_eq!(tool_task.await.unwrap().status(), StatusCode::OK);
        let close_response = close_task.await.unwrap();
        let close_status = close_response.status();
        let close_body = axum::body::to_bytes(close_response.into_body(), 64 * 1024)
            .await
            .unwrap();
        assert_eq!(
            close_status,
            StatusCode::OK,
            "close failed: {}",
            String::from_utf8_lossy(&close_body)
        );
        tool_server.abort();
        provider.abort();
    }

    #[test]
    fn provider_usage_and_reasoning_are_preserved() {
        let raw = concat!(
            "data: {\"model\":\"gpt-test\",\"choices\":[{\"delta\":{",
            "\"content\":\"answer\",\"reasoning_content\":\"thought\"},\"finish_reason\":\"stop\"}],",
            "\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":3,\"cost_usd\":0.00125,",
            "\"prompt_tokens_details\":{\"cached_tokens\":4}}}\n\n"
        );
        let parsed = parse_provider_chunk(raw).unwrap().unwrap();
        assert_eq!(parsed.message, "answer");
        assert_eq!(parsed.reasoning.as_deref(), Some("thought"));
        assert_eq!(parsed.model_name.as_deref(), Some("gpt-test"));
        assert_eq!(parsed.metrics.prompt_tokens, Some(10));
        assert_eq!(parsed.metrics.completion_tokens, Some(3));
        assert_eq!(parsed.metrics.cached_tokens, Some(4));
        assert!(parsed.usage_reported);
        assert_eq!(parsed.finish_reason.as_deref(), Some("stop"));
        assert_eq!(parsed.cost_usd_micros, 1250);
        assert!(parsed.tool_call_deltas.is_empty());
    }

    #[test]
    fn hostile_provider_metrics_are_rejected() {
        for raw in [
            r#"{"usage":{"completion_tokens":9007199254740993}}"#,
            r#"{"usage":{"prompt_tokens":-1}}"#,
            r#"{"usage":{"prompt_tokens_details":{"cached_tokens":"many"}}}"#,
            r#"{"usage":{"cost_usd":1e30}}"#,
            r#"{"usage":{"cost_usd":-1}}"#,
        ] {
            assert!(
                parse_provider_chunk(raw).is_err(),
                "accepted hostile metrics: {raw}"
            );
        }
    }

    #[test]
    fn streaming_tool_call_arguments_reassemble() {
        let first = r#"data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call-1","function":{"name":"db_write","arguments":"{\"table\":"}}]}}]}"#;
        let second = r#"data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"items\",\"row\":{}}"}}]},"finish_reason":"tool_calls"}]}"#;
        let first_delta = parse_provider_chunk(first).unwrap().unwrap().tool_call_deltas;
        let second_delta = parse_provider_chunk(second).unwrap().unwrap().tool_call_deltas;
        assert_eq!(first_delta.len(), 1);
        assert_eq!(second_delta.len(), 1);
        let arguments = format!("{}{}", first_delta[0].arguments, second_delta[0].arguments);
        assert_eq!(
            serde_json::from_str::<Value>(&arguments).unwrap(),
            json!({"table": "items", "row": {}})
        );
        assert_eq!(map_finish_reason("tool_calls"), StopReason::ToolUse);
    }

    #[test]
    fn hostile_provider_tool_call_index_is_rejected() {
        let raw = r#"data: {"choices":[{"delta":{"tool_calls":[{"index":18446744073709551615,"function":{"name":"n","arguments":"{}"}}]}}]}"#;
        let parsed = parse_provider_chunk(raw).unwrap().unwrap();
        assert_eq!(parsed.tool_call_deltas.len(), 1);
        assert_eq!(parsed.tool_call_deltas[0].index, u64::MAX);
    }

    #[test]
    fn non_stream_tool_calls_receive_distinct_positional_indices() {
        let parsed = parse_provider_chunk(
            r#"{"choices":[{"message":{"tool_calls":[{"id":"a","function":{"name":"read","arguments":"{}"}},{"id":"b","function":{"name":"write","arguments":"{}"}}]}}]}"#,
        )
        .unwrap()
        .unwrap();
        assert_eq!(parsed.tool_call_deltas.len(), 2);
        assert_eq!(parsed.tool_call_deltas[0].index, 0);
        assert_eq!(parsed.tool_call_deltas[1].index, 1);
    }

    #[test]
    fn sse_frame_boundary_accepts_crlf_and_cr() {
        assert_eq!(sse_frame_end(b"data: {}\r\n\r"), None);
        assert_eq!(sse_frame_end(b"data: {}\r\n\r\nrest"), Some(12));
        assert_eq!(sse_frame_end(b"data: {}\r\rrest"), Some(10));
    }

    #[tokio::test]
    async fn split_non_sse_utf8_is_captured_as_one_json_document() {
        let directory = tempfile::tempdir().unwrap();
        let (state, provider) = test_state(directory.path()).await;
        let app = build_router(state.clone());
        let response = app
            .oneshot(chat_request_with_payload(
                "split-json",
                json!({
                    "model": "split-json",
                    "stream": false,
                    "messages": [{"role": "user", "content": "hello"}]
                }),
            ))
            .await
            .unwrap();
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap()["choices"][0]["message"]["content"],
            "héllo"
        );
        let session = state.sessions.get("split-json").unwrap();
        session.wait_for_worker_jobs().await;
        let crate::reconciler::FinalizeOutcome::Atif { path } = state
            .finalizer
            .close_session(session, StopReason::SessionClosed)
            .await
            .unwrap()
        else {
            panic!("expected ATIF")
        };
        let trajectory: ab_atif::Trajectory = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(trajectory.steps[1].message, Value::String("héllo".to_owned()));
        provider.abort();
    }

    #[tokio::test]
    async fn malformed_non_sse_json_fails_capture_before_delivery() {
        let directory = tempfile::tempdir().unwrap();
        let (state, provider) = test_state(directory.path()).await;
        let app = build_router(state.clone());
        let response = app
            .oneshot(chat_request_with_payload(
                "malformed-json",
                json!({
                    "model": "malformed-json",
                    "stream": false,
                    "messages": [{"role": "user", "content": "hello"}]
                }),
            ))
            .await
            .unwrap();
        // The non-SSE path drains the relay server-side, so a capture
        // failure surfaces as a clean 502 + JSON error instead of a
        // committed 200 with a severed body.
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        assert!(serde_json::from_slice::<Value>(&body).unwrap()["error"].is_string());
        let session = state.sessions.get("malformed-json").unwrap();
        assert!(session.capture_failed());
        provider.abort();
    }

    #[tokio::test]
    async fn repeated_provider_responses_open_the_loop_breaker() {
        let directory = tempfile::tempdir().unwrap();
        let (mut state, provider) = test_state(directory.path()).await;
        let config = Arc::get_mut(&mut state.config).unwrap();
        config.breaker.min_tokens = 0;
        config.breaker.window = 3;
        let app = build_router(state.clone());
        for _ in 0..4 {
            let response = app.clone().oneshot(chat_request("response-loop")).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            axum::body::to_bytes(response.into_body(), 64 * 1024)
                .await
                .unwrap();
            state
                .sessions
                .get("response-loop")
                .unwrap()
                .wait_for_worker_jobs()
                .await;
        }
        let blocked = app.oneshot(chat_request("response-loop")).await.unwrap();
        assert_eq!(blocked.status(), StatusCode::TOO_MANY_REQUESTS);
        provider.abort();
    }

    #[tokio::test]
    async fn empty_and_failed_upstream_responses_are_audited_as_failures() {
        let directory = tempfile::tempdir().unwrap();
        let (state, provider) = test_state(directory.path()).await;
        let app = build_router(state.clone());
        for (session_id, model) in [("empty-error", "empty-error"), ("json-error", "json-error")] {
            let response = app
                .clone()
                .oneshot(chat_request_with_payload(
                    session_id,
                    json!({
                        "model": model,
                        "stream": false,
                        "messages": [{"role": "user", "content": "hello"}]
                    }),
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
            axum::body::to_bytes(response.into_body(), 64 * 1024)
                .await
                .unwrap();
            let session = state.sessions.get(session_id).unwrap();
            session.wait_for_worker_jobs().await;
            assert!(!session.capture_failed());
            let records = active_records(directory.path(), &state, session_id);
            assert_eq!(records.len(), 2);
            let event: ab_events::OcsfEvent =
                serde_json::from_value(records.last().unwrap().event.clone()).unwrap();
            assert_eq!(event.class_name, ab_events::EventClass::StopReason);
            assert_eq!(event.status_id, ab_events::StatusId::Failure.id());
            assert_eq!(event.payload["http_status"], 500);
        }
        provider.abort();
    }

    #[tokio::test]
    async fn regressing_provider_usage_fails_capture_before_later_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let (state, provider) = test_state(directory.path()).await;
        let response = build_router(state.clone())
            .oneshot(chat_request_with_payload(
                "regressive-usage",
                json!({
                    "model": "regressive-usage",
                    "stream": true,
                    "messages": [{"role": "user", "content": "hello"}]
                }),
            ))
            .await
            .unwrap();
        assert!(axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .is_err());
        let session = state.sessions.get("regressive-usage").unwrap();
        assert!(session.capture_failed());
        session.wait_for_worker_jobs().await;
        let records = active_records(directory.path(), &state, "regressive-usage");
        assert_eq!(records.len(), 1);
        assert!(records[0]
            .response_attempt
            .as_ref()
            .is_some_and(|attempt| !attempt.terminal));
        provider.abort();
    }

    #[tokio::test]
    async fn successful_provider_response_requires_choices() {
        let directory = tempfile::tempdir().unwrap();
        let (state, provider) = test_state(directory.path()).await;
        let response = build_router(state.clone())
            .oneshot(chat_request_with_payload(
                "empty-success",
                json!({
                    "model": "empty-success",
                    "stream": false,
                    "messages": [{"role": "user", "content": "hello"}]
                }),
            ))
            .await
            .unwrap();
        // Missing choices fails capture; the server-side drain converts
        // the refusal into a 502 + JSON error rather than a severed body.
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        assert!(serde_json::from_slice::<Value>(&body).unwrap()["error"].is_string());
        assert!(state.sessions.get("empty-success").unwrap().capture_failed());
        provider.abort();
    }

    #[tokio::test]
    async fn cumulative_usage_settles_against_provisional_charge() {
        let directory = tempfile::tempdir().unwrap();
        let payload = json!({
            "model": "provisional-usage",
            "stream": true,
            "messages": [{"role": "user", "content": "hello"}]
        });
        let prompt_tokens = ab_core::tokens::approx_tokens(&payload.to_string());
        let (state, provider) = test_state_with_token_cap(directory.path(), Some(prompt_tokens + 2)).await;
        let response = build_router(state.clone())
            .oneshot(chat_request_with_payload("provisional-usage", payload))
            .await
            .unwrap();
        assert!(axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .is_ok());
        let session = state.sessions.get("provisional-usage").unwrap();
        session.wait_for_worker_jobs().await;
        assert_eq!(
            session
                .totals
                .completion_tokens
                .load(std::sync::atomic::Ordering::Acquire),
            2
        );
        provider.abort();
    }

    #[tokio::test]
    async fn provider_tool_call_index_out_of_range_fails_capture() {
        let directory = tempfile::tempdir().unwrap();
        let (state, provider) = test_state(directory.path()).await;
        let response = build_router(state.clone())
            .oneshot(chat_request_with_payload(
                "tool-oob-index",
                json!({
                    "model": "tool-oob-index",
                    "stream": true,
                    "messages": [{"role": "user", "content": "hello"}]
                }),
            ))
            .await
            .unwrap();
        assert!(axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .is_err());
        assert!(state.sessions.get("tool-oob-index").unwrap().capture_failed());
        provider.abort();
    }

    #[tokio::test]
    async fn tool_arguments_without_usage_are_budgeted_before_delivery() {
        let directory = tempfile::tempdir().unwrap();
        let payload = json!({
            "model": "tool-no-usage",
            "stream": true,
            "messages": [{"role": "user", "content": "hello"}]
        });
        let prompt_tokens = ab_core::tokens::approx_tokens(&payload.to_string());
        let (state, provider) = test_state_with_token_cap(directory.path(), Some(prompt_tokens)).await;
        let response = build_router(state)
            .oneshot(chat_request_with_payload("tool-no-usage", payload))
            .await
            .unwrap();
        assert!(axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .is_err());
        provider.abort();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn completion_budget_store_does_not_block_stream_runtime() {
        let directory = tempfile::tempdir().unwrap();
        let (mut state, provider) = test_state_with_token_cap(directory.path(), Some(10_000)).await;
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        state.store = Arc::new(SlowStore {
            inner: InMemoryStore::new(),
            calls: Arc::clone(&calls),
        });
        let response = build_router(state)
            .oneshot(chat_request("slow-budget"))
            .await
            .unwrap();
        let body = tokio::spawn(async move {
            axum::body::to_bytes(response.into_body(), 64 * 1024)
                .await
                .unwrap()
        });

        let started = std::time::Instant::now();
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(
            started.elapsed() < Duration::from_millis(75),
            "completion budget storage blocked the Tokio reactor"
        );
        assert!(!body.await.unwrap().is_empty());
        assert_eq!(calls.load(std::sync::atomic::Ordering::Acquire), 2);
        provider.abort();
    }

    #[tokio::test]
    async fn completion_tokens_are_blocked_before_delivery() {
        let directory = tempfile::tempdir().unwrap();
        let prompt_tokens = ab_core::tokens::approx_tokens(&chat_payload().to_string());
        let (state, provider) = test_state_with_token_cap(directory.path(), Some(prompt_tokens)).await;
        let app = build_router(state.clone());
        let response = app.oneshot(chat_request("completion-budget")).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .is_err());
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if state
                    .sessions
                    .get("completion-budget")
                    .is_some_and(|session| session.is_closed())
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        provider.abort();
    }

    /// Regression lock for the upstream-response header forwarding
    /// trust-boundary bug (CWE-346 / CWE-16). Before the fix, every
    /// upstream response header except `Content-Length` was blindly
    /// forwarded to the client — letting a hostile or MITM'd upstream
    ///
    /// - set cookies on our domain (`Set-Cookie`),
    /// - open CORS on our origin (`Access-Control-Allow-*`),
    /// - leak upstream implementation identity (`Server`, `Via`,
    ///   `X-Powered-By`, `X-Request-ID`),
    /// - inject conflicting framing/hop-by-hop metadata (`Connection`,
    ///   `Transfer-Encoding`, `Keep-Alive`, `Upgrade`, `TE`, `Trailer`,
    ///   `Proxy-Authenticate`, `Proxy-Authorization`).
    ///
    /// `is_forwardable_upstream_header` is now the sole gate on which
    /// upstream headers cross the proxy trust boundary — this test locks
    /// each dangerous class out and confirms benign headers (`Content-Type`,
    /// `Cache-Control`, `ETag`) still pass through.
    #[test]
    fn upstream_response_headers_do_not_cross_proxy_trust_boundary() {
        use axum::http::HeaderName;
        let dangerous = [
            // Cookie injection on our domain from a hostile upstream.
            "set-cookie",
            // CORS bypass — we never let the upstream open our origin.
            "access-control-allow-origin",
            "access-control-allow-credentials",
            "access-control-allow-methods",
            "access-control-allow-headers",
            "access-control-expose-headers",
            "access-control-max-age",
            // RFC 7230 §6.1 hop-by-hop headers — a proxy must not
            // forward these; forwarding `Transfer-Encoding` enables
            // classical HTTP request smuggling.
            "connection",
            "keep-alive",
            "transfer-encoding",
            "upgrade",
            "te",
            "trailer",
            "proxy-authenticate",
            "proxy-authorization",
            // Framing metadata that hyper computes from the response
            // body; the upstream's value would be wrong.
            "content-length",
            // Implementation-identity leaks.
            "server",
            "via",
            "x-powered-by",
            "x-request-id",
        ];
        for name in dangerous {
            let header = HeaderName::from_static(name);
            assert!(
                !is_forwardable_upstream_header(&header),
                "dangerous header {name:?} must not be forwarded to the client"
            );
        }

        let benign = [
            "content-type",
            "content-encoding",
            "cache-control",
            "etag",
            "last-modified",
            "vary",
            "expires",
        ];
        for name in benign {
            let header = HeaderName::from_static(name);
            assert!(
                is_forwardable_upstream_header(&header),
                "benign header {name:?} must still be forwarded"
            );
        }
    }

    /// Regression lock for CWE-209 information exposure on the MCP
    /// tool-call path — the second occurrence of pass 17's chat/completion
    /// leak. Before this fix, when the tool-upstream request failed
    /// (unroutable host, timeout, TLS error, …) `mcp_call` returned
    /// `lifecycle_error(format!("forward tool call: {reqwest_err}"))`
    /// which — because `reqwest::Error::Display` embeds the request URL —
    /// leaked the operator-configured tool-upstream URL (potentially an
    /// internal hostname) to any client that could hit `/mcp`. The
    /// `read_limited_tool_response` mid-stream error path had the same
    /// bug. The client-facing message must now be a stable, non-identifying
    /// category (e.g. `"upstream unreachable"`), matching pass 17's
    /// classifier categories.
    #[tokio::test]
    async fn mcp_tool_upstream_failure_does_not_leak_configured_url() {
        // Distinctive sentinel host so any regression is unmissable.
        let sentinel_host = "internal-mcp-sentinel-host.corp.example";
        let sentinel_url = format!("http://{sentinel_host}:65002/mcp");
        let directory = tempfile::tempdir().unwrap();
        let (mut state, provider) = test_state(directory.path()).await;
        Arc::get_mut(&mut state.config).unwrap().tool_upstream_url = Some(sentinel_url);
        let response = build_router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/mcp")
                    .header("x-ab-session", "mcp-cwe-209-check")
                    .body(Body::from(
                        r#"{"jsonrpc":"2.0","id":"leak","method":"tools/call","params":{"name":"read","arguments":{}}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::BAD_GATEWAY,
            "tool-upstream faults must surface as 502 like the chat relay, not 500"
        );
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(
            !body.contains(sentinel_host),
            "MCP forward-tool error body {body:?} leaks the configured tool-upstream host"
        );
        assert!(
            !body.contains("65002"),
            "MCP forward-tool error body {body:?} leaks the configured tool-upstream port"
        );
        assert!(
            !body.contains("corp.example"),
            "MCP forward-tool error body {body:?} leaks the configured tool-upstream domain"
        );
        provider.abort();
    }
}
