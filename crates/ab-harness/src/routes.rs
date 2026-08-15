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
        .route(
            "/v1/chat/completions",
            post(chat_completions).options(cors_deny),
        )
        .route("/v1/mcp", post(mcp_call).options(cors_deny))
        .route("/mcp", post(mcp_call).options(cors_deny))
        .route(
            "/v1/sessions/{id}/close",
            post(close_session).options(cors_deny),
        )
        .route(
            "/v1/sessions/{id}/promote",
            post(promote_session).options(cors_deny),
        );
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
    // Round-13 F5: sanitize the session id BEFORE binding it into the
    // span. Previously the raw header value went in verbatim, which
    // (1) risked unbounded label cardinality on OTLP exporters that
    // map span attributes to metric labels — every distinct
    // client-supplied session id (including hostile garbage) became
    // its own series; (2) created a split-brain when a client sent
    // two `X-AB-Session` headers — `HeaderMap::get` returned the
    // first while `pipeline::single_header` (round-13) refused the
    // whole request, so traces named a "friendly" id for a hard-503;
    // (3) accepted values that pass `HeaderValue::to_str` but fail
    // `SessionId::parse` (too long, control chars in disguise). Use
    // `single_header` + `SessionId::parse` to bind ONE consistent
    // value or the sentinel `"invalid"`.
    // Round-14 F7: use a sentinel that CANNOT pass `SessionId::parse`
    // (0x21..=0x7e visible-ASCII only), so a client cannot legitimately
    // send `X-AB-Session: invalid` and share a trace label with a
    // rejected request. The leading space (0x20) is outside the
    // allowed range → collision-free.
    let headers = request.headers();
    let session_id = match crate::pipeline::single_header(headers, crate::pipeline::SESSION_HEADER) {
        Ok(Some(value)) => value
            .to_str()
            .ok()
            .and_then(|v| ab_core::SessionId::parse(v).ok())
            .map(|id| id.to_string())
            .unwrap_or_else(|| " rejected".to_owned()),
        Ok(None) => "unbound".to_owned(),
        Err(_) => " duplicate-header".to_owned(),
    };
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
    // Round-29 F6: DO NOT expose the CARGO_PKG_VERSION on this
    // unauthenticated endpoint. Version disclosure lets a LAN
    // attacker correlate an agentbridge deployment to a specific
    // known-vulnerable release without needing a chat probe. The
    // authenticated /metrics endpoint still surfaces build info
    // via the ab_build_info HELP text for operators who need it.
    Json(json!({
        "status": "ok",
        // Product identifier so callers (abctl start) can tell a real
        // AgentBridge apart from an unrelated service squatting the
        // port. This is not a version number and reveals no
        // vulnerability-relevant information.
        "service": "agentbridge",
    }))
}

/// Round-31 F5: explicit deny-CORS OPTIONS handler.
///
/// The harness is a same-origin proxy; no cross-origin client is
/// expected or supported. Without this route, axum's default reply to
/// a preflight (`OPTIONS /v1/chat/completions`) is `405 Method Not
/// Allowed` with an `Allow: POST` header — inconsistent with the
/// round-29 F6 "no discoverable posture" hygiene, and confusing to any
/// operator whose LAN browser client accidentally triggers a preflight.
/// Reply with `204 No Content` and NO `Access-Control-Allow-Origin`
/// header: browsers correctly treat this as "cross-origin denied" and
/// refuse the actual request, making the posture explicit at the wire.
async fn cors_deny() -> Response {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::NO_CONTENT;
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    // Do not echo the requester's Origin. Do not include any
    // Access-Control-Allow-* header. This deliberately fails the
    // browser's preflight check.
    response
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
    // reqwest is built without the `gzip` feature (see Cargo.toml), so
    // the client does not decode `Content-Encoding: gzip`. If the
    // provider or a CDN in front of it compresses the SSE response,
    // `absorb_network_chunk` immediately fails
    // `std::str::from_utf8(&frame)` and aborts every stream. Refuse
    // the response up front with a clear error rather than corrupt
    // the audit trail with UTF-8-error frames.
    //
    // Multi-value / multi-line semantics: an upstream that sends
    // `Content-Encoding: identity` on one line and
    // `Content-Encoding: gzip` on another (some layered reverse
    // proxies do this) would slip past a `.get(...)` that only reads
    // the first value. Iterate `get_all` and require EVERY value to
    // be empty or `identity` case-insensitively; also split each
    // value on `,` so `gzip, identity` (single header, two tokens)
    // is caught.
    for value in upstream_headers.get_all(axum::http::header::CONTENT_ENCODING) {
        let raw = value.to_str().unwrap_or_default();
        for token in raw.split(',') {
            let token = token.trim();
            if token.is_empty() || token.eq_ignore_ascii_case("identity") {
                continue;
            }
            return pipeline_error(crate::pipeline::PipelineError::Upstream(format!(
                "upstream responded with unsupported Content-Encoding token {token:?} \
                 (full header: {raw:?}) — the proxy is built without decompression \
                 support; enable it upstream (Accept-Encoding: identity) or rebuild \
                 with the reqwest `gzip` feature"
            )));
        }
    }
    // Round-25 F3: RFC 7231 §3.1.1.1 says media type/subtype are
    // case-insensitive and the header value may carry parameters
    // (`; charset=utf-8`). Byte-exact `starts_with("text/event-stream")`
    // misses `Text/Event-Stream` (some CDNs re-title-case) and can also
    // mis-fire on hypothetical `text/event-stream-json`. Split on `;`
    // then compare with `eq_ignore_ascii_case` so SSE is detected
    // regardless of casing and parameters. A misclassified SSE stream
    // gets buffered to the 16 MiB provider cap in the non-SSE branch
    // and either loses streaming semantics (client sees no deltas
    // until upstream EOF) or is refused with 502 despite being valid.
    let is_sse = is_sse_content_type(&upstream_headers);
    let stream = upstream
        .bytes_stream()
        .map(|chunk| chunk.map_err(std::io::Error::other));
    let stream = AbortFinalizingStream {
        inner: stream.boxed(),
        session,
        identity,
        response_permit: Some(response_permit),
        worker: state.worker.clone(),
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
    // Round-29 F4: pin `X-Content-Type-Options: nosniff` on every
    // upstream-relayed response. The relay forwards the upstream's
    // Content-Type verbatim (validated by our `is_sse_content_type`
    // for framing decisions, but not sanitised for the client).
    // A rogue upstream, MITM at egress, or CDN mis-config could
    // otherwise flip Content-Type to `text/html; charset=utf-8` on
    // a body carrying prompt-echoed attacker bytes — turning what
    // the audit trail attests as "assistant output" into HTML the
    // browser might render. `nosniff` prevents browser-side MIME
    // sniffing from disagreeing with the declared type and closes
    // the reflected-content path.
    response.headers_mut().insert(
        axum::http::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
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

/// Round-25 F3: detect `text/event-stream` in `Content-Type`
/// case-insensitively, accepting parameters like `; charset=utf-8`.
/// RFC 7231 §3.1.1.1 says media type/subtype are case-insensitive.
/// Byte-exact matching missed `Text/Event-Stream` (some CDNs
/// re-title-case) and mis-fired on hypothetical
/// `text/event-stream-json`. Misclassification cost: the non-SSE
/// branch buffers up to the 16 MiB provider cap and either loses
/// streaming semantics or refuses valid streams with 502.
fn is_sse_content_type(headers: &HeaderMap) -> bool {
    headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            let head = value.split(';').next().unwrap_or("").trim();
            head.eq_ignore_ascii_case("text/event-stream")
        })
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
    // Round-33 F1: closes the round-32 F3 concurrent-MCP budget
    // double-spend by threading the debited `payout_micros` out of
    // `ToolVerdict::Allowed` and calling `ActionBudget::refund_
    // tool_call` on the lost-claim branch. `refund` is best-effort
    // (backend errors are silently absorbed) so a Redis blip on the
    // compensation path cannot turn the CONFLICT response into 5xx.
    match state.intercept_tool_nonblocking(&headers, &body).await {
        Ok(ToolVerdict::Allowed {
            tool,
            budget_remaining,
            elapsed_us,
            payout_micros,
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
                        "concurrent tool execution claim lost; refunding budget"
                    );
                    // Round-33 F1: refund the exact amount debited so
                    // `payout_remaining` and per-tool counters reflect
                    // only admitted work, not the lost race.
                    ab_state::ActionBudget::new(
                        state.store.as_ref(),
                        &execution.session_id,
                        &state.config.budget,
                    )
                    .refund_tool_call(&execution.tool, payout_micros);
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
                            Ok((bytes, content_type)) => {
                                let outcome = ToolOutcome {
                                    status: status.as_u16(),
                                    body_hex: hex::encode(&bytes),
                                    content_type,
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
                        //
                        // Round-34 F4: also do not log the raw error to
                        // tracing::warn — `reqwest::Error::Display` embeds
                        // the same URL, and the tracing subscriber flows
                        // to Vector -> OTLP -> SIEM per the deploy
                        // topology. If OTLP is exported to a third party
                        // with a lower trust boundary than the operator,
                        // the internal `tool_upstream_url` leaks there.
                        // Log structured fields only.
                        let category = crate::pipeline::classify_upstream_error(&error);
                        tracing::warn!(
                            category = category,
                            error.status = ?error.status(),
                            error.is_timeout = error.is_timeout(),
                            error.is_connect = error.is_connect(),
                            error.is_request = error.is_request(),
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

/// Round-32 F2: capture and preserve the upstream tool response's
/// `Content-Type` so the MCP client sees exactly what the tool
/// upstream sent. Without this, `Bytes: IntoResponse` stamps
/// `application/octet-stream`, which strict JSON-RPC 2.0 clients
/// (spec: MUST be `application/json`) reject and downstream SIEM
/// filters mis-classify as binary. We store the string (not
/// HeaderValue) so it round-trips through the on-disk `ToolOutcome`
/// journal for cached-outcome replay.
async fn read_limited_tool_response(
    response: reqwest::Response,
) -> Result<(Bytes, Option<String>), String> {
    let content_type = response
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let mut stream = response.bytes_stream();
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        // CWE-209: `reqwest::Error::Display` embeds the request URL — leaking
        // the operator-configured tool-upstream URL to the client if we
        // returned it verbatim. Use the stable classifier and log
        // structured fields for operators (round-34 F4: never `%error`
        // — that renders the URL into any downstream OTLP sink).
        let chunk = chunk.map_err(|error| {
            let category = crate::pipeline::classify_upstream_error(&error);
            tracing::warn!(
                category = category,
                error.status = ?error.status(),
                error.is_timeout = error.is_timeout(),
                error.is_connect = error.is_connect(),
                error.is_body = error.is_body(),
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
    Ok((Bytes::from(body), content_type))
}

/// Build a tool-response with the round-32 F2 Content-Type
/// preserved. Defaults to `application/json` — MCP is JSON-RPC 2.0
/// by convention — when the upstream did not set one or set an
/// unrepresentable value.
fn tool_response(status: StatusCode, bytes: Bytes, content_type: Option<&str>) -> Response {
    let mut response = (status, bytes).into_response();
    let value = content_type
        .and_then(|ct| HeaderValue::from_str(ct).ok())
        .unwrap_or_else(|| HeaderValue::from_static("application/json"));
    response
        .headers_mut()
        .insert(axum::http::header::CONTENT_TYPE, value);
    response
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
    // Round-32 F2: preserve the upstream Content-Type so a spec-
    // conforming JSON-RPC 2.0 client sees `application/json`
    // (default) or whatever the tool upstream declared, not axum's
    // `application/octet-stream`.
    tool_response(status, bytes, outcome.content_type.as_deref())
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct ToolOutcome {
    status: u16,
    body_hex: String,
    /// Round-32 F2: MCP client requires the upstream tool response's
    /// `Content-Type` to round-trip on cached-outcome replay too, so
    /// strict JSON-RPC 2.0 clients see `application/json` on replay
    /// just as they did on the fresh forward. `#[serde(default)]` so
    /// journals persisted before the field existed decode as `None`
    /// (which the response builder will map to the JSON default).
    #[serde(default)]
    content_type: Option<String>,
}

impl ToolOutcome {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.status).unwrap_or(StatusCode::BAD_GATEWAY);
        match hex::decode(self.body_hex) {
            Ok(body) => tool_response(status, Bytes::from(body), self.content_type.as_deref()),
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
            // A torn intent (crash between create_new and sync_all in
            // claim_sync) leaves a 0-byte or partial file at the final
            // intent_path. If we bubble the journal::open error via `?`
            // the recovery loop aborts on the first torn intent and
            // every subsequent tool session stays unrecovered
            // indefinitely. Quarantine the file so the reconciler makes
            // progress on the rest of the spool; the tool execution
            // itself is still uncertain — a subsequent retry by the
            // client will get TOOL_OUTCOME_UNCERTAIN and can decide.
            let intent_bytes = std::fs::read(&path).map_err(|error| error.to_string())?;
            let intent: ToolIntent = match crate::journal::open(
                &control_key,
                &format!("{}:{key}", crate::journal::TOOL_INTENT_DOMAIN),
                0,
                &intent_bytes,
            ) {
                Ok(intent) => intent,
                Err(error) => {
                    let quarantine = path.with_extension("intent.torn");
                    tracing::warn!(
                        %error,
                        original = %path.display(),
                        quarantine = %quarantine.display(),
                        "torn tool-execution intent quarantined so recovery can proceed"
                    );
                    if let Err(rename_err) = std::fs::rename(&path, &quarantine) {
                        tracing::warn!(%rename_err, "failed to quarantine torn intent — leaving in place");
                    }
                    intent_keys.remove(key);
                    continue;
                }
            };
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
        // Refuse duplicate x-ab-session headers (see
        // `pipeline::single_header` for the rationale — proxies
        // sometimes merge duplicates on the wire and log aggregators
        // can then observe a comma-joined value that leaks a
        // client-desync into audit).
        let session_id = crate::pipeline::single_header(headers, crate::pipeline::SESSION_HEADER)?
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
    // Round-27 F4: `promote()` silently drives `close_session_locked`
    // on any still-open session. If an operator split the two scopes
    // (compliance auditor gets `session:promote`, on-call gets
    // `session:close`), a `session:promote`-only bearer could
    // otherwise force-close any live agent session by promoting it —
    // bypassing `session:close` entirely. When the session is still
    // open, additionally require the close scope so promote ⊇ close
    // in the scope authority sense.
    if !session.is_closed() {
        if let Err(error) =
            state.authorize_session(&headers, &session, &state.config.session_close_scope)
        {
            return pipeline_error(error);
        }
    }
    match state.finalizer.promote(session).await {
        Ok(receipt) => Json(receipt).into_response(),
        Err(error) => lifecycle_error(error.to_string()),
    }
}

fn pipeline_error(error: crate::pipeline::PipelineError) -> Response {
    use crate::pipeline::PipelineError;
    let close = matches!(error, PipelineError::Abort(_));
    let status = error.status();
    let mut response = (status, Json(json!({"error": error.to_string()}))).into_response();
    if close {
        response
            .headers_mut()
            .insert(axum::http::header::CONNECTION, HeaderValue::from_static("close"));
    }
    // Drive advisory-header attachment off the numeric HTTP status
    // rather than variant identity. `PipelineError` is
    // `#[non_exhaustive]`, so a future variant (e.g. `Timeout` → 504,
    // `RateLimited` → 429) would silently skip Retry-After under a
    // `matches!(error, PipelineError::Unavailable(_))` chain — exactly
    // the SDK-hammering regression this arm exists to prevent. Using
    // the status code centralises the semantic once and covers every
    // present and future variant that maps to the same class.
    match status.as_u16() {
        // 429 / 502 / 503 / 504 — retryable per RFC 7231 §7.1.3; the
        // header value is deliberately short so the audit-capture
        // recovery window is fast, but long enough that clients do not
        // hammer during transient failures.
        429 | 502 | 503 | 504 => {
            response
                .headers_mut()
                .insert(axum::http::header::RETRY_AFTER, HeaderValue::from_static("5"));
        }
        // 401 — RFC 7235 §3.1 MUST send `WWW-Authenticate`; RFC 6750 §3
        // defines the Bearer challenge shape used with NHI JWTs.
        401 => {
            response.headers_mut().insert(
                axum::http::header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Bearer realm=\"agentbridge\", error=\"invalid_token\""),
            );
        }
        _ => {}
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
    response_permit: Option<crate::worker::ResponsePermit>,
    /// Handle to submit the response-capture job at end-of-stream. The
    /// permit above only holds the `response_capacity` semaphore slot
    /// — the mpsc queue slot is re-acquired at submit time via
    /// `ResponsePermit::submit(&worker, job)`.
    worker: crate::worker::WorkerHandle,
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
        // Round-29 F1: non-success upstream bodies are relayed
        // verbatim; do NOT try to parse them as chat-completion SSE
        // frames. An `event: error` / `data: {"error":...}` frame
        // from a 4xx/5xx stream would otherwise fail the strict
        // parser and collapse the true status into a 502. Drop the
        // buffered bytes on the floor (the wire body has already
        // been relayed to the client via `pending_output`) and
        // let flush_protocol_buffer's own guard finalise.
        if !self.upstream_status.is_success() {
            self.protocol_buffer.clear();
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
        // Round-29 F1: never fail-closed on a non-success upstream body.
        // Providers ship text/plain and HTML error pages on 4xx/5xx
        // (OpenAI's Cloudflare frontend returns text/html on 429;
        // Anthropic ships 503 HTML from AWS ALBs during backend
        // restarts). The strict JSON parse below would fail and be
        // mapped to a fresh 502, silently dropping the real status +
        // Retry-After header. SDKs treat "502 without Retry-After" as
        // an immediate retry candidate, so a rate-limited upstream
        // gets hammered instead of backed off. Skip the parse for
        // non-success responses; the buffered body still relays
        // through the buffered non-SSE branch and the true
        // upstream_status is preserved into the response later.
        if !self.upstream_status.is_success() {
            let _ = std::mem::take(&mut self.protocol_buffer);
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
        permit.submit(
            &self.worker,
            crate::worker::WorkerJob {
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
            },
        )?;
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
    // SSE spec (§9.2.4) requires the leading U+FEFF (BOM) to be
    // discarded once, at the start of the stream. Rust's `.trim()` does
    // not strip U+FEFF (char::is_whitespace() returns false for it), so
    // a provider that ships a BOM would otherwise cause every following
    // parse to fail on either `strip_prefix("data:")` (BOM before
    // "data") or `serde_json::from_str` (BOM before "{"). Do the strip
    // exactly once here; subsequent chunks in a stream will not carry
    // another BOM.
    let raw = raw.strip_prefix('\u{feff}').unwrap_or(raw);
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
    // Track the last `event:` type seen in this frame. SSE §9.2.8 says
    // an SSE client dispatches by event name; "message" (empty or
    // omitted) is the default. AgentBridge attributes the `data:`
    // payload to the audit trail (receipt, ATIF) as if it were the
    // model's output — but a hostile upstream (rogue provider,
    // TLS-MITM at egress, misconfigured cache) can send
    // `event: error\ndata: {"choices":[{"delta":{"content":"…"}}]}` —
    // spec-compliant SSE clients (browsers, OpenAI SDK's error hook)
    // would dispatch that to the ERROR listener, so the user sees an
    // error UI while our receipt records the payload as the model's
    // response. That defeats the cryptographic-attestation posture.
    // Only accept `event:` empty or `"message"` for capture; other
    // types abort the frame with a diagnostic and let the caller
    // mark_capture_failed rather than sign attributable content.
    let mut event_type = String::new();
    for line in raw.split(['\r', '\n']) {
        if let Some(value) = line.strip_prefix("data:") {
            is_sse = true;
            // SSE spec (§9.2.6): strip exactly ONE leading U+0020
            // SPACE — the field is otherwise verbatim. `.trim_start()`
            // would eat runs of Unicode whitespace and silently
            // mis-account any provider that sends `data:  {...}` with a
            // meaningful second byte.
            data.push(value.strip_prefix(' ').unwrap_or(value));
        } else if let Some(value) = line.strip_prefix("event:") {
            is_sse = true;
            event_type = value.strip_prefix(' ').unwrap_or(value).to_owned();
        } else if line == "data"
            || line.starts_with("id:")
            || line.starts_with("retry:")
            || line.starts_with(':')
        {
            is_sse = true;
        }
    }
    if is_sse && !event_type.is_empty() && event_type != "message" {
        return Err(format!(
            "provider SSE frame carries unsupported event type {event_type:?}; \
             AgentBridge only captures the default `message` event because non-message \
             events (error, ping, custom) are dispatched to different client listeners \
             per SSE §9.2.8 and would be attributed to the wrong audit surface"
        ));
    }
    let candidate = if is_sse {
        if data.is_empty() {
            return Ok(None);
        }
        data.join("\n")
    } else {
        raw.trim().to_owned()
    };
    // Robust `[DONE]` sentinel handling. Some providers double-terminate
    // (`data: [DONE]\ndata: [DONE]`), send trailing whitespace, or emit
    // an empty keepalive line followed by `[DONE]`. The strict
    // byte-exact check used to fail every subsequent stream on such
    // benign variants — `trim` + per-line probe catches them.
    if candidate.is_empty()
        || candidate.trim() == "[DONE]"
        || data
            .iter()
            .all(|entry| entry.trim().is_empty() || entry.trim() == "[DONE]")
            && !data.is_empty()
    {
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
        // Round-29 F5: abort the pending budget task. `spawn_blocking`
        // returns a JoinHandle whose Drop does NOT cancel the queued
        // closure; the blocking pool would otherwise run
        // `ActionBudget::try_tokens(delta)` AFTER the session was
        // sealed by the preceding `mark_capture_failed`, silently
        // debiting the session's budget key for a request the client
        // never received. `abort()` is best-effort for a closure
        // already picked up by the blocking pool (blocking tasks
        // have no cancellation points) but reliably cancels a
        // still-queued task — closing the common case. A full fix
        // would thread a shutdown token into `try_tokens`; deferred
        // until that helper takes a cancellation argument.
        if let Some(pending) = self.pending_budget.take() {
            pending.task.abort();
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
                    // Detach: the drop is sync and cannot await. Mirror
                    // the outcome to tracing *and* a Prometheus counter
                    // so a PromQL alert can catch the class — the
                    // fallback path is otherwise invisible until the
                    // idle sweeper reaps the "still open" session.
                    runtime.spawn(async move {
                        if let Err(error) = finalizer.close_session(session, StopReason::Other).await {
                            finalizer
                                .metrics()
                                .counter(
                                    "ab_stream_abort_close_failures_total",
                                    "Background close after a stream abort failed; \
                                     the session is left open until the idle sweeper reaps it",
                                )
                                .inc();
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
                    self.finalizer
                        .metrics()
                        .counter(
                            "ab_stream_abort_no_runtime_total",
                            "Stream abort observed no tokio runtime; capture marked failed for \
                             reconciler retry",
                        )
                        .inc();
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
            Arc::new(Ed25519Signer::from_seed(&[11; 32])),
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
        // Reserve a full permit pair up front (worker slot + response
        // slot) so `submit_response_capture` in drop has somewhere to
        // send the job; the response permit lives on
        // `AbortFinalizingStream` for the stream's lifetime.
        let permits = state
            .worker
            .try_reserve_pair("pending-budget-close")
            .expect("test setup: fused worker/response permit");
        // The worker permit is dropped here — the test does not
        // actually submit a job through it; the response permit is
        // what the stream drop cares about.
        drop(permits.worker);
        let permit = permits.response;
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
            worker: state.worker.clone(),
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
                Arc::new(Ed25519Signer::from_seed(&[12; 32])),
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

        // 4) No identity validator configured but the client sent a
        //    bearer: refuse with 401 rather than record the request as
        //    anonymous (a repudiation vector — see resolve_identity's
        //    "bearer presented but validator not configured" arm).
        //    The response is the block; the fact that no wire capture
        //    landed also proves the credential does not leak.
        let config = crate::config::HarnessConfig::for_tests(&format!("http://{address}"), &spool, &spool);
        let request = Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .header("x-ab-session", "auth-wire")
            .header(axum::http::header::AUTHORIZATION, "Bearer client-owned-key")
            .body(Body::from(chat_payload().to_string()))
            .unwrap();
        let response = build_router(build_state(config)).oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "presenting a bearer with no validator configured must be refused rather than \
             silently recorded as anonymous — that would let a signed request end up \
             attributed to `charter=anonymous` in the receipt"
        );
        assert!(
            captured.lock().is_empty(),
            "no credential must reach upstream when the request was refused"
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
                content_type: Some("application/json".to_owned()),
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

    /// Leading BOM (U+FEFF) on an SSE stream must be stripped per
    /// §9.2.4. Rust's `.trim()` and `.trim_start()` do NOT remove
    /// U+FEFF (char::is_whitespace returns false for it), so without
    /// an explicit strip the very first `data:` line would parse as
    /// `"\u{FEFF}data:"` and the frame would take the non-SSE path
    /// where `serde_json::from_str` chokes on the BOM prefix.
    #[test]
    fn parse_provider_chunk_strips_leading_bom() {
        let raw = "\u{feff}data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n";
        let parsed = parse_provider_chunk(raw)
            .expect("BOM-prefixed SSE frame must parse")
            .expect("must yield a chunk");
        assert_eq!(parsed.message, "hi");
    }

    /// SSE §9.2.8: an SSE client dispatches events by name, so
    /// `event: error\ndata: {model-shaped-JSON}` is delivered to the
    /// browser/SDK's `error` listener — NOT the default `message`
    /// listener. AgentBridge attributes captured `data:` payloads to
    /// the signed receipt / ATIF as if they were model output, so a
    /// hostile upstream (rogue provider, TLS-MITM at egress mesh, a
    /// misconfigured caching proxy) could forge receipt content while
    /// the user's UI showed nothing suspicious. Refuse the frame with
    /// a diagnostic so the caller marks capture-failed rather than
    /// signs attributable content that never was displayed.
    #[test]
    fn parse_provider_chunk_refuses_non_message_sse_event_types() {
        for event in ["error", "ping", "custom_signal"] {
            let raw = format!(
                "event: {event}\ndata: {{\"choices\":[{{\"delta\":{{\"content\":\"forged\"}}}}]}}\n\n"
            );
            let err = match parse_provider_chunk(&raw) {
                Ok(_) => panic!("event type {event:?} must be refused"),
                Err(error) => error,
            };
            assert!(
                err.contains("unsupported event type") && err.contains(event),
                "expected diagnostic naming event type {event:?}, got: {err}"
            );
        }
        // Explicit `event: message` is accepted (spec default) — must
        // NOT be refused by the same guard.
        let ok_raw = "event: message\ndata: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n";
        let parsed = match parse_provider_chunk(ok_raw) {
            Ok(Some(chunk)) => chunk,
            Ok(None) => panic!("explicit event: message must yield a chunk"),
            Err(error) => panic!("explicit event: message must be accepted, got: {error}"),
        };
        assert_eq!(parsed.message, "hi");
    }

    #[test]
    fn parse_provider_chunk_treats_done_variants_as_stream_end() {
        for raw in [
            "data: [DONE]\ndata: [DONE]\n\n",
            "data: [DONE]  \n\n",
            "data:\ndata: [DONE]\n\n",
        ] {
            let result = parse_provider_chunk(raw);
            match result {
                Ok(None) => {}
                Ok(Some(_)) => panic!("[DONE] variant must terminate stream (None) for {raw:?}"),
                Err(error) => panic!("[DONE] variant must not fail parse: {raw:?}: {error}"),
            }
        }
    }

    /// SSE §9.2.6: the `data:` field strips exactly one leading
    /// U+0020 SPACE — no more, and no other whitespace class. A
    /// regression to `.trim_start()` would eat runs of Unicode
    /// whitespace and silently corrupt payloads whose second byte
    /// after `data:` is another space or a tab.
    ///
    /// Distinguishing input: `data:  hi\n\n` — two spaces then a
    /// literal `hi`. Non-SSE parse via serde_json would fail on
    /// `"hi"` unquoted, so the frame goes through the SSE path where
    /// the `data:` accumulator kept one leading space (spec-compliant)
    /// and serde_json then fails on ` hi` — this is exactly what the
    /// spec's "leave everything after the first space verbatim"
    /// behaviour dictates. A `.trim_start()` regression would silently
    /// consume both spaces and produce the same (still-invalid) input.
    /// We instead pick a JSON payload where the number of leading
    /// spaces changes the parse result: `{"choices":[{"delta":{"content":" hi"}}]}`
    /// with wire `data:  {"choices"...}` — under `strip_prefix(' ')`
    /// the accumulated frame starts with a space then `{`, both parse
    /// fine and the extracted `content` field is `" hi"`; under
    /// `.trim_start()` the frame starts with `{`, also parses fine and
    /// yields the same `" hi"`. So parse content doesn't discriminate.
    ///
    /// Instead observe the raw data buffer that the parser builds:
    /// use a plain non-JSON `data:` value and assert the trimmed
    /// prefix. Since the parser now runs serde_json on the assembled
    /// frame, the only way to expose the trim behaviour is a test on
    /// a lower-level helper. We keep this test as a smoke check on a
    /// case where the frame *fails* differently: two-space prefix
    /// with a leading space kept produces a JSON parse failure the
    /// old `trim_start` would not have produced.
    #[test]
    fn parse_provider_chunk_strips_exactly_one_leading_space() {
        // Bare non-JSON `hello` — invalid JSON either way. With
        // `strip_prefix(' ')` (spec-correct) the parser accumulates
        // ` \thello` (space+tab+hello). With `.trim_start()` (buggy)
        // it accumulates `hello`. Both produce `Err(...)` from
        // serde_json but the reported column differs — the trimmed
        // form reports column 1 (immediate `h`); the correctly
        // preserved form reports a later column because of the
        // retained tab.
        let raw = "data:  \thello\n\n";
        let result = parse_provider_chunk(raw);
        let error = match result {
            Ok(_) => panic!("bare hello must not parse as valid provider frame"),
            Err(error) => error,
        };
        assert!(
            error.contains("column 2") || error.contains("column 3"),
            "expected error to name a column past the retained leading space+tab; \
             got: {error}"
        );
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
        // Loop-breaker verdicts are permanent for the current session:
        // 403 stops mainstream LLM-SDK auto-retry loops that would
        // otherwise burn budget re-hitting the same breaker (see
        // pipeline.rs::PipelineError::status).
        assert_eq!(blocked.status(), StatusCode::FORBIDDEN);
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

    #[tokio::test]
    async fn pipeline_error_carries_retry_after_and_www_authenticate() {
        // Contract: 503 SHOULD carry Retry-After (RFC 7231 §7.1.3);
        // 401 MUST carry WWW-Authenticate (RFC 7235 §3.1). These
        // headers are the mechanism by which intermediaries and SDKs
        // decide to back off / prompt for credentials — without them,
        // mainstream LLM SDKs interpret 503 as "retry immediately"
        // and 401 as "broken proxy".
        use crate::pipeline::PipelineError;

        let unavailable = pipeline_error(PipelineError::Unavailable("worker queue full".into()));
        assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            unavailable
                .headers()
                .get(axum::http::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok()),
            Some("5")
        );

        let upstream = pipeline_error(PipelineError::Upstream("bad gateway".into()));
        assert_eq!(upstream.status(), StatusCode::BAD_GATEWAY);
        assert!(upstream.headers().get(axum::http::header::RETRY_AFTER).is_some());

        let unauthorized = pipeline_error(PipelineError::Unauthorized("bad token".into()));
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
        let auth = unauthorized
            .headers()
            .get(axum::http::header::WWW_AUTHENTICATE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert!(
            auth.starts_with("Bearer"),
            "WWW-Authenticate must be a Bearer challenge, got {auth:?}"
        );

        // Permanent verdicts must NOT carry Retry-After — that would
        // encourage the very retry loop we're trying to stop.
        let blocked = pipeline_error(PipelineError::Blocked("loop breaker".into()));
        assert_eq!(blocked.status(), StatusCode::FORBIDDEN);
        assert!(blocked.headers().get(axum::http::header::RETRY_AFTER).is_none());
        let abort = pipeline_error(PipelineError::Abort("stop retrying".into()));
        assert_eq!(abort.status(), StatusCode::CONFLICT);
        assert!(abort.headers().get(axum::http::header::RETRY_AFTER).is_none());
    }

    /// Round-25 F3: SSE detection is case-insensitive and tolerates
    /// media-type parameters. Byte-exact `starts_with` previously
    /// misclassified `Text/Event-Stream` (some CDNs re-title-case)
    /// and any `text/event-stream; charset=utf-8` with a leading
    /// title-cased subtype. Misclassified SSE streams get buffered
    /// to the 16 MiB provider cap and either lose streaming
    /// semantics or 502 despite being valid.
    #[test]
    fn is_sse_content_type_is_case_insensitive_and_param_tolerant() {
        fn ct(value: &str) -> HeaderMap {
            let mut headers = HeaderMap::new();
            headers.insert(
                axum::http::header::CONTENT_TYPE,
                value.parse().expect("header value"),
            );
            headers
        }
        assert!(is_sse_content_type(&ct("text/event-stream")));
        assert!(is_sse_content_type(&ct("Text/Event-Stream")));
        assert!(is_sse_content_type(&ct("TEXT/EVENT-STREAM")));
        assert!(is_sse_content_type(&ct("text/event-stream; charset=utf-8")));
        assert!(is_sse_content_type(&ct(
            "Text/Event-Stream ; charset=utf-8"
        )));
        // Non-SSE and superstring both must not match.
        assert!(!is_sse_content_type(&ct("application/json")));
        assert!(!is_sse_content_type(&ct("text/event-stream-json")));
        // Absent header returns false.
        assert!(!is_sse_content_type(&HeaderMap::new()));
    }

    /// Round-31 F5: OPTIONS to every mutating route replies with
    /// `204 No Content` and NO Access-Control-Allow-* headers.
    /// Browsers must interpret this as "cross-origin denied" and
    /// refuse the actual request — making the same-origin-only
    /// posture explicit at the wire. Guards against a future PR
    /// accidentally adding `CorsLayer::permissive()`.
    #[tokio::test]
    async fn options_returns_204_without_cors_headers() {
        let directory = tempfile::tempdir().unwrap();
        let (state, provider) = test_state(directory.path()).await;
        for path in [
            "/v1/chat/completions",
            "/v1/mcp",
            "/mcp",
            "/v1/sessions/some-id/close",
            "/v1/sessions/some-id/promote",
        ] {
            let response = build_router(state.clone())
                .oneshot(
                    Request::builder()
                        .method(axum::http::Method::OPTIONS)
                        .uri(path)
                        .header("origin", "http://attacker.example")
                        .header("access-control-request-method", "POST")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::NO_CONTENT,
                "OPTIONS {path} should return 204, got {}",
                response.status()
            );
            for header in [
                "access-control-allow-origin",
                "access-control-allow-methods",
                "access-control-allow-headers",
                "access-control-allow-credentials",
            ] {
                assert!(
                    response.headers().get(header).is_none(),
                    "OPTIONS {path} must not emit {header} — got {:?}",
                    response.headers().get(header)
                );
            }
        }
        provider.abort();
    }

    /// Round-32 F2: cached MCP tool-outcome replays preserve the
    /// upstream Content-Type end-to-end (including through the
    /// on-disk journal roundtrip). Strict JSON-RPC 2.0 clients
    /// (spec: MUST be `application/json`) would previously receive
    /// `application/octet-stream` on both the fresh forward and the
    /// cached replay. This test locks in:
    ///   1. `ToolOutcome::into_response` honours a set content_type.
    ///   2. A `None` content_type defaults to `application/json`
    ///      (MCP is JSON-RPC 2.0 by convention).
    ///   3. Serialising and re-deserialising a `ToolOutcome` (i.e.
    ///      the on-disk journal round-trip) preserves the field.
    ///   4. Legacy journals without the field decode as `None` and
    ///      pick up the default via #1.
    #[test]
    fn round_32_f2_tool_outcome_preserves_content_type() {
        // (1) Custom content_type survives.
        let outcome = ToolOutcome {
            status: 200,
            body_hex: hex::encode(b"{\"jsonrpc\":\"2.0\"}"),
            content_type: Some("application/problem+json".to_owned()),
        };
        let response = outcome.into_response();
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/problem+json")
        );
        // (2) None -> application/json default.
        let outcome_no_ct = ToolOutcome {
            status: 200,
            body_hex: hex::encode(b"{}"),
            content_type: None,
        };
        let response = outcome_no_ct.into_response();
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json")
        );
        // (3) Journal round-trip preserves the field.
        let sealed = serde_json::to_string(&ToolOutcome {
            status: 429,
            body_hex: hex::encode(b"{}"),
            content_type: Some("text/plain".to_owned()),
        })
        .unwrap();
        let recovered: ToolOutcome = serde_json::from_str(&sealed).unwrap();
        assert_eq!(recovered.content_type.as_deref(), Some("text/plain"));
        // (4) Legacy journal without the field decodes as None.
        let legacy = r#"{"status":200,"body_hex":"7b7d"}"#;
        let outcome: ToolOutcome = serde_json::from_str(legacy).unwrap();
        assert!(outcome.content_type.is_none());
    }
}
