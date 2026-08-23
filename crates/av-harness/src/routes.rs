//! Axum HTTP routes for proxy, MCP interception, lifecycle, and operations.

use crate::pipeline::AppState;
use av_core::time::elapsed_us;
use av_events::StopReason;
use av_sandbox::ToolVerdict;
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
        .route("/livez", get(livez))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        .route("/v1/chat/completions", post(chat_completions).options(cors_deny))
        .route("/v1/mcp", post(mcp_call).options(cors_deny))
        .route("/mcp", post(mcp_call).options(cors_deny))
        .route("/v1/sessions/{id}/close", post(close_session).options(cors_deny))
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
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            request_metrics,
        ))
        .layer(axum::middleware::from_fn(trace_request))
        // axum's default body limit is 2 MiB, which silently rejects large
        // chat contexts (Claude 200k, GPT-4 128k) before the sandbox even
        // sees the payload. `max_request_bytes` (default 4 MiB, matching
        // the sandbox `MAX_PAYLOAD_BYTES`) is the single knob operators
        // control.
        .layer(axum::extract::DefaultBodyLimit::max(max_body))
        .with_state(state)
}

/// Round-51 §8.7: data-plane request metrics. Every HTTP request —
/// including the early-4xx returns the review flagged as unaudited —
/// lands in `av_requests_total{route,status_class}` and
/// `av_request_duration_seconds{route}`. The route label is drawn
/// from a FIXED set (no client-controlled values) so metric
/// cardinality is bounded; unknown paths collapse to `other`.
async fn request_metrics(State(state): State<AppState>, request: Request<Body>, next: Next) -> Response {
    let route = route_label(request.uri().path());
    let started = std::time::Instant::now();
    let response = next.run(request).await;
    let status_class = match response.status().as_u16() {
        100..=199 => "1xx",
        200..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        _ => "5xx",
    };
    state
        .metrics
        .counter(
            &format!("av_requests_total{{route=\"{route}\",status_class=\"{status_class}\"}}"),
            "HTTP requests by route and status class",
        )
        .inc();
    state
        .metrics
        .histogram_with_bounds(
            &format!("av_request_duration_seconds{{route=\"{route}\"}}"),
            "End-to-end HTTP request latency by route",
            av_core::metrics::WIDE_LATENCY_BOUNDS_US,
        )
        .observe_us(elapsed_us(started));
    response
}

/// Fixed route-label set for `av_requests_total`. NEVER interpolate a
/// client-controlled value here — Prometheus cardinality is bounded
/// only because this set is closed.
fn route_label(path: &str) -> &'static str {
    match path {
        "/v1/chat/completions" => "chat",
        "/v1/mcp" | "/mcp" => "mcp",
        "/health" => "health",
        "/livez" => "livez",
        "/readyz" => "readyz",
        "/metrics" => "metrics",
        _ if path.starts_with("/v1/sessions/") && path.ends_with("/close") => "session_close",
        _ if path.starts_with("/v1/sessions/") && path.ends_with("/promote") => "session_promote",
        _ if path.starts_with("/dashboard") || path.starts_with("/api/v1/dashboard") => "dashboard",
        _ => "other",
    }
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
    // two `X-AV-Session` headers — `HeaderMap::get` returned the
    // first while `pipeline::single_header` (round-13) refused the
    // whole request, so traces named a "friendly" id for a hard-400;
    // (3) accepted values that pass `HeaderValue::to_str` but fail
    // `SessionId::parse` (too long, control chars in disguise). Use
    // `single_header` + `SessionId::parse` to bind ONE consistent
    // value or the sentinel `"invalid"`.
    // Round-14 F7: use a sentinel that CANNOT pass `SessionId::parse`
    // (0x21..=0x7e visible-ASCII only), so a client cannot legitimately
    // send `X-AV-Session: invalid` and share a trace label with a
    // rejected request. The leading space (0x20) is outside the
    // allowed range → collision-free.
    let headers = request.headers();
    let session_id = match crate::pipeline::single_header(headers, crate::pipeline::SESSION_HEADER) {
        Ok(Some(value)) => value
            .to_str()
            .ok()
            .and_then(|v| av_core::SessionId::parse(v).ok())
            .map(|id| id.to_string())
            .unwrap_or_else(|| " rejected".to_owned()),
        Ok(None) => "unbound".to_owned(),
        Err(_) => " duplicate-header".to_owned(),
    };
    let span = tracing::info_span!(
        "agentvisor.request",
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
    // attacker correlate an agentvisor deployment to a specific
    // known-vulnerable release without needing a chat probe. No
    // harness endpoint surfaces build info (`/metrics` included);
    // the version appears only in the *outbound* upstream
    // `User-Agent` built in `pipeline.rs`.
    Json(json!({
        "status": "ok",
        // Product identifier so callers (avctl start) can tell a real
        // AgentVisor AI apart from an unrelated service squatting the
        // port. This is not a version number and reveals no
        // vulnerability-relevant information.
        "service": "agentvisor",
    }))
}

/// Kubernetes-style liveness probe.
///
/// Constant response: liveness answers "is the process alive at all?"
/// and must NOT couple to backend health — otherwise a transient state
/// backend outage triggers a pod restart cascade instead of a
/// readiness-based traffic drain. This mirrors `/health` (kept for
/// backward compatibility) but with a name that reads as its intent.
/// Point `livenessProbe` at `/livez`; point `readinessProbe` at
/// `/readyz`. See engineering review §8.3.
async fn livez() -> impl IntoResponse {
    Json(json!({
        "status": "alive",
        "service": "agentvisor",
    }))
}

/// Kubernetes-style readiness probe.
///
/// 200 when the harness can serve a request end-to-end; 503 while
/// draining or when a required backend is unavailable. Checks:
///   * `draining` — set by the SIGTERM handler before axum's graceful
///     drain begins, so the LB stops sending new traffic first.
///   * `atif_spool_dir` — attempts a metadata read so a missing / read-only
///     spool (the shape that produces `503 audit capture unavailable`
///     for every chat request) is reflected in readiness rather than
///     hidden behind a hardcoded `/health` 200.
///
/// Returns the JSON body regardless of status so operators can diff
/// which check failed without opening a shell.
async fn readyz(State(state): State<AppState>) -> impl IntoResponse {
    let draining = state.draining.load(std::sync::atomic::Ordering::SeqCst);
    let spool_ok = std::fs::metadata(std::path::Path::new(&state.config.atif_spool_dir))
        .map(|m| m.is_dir())
        .unwrap_or(false);
    let ready = !draining && spool_ok;
    let body = Json(json!({
        "status": if ready { "ready" } else { "not_ready" },
        "service": "agentvisor",
        "checks": {
            "draining": draining,
            "spool_dir_readable": spool_ok,
        },
    }));
    if ready {
        (StatusCode::OK, body).into_response()
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, body).into_response()
    }
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
    // Refresh gauges immediately before rendering so the scrape
    // reflects the live registry state (round-51 W2). A gauge held
    // as `Arc<Gauge>` in AppState would also work, but sampling
    // once per scrape avoids inc/dec bookkeeping on every session
    // insert/remove and cannot drift out of sync with the actual
    // dashmap state.
    state
        .metrics
        .gauge(
            "av_open_sessions",
            "Currently-open sessions in the in-memory registry",
        )
        .set(state.sessions.len() as u64);
    // Round-51 §8.7: worker backlog + spool footprint, sampled per
    // scrape. Queue depth is one atomic load; the spool walk is a
    // single-level read_dir summing entry sizes (a few ms even at
    // tens of thousands of files, amortized across the scrape
    // interval).
    state
        .metrics
        .gauge(
            "av_worker_queue_depth",
            "Accepted-but-not-yet-completed worker jobs",
        )
        .set(state.worker.queue_depth());
    let (spool_bytes, spool_files) = spool_footprint(std::path::Path::new(&state.config.atif_spool_dir));
    state
        .metrics
        .gauge(
            "av_spool_bytes",
            "Total bytes in the top-level ATIF spool directory",
        )
        .set(spool_bytes);
    state
        .metrics
        .gauge(
            "av_spool_files",
            "File count in the top-level ATIF spool directory",
        )
        .set(spool_files);
    let mut response = Response::new(Body::from(state.metrics.render()));
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    response
}

/// Sum size and count of regular files in the top level of the spool
/// directory. Non-recursive on purpose: subdirectories (broker-acks/,
/// receipts/) have bounded per-session cost and a recursive walk per
/// scrape would reintroduce the §8.1 O(spool) tax on another path.
fn spool_footprint(dir: &std::path::Path) -> (u64, u64) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return (0, 0);
    };
    let mut bytes = 0u64;
    let mut files = 0u64;
    for entry in entries.flatten() {
        if let Ok(metadata) = entry.metadata() {
            if metadata.is_file() {
                bytes = bytes.saturating_add(metadata.len());
                files = files.saturating_add(1);
            }
        }
    }
    (bytes, files)
}

async fn chat_completions(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    // Round-22 F1 (av-harness routes): refuse duplicate top-level or
    // nested JSON keys before parsing. `Json<Value>` used
    // `serde_json` default "last-wins" semantics, so a hostile client
    // could send `{"messages":[safe],"messages":[hostile]}` — the
    // harness saw the hostile array, but any auditor/dashboard
    // reading the raw request bytes (e.g. via
    // `av_events::atif_capture_from_request` chain input) sees an
    // ambiguous document, breaking the "same signature ⇔ same
    // bytes" auditor invariant that round-15 F3 pinned for receipts.
    // Same fix as `parse_tool_call` on the MCP path — use the shared
    // primitive.
    if let Err(reason) = av_sandbox::refuse_duplicate_json_keys(&body) {
        return pipeline_error(crate::pipeline::PipelineError::BadRequest(format!(
            "chat request rejected: {reason}"
        )));
    }
    let payload: Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(error) => return pipeline_error(crate::pipeline::PipelineError::BadRequest(error.to_string())),
    };
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
        capture_guard,
    } = forwarded;
    let Some(response_permit) = response_permit else {
        // Defensive: `prepare_chat` always reserves a permit. Even so,
        // retire the durable marker and the journalled attempt through
        // the plain worker queue before failing — returning directly
        // would leak the spool/inflight-responses/ marker (crash
        // recovery then quarantines the session) and leave a dangling
        // non-terminal ResponseAttempt. If even that submit fails, fail
        // the session closed rather than dropping the capture silently.
        let (response_marker, response_attempt_id) = capture_guard.disarm();
        let capture_session = Arc::clone(&session);
        if state
            .worker
            .try_submit(crate::pipeline::refused_response_failure_job(
                session,
                identity,
                "response_capture_permit_missing".to_owned(),
                response_marker,
                response_attempt_id,
            ))
            .is_err()
        {
            capture_session.mark_capture_failed();
        }
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
    let mut refused_encoding: Option<(String, String)> = None;
    'encodings: for value in upstream_headers.get_all(axum::http::header::CONTENT_ENCODING) {
        let raw = value.to_str().unwrap_or_default();
        for token in raw.split(',') {
            let token = token.trim();
            if token.is_empty() || token.eq_ignore_ascii_case("identity") {
                continue;
            }
            refused_encoding = Some((token.to_owned(), raw.to_owned()));
            break 'encodings;
        }
    }
    if let Some((token, raw)) = refused_encoding {
        // Retire the durable in-flight marker and terminally fail the
        // journalled response attempt before refusing — mirroring
        // forward_chat's Err arm. Returning without this leaked the
        // marker (recover_spooled_sessions quarantined the session on
        // every subsequent boot) and left a dangling non-terminal
        // attempt while the session later closed with a "clean"
        // receipt. Stable classifier only in the persisted record —
        // the header token is upstream-controlled bytes. If the shard
        // is full, fail the session closed rather than dropping the
        // capture silently (same rationale as forward_chat's Err arm).
        let (response_marker, response_attempt_id) = capture_guard.disarm();
        let capture_session = Arc::clone(&session);
        if response_permit
            .submit(
                &state.worker,
                crate::pipeline::refused_response_failure_job(
                    session,
                    identity,
                    "upstream_unsupported_content_encoding".to_owned(),
                    response_marker,
                    response_attempt_id,
                ),
            )
            .is_err()
        {
            capture_session.mark_capture_failed();
        }
        return pipeline_error(crate::pipeline::PipelineError::Upstream(format!(
            "upstream responded with unsupported Content-Encoding token {token:?} \
             (full header: {raw:?}) — the proxy is built without decompression \
             support; enable it upstream (Accept-Encoding: identity) or rebuild \
             with the reqwest `gzip` feature"
        )));
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
    // `AbortFinalizingStream` owns marker retirement and attempt
    // termination from here (including on mid-stream client disconnect,
    // via its own Drop); hand both over and disarm the guard.
    let (response_marker, response_attempt_id) = capture_guard.disarm();
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
        response_metrics: av_events::EventMetrics::default(),
        charged_completion_tokens: 0,
        last_reported_completion_tokens: None,
        last_reported_prompt_tokens: None,
        last_reported_cached_tokens: None,
        last_reported_cost_usd_micros: None,
        saw_chunk: false,
        capture_attempted: false,
        is_sse,
        protocol_buffer: Vec::new(),
        pending_output: std::collections::VecDeque::new(),
        pending_budget: None,
        captured_bytes: 0,
        completed: false,
    };
    let mut response = if is_sse {
        // Peek the FIRST item before committing the response head: when
        // the first poll fails (empty 200 body, first frame invalid
        // JSON, hostile usage fields), returning `Body::from_stream`
        // directly made hyper abort the connection before flushing the
        // status line — the client saw a raw empty reply (curl exit 52,
        // http_code 000) instead of the clean 502/403 this file's own
        // policy mandates. SDKs classify that as a network error and
        // auto-retry, and each retry burns admission budget and seals
        // another artifact-less session. Mid-stream failures (bytes
        // already relayed) remain severed — unavoidable once the head
        // is committed — but the pre-first-byte case surfaces as a real
        // HTTP error exactly like the buffered non-SSE branch.
        let mut relay = Box::pin(stream);
        match relay.next().await {
            Some(Err(error)) => {
                let mapped = if error.kind() == std::io::ErrorKind::QuotaExceeded {
                    crate::pipeline::PipelineError::Blocked(error.to_string())
                } else {
                    crate::pipeline::PipelineError::Upstream(error.to_string())
                };
                // Dropping the relay runs its finalization Drop
                // (evidence capture + session seal).
                return pipeline_error(mapped);
            }
            Some(Ok(first)) => {
                let head = futures::stream::once(async move { Ok::<_, std::io::Error>(first) });
                Response::new(Body::from_stream(head.chain(relay)))
            }
            // Clean zero-item stream: every capture gate already ran
            // inside the relay's EOF arm and succeeded.
            None => Response::new(Body::empty()),
        }
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
                    // Round-6 (hunt4 protocol F3): route through
                    // `pipeline_error` so the status class matches the
                    // admission-time decision for the SAME condition
                    // and the advisory headers are attached. The prior
                    // hand-built 429 contradicted the deliberate
                    // 403-not-429 choice for budget caps (a permanent
                    // per-session refusal SDKs must not auto-retry)
                    // and omitted the Retry-After that this file's own
                    // policy mandates on every 502.
                    let mapped = if error.kind() == std::io::ErrorKind::QuotaExceeded {
                        crate::pipeline::PipelineError::Blocked(error.to_string())
                    } else {
                        crate::pipeline::PipelineError::Upstream(error.to_string())
                    };
                    // Dropping the relay here runs its finalization Drop
                    // (evidence capture + session seal), same as when a
                    // client observed the severed stream.
                    return pipeline_error(mapped);
                }
                None => break,
            }
        }
        Response::new(Body::from(buffered))
    };
    *response.status_mut() = status;
    for (name, value) in &upstream_headers {
        if is_forwardable_upstream_header(name, &state.config.upstream_auth_header) {
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
///
/// Round-16 F1 (routes): the denylist covered `Authorization` (RFC 7235)
/// but NOT any custom-name auth header the harness itself uses to
/// authenticate to the upstream. Every LLM provider uses a distinct
/// custom header — `api-key` (Azure), `x-api-key` (Amazon Bedrock,
/// Together AI), `x-goog-api-key` (Google), `anthropic-api-key`
/// (Anthropic). A malicious or compromised upstream that echoes back
/// its request's auth header in the response would then leak the
/// operator's provider credential straight through to the caller.
/// Two-layer defense: (a) refuse every well-known API-key header name
/// by static allowlist below, AND (b) refuse the currently-configured
/// `upstream_auth_header` name so operator-specific choices are also
/// covered.
fn is_forwardable_upstream_header(name: &axum::http::HeaderName, upstream_auth_header: &str) -> bool {
    use axum::http::header;
    // Any header name whose lowercased ASCII equals the configured
    // upstream auth header MUST be stripped. `HeaderName` display is
    // already lowercase-normalised.
    if name.as_str().eq_ignore_ascii_case(upstream_auth_header) {
        return false;
    }
    let is_denied = *name == header::CONTENT_LENGTH
        || *name == header::TRANSFER_ENCODING
        || *name == header::CONNECTION
        || *name == header::UPGRADE
        || *name == header::TE
        || *name == header::TRAILER
        || *name == header::PROXY_AUTHENTICATE
        || *name == header::PROXY_AUTHORIZATION
        // The harness holds the operator's provider credential; an upstream
        // that echoes the request's Authorization header back in its
        // response must not leak it to the client.
        || *name == header::AUTHORIZATION
        || *name == header::SET_COOKIE
        || *name == header::SERVER
        || *name == header::VIA
        || name.as_str().eq_ignore_ascii_case("keep-alive")
        || name.as_str().eq_ignore_ascii_case("x-powered-by")
        || name.as_str().eq_ignore_ascii_case("x-request-id")
        // Well-known provider API-key header names (round-16 F1).
        // Verified against public docs of Azure OpenAI, AWS Bedrock,
        // Google Vertex, Anthropic, Cohere, DeepSeek, Together AI,
        // Groq, Mistral, and Fireworks.
        || name.as_str().eq_ignore_ascii_case("api-key")
        || name.as_str().eq_ignore_ascii_case("x-api-key")
        || name.as_str().eq_ignore_ascii_case("x-goog-api-key")
        || name.as_str().eq_ignore_ascii_case("anthropic-api-key")
        || name.as_str().eq_ignore_ascii_case("openai-api-key")
        || name.as_str().eq_ignore_ascii_case("x-auth-token")
        || name.as_str().eq_ignore_ascii_case("x-amz-security-token")
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

/// Per-execution-key completion gate. Retains only gates that another
/// request currently holds (strong count > 1), so the map stays bounded
/// by in-flight completions rather than growing per historical key.
fn tool_audit_gate(state: &AppState, key: &str) -> Arc<tokio::sync::Mutex<()>> {
    let mut gates = state.tool_audit_gates.lock();
    gates.retain(|_, gate| Arc::strong_count(gate) > 1);
    Arc::clone(gates.entry(key.to_owned()).or_default())
}

async fn mcp_call(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    // Round-18 F2 (routes): reject an inbound request whose declared
    // `Content-Type` is not `application/json`. MCP is JSON-RPC 2.0
    // (spec: MUST be `application/json`), and a client sending e.g.
    // `Content-Type: multipart/form-data` with a JSON body would
    // otherwise process successfully — a spec-violation surface with
    // no defensible use case. Missing Content-Type is tolerated
    // (some minimal clients skip it and JSON-RPC parsers accept the
    // body's shape).
    if let Some(value) = headers.get(axum::http::header::CONTENT_TYPE) {
        let is_json = value
            .to_str()
            .ok()
            .and_then(|s| s.split(';').next())
            .map(|main| main.trim().eq_ignore_ascii_case("application/json"))
            .unwrap_or(false);
        if !is_json {
            let display = value.to_str().unwrap_or("<non-ascii>");
            return pipeline_error(crate::pipeline::PipelineError::BadRequest(format!(
                "MCP requires Content-Type: application/json (spec: JSON-RPC 2.0), got {display:?}"
            )));
        }
    }
    // The tool path mutates durable state at several awaits: the sandbox
    // gate debits the budget, `execution.claim()` claims the execution
    // key, the upstream call executes the tool, and persist/audit resolve
    // the outcome. Axum drops the handler future on client disconnect; a
    // cancellation between any two of those steps used to strand the
    // intermediate state with no owner — a claimed-but-unresolved key
    // answers every retry with 409 TOOL_OUTCOME_UNCERTAIN while the
    // session lives (restart-time quarantine skips active sessions), and
    // a debited-but-unrefunded budget burns quota headroom per
    // disconnect. Run the whole body on a spawned task so it always runs
    // to completion; the handler merely awaits (and may abandon) the
    // result.
    match tokio::spawn(mcp_call_inner(state, headers, body)).await {
        Ok(response) => response,
        Err(join_error) => lifecycle_error(format!("tool call task failed: {join_error}")),
    }
}

async fn mcp_call_inner(state: AppState, headers: HeaderMap, body: Bytes) -> Response {
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
                // Round-51 §5.1: the three cached-state arms below used
                // to repeat this lookup+authorize block verbatim,
                // differing only in the error string, and recomputed
                // `tool_scope` per arm. One helper, one scope.
                // Boxed Err keeps the closure's Result at pointer size
                // (clippy::result_large_err — Response is 128+ bytes).
                let authorized_session = |missing_context: &str| -> Result<(), Box<Response>> {
                    let Some(session) = state.sessions.get(&execution.session_id) else {
                        return Err(Box::new(pipeline_error(
                            crate::pipeline::PipelineError::BadRequest(format!(
                                "unknown session for {missing_context}"
                            )),
                        )));
                    };
                    state
                        .authorize_session(&headers, &session, &required_scope)
                        .map_err(|error| Box::new(pipeline_error(error)))
                };
                match execution.load().await {
                    Ok(ToolExecutionState::Completed(outcome)) => {
                        if let Err(response) = authorized_session("cached tool result") {
                            return *response;
                        }
                        return outcome.into_response();
                    }
                    Ok(ToolExecutionState::Unaudited(outcome)) => {
                        if let Err(response) = authorized_session("pending tool audit") {
                            return *response;
                        }
                        (Some(execution), Some(outcome))
                    }
                    Ok(ToolExecutionState::Pending) => {
                        if let Err(response) = authorized_session("pending tool execution") {
                            return *response;
                        }
                        return (
                            StatusCode::CONFLICT,
                            Json(json!({"error": TOOL_OUTCOME_UNCERTAIN})),
                        )
                            .into_response();
                    }
                    Ok(ToolExecutionState::Missing) => (Some(execution), None),
                    Err(error) if error == TOOL_REQUEST_MISMATCH => {
                        // Same session-binding discipline as every other
                        // `load()` arm above: without it, any holder of a
                        // valid `tool:<name>`-scoped token could probe
                        // whether an execution key exists under a DIFFERENT
                        // request/principal (409 vs the Missing path) for
                        // sessions it is not bound to — a session-content
                        // oracle of the same shape as the fixed
                        // close/promote existence oracle.
                        let Some(session) = state.sessions.get(&execution.session_id) else {
                            return pipeline_error(crate::pipeline::PipelineError::BadRequest(
                                "unknown session for tool execution".to_owned(),
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
    if let (Some(execution), Some(_)) = (execution.as_ref(), unaudited_outcome.as_ref()) {
        let _lease = match state.lease_session(&headers) {
            Ok(lease) => lease,
            Err(error) => return pipeline_error(error),
        };
        // Serialize with any racing completion of the same execution key
        // (fresh forward awaiting its audit, or another replay), then
        // re-check the on-disk state: without this, both requests would
        // submit a `tool_completed` job for one execution — two durable
        // execution records on the audit stream and in the signed chain.
        let gate = tool_audit_gate(&state, &execution.key);
        let _gate = gate.lock().await;
        let outcome = match execution.load().await {
            Ok(ToolExecutionState::Completed(outcome)) => return outcome.into_response(),
            Ok(ToolExecutionState::Unaudited(outcome)) => outcome,
            Ok(_) => return lifecycle_error("tool execution state changed during audit".to_owned()),
            Err(error) => return lifecycle_error(error),
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
        return complete_tool_audit(&state, execution, outcome, completion_permit, session).await;
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
                let execution = match execution {
                    Some(execution) => execution,
                    None => return lifecycle_error("tool execution state is missing".to_owned()),
                };
                // The sandbox debited the budget when it returned Allowed;
                // every failure between here and a successful `claim()`
                // must refund it, or a saturated worker / close race
                // drains `max_total_tool_calls` and payout headroom with
                // zero tools executed (each client retry re-debits).
                let refund_admission = || {
                    av_state::ActionBudget::new(
                        state.store.as_ref(),
                        &execution.session_id,
                        &state.config.budget,
                    )
                    .refund_tool_call(&execution.tool, payout_micros);
                };
                let _lease = match state.lease_session(&headers) {
                    Ok(lease) => lease,
                    Err(error) => {
                        refund_admission();
                        return pipeline_error(error);
                    }
                };
                let completion_permit = match state.worker.try_reserve(&execution.session_id) {
                    Ok(permit) => permit,
                    Err(error) => {
                        refund_admission();
                        return pipeline_error(crate::pipeline::PipelineError::Unavailable(
                            error.to_string(),
                        ));
                    }
                };
                match execution.claim().await {
                    Ok(()) => {}
                    Err(ClaimError::Race) => {
                        // A lost claim race means another in-flight request owns
                        // this execution; answer exactly like the Pending state
                        // and keep the underlying io detail out of the wire.
                        tracing::warn!(
                            session = %execution.session_id,
                            "concurrent tool execution claim lost; refunding budget"
                        );
                        // Round-33 F1: refund the exact amount debited so
                        // the budget counters reflect only admitted work,
                        // not the lost race.
                        av_state::ActionBudget::new(
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
                    Err(ClaimError::Backend(error)) => {
                        // Infrastructure failure — StorageFull, PermissionDenied,
                        // etc. The tool provably did not execute (we never
                        // reached upstream); refund the admission charge and
                        // surface a 503 so the client backs off, instead of a
                        // 409 that implies "someone else already ran it".
                        tracing::warn!(
                            session = %execution.session_id,
                            %error,
                            "tool execution claim failed; refunding budget"
                        );
                        av_state::ActionBudget::new(
                            state.store.as_ref(),
                            &execution.session_id,
                            &state.config.budget,
                        )
                        .refund_tool_call(&execution.tool, payout_micros);
                        return pipeline_error(crate::pipeline::PipelineError::Unavailable(
                            "tool execution intent could not be persisted".to_owned(),
                        ));
                    }
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
                        // Round-6 (hunt4 protocol F1): reject non-identity
                        // Content-Encoding on the tool relay for the same
                        // reason the chat path does (reqwest 0.12 has no
                        // decompression features enabled). Without this
                        // guard the compressed bytes would be relayed to
                        // the MCP client with a plain application/json
                        // header, persisted as the durable ToolOutcome
                        // replayed on every retry, and journaled via
                        // from_utf8_lossy as the ATTESTED tool output —
                        // mojibake in the signed audit chain.
                        let upstream_headers = upstream.headers();
                        let mut refused_encoding: Option<(String, String)> = None;
                        'tool_encodings: for value in
                            upstream_headers.get_all(axum::http::header::CONTENT_ENCODING)
                        {
                            let raw = value.to_str().unwrap_or_default();
                            for token in raw.split(',') {
                                let token = token.trim();
                                if token.is_empty() || token.eq_ignore_ascii_case("identity") {
                                    continue;
                                }
                                refused_encoding = Some((token.to_owned(), raw.to_owned()));
                                break 'tool_encodings;
                            }
                        }
                        if let Some((token, raw)) = refused_encoding {
                            let failure = ToolOutcome {
                                status: StatusCode::BAD_GATEWAY.as_u16(),
                                body_hex: hex::encode(
                                    serde_json::to_vec(&json!({
                                        "error": format!(
                                            "tool upstream responded with unsupported Content-Encoding token {token:?} (full header: {raw:?})",
                                        ),
                                    }))
                                    .unwrap_or_default(),
                                ),
                                content_type: Some("application/json".to_owned()),
                            };
                            let gate = tool_audit_gate(&state, &execution.key);
                            let _gate = gate.lock().await;
                            if let Err(error) = execution.persist(&failure).await {
                                return lifecycle_error(error);
                            }
                            let session = match state.sessions.get(&execution.session_id) {
                                Some(session) => session,
                                None => return lifecycle_error("tool session disappeared".to_owned()),
                            };
                            return complete_tool_audit(
                                &state,
                                &execution,
                                failure,
                                completion_permit,
                                session,
                            )
                            .await;
                        }
                        match read_limited_tool_response(upstream).await {
                            Ok((bytes, content_type)) => {
                                let outcome = ToolOutcome {
                                    status: status.as_u16(),
                                    body_hex: hex::encode(&bytes),
                                    content_type,
                                };
                                // Hold the per-key gate across persist +
                                // audit so an Unaudited replay arriving
                                // between them serializes behind us and
                                // re-checks state instead of double-
                                // emitting the completion event.
                                let gate = tool_audit_gate(&state, &execution.key);
                                let _gate = gate.lock().await;
                                if let Err(error) = execution.persist(&outcome).await {
                                    return lifecycle_error(error);
                                }
                                let session = match state.sessions.get(&execution.session_id) {
                                    Some(session) => session,
                                    None => return lifecycle_error("tool session disappeared".to_owned()),
                                };
                                complete_tool_audit(&state, &execution, outcome, completion_permit, session)
                                    .await
                            }
                            Err(error) => {
                                // The upstream received the request and began
                                // responding: the tool executed (or may
                                // have). Record the failure as the outcome so
                                // the execution key resolves and the
                                // completion audit is emitted — otherwise the
                                // key strands at Pending (every retry gets
                                // 409) with an Allowed verdict and no
                                // completion on the audit stream, resolvable
                                // only by restart-time quarantine. `error`
                                // carries only the stable category / size
                                // text, never the upstream URL.
                                let failure = ToolOutcome {
                                    status: StatusCode::BAD_GATEWAY.as_u16(),
                                    body_hex: hex::encode(
                                        serde_json::to_vec(&json!({
                                            "error": format!("tool executed but its response could not be read: {error}"),
                                        }))
                                        .unwrap_or_default(),
                                    ),
                                    content_type: Some("application/json".to_owned()),
                                };
                                let gate = tool_audit_gate(&state, &execution.key);
                                let _gate = gate.lock().await;
                                if execution.persist(&failure).await.is_ok() {
                                    if let Some(session) = state.sessions.get(&execution.session_id) {
                                        return complete_tool_audit(
                                            &state,
                                            &execution,
                                            failure,
                                            completion_permit,
                                            session,
                                        )
                                        .await;
                                    }
                                }
                                pipeline_error(crate::pipeline::PipelineError::Upstream(format!(
                                    "read tool response: {error}"
                                )))
                            }
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
                        // A connect failure means the connection never
                        // opened: the upstream provably did not execute the
                        // tool. Release the claimed execution key and refund
                        // the admission charge so the client's retry is
                        // clean, instead of stranded at "outcome uncertain"
                        // with a burned budget slot. Release-then-refund
                        // ordering: a crash between the two leaves the
                        // charge in place (conservative) rather than a
                        // refunded-but-claimed key. Timeout/read/request
                        // failures stay claimed — the tool may have executed.
                        if error.is_connect() {
                            match execution.release_unexecuted().await {
                                Ok(()) => refund_admission(),
                                Err(release_error) => tracing::warn!(
                                    session = %execution.session_id,
                                    error = %release_error,
                                    "failed to release unexecuted tool intent; charge kept, key stays claimed"
                                ),
                            }
                        }
                        // Upstream faults must surface as 502 (as the chat
                        // relay does), not 500: a 500 blames the harness and
                        // misroutes operator alerting/retry policy.
                        pipeline_error(crate::pipeline::PipelineError::Upstream(format!(
                            "forward tool call: {category}"
                        )))
                    }
                }
            } else {
                // Round-6 (hunt4 protocol F4): verdict-only mode must
                // return a conformant JSON-RPC response — the Blocked
                // arm already does (id echo + error object), so a
                // client could correlate failures but not successes.
                // Echo the request id (string/number/null per spec).
                let request_id = serde_json::from_slice::<Value>(&body)
                    .ok()
                    .and_then(|request| request.get("id").cloned())
                    .unwrap_or(Value::Null);
                (
                    StatusCode::OK,
                    Json(json!({
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "result": {
                            "allowed": true,
                            "tool": tool,
                            "budget_remaining": budget_remaining,
                            "decision_us": elapsed_us,
                        },
                    })),
                )
                    .into_response()
            }
        }
        Ok(ToolVerdict::Blocked { response, stage, .. }) => {
            // Round-6 (hunt4 protocol F5): a request that never parsed
            // (stage "parse") gets 400, not 403 — no authorization
            // decision was made. Policy/schema/budget refusals keep 403.
            let status = if stage == "parse" {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::FORBIDDEN
            };
            (status, Json(response)).into_response()
        }
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
async fn read_limited_tool_response(response: reqwest::Response) -> Result<(Bytes, Option<String>), String> {
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
    // Round-51 §3.5: the MCP relay forwards the tool upstream's
    // Content-Type verbatim; pin nosniff exactly like the chat relay
    // (round-29 F4) so a rogue tool upstream flipping the type to
    // text/html cannot get attacker-echoed bytes rendered by a
    // browser-side MIME sniff.
    response.headers_mut().insert(
        axum::http::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    response
}

async fn complete_tool_audit(
    state: &AppState,
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
    // If a prior attempt in this process already journaled the completion
    // event but failed to write the `.audited` marker, re-attempt only the
    // marker — re-submitting the job would put a second execution record
    // (with a fresh event uid) on the audit stream and in the signed chain.
    let already_emitted = state.tool_audits_emitted.lock().contains(&execution.key);
    if !already_emitted {
        completion_permit.submit(crate::worker::WorkerJob {
            session: Arc::clone(&session),
            identity: session.current_identity(),
            class: av_events::EventClass::Session,
            payload: json!({
                "action": "tool_completed",
                "execution_key": &execution.key,
                "status": status.as_u16(),
                "response_sha256": av_core::digest::sha256_hex(&bytes),
            }),
            text: String::new(),
            analyze_loop: false,
            status: if success {
                av_events::StatusId::Success
            } else {
                av_events::StatusId::Failure
            },
            stop_reason: (!success).then_some(StopReason::Other),
            native_stop_reason: None,
            metrics: av_events::EventMetrics::default(),
            cost_usd_micros: 0,
            atif: Some(crate::worker::AtifCapture {
                source: av_atif::Source::System,
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
        // The event is durably journaled; remember that before attempting
        // the marker so a marker failure retries without re-emitting.
        state.tool_audits_emitted.lock().insert(execution.key.clone());
    }
    if let Err(error) = execution.mark_audited().await {
        return lifecycle_error(error);
    }
    state.tool_audits_emitted.lock().remove(&execution.key);
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

/// Two distinct failure modes for `ToolExecution::claim` that must
/// produce different client responses. Round-49 F3: previously
/// `claim_sync` mapped ALL failures to a `String` and the caller in
/// `mcp_call_inner` answered every one with `409 TOOL_OUTCOME_UNCERTAIN`
/// — reporting infrastructure faults (StorageFull, PermissionDenied,
/// ReadOnlyFilesystem, Interrupted) as if the client had lost a
/// concurrent race, so retries looped on the underlying disk fault
/// while the client learned nothing useful.
#[derive(Debug)]
enum ClaimError {
    /// The intent file already existed (`create_new` returned
    /// `AlreadyExists`). Another in-flight request owns this
    /// execution key — the legitimate race case that `409
    /// TOOL_OUTCOME_UNCERTAIN` was designed for.
    Race,
    /// An I/O or MAC-seal failure independent of concurrent claim
    /// contention. Maps to a 5xx so operators are alerted to a real
    /// infrastructure problem instead of retrying on false uncertainty.
    Backend(String),
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
            let intent_bytes = match std::fs::read(&path) {
                Ok(bytes) => bytes,
                // The session's close legitimately removes its tool-execution
                // files between the directory listing and this read.
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    intent_keys.remove(key);
                    continue;
                }
                Err(error) => return Err(error.to_string()),
            };
            let intent: ToolIntent = match crate::journal::open(
                &control_key,
                &format!("{}:{key}", crate::journal::TOOL_INTENT_DOMAIN),
                0,
                &intent_bytes,
            ) {
                Ok(intent) => intent,
                Err(error) => {
                    // Round-22 F2 (self-fix of round-21 F4): build
                    // the quarantine name EXPLICITLY. The prior use
                    // of `path.with_extension("intent.torn")` on a
                    // `<key>.intent.json` path replaces only the
                    // `json` component and produces
                    // `<key>.intent.intent.torn` — the ugly
                    // double-`intent` form. Explicit join gives the
                    // clean `<key>.intent.torn` name that
                    // remove_tool_executions's defense-in-depth
                    // cleanup expects.
                    let file_name = path
                        .file_stem()
                        .and_then(std::ffi::OsStr::to_str)
                        .and_then(|stem| stem.strip_suffix(".intent"))
                        .map(|key| format!("{key}.intent.torn"));
                    let quarantine = match file_name {
                        Some(name) => path.with_file_name(name),
                        None => path.with_extension("intent.torn"),
                    };
                    tracing::warn!(
                        %error,
                        original = %av_core::fsutil::basename(&path),
                        quarantine = %av_core::fsutil::basename(&quarantine),
                        "torn tool-execution intent quarantined so recovery can proceed"
                    );
                    if let Err(rename_err) = std::fs::rename(&path, &quarantine) {
                        tracing::warn!(%rename_err, "failed to quarantine torn intent — leaving in place");
                    }
                    // Round-6 (hunt3 F2): also quarantine the outcome
                    // and audited siblings. Leaving them behind trips
                    // the orphan-outcome check below in the same tick
                    // and every tick thereafter, permanently stalling
                    // recovery — the exact brick this quarantine
                    // discipline exists to prevent.
                    quarantine_orphan_sibling(&directory, key, crate::spool::TOOL_OUTCOME_SUFFIX, "outcome");
                    quarantine_orphan_sibling(&directory, key, crate::spool::TOOL_AUDITED_SUFFIX, "audited");
                    intent_keys.remove(key);
                    continue;
                }
            };
            if intent.execution_key != key {
                return Err("tool intent path does not match authenticated execution key".to_owned());
            }
            let outcome_path = directory.join(format!("{key}{}", crate::spool::TOOL_OUTCOME_SUFFIX));
            // NotFound between the exists-style check and the read: the
            // outcome is genuinely absent (or was GC'd with its session's
            // close mid-scan) — record unresolved and move on rather than
            // aborting the whole recovery pass.
            let outcome_bytes = match std::fs::read(&outcome_path) {
                Ok(bytes) => bytes,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    unresolved_sessions.insert(intent.session_id);
                    continue;
                }
                Err(error) => return Err(error.to_string()),
            };
            let _: ToolOutcome = match crate::journal::open(
                &control_key,
                &format!("{}:{key}", crate::journal::TOOL_OUTCOME_DOMAIN),
                0,
                &outcome_bytes,
            ) {
                Ok(outcome) => outcome,
                Err(error) => {
                    // Round-6 (hunt3 F2): warn+quarantine the unverifiable
                    // outcome (and any sibling audited file) instead of
                    // aborting the whole recovery pass and bricking the
                    // startup.
                    tracing::warn!(
                        %error,
                        key = %key,
                        "torn tool-execution outcome quarantined so recovery can proceed"
                    );
                    quarantine_orphan_sibling(&directory, key, crate::spool::TOOL_OUTCOME_SUFFIX, "outcome");
                    quarantine_orphan_sibling(&directory, key, crate::spool::TOOL_AUDITED_SUFFIX, "audited");
                    unresolved_sessions.insert(intent.session_id);
                    continue;
                }
            };
            let audited_path = directory.join(format!("{key}{}", crate::spool::TOOL_AUDITED_SUFFIX));
            let audited_bytes = match std::fs::read(&audited_path) {
                Ok(bytes) => bytes,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    unresolved_sessions.insert(intent.session_id);
                    continue;
                }
                Err(error) => return Err(error.to_string()),
            };
            let _: serde_json::Value = match crate::journal::open(
                &control_key,
                &format!("{}:{key}", crate::journal::TOOL_AUDITED_DOMAIN),
                0,
                &audited_bytes,
            ) {
                Ok(value) => value,
                Err(error) => {
                    tracing::warn!(
                        %error,
                        key = %key,
                        "torn tool-execution audited record quarantined so recovery can proceed"
                    );
                    quarantine_orphan_sibling(&directory, key, crate::spool::TOOL_AUDITED_SUFFIX, "audited");
                    unresolved_sessions.insert(intent.session_id);
                    continue;
                }
            };
        }
        for entry in std::fs::read_dir(&directory).map_err(|error| error.to_string())? {
            let path = entry.map_err(|error| error.to_string())?.path();
            let Some(name) = path.file_name().and_then(std::ffi::OsStr::to_str) else {
                continue;
            };
            if let Some(key) = name.strip_suffix(crate::spool::TOOL_OUTCOME_SUFFIX) {
                if !intent_keys.contains(key) {
                    // Round-6 (hunt3 F2): an orphan outcome must not
                    // return Err — that turns the recovery tick into a
                    // permanent brick, especially at boot where
                    // recover_spooled_sessions is fatal. Rename the
                    // outcome (and any sibling audited) to a
                    // `.corrupt-*` name so nothing scans them again.
                    tracing::warn!(
                        key = %key,
                        "orphan tool outcome without authenticated intent quarantined"
                    );
                    quarantine_orphan_sibling(&directory, key, crate::spool::TOOL_OUTCOME_SUFFIX, "outcome");
                    quarantine_orphan_sibling(&directory, key, crate::spool::TOOL_AUDITED_SUFFIX, "audited");
                }
            }
        }
        Ok(unresolved_sessions)
    })
    .await
    .map_err(|error| error.to_string())?
}

/// Rename `<directory>/<key><suffix>` to a `.corrupt-<uid>` name so
/// nothing else scans it. Silent-ok when the sibling doesn't exist
/// (the common case). See round-5 hunt3 F2.
fn quarantine_orphan_sibling(directory: &std::path::Path, key: &str, suffix: &str, role: &str) {
    let path = directory.join(format!("{key}{suffix}"));
    if !path.exists() {
        return;
    }
    let uid = av_core::new_event_uid();
    let quarantine = directory.join(format!("{key}{suffix}.corrupt-{uid}"));
    if let Err(rename_err) = std::fs::rename(&path, &quarantine) {
        tracing::warn!(
            %rename_err,
            role = %role,
            original = %av_core::fsutil::basename(&path),
            "failed to quarantine orphan tool-execution sibling — leaving in place"
        );
    } else {
        tracing::warn!(
            role = %role,
            original = %av_core::fsutil::basename(&path),
            quarantine = %av_core::fsutil::basename(&quarantine),
            "orphan tool-execution sibling quarantined"
        );
    }
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
        // Refuse duplicate x-av-session headers (see
        // `pipeline::single_header` for the rationale — proxies
        // sometimes merge duplicates on the wire and log aggregators
        // can then observe a comma-joined value that leaks a
        // client-desync into audit).
        let session_id = crate::pipeline::single_header(headers, crate::pipeline::SESSION_HEADER)?
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| crate::pipeline::PipelineError::BadRequest("missing x-av-session".to_owned()))?;
        // Same validation as the pipeline's `session_id`: an id the intercept
        // path would reject must not key a tool-execution intent either.
        let session_id = av_core::SessionId::parse(session_id)
            .map(|id| id.to_string())
            .map_err(|error| crate::pipeline::PipelineError::BadRequest(error.to_string()))?;
        let call = av_sandbox::parse_tool_call(body)
            .map_err(|error| crate::pipeline::PipelineError::BadRequest(error.to_string()))?;
        // `parse_tool_call` accepts `"id": null` per JSON-RPC 2.0, but the
        // forwarded-execution key is `sha256("{session}:{id}")` — a null id
        // would collapse every null-id call in a session onto one execution
        // key, replaying the first call's cached outcome for later,
        // different calls. Require a concrete id here.
        let id = call.id.filter(|id| !id.is_null()).ok_or_else(|| {
            crate::pipeline::PipelineError::BadRequest(
                "forwarded tool calls require a non-null JSON-RPC id for idempotency".to_owned(),
            )
        })?;
        let request: Value = serde_json::from_slice(body)
            .map_err(|error| crate::pipeline::PipelineError::BadRequest(error.to_string()))?;
        let canonical = av_receipts::canonicalize(&request)
            .map_err(|error| crate::pipeline::PipelineError::BadRequest(error.to_string()))?;
        let request_digest = av_core::digest::sha256_hex(canonical.as_bytes());
        let key_material = format!("{session_id}:{}", id);
        let key = av_core::digest::sha256_hex(key_material.as_bytes());
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
        identity: &av_events::AgentIdentity,
    ) -> Result<(), crate::pipeline::PipelineError> {
        let stable_identity = json!({
            "version": identity.version,
            "charter": identity.charter,
            "instance_uid": identity.instance_uid,
        });
        let canonical = av_receipts::canonicalize(&stable_identity)
            .map_err(|error| crate::pipeline::PipelineError::BadRequest(error.to_string()))?;
        self.principal_digest = av_core::digest::sha256_hex(canonical.as_bytes());
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

    async fn claim(&self) -> Result<(), ClaimError> {
        let execution = self.clone();
        tokio::task::spawn_blocking(move || execution.claim_sync())
            .await
            .map_err(|error| ClaimError::Backend(error.to_string()))?
    }

    /// Delete this execution's intent file after a provably-not-executed
    /// forward (connect failure), restoring the key for a clean retry.
    /// NotFound is tolerated — the claim was ours, so a missing file only
    /// means a prior release already ran.
    ///
    /// Round-49 F2: the post-remove directory fsync is best-effort.
    /// `remove_file` returning Ok is durable-enough for the release
    /// semantics — a crash before the dir fsync makes the intent file
    /// resurrect on recovery, at which point `unresolved_tool_sessions`
    /// correctly quarantines the session (fail-closed). Previously any
    /// fsync failure returned Err and the caller at `mcp_call_inner`'s
    /// connect-failure branch skipped the budget refund, leaving the
    /// key unclaimed AND the budget debited — the exact bug the
    /// release-then-refund ordering was supposed to prevent.
    async fn release_unexecuted(&self) -> Result<(), String> {
        let execution = self.clone();
        tokio::task::spawn_blocking(move || {
            match std::fs::remove_file(&execution.intent_path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(error) => return Err(error.to_string()),
            }
            if let Some(directory) = execution.intent_path.parent() {
                if let Err(error) = std::fs::File::open(directory).and_then(|directory| directory.sync_all())
                {
                    tracing::warn!(
                        path = %av_core::fsutil::basename(&execution.intent_path),
                        %error,
                        "release_unexecuted: intent removed but directory fsync failed; treating as released"
                    );
                }
            }
            Ok(())
        })
        .await
        .map_err(|error| error.to_string())?
    }

    fn claim_sync(&self) -> Result<(), ClaimError> {
        use std::io::Write as _;
        let directory = self
            .intent_path
            .parent()
            .ok_or_else(|| ClaimError::Backend("tool execution directory is missing".to_owned()))?;
        std::fs::create_dir_all(directory).map_err(|error| ClaimError::Backend(error.to_string()))?;
        // `create_new(true)` is atomic on the underlying filesystem —
        // its only reason to return `AlreadyExists` is that another
        // in-flight request has already claimed this execution key
        // (the sole legitimate race source). Any other IoError kind
        // (StorageFull, PermissionDenied, InvalidInput, ReadOnlyFilesystem,
        // Interrupted, etc.) is a genuine infrastructure failure and
        // must NOT be reported to the client as a lost race — the
        // caller would answer 409 TOOL_OUTCOME_UNCERTAIN and retries
        // would loop on the same underlying disk fault while the
        // client learns nothing useful. Split the two shapes at the
        // source so the caller can respond appropriately.
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&self.intent_path)
            .map_err(|error| match error.kind() {
                std::io::ErrorKind::AlreadyExists => ClaimError::Race,
                _ => ClaimError::Backend(format!("tool execution intent unavailable: {error}")),
            })?;
        let intent = crate::journal::seal(
            &self.control_key,
            &format!("{}:{}", crate::journal::TOOL_INTENT_DOMAIN, self.key),
            0,
            &self.intent(),
        )
        .map_err(ClaimError::Backend)?;
        file.write_all(&intent)
            .map_err(|error| ClaimError::Backend(error.to_string()))?;
        file.sync_all()
            .map_err(|error| ClaimError::Backend(error.to_string()))?;
        std::fs::File::open(directory)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| ClaimError::Backend(error.to_string()))
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
    av_core::fsutil::write_atomic(path, bytes).map_err(|error| error.to_string())
}

async fn close_session(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(session) = state.sessions.get(&id) else {
        // Authenticate BEFORE revealing whether the session exists.
        // Returning 404 straight from the registry miss gave
        // unauthenticated callers a response-differential oracle
        // (404 = free, 401 = live) to enumerate active session ids
        // without ever presenting a token. Run the same identity +
        // scope resolution the found-path runs, so the status split
        // is identical whether or not the id is live.
        if let Err(error) = state.resolve_identity(&headers, Some(state.config.session_close_scope.as_str()))
        {
            return pipeline_error(error);
        }
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
        Err(error) => finalize_error_response(&error),
    }
}

async fn promote_session(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(session) = state.sessions.get(&id) else {
        // Same authenticate-before-404 discipline as `close_session`:
        // no session-existence oracle for unauthenticated callers.
        if let Err(error) =
            state.resolve_identity(&headers, Some(state.config.session_promote_scope.as_str()))
        {
            return pipeline_error(error);
        }
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
        if let Err(error) = state.authorize_session(&headers, &session, &state.config.session_close_scope) {
            return pipeline_error(error);
        }
    }
    match state.finalizer.promote(session).await {
        Ok(receipt) => Json(receipt).into_response(),
        Err(error) => finalize_error_response(&error),
    }
}

/// Typed status mapping for close/promote failures. Flattening every
/// `FinalizeError` to 500 (the old behavior) misclassified deterministic
/// fail-closed refusals as server faults: SDKs retry 500s pointlessly
/// against a permanently-quarantined session, and operators page on 5xx
/// rates for what is working policy (the same rationale as the breaker's
/// deliberate 403-not-429 choice, and the tool path's CONFLICT mapping).
fn finalize_error_response(error: &crate::reconciler::FinalizeError) -> Response {
    use crate::reconciler::FinalizeError;
    let status = match error {
        // Deterministic state conflicts: the request conflicts with the
        // session's current state and retrying cannot change the outcome
        // (quarantined capture, no artifact to promote, promotion already
        // in progress).
        FinalizeError::CaptureIncomplete | FinalizeError::Promotion(_) => StatusCode::CONFLICT,
        // Round-28 F1: permanent bridge misconfiguration (unknown
        // topic, unresolvable schema) — retrying without operator
        // action cannot succeed. Map to 400 so SDKs stop retrying
        // and pagers fire on operator config errors, not on
        // transient outages.
        FinalizeError::BridgeConfig(_) => StatusCode::BAD_REQUEST,
        // Transient infrastructure: the broker is unreachable; the close
        // stays pending and a retry (or the reconciler sweep) completes it.
        FinalizeError::Bridge(_) => StatusCode::SERVICE_UNAVAILABLE,
        // Everything else is a genuine internal fault.
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    let mut response = (status, Json(json!({"error": error.to_string()}))).into_response();
    if status == StatusCode::SERVICE_UNAVAILABLE {
        // Same advisory as pipeline_error's retryable class.
        response
            .headers_mut()
            .insert(axum::http::header::RETRY_AFTER, HeaderValue::from_static("5"));
    }
    response
}

fn pipeline_error(error: crate::pipeline::PipelineError) -> Response {
    use crate::pipeline::PipelineError;
    let close = matches!(error, PipelineError::Abort(_));
    let status = error.status();
    // Round-51 §9.3: OpenAI-shaped error body. SDKs dispatch on
    // `error.type` / `error.code` (`openai.APIError.code`), and the
    // previous bare `{"error": "<string>"}` left that handling dead —
    // five inconsistent shapes across sibling routes. `message` keeps
    // the exact text the old shape carried; `type` follows OpenAI's
    // taxonomy so stock retry/backoff classifiers behave correctly.
    let error_type = match status.as_u16() {
        400 | 404 | 409 | 413 => "invalid_request_error",
        401 => "authentication_error",
        403 => "permission_error",
        429 => "rate_limit_error",
        _ => "api_error",
    };
    let mut response = (
        status,
        Json(json!({
            "error": {
                "message": error.to_string(),
                "type": error_type,
                "param": null,
                "code": status.as_u16(),
            }
        })),
    )
        .into_response();
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
                HeaderValue::from_static("Bearer realm=\"agentvisor\", error=\"invalid_token\""),
            );
        }
        _ => {}
    }
    response
}

fn lifecycle_error(error: String) -> Response {
    // Same OpenAI-shaped body as `pipeline_error` (round-51 §9.3) so
    // the two sibling routes agree on one error contract.
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({
            "error": {
                "message": error,
                "type": "api_error",
                "param": null,
                "code": 500,
            }
        })),
    )
        .into_response()
}

struct AbortFinalizingStream {
    inner: BoxStream<'static, Result<Bytes, std::io::Error>>,
    session: Arc<crate::session::Session>,
    identity: av_events::AgentIdentity,
    response_permit: Option<crate::worker::ResponsePermit>,
    /// Handle to submit the response-capture job at end-of-stream. The
    /// permit above only holds the `response_capacity` semaphore slot
    /// — the mpsc queue slot is re-acquired at submit time via
    /// `ResponsePermit::submit(&worker, job)`.
    worker: crate::worker::WorkerHandle,
    store: Arc<dyn av_state::StateStore>,
    budget: av_state::BudgetSpec,
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
    response_tool_calls: std::collections::BTreeMap<(u64, u64), PartialToolCall>,
    response_metrics: av_events::EventMetrics,
    charged_completion_tokens: u64,
    last_reported_completion_tokens: Option<u64>,
    last_reported_prompt_tokens: Option<u64>,
    last_reported_cached_tokens: Option<u64>,
    last_reported_cost_usd_micros: Option<u64>,
    saw_chunk: bool,
    /// At-most-once guard for `submit_response_capture`. Set BEFORE the
    /// fallible `ResponsePermit::submit` on purpose: if the shard is full
    /// the capture event is intentionally dropped (counted in
    /// `av_events_dropped_total{stage="response_slot"}`) and MUST NOT be
    /// retried by a later call. Do not "fix" the ordering by setting this
    /// after the submit — that would reintroduce double-submit attempts
    /// against a consumed permit.
    capture_attempted: bool,
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
        // Cumulative-cost contract (round-6 hunt3 math F2): providers
        // that report `cost_usd` are expected to report it CUMULATIVELY
        // (OpenRouter-style final/rolling usage frames) — `max()` folds
        // that correctly and tolerates repeated identical frames. A
        // provider emitting per-chunk INCREMENTAL costs is mostly
        // caught by `reject_metric_regression` (any decrease fails the
        // stream), but a monotone non-decreasing incremental sequence
        // (e.g. equal per-chunk costs) passes the guard and attests
        // only the LAST chunk's amount. That shape is indistinguishable
        // from legitimate repeated cumulative frames on the wire, so it
        // cannot be rejected without breaking conformant providers —
        // recorded here as the documented accepted limitation
        // (undercount is bounded by the true total; never an
        // overcharge).
        self.response_cost_usd_micros = self.response_cost_usd_micros.max(parsed.cost_usd_micros);
        for delta in parsed.tool_call_deltas {
            if delta.index >= MAX_PROVIDER_TOOL_CALLS as u64 {
                return Err(format!(
                    "provider tool-call index {} is out of range",
                    delta.index
                ));
            }
            let key = (delta.choice_index, delta.index);
            if !self.response_tool_calls.contains_key(&key)
                && self.response_tool_calls.len() >= MAX_PROVIDER_TOOL_CALLS
            {
                return Err(format!(
                    "provider response exceeds {MAX_PROVIDER_TOOL_CALLS} tool calls"
                ));
            }
            let partial = self.response_tool_calls.entry(key).or_default();
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
        let delta = if parsed.usage_reported && parsed.completion_reported {
            let previous = self.last_reported_completion_tokens.unwrap_or(0);
            if reported_completion < previous {
                return Err("provider completion usage regressed".to_owned());
            }
            self.last_reported_completion_tokens = Some(reported_completion);
            let delta = reported_completion.saturating_sub(self.charged_completion_tokens);
            // Authoritative usage overrides any prior estimate. The
            // regression check above guarantees monotonicity across
            // authoritative frames, so `max()` here would only keep a
            // stale estimate that happened to exceed the true count —
            // and that estimate lands in the attested `completion_tokens`
            // recorded on the ATIF step, signed receipt, and session
            // totals. Trigger: content chunks land with `"usage": null`
            // (OpenAI `stream_options.include_usage`), the parser fills
            // in `approx_tokens`, and those estimates get folded into
            // `response_metrics.completion_tokens` via the estimate
            // branch below; a final cumulative `{"usage":{"completion_tokens":6}}`
            // with the accumulated estimate at 10 would attest 10.
            self.response_metrics.completion_tokens = Some(reported_completion);
            delta
        } else {
            let total = self
                .response_metrics
                .completion_tokens
                .unwrap_or(0)
                .checked_add(reported_completion)
                .filter(|total| *total <= av_core::error::JCS_SAFE_MAX)
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
            av_state::ActionBudget::new(store.as_ref(), &session_id, &budget)
                .try_tokens(delta)
                .map_err(|error| format!("token budget backend failed closed: {error}"))
        });
        self.pending_budget = Some(PendingBudget { task, continuation });
    }

    fn submit_response_capture(&mut self, failure: Option<String>) -> Result<(), crate::worker::SubmitError> {
        if self.capture_attempted {
            return Ok(());
        }
        self.capture_attempted = true;
        let reasoning =
            (!self.response_reasoning.is_empty()).then(|| std::mem::take(&mut self.response_reasoning));
        // Materialize the tool-call list up front so we can fall back to
        // its content when the response body has neither an assistant
        // message nor reasoning. Round-53 F1: without this, tool-only
        // responses (a legitimate agent mode: "return only tool_calls,
        // no assistant text") collapsed to an all-zero embedding at
        // `av_loopdetect::embed`, which the breaker treats as a hostile
        // duplicate and grows the loop streak on — so a healthy agent
        // that just happened to be tool-driven would get flagged as
        // looping after the min-tokens threshold.
        let tool_calls: Vec<av_atif::ToolCall> = std::mem::take(&mut self.response_tool_calls)
            .into_values()
            .map(|partial| {
                let arguments = serde_json::from_str(&partial.arguments)
                    .unwrap_or_else(|_| json!({"raw": partial.arguments}));
                av_atif::ToolCall {
                    tool_call_id: partial.id.unwrap_or_else(av_core::new_event_uid),
                    function_name: partial.name.unwrap_or_else(|| "unknown".to_owned()),
                    arguments,
                    extra: None,
                }
            })
            .collect();
        let analysis_text = if let Some(text) = reasoning.clone() {
            text
        } else if !self.response_message.is_empty() {
            self.response_message.clone()
        } else if !tool_calls.is_empty() {
            tool_calls
                .iter()
                .map(|tc| format!("{}({})", tc.function_name, tc.arguments))
                .collect::<Vec<_>>()
                .join(" ")
        } else {
            String::new()
        };
        // Skip loop analysis when the response is genuinely empty (no
        // reasoning, no message, no tool calls) — a zero-vector embed
        // would otherwise poison the breaker's duplicate detection.
        let analyze_loop = !analysis_text.is_empty();
        let native_finish_reason = self.response_finish_reason.clone();
        let (class, status, stop_reason, payload) = if let Some(reason) = failure {
            (
                av_events::EventClass::StopReason,
                av_events::StatusId::Failure,
                Some(av_events::StopReason::BudgetExceeded),
                json!({"reason": reason, "direction": "upstream_response"}),
            )
        } else if !self.upstream_status.is_success() {
            (
                av_events::EventClass::StopReason,
                av_events::StatusId::Failure,
                Some(av_events::StopReason::Other),
                json!({
                    "direction": "upstream_response",
                    "http_status": self.upstream_status.as_u16(),
                }),
            )
        } else if let Some(native) = &native_finish_reason {
            (
                av_events::EventClass::StopReason,
                av_events::StatusId::Success,
                Some(map_finish_reason(native)),
                json!({
                    "direction": "upstream_response",
                    "finish_reason": native,
                    "http_status": self.upstream_status.as_u16(),
                }),
            )
        } else if self.is_sse {
            // Engineering-review §6.4 (round-51): an SSE stream that
            // ended without ANY finish_reason chunk is a truncated
            // generation — provider crash, LB idle-timeout, worker
            // OOM. OpenAI-protocol streams always carry a
            // finish_reason chunk before [DONE], so its absence must
            // not be attested as a complete success: a compliance
            // reviewer could not otherwise distinguish a truncated
            // response from a finished one (previously this shape
            // recorded StatusId::Success with no stop reason — and a
            // zero-byte 200 stream looked identical to a real one).
            (
                av_events::EventClass::StopReason,
                av_events::StatusId::Unknown,
                Some(av_events::StopReason::Other),
                json!({
                    "direction": "upstream_response",
                    "http_status": self.upstream_status.as_u16(),
                    "truncated": true,
                    "reason": "stream ended without a finish_reason chunk",
                }),
            )
        } else {
            (
                av_events::EventClass::Session,
                av_events::StatusId::Success,
                None,
                json!({
                    "direction": "upstream_response",
                    "http_status": self.upstream_status.as_u16(),
                }),
            )
        };
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
                analyze_loop,
                status,
                stop_reason,
                native_stop_reason: native_finish_reason,
                metrics: self.response_metrics,
                cost_usd_micros: self.response_cost_usd_micros,
                atif: Some(crate::worker::AtifCapture {
                    source: av_atif::Source::Agent,
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
    task: tokio::task::JoinHandle<Result<av_state::BudgetDecision, String>>,
    continuation: BudgetContinuation,
}

#[derive(Default)]
struct PartialToolCall {
    id: Option<String>,
    name: Option<String>,
    arguments: String,
}

struct ProviderToolCallDelta {
    /// The `choices[].index` this delta belongs to. Multi-choice
    /// (`n > 1`) responses reuse tool-call index 0 in every choice, so
    /// reassembly must key on (choice, tool index) or distinct calls
    /// merge into one corrupt audit record.
    choice_index: u64,
    index: u64,
    id: Option<String>,
    name: Option<String>,
    arguments: String,
}

struct ParsedProviderChunk {
    message: String,
    reasoning: Option<String>,
    model_name: Option<String>,
    metrics: av_events::EventMetrics,
    usage_reported: bool,
    /// True only when the provider itself supplied `completion_tokens`
    /// (as opposed to the per-chunk heuristic estimate filled in below).
    /// `absorb_frame`'s cumulative-usage branch must key on this, not on
    /// `usage_reported` alone: a usage object without a completion count
    /// (`{"prompt_tokens": 7}` or `"completion_tokens": null`) would
    /// otherwise feed a non-cumulative estimate into cumulative math.
    completion_reported: bool,
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

/// Fuzz-only shim over the internal `parse_provider_chunk` — accepts
/// arbitrary bytes and returns nothing (the fuzz harness just cares
/// that the parser is total under Unicode / SSE malformation). Not
/// part of the stable API; see [`crate::fuzz`] for the documented
/// re-export path.
#[doc(hidden)]
pub fn __fuzz_parse_provider_chunk(raw: &[u8]) {
    if let Ok(s) = std::str::from_utf8(raw) {
        let _ = parse_provider_chunk(s);
    }
}

/// Fuzz-only shim over the internal `sse_frame_end` framing scanner.
/// See [`__fuzz_parse_provider_chunk`] for rationale.
#[doc(hidden)]
pub fn __fuzz_sse_frame_end(raw: &[u8]) {
    let _ = sse_frame_end(raw);
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

    /// Engineering-review §6.2 (round-51): scope a mid-stream capture
    /// failure to THIS response instead of sealing the whole session.
    /// The failure reason is recorded into the audit trail via
    /// `submit_response_capture(Some(_))` (at-most-once), so the turn
    /// is attested as failed and the session stays usable for future
    /// turns — a transient provider framing quirk no longer costs the
    /// operator every previously-captured turn. Only when the audit
    /// worker itself cannot accept the capture do we fall back to
    /// sealing the session: without the failure record the audit chain
    /// has a hole no later close could explain.
    fn record_response_failure(&mut self, reason: &str) {
        if let Err(error) = self.submit_response_capture(Some(reason.to_owned())) {
            tracing::warn!(
                %error,
                session = %self.session.id,
                "response-failure capture submit failed; sealing session capture"
            );
            self.session.mark_capture_failed();
        }
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
                Ok(Ok(av_state::BudgetDecision::Allowed { .. })) => None,
                Ok(Ok(av_state::BudgetDecision::Refused { limit, cap })) => {
                    // Genuine mid-stream cap exhaustion — the ONLY arm
                    // that latches. The Ok(Err(..)) arm below is the
                    // quota-backend outage (fail-closed refusal, not
                    // enforcement): latching it converted a transient
                    // store blip into a permanent id lockout, the exact
                    // defect the chat path's backend-error arm
                    // deliberately avoids.
                    self.session
                        .latch_enforcement(av_events::StopReason::BudgetExceeded);
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
                // QuotaExceeded is an in-process marker: the non-SSE
                // drain in `chat_completions` maps it to
                // `PipelineError::Blocked` → HTTP 403 (the same
                // deliberately-not-429 policy as the breaker path)
                // so budget refusals reach the client as a real
                // error instead of a severed body.
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
                                self.record_response_failure(&error);
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
                        let reason = error.to_string();
                        self.record_response_failure(&reason);
                        self.pending_output.clear();
                        let error = self.abort_error(reason);
                        return Poll::Ready(Some(Err(error)));
                    }
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(None) => {
                        let delta = match self.flush_protocol_buffer() {
                            Ok(delta) => delta,
                            Err(error) => {
                                self.record_response_failure(&error);
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
                        // A 200 with a completely EMPTY body produced no
                        // frame, so `absorb_frame`'s "successful provider
                        // response has no choices array" guard never ran —
                        // without this check the session would attest a
                        // clean assistant turn that never happened (while
                        // the strictly-less-broken `200 {}` body fails
                        // capture). `saw_chunk` exists precisely to gate
                        // this.
                        if self.upstream_status.is_success() && !self.saw_chunk {
                            self.session.mark_capture_failed();
                            self.pending_output.clear();
                            let error =
                                self.abort_error("successful provider response has an empty body".to_owned());
                            return Poll::Ready(Some(Err(error)));
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
                    self.record_response_failure(&error);
                    let error = self.abort_error(error);
                    Poll::Ready(Some(Err(error)))
                }
            },
            Poll::Ready(Some(Err(error))) => {
                let reason = error.to_string();
                self.record_response_failure(&reason);
                let error = self.abort_error(reason);
                Poll::Ready(Some(Err(error)))
            }
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => {
                let delta = match self.flush_protocol_buffer() {
                    Ok(delta) => delta,
                    Err(error) => {
                        self.record_response_failure(&error);
                        let error = self.abort_error(error);
                        return Poll::Ready(Some(Err(error)));
                    }
                };
                if delta > 0 {
                    self.begin_budget_check(delta, BudgetContinuation::FinishSse);
                    context.waker().wake_by_ref();
                    return Poll::Pending;
                }
                // Same empty-body fail-closed guard as the non-SSE arm
                // above: a 200 SSE response that delivered zero bytes
                // must not be attested as a clean assistant turn.
                if self.upstream_status.is_success() && !self.saw_chunk {
                    self.session.mark_capture_failed();
                    let error = self.abort_error("successful provider response has an empty body".to_owned());
                    return Poll::Ready(Some(Err(error)));
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
    // omitted) is the default. AgentVisor AI attributes the `data:`
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
        // Engineering-review §6.2: narrow the named-event refusal to
        // frames that actually carry captured data. A named-event
        // keepalive with an empty `data:` field (`event: ping\n\n`,
        // `event: heartbeat\n\n`) can't taint the audit surface — no
        // bytes are attributed to the receipt — so treat it as a
        // skipped frame rather than aborting the whole stream and
        // sealing the session. Only refuse when non-empty `data:`
        // lines would otherwise be attributed to the model output.
        if data.iter().all(|entry| entry.trim().is_empty()) {
            return Ok(None);
        }
        return Err(format!(
            "provider SSE frame carries unsupported event type {event_type:?}; \
             AgentVisor AI only captures the default `message` event because non-message \
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
    // OpenAI streams with `stream_options: {"include_usage": true}` carry
    // `"usage": null` on every content chunk, with the real usage object
    // only on the final chunk (vLLM/LiteLLM shims do the same). A null
    // usage must fall through to the estimate/accumulate path exactly like
    // an absent key: flagging it as reported would feed absorb_frame's
    // cumulative-usage branch a per-chunk heuristic estimate, which both
    // kills the stream with a spurious "provider completion usage
    // regressed" error (estimates are not monotonic) and, when estimates
    // happen to stay monotonic, zeroes every mid-stream budget delta.
    if let Some(usage) = value.get("usage").filter(|usage| !usage.is_null()) {
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
            let micros = (cost * av_core::units::USD_MICROS_PER_DOLLAR as f64).round();
            if micros > av_core::error::JCS_SAFE_MAX as f64 {
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
        for (choice_position, choice) in choices.iter().enumerate() {
            // Distinguish choices in multi-choice (`n > 1`) responses:
            // tool-call deltas are keyed by (choice, tool index) downstream,
            // otherwise `choices[0].tool_calls[0]` and
            // `choices[1].tool_calls[0]` merge into one corrupt audit record
            // (concatenated argument fragments, last-writer-wins id/name).
            let choice_index = choice
                .get("index")
                .and_then(Value::as_u64)
                .or_else(|| u64::try_from(choice_position).ok())
                .unwrap_or(u64::MAX);
            if let Some(reason) = choice
                .get("finish_reason")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
            {
                // Round-6 (hunt2 F4): empty-string finish_reason from
                // OpenAI-compatible shims used to enter the audit
                // chain as `Some("")`, which the JSON schema then
                // rejects at publish (`minLength: 1`) — permanently
                // fail-closing the session AFTER the bytes were
                // already relayed. Treat empty as absent.
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
                        choice_index,
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
    let completion_reported = completion_tokens.is_some();
    let completion_tokens = completion_tokens.unwrap_or_else(|| {
        let mut estimated = av_core::tokens::approx_tokens(&message)
            .saturating_add(av_core::tokens::approx_tokens(&reasoning));
        for call in &tool_call_deltas {
            estimated = estimated
                .saturating_add(call.name.as_deref().map_or(0, av_core::tokens::approx_tokens))
                .saturating_add(av_core::tokens::approx_tokens(&call.arguments));
        }
        estimated
    });
    Ok(Some(ParsedProviderChunk {
        message,
        reasoning: (!reasoning.is_empty()).then_some(reasoning),
        model_name,
        metrics: av_events::EventMetrics {
            prompt_tokens,
            completion_tokens: Some(completion_tokens),
            cached_tokens,
            pruned_tokens: None,
            pruning_ratio_millis: None,
        },
        usage_reported,
        completion_reported,
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
    // Some OpenAI-compatible shims emit explicit nulls for usage fields
    // they don't track; treat them like absent keys rather than failing
    // the frame.
    if value.is_null() {
        return Ok(None);
    }
    let value = value
        .as_u64()
        .ok_or_else(|| format!("provider {field} is not a nonnegative integer"))?;
    if value > av_core::error::JCS_SAFE_MAX {
        return Err(format!("provider {field} exceeds JCS-safe bounds"));
    }
    Ok(Some(value))
}

fn map_finish_reason(native: &str) -> av_events::StopReason {
    match native {
        "stop" | "stop_sequence" | "end_turn" => av_events::StopReason::Stop,
        "length" | "max_tokens" => av_events::StopReason::MaxTokens,
        "tool_calls" | "function_call" | "tool_use" => av_events::StopReason::ToolUse,
        "content_filter" => av_events::StopReason::ContentFilter,
        _ => av_events::StopReason::Other,
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
        //
        // Engineering-review §6.2 (D7): a client disconnect mid-budget-check
        // or a garbled trailing frame is a per-RESPONSE failure — the
        // audit chain is still consistent because we can record the
        // truncation reason via `submit_response_capture(Some(_))`.
        // Sealing the whole session (which the previous fail-closed logic
        // did) bricked every future turn of the agent conversation for
        // any transient network hiccup. `mark_capture_failed()` is now
        // reserved for the one genuinely fatal drop path: the audit
        // worker itself is unreachable, so no future response could be
        // safely captured either.
        let is_closed = self.session.is_closed();
        let budget_incomplete = self.pending_budget.is_some();
        // Round-29 F5: abort the pending budget task. `spawn_blocking`
        // returns a JoinHandle whose Drop does NOT cancel the queued
        // closure; the blocking pool would otherwise run
        // `ActionBudget::try_tokens(delta)` AFTER the drop, silently
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
        let (flush_reason, budget_delta) = match self.flush_protocol_buffer() {
            Ok(delta) => (None, delta),
            Err(error) => {
                tracing::warn!(%error, "provider stream flush failed on drop");
                (Some(format!("provider stream flush failed: {error}")), 0u64)
            }
        };
        // Compose a per-response failure reason. `budget_incomplete`
        // dominates because it always implies the client disconnected
        // before the last chunk was billed; a garbled frame is next
        // most specific; an unbilled tail (delta > 0 with no
        // per-chunk error) means the connection dropped between the
        // last successful budget check and the flush.
        let response_failure: Option<String> = if budget_incomplete {
            Some("client disconnected before response budget check completed".to_owned())
        } else if let Some(reason) = flush_reason {
            Some(reason)
        } else if budget_delta > 0 {
            Some(format!(
                "client disconnected with {budget_delta} unbilled response bytes"
            ))
        } else {
            None
        };
        if let Err(error) = self.submit_response_capture(response_failure) {
            tracing::warn!(%error, "response-capture submit failed on drop");
            if !is_closed {
                // The audit worker is unreachable — no future response
                // on this session could be captured either. This is
                // the one genuinely session-fatal drop path.
                self.session.mark_capture_failed();
            }
        }
        // Engineering-review §6.4 (round-51): a client disconnect must
        // not seal the whole conversation. Spawn the background close
        // ONLY when this abort left nothing capturable AND no
        // concurrent stream is in flight — the ephemeral one-shot
        // case where the session would otherwise linger as an empty
        // husk until the idle sweeper. In every other case the
        // session stays OPEN: the truncated turn was recorded above
        // via response capture, a client retrying with the same
        // session id keeps working, and the idle sweeper finalizes
        // if the client never comes back. This was the direct
        // trigger for the §6.1 recycled-id artifact destruction.
        // NB: our own SessionLease is still held during this body
        // (fields drop after Drop::drop), so `> 1` means "another
        // stream besides ours".
        let nothing_captured = !self.saw_chunk && self.captured_bytes == 0;
        let other_streams = self.session.active_streams_count() > 1;
        if !is_closed && nothing_captured && !other_streams {
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
                                    "av_stream_abort_close_failures_total",
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
                            "av_stream_abort_no_runtime_total",
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
    use av_bridge::{BusError, EventBus, PublishAck, StoredEvent};
    use av_receipts::Ed25519Signer;
    use av_sandbox::{Sandbox, SandboxConfig};
    use av_state::{InMemoryStore, Spend, StateError, StateStore};
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
            av_events::EventClass::all()
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
        if payload.get("model").and_then(Value::as_str) == Some("split-sse") {
            // One SSE frame split across two TCP chunks, cut mid-way
            // through the é's UTF-8 encoding (0xc3 0xa9). Exercises the
            // protocol_buffer reassembly path that no other SSE mock
            // reaches (round-51 §10.2: every SSE mock emitted whole
            // frames per chunk).
            let frame = "data: {\"choices\":[{\"delta\":{\"content\":\"héllo\"},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n"
                .as_bytes()
                .to_vec();
            let split = frame.iter().position(|byte| *byte == 0xc3).unwrap() + 1;
            let chunks = vec![
                Ok::<_, std::convert::Infallible>(Bytes::copy_from_slice(&frame[..split])),
                Ok(Bytes::copy_from_slice(&frame[split..])),
            ];
            let mut response = Response::new(Body::from_stream(futures::stream::iter(chunks)));
            response.headers_mut().insert(
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_static("text/event-stream"),
            );
            return response;
        }
        if payload.get("model").and_then(Value::as_str) == Some("truncated-stream") {
            // One delta, then a clean end: no finish_reason, no usage,
            // no [DONE] — the §6.4 truncation shape (provider crash,
            // LB idle-timeout).
            let mut response = Response::new(Body::from(
                "data: {\"choices\":[{\"delta\":{\"content\":\"partial ans\"}}]}\n\n",
            ));
            response.headers_mut().insert(
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_static("text/event-stream"),
            );
            return response;
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
        if payload.get("model").and_then(Value::as_str) == Some("gzip-encoded") {
            // Body content is irrelevant: the encoding refusal fires on
            // the header alone, before any byte is read.
            let mut response = Response::new(Body::from("compressed-bytes"));
            response.headers_mut().insert(
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            response.headers_mut().insert(
                axum::http::header::CONTENT_ENCODING,
                HeaderValue::from_static("gzip"),
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

    /// Round-17 live-stress finding: deterministic fail-closed lifecycle
    /// refusals (quarantined capture, unfulfillable promotion) used to
    /// surface as HTTP 500 — SDKs retried them pointlessly and 5xx-rate
    /// pagers fired on working policy. They must map to 409 Conflict,
    /// mirroring the tool path's state-conflict convention.
    #[tokio::test]
    async fn quarantined_session_close_and_promote_map_to_conflict_not_500() {
        let directory = tempfile::tempdir().unwrap();
        let (state, provider) = test_state(directory.path()).await;
        let app = build_router(state.clone());
        // Open a session, then quarantine it (capture failed).
        let opened = app.clone().oneshot(chat_request("quarantine-409")).await.unwrap();
        assert_eq!(opened.status(), StatusCode::OK);
        axum::body::to_bytes(opened.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let session = state.sessions.get("quarantine-409").unwrap();
        session.wait_for_worker_jobs().await;
        session.mark_capture_failed();

        let close = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/sessions/quarantine-409/close")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            close.status(),
            StatusCode::CONFLICT,
            "capture-incomplete close refusal is a state conflict, not a server fault"
        );
        let promote = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/sessions/quarantine-409/promote")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            promote.status(),
            StatusCode::CONFLICT,
            "unfulfillable promotion refusal is a state conflict, not a server fault"
        );
        provider.abort();
    }

    fn chat_request_with_payload(session: &str, payload: Value) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .header("x-av-session", session)
            .header("x-av-workflow", "unsigned")
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

    /// Round-22 F1 (av-harness routes): `/v1/chat/completions` must
    /// refuse duplicate top-level or nested JSON keys, mirroring the
    /// MCP path's `parse_tool_call` policy. `serde_json`'s default
    /// last-wins semantics would otherwise let a hostile client
    /// send `{"messages":[safe],"messages":[hostile]}` and the
    /// harness would see the hostile array while any auditor reading
    /// the raw request bytes sees the ambiguous document. Same
    /// class as round-15 F3's receipt-null malleability, applied at
    /// chat ingress.
    #[tokio::test]
    async fn chat_completions_refuses_duplicate_json_keys() {
        let directory = tempfile::tempdir().unwrap();
        let (state, provider) = test_state(directory.path()).await;
        let app = build_router(state.clone());
        // Two `messages` keys in the top-level object; second wins by
        // `serde_json` default, but the harness must refuse ambiguity
        // instead of silently taking the last value.
        let dup = br#"{"model":"mock","messages":[{"role":"user","content":"safe"}],"messages":[{"role":"user","content":"hostile"}]}"#;
        let request = Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .header("x-av-session", "dup-key")
            .header("x-av-workflow", "unsigned")
            .body(Body::from(&dup[..]))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "duplicate `messages` key must be refused with 400, not silently taken"
        );
        let body = axum::body::to_bytes(response.into_body(), 4 * 1024)
            .await
            .unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(
            text.contains("duplicate"),
            "response body must name the reason, got {text:?}"
        );
        provider.abort();
    }

    fn active_records(
        directory: &std::path::Path,
        state: &AppState,
        session_id: &str,
    ) -> Vec<crate::worker::ActiveJournalRecord> {
        let digest = av_core::digest::sha256_hex(session_id.as_bytes());
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
        assert_eq!(response.headers().get("x-av-session").unwrap(), "http-flow");
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
        let trajectory: av_atif::Trajectory =
            serde_json::from_slice(&tokio::fs::read(&artifact).await.unwrap()).unwrap();
        if let Some(destination) = std::env::var_os("AV_HARBOR_INTEROP_OUT") {
            std::fs::copy(&artifact, destination).unwrap();
        }
        assert_eq!(
            trajectory.steps.len(),
            2,
            "request and response must both be captured"
        );
        assert_eq!(trajectory.steps[0].source, av_atif::Source::User);
        assert!(trajectory.steps[0].metrics.is_none());
        assert_eq!(trajectory.steps[1].source, av_atif::Source::Agent);
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
        let receipt: av_receipts::Receipt = serde_json::from_slice(
            &axum::body::to_bytes(promoted.into_body(), 64 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        receipt.verify_embedded().unwrap();
        assert_eq!(receipt.body.stop_reason_id, av_events::StopReason::Stop.id());
        assert_eq!(receipt.body.cost.completion_tokens, 3);
        assert_eq!(receipt.body.cost.cached_tokens, 4);
        assert_eq!(receipt.body.cost.cost_usd_micros, 1_250);
        assert_eq!(
            receipt.body.cost.prompt_tokens,
            av_core::tokens::approx_tokens(&chat_payload().to_string()),
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
                    .header("x-av-session", "mcp-flow")
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
        // Round-6 (hunt4 protocol F4): the ack is a conformant JSON-RPC
        // response now — id echoed, result envelope present.
        assert_eq!(allowed_body["jsonrpc"], "2.0");
        assert_eq!(allowed_body["id"], 1);
        assert!(allowed_body["result"]["decision_us"].as_u64().unwrap() < 5_000);

        let blocked = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/mcp")
                    .header("x-av-session", "mcp-flow")
                    .body(Body::from("not-json"))
                    .unwrap(),
            )
            .await
            .unwrap();
        // Round-6 (hunt4 protocol F5): invalid JSON is a protocol
        // failure (-32700 / HTTP 400), not a policy decision (403).
        assert_eq!(blocked.status(), StatusCode::BAD_REQUEST);
        let blocked_body: Value = serde_json::from_slice(
            &axum::body::to_bytes(blocked.into_body(), 64 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(blocked_body["error"]["code"], -32700);

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
        assert!(metrics.contains("av_stage_duration_seconds") || metrics.contains("av_sessions"));

        let aborted = app.clone().oneshot(chat_request("abort-flow")).await.unwrap();
        drop(aborted);
        // Round-51 §6.4: a client abort AFTER content was captured (the
        // SSE peek already consumed the first frame) must NOT force-close
        // the conversation — the turn is recorded and the session stays
        // open for the client's next request; the idle sweeper owns
        // eventual finalization. Only a nothing-captured one-shot abort
        // spawns the background close.
        let session = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if let Some(session) = state.sessions.get("abort-flow") {
                    if session.active_streams_count() == 0 {
                        break session;
                    }
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("abort stream never drained");
        assert!(
            !session.is_closed(),
            "an abort after captured content must leave the conversation open"
        );
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
            .header("x-av-session", "stream-close-race")
            .header("x-av-workflow", "signed")
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

        let identity = av_events::AgentIdentity {
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
            tokio::spawn(async { Ok::<_, String>(av_state::BudgetDecision::Allowed { remaining: 100 }) });

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
            response_metrics: av_events::EventMetrics::default(),
            charged_completion_tokens: 3,
            last_reported_completion_tokens: Some(3),
            last_reported_prompt_tokens: None,
            last_reported_cached_tokens: None,
            last_reported_cost_usd_micros: None,
            saw_chunk: true,
            capture_attempted: false,
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
                        .header("x-av-session", "tool-once")
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
                    .header("x-av-session", "tool-once")
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
                    .header("x-av-session", "tool-once")
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
                .header("x-av-session", "auth-wire");
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
            .header("x-av-session", "auth-wire")
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
                    .header("x-av-session", "tool-auth")
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
        headers.insert("x-av-session", HeaderValue::from_static("tool-recovery"));
        let body = br#"{"jsonrpc":"2.0","id":"recover","method":"tools/call","params":{"name":"read","arguments":{}}}"#;
        let mut execution =
            ToolExecution::from_request(&directory.path().to_string_lossy(), &headers, body, control_key)
                .unwrap();
        execution
            .bind_principal(&av_events::AgentIdentity {
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
                    .header("x-av-session", "tool-redirect")
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
                .header("x-av-session", "claim-race")
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
                        .header("x-av-session", "held-tool")
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
    #[allow(clippy::cast_possible_truncation)] // xorshift indices; truncation is harmless fuzz entropy
    fn fuzz_parse_provider_chunk_is_total() {
        // Randomized totality check (hand-rolled xorshift so no
        // new dev-dependency): mutations of valid frames plus raw garbage
        // must never panic the parser, only return Ok/Err.
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let seeds: Vec<&str> = vec![
            "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}],\"usage\":null}\n\n",
            "data: {\"model\":\"m\",\"choices\":[{\"delta\":{\"content\":\"a\",\"reasoning_content\":\"r\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":3,\"cost_usd\":0.001,\"prompt_tokens_details\":{\"cached_tokens\":4}}}\n\n",
            "data: {\"choices\":[{\"index\":1,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c\",\"function\":{\"name\":\"f\",\"arguments\":\"{}\"}}]}}]}\n\n",
            "data: [DONE]\n\n",
            "event: message\ndata: {\"choices\":[]}\n\n",
            "{\"choices\":[{\"message\":{\"content\":\"x\",\"tool_calls\":[{\"id\":\"a\",\"function\":{\"name\":\"n\",\"arguments\":\"{}\"}}]}}],\"usage\":{\"completion_tokens\":1}}",
        ];
        for _ in 0..200_000 {
            let seed = seeds[(next() as usize) % seeds.len()];
            let mut bytes = seed.as_bytes().to_vec();
            for _ in 0..=(next() % 8) {
                match next() % 3 {
                    0 if !bytes.is_empty() => {
                        let idx = (next() as usize) % bytes.len();
                        bytes[idx] = (next() & 0xFF) as u8;
                    }
                    1 if !bytes.is_empty() => {
                        let idx = (next() as usize) % bytes.len();
                        bytes.truncate(idx);
                    }
                    _ => {
                        let idx = if bytes.is_empty() {
                            0
                        } else {
                            (next() as usize) % bytes.len()
                        };
                        bytes.insert(idx, (next() & 0xFF) as u8);
                    }
                }
            }
            let raw = String::from_utf8_lossy(&bytes).into_owned();
            let _ = parse_provider_chunk(&raw);
            let _ = sse_frame_end(&bytes);
        }
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
    fn null_usage_chunks_are_not_reported_usage() {
        // OpenAI `stream_options: {"include_usage": true}` emits
        // `"usage": null` on every content chunk; only the final chunk
        // carries the real object. A null usage must behave exactly like
        // an absent key: usage_reported = false, completion tokens
        // estimated. Treating it as reported previously fed absorb_frame's
        // cumulative branch per-chunk estimates → spurious "usage
        // regressed" stream kill + session quarantine.
        let raw = r#"data: {"choices":[{"delta":{"content":"Hello"}}],"usage":null}"#;
        let parsed = parse_provider_chunk(raw).unwrap().unwrap();
        assert!(!parsed.usage_reported, "null usage must not count as reported");
        assert!(!parsed.completion_reported);
        assert_eq!(parsed.message, "Hello");
        // Estimated from the delta text, not taken from the null object.
        assert_eq!(
            parsed.metrics.completion_tokens,
            Some(av_core::tokens::approx_tokens("Hello"))
        );
        // Null fields inside a real usage object are tolerated like
        // absent keys (some OpenAI-compatible shims emit them).
        let raw = r#"data: {"choices":[{"delta":{"content":"x"}}],"usage":{"prompt_tokens":7,"completion_tokens":null}}"#;
        let parsed = parse_provider_chunk(raw).unwrap().unwrap();
        assert!(parsed.usage_reported);
        assert!(
            !parsed.completion_reported,
            "a null completion count must not drive cumulative-usage math"
        );
        assert_eq!(parsed.metrics.prompt_tokens, Some(7));
        assert_eq!(
            parsed.metrics.completion_tokens,
            Some(av_core::tokens::approx_tokens("x"))
        );
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
    /// listener. AgentVisor AI attributes captured `data:` payloads to
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

    /// Engineering-review §6.2 (D7): a named SSE event with EMPTY
    /// `data:` (or no `data:` at all) is a keepalive/heartbeat that
    /// carries no audit surface — refusing it (and thereby aborting
    /// the whole client stream + sealing the session) was
    /// over-restrictive. Such frames must be treated as skip
    /// (returning `Ok(None)`), leaving the full-refusal semantics
    /// intact for frames whose `data:` field would otherwise be
    /// attributed to the model output under the wrong event name.
    #[test]
    fn parse_provider_chunk_treats_dataless_named_events_as_keepalives() {
        for raw in [
            "event: ping\n\n",
            "event: heartbeat\n\n",
            "event: keep-alive\ndata:\n\n",
            "event: status\ndata:   \n\n",
        ] {
            match parse_provider_chunk(raw) {
                Ok(None) => {}
                Ok(Some(_)) => panic!("dataless named event must not yield a chunk: {raw:?}"),
                Err(error) => panic!("dataless named event {raw:?} must not fail the stream (D7): {error}"),
            }
        }
        // A named event that DOES carry attributable data must still
        // be refused — the security posture the original guard exists
        // for is preserved.
        let poison = "event: error\ndata: {\"choices\":[{\"delta\":{\"content\":\"x\"}}]}\n\n";
        assert!(
            parse_provider_chunk(poison).is_err(),
            "named event with non-empty data must still be refused"
        );
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
        let trajectory: av_atif::Trajectory = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
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
        {
            // Round-51 §9.3: OpenAI-shaped error object — SDK
            // `e.code` / `e.type` dispatch must have material.
            let parsed = serde_json::from_slice::<Value>(&body).unwrap();
            assert!(parsed["error"]["message"].is_string(), "{parsed}");
            assert!(parsed["error"]["type"].is_string(), "{parsed}");
            assert!(parsed["error"]["code"].is_number(), "{parsed}");
        }
        let session = state.sessions.get("malformed-json").unwrap();
        // Round-51 §6.2: the malformed frame is scoped to THIS
        // response — recorded as a failed capture — instead of
        // sealing the whole session. The session must stay usable
        // for the client's next turn.
        assert!(
            !session.capture_failed(),
            "a single malformed provider frame must not brick the session"
        );
        provider.abort();
    }

    /// Refusing an unsupported Content-Encoding must retire the durable
    /// in-flight response marker and terminally fail the journalled
    /// response attempt — otherwise `recover_spooled_sessions`
    /// quarantines the session forever over a request the client
    /// already saw fail as a clean 502.
    #[tokio::test]
    async fn unsupported_content_encoding_refusal_retires_marker_and_attempt() {
        let directory = tempfile::tempdir().unwrap();
        let (state, provider) = test_state(directory.path()).await;
        let response = build_router(state.clone())
            .oneshot(chat_request_with_payload(
                "gzip-encoded",
                json!({
                    "model": "gzip-encoded",
                    "stream": false,
                    "messages": [{"role": "user", "content": "hello"}]
                }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        let error = serde_json::from_slice::<Value>(&body).unwrap()["error"]["message"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(error.contains("Content-Encoding"), "unexpected error: {error}");
        let session = state.sessions.get("gzip-encoded").unwrap();
        session.wait_for_worker_jobs().await;
        crate::worker::ensure_no_inflight_responses(directory.path(), &state.journal_key)
            .await
            .expect("refusal must retire the in-flight response marker");
        let records = active_records(directory.path(), &state, "gzip-encoded");
        assert!(
            records
                .iter()
                .filter_map(|record| record.response_attempt.as_ref())
                .any(|attempt| attempt.terminal),
            "refusal must journal a terminal response attempt"
        );
        let event: av_events::OcsfEvent =
            serde_json::from_value(records.last().unwrap().event.clone()).unwrap();
        assert_eq!(event.class_name, av_events::EventClass::StopReason);
        assert_eq!(event.status_id, av_events::StatusId::Failure.id());
        assert_eq!(event.payload["reason"], "upstream_unsupported_content_encoding");
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
            let event: av_events::OcsfEvent =
                serde_json::from_value(records.last().unwrap().event.clone()).unwrap();
            assert_eq!(event.class_name, av_events::EventClass::StopReason);
            assert_eq!(event.status_id, av_events::StatusId::Failure.id());
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
        // Round-51 §6.2: the regressive-usage frame fails THIS
        // response's capture (recorded with a failure reason via
        // submit_response_capture) — it must not seal the session.
        assert!(
            !session.capture_failed(),
            "a regressive usage frame must be scoped to the response, not the session"
        );
        session.wait_for_worker_jobs().await;
        let records = active_records(directory.path(), &state, "regressive-usage");
        // Two records: the request capture and the terminally-failed
        // response capture — the failure record IS the audit trail
        // entry for this turn.
        assert_eq!(records.len(), 2);
        assert!(records.iter().any(|record| record.response_attempt.is_some()));
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
        {
            // Round-51 §9.3: OpenAI-shaped error object — SDK
            // `e.code` / `e.type` dispatch must have material.
            let parsed = serde_json::from_slice::<Value>(&body).unwrap();
            assert!(parsed["error"]["message"].is_string(), "{parsed}");
            assert!(parsed["error"]["type"].is_string(), "{parsed}");
            assert!(parsed["error"]["code"].is_number(), "{parsed}");
        }
        // Round-51 §6.2: choices-less success is a per-response
        // capture failure, not a session seal.
        assert!(
            !state.sessions.get("empty-success").unwrap().capture_failed(),
            "a choices-less response must not brick the session"
        );
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
        let prompt_tokens = av_core::tokens::approx_tokens(&payload.to_string());
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
        // The capture failure hits the FIRST frame, before any byte was
        // relayed — the peek-before-commit path now surfaces it as a
        // clean upstream error response instead of a severed body
        // (which SDKs treated as a retryable network error).
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert!(axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .is_ok());
        // Round-51 §6.2: an out-of-range tool-call index fails the
        // response capture (surfaced as the clean 502 above via the
        // peek-before-commit path) but leaves the session usable.
        assert!(
            !state.sessions.get("tool-oob-index").unwrap().capture_failed(),
            "an out-of-range tool-call index must be scoped to the response"
        );
        provider.abort();
    }

    /// Round-51 §10.2: no SSE mock ever split a frame across a stream
    /// chunk, though `protocol_buffer` exists precisely to reassemble
    /// one. Split a frame mid-way through a multi-byte UTF-8 scalar
    /// and prove the reassembled message reaches the audit trail
    /// intact (the non-SSE equivalent lives at `split-json`).
    #[tokio::test]
    async fn sse_frame_split_across_chunks_reassembles_before_capture() {
        let directory = tempfile::tempdir().unwrap();
        let (state, provider) = test_state(directory.path()).await;
        let response = build_router(state.clone())
            .oneshot(chat_request_with_payload(
                "split-sse",
                json!({
                    "model": "split-sse",
                    "stream": true,
                    "messages": [{"role": "user", "content": "hello"}]
                }),
            ))
            .await
            .unwrap();
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        // The client sees the full reassembled bytes.
        assert!(
            String::from_utf8_lossy(&body).contains("héllo"),
            "client bytes truncated"
        );
        let session = state.sessions.get("split-sse").unwrap();
        session.wait_for_worker_jobs().await;
        assert!(
            !session.capture_failed(),
            "a chunk-split frame must not fail capture"
        );
        let crate::reconciler::FinalizeOutcome::Atif { path } = state
            .finalizer
            .close_session(session, StopReason::SessionClosed)
            .await
            .unwrap()
        else {
            panic!("expected ATIF")
        };
        let trajectory: av_atif::Trajectory = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(
            trajectory.steps[1].message,
            Value::String("héllo".to_owned()),
            "the audit trail must carry the reassembled multi-byte content"
        );
        provider.abort();
    }

    /// Engineering-review §6.4 (round-51): an SSE stream that ends
    /// cleanly but never carries a finish_reason chunk (provider
    /// crash, LB idle-timeout, worker OOM) is a TRUNCATED generation
    /// and must not be attested as a complete success — previously it
    /// recorded StatusId::Success with no stop reason, so a
    /// compliance reviewer could not distinguish a truncated
    /// response from a finished one.
    #[tokio::test]
    async fn truncated_stream_is_not_attested_as_a_complete_success() {
        let directory = tempfile::tempdir().unwrap();
        let (state, provider) = test_state(directory.path()).await;
        let response = build_router(state.clone())
            .oneshot(chat_request_with_payload(
                "truncated-stream",
                json!({
                    "model": "truncated-stream",
                    "stream": true,
                    "messages": [{"role": "user", "content": "hello"}]
                }),
            ))
            .await
            .unwrap();
        // The client still receives the partial bytes — truncation is
        // an audit classification, not a client-facing refusal.
        assert!(axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .is_ok());
        let session = state.sessions.get("truncated-stream").unwrap();
        session.wait_for_worker_jobs().await;
        let records = active_records(directory.path(), &state, "truncated-stream");
        let truncated = records.iter().any(|record| {
            record
                .event
                .get("payload")
                .is_some_and(|payload| payload.get("truncated").and_then(Value::as_bool) == Some(true))
        });
        assert!(
            truncated,
            "a finish_reason-less SSE end must be journalled with a truncated marker; records: {:?}",
            records
                .iter()
                .map(|r| r.event.get("payload").cloned())
                .collect::<Vec<_>>()
        );
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
        let prompt_tokens = av_core::tokens::approx_tokens(&payload.to_string());
        let (state, provider) = test_state_with_token_cap(directory.path(), Some(prompt_tokens)).await;
        let response = build_router(state)
            .oneshot(chat_request_with_payload("tool-no-usage", payload))
            .await
            .unwrap();
        // The budget refusal fires on the FIRST frame; peek-before-commit
        // surfaces it as the deliberate 403 (not-429) refusal instead of
        // a severed stream.
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .is_ok());
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
        let prompt_tokens = av_core::tokens::approx_tokens(&chat_payload().to_string());
        let (state, provider) = test_state_with_token_cap(directory.path(), Some(prompt_tokens)).await;
        let app = build_router(state.clone());
        let response = app.oneshot(chat_request("completion-budget")).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        // The completion-side budget refusal severs the body mid-stream.
        assert!(axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .is_err());
        // Round-51 §6.4: a budget-refused turn is recorded as a failed
        // response capture but must NOT seal or force-close the
        // session — per-minute windows refill, and the client's next
        // turn under the same id must be admissible. The idle sweeper
        // owns eventual finalization.
        let session = state.sessions.get("completion-budget").unwrap();
        session.wait_for_streams().await;
        assert!(
            !session.capture_failed(),
            "budget refusal must be scoped to the response, not the session"
        );
        assert!(
            !session.is_closed(),
            "budget refusal must not force-close the conversation"
        );
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
        // Round-16 F1: also include every well-known API-key header
        // name and both directions of the configured upstream_auth_header
        // check. `authorization` is the runtime default.
        let dangerous = [
            "set-cookie",
            "access-control-allow-origin",
            "access-control-allow-credentials",
            "access-control-allow-methods",
            "access-control-allow-headers",
            "access-control-expose-headers",
            "access-control-max-age",
            "connection",
            "keep-alive",
            "transfer-encoding",
            "upgrade",
            "te",
            "trailer",
            "proxy-authenticate",
            "proxy-authorization",
            "content-length",
            "server",
            "via",
            "x-powered-by",
            "x-request-id",
            // Round-16 F1: provider API-key headers must never echo
            // back from an upstream — they carry the operator's
            // outbound credential.
            "authorization",
            "api-key",
            "x-api-key",
            "x-goog-api-key",
            "anthropic-api-key",
            "openai-api-key",
            "x-auth-token",
            "x-amz-security-token",
        ];
        for name in dangerous {
            let header = HeaderName::from_static(name);
            assert!(
                !is_forwardable_upstream_header(&header, "authorization"),
                "dangerous header {name:?} must not be forwarded to the client"
            );
        }

        // Round-16 F1: the currently-configured upstream_auth_header
        // MUST be refused even for operator-picked odd names. Simulate
        // an operator using an exotic header (e.g. `x-my-secret`).
        let exotic = HeaderName::from_static("x-my-secret");
        assert!(
            !is_forwardable_upstream_header(&exotic, "x-my-secret"),
            "operator-configured upstream_auth_header must be refused",
        );

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
                is_forwardable_upstream_header(&header, "authorization"),
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
                    .header("x-av-session", "mcp-cwe-209-check")
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
        assert!(is_sse_content_type(&ct("Text/Event-Stream ; charset=utf-8")));
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

    /// `/livez` and `/readyz` are the Kubernetes-style split of the
    /// legacy `/health` constant. Liveness stays a constant; readiness
    /// couples to the draining flag and to a spool-directory
    /// readability check so a full or missing spool volume immediately
    /// steers new traffic elsewhere. See engineering review §8.3.
    #[tokio::test]
    async fn livez_and_readyz_reflect_service_readiness() {
        let scratch = tempfile::tempdir().unwrap();
        let spool = scratch.path().join("spool");
        std::fs::create_dir_all(&spool).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let provider = Router::new().route("/v1/chat/completions", post(mock_chat));
        let _server = tokio::spawn(async move {
            axum::serve(listener, provider).await.unwrap();
        });
        let config = crate::config::HarnessConfig::for_tests(
            &format!("http://{address}"),
            &spool.to_string_lossy(),
            &spool.to_string_lossy(),
        );
        let state = AppState::new(
            config,
            Arc::new(InMemoryStore::new()),
            Arc::new(Sandbox::new(SandboxConfig::default(), Vec::new()).unwrap()),
            Arc::new(NullBus),
            None,
            Arc::new(Ed25519Signer::from_seed(&[19; 32])),
        )
        .unwrap();
        let app = crate::build_router(state.clone());

        // /livez must always respond 200 with a constant body — it is
        // decoupled from backend health by design.
        let live = app
            .clone()
            .oneshot(Request::builder().uri("/livez").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(live.status(), StatusCode::OK);

        // /readyz on a healthy pod: spool exists, not draining → 200.
        let ready = app
            .clone()
            .oneshot(Request::builder().uri("/readyz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(ready.status(), StatusCode::OK);

        // Draining flag flipped: /readyz must return 503 immediately.
        state.draining.store(true, std::sync::atomic::Ordering::SeqCst);
        let not_ready = app
            .clone()
            .oneshot(Request::builder().uri("/readyz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(not_ready.status(), StatusCode::SERVICE_UNAVAILABLE);

        // /livez remains 200 while draining — restart-cascade guard.
        let still_live = app
            .clone()
            .oneshot(Request::builder().uri("/livez").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(still_live.status(), StatusCode::OK);
    }

    /// Round-51 W2: `/metrics` scrape must emit both a live
    /// `av_open_sessions` gauge (sampled at scrape time from the
    /// registry) and a labelled `av_signing_key_info` gauge whose
    /// value is 1 whenever the process holds the signer.
    #[tokio::test]
    async fn metrics_scrape_emits_open_sessions_gauge_and_signing_key_info() {
        let scratch = tempfile::tempdir().unwrap();
        let spool = scratch.path().join("spool");
        std::fs::create_dir_all(&spool).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let provider = Router::new().route("/v1/chat/completions", post(mock_chat));
        let _server = tokio::spawn(async move {
            axum::serve(listener, provider).await.unwrap();
        });
        let config = crate::config::HarnessConfig::for_tests(
            &format!("http://{address}"),
            &spool.to_string_lossy(),
            &spool.to_string_lossy(),
        );
        let signer = Ed25519Signer::from_seed(&[31; 32]);
        use av_receipts::Signer as _;
        let key_id = signer.key_id().to_owned();
        let public_key_hex = hex::encode(signer.public_key_bytes());
        let state = AppState::new(
            config,
            Arc::new(InMemoryStore::new()),
            Arc::new(Sandbox::new(SandboxConfig::default(), Vec::new()).unwrap()),
            Arc::new(NullBus),
            None,
            Arc::new(signer),
        )
        .unwrap();
        // Mirror main.rs's startup registration so the gauge is
        // reachable from the same route.
        state
            .metrics
            .gauge(
                &format!("av_signing_key_info{{key_id=\"{key_id}\",public_key_hex=\"{public_key_hex}\"}}"),
                "test signing key info",
            )
            .set(1);
        let app = crate::build_router(state.clone());

        // Scrape with an empty registry — gauge sample must be 0.
        let response = app
            .clone()
            .oneshot(Request::builder().uri("/metrics").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body = String::from_utf8_lossy(
            &axum::body::to_bytes(response.into_body(), 256 * 1024)
                .await
                .unwrap(),
        )
        .into_owned();
        assert!(body.contains("# TYPE av_open_sessions gauge"), "{body}");
        assert!(body.contains("av_open_sessions 0"), "{body}");
        // Round-51 §8.7: data-plane series must exist from boot.
        assert!(body.contains("# TYPE av_worker_queue_depth gauge"), "{body}");
        assert!(body.contains("# TYPE av_spool_bytes gauge"), "{body}");
        assert!(body.contains("# TYPE av_requests_total counter"), "{body}");
        assert!(
            body.contains("av_requests_total{route=\"chat\",status_class=\"2xx\"}"),
            "{body}"
        );
        assert!(
            body.contains("av_upstream_errors_total{kind=\"timeout\"}"),
            "{body}"
        );
        assert!(body.contains("av_upstream_latency_seconds"), "{body}");
        assert!(
            body.contains(&format!("av_signing_key_info{{key_id=\"{key_id}\"")),
            "signing-key info gauge missing from scrape: {body}"
        );

        // Register a session and scrape again — gauge must reflect 1.
        state.sessions.insert_recovered(crate::session::Session::new(
            "gauge-test".to_owned(),
            crate::session::Workflow::Unsigned,
            av_events::AgentIdentity {
                version: "1".to_owned(),
                charter: "test".into(),
                instance_uid: "instance-1".to_owned(),
                ttl_remaining_s: Some(600),
            },
            Default::default(),
        ));
        let response = app
            .clone()
            .oneshot(Request::builder().uri("/metrics").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body = String::from_utf8_lossy(
            &axum::body::to_bytes(response.into_body(), 256 * 1024)
                .await
                .unwrap(),
        )
        .into_owned();
        assert!(body.contains("av_open_sessions 1"), "{body}");
    }
}
