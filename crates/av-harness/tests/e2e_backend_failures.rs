//! End-to-end tests for production failure behavior: what the gateway does
//! when a backend fails after the handshake, when a request times out, when
//! the budget runs out, and what the operational probes report.
//!
//! The unit tests cover each classifier and each budget rule in isolation.
//! These tests drive the same rules through the live HTTP gateway so a
//! regression in the wiring — a refund skipped on one ledger, a timeout
//! remapped to the wrong status, a probe that leaks the build version — is
//! caught the way an operator would see it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use av_harness::config::{BackendAuth, BackendConfig, BackendTransport};
use av_state::BudgetSpec;
use axum::response::IntoResponse;
use serde_json::{json, Value};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

const HMAC_SECRET: &[u8] = b"test-hmac-secret-for-backend-failures";
const HMAC_KID: &str = "fail-kid";

/// The tool-response size cap enforced by both the plain transport and the
/// MCP client. One byte over this must be refused as an unreadable body.
const MAX_TOOL_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

type Request = axum::http::Request<axum::body::Body>;

// ── Helpers ─────────────────────────────────────────────────────

/// How a test backend answers `tools/call` after a successful handshake.
#[derive(Clone, Copy)]
enum CallBehavior {
    /// Reply with HTTP 500 and a distinctive body.
    Http500,
    /// Accept the request and never answer.
    Hang,
    /// Reply with a body one byte over the response size cap.
    Oversized,
    /// Reply with HTTP 200 and a JSON-RPC error object.
    JsonRpcError,
}

/// How a test chat upstream answers `/v1/chat/completions`.
#[derive(Clone, Copy)]
enum ChatBehavior {
    /// Reply with HTTP 500.
    Http500,
    /// Accept the request and never answer.
    Hang,
}

fn gateway(
    backends: Vec<BackendConfig>,
    upstream: Option<&str>,
    tweak: impl FnOnce(&mut av_harness::HarnessConfig),
) -> Arc<av_harness::AppState> {
    let mut config = common::leaked_test_config();
    if let Some(url) = upstream {
        config.upstream_url = url.to_owned();
    }
    config.backends = backends;
    tweak(&mut config);
    let sandbox = common::sandbox_for(&config);
    common::app_state(
        config,
        sandbox,
        Arc::new(common::CountingBus::default()),
        7,
    )
}

fn gateway_with_identity(
    backends: Vec<BackendConfig>,
    tweak: impl FnOnce(&mut av_harness::HarnessConfig),
) -> Arc<av_harness::AppState> {
    let mut config = common::leaked_test_config();
    config.require_identity = true;
    config.backends = backends;
    tweak(&mut config);
    let sandbox = common::sandbox_for(&config);
    common::app_state_with_identity(
        config,
        sandbox,
        Arc::new(common::CountingBus::default()),
        7,
        HMAC_SECRET,
        HMAC_KID,
    )
}

fn backend(name: &str, url: &str, tools: &[&str]) -> BackendConfig {
    BackendConfig {
        name: name.into(),
        url: url.into(),
        auth: BackendAuth::None,
        tools: tools.iter().map(|tool| (*tool).to_owned()).collect(),
        transport: BackendTransport::Mcp,
    }
}

fn token(state: &av_harness::AppState, sub: &str, scopes: &[&str], jti: &str) -> String {
    common::mint_nhi_token(
        HMAC_SECRET,
        HMAC_KID,
        &state.config.audience,
        &common::NhiSpec {
            sub,
            instance_uid: "inst-fail",
            scopes,
            jti,
        },
    )
}

fn tool_call(session: &str, bearer: Option<&str>, tool: &str, id: u64) -> Request {
    let body = serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {"name": tool, "arguments": {"query": "q"}}
    }))
    .unwrap();
    let mut builder = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/mcp")
        .header("content-type", "application/json")
        .header("x-av-session", session);
    if let Some(bearer) = bearer {
        builder = builder.header("authorization", format!("Bearer {bearer}"));
    }
    builder.body(axum::body::Body::from(body)).unwrap()
}

fn chat_request(session: &str, payload: Value) -> Request {
    let body = serde_json::to_vec(&payload).unwrap();
    axum::http::Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header("content-type", "application/json")
        .header("x-av-session", session)
        .body(axum::body::Body::from(body))
        .unwrap()
}

fn get(uri: &str) -> Request {
    axum::http::Request::builder()
        .method("GET")
        .uri(uri)
        .body(axum::body::Body::empty())
        .unwrap()
}

struct Reply {
    status: axum::http::StatusCode,
    headers: axum::http::HeaderMap,
    body: Vec<u8>,
}

impl Reply {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }
}

async fn send(state: &Arc<av_harness::AppState>, request: Request) -> Reply {
    let router = av_harness::build_router((**state).clone());
    let response = tower::ServiceExt::oneshot(router, request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = axum::body::to_bytes(response.into_body(), 1 << 22).await.unwrap();
    Reply {
        status,
        headers,
        body: body.to_vec(),
    }
}

/// Parse a single `name{labels} value` line out of a Prometheus scrape.
fn metric_value(scrape: &str, prefix: &str) -> Option<f64> {
    scrape.lines().find_map(|line| {
        let line = line.trim();
        if line.starts_with('#') || !line.starts_with(prefix) {
            return None;
        }
        let rest = line.get(prefix.len()..)?;
        let rest = rest.trim_start();
        // Skip past any `{...}` label block.
        let rest = if let Some(stripped) = rest.strip_prefix('{') {
            let end = stripped.find('}')?;
            stripped.get(end + 1..)?.trim_start()
        } else {
            rest
        };
        rest.parse::<f64>().ok()
    })
}

/// Bind an ephemeral port and immediately release it, so the port is free
/// and nothing is listening. A connect to this URL is refused.
fn closed_port_url() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    format!("http://{addr}/mcp")
}

/// An MCP backend that completes the handshake and then answers `tools/call`
/// according to `behavior`.
async fn backend_with_call_behavior(behavior: CallBehavior) -> String {
    let app = axum::Router::new().fallback(
        move |body: axum::body::Bytes| async move {
            let request: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
            let id = request.get("id").cloned().unwrap_or(Value::Null);
            let method = request.get("method").and_then(Value::as_str).unwrap_or_default();
            if request.get("id").is_none() && method.starts_with("notifications/") {
                return axum::http::StatusCode::ACCEPTED.into_response();
            }
            match method {
                "initialize" => {
                    let mut response = axum::Json(json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "protocolVersion": "2025-11-25",
                            "capabilities": {"tools": {}},
                            "serverInfo": {"name": "failing-backend", "version": "1"}
                        }
                    }))
                    .into_response();
                    response.headers_mut().insert(
                        "mcp-session-id",
                        axum::http::HeaderValue::from_static("failing-backend-session"),
                    );
                    response
                }
                "tools/list" => axum::Json(json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {"tools": []}
                }))
                .into_response(),
                _ => match behavior {
                    CallBehavior::Http500 => (
                        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                        "backend exploded after handshake",
                    )
                        .into_response(),
                    CallBehavior::Hang => {
                        tokio::time::sleep(Duration::from_secs(60)).await;
                        axum::http::StatusCode::OK.into_response()
                    }
                    CallBehavior::Oversized => {
                        let huge = vec![b'x'; MAX_TOOL_RESPONSE_BYTES + 1];
                        (
                            axum::http::StatusCode::OK,
                            [(axum::http::header::CONTENT_TYPE, "text/plain")],
                            huge,
                        )
                            .into_response()
                    }
                    CallBehavior::JsonRpcError => axum::Json(json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {"code": -32000, "message": "tool failed inside the backend"}
                    }))
                    .into_response(),
                },
            }
        },
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/mcp", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    url
}

/// A chat upstream that answers `/v1/chat/completions` according to
/// `behavior`.
async fn chat_upstream(behavior: ChatBehavior) -> String {
    let app = axum::Router::new().fallback(move || async move {
        match behavior {
            ChatBehavior::Http500 => (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "chat backend exploded",
            )
                .into_response(),
            ChatBehavior::Hang => {
                tokio::time::sleep(Duration::from_secs(60)).await;
                axum::http::StatusCode::OK.into_response()
            }
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    url
}

fn single_call_budget() -> BudgetSpec {
    BudgetSpec {
        max_total_tool_calls: Some(1),
        ..BudgetSpec::default()
    }
}

// ── Backend failure after a successful handshake ────────────────

#[tokio::test]
async fn a_tool_backend_that_fails_after_the_handshake_relays_the_error_and_keeps_the_claim() {
    let url = backend_with_call_behavior(CallBehavior::Http500).await;
    let state = gateway(
        vec![backend("svc", &url, &["lookup"])],
        None,
        |config| {
            // One call total. A refund would let a second call through;
            // keeping the debit must refuse it.
            config.budget.max_total_tool_calls = Some(1);
        },
    );

    let first = send(&state, tool_call("sess-500", None, "lookup", 1)).await;
    assert_eq!(first.status, 500, "{}", first.text());
    assert!(
        first.text().contains("backend exploded after handshake"),
        "the upstream body must be relayed, not replaced: {}",
        first.text()
    );

    // The same execution key replays the journaled outcome. A duplicate
    // must not be treated as an uncertain pending call.
    let replay = send(&state, tool_call("sess-500", None, "lookup", 1)).await;
    assert_eq!(replay.status, 500, "{}", replay.text());
    assert!(
        replay.text().contains("backend exploded after handshake"),
        "a retry of the same id must replay the same outcome: {}",
        replay.text()
    );

    // The first call kept its debit, so a fresh execution is over budget.
    let fresh = send(&state, tool_call("sess-500", None, "lookup", 2)).await;
    assert_eq!(fresh.status, 403, "{}", fresh.json());
    assert_eq!(
        fresh.json()["error"]["data"]["code"], "BUDGET_EXCEEDED",
        "a backend failure that is not a connect error must not refund: {}",
        fresh.json()
    );
}

#[tokio::test]
async fn a_json_rpc_error_after_the_handshake_is_relayed_like_any_other_answer() {
    let url = backend_with_call_behavior(CallBehavior::JsonRpcError).await;
    let state = gateway(
        vec![backend("svc", &url, &["lookup"])],
        None,
        |config| {
            config.budget.max_total_tool_calls = Some(1);
        },
    );

    let reply = send(&state, tool_call("sess-jrpc", None, "lookup", 1)).await;
    // A JSON-RPC error object is a valid answer. The gateway relays it
    // with the upstream status rather than inventing a new one.
    assert_eq!(reply.status, 200, "{}", reply.text());
    assert_eq!(
        reply.json()["error"]["message"], "tool failed inside the backend",
        "the JSON-RPC error must be relayed unchanged: {}",
        reply.json()
    );

    let fresh = send(&state, tool_call("sess-jrpc", None, "lookup", 2)).await;
    assert_eq!(fresh.status, 403, "{}", fresh.json());
    assert_eq!(fresh.json()["error"]["data"]["code"], "BUDGET_EXCEEDED");
}

// ── Timeout keeps the debit ─────────────────────────────────────

#[tokio::test]
async fn a_tool_timeout_is_502_and_keeps_the_budget_debit() {
    let url = backend_with_call_behavior(CallBehavior::Hang).await;
    let state = gateway(
        vec![backend("svc", &url, &["lookup"])],
        None,
        |config| {
            config.budget.max_total_tool_calls = Some(1);
            config.mcp_request_timeout_s = Some(1);
        },
    );

    // The tool path maps every send failure that is not a connect error
    // to 502, not 504. Only the chat path distinguishes timeout with
    // `PipelineError::upstream_timeout`. The timeout is recorded as an
    // unreadable answer because the backend may have executed the tool
    // before the deadline fired.
    let first = send(&state, tool_call("sess-timeout", None, "lookup", 1)).await;
    assert_eq!(first.status, 502, "{}", first.text());
    assert!(
        first.text().contains("tool executed but its response could not be read"),
        "a tool timeout is journaled as an unreadable answer: {}",
        first.text()
    );
    assert!(
        first.text().contains("upstream timed out"),
        "a timeout must use the stable category string, not the raw error: {}",
        first.text()
    );
    assert!(
        !first.text().contains(&url),
        "the upstream URL must not leak into the client body: {}",
        first.text()
    );

    // A timeout means the request may have reached the provider. The
    // debit stays, so a second execution is refused rather than retried
    // for free.
    let second = send(&state, tool_call("sess-timeout", None, "lookup", 2)).await;
    assert_eq!(second.status, 403, "{}", second.json());
    assert_eq!(
        second.json()["error"]["data"]["code"], "BUDGET_EXCEEDED",
        "a timeout must keep the debit: {}",
        second.json()
    );
}

#[tokio::test]
async fn a_chat_timeout_is_504_and_keeps_the_token_debit() {
    let url = chat_upstream(ChatBehavior::Hang).await;
    let payload = common::chat("hi");
    let cost = av_core::tokens::approx_tokens_json(&payload);
    let state = gateway(Vec::new(), Some(&url), |config| {
        // Charge the exact size of this payload so the first call is
        // admitted and the second is over the cap.
        config.compression_enabled = false;
        config.budget.max_tokens = Some(cost);
        config.upstream_read_timeout_s = Some(1);
    });

    let first = send(&state, chat_request("sess-chat-timeout", payload.clone())).await;
    assert_eq!(first.status, 504, "{}", first.text());
    assert!(
        first.text().contains("upstream timed out"),
        "a chat timeout must use the stable category string: {}",
        first.text()
    );
    assert_eq!(
        first
            .headers
            .get("retry-after")
            .and_then(|value| value.to_str().ok()),
        Some("5"),
        "a retryable 504 must carry Retry-After"
    );

    let second = send(&state, chat_request("sess-chat-timeout", payload)).await;
    assert_eq!(second.status, 403, "{}", second.json());
    assert_eq!(second.json()["error"]["type"], "permission_error");
    assert!(
        second.text().contains(&format!("max_tokens exceeded (cap {cost})")),
        "the token debit must survive a timeout: {}",
        second.text()
    );
}

// ── Connection refused refunds the debit ────────────────────────

#[tokio::test]
async fn a_connection_refused_backend_refunds_the_debit_on_both_ledgers() {
    let dead = closed_port_url();
    let state = gateway_with_identity(
        vec![backend("dead", &dead, &["lookup"])],
        |config| {
            // Bind the session ledger and the principal ledger at one
            // call each. Two admitted attempts prove both were refunded:
            // if either ledger kept the charge, the second call would be
            // refused for budget.
            config.budget = single_call_budget();
            config.principal_budget = Some(single_call_budget());
        },
    );
    let bearer = token(&state, "user:ana@acme.io", &["tool:*"], "j-dead");

    let first = send(&state, tool_call("sess-dead", Some(&bearer), "lookup", 1)).await;
    assert_eq!(first.status, 502, "{}", first.text());
    assert!(
        first.text().contains("upstream unreachable"),
        "a refused connection must use the stable category string: {}",
        first.text()
    );
    assert!(
        !first.text().contains(&dead),
        "the upstream URL must not leak into the client body: {}",
        first.text()
    );
    assert_eq!(
        first
            .headers
            .get("retry-after")
            .and_then(|value| value.to_str().ok()),
        Some("5"),
        "a retryable 502 must carry Retry-After"
    );

    let second = send(&state, tool_call("sess-dead", Some(&bearer), "lookup", 2)).await;
    assert_eq!(
        second.status,
        502,
        "a refunded debit must admit the retry the same way: {}",
        second.text()
    );
    assert!(second.text().contains("upstream unreachable"));
}

// ── Oversized tool response ─────────────────────────────────────

#[tokio::test]
async fn an_oversized_tool_response_is_refused_without_leaking_the_upstream_url() {
    let url = backend_with_call_behavior(CallBehavior::Oversized).await;
    let state = gateway(
        vec![backend("svc", &url, &["lookup"])],
        None,
        |_| {},
    );

    let first = send(&state, tool_call("sess-huge", None, "lookup", 1)).await;
    assert_eq!(first.status, 502, "{}", first.text());
    assert!(
        first.text().contains("tool executed but its response could not be read"),
        "an unreadable body is a 502 with a stable message: {}",
        first.text()
    );
    assert!(
        !first.text().contains(&url),
        "the upstream URL must not leak into the client body: {}",
        first.text()
    );

    // The outcome was journaled as a 502, so the same execution key
    // replays that 502 instead of re-running the tool.
    let replay = send(&state, tool_call("sess-huge", None, "lookup", 1)).await;
    assert_eq!(replay.status, 502, "{}", replay.text());
    assert!(replay
        .text()
        .contains("tool executed but its response could not be read"));
}

// ── Upstream error mapping and metrics ──────────────────────────

#[tokio::test]
async fn a_chat_backend_that_returns_500_is_relayed_not_remapped() {
    let url = chat_upstream(ChatBehavior::Http500).await;
    let state = gateway(Vec::new(), Some(&url), |_| {});

    let reply = send(&state, chat_request("sess-chat-500", common::chat_payload())).await;
    assert_eq!(reply.status, 500, "{}", reply.text());
    assert!(
        reply.text().contains("chat backend exploded"),
        "a 5xx from the chat upstream must be relayed, not remapped: {}",
        reply.text()
    );

    let scrape = send(&state, get("/metrics")).await;
    assert_eq!(scrape.status, 200);
    let scrape = scrape.text();
    let upstream_5xx = metric_value(&scrape, "av_upstream_errors_total{kind=\"http_5xx\"}")
        .unwrap_or(0.0);
    assert!(
        upstream_5xx >= 1.0,
        "a relayed 5xx must bump the http_5xx counter:\n{scrape}"
    );
    let chat_5xx = metric_value(&scrape, "av_requests_total{route=\"chat\",status_class=\"5xx\"}")
        .unwrap_or(0.0);
    assert!(
        chat_5xx >= 1.0,
        "a 5xx chat answer must bump the chat 5xx counter:\n{scrape}"
    );
}

#[tokio::test]
async fn metrics_pre_registers_every_documented_series_on_a_fresh_boot() {
    let state = gateway(Vec::new(), None, |_| {});
    let scrape = send(&state, get("/metrics")).await;
    assert_eq!(scrape.status, 200);
    assert_eq!(
        scrape.headers.get("content-type").and_then(|value| value.to_str().ok()),
        Some("text/plain; version=0.0.4; charset=utf-8"),
    );
    let scrape = scrape.text();

    for kind in ["timeout", "connect", "send", "http_5xx"] {
        let key = format!("av_upstream_errors_total{{kind=\"{kind}\"}}");
        assert!(
            scrape.contains(&key),
            "a fresh boot must pre-register {key}:\n{scrape}"
        );
    }
    for route in ["chat", "mcp", "session_close", "session_promote"] {
        for class in ["2xx", "4xx", "5xx"] {
            let key = format!("av_requests_total{{route=\"{route}\",status_class=\"{class}\"}}");
            assert!(
                scrape.contains(&key),
                "a fresh boot must pre-register {key}:\n{scrape}"
            );
        }
    }
    assert!(
        scrape.contains("av_upstream_latency_seconds"),
        "a fresh boot must pre-register the upstream latency histogram:\n{scrape}"
    );
}

// ── Operational probes ──────────────────────────────────────────

#[tokio::test]
async fn health_and_metrics_do_not_disclose_the_build_version() {
    let state = gateway(Vec::new(), None, |_| {});

    let health = send(&state, get("/health")).await;
    assert_eq!(health.status, 200);
    assert_eq!(health.json()["status"], "ok");
    assert_eq!(health.json()["service"], "agentvisor");
    let health_body = health.text();
    assert!(
        !health_body.contains(env!("CARGO_PKG_VERSION")),
        "the unauthenticated health probe must not disclose the build version: {health_body}"
    );
    assert!(
        health.json().get("version").is_none(),
        "the health probe must not carry a version field: {health_body}"
    );

    let metrics = send(&state, get("/metrics")).await;
    assert_eq!(metrics.status, 200);
    let metrics_body = metrics.text();
    assert!(
        !metrics_body.contains(env!("CARGO_PKG_VERSION")),
        "the metrics scrape must not disclose the build version"
    );
}

#[tokio::test]
async fn livez_stays_alive_while_readyz_reports_a_missing_spool() {
    let mut config = common::leaked_test_config();
    // `AppState::new` does not create the spool directory. Pointing at a
    // path that does not exist is the outage shape this probe exists to
    // surface.
    config.atif_spool_dir = config.atif_spool_dir.clone() + "/missing-spool";
    let sandbox = common::sandbox_for(&config);
    let state = common::app_state(
        config,
        sandbox,
        Arc::new(common::CountingBus::default()),
        7,
    );

    let livez = send(&state, get("/livez")).await;
    assert_eq!(livez.status, 200, "{}", livez.text());
    assert_eq!(livez.json()["status"], "alive");

    let readyz = send(&state, get("/readyz")).await;
    assert_eq!(readyz.status, 503, "{}", readyz.json());
    assert_eq!(readyz.json()["status"], "not_ready");
    assert_eq!(readyz.json()["checks"]["spool_dir_writable"], false);
    assert_eq!(readyz.json()["checks"]["draining"], false);
}

#[tokio::test]
async fn livez_stays_alive_while_readyz_reports_draining() {
    let state = gateway(Vec::new(), None, |_| {});
    state.draining.store(true, Ordering::SeqCst);

    let livez = send(&state, get("/livez")).await;
    assert_eq!(livez.status, 200, "{}", livez.text());
    assert_eq!(livez.json()["status"], "alive");

    let readyz = send(&state, get("/readyz")).await;
    assert_eq!(readyz.status, 503, "{}", readyz.json());
    assert_eq!(readyz.json()["status"], "not_ready");
    assert_eq!(readyz.json()["checks"]["draining"], true);
}

#[tokio::test]
async fn readyz_reports_ready_on_a_writable_spool() {
    let state = gateway(Vec::new(), None, |_| {});
    let readyz = send(&state, get("/readyz")).await;
    assert_eq!(readyz.status, 200, "{}", readyz.json());
    assert_eq!(readyz.json()["status"], "ready");
    assert_eq!(readyz.json()["checks"]["spool_dir_writable"], true);
    assert_eq!(readyz.json()["checks"]["draining"], false);
    assert!(readyz.json()["checks"].get("revocation_available").is_some());
    assert!(readyz.json()["checks"].get("revocation_local_entries").is_some());
}

// ── Budget refusals ─────────────────────────────────────────────

#[tokio::test]
async fn a_chat_token_budget_refusal_is_an_openai_shaped_403() {
    let state = gateway(Vec::new(), None, |config| {
        config.compression_enabled = false;
        config.budget.max_tokens = Some(1);
    });

    let reply = send(&state, chat_request("sess-chat-budget", common::chat_payload())).await;
    assert_eq!(reply.status, 403, "{}", reply.json());
    assert_eq!(
        reply.json()["error"]["type"], "permission_error",
        "a budget refusal is a permission error: {}",
        reply.json()
    );
    assert_eq!(reply.json()["error"]["code"], 403);
    assert!(
        reply.text().contains("max_tokens exceeded (cap 1)"),
        "the refusal names the limit and the cap: {}",
        reply.json()
    );
}

#[tokio::test]
async fn a_tool_call_budget_refusal_is_a_json_rpc_budget_exceeded() {
    let upstream = common::MockBackend::start().await;
    let state = gateway(
        vec![backend("svc", &upstream.url, &["lookup"])],
        None,
        |config| {
            config.budget.max_total_tool_calls = Some(1);
        },
    );

    // The first call must actually spend the budget. A failure that
    // refunds would leave the second call admitted.
    let first = send(&state, tool_call("sess-tool-budget", None, "lookup", 1)).await;
    assert_eq!(first.status, 200, "{}", first.text());

    let second = send(&state, tool_call("sess-tool-budget", None, "lookup", 2)).await;
    assert_eq!(second.status, 403, "{}", second.json());
    assert_eq!(
        second.json()["error"]["data"]["code"], "BUDGET_EXCEEDED",
        "a tool budget refusal carries the stable denial code: {}",
        second.json()
    );
}