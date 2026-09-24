//! End-to-end tests for the gateway's MCP Streamable HTTP support: the
//! server role a stock MCP client talks to, and the client role the gateway
//! plays toward `transport = "mcp"` backends.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use av_harness::config::{BackendAuth, BackendConfig, BackendTransport, MissionConfig};
use axum::response::IntoResponse as _;
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

const HMAC_SECRET: &[u8] = b"test-hmac-secret-for-mcp-gateway-0123";
const HMAC_KID: &str = "mcp-kid";

type Request = axum::http::Request<axum::body::Body>;

struct Reply {
    status: axum::http::StatusCode,
    headers: axum::http::HeaderMap,
    json: Value,
}

async fn send(state: &Arc<av_harness::AppState>, request: Request) -> Reply {
    let router = av_harness::build_router((**state).clone());
    let response = tower::ServiceExt::oneshot(router, request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap();
    let json = serde_json::from_slice(&body).unwrap_or(Value::Null);
    Reply {
        status,
        headers,
        json,
    }
}

fn backend(name: &str, url: &str, auth: BackendAuth, tools: &[&str]) -> BackendConfig {
    BackendConfig {
        name: name.into(),
        url: url.into(),
        auth,
        tools: tools.iter().map(|tool| (*tool).to_owned()).collect(),
        transport: BackendTransport::Mcp,
    }
}

fn gateway(
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
        3,
        HMAC_SECRET,
        HMAC_KID,
    )
}

fn token(state: &av_harness::AppState, sub: &str, scopes: &[&str], jti: &str) -> String {
    common::mint_nhi_token(
        HMAC_SECRET,
        HMAC_KID,
        &state.config.audience,
        &common::NhiSpec {
            sub,
            instance_uid: "inst-mcp",
            scopes,
            jti,
        },
    )
}

fn post(uri: &str, bearer: &str, session: Option<&str>) -> axum::http::request::Builder {
    let mut builder = axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("authorization", format!("Bearer {bearer}"));
    if let Some(session) = session {
        builder = builder.header("mcp-session-id", session);
    }
    builder
}

fn rpc(uri: &str, bearer: &str, session: Option<&str>, body: Value) -> Request {
    post(uri, bearer, session)
        .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

fn initialize_body(version: &str) -> Value {
    json!({
        "jsonrpc": "2.0", "id": 0, "method": "initialize",
        "params": {"protocolVersion": version, "capabilities": {}, "clientInfo": {"name": "stock", "version": "1"}}
    })
}

async fn initialize(state: &Arc<av_harness::AppState>, uri: &str, bearer: &str) -> String {
    let reply = send(state, rpc(uri, bearer, None, initialize_body("2025-11-25"))).await;
    assert_eq!(reply.status, 200, "{}", reply.json);
    reply.headers["mcp-session-id"].to_str().unwrap().to_owned()
}

fn call(id: u64, tool: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": tool, "arguments": {"q": "x"}}})
}

fn names(reply: &Reply) -> Vec<String> {
    reply.json["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap().to_owned())
        .collect()
}

// ── Server role: lifecycle ────────────────────────────────────────

#[tokio::test]
async fn stock_client_handshake_negotiates_version_and_answers_ping_and_notifications() {
    let state = gateway(Vec::new(), |_| {});
    let bearer = token(&state, "user:ana@acme.io", &["tool:*"], "j-init");

    let reply = send(&state, rpc("/mcp", &bearer, None, initialize_body("2025-06-18"))).await;
    assert_eq!(reply.status, 200);
    assert_eq!(reply.json["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(
        reply.json["result"]["capabilities"]["tools"]["listChanged"],
        false
    );
    assert_eq!(reply.json["id"], 0);
    let session = reply.headers["mcp-session-id"].to_str().unwrap().to_owned();
    assert!(session.bytes().all(|b| (0x21..=0x7e).contains(&b)));

    let unknown = send(&state, rpc("/mcp", &bearer, None, initialize_body("1999-01-01"))).await;
    assert_eq!(
        unknown.json["result"]["protocolVersion"], "2025-11-25",
        "an unsupported request version gets the latest supported one"
    );

    let notified = send(
        &state,
        rpc(
            "/mcp",
            &bearer,
            Some(&session),
            json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        ),
    )
    .await;
    assert_eq!(notified.status, 202);

    let ping = send(
        &state,
        rpc(
            "/mcp",
            &bearer,
            Some(&session),
            json!({"jsonrpc": "2.0", "id": "p1", "method": "ping"}),
        ),
    )
    .await;
    assert_eq!(ping.status, 200);
    assert_eq!(ping.json, json!({"jsonrpc": "2.0", "id": "p1", "result": {}}));
}

#[tokio::test]
async fn lifecycle_messages_still_require_identity() {
    let state = gateway(Vec::new(), |_| {});
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            serde_json::to_vec(&initialize_body("2025-11-25")).unwrap(),
        ))
        .unwrap();
    assert_eq!(send(&state, request).await.status, 401);
}

#[tokio::test]
async fn session_ids_are_bound_to_the_principal_and_cannot_be_forged() {
    let state = gateway(Vec::new(), |_| {});
    let ana = token(&state, "user:ana@acme.io", &["tool:*"], "j-ana");
    let bo = token(&state, "user:bo@acme.io", &["tool:*"], "j-bo");
    let session = initialize(&state, "/mcp", &ana).await;
    let ping = json!({"jsonrpc": "2.0", "id": 1, "method": "ping"});

    assert_eq!(
        send(&state, rpc("/mcp", &ana, Some(&session), ping.clone()))
            .await
            .status,
        200
    );
    assert_eq!(
        send(&state, rpc("/mcp", &bo, Some(&session), ping.clone()))
            .await
            .status,
        404,
        "another principal's session id is unknown to this caller"
    );
    let mut forged = session.clone();
    forged.pop();
    forged.push('0');
    if forged == session {
        forged.pop();
        forged.push('1');
    }
    assert_eq!(
        send(&state, rpc("/mcp", &ana, Some(&forged), ping.clone()))
            .await
            .status,
        404
    );

    let mismatched = post("/mcp", &ana, Some(&session))
        .header("x-av-session", "some-other-session")
        .body(axum::body::Body::from(serde_json::to_vec(&ping).unwrap()))
        .unwrap();
    assert_eq!(send(&state, mismatched).await.status, 400);
}

#[tokio::test]
async fn origin_and_protocol_version_headers_are_enforced() {
    let state = gateway(Vec::new(), |config| {
        config.mcp_allowed_origins = vec!["https://console.acme.io".into()];
    });
    let bearer = token(&state, "user:ana@acme.io", &["tool:*"], "j-origin");
    let body = initialize_body("2025-11-25");
    let with = |origin: Option<&str>, version: Option<&str>| {
        let mut builder = post("/mcp", &bearer, None);
        if let Some(origin) = origin {
            builder = builder.header("origin", origin);
        }
        if let Some(version) = version {
            builder = builder.header("mcp-protocol-version", version);
        }
        builder
            .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    };
    assert_eq!(
        send(&state, with(Some("https://evil.example"), None))
            .await
            .status,
        403
    );
    assert_eq!(
        send(&state, with(Some("https://console.acme.io"), None))
            .await
            .status,
        200
    );
    assert_eq!(send(&state, with(None, Some("2025-06-18"))).await.status, 200);
    assert_eq!(send(&state, with(None, Some("bogus"))).await.status, 400);
}

#[tokio::test]
async fn get_is_method_not_allowed_and_delete_closes_the_audited_session() {
    let upstream = common::MockBackend::start().await;
    let state = gateway(
        vec![backend(
            "alpha",
            &upstream.url,
            BackendAuth::None,
            &["alpha_search"],
        )],
        |_| {},
    );
    let bearer = token(&state, "user:ana@acme.io", &["tool:*", "session:close"], "j-del");

    let get = axum::http::Request::builder()
        .method("GET")
        .uri("/mcp")
        .body(axum::body::Body::empty())
        .unwrap();
    let reply = send(&state, get).await;
    assert_eq!(reply.status, 405);
    assert_eq!(reply.headers["allow"], "POST, DELETE");

    let session = initialize(&state, "/mcp", &bearer).await;
    let first = send(
        &state,
        rpc("/mcp", &bearer, Some(&session), call(1, "alpha_search")),
    )
    .await;
    assert_eq!(first.status, 200, "{}", first.json);
    let second = send(
        &state,
        rpc("/mcp", &bearer, Some(&session), call(2, "alpha_search")),
    )
    .await;
    assert_eq!(second.status, 200, "{}", second.json);
    // Both calls of the MCP session landed in one audited session.
    assert_eq!(state.sessions.len(), 1);

    let delete = axum::http::Request::builder()
        .method("DELETE")
        .uri("/mcp")
        .header("authorization", format!("Bearer {bearer}"))
        .header("mcp-session-id", &session)
        .body(axum::body::Body::empty())
        .unwrap();
    let closed = send(&state, delete).await;
    assert_eq!(closed.status, 200, "{}", closed.json);
    let without_session = axum::http::Request::builder()
        .method("DELETE")
        .uri("/mcp")
        .header("authorization", format!("Bearer {bearer}"))
        .body(axum::body::Body::empty())
        .unwrap();
    assert_eq!(send(&state, without_session).await.status, 400);
}

// ── Server role: discovery and routing ────────────────────────────

#[tokio::test]
async fn tools_list_aggregates_backends_and_lists_only_callable_tools() {
    let tool = |name: &str| json!({"name": name, "description": format!("{name} tool"), "inputSchema": {"type": "object"}});
    let alpha = common::MockBackend::with_tools(vec![
        tool("alpha_search"),
        tool("alpha_admin"),
        tool("Alpha_Upper"),
        tool("beta_lookup"),
        tool("alpha_other"),
    ])
    .await;
    let beta = common::MockBackend::with_tools(vec![tool("beta_lookup")]).await;
    let state = gateway(
        vec![
            backend(
                "alpha",
                &alpha.url,
                BackendAuth::None,
                &["alpha_search", "alpha_admin", "alpha_other"],
            ),
            backend("beta", &beta.url, BackendAuth::None, &["beta_lookup"]),
        ],
        |config| {
            config.enforce_identity_scopes = true;
            config.intent_map.insert("alpha_search".into(), "search".into());
            config.intent_map.insert("beta_lookup".into(), "lookup".into());
            config.mission = Some(MissionConfig {
                id: "m1".into(),
                allowed_intents: vec!["search".into(), "lookup".into()],
                expires_at: u64::MAX / 2,
                agents: Vec::new(),
                charters: Vec::new(),
                subjects: Vec::new(),
            });
        },
    );
    let bearer = token(
        &state,
        "user:ana@acme.io",
        &["tool:alpha_search", "tool:beta_lookup", "tool:alpha_other"],
        "j-list",
    );
    let session = initialize(&state, "/mcp", &bearer).await;
    let list = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/list"});
    let reply = send(&state, rpc("/mcp", &bearer, Some(&session), list.clone())).await;
    assert_eq!(reply.status, 200, "{}", reply.json);
    assert_eq!(names(&reply), vec!["alpha_search", "beta_lookup"]);
    assert_eq!(
        reply.json["result"]["tools"][0]["description"],
        "alpha_search tool"
    );

    // Discovery used the MCP handshake on each backend.
    for mock in [&alpha, &beta] {
        let seen = mock.requests();
        assert_eq!(
            serde_json::from_slice::<Value>(&seen[0].body).unwrap()["method"],
            "initialize"
        );
        assert!(seen
            .iter()
            .any(|request| request.header("mcp-session-id") == Some("mock-backend-session")));
    }

    let metrics = state.metrics.render();
    for reason in ["scope", "invalid_name", "unrouted", "policy"] {
        assert!(
            metrics.contains(&format!("av_mcp_tools_withheld_total{{reason=\"{reason}\"}}")),
            "missing withheld reason {reason}: {metrics}"
        );
    }

    let paged = json!({"jsonrpc": "2.0", "id": 8, "method": "tools/list", "params": {"cursor": "abc"}});
    let reply = send(&state, rpc("/mcp", &bearer, Some(&session), paged)).await;
    assert_eq!(reply.json["error"]["code"], -32602);

    // The per-backend endpoint lists only its backend's tools.
    let beta_session = initialize(&state, "/mcp/beta", &bearer).await;
    let reply = send(&state, rpc("/mcp/beta", &bearer, Some(&beta_session), list)).await;
    assert_eq!(names(&reply), vec!["beta_lookup"]);
}

#[tokio::test]
async fn per_backend_route_refuses_other_backends_tools_and_unknown_backends() {
    let alpha = common::MockBackend::start().await;
    let beta = common::MockBackend::start().await;
    let state = gateway(
        vec![
            backend("alpha", &alpha.url, BackendAuth::None, &["alpha_search"]),
            backend("beta", &beta.url, BackendAuth::None, &["beta_lookup"]),
        ],
        |_| {},
    );
    let bearer = token(&state, "user:ana@acme.io", &["tool:*"], "j-route");
    let session = initialize(&state, "/mcp/alpha", &bearer).await;

    let refused = send(
        &state,
        rpc("/mcp/alpha", &bearer, Some(&session), call(1, "beta_lookup")),
    )
    .await;
    assert_eq!(refused.status, 403, "{}", refused.json);
    assert_eq!(refused.json["error"]["data"]["code"], "NO_BACKEND");
    assert!(beta.requests().is_empty(), "the other backend is never contacted");

    let allowed = send(
        &state,
        rpc("/mcp/alpha", &bearer, Some(&session), call(2, "alpha_search")),
    )
    .await;
    assert_eq!(allowed.status, 200, "{}", allowed.json);
    assert_eq!(alpha.tool_calls().len(), 1);

    let unknown = send(
        &state,
        rpc("/mcp/nope", &bearer, Some(&session), call(3, "alpha_search")),
    )
    .await;
    assert_eq!(unknown.status, 404);
}

// ── Client role: transport details ────────────────────────────────

#[tokio::test]
async fn mcp_backend_calls_carry_session_version_and_accept_headers() {
    let upstream = common::MockBackend::start().await;
    let state = gateway(
        vec![backend(
            "alpha",
            &upstream.url,
            BackendAuth::None,
            &["alpha_search"],
        )],
        |_| {},
    );
    let bearer = token(&state, "user:ana@acme.io", &["tool:*"], "j-headers");
    let session = initialize(&state, "/mcp", &bearer).await;
    let reply = send(
        &state,
        rpc("/mcp", &bearer, Some(&session), call(1, "alpha_search")),
    )
    .await;
    assert_eq!(reply.status, 200, "{}", reply.json);
    let seen = upstream.requests();
    let methods: Vec<Value> = seen
        .iter()
        .map(|request| serde_json::from_slice::<Value>(&request.body).unwrap()["method"].clone())
        .collect();
    assert_eq!(
        methods,
        vec![
            json!("initialize"),
            json!("notifications/initialized"),
            json!("tools/call")
        ]
    );
    for request in &seen {
        assert_eq!(
            request.header("accept"),
            Some("application/json, text/event-stream")
        );
    }
    let call = &upstream.tool_calls()[0];
    assert_eq!(call.header("mcp-session-id"), Some("mock-backend-session"));
    assert_eq!(call.header("mcp-protocol-version"), Some("2025-11-25"));
}

#[tokio::test]
async fn legacy_tool_upstream_keeps_the_plain_json_rpc_transport() {
    let upstream = common::MockBackend::start().await;
    let state = gateway(Vec::new(), |config| {
        config.tool_upstream_url = Some(upstream.url.clone())
    });
    let bearer = token(&state, "user:ana@acme.io", &["tool:*"], "j-legacy");
    let session = initialize(&state, "/mcp", &bearer).await;
    let reply = send(&state, rpc("/mcp", &bearer, Some(&session), call(1, "anything"))).await;
    assert_eq!(reply.status, 200, "{}", reply.json);
    let seen = upstream.requests();
    assert_eq!(seen.len(), 1, "no MCP handshake on the json_rpc transport");
    assert_eq!(seen[0].header("mcp-session-id"), None);
}

#[tokio::test]
async fn forward_token_reaches_only_its_backend() {
    let forwarded = common::MockBackend::start().await;
    let other = common::MockBackend::start().await;
    let state = gateway(
        vec![
            backend("fwd", &forwarded.url, BackendAuth::ForwardToken, &["fwd_tool"]),
            backend("other", &other.url, BackendAuth::None, &["other_tool"]),
        ],
        |_| {},
    );
    let bearer = token(&state, "user:ana@acme.io", &["tool:*"], "j-forward");
    let session = initialize(&state, "/mcp", &bearer).await;
    assert_eq!(
        send(&state, rpc("/mcp", &bearer, Some(&session), call(1, "fwd_tool")))
            .await
            .status,
        200
    );
    assert_eq!(
        send(
            &state,
            rpc("/mcp", &bearer, Some(&session), call(2, "other_tool"))
        )
        .await
        .status,
        200
    );
    for request in forwarded.requests() {
        assert_eq!(
            request.header("authorization"),
            Some(format!("Bearer {bearer}").as_str())
        );
    }
    for request in other.requests() {
        assert!(
            !request.everything().contains(&bearer),
            "the caller token leaked to another backend"
        );
    }
}

#[test]
fn forward_token_requires_identity() {
    let mut config = common::leaked_test_config();
    config.backends = vec![backend(
        "fwd",
        "http://fwd:1/mcp",
        BackendAuth::ForwardToken,
        &["t"],
    )];
    let error = config.validate().unwrap_err();
    assert!(error.contains("forward_token"), "{error}");
}

/// Requests a scripted backend received: (HTTP method, session id, body).
type SeenRequests = Arc<Mutex<Vec<(String, Option<String>, Value)>>>;

/// A scripted Streamable HTTP backend for SSE, expiry and resumption.
#[derive(Clone, Default)]
struct Script {
    /// Answer the first tools/call with 404 (session ended).
    expire_first_call: bool,
    /// End the first tools/call stream early, then serve the response on
    /// a `GET` resumption.
    resume: bool,
    initializes: Arc<AtomicUsize>,
    calls: Arc<AtomicUsize>,
    seen: SeenRequests,
}

async fn scripted_backend(script: Script) -> String {
    let app = axum::Router::new().fallback(
        move |method: axum::http::Method, headers: axum::http::HeaderMap, body: axum::body::Bytes| {
            let script = script.clone();
            async move {
                let session = headers
                    .get("mcp-session-id")
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned);
                let request = serde_json::from_slice::<Value>(&body).unwrap_or(Value::Null);
                script
                    .seen
                    .lock()
                    .push((method.to_string(), session.clone(), request.clone()));
                let sse = |text: String| {
                    ([(axum::http::header::CONTENT_TYPE, "text/event-stream")], text).into_response()
                };
                if method == axum::http::Method::GET {
                    assert_eq!(headers.get("last-event-id").unwrap(), "e1");
                    return sse(
                        "id: e2\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"resumed\"}]}}\n\n"
                            .to_owned(),
                    );
                }
                let id = request.get("id").cloned();
                match (request.get("method").and_then(Value::as_str), id) {
                    (Some("initialize"), Some(id)) => {
                        let n = script.initializes.fetch_add(1, Ordering::SeqCst) + 1;
                        let mut response = axum::Json(json!({
                            "jsonrpc": "2.0", "id": id,
                            "result": {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                                       "serverInfo": {"name": "scripted", "version": "1"}}
                        }))
                        .into_response();
                        response
                            .headers_mut()
                            .insert("mcp-session-id", format!("scripted-{n}").parse().unwrap());
                        response
                    }
                    (Some("tools/call"), Some(id)) => {
                        let n = script.calls.fetch_add(1, Ordering::SeqCst) + 1;
                        if script.expire_first_call && n == 1 {
                            return axum::http::StatusCode::NOT_FOUND.into_response();
                        }
                        if script.resume && n == 1 {
                            return sse("id: e1\nretry: 10\ndata:\n\n".to_owned());
                        }
                        sse(format!(
                            "id: 1\ndata:\n\n\
                             data: {{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{{\"progress\":1}}}}\n\n\
                             data: {{\"jsonrpc\":\"2.0\",\"id\":\"srv-1\",\"method\":\"ping\"}}\n\n\
                             data: {{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":{{\"content\":[{{\"type\":\"text\",\"text\":\"streamed\"}}]}}}}\n\n"
                        ))
                    }
                    _ => axum::http::StatusCode::ACCEPTED.into_response(),
                }
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

#[tokio::test]
async fn sse_responses_are_decoded_and_server_pings_are_answered() {
    let script = Script::default();
    let url = scripted_backend(script.clone()).await;
    let state = gateway(
        vec![backend("s", &url, BackendAuth::None, &["stream_tool"])],
        |_| {},
    );
    let bearer = token(&state, "user:ana@acme.io", &["tool:*"], "j-sse");
    let session = initialize(&state, "/mcp", &bearer).await;
    let reply = send(
        &state,
        rpc("/mcp", &bearer, Some(&session), call(1, "stream_tool")),
    )
    .await;
    assert_eq!(reply.status, 200, "{}", reply.json);
    assert_eq!(reply.json["result"]["content"][0]["text"], "streamed");
    assert_eq!(reply.json["id"], 1);
    let seen = script.seen.lock().clone();
    assert!(
        seen.iter()
            .any(|(_, _, body)| body == &json!({"jsonrpc": "2.0", "id": "srv-1", "result": {}})),
        "the backend's ping must be answered: {seen:?}"
    );
    // The negotiated version (2025-06-18) is what later requests carry.
    assert!(
        seen.iter()
            .all(|(_, session, body)| body["method"] == "initialize"
                || session.as_deref() == Some("scripted-1"))
    );
}

#[tokio::test]
async fn expired_backend_session_is_renewed_and_the_call_retried_once() {
    let script = Script {
        expire_first_call: true,
        ..Script::default()
    };
    let url = scripted_backend(script.clone()).await;
    let state = gateway(
        vec![backend("s", &url, BackendAuth::None, &["stream_tool"])],
        |_| {},
    );
    let bearer = token(&state, "user:ana@acme.io", &["tool:*"], "j-expire");
    let session = initialize(&state, "/mcp", &bearer).await;
    let reply = send(
        &state,
        rpc("/mcp", &bearer, Some(&session), call(1, "stream_tool")),
    )
    .await;
    assert_eq!(reply.status, 200, "{}", reply.json);
    assert_eq!(script.initializes.load(Ordering::SeqCst), 2);
    assert_eq!(script.calls.load(Ordering::SeqCst), 2);
    let seen = script.seen.lock().clone();
    let call_sessions: Vec<Option<String>> = seen
        .iter()
        .filter(|(_, _, body)| body["method"] == "tools/call")
        .map(|(_, session, _)| session.clone())
        .collect();
    assert_eq!(
        call_sessions,
        vec![Some("scripted-1".into()), Some("scripted-2".into())]
    );
}

#[tokio::test]
async fn an_early_ended_stream_is_resumed_with_last_event_id() {
    let script = Script {
        resume: true,
        ..Script::default()
    };
    let url = scripted_backend(script.clone()).await;
    let state = gateway(
        vec![backend("s", &url, BackendAuth::None, &["stream_tool"])],
        |_| {},
    );
    let bearer = token(&state, "user:ana@acme.io", &["tool:*"], "j-resume");
    let session = initialize(&state, "/mcp", &bearer).await;
    let reply = send(
        &state,
        rpc("/mcp", &bearer, Some(&session), call(1, "stream_tool")),
    )
    .await;
    assert_eq!(reply.status, 200, "{}", reply.json);
    assert_eq!(reply.json["result"]["content"][0]["text"], "resumed");
    assert!(script.seen.lock().iter().any(|(method, _, _)| method == "GET"));
}

#[tokio::test]
async fn a_backend_that_refuses_initialize_gets_no_tool_call_and_the_budget_is_refunded() {
    let seen: Arc<Mutex<Vec<Value>>> = Arc::default();
    let recorded = Arc::clone(&seen);
    let app = axum::Router::new().fallback(move |body: axum::body::Bytes| {
        let recorded = Arc::clone(&recorded);
        async move {
            recorded
                .lock()
                .push(serde_json::from_slice(&body).unwrap_or(Value::Null));
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/mcp", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let state = gateway(
        vec![backend("broken", &url, BackendAuth::None, &["broken_tool"])],
        |config| {
            config.budget.max_total_tool_calls = Some(1);
        },
    );
    let bearer = token(&state, "user:ana@acme.io", &["tool:*"], "j-broken");
    let request = |id| {
        let mut request = rpc("/mcp", &bearer, None, call(id, "broken_tool"));
        request
            .headers_mut()
            .insert("x-av-session", "refund-session".parse().unwrap());
        request
    };
    assert_eq!(send(&state, request(1)).await.status, 502);
    assert!(seen.lock().iter().all(|body| body["method"] != "tools/call"));
    // The single-call budget was refunded, so a retry is admitted again
    // (it fails the same way, but it is not refused for budget).
    assert_eq!(send(&state, request(2)).await.status, 502);
}

#[tokio::test]
async fn each_agent_session_gets_its_own_backend_session() {
    let script = Script::default();
    let url = scripted_backend(script.clone()).await;
    let state = gateway(
        vec![backend("s", &url, BackendAuth::None, &["stream_tool"])],
        |_| {},
    );
    let bearer = token(&state, "user:ana@acme.io", &["tool:*"], "j-isolation");

    let first = initialize(&state, "/mcp", &bearer).await;
    for id in [1, 2] {
        let reply = send(
            &state,
            rpc("/mcp", &bearer, Some(&first), call(id, "stream_tool")),
        )
        .await;
        assert_eq!(reply.status, 200, "{}", reply.json);
    }
    assert_eq!(
        script.initializes.load(Ordering::SeqCst),
        1,
        "calls in one MCP session reuse one backend session"
    );

    let second = initialize(&state, "/mcp", &bearer).await;
    let reply = send(
        &state,
        rpc("/mcp", &bearer, Some(&second), call(1, "stream_tool")),
    )
    .await;
    assert_eq!(reply.status, 200, "{}", reply.json);
    assert_eq!(script.initializes.load(Ordering::SeqCst), 2);

    let sessions: Vec<Option<String>> = script
        .seen
        .lock()
        .iter()
        .filter(|(_, _, body)| body["method"] == "tools/call")
        .map(|(_, session, _)| session.clone())
        .collect();
    assert_eq!(
        sessions,
        vec![
            Some("scripted-1".into()),
            Some("scripted-1".into()),
            Some("scripted-2".into())
        ],
        "a second agent session never shares the first one's backend session"
    );
}

#[tokio::test]
async fn private_backends_are_reachable_by_name_when_only_private_addresses_are_allowed() {
    let upstream = common::MockBackend::with_tools(vec![
        json!({"name": "alpha_search", "inputSchema": {"type": "object"}}),
    ])
    .await;
    // Address the backend by host name so the private-only resolver runs.
    let by_name = upstream.url.replace("127.0.0.1", "localhost");
    let state = gateway(
        vec![backend("alpha", &by_name, BackendAuth::None, &["alpha_search"])],
        |config| {
            config.require_private_backends = true;
        },
    );
    let bearer = token(&state, "user:ana@acme.io", &["tool:*"], "j-private");
    let session = initialize(&state, "/mcp", &bearer).await;
    let listed = send(
        &state,
        rpc(
            "/mcp",
            &bearer,
            Some(&session),
            json!({"jsonrpc": "2.0", "id": 5, "method": "tools/list"}),
        ),
    )
    .await;
    assert_eq!(names(&listed), vec!["alpha_search"]);
    let reply = send(
        &state,
        rpc("/mcp", &bearer, Some(&session), call(1, "alpha_search")),
    )
    .await;
    assert_eq!(reply.status, 200, "{}", reply.json);
}

#[test]
fn a_public_backend_address_refuses_boot_when_backends_must_be_private() {
    let mut config = common::leaked_test_config();
    config.require_private_backends = true;
    config.backends = vec![backend("public", "http://8.8.8.8/mcp", BackendAuth::None, &["t"])];
    assert!(config
        .validate()
        .unwrap_err()
        .contains("require_private_backends"));
    config.backends = vec![backend(
        "agentvisor-ai",
        "http://10.0.0.1/mcp",
        BackendAuth::None,
        &["t"],
    )];
    assert!(
        config.validate().unwrap_err().contains("same as `audience`"),
        "a backend may not share the gateway's audience name"
    );
}
