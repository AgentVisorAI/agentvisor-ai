//! End-to-end tests for RFC 8693 actor tokens, human attribution, intent
//! token claims, per-agent missions, and the external AuthZEN PDP.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use av_harness::config::{AuthzenConfig, BackendAuth, BackendConfig, BackendTransport, MissionConfig};
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::sync::Arc;

const HMAC_SECRET: &[u8] = b"test-hmac-secret-for-identity-policy-0";
const HMAC_KID: &str = "idp-kid";
const EXCHANGE_SEED: [u8; 32] = [71u8; 32];
const BACKEND_SECRET: &str = "introspection-secret-for-backend-svc-000000";

type Request = axum::http::Request<axum::body::Body>;

struct Reply {
    status: axum::http::StatusCode,
    json: Value,
}

async fn send(state: &Arc<av_harness::AppState>, request: Request) -> Reply {
    let router = av_harness::build_router((**state).clone());
    let response = tower::ServiceExt::oneshot(router, request).await.unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap();
    Reply {
        status,
        json: serde_json::from_slice(&body).unwrap_or(Value::Null),
    }
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

fn gateway(
    backends: Vec<BackendConfig>,
    tweak: impl FnOnce(&mut av_harness::HarnessConfig),
) -> (Arc<av_harness::AppState>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let seed = common::owner_only_file(dir.path(), "exchange.key", &hex::encode(EXCHANGE_SEED));
    let mut config = common::leaked_test_config();
    config.require_identity = true;
    config.token_exchange_seed_file = Some(seed);
    config.backends = backends;
    tweak(&mut config);
    let sandbox = common::sandbox_for(&config);
    let state = common::app_state_with_identity(
        config,
        sandbox,
        Arc::new(common::CountingBus::default()),
        4,
        HMAC_SECRET,
        HMAC_KID,
    );
    (state, dir)
}

fn token(state: &av_harness::AppState, sub: &str, instance: &str, scopes: &[&str], jti: &str) -> String {
    common::mint_nhi_token(
        HMAC_SECRET,
        HMAC_KID,
        &state.config.audience,
        &common::NhiSpec {
            sub,
            instance_uid: instance,
            scopes,
            jti,
        },
    )
}

fn form(uri: &str, body: String) -> Request {
    axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(body))
        .unwrap()
}

fn tool_call(bearer: &str, session: &str, tool: &str, id: u64) -> Request {
    axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {bearer}"))
        .header("x-av-session", session)
        .body(axum::body::Body::from(
            serde_json::to_vec(&json!({
                "jsonrpc": "2.0", "id": id, "method": "tools/call",
                "params": {"name": tool, "arguments": {}}
            }))
            .unwrap(),
        ))
        .unwrap()
}

const EXCHANGE: &str = "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange\
    &subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt&audience=svc";
const JWT_TYPE: &str = "urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt";

fn decode_unverified(jwt: &str) -> Value {
    use base64::Engine as _;
    let payload = jwt.split('.').nth(1).unwrap();
    serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .unwrap(),
    )
    .unwrap()
}

// ── RFC 8693 actor tokens ─────────────────────────────────────────

#[tokio::test]
async fn actor_token_exchange_records_both_agents_and_intersects_three_scope_sets() {
    let (state, _dir) = gateway(
        vec![backend("svc", "http://127.0.0.1:9/mcp", &["read"])],
        |config| {
            config.token_exchange_enabled = true;
        },
    );
    let subject = token(
        &state,
        "user:ana@acme.io",
        "inst-parent",
        &["tool:read", "tool:write"],
        "j-subject",
    );
    let actor = token(
        &state,
        "user:ana@acme.io",
        "inst-child",
        &["tool:read", "payout"],
        "j-actor",
    );
    let reply = send(
        &state,
        form(
            "/v1/token",
            format!("{EXCHANGE}&subject_token={subject}&actor_token={actor}&actor_token_type={JWT_TYPE}"),
        ),
    )
    .await;
    assert_eq!(reply.status, 200, "{}", reply.json);
    assert_eq!(reply.json["scope"], "tool:read", "requested ∩ subject ∩ actor");
    let claims = decode_unverified(reply.json["access_token"].as_str().unwrap());
    assert_eq!(claims["sub"], "user:ana@acme.io");
    assert_eq!(claims["azp"], "inst-child");
    assert_eq!(claims["act"]["sub"], "inst-child");
    assert_eq!(claims["act"]["act"]["sub"], "inst-parent");
    assert_eq!(claims["av_actor_tokens"][0]["jti"], "j-actor");
}

#[tokio::test]
async fn actor_token_parameters_are_validated() {
    let (state, _dir) = gateway(
        vec![backend("svc", "http://127.0.0.1:9/mcp", &["read"])],
        |config| {
            config.token_exchange_enabled = true;
        },
    );
    let subject = token(&state, "user:ana@acme.io", "inst-parent", &["tool:read"], "j-s2");
    let actor = token(&state, "user:ana@acme.io", "inst-child", &["tool:read"], "j-a2");
    let missing_type = send(
        &state,
        form(
            "/v1/token",
            format!("{EXCHANGE}&subject_token={subject}&actor_token={actor}"),
        ),
    )
    .await;
    assert_eq!(missing_type.status, 400);
    assert_eq!(missing_type.json["error"], "invalid_request");
    let wrong_type = send(
        &state,
        form(
            "/v1/token",
            format!(
                "{EXCHANGE}&subject_token={subject}&actor_token={actor}\
                 &actor_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token"
            ),
        ),
    )
    .await;
    assert_eq!(wrong_type.status, 400);
    let forged_actor = send(
        &state,
        form(
            "/v1/token",
            format!("{EXCHANGE}&subject_token={subject}&actor_token=not.a.jwt&actor_token_type={JWT_TYPE}"),
        ),
    )
    .await;
    assert_eq!(forged_actor.status, 400);
    assert_eq!(
        forged_actor.json["error_description"],
        "identity validation failed"
    );
}

#[tokio::test]
async fn revoking_the_actor_revokes_the_exchanged_token() {
    let (state, _dir) = gateway(
        vec![backend("svc", "http://127.0.0.1:9/mcp", &["read"])],
        |config| {
            config.token_exchange_enabled = true;
            config
                .introspection_tokens
                .push(av_harness::config::IntrospectionTokenConfig {
                    backend: "svc".into(),
                    sha256: av_core::digest::sha256_hex(BACKEND_SECRET.as_bytes()),
                });
        },
    );
    let subject = token(&state, "user:ana@acme.io", "inst-parent", &["tool:read"], "j-s3");
    let actor = token(&state, "user:ana@acme.io", "inst-child", &["tool:read"], "j-a3");
    let exchanged = send(
        &state,
        form(
            "/v1/token",
            format!("{EXCHANGE}&subject_token={subject}&actor_token={actor}&actor_token_type={JWT_TYPE}"),
        ),
    )
    .await;
    let access = exchanged.json["access_token"].as_str().unwrap().to_owned();
    let introspect = |token: String| {
        let mut request = form("/v1/introspect", format!("token={token}"));
        request.headers_mut().insert(
            "authorization",
            format!("Bearer {BACKEND_SECRET}").parse().unwrap(),
        );
        request
    };
    assert_eq!(
        send(&state, introspect(access.clone())).await.json["active"],
        true
    );
    assert_eq!(
        send(&state, form("/v1/revoke", format!("token={actor}")))
            .await
            .status,
        200
    );
    assert_eq!(
        send(&state, introspect(access)).await.json["active"],
        false,
        "revoking the actor must revoke what it obtained"
    );
}

// ── Human attribution ─────────────────────────────────────────────

#[tokio::test]
async fn tokens_whose_subject_is_not_a_human_are_refused() {
    let upstream = common::MockBackend::start().await;
    let (state, _dir) = gateway(vec![backend("svc", &upstream.url, &["read"])], |config| {
        config.identity_human_subject_pattern = Some("^user:".into());
    });
    let machine = token(&state, "service:cron", "inst-1", &["tool:*"], "j-machine");
    assert_eq!(
        send(&state, tool_call(&machine, "h-1", "read", 1)).await.status,
        401
    );
    let human = token(&state, "user:ana@acme.io", "inst-1", &["tool:*"], "j-human");
    assert_eq!(
        send(&state, tool_call(&human, "h-2", "read", 1)).await.status,
        200
    );
}

#[test]
fn an_invalid_human_subject_pattern_refuses_boot() {
    let mut config = common::leaked_test_config();
    config.identity_human_subject_pattern = Some("(unclosed".into());
    assert!(config
        .validate()
        .unwrap_err()
        .contains("identity_human_subject_pattern"));
}

// ── Intent tokens and per-agent missions ─────────────────────────

fn agent_mission(id: &str, agent: &str, intents: &[&str]) -> MissionConfig {
    MissionConfig {
        id: id.into(),
        allowed_intents: intents.iter().map(|intent| (*intent).to_owned()).collect(),
        expires_at: u64::MAX / 2,
        agents: vec![agent.into()],
        charters: Vec::new(),
        subjects: Vec::new(),
    }
}

#[tokio::test]
async fn intent_tokens_name_the_human_the_agent_and_the_missions() {
    let upstream = common::MockBackend::start().await;
    let (state, _dir) = gateway(vec![backend("svc", &upstream.url, &["read"])], |config| {
        config.intent_map.insert("read".into(), "data.read".into());
        config.missions = vec![agent_mission("reader", "inst-a", &["data.read"])];
    });
    let bearer = token(&state, "user:ana@acme.io", "inst-a", &["tool:*"], "j-intent");
    assert_eq!(
        send(&state, tool_call(&bearer, "i-1", "read", 1)).await.status,
        200
    );
    let call = &upstream.tool_calls()[0];
    let intent = decode_unverified(call.header("x-av-intent-token").unwrap());
    assert_eq!(intent["sub"], "user:ana@acme.io");
    assert_eq!(intent["act"]["sub"], "inst-a");
    assert_eq!(intent["intent"], "data.read");
    assert_eq!(intent["missions"], json!(["reader"]));
}

#[tokio::test]
async fn per_agent_missions_narrow_only_the_selected_agent() {
    let upstream = common::MockBackend::start().await;
    let (state, _dir) = gateway(
        vec![backend("svc", &upstream.url, &["read", "write"])],
        |config| {
            config.intent_map.insert("read".into(), "data.read".into());
            config.intent_map.insert("write".into(), "data.mutate".into());
            config.missions = vec![agent_mission("reader", "inst-a", &["data.read"])];
        },
    );
    let agent_a = token(&state, "user:ana@acme.io", "inst-a", &["tool:*"], "j-a");
    let agent_b = token(&state, "user:ana@acme.io", "inst-b", &["tool:*"], "j-b");
    let refused = send(&state, tool_call(&agent_a, "m-1", "write", 1)).await;
    assert_eq!(refused.status, 403, "{}", refused.json);
    assert_eq!(refused.json["error"]["data"]["code"], "MISSION_DENIED");
    assert_eq!(
        send(&state, tool_call(&agent_a, "m-2", "read", 1)).await.status,
        200
    );
    assert_eq!(
        send(&state, tool_call(&agent_b, "m-3", "write", 1)).await.status,
        200
    );
}

#[test]
fn mission_configuration_is_validated() {
    let mut config = common::leaked_test_config();
    let mut unselective = agent_mission("m", "x", &["i"]);
    unselective.agents.clear();
    config.missions = vec![unselective];
    assert!(config
        .validate()
        .unwrap_err()
        .contains("no agents, charters, or subjects"));

    let mut config = common::leaked_test_config();
    config.mission = Some(agent_mission("global", "x", &["i"]));
    assert!(config.validate().unwrap_err().contains("[[missions]]"));

    let mut config = common::leaked_test_config();
    config.missions = vec![
        agent_mission("dup", "a", &["i"]),
        agent_mission("dup", "b", &["i"]),
    ];
    assert!(config.validate().unwrap_err().contains("more than once"));
}

// ── External AuthZEN PDP ──────────────────────────────────────────

#[derive(Clone, Default)]
struct Pdp {
    requests: Arc<Mutex<Vec<(String, Value)>>>,
    broken: bool,
}

async fn start_pdp(pdp: Pdp) -> String {
    let app = axum::Router::new().fallback(
        move |uri: axum::http::Uri, headers: axum::http::HeaderMap, body: axum::body::Bytes| {
            let pdp = pdp.clone();
            async move {
                assert!(
                    headers.get("x-request-id").is_some(),
                    "AuthZEN requests carry X-Request-ID"
                );
                let request: Value = serde_json::from_slice(&body).unwrap();
                pdp.requests.lock().push((uri.path().to_owned(), request.clone()));
                if pdp.broken {
                    return (
                        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                        axum::Json(json!("down")),
                    );
                }
                let decide = |resource: &Value| resource["id"] != "danger";
                let answer = if uri.path().ends_with("/evaluations") {
                    let evaluations: Vec<Value> = request["evaluations"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|evaluation| json!({"decision": decide(&evaluation["resource"])}))
                        .collect();
                    json!({"evaluations": evaluations})
                } else if decide(&request["resource"]) {
                    json!({"decision": true})
                } else {
                    json!({"decision": false, "context": {"reason_admin": {"en": "danger is off limits"}}})
                };
                (axum::http::StatusCode::OK, axum::Json(answer))
            }
        },
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    base
}

fn authzen(base: &str, batch: bool) -> AuthzenConfig {
    AuthzenConfig {
        evaluation_endpoint: format!("{base}/access/v1/evaluation"),
        evaluations_endpoint: batch.then(|| format!("{base}/access/v1/evaluations")),
        auth_file: None,
        timeout_ms: 2_000,
    }
}

#[tokio::test]
async fn authzen_permits_denies_and_receives_the_documented_request_shape() {
    let pdp = Pdp::default();
    let base = start_pdp(pdp.clone()).await;
    let upstream = common::MockBackend::start().await;
    let (state, _dir) = gateway(
        vec![backend("svc", &upstream.url, &["read", "danger"])],
        |config| {
            config.intent_map.insert("read".into(), "data.read".into());
            config.authzen = Some(authzen(&base, false));
        },
    );
    let bearer = token(&state, "user:ana@acme.io", "inst-a", &["tool:*"], "j-pdp");

    assert_eq!(
        send(&state, tool_call(&bearer, "z-1", "read", 1)).await.status,
        200
    );
    let (path, request) = pdp.requests.lock()[0].clone();
    assert_eq!(path, "/access/v1/evaluation");
    assert_eq!(request["subject"]["type"], "user");
    assert_eq!(request["subject"]["id"], "user:ana@acme.io");
    assert_eq!(
        request["subject"]["properties"]["agent"]["instance_uid"],
        "inst-a"
    );
    assert_eq!(request["action"]["name"], "data.read");
    assert_eq!(
        request["resource"],
        json!({"type": "tool", "id": "read", "properties": {"backend": "svc"}})
    );
    assert_eq!(request["context"]["session_id"], "z-1");

    let denied = send(&state, tool_call(&bearer, "z-2", "danger", 2)).await;
    assert_eq!(denied.status, 403, "{}", denied.json);
    assert_eq!(denied.json["error"]["data"]["code"], "PDP_DENIED");
    assert!(denied.json["error"]["data"]["reason"]
        .as_str()
        .unwrap()
        .contains("danger is off limits"));
    assert_eq!(
        upstream.tool_calls().len(),
        1,
        "a denied call never reaches the backend"
    );
}

#[tokio::test]
async fn an_unreachable_authzen_pdp_fails_closed() {
    let base = start_pdp(Pdp {
        broken: true,
        ..Pdp::default()
    })
    .await;
    let upstream = common::MockBackend::start().await;
    let (state, _dir) = gateway(vec![backend("svc", &upstream.url, &["read"])], |config| {
        config.authzen = Some(authzen(&base, false));
    });
    let bearer = token(&state, "user:ana@acme.io", "inst-a", &["tool:*"], "j-down");
    assert_eq!(
        send(&state, tool_call(&bearer, "d-1", "read", 1)).await.status,
        503
    );
    assert!(upstream.requests().is_empty());
}

#[tokio::test]
async fn tools_list_asks_authzen_in_one_batch() {
    let pdp = Pdp::default();
    let base = start_pdp(pdp.clone()).await;
    let tool = |name: &str| json!({"name": name, "inputSchema": {"type": "object"}});
    let upstream = common::MockBackend::with_tools(vec![tool("read"), tool("danger")]).await;
    let (state, _dir) = gateway(
        vec![backend("svc", &upstream.url, &["read", "danger"])],
        |config| {
            config.authzen = Some(authzen(&base, true));
        },
    );
    let bearer = token(&state, "user:ana@acme.io", "inst-a", &["tool:*"], "j-batch");
    let list = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {bearer}"))
        .body(axum::body::Body::from(
            serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})).unwrap(),
        ))
        .unwrap();
    let reply = send(&state, list).await;
    let names: Vec<&str> = reply.json["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["read"]);
    let requests = pdp.requests.lock().clone();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].0, "/access/v1/evaluations");
    assert_eq!(requests[0].1["evaluations"].as_array().unwrap().len(), 2);
}

#[test]
fn authzen_configuration_is_validated() {
    let mut config = common::leaked_test_config();
    config.authzen = Some(AuthzenConfig {
        evaluation_endpoint: "ftp://pdp".into(),
        evaluations_endpoint: None,
        auth_file: None,
        timeout_ms: 0,
    });
    let error = config.validate().unwrap_err();
    assert!(error.contains("authzen.evaluation_endpoint"), "{error}");
    assert!(error.contains("timeout_ms"), "{error}");
}

// ── Runtime evidence: content sink ────────────────────────────────

#[derive(Default)]
struct RecordingSink(Mutex<Vec<av_harness::content::ContentRecord>>);

impl av_harness::content::ContentSink for RecordingSink {
    fn record(&self, record: av_harness::content::ContentRecord) {
        self.0.lock().push(record);
    }
}

#[tokio::test]
async fn journaled_tool_steps_reach_the_content_sink_after_redaction() {
    let upstream = common::MockBackend::start().await;
    let (state, _dir) = gateway(vec![backend("svc", &upstream.url, &["read"])], |config| {
        config.redaction_patterns = vec!["secret-[0-9]+".into()];
    });
    let sink = Arc::new(RecordingSink::default());
    state
        .set_content_sink(Arc::clone(&sink) as Arc<dyn av_harness::content::ContentSink>)
        .unwrap();
    let bearer = token(&state, "user:ana@acme.io", "inst-sink", &["tool:*"], "j-sink");
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {bearer}"))
        .header("x-av-session", "sink-session")
        .body(axum::body::Body::from(
            serde_json::to_vec(&json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "read", "arguments": {"note": "secret-123"}}
            }))
            .unwrap(),
        ))
        .unwrap();
    assert_eq!(send(&state, request).await.status, 200);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let records = sink.0.lock().clone();
        let tool = records
            .iter()
            .find(|record| record.class == av_events::EventClass::ToolCall);
        let completed = records.iter().any(|record| {
            record.event.pointer("/payload/action").and_then(Value::as_str) == Some("tool_completed")
        });
        if let (Some(tool), true) = (tool, completed) {
            assert_eq!(tool.session_id, "sink-session");
            assert_eq!(tool.identity.instance_uid, "inst-sink");
            let calls = tool.tool_calls.as_ref().unwrap().to_string();
            assert!(calls.contains("\"read\""), "{calls}");
            assert!(
                !calls.contains("secret-123"),
                "journal redaction applies before the sink: {calls}"
            );
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "sink never received the tool steps: {records:?}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}
