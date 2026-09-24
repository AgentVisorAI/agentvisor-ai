//! End-to-end tests for the RFC 7523 workload grant: a Cloud Foundry app
//! instance proves its instance identity and receives an agent token that
//! works on every gateway route.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use av_harness::config::{
    BackendAuth, BackendConfig, BackendTransport, WorkloadIdentityConfig, WorkloadMapping,
};
use base64::Engine as _;
use serde_json::{json, Value};
use std::sync::Arc;

const HMAC_SECRET: &[u8] = b"test-hmac-secret-for-workload-ident-0";
const HMAC_KID: &str = "workload-kid";
const EXCHANGE_SEED: [u8; 32] = [81u8; 32];
const FIXTURES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../av-identity/tests/fixtures/cf-instance-identity"
);
const INSTANCE_GUID: &str = "0b6c1d2e-3f40-4a5b-8c6d-7e8f90a1b2c3";
const APP_GUID: &str = "7c2d1e3f-4051-4263-b475-96a7b8c9d0e1";

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

fn fixture(name: &str) -> String {
    std::fs::read_to_string(format!("{FIXTURES}/{name}")).unwrap()
}

fn mapping(app_guid: &str) -> WorkloadMapping {
    WorkloadMapping {
        name: "billing-agent".into(),
        cf_app_guid: Some(app_guid.into()),
        cf_space_guid: None,
        cf_org_guid: None,
        sub: "user:ana@acme.io".into(),
        charter: "billing".into(),
        version: "7".into(),
        scopes: vec!["tool:*".into()],
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
    config.identity_human_subject_pattern = Some("^user:".into());
    config.workload_identity = Some(WorkloadIdentityConfig {
        ca_file: format!("{FIXTURES}/root.pem"),
        token_ttl_s: 300,
    });
    config.workload_identities = vec![mapping(APP_GUID)];
    config.backends = backends;
    tweak(&mut config);
    let sandbox = common::sandbox_for(&config);
    let state = common::app_state_with_identity(
        config,
        sandbox,
        Arc::new(common::CountingBus::default()),
        5,
        HMAC_SECRET,
        HMAC_KID,
    );
    (state, dir)
}

fn der(pem: &str) -> String {
    let body: String = pem.lines().filter(|line| !line.starts_with("-----")).collect();
    base64::engine::general_purpose::STANDARD
        .encode(base64::engine::general_purpose::STANDARD.decode(body).unwrap())
}

fn assertion(jti: &str) -> String {
    let now = av_core::time::now_ms() / 1000;
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.x5c = Some(vec![
        der(&fixture("instance.pem")),
        der(&fixture("intermediate.pem")),
    ]);
    jsonwebtoken::encode(
        &header,
        &json!({"iss": INSTANCE_GUID, "sub": INSTANCE_GUID, "aud": "agentvisor-ai",
                "iat": now, "exp": now + 120, "jti": jti}),
        &jsonwebtoken::EncodingKey::from_rsa_pem(fixture("instance.key").as_bytes()).unwrap(),
    )
    .unwrap()
}

fn grant(assertion: &str, scope: Option<&str>) -> Request {
    let mut body =
        format!("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion={assertion}");
    if let Some(scope) = scope {
        body.push_str(&format!("&scope={}", scope.replace(':', "%3A").replace(' ', "+")));
    }
    axum::http::Request::builder()
        .method("POST")
        .uri("/v1/token")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(body))
        .unwrap()
}

fn tool_call(bearer: &str, session: &str) -> Request {
    axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {bearer}"))
        .header("x-av-session", session)
        .body(axum::body::Body::from(
            serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                        "params": {"name": "charge", "arguments": {}}}))
            .unwrap(),
        ))
        .unwrap()
}

fn decode(jwt: &str) -> Value {
    let payload = jwt.split('.').nth(1).unwrap();
    serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .unwrap(),
    )
    .unwrap()
}

#[tokio::test]
async fn an_instance_identity_becomes_an_agent_token_that_is_attributable_to_a_human() {
    let upstream = common::MockBackend::start().await;
    let (state, _dir) = gateway(
        vec![BackendConfig {
            name: "payments".into(),
            url: upstream.url.clone(),
            auth: BackendAuth::None,
            tools: vec!["charge".into()],
            transport: BackendTransport::Mcp,
        }],
        |_| {},
    );
    let reply = send(&state, grant(&assertion("w-1"), None)).await;
    assert_eq!(reply.status, 200, "{}", reply.json);
    assert_eq!(reply.json["token_type"], "Bearer");
    assert_eq!(reply.json["expires_in"], 300);
    assert_eq!(reply.json["scope"], "tool:*");
    let token = reply.json["access_token"].as_str().unwrap().to_owned();
    let claims = decode(&token);
    assert_eq!(claims["sub"], "user:ana@acme.io");
    assert_eq!(claims["iss"], "agentvisor-ai#workload");
    assert_eq!(claims["instance_uid"], INSTANCE_GUID);
    assert_eq!(claims["azp"], format!("cf-app:{APP_GUID}"));
    assert_eq!(claims["charter"], "billing");

    let call = send(&state, tool_call(&token, "w-session")).await;
    assert_eq!(call.status, 200, "{}", call.json);
    let intent = decode(upstream.tool_calls()[0].header("x-av-intent-token").unwrap());
    assert_eq!(intent["sub"], "user:ana@acme.io");
    assert_eq!(intent["act"]["sub"], INSTANCE_GUID);

    // The agent token can be revoked like any other identity.
    let revoke = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/revoke")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(format!("token={token}")))
        .unwrap();
    assert_eq!(send(&state, revoke).await.status, 200);
    assert_eq!(send(&state, tool_call(&token, "w-session-2")).await.status, 401);
}

#[tokio::test]
async fn assertions_are_single_use_and_scopes_only_narrow() {
    let (state, _dir) = gateway(Vec::new(), |_| {});
    let first = assertion("w-2");
    assert_eq!(send(&state, grant(&first, None)).await.status, 200);
    let replay = send(&state, grant(&first, None)).await;
    assert_eq!(replay.status, 400);
    assert_eq!(replay.json["error"], "invalid_grant");
    assert!(state
        .metrics
        .render()
        .contains("av_workload_assertions_rejected_total{reason=\"replay\"}"));

    let narrowed = send(&state, grant(&assertion("w-3"), Some("tool:charge"))).await;
    assert_eq!(narrowed.status, 200, "{}", narrowed.json);
    assert_eq!(narrowed.json["scope"], "tool:charge");
    let widened = send(&state, grant(&assertion("w-4"), Some("admin:all"))).await;
    assert_eq!(widened.json["error"], "invalid_scope");
}

#[tokio::test]
async fn unregistered_workloads_and_gateways_without_workload_identity_refuse_the_grant() {
    let (state, _dir) = gateway(Vec::new(), |config| {
        config.workload_identities = vec![mapping("00000000-0000-0000-0000-000000000000")];
    });
    let reply = send(&state, grant(&assertion("w-5"), None)).await;
    assert_eq!(reply.status, 400);
    assert_eq!(
        reply.json["error_description"],
        "this workload is not registered with the gateway"
    );

    let (plain, _dir) = gateway(Vec::new(), |config| {
        config.workload_identity = None;
        config.workload_identities.clear();
    });
    let reply = send(&plain, grant(&assertion("w-6"), None)).await;
    assert_eq!(reply.json["error"], "unsupported_grant_type");
}

#[test]
fn workload_configuration_is_validated() {
    let base = || {
        let mut config = common::leaked_test_config();
        config.token_exchange_seed_file = Some("/run/secrets/seed".into());
        config.workload_identity = Some(WorkloadIdentityConfig {
            ca_file: "/etc/ca.pem".into(),
            token_ttl_s: 300,
        });
        config.workload_identities = vec![mapping(APP_GUID)];
        config
    };
    let mut config = base();
    config.identity_human_subject_pattern = Some("^user:".into());
    config.workload_identities[0].sub = "service:cron".into();
    assert!(config
        .validate()
        .unwrap_err()
        .contains("identity_human_subject_pattern"));

    let mut config = base();
    config.token_exchange_seed_file = None;
    assert!(config
        .validate()
        .unwrap_err()
        .contains("token_exchange_seed_file"));

    let mut config = base();
    config.workload_identities[0].cf_app_guid = None;
    assert!(config.validate().unwrap_err().contains("cf_app_guid"));

    let mut config = base();
    config.workload_identity = None;
    assert!(config
        .validate()
        .unwrap_err()
        .contains("requires [workload_identity]"));
}
