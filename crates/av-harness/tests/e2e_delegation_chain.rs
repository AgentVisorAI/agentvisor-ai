//! End-to-end tests for the delegation chain: the `parent_token` ancestry
//! and the RFC 8693 `act` nesting that bind an agent's token to the human
//! who authorized it and to every agent that delegated to it.
//!
//! `IdentityValidator::validate_inner` and `build_exchanged_claims` enforce
//! these rules. Their unit tests cover the logic. These tests drive the
//! same rules through the live HTTP gateway so a regression in the wiring —
//! a missing `set_max_chain_depth`, a check skipped on the request path, an
//! error mapped to the wrong status — is caught the way a client would see
//! it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use av_harness::config::{BackendAuth, BackendConfig};
use av_identity::{
    ActorClaim, Audience, InMemoryRevocationStore, NhiClaims, RevocationStore,
};
use std::sync::Arc;

const HMAC_SECRET: &[u8] = b"test-hmac-secret-for-delegation-chain-0";
const HMAC_KID: &str = "chain-kid";
const EXCHANGE_SEED: [u8; 32] = [42u8; 32];

type Request = axum::http::Request<axum::body::Body>;

// ── Helpers ─────────────────────────────────────────────────────

fn now_s() -> u64 {
    av_core::time::now_ms() / 1000
}

fn gateway(
    backends: Vec<BackendConfig>,
    tweak: impl FnOnce(&mut av_harness::HarnessConfig),
) -> (Arc<av_harness::AppState>, tempfile::TempDir) {
    gateway_with_revocation(backends, tweak, Arc::new(InMemoryRevocationStore::new()))
}

fn gateway_with_revocation(
    backends: Vec<BackendConfig>,
    tweak: impl FnOnce(&mut av_harness::HarnessConfig),
    revocation: Arc<dyn RevocationStore>,
) -> (Arc<av_harness::AppState>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let seed = common::owner_only_file(dir.path(), "exchange.key", &hex::encode(EXCHANGE_SEED));
    let mut config = common::leaked_test_config();
    config.require_identity = true;
    config.token_exchange_enabled = true;
    config.token_exchange_seed_file = Some(seed);
    config.backends = backends;
    tweak(&mut config);
    let sandbox = common::sandbox_for(&config);
    let state = common::app_state_with_revocation(
        config,
        sandbox,
        Arc::new(common::CountingBus::default()),
        2,
        HMAC_SECRET,
        HMAC_KID,
        revocation,
    );
    (state, dir)
}

fn backend(name: &str, url: &str, tools: &[&str]) -> BackendConfig {
    BackendConfig {
        name: name.into(),
        url: url.into(),
        auth: BackendAuth::None,
        tools: tools.iter().map(|tool| (*tool).to_owned()).collect(),
        transport: Default::default(),
    }
}

/// Claims for a root token. `now` is pinned so parent and child share an
/// `iat` unless a test deliberately separates them.
fn base_claims(now: u64, audience: &str, jti: &str, scopes: &[&str]) -> NhiClaims {
    NhiClaims {
        sub: "user:bob@acme.io".into(),
        iss: "test-issuer".into(),
        aud: Audience::Single(audience.to_owned()),
        iat: now,
        nbf: None,
        exp: now + 300,
        jti: jti.to_owned(),
        azp: Some("caller-app".into()),
        act: None,
        instance_uid: "inst-chain-test".into(),
        charter: "support-agent".into(),
        version: "1.0".into(),
        scopes: scopes.iter().map(|scope| (*scope).to_owned()).collect(),
        parent_token: None,
    }
}

fn mint(claims: &NhiClaims) -> String {
    let header = jsonwebtoken::Header {
        alg: jsonwebtoken::Algorithm::HS256,
        kid: Some(HMAC_KID.to_owned()),
        ..Default::default()
    };
    jsonwebtoken::encode(
        &header,
        claims,
        &jsonwebtoken::EncodingKey::from_secret(HMAC_SECRET),
    )
    .unwrap()
}

fn tool_call(session: &str, bearer: &str, tool: &str, id: u64) -> Request {
    let body = serde_json::to_vec(&serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {"name": tool, "arguments": {}}
    }))
    .unwrap();
    axum::http::Request::builder()
        .method("POST")
        .uri("/v1/mcp")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {bearer}"))
        .header("x-av-session", session)
        .body(axum::body::Body::from(body))
        .unwrap()
}

fn form(uri: &str, body: String) -> Request {
    axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(body))
        .unwrap()
}

struct Reply {
    status: axum::http::StatusCode,
    json: serde_json::Value,
}

async fn send(state: &Arc<av_harness::AppState>, request: Request) -> Reply {
    let router = av_harness::build_router((**state).clone());
    let response = tower::ServiceExt::oneshot(router, request).await.unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap();
    Reply {
        status,
        json: serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null),
    }
}

/// Assert that a refused call is a clean 401 whose body does not leak
/// which invariant failed. The classifier collapses every identity error
/// to one opaque message so a prober cannot map responses to rules.
fn assert_opaque_401(reply: &Reply, what: &str) {
    assert_eq!(reply.status, 401, "{what}: {}", reply.json);
    let body = reply.json.to_string();
    for leak in [
        "Escalation",
        "ChainTooDeep",
        "TooDeep",
        "delegation",
        "parent",
        "tool:write",
        "chain-kid",
        "test-issuer",
    ] {
        assert!(
            !body.contains(leak),
            "{what}: response echoes {leak:?}: {body}"
        );
    }
}

fn exchange_body(subject: &str, audience: &str) -> String {
    format!(
        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange\
         &subject_token={subject}\
         &subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt\
         &audience={audience}"
    )
}

fn exchange_body_with_actor(subject: &str, actor: &str, audience: &str) -> String {
    format!(
        "{}&actor_token={actor}\
         &actor_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt",
        exchange_body(subject, audience)
    )
}

// ── Positive control: a valid chain is accepted ─────────────────

#[tokio::test]
async fn a_valid_delegation_chain_reaches_the_backend() {
    let upstream = common::MockBackend::start().await;
    let (state, _dir) = gateway(
        vec![backend("svc", &upstream.url, &["lookup"])],
        |_| {},
    );
    let now = now_s();
    let audience = state.config.audience.clone();

    let root_jwt = mint(&base_claims(now, &audience, "jti-root", &["tool:*"]));
    let mut child = base_claims(now, &audience, "jti-child", &["tool:lookup"]);
    child.parent_token = Some(root_jwt);
    let child_jwt = mint(&child);

    let reply = send(&state, tool_call("sess-valid", &child_jwt, "lookup", 1)).await;
    assert_eq!(reply.status, 200, "{}", reply.json);
    assert_eq!(
        upstream.tool_calls().len(),
        1,
        "the delegated call must reach the backend"
    );
}

// ── Delegation invariants, over HTTP ────────────────────────────

#[tokio::test]
async fn a_child_token_must_not_outlive_its_parent() {
    let upstream = common::MockBackend::start().await;
    let (state, _dir) = gateway(
        vec![backend("svc", &upstream.url, &["lookup"])],
        |_| {},
    );
    let now = now_s();
    let audience = state.config.audience.clone();

    let mut root = base_claims(now, &audience, "jti-root", &["tool:*"]);
    root.exp = now + 100;
    let root_jwt = mint(&root);

    let mut child = base_claims(now, &audience, "jti-child", &["tool:lookup"]);
    child.exp = now + 200;
    child.parent_token = Some(root_jwt);
    let child_jwt = mint(&child);

    let reply = send(&state, tool_call("sess-exp", &child_jwt, "lookup", 1)).await;
    assert_opaque_401(&reply, "a child that outlives its parent");
    assert!(
        upstream.tool_calls().is_empty(),
        "the refused call must not reach the backend"
    );
}

#[tokio::test]
async fn a_child_token_must_not_be_issued_before_its_parent() {
    let upstream = common::MockBackend::start().await;
    let (state, _dir) = gateway(
        vec![backend("svc", &upstream.url, &["lookup"])],
        |_| {},
    );
    let now = now_s();
    let audience = state.config.audience.clone();

    let root_jwt = mint(&base_claims(now, &audience, "jti-root", &["tool:*"]));

    // The child claims to have been issued ten seconds before the parent
    // that delegated it. That inverts the authorization causality.
    let mut child = base_claims(now - 10, &audience, "jti-child", &["tool:lookup"]);
    child.exp = now + 300;
    child.parent_token = Some(root_jwt);
    let child_jwt = mint(&child);

    let reply = send(&state, tool_call("sess-iat", &child_jwt, "lookup", 1)).await;
    assert_opaque_401(&reply, "a child issued before its parent");
    assert!(upstream.tool_calls().is_empty());
}

#[tokio::test]
async fn a_child_token_must_not_be_usable_before_its_parent() {
    let upstream = common::MockBackend::start().await;
    let (state, _dir) = gateway(
        vec![backend("svc", &upstream.url, &["lookup"])],
        |_| {},
    );
    let now = now_s();
    let audience = state.config.audience.clone();

    // The parent does not become usable until now+15. The child omits
    // `nbf`, so its effective start falls back to `iat` = now — five
    // seconds before the parent's grant becomes active. A child must
    // never claim authority before the parent that granted it did.
    let mut root = base_claims(now, &audience, "jti-root", &["tool:*"]);
    root.nbf = Some(now + 15);
    let root_jwt = mint(&root);

    let mut child = base_claims(now, &audience, "jti-child", &["tool:lookup"]);
    child.parent_token = Some(root_jwt);
    let child_jwt = mint(&child);

    let reply = send(&state, tool_call("sess-nbf", &child_jwt, "lookup", 1)).await;
    assert_opaque_401(&reply, "a child usable before its parent");
    assert!(upstream.tool_calls().is_empty());
}

#[tokio::test]
async fn a_child_token_must_not_widen_its_parent_scopes() {
    let upstream = common::MockBackend::start().await;
    let (state, _dir) = gateway(
        vec![backend("svc", &upstream.url, &["lookup", "write"])],
        |_| {},
    );
    let now = now_s();
    let audience = state.config.audience.clone();

    let root_jwt = mint(&base_claims(now, &audience, "jti-root", &["tool:lookup"]));

    // The parent holds only `tool:lookup`. The child claims `tool:write`
    // as well. A child's privileges are the intersection with its parent,
    // never the union, so the extra scope must refuse the whole token.
    let mut child = base_claims(
        now,
        &audience,
        "jti-child",
        &["tool:lookup", "tool:write"],
    );
    child.parent_token = Some(root_jwt);
    let child_jwt = mint(&child);

    let reply = send(&state, tool_call("sess-scope", &child_jwt, "write", 1)).await;
    assert_opaque_401(&reply, "a child that widens its parent's scopes");
    assert!(upstream.tool_calls().is_empty());
}

#[tokio::test]
async fn a_wildcard_parent_still_allows_narrowing() {
    let upstream = common::MockBackend::start().await;
    let (state, _dir) = gateway(
        vec![backend("svc", &upstream.url, &["lookup"])],
        |_| {},
    );
    let now = now_s();
    let audience = state.config.audience.clone();

    // `tool:*` covers `tool:lookup`, so narrowing is legal. This guards
    // the wildcard-parent case: delegation must not become stricter than
    // the runtime authorization gate.
    let root_jwt = mint(&base_claims(now, &audience, "jti-root", &["tool:*"]));
    let mut child = base_claims(now, &audience, "jti-child", &["tool:lookup"]);
    child.parent_token = Some(root_jwt);
    let child_jwt = mint(&child);

    let reply = send(&state, tool_call("sess-wild", &child_jwt, "lookup", 1)).await;
    assert_eq!(reply.status, 200, "{}", reply.json);
}

// ── Depth caps, over HTTP ───────────────────────────────────────

#[tokio::test]
async fn a_delegation_chain_deeper_than_the_cap_is_refused() {
    let upstream = common::MockBackend::start().await;
    let (state, _dir) = gateway(
        vec![backend("svc", &upstream.url, &["lookup"])],
        |config| config.max_delegation_depth = 2,
    );
    let now = now_s();
    let audience = state.config.audience.clone();

    // Four tokens, three delegation links. The cap is two.
    let level0 = mint(&base_claims(now, &audience, "jti-l0", &["tool:*"]));
    let mut level1 = base_claims(now, &audience, "jti-l1", &["tool:lookup"]);
    level1.parent_token = Some(level0);
    let level1 = mint(&level1);
    let mut level2 = base_claims(now, &audience, "jti-l2", &["tool:lookup"]);
    level2.parent_token = Some(level1);
    let level2 = mint(&level2);
    let mut level3 = base_claims(now, &audience, "jti-l3", &["tool:lookup"]);
    level3.parent_token = Some(level2);
    let level3 = mint(&level3);

    let reply = send(&state, tool_call("sess-deep", &level3, "lookup", 1)).await;
    assert_opaque_401(&reply, "a chain past the depth cap");
    assert!(upstream.tool_calls().is_empty());
}

#[tokio::test]
async fn an_act_chain_deeper_than_the_cap_is_refused() {
    let upstream = common::MockBackend::start().await;
    let (state, _dir) = gateway(
        vec![backend("svc", &upstream.url, &["lookup"])],
        |config| config.max_delegation_depth = 2,
    );
    let now = now_s();
    let audience = state.config.audience.clone();

    // Three nested `act` links. The cap is two.
    let mut chain = ActorClaim {
        sub: "agent:leaf".into(),
        act: None,
    };
    for level in 0..2 {
        chain = ActorClaim {
            sub: format!("agent:level{level}"),
            act: Some(Box::new(chain)),
        };
    }
    let mut claims = base_claims(now, &audience, "jti-act", &["tool:lookup"]);
    claims.act = Some(chain);
    let token = mint(&claims);

    let reply = send(&state, tool_call("sess-act", &token, "lookup", 1)).await;
    assert_opaque_401(&reply, "an act chain past the depth cap");
    assert!(upstream.tool_calls().is_empty());
}

// ── Revocation cuts off the whole chain ─────────────────────────

#[tokio::test]
async fn revoking_the_delegator_cuts_off_the_child() {
    let upstream = common::MockBackend::start().await;
    let store = Arc::new(InMemoryRevocationStore::new());
    let (state, _dir) = gateway_with_revocation(
        vec![backend("svc", &upstream.url, &["lookup"])],
        |_| {},
        Arc::clone(&store) as Arc<dyn RevocationStore>,
    );
    let now = now_s();
    let audience = state.config.audience.clone();

    let root_jwt = mint(&base_claims(now, &audience, "jti-root", &["tool:*"]));
    let mut child = base_claims(now, &audience, "jti-child", &["tool:lookup"]);
    child.parent_token = Some(root_jwt);
    let child_jwt = mint(&child);

    // A sibling root token proves the gateway still works after the
    // revocation below, so the child's refusal is the revocation and not
    // a broken harness.
    let sibling_jwt = mint(&base_claims(now, &audience, "jti-sibling", &["tool:*"]));

    store.revoke("jti-root", now + 3_600).unwrap();

    let refused = send(&state, tool_call("sess-cut", &child_jwt, "lookup", 1)).await;
    assert_opaque_401(&refused, "a child of a revoked delegator");
    assert!(upstream.tool_calls().is_empty());

    let allowed = send(&state, tool_call("sess-cut", &sibling_jwt, "lookup", 2)).await;
    assert_eq!(allowed.status, 200, "{}", allowed.json);
    assert_eq!(upstream.tool_calls().len(), 1);
}

// ── The exchange endpoint refuses unsafe chains ─────────────────

#[tokio::test]
async fn exchange_refuses_a_delegated_actor_token() {
    let (state, _dir) = gateway(
        vec![backend("svc", "http://127.0.0.1:9", &["lookup"])],
        |_| {},
    );
    let now = now_s();
    let audience = state.config.audience.clone();

    let subject_jwt = mint(&base_claims(now, &audience, "jti-subject", &["tool:lookup"]));

    // RFC 8693 actors must be undelegated: presenting an actor that
    // already carries a parent would let one agent silently act as two.
    let parent_jwt = mint(&base_claims(now, &audience, "jti-actor-parent", &["tool:*"]));
    let mut actor = base_claims(now, &audience, "jti-actor", &["tool:lookup"]);
    actor.parent_token = Some(parent_jwt);
    let actor_jwt = mint(&actor);

    let reply = send(
        &state,
        form(
            "/v1/token",
            exchange_body_with_actor(&subject_jwt, &actor_jwt, "svc"),
        ),
    )
    .await;
    assert_eq!(
        reply.status,
        400,
        "a delegated actor must be refused: {}",
        reply.json
    );
    assert_eq!(
        reply.json["error"], "invalid_grant",
        "RFC 8693 delegation misuse is invalid_grant: {}",
        reply.json
    );
}

#[tokio::test]
async fn exchange_refuses_when_a_link_would_exceed_the_depth_cap() {
    let (state, _dir) = gateway(
        vec![backend("svc", "http://127.0.0.1:9", &["lookup"])],
        |config| config.max_delegation_depth = 1,
    );
    let now = now_s();
    let audience = state.config.audience.clone();

    // The subject already sits at the cap. Adding one more `act` link for
    // this exchange would take the chain to two, past the cap of one.
    let mut subject = base_claims(now, &audience, "jti-subject", &["tool:lookup"]);
    subject.act = Some(ActorClaim {
        sub: "agent:inner".into(),
        act: None,
    });
    let subject_jwt = mint(&subject);

    let reply = send(
        &state,
        form("/v1/token", exchange_body(&subject_jwt, "svc")),
    )
    .await;
    assert_eq!(
        reply.status,
        400,
        "the exchange must not push the chain past the cap: {}",
        reply.json
    );
    assert_eq!(
        reply.json["error"], "invalid_grant",
        "a depth overflow is invalid_grant: {}",
        reply.json
    );
}