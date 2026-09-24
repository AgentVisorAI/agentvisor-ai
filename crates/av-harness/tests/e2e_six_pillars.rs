//! End-to-end tests for the six security pillars.
//!
//! Pillar 1: Per-agent identity (act claim, azp, delegation depth, revocation)
//! Pillar 2: Per-call authorization (intent mapping, missions, denial codes)
//! Pillar 3: Credential handling (token exchange, scope intersection)
//! Pillar 4: Backend isolation (per-backend routing, credential isolation)
//! Pillar 5: Runtime evidence (denial codes in OCSF, intent tokens)
//! Pillar 6: Developer ergonomics (config defaults, backward compat)

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use av_harness::config::{BackendAuth, BackendConfig, HarnessConfig, MissionConfig};
use av_identity::{
    build_exchanged_claims, scope_intersection, ActorClaim, ExchangeParams, InMemoryRevocationStore,
    RevocationStore,
};
use av_sandbox::{DenialCode, Sandbox, SandboxConfig};
use std::sync::Arc;

// ── Pillar 1: Identity ────────────────────────────────────────────

#[test]
fn act_claim_depth_counts_nesting() {
    let inner = ActorClaim {
        sub: "agent:level2".into(),
        act: None,
    };
    assert_eq!(inner.depth(), 0, "leaf node has depth 0");
    let outer = ActorClaim {
        sub: "agent:level1".into(),
        act: Some(Box::new(inner)),
    };
    assert_eq!(outer.depth(), 1, "one level of nesting = depth 1");
}

#[test]
fn deeply_nested_act_chain() {
    let mut chain = ActorClaim {
        sub: "agent:leaf".into(),
        act: None,
    };
    for i in 0..10 {
        chain = ActorClaim {
            sub: format!("agent:level{i}"),
            act: Some(Box::new(chain)),
        };
    }
    assert_eq!(chain.depth(), 10, "10 wraps = depth 10");
}

#[test]
fn revocation_store_revoke_and_query() {
    let store = InMemoryRevocationStore::new();
    assert!(!store.is_revoked("jti-1").unwrap());
    store.revoke("jti-1", 9999).unwrap();
    assert!(store.is_revoked("jti-1").unwrap());
    assert!(!store.is_revoked("jti-2").unwrap());
}

#[test]
fn revocation_store_sweep_removes_expired() {
    let store = InMemoryRevocationStore::new();
    store.revoke("old", 100).unwrap();
    store.revoke("fresh", 9999).unwrap();
    assert_eq!(store.len(), 2);
    store.sweep(500);
    assert_eq!(store.len(), 1);
    assert!(!store.is_revoked("old").unwrap());
    assert!(store.is_revoked("fresh").unwrap());
}

#[test]
fn revocation_store_empty_is_not_revoked() {
    let store = InMemoryRevocationStore::new();
    assert!(store.is_empty());
    assert!(!store.is_revoked("anything").unwrap());
}

// ── Pillar 2: Authorization (PDP, intent mapping, missions) ────────

#[test]
fn pdp_mapped_tool_resolves_intent() {
    let pdp = test_pdp(&[("db_write", "data.mutate")], false, None);
    match pdp.decide("db_write", 1000) {
        av_harness::authz::AuthzDecision::Permit { intent, .. } => {
            assert_eq!(intent, "data.mutate");
        }
        av_harness::authz::AuthzDecision::Deny { .. } => panic!("expected permit"),
    }
}

#[test]
fn pdp_unmapped_tool_denied_when_required() {
    let pdp = test_pdp(&[("db_write", "data.mutate")], true, None);
    match pdp.decide("unknown_tool", 1000) {
        av_harness::authz::AuthzDecision::Deny { code, .. } => {
            assert_eq!(code, DenialCode::UnmappedTool);
        }
        av_harness::authz::AuthzDecision::Permit { .. } => panic!("expected deny"),
    }
}

#[test]
fn pdp_expired_mission_denied() {
    let mission = MissionConfig {
        id: "m-expired".into(),
        allowed_intents: vec!["data.mutate".into()],
        expires_at: 500,
    };
    let pdp = test_pdp(&[("db_write", "data.mutate")], false, Some(mission));
    match pdp.decide("db_write", 1000) {
        av_harness::authz::AuthzDecision::Deny { code, reason } => {
            assert_eq!(code, DenialCode::MissionExpired);
            assert!(
                reason.contains("expired"),
                "reason should mention expiry: {reason}"
            );
        }
        av_harness::authz::AuthzDecision::Permit { .. } => panic!("expected deny"),
    }
}

#[test]
fn pdp_mission_denies_unlisted_intent() {
    let mission = MissionConfig {
        id: "m-narrow".into(),
        allowed_intents: vec!["data.read".into()],
        expires_at: 9999,
    };
    let pdp = test_pdp(&[("db_write", "data.mutate")], false, Some(mission));
    match pdp.decide("db_write", 1000) {
        av_harness::authz::AuthzDecision::Deny { code, .. } => {
            assert_eq!(code, DenialCode::MissionDenied);
        }
        av_harness::authz::AuthzDecision::Permit { .. } => panic!("expected deny"),
    }
}

#[test]
fn pdp_no_token_without_signer() {
    let pdp = test_pdp(&[("search", "data.read")], false, None);
    assert!(
        matches!(
            pdp.decide("search", 1000),
            av_harness::authz::AuthzDecision::Permit { .. }
        ),
        "expected permit"
    );
    assert!(
        pdp.mint_intent_token("search", "data.read", "inst-1", "backend-a", 1000)
            .is_none(),
        "no signer → no intent token"
    );
}

// ── Pillar 3: Token exchange (scope intersection, claims) ───────

#[test]
fn scope_intersection_exact_match() {
    let a = vec!["tool:read".to_owned(), "tool:write".to_owned()];
    let b = vec!["tool:read".to_owned(), "payout".to_owned()];
    let result = scope_intersection(&a, &b);
    assert_eq!(result, vec!["tool:read"]);
}

#[test]
fn scope_intersection_wildcard_expands() {
    let a = vec!["tool:*".to_owned()];
    let b = vec!["tool:read".to_owned(), "tool:write".to_owned()];
    let result = scope_intersection(&a, &b);
    assert!(result.contains(&"tool:read".to_owned()));
    assert!(result.contains(&"tool:write".to_owned()));
}

#[test]
fn scope_intersection_star_covers_everything() {
    let a = vec!["*".to_owned()];
    let b = vec!["tool:read".to_owned(), "payout".to_owned()];
    let result = scope_intersection(&a, &b);
    assert_eq!(result.len(), 2);
}

#[test]
fn scope_intersection_disjoint_is_empty() {
    let a = vec!["tool:read".to_owned()];
    let b = vec!["payout".to_owned()];
    assert!(scope_intersection(&a, &b).is_empty());
}

#[test]
fn exchange_preserves_sub_and_narrows_scopes() {
    let subject = test_claims(&["tool:read", "tool:write", "payout"]);
    let params = ExchangeParams {
        subject: &subject,
        subject_chain: &[av_identity::RevocationIdentity {
            iss: subject.iss.clone(),
            jti: subject.jti.clone(),
            instance_uid: subject.instance_uid.clone(),
            iat: subject.iat,
        }],
        subject_delegation_depth: subject.act.as_ref().map_or(0, |a| 1 + a.depth()),
        target_audience: "backend-a",
        requested_scopes: Some("tool:read payout"),
        azp: "client-1",
        now_s: 1100,
        ttl_s: 60,
        issuer: "agentvisor-ai",
        max_depth: 4,
        allowed_audiences: &[],
    };
    let result = build_exchanged_claims(&params).unwrap();
    assert_eq!(
        result.sub, "user:alice@corp.com",
        "sub must stay the human principal"
    );
    assert_eq!(result.azp, Some("client-1".to_owned()));
    assert!(result.act.is_some(), "agent identity must go into act");
    assert_eq!(result.scopes, vec!["tool:read", "payout"]);
    assert_eq!(result.exp - result.iat, 60, "TTL must match requested");
    assert_eq!(result.iss, "agentvisor-ai", "iss must be the gateway");
}

#[test]
fn exchange_refuses_scope_escalation() {
    let subject = test_claims(&["tool:read"]);
    let params = ExchangeParams {
        subject: &subject,
        subject_chain: &[av_identity::RevocationIdentity {
            iss: subject.iss.clone(),
            jti: subject.jti.clone(),
            instance_uid: subject.instance_uid.clone(),
            iat: subject.iat,
        }],
        subject_delegation_depth: subject.act.as_ref().map_or(0, |a| 1 + a.depth()),
        target_audience: "backend-a",
        requested_scopes: Some("tool:write"),
        azp: "client-1",
        now_s: 1100,
        ttl_s: 60,
        issuer: "agentvisor-ai",
        max_depth: 4,
        allowed_audiences: &[],
    };
    let result = build_exchanged_claims(&params);
    assert!(result.is_err(), "requesting scopes beyond subject must fail");
}

#[test]
fn exchange_adds_act_link() {
    let mut subject = test_claims(&["tool:read"]);
    subject.act = Some(ActorClaim {
        sub: "agent:billing".into(),
        act: None,
    });
    let params = ExchangeParams {
        subject: &subject,
        subject_chain: &[av_identity::RevocationIdentity {
            iss: subject.iss.clone(),
            jti: subject.jti.clone(),
            instance_uid: subject.instance_uid.clone(),
            iat: subject.iat,
        }],
        subject_delegation_depth: subject.act.as_ref().map_or(0, |a| 1 + a.depth()),
        target_audience: "backend-b",
        requested_scopes: None,
        azp: "client-2",
        now_s: 1100,
        ttl_s: 60,
        issuer: "agentvisor-ai",
        max_depth: 4,
        allowed_audiences: &[],
    };
    let result = build_exchanged_claims(&params).unwrap();
    let act = result.act.as_ref().unwrap();
    assert_eq!(act.sub, "client-2", "new azp must become the outermost actor");
    let inner = act.act.as_ref().unwrap();
    assert_eq!(
        inner.sub, "agent:billing",
        "previous act chain must be nested inside"
    );
}

// ── Pillar 4: Backend isolation ─────────────────────────────────

#[test]
fn backend_router_explicit_routing() {
    let router = av_harness::backend::BackendRouter::new(
        &[
            backend_cfg("db", "http://db:8080", &["db_write", "db_read"]),
            backend_cfg("search", "http://search:8080", &["search"]),
        ],
        None,
        None,
    )
    .unwrap();
    assert_eq!(router.resolve("db_write").unwrap().name, "db");
    assert_eq!(router.resolve("search").unwrap().name, "search");
    assert!(router.resolve("unknown").is_none());
}

#[test]
fn backend_router_default_catches_unmapped() {
    let router = av_harness::backend::BackendRouter::new(
        &[
            backend_cfg("db", "http://db:8080", &["db_write"]),
            backend_cfg("fallback", "http://fallback:8080", &[]),
        ],
        None,
        None,
    )
    .unwrap();
    assert_eq!(router.resolve("anything_else").unwrap().name, "fallback");
}

#[test]
fn backend_router_implicit_default_from_fallback_url() {
    let router = av_harness::backend::BackendRouter::new(&[], Some("http://tool:8080"), None).unwrap();
    assert_eq!(router.resolve("any_tool").unwrap().url, "http://tool:8080");
}

#[test]
fn backend_router_duplicate_tool_refused() {
    let result = av_harness::backend::BackendRouter::new(
        &[
            backend_cfg("a", "http://a:8080", &["shared"]),
            backend_cfg("b", "http://b:8080", &["shared"]),
        ],
        None,
        None,
    );
    assert!(result.is_err(), "duplicate tool mapping must be rejected");
}

#[test]
fn credential_isolation_between_backends() {
    std::env::set_var("E2E_TEST_BACKEND_KEY", "secret-for-a");
    let router = av_harness::backend::BackendRouter::new(
        &[
            BackendConfig {
                name: "a".into(),
                url: "http://a:8080".into(),
                auth: BackendAuth::StaticEnv("E2E_TEST_BACKEND_KEY".into()),
                tools: vec!["tool_a".into()],
            },
            backend_cfg("b", "http://b:8080", &["tool_b"]),
        ],
        None,
        None,
    )
    .unwrap();
    let a = router.resolve("tool_a").unwrap();
    assert!(a.auth_header.is_some(), "backend a must have credentials");
    let b = router.resolve("tool_b").unwrap();
    assert!(b.auth_header.is_none(), "backend b must NOT have a's credentials");
    std::env::remove_var("E2E_TEST_BACKEND_KEY");
}

// ── Pillar 5: Runtime evidence (denial codes, OCSF) ─────────────

#[test]
fn denial_code_serde_round_trip() {
    for code in &[
        DenialCode::UnmappedTool,
        DenialCode::MissionExpired,
        DenialCode::MissionDenied,
        DenialCode::ScopeInsufficient,
        DenialCode::TokenRevoked,
        DenialCode::IntentTokenError,
        DenialCode::ParseError,
        DenialCode::PolicyDenied,
        DenialCode::BudgetExceeded,
    ] {
        let serialized = serde_json::to_string(code).unwrap();
        let deserialized: DenialCode = serde_json::from_str(&serialized).unwrap();
        assert_eq!(*code, deserialized, "round-trip failed for {code:?}");
    }
}

#[test]
fn denial_code_as_str_matches_serde_name() {
    assert_eq!(DenialCode::UnmappedTool.as_str(), "UNMAPPED_TOOL");
    assert_eq!(DenialCode::MissionExpired.as_str(), "MISSION_EXPIRED");
    assert_eq!(DenialCode::MissionDenied.as_str(), "MISSION_DENIED");
    assert_eq!(DenialCode::TokenRevoked.as_str(), "TOKEN_REVOKED");
    assert_eq!(DenialCode::PolicyDenied.as_str(), "POLICY_DENIED");
    assert_eq!(DenialCode::BudgetExceeded.as_str(), "BUDGET_EXCEEDED");
}

#[test]
fn denial_code_display_matches_as_str() {
    let code = DenialCode::UnmappedTool;
    assert_eq!(format!("{code}"), code.as_str());
}

// ── Pillar 6: Developer ergonomics (config defaults) ─────────────

#[test]
fn config_defaults_are_safe() {
    let config = HarnessConfig::from_toml("upstream_url = \"http://upstream\"").unwrap();
    assert!(
        config.max_delegation_depth > 0 && config.max_delegation_depth <= 10,
        "default max_delegation_depth should be a reasonable bound"
    );
    assert_eq!(
        config.intent_token_ttl_s, 60,
        "intent token TTL should default to 60s"
    );
    assert!(
        !config.token_exchange_enabled,
        "token exchange should be opt-in, not on by default"
    );
    assert!(!config.require_intent_mapping, "intent mapping should be opt-in");
    assert!(
        config.backends.is_empty(),
        "no backends by default (backward compat)"
    );
    assert!(config.mission.is_none(), "no mission by default");
}

#[test]
fn config_backward_compat_no_backends() {
    let config = HarnessConfig::from_toml("upstream_url = \"http://upstream\"").unwrap();
    let router = av_harness::backend::BackendRouter::new(&config.backends, None, None).unwrap();
    assert!(router.is_empty());
    assert!(router.resolve("read_record").is_none());
    let router =
        av_harness::backend::BackendRouter::new(&config.backends, Some("http://legacy-tools"), None).unwrap();
    assert_eq!(router.len(), 1);
    for tool in ["read_record", "unmapped_tool"] {
        let backend = router.resolve(tool).unwrap();
        assert_eq!(backend.name, "default");
        assert_eq!(backend.url, "http://legacy-tools");
    }
}

// ── Cross-pillar: mission narrowing never widens ────────────────

#[test]
fn mission_narrowing_never_widens_static_policy() {
    let mission = MissionConfig {
        id: "narrow".into(),
        allowed_intents: vec!["data.read".into()],
        expires_at: 9999,
    };
    let pdp = test_pdp(
        &[("db_write", "data.mutate"), ("db_read", "data.read")],
        false,
        Some(mission),
    );
    match pdp.decide("db_write", 1000) {
        av_harness::authz::AuthzDecision::Deny { code, .. } => {
            assert_eq!(code, DenialCode::MissionDenied);
        }
        av_harness::authz::AuthzDecision::Permit { .. } => {
            panic!("mission should narrow, not widen: db_write maps to data.mutate which is not in allowed_intents");
        }
    }
    match pdp.decide("db_read", 1000) {
        av_harness::authz::AuthzDecision::Permit { intent, .. } => {
            assert_eq!(intent, "data.read");
        }
        av_harness::authz::AuthzDecision::Deny { .. } => {
            panic!("db_read maps to data.read which IS in allowed_intents");
        }
    }
}

// ── Cross-pillar: scope intersection = child ⊆ parent ──────────

#[test]
fn delegation_scope_is_intersection_never_union() {
    let parent_scopes = vec!["tool:read".to_owned(), "payout".to_owned()];
    let child_request = vec![
        "tool:read".to_owned(),
        "tool:write".to_owned(),
        "payout".to_owned(),
    ];
    let effective = scope_intersection(&child_request, &parent_scopes);
    assert!(
        effective.contains(&"tool:read".to_owned()),
        "tool:read is in both sets"
    );
    assert!(effective.contains(&"payout".to_owned()), "payout is in both sets");
    assert!(
        !effective.contains(&"tool:write".to_owned()),
        "tool:write is NOT in parent — intersection must exclude it"
    );
}

// ── Helpers ─────────────────────────────────────────────────────

fn test_pdp(
    intents: &[(&str, &str)],
    require: bool,
    mission: Option<MissionConfig>,
) -> av_harness::authz::PolicyDecisionPoint {
    let mut config = common::leaked_test_config();
    config.intent_map = intents
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    config.require_intent_mapping = require;
    config.mission = mission;
    config.intent_token_ttl_s = 60;
    av_harness::authz::PolicyDecisionPoint::from_config(&config, None)
}

fn test_claims(scopes: &[&str]) -> av_identity::NhiClaims {
    av_identity::NhiClaims {
        sub: "user:alice@corp.com".into(),
        iss: "idp.corp.com".into(),
        aud: "agentvisor-ai".into(),
        iat: 1000,
        nbf: None,
        exp: 1900,
        jti: "jti-test".into(),
        azp: None,
        act: None,
        instance_uid: "inst-1".into(),
        charter: "support".into(),
        version: "1.0".into(),
        scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
        parent_token: None,
    }
}

fn backend_cfg(name: &str, url: &str, tools: &[&str]) -> BackendConfig {
    BackendConfig {
        name: name.into(),
        url: url.into(),
        auth: BackendAuth::None,
        tools: tools.iter().map(|s| (*s).to_owned()).collect(),
    }
}

// ── Pillar 3: Signed token exchange ──────────────────────────────

#[test]
fn signed_exchange_token_verifies_with_ed25519() {
    let seed = [42u8; 32];
    let signer = av_harness::authz::TokenSigner::from_seed(&seed);

    let claims = test_claims(&["tool:read", "tool:write"]);
    let jwt = signer.sign(&claims).expect("signing must succeed");

    // The JWT has three dot-separated parts.
    assert_eq!(jwt.matches('.').count(), 2, "JWT must have 3 segments");

    // Decode the header and verify EdDSA + kid.
    let header = jsonwebtoken::decode_header(&jwt).unwrap();
    assert_eq!(header.alg, jsonwebtoken::Algorithm::EdDSA);
    assert!(header.kid.is_some(), "header must carry kid");
    assert_eq!(header.kid.as_deref().unwrap(), signer.kid());

    // Build a DecodingKey from the same seed's public key and verify.
    let receipt_signer = av_receipts::Ed25519Signer::from_seed(&seed);
    let pk_bytes = av_receipts::Signer::public_key_bytes(&receipt_signer);
    let decoding_key = jsonwebtoken::DecodingKey::from_ed_components(&base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        pk_bytes,
    ))
    .unwrap();
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
    validation.validate_exp = false;
    validation.validate_aud = false;
    validation.required_spec_claims.clear();
    let decoded = jsonwebtoken::decode::<av_identity::NhiClaims>(&jwt, &decoding_key, &validation)
        .expect("JWT must verify");
    assert_eq!(decoded.claims.sub, "user:alice@corp.com");
}

#[test]
fn signed_intent_token_is_valid_jwt() {
    let seed = [43u8; 32];
    let signer = std::sync::Arc::new(av_harness::authz::TokenSigner::from_seed(&seed));

    let mut config = av_harness::config::HarnessConfig::for_tests("http://127.0.0.1:9", "/tmp", "/tmp");
    config.intent_map.insert("db_write".into(), "data.mutate".into());

    let pdp = av_harness::authz::PolicyDecisionPoint::from_config(&config, Some(signer.clone()));
    let now_s = av_core::time::now_ms() / 1000;

    let intent = match pdp.decide("db_write", now_s) {
        av_harness::authz::AuthzDecision::Permit { intent } => intent,
        av_harness::authz::AuthzDecision::Deny { .. } => panic!("expected permit"),
    };
    assert_eq!(intent, "data.mutate");
    let token = pdp
        .mint_intent_token("db_write", &intent, "inst-1", "db-backend", now_s)
        .expect("must have intent token");
    assert_eq!(token.matches('.').count(), 2, "intent token must be a signed JWT");
    let header = jsonwebtoken::decode_header(&token).unwrap();
    assert_eq!(header.alg, jsonwebtoken::Algorithm::EdDSA);
    assert_eq!(header.typ.as_deref(), Some(av_harness::authz::INTENT_TOKEN_TYP));
}

// ── JWKS endpoint ────────────────────────────────────────────────

#[test]
fn jwks_contains_ed25519_key_matching_signer() {
    let seed = [44u8; 32];
    let signer = av_harness::authz::TokenSigner::from_seed(&seed);
    let jwks = signer.jwks_json();
    let keys = jwks["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 1);
    let key = &keys[0];
    assert_eq!(key["kty"], "OKP");
    assert_eq!(key["crv"], "Ed25519");
    assert_eq!(key["alg"], "EdDSA");
    assert_eq!(key["use"], "sig");
    assert_eq!(key["kid"], signer.kid());
    assert!(key["x"].is_string(), "x (public key) must be present");

    // Verify that the public key in JWKS can verify a token signed by this signer.
    let claims = test_claims(&["tool:read"]);
    let jwt = signer.sign(&claims).unwrap();
    let x_b64 = key["x"].as_str().unwrap();
    let decoding_key = jsonwebtoken::DecodingKey::from_ed_components(x_b64).unwrap();
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
    validation.validate_exp = false;
    validation.validate_aud = false;
    validation.required_spec_claims.clear();
    let decoded = jsonwebtoken::decode::<av_identity::NhiClaims>(&jwt, &decoding_key, &validation)
        .expect("JWKS public key must verify tokens signed by the same signer");
    assert_eq!(decoded.claims.sub, "user:alice@corp.com");
}

// ── Config validation: new fields ────────────────────────────────

#[test]
fn validate_require_mapping_with_empty_map() {
    let mut config = av_harness::config::HarnessConfig::for_tests("http://127.0.0.1:9", "/tmp", "/tmp");
    config.require_intent_mapping = true;
    config.intent_map.clear();
    let err = config.validate().unwrap_err();
    assert!(err.contains("intent_map is empty"), "got: {err}");
}

#[test]
fn validate_exchange_without_seed() {
    let mut config = av_harness::config::HarnessConfig::for_tests("http://127.0.0.1:9", "/tmp", "/tmp");
    config.token_exchange_enabled = true;
    config.token_exchange_seed_file = None;
    let err = config.validate().unwrap_err();
    assert!(err.contains("token_exchange_seed_file"), "got: {err}");
}

#[test]
fn validate_zero_intent_ttl() {
    let mut config = av_harness::config::HarnessConfig::for_tests("http://127.0.0.1:9", "/tmp", "/tmp");
    config.intent_token_ttl_s = 0;
    let err = config.validate().unwrap_err();
    assert!(err.contains("intent_token_ttl_s"), "got: {err}");
}

// ── HTTP-level integration tests (router.oneshot) ───────────────

#[tokio::test]
async fn jwks_endpoint_returns_empty_keys_without_signer() {
    let state = common::app_state(
        common::leaked_test_config(),
        Sandbox::new(SandboxConfig::default(), Vec::new()).unwrap(),
        Arc::new(common::CountingBus::default()),
        1,
    );
    let router = av_harness::build_router((*state).clone());
    let req = axum::http::Request::builder()
        .uri("/.well-known/jwks.json")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = tower::ServiceExt::oneshot(router, req).await.unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1 << 16).await.unwrap();
    let jwks: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let keys = jwks["keys"].as_array().unwrap();
    assert!(keys.is_empty(), "no signer configured → empty JWKS");
}

#[tokio::test]
async fn jwks_endpoint_returns_key_when_signer_present() {
    let seed = [55u8; 32];
    let dir = tempfile::tempdir().unwrap();
    let seed_path = dir.path().join("exchange.key");
    std::fs::write(&seed_path, hex::encode(seed)).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&seed_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    let mut config = common::leaked_test_config();
    config.token_exchange_enabled = true;
    config.token_exchange_seed_file = Some(seed_path.to_string_lossy().into_owned());
    let state = common::app_state(
        config,
        Sandbox::new(SandboxConfig::default(), Vec::new()).unwrap(),
        Arc::new(common::CountingBus::default()),
        2,
    );
    let router = av_harness::build_router((*state).clone());
    let req = axum::http::Request::builder()
        .uri("/.well-known/jwks.json")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = tower::ServiceExt::oneshot(router, req).await.unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1 << 16).await.unwrap();
    let jwks: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let keys = jwks["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 1, "one key in JWKS");
    assert_eq!(keys[0]["kty"], "OKP");
    assert_eq!(keys[0]["crv"], "Ed25519");
    assert_eq!(keys[0]["alg"], "EdDSA");
}

#[tokio::test]
async fn exchange_endpoint_disabled_returns_404() {
    let mut config = common::leaked_test_config();
    config.token_exchange_enabled = false;
    let state = common::app_state(
        config,
        Sandbox::new(SandboxConfig::default(), Vec::new()).unwrap(),
        Arc::new(common::CountingBus::default()),
        1,
    );
    let router = av_harness::build_router((*state).clone());
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/token")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(axum::body::Body::from("grant_type=foo"))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(router, req).await.unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn exchange_endpoint_requires_identity_validator() {
    let seed = [56u8; 32];
    let dir = tempfile::tempdir().unwrap();
    let seed_path = dir.path().join("exchange.key");
    std::fs::write(&seed_path, hex::encode(seed)).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&seed_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mut config = common::leaked_test_config();
    config.token_exchange_enabled = true;
    config.token_exchange_seed_file = Some(seed_path.to_string_lossy().into_owned());
    let state = common::app_state(
        config,
        Sandbox::new(SandboxConfig::default(), Vec::new()).unwrap(),
        Arc::new(common::CountingBus::default()),
        2,
    );
    let router = av_harness::build_router((*state).clone());
    let form_body = "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange\
        &subject_token=x&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt\
        &audience=backend-a";
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/token")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(form_body))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(router, req).await.unwrap();
    assert_eq!(
        resp.status(),
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        "exchange without identity validator must return 500"
    );
}

#[test]
fn exchange_request_parses_from_form_urlencoded() {
    let form = "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange\
        &subject_token=eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.e30.sig\
        &subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt\
        &audience=backend-a\
        &scope=tool%3Aread";
    let req: av_identity::TokenExchangeRequest = serde_urlencoded::from_str(form).unwrap();
    assert_eq!(req.grant_type, av_identity::TOKEN_EXCHANGE_GRANT_TYPE);
    assert_eq!(req.subject_token_type, av_identity::exchange::JWT_TOKEN_TYPE);
    assert_eq!(req.audience, "backend-a");
    assert_eq!(req.scope.as_deref(), Some("tool:read"));
}

// ── Config validation: exchange TTL boundaries ──────────────────

#[test]
fn validate_zero_exchange_ttl() {
    let mut config = av_harness::config::HarnessConfig::for_tests("http://127.0.0.1:9", "/tmp", "/tmp");
    config.token_exchange_ttl_s = 0;
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("token_exchange_ttl_s"),
        "zero exchange TTL must be rejected, got: {err}"
    );
}

#[test]
fn validate_exchange_ttl_above_ceiling() {
    let mut config = av_harness::config::HarnessConfig::for_tests("http://127.0.0.1:9", "/tmp", "/tmp");
    config.token_exchange_ttl_s = 901;
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("900"),
        "exchange TTL above 900 must be rejected, got: {err}"
    );
}

#[test]
fn validate_exchange_ttl_at_ceiling_passes() {
    let mut config = av_harness::config::HarnessConfig::for_tests("http://127.0.0.1:9", "/tmp", "/tmp");
    config.token_exchange_ttl_s = 900;
    assert!(
        config.validate().is_ok(),
        "exchange TTL of exactly 900 must pass validation"
    );
}

// ── RFC 6749 §5.2 error format ──────────────────────────────────

#[tokio::test]
async fn exchange_error_response_follows_oauth_format() {
    let seed = [78u8; 32];
    let dir = tempfile::tempdir().unwrap();
    let seed_path = dir.path().join("exchange.key");
    std::fs::write(&seed_path, hex::encode(seed)).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&seed_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mut config = common::leaked_test_config();
    config.token_exchange_enabled = true;
    config.token_exchange_seed_file = Some(seed_path.to_string_lossy().into_owned());
    let state = common::app_state_with_identity(
        config,
        Sandbox::new(SandboxConfig::default(), Vec::new()).unwrap(),
        Arc::new(common::CountingBus::default()),
        2,
        HMAC_SECRET,
        HMAC_KID,
    );
    let router = av_harness::build_router((*state).clone());
    let form_body = "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange\
        &subject_token=x&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt\
        &audience=backend-a";
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/token")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(form_body))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(router, req).await.unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(resp.into_body(), 1 << 16).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "invalid_request");
    assert!(
        json.get("error").is_some(),
        "OAuth error response must have 'error' field, got: {json}"
    );
    assert!(
        json.get("error_description").is_some(),
        "OAuth error response must have 'error_description' field, got: {json}"
    );
}

// ── Backend router: StaticFile permission check ─────────────────

#[test]
fn backend_static_file_rejects_world_readable() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secret.key");
    std::fs::write(&path, "super-secret-key").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    let configs = vec![BackendConfig {
        name: "insecure".into(),
        url: "http://backend:8080".into(),
        auth: BackendAuth::StaticFile(path.to_string_lossy().into_owned()),
        tools: vec!["tool_a".into()],
    }];
    let result = av_harness::backend::BackendRouter::new(&configs, None, None);
    #[cfg(unix)]
    assert!(result.is_err(), "world-readable secret file must be rejected");
}

#[test]
fn backend_static_file_accepts_owner_only() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secret.key");
    std::fs::write(&path, "super-secret-key").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let configs = vec![BackendConfig {
        name: "secure".into(),
        url: "http://backend:8080".into(),
        auth: BackendAuth::StaticFile(path.to_string_lossy().into_owned()),
        tools: vec!["tool_a".into()],
    }];
    let result = av_harness::backend::BackendRouter::new(&configs, None, None);
    assert!(
        result.is_ok(),
        "owner-only secret file must be accepted, got: {:?}",
        result.err()
    );
}

// ── Config: exchange backend requires identity + seed ───────────

#[test]
fn validate_exchange_backend_without_identity() {
    let mut config = av_harness::config::HarnessConfig::for_tests("http://127.0.0.1:9", "/tmp", "/tmp");
    config.require_identity = false;
    config.backends.push(BackendConfig {
        name: "ext".into(),
        url: "http://ext:8080".into(),
        auth: BackendAuth::Exchange,
        tools: vec!["ext_tool".into()],
    });
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("require_identity"),
        "exchange backend without require_identity must be rejected, got: {err}"
    );
}

#[test]
fn validate_exchange_backend_without_seed() {
    let mut config = av_harness::config::HarnessConfig::for_tests("http://127.0.0.1:9", "/tmp", "/tmp");
    config.require_identity = true;
    config.token_exchange_seed_file = None;
    config.backends.push(BackendConfig {
        name: "ext".into(),
        url: "http://ext:8080".into(),
        auth: BackendAuth::Exchange,
        tools: vec!["ext_tool".into()],
    });
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("token_exchange_seed_file"),
        "exchange backend without seed must be rejected, got: {err}"
    );
}

// ── Exchange endpoint: full success path ────────────────────────

#[tokio::test]
async fn exchange_endpoint_returns_valid_signed_token() {
    let hmac_secret = b"test-hmac-secret-for-exchange-test-0123";
    let hmac_kid = "test-kid";
    let exchange_seed = [99u8; 32];
    let dir = tempfile::tempdir().unwrap();
    let seed_path = dir.path().join("exchange.key");
    std::fs::write(&seed_path, hex::encode(exchange_seed)).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&seed_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mut config = common::leaked_test_config();
    config.token_exchange_enabled = true;
    config.token_exchange_seed_file = Some(seed_path.to_string_lossy().into_owned());
    config.token_exchange_ttl_s = 123;
    config.backends.push(BackendConfig {
        name: "backend-a".into(),
        url: "http://backend-a:8080".into(),
        auth: BackendAuth::None,
        tools: vec!["tool_a".into()],
    });
    let state = common::app_state_with_identity(
        config,
        Sandbox::new(SandboxConfig::default(), Vec::new()).unwrap(),
        Arc::new(common::CountingBus::default()),
        2,
        hmac_secret,
        hmac_kid,
    );

    let now_s = av_core::time::now_ms() / 1000;
    let subject_claims = av_identity::NhiClaims {
        sub: "user:alice@corp.com".into(),
        iss: "test-issuer".into(),
        aud: av_identity::Audience::Single(state.config.audience.clone()),
        iat: now_s,
        nbf: None,
        exp: now_s + 300,
        jti: "jti-subject-1".into(),
        azp: Some("client-app".into()),
        act: None,
        instance_uid: "inst-001".into(),
        charter: "billing-agent".into(),
        version: "1.0".into(),
        scopes: vec!["tool:read".into(), "tool:write".into()],
        parent_token: None,
    };
    let header = jsonwebtoken::Header {
        alg: jsonwebtoken::Algorithm::HS256,
        kid: Some(hmac_kid.to_owned()),
        ..Default::default()
    };
    let encoding_key = jsonwebtoken::EncodingKey::from_secret(hmac_secret);
    let subject_jwt = jsonwebtoken::encode(&header, &subject_claims, &encoding_key).unwrap();

    let form_body = format!(
        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange\
         &subject_token={subject_jwt}\
         &subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt\
         &audience=backend-a\
         &scope=tool%3Aread"
    );
    let router = av_harness::build_router((*state).clone());
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/token")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(form_body))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(router, req).await.unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);

    let resp_headers = resp.headers().clone();
    assert_eq!(
        resp_headers.get("cache-control").and_then(|v| v.to_str().ok()),
        Some("no-store"),
        "RFC 6749 §5.1: success response must carry Cache-Control: no-store"
    );
    assert_eq!(
        resp_headers.get("pragma").and_then(|v| v.to_str().ok()),
        Some("no-cache"),
        "RFC 6749 §5.1: success response must carry Pragma: no-cache"
    );

    let body = axum::body::to_bytes(resp.into_body(), 1 << 16).await.unwrap();
    let token_resp: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(token_resp["token_type"], "Bearer");
    assert_eq!(token_resp["expires_in"], 123);
    assert_eq!(token_resp["scope"], "tool:read");

    let access_token = token_resp["access_token"].as_str().unwrap();
    let signer = av_harness::authz::TokenSigner::from_seed(&exchange_seed);
    let jwks = signer.jwks_json();
    let x_b64 = jwks["keys"][0]["x"].as_str().unwrap();
    let decoding_key = jsonwebtoken::DecodingKey::from_ed_components(x_b64).unwrap();
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
    validation.validate_exp = false;
    validation.validate_aud = false;
    validation.required_spec_claims.clear();
    let decoded = jsonwebtoken::decode::<av_identity::NhiClaims>(access_token, &decoding_key, &validation)
        .expect("exchanged token must verify with the exchange signer's public key");
    assert_eq!(
        decoded.claims.sub, "user:alice@corp.com",
        "sub must be the human principal"
    );
    assert_eq!(
        decoded.claims.aud,
        av_identity::Audience::Single("backend-a".to_owned())
    );
    assert_eq!(
        decoded.claims.iss, state.config.audience,
        "iss must be the gateway"
    );
    assert_eq!(
        decoded.claims.azp.as_deref(),
        Some("inst-001"),
        "azp must be the calling agent's instance_uid"
    );
    assert_eq!(
        decoded.claims.exp - decoded.claims.iat,
        123,
        "TTL must match token_exchange_ttl_s"
    );
    let act = decoded
        .claims
        .act
        .as_ref()
        .expect("act claim must be present for delegation");
    assert_eq!(act.sub, "inst-001", "act.sub must identify the calling agent");
    assert_eq!(
        decoded.claims.scopes,
        vec!["tool:read"],
        "scopes must be the intersection"
    );
}

#[tokio::test]
async fn exchange_endpoint_rejects_unknown_audience() {
    let hmac_secret = b"test-hmac-secret-for-exchange-test-0123";
    let hmac_kid = "test-kid";
    let exchange_seed = [99u8; 32];
    let dir = tempfile::tempdir().unwrap();
    let seed_path = dir.path().join("exchange.key");
    std::fs::write(&seed_path, hex::encode(exchange_seed)).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&seed_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mut config = common::leaked_test_config();
    config.token_exchange_enabled = true;
    config.token_exchange_seed_file = Some(seed_path.to_string_lossy().into_owned());
    config.backends.push(BackendConfig {
        name: "backend-a".into(),
        url: "http://backend-a:8080".into(),
        auth: BackendAuth::None,
        tools: vec!["tool_a".into()],
    });
    let state = common::app_state_with_identity(
        config,
        Sandbox::new(SandboxConfig::default(), Vec::new()).unwrap(),
        Arc::new(common::CountingBus::default()),
        2,
        hmac_secret,
        hmac_kid,
    );

    let now_s = av_core::time::now_ms() / 1000;
    let subject_claims = av_identity::NhiClaims {
        sub: "user:bob@corp.com".into(),
        iss: "test-issuer".into(),
        aud: av_identity::Audience::Single(state.config.audience.clone()),
        iat: now_s,
        nbf: None,
        exp: now_s + 300,
        jti: "jti-aud-test".into(),
        azp: None,
        act: None,
        instance_uid: "inst-002".into(),
        charter: "default".into(),
        version: "1.0".into(),
        scopes: vec!["tool:read".into()],
        parent_token: None,
    };
    let header = jsonwebtoken::Header {
        alg: jsonwebtoken::Algorithm::HS256,
        kid: Some(hmac_kid.to_owned()),
        ..Default::default()
    };
    let encoding_key = jsonwebtoken::EncodingKey::from_secret(hmac_secret);
    let subject_jwt = jsonwebtoken::encode(&header, &subject_claims, &encoding_key).unwrap();

    let form_body = format!(
        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange\
         &subject_token={subject_jwt}\
         &subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt\
         &audience=not-a-backend"
    );
    let router = av_harness::build_router((*state).clone());
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/token")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(form_body))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(router, req).await.unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(resp.into_body(), 1 << 16).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "invalid_target");
}

#[tokio::test]
async fn exchange_endpoint_rejects_bad_grant_type() {
    let hmac_secret = b"test-hmac-secret-for-exchange-test-0123";
    let hmac_kid = "test-kid";
    let exchange_seed = [99u8; 32];
    let dir = tempfile::tempdir().unwrap();
    let seed_path = dir.path().join("exchange.key");
    std::fs::write(&seed_path, hex::encode(exchange_seed)).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&seed_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mut config = common::leaked_test_config();
    config.token_exchange_enabled = true;
    config.token_exchange_seed_file = Some(seed_path.to_string_lossy().into_owned());
    let state = common::app_state_with_identity(
        config,
        Sandbox::new(SandboxConfig::default(), Vec::new()).unwrap(),
        Arc::new(common::CountingBus::default()),
        2,
        hmac_secret,
        hmac_kid,
    );
    let router = av_harness::build_router((*state).clone());
    let form_body = "grant_type=authorization_code&subject_token=x\
        &subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt\
        &audience=backend-a";
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/token")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(form_body))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(router, req).await.unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(resp.into_body(), 1 << 16).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "unsupported_grant_type");
}

#[tokio::test]
async fn exchange_endpoint_rejects_garbage_subject_token() {
    let hmac_secret = b"test-hmac-secret-for-exchange-test-0123";
    let hmac_kid = "test-kid";
    let exchange_seed = [99u8; 32];
    let dir = tempfile::tempdir().unwrap();
    let seed_path = dir.path().join("exchange.key");
    std::fs::write(&seed_path, hex::encode(exchange_seed)).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&seed_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mut config = common::leaked_test_config();
    config.token_exchange_enabled = true;
    config.token_exchange_seed_file = Some(seed_path.to_string_lossy().into_owned());
    config.backends.push(BackendConfig {
        name: "backend-a".into(),
        url: "http://backend-a:8080".into(),
        auth: BackendAuth::None,
        tools: vec!["tool_a".into()],
    });
    let state = common::app_state_with_identity(
        config,
        Sandbox::new(SandboxConfig::default(), Vec::new()).unwrap(),
        Arc::new(common::CountingBus::default()),
        2,
        hmac_secret,
        hmac_kid,
    );
    let router = av_harness::build_router((*state).clone());
    let form_body = "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange\
        &subject_token=not-a-jwt-at-all\
        &subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt\
        &audience=backend-a";
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/token")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(form_body))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(router, req).await.unwrap();
    assert_eq!(
        resp.status(),
        axum::http::StatusCode::BAD_REQUEST,
        "garbage subject token must be rejected"
    );
    let body = axum::body::to_bytes(resp.into_body(), 1 << 16).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        json["error"], "invalid_request",
        "garbage subject token is invalid_request under RFC 8693 section 2.2.2"
    );
}

#[tokio::test]
async fn exchange_endpoint_rejects_disjoint_scopes() {
    let hmac_secret = b"test-hmac-secret-for-exchange-test-0123";
    let hmac_kid = "test-kid";
    let exchange_seed = [99u8; 32];
    let dir = tempfile::tempdir().unwrap();
    let seed_path = dir.path().join("exchange.key");
    std::fs::write(&seed_path, hex::encode(exchange_seed)).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&seed_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mut config = common::leaked_test_config();
    config.token_exchange_enabled = true;
    config.token_exchange_seed_file = Some(seed_path.to_string_lossy().into_owned());
    config.backends.push(BackendConfig {
        name: "backend-a".into(),
        url: "http://backend-a:8080".into(),
        auth: BackendAuth::None,
        tools: vec!["tool_a".into()],
    });
    let state = common::app_state_with_identity(
        config,
        Sandbox::new(SandboxConfig::default(), Vec::new()).unwrap(),
        Arc::new(common::CountingBus::default()),
        2,
        hmac_secret,
        hmac_kid,
    );

    let now_s = av_core::time::now_ms() / 1000;
    let subject_claims = av_identity::NhiClaims {
        sub: "user:alice@corp.com".into(),
        iss: "test-issuer".into(),
        aud: av_identity::Audience::Single(state.config.audience.clone()),
        iat: now_s,
        nbf: None,
        exp: now_s + 300,
        jti: "jti-scope-test".into(),
        azp: Some("client-app".into()),
        act: None,
        instance_uid: "inst-001".into(),
        charter: "billing-agent".into(),
        version: "1.0".into(),
        scopes: vec!["chat:write".into()],
        parent_token: None,
    };
    let header = jsonwebtoken::Header {
        alg: jsonwebtoken::Algorithm::HS256,
        kid: Some(hmac_kid.to_owned()),
        ..Default::default()
    };
    let encoding_key = jsonwebtoken::EncodingKey::from_secret(hmac_secret);
    let subject_jwt = jsonwebtoken::encode(&header, &subject_claims, &encoding_key).unwrap();

    let form_body = format!(
        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange\
         &subject_token={subject_jwt}\
         &subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt\
         &audience=backend-a\
         &scope=admin%3Aall"
    );
    let router = av_harness::build_router((*state).clone());
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/token")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(form_body))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(router, req).await.unwrap();
    assert_eq!(
        resp.status(),
        axum::http::StatusCode::BAD_REQUEST,
        "disjoint scopes must be rejected"
    );
    let body = axum::body::to_bytes(resp.into_body(), 1 << 16).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        json["error"], "invalid_scope",
        "requesting scopes the subject does not hold is invalid_scope"
    );
}

// ── Pillar 4: Backend isolation (live tool calls through the router) ─

const HMAC_SECRET: &[u8] = b"test-hmac-secret-for-exchange-test-0123";
const HMAC_KID: &str = "test-kid";
const EXCHANGE_SEED: [u8; 32] = [99u8; 32];

type Request = axum::http::Request<axum::body::Body>;

/// Harness with an HMAC identity validator, an exchange signing seed, and
/// `backends`. `tweak` edits the config before `AppState::new` runs, so
/// every derived component sees the final config.
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
    let seed_path = common::owner_only_file(dir.path(), "exchange.key", &hex::encode(EXCHANGE_SEED));
    let mut config = common::leaked_test_config();
    config.require_identity = true;
    config.token_exchange_seed_file = Some(seed_path);
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

fn backend(name: &str, url: &str, auth: BackendAuth, tools: &[&str]) -> BackendConfig {
    BackendConfig {
        name: name.into(),
        url: url.into(),
        auth,
        tools: tools.iter().map(|tool| (*tool).to_owned()).collect(),
    }
}

fn caller_token(state: &av_harness::AppState, scopes: &[&str], jti: &str) -> String {
    common::mint_nhi_token(
        HMAC_SECRET,
        HMAC_KID,
        &state.config.audience,
        &common::NhiSpec {
            sub: "user:bob@acme.io",
            instance_uid: "inst-backend-test",
            scopes,
            jti,
        },
    )
}

fn tool_call(session: &str, bearer: Option<&str>, tool: &str, id: u64) -> Request {
    let body = serde_json::to_vec(&serde_json::json!({
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
    headers: axum::http::HeaderMap,
    json: serde_json::Value,
}

async fn send(state: &Arc<av_harness::AppState>, request: Request) -> Reply {
    let router = av_harness::build_router((**state).clone());
    let response = tower::ServiceExt::oneshot(router, request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap();
    let json = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
    Reply {
        status,
        headers,
        json,
    }
}

async fn served_jwks(state: &Arc<av_harness::AppState>) -> serde_json::Value {
    let request = axum::http::Request::builder()
        .uri("/.well-known/jwks.json")
        .body(axum::body::Body::empty())
        .unwrap();
    let reply = send(state, request).await;
    assert_eq!(reply.status, 200);
    reply.json
}

fn bearer_of(request: &common::CapturedRequest) -> &str {
    request
        .header("authorization")
        .and_then(|value| value.strip_prefix("Bearer "))
        .expect("backend must receive a Bearer credential")
}

#[tokio::test]
async fn exchange_backend_gets_a_least_privilege_token_and_never_the_caller_bearer() {
    let upstream = common::MockBackend::start().await;
    let (state, _dir) = gateway(
        vec![backend(
            "secure-backend",
            &upstream.url,
            BackendAuth::Exchange,
            &["lookup"],
        )],
        |config| config.token_exchange_ttl_s = 120,
    );
    assert!(
        state.config.tool_upstream_url.is_none(),
        "this is a backends-only deployment: no tool_upstream_url"
    );
    let caller = caller_token(&state, &["tool:lookup", "chat:write", "payout:send"], "jti-a");

    let reply = send(&state, tool_call("p4-exchange", Some(&caller), "lookup", 7)).await;
    assert_eq!(reply.status, 200, "forwarded call must succeed: {}", reply.json);
    assert_eq!(reply.json["id"], 7);
    assert_eq!(reply.json["result"]["content"][0]["text"], "ok");

    let received = upstream.requests();
    assert_eq!(received.len(), 1, "exactly one forwarded request");
    let forwarded = &received[0];
    assert!(
        !forwarded.everything().contains(&caller),
        "the caller's NHI bearer must never reach a backend"
    );

    let jwks = served_jwks(&state).await;
    let bearer = bearer_of(forwarded);
    let header = jsonwebtoken::decode_header(bearer).unwrap();
    assert_eq!(header.alg, jsonwebtoken::Algorithm::EdDSA);
    assert_eq!(header.kid.as_deref(), jwks["keys"][0]["kid"].as_str());
    let token = common::verify_with_jwks::<av_identity::NhiClaims>(&jwks, bearer).claims;
    assert_eq!(token.sub, "user:bob@acme.io", "sub stays the human principal");
    assert_eq!(token.aud, av_identity::Audience::Single("secure-backend".into()));
    assert_eq!(token.iss, state.config.audience);
    assert_eq!(token.azp.as_deref(), Some("inst-backend-test"));
    assert_eq!(
        token.act.as_ref().map(|actor| actor.sub.as_str()),
        Some("inst-backend-test")
    );
    assert_eq!(
        token.scopes,
        vec!["tool:lookup"],
        "only the called tool's scope may reach the backend"
    );
    assert_eq!(token.exp - token.iat, 120);

    let intent_jwt = forwarded
        .header("x-av-intent-token")
        .expect("a signed intent token must accompany the call");
    let intent_header = jsonwebtoken::decode_header(intent_jwt).unwrap();
    assert_eq!(
        intent_header.typ.as_deref(),
        Some(av_harness::authz::INTENT_TOKEN_TYP)
    );
    let intent = common::verify_with_jwks::<av_harness::authz::IntentClaims>(&jwks, intent_jwt).claims;
    assert_eq!(
        intent.aud, "secure-backend",
        "intent tokens are bound to their backend"
    );
    assert_eq!(intent.iss, state.config.audience);
    assert_eq!(
        intent.sub, "inst-backend-test",
        "intent tokens name the calling agent"
    );
    assert_eq!(intent.tool, "lookup");
    assert_eq!(intent.intent, "lookup");
}

#[tokio::test]
async fn exchange_backend_narrows_a_wildcard_grant_to_the_called_tool() {
    let upstream = common::MockBackend::start().await;
    let (state, _dir) = gateway(
        vec![backend(
            "secure-backend",
            &upstream.url,
            BackendAuth::Exchange,
            &["lookup"],
        )],
        |_| {},
    );
    let caller = caller_token(&state, &["tool:*"], "jti-wildcard");
    let reply = send(&state, tool_call("p4-wildcard", Some(&caller), "lookup", 1)).await;
    assert_eq!(reply.status, 200, "{}", reply.json);
    let jwks = served_jwks(&state).await;
    let received = upstream.requests();
    let token = common::verify_with_jwks::<av_identity::NhiClaims>(&jwks, bearer_of(&received[0])).claims;
    assert_eq!(token.scopes, vec!["tool:lookup"]);
}

#[tokio::test]
async fn refused_exchange_refunds_the_budget_and_leaves_no_pending_claim() {
    let upstream = common::MockBackend::start().await;
    let (state, _dir) = gateway(
        vec![backend(
            "secure-backend",
            &upstream.url,
            BackendAuth::Exchange,
            &["lookup"],
        )],
        |config| config.budget.max_total_tool_calls = Some(1),
    );
    let unscoped = caller_token(&state, &["chat:write"], "jti-unscoped");
    for attempt in 0..3 {
        let reply = send(&state, tool_call("p4-refund", Some(&unscoped), "lookup", 1)).await;
        assert_eq!(reply.status, 403, "attempt {attempt}: {}", reply.json);
        assert!(
            reply.json.to_string().contains("backend token exchange failed"),
            "attempt {attempt} must fail at the exchange, not on budget or a stale claim: {}",
            reply.json
        );
    }
    assert!(
        upstream.requests().is_empty(),
        "a refused exchange must not reach the backend"
    );

    let scoped = caller_token(&state, &["tool:lookup"], "jti-scoped");
    let reply = send(&state, tool_call("p4-refund", Some(&scoped), "lookup", 1)).await;
    assert_eq!(
        reply.status, 200,
        "the one budgeted call must still be available after three refusals: {}",
        reply.json
    );
    assert_eq!(upstream.requests().len(), 1);

    let over_cap = send(&state, tool_call("p4-refund", Some(&scoped), "lookup", 2)).await;
    assert_eq!(over_cap.status, 403, "{}", over_cap.json);
    assert_eq!(
        over_cap.json["error"]["data"]["code"], "BUDGET_EXCEEDED",
        "the cap is real, so the successful call above proves the refunds happened"
    );
}

#[tokio::test]
async fn static_and_open_backends_never_see_the_caller_bearer_or_each_others_secret() {
    let static_upstream = common::MockBackend::start().await;
    let open_upstream = common::MockBackend::start().await;
    let secrets = tempfile::tempdir().unwrap();
    let secret_path = common::owner_only_file(secrets.path(), "static.token", "static-backend-secret\n");
    let (state, _dir) = gateway(
        vec![
            backend(
                "static-backend",
                &static_upstream.url,
                BackendAuth::StaticFile(secret_path),
                &["read_static"],
            ),
            backend(
                "open-backend",
                &open_upstream.url,
                BackendAuth::None,
                &["read_open"],
            ),
        ],
        |_| {},
    );
    let caller = caller_token(&state, &["tool:*"], "jti-static");
    assert_eq!(
        send(&state, tool_call("p4-static", Some(&caller), "read_static", 1))
            .await
            .status,
        200
    );
    assert_eq!(
        send(&state, tool_call("p4-static", Some(&caller), "read_open", 2))
            .await
            .status,
        200
    );

    let static_seen = static_upstream.requests();
    let open_seen = open_upstream.requests();
    assert_eq!((static_seen.len(), open_seen.len()), (1, 1));
    assert_eq!(
        static_seen[0].header("authorization"),
        Some("Bearer static-backend-secret")
    );
    assert_eq!(
        open_seen[0].header("authorization"),
        None,
        "an auth = none backend receives no credential at all"
    );
    for request in static_seen.iter().chain(&open_seen) {
        assert!(
            !request.everything().contains(&caller),
            "caller bearer leaked to a backend"
        );
    }
    assert!(
        !open_seen[0].everything().contains("static-backend-secret"),
        "one backend's credential must never reach another"
    );
}

#[tokio::test]
async fn tool_upstream_bearer_reaches_the_implicit_default_backend() {
    let upstream = common::MockBackend::start().await;
    let secrets = tempfile::tempdir().unwrap();
    let token_path = common::owner_only_file(secrets.path(), "tool.token", "tool-upstream-secret\n");
    let mut config = common::leaked_test_config();
    config.tool_upstream_url = Some(upstream.url.clone());
    config.tool_upstream_bearer_file = Some(token_path);
    // AppState::new sees the final config, as `agentvisord` does at boot.
    let sandbox = common::sandbox_for(&config);
    let state = common::app_state(config, sandbox, Arc::new(common::CountingBus::default()), 2);
    let reply = send(&state, tool_call("p4-default", None, "anything", 1)).await;
    assert_eq!(reply.status, 200, "{}", reply.json);
    let received = upstream.requests();
    assert_eq!(received.len(), 1);
    assert_eq!(
        received[0].header("authorization"),
        Some("Bearer tool-upstream-secret")
    );
}

#[tokio::test]
async fn each_tool_reaches_only_its_backend_and_unrouted_tools_are_decided_not_forwarded() {
    let alpha = common::MockBackend::start().await;
    let beta = common::MockBackend::start().await;
    let (state, _dir) = gateway(
        vec![
            backend("alpha", &alpha.url, BackendAuth::None, &["alpha_tool"]),
            backend("beta", &beta.url, BackendAuth::None, &["beta_tool"]),
        ],
        |_| {},
    );
    let caller = caller_token(&state, &["tool:*"], "jti-routing");
    assert_eq!(
        send(&state, tool_call("p4-route", Some(&caller), "alpha_tool", 1))
            .await
            .status,
        200
    );
    assert_eq!(
        send(&state, tool_call("p4-route", Some(&caller), "beta_tool", 2))
            .await
            .status,
        200
    );
    let unrouted = send(&state, tool_call("p4-route", Some(&caller), "unrouted_tool", 3)).await;
    assert_eq!(unrouted.status, 200, "{}", unrouted.json);
    assert_eq!(unrouted.json["result"]["allowed"], true);

    let (alpha_seen, beta_seen) = (alpha.requests(), beta.requests());
    assert_eq!((alpha_seen.len(), beta_seen.len()), (1, 1));
    assert!(String::from_utf8_lossy(&alpha_seen[0].body).contains("alpha_tool"));
    assert!(String::from_utf8_lossy(&beta_seen[0].body).contains("beta_tool"));
}

// ── Pillar 2: the PDP gates every mode before the budget is charged ─

async fn wait_for_event(
    bus: &common::RecordingBus,
    matches: impl Fn(&serde_json::Value) -> bool,
) -> serde_json::Value {
    for _ in 0..400 {
        if let Some(event) = bus.payloads.lock().iter().find(|event| matches(event)) {
            return event.clone();
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("expected audit event never reached the bus");
}

#[tokio::test]
async fn pdp_denials_are_uncharged_and_audited_as_denials_in_verdict_only_mode() {
    let bus = Arc::new(common::RecordingBus::default());
    let mut config = common::leaked_test_config();
    config.require_intent_mapping = true;
    config.intent_map.insert("search".into(), "data.read".into());
    config.budget.max_total_tool_calls = Some(1);
    let sandbox = common::sandbox_for(&config);
    let state = common::app_state(
        config,
        sandbox,
        Arc::clone(&bus) as Arc<dyn av_bridge::EventBus>,
        2,
    );
    assert!(
        state.config.tool_upstream_url.is_none() && state.backend_router.is_empty(),
        "verdict-only mode: nothing to forward to"
    );
    for id in 40..43 {
        let reply = send(&state, tool_call("p2-verdict", None, "unmapped", id)).await;
        assert_eq!(reply.status, 403, "{}", reply.json);
        assert_eq!(
            reply.json["id"], id,
            "JSON-RPC 2.0 §5: the error echoes the request id"
        );
        assert_eq!(reply.json["error"]["code"], -32001);
        assert_eq!(reply.json["error"]["data"]["code"], "UNMAPPED_TOOL");
    }
    let reply = send(&state, tool_call("p2-verdict", None, "search", 50)).await;
    assert_eq!(
        reply.status, 200,
        "denied calls were never charged, so the single budgeted call remains: {}",
        reply.json
    );
    assert_eq!(reply.json["result"]["allowed"], true);
    let over_cap = send(&state, tool_call("p2-verdict", None, "search", 51)).await;
    assert_eq!(over_cap.status, 403, "{}", over_cap.json);
    assert_eq!(
        over_cap.json["error"]["data"]["code"], "BUDGET_EXCEEDED",
        "the cap is real, so the allowed call above proves the denials were uncharged"
    );

    let denial = wait_for_event(&bus, |event| {
        event.pointer("/payload/denial_code") == Some(&serde_json::json!("UNMAPPED_TOOL"))
    })
    .await;
    assert_eq!(
        denial["payload"]["allowed"], false,
        "the audit trail must say denied"
    );
    assert_eq!(denial["payload"]["stage"], "policy");
    assert_eq!(denial["payload"]["policy"], "pdp.intent_map");
}

#[tokio::test]
async fn expired_mission_blocks_a_forwarded_call_before_any_backend_contact() {
    let upstream = common::MockBackend::start().await;
    let (state, _dir) = gateway(
        vec![backend(
            "ops",
            &upstream.url,
            BackendAuth::None,
            &["deploy_check"],
        )],
        |config| {
            config.intent_map.insert("deploy_check".into(), "ops.read".into());
            config.mission = Some(MissionConfig {
                id: "m-over".into(),
                allowed_intents: vec!["ops.read".into()],
                expires_at: 1,
            });
        },
    );
    let caller = caller_token(&state, &["tool:*"], "jti-mission");
    let reply = send(&state, tool_call("p2-mission", Some(&caller), "deploy_check", 9)).await;
    assert_eq!(reply.status, 403, "{}", reply.json);
    assert_eq!(reply.json["id"], 9);
    assert_eq!(reply.json["error"]["data"]["code"], "MISSION_EXPIRED");
    assert!(upstream.requests().is_empty());
}

// ── Pillar 3: exchange audiences are fail-closed ─────────────────

#[tokio::test]
async fn token_exchange_refuses_every_audience_when_no_backends_exist() {
    let (state, _dir) = gateway(Vec::new(), |config| config.token_exchange_enabled = true);
    let subject = caller_token(&state, &["tool:read"], "jti-no-backends");
    let reply = send(
        &state,
        form(
            "/v1/token",
            format!(
                "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange\
                 &subject_token={subject}\
                 &subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt\
                 &audience=https%3A%2F%2Fanything.example"
            ),
        ),
    )
    .await;
    assert_eq!(reply.status, 400, "{}", reply.json);
    assert_eq!(reply.json["error"], "invalid_target");
}

#[tokio::test]
async fn token_exchange_hides_identity_error_details() {
    let (state, _dir) = gateway(
        vec![backend(
            "backend-a",
            "http://backend-a:8080",
            BackendAuth::None,
            &["t"],
        )],
        |config| config.token_exchange_enabled = true,
    );
    let foreign_kid = common::mint_nhi_token(
        HMAC_SECRET,
        "some-unknown-kid",
        &state.config.audience,
        &common::NhiSpec {
            sub: "user:x",
            instance_uid: "inst-x",
            scopes: &["tool:read"],
            jti: "jti-x",
        },
    );
    let reply = send(
        &state,
        form(
            "/v1/token",
            format!(
                "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange\
                 &subject_token={foreign_kid}\
                 &subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt\
                 &audience=backend-a"
            ),
        ),
    )
    .await;
    assert_eq!(reply.status, 400);
    assert_eq!(reply.json["error"], "invalid_request");
    let description = reply.json["error_description"].as_str().unwrap();
    assert!(
        !description.contains("some-unknown-kid"),
        "the response must not echo configured or probed kids: {description}"
    );
}

#[test]
fn token_exchange_config_requires_backends_and_an_identity_source() {
    let mut config = av_harness::config::HarnessConfig::for_tests("http://127.0.0.1:9", "/tmp", "/tmp");
    config.token_exchange_enabled = true;
    config.token_exchange_seed_file = Some("/tmp/exchange.key".into());
    let error = config.validate().unwrap_err();
    assert!(error.contains("no [[backends]] are configured"), "{error}");
    assert!(error.contains("neither identity_jwks_url nor"), "{error}");
}

// ── Pillar 1: RFC 7009 revocation, end to end ─────────────────────

fn revoke_form(token: &str) -> Request {
    form(
        "/v1/revoke",
        format!("token={token}&token_type_hint=access_token"),
    )
}

#[tokio::test]
async fn revoked_token_is_refused_on_the_next_call_and_other_tokens_keep_working() {
    let upstream = common::MockBackend::start().await;
    let (state, _dir) = gateway(
        vec![backend("svc", &upstream.url, BackendAuth::None, &["lookup"])],
        |_| {},
    );
    let doomed = caller_token(&state, &["tool:*"], "jti-doomed");
    let survivor = caller_token(&state, &["tool:*"], "jti-survivor");
    assert_eq!(
        send(&state, tool_call("p1-revoke-a", Some(&doomed), "lookup", 1))
            .await
            .status,
        200
    );

    let reply = send(&state, revoke_form(&doomed)).await;
    assert_eq!(reply.status, 200);
    assert_eq!(
        reply.headers.get("cache-control").and_then(|v| v.to_str().ok()),
        Some("no-store")
    );

    let refused = send(&state, tool_call("p1-revoke-a", Some(&doomed), "lookup", 2)).await;
    assert_eq!(
        refused.status, 401,
        "a revoked token must be refused: {}",
        refused.json
    );
    assert_eq!(
        send(&state, tool_call("p1-revoke-b", Some(&survivor), "lookup", 3))
            .await
            .status,
        200,
        "revocation is per token, not per agent"
    );
    assert_eq!(
        upstream.requests().len(),
        2,
        "the refused call never reached the backend"
    );

    let again = send(&state, revoke_form(&doomed)).await;
    assert_eq!(again.status, 200, "revocation is idempotent (RFC 7009 §2.2)");
}

#[tokio::test]
async fn revocation_endpoint_answers_200_for_invalid_tokens_and_400_without_a_token() {
    let (state, _dir) = gateway(Vec::new(), |_| {});
    assert_eq!(send(&state, revoke_form("not-a-jwt")).await.status, 200);
    let forged = common::mint_nhi_token(
        b"attacker-secret-not-the-real-one-000000",
        HMAC_KID,
        &state.config.audience,
        &common::NhiSpec {
            sub: "user:x",
            instance_uid: "inst-x",
            scopes: &[],
            jti: "jti-forged",
        },
    );
    assert_eq!(send(&state, revoke_form(&forged)).await.status, 200);
    let missing = send(&state, form("/v1/revoke", "token_type_hint=access_token".into())).await;
    assert_eq!(missing.status, 400);
    assert_eq!(missing.json["error"], "invalid_request");
}

#[tokio::test]
async fn revocation_endpoint_is_absent_without_an_identity_validator() {
    let state = common::app_state(
        common::leaked_test_config(),
        Sandbox::new(SandboxConfig::default(), Vec::new()).unwrap(),
        Arc::new(common::CountingBus::default()),
        2,
    );
    assert_eq!(send(&state, revoke_form("anything")).await.status, 404);
}

struct UnreachableRevocationList;

impl RevocationStore for UnreachableRevocationList {
    fn revoke(&self, _jti: &str, _expires_at: u64) -> Result<(), String> {
        Err("redis unreachable".into())
    }

    fn is_revoked(&self, _jti: &str) -> Result<bool, String> {
        Err("redis unreachable".into())
    }
}

#[tokio::test]
async fn unreachable_revocation_list_fails_closed_with_503_everywhere() {
    let upstream = common::MockBackend::start().await;
    let (state, _dir) = gateway_with_revocation(
        vec![backend("svc", &upstream.url, BackendAuth::Exchange, &["lookup"])],
        |config| config.token_exchange_enabled = true,
        Arc::new(UnreachableRevocationList),
    );
    let caller = caller_token(&state, &["tool:*"], "jti-outage");

    let call = send(&state, tool_call("p1-outage", Some(&caller), "lookup", 1)).await;
    assert_eq!(
        call.status, 503,
        "a store outage is not the caller's fault: {}",
        call.json
    );
    assert!(call.headers.contains_key("retry-after"));

    let revoke = send(&state, revoke_form(&caller)).await;
    assert_eq!(revoke.status, 503, "RFC 7009 §2.2.1: the client must retry");
    assert_eq!(revoke.json["error"], "temporarily_unavailable");
    assert!(revoke.headers.contains_key("retry-after"));

    let exchange = send(
        &state,
        form(
            "/v1/token",
            format!(
                "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange\
                 &subject_token={caller}\
                 &subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt\
                 &audience=svc"
            ),
        ),
    )
    .await;
    assert_eq!(exchange.status, 503);
    assert_eq!(exchange.json["error"], "temporarily_unavailable");
    assert!(upstream.requests().is_empty());
}

#[tokio::test]
async fn revoking_a_token_stops_its_backend_exchanges() {
    let upstream = common::MockBackend::start().await;
    let (state, _dir) = gateway(
        vec![backend("svc", &upstream.url, BackendAuth::Exchange, &["lookup"])],
        |_| {},
    );
    let caller = caller_token(&state, &["tool:lookup"], "jti-exchange-revoked");
    assert_eq!(
        send(&state, tool_call("p1-exchange", Some(&caller), "lookup", 1))
            .await
            .status,
        200
    );
    assert_eq!(send(&state, revoke_form(&caller)).await.status, 200);
    assert_eq!(
        send(&state, tool_call("p1-exchange", Some(&caller), "lookup", 2))
            .await
            .status,
        401
    );
    assert_eq!(
        upstream.requests().len(),
        1,
        "no exchanged token is minted for a revoked caller"
    );
}

const OPERATOR_SECRET: &str = "operator-test-secret-with-at-least-32-bytes";
const BACKEND_SECRET: &str = "backend-test-secret-with-at-least-32-bytes";

fn configure_revocation_admin(config: &mut av_harness::HarnessConfig) {
    config
        .operator_tokens
        .push(av_harness::config::OperatorTokenConfig {
            name: "test-operator".into(),
            sha256: av_core::digest::sha256_hex(OPERATOR_SECRET.as_bytes()),
        });
    config
        .introspection_tokens
        .push(av_harness::config::IntrospectionTokenConfig {
            backend: "svc".into(),
            sha256: av_core::digest::sha256_hex(BACKEND_SECRET.as_bytes()),
        });
}

fn authorized(mut request: Request, secret: &str) -> Request {
    request
        .headers_mut()
        .insert("authorization", format!("Bearer {secret}").parse().unwrap());
    request
}

fn admin_request(body: serde_json::Value, secret: &str) -> Request {
    authorized(
        axum::http::Request::builder()
            .method("POST")
            .uri("/admin/v1/revocations")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap(),
        secret,
    )
}

async fn exchange_token(state: &Arc<av_harness::AppState>, subject: &str) -> String {
    let reply = send(state, form("/v1/token", format!(
        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&subject_token={subject}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt&audience=svc&scope=tool%3Alookup"
    ))).await;
    assert_eq!(reply.status, 200, "{}", reply.json);
    reply.json["access_token"].as_str().unwrap().to_owned()
}

async fn introspection(state: &Arc<av_harness::AppState>, token: &str) -> Reply {
    send(
        state,
        authorized(form("/v1/introspect", format!("token={token}")), BACKEND_SECRET),
    )
    .await
}

struct DelayedIntrospectionRead {
    entered: tokio::sync::oneshot::Sender<()>,
    resume: std::sync::mpsc::Receiver<Result<bool, String>>,
}

#[derive(Default)]
struct DelayedIntrospectionRevocations {
    next: std::sync::Mutex<Option<DelayedIntrospectionRead>>,
    reads: std::sync::atomic::AtomicUsize,
}

impl RevocationStore for DelayedIntrospectionRevocations {
    fn revoke(&self, _jti: &str, _expires_at: u64) -> Result<(), String> {
        Err("test store does not support writes".into())
    }

    fn is_revoked(&self, _jti: &str) -> Result<bool, String> {
        self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let pending = self.next.lock().unwrap().take();
        if let Some(pending) = pending {
            let _ = pending.entered.send(());
            pending
                .resume
                .recv_timeout(std::time::Duration::from_secs(12))
                .map_err(|error| error.to_string())?
        } else {
            Ok(false)
        }
    }
}

async fn delayed_introspection_expiry_case(expires_during_read: bool, store_failure: bool) {
    use std::sync::atomic::Ordering::SeqCst;
    use std::time::Duration;

    let store = Arc::new(DelayedIntrospectionRevocations::default());
    let (state, _dir) = gateway_with_revocation(
        vec![backend(
            "svc",
            "http://127.0.0.1:9",
            BackendAuth::Exchange,
            &["lookup"],
        )],
        |config| {
            config.token_exchange_enabled = true;
            config.token_exchange_ttl_s = if expires_during_read { 3 } else { 60 };
            configure_revocation_admin(config);
        },
        store.clone(),
    );
    let subject = caller_token(&state, &["tool:lookup"], "delayed-introspection-subject");
    let token = exchange_token(&state, &subject).await;
    let first = introspection(&state, &token).await;
    assert_eq!(first.status, 200);
    assert_eq!(first.json["active"], true, "the token must initially be usable");
    let expires = first.json["exp"].as_u64().unwrap();
    let reads_before = store.reads.load(SeqCst);
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (resume_tx, resume_rx) = std::sync::mpsc::channel();
    *store.next.lock().unwrap() = Some(DelayedIntrospectionRead {
        entered: entered_tx,
        resume: resume_rx,
    });
    let request_state = Arc::clone(&state);
    let request = tokio::spawn(async move { introspection(&request_state, &token).await });
    tokio::time::timeout(Duration::from_secs(2), entered_rx)
        .await
        .expect("valid token must reach revocation storage before it expires")
        .unwrap();
    assert!(av_core::time::now_ms() / 1000 < expires);
    assert!(
        !request.is_finished(),
        "the revocation read must actually be held"
    );
    if expires_during_read {
        // Cross a complete second beyond exp, rather than racing the exact
        // integer boundary. The dependency wait itself also has a hard bound.
        tokio::time::timeout(Duration::from_secs(6), async {
            while av_core::time::now_ms() / 1000 <= expires {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
    } else {
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(av_core::time::now_ms() / 1000 < expires);
    }
    resume_tx
        .send(if store_failure {
            Err("injected revocation outage".into())
        } else {
            Ok(false)
        })
        .unwrap();
    let reply = tokio::time::timeout(Duration::from_secs(3), request)
        .await
        .unwrap()
        .unwrap();
    if store_failure {
        assert_eq!(reply.status, 503);
        assert_eq!(reply.json, serde_json::json!({"error":"temporarily_unavailable"}));
        assert!(reply.headers.contains_key("retry-after"));
    } else if expires_during_read {
        assert_eq!(reply.status, 200);
        assert_eq!(
            reply.json,
            serde_json::json!({"active":false}),
            "introspection must not report active after expiry during storage lookup"
        );
    } else {
        assert_eq!(reply.status, 200);
        assert_eq!(reply.json["active"], true);
        assert_eq!(reply.json["exp"], expires);
    }
    assert_eq!(store.reads.load(SeqCst), reads_before + 1);
    assert_eq!(reply.headers.get("cache-control").unwrap(), "no-store");
    tokio::time::timeout(Duration::from_secs(2), state.mcp_inflight.wait_drained())
        .await
        .unwrap();
    assert_eq!(
        state.mcp_admission.available_permits(),
        state.config.mcp_concurrency
    );
    assert_eq!(state.sessions.len(), 0);
}

#[tokio::test]
async fn introspection_refreshes_expiry_after_delayed_revocation_read() {
    delayed_introspection_expiry_case(true, false).await;
}

#[tokio::test]
async fn introspection_refreshes_expiry_preserving_still_live_tokens() {
    delayed_introspection_expiry_case(false, false).await;
}

#[tokio::test]
async fn introspection_refreshes_expiry_preserving_revocation_outage() {
    delayed_introspection_expiry_case(true, true).await;
}

#[tokio::test]
async fn exchanged_tokens_and_their_ancestors_can_be_revoked() {
    let (state, _dir) = gateway(
        vec![backend(
            "svc",
            "http://127.0.0.1:9",
            BackendAuth::Exchange,
            &["lookup"],
        )],
        |config| {
            config.token_exchange_enabled = true;
            configure_revocation_admin(config);
        },
    );
    let subject = caller_token(&state, &["tool:lookup"], "exchange-parent");
    let first = exchange_token(&state, &subject).await;
    let second = exchange_token(&state, &subject).await;
    assert_eq!(introspection(&state, &first).await.json["active"], true);
    assert_eq!(send(&state, revoke_form(&first)).await.status, 200);
    assert_eq!(introspection(&state, &first).await.json["active"], false);
    assert_eq!(introspection(&state, &second).await.json["active"], true);
    assert_eq!(send(&state, revoke_form(&subject)).await.status, 200);
    assert_eq!(introspection(&state, &second).await.json["active"], false);
}

#[tokio::test]
async fn introspection_authenticates_backend_and_enforces_audience_and_token_type() {
    let (state, _dir) = gateway(
        vec![
            backend("svc", "http://127.0.0.1:9", BackendAuth::Exchange, &["lookup"]),
            backend("other", "http://127.0.0.1:9", BackendAuth::None, &["other"]),
        ],
        |config| {
            config.token_exchange_enabled = true;
            configure_revocation_admin(config);
        },
    );
    let subject = caller_token(&state, &["tool:lookup"], "introspection-parent");
    let token = exchange_token(&state, &subject).await;
    assert_eq!(
        send(&state, form("/v1/introspect", format!("token={token}")))
            .await
            .status,
        401
    );
    assert_eq!(
        send(
            &state,
            authorized(form("/v1/introspect", format!("token={token}")), OPERATOR_SECRET)
        )
        .await
        .status,
        401
    );
    assert_eq!(
        introspection(&state, &subject).await.json,
        serde_json::json!({"active": false})
    );
    let intent = av_harness::authz::TokenSigner::from_seed(&EXCHANGE_SEED).sign_with_typ(&serde_json::json!({"iss":state.config.audience,"aud":"svc","exp":av_core::time::now_ms()/1000+60}), av_harness::authz::INTENT_TOKEN_TYP).unwrap();
    assert_eq!(introspection(&state, &intent).await.json["active"], false);
    let foreign = send(&state, form("/v1/token", format!("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&subject_token={subject}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt&audience=other"))).await;
    assert_eq!(foreign.status, 200);
    assert_eq!(
        introspection(&state, foreign.json["access_token"].as_str().unwrap())
            .await
            .json["active"],
        false
    );
    let mut damaged = token.into_bytes();
    let last = damaged.len() - 10;
    damaged[last] = if damaged[last] == b'A' { b'B' } else { b'A' };
    assert_eq!(
        introspection(&state, std::str::from_utf8(&damaged).unwrap())
            .await
            .json["active"],
        false
    );
}

#[tokio::test]
async fn operator_revokes_by_jti_and_by_instance_without_holding_tokens() {
    let upstream = common::MockBackend::start().await;
    let (state, _dir) = gateway(
        vec![backend("svc", &upstream.url, BackendAuth::Exchange, &["lookup"])],
        |config| {
            config.token_exchange_enabled = true;
            configure_revocation_admin(config);
        },
    );
    let first = caller_token(&state, &["tool:lookup"], "admin-first");
    let second = caller_token(&state, &["tool:lookup"], "admin-second");
    let exchange = exchange_token(&state, &second).await;
    let body = serde_json::json!({"jti":"admin-first"});
    assert_eq!(
        send(&state, admin_request(body.clone(), &first)).await.status,
        401
    );
    assert_eq!(
        send(&state, admin_request(body, OPERATOR_SECRET)).await.json["audited"],
        true
    );
    assert_eq!(
        send(&state, tool_call("admin-first-call", Some(&first), "lookup", 1))
            .await
            .status,
        401
    );
    assert_eq!(
        send(&state, tool_call("admin-second-call", Some(&second), "lookup", 1))
            .await
            .status,
        200
    );
    assert_eq!(
        send(
            &state,
            admin_request(
                serde_json::json!({"instance_uid":"inst-backend-test"}),
                OPERATOR_SECRET
            )
        )
        .await
        .json["revoked"],
        true
    );
    assert_eq!(
        send(&state, tool_call("admin-second-call", Some(&second), "lookup", 2))
            .await
            .status,
        401
    );
    assert_eq!(introspection(&state, &exchange).await.json["active"], false);
    assert_eq!(upstream.requests().len(), 1);
    assert_eq!(
        send(
            &state,
            admin_request(
                serde_json::json!({"jti":"a", "instance_uid":"b"}),
                OPERATOR_SECRET
            )
        )
        .await
        .status,
        400
    );
}

#[tokio::test]
async fn revocation_audit_is_signed_deduplicated_and_contains_no_credentials() {
    let (state, _dir) = gateway(Vec::new(), |_| {});
    let token = caller_token(&state, &["tool:*"], "audited-revocation");
    let replies = futures::future::join_all((0..8).map(|_| send(&state, revoke_form(&token)))).await;
    assert!(replies.iter().all(|reply| reply.status == 200));
    let receipts: Vec<_> =
        std::fs::read_dir(std::path::Path::new(&state.config.atif_spool_dir).join("receipts"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
            .collect();
    assert_eq!(receipts.len(), 1);
    let bytes = std::fs::read(&receipts[0]).unwrap();
    assert!(!String::from_utf8_lossy(&bytes).contains(&token));
    let receipt: av_receipts::Receipt = serde_json::from_slice(&bytes).unwrap();
    receipt.verify(&common::ring(&[&common::signer(2)])).unwrap();
    let receipt_json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(
        receipt_json.to_string().contains("token-revoked-"),
        "{receipt_json}"
    );
    assert_eq!(send(&state, revoke_form("forged")).await.status, 200);
    assert_eq!(
        std::fs::read_dir(std::path::Path::new(&state.config.atif_spool_dir).join("receipts"))
            .unwrap()
            .count(),
        receipts.len()
    );
}

#[tokio::test]
async fn revocation_audit_budget_never_prevents_revocation() {
    let (state, _dir) = gateway(Vec::new(), |config| config.revocation_audit_per_minute = 1);
    let a = caller_token(&state, &["tool:*"], "budget-a");
    let b = caller_token(&state, &["tool:*"], "budget-b");
    for token in [&a, &b] {
        assert_eq!(send(&state, revoke_form(token)).await.status, 200);
    }
    let validator = state.identity.as_ref().unwrap();
    assert!(matches!(
        validator.validate(&a),
        Err(av_identity::IdentityError::Revoked(_))
    ));
    assert!(matches!(
        validator.validate(&b),
        Err(av_identity::IdentityError::Revoked(_))
    ));
    assert!(state
        .metrics
        .render()
        .contains("av_tokens_revoked_unaudited_total{reason=\"budget\"} 1"));
}

#[tokio::test]
async fn future_activation_token_can_be_revoked_before_it_becomes_valid() {
    let (state, _dir) = gateway(Vec::new(), |_| {});
    let token = caller_token(&state, &["tool:*"], "future-revocation");
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.set_audience(&[&state.config.audience]);
    let mut claims = jsonwebtoken::decode::<av_identity::NhiClaims>(
        &token,
        &jsonwebtoken::DecodingKey::from_secret(HMAC_SECRET),
        &validation,
    )
    .unwrap()
    .claims;
    claims.nbf = Some(av_core::time::now_ms() / 1000 + 120);
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    header.kid = Some(HMAC_KID.into());
    let future = jsonwebtoken::encode(
        &header,
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(HMAC_SECRET),
    )
    .unwrap();
    assert!(state.identity.as_ref().unwrap().validate(&future).is_err());
    assert_eq!(send(&state, revoke_form(&future)).await.status, 200);
    assert!(state
        .identity
        .as_ref()
        .unwrap()
        .revocation_store()
        .unwrap()
        .check_token(&claims.iss, &claims.jti, &claims.instance_uid, claims.iat)
        .unwrap()
        .is_some());
}

#[tokio::test]
async fn cached_results_and_sessions_are_bound_to_the_human_principal() {
    let upstream = common::MockBackend::start().await;
    let (state, _dir) = gateway(
        vec![backend("svc", &upstream.url, BackendAuth::Exchange, &["lookup"])],
        |_| {},
    );
    let alice = caller_token(&state, &["tool:lookup", "session:close"], "human-alice");
    let bob = common::mint_nhi_token(
        HMAC_SECRET,
        HMAC_KID,
        &state.config.audience,
        &common::NhiSpec {
            sub: "different-human",
            instance_uid: "inst-backend-test",
            scopes: &["tool:lookup", "session:close"],
            jti: "human-bob",
        },
    );
    assert_eq!(
        send(&state, tool_call("human-session", Some(&alice), "lookup", 1))
            .await
            .status,
        200
    );
    assert_eq!(
        send(&state, tool_call("human-session", Some(&bob), "lookup", 1))
            .await
            .status,
        401
    );
    assert_eq!(
        send(&state, tool_call("human-session", Some(&bob), "lookup", 2))
            .await
            .status,
        401
    );
    let close = authorized(
        axum::http::Request::builder()
            .method("POST")
            .uri("/v1/sessions/human-session/close")
            .body(axum::body::Body::empty())
            .unwrap(),
        &bob,
    );
    assert_eq!(send(&state, close).await.status, 401);
    assert_eq!(upstream.requests().len(), 1);
}

#[tokio::test]
async fn exchange_refusal_is_a_denial_and_does_not_spend_budget() {
    let upstream = common::MockBackend::start().await;
    let (state, _dir) = gateway(
        vec![backend("svc", &upstream.url, BackendAuth::Exchange, &["lookup"])],
        |config| {
            config.enforce_identity_scopes = false;
            config.default_workflow = "signed".into();
            config.budget.max_total_tool_calls = Some(1);
        },
    );
    let empty = caller_token(&state, &[], "empty-scopes");
    let denied = send(&state, tool_call("exchange-denial", Some(&empty), "lookup", 1)).await;
    assert_eq!(denied.status, 403, "{}", denied.json);
    assert_eq!(denied.json["id"], 1);
    assert!(denied.json["error"]["data"]["code"].is_string());
    let permitted = caller_token(&state, &["tool:lookup"], "permitted-scopes");
    assert_eq!(
        send(
            &state,
            tool_call("exchange-denial", Some(&permitted), "lookup", 2)
        )
        .await
        .status,
        200
    );
    state.worker.wait_idle().await;
    let session = state.sessions.get("exchange-denial").unwrap();
    use std::sync::atomic::Ordering;
    assert_eq!(session.totals.tool_allowed.load(Ordering::Relaxed), 1);
    assert_eq!(session.totals.tool_blocked.load(Ordering::Relaxed), 1);
    assert_eq!(upstream.requests().len(), 1);
    let metrics = state.metrics.render();
    assert!(metrics.contains("av_identity_validations_total 2"), "{metrics}");
}

struct WriteFailingRevocationList;
impl RevocationStore for WriteFailingRevocationList {
    fn revoke(&self, _jti: &str, _expires_at: u64) -> Result<(), String> {
        Err("write unavailable".into())
    }
    fn is_revoked(&self, _jti: &str) -> Result<bool, String> {
        Ok(false)
    }
}

#[tokio::test]
async fn revocation_write_failure_is_retryable_and_creates_no_audit_session() {
    let (state, _dir) = gateway_with_revocation(Vec::new(), |_| {}, Arc::new(WriteFailingRevocationList));
    let token = caller_token(&state, &["tool:*"], "write-failure");
    let sessions = state.sessions.len();
    let reply = send(&state, revoke_form(&token)).await;
    assert_eq!(reply.status, 503);
    assert!(reply.headers.contains_key("retry-after"));
    assert_eq!(state.sessions.len(), sessions);
    assert!(state.identity.as_ref().unwrap().validate(&token).is_ok());
}

#[tokio::test]
async fn forged_token_cannot_revoke_a_genuine_token_with_the_same_jti() {
    let (state, _dir) = gateway(Vec::new(), |_| {});
    let genuine = caller_token(&state, &["tool:*"], "forged-collision");
    let forged = common::mint_nhi_token(
        b"incorrect-secret-longer-than-32-bytes",
        HMAC_KID,
        &state.config.audience,
        &common::NhiSpec {
            sub: "user:bob@acme.io",
            instance_uid: "inst-backend-test",
            scopes: &["tool:*"],
            jti: "forged-collision",
        },
    );
    assert!(state.identity.as_ref().unwrap().validate(&genuine).is_ok());
    assert_eq!(send(&state, revoke_form(&forged)).await.status, 200);
    assert!(state.identity.as_ref().unwrap().validate(&genuine).is_ok());
    assert_eq!(state.sessions.len(), 0);
}

#[tokio::test]
async fn holder_revocation_accepts_trusted_external_key_id_collision() {
    use av_identity::KeyMaterial;
    use av_receipts::Signer as _;
    use base64::Engine as _;

    for algorithm in [jsonwebtoken::Algorithm::EdDSA, jsonwebtoken::Algorithm::HS256] {
        let (state, _dir) = gateway(Vec::new(), |_| {});
        let validator = state.identity.as_ref().unwrap();
        let kid = state.token_signer.as_ref().unwrap().kid();
        let claims = validator
            .validate(&caller_token(&state, &["tool:*"], "external-key-id-collision"))
            .unwrap()
            .claims;
        let mut header = jsonwebtoken::Header::new(algorithm);
        header.kid = Some(kid.to_owned());
        let token = match algorithm {
            jsonwebtoken::Algorithm::EdDSA => {
                // IdP key identifiers need not be unique across issuers. Use the
                // same algorithm and kid, but different signing key material.
                let signer = av_receipts::Ed25519Signer::from_seed(&[71; 32]);
                let base64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
                validator
                    .add_key(
                        kid,
                        KeyMaterial::Ed25519Jwk(base64.encode(signer.public_key_bytes())),
                    )
                    .unwrap();
                let message = format!(
                    "{}.{}",
                    base64.encode(serde_json::to_vec(&header).unwrap()),
                    base64.encode(serde_json::to_vec(&claims).unwrap()),
                );
                format!("{message}.{}", base64.encode(signer.sign(message.as_bytes())))
            }
            jsonwebtoken::Algorithm::HS256 => {
                validator
                    .add_key(kid, KeyMaterial::HmacSecret(HMAC_SECRET.to_vec()))
                    .unwrap();
                jsonwebtoken::encode(
                    &header,
                    &claims,
                    &jsonwebtoken::EncodingKey::from_secret(HMAC_SECRET),
                )
                .unwrap()
            }
            _ => unreachable!(),
        };
        assert!(validator.validate(&token).is_ok(), "{algorithm:?}");
        let (message, signature) = token.rsplit_once('.').unwrap();
        let mut forged_signature = signature.as_bytes().to_vec();
        forged_signature[0] = if forged_signature[0] == b'A' { b'B' } else { b'A' };
        let forged = format!("{message}.{}", String::from_utf8(forged_signature).unwrap());
        assert!(validator.validate(&forged).is_err());
        assert_eq!(send(&state, revoke_form(&forged)).await.status, 200);
        assert!(validator.validate(&token).is_ok());
        assert_eq!(
            state.sessions.len(),
            0,
            "a forged token must not produce an audit session"
        );
        assert_eq!(send(&state, revoke_form(&token)).await.status, 200);
        assert!(
            matches!(
                validator.validate(&token),
                Err(av_identity::IdentityError::Revoked(_))
            ),
            "the trusted external {algorithm:?} token must actually be revoked despite its matching kid"
        );
        assert!(state
            .exchanged_revocations
            .check_token(&claims.iss, &claims.jti, &claims.instance_uid, claims.iat)
            .unwrap()
            .is_none());
        state.worker.wait_idle().await;
    }
}

#[tokio::test]
async fn holder_revocation_retries_unknown_leaf_and_delegation_parent_keys() {
    let (state, _dir) = gateway(Vec::new(), |_| {});
    let validator = state.identity.as_ref().unwrap();
    let gateway_kid = state.token_signer.as_ref().unwrap().kid();
    let mut claims = validator
        .validate(&caller_token(&state, &["tool:*"], "unknown-parent"))
        .unwrap()
        .claims;
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    header.kid = Some("rotating-parent-key".into());
    let key = jsonwebtoken::EncodingKey::from_secret(HMAC_SECRET);
    let parent = jsonwebtoken::encode(&header, &claims, &key).unwrap();
    assert!(matches!(
        validator.validate_for_revocation(&parent),
        Err(av_identity::IdentityError::UnknownKid(kid)) if kid == "rotating-parent-key"
    ));
    let reply = send(&state, revoke_form(&parent)).await;
    assert_eq!(reply.status, 503);
    assert!(reply.headers.contains_key("retry-after"));

    // The leaf key is known and shares the gateway kid, but full validation
    // fails on an unrelated parent key. Its failure must remain retryable.
    validator
        .add_key(
            gateway_kid,
            av_identity::KeyMaterial::HmacSecret(HMAC_SECRET.to_vec()),
        )
        .unwrap();
    header.kid = Some(gateway_kid.to_owned());
    claims.jti = "colliding-leaf-with-unknown-parent".into();
    claims.parent_token = Some(parent.clone());
    let child = jsonwebtoken::encode(&header, &claims, &key).unwrap();
    assert!(matches!(
        validator.validate_for_revocation(&child),
        Err(av_identity::IdentityError::UnknownKid(kid)) if kid == "rotating-parent-key"
    ));
    let reply = send(&state, revoke_form(&child)).await;
    assert_eq!(reply.status, 503);
    assert!(reply.headers.contains_key("retry-after"));
    assert_eq!(state.sessions.len(), 0);
    for store in [
        validator.revocation_store().unwrap(),
        &state.exchanged_revocations,
    ] {
        assert!(store
            .check_token(&claims.iss, &claims.jti, &claims.instance_uid, claims.iat)
            .unwrap()
            .is_none());
    }

    // Once rotation delivers the parent key, the same delegated token can be
    // fully validated and revoked; the previous 503 did not mutate its state.
    validator
        .add_key(
            "rotating-parent-key",
            av_identity::KeyMaterial::HmacSecret(HMAC_SECRET.to_vec()),
        )
        .unwrap();
    assert!(validator.validate(&parent).is_ok());
    assert!(validator.validate(&child).is_ok());
    assert_eq!(send(&state, revoke_form(&child)).await.status, 200);
    assert!(matches!(
        validator.validate(&child),
        Err(av_identity::IdentityError::Revoked(_))
    ));
    assert!(validator.validate(&parent).is_ok());
    state.worker.wait_idle().await;
}

#[tokio::test]
async fn gateway_signed_tokens_keep_the_exchanged_revocation_namespace() {
    let (state, _dir) = gateway(
        vec![backend(
            "svc",
            "http://127.0.0.1:9",
            BackendAuth::Exchange,
            &["lookup"],
        )],
        |config| {
            // Inbound and backend audiences intentionally overlap, and the
            // gateway key is also trusted inbound. Only the exchange profile
            // and actual signing key can prevent an inappropriate fallback.
            config.audience = "svc".into();
            config.token_exchange_enabled = true;
            configure_revocation_admin(config);
        },
    );
    let validator = state.identity.as_ref().unwrap();
    let signer = state.token_signer.as_ref().unwrap();
    validator
        .add_key(
            signer.kid(),
            av_identity::KeyMaterial::Ed25519Jwk(signer.jwks_json()["keys"][0]["x"].as_str().unwrap().into()),
        )
        .unwrap();
    let subject = caller_token(&state, &["tool:lookup"], "gateway-malformed-profile");
    let mut claims = validator.validate(&subject).unwrap().claims;
    claims.iss = state.config.audience.clone();
    claims.nbf = Some(claims.iat);
    claims.act = Some(ActorClaim {
        sub: "user:bob@acme.io".into(),
        act: None,
    });
    let legacy = signer.sign(&claims).unwrap();
    let invalid_ancestry = signer
        .sign(&av_identity::ExchangedClaims {
            claims: claims.clone(),
            av_subject_tokens: Vec::new(),
            av_delegation_depth: 1,
        })
        .unwrap();
    for token in [legacy, invalid_ancestry] {
        assert!(
            validator.validate_for_revocation(&token).is_ok(),
            "fallback would otherwise accept this token"
        );
        assert!(av_identity::verify_exchanged_token(
            &token,
            &av_identity::ExchangedValidation {
                key: &signer.decoding_key(),
                kid: signer.kid(),
                issuer: &state.config.audience,
                allowed_audiences: &["svc".to_owned()],
                max_depth: state.config.max_delegation_depth,
                now_s: av_core::time::now_ms() / 1000,
                token_type: "JWT",
                for_revocation: true,
            },
        )
        .is_err());
        assert_eq!(send(&state, revoke_form(&token)).await.status, 200);
        assert!(
            validator.validate(&token).is_ok(),
            "invalid gateway profiles must not revoke inbound tokens"
        );
        assert!(state
            .exchanged_revocations
            .check_token(&claims.iss, &claims.jti, &claims.instance_uid, claims.iat)
            .unwrap()
            .is_none());
        assert_eq!(state.sessions.len(), 0);
    }

    let token = exchange_token(&state, &subject).await;
    let claims = validator.validate_for_revocation(&token).unwrap().claims;
    assert_eq!(introspection(&state, &token).await.json["active"], true);
    assert_eq!(send(&state, revoke_form(&token)).await.status, 200);
    assert_eq!(introspection(&state, &token).await.json["active"], false);
    assert!(validator
        .revocation_store()
        .unwrap()
        .check_token(&claims.iss, &claims.jti, &claims.instance_uid, claims.iat)
        .unwrap()
        .is_none());
    assert!(state
        .exchanged_revocations
        .check_token(&claims.iss, &claims.jti, &claims.instance_uid, claims.iat)
        .unwrap()
        .is_some());
    state.worker.wait_idle().await;
}

#[tokio::test]
async fn forged_exchanged_token_has_the_same_revocation_response_as_garbage() {
    let (state, _dir) = gateway(
        vec![backend(
            "svc",
            "http://127.0.0.1:9",
            BackendAuth::Exchange,
            &["lookup"],
        )],
        |config| {
            config.token_exchange_enabled = true;
            configure_revocation_admin(config);
        },
    );
    let subject = caller_token(&state, &["tool:lookup"], "forged-exchange-parent");
    let token = exchange_token(&state, &subject).await;
    let mut bytes = token.clone().into_bytes();
    let position = bytes.len() - 10;
    bytes[position] = if bytes[position] == b'A' { b'B' } else { b'A' };
    assert_eq!(
        send(&state, revoke_form(std::str::from_utf8(&bytes).unwrap()))
            .await
            .status,
        200
    );
    assert_eq!(introspection(&state, &token).await.json["active"], true);
}

#[tokio::test]
async fn operator_jti_revocation_accepts_unicode_and_does_not_report_an_instance_cutoff() {
    let (state, _dir) = gateway(
        vec![backend(
            "svc",
            "http://127.0.0.1:9",
            BackendAuth::None,
            &["lookup"],
        )],
        configure_revocation_admin,
    );
    let jti = "界".repeat(200);
    let token = caller_token(&state, &["tool:lookup"], &jti);
    assert!(state.identity.as_ref().unwrap().validate(&token).is_ok());
    let reply = send(
        &state,
        admin_request(serde_json::json!({"jti":jti}), OPERATOR_SECRET),
    )
    .await;
    assert_eq!(reply.status, 200, "{}", reply.json);
    assert!(reply.json["issued_at_or_before"].is_null());
    assert!(matches!(
        state.identity.as_ref().unwrap().validate(&token),
        Err(av_identity::IdentityError::Revoked(_))
    ));
    assert_eq!(
        send(
            &state,
            admin_request(
                serde_json::json!({"instance_uid":"x".repeat(129)}),
                OPERATOR_SECRET
            )
        )
        .await
        .status,
        400
    );
}

struct PausedRevocationList {
    inner: InMemoryRevocationStore,
    entered: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    proceed: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
}
impl RevocationStore for PausedRevocationList {
    fn revoke(&self, jti: &str, expires_at: u64) -> Result<(), String> {
        self.inner.revoke(jti, expires_at)
    }
    fn try_revoke_token(
        &self,
        issuer: &str,
        jti: &str,
        expires_at: u64,
    ) -> Result<av_identity::RevokeOutcome, String> {
        let result = self.inner.try_revoke_token(issuer, jti, expires_at)?;
        if let Some(entered) = self.entered.lock().unwrap().take() {
            let _ = entered.send(());
        }
        self.proceed
            .lock()
            .unwrap()
            .recv_timeout(std::time::Duration::from_secs(5))
            .map_err(|error| error.to_string())?;
        Ok(result)
    }
    fn is_revoked(&self, jti: &str) -> Result<bool, String> {
        self.inner.is_revoked(jti)
    }
    fn check_token(
        &self,
        issuer: &str,
        jti: &str,
        uid: &str,
        iat: u64,
    ) -> Result<Option<av_identity::RevokedBy>, String> {
        self.inner.check_token(issuer, jti, uid, iat)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_disconnect_after_revocation_write_does_not_cancel_signed_audit() {
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (proceed_tx, proceed_rx) = std::sync::mpsc::channel();
    let store = Arc::new(PausedRevocationList {
        inner: InMemoryRevocationStore::new(),
        entered: std::sync::Mutex::new(Some(entered_tx)),
        proceed: std::sync::Mutex::new(proceed_rx),
    });
    let (state, _dir) = gateway_with_revocation(Vec::new(), |_| {}, store);
    let token = caller_token(&state, &["tool:*"], "disconnect-revocation");
    let request_state = Arc::clone(&state);
    let request_token = token.clone();
    let request = tokio::spawn(async move { send(&request_state, revoke_form(&request_token)).await });
    tokio::time::timeout(std::time::Duration::from_secs(5), entered_rx)
        .await
        .unwrap()
        .unwrap();
    request.abort();
    proceed_tx.send(()).unwrap();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        state.mcp_inflight.wait_drained(),
    )
    .await
    .unwrap();
    assert!(matches!(
        state.identity.as_ref().unwrap().validate(&token),
        Err(av_identity::IdentityError::Revoked(_))
    ));
    let receipts =
        std::fs::read_dir(std::path::Path::new(&state.config.atif_spool_dir).join("receipts")).unwrap();
    assert_eq!(
        receipts.count(),
        1,
        "detached handler must finish its signed audit after disconnect"
    );
}

#[tokio::test]
async fn holder_revocation_is_issuer_scoped_and_operator_revocation_remains_global() {
    let (state, _dir) = gateway(
        vec![backend(
            "svc",
            "http://127.0.0.1:9",
            BackendAuth::Exchange,
            &["lookup"],
        )],
        |config| {
            config.token_exchange_enabled = true;
            configure_revocation_admin(config);
        },
    );
    let first = caller_token(&state, &["tool:lookup"], "shared-jti");
    let validator = state.identity.as_ref().unwrap();
    let mut other_claims = validator.validate(&first).unwrap().claims;
    other_claims.iss = "independent-issuer".into();
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    header.kid = Some("independent-issuer-key".into());
    let other_secret = b"independent-issuer-secret-at-least-32-bytes";
    validator
        .add_key(
            "independent-issuer-key",
            av_identity::KeyMaterial::HmacSecret(other_secret.to_vec()),
        )
        .unwrap();
    let second = jsonwebtoken::encode(
        &header,
        &other_claims,
        &jsonwebtoken::EncodingKey::from_secret(other_secret),
    )
    .unwrap();
    assert!(validator.validate(&second).is_ok());
    let first_exchange = exchange_token(&state, &first).await;
    let second_exchange = exchange_token(&state, &second).await;

    assert_eq!(send(&state, revoke_form(&first)).await.status, 200);
    assert!(matches!(
        validator.validate(&first),
        Err(av_identity::IdentityError::Revoked(_))
    ));
    assert!(
        validator.validate(&second).is_ok(),
        "another issuer's identical JTI must remain usable"
    );
    assert_eq!(introspection(&state, &first_exchange).await.json["active"], false);
    assert_eq!(introspection(&state, &second_exchange).await.json["active"], true);

    assert_eq!(
        send(
            &state,
            admin_request(
                serde_json::json!({"jti":"shared-jti", "token_kind":"nhi"}),
                OPERATOR_SECRET
            )
        )
        .await
        .status,
        200
    );
    assert!(matches!(
        validator.validate(&second),
        Err(av_identity::IdentityError::Revoked(_))
    ));
    assert_eq!(
        introspection(&state, &second_exchange).await.json["active"],
        false
    );
}

#[tokio::test]
async fn invalid_oauth_scope_syntax_returns_invalid_scope() {
    let (state, _dir) = gateway(
        vec![backend(
            "svc",
            "http://127.0.0.1:9",
            BackendAuth::Exchange,
            &["lookup"],
        )],
        |config| {
            config.token_exchange_enabled = true;
        },
    );
    let token = caller_token(&state, &["tool:*"], "scope-grammar");
    for scope in [
        "tool:read\ttool:delete",
        "tool:read\\write",
        "tool:\"read",
        "tool:café",
        "tool:read  tool:write",
    ] {
        let body = serde_urlencoded::to_string([
            ("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange"),
            ("subject_token", token.as_str()),
            ("subject_token_type", "urn:ietf:params:oauth:token-type:jwt"),
            ("audience", "svc"),
            ("scope", scope),
        ])
        .unwrap();
        let result = send(&state, form("/v1/token", body)).await;
        assert_eq!(result.status, 400);
        assert_eq!(result.json["error"], "invalid_scope");
    }
}
