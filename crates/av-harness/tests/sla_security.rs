//! Sequential authenticated admission diagnostic with live shared revocation
//! and bounded Redis quota accounting. This complements the anonymous 10k test.
//! The timer covers the admission wrapper, including identity validation and
//! Redis calls, but excludes HTTP parsing, upstream I/O, and request cleanup.
//! Dropping each prepared request after sampling schedules an asynchronous
//! refund and audit work that can contend with later samples. Dependency-outage
//! refusal and recovery are exercised separately by the live-pillars helper.
#![cfg(feature = "redis")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use av_harness::pipeline::PipelineError;
use av_harness::revocation::{GuardedRevocationStore, StateRevocationStore};
use av_harness::{AppState, HarnessConfig};
use av_identity::{IdentityError, IdentityValidator, KeyMaterial, RevocationStore};
use std::sync::Arc;
use std::time::Instant;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "release diagnostic requiring live AV_REDIS_URL"]
#[allow(clippy::assertions_on_constants)] // Fail loudly if explicitly run in debug mode.
async fn authenticated_admission_with_live_revocation_and_quota() {
    assert!(!cfg!(debug_assertions), "run this diagnostic in release mode");
    let url = std::env::var("AV_REDIS_URL").expect("live Redis is required");
    let directory = tempfile::tempdir().unwrap();
    let mut config =
        HarnessConfig::for_tests("http://127.0.0.1:9", &directory.path().to_string_lossy(), "/tmp");
    config.require_identity = true;
    config.enforce_identity_scopes = true;
    config.state_backend = "redis".to_owned();
    config.state_endpoint = Some(url.clone());
    config.budget.max_tokens = Some(1_000_000);
    config.worker_channel_capacity = 4096;
    let state_store: Arc<dyn av_state::StateStore> =
        Arc::new(av_state::redis_store::RedisStore::connect(&url).unwrap());
    let revocation = Arc::new(StateRevocationStore::new(state_store.clone()));
    let guarded = Arc::new(GuardedRevocationStore::new(
        revocation.clone(),
        &av_core::metrics::Registry::new(),
        "nhi",
    ));
    let secret = b"security-benchmark-only-hmac-secret";
    let mut validator = IdentityValidator::new(&config.audience);
    validator
        .add_key("sla", KeyMaterial::HmacSecret(secret.to_vec()))
        .unwrap();
    validator.set_revocation_store(guarded);
    let validator = Arc::new(validator);
    let instance = av_core::new_event_uid();
    let jti = av_core::new_event_uid();
    let token = common::mint_nhi_token(
        secret,
        "sla",
        &config.audience,
        &common::NhiSpec {
            sub: "sla-security",
            instance_uid: &instance,
            scopes: &[&config.chat_scope],
            jti: &jti,
        },
    );
    let sandbox = common::sandbox_for(&config);
    let state = AppState::new(
        config,
        state_store.clone(),
        Arc::new(sandbox),
        Arc::new(common::NullBus),
        Some(validator.clone()),
        Arc::new(common::signer(33)),
    )
    .unwrap();

    // Untimed checks ensure the measured configuration really enforces both
    // authentication and scope, rather than merely accepting a valid token.
    let headers = common::signed_headers(&format!("security-{instance}-missing-token"));
    let missing_token = state
        .prepare_chat_nonblocking(&headers, common::chat_payload(), 0, None)
        .await
        .err()
        .expect("missing credentials must fail authentication");
    assert!(matches!(missing_token, PipelineError::Unauthorized(_)));
    let wrong_scope_jti = av_core::new_event_uid();
    let wrong_scope_token = common::mint_nhi_token(
        secret,
        "sla",
        &state.config.audience,
        &common::NhiSpec {
            sub: "sla-security",
            instance_uid: &instance,
            scopes: &["unrelated:scope"],
            jti: &wrong_scope_jti,
        },
    );
    let mut headers = common::signed_headers(&format!("security-{instance}-wrong-scope"));
    headers.insert(
        "authorization",
        format!("Bearer {wrong_scope_token}").parse().unwrap(),
    );
    let wrong_scope = state
        .prepare_chat_nonblocking(&headers, common::chat_payload(), 0, None)
        .await
        .err()
        .expect("a valid token without the chat scope must fail authorization");
    assert!(matches!(wrong_scope, PipelineError::Blocked { ref context, .. }
        if context.contains(&state.config.chat_scope)));

    // This fresh session has a separate counter from every warmup and sample.
    // Read before dropping the request, while its admission debit is still held.
    let quota_session = format!("security-{instance}-quota-check");
    let mut headers = common::signed_headers(&quota_session);
    headers.insert("authorization", format!("Bearer {token}").parse().unwrap());
    let prepared = state
        .prepare_chat_nonblocking(&headers, common::chat_payload(), 0, None)
        .await
        .unwrap();
    assert_eq!(prepared.identity.instance_uid, instance);
    let billed_tokens = av_core::tokens::approx_tokens_json(&prepared.payload);
    assert!(billed_tokens > 0);
    let quota_key = format!("{}tokens", av_state::ActionBudget::session_prefix(&quota_session));
    let recorded_tokens = tokio::task::spawn_blocking(move || state_store.get(&quota_key))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        recorded_tokens, billed_tokens,
        "admission must debit the live Redis quota"
    );
    drop(prepared);

    let mut samples = Vec::with_capacity(200);
    for index in 0..220 {
        let mut headers = common::signed_headers(&format!("security-{instance}-{index}"));
        headers.insert("authorization", format!("Bearer {token}").parse().unwrap());
        let start = Instant::now();
        let prepared = state
            .prepare_chat_nonblocking(&headers, common::chat_payload(), 0, None)
            .await
            .unwrap();
        let elapsed_us = start.elapsed().as_micros();
        if index >= 20 {
            samples.push(elapsed_us);
        }
        assert_eq!(prepared.identity.instance_uid, instance);
        drop(prepared);
    }
    samples.sort_unstable();
    println!(
        "authenticated_redis_admission samples={} p95_us={} p99_us={} max_us={}",
        samples.len(),
        samples.get(189).unwrap(),
        samples.get(197).unwrap(),
        samples.last().unwrap()
    );
    // Write through the backing store, bypassing the guard's positive cache,
    // so the validator must observe the revocation in shared Redis.
    revocation.try_revoke_token("test-issuer", &jti, 0).unwrap();
    let mut headers = common::signed_headers(&format!("security-{instance}-revoked"));
    headers.insert("authorization", format!("Bearer {token}").parse().unwrap());
    let revoked = state
        .prepare_chat_nonblocking(&headers, common::chat_payload(), 0, None)
        .await
        .err()
        .expect("a revoked identity must fail authentication");
    assert!(matches!(revoked, PipelineError::Unauthorized(_)));
    assert!(
        matches!(validator.validate(&token), Err(IdentityError::Revoked(ref token_id)) if token_id == &jti)
    );
    state.worker.wait_idle().await;
}
