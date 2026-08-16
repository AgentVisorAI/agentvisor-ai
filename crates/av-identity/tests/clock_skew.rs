//! Cross-machine and UTC-skew stress tests for NHI validation.
//!
//! Scenarios exercised:
//!   1. Two machines with clocks a few seconds apart still authenticate
//!      each other's tokens (validator leeway = 30s).
//!   2. A machine whose clock is beyond the leeway is rejected.
//!   3. The validator uses UTC epoch seconds — a token issued by a machine
//!      running local time in a non-UTC zone still validates (jsonwebtoken
//!      encodes epoch seconds).
//!   4. Timestamp edge cases: `exp == iat`, `iat == 0`, huge `iat`, `exp`
//!      exactly at the boundary.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use av_identity::{IdentityError, IdentityValidator, KeyMaterial, NhiClaims, MAX_TTL_SECS};
use ed25519_dalek::pkcs8::{spki::der::pem::LineEnding, EncodePrivateKey, EncodePublicKey};
use jsonwebtoken::{Algorithm, EncodingKey, Header};

struct TestKeys {
    kid: String,
    encoding: EncodingKey,
    public_pem: String,
}

fn ed25519_keys(kid: &str) -> TestKeys {
    let signing = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let private_pem = signing.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
    let public_pem = signing.verifying_key().to_public_key_pem(LineEnding::LF).unwrap();
    TestKeys {
        kid: kid.to_owned(),
        encoding: EncodingKey::from_ed_pem(private_pem.as_bytes()).unwrap(),
        public_pem,
    }
}

fn now_s() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn claims_with(iat: u64, exp: u64) -> NhiClaims {
    NhiClaims {
        sub: "agent:test".into(),
        iss: "https://idp.example.com".into(),
        aud: "harness-prod".into(),
        iat,
        nbf: None,
        exp,
        jti: av_core::new_event_uid(),
        instance_uid: "inst-1".into(),
        charter: "support".into(),
        version: "1.2.3".into(),
        scopes: vec!["tool:read".to_owned()],
        parent_token: None,
    }
}

fn mint(keys: &TestKeys, claims: &NhiClaims) -> String {
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(keys.kid.clone());
    jsonwebtoken::encode(&header, claims, &keys.encoding).unwrap()
}

fn validator(keys: &TestKeys) -> IdentityValidator {
    let v = IdentityValidator::new("harness-prod");
    v.add_key(keys.kid.clone(), KeyMaterial::Ed25519Pem(keys.public_pem.clone()))
        .unwrap();
    v
}

// ------------------------------------------------------------------
// Cross-machine clock-skew scenarios (validator leeway = 30 s).
// ------------------------------------------------------------------

/// A token minted on a machine whose clock is 20 seconds ahead of the
/// validator's clock must still validate because the 30-second leeway
/// absorbs the drift.
#[test]
fn future_iat_within_leeway_is_accepted() {
    let keys = ed25519_keys("k1");
    let v = validator(&keys);
    let now = now_s();
    let claims = claims_with(now + 20, now + 20 + 300);
    let token = mint(&keys, &claims);
    let id = v.validate(&token).expect("skew within leeway must validate");
    assert!(id.ttl_remaining_s > 250);
}

/// A token minted 25 seconds ahead is still inside the 30 s leeway.
#[test]
fn future_iat_just_below_leeway_is_accepted() {
    let keys = ed25519_keys("k1");
    let v = validator(&keys);
    let now = now_s();
    let claims = claims_with(now + 25, now + 25 + 60);
    let token = mint(&keys, &claims);
    v.validate(&token)
        .expect("iat 25 s ahead must fit inside the 30 s leeway");
}

/// A machine that is 5 minutes ahead is beyond any reasonable leeway;
/// the validator must refuse to accept its tokens with `FutureIat`.
#[test]
fn future_iat_beyond_leeway_is_rejected_as_futureiat() {
    let keys = ed25519_keys("k1");
    let v = validator(&keys);
    let now = now_s();
    let far_future = now + 5 * 60;
    let claims = claims_with(far_future, far_future + 300);
    let token = mint(&keys, &claims);
    match v.validate(&token) {
        Err(IdentityError::FutureIat { .. }) => {}
        other => panic!("expected FutureIat, got {other:?}"),
    }
}

/// A machine 20 seconds *behind* the validator that just recently minted
/// a short-lived token must still validate — the token's `exp` is 20 s
/// closer to the validator's now, but as long as the token is not yet
/// expired the validator accepts it. The 30 s leeway on `exp` (applied by
/// jsonwebtoken) tolerates recently-expired tokens too.
#[test]
fn past_iat_within_normal_lifetime_is_accepted() {
    let keys = ed25519_keys("k1");
    let v = validator(&keys);
    let now = now_s();
    let past_iat = now - 20;
    let claims = claims_with(past_iat, past_iat + 300);
    let token = mint(&keys, &claims);
    v.validate(&token)
        .expect("recently-issued token must still validate");
}

/// A token that expired exactly 10 seconds ago is still inside jsonwebtoken's
/// 30 s leeway on `exp`.
#[test]
fn recently_expired_token_within_leeway_is_accepted() {
    let keys = ed25519_keys("k1");
    let v = validator(&keys);
    let now = now_s();
    let iat = now - 200;
    let exp = now - 10;
    let claims = claims_with(iat, exp);
    let token = mint(&keys, &claims);
    v.validate(&token)
        .expect("token expired within leeway must still validate");
}

/// A token that expired more than 60 seconds ago must be rejected.
#[test]
fn long_expired_token_is_rejected() {
    let keys = ed25519_keys("k1");
    let v = validator(&keys);
    let now = now_s();
    let iat = now - 300;
    let exp = now - 60;
    let claims = claims_with(iat, exp);
    let token = mint(&keys, &claims);
    match v.validate(&token) {
        Err(IdentityError::Verification(_)) => {}
        other => panic!("expected Verification/expired, got {other:?}"),
    }
}

// ------------------------------------------------------------------
// Malformed timestamp claims.
// ------------------------------------------------------------------

/// A token with `exp == iat` has zero TTL — nonsensical. Must never
/// validate: refused as `BadTimestamps`, or as `Verification` when the
/// JWT library rejects the already-expired instant first.
#[test]
fn exp_equal_to_iat_never_validates() {
    let keys = ed25519_keys("k1");
    let v = validator(&keys);
    let now = now_s();
    let claims = claims_with(now, now);
    let token = mint(&keys, &claims);
    match v.validate(&token) {
        // jsonwebtoken may reject `exp == now` as expired first; either
        // Verification or BadTimestamps is acceptable, but the token must
        // NEVER validate.
        Err(IdentityError::BadTimestamps { .. } | IdentityError::Verification(_)) => {}
        other => panic!("expected BadTimestamps or Verification, got {other:?}"),
    }
}

/// A token with `exp < iat` is impossible — reject.
#[test]
fn exp_below_iat_is_rejected_as_bad_timestamps() {
    let keys = ed25519_keys("k1");
    let v = validator(&keys);
    let now = now_s();
    let claims = claims_with(now, now.saturating_sub(1));
    let token = mint(&keys, &claims);
    match v.validate(&token) {
        Err(IdentityError::BadTimestamps { .. } | IdentityError::Verification(_)) => {}
        other => panic!("expected BadTimestamps, got {other:?}"),
    }
}

/// A token whose declared TTL exceeds `MAX_TTL_SECS` must be rejected as
/// `TtlTooLong` — regardless of clock skew between minter and validator.
#[test]
fn ttl_exceeds_15_min_rejected_even_when_iat_is_recent() {
    let keys = ed25519_keys("k1");
    let v = validator(&keys);
    let now = now_s();
    let claims = claims_with(now, now + MAX_TTL_SECS + 1);
    let token = mint(&keys, &claims);
    match v.validate(&token) {
        Err(IdentityError::TtlTooLong(ttl)) => assert_eq!(ttl, MAX_TTL_SECS + 1),
        other => panic!("expected TtlTooLong, got {other:?}"),
    }
}

/// A token with `iat = 0` (either bug or attempted attack) must be
/// rejected — an epoch-zero iat with any positive exp will either be
/// expired (`now >> exp`) or exceed the TTL cap.
#[test]
fn iat_zero_is_never_accepted() {
    let keys = ed25519_keys("k1");
    let v = validator(&keys);
    let claims = claims_with(0, 300);
    let token = mint(&keys, &claims);
    assert!(v.validate(&token).is_err(), "iat=0 must never validate");
}

/// A token with pathologically huge `iat` and `exp` must be rejected as
/// `FutureIat` and not overflow anywhere.
#[test]
fn extreme_future_iat_is_rejected_without_panicking() {
    let keys = ed25519_keys("k1");
    let v = validator(&keys);
    // Roughly year 275760 A.D. — still fits in i64 for jsonwebtoken.
    let iat = 8_640_000_000_000u64;
    let claims = claims_with(iat, iat + MAX_TTL_SECS);
    let token = mint(&keys, &claims);
    match v.validate(&token) {
        Err(IdentityError::FutureIat { .. }) => {}
        other => panic!("expected FutureIat, got {other:?}"),
    }
}

// ------------------------------------------------------------------
// Timezone / UTC invariants: the on-wire representation is always
// epoch seconds. A machine whose local time is not UTC still mints and
// consumes the same integer seconds — timezones are irrelevant to the
// signed claim body.
// ------------------------------------------------------------------

/// Two independently-minted tokens with identical timestamp claims
/// (each carries a fresh random `jti`) must
/// validate identically regardless of what local timezone the minter's
/// process was configured for — because the wire format is UTC epoch
/// seconds, not a formatted local timestamp.
#[test]
fn wire_claims_carry_utc_epoch_seconds_only() {
    let keys = ed25519_keys("k1");
    let v = validator(&keys);
    let now = now_s();
    let claims_a = claims_with(now, now + 300);
    let claims_b = claims_with(now, now + 300);
    let token_a = mint(&keys, &claims_a);
    let token_b = mint(&keys, &claims_b);

    // Tokens will differ (jti is random), but the timestamps in both must
    // be interpreted as UTC epoch seconds.
    let a = v.validate(&token_a).unwrap();
    let b = v.validate(&token_b).unwrap();
    // TTL remaining computed against the validator's UTC clock; both
    // tokens must report the same (± 1 s for the clock read between them).
    let diff = a.ttl_remaining_s.abs_diff(b.ttl_remaining_s);
    assert!(diff <= 1, "ttl diff {diff}s exceeds 1s tolerance");
}

/// `iat < exp` with normal drift must not accidentally trip the TTL cap
/// because `exp - iat` can silently underflow if one comes from a machine
/// N seconds ahead — the current implementation guards this with an
/// explicit `exp <= iat` check first.
#[test]
fn iat_close_to_now_never_underflows_ttl_computation() {
    let keys = ed25519_keys("k1");
    let v = validator(&keys);
    let now = now_s();
    // Both come from a machine 25 s ahead (within leeway). `exp - iat = 300`.
    let iat = now + 25;
    let exp = iat + 300;
    let claims = claims_with(iat, exp);
    let token = mint(&keys, &claims);
    let id = v.validate(&token).unwrap();
    assert!(id.ttl_remaining_s > 0 && id.ttl_remaining_s < MAX_TTL_SECS);
}

/// Rapid successive validations must produce non-increasing `ttl_remaining_s`
/// under a monotone wall clock — an *increase* detected across two same-token
/// validations would signal that `now_ms()` ran backward, which the workspace
/// guarantees does not happen under normal operation.
#[test]
fn ttl_remaining_is_non_increasing_across_rapid_validations() {
    let keys = ed25519_keys("k1");
    let v = validator(&keys);
    let now = now_s();
    let claims = claims_with(now, now + 600);
    let token = mint(&keys, &claims);
    let mut previous = v.validate(&token).unwrap().ttl_remaining_s;
    for _ in 0..1_000 {
        let current = v.validate(&token).unwrap().ttl_remaining_s;
        assert!(
            current <= previous,
            "ttl_remaining_s went up: {previous} -> {current}",
        );
        previous = current;
    }
}
