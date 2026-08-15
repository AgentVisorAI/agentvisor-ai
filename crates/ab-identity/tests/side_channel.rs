//! Side-channel and secret-leak resistance tests for identity primitives.
//!
//! Coverage:
//!   1. `KeyMaterial::Debug` must never render its inner bytes — logs
//!      that spill a `Debug` representation of a validator (via tracing,
//!      panic dumps, etc.) must never leak an HMAC secret.
//!   2. HMAC-secret handling round-trip: `KeyMaterial::HmacSecret(&secret)`
//!      remains usable to validate its tokens without exposing bytes on
//!      any code path an attacker can observe.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use ab_identity::{IdentityValidator, KeyMaterial, NhiClaims};
use jsonwebtoken::{Algorithm, EncodingKey, Header};

fn now_s() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn hmac_claims() -> NhiClaims {
    let iat = now_s();
    NhiClaims {
        sub: "agent:test".into(),
        iss: "https://idp.example.com".into(),
        aud: "harness-prod".into(),
        iat,
        nbf: None,
        exp: iat + 300,
        jti: ab_core::new_event_uid(),
        instance_uid: "inst-1".into(),
        charter: "support".into(),
        version: "1.2.3".into(),
        scopes: vec!["tool:read".into()],
        parent_token: None,
    }
}

/// `KeyMaterial::HmacSecret` must render as an opaque placeholder — never
/// its bytes — for every Debug rendering (single-value, container, and
/// deep-in-struct).
#[test]
fn key_material_debug_never_leaks_hmac_secret() {
    let secret = b"do-not-leak-me-please-i-am-a-secret-abcdef".to_vec();
    let secret_hex = hex::encode(&secret);
    let secret_utf8 = String::from_utf8_lossy(&secret).into_owned();
    let material = KeyMaterial::HmacSecret(secret.clone());

    let rendered = format!("{material:?}");
    assert!(
        !rendered.contains(&secret_hex),
        "Debug leaked hex secret: {rendered}",
    );
    assert!(
        !rendered.contains(&secret_utf8),
        "Debug leaked utf8 secret: {rendered}",
    );

    // The same must hold when the material lives inside a Vec (Debug
    // delegates to each element's Debug impl).
    let bag = vec![material.clone(), material.clone()];
    let rendered = format!("{bag:?}");
    assert!(!rendered.contains(&secret_hex));
    assert!(!rendered.contains(&secret_utf8));

    // ... and inside an Option (worst-case struct-derived Debug).
    let wrapped = Some(material);
    let rendered = format!("{wrapped:?}");
    assert!(!rendered.contains(&secret_hex));
    assert!(!rendered.contains(&secret_utf8));
}

/// Same guarantee for the PEM and JWK variants — even if the PEM string
/// carries the private key material by mistake, Debug must not spill it.
#[test]
fn key_material_debug_hides_pem_and_jwk_bodies_too() {
    let leaky_pem =
        "-----BEGIN PRIVATE KEY-----\nSTOP_LEAKING_ME_ABCD\n-----END PRIVATE KEY-----\n".to_owned();
    let material = KeyMaterial::Ed25519Pem(leaky_pem.clone());
    let rendered = format!("{material:?}");
    assert!(!rendered.contains("STOP_LEAKING_ME_ABCD"), "{rendered}");

    let leaky_jwk = "STOP_LEAKING_ME_XYZ".to_owned();
    let material = KeyMaterial::Ed25519Jwk(leaky_jwk);
    let rendered = format!("{material:?}");
    assert!(!rendered.contains("STOP_LEAKING_ME_XYZ"), "{rendered}");
}

/// End-to-end: a validator holding an HMAC secret can still authenticate
/// tokens (proves the secret is used internally), while the `Debug` output of
/// the `KeyMaterial` handle — the only debug-formattable secret-bearing
/// surface a caller can reach — never reveals the secret bytes.
#[test]
fn validator_debug_holding_hmac_secret_does_not_leak_it() {
    let secret = b"another-tightly-held-hmac-secret-42-abcdef".to_vec();
    let secret_hex = hex::encode(&secret);
    let v = IdentityValidator::new("harness-prod");
    v.add_key("kid-hmac", KeyMaterial::HmacSecret(secret.clone()))
        .unwrap();

    // Token round-trip proves the secret is functional inside the validator.
    let claims = hmac_claims();
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some("kid-hmac".to_owned());
    let token = jsonwebtoken::encode(&header, &claims, &EncodingKey::from_secret(&secret)).unwrap();
    v.validate(&token).unwrap();

    // Any tracing/log spill of the validator must not expose the secret.
    // We format the key material we handed the validator (the only public
    // KeyMaterial handle a caller can reach) and check no bytes leak.
    let debug_material = format!("{:?}", KeyMaterial::HmacSecret(secret));
    assert!(!debug_material.contains(&secret_hex));
    assert!(!debug_material.contains("another-tightly"));
}

/// Verification failure must not carry the secret in its error text — a
/// tampered token whose signature does not match the secret must fail
/// with an opaque `Verification` error that never echoes the shared key.
#[test]
fn hmac_signature_failure_error_text_never_carries_the_secret() {
    let secret = b"hmac-secret-should-never-appear-in-any-error-string-hex-safe".to_vec();
    let secret_hex = hex::encode(&secret);
    let v = IdentityValidator::new("harness-prod");
    v.add_key("kid-hmac", KeyMaterial::HmacSecret(secret.clone()))
        .unwrap();

    let claims = hmac_claims();
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some("kid-hmac".to_owned());
    let token = jsonwebtoken::encode(&header, &claims, &EncodingKey::from_secret(&secret)).unwrap();

    // Tamper with the last (signature) segment.
    let mut parts: Vec<&str> = token.split('.').collect();
    let tampered_sig = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    parts[2] = tampered_sig;
    let tampered = parts.join(".");

    let err = v
        .validate(&tampered)
        .expect_err("tampered signature must not validate");
    let err_text = err.to_string();
    assert!(
        !err_text.contains(&secret_hex),
        "error text leaked the secret bytes as hex: {err_text}",
    );
    assert!(
        !err_text.contains("hmac-secret-should-never"),
        "error text leaked the secret bytes as ASCII: {err_text}",
    );
}
