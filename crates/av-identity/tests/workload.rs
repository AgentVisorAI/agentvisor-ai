//! RFC 7523 workload assertions signed with a Cloud Foundry instance
//! identity certificate, verified against the committed test chain
//! (`tests/fixtures/cf-instance-identity`, regenerate with `generate.sh`).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use av_identity::{WorkloadError, WorkloadTrust};
use base64::Engine as _;
use serde_json::json;

const ROOT: &str = include_str!("fixtures/cf-instance-identity/root.pem");
const INTERMEDIATE: &str = include_str!("fixtures/cf-instance-identity/intermediate.pem");
const INSTANCE: &str = include_str!("fixtures/cf-instance-identity/instance.pem");
const INSTANCE_KEY: &str = include_str!("fixtures/cf-instance-identity/instance.key");
const EXPIRED: &str = include_str!("fixtures/cf-instance-identity/expired.pem");
const EXPIRED_KEY: &str = include_str!("fixtures/cf-instance-identity/expired.key");
const ROGUE: &str = include_str!("fixtures/cf-instance-identity/rogue.pem");
const ROGUE_KEY: &str = include_str!("fixtures/cf-instance-identity/rogue.key");

const INSTANCE_GUID: &str = "0b6c1d2e-3f40-4a5b-8c6d-7e8f90a1b2c3";
const AUDIENCE: &str = "agentvisor-ai";

fn der(pem: &str) -> String {
    let body: String = pem.lines().filter(|line| !line.starts_with("-----")).collect();
    // Round-trip to validate and normalize the base64.
    let bytes = base64::engine::general_purpose::STANDARD.decode(body).unwrap();
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn now() -> u64 {
    av_core::time::now_ms() / 1000
}

fn assertion(chain: &[&str], key: &str, claims: serde_json::Value) -> String {
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.x5c = Some(chain.iter().map(|pem| der(pem)).collect());
    jsonwebtoken::encode(
        &header,
        &claims,
        &jsonwebtoken::EncodingKey::from_rsa_pem(key.as_bytes()).unwrap(),
    )
    .unwrap()
}

fn claims(jti: &str) -> serde_json::Value {
    let now = now();
    json!({"iss": INSTANCE_GUID, "sub": INSTANCE_GUID, "aud": AUDIENCE, "iat": now, "exp": now + 120, "jti": jti})
}

fn trust() -> WorkloadTrust {
    WorkloadTrust::from_pem(ROOT.as_bytes()).unwrap()
}

#[test]
fn a_valid_instance_assertion_yields_the_cloud_foundry_identity() {
    let trust = trust();
    let token = assertion(&[INSTANCE, INTERMEDIATE], INSTANCE_KEY, claims("a-1"));
    let verified = trust.verify(&token, AUDIENCE, now()).unwrap();
    assert_eq!(verified.identity.instance_guid, INSTANCE_GUID);
    assert_eq!(verified.identity.app_guid, "7c2d1e3f-4051-4263-b475-96a7b8c9d0e1");
    assert_eq!(
        verified.identity.space_guid,
        "6b1c0d2e-3f40-4152-a364-8596a7b8c9d0"
    );
    assert_eq!(verified.identity.org_guid, "5a0b9c1d-2e3f-4051-9263-748596a7b8c9");
    assert_eq!(verified.jti, "a-1");
}

#[test]
fn an_assertion_cannot_be_replayed() {
    let trust = trust();
    let token = assertion(&[INSTANCE, INTERMEDIATE], INSTANCE_KEY, claims("a-2"));
    trust.verify(&token, AUDIENCE, now()).unwrap();
    assert_eq!(
        trust.verify(&token, AUDIENCE, now()).unwrap_err(),
        WorkloadError::Replay
    );
}

#[test]
fn untrusted_expired_or_incomplete_chains_are_refused() {
    let trust = trust();
    let rogue = assertion(&[ROGUE], ROGUE_KEY, claims("r-1"));
    assert!(matches!(
        trust.verify(&rogue, AUDIENCE, now()),
        Err(WorkloadError::Chain(_))
    ));
    let expired = assertion(&[EXPIRED, INTERMEDIATE], EXPIRED_KEY, claims("e-1"));
    assert!(matches!(
        trust.verify(&expired, AUDIENCE, now()),
        Err(WorkloadError::Chain(_))
    ));
    let missing_intermediate = assertion(&[INSTANCE], INSTANCE_KEY, claims("m-1"));
    assert!(matches!(
        trust.verify(&missing_intermediate, AUDIENCE, now()),
        Err(WorkloadError::Chain(_))
    ));
}

#[test]
fn a_certificate_used_with_another_key_is_refused() {
    let trust = trust();
    let forged = assertion(&[INSTANCE, INTERMEDIATE], EXPIRED_KEY, claims("f-1"));
    assert_eq!(
        trust.verify(&forged, AUDIENCE, now()).unwrap_err(),
        WorkloadError::Signature
    );
}

#[test]
fn claims_are_checked() {
    let trust = trust();
    let now = now();
    let cases = [
        json!({"iss": INSTANCE_GUID, "sub": INSTANCE_GUID, "aud": "someone-else", "iat": now, "exp": now + 60, "jti": "c-1"}),
        json!({"iss": INSTANCE_GUID, "sub": "other-instance", "aud": AUDIENCE, "iat": now, "exp": now + 60, "jti": "c-2"}),
        json!({"iss": INSTANCE_GUID, "sub": INSTANCE_GUID, "aud": AUDIENCE, "iat": now, "exp": now + 3600, "jti": "c-3"}),
        json!({"iss": INSTANCE_GUID, "sub": INSTANCE_GUID, "aud": AUDIENCE, "iat": now - 400, "exp": now - 100, "jti": "c-4"}),
        json!({"iss": INSTANCE_GUID, "sub": INSTANCE_GUID, "aud": AUDIENCE, "iat": now + 600, "exp": now + 700, "jti": "c-5"}),
        json!({"iss": INSTANCE_GUID, "sub": INSTANCE_GUID, "aud": AUDIENCE, "iat": now, "exp": now + 60, "jti": ""}),
        json!({"iss": INSTANCE_GUID, "sub": INSTANCE_GUID, "aud": AUDIENCE, "iat": now, "exp": now + 60}),
    ];
    for (index, case) in cases.into_iter().enumerate() {
        let token = assertion(&[INSTANCE, INTERMEDIATE], INSTANCE_KEY, case);
        assert!(
            matches!(trust.verify(&token, AUDIENCE, now), Err(WorkloadError::Claims(_))),
            "case {index} must be refused"
        );
    }
    let many_audiences = json!({
        "iss": INSTANCE_GUID, "sub": INSTANCE_GUID, "aud": ["x", AUDIENCE], "iat": now, "exp": now + 60, "jti": "c-6"
    });
    let token = assertion(&[INSTANCE, INTERMEDIATE], INSTANCE_KEY, many_audiences);
    assert!(trust.verify(&token, AUDIENCE, now).is_ok());
}

#[test]
fn only_rs256_with_x5c_is_accepted() {
    let trust = trust();
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    header.x5c = Some(vec![der(INSTANCE)]);
    let hmac = jsonwebtoken::encode(
        &header,
        &claims("h-1"),
        &jsonwebtoken::EncodingKey::from_secret(b"secret"),
    )
    .unwrap();
    assert!(matches!(
        trust.verify(&hmac, AUDIENCE, now()),
        Err(WorkloadError::Malformed(_))
    ));
    let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    let no_chain = jsonwebtoken::encode(
        &header,
        &claims("h-2"),
        &jsonwebtoken::EncodingKey::from_rsa_pem(INSTANCE_KEY.as_bytes()).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        trust.verify(&no_chain, AUDIENCE, now()),
        Err(WorkloadError::Malformed(_))
    ));
    assert!(matches!(
        trust.verify("not-a-jwt", AUDIENCE, now()),
        Err(WorkloadError::Malformed(_))
    ));
}

#[test]
fn trust_bundles_must_contain_certificates() {
    assert!(matches!(
        WorkloadTrust::from_pem(b"nothing here"),
        Err(WorkloadError::Config(_))
    ));
    let both = format!("{ROOT}\n{INTERMEDIATE}");
    assert_eq!(
        WorkloadTrust::from_pem(both.as_bytes()).unwrap().anchor_count(),
        2
    );
}
