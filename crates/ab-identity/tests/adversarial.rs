//! Adversarial NHI validation suite (plan D8/D13.8): forged algs, confusion
//! attacks, TTL abuse, scope escalation, chain-depth abuse, tampering.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use ab_identity::{IdentityError, IdentityValidator, KeyMaterial, NhiClaims, MAX_TTL_SECS};
use base64::Engine as _;
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
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

fn claims(scopes: &[&str], ttl: u64, parent_token: Option<String>) -> NhiClaims {
    let iat = now_s();
    NhiClaims {
        sub: "agent:test".into(),
        iss: "https://idp.example.com".into(),
        aud: "harness-prod".into(),
        iat,
        nbf: None,
        exp: iat + ttl,
        jti: ab_core::new_event_uid(),
        instance_uid: "inst-1".into(),
        charter: "support".into(),
        version: "1.2.3".into(),
        scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
        parent_token,
    }
}

fn mint(keys: &TestKeys, claims: &NhiClaims) -> String {
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(keys.kid.clone());
    jsonwebtoken::encode(&header, claims, &keys.encoding).unwrap()
}

fn validator(keys: &TestKeys) -> IdentityValidator {
    let mut v = IdentityValidator::new("harness-prod");
    v.add_key(keys.kid.clone(), KeyMaterial::Ed25519Pem(keys.public_pem.clone()));
    v
}

#[test]
fn valid_token_accepted_with_identity_block() {
    let keys = ed25519_keys("k1");
    let v = validator(&keys);
    let token = mint(&keys, &claims(&["tool:read"], 600, None));
    let id = v.validate(&token).unwrap();
    assert_eq!(id.chain_depth, 0);
    assert!(id.ttl_remaining_s > 500 && id.ttl_remaining_s <= 600);
    let block = id.agent_identity();
    assert_eq!(block.instance_uid, "inst-1");
    assert_eq!(block.charter, "support");
    assert_eq!(block.version, "1.2.3");
    assert!(block.ttl_remaining_s.is_some());
}

#[test]
fn ttl_over_15_minutes_rejected() {
    let keys = ed25519_keys("k1");
    let v = validator(&keys);
    let token = mint(&keys, &claims(&[], MAX_TTL_SECS + 1, None));
    assert!(matches!(v.validate(&token), Err(IdentityError::TtlTooLong(_))));
    // Exactly 15 minutes is fine.
    let token = mint(&keys, &claims(&[], MAX_TTL_SECS, None));
    v.validate(&token).unwrap();
}

#[test]
fn expired_token_rejected() {
    let keys = ed25519_keys("k1");
    let v = validator(&keys);
    let mut c = claims(&[], 600, None);
    c.iat = now_s() - 800;
    c.exp = now_s() - 200; // expired beyond the 30s leeway
    let token = mint(&keys, &c);
    assert!(matches!(v.validate(&token), Err(IdentityError::Verification(_))));
}

#[test]
fn future_nbf_rejected() {
    let keys = ed25519_keys("k1");
    let v = validator(&keys);
    let mut c = claims(&[], 600, None);
    c.nbf = Some(now_s() + 300);
    let token = mint(&keys, &c);
    assert!(matches!(v.validate(&token), Err(IdentityError::Verification(_))));
}

#[test]
fn wrong_audience_rejected() {
    let keys = ed25519_keys("k1");
    let v = validator(&keys);
    let mut c = claims(&[], 600, None);
    c.aud = "other-deployment".into();
    let token = mint(&keys, &c);
    assert!(matches!(v.validate(&token), Err(IdentityError::Verification(_))));
}

#[test]
fn issuer_allowlist_enforced() {
    let keys = ed25519_keys("k1");
    let mut v = validator(&keys);
    v.allow_issuers(vec!["https://okta.example.com".into()]);
    let token = mint(&keys, &claims(&[], 600, None));
    assert!(matches!(v.validate(&token), Err(IdentityError::BadIssuer(_))));
}

#[test]
fn alg_none_rejected() {
    let keys = ed25519_keys("k1");
    let v = validator(&keys);
    // Hand-forge an alg=none token with our kid.
    let b64 = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
    let header = b64(br#"{"alg":"none","typ":"JWT","kid":"k1"}"#);
    let payload = b64(serde_json::to_vec(&claims(&["tool:admin"], 600, None)).unwrap().as_slice());
    for forged in [format!("{header}.{payload}."), format!("{header}.{payload}")] {
        let err = v.validate(&forged);
        assert!(err.is_err(), "alg=none accepted: {forged}");
    }
}

#[test]
fn algorithm_confusion_hs256_signed_with_public_pem_rejected() {
    // Classic confusion: attacker HMAC-signs with the *public* PEM bytes and
    // labels the token HS256. The kid maps to an Ed25519 key, so the stated
    // alg must be refused before any verification is attempted.
    let keys = ed25519_keys("k1");
    let v = validator(&keys);
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some("k1".into());
    let forged = jsonwebtoken::encode(
        &header,
        &claims(&["tool:admin"], 600, None),
        &EncodingKey::from_secret(keys.public_pem.as_bytes()),
    )
    .unwrap();
    assert!(matches!(v.validate(&forged), Err(IdentityError::AlgorithmRejected { .. })));
}

#[test]
fn wrong_key_signature_rejected() {
    let real = ed25519_keys("k1");
    let attacker = ed25519_keys("k1"); // same kid, different key
    let v = validator(&real);
    let forged = mint(&attacker, &claims(&["tool:admin"], 600, None));
    assert!(matches!(v.validate(&forged), Err(IdentityError::Verification(_))));
}

#[test]
fn tampered_payload_rejected() {
    let keys = ed25519_keys("k1");
    let v = validator(&keys);
    let token = mint(&keys, &claims(&["tool:read"], 600, None));
    let mut parts: Vec<String> = token.split('.').map(str::to_owned).collect();
    // Bit-flip inside the payload.
    let mut payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&parts[1]).unwrap();
    payload[10] ^= 1;
    parts[1] = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&payload);
    let tampered = parts.join(".");
    assert!(v.validate(&tampered).is_err());
}

#[test]
fn truncated_token_rejected() {
    let keys = ed25519_keys("k1");
    let v = validator(&keys);
    let token = mint(&keys, &claims(&[], 600, None));
    for cut in [token.len() - 1, token.len() / 2, 10, 1] {
        assert!(v.validate(&token[..cut]).is_err(), "truncation at {cut} accepted");
    }
    assert!(v.validate("").is_err());
}

#[test]
fn missing_and_unknown_kid_rejected() {
    let keys = ed25519_keys("k1");
    let v = validator(&keys);
    // No kid at all.
    let header = Header::new(Algorithm::EdDSA);
    let token = jsonwebtoken::encode(&header, &claims(&[], 600, None), &keys.encoding).unwrap();
    assert!(matches!(v.validate(&token), Err(IdentityError::MissingKid)));
    // Unknown kid.
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some("k-unknown".into());
    let token = jsonwebtoken::encode(&header, &claims(&[], 600, None), &keys.encoding).unwrap();
    assert!(matches!(v.validate(&token), Err(IdentityError::UnknownKid(_))));
}

#[test]
fn empty_identity_fields_rejected() {
    let keys = ed25519_keys("k1");
    let v = validator(&keys);
    for field in ["instance_uid", "charter", "version"] {
        let mut c = claims(&[], 600, None);
        match field {
            "instance_uid" => c.instance_uid = String::new(),
            "charter" => c.charter = String::new(),
            _ => c.version = String::new(),
        }
        let token = mint(&keys, &c);
        assert!(
            matches!(v.validate(&token), Err(IdentityError::EmptyField(_))),
            "empty {field} accepted"
        );
    }
}

// ---------- Delegation (scope inheritance) ----------

#[test]
fn valid_delegation_chain_accepted() {
    let keys = ed25519_keys("k1");
    let v = validator(&keys);
    let parent = claims(&["tool:read", "tool:write", "payout"], 800, None);
    let parent_token = mint(&keys, &parent);
    let mut child = claims(&["tool:read"], 600, Some(parent_token));
    child.exp = parent.exp - 10;
    child.sub = "agent:child".into();
    let id = v.validate(&mint(&keys, &child)).unwrap();
    assert_eq!(id.chain_depth, 1);
    assert_eq!(id.claims.sub, "agent:child");
}

#[test]
fn scope_escalation_rejected_at_any_link() {
    let keys = ed25519_keys("k1");
    let v = validator(&keys);
    // Parent has read only; child claims write.
    let parent = claims(&["tool:read"], 800, None);
    let parent_token = mint(&keys, &parent);
    let mut child = claims(&["tool:read", "tool:write"], 600, Some(parent_token));
    child.exp = parent.exp - 10;
    let err = v.validate(&mint(&keys, &child));
    assert!(
        matches!(err, Err(IdentityError::ScopeEscalation { ref scope }) if scope == "tool:write"),
        "{err:?}"
    );

    // Grandparent(read) -> parent(read,FORGED write) -> child(write):
    // escalation must be caught at the parent/grandparent link.
    let grandparent = claims(&["tool:read"], 890, None);
    let gp_token = mint(&keys, &grandparent);
    let mut parent2 = claims(&["tool:read", "tool:write"], 700, Some(gp_token));
    parent2.exp = grandparent.exp - 10;
    let p2_token = mint(&keys, &parent2);
    let mut child2 = claims(&["tool:write"], 600, Some(p2_token));
    child2.exp = parent2.exp - 10;
    assert!(matches!(
        v.validate(&mint(&keys, &child2)),
        Err(IdentityError::ScopeEscalation { .. })
    ));
}

#[test]
fn child_outliving_parent_rejected() {
    let keys = ed25519_keys("k1");
    let v = validator(&keys);
    let parent = claims(&["tool:read"], 300, None);
    let parent_token = mint(&keys, &parent);
    let mut child = claims(&["tool:read"], 600, Some(parent_token)); // exp beyond parent
    child.exp = parent.exp + 100;
    assert!(matches!(v.validate(&mint(&keys, &child)), Err(IdentityError::ExpEscalation { .. })));
}

#[test]
fn chain_depth_capped() {
    let keys = ed25519_keys("k1");
    let mut v = validator(&keys);
    v.set_max_chain_depth(2);
    let mut token = mint(&keys, &claims(&["s"], 890, None));
    for i in 0..3u64 {
        let mut c = claims(&["s"], 800 - i * 100, Some(token.clone()));
        c.exp = now_s() + 500 - i * 100;
        token = mint(&keys, &c);
    }
    assert!(matches!(v.validate(&token), Err(IdentityError::ChainTooDeep(2))));
}

#[test]
fn expired_parent_invalidates_child() {
    let keys = ed25519_keys("k1");
    let v = validator(&keys);
    let mut parent = claims(&["tool:read"], 600, None);
    parent.iat = now_s() - 800;
    parent.exp = now_s() - 100; // parent already expired
    let parent_token = mint(&keys, &parent);
    let mut child = claims(&["tool:read"], 300, Some(parent_token));
    child.exp = now_s() + 300;
    // Child alone is valid, but its lineage is dead → reject.
    assert!(v.validate(&mint(&keys, &child)).is_err());
}

// ---------- HS256 dev path ----------

#[test]
fn hs256_with_shared_secret_works_and_is_isolated() {
    let mut v = IdentityValidator::new("harness-prod");
    v.add_key("hmac-1", KeyMaterial::HmacSecret(b"super-secret-dev-key".to_vec()));
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some("hmac-1".into());
    let token = jsonwebtoken::encode(
        &header,
        &claims(&["tool:read"], 600, None),
        &EncodingKey::from_secret(b"super-secret-dev-key"),
    )
    .unwrap();
    v.validate(&token).unwrap();

    // EdDSA-labeled token pointing at the HMAC kid must be refused (confusion, reverse direction).
    let ed = ed25519_keys("hmac-1");
    let forged = mint(&ed, &claims(&["tool:admin"], 600, None));
    assert!(matches!(v.validate(&forged), Err(IdentityError::AlgorithmRejected { .. })));
}
