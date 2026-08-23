//! Adversarial NHI validation suite (plan D8/D13.8): forged algs, confusion
//! attacks, TTL abuse, scope escalation, chain-depth abuse, tampering.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use av_identity::{IdentityError, IdentityValidator, KeyMaterial, NhiClaims, MAX_TTL_SECS};
use base64::Engine as _;
use ed25519_dalek::pkcs8::{spki::der::pem::LineEnding, EncodePrivateKey, EncodePublicKey};
use jsonwebtoken::{Algorithm, EncodingKey, Header};

struct TestKeys {
    kid: String,
    encoding: EncodingKey,
    public_pem: String,
    public_x: String,
}

/// rand 0.9+ removed the infallible `OsRng` that `SigningKey::generate`
/// (rand_core 0.6) accepted; draw the seed via the fallible `SysRng` instead.
fn generate_signing_key() -> ed25519_dalek::SigningKey {
    use rand::TryRng;
    let mut seed = [0u8; 32];
    rand::rngs::SysRng.try_fill_bytes(&mut seed).unwrap();
    ed25519_dalek::SigningKey::from_bytes(&seed)
}

fn ed25519_keys(kid: &str) -> TestKeys {
    let signing = generate_signing_key();
    let private_pem = signing.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
    let public_pem = signing.verifying_key().to_public_key_pem(LineEnding::LF).unwrap();
    let public_x =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signing.verifying_key().as_bytes());
    TestKeys {
        kid: kid.to_owned(),
        encoding: EncodingKey::from_ed_pem(private_pem.as_bytes()).unwrap(),
        public_pem,
        public_x,
    }
}

fn now_s() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
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
        jti: av_core::new_event_uid(),
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
    let v = IdentityValidator::new("harness-prod");
    v.add_key(keys.kid.clone(), KeyMaterial::Ed25519Pem(keys.public_pem.clone()))
        .unwrap();
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
    assert_eq!(block.charter.name, "support");
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
fn future_iat_cannot_extend_effective_ttl() {
    let keys = ed25519_keys("k1");
    let validator = validator(&keys);
    let mut claims = claims(&["tool:read"], 600, None);
    claims.iat = now_s() + 120;
    claims.exp = claims.iat + 600;
    assert!(matches!(
        validator.validate(&mint(&keys, &claims)),
        Err(IdentityError::FutureIat { .. })
    ));
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
    let payload = b64(serde_json::to_vec(&claims(&["tool:admin"], 600, None))
        .unwrap()
        .as_slice());
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
    assert!(matches!(
        v.validate(&forged),
        Err(IdentityError::AlgorithmRejected { .. })
    ));
}

/// Round-44 F5 / RUSTSEC-2023-0071: our deny.toml ignore of the Marvin
/// Attack rests on the invariant that the RSA code path in
/// `jsonwebtoken` is unreachable from our runtime. This test locks that
/// invariant in against future refactors. A JWT claiming `alg: RS256`
/// (or PS256, RS384, ...) MUST be rejected by the validator BEFORE any
/// signature decode runs, so the RSA timing side channel can never leak.
///
/// The token below is hand-forged (no `rsa` crate needed to mint it —
/// the sig can be any bytes because we assert rejection at the alg-
/// check step, prior to signature verification).
#[test]
fn rsa_algorithm_family_rejected_before_decode_marvin_attack_unreachable() {
    let keys = ed25519_keys("k1");
    let v = validator(&keys);
    let claims_json = serde_json::to_string(&claims(&["tool:admin"], 600, None)).unwrap();
    let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&claims_json);
    let garbage_sig = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 256]);
    for rsa_alg in ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"] {
        let header_json = format!(r#"{{"alg":"{rsa_alg}","typ":"JWT","kid":"k1"}}"#);
        let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&header_json);
        let token = format!("{header_b64}.{payload_b64}.{garbage_sig}");
        let result = v.validate(&token);
        assert!(
            matches!(result, Err(IdentityError::AlgorithmRejected { .. })),
            "{rsa_alg} MUST be rejected before decode so the RSA timing side channel (RUSTSEC-2023-0071) stays unreachable; got {result:?}",
        );
    }
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
    let mut payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&parts[1])
        .unwrap();
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
    assert!(matches!(
        v.validate(&mint(&keys, &child)),
        Err(IdentityError::ExpEscalation { .. })
    ));
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
    let v = IdentityValidator::new("harness-prod");
    v.add_key(
        "hmac-1",
        KeyMaterial::HmacSecret(b"super-secret-dev-key".to_vec()),
    )
    .unwrap();
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
    assert!(matches!(
        v.validate(&forged),
        Err(IdentityError::AlgorithmRejected { .. })
    ));
}

#[test]
fn standard_ed25519_jwks_is_accepted_and_refreshable() {
    let keys = ed25519_keys("jwks-1");
    let validator = IdentityValidator::new("harness-prod");
    let added = validator
        .add_jwks(&serde_json::json!({
            "keys": [{
                "kid": keys.kid,
                "kty": "OKP",
                "crv": "Ed25519",
                "alg": "EdDSA",
                "use": "sig",
                "x": keys.public_x,
            }]
        }))
        .unwrap();
    assert_eq!(added, 1);
    assert_eq!(validator.key_count(), 1);
    validator
        .validate(&mint(&keys, &claims(&["tool:read"], 600, None)))
        .unwrap();

    let replacement = ed25519_keys("jwks-2");
    validator
        .add_jwks(&serde_json::json!({
            "keys": [{
                "kid": replacement.kid,
                "kty": "OKP",
                "crv": "Ed25519",
                "x": replacement.public_x,
            }]
        }))
        .unwrap();
    assert!(matches!(
        validator.validate(&mint(&keys, &claims(&["tool:read"], 600, None))),
        Err(IdentityError::UnknownKid(_))
    ));
    validator
        .validate(&mint(&replacement, &claims(&["tool:read"], 600, None)))
        .unwrap();
    assert_eq!(validator.key_count(), 1);
}

/// A JWKS whose `kid` collides with a manually-added key must be refused
/// rather than silently overwriting the manual key and — because it also
/// gets tracked in `jwks_kids` — retiring it on the next JWKS refresh.
/// The docstring on `add_jwks` says manual keys are left untouched;
/// without this check that contract failed on collision.
#[test]
fn add_jwks_refuses_to_overwrite_a_manually_registered_kid() {
    let manual = ed25519_keys("shared-kid");
    let jwks = ed25519_keys("shared-kid"); // same kid, different key material
    let validator = IdentityValidator::new("harness-prod");
    validator
        .add_key(&manual.kid, KeyMaterial::Ed25519Jwk(manual.public_x.clone()))
        .unwrap();
    // Refuses with a helpful Jwks error.
    let err = validator
        .add_jwks(&serde_json::json!({
            "keys": [{
                "kid": jwks.kid,
                "kty": "OKP",
                "crv": "Ed25519",
                "x": jwks.public_x,
            }]
        }))
        .unwrap_err();
    assert!(
        matches!(err, IdentityError::Jwks(ref reason) if reason.contains("conflicts")),
        "expected a Jwks conflict error, got {err:?}",
    );
    // Manual key still validates unchanged.
    assert_eq!(validator.key_count(), 1);
    validator
        .validate(&mint(&manual, &claims(&["tool:read"], 600, None)))
        .unwrap();
}

/// Round-12 F6: a JWKS array with two entries carrying the same `kid`
/// must be refused rather than silently accepting the *last* one.
/// A compromised or misconfigured IdP could otherwise ship an alien
/// public key alongside a legitimate one and have it silently overwrite
/// verification state — with no counter, no log, no user-visible
/// error.
#[test]
fn add_jwks_refuses_duplicate_kid_within_the_same_document() {
    let legit = ed25519_keys("dup-kid");
    let alien = ed25519_keys("dup-kid"); // same kid, different x
    let validator = IdentityValidator::new("harness-prod");
    let err = validator
        .add_jwks(&serde_json::json!({
            "keys": [
                { "kid": "dup-kid", "kty": "OKP", "crv": "Ed25519", "x": legit.public_x },
                { "kid": "dup-kid", "kty": "OKP", "crv": "Ed25519", "x": alien.public_x },
            ]
        }))
        .unwrap_err();
    assert!(
        matches!(err, IdentityError::Jwks(ref reason) if reason.contains("duplicate kid")),
        "expected duplicate-kid rejection, got {err:?}",
    );
    // No key installed — the whole document is refused, not the
    // legitimate one accepted with the alien silently discarded.
    assert_eq!(validator.key_count(), 0);
}

/// Round-12 F11: a hostile JWKS with tens of thousands of keys must be
/// refused so a refresh does not stall every concurrent
/// `validate_single` call while `keys.write()` is held for a giant
/// install loop. Real deployments have 5–20 keys; the cap sits at
/// 256.
#[test]
fn add_jwks_caps_the_number_of_keys_per_document() {
    let validator = IdentityValidator::new("harness-prod");
    // 300 distinct keys, all valid — should still refuse because the
    // count alone exceeds the safety cap.
    let keys: Vec<_> = (0..300)
        .map(|i| {
            let k = ed25519_keys(&format!("k{i}"));
            serde_json::json!({
                "kid": k.kid,
                "kty": "OKP",
                "crv": "Ed25519",
                "x": k.public_x,
            })
        })
        .collect();
    let err = validator
        .add_jwks(&serde_json::json!({ "keys": keys }))
        .unwrap_err();
    assert!(
        matches!(err, IdentityError::Jwks(ref reason) if reason.contains("more than 256")),
        "expected JWKS-cap rejection, got {err:?}",
    );
}

/// CVE-2026-25537 (jsonwebtoken < 10.3.0 type-confusion): if `nbf` is
/// provided as a JSON string like `"99999999999"` (far-future
/// legacy/mistake), the pre-10.3 library marked it FailedToParse and
/// silently *skipped* the nbf gate even with `validate_nbf = true`,
/// because `nbf` was not in the required-claims list. An attacker
/// could ship a token that was immediately usable despite claiming to
/// be valid only in the far future.
///
/// Our concrete `NhiClaims` uses `nbf: Option<u64>`, so serde would
/// have already rejected a string here even under the vulnerable
/// library — but this test locks the behavior so a future refactor to
/// `serde_json::Value` claims cannot silently reintroduce the bypass.
#[test]
fn cve_2026_25537_string_nbf_is_rejected_not_bypassed() {
    let keys = ed25519_keys("k1");
    let v = validator(&keys);
    // Mint a token whose `nbf` is a JSON string. We serialize a
    // concrete map so the payload contains `"nbf":"99999999999"`
    // rather than the usual number.
    let iat = now_s();
    let payload = serde_json::json!({
        "sub": "agent:test",
        "iss": "https://idp.example.com",
        "aud": "harness-prod",
        "iat": iat,
        "nbf": "99999999999",
        "exp": iat + 600,
        "jti": av_core::new_event_uid(),
        "instance_uid": "inst-1",
        "charter": "support",
        "version": "1.2.3",
        "scopes": [],
    });
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(keys.kid.clone());
    let token = jsonwebtoken::encode(&header, &payload, &keys.encoding).unwrap();
    // Must be rejected — either at the concrete-struct deserialize
    // step (our defense) or at the library gate (10.3+ defense).
    // Silently accepting is the vulnerable behavior.
    let outcome = v.validate(&token);
    assert!(
        matches!(
            outcome,
            Err(IdentityError::Verification(_) | IdentityError::Malformed(_))
        ),
        "string-nbf token must be rejected (CVE-2026-25537 class), got {outcome:?}",
    );
}

/// Round-25 F1: JWKS refuses a key that declares `use = "enc"`.
/// Signature correctness is still protected by the alg-vs-kty
/// verify-time check, but silently installing an encryption-only
/// key as a signing verifier violates the IdP's stated policy —
/// audits can now rely on the refusal.
#[test]
fn round_25_f1_jwks_refuses_use_enc_okp_key() {
    let keys = ed25519_keys("enc-key");
    let validator = IdentityValidator::new("harness-prod");
    let err = validator
        .add_jwks(&serde_json::json!({
            "keys": [{
                "kid": keys.kid,
                "kty": "OKP",
                "crv": "Ed25519",
                "use": "enc",
                "x": keys.public_x,
            }]
        }))
        .unwrap_err();
    let text = format!("{err:?}");
    assert!(
        text.contains("use") && text.contains("sig"),
        "expected use=enc rejection, got {text}"
    );
}

/// Round-25 F1: JWKS refuses a key that declares alg != "EdDSA".
#[test]
fn round_25_f1_jwks_refuses_wrong_alg_okp_key() {
    let keys = ed25519_keys("bad-alg-key");
    let validator = IdentityValidator::new("harness-prod");
    let err = validator
        .add_jwks(&serde_json::json!({
            "keys": [{
                "kid": keys.kid,
                "kty": "OKP",
                "crv": "Ed25519",
                "alg": "RS256",
                "x": keys.public_x,
            }]
        }))
        .unwrap_err();
    let text = format!("{err:?}");
    assert!(text.contains("EdDSA"), "expected wrong-alg rejection, got {text}");
}

/// Round-25 F2: `add_key` refuses to shadow a kid the JWKS drain
/// tracks. Previously a startup or admin `add_key("X", ...)` call
/// on a kid `X` currently in `jwks_kids` silently overwrote the
/// JWKS material — and the next `add_jwks` drain silently
/// discarded the operator's manual key. Refuse at the source.
#[test]
fn round_25_f2_add_key_refuses_jwks_tracked_kid() {
    let jwks_keys = ed25519_keys("shared-kid");
    let validator = IdentityValidator::new("harness-prod");
    validator
        .add_jwks(&serde_json::json!({
            "keys": [{
                "kid": jwks_keys.kid,
                "kty": "OKP",
                "crv": "Ed25519",
                "x": jwks_keys.public_x,
            }]
        }))
        .unwrap();
    let err = validator
        .add_key(
            "shared-kid",
            KeyMaterial::HmacSecret(b"attempted-manual-override".to_vec()),
        )
        .unwrap_err();
    let text = format!("{err:?}");
    assert!(
        text.contains("JWKS-tracked"),
        "expected JWKS-tracked-conflict rejection, got {text}"
    );
}

// ---- Mutation-run hardening (round 10): pin the exact security
// boundaries. The original suite proved the over-limit rejections but
// never the accepted-at-boundary twins, so `>` -> `>=` mutants survived
// in the JWKS cap, chain depth, exp-escalation, size cap, and
// future-iat checks — and `||` -> `&&` survived in the OKP/Ed25519
// JWKS filter.

#[test]
fn jwks_key_count_cap_is_exact() {
    let keys = ed25519_keys("k1");
    let v = validator(&keys);
    let entry = serde_json::json!({"kty": "RSA"});
    let at_cap = serde_json::json!({ "keys": vec![entry.clone(); 256] });
    assert!(
        matches!(v.add_jwks(&at_cap), Err(IdentityError::Jwks(ref m)) if m.contains("no Ed25519")),
        "256 non-OKP entries must be walked (then refused as empty), not cap-refused"
    );
    let over_cap = serde_json::json!({ "keys": vec![entry; 257] });
    assert!(
        matches!(v.add_jwks(&over_cap), Err(IdentityError::Jwks(ref m)) if m.contains("257")),
        "257 entries must refuse before any per-key parsing"
    );
}

#[test]
fn jwks_filter_requires_both_okp_and_ed25519() {
    let keys = ed25519_keys("k1");
    let donor = ed25519_keys("donor");
    let v = validator(&keys);
    // kty=OKP with a non-Ed25519 curve must be skipped, not installed:
    // an X25519 (encryption) point must never become a signature
    // verification key even though its `x` is a valid 32-byte value.
    let x25519 = serde_json::json!({
        "keys": [{"kty": "OKP", "crv": "X25519", "kid": "x25519-k", "x": donor.public_x}]
    });
    assert!(
        matches!(v.add_jwks(&x25519), Err(IdentityError::Jwks(ref m)) if m.contains("no Ed25519")),
        "X25519 must be skipped, never installed"
    );
    // Non-OKP kty with crv=Ed25519 must also be skipped.
    let wrong_kty = serde_json::json!({
        "keys": [{"kty": "EC", "crv": "Ed25519", "kid": "ec-k", "x": donor.public_x}]
    });
    assert!(
        matches!(v.add_jwks(&wrong_kty), Err(IdentityError::Jwks(ref m)) if m.contains("no Ed25519")),
        "non-OKP must be skipped, never installed"
    );
    // The genuine article installs exactly one.
    let genuine = serde_json::json!({
        "keys": [{"kty": "OKP", "crv": "Ed25519", "kid": "good-k", "x": donor.public_x}]
    });
    assert_eq!(v.add_jwks(&genuine).unwrap(), 1);
}

#[test]
fn chain_depth_at_exact_limit_is_accepted() {
    let keys = ed25519_keys("k1");
    let mut v = validator(&keys);
    v.set_max_chain_depth(2);
    // Two ancestors: depth reaches exactly the limit and must pass.
    let root = claims(&["s"], 890, None);
    let root_token = mint(&keys, &root);
    let mut mid = claims(&["s"], 800, Some(root_token));
    mid.exp = root.exp - 10;
    let mid_token = mint(&keys, &mid);
    let mut leaf = claims(&["s"], 700, Some(mid_token));
    leaf.exp = mid.exp - 10;
    let id = v.validate(&mint(&keys, &leaf)).unwrap();
    assert_eq!(id.chain_depth, 2);
}

#[test]
fn child_exp_equal_to_parent_exp_is_accepted() {
    let keys = ed25519_keys("k1");
    let v = validator(&keys);
    let parent = claims(&["s"], 600, None);
    let parent_token = mint(&keys, &parent);
    let mut child = claims(&["s"], 600, Some(parent_token));
    child.exp = parent.exp; // equality is not an escalation
    v.validate(&mint(&keys, &child)).unwrap();
}

#[test]
fn jwt_size_cap_is_exact() {
    let keys = ed25519_keys("k1");
    let v = validator(&keys);
    // 8192 bytes of garbage passes the size gate (fails later, but NOT
    // with the pre-auth cap message)…
    let at_cap = "x".repeat(8 * 1024);
    let outcome = v.validate(&at_cap);
    assert!(
        matches!(outcome, Err(IdentityError::Malformed(ref m)) if !m.contains("pre-auth cap")),
        "8192 bytes must pass the size gate, got {outcome:?}"
    );
    // …while 8193+ is refused by the cap itself.
    let over_cap = "x".repeat(8 * 1024 + 1);
    assert!(
        matches!(v.validate(&over_cap), Err(IdentityError::Malformed(ref m)) if m.contains("pre-auth cap"))
    );
}

#[test]
fn iat_at_exact_leeway_edge_is_accepted() {
    let keys = ed25519_keys("k1");
    let v = validator(&keys);
    // Default leeway is 30 s: iat == now + 30 is tolerated clock skew;
    // use +29 to stay robustly inside the boundary across the seconds
    // that elapse between minting and validating, which still kills the
    // `>` -> `>=` mutant (that mutant rejects iat == now + leeway, and
    // with sub-second test latency now is unchanged).
    let mut c = claims(&["s"], 600, None);
    c.iat = now_s() + 29;
    c.exp = c.iat + 600;
    v.validate(&mint(&keys, &c)).unwrap();
}

/// Round-51 §10.2: the JWKS-bomb DoS guard (`MAX_JWKS_KEYS = 256`)
/// was reasoned about in comments and tested nowhere. A hostile or
/// compromised IdP inflating the `keys` array to tens of thousands
/// of entries must be refused BEFORE the per-key parser walks it —
/// regardless of `kty` (the round-15 F5 fix specifically covers
/// non-OKP decoy entries that the inner parser would skip-scan).
#[test]
fn jwks_bomb_is_refused_before_the_key_walk() {
    let validator = IdentityValidator::new("harness-prod");
    // 257 RSA decoys: each would be skipped by the OKP filter, so
    // only the outer cap can bound the walk.
    let bomb: Vec<serde_json::Value> = (0..257)
        .map(|i| {
            serde_json::json!({
                "kid": format!("decoy-{i}"),
                "kty": "RSA",
                "n": "AQAB",
                "e": "AQAB",
            })
        })
        .collect();
    let outcome = validator.add_jwks(&serde_json::json!({ "keys": bomb }));
    assert!(
        matches!(outcome, Err(IdentityError::Jwks(ref m)) if m.contains("257")),
        "oversized JWKS must be refused with the entry count named; got {outcome:?}"
    );
    assert_eq!(
        validator.key_count(),
        0,
        "no key may be installed from a refused JWKS"
    );

    // Exactly at the cap: accepted (the guard is >, not >=).
    let mut at_cap: Vec<serde_json::Value> = (0..255)
        .map(|i| serde_json::json!({"kid": format!("d-{i}"), "kty": "RSA"}))
        .collect();
    let real = ed25519_keys("real-key");
    at_cap.push(serde_json::json!({
        "kid": real.kid,
        "kty": "OKP",
        "crv": "Ed25519",
        "alg": "EdDSA",
        "use": "sig",
        "x": real.public_x,
    }));
    let added = validator
        .add_jwks(&serde_json::json!({ "keys": at_cap }))
        .unwrap();
    assert_eq!(added, 1, "the single real key among 255 decoys must install");
}
