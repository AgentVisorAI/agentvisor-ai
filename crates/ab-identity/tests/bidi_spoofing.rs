//! Trojan-Source / bidi-override defense tests for NHI identity validation.
//!
//! A hostile IdP that mints tokens with bidirectional-override or
//! zero-width characters in identity fields could make an operator see
//! `instance_uid: "admin"` in a receipt or audit chain while the raw
//! bytes are `admin\u{202E}nimda`. The validator must refuse those
//! tokens up front so no downstream consumer (log, receipt, event chain)
//! ever renders the spoofed identity.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::type_complexity
)]

use ab_identity::{IdentityError, IdentityValidator, KeyMaterial, NhiClaims};
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

fn base_claims() -> NhiClaims {
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

/// Every identity-carrying field must independently refuse a
/// Trojan-Source RLO character; no field is allowed to slip a spoofed
/// glyph past the validator.
#[test]
fn every_identity_field_rejects_the_rlo_override() {
    let keys = ed25519_keys("k1");
    let v = validator(&keys);

    let mutators: Vec<(Box<dyn Fn(&mut NhiClaims)>, &str)> = vec![
        (
            Box::new(|c| c.instance_uid = "admin\u{202E}nimda".into()),
            "instance_uid",
        ),
        (
            Box::new(|c| c.charter = "payments\u{202E}stnemyapx".into()),
            "charter",
        ),
        (Box::new(|c| c.version = "1.0.0\u{202E}0.0.1".into()), "version"),
        (Box::new(|c| c.sub = "agent:legit\u{202E}nimda".into()), "sub"),
        (
            Box::new(|c| c.iss = "https://ok\u{202E}dab.example".into()),
            "iss",
        ),
        (Box::new(|c| c.jti = "id-1\u{202E}spoof".into()), "jti"),
    ];

    for (mutator, field) in mutators {
        let mut claims = base_claims();
        mutator(&mut claims);
        let token = mint(&keys, &claims);
        match v.validate(&token) {
            Err(IdentityError::SpoofingCharacter(bad)) => assert_eq!(bad, field),
            other => panic!("field {field} must be refused: {other:?}"),
        }
    }
}

/// Every other classical bidi / zero-width Trojan-Source glyph must be
/// caught too — this locks the full set of dangerous code points
/// (embedding, override, isolate, marks, zero-widths, BOM).
#[test]
fn every_dangerous_code_point_is_refused_in_instance_uid() {
    let keys = ed25519_keys("k1");
    let v = validator(&keys);
    let dangerous = [
        '\u{061C}', '\u{200B}', '\u{200C}', '\u{200D}', '\u{200E}', '\u{200F}', '\u{202A}', '\u{202B}',
        '\u{202C}', '\u{202D}', '\u{202E}', '\u{2060}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
        '\u{FEFF}',
    ];
    for c in dangerous {
        let mut claims = base_claims();
        claims.instance_uid = format!("legit{c}spoof");
        let token = mint(&keys, &claims);
        match v.validate(&token) {
            Err(IdentityError::SpoofingCharacter("instance_uid")) => {}
            other => panic!("U+{:04X} slipped through: {other:?}", c as u32),
        }
    }
}

/// Sanity: legitimate UTF-8 (non-bidi) content still passes. We don't
/// want a false positive on plain accented text.
#[test]
fn plain_utf8_identity_fields_are_still_accepted() {
    let keys = ed25519_keys("k1");
    let v = validator(&keys);
    let mut claims = base_claims();
    claims.charter = "réseau-paiements".into();
    claims.version = "1.2.3-α".into();
    let token = mint(&keys, &claims);
    v.validate(&token)
        .expect("plain non-bidi UTF-8 must still validate");
}
