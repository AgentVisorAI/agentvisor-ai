//! Revocation through the validator: leaf and delegation-chain JTIs, the
//! shared-store accessor, and fail-closed behavior when the store is down.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use av_identity::{
    IdentityError, IdentityValidator, InMemoryRevocationStore, KeyMaterial, NhiClaims, RevocationStore,
};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use std::sync::Arc;

const SECRET: &[u8] = b"revocation-suite-hmac-secret-0123456789";
const KID: &str = "rev-kid";
const AUDIENCE: &str = "harness-prod";

fn now_s() -> u64 {
    av_core::time::now_ms() / 1000
}

fn claims(jti: &str, scopes: &[&str], ttl: u64, parent_token: Option<String>) -> NhiClaims {
    let iat = now_s();
    NhiClaims {
        sub: "user:alice@corp.com".into(),
        iss: "https://idp.example.com".into(),
        aud: AUDIENCE.into(),
        iat,
        nbf: None,
        exp: iat + ttl,
        jti: jti.into(),
        azp: None,
        act: None,
        instance_uid: "inst-1".into(),
        charter: "support".into(),
        version: "1.0".into(),
        scopes: scopes.iter().map(|scope| (*scope).to_owned()).collect(),
        parent_token,
    }
}

fn mint_with(secret: &[u8], claims: &NhiClaims) -> String {
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some(KID.to_owned());
    jsonwebtoken::encode(&header, claims, &EncodingKey::from_secret(secret)).unwrap()
}

fn mint(claims: &NhiClaims) -> String {
    mint_with(SECRET, claims)
}

fn validator_with(store: Arc<dyn RevocationStore>) -> IdentityValidator {
    let mut validator = IdentityValidator::new(AUDIENCE);
    validator
        .add_key(KID, KeyMaterial::HmacSecret(SECRET.to_vec()))
        .unwrap();
    validator.set_revocation_store(store);
    validator
}

struct UnreachableStore;

impl RevocationStore for UnreachableStore {
    fn revoke(&self, _jti: &str, _expires_at: u64) -> Result<(), String> {
        Err("store offline".into())
    }

    fn is_revoked(&self, _jti: &str) -> Result<bool, String> {
        Err("store offline".into())
    }
}

#[test]
fn unrevoked_token_validates() {
    let validator = validator_with(Arc::new(InMemoryRevocationStore::new()));
    let token = mint(&claims("jti-live", &["tool:read"], 300, None));
    assert_eq!(validator.validate(&token).unwrap().claims.jti, "jti-live");
}

#[test]
fn revoked_leaf_token_is_refused() {
    let store = Arc::new(InMemoryRevocationStore::new());
    let validator = validator_with(Arc::clone(&store) as Arc<dyn RevocationStore>);
    let token = mint(&claims("jti-leaf", &["tool:read"], 300, None));
    assert!(validator.validate(&token).is_ok());
    store.revoke("jti-leaf", now_s() + 300).unwrap();
    assert_eq!(
        validator.validate(&token).unwrap_err(),
        IdentityError::Revoked("jti-leaf".into())
    );
}

#[test]
fn revoking_a_delegator_cuts_off_its_delegated_tokens() {
    let store = Arc::new(InMemoryRevocationStore::new());
    let validator = validator_with(Arc::clone(&store) as Arc<dyn RevocationStore>);
    let parent = mint(&claims("jti-parent", &["tool:*"], 300, None));
    let child = mint(&claims("jti-child", &["tool:lookup"], 200, Some(parent)));
    assert!(
        validator.validate(&child).is_ok(),
        "the chain is valid before revocation"
    );

    store.revoke("jti-parent", now_s() + 300).unwrap();
    assert_eq!(
        validator.validate(&child).unwrap_err(),
        IdentityError::Revoked("jti-parent".into()),
        "a child must not outlive its delegator's revocation"
    );
}

#[test]
fn unreachable_store_fails_closed_with_a_distinct_error() {
    let validator = validator_with(Arc::new(UnreachableStore));
    let token = mint(&claims("jti-any", &["tool:read"], 300, None));
    match validator.validate(&token) {
        Err(IdentityError::RevocationUnavailable(detail)) => assert!(detail.contains("offline")),
        other => panic!("expected RevocationUnavailable, got {other:?}"),
    }
}

#[test]
fn revocation_store_accessor_shares_the_validators_list() {
    let validator = validator_with(Arc::new(InMemoryRevocationStore::new()));
    let token = mint(&claims("jti-shared", &["tool:read"], 300, None));
    validator
        .revocation_store()
        .expect("store attached")
        .revoke("jti-shared", now_s() + 300)
        .unwrap();
    assert_eq!(
        validator.validate(&token).unwrap_err(),
        IdentityError::Revoked("jti-shared".into())
    );
}

#[test]
fn forged_tokens_cannot_probe_the_revocation_list() {
    let store = Arc::new(InMemoryRevocationStore::new());
    store.revoke("jti-probe", now_s() + 300).unwrap();
    let validator = validator_with(Arc::clone(&store) as Arc<dyn RevocationStore>);
    let forged = mint_with(
        b"attacker-secret-not-the-real-one-000000",
        &claims("jti-probe", &["tool:read"], 300, None),
    );
    match validator.validate(&forged) {
        Err(IdentityError::Revoked(_)) => {
            panic!("an unsigned caller learned that jti-probe is revoked")
        }
        Err(_) => {}
        Ok(_) => panic!("a forged token validated"),
    }
}

#[test]
fn validator_without_a_store_never_refuses_for_revocation() {
    let validator = IdentityValidator::new(AUDIENCE);
    validator
        .add_key(KID, KeyMaterial::HmacSecret(SECRET.to_vec()))
        .unwrap();
    assert!(validator.revocation_store().is_none());
    let token = mint(&claims("jti-free", &["tool:read"], 300, None));
    assert!(validator.validate(&token).is_ok());
}

#[test]
fn revocation_retention_covers_expiry_leeway_including_last_second() {
    let store = Arc::new(InMemoryRevocationStore::new());
    let validator = validator_with(store.clone());
    let now = now_s();
    let mut c = claims("expired-but-accepted", &["tool:read"], 300, None);
    c.iat = now - 100;
    c.exp = now - 10;
    let token = mint(&c);
    assert!(validator.validate(&token).is_ok());
    let retained_until = c.exp + validator.leeway_secs();
    store.revoke(&c.jti, retained_until).unwrap();
    store.sweep(now);
    assert!(matches!(
        validator.validate(&token),
        Err(IdentityError::Revoked(_))
    ));
    store.sweep(retained_until);
    assert!(store.is_revoked(&c.jti).unwrap());
    store.sweep(retained_until + 1);
    assert!(!store.is_revoked(&c.jti).unwrap());
}

#[test]
fn empty_jti_is_rejected_before_revocation_lookup() {
    let validator = validator_with(Arc::new(UnreachableStore));
    let token = mint(&claims("", &["tool:read"], 300, None));
    assert_eq!(
        validator.validate(&token).unwrap_err(),
        IdentityError::EmptyField("jti")
    );
}

#[test]
fn instance_cutoff_is_inclusive_monotonic_and_does_not_match_actor_names() {
    let store = Arc::new(InMemoryRevocationStore::new());
    let validator = validator_with(store.clone());
    let now = now_s();
    let cutoff = now - 10;
    store.revoke_instance("inst-1", cutoff, now + 1000).unwrap();
    store.revoke_instance("inst-1", cutoff - 1, now - 1).unwrap();
    store.sweep(now);
    let mut c = claims("cutoff-token", &["tool:read"], 300, None);
    c.iat = cutoff;
    assert_eq!(
        validator.validate(&mint(&c)).unwrap_err(),
        IdentityError::InstanceRevoked {
            instance_uid: "inst-1".into(),
            cutoff
        }
    );
    c.iat += 1;
    assert!(validator.validate(&mint(&c)).is_ok());
    c.iat = cutoff;
    c.instance_uid = "other-instance".into();
    c.act = Some(av_identity::ActorClaim {
        sub: "inst-1".into(),
        act: None,
    });
    assert!(validator.validate(&mint(&c)).is_ok());
    store.sweep(now + 1000);
    assert_eq!(store.len(), 1);
    store.sweep(now + 1001);
    assert!(store.is_empty());
}

#[test]
fn instance_revocation_applies_to_parents_and_preserves_signed_ancestry() {
    let store = Arc::new(InMemoryRevocationStore::new());
    let validator = validator_with(store.clone());
    let mut parent = claims("parent", &["tool:*"], 300, None);
    parent.instance_uid = "delegator".into();
    let child = claims("child", &["tool:read"], 200, Some(mint(&parent)));
    let verified = validator.validate(&mint(&child)).unwrap();
    assert_eq!(
        verified.chain_tokens,
        vec![
            av_identity::RevocationIdentity::from(&child),
            av_identity::RevocationIdentity::from(&parent)
        ]
    );
    store
        .revoke_instance(&parent.instance_uid, parent.iat, parent.exp + 30)
        .unwrap();
    assert!(matches!(
        validator.validate(&mint(&child)),
        Err(IdentityError::InstanceRevoked { .. })
    ));
    let forged = mint_with(b"wrong-secret", &child);
    assert!(matches!(
        validator.validate(&forged),
        Err(IdentityError::Verification(_))
    ));
}

#[test]
fn depth_includes_actors_inside_every_parent() {
    let validator = validator_with(Arc::new(InMemoryRevocationStore::new()));
    let mut parent = claims("parent", &["tool:*"], 300, None);
    for i in 0..4 {
        parent.act = Some(av_identity::ActorClaim {
            sub: format!("actor-{i}"),
            act: parent.act.map(Box::new),
        });
    }
    assert_eq!(
        validator.validate(&mint(&parent)).unwrap().total_delegation_depth,
        4
    );
    let child = claims("child", &["tool:read"], 200, Some(mint(&parent)));
    assert_eq!(
        validator.validate(&mint(&child)).unwrap_err(),
        IdentityError::ChainTooDeep(4)
    );
    parent.act = parent.act.unwrap().act.map(|a| *a);
    let child = claims("child", &["tool:read"], 200, Some(mint(&parent)));
    assert_eq!(
        validator.validate(&mint(&child)).unwrap().total_delegation_depth,
        4
    );
}

#[test]
fn holder_can_revoke_bounded_future_token_without_granting_access() {
    let store = Arc::new(InMemoryRevocationStore::new());
    let validator = validator_with(store.clone());
    let mut c = claims("scheduled", &["tool:read"], 300, None);
    c.iat += 120;
    c.nbf = Some(c.iat);
    c.exp = c.iat + 300;
    let token = mint(&c);
    assert!(validator.validate(&token).is_err());
    assert!(validator.validate_for_revocation(&token).is_ok());
    store.revoke(&c.jti, c.exp + 30).unwrap();
    assert!(validator.validate_for_revocation(&token).is_ok());
    c.iat += 3600;
    c.nbf = Some(c.iat);
    c.exp = c.iat + 300;
    assert!(matches!(
        validator.validate_for_revocation(&mint(&c)),
        Err(IdentityError::FutureIat { .. })
    ));
    assert!(validator
        .validate_for_revocation(&mint_with(b"wrong-key", &c))
        .is_err());
}

#[test]
fn racing_revocations_create_only_one_audit_action() {
    let store = Arc::new(InMemoryRevocationStore::new());
    let joins: Vec<_> = (0..32)
        .map(|_| {
            let store = store.clone();
            std::thread::spawn(move || store.try_revoke("raced-jti", 1000).unwrap())
        })
        .collect();
    let outcomes: Vec<_> = joins.into_iter().map(|j| j.join().unwrap()).collect();
    assert_eq!(
        outcomes
            .iter()
            .filter(|v| **v == av_identity::RevokeOutcome::Revoked)
            .count(),
        1
    );
}

#[test]
fn issuer_supplied_exchange_ancestry_cannot_replace_verified_parent_identities() {
    let validator = validator_with(Arc::new(InMemoryRevocationStore::new()));
    let parent = claims("real-parent", &["tool:*"], 300, None);
    let child = claims("real-child", &["tool:read"], 200, Some(mint(&parent)));
    let mut payload = serde_json::to_value(&child).unwrap();
    payload.as_object_mut().unwrap().insert(
        "av_subject_tokens".into(),
        serde_json::json!([
            {"jti":"forged-ancestor", "instance_uid":"other-agent", "iat":child.iat}
        ]),
    );
    payload
        .as_object_mut()
        .unwrap()
        .insert("av_delegation_depth".into(), serde_json::json!(0));
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some(KID.into());
    let token = jsonwebtoken::encode(&header, &payload, &EncodingKey::from_secret(SECRET)).unwrap();
    let verified = validator.validate(&token).unwrap();
    assert_eq!(
        verified.chain_tokens,
        vec![
            av_identity::RevocationIdentity::from(&child),
            av_identity::RevocationIdentity::from(&parent)
        ]
    );
    assert_eq!(verified.total_delegation_depth, 1);
}

#[test]
fn issuer_scoped_revocation_does_not_affect_another_issuer_or_key_domain() {
    use av_identity::{RevokeOutcome, RevokedBy};
    let store = Arc::new(InMemoryRevocationStore::new());
    let validator = validator_with(store.clone());
    let first = claims("shared-jti", &["tool:read"], 300, None);
    let mut other = first.clone();
    other.iss = "https://independent-issuer.example".into();
    assert_eq!(
        store
            .try_revoke_token(&first.iss, &first.jti, first.exp + 30)
            .unwrap(),
        RevokeOutcome::Revoked
    );
    assert_eq!(
        store
            .try_revoke_token(&first.iss, &first.jti, first.exp + 10)
            .unwrap(),
        RevokeOutcome::AlreadyRevoked
    );
    assert!(matches!(
        validator.validate(&mint(&first)),
        Err(IdentityError::Revoked(_))
    ));
    assert!(validator.validate(&mint(&other)).is_ok());
    assert!(
        !store.is_revoked(&first.jti).unwrap(),
        "scoped writes must not become global rules"
    );
    store.sweep(first.exp + 30);
    assert_eq!(
        store
            .check_token(&first.iss, &first.jti, &first.instance_uid, first.iat)
            .unwrap(),
        Some(RevokedBy::Jti)
    );
    store.sweep(first.exp + 31);
    assert!(store.is_empty());
    store.revoke(&first.jti, first.exp + 60).unwrap();
    assert!(matches!(
        validator.validate(&mint(&other)),
        Err(IdentityError::Revoked(_))
    ));

    store.try_revoke_token("a:b", "c", first.exp).unwrap();
    assert_eq!(store.check_token("a", "b:c", "uid", first.iat).unwrap(), None);
}

#[test]
fn inbound_validator_refuses_backend_profiles_even_with_a_trusted_key() {
    let validator = validator_with(Arc::new(InMemoryRevocationStore::new()));
    let claims = claims("profile", &["tool:read"], 300, None);
    for typ in ["av-intent+jwt", "av-tool+jwt"] {
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(KID.into());
        header.typ = Some(typ.into());
        let token = jsonwebtoken::encode(&header, &claims, &EncodingKey::from_secret(SECRET)).unwrap();
        assert!(validator.validate(&token).is_err());
        assert!(validator.validate_for_revocation(&token).is_err());
    }
}

#[test]
fn required_principals_and_scope_boundaries_are_not_ambiguous() {
    let validator = validator_with(Arc::new(InMemoryRevocationStore::new()));
    for field in ["sub", "iss"] {
        let mut invalid = claims("invalid-principal", &["tool:read"], 300, None);
        if field == "sub" {
            invalid.sub.clear();
        } else {
            invalid.iss.clear();
        }
        assert_eq!(
            validator.validate(&mint(&invalid)).unwrap_err(),
            IdentityError::EmptyField(field)
        );
    }
    for scope in [
        "",
        "tool:read tool:delete",
        "tool:read\ttool:delete",
        "tool:read\n",
        "tool:read\u{00a0}tool:delete",
        "tool:read\0",
    ] {
        let invalid = claims("invalid-scope", &[scope], 300, None);
        assert!(
            validator.validate(&mint(&invalid)).is_err(),
            "accepted scope {scope:?}"
        );
        assert!(validator.validate_for_revocation(&mint(&invalid)).is_err());
    }
}

#[test]
fn signed_tokens_with_unsupported_jose_extensions_are_refused() {
    let validator = validator_with(Arc::new(InMemoryRevocationStore::new()));
    let claims = claims("critical-extension", &["tool:read"], 300, None);
    for mutation in 0..3 {
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(KID.into());
        match mutation {
            0 => header.crit = Some(vec!["issuer-restriction".into()]),
            1 => header.crit = Some(vec![]),
            _ => header.extras.insert("b64", false),
        }
        let token = jsonwebtoken::encode(&header, &claims, &EncodingKey::from_secret(SECRET)).unwrap();
        assert!(validator.validate(&token).is_err());
        assert!(validator.validate_for_revocation(&token).is_err());
    }
}

#[test]
fn accepted_revocation_identifiers_are_addressable_by_the_operator_endpoint() {
    let validator = validator_with(Arc::new(InMemoryRevocationStore::new()));
    for invalid in ["   ", "\t", "\u{00a0}", "id\0suffix", "id\n", "id\u{007f}"] {
        for field in ["jti", "instance_uid"] {
            let mut token = claims("addressable", &["tool:read"], 300, None);
            if field == "jti" {
                token.jti = invalid.into();
            } else {
                token.instance_uid = invalid.into();
            }
            assert!(
                validator.validate(&mint(&token)).is_err(),
                "accepted {field}={invalid:?}"
            );
            assert!(validator.validate_for_revocation(&mint(&token)).is_err());
        }
    }
    let mut valid = claims("issuer token:42", &["tool:read"], 300, None);
    valid.instance_uid = "équipe:42".into();
    assert!(
        validator.validate(&mint(&valid)).is_ok(),
        "nonempty printable identifiers retain compatibility"
    );
}
