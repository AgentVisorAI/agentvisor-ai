//! Live Redis contract for the shared revocation list. Set `AV_REDIS_URL`
//! to run; the skip prints loudly, as in `av-state`'s Redis contract suite.
#![cfg(feature = "redis")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use av_harness::revocation::StateRevocationStore;
use av_identity::RevocationStore;
use av_state::redis_store::RedisStore;
use std::sync::Arc;

/// One independent connection pool per call, standing in for one replica.
fn replica() -> Option<StateRevocationStore> {
    match std::env::var("AV_REDIS_URL") {
        Ok(url) => Some(StateRevocationStore::new(Arc::new(
            RedisStore::connect(&url).expect("redis connect"),
        ))),
        Err(_) => {
            eprintln!("SKIPPED (AV_REDIS_URL unset): revocation contract tests require a live Redis");
            None
        }
    }
}

#[test]
fn revocation_written_by_one_replica_is_seen_by_another() {
    let (Some(writer), Some(reader)) = (replica(), replica()) else {
        return;
    };
    let jti = format!("jti-{}", av_core::new_event_uid());
    assert!(!reader.is_revoked(&jti).unwrap());
    writer.revoke(&jti, 0).unwrap();
    assert!(
        reader.is_revoked(&jti).unwrap(),
        "replicas must share one revocation list"
    );
    assert!(
        !reader
            .is_revoked(&format!("jti-{}", av_core::new_event_uid()))
            .unwrap(),
        "only the revoked JTI is refused"
    );
}

#[test]
fn revoking_twice_through_redis_is_harmless() {
    let Some(store) = replica() else { return };
    let jti = format!("jti-{}", av_core::new_event_uid());
    store.revoke(&jti, 0).unwrap();
    store.revoke(&jti, 0).unwrap();
    assert!(store.is_revoked(&jti).unwrap());
}

#[test]
fn instance_cutoffs_cross_replicas_never_move_backwards() {
    use av_identity::RevokedBy;
    let (Some(writer), Some(reader)) = (replica(), replica()) else {
        return;
    };
    let instance = format!("instance-{}", av_core::new_event_uid());
    assert_eq!(reader.check("fresh-jti", &instance, 1000).unwrap(), None);
    writer.revoke_instance(&instance, 1000, 2000).unwrap();
    writer.revoke_instance(&instance, 900, 1900).unwrap();
    assert_eq!(
        reader.check("fresh-jti", &instance, 1000).unwrap(),
        Some(RevokedBy::Instance { cutoff: 1000 })
    );
    assert_eq!(
        reader.check("another-jti", &instance, 999).unwrap(),
        Some(RevokedBy::Instance { cutoff: 1000 })
    );
    assert_eq!(reader.check("fresh-jti", &instance, 1001).unwrap(), None);
    assert_eq!(reader.check("fresh-jti", "another-instance", 999).unwrap(), None);
}

#[test]
fn concurrent_replica_revocations_report_only_one_new_entry() {
    use av_identity::RevokeOutcome;
    let (Some(a), Some(b)) = (replica(), replica()) else {
        return;
    };
    let jti = format!("jti-{}", av_core::new_event_uid());
    let first_jti = jti.clone();
    let first = std::thread::spawn(move || a.try_revoke(&first_jti, 2000).unwrap());
    let second = std::thread::spawn(move || b.try_revoke(&jti, 2000).unwrap());
    let outcomes = [first.join().unwrap(), second.join().unwrap()];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == RevokeOutcome::Revoked)
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == RevokeOutcome::AlreadyRevoked)
            .count(),
        1
    );
}

#[test]
fn exchanged_namespace_stays_separate_in_redis() {
    let Some(upstream) = replica() else { return };
    let url = std::env::var("AV_REDIS_URL").unwrap();
    let exchanged =
        StateRevocationStore::with_namespace(Arc::new(RedisStore::connect(&url).unwrap()), "exchanged");
    let jti = format!("same-jti-{}", av_core::new_event_uid());
    upstream.revoke(&jti, 2000).unwrap();
    assert!(!exchanged.is_revoked(&jti).unwrap());
    exchanged.revoke(&jti, 2000).unwrap();
    assert!(exchanged.is_revoked(&jti).unwrap());
}

#[test]
fn guarded_replica_observes_remote_revocations_without_caching_live_answers() {
    use av_harness::revocation::GuardedRevocationStore;
    use av_identity::RevokedBy;
    let (Some(writer), Some(reader)) = (replica(), replica()) else {
        return;
    };
    let metrics = av_core::metrics::Registry::new();
    let guarded = GuardedRevocationStore::new(Arc::new(reader), &metrics, "nhi");
    let jti = format!("jti-{}", av_core::new_event_uid());
    let instance = format!("instance-{}", av_core::new_event_uid());
    assert!(!guarded.is_revoked(&jti).unwrap());
    assert_eq!(guarded.health().unwrap().local_entries, 0);
    writer.revoke(&jti, 0).unwrap();
    assert!(guarded.is_revoked(&jti).unwrap());
    assert!(guarded.is_revoked(&jti).unwrap());
    assert_eq!(guarded.health().unwrap().local_entries, 1);
    assert_eq!(guarded.check("different-jti", &instance, 1000).unwrap(), None);
    writer.revoke_instance(&instance, 1000, 0).unwrap();
    assert_eq!(
        guarded.check("different-jti", &instance, 1000).unwrap(),
        Some(RevokedBy::Instance { cutoff: 1000 })
    );
    assert_eq!(guarded.check("newer-token", &instance, 1001).unwrap(), None);
    assert_eq!(guarded.health().unwrap().local_entries, 2);
    assert!(guarded.health().unwrap().available);
}

#[test]
fn issuer_scoped_revocations_propagate_without_cross_issuer_cache_contamination() {
    use av_harness::revocation::GuardedRevocationStore;
    use av_identity::{RevokeOutcome, RevokedBy};
    let (Some(writer), Some(reader)) = (replica(), replica()) else {
        return;
    };
    let jti = format!("same-jti-{}", av_core::new_event_uid());
    let instance = format!("instance-{}", av_core::new_event_uid());
    let metrics = av_core::metrics::Registry::new();
    let guard = GuardedRevocationStore::new(Arc::new(reader), &metrics, "nhi");
    assert_eq!(
        guard.check_token("issuer-a", &jti, &instance, 1000).unwrap(),
        None
    );
    assert_eq!(
        writer.try_revoke_token("issuer-a", &jti, 2000).unwrap(),
        RevokeOutcome::Revoked
    );
    assert_eq!(
        writer.try_revoke_token("issuer-a", &jti, 2000).unwrap(),
        RevokeOutcome::AlreadyRevoked
    );
    assert_eq!(
        guard.check_token("issuer-a", &jti, &instance, 1000).unwrap(),
        Some(RevokedBy::Jti)
    );
    assert_eq!(
        guard.check_token("issuer-b", &jti, &instance, 1000).unwrap(),
        None
    );
    assert!(!guard.is_revoked(&jti).unwrap());
    writer.revoke(&jti, 2000).unwrap();
    assert_eq!(
        guard.check_token("issuer-b", &jti, &instance, 1000).unwrap(),
        Some(RevokedBy::Jti)
    );
    writer.revoke_instance(&instance, 1000, 2000).unwrap();
    assert_eq!(
        guard.check_token("issuer-c", "new-jti", &instance, 1000).unwrap(),
        Some(RevokedBy::Instance { cutoff: 1000 })
    );
}
