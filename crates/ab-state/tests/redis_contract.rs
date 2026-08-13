//! Redis `StateStore` contract tests. Live-gated: set `AB_REDIS_URL` to run.
//! Skips print loudly — a silent skip is itself a silent error (D13.21).
#![cfg(feature = "redis")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ab_state::redis_store::RedisStore;
use ab_state::StateStore;

fn store() -> Option<RedisStore> {
    match std::env::var("AB_REDIS_URL") {
        Ok(url) => Some(RedisStore::connect(&url).expect("redis connect")),
        Err(_) => {
            eprintln!("SKIPPED (AB_REDIS_URL unset): redis contract tests require a live server");
            None
        }
    }
}

#[test]
fn redis_contract_add_get_spend() {
    let Some(s) = store() else { return };
    let key = format!("ab-test:{}", ab_core::new_event_uid());
    assert_eq!(s.get(&key).unwrap(), 0);
    assert_eq!(s.add(&key, 5).unwrap(), 5);
    assert!(s.try_spend(&key, 5, 10).unwrap());
    assert!(!s.try_spend(&key, 1, 10).unwrap());
    assert_eq!(s.get(&key).unwrap(), 10);
    s.remove(&key);
    assert_eq!(s.get(&key).unwrap(), 0);
}

#[test]
fn redis_never_rounds_a_spend_past_jcs_max() {
    let Some(s) = store() else { return };
    let key = format!("ab-test-boundary:{}", ab_core::new_event_uid());
    assert_eq!(
        s.add(&key, ab_core::error::JCS_SAFE_MAX).unwrap(),
        ab_core::error::JCS_SAFE_MAX
    );
    assert!(!s.try_spend(&key, 1, ab_core::error::JCS_SAFE_MAX).unwrap());
    assert_eq!(s.get(&key).unwrap(), ab_core::error::JCS_SAFE_MAX);
    s.remove(&key);
}
