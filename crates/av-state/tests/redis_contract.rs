//! Redis `StateStore` contract tests. Live-gated: set `AV_REDIS_URL` to run.
//! Skips print loudly — a silent skip is itself a silent error (D13.21).
#![cfg(feature = "redis")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use av_state::redis_store::RedisStore;
use av_state::{Spend, StateStore};

fn store() -> Option<RedisStore> {
    match std::env::var("AV_REDIS_URL") {
        Ok(url) => Some(RedisStore::connect(&url).expect("redis connect")),
        Err(_) => {
            eprintln!("SKIPPED (AV_REDIS_URL unset): redis contract tests require a live server");
            None
        }
    }
}

#[test]
fn redis_contract_add_get_spend() {
    let Some(s) = store() else { return };
    let key = format!("av-test:{}", av_core::new_event_uid());
    assert_eq!(s.get(&key).unwrap(), 0);
    assert_eq!(s.add(&key, 5).unwrap(), 5);
    assert!(s.try_spend(&key, 5, 10).unwrap());
    assert!(!s.try_spend(&key, 1, 10).unwrap());
    assert_eq!(s.get(&key).unwrap(), 10);
    s.remove(&key);
    assert_eq!(s.get(&key).unwrap(), 0);
}

/// The multi-key `TRY_SPEND_LUA` script is the Redis *Cluster* acid test:
/// without `{hash-tag}` keys (the shape `ActionBudget::key` produces) a
/// cluster answers CROSSSLOT and every budget check fails. Runs against
/// whatever `AV_REDIS_URL` points at; against a comma-separated cluster URL
/// it proves the production key discipline holds on a real slot map.
#[test]
fn redis_contract_multi_key_spend_shares_one_slot() {
    let Some(s) = store() else { return };
    let tag = av_core::new_event_uid();
    let tokens = format!("budget:{{{tag}}}:tokens");
    let tool = format!("budget:{{{tag}}}:tool:db_write");
    assert_eq!(
        s.try_spend_many(&[
            Spend {
                key: tokens.clone(),
                amount: 7,
                limit: 10,
            },
            Spend {
                key: tool.clone(),
                amount: 1,
                limit: 3,
            },
        ])
        .unwrap(),
        None,
        "first multi-key spend must commit"
    );
    // Second spend exceeds the token limit; the tool counter must not move
    // (atomicity across keys, not just per-key).
    assert_eq!(
        s.try_spend_many(&[
            Spend {
                key: tokens.clone(),
                amount: 5,
                limit: 10,
            },
            Spend {
                key: tool.clone(),
                amount: 1,
                limit: 3,
            },
        ])
        .unwrap(),
        Some(0),
        "over-limit spend must report the failing index"
    );
    assert_eq!(s.get(&tokens).unwrap(), 7);
    assert_eq!(s.get(&tool).unwrap(), 1);
    s.remove(&tokens);
    s.remove(&tool);
}

#[test]
fn redis_never_rounds_a_spend_past_jcs_max() {
    let Some(s) = store() else { return };
    let key = format!("av-test-boundary:{}", av_core::new_event_uid());
    assert_eq!(
        s.add(&key, av_core::error::JCS_SAFE_MAX).unwrap(),
        av_core::error::JCS_SAFE_MAX
    );
    assert!(!s.try_spend(&key, 1, av_core::error::JCS_SAFE_MAX).unwrap());
    assert_eq!(s.get(&key).unwrap(), av_core::error::JCS_SAFE_MAX);
    s.remove(&key);
}
