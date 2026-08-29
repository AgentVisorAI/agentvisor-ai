//! Redis `StateStore` contract tests. Live-gated: set `AV_REDIS_URL` to run.
//! Skips print loudly — a silent skip is itself a silent error (D13.21).
#![cfg(feature = "redis")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use av_state::redis_store::RedisStore;
use av_state::{Spend, StateStore, TrySpendOutcome};

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
    // R111 F2: assertions match the R66 F3 TrySpendOutcome API.
    // Prior shape compared against Option<usize> ({None, Some(idx)})
    // — the pre-R66 refactor return type. The compile error blocked
    // every runtime invocation, including the AV_REDIS_URL-gated
    // race regression suite this file names as its raison d'être
    // ('D13.9: a budget must never over-spend by racing'). Silent
    // coverage regression since R66 landed.
    assert!(
        matches!(
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
            TrySpendOutcome::Committed { .. }
        ),
        "first multi-key spend must commit"
    );
    // Second spend exceeds the token limit; the tool counter must not move
    // (atomicity across keys, not just per-key).
    assert!(
        matches!(
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
            TrySpendOutcome::Refused { index: 0 }
        ),
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

/// Mutation-run hardening: `RedisStore::refund` had no live
/// contract test at all — a mutant deleting its body survived. Round-trip
/// a spend + refund and prove the headroom returns; also prove the
/// no-resurrect rule holds against a live server (refund on a
/// removed key must not recreate it).
#[test]
fn redis_contract_refund_roundtrip_and_no_resurrect() {
    let Some(s) = store() else { return };
    let key = format!("av-test-refund:{{{}}}", av_core::new_event_uid());
    assert!(s.try_spend(&key, 7, 10).unwrap());
    s.refund(&key, 3);
    assert_eq!(s.get(&key).unwrap(), 4, "refund must subtract");
    // Saturating: refunding more than spent clamps at zero, never negative.
    s.refund(&key, 100);
    assert_eq!(s.get(&key).unwrap(), 0);
    // No-resurrect: refund after remove must not recreate the key.
    assert!(s.try_spend(&key, 5, 10).unwrap());
    s.remove(&key);
    s.refund(&key, 5);
    assert_eq!(s.get(&key).unwrap(), 0, "refund must not resurrect a removed key");
}

/// Mutation-run hardening: the JCS_SAFE_MAX guard in
/// `spend_many_on` and the duplicate-key rejection lacked exact live
/// coverage (`>` -> `>=`, `||` -> `&&` survived).
#[test]
fn redis_contract_spend_many_guards_are_exact() {
    use av_state::StateError;
    let max = av_core::error::JCS_SAFE_MAX;
    let Some(s) = store() else { return };
    let tag = av_core::new_event_uid();
    // amount == limit == JCS_SAFE_MAX commits (kills > -> >=)…
    let key = format!("av-test-max:{{{tag}}}");
    assert!(matches!(
        s.try_spend_many(&[Spend {
            key: key.clone(),
            amount: max,
            limit: max,
        }])
        .unwrap(),
        TrySpendOutcome::Committed { .. }
    ),);
    s.remove(&key);
    // …and each side one past the cap is Overflow independently
    // (kills || -> && which would require BOTH to exceed).
    for (amount, limit) in [(max + 1, max), (1, max + 1)] {
        let outcome = s.try_spend_many(&[Spend {
            key: format!("av-test-over:{{{tag}}}"),
            amount,
            limit,
        }]);
        assert!(matches!(outcome, Err(StateError::Overflow(_))), "got {outcome:?}");
    }
    // Duplicate keys are refused before the Lua script runs.
    let dup = format!("av-test-dup:{{{tag}}}");
    let outcome = s.try_spend_many(&[
        Spend {
            key: dup.clone(),
            amount: 1,
            limit: 10,
        },
        Spend {
            key: dup,
            amount: 1,
            limit: 10,
        },
    ]);
    assert!(
        matches!(outcome, Err(StateError::Backend(ref m)) if m.contains("duplicate")),
        "got {outcome:?}"
    );
}

/// Mutation-run hardening: the negative-counter defenses in
/// `add_on`/`get_on` were unreachable through the store's own API (it
/// never writes negatives), so their guards survived mutation. Poison a
/// counter out-of-band — an operator's raw DECRBY or a hostile writer —
/// and prove both paths refuse loudly instead of wrapping into a huge
/// unsigned balance.
#[test]
fn redis_contract_poisoned_negative_counter_is_refused() {
    use av_state::StateError;
    let Some(s) = store() else { return };
    let Ok(url) = std::env::var("AV_REDIS_URL") else {
        return;
    };
    let key = format!("av-test-poison:{{{}}}", av_core::new_event_uid());
    // Route the out-of-band poison write through a cluster-aware client
    // when the URL lists multiple nodes: against a real multi-master
    // slot map, a raw single-node connection to the first member
    // answers `MOVED` for ~2/3 of keys and the write (not the guard
    // under test) fails.
    let members: Vec<&str> = url.split(',').map(str::trim).collect();
    if members.len() > 1 {
        let cluster = redis::cluster::ClusterClient::new(members.clone()).expect("cluster client");
        let mut raw = cluster.get_connection().expect("cluster conn");
        let _: i64 = redis::cmd("DECRBY").arg(&key).arg(5).query(&mut raw).unwrap();
    } else {
        let Some(member) = members.first() else { return };
        let client = redis::Client::open(*member).expect("raw client");
        let mut raw = client.get_connection().expect("raw conn");
        let _: i64 = redis::cmd("DECRBY").arg(&key).arg(5).query(&mut raw).unwrap();
    }
    let got = s.get(&key);
    assert!(
        matches!(got, Err(StateError::Overflow(_))),
        "get on a poisoned counter must be Overflow, got {got:?}"
    );
    let added = s.add(&key, 1);
    assert!(
        matches!(added, Err(StateError::Overflow(_))),
        "add on a poisoned counter must be Overflow, got {added:?}"
    );
    s.remove(&key);
}

/// The ONE shared backend contract. Runs the identical
/// assertions the in-memory suite runs (store.rs unit test) so the two
/// backends cannot silently drift on semantics again.
#[test]
fn redis_satisfies_the_shared_state_store_contract() {
    let Some(s) = store() else { return };
    av_state::state_store_contract(&s, &av_core::new_event_uid());
}
