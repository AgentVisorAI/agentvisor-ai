//! Session/agent state: atomic counters, token-velocity windows, rate limits,
//! and action budgets (brief Modules B/D and the §8 "In-Memory State" layer).
//!
//! The core abstraction is [`StateStore`]: check-and-spend operations that are
//! atomic even under concurrent tool calls from parallel sub-agents
//! (silent-error class D13.9 — a budget must never over-spend by racing).
//! `InMemoryStore` is the single-node reference; a Redis Cluster backend
//! compiles behind the `redis` feature for multi-node deployments and is
//! contract-tested against a live server when `AV_REDIS_URL` is set.
//!
//! All arithmetic here is checked — budget/monetary code must fail loudly,
//! never wrap.

pub mod budget;
pub mod store;
pub mod velocity;

pub use budget::{ActionBudget, BudgetDecision, BudgetSpec};
pub use store::{InMemoryStore, Refund, Spend, StateError, StateStore, TrySpendOutcome};
pub use velocity::TokenVelocity;

#[cfg(feature = "redis")]
pub mod redis_store;

/// Shared backend-agnostic `StateStore` contract.
///
/// EVOLUTION.md promises "new connectors must satisfy the same contract
/// tests" — previously the in-memory and Redis suites asserted different
/// things (none of the concurrency-adjacent semantics ran against Redis
/// at all), so the implementations drifted (TTL, `remove_prefix`).
/// Every backend's test suite MUST call this one function; backend-
/// specific behavior (cluster slots, TTL) stays in the backend's own
/// suite ON TOP of this contract, never instead of it.
///
/// `hash_tag` is interpolated into every key inside `{…}` so Redis
/// Cluster callers keep all contract keys in one slot; in-memory
/// callers can pass anything unique.
#[doc(hidden)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::missing_panics_doc)]
pub fn state_store_contract(store: &dyn StateStore, hash_tag: &str) {
    let key = |name: &str| format!("contract:{{{hash_tag}}}:{name}");

    // -- add / get roundtrip; absent key reads 0.
    let counter = key("counter");
    assert_eq!(store.get(&counter).unwrap(), 0, "absent key must read 0");
    assert_eq!(store.add(&counter, 5).unwrap(), 5);
    assert_eq!(store.add(&counter, 2).unwrap(), 7);
    assert_eq!(store.get(&counter).unwrap(), 7);

    // -- try_spend: exact-fit passes, one-over refuses, nothing partial.
    let spend = key("spend");
    assert!(store.try_spend(&spend, 6, 10).unwrap());
    assert!(store.try_spend(&spend, 4, 10).unwrap(), "exact fit must pass");
    assert!(!store.try_spend(&spend, 1, 10).unwrap(), "over-cap must refuse");
    assert_eq!(
        store.get(&spend).unwrap(),
        10,
        "refused spend must record nothing"
    );

    // -- try_spend_many: all-or-nothing across dimensions.
    let dim_a = key("dim-a");
    let dim_b = key("dim-b");
    assert_eq!(
        store
            .try_spend_many(&[
                Spend {
                    key: dim_a.clone(),
                    amount: 3,
                    limit: 10
                },
                Spend {
                    key: dim_b.clone(),
                    amount: 20,
                    limit: 10
                },
            ])
            .unwrap(),
        TrySpendOutcome::Refused { index: 1 },
        "second dimension over-cap must be reported by index"
    );
    assert_eq!(
        store.get(&dim_a).unwrap(),
        0,
        "failed multi-spend must commit NOTHING"
    );
    // dim_a: 3/10 -> remaining 7; dim_b: 4/10 -> remaining 6. Min = 6.
    assert_eq!(
        store
            .try_spend_many(&[
                Spend {
                    key: dim_a.clone(),
                    amount: 3,
                    limit: 10
                },
                Spend {
                    key: dim_b.clone(),
                    amount: 4,
                    limit: 10
                },
            ])
            .unwrap(),
        TrySpendOutcome::Committed {
            post_commit_min_remaining: 6,
        },
        "R66 F3: try_spend_many must return post-commit min-headroom \
         computed inside the atomic section; a subsequent get-based \
         computation would race with concurrent remove_prefix/spend/refund"
    );
    assert_eq!(store.get(&dim_a).unwrap(), 3);
    assert_eq!(store.get(&dim_b).unwrap(), 4);

    // -- try_spend_many refuses duplicate keys (API-misuse class).
    assert!(
        store
            .try_spend_many(&[
                Spend {
                    key: dim_a.clone(),
                    amount: 1,
                    limit: 10
                },
                Spend {
                    key: dim_a.clone(),
                    amount: 1,
                    limit: 10
                },
            ])
            .is_err(),
        "duplicate keys in one multi-spend must be refused, not double-counted"
    );

    // -- refund: subtracts, saturates at 0, never resurrects a removed key.
    let refund = key("refund");
    assert!(store.try_spend(&refund, 7, 10).unwrap());
    store.refund(&refund, 3);
    assert_eq!(store.get(&refund).unwrap(), 4, "refund must subtract");
    store.refund(&refund, 100);
    assert_eq!(
        store.get(&refund).unwrap(),
        0,
        "refund must clamp at 0, never underflow"
    );
    store.remove(&refund);
    store.refund(&refund, 5);
    assert_eq!(
        store.get(&refund).unwrap(),
        0,
        "refund after remove must not resurrect the counter"
    );

    // -- refund_many: same semantics as per-key refund, one atomic
    // transaction. Every backend MUST subtract each amount, saturate
    // at 0, and never resurrect a removed cell.
    let m_a = key("refund_many_a");
    let m_b = key("refund_many_b");
    let m_c = key("refund_many_c");
    assert!(store.try_spend(&m_a, 7, 10).unwrap());
    assert!(store.try_spend(&m_b, 5, 10).unwrap());
    // c intentionally never spent — refund_many on a fresh key must
    // NOT resurrect it (same "never resurrect" invariant as `refund`).
    store.refund_many(&[
        Refund {
            key: m_a.clone(),
            amount: 3,
        },
        Refund {
            key: m_b.clone(),
            amount: 100,
        },
        Refund {
            key: m_c.clone(),
            amount: 1,
        },
    ]);
    assert_eq!(
        store.get(&m_a).unwrap(),
        4,
        "refund_many must subtract every listed amount"
    );
    assert_eq!(
        store.get(&m_b).unwrap(),
        0,
        "refund_many must clamp at 0 like per-key refund"
    );
    assert_eq!(
        store.get(&m_c).unwrap(),
        0,
        "refund_many on a fresh key must not resurrect it"
    );
    // Empty batch is a no-op.
    store.refund_many(&[]);
    assert_eq!(store.get(&m_a).unwrap(), 4);

    // -- remove / remove_prefix: whole-session cleanup.
    store.remove(&counter);
    assert_eq!(store.get(&counter).unwrap(), 0);
    store.remove_prefix(&key(""));
    assert_eq!(
        store.get(&spend).unwrap(),
        0,
        "remove_prefix must clear every key under the prefix (native TTL is NOT a substitute: a recycled session id would inherit the prior incarnation's counters)"
    );
    assert_eq!(store.get(&dim_a).unwrap(), 0);
    assert_eq!(store.get(&dim_b).unwrap(), 0);
}
