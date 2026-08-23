//! The `StateStore` trait and the in-memory reference implementation.

use dashmap::DashMap;
use parking_lot::Mutex;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

/// State-layer errors.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum StateError {
    /// Arithmetic would overflow.
    #[error("counter overflow for key {0:?}")]
    Overflow(String),
    /// Backend failure or state-operation contract violation (network
    /// stores; also API misuse such as duplicate keys in one batch).
    #[error("state backend unavailable: {0}")]
    Backend(String),
}

/// One key/amount/limit entry in an atomic multi-dimensional spend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spend {
    /// Counter key.
    pub key: String,
    /// Amount to add.
    pub amount: u64,
    /// Maximum resulting counter value.
    pub limit: u64,
}

/// Atomic counter operations. Every mutation is atomic with respect to
/// concurrent callers; `try_spend` is a single check-and-spend (never a
/// read-then-write).
///
/// # Counter lifetime
///
/// Backends with native expiry apply a TTL to every counter they touch:
/// `RedisStore` refreshes a 24 h TTL (`BUDGET_COUNTER_TTL_SECS` in
/// `redis_store.rs`) on each spend/add/refund, so a session idle past
/// that window has its budget counters silently reset. `InMemoryStore`
/// never expires. Callers must bound session lifetimes to the backend
/// TTL (or clean up explicitly via `remove`/`remove_prefix`) so the two
/// backends stay behaviorally aligned across dev and prod.
pub trait StateStore: Send + Sync {
    /// Add `delta` to `key`, returning the new value.
    fn add(&self, key: &str, delta: u64) -> Result<u64, StateError>;

    /// Backend counter TTL in seconds, if the backend expires counters
    /// natively. `None` means counters live for the process lifetime
    /// (in-memory). Round-51 §4.2: this makes the prod/dev divergence
    /// a VALUE callers can inspect (startup logs it; ops docs cite it)
    /// instead of a doc comment — a session active longer than this
    /// window has its budget counters silently reset against the
    /// expiring backend only.
    fn counter_ttl_secs(&self) -> Option<u64> {
        None
    }

    /// Read the current value of `key` (0 if absent).
    fn get(&self, key: &str) -> Result<u64, StateError>;

    /// Atomically spend `amount` from the remaining budget `limit - spent(key)`.
    /// Returns `Ok(true)` and records the spend if the full `amount` fits,
    /// `Ok(false)` (recording nothing) otherwise.
    fn try_spend(&self, key: &str, amount: u64, limit: u64) -> Result<bool, StateError>;

    /// Atomically validate and commit every spend, or commit none. Returns the
    /// index of the first dimension that would exceed its limit.
    ///
    /// Every `Spend` in `spends` must carry a distinct `key`; two entries for
    /// the same key would each observe the pre-commit value in the check
    /// phase and pass their independent limit checks, then the commit phase
    /// would sum them and blow through the cap. Duplicate keys return
    /// `StateError::Backend` (not `Overflow`), matching the API-misuse class.
    fn try_spend_many(&self, spends: &[Spend]) -> Result<Option<usize>, StateError>;

    /// Remove a key (session cleanup).
    fn remove(&self, key: &str);

    /// Return a previously-spent `amount` to a counter. Saturating: if
    /// the stored value is below `amount` (e.g. a concurrent
    /// `remove_prefix` cleared it first, or another refund already
    /// covered part of the debt) the counter clamps at 0 rather than
    /// underflowing into "negative budget". Backends must never
    /// propagate a refund error to the caller — the refund is
    /// best-effort compensation on a lost-race path where the primary
    /// verdict has already been decided. Default `remove_prefix`
    /// semantics apply: backends with native TTL expiry may fold this
    /// into their own cleanup if they prefer.
    ///
    /// Round-33 F1: introduced to close the round-32 F3 concurrent-MCP
    /// budget double-spend. When two identical MCP requests race and
    /// one loses the atomic `execution.claim()`, the sandbox-gate
    /// spend is refunded so the budget counters reflect only the
    /// admitted work.
    fn refund(&self, key: &str, amount: u64) {
        let _ = (key, amount);
    }

    /// Remove every key beginning with `prefix` (whole-session cleanup at
    /// finalization). Every backend must implement this: native expiry
    /// (e.g. Redis TTLs) is NOT a substitute, because a finalized session
    /// id can be recycled into a fresh session within the TTL window and
    /// would inherit the prior incarnation's counters. In-process backends
    /// additionally need it or session-keyed counters accumulate for the
    /// process lifetime.
    ///
    /// Round-15 F2 (av-state): CLUSTER-MODE HAZARD FOR FUTURE CALLERS.
    /// The Redis Cluster implementation of `remove_prefix` routes SCAN
    /// and DEL to a SINGLE hash slot — the one derived from the prefix.
    /// This works only when every key under the prefix shares that
    /// slot, i.e. the prefix contains a Redis Cluster hash tag
    /// (`{...}`). Today `ActionBudget::session_prefix` wraps the digest
    /// in a `{hash-tag}` (see `budget.rs`), so all its keys land in
    /// the same slot and this is safe. A future caller that does NOT
    /// hash-tag its prefix would silently leave keys behind in other
    /// slots. Cross-slot SCAN is not supported by Redis Cluster —
    /// there is no correct implementation for a non-tagged prefix, so
    /// this remains a caller-side invariant.
    fn remove_prefix(&self, prefix: &str) {
        let _ = prefix;
    }
}

/// Reject duplicate keys in one multi-spend batch (round-51 §5.4:
/// previously written verbatim in both backends). Every backend's
/// check phase reads the pre-commit value once per entry — two spends
/// on the same key would each pass their independent limit checks and
/// the commit phase would sum them, silently blowing through the cap.
pub(crate) fn refuse_duplicate_spend_keys(spends: &[Spend]) -> Result<(), StateError> {
    let mut seen = std::collections::HashSet::with_capacity(spends.len());
    for spend in spends {
        if !seen.insert(spend.key.as_str()) {
            return Err(StateError::Backend(format!(
                "try_spend_many received duplicate key {:?}",
                spend.key,
            )));
        }
    }
    Ok(())
}

/// Single-node in-memory store: atomic counters behind a short transaction
/// mutex that serializes check-and-spend so multi-key spends stay atomic.
#[derive(Debug, Default)]
pub struct InMemoryStore {
    counters: DashMap<String, Arc<AtomicI64>>,
    transaction_lock: Mutex<()>,
}

impl InMemoryStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    fn cell(&self, key: &str) -> Arc<AtomicI64> {
        self.counters
            .entry(key.to_owned())
            .or_insert_with(|| Arc::new(AtomicI64::new(0)))
            .clone()
    }
}

/// Shared counter ceiling. Round-20 F1/F7: both `InMemoryStore` and
/// `RedisStore::add_on` MUST use this exact value, otherwise the
/// same trait call succeeds on the in-memory dev/test backend and
/// silently fails with `StateError::Overflow` in production against
/// Redis. `av_core::error::JCS_SAFE_MAX = 2^53` is the tightest
/// bound (imposed by JCS canonicalization — integers past that
/// point lose precision in receipt bodies), so both backends align
/// with the eventually-signed representation.
pub(crate) const COUNTER_MAX: i64 = av_core::error::JCS_SAFE_MAX as i64;

impl StateStore for InMemoryStore {
    fn add(&self, key: &str, delta: u64) -> Result<u64, StateError> {
        let _transaction = self.transaction_lock.lock();
        let delta = i64::try_from(delta).map_err(|_| StateError::Overflow(key.to_owned()))?;
        let cell = self.cell(key);
        let prev = cell.load(Ordering::Acquire);
        let new = prev
            .checked_add(delta)
            .filter(|v| *v <= COUNTER_MAX)
            .ok_or_else(|| StateError::Overflow(key.to_owned()))?;
        // Only write after confirming no overflow — no transient negative visible to readers.
        cell.store(new, Ordering::Release);
        // A negative counter is unreachable through this API (spends check
        // limits, refunds clamp at 0), but if one ever appears the silent
        // `unwrap_or(0)` below would mask the corruption; surface it like
        // `get` does.
        u64::try_from(new).map_err(|_| StateError::Overflow(key.to_owned()))
    }

    fn get(&self, key: &str) -> Result<u64, StateError> {
        match self.counters.get(key) {
            None => Ok(0),
            Some(cell) => {
                let raw = cell.load(Ordering::Acquire);
                if raw < 0 {
                    return Err(StateError::Overflow(key.to_owned()));
                }
                u64::try_from(raw).map_err(|_| StateError::Overflow(key.to_owned()))
            }
        }
    }

    fn try_spend(&self, key: &str, amount: u64, limit: u64) -> Result<bool, StateError> {
        Ok(self
            .try_spend_many(&[Spend {
                key: key.to_owned(),
                amount,
                limit,
            }])?
            .is_none())
    }

    fn try_spend_many(&self, spends: &[Spend]) -> Result<Option<usize>, StateError> {
        let _transaction = self.transaction_lock.lock();
        refuse_duplicate_spend_keys(spends)?;
        let mut prepared = Vec::with_capacity(spends.len());
        for (index, spend) in spends.iter().enumerate() {
            // Round-21 F1: match RedisStore's Overflow-reject
            // discipline instead of silently clamping `limit` down
            // to COUNTER_MAX. A caller with a config typo
            // (`max_payout_usd_micros` with one extra zero) would
            // otherwise succeed on the InMemoryStore dev/test path
            // and fail with `Overflow` in Redis prod — the exact
            // cross-backend divergence class round-20 F1 closed
            // for `add`.
            if spend.amount > av_core::error::JCS_SAFE_MAX {
                return Err(StateError::Overflow(spend.key.clone()));
            }
            if spend.limit > av_core::error::JCS_SAFE_MAX {
                return Err(StateError::Overflow(spend.key.clone()));
            }
            let amount = i64::try_from(spend.amount).map_err(|_| StateError::Overflow(spend.key.clone()))?;
            let limit = i64::try_from(spend.limit).map_err(|_| StateError::Overflow(spend.key.clone()))?;
            let cell = self.cell(&spend.key);
            let current = cell.load(Ordering::Acquire);
            let next = current
                .checked_add(amount)
                .ok_or_else(|| StateError::Overflow(spend.key.clone()))?;
            if next > limit {
                return Ok(Some(index));
            }
            prepared.push((cell, amount));
        }
        for (cell, amount) in prepared {
            cell.fetch_add(amount, Ordering::AcqRel);
        }
        Ok(None)
    }

    fn remove(&self, key: &str) {
        let _transaction = self.transaction_lock.lock();
        self.counters.remove(key);
    }

    /// Round-33 F1: saturating refund. `saturating_sub` on i64 keeps
    /// the value non-negative even under concurrent `remove_prefix`
    /// or a duplicate refund; the transaction lock keeps the
    /// load/store pair atomic with respect to other spend / add
    /// operations on the same key.
    ///
    /// Round-34 F1: NEVER resurrect a cell that a concurrent
    /// `remove_prefix` already dropped. The prior implementation
    /// used `self.cell(key)` which materialises a fresh `0`
    /// AtomicI64 in the DashMap via `entry().or_insert_with(...)`.
    /// Under the round-33 lost-claim-plus-idle-close ordering
    /// (mcp_call's sandbox-gate debit races with the reconciler's
    /// clear_budget_state), the refund path would create a
    /// permanent 0-cell for a sealed session that no future
    /// remove_prefix would ever collect — attacker-driven memory
    /// growth. Skip the refund silently when the cell is gone;
    /// the "budget spent" state is already whatever the caller
    /// wanted (probably 0) and there's nothing to compensate.
    fn refund(&self, key: &str, amount: u64) {
        let _transaction = self.transaction_lock.lock();
        let Some(cell) = self.counters.get(key).map(|entry| Arc::clone(entry.value())) else {
            return;
        };
        let prev = cell.load(Ordering::Acquire);
        let amount = i64::try_from(amount).unwrap_or(i64::MAX);
        let next = prev.saturating_sub(amount).max(0);
        cell.store(next, Ordering::Release);
    }

    fn remove_prefix(&self, prefix: &str) {
        let _transaction = self.transaction_lock.lock();
        self.counters.retain(|key, _| !key.starts_with(prefix));
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    /// Round-51 §4.2: the ONE shared backend contract, mirrored by
    /// `redis_contract.rs::redis_satisfies_the_shared_state_store_contract`
    /// so the two backends cannot silently drift on semantics again.
    #[test]
    fn in_memory_satisfies_the_shared_state_store_contract() {
        let store = InMemoryStore::new();
        crate::state_store_contract(&store, "contract-tag");
    }

    #[test]
    fn remove_prefix_drops_only_matching_keys() {
        let store = InMemoryStore::new();
        store.add("budget:{aaaa}:tokens", 5).unwrap();
        store.add("budget:{aaaa}:tool:db_write", 1).unwrap();
        store.add("budget:{bbbb}:tokens", 7).unwrap();
        store.remove_prefix("budget:{aaaa}:");
        assert_eq!(store.get("budget:{aaaa}:tokens").unwrap(), 0);
        assert_eq!(store.get("budget:{aaaa}:tool:db_write").unwrap(), 0);
        assert_eq!(
            store.get("budget:{bbbb}:tokens").unwrap(),
            7,
            "other sessions' counters must survive a prefix removal",
        );
        assert_eq!(store.counters.len(), 1, "removed cells must actually be freed");
    }

    #[test]
    fn add_overflow_rollback_is_never_visible_to_concurrent_get() {
        // Before the fix, add() did fetch_add + fetch_sub to roll back, and
        // get() held no lock — so a concurrent get() could see a transiently
        // negative counter and return Err(Overflow) spuriously.
        // The fix uses store() only after confirming no overflow, so no
        // negative value ever hits the cell.
        use std::sync::{Arc, Barrier};
        use std::thread;

        let store = Arc::new(InMemoryStore::new());
        store.add("k", 5).unwrap();
        let barrier = Arc::new(Barrier::new(3));

        // Writer: push add() to overflow (delta = i64::MAX triggers Overflow).
        let s1 = Arc::clone(&store);
        let b1 = Arc::clone(&barrier);
        let writer = thread::spawn(move || {
            b1.wait();
            for _ in 0..500 {
                let _ = s1.add("k", u64::MAX / 2); // will overflow
            }
        });

        // Reader: must never see Err(Overflow) from a spurious negative.
        let s2 = Arc::clone(&store);
        let b2 = Arc::clone(&barrier);
        let reader1 = thread::spawn(move || {
            b2.wait();
            for _ in 0..2_000 {
                let v = s2.get("k");
                assert!(v.is_ok(), "spurious Overflow from concurrent get: {v:?}");
            }
        });

        let s3 = Arc::clone(&store);
        let b3 = Arc::clone(&barrier);
        let reader2 = thread::spawn(move || {
            b3.wait();
            for _ in 0..2_000 {
                let v = s3.get("k");
                assert!(v.is_ok(), "spurious Overflow from concurrent get: {v:?}");
            }
        });

        writer.join().unwrap();
        reader1.join().unwrap();
        reader2.join().unwrap();
    }

    #[test]
    fn poisoned_negative_value_surfaces_as_overflow_not_silent_zero() {
        // Direct cell manipulation simulates a wire-format corruption or a bug
        // that leaves the counter negative. `get` must surface an Overflow
        // error, not silently zero — the previous behavior would let a
        // corrupted account get a free reset.
        let s = InMemoryStore::new();
        let cell = s.cell("k");
        cell.store(-1, Ordering::Release);
        match s.get("k") {
            Err(StateError::Overflow(_)) => (),
            other => panic!("expected Overflow on negative counter, got {other:?}"),
        }
    }

    #[test]
    fn add_and_get() {
        let s = InMemoryStore::new();
        assert_eq!(s.get("k").unwrap(), 0);
        assert_eq!(s.add("k", 5).unwrap(), 5);
        assert_eq!(s.add("k", 3).unwrap(), 8);
        assert_eq!(s.get("k").unwrap(), 8);
        s.remove("k");
        assert_eq!(s.get("k").unwrap(), 0);
    }

    #[test]
    fn try_spend_respects_limit_exactly() {
        let s = InMemoryStore::new();
        assert!(s.try_spend("b", 3, 3).unwrap()); // exactly to the limit: OK
        assert!(!s.try_spend("b", 1, 3).unwrap()); // over: refused
        assert_eq!(s.get("b").unwrap(), 3, "refused spend must not record");
    }

    #[test]
    fn zero_amount_spend_is_free() {
        let s = InMemoryStore::new();
        assert!(s.try_spend("z", 0, 0).unwrap());
        assert_eq!(s.get("z").unwrap(), 0);
    }

    #[test]
    fn overflow_is_loud_not_wrapping() {
        let s = InMemoryStore::new();
        assert!(matches!(s.add("o", u64::MAX), Err(StateError::Overflow(_))));
    }

    /// Silent-error D13.9: 64 threads × 1000 attempts against a 10_000 budget —
    /// exactly 10_000 must be spent, never more.
    #[test]
    fn concurrent_spend_never_exceeds_budget() {
        let s = Arc::new(InMemoryStore::new());
        let limit = 10_000u64;
        let mut handles = Vec::new();
        for _ in 0..64 {
            let s = Arc::clone(&s);
            handles.push(std::thread::spawn(move || {
                let mut granted = 0u64;
                for _ in 0..1000 {
                    if s.try_spend("shared", 1, limit).unwrap() {
                        granted += 1;
                    }
                }
                granted
            }));
        }
        let total: u64 = handles.into_iter().map(|h| h.join().unwrap()).sum();
        assert_eq!(total, limit, "grants must equal the budget exactly");
        assert_eq!(s.get("shared").unwrap(), limit);
    }

    /// Mixed amounts race: partial spends must never let the sum exceed the cap.
    #[test]
    fn concurrent_mixed_amounts_never_over_cap() {
        let s = Arc::new(InMemoryStore::new());
        let limit = 5_000u64;
        let mut handles = Vec::new();
        for t in 0..32 {
            let s = Arc::clone(&s);
            handles.push(std::thread::spawn(move || {
                let mut spent = 0u64;
                let amount = (t % 7) + 1;
                for _ in 0..500 {
                    if s.try_spend("cap", amount, limit).unwrap() {
                        spent += amount;
                    }
                }
                spent
            }));
        }
        let total: u64 = handles.into_iter().map(|h| h.join().unwrap()).sum();
        assert!(total <= limit, "over-spend: {total} > {limit}");
        assert_eq!(s.get("cap").unwrap(), total);
    }

    /// Vicious bug caught in review round 16: `try_spend_many` used to
    /// validate each Spend against the pre-commit cell value and then commit
    /// them all sequentially. When two Spends referenced the same key, both
    /// passed their independent limit checks (each saw `current = 0`), then
    /// the commit phase INCRBY'd both — silently blowing through the cap.
    /// Duplicate keys must fail loudly with `Backend`, not silently double-spend.
    #[test]
    fn try_spend_many_refuses_duplicate_keys() {
        let s = InMemoryStore::new();
        let outcome = s.try_spend_many(&[
            Spend {
                key: "budget".to_owned(),
                amount: 60,
                limit: 100,
            },
            Spend {
                key: "budget".to_owned(),
                amount: 60,
                limit: 100,
            },
        ]);
        match outcome {
            Err(StateError::Backend(reason)) => {
                assert!(reason.contains("duplicate key"), "wrong reason: {reason}");
            }
            other => panic!("must reject duplicate keys, got {other:?}"),
        }
        assert_eq!(
            s.get("budget").unwrap(),
            0,
            "no partial spend must have been committed",
        );
    }

    /// Symmetric locking of the fix: legitimate distinct-key multi-spends must
    /// still succeed exactly as before.
    #[test]
    fn try_spend_many_distinct_keys_still_commits_atomically() {
        let s = InMemoryStore::new();
        assert_eq!(
            s.try_spend_many(&[
                Spend {
                    key: "a".to_owned(),
                    amount: 3,
                    limit: 10,
                },
                Spend {
                    key: "b".to_owned(),
                    amount: 4,
                    limit: 10,
                },
            ])
            .unwrap(),
            None,
        );
        assert_eq!(s.get("a").unwrap(), 3);
        assert_eq!(s.get("b").unwrap(), 4);
    }

    /// Round-21 F1: cross-backend divergence closed for
    /// `try_spend_many`. Historically InMemoryStore silently
    /// clamped `limit` down to COUNTER_MAX while Redis rejected
    /// the same call with `Overflow`. A caller with a config typo
    /// used to succeed in dev/test and fail in Redis prod. Both
    /// backends now match: reject Overflow on `amount` or `limit`
    /// past JCS_SAFE_MAX.
    #[test]
    fn try_spend_many_rejects_limits_past_counter_max() {
        let s = InMemoryStore::new();
        let outcome = s.try_spend_many(&[Spend {
            key: "a".to_owned(),
            amount: 1,
            limit: av_core::error::JCS_SAFE_MAX + 1,
        }]);
        assert!(
            matches!(outcome, Err(StateError::Overflow(_))),
            "expected Overflow rejection, got {outcome:?}"
        );
    }

    #[test]
    fn try_spend_many_rejects_amounts_past_counter_max() {
        let s = InMemoryStore::new();
        let outcome = s.try_spend_many(&[Spend {
            key: "a".to_owned(),
            amount: av_core::error::JCS_SAFE_MAX + 1,
            limit: u64::MAX,
        }]);
        assert!(
            matches!(outcome, Err(StateError::Overflow(_))),
            "expected Overflow rejection, got {outcome:?}"
        );
    }

    /// Round-34 F1: refund must NEVER resurrect a cell that a prior
    /// remove_prefix cleared. The round-33 F1 refund path used
    /// `self.cell(key)` which materialises a fresh 0-entry via
    /// `entry().or_insert_with(...)`. Under the lost-claim-plus-
    /// idle-close ordering (mcp_call sandbox-gate debit races
    /// reconciler's clear_budget_state), that refund on a swept
    /// session would leave a permanent zero-valued cell that no
    /// future remove_prefix could reap — attacker-choosable
    /// memory growth against a sealed session id.
    #[test]
    fn refund_after_remove_prefix_does_not_resurrect_cells() {
        let s = InMemoryStore::new();
        s.add("budget:{aaaa}:tool:db_write", 1).unwrap();
        s.add("budget:{aaaa}:total_calls", 1).unwrap();
        s.add("budget:{aaaa}:payout", 500_000).unwrap();
        // Simulate the reconciler's clear_budget_state sweeping the
        // session between the sandbox debit and the harness refund.
        s.remove_prefix("budget:{aaaa}:");
        assert_eq!(s.counters.len(), 0, "prefix sweep must have cleared all");
        // Now the harness's refund path fires on the same three
        // keys after the sweep — it must be a silent no-op, NOT
        // a materialize-then-zero.
        s.refund("budget:{aaaa}:tool:db_write", 1);
        s.refund("budget:{aaaa}:total_calls", 1);
        s.refund("budget:{aaaa}:payout", 500_000);
        assert_eq!(
            s.counters.len(),
            0,
            "refund on a swept session must not resurrect counter cells (attacker-choosable growth)"
        );
    }

    /// Round-34 F1: refund on a live session (not swept) still
    /// compensates the debit exactly. Ensures the no-resurrect
    /// guard didn't break the happy path.
    #[test]
    fn refund_on_live_session_still_compensates_exactly() {
        let s = InMemoryStore::new();
        s.add("budget:{live}:tool:db_write", 3).unwrap();
        s.refund("budget:{live}:tool:db_write", 1);
        assert_eq!(s.get("budget:{live}:tool:db_write").unwrap(), 2);
        // Over-refund saturates at 0.
        s.refund("budget:{live}:tool:db_write", 10);
        assert_eq!(s.get("budget:{live}:tool:db_write").unwrap(), 0);
    }
}
