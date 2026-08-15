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
    /// Backend unavailable (network stores).
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
pub trait StateStore: Send + Sync {
    /// Add `delta` to `key`, returning the new value.
    fn add(&self, key: &str, delta: u64) -> Result<u64, StateError>;

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

    /// Remove every key beginning with `prefix` (whole-session cleanup at
    /// finalization). Backends with native expiry (e.g. Redis TTLs) may
    /// leave this as the default no-op; in-process backends must implement
    /// it or session-keyed counters accumulate for the process lifetime.
    fn remove_prefix(&self, prefix: &str) {
        let _ = prefix;
    }
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
/// Redis. `ab_core::error::JCS_SAFE_MAX = 2^53` is the tightest
/// bound (imposed by JCS canonicalization — integers past that
/// point lose precision in receipt bodies), so both backends align
/// with the eventually-signed representation.
pub(crate) const COUNTER_MAX: i64 = ab_core::error::JCS_SAFE_MAX as i64;

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
        Ok(u64::try_from(new).unwrap_or(0))
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
        // Reject duplicate keys: check phase reads current + adds amount per entry.
        // Two spends on the same key would each see the pre-commit value and pass
        // their independent limit checks, then the commit phase would sum them
        // and silently blow through the cap.
        let mut seen = std::collections::HashSet::with_capacity(spends.len());
        for spend in spends {
            if !seen.insert(spend.key.as_str()) {
                return Err(StateError::Backend(format!(
                    "try_spend_many received duplicate key {:?}",
                    spend.key,
                )));
            }
        }
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
            if spend.amount > ab_core::error::JCS_SAFE_MAX {
                return Err(StateError::Overflow(spend.key.clone()));
            }
            if spend.limit > ab_core::error::JCS_SAFE_MAX {
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

    fn remove_prefix(&self, prefix: &str) {
        let _transaction = self.transaction_lock.lock();
        self.counters.retain(|key, _| !key.starts_with(prefix));
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

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
            limit: ab_core::error::JCS_SAFE_MAX + 1,
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
            amount: ab_core::error::JCS_SAFE_MAX + 1,
            limit: u64::MAX,
        }]);
        assert!(
            matches!(outcome, Err(StateError::Overflow(_))),
            "expected Overflow rejection, got {outcome:?}"
        );
    }
}
