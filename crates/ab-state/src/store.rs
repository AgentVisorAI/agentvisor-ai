//! The `StateStore` trait and the in-memory reference implementation.

use dashmap::DashMap;
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

    /// Remove a key (session cleanup).
    fn remove(&self, key: &str);
}

/// Single-node in-memory store on lock-free atomics.
#[derive(Debug, Default)]
pub struct InMemoryStore {
    counters: DashMap<String, Arc<AtomicI64>>,
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

const MAX: i64 = i64::MAX / 2; // headroom so races can't reach the wrap point

impl StateStore for InMemoryStore {
    fn add(&self, key: &str, delta: u64) -> Result<u64, StateError> {
        let delta = i64::try_from(delta).map_err(|_| StateError::Overflow(key.to_owned()))?;
        let cell = self.cell(key);
        let prev = cell.fetch_add(delta, Ordering::AcqRel);
        let new = prev.checked_add(delta).filter(|v| *v <= MAX);
        match new {
            Some(v) => Ok(u64::try_from(v).unwrap_or(0)),
            None => {
                // Roll back the poisoned add and fail loudly.
                cell.fetch_sub(delta, Ordering::AcqRel);
                Err(StateError::Overflow(key.to_owned()))
            }
        }
    }

    fn get(&self, key: &str) -> Result<u64, StateError> {
        Ok(self
            .counters
            .get(key)
            .map(|c| c.load(Ordering::Acquire))
            .map(|v| u64::try_from(v).unwrap_or(0))
            .unwrap_or(0))
    }

    fn try_spend(&self, key: &str, amount: u64, limit: u64) -> Result<bool, StateError> {
        let amount_i = i64::try_from(amount).map_err(|_| StateError::Overflow(key.to_owned()))?;
        let limit_i = i64::try_from(limit.min(u64::try_from(MAX).unwrap_or(u64::MAX)))
            .map_err(|_| StateError::Overflow(key.to_owned()))?;
        let cell = self.cell(key);
        // Compare-and-swap loop: the only race-safe check-and-spend.
        let mut current = cell.load(Ordering::Acquire);
        loop {
            let next = match current.checked_add(amount_i) {
                Some(v) => v,
                None => return Err(StateError::Overflow(key.to_owned())),
            };
            if next > limit_i {
                return Ok(false);
            }
            match cell.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return Ok(true),
                Err(observed) => current = observed,
            }
        }
    }

    fn remove(&self, key: &str) {
        self.counters.remove(key);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

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
}
