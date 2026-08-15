//! Token-velocity tracking: sliding-window tokens-per-second intended for
//! rate limiting. (The loop-breaker's `N+ tokens` arm uses its own
//! cumulative per-session counter, not this window.)
//!
//! # Round-31 F4 — NOT WIRED INTO ENFORCEMENT
//!
//! There are currently zero production callers of [`TokenVelocity`]; the
//! only users outside this crate are the integration tests in
//! `crates/ab-state/tests/e2e_race_velocity.rs`. The type predates the
//! current admission / loop-breaker plumbing and was never connected to
//! either the breaker's `min_tokens` gate (in `ab_loopdetect`) or any
//! harness rate-limit path.
//!
//! **Do not wire this into the breaker without a shared per-session
//! lock.** The velocity `record_at` mutation and the breaker's `observe`
//! mutation live under different [`parking_lot::Mutex`] instances, so a
//! blind wire-up races the two counters. If you need per-session
//! velocity in the breaker, extend `ab_loopdetect::Breaker` with its own
//! velocity window guarded by the same mutex the breaker already holds.
//!
//! The type is kept public for now (rather than deleted) because the
//! sliding-window arithmetic is exercised by the
//! `e2e_race_velocity` adversarial tests that lock in the
//! round-26 F5 `saturating_add` discipline — reusable ground for the
//! future breaker-integrated window when someone builds it.

use parking_lot::Mutex;
use std::collections::VecDeque;

/// Sliding-window token counter.
#[derive(Debug)]
pub struct TokenVelocity {
    window_ms: u64,
    samples: Mutex<VecDeque<(u64, u64)>>, // (timestamp_ms, tokens)
}

impl TokenVelocity {
    /// Create a tracker with the given window size in milliseconds.
    pub fn new(window_ms: u64) -> Self {
        Self {
            window_ms: window_ms.max(1),
            samples: Mutex::new(VecDeque::new()),
        }
    }

    /// Record `tokens` at time `now_ms` and return the windowed total.
    pub fn record_at(&self, now_ms: u64, tokens: u64) -> u64 {
        let mut samples = self.samples.lock();
        samples.push_back((now_ms, tokens));
        let cutoff = now_ms.saturating_sub(self.window_ms);
        while samples.front().is_some_and(|(t, _)| *t < cutoff) {
            samples.pop_front();
        }
        // Round-26 F5: `Iterator::sum` on `u64` panics in debug and
        // silently wraps in release on overflow. Every other counter
        // and spend site in ab_state uses `checked_add` or
        // `saturating_add` — velocity was the last inconsistent
        // site. Realistically requires ~2^64 windowed tokens, but
        // the discipline gap means a future refactor that turns
        // `window_ms` into a `Duration::MAX` sentinel could reach
        // it. Cheap to fix.
        samples
            .iter()
            .fold(0u64, |acc, (_, n)| acc.saturating_add(*n))
    }

    /// Record at the current wall clock.
    pub fn record(&self, tokens: u64) -> u64 {
        self.record_at(ab_core::time::now_ms(), tokens)
    }

    /// Windowed total without recording.
    pub fn current_at(&self, now_ms: u64) -> u64 {
        let samples = self.samples.lock();
        let cutoff = now_ms.saturating_sub(self.window_ms);
        // Round-26 F5: mirror record_at's saturating_add discipline.
        samples
            .iter()
            .filter(|(t, _)| *t >= cutoff)
            .fold(0u64, |acc, (_, n)| acc.saturating_add(*n))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn accumulates_within_window() {
        let v = TokenVelocity::new(1000);
        assert_eq!(v.record_at(0, 100), 100);
        assert_eq!(v.record_at(500, 50), 150);
        assert_eq!(v.record_at(999, 25), 175);
    }

    #[test]
    fn old_samples_expire() {
        let v = TokenVelocity::new(1000);
        v.record_at(0, 100);
        v.record_at(500, 50);
        // t=1400 → cutoff 400: only the t=0 sample expires.
        assert_eq!(v.record_at(1400, 10), 60);
        // t=1600 → cutoff 600: the t=500 sample expires too.
        assert_eq!(v.current_at(1600), 10);
        assert_eq!(v.current_at(3000), 0, "everything expires eventually");
    }

    #[test]
    fn clock_going_backwards_does_not_panic() {
        let v = TokenVelocity::new(1000);
        v.record_at(5000, 10);
        // Skewed clock: earlier timestamp after a later one.
        let total = v.record_at(4000, 5);
        assert!(total >= 5, "must count at least the new sample, got {total}");
    }

    #[test]
    fn record_returns_the_windowed_total_including_the_new_sample() {
        // The wall-clock `record` wrapper must not be reducible to a
        // constant (mutant misses on `record -> 0 / 1`).
        let v = TokenVelocity::new(60_000);
        let first = v.record(7);
        assert_eq!(first, 7, "first record must return the value just written");
        let second = v.record(3);
        assert_eq!(
            second, 10,
            "second record must reflect both samples inside the window"
        );
    }

    /// Round-26 F5: `Iterator::sum` on `u64` panics in debug and
    /// wraps in release on overflow. Every other counter/spend
    /// site in ab_state uses checked/saturating arithmetic;
    /// velocity now does too. Two u64::MAX samples inside the
    /// window must return u64::MAX (saturated), not panic and not
    /// wrap to a small number.
    #[test]
    fn windowed_sum_saturates_instead_of_wrapping_or_panicking() {
        let v = TokenVelocity::new(60_000);
        v.record_at(1_000, u64::MAX);
        let total = v.record_at(2_000, u64::MAX);
        assert_eq!(
            total,
            u64::MAX,
            "windowed sum must saturate at u64::MAX, got {total}"
        );
        // current_at path also.
        let peek = v.current_at(3_000);
        assert_eq!(
            peek, u64::MAX,
            "current_at must saturate at u64::MAX, got {peek}"
        );
    }
}
