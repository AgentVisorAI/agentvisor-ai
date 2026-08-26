//! Unit-conversion constants shared workspace-wide.
//!
//! Every crate that mixes seconds/milliseconds or dollars/micro-dollars must
//! use these names rather than open-coding the conversion factors — a
//! misplaced `1_000` vs `1_000_000` was a real class of bug in earlier
//! rounds of this review.

/// Milliseconds per second.
pub const MS_PER_SEC: u64 = 1_000;

/// Milliseconds per hour.
pub const MS_PER_HOUR: u64 = 3_600 * MS_PER_SEC;

/// Milliseconds per day.
pub const MS_PER_DAY: u64 = 24 * MS_PER_HOUR;

/// Seconds per day.
pub const SECS_PER_DAY: u64 = 24 * 3_600;

/// USD micro-units per dollar. All internal cost bookkeeping stays in
/// micro-USD (`u64`) to keep every arithmetic step in exact integers; only
/// wire-facing serialization converts to floating point.
pub const USD_MICROS_PER_DOLLAR: u64 = 1_000_000;

/// Upper bound for cumulative `cost_usd_micros` counters, aligned with
/// `av_atif::validate::MAX_COST_USD` (9e9 USD). Introduced in R69 to
/// close R64 F3: the recovery folds in `av-harness/src/worker.rs`
/// gated `cost_usd_micros` on `av_core::error::JCS_SAFE_MAX` (2^53 =
/// ~$9.007e9 micro-scaled), while the strict ATIF validator refuses
/// any `total_cost_usd > 9e9`. The $7.2M gap between the two ceilings
/// (`JCS_SAFE_MAX / USD_MICROS_PER_DOLLAR = 9,007,199 USD past 9e9`)
/// meant a hostile / drift-authenticated journal replay whose summed
/// costs landed in the window would fold cleanly through recovery
/// (fold says "safe"), then the very next `av_atif::write_atomic`
/// call would strict-refuse the trajectory — the session became
/// un-writable across every reconciler tick. Tightening the fold
/// cost cap to `9e9 * USD_MICROS_PER_DOLLAR = 9e15 micros` (still
/// safely below `JCS_SAFE_MAX = 9.007e15`) means any cost that
/// passes the fold also passes ATIF strict validation.
pub const COST_MICROS_MAX: u64 = 9_000_000_000 * USD_MICROS_PER_DOLLAR;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn factors_agree_with_first_principles() {
        assert_eq!(MS_PER_SEC, 1_000);
        assert_eq!(MS_PER_HOUR, 3_600_000);
        assert_eq!(MS_PER_DAY, 86_400_000);
        assert_eq!(SECS_PER_DAY, 86_400);
        assert_eq!(USD_MICROS_PER_DOLLAR, 1_000_000);
        assert_eq!(COST_MICROS_MAX, 9_000_000_000_000_000);
        // R69 R64 F3 alignment: must be strictly below JCS_SAFE_MAX,
        // so any cost that passes the recovery fold also passes the
        // ATIF strict validator (which refuses total_cost_usd > 9e9).
        // Compile-time-provable relationship — but expressing it as
        // an assertion is the point: any future edit to either
        // constant that widens the gap must trip this test.
        #[allow(clippy::assertions_on_constants)]
        {
            assert!(COST_MICROS_MAX < crate::error::JCS_SAFE_MAX);
        }
    }
}
