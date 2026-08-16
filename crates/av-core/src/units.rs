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
    }
}
