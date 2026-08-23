//! Time helpers.
//!
//! Wall-clock time is used for display and record timestamps; ordering
//! decisions inside a session always use the per-session sequence number, never
//! the wall clock (clock skew must not corrupt event-chain order — silent-error
//! class D13.6 in the plan).

use std::time::{SystemTime, UNIX_EPOCH};

/// Milliseconds since the Unix epoch. Saturates at 0 if the system clock is
/// before the epoch (never panics).
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// RFC 3339 / ISO-8601 UTC timestamp with millisecond precision, e.g.
/// `2026-08-10T17:03:05.123Z`. Hand-rolled civil-from-days conversion so we
/// avoid a chrono dependency in the core crate.
pub fn iso8601_ms(epoch_ms: u64) -> String {
    let secs = epoch_ms / crate::units::MS_PER_SEC;
    let ms = epoch_ms % crate::units::MS_PER_SEC;
    let days = secs / crate::units::SECS_PER_DAY;
    let rem = secs % crate::units::SECS_PER_DAY;
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (year, month, day) = civil_from_days(days as i64);
    format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}.{ms:03}Z")
}

/// Current time as ISO-8601 UTC.
pub fn now_iso8601() -> String {
    iso8601_ms(now_ms())
}

/// Elapsed microseconds since `started`, saturating at `u64::MAX` if a caller
/// somehow measures longer than ~585 000 years.
pub fn elapsed_us(started: std::time::Instant) -> u64 {
    u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX)
}

/// Howard Hinnant's `civil_from_days` algorithm (public domain).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    (if m <= 2 { y + 1 } else { y }, m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing)]

    use super::*;

    /// Mutation-run hardening: `elapsed_us` feeds SLA metrics and verdict
    /// latency fields; mutants returning 0/1 survived. 10 ms of real sleep
    /// must measure as at least 2 000 µs on any scheduler.
    #[test]
    fn elapsed_us_measures_real_time() {
        let started = std::time::Instant::now();
        std::thread::sleep(std::time::Duration::from_millis(10));
        assert!(elapsed_us(started) >= 2_000);
    }

    #[test]
    fn epoch_zero() {
        assert_eq!(iso8601_ms(0), "1970-01-01T00:00:00.000Z");
    }

    #[test]
    fn known_timestamp() {
        // 2026-08-10T00:00:00Z == 1786320000000 ms (20675 days × 86400 s)
        assert_eq!(iso8601_ms(1_786_320_000_000), "2026-08-10T00:00:00.000Z");
    }

    #[test]
    fn leap_year_feb_29() {
        // 2024-02-29T12:34:56.789Z == 1709210096789
        assert_eq!(iso8601_ms(1_709_210_096_789), "2024-02-29T12:34:56.789Z");
    }

    #[test]
    fn year_2038_safe() {
        // 2100-01-01T00:00:00Z = 4102444800000 ms — u64 ms has centuries of headroom.
        assert_eq!(iso8601_ms(4_102_444_800_000), "2100-01-01T00:00:00.000Z");
    }

    #[test]
    fn now_is_sane() {
        let now = now_ms();
        assert!(now > 1_700_000_000_000, "clock reads before Nov 2023: {now}");
        let iso = now_iso8601();
        assert!(iso.ends_with('Z') && iso.len() == 24, "bad iso format: {iso}");
    }

    #[test]
    fn civil_from_days_exercises_month_and_day_arithmetic() {
        // Epoch day zero, Mar 1 2024 (day after a leap Feb 29), Dec 31 2099
        // (last day before the 100-year non-leap boundary), and Feb 29 2000
        // (400-year leap). Each hits a different branch of civil_from_days;
        // any `+`/`-` mutation flips the observable date fields.
        let cases: &[(u64, &str)] = &[
            (0, "1970-01-01T00:00:00.000Z"),
            (1_709_251_200_000, "2024-03-01T00:00:00.000Z"),
            (4_102_358_400_000, "2099-12-31T00:00:00.000Z"),
            (951_782_400_000, "2000-02-29T00:00:00.000Z"),
        ];
        for (epoch_ms, expected) in cases {
            assert_eq!(&iso8601_ms(*epoch_ms), expected, "epoch_ms={epoch_ms}");
        }
    }

    // ------------------------------------------------------------------
    // Stress tests: time-related error conditions across machines/UTC.
    // ------------------------------------------------------------------

    /// Output must always be UTC (Zulu) — the code has no timezone lookup and
    /// callers on machines with non-UTC local time still receive UTC.
    #[test]
    fn iso8601_ms_always_emits_utc_zulu() {
        for &epoch_ms in &[0u64, 1_000, 1_786_320_000_000, 4_102_444_800_000] {
            let iso = iso8601_ms(epoch_ms);
            assert!(iso.ends_with('Z'), "must end with Z: {iso}");
            assert!(!iso.contains('+'), "must not carry a `+HH:MM` offset: {iso}");
            assert!(
                !iso[1..].contains('-') || iso.matches('-').count() == 2,
                "only date separators are allowed: {iso}",
            );
        }
    }

    /// Millisecond precision must be honored for every value in `0..1000`.
    #[test]
    fn iso8601_ms_millisecond_precision_is_lossless() {
        let base = 1_786_320_000_000u64; // 2026-08-10T00:00:00.000Z
        for ms in 0..1000 {
            let iso = iso8601_ms(base + ms);
            let expected = format!("2026-08-10T00:00:00.{ms:03}Z");
            assert_eq!(iso, expected, "ms={ms}");
        }
    }

    /// Same epoch value always produces the same string, regardless of the
    /// machine's timezone, DST state, or how many other threads called it.
    #[test]
    fn iso8601_ms_is_deterministic_across_calls() {
        let cases = [0u64, 1_000, 86_400_000, 1_786_320_000_000, 4_102_444_800_000];
        for &epoch_ms in &cases {
            let a = iso8601_ms(epoch_ms);
            let b = iso8601_ms(epoch_ms);
            let c = iso8601_ms(epoch_ms);
            assert_eq!(a, b);
            assert_eq!(b, c);
        }
    }

    /// The four-digit year format holds for every representable second through
    /// the end of year 9999 (23:59:59.999Z), the last instant a fixed-width
    /// 24-char timestamp can encode.
    #[test]
    fn iso8601_ms_stays_24_chars_through_year_9999() {
        // 9999-12-31T23:59:59.999Z
        let last_4digit_ms = 253_402_300_799_999u64;
        let iso = iso8601_ms(last_4digit_ms);
        assert_eq!(iso, "9999-12-31T23:59:59.999Z");
        assert_eq!(iso.len(), 24, "must stay at 24 chars through year 9999");
    }

    /// u64::MAX epoch_ms must not panic — behavior beyond year 9999 is
    /// out-of-spec (the format widens past 24 chars) but callers hitting
    /// pathological values from bug or attack should observe graceful output,
    /// never a crash or an overflow abort.
    #[test]
    fn iso8601_ms_does_not_panic_at_u64_max() {
        let iso = iso8601_ms(u64::MAX);
        assert!(iso.ends_with('Z'), "still emits UTC-Z: {iso}");
        assert!(iso.len() >= 24, "still valid-shape: {iso}");
    }

    /// Wall-clock time must not run backward as observed by consecutive
    /// `now_ms()` calls under normal operation. Two rapid samples might tie,
    /// but the second is never less than the first. (Pre-epoch clocks are a
    /// separate concern: `now_ms` saturates at 0 rather than panicking, which
    /// this smoke test cannot induce.)
    #[test]
    fn now_ms_never_panics_and_is_monotonic_under_normal_operation() {
        let mut previous = now_ms();
        for _ in 0..1_000 {
            let current = now_ms();
            assert!(
                current >= previous,
                "wall clock ran backward: {previous} -> {current}",
            );
            previous = current;
        }
    }

    /// `now_iso8601()` must always round-trip its shape invariant (24 chars,
    /// ends with `Z`) for any real-world clock reading.
    #[test]
    fn now_iso8601_shape_holds_for_real_clock() {
        for _ in 0..100 {
            let iso = now_iso8601();
            assert!(iso.ends_with('Z'), "{iso}");
            assert_eq!(iso.len(), 24, "{iso}");
            // dashes at positions 4 and 7, T at 10, colons at 13, 16, dot at 19.
            let bytes = iso.as_bytes();
            assert_eq!(bytes[4], b'-');
            assert_eq!(bytes[7], b'-');
            assert_eq!(bytes[10], b'T');
            assert_eq!(bytes[13], b':');
            assert_eq!(bytes[16], b':');
            assert_eq!(bytes[19], b'.');
        }
    }

    /// The Feb-28 -> Mar-1 boundary must respect leap-year rules for every
    /// 1-, 4-, 100-, and 400-year cycle representable within u64.
    #[test]
    fn iso8601_ms_leap_year_boundaries_are_correct() {
        // (feb_28_ms, expected_next_day_iso).
        // 2000: 400-year rule -> leap, so Feb 29 exists.
        // 2100: 100-year but not 400 -> non-leap, Feb 28 -> Mar 1.
        // 2400: 400-year -> leap, Feb 29 exists.
        // 2024: simple 4-year -> leap, Feb 29 exists.
        // 2023: not divisible by 4 -> non-leap, Feb 28 -> Mar 1.
        let cases: &[(u64, &str)] = &[
            (951_696_000_000, "2000-02-29T00:00:00.000Z"), // 2000-02-28 + 1 day
            (4_107_456_000_000, "2100-03-01T00:00:00.000Z"), // 2100-02-28 + 1 day
            (
                13_569_465_600_000 + 58 * crate::units::MS_PER_DAY,
                "2400-02-29T00:00:00.000Z",
            ), // 2400
            (1_709_078_400_000, "2024-02-29T00:00:00.000Z"), // 2024-02-28 + 1 day
            (1_677_542_400_000, "2023-03-01T00:00:00.000Z"), // 2023-02-28 + 1 day
        ];
        for &(feb_28_ms, expected_next) in cases {
            let next_day = iso8601_ms(feb_28_ms + crate::units::MS_PER_DAY);
            assert_eq!(next_day, expected_next, "feb_28_ms={feb_28_ms}");
        }
    }

    /// The elapsed_us helper never panics regardless of how far in the past
    /// `Instant` was sampled, and its output stays monotone-nondecreasing for
    /// samples taken in-order from the same instant.
    #[test]
    fn elapsed_us_never_panics_and_is_monotone() {
        let started = std::time::Instant::now();
        let a = elapsed_us(started);
        let b = elapsed_us(started);
        assert!(b >= a, "elapsed_us reversed: {a} -> {b}");
        assert!(a < u64::MAX);
    }
}

#[cfg(test)]
mod calendar_tests {
    /// Mutation-run hardening (round 12): pin Hinnant's calendar math
    /// through the public formatter at epoch, a 400-rule leap day, and
    /// a century non-leap boundary — kills the `z + 719_468` arithmetic
    /// mutants that would shift every rendered audit timestamp.
    #[test]
    fn iso8601_ms_pins_known_dates() {
        assert_eq!(super::iso8601_ms(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(super::iso8601_ms(951_782_400_000), "2000-02-29T00:00:00.000Z");
        assert_eq!(super::iso8601_ms(4_107_542_399_000), "2100-02-28T23:59:59.000Z");
    }
}
