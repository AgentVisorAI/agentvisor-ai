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
    let secs = epoch_ms / 1000;
    let ms = epoch_ms % 1000;
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (year, month, day) = civil_from_days(days as i64);
    format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}.{ms:03}Z")
}

/// Current time as ISO-8601 UTC.
pub fn now_iso8601() -> String {
    iso8601_ms(now_ms())
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
    use super::*;

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
        assert!(now > 1_700_000_000_000, "clock reads before 2023: {now}");
        let iso = now_iso8601();
        assert!(iso.ends_with('Z') && iso.len() == 24, "bad iso format: {iso}");
    }
}
