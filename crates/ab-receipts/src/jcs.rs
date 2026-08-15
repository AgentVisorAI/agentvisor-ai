//! RFC 8785 — JSON Canonicalization Scheme (JCS).
//!
//! Rules implemented (and tested against the RFC's own vectors):
//! - object keys sorted by **UTF-16 code units** (surrogate order, not byte
//!   order — they differ for supplementary-plane characters);
//! - numbers serialized with ECMAScript `ToString(Number)` semantics
//!   (shortest round-trip digits; decimal notation for exponents in
//!   (-7, 21); `e+`/`e-` exponential outside; `-0` → `0`);
//! - strings minimally escaped (`\"`, `\\`, `\b`, `\f`, `\n`, `\r`, `\t`,
//!   `\u00XX` for other controls; everything else literal UTF-8);
//! - no insignificant whitespace.
//!
//! Integers beyond ±2^53 are **rejected** (not silently rounded): JCS numbers
//! are IEEE-754 doubles and precision loss would corrupt canonical hashes
//! (silent-error class D13.4).

use serde_json::Value;
use std::fmt::Write as _;

/// Canonicalization failures.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum JcsError {
    /// Integer outside the exactly-representable double range.
    #[error("integer {0} outside ±2^53; JCS would lose precision")]
    UnsafeInteger(String),
    /// Non-finite number (unreachable via `serde_json::Value`, kept for defense).
    #[error("non-finite number cannot be canonicalized")]
    NonFinite,
    /// Round-40 F5: value nesting exceeds `MAX_NESTED_DEPTH`.
    ///
    /// Current call sites all feed `canonicalize` a `Value` that was
    /// parsed by `serde_json::from_slice` (default recursion limit
    /// 128), or serialized from a typed struct with bounded depth,
    /// so this cap is transitively already enforced. The cap here is
    /// defense-in-depth against a future caller that pipes an
    /// unbounded-parsed `Value` (e.g. `serde_json::Deserializer::
    /// disable_recursion_limit`) or a merged deep tree — without
    /// this bound, `write_value` would recurse until the OS stack
    /// overflows.
    #[error("value nesting exceeds {0}; JCS refuses to recurse further")]
    TooDeep(usize),
}

/// Round-40 F5: matches `ab_receipts::receipt::MAX_NESTED_DEPTH`
/// (128), which is also the serde_json default parser recursion
/// limit — anything a legit strict-load receipt could carry.
const MAX_NESTED_DEPTH: usize = 128;

/// Canonicalize a JSON value per RFC 8785. Returns the canonical UTF-8 string.
pub fn canonicalize(value: &Value) -> Result<String, JcsError> {
    // Typical receipt canonicalizes to a few hundred bytes; pre-allocate to
    // avoid the growth-doubling churn on the first few pushes.
    let mut out = String::with_capacity(512);
    write_value(value, &mut out, 0)?;
    Ok(out)
}

fn write_value(value: &Value, out: &mut String, depth: usize) -> Result<(), JcsError> {
    if depth > MAX_NESTED_DEPTH {
        return Err(JcsError::TooDeep(MAX_NESTED_DEPTH));
    }
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => write_number(n, out)?,
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(item, out, depth + 1)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            // Sort keys by UTF-16 code-unit sequence.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| utf16_cmp(a, b));
            out.push('{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(key, out);
                out.push(':');
                if let Some(v) = map.get(*key) {
                    write_value(v, out, depth + 1)?;
                }
            }
            out.push('}');
        }
    }
    Ok(())
}

/// Compare two strings by their UTF-16 code-unit sequences (RFC 8785 §3.2.3).
fn utf16_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000C}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

use ab_core::error::JCS_SAFE_MAX;

fn write_number(n: &serde_json::Number, out: &mut String) -> Result<(), JcsError> {
    if let Some(u) = n.as_u64() {
        if u > JCS_SAFE_MAX {
            return Err(JcsError::UnsafeInteger(u.to_string()));
        }
        let _ = write!(out, "{u}");
        return Ok(());
    }
    if let Some(i) = n.as_i64() {
        if i < -(JCS_SAFE_MAX as i64) {
            return Err(JcsError::UnsafeInteger(i.to_string()));
        }
        let _ = write!(out, "{i}");
        return Ok(());
    }
    let f = n.as_f64().ok_or(JcsError::NonFinite)?;
    if !f.is_finite() {
        return Err(JcsError::NonFinite);
    }
    out.push_str(&ecma_number(f));
    Ok(())
}

/// ECMAScript `ToString(Number)` (ECMA-262 §6.1.6.1.20) for finite doubles.
///
/// Digits come from ryu (shortest **correctly-rounded** representation —
/// Rust's `{:e}`/Grisu is shortest but not always correctly rounded, which the
/// RFC 8785 Appendix vectors catch); the ECMAScript layout rules are then
/// applied to (digits, k).
fn ecma_number(f: f64) -> String {
    if f == 0.0 {
        return "0".to_owned(); // covers -0.0 per ES semantics
    }
    if f < 0.0 {
        let mut s = String::with_capacity(24);
        s.push('-');
        s.push_str(&ecma_number(-f));
        return s;
    }
    let mut buf = ryu::Buffer::new();
    let printed = buf.format_finite(f);
    let (digits, k) = digits_and_k(printed);
    let digits = digits.as_str();
    let n = digits.len() as i64;

    if (1..=21).contains(&k) && n <= k {
        // Integer: digits followed by k-n zeros.
        let mut s = String::from(digits);
        for _ in 0..(k - n) {
            s.push('0');
        }
        s
    } else if (1..=21).contains(&k) {
        // Decimal point inside the digits; 1 <= k < n here so the split is in-bounds.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let (int_part, frac_part) = digits.split_at(k as usize);
        format!("{int_part}.{frac_part}")
    } else if (-5..=0).contains(&k) {
        // 0.000ddd… (ECMA-262: −6 < k ≤ 0)
        let mut s = String::from("0.");
        for _ in 0..(-k) {
            s.push('0');
        }
        s.push_str(digits);
        s
    } else {
        // Exponential: d[.ddd]e±(k-1)
        let exp_val = k - 1;
        let sign = if exp_val >= 0 { "+" } else { "-" };
        let (first, rest) = digits.split_at(1);
        if rest.is_empty() {
            format!("{first}e{sign}{}", exp_val.abs())
        } else {
            format!("{first}.{rest}e{sign}{}", exp_val.abs())
        }
    }
}

/// Decompose a ryu-printed positive finite float (`"123.45"`, `"1.5e-7"`,
/// `"12.0"`) into shortest digit string and ECMAScript `k` (value =
/// 0.digits × 10^k).
fn digits_and_k(printed: &str) -> (String, i64) {
    let (mantissa, e) = match printed.split_once(['e', 'E']) {
        Some((m, exp)) => (m, exp.parse::<i64>().unwrap_or(0)),
        None => (printed, 0),
    };
    let (int_part, frac_part) = match mantissa.split_once('.') {
        Some((i, f)) => (i, f),
        None => (mantissa, ""),
    };
    let int_stripped = int_part.trim_start_matches('0');
    let (raw, k) = if int_stripped.is_empty() {
        let lead_zeros = frac_part.len() - frac_part.trim_start_matches('0').len();
        (
            frac_part.trim_start_matches('0').to_owned(),
            e - lead_zeros as i64,
        )
    } else {
        (
            format!("{int_stripped}{frac_part}"),
            int_stripped.len() as i64 + e,
        )
    };
    let digits = raw.trim_end_matches('0');
    if digits.is_empty() {
        ("0".to_owned(), k)
    } else {
        (digits.to_owned(), k)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use serde_json::json;

    /// RFC 8785 Appendix B number vectors (IEEE-754 bit patterns → canonical text).
    #[test]
    fn rfc8785_appendix_b_numbers() {
        let vectors: &[(u64, &str)] = &[
            (0x0000000000000000, "0"),
            (0x8000000000000000, "0"), // -0 → 0
            (0x0000000000000001, "5e-324"),
            (0x8000000000000001, "-5e-324"),
            (0x7fefffffffffffff, "1.7976931348623157e+308"),
            (0xffefffffffffffff, "-1.7976931348623157e+308"),
            (0x4340000000000000, "9007199254740992"),
            (0xc340000000000000, "-9007199254740992"),
            (0x444b1ae4d6e2ef50, "1e+21"),
            (0x3eb0c6f7a0b5ed8d, "0.000001"),
            (0x3e7ad7f29abcaf48, "1e-7"),
            (0x41b3de4355555553, "333333333.3333332"),
            (0x41b3de4355555554, "333333333.33333325"),
            (0x41b3de4355555555, "333333333.3333333"),
            (0x41b3de4355555556, "333333333.3333334"),
            (0x41b3de4355555557, "333333333.33333343"),
            (0xbecbf647612f3696, "-0.0000033333333333333333"),
            (0x43143ff3c1cb0959, "1424953923781206.2"),
        ];
        for (bits, expected) in vectors {
            let f = f64::from_bits(*bits);
            assert_eq!(&ecma_number(f), expected, "bits {bits:#018x}");
        }
    }

    #[test]
    fn integer_forms() {
        assert_eq!(ecma_number(1.0), "1");
        assert_eq!(ecma_number(42.0), "42");
        assert_eq!(ecma_number(100000.0), "100000");
        assert_eq!(ecma_number(1e20), "100000000000000000000");
        assert_eq!(ecma_number(1e21), "1e+21");
        assert_eq!(ecma_number(-1e21), "-1e+21");
    }

    #[test]
    fn fraction_forms() {
        assert_eq!(ecma_number(0.5), "0.5");
        assert_eq!(ecma_number(0.000001), "0.000001");
        assert_eq!(ecma_number(0.0000001), "1e-7");
        assert_eq!(ecma_number(1.5), "1.5");
        assert_eq!(ecma_number(1.2345678901234567), "1.2345678901234567");
    }

    /// RFC 8785 §3.2.3 key-sorting example (UTF-16 order incl. supplementary chars).
    #[test]
    fn rfc8785_key_sorting() {
        // Keys via JSON escapes (editor normalization must not corrupt the vector):
        // \u20AC €, \uD83D\uDE02 😂 (U+1F602), \uFB33 דּ (precomposed).
        // UTF-16 code-unit order: 20AC < D83D < FB33 — differs from code-point
        // order, where 1F602 would sort last.
        let v: Value = serde_json::from_str(r#"{"\uFB33": 3, "\uD83D\uDE02": 2, "\u20AC": 1}"#).unwrap();
        let c = canonicalize(&v).unwrap();
        assert_eq!(c, "{\"\u{20ac}\":1,\"\u{1f602}\":2,\"\u{fb33}\":3}");
    }

    /// RFC 8785 Appendix A weird-input vector.
    #[test]
    fn rfc8785_structure_vector() {
        let input = r#"{
          "numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
          "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
          "literals": [null, true, false]
        }"#;
        let v: Value = serde_json::from_str(input).unwrap();
        let c = canonicalize(&v).unwrap();
        let expected = "{\"literals\":[null,true,false],\"numbers\":[333333333.3333333,1e+30,4.5,0.002,1e-27],\"string\":\"€$\\u000f\\nA'B\\\"\\\\\\\\\\\"/\"}";
        assert_eq!(c, expected);
    }

    #[test]
    fn string_escapes() {
        let v = json!({"a": "line\nbreak\ttab\u{0001}ctl\"quote\\back"});
        let c = canonicalize(&v).unwrap();
        assert_eq!(c, "{\"a\":\"line\\nbreak\\ttab\\u0001ctl\\\"quote\\\\back\"}");
    }

    #[test]
    fn unsafe_integers_rejected() {
        let over = serde_json::Number::from((1u64 << 53) + 1);
        let v = Value::Number(over);
        assert_eq!(
            canonicalize(&v),
            Err(JcsError::UnsafeInteger(((1u64 << 53) + 1).to_string()))
        );
        let under = serde_json::Number::from(-(1i64 << 53) - 1);
        assert!(canonicalize(&Value::Number(under)).is_err());
        // Exactly ±2^53 is fine.
        assert!(canonicalize(&json!(1u64 << 53)).is_ok());
        assert!(canonicalize(&json!(-(1i64 << 53))).is_ok());
    }

    #[test]
    fn insertion_order_does_not_matter() {
        // serde_json preserve_order keeps insertion order, so these two Values
        // have different internal order — canonical output must be identical.
        let a: Value = serde_json::from_str(r#"{"z":1,"a":2,"m":{"y":1,"b":2}}"#).unwrap();
        let b: Value = serde_json::from_str(r#"{"a":2,"m":{"b":2,"y":1},"z":1}"#).unwrap();
        assert_eq!(canonicalize(&a).unwrap(), canonicalize(&b).unwrap());
    }

    #[test]
    fn canonicalization_is_idempotent() {
        let v = json!({"b": [1.5, "x", {"k": 1e21}], "a": null});
        let once = canonicalize(&v).unwrap();
        let reparsed: Value = serde_json::from_str(&once).unwrap();
        let twice = canonicalize(&reparsed).unwrap();
        assert_eq!(once, twice);
    }

    #[test]
    fn empty_containers() {
        assert_eq!(canonicalize(&json!({})).unwrap(), "{}");
        assert_eq!(canonicalize(&json!([])).unwrap(), "[]");
        assert_eq!(canonicalize(&json!("")).unwrap(), "\"\"");
    }

    #[test]
    fn space_at_boundary_u0020_is_not_escaped() {
        // The escape guard is `< 0x20`: space (U+0020) sits at the boundary
        // and must stay literal, not become "\u0020". This detects the
        // <-vs-<= off-by-one silently corrupting canonical output.
        let v = json!({"a": "a b"});
        assert_eq!(canonicalize(&v).unwrap(), "{\"a\":\"a b\"}");
        // And U+001F just below the boundary DOES get escaped.
        let v2 = json!({"a": "a\u{001f}b"});
        assert_eq!(canonicalize(&v2).unwrap(), "{\"a\":\"a\\u001fb\"}");
    }

    #[test]
    fn positive_zero_never_prints_with_a_minus_sign() {
        // ES semantics: both zeros print "0". The `f == 0.0` early return
        // covers -0.0 too (IEEE: -0.0 == 0.0), and it must stay ahead of the
        // sign-handling branch — dropping or reordering it would send -0.0
        // through ryu and emit "-0".
        assert_eq!(ecma_number(0.0), "0");
        assert_eq!(ecma_number(-0.0), "0");
    }

    /// Round-40 F5: recursion is capped at `MAX_NESTED_DEPTH`. All
    /// current call sites feed `canonicalize` a `Value` parsed by
    /// serde_json (default limit 128) so this cap is transitively
    /// redundant today, but a future caller that pipes a
    /// disable_recursion_limit-parsed Value would otherwise
    /// stack-overflow. Build a nested array manually (bypassing
    /// serde_json's parser cap) and assert `TooDeep` is returned
    /// cleanly rather than the process crashing.
    #[test]
    fn canonicalize_refuses_pathologically_nested_arrays() {
        let mut v = Value::Array(vec![Value::Null]);
        for _ in 0..MAX_NESTED_DEPTH + 10 {
            v = Value::Array(vec![v]);
        }
        assert_eq!(
            canonicalize(&v),
            Err(JcsError::TooDeep(MAX_NESTED_DEPTH))
        );
    }

    #[test]
    fn canonicalize_accepts_depths_up_to_the_cap() {
        // Build a nested tree at exactly MAX_NESTED_DEPTH to lock
        // in the boundary behaviour. `MAX_NESTED_DEPTH + 1` is the
        // cutoff; MAX itself must still succeed.
        let mut v = Value::Null;
        for _ in 0..MAX_NESTED_DEPTH {
            v = Value::Array(vec![v]);
        }
        assert!(canonicalize(&v).is_ok());
    }
}
