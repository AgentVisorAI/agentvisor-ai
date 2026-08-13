//! Exotic character + encoding stress tests.
//!
//! Attackers historically break gates by feeding text that looks safe to
//! one layer and hostile to the next: BOM markers that shift byte offsets,
//! zero-width characters that hide instructions, right-to-left overrides
//! that swap displayed order, Unicode Tags (already covered in
//! `e2e_sota_attacks`) plus these more exotic classes:
//!
//!   - normalization confusables (NFC vs NFD vs NFKC)
//!   - visual homoglyphs (Latin `a` vs Cyrillic `а`)
//!   - line separator + paragraph separator (Cargo::json parsers vs older
//!     JS parsers disagreed until ES2019)
//!   - bidi overrides / isolates (CVE-2021-42574 style "Trojan Source")
//!   - CJK fullwidth ASCII (fullwidth letters as confusables)
//!   - astral-plane / supplementary characters (emoji + math symbols +
//!     ancient scripts)
//!   - code points adjacent to the surrogate range (U+D7FF / U+E000 —
//!     actual surrogate halves cannot exist in valid UTF-8)
//!   - control characters allowed by JSON (U+0080..U+009F)
//!   - invalid UTF-8 byte sequences (must be rejected by serde, never
//!     silently coerced)
//!
//! Each test asserts that the relevant AgentBridge boundary responds
//! *predictably* to the exotic input — either accepts it verbatim (with the
//! same bytes on both sides) or rejects it with a typed error.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    text_direction_codepoint_in_literal
)]

use ab_core::ids::{InstanceUid, SessionId};
use ab_core::tokens::{approx_tokens, approx_tokens_json};
use ab_receipts::{
    canonicalize, CostSummary, Ed25519Signer, EventChain, JcsError, Keyring, Receipt, ReceiptBody,
    ReceiptSubject, Signer, ToolCallSummary,
};
use serde_json::{json, Value};

fn signer() -> Ed25519Signer {
    Ed25519Signer::from_seed([171; 32])
}
fn ring(s: &Ed25519Signer) -> Keyring {
    let mut r = Keyring::new();
    r.add_key_bytes(&Signer::public_key_bytes(s)).unwrap();
    r
}
fn body(session: &str, stop_reason: String) -> ReceiptBody {
    ReceiptBody {
        receipt_version: 1,
        receipt_id: "r".to_owned(),
        session_id: session.to_owned(),
        issued_at: 1,
        issued_at_iso: "1970-01-01T00:00:00.001Z".to_owned(),
        ai_agent: ab_events::AgentIdentity {
            version: "1".to_owned(),
            charter: ab_events::CharterFile::from("c"),
            instance_uid: "i".to_owned(),
            ttl_remaining_s: None,
        },
        subject: ReceiptSubject::EventChain {
            chain_head: "0e".repeat(32),
            event_count: 1,
        },
        tool_calls: ToolCallSummary::default(),
        cost: CostSummary::default(),
        stop_reason_id: 1,
        stop_reason,
        key_id: String::new(),
        public_key_b64: String::new(),
    }
}

// ---------------------------------------------------------------------------
// 1. `SessionId::parse` refuses every non-visible-ASCII byte class we care
//    about: NUL, control, DEL, high-ASCII, UTF-8 continuation bytes, BOM,
//    tabs/newlines/spaces. Baseline for the id gate.
// ---------------------------------------------------------------------------

#[test]
fn session_id_refuses_exotic_control_and_non_ascii_bytes() {
    let bad: &[&str] = &[
        "\0",              // NUL
        "\x01",            // SOH
        "\x1f",            // US
        "\x7f",            // DEL
        " ",               // space (visible ASCII starts at 0x21)
        "\t",              // tab
        "\n",              // LF
        "\r",              // CR
        "\u{feff}session", // BOM
        "café",            // non-ASCII
        "𝕊ession",         // supplementary plane
        "hi\u{200b}world", // zero-width space
        "hi\u{202e}world", // right-to-left override
        "hi\u{2028}world", // line separator
        "hi\u{2029}world", // paragraph separator
    ];
    for s in bad {
        assert!(
            SessionId::parse(s).is_err(),
            "SessionId::parse({s:?}) unexpectedly accepted"
        );
        assert!(
            InstanceUid::parse(s).is_err(),
            "InstanceUid::parse({s:?}) unexpectedly accepted"
        );
    }
    // But every printable ASCII from ! to ~ MUST parse.
    for byte in 0x21u8..=0x7e {
        let s = String::from(byte as char);
        SessionId::parse(&s).unwrap();
        InstanceUid::parse(&s).unwrap();
    }
}

// ---------------------------------------------------------------------------
// 2. Tokenizer never panics on ANY of the exotic classes, and every one of
//    these exotic cases yields a non-zero count so the budget can't be
//    zero-costed by cramming Unicode into a prompt.
// ---------------------------------------------------------------------------

#[test]
fn tokenizer_survives_every_exotic_class_and_bills_them() {
    let cases: &[&str] = &[
        "\u{feff}",                 // BOM alone
        "\u{200b}\u{200c}\u{200d}", // zero-width space/joiner/non-joiner
        "\u{202a}foo\u{202c}",      // LRE + PDF
        "\u{202e}reverse\u{202c}",  // RLO
        "\u{2066}iso\u{2069}",      // LRI + PDI
        "\u{fffd}",                 // replacement char
        "𝓗ᴇʟʟᴏ 𝓦ᴏʀʟᴅ",              // mathematical + phonetic
        "🇫🇷🇺🇸🏴󠁧󠁢󠁷󠁬󠁳󠁿",                   // regional indicators + tag flag
        "\u{e0041}\u{e0042}",       // Unicode Tags letters
        "café\u{301}",              // NFC + NFD combining
        "аbсdе",                    // Cyrillic homoglyphs for abcde
        "\u{d7ff}\u{e000}",         // just below/above surrogate range
        "𐐷Deseret",                 // supplementary plane
        "‮reversed input",           // literal RLO
        "\u{7}bell\u{08}bs",        // control chars
        "\u{85}NEL",                // Next Line (C1)
        "\u{a0}nbsp",               // non-breaking space
    ];
    for s in cases {
        let count = approx_tokens(s);
        assert!(count >= 1, "exotic case zero-costed: {s:?}");
        assert!(count < 1_000_000, "runaway token count for {s:?}: {count}");
    }
    // Homoglyphs must NOT tokenize identically to their ASCII look-alikes.
    let ascii = approx_tokens("abcde");
    let cyril = approx_tokens("аbсdе");
    assert_ne!(ascii, cyril, "Cyrillic homoglyphs count as ASCII — budget bypass");
}

// ---------------------------------------------------------------------------
// 3. JCS canonicalizes every legal Unicode class byte-identically to how
//    it would be read back, and REJECTS malformed UTF-8 (which can't reach
//    canonicalize via `Value` anyway — serde_json rejects earlier).
// ---------------------------------------------------------------------------

#[test]
fn jcs_canonicalizes_every_legal_unicode_and_serde_rejects_invalid_utf8() {
    let cases: &[Value] = &[
        json!({"k": "\u{feff}"}),
        json!({"k": "\u{200b}\u{200c}"}),
        json!({"k": "\u{202e}reversed\u{202c}"}),
        json!({"k": "𝓗ello 𝕎orld"}),
        json!({"k": "\u{fffd}"}),
        json!({"k": "café"}),
        json!({"k": "cafe\u{301}"}),
        json!({"k": "𐐷"}),
        json!({"k": "🎉🚀🇫🇷"}),
        json!({"k": "\u{7f}"}),
        json!({"k": "\u{85}\u{a0}"}),
    ];
    for v in cases {
        let out = canonicalize(v).unwrap();
        // Round-trip: canon parses back into an equivalent Value.
        let back: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(&back, v);
    }
    // Invalid UTF-8 bytes never make it to canonicalize because serde_json
    // rejects them at parse time.
    let bad = b"{\"k\":\"\xff\xfe\"}";
    assert!(serde_json::from_slice::<Value>(bad).is_err());
}

// ---------------------------------------------------------------------------
// 4. Unicode normalization confusables — NFC and NFD encodings of "café"
//    plus a fullwidth confusable produce distinct JCS canonical bytes, so
//    a signature under one form NEVER verifies another. No homoglyph
//    forgery via normalization. (For "café", NFKC≡NFC and NFKD≡NFD, so
//    these three variants cover the distinct forms.)
// ---------------------------------------------------------------------------

#[test]
fn each_unicode_normalization_form_yields_a_distinct_canonical_string() {
    let variants = [
        "caf\u{e9}",                      // NFC (é as single code point)
        "cafe\u{301}",                    // NFD (e + combining acute)
        "\u{ff43}\u{ff41}\u{ff46}\u{e9}", // fullwidth c a f + NFC é
    ];
    let mut canons: Vec<String> = variants
        .iter()
        .map(|s| canonicalize(&json!({"name": *s})).unwrap())
        .collect();
    let before = canons.len();
    canons.sort();
    canons.dedup();
    assert_eq!(before, canons.len(), "normalization variants collided");
}

// ---------------------------------------------------------------------------
// 5. JCS rejects one class outright: numeric strings that carry unsafe
//    integers embedded in an object are still fine (they're strings), but
//    an integer VALUE outside ±2^53 is rejected. Test both boundaries with
//    exotic-looking large integers (2^53 - 1 accepted, 2^53 + 1 rejected).
// ---------------------------------------------------------------------------

#[test]
fn jcs_boundary_reject_around_2_pow_53() {
    let ok = 9_007_199_254_740_991_u64; // 2^53 - 1
    let unsafe_int = 9_007_199_254_740_993_u64; // 2^53 + 1
    assert!(canonicalize(&json!({"n": ok})).is_ok());
    match canonicalize(&json!({"n": unsafe_int})) {
        Err(JcsError::UnsafeInteger(_)) => {}
        other => panic!("expected UnsafeInteger, got {other:?}"),
    }
    // A stringified large integer must not be re-parsed and re-checked.
    let ok_str = canonicalize(&json!({"n": unsafe_int.to_string()})).unwrap();
    assert!(ok_str.contains("\"9007199254740993\""));
}

// ---------------------------------------------------------------------------
// 6. Receipt round-trip over an 8-KiB exotic-character `stop_reason`:
//    combines the entire exotic vocabulary into one long free-text field,
//    signs, then verifies. Any single lost byte or normalization would
//    break verification.
// ---------------------------------------------------------------------------

#[test]
fn receipt_round_trips_a_stop_reason_full_of_exotic_characters() {
    let s = signer();
    let ring = ring(&s);
    let mut exotic = String::with_capacity(8 * 1024);
    let ingredients = [
        "\u{feff}",
        "🎉🚀",
        "𝓗ello 𝕎orld",
        "café",
        "cafe\u{301}",
        "\u{202e}rlo\u{202c}",
        "\u{200b}\u{200c}",
        "𐐷",
        "\u{fffd}",
        "\u{ff41}\u{ff42}\u{ff43}", // fullwidth abc
        "𝟢𝟣𝟤",                      // math digits
        "\u{85}\u{a0}\u{7f}",       // control set
    ];
    while exotic.len() < 8 * 1024 {
        for i in &ingredients {
            exotic.push_str(i);
        }
    }
    let receipt = Receipt::issue(body("sess-exotic", exotic.clone()), &s).unwrap();
    receipt.verify(&ring).unwrap();
    assert_eq!(receipt.body.stop_reason, exotic);
    // JSON serialization round-trip preserves every byte.
    let bytes = serde_json::to_vec(&receipt).unwrap();
    let restored: Receipt = serde_json::from_slice(&bytes).unwrap();
    restored.verify(&ring).unwrap();
    assert_eq!(restored.body.stop_reason, exotic);
}

// ---------------------------------------------------------------------------
// 7. Event chain: distinct events built from exotic-character content that
//    could be confused for the same string produce distinct heads. Proves
//    the chain doesn't secretly normalize on the way to SHA-256.
// ---------------------------------------------------------------------------

#[test]
fn chain_distinguishes_visually_identical_but_bytewise_different_events() {
    let ascii_a = EventChain::compute("sess", &[json!({"c": "café"})])
        .unwrap()
        .head_hex();
    let nfd_a = EventChain::compute("sess", &[json!({"c": "cafe\u{301}"})])
        .unwrap()
        .head_hex();
    let cyril_a = EventChain::compute("sess", &[json!({"c": "аbсdе"})]) // Cyrillic
        .unwrap()
        .head_hex();
    let ascii_l = EventChain::compute("sess", &[json!({"c": "abcde"})])
        .unwrap()
        .head_hex();
    assert_ne!(ascii_a, nfd_a);
    assert_ne!(cyril_a, ascii_l);
}

// ---------------------------------------------------------------------------
// 8. Tokenizer JSON path (`approx_tokens_json`) never zeroes out for a
//    non-null value — pathological inputs (very deep, very wide,
//    exotic-heavy) still produce a positive token count so budgets can
//    never be silently bypassed.
// ---------------------------------------------------------------------------

#[test]
fn tokenizer_json_path_is_positive_for_all_non_null_exotic_payloads() {
    let cases: &[Value] = &[
        json!("\u{feff}"),
        json!({"messages": [{"role": "user", "content": "\u{202e}rlo\u{202c}"}]}),
        json!({"messages": [{"role": "user", "content": "🎉".repeat(1_000)}]}),
        json!([[[[[[[[[[[[[[[[[["deep"]]]]]]]]]]]]]]]]]]),
        json!({"cafe\u{301}": "α", "α": "cafe\u{301}"}),
    ];
    for v in cases {
        let n = approx_tokens_json(v);
        assert!(n > 0, "tokenizer zeroed out on {v:?}");
    }
    // Null and empty container edge cases: also finite and non-panicking.
    for v in [Value::Null, json!({}), json!([])] {
        let _ = approx_tokens_json(&v);
    }
}
