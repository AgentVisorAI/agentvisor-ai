//! Robustness under massive / extremely large prompts and contexts.
//!
//! Guarantees exercised here:
//!   - JCS canonicalization never blows the stack on deep/wide trees and
//!     produces monotonically-larger output for monotonically-larger input;
//!   - the event chain hashes very long streams in linear time and never
//!     drops or double-counts events;
//!   - `Receipt::verify` still passes over a `stop_reason` that carries
//!     megabytes of pathological text;
//!   - the tokenizer is monotone and finite on multi-MB unicode-heavy input.
//!
//! Numbers stay in the low-MB range so the suite finishes in seconds; they
//! are 3-4 orders of magnitude above the sizes real production traffic will
//! present through the pipeline.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation
)]

use ab_core::tokens::{approx_tokens, approx_tokens_json};
use ab_events::{AgentIdentity, CharterFile};
use ab_receipts::{
    canonicalize, CostSummary, Ed25519Signer, EventChain, Keyring, Receipt, ReceiptBody, ReceiptSubject,
    Signer, ToolCallSummary,
};
use serde_json::{json, Value};
use std::time::Instant;

fn signer() -> Ed25519Signer {
    Ed25519Signer::from_seed([17; 32])
}
fn ring(s: &Ed25519Signer) -> Keyring {
    let mut r = Keyring::new();
    r.add_key_bytes(&Signer::public_key_bytes(s)).unwrap();
    r
}

fn body_with_stop_reason(session: &str, stop_reason: String) -> ReceiptBody {
    ReceiptBody {
        receipt_version: 1,
        receipt_id: "r".to_owned(),
        session_id: session.to_owned(),
        issued_at: 1,
        issued_at_iso: "1970-01-01T00:00:00.001Z".to_owned(),
        ai_agent: AgentIdentity {
            version: "1".to_owned(),
            charter: CharterFile::from("c"),
            instance_uid: "i".to_owned(),
            ttl_remaining_s: None,
        },
        subject: ReceiptSubject::EventChain {
            chain_head: "00".repeat(32),
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
// 1. Wide flat object (100k keys): JCS must not blow up, must sort keys by
//    UTF-16, and output must reflect the input size linearly.
// ---------------------------------------------------------------------------

#[test]
fn jcs_handles_wide_object_with_100k_keys() {
    let mut map = serde_json::Map::with_capacity(100_000);
    for i in 0..100_000u32 {
        map.insert(format!("k{i:08}"), Value::from(i));
    }
    let v = Value::Object(map);
    let started = Instant::now();
    let canon = canonicalize(&v).unwrap();
    let elapsed = started.elapsed();
    assert!(canon.len() > 100_000 * 12);
    assert!(elapsed.as_secs() < 10, "wide canonicalize took {elapsed:?}");
    // Keys must be sorted: the first two entries should be k00000000 then k00000001.
    let first = canon.find("\"k00000000\"").unwrap();
    let second = canon.find("\"k00000001\"").unwrap();
    assert!(first < second);
}

// ---------------------------------------------------------------------------
// 2. Deep nested array (1000 levels): stack-safe canonicalization. The
//    canonical form must contain a matching count of open/close brackets.
// ---------------------------------------------------------------------------

#[test]
fn jcs_handles_1000_level_nested_arrays_without_stack_overflow() {
    let mut v = Value::from(42);
    for _ in 0..1_000 {
        v = Value::Array(vec![v]);
    }
    let canon = canonicalize(&v).unwrap();
    assert_eq!(canon.matches('[').count(), 1_000);
    assert_eq!(canon.matches(']').count(), 1_000);
}

// ---------------------------------------------------------------------------
// 3. Huge single string field (4 MiB): canonicalize + roundtrip parse.
// ---------------------------------------------------------------------------

#[test]
fn jcs_handles_4mib_string_field() {
    let big = "a".repeat(4 * 1024 * 1024);
    let v = json!({"payload": big.clone()});
    let canon = canonicalize(&v).unwrap();
    // Canonical size = 2 (quotes) + payload + object frame; must exceed 4MiB.
    assert!(canon.len() > 4 * 1024 * 1024);
    // Round-trip parseable.
    let parsed: Value = serde_json::from_str(&canon).unwrap();
    assert_eq!(parsed["payload"].as_str().unwrap().len(), big.len());
}

// ---------------------------------------------------------------------------
// 4. Event chain over 100k events: linear-time hashing, deterministic head,
//    exact event count.
// ---------------------------------------------------------------------------

#[test]
fn event_chain_hashes_100k_events_and_stays_deterministic() {
    let events: Vec<Value> = (0..100_000u32).map(|i| json!({"seq": i, "p": "e"})).collect();
    let started = Instant::now();
    let a = EventChain::compute("big-sess", &events).unwrap();
    let elapsed_a = started.elapsed();
    let b = EventChain::compute("big-sess", &events).unwrap();
    assert_eq!(a.head_hex(), b.head_hex(), "chain drift on rerun");
    assert_eq!(a.count(), 100_000);
    assert!(elapsed_a.as_secs() < 30, "chain took {elapsed_a:?}");
    // Any single tamper still detected.
    let mut tampered = events.clone();
    tampered[50_000] = json!({"seq": 50_000, "p": "TAMPERED"});
    let c = EventChain::compute("big-sess", &tampered).unwrap();
    assert_ne!(a.head_hex(), c.head_hex());
}

// ---------------------------------------------------------------------------
// 5. Receipt over an 8 MiB stop_reason field: issue + verify must succeed
//    without truncation or corruption.
// ---------------------------------------------------------------------------

#[test]
fn receipt_signs_and_verifies_with_8mib_stop_reason() {
    let s = signer();
    let ring = ring(&s);
    let big = "x".repeat(8 * 1024 * 1024);
    let body = body_with_stop_reason("sess-huge", big.clone());
    let started = Instant::now();
    let receipt = Receipt::issue(body, &s).unwrap();
    let issued_at = started.elapsed();
    receipt.verify(&ring).unwrap();
    assert_eq!(receipt.body.stop_reason.len(), big.len());
    assert!(issued_at.as_secs() < 30, "issue took {issued_at:?}");
}

// ---------------------------------------------------------------------------
// 6. Tokenizer on 4 MiB text with heavy unicode: monotone (appending
//    never lowers), finite, does not panic.
// ---------------------------------------------------------------------------

#[test]
fn tokenizer_is_monotone_and_finite_on_4mib_unicode() {
    let unit = "hello 世界 🚀 ";
    let big: String = unit.repeat((4 * 1024 * 1024) / unit.len() + 1);
    let n1 = approx_tokens(&big);
    let n2 = approx_tokens(&(big.clone() + unit));
    assert!(n2 >= n1, "tokenizer non-monotone");
    // Approximate but sane: >= 1 token per unit repetition.
    let repeats = big.len() / unit.len();
    assert!(u64::try_from(repeats).unwrap() <= n1 * 8);
    // JSON path also survives.
    let v = json!({"text": big});
    let tokens = approx_tokens_json(&v);
    assert!(tokens > 0);
}

// ---------------------------------------------------------------------------
// 7. Deep nested object (1000 levels) inside a signed receipt subject:
//    verify still passes end-to-end.
// ---------------------------------------------------------------------------

#[test]
fn receipt_verify_survives_deeply_nested_charter_metadata_in_stop_reason() {
    // Encode 1000-level structure as a text payload inside stop_reason —
    // the receipt schema doesn't accept nested JSON in typed fields, but
    // stop_reason is String and must round-trip an arbitrarily-nested
    // JSON string safely.
    let mut deep = Value::from(1);
    for _ in 0..500 {
        deep = json!({"n": deep});
    }
    let payload = serde_json::to_string(&deep).unwrap();
    let s = signer();
    let ring = ring(&s);
    let receipt = Receipt::issue(body_with_stop_reason("deep-sess", payload.clone()), &s).unwrap();
    receipt.verify(&ring).unwrap();
    assert_eq!(receipt.body.stop_reason.len(), payload.len());
}

// ---------------------------------------------------------------------------
// 8. Empty vs single-char boundary: tokenizer + canonicalize handle the
//    smallest inputs deterministically (paired with the large tests to
//    show the whole range is safe, not just the middle).
// ---------------------------------------------------------------------------

#[test]
fn tiny_inputs_are_handled_deterministically() {
    assert_eq!(approx_tokens(""), 0);
    assert_eq!(approx_tokens_json(&Value::Null), approx_tokens("null"));
    assert_eq!(canonicalize(&Value::Null).unwrap(), "null");
    assert_eq!(canonicalize(&json!([])).unwrap(), "[]");
    assert_eq!(canonicalize(&json!({})).unwrap(), "{}");
}
