//! Race-condition resilience for the harness concurrency primitives that
//! aren't part of the state store: the event chain under Mutex, the JSON
//! canonicalizer's re-entrancy under threads, and receipt issuance under
//! signer sharing.
//!
//! No thread-unsafe crate can be used from N native threads without the
//! store's own synchronization holding. Each test uses a barrier to line
//! threads up, then asserts a global consistency invariant.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation
)]

use ab_events::{AgentIdentity, CharterFile};
use ab_receipts::{
    canonicalize, CostSummary, Ed25519Signer, EventChain, Keyring, Receipt, ReceiptBody, ReceiptSubject,
    Signer, ToolCallSummary,
};
use parking_lot::Mutex;
use serde_json::json;
use std::sync::{Arc, Barrier};
use std::thread;

fn signer() -> Ed25519Signer {
    Ed25519Signer::from_seed(&[44; 32])
}

fn ring(s: &Ed25519Signer) -> Keyring {
    let mut r = Keyring::new();
    r.add_key_bytes(&Signer::public_key_bytes(s)).unwrap();
    r
}

fn body(session: &str, count: u64) -> ReceiptBody {
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
            event_count: count,
        },
        tool_calls: ToolCallSummary::default(),
        cost: CostSummary::default(),
        stop_reason_id: 1,
        stop_reason: "SessionClosed".to_owned(),
        key_id: String::new(),
        public_key_b64: String::new(),
    }
}

// ---------------------------------------------------------------------------
// 1. Chain append serialization: N threads racing to append distinct events
//    through a shared Mutex must not lose appends; the final count equals
//    the total appends (N × K).
// ---------------------------------------------------------------------------

#[test]
fn concurrent_chain_appends_preserve_count_and_serialize_hashing() {
    let chain = Arc::new(Mutex::new(EventChain::new("sess-race")));
    const N: u64 = 32;
    const K: u64 = 200;
    let barrier = Arc::new(Barrier::new(N as usize));
    let handles: Vec<_> = (0..N)
        .map(|t| {
            let chain = Arc::clone(&chain);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                for k in 0..K {
                    let ev = json!({"t": t, "k": k});
                    chain.lock().append(&ev).unwrap();
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(chain.lock().count(), N * K);
}

// ---------------------------------------------------------------------------
// 2. Canonicalize re-entrancy: JCS is a pure function; N threads
//    canonicalizing the same value must produce byte-identical output.
// ---------------------------------------------------------------------------

#[test]
fn canonicalize_is_thread_safe_and_deterministic() {
    let input = Arc::new(json!({
        "z": [1, 2, 3],
        "a": {"nested": true, "count": 42},
        "m": "café",
    }));
    let expected = canonicalize(&input).unwrap();
    const N: usize = 32;
    let barrier = Arc::new(Barrier::new(N));
    let mut handles = Vec::new();
    for _ in 0..N {
        let input = Arc::clone(&input);
        let barrier = Arc::clone(&barrier);
        let expected = expected.clone();
        handles.push(thread::spawn(move || {
            barrier.wait();
            for _ in 0..500 {
                assert_eq!(canonicalize(&input).unwrap(), expected);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// ---------------------------------------------------------------------------
// 3. Shared signer under contention: N threads issue receipts with the same
//    signer. Every produced receipt must verify against the ring, and no
//    two threads producing identical bodies may see different signatures
//    (RFC 8032 Ed25519 is deterministic).
// ---------------------------------------------------------------------------

#[test]
fn shared_signer_issues_valid_deterministic_receipts_under_contention() {
    let s = Arc::new(signer());
    let ring = Arc::new(ring(&s));
    const N: usize = 32;
    let barrier = Arc::new(Barrier::new(N));
    let mut handles = Vec::new();
    for t in 0..N {
        let s = Arc::clone(&s);
        let ring = Arc::clone(&ring);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            for k in 0..50_u64 {
                // Half the threads use the same body (must produce identical
                // signatures), the other half use unique bodies (must all
                // verify).
                let session = if t % 2 == 0 {
                    "shared".to_owned()
                } else {
                    format!("thread-{t}-{k}")
                };
                let count = if t % 2 == 0 { 1 } else { k + 1 };
                let receipt = Receipt::issue(body(&session, count), s.as_ref()).unwrap();
                receipt.verify(&ring).unwrap();
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    // Determinism spot-check outside the race.
    let r1 = Receipt::issue(body("shared", 1), s.as_ref()).unwrap();
    let r2 = Receipt::issue(body("shared", 1), s.as_ref()).unwrap();
    assert_eq!(r1.signature_b64, r2.signature_b64);
}

// ---------------------------------------------------------------------------
// 4. Chain fork determinism: two independent chains with the same session
//    id built from disjoint threads with the SAME event set (fed in the
//    SAME order) must produce the SAME head. Detects any hidden global
//    state (thread-locals, statics) that would leak into hashing.
// ---------------------------------------------------------------------------

#[test]
fn two_chains_with_identical_input_produce_identical_head_across_threads() {
    let events: Vec<serde_json::Value> = (0..500).map(|i| json!({"i": i, "p": "e"})).collect();
    let events = Arc::new(events);
    let barrier = Arc::new(Barrier::new(2));
    let events_a = Arc::clone(&events);
    let barrier_a = Arc::clone(&barrier);
    let a = thread::spawn(move || {
        barrier_a.wait();
        EventChain::compute("sess", &events_a).unwrap().head_hex()
    });
    let events_b = Arc::clone(&events);
    let barrier_b = Arc::clone(&barrier);
    let b = thread::spawn(move || {
        barrier_b.wait();
        EventChain::compute("sess", &events_b).unwrap().head_hex()
    });
    assert_eq!(a.join().unwrap(), b.join().unwrap());
}
