//! Cross-crate edge-case verification.
//!
//! Boundary values that are easy to get wrong: exact-limit budget spends,
//! exact-limit JCS integers, exact-cutoff retention, session ID length
//! boundaries, empty/single-shard cases, compact-vs-pretty JSON receipt
//! canonicalization, zero-seed Ed25519 signing, and concurrent lifecycle
//! idempotency.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

use av_bridge::{BridgeManifest, BusError, EmbeddedBroker, EventBus, PublishAck, StoredEvent};
use av_events::{AgentIdentity, CharterFile, EventClass};
use av_harness::{AppState, HarnessConfig};
use av_receipts::{
    canonicalize, CostSummary, Ed25519Signer, JcsError, Keyring, Receipt, ReceiptBody, ReceiptError,
    ReceiptSubject, Signer, ToolCallSummary,
};
use av_sandbox::{Sandbox, SandboxConfig};
use av_state::{ActionBudget, BudgetDecision, BudgetSpec, InMemoryStore};
use axum::http::{HeaderMap, HeaderValue};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

// ------------------------------------------------------------------
// 1. JCS boundary: exactly 2^53 accepted, 2^53+1 refused.
// ------------------------------------------------------------------

#[test]
fn jcs_accepts_exactly_two_to_the_fifty_third_and_rejects_one_above() {
    let boundary = json!({ "n": u64::pow(2, 53) });
    assert!(canonicalize(&boundary).is_ok(), "2^53 must canonicalize");
    let over = json!({ "n": u64::pow(2, 53) + 1 });
    match canonicalize(&over) {
        Err(JcsError::UnsafeInteger(_)) => (),
        other => panic!("2^53+1 must fail with UnsafeInteger, got {other:?}"),
    }
    // Negative boundary is symmetric.
    let neg_boundary = json!({ "n": -(1i64 << 53) });
    assert!(canonicalize(&neg_boundary).is_ok(), "-2^53 must canonicalize");
    let neg_over = json!({ "n": -(1i64 << 53) - 1 });
    assert!(
        canonicalize(&neg_over).is_err(),
        "-(2^53)-1 must fail canonicalization"
    );
}

// ------------------------------------------------------------------
// 2. Receipt signed with EventChain.event_count = 2^53 signs+verifies;
//    2^53+1 must fail at issue time (JCS refuses).
// ------------------------------------------------------------------

fn body_with_event_count(count: u64) -> ReceiptBody {
    ReceiptBody {
        receipt_version: 1,
        receipt_id: "r".to_owned(),
        session_id: "s".to_owned(),
        issued_at: 0,
        issued_at_iso: "1970-01-01T00:00:00Z".to_owned(),
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

#[test]
fn receipt_signs_at_jcs_boundary_and_refuses_above() {
    let signer = Ed25519Signer::from_seed(&[1; 32]);
    let ok = Receipt::issue(body_with_event_count(1u64 << 53), &signer);
    assert!(ok.is_ok(), "event_count = 2^53 must sign");

    let over = Receipt::issue(body_with_event_count((1u64 << 53) + 1), &signer);
    match over {
        Err(ReceiptError::Jcs(JcsError::UnsafeInteger(_))) => (),
        other => panic!("2^53+1 must refuse to sign, got {other:?}"),
    }
}

// ------------------------------------------------------------------
// 3. Compact and pretty JSON receipts both verify (JCS invariance).
// ------------------------------------------------------------------

#[test]
fn compact_and_pretty_receipt_json_both_verify() {
    let signer = Ed25519Signer::from_seed(&[2; 32]);
    let receipt = Receipt::issue(body_with_event_count(5), &signer).unwrap();
    let mut ring = Keyring::new();
    ring.add_key_bytes(&Signer::public_key_bytes(&signer)).unwrap();

    // Round-trip via pretty JSON.
    let pretty = serde_json::to_string_pretty(&receipt).unwrap();
    let compact = serde_json::to_string(&receipt).unwrap();
    let via_pretty: Receipt = serde_json::from_str(&pretty).unwrap();
    let via_compact: Receipt = serde_json::from_str(&compact).unwrap();
    via_pretty.verify(&ring).unwrap();
    via_compact.verify(&ring).unwrap();
    // Interleaved fields (map key reorder in serialization) must also verify
    // because JCS re-canonicalizes.
    let parsed: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&compact).unwrap();
    // Move signature_b64 first — preserve_order is enabled workspace-wide,
    // so rebuilding the map signature-first genuinely reorders the wire
    // bytes; client shuffling map order must not matter.
    let mut shuffled_map = serde_json::Map::new();
    let sig = parsed.get("signature_b64").unwrap().clone();
    shuffled_map.insert("signature_b64".to_string(), sig);
    for (key, value) in parsed {
        if key != "signature_b64" {
            shuffled_map.insert(key, value);
        }
    }
    let shuffled = serde_json::to_string(&shuffled_map).unwrap();
    let reshuffled: Receipt = serde_json::from_str(&shuffled).unwrap();
    reshuffled.verify(&ring).unwrap();
}

// ------------------------------------------------------------------
// 4. Zero-seed Ed25519 signs and verifies (spec-legal edge case).
// ------------------------------------------------------------------

#[test]
fn zero_seed_ed25519_signs_and_verifies() {
    let signer = Ed25519Signer::from_seed(&[0; 32]);
    let receipt = Receipt::issue(body_with_event_count(1), &signer).unwrap();
    let mut ring = Keyring::new();
    ring.add_key_bytes(&Signer::public_key_bytes(&signer)).unwrap();
    receipt.verify(&ring).unwrap();
}

// ------------------------------------------------------------------
// 5. SessionId length boundary: exactly 128 pass, 129 fail; visible-ASCII
//    boundary bytes 0x21 and 0x7e pass; 0x20 and 0x7f fail.
// ------------------------------------------------------------------

fn state(config: HarnessConfig) -> Arc<AppState> {
    #[derive(Default)]
    struct Bus {
        n: AtomicU64,
    }
    impl EventBus for Bus {
        fn publish(&self, topic: &str, _key: &str, _value: &Value) -> Result<PublishAck, BusError> {
            let offset = self.n.fetch_add(1, Ordering::AcqRel);
            Ok(PublishAck {
                topic: topic.to_owned(),
                partition: 0,
                offset,
            })
        }
        fn fetch(&self, _t: &str, _p: u32, _o: u64, _m: usize) -> Result<Vec<StoredEvent>, BusError> {
            Ok(Vec::new())
        }
        fn partitions(&self, _t: &str) -> Result<u32, BusError> {
            Ok(1)
        }
        fn topics(&self) -> Vec<String> {
            EventClass::all().iter().map(|c| c.topic().to_owned()).collect()
        }
    }
    Arc::new(
        AppState::new(
            config,
            Arc::new(InMemoryStore::new()),
            Arc::new(Sandbox::new(SandboxConfig::default(), Vec::new()).unwrap()),
            Arc::new(Bus::default()),
            None,
            Arc::new(Ed25519Signer::from_seed(&[3; 32])),
        )
        .unwrap(),
    )
}

fn chat_payload() -> Value {
    json!({"model": "m", "messages": [{"role": "user", "content": "hi"}]})
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn session_id_exact_length_boundary() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = HarnessConfig::for_tests(
        "http://127.0.0.1:9",
        &dir.path().to_string_lossy(),
        &dir.path().to_string_lossy(),
    );
    let state = state(cfg);
    for good_len in [1usize, 32, 127, 128] {
        let id = "a".repeat(good_len);
        let mut h = HeaderMap::new();
        h.insert("x-av-session", HeaderValue::from_str(&id).unwrap());
        assert!(
            state.prepare_chat(&h, chat_payload()).is_ok(),
            "session id length {good_len} must be accepted"
        );
    }
    for bad_len in [129usize, 200] {
        let id = "a".repeat(bad_len);
        let mut h = HeaderMap::new();
        h.insert("x-av-session", HeaderValue::from_str(&id).unwrap());
        assert!(
            state.prepare_chat(&h, chat_payload()).is_err(),
            "session id length {bad_len} must be rejected"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn session_id_visible_ascii_boundary() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = HarnessConfig::for_tests(
        "http://127.0.0.1:9",
        &dir.path().to_string_lossy(),
        &dir.path().to_string_lossy(),
    );
    let state = state(cfg);
    // Through the HTTP layer: 0x21..=0x7e are all accepted.
    for good in ["!", "~", "!~a", "abc-DEF_123.xyz"] {
        let mut h = HeaderMap::new();
        h.insert("x-av-session", HeaderValue::from_str(good).unwrap());
        assert!(
            state.prepare_chat(&h, chat_payload()).is_ok(),
            "session id {good:?} must be accepted"
        );
    }
    // Direct against SessionId::parse — bytes outside VCHAR are refused there
    // regardless of whether the HTTP layer would let them through.
    for bad in [
        "",
        " lead-space",
        "trail-space ",
        "with space",
        "tab\there",
        "del\x7f",
    ] {
        assert!(
            av_core::SessionId::parse(bad).is_err(),
            "SessionId must reject {bad:?}"
        );
    }
    for edge in ["!", "~", "!~a"] {
        assert!(
            av_core::SessionId::parse(edge).is_ok(),
            "SessionId must accept {edge:?}"
        );
    }
}

// ------------------------------------------------------------------
// 6. Budget: spend exactly at cap allowed, one over refused, and
//    each try_tool_call is transactional (over-spend never records).
// ------------------------------------------------------------------

#[test]
fn payout_budget_at_exact_cap_is_allowed_and_one_over_refused() {
    let store = InMemoryStore::new();
    let spec = BudgetSpec {
        max_payout_usd_micros: Some(50_000_000), // $50 exact
        ..BudgetSpec::default()
    };
    let budget = ActionBudget::new(&store, "session-cap", &spec);
    // First: spend exactly the cap. Must be allowed.
    match budget.try_tool_call("payout", 50_000_000) {
        Ok(BudgetDecision::Allowed { .. }) => (),
        other => panic!("exact-cap payout must be allowed, got {other:?}"),
    }
    // Second: any further payout must be refused.
    match budget.try_tool_call("payout", 1) {
        Ok(BudgetDecision::Refused { limit, cap }) => {
            assert_eq!(cap, 50_000_000);
            assert!(
                limit.contains("payout"),
                "limit name should mention payout: {limit}"
            );
        }
        other => panic!("one-micro over cap must refuse, got {other:?}"),
    }
    // Third: even a zero-payout tool that isn't consequential must be allowed
    // (the payout cap is not tripped by 0).
    match budget.try_tool_call("read", 0) {
        Ok(BudgetDecision::Allowed { .. }) => (),
        other => panic!("zero-payout read must be allowed, got {other:?}"),
    }
}

#[test]
fn per_tool_cap_of_zero_blocks_the_first_call() {
    let store = InMemoryStore::new();
    let mut per = BTreeMap::new();
    per.insert("payout".to_owned(), 0u64);
    let spec = BudgetSpec {
        max_tool_calls: per,
        ..BudgetSpec::default()
    };
    let budget = ActionBudget::new(&store, "sess-zero-cap", &spec);
    match budget.try_tool_call("payout", 0) {
        Ok(BudgetDecision::Refused { limit, cap }) => {
            assert_eq!(cap, 0);
            assert!(limit.contains("payout"), "{limit}");
        }
        other => panic!("cap=0 must refuse the very first call, got {other:?}"),
    }
}

// ------------------------------------------------------------------
// 7. Broker: fetch(max=0) returns empty; retention keeps records exactly
//    at the cutoff timestamp.
// ------------------------------------------------------------------

fn min_manifest() -> BridgeManifest {
    let mut m = BridgeManifest::default_for("edge-cases");
    for topic in &mut m.topics {
        topic.schema_ref = None;
        topic.partitions = 1;
    }
    m
}

#[test]
fn broker_fetch_with_max_one_returns_at_most_one_record() {
    let dir = tempfile::tempdir().unwrap();
    let broker = EmbeddedBroker::provision(dir.path(), &min_manifest()).unwrap();
    for i in 0..3 {
        broker
            .publish(
                "agent.tool_call",
                "inst",
                &json!({"metadata": {"uid": format!("u-{i}")}}),
            )
            .unwrap();
    }
    let fetched = broker.fetch("agent.tool_call", 0, 0, 1).unwrap();
    assert_eq!(fetched.len(), 1, "max=1 must cap at 1, got {fetched:?}");
}

#[test]
fn broker_fetch_with_max_zero_returns_empty() {
    let dir = tempfile::tempdir().unwrap();
    let broker = EmbeddedBroker::provision(dir.path(), &min_manifest()).unwrap();
    broker
        .publish("agent.tool_call", "inst", &json!({"metadata": {"uid": "u-zero"}}))
        .unwrap();
    let fetched = broker.fetch("agent.tool_call", 0, 0, 0).unwrap();
    assert!(
        fetched.is_empty(),
        "max=0 must return no records, got {fetched:?}"
    );
}

#[test]
fn broker_retention_keeps_records_at_exact_cutoff() {
    // Publish a record; then enforce retention with `now` chosen so cutoff
    // equals the record's stored_at. The record must be KEPT (strict <).
    let dir = tempfile::tempdir().unwrap();
    let cold = tempfile::tempdir().unwrap();
    let mut m = min_manifest();
    for topic in &mut m.topics {
        topic.retention.hot_hours = 1;
        topic.retention.cold_uri = Some(cold.path().to_string_lossy().into_owned());
    }
    let broker = EmbeddedBroker::provision(dir.path(), &m).unwrap();
    broker
        .publish(
            "agent.tool_call",
            "inst",
            &json!({"metadata": {"uid": "boundary"}}),
        )
        .unwrap();
    // A `now` that puts the cutoff exactly at the record's stored_at means the
    // record's `stored_at < cutoff` predicate is FALSE — so it stays.
    let record = broker.fetch("agent.tool_call", 0, 0, 1).unwrap()[0].clone();
    let cutoff = record.stored_at;
    let now = cutoff + u64::from(m.topics[0].retention.hot_hours) * 3_600_000;
    let expired = broker.enforce_retention(now).unwrap();
    assert_eq!(
        expired, 0,
        "records at exact cutoff (stored_at == cutoff) must be kept"
    );
    // The record is still fetchable.
    let after = broker.fetch("agent.tool_call", 0, 0, 10).unwrap();
    assert_eq!(after.len(), 1);
}

#[test]
fn broker_retention_expires_records_one_ms_older_than_cutoff() {
    // Same setup, but shift now by one extra ms so cutoff > stored_at.
    let dir = tempfile::tempdir().unwrap();
    let cold = tempfile::tempdir().unwrap();
    let mut m = min_manifest();
    for topic in &mut m.topics {
        topic.retention.hot_hours = 1;
        topic.retention.cold_uri = Some(cold.path().to_string_lossy().into_owned());
    }
    let broker = EmbeddedBroker::provision(dir.path(), &m).unwrap();
    broker
        .publish(
            "agent.tool_call",
            "inst",
            &json!({"metadata": {"uid": "expiring"}}),
        )
        .unwrap();
    let record = broker.fetch("agent.tool_call", 0, 0, 1).unwrap()[0].clone();
    let now = record.stored_at + u64::from(m.topics[0].retention.hot_hours) * 3_600_000 + 1;
    let expired = broker.enforce_retention(now).unwrap();
    assert_eq!(expired, 1);
}

// ------------------------------------------------------------------
// 8. Concurrent close_session on the same session is idempotent.
// ------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_close_session_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = HarnessConfig::for_tests(
        "http://127.0.0.1:9",
        &dir.path().to_string_lossy(),
        &dir.path().to_string_lossy(),
    );
    let state = state(cfg);
    let mut h = HeaderMap::new();
    h.insert("x-av-session", HeaderValue::from_static("idem-close"));
    state.prepare_chat(&h, chat_payload()).unwrap();
    let session = state.sessions.get("idem-close").unwrap();
    // Race N close_session invocations on the same session.
    let mut handles = Vec::new();
    for _ in 0..8 {
        let state = Arc::clone(&state);
        let session = Arc::clone(&session);
        handles.push(tokio::spawn(async move {
            state
                .finalizer
                .close_session(session, av_events::StopReason::SessionClosed)
                .await
        }));
    }
    let mut did_work = 0;
    let mut already_count = 0;
    for h in handles {
        match h.await.unwrap().unwrap() {
            av_harness::reconciler::FinalizeOutcome::AlreadyClosed => already_count += 1,
            // Either a signed Receipt or an ATIF trajectory is a valid finalize
            // outcome; the invariant is "exactly one did work".
            _ => did_work += 1,
        }
    }
    assert_eq!(
        did_work, 1,
        "exactly one close must do work, got did_work={did_work} already={already_count}"
    );
    assert_eq!(already_count, 7);
    assert!(session.is_closed());
}

// ------------------------------------------------------------------
// 9. Empty policy chain default = every allow-list-free tool passes.
// ------------------------------------------------------------------

#[test]
fn empty_policy_chain_allows_arbitrary_tools() {
    let sandbox = Sandbox::new(SandboxConfig::default(), Vec::new()).unwrap();
    let store = InMemoryStore::new();
    let raw = serde_json::to_vec(&json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "anything", "arguments": {}}
    }))
    .unwrap();
    let verdict = sandbox.check(&store, "s", &raw);
    assert!(verdict.is_allowed(), "empty policy chain must default-allow");
}

// ------------------------------------------------------------------
// 10. Manifest boundary: partition count 1 accepted (already tested);
//     large but sane count 1024 accepted (the exact cap; > 1024 rejection
//     is pinned by manifest.rs's own boundary tests).
// ------------------------------------------------------------------

#[test]
fn manifest_supports_a_large_but_sane_partition_count() {
    let mut m = min_manifest();
    m.topics[0].partitions = 1024;
    // Validate structurally; do not actually provision 1024 empty partitions.
    assert!(m.validate().is_ok(), "1024 partitions must validate");
}

#[test]
fn manifest_supports_the_maximum_replication_factor() {
    let mut m = min_manifest();
    m.replication_factor = 5;
    assert!(m.validate().is_ok(), "replication_factor=5 must validate");
    m.replication_factor = 6;
    assert!(m.validate().is_err(), "replication_factor=6 must be rejected");
}
