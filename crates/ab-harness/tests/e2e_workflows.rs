//! End-to-end workflow round-trips: signed close, unsigned close + promote,
//! and the invariants that connect them (event count, ATIF integrity, promote
//! idempotency, and event publication to the correct topic).

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

use ab_bridge::{BusError, EventBus, PublishAck, StoredEvent};
use ab_events::{EventClass, StopReason};
use ab_harness::reconciler::FinalizeOutcome;
use ab_harness::{AppState, HarnessConfig};
use ab_receipts::{Ed25519Signer, ReceiptSubject};
use ab_sandbox::{Sandbox, SandboxConfig};
use ab_state::InMemoryStore;
use axum::http::{HeaderMap, HeaderValue};
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

// ------------------------------------------------------------------
// A bus that also captures per-topic counts and per-key metadata for
// verification.
// ------------------------------------------------------------------

#[derive(Default)]
struct RecordingBus {
    published: AtomicU64,
    per_topic: Mutex<std::collections::HashMap<String, u64>>,
    seen_uids: Mutex<Vec<String>>,
}

impl EventBus for RecordingBus {
    fn publish(&self, topic: &str, _key: &str, value: &Value) -> Result<PublishAck, BusError> {
        let offset = self.published.fetch_add(1, Ordering::AcqRel);
        *self.per_topic.lock().entry(topic.to_owned()).or_default() += 1;
        if let Some(uid) = value
            .get("metadata")
            .and_then(|m| m.get("uid"))
            .and_then(Value::as_str)
        {
            self.seen_uids.lock().push(uid.to_owned());
        }
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

fn state_with_bus(bus: Arc<RecordingBus>) -> Arc<AppState> {
    let dir = tempfile::tempdir().unwrap();
    let mut config = HarnessConfig::for_tests(
        "http://127.0.0.1:9",
        &dir.path().to_string_lossy(),
        &dir.path().to_string_lossy(),
    );
    config.breaker.min_tokens = u64::MAX;
    std::mem::forget(dir);
    Arc::new(
        AppState::new(
            config,
            Arc::new(InMemoryStore::new()),
            Arc::new(Sandbox::new(SandboxConfig::default(), Vec::new()).unwrap()),
            bus,
            None,
            Arc::new(Ed25519Signer::from_seed([5; 32])),
        )
        .unwrap(),
    )
}

fn headers(session: &str, workflow: &'static str) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert("x-ab-session", HeaderValue::from_str(session).unwrap());
    h.insert("x-ab-workflow", HeaderValue::from_static(workflow));
    h
}

fn chat_payload() -> Value {
    json!({"model": "m", "messages": [{"role": "user", "content": "hi"}]})
}

// ------------------------------------------------------------------
// 1. Signed workflow round-trip: N chat preps → close → Receipt.
//    Receipt.body.subject must be EventChain with event_count matching
//    the actual work published to the bus.
// ------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn signed_workflow_close_produces_receipt_with_matching_event_count() {
    let bus = Arc::new(RecordingBus::default());
    let state = state_with_bus(Arc::clone(&bus));
    let h = headers("wf-signed", "signed");
    const STEPS: u64 = 3;
    for _ in 0..STEPS {
        state.prepare_chat(&h, chat_payload()).unwrap();
    }
    let session = state.sessions.get("wf-signed").unwrap();
    let outcome = state
        .finalizer
        .close_session(session.clone(), StopReason::SessionClosed)
        .await
        .unwrap();
    let receipt = match outcome {
        FinalizeOutcome::Receipt { receipt } => receipt,
        other => panic!("expected Receipt, got {other:?}"),
    };
    // Verify subject matches the recorded chain.
    match &receipt.body.subject {
        ReceiptSubject::EventChain { event_count, .. } => {
            assert_eq!(
                *event_count, STEPS,
                "receipt event_count must match published steps"
            );
        }
        other => panic!("expected EventChain subject, got {other:?}"),
    }
    // Receipt round-trip verifies against the embedded key.
    receipt.verify_embedded().unwrap();
    // Session is closed.
    assert!(session.is_closed());
}

// ------------------------------------------------------------------
// 2. Unsigned workflow round-trip: close writes an ATIF file that
//    passes strict validation.
// ------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unsigned_workflow_close_writes_valid_atif_file() {
    let bus = Arc::new(RecordingBus::default());
    let state = state_with_bus(Arc::clone(&bus));
    let h = headers("wf-unsigned", "unsigned");
    for _ in 0..2 {
        state.prepare_chat(&h, chat_payload()).unwrap();
    }
    let session = state.sessions.get("wf-unsigned").unwrap();
    let outcome = state
        .finalizer
        .close_session(session.clone(), StopReason::SessionClosed)
        .await
        .unwrap();
    let path = match outcome {
        FinalizeOutcome::Atif { path } => path,
        other => panic!("expected Atif, got {other:?}"),
    };
    assert!(path.exists(), "ATIF path must be persisted on disk");
    let bytes = std::fs::read(&path).unwrap();
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    let issues = ab_atif::validate_value(&value, ab_atif::Mode::Strict);
    assert!(
        issues.is_empty(),
        "persisted ATIF must pass strict validation, got: {issues:?}"
    );
    assert!(session.is_closed());
    // The strict provenance sidecar must also exist.
    let auth = path.with_extension("atif-auth");
    assert!(
        auth.exists(),
        "ATIF must have an authenticated provenance sidecar"
    );
}

// ------------------------------------------------------------------
// 3. Promote: unsigned close → promote → AtifTrajectory receipt.
// ------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unsigned_workflow_promote_produces_atif_trajectory_receipt() {
    let bus = Arc::new(RecordingBus::default());
    let state = state_with_bus(Arc::clone(&bus));
    let h = headers("wf-promote", "unsigned");
    for _ in 0..2 {
        state.prepare_chat(&h, chat_payload()).unwrap();
    }
    let session = state.sessions.get("wf-promote").unwrap();
    state
        .finalizer
        .close_session(session.clone(), StopReason::SessionClosed)
        .await
        .unwrap();
    let receipt = state.finalizer.promote(session.clone()).await.unwrap();
    match &receipt.body.subject {
        ReceiptSubject::AtifTrajectory {
            trajectory_digest,
            step_count,
            retroactive,
        } => {
            assert_eq!(trajectory_digest.len(), 64, "digest is a sha256 hex");
            assert!(*retroactive);
            assert!(*step_count >= 1, "promoted trajectory must have >= 1 step");
        }
        other => panic!("expected AtifTrajectory subject, got {other:?}"),
    }
    receipt.verify_embedded().unwrap();
    assert!(session.is_promoted());
}

// ------------------------------------------------------------------
// 4. Promote of an *open* unsigned session works: promote implicitly
//    finalizes the trajectory in one shot. Locking in the convenience.
// ------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn promote_of_an_open_unsigned_session_finalizes_and_promotes() {
    let bus = Arc::new(RecordingBus::default());
    let state = state_with_bus(Arc::clone(&bus));
    let h = headers("wf-promote-open", "unsigned");
    state.prepare_chat(&h, chat_payload()).unwrap();
    let session = state.sessions.get("wf-promote-open").unwrap();
    let receipt = state
        .finalizer
        .promote(session.clone())
        .await
        .expect("promote-of-open must succeed by implicit finalize");
    match &receipt.body.subject {
        ReceiptSubject::AtifTrajectory { retroactive, .. } => assert!(*retroactive),
        other => panic!("expected AtifTrajectory, got {other:?}"),
    }
    assert!(session.is_promoted());
    receipt.verify_embedded().unwrap();
}

// ------------------------------------------------------------------
// 5. Signed close + promote is a no-op (returns the same receipt).
// ------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn signed_close_then_promote_returns_the_same_receipt() {
    let bus = Arc::new(RecordingBus::default());
    let state = state_with_bus(Arc::clone(&bus));
    let h = headers("wf-signed-then-promote", "signed");
    state.prepare_chat(&h, chat_payload()).unwrap();
    let session = state.sessions.get("wf-signed-then-promote").unwrap();
    let receipt = match state
        .finalizer
        .close_session(session.clone(), StopReason::SessionClosed)
        .await
        .unwrap()
    {
        FinalizeOutcome::Receipt { receipt } => receipt,
        other => panic!("expected Receipt, got {other:?}"),
    };
    let promoted = state.finalizer.promote(session.clone()).await.unwrap();
    assert_eq!(receipt.body.receipt_id, promoted.body.receipt_id);
    assert_eq!(receipt.signature_b64, promoted.signature_b64);
    assert_eq!(receipt.body.subject, promoted.body.subject);
}

// ------------------------------------------------------------------
// 6. Receipt event flows to the receipt topic on signed close.
// ------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn signed_close_emits_a_receipt_event_to_the_receipt_topic() {
    let bus = Arc::new(RecordingBus::default());
    let state = state_with_bus(Arc::clone(&bus));
    let h = headers("wf-receipt-emit", "signed");
    state.prepare_chat(&h, chat_payload()).unwrap();
    let session = state.sessions.get("wf-receipt-emit").unwrap();
    state
        .finalizer
        .close_session(session.clone(), StopReason::SessionClosed)
        .await
        .unwrap();
    let counts = bus.per_topic.lock().clone();
    let receipt_topic = EventClass::Receipt.topic();
    let count = counts.get(receipt_topic).copied().unwrap_or(0);
    assert!(
        count >= 1,
        "signed close must publish >= 1 event on the receipt topic, per-topic={counts:?}"
    );
}

// ------------------------------------------------------------------
// 7. Concurrent close + promote race on an unsigned session:
//    exactly one promote succeeds; the losing side sees a promoted
//    receipt (idempotency).
// ------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_promote_on_the_same_session_is_idempotent() {
    let bus = Arc::new(RecordingBus::default());
    let state = state_with_bus(Arc::clone(&bus));
    let h = headers("wf-promote-race", "unsigned");
    state.prepare_chat(&h, chat_payload()).unwrap();
    let session = state.sessions.get("wf-promote-race").unwrap();
    state
        .finalizer
        .close_session(session.clone(), StopReason::SessionClosed)
        .await
        .unwrap();
    let mut handles = Vec::new();
    for _ in 0..8 {
        let state = Arc::clone(&state);
        let session = Arc::clone(&session);
        handles.push(tokio::spawn(
            async move { state.finalizer.promote(session).await },
        ));
    }
    let mut receipts = Vec::new();
    for h in handles {
        let receipt = h.await.unwrap().unwrap();
        receipts.push(receipt);
    }
    // All 8 promote calls succeeded and returned the same receipt (id +
    // signature bytes must be byte-identical — no forked chains).
    assert!(session.is_promoted());
    let head = receipts[0].clone();
    for r in &receipts[1..] {
        assert_eq!(r.body.receipt_id, head.body.receipt_id);
        assert_eq!(r.signature_b64, head.signature_b64);
        assert_eq!(r.body.subject, head.body.subject);
    }
}
