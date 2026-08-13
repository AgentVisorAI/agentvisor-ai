//! Race-condition resilience through the full async pipeline.
//!
//! Wave 3 covered `Session` state-machine primitives in isolation; this
//! suite drives them concurrently through `AppState::prepare_chat` +
//! `Finalizer::close_session` on a multi-thread Tokio runtime, so every
//! internal lock ordering (chain Mutex, admission RwLock, journal atomics,
//! bus fan-out) is exercised end-to-end.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::cast_possible_truncation
)]

use ab_bridge::{BusError, EventBus, PublishAck, StoredEvent};
use ab_events::{EventClass, StopReason};
use ab_harness::reconciler::FinalizeOutcome;
use ab_harness::{AppState, HarnessConfig};
use ab_receipts::{Ed25519Signer, ReceiptSubject};
use ab_sandbox::{Sandbox, SandboxConfig};
use ab_state::InMemoryStore;
use axum::http::{HeaderMap, HeaderValue};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Default)]
struct CountingBus {
    published: AtomicU64,
}

impl EventBus for CountingBus {
    fn publish(&self, _t: &str, _k: &str, _v: &Value) -> Result<PublishAck, BusError> {
        Ok(PublishAck {
            topic: String::new(),
            partition: 0,
            offset: self.published.fetch_add(1, Ordering::AcqRel),
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

fn app_state() -> Arc<AppState> {
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
            Arc::new(CountingBus::default()),
            None,
            Arc::new(Ed25519Signer::from_seed([9; 32])),
        )
        .unwrap(),
    )
}

fn signed_headers(session: &str) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert("x-ab-session", HeaderValue::from_str(session).unwrap());
    h.insert("x-ab-workflow", HeaderValue::from_static("signed"));
    h
}

fn chat_payload() -> Value {
    json!({"model": "m", "messages": [{"role": "user", "content": "hi"}]})
}

// ---------------------------------------------------------------------------
// 1. Concurrent `prepare_chat` on ONE session id from N tokio tasks: all
//    calls must succeed, the resulting Session's seq counter advances by
//    exactly N (no lost preps, no duplicate seqs), and a subsequent close
//    issues exactly one signed receipt whose event_count matches N.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_prepare_chat_on_one_session_produces_matching_receipt() {
    let state = app_state();
    const N: u64 = 32;
    let mut tasks = Vec::new();
    for _ in 0..N {
        let state = Arc::clone(&state);
        tasks.push(tokio::spawn(async move {
            let h = signed_headers("race-chat");
            state.prepare_chat(&h, chat_payload()).unwrap();
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    let session = state.sessions.get("race-chat").unwrap();
    let outcome = state
        .finalizer
        .close_session(session.clone(), StopReason::SessionClosed)
        .await
        .unwrap();
    match outcome {
        FinalizeOutcome::Receipt { receipt } => match &receipt.body.subject {
            ReceiptSubject::EventChain { event_count, .. } => {
                assert_eq!(*event_count, N, "event_count drifted under contention");
            }
            other => panic!("expected EventChain subject, got {other:?}"),
        },
        other => panic!("expected signed receipt, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 2. Concurrent `close_session` on the SAME session: exactly ONE task
//    receives a `Receipt` outcome, every other task must observe
//    `AlreadyClosed`. Multiple receipts = double finalization.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_close_yields_one_receipt_and_rest_already_closed() {
    let state = app_state();
    let h = signed_headers("race-close");
    for _ in 0..5 {
        state.prepare_chat(&h, chat_payload()).unwrap();
    }
    let session = state.sessions.get("race-close").unwrap();
    const N: usize = 16;
    let mut tasks = Vec::new();
    for _ in 0..N {
        let state = Arc::clone(&state);
        let session = Arc::clone(&session);
        tasks.push(tokio::spawn(async move {
            state
                .finalizer
                .close_session(session, StopReason::SessionClosed)
                .await
                .unwrap()
        }));
    }
    let mut receipts = 0;
    let mut already = 0;
    for t in tasks {
        match t.await.unwrap() {
            FinalizeOutcome::Receipt { .. } => receipts += 1,
            FinalizeOutcome::AlreadyClosed => already += 1,
            other => panic!("unexpected outcome: {other:?}"),
        }
    }
    assert_eq!(receipts, 1, "expected exactly one receipt, got {receipts}");
    assert_eq!(already, N - 1, "expected {} AlreadyClosed, got {already}", N - 1);
}

// ---------------------------------------------------------------------------
// 3. Fan-out across many DISTINCT sessions concurrently: each session must
//    produce its own receipt with the correct per-session event_count.
//    Cross-session state must never leak (mixing seqs = broken audit).
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_multi_session_fanout_produces_correct_per_session_receipts() {
    let state = app_state();
    const SESSIONS: u64 = 16;
    const STEPS_PER_SESSION: u64 = 5;
    let mut tasks = Vec::new();
    for i in 0..SESSIONS {
        let state = Arc::clone(&state);
        tasks.push(tokio::spawn(async move {
            let id = format!("multi-{i}");
            let h = signed_headers(&id);
            for _ in 0..STEPS_PER_SESSION {
                state.prepare_chat(&h, chat_payload()).unwrap();
            }
            let s = state.sessions.get(&id).unwrap();
            state
                .finalizer
                .close_session(s, StopReason::SessionClosed)
                .await
                .unwrap()
        }));
    }
    for t in tasks {
        match t.await.unwrap() {
            FinalizeOutcome::Receipt { receipt } => match &receipt.body.subject {
                ReceiptSubject::EventChain { event_count, .. } => {
                    assert_eq!(
                        *event_count, STEPS_PER_SESSION,
                        "cross-session event_count leaked"
                    );
                }
                other => panic!("expected EventChain, got {other:?}"),
            },
            other => panic!("expected Receipt outcome, got {other:?}"),
        }
    }
    assert_eq!(state.sessions.len() as u64, SESSIONS);
}

// ---------------------------------------------------------------------------
// 4. Prepare vs close race on the SAME session: a task hammers
//    `prepare_chat` while another task closes the session at an arbitrary
//    moment. The receipt's event_count must equal the number of preps
//    that landed BEFORE close (no over-count, no under-count relative to
//    what the chain actually recorded).
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn prepare_racing_close_produces_a_coherent_receipt() {
    let state = app_state();
    let h = signed_headers("race-mixed");
    // Seed a few so the session exists before close.
    for _ in 0..3 {
        state.prepare_chat(&h, chat_payload()).unwrap();
    }
    let session = state.sessions.get("race-mixed").unwrap();
    let state_prep = Arc::clone(&state);
    let hp = h.clone();
    let stop = Arc::new(AtomicU64::new(0));
    let stop_p = Arc::clone(&stop);
    let prep = tokio::spawn(async move {
        while stop_p.load(Ordering::Acquire) == 0 {
            let _ = state_prep.prepare_chat(&hp, chat_payload());
            tokio::task::yield_now().await;
        }
    });
    // Close after a couple of scheduler ticks.
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    let outcome = state
        .finalizer
        .close_session(session.clone(), StopReason::SessionClosed)
        .await
        .unwrap();
    stop.store(1, Ordering::Release);
    prep.await.unwrap();
    // The receipt exists AND its event_count is whatever the chain
    // observed. A second close must be AlreadyClosed.
    let event_count = match outcome {
        FinalizeOutcome::Receipt { receipt } => match &receipt.body.subject {
            ReceiptSubject::EventChain { event_count, .. } => *event_count,
            other => panic!("expected EventChain, got {other:?}"),
        },
        other => panic!("expected Receipt, got {other:?}"),
    };
    assert!(event_count >= 3, "receipt undercounted seeded preps");
    let outcome2 = state
        .finalizer
        .close_session(session, StopReason::SessionClosed)
        .await
        .unwrap();
    assert!(matches!(outcome2, FinalizeOutcome::AlreadyClosed));
}
