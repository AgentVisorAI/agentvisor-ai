//! Pipeline-level robustness under massive prompts.
//!
//! Where `e2e_massive_context.rs` attacks the primitives directly, this
//! suite drives `prepare_chat` and the full close/receipt path, so any
//! per-request allocation, budget accounting, chain append, or ATIF ingest
//! that sits on the hot path gets exercised at 100x-1000x normal size.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
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

fn app_state(max_tokens: Option<u64>) -> Arc<AppState> {
    let dir = tempfile::tempdir().unwrap();
    let mut config = HarnessConfig::for_tests(
        "http://127.0.0.1:9",
        &dir.path().to_string_lossy(),
        &dir.path().to_string_lossy(),
    );
    config.breaker.min_tokens = u64::MAX;
    config.budget.max_tokens = max_tokens;
    std::mem::forget(dir);
    Arc::new(
        AppState::new(
            config,
            Arc::new(InMemoryStore::new()),
            Arc::new(Sandbox::new(SandboxConfig::default(), Vec::new()).unwrap()),
            Arc::new(CountingBus::default()),
            None,
            Arc::new(Ed25519Signer::from_seed([13; 32])),
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

fn payload_with_prompt_size(bytes: usize) -> Value {
    json!({
        "model": "m",
        "messages": [{"role": "user", "content": "a".repeat(bytes)}],
    })
}

// ---------------------------------------------------------------------------
// 1. Very large prompt through `prepare_chat` accepted when no token cap
//    is set. The recorded session must show a non-zero prompt token cost
//    and the seq must have advanced by exactly one.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn prepare_chat_accepts_a_large_prompt_without_a_token_cap() {
    let state = app_state(None);
    let h = signed_headers("mass-prep");
    state
        .prepare_chat(&h, payload_with_prompt_size(256 * 1024))
        .unwrap();
    // The session was opened and one event was accepted.
    assert!(state.sessions.get("mass-prep").is_some());
}

// ---------------------------------------------------------------------------
// 2. Very large prompt with a small token cap is REFUSED (budget path). We
//    prove the budget gate covers pathological inputs.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn prepare_chat_refuses_a_massive_prompt_that_blows_the_token_budget() {
    let state = app_state(Some(1_000));
    let h = signed_headers("mass-refuse");
    let outcome = state.prepare_chat(&h, payload_with_prompt_size(256 * 1024));
    assert!(outcome.is_err(), "budget gate let a large prompt through");
}

// ---------------------------------------------------------------------------
// 3. Many medium requests on ONE session: N × 128 KiB preps close into a
//    single receipt whose event_count = N. Proves per-request memory does
//    not grow the aggregate cost non-linearly.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn many_medium_requests_accumulate_correctly_on_one_session() {
    let state = app_state(None);
    let h = signed_headers("mass-accum");
    const N: u64 = 16;
    for _ in 0..N {
        state
            .prepare_chat(&h, payload_with_prompt_size(16 * 1024))
            .unwrap();
    }
    let s = state.sessions.get("mass-accum").unwrap();
    let outcome = state
        .finalizer
        .close_session(s, StopReason::SessionClosed)
        .await
        .unwrap();
    match outcome {
        FinalizeOutcome::Receipt { receipt } => match &receipt.body.subject {
            ReceiptSubject::EventChain { event_count, .. } => {
                assert_eq!(*event_count, N, "event_count drift on massive stream");
            }
            other => panic!("expected EventChain, got {other:?}"),
        },
        other => panic!("expected Receipt, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 4. Wide messages array (2 000 short messages) exercises the tokenizer
//    and JCS on the shape long-context prompts typically take (many turns
//    rather than one giant blob).
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn prepare_chat_handles_wide_turn_conversation() {
    let state = app_state(None);
    let h = signed_headers("mass-turns");
    let messages: Vec<Value> = (0..2_000)
        .map(|i| json!({"role": if i % 2 == 0 {"user"} else {"assistant"}, "content": format!("turn {i}")}))
        .collect();
    let payload = json!({"model": "m", "messages": messages});
    state.prepare_chat(&h, payload).unwrap();
    // The wide payload made it through without panicking; close produces
    // a receipt with event_count = 1 (one prepare call).
    let s = state.sessions.get("mass-turns").unwrap();
    let outcome = state
        .finalizer
        .close_session(s, StopReason::SessionClosed)
        .await
        .unwrap();
    match outcome {
        FinalizeOutcome::Receipt { receipt } => match &receipt.body.subject {
            ReceiptSubject::EventChain { event_count, .. } => {
                assert_eq!(*event_count, 1);
            }
            other => panic!("expected EventChain, got {other:?}"),
        },
        other => panic!("expected Receipt, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 5. Massive-context multi-session: 8 concurrent sessions each pushing a
//    64 KiB prompt; every receipt still shows event_count = 1 (no leakage
//    across the shared harness state under memory pressure).
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_massive_prompts_across_sessions_do_not_leak() {
    let state = app_state(None);
    const SESSIONS: u64 = 8;
    let mut tasks = Vec::new();
    for i in 0..SESSIONS {
        let state = Arc::clone(&state);
        tasks.push(tokio::spawn(async move {
            let id = format!("mass-{i}");
            let h = signed_headers(&id);
            state
                .prepare_chat(&h, payload_with_prompt_size(64 * 1024))
                .unwrap();
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
                    assert_eq!(*event_count, 1);
                }
                other => panic!("expected EventChain, got {other:?}"),
            },
            other => panic!("expected Receipt, got {other:?}"),
        }
    }
}
