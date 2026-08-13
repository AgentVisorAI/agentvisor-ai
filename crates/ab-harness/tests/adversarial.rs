//! Cross-crate adversarial concurrency and fidelity tests.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use ab_bridge::{BusError, EventBus, PublishAck, StoredEvent};
use ab_events::EventClass;
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
    fn publish(&self, topic: &str, _key: &str, _value: &Value) -> Result<PublishAck, BusError> {
        let offset = self.published.fetch_add(1, Ordering::AcqRel);
        Ok(PublishAck {
            topic: topic.to_owned(),
            partition: 0,
            offset,
        })
    }

    fn fetch(
        &self,
        _topic: &str,
        _partition: u32,
        _offset: u64,
        _max: usize,
    ) -> Result<Vec<StoredEvent>, BusError> {
        Ok(Vec::new())
    }

    fn partitions(&self, _topic: &str) -> Result<u32, BusError> {
        Ok(1)
    }

    fn topics(&self) -> Vec<String> {
        EventClass::all()
            .iter()
            .map(|class| class.topic().to_owned())
            .collect()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn sixty_four_agents_preserve_all_signed_steps_under_contention() {
    const AGENTS: usize = 64;
    const STEPS: usize = 100;

    let directory = tempfile::tempdir().unwrap();
    let mut config = HarnessConfig::for_tests(
        "http://127.0.0.1:9",
        &directory.path().to_string_lossy(),
        &directory.path().to_string_lossy(),
    );
    config.worker_channel_capacity = AGENTS * STEPS * 2;
    config.breaker.min_tokens = u64::MAX;
    let bus = Arc::new(CountingBus::default());
    let state = Arc::new(
        AppState::new(
            config,
            Arc::new(InMemoryStore::new()),
            Arc::new(Sandbox::new(SandboxConfig::default(), Vec::new()).unwrap()),
            bus.clone(),
            None,
            Arc::new(Ed25519Signer::from_seed([41; 32])),
        )
        .unwrap(),
    );

    let mut agents = Vec::new();
    for agent in 0..AGENTS {
        let state = Arc::clone(&state);
        agents.push(tokio::spawn(async move {
            let session_id = format!("adversarial-{agent}");
            let mut headers = HeaderMap::new();
            headers.insert("x-ab-session", HeaderValue::from_str(&session_id).unwrap());
            headers.insert("x-ab-workflow", HeaderValue::from_static("signed"));
            for step in 0..STEPS {
                state
                    .prepare_chat(
                        &headers,
                        json!({
                            "model": "adversarial",
                            "messages": [{
                                "role": "user",
                                "content": format!("agent {agent} distinct step {step}")
                            }]
                        }),
                    )
                    .unwrap();
            }
            session_id
        }));
    }

    let mut session_ids = Vec::new();
    for agent in agents {
        session_ids.push(agent.await.unwrap());
    }
    for session_id in session_ids {
        let session = state.sessions.get(&session_id).unwrap();
        let receipt = match state
            .finalizer
            .close_session(session, ab_events::StopReason::SessionClosed)
            .await
            .unwrap()
        {
            ab_harness::reconciler::FinalizeOutcome::Receipt { receipt } => receipt,
            other => panic!("unexpected finalization outcome: {other:?}"),
        };
        receipt.verify_embedded().unwrap();
        match &receipt.body.subject {
            ReceiptSubject::EventChain { event_count, .. } => {
                assert_eq!(*event_count, STEPS as u64);
            }
            other => panic!("unexpected receipt subject: {other:?}"),
        }
    }

    assert_eq!(
        bus.published.load(Ordering::Acquire),
        (AGENTS * STEPS + AGENTS * 2) as u64,
        "every action, session close, and issued receipt must emit an event"
    );
    let metrics = state.metrics.render();
    assert!(metrics.contains("ab_events_dropped_total{stage=\"worker_queue\"} 0"));
}
