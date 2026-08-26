//! Cross-crate adversarial concurrency and fidelity tests.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use av_receipts::ReceiptSubject;
use av_sandbox::{Sandbox, SandboxConfig};
use axum::http::{HeaderMap, HeaderValue};
use serde_json::json;
use std::sync::atomic::Ordering;
use std::sync::Arc;

mod common;
use common::CountingBus;

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn sixty_four_agents_preserve_all_signed_steps_under_contention() {
    const AGENTS: usize = 64;
    const STEPS: usize = 100;

    let mut config = common::leaked_test_config();
    config.worker_channel_capacity = AGENTS * STEPS * 2;
    config.breaker.min_tokens = u64::MAX;
    let bus = Arc::new(CountingBus::default());
    let state = common::app_state(
        config,
        Sandbox::new(SandboxConfig::default(), Vec::new()).unwrap(),
        bus.clone(),
        41,
    );

    let mut agents = Vec::new();
    for agent in 0..AGENTS {
        let state = Arc::clone(&state);
        agents.push(tokio::spawn(async move {
            let session_id = format!("adversarial-{agent}");
            let mut headers = HeaderMap::new();
            headers.insert("x-av-session", HeaderValue::from_str(&session_id).unwrap());
            headers.insert("x-av-workflow", HeaderValue::from_static("signed"));
            for step in 0..STEPS {
                let prepared = state
                    .prepare_chat(
                        &headers,
                        json!({
                            "model": "adversarial",
                            "messages": [{
                                "role": "user",
                                "content": format!("agent {agent} distinct step {step}")
                            }]
                        }),
                        None,
                    )
                    .unwrap();
                // Dropping without forwarding models a client disconnect:
                // the capture guard resolves the journalled attempt with a
                // terminal failure event, so every step contributes TWO
                // chain events (admission + resolution).
                drop(prepared);
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
            .close_session(session, av_events::StopReason::SessionClosed)
            .await
            .unwrap()
        {
            av_harness::reconciler::FinalizeOutcome::Receipt { receipt } => receipt,
            other => panic!("unexpected finalization outcome: {other:?}"),
        };
        receipt.verify_embedded().unwrap();
        match &receipt.body.subject {
            ReceiptSubject::EventChain { event_count, .. } => {
                // Admission + guard-resolution event per step (see the
                // drop comment above).
                assert_eq!(*event_count, (STEPS * 2) as u64);
            }
            other => panic!("unexpected receipt subject: {other:?}"),
        }
    }

    assert_eq!(
        bus.published.load(Ordering::Acquire),
        (AGENTS * STEPS * 2 + AGENTS * 2) as u64,
        "every action, its capture-guard resolution, session close, and issued receipt must emit an event"
    );
    let metrics = state.metrics.render();
    assert!(metrics.contains("av_events_dropped_total{stage=\"worker_queue\"} 0"));
}
