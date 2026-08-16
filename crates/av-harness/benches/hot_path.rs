//! Criterion benchmarks for AgentVisor AI hot-path operations.
#![allow(missing_docs, clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use av_bridge::{BusError, EventBus, PublishAck, StoredEvent};
use av_events::{AgentIdentity, EventClass, EventMetrics, StatusId, StopReason};
use av_harness::session::{Session, Workflow};
use av_harness::worker::WorkerJob;
use av_harness::{AppState, HarnessConfig};
use av_receipts::{Ed25519Signer, Receipt, ReceiptSubject};
use av_sandbox::{Sandbox, SandboxConfig};
use av_state::InMemoryStore;
use axum::http::{HeaderMap, HeaderValue};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use serde_json::{json, Value};
use std::sync::Arc;

struct NullBus;

impl EventBus for NullBus {
    fn publish(&self, topic: &str, _key: &str, _value: &Value) -> Result<PublishAck, BusError> {
        Ok(PublishAck {
            topic: topic.to_owned(),
            partition: 0,
            offset: 0,
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

fn benchmark(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let _guard = runtime.enter();
    let directory = tempfile::tempdir().unwrap();
    let mut config = HarnessConfig::for_tests(
        "http://127.0.0.1:9",
        &directory.path().to_string_lossy(),
        &directory.path().to_string_lossy(),
    );
    config.worker_channel_capacity = 100_000;
    let sandbox = Arc::new(Sandbox::new(SandboxConfig::default(), Vec::new()).unwrap());
    let state = AppState::new(
        config,
        Arc::new(InMemoryStore::new()),
        Arc::clone(&sandbox),
        Arc::new(NullBus),
        None,
        Arc::new(Ed25519Signer::from_seed(&[31; 32])),
    )
    .unwrap();
    let mut headers = HeaderMap::new();
    headers.insert("x-av-session", HeaderValue::from_static("bench-session"));
    headers.insert("x-av-workflow", HeaderValue::from_static("signed"));
    let payload = json!({
        "model": "bench",
        "messages": [{"role": "user", "content": "benchmark middleware"}],
    });

    c.bench_function("hot_path_prepare", |bench| {
        bench.iter(|| {
            black_box(
                state
                    .prepare_chat(&headers, payload.clone())
                    .unwrap()
                    .middleware_us,
            )
        });
    });

    c.bench_function("worker_try_submit", |bench| {
        let session = Arc::new(Session::new(
            "enqueue-bench".to_owned(),
            Workflow::Signed,
            AgentIdentity {
                version: "1".to_owned(),
                charter: "bench".into(),
                instance_uid: "bench-instance".to_owned(),
                ttl_remaining_s: Some(600),
            },
            Default::default(),
        ));
        bench.iter(|| {
            black_box(state.worker.try_submit(WorkerJob {
                session: Arc::clone(&session),
                identity: session.current_identity(),
                class: EventClass::Session,
                payload: json!({}),
                text: "bench".to_owned(),
                analyze_loop: false,
                status: StatusId::Success,
                stop_reason: None,
                native_stop_reason: None,
                metrics: EventMetrics::default(),
                cost_usd_micros: 0,
                atif: None,
                response_marker: None,
                response_attempt: None,
            }))
        });
    });

    c.bench_function("mcp_block", |bench| {
        let store = InMemoryStore::new();
        bench.iter(|| black_box(sandbox.check(&store, "bench", b"not-json").elapsed_us()));
    });

    c.bench_function("receipt_sign", |bench| {
        let signer = Ed25519Signer::from_seed(&[32; 32]);
        let identity = AgentIdentity {
            version: "1".to_owned(),
            charter: "bench".into(),
            instance_uid: "bench-instance".to_owned(),
            ttl_remaining_s: Some(600),
        };
        bench.iter(|| {
            let body = av_receipts::receipt::new_body(
                "receipt-bench".to_owned(),
                identity.clone(),
                ReceiptSubject::EventChain {
                    chain_head: "0".repeat(64),
                    event_count: 1,
                },
                Default::default(),
                Default::default(),
                StopReason::SessionClosed,
            );
            black_box(Receipt::issue(body, &signer).unwrap())
        });
    });
}

criterion_group!(benches, benchmark);
criterion_main!(benches);
