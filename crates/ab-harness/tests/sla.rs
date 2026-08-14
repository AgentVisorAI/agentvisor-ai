//! Release-mode MVP SLA gates. Run with `make sla`.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use ab_bridge::{BridgeManifest, BusError, EmbeddedBroker, EventBus, PublishAck, StoredEvent};
use ab_events::{AgentIdentity, EventClass, EventMetrics, StatusId, StopReason};
use ab_harness::reconciler::Finalizer;
use ab_harness::session::{Session, Workflow};
use ab_harness::worker::WorkerJob;
use ab_harness::{build_router, AppState, HarnessConfig};
use ab_receipts::{Ed25519Signer, Receipt, ReceiptSubject};
use ab_sandbox::{PolicyEngine, Sandbox, SandboxConfig, WasmPolicy};
use ab_state::InMemoryStore;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, Request};
use axum::response::Response;
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tower::ServiceExt as _;

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

fn production_sandbox() -> Sandbox {
    let mut schemas = std::collections::HashMap::new();
    schemas.insert(
        "db_write".to_owned(),
        serde_json::from_str(include_str!("../../../config/tool-schemas/db_write.json")).unwrap(),
    );
    let policies: Vec<Box<dyn PolicyEngine>> = vec![Box::new(
        WasmPolicy::from_bytes(
            "payload_limit",
            include_bytes!("../../../config/policies/payload_limit.wat"),
        )
        .unwrap(),
    )];
    Sandbox::new(
        SandboxConfig {
            schemas,
            budget: Default::default(),
            payout_field: "amount_usd".to_owned(),
            require_schema: true,
        },
        policies,
    )
    .unwrap()
}

fn state(upstream: &str, spool: &std::path::Path, capacity: usize, real_bridge: bool) -> AppState {
    let mut config = HarnessConfig::for_tests(upstream, &spool.to_string_lossy(), "/tmp");
    config.worker_channel_capacity = capacity;
    config.upstream_http2_prior_knowledge = true;
    let manifest = BridgeManifest::default_for("sla-runtime");
    let bridge: Arc<dyn EventBus> = if real_bridge {
        #[cfg(feature = "kafka")]
        if let Ok(broker) = std::env::var("AB_KAFKA_BROKER") {
            Arc::new(tokio::task::block_in_place(|| {
                ab_bridge::kafka_bus::KafkaBus::provision(&broker, &manifest).unwrap()
            }))
        } else {
            Arc::new(EmbeddedBroker::provision(&spool.join("bridge"), &manifest).unwrap())
        }
        #[cfg(not(feature = "kafka"))]
        {
            Arc::new(EmbeddedBroker::provision(&spool.join("bridge"), &manifest).unwrap())
        }
    } else {
        Arc::new(NullBus)
    };
    let store: Arc<dyn ab_state::StateStore> = {
        #[cfg(feature = "redis")]
        if let Ok(url) = std::env::var("AB_REDIS_URL") {
            Arc::new(ab_state::redis_store::RedisStore::connect(&url).unwrap())
        } else {
            Arc::new(InMemoryStore::new())
        }
        #[cfg(not(feature = "redis"))]
        {
            Arc::new(InMemoryStore::new())
        }
    };
    AppState::new(
        config,
        store,
        Arc::new(production_sandbox()),
        bridge,
        None,
        Arc::new(Ed25519Signer::from_seed([21; 32])),
    )
    .unwrap()
}

fn identity() -> AgentIdentity {
    AgentIdentity {
        version: "1".to_owned(),
        charter: "sla".into(),
        instance_uid: "sla-instance".to_owned(),
        ttl_remaining_s: Some(600),
    }
}

fn percentile(values: &mut [u64], quantile: usize) -> u64 {
    values.sort_unstable();
    let rank = values.len().saturating_mul(quantile).saturating_add(99) / 100;
    values.get(rank.saturating_sub(1)).copied().unwrap_or(0)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "release SLA measurement"]
async fn sla_core_metrics() {
    let directory = tempfile::tempdir().unwrap();
    let state = state("http://127.0.0.1:9", directory.path(), 20_000, true);
    let payload = json!({
        "model": "sla",
        "messages": [{"role": "user", "content": "measure middleware"}],
    });
    let mut hot_path = Vec::with_capacity(2_000);
    for index in 0..2_000 {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-ab-session",
            HeaderValue::from_str(&format!("sla-{index}")).unwrap(),
        );
        headers.insert("x-ab-workflow", HeaderValue::from_static("signed"));
        let started = Instant::now();
        state
            .prepare_chat_nonblocking(&headers, payload.clone())
            .await
            .unwrap();
        hot_path.push(u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX));
    }
    let hot_p95 = percentile(&mut hot_path.clone(), 95);
    let hot_p99 = percentile(&mut hot_path, 99);
    assert!(hot_p95 <= 5_000, "hot-path p95 {hot_p95}us exceeds 5000us");
    assert!(hot_p99 <= 8_000, "hot-path p99 {hot_p99}us exceeds 8000us");
    state.worker.wait_idle().await;

    let mut durable_admission = Vec::with_capacity(200);
    for index in 0..200 {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-ab-session",
            HeaderValue::from_str(&format!("durable-sla-{index}")).unwrap(),
        );
        headers.insert("x-ab-workflow", HeaderValue::from_static("signed"));
        let started = Instant::now();
        state
            .prepare_chat_durable(&headers, payload.clone())
            .await
            .unwrap();
        durable_admission.push(u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX));
    }
    let durable_p95 = percentile(&mut durable_admission.clone(), 95);
    let durable_p99 = percentile(&mut durable_admission, 99);
    let session = Arc::new(Session::new(
        "enqueue-sla".to_owned(),
        Workflow::Signed,
        identity(),
        Default::default(),
    ));
    let mut enqueue = Vec::with_capacity(2_000);
    for _ in 0..2_000 {
        let started = Instant::now();
        let _ = state.worker.try_submit(WorkerJob {
            session: Arc::clone(&session),
            class: EventClass::Session,
            identity: session.current_identity(),
            payload: json!({"sla": true}),
            text: "enqueue".to_owned(),
            analyze_loop: false,
            status: StatusId::Success,
            stop_reason: None,
            native_stop_reason: None,
            metrics: EventMetrics::default(),
            cost_usd_micros: 0,
            atif: None,
            response_marker: None,
            response_attempt: None,
        });
        enqueue.push(u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX));
    }
    let enqueue_p99 = percentile(&mut enqueue, 99);
    assert!(enqueue_p99 <= 500, "enqueue p99 {enqueue_p99}us exceeds 500us");

    let app = build_router(state.clone());
    let mut blocked = Vec::with_capacity(1_000);
    let invalid_call = serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "db_write", "arguments": {"table": 42, "row": {}}}
    }))
    .unwrap();
    for index in 0..1_000 {
        let started = Instant::now();
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/mcp")
                    .header("x-ab-session", format!("mcp-sla-{index}"))
                    .body(Body::from(invalid_call.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
        blocked.push(u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX));
    }
    let block_p99 = percentile(&mut blocked, 99);
    assert!(block_p99 < 5_000, "MCP block p99 {block_p99}us exceeds 5000us");
    state.worker.wait_idle().await;

    let signer = Arc::new(Ed25519Signer::from_seed([22; 32]));
    let metrics = Arc::new(ab_core::metrics::Registry::new());
    let finalizer = Finalizer::new(signer.clone(), directory.path().to_path_buf(), metrics.clone());
    for index in 0..200 {
        let session = Arc::new(Session::new(
            format!("sign-{index}"),
            Workflow::Signed,
            identity(),
            Default::default(),
        ));
        finalizer
            .close_session(session, StopReason::SessionClosed)
            .await
            .unwrap();
    }
    let sign_p99 = metrics
        .histogram("ab_receipt_sign_duration_seconds", "Receipt signing latency")
        .quantile_us(0.99);
    assert!(sign_p99 < 2_000, "receipt sign p99 {sign_p99}us exceeds 2000us");

    let unsigned = Arc::new(Session::new(
        "promotion-sla".to_owned(),
        Workflow::Unsigned,
        identity(),
        Default::default(),
    ));
    unsigned
        .atif
        .lock()
        .push_step(ab_atif::Step {
            step_id: 0,
            timestamp: Some(ab_core::time::now_iso8601()),
            source: ab_atif::Source::Agent,
            message: json!("promotion"),
            reasoning_effort: None,
            reasoning_content: None,
            model_name: None,
            tool_calls: None,
            observation: None,
            metrics: Some(ab_atif::Metrics {
                prompt_tokens: Some(10),
                completion_tokens: Some(2),
                cached_tokens: Some(4),
                cost_usd: Some(0.0),
                logprobs: None,
                completion_token_ids: None,
                prompt_token_ids: None,
                extra: None,
            }),
            is_copied_context: None,
            llm_call_count: Some(1),
            extra: None,
        })
        .unwrap();
    finalizer
        .close_session(Arc::clone(&unsigned), StopReason::SessionClosed)
        .await
        .unwrap();
    let promotion_started = Instant::now();
    finalizer
        .promote(unsigned)
        .await
        .unwrap()
        .verify_embedded()
        .unwrap();
    let promotion_ms = promotion_started.elapsed().as_millis();
    assert!(promotion_ms < 60_000, "promotion took {promotion_ms}ms");

    let manifest_dir = tempfile::tempdir().unwrap();
    let provision_started = Instant::now();
    let bridge = EmbeddedBroker::provision(
        manifest_dir.path(),
        &BridgeManifest::default_for("sla-portability"),
    )
    .unwrap();
    assert_eq!(bridge.topics().len(), EventClass::all().len());
    assert!(provision_started.elapsed() < Duration::from_secs(15 * 60));

    let receipt_body = ab_receipts::receipt::new_body(
        "offline".to_owned(),
        identity(),
        ReceiptSubject::EventChain {
            chain_head: "0".repeat(64),
            event_count: 0,
        },
        Default::default(),
        Default::default(),
        StopReason::SessionClosed,
    );
    Receipt::issue(receipt_body, signer.as_ref())
        .unwrap()
        .verify_embedded()
        .unwrap();

    println!(
        "SLA hot_p95_us={hot_p95} hot_p99_us={hot_p99} durable_p95_us={durable_p95} durable_p99_us={durable_p99} enqueue_p99_us={enqueue_p99} mcp_block_p99_us={block_p99} receipt_sign_p99_us={sign_p99} promotion_ms={promotion_ms} provision_ms={}",
        provision_started.elapsed().as_millis()
    );
}

#[derive(Clone)]
struct HoldState {
    arrived: Arc<AtomicUsize>,
    release: tokio::sync::watch::Receiver<bool>,
}

async fn held_provider(State(mut state): State<HoldState>, Json(_): Json<Value>) -> Response {
    state.arrived.fetch_add(1, Ordering::AcqRel);
    while !*state.release.borrow() {
        if state.release.changed().await.is_err() {
            break;
        }
    }
    Response::new(Body::from("{\"choices\":[]}"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 12)]
#[ignore = "requires RUN_HEAVY_PERF=1 and a high file-descriptor limit"]
async fn sla_10k_streaming_connections() {
    if std::env::var("RUN_HEAVY_PERF").as_deref() != Ok("1") {
        eprintln!("SKIPPED (set RUN_HEAVY_PERF=1)");
        return;
    }
    let connections = std::env::var("AB_SLA_CONNECTIONS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(10_000);
    assert!(
        connections >= 10_000,
        "10k SLA gate cannot run with fewer than 10,000 connections"
    );
    let arrival_timeout = Duration::from_secs(
        std::env::var("AB_SLA_ARRIVAL_TIMEOUT_S")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(900),
    );
    let (release_tx, release_rx) = tokio::sync::watch::channel(false);
    let arrived = Arc::new(AtomicUsize::new(0));
    let provider_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let provider_address = provider_listener.local_addr().unwrap();
    let provider = Router::new()
        .route("/v1/chat/completions", post(held_provider))
        .with_state(HoldState {
            arrived: Arc::clone(&arrived),
            release: release_rx.clone(),
        });
    let provider_task = tokio::spawn(async move {
        loop {
            let (socket, _) = provider_listener.accept().await.unwrap();
            let service = hyper_util::service::TowerToHyperService::new(provider.clone());
            tokio::spawn(async move {
                hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
                    .max_concurrent_streams(20_000)
                    .serve_connection(hyper_util::rt::TokioIo::new(socket), service)
                    .await
                    .unwrap();
            });
        }
    });

    let directory = tempfile::tempdir().unwrap();
    let state = state(
        &format!("http://{provider_address}"),
        directory.path(),
        32_768,
        true,
    );
    let harness_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let harness_address = harness_listener.local_addr().unwrap();
    let harness_task = tokio::spawn(async move {
        axum::serve(harness_listener, build_router(state)).await.unwrap();
    });

    let body = r#"{"model":"sla","stream":true,"messages":[{"role":"user","content":"hold"}]}"#;
    let started = Instant::now();
    let mut clients = Vec::with_capacity(connections);
    let connect_limit = Arc::new(tokio::sync::Semaphore::new(256));
    for index in 0..connections {
        let mut release = release_rx.clone();
        let connect_limit = Arc::clone(&connect_limit);
        let request = format!(
            "POST /v1/chat/completions HTTP/1.1\r\nHost: {harness_address}\r\nContent-Type: application/json\r\nX-AB-Session: network-{index}\r\nX-AB-Workflow: signed\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        clients.push(tokio::spawn(async move {
            let permit = connect_limit
                .acquire_owned()
                .await
                .map_err(std::io::Error::other)?;
            let mut socket = tokio::net::TcpStream::connect(harness_address).await?;
            socket.write_all(request.as_bytes()).await?;
            drop(permit);
            while !*release.borrow() {
                release.changed().await.map_err(std::io::Error::other)?;
            }
            let mut response = Vec::new();
            socket.read_to_end(&mut response).await?;
            Ok::<_, std::io::Error>(response)
        }));
    }

    tokio::time::timeout(arrival_timeout, async {
        let mut reported_thousands = 0usize;
        while arrived.load(Ordering::Acquire) < connections {
            let current = arrived.load(Ordering::Acquire);
            let thousands = current / 1_000;
            if thousands > reported_thousands {
                reported_thousands = thousands;
                println!("SLA ramp arrived={current}/{connections}");
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "only {} of {connections} connections reached the provider",
            arrived.load(Ordering::Acquire)
        )
    });
    assert_eq!(arrived.load(Ordering::Acquire), connections);
    release_tx.send(true).unwrap();
    let mut middleware_latencies = Vec::with_capacity(connections);
    for client in clients {
        let response = client.await.unwrap().unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200"));
        let headers = std::str::from_utf8(&response).unwrap();
        let middleware_us = headers
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("x-ab-middleware-us:")
                    .and_then(|value| value.trim().parse::<u64>().ok())
            })
            .expect("middleware latency header missing");
        middleware_latencies.push(middleware_us);
    }
    let p95_us = percentile(&mut middleware_latencies.clone(), 95);
    let p99_us = percentile(&mut middleware_latencies, 99);
    assert!(p95_us <= 5_000, "10k-load p95 {p95_us}us exceeds 5000us");
    assert!(p99_us <= 8_000, "10k-load p99 {p99_us}us exceeds 8000us");
    println!(
        "SLA concurrent_connections={connections} completed_ms={} p95_us={p95_us} p99_us={p99_us}",
        started.elapsed().as_millis()
    );
    harness_task.abort();
    provider_task.abort();
}
