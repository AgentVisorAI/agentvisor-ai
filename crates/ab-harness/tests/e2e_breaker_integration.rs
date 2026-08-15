//! Rambling-detector integration tests — the full harness pipeline.
//!
//! Wave 3 targets surfaces the unit tests (e2e_breaker.rs) cannot reach:
//!   - breaker wired through AppState::prepare_chat + reconciler close
//!   - custom HashEmbedder dimensions and their delta properties
//!   - NoopVectorSink + VectorSink trait contract
//!   - statistical delta distribution properties on the hash embedder
//!   - the Inject action's auto-reset via the harness pipeline

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

use ab_bridge::{BusError, EventBus, PublishAck, StoredEvent};
use ab_events::EventClass;
use ab_harness::{AppState, HarnessConfig};
use ab_loopdetect::{cosine, BreakerConfig, Embedder, HashEmbedder, NoopVectorSink, VectorSink};
use ab_receipts::Ed25519Signer;
use ab_sandbox::{Sandbox, SandboxConfig};
use ab_state::InMemoryStore;
use axum::http::{HeaderMap, HeaderValue};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Default delta_epsilon from BreakerConfig::default() — must match the source.
const EPSILON: f32 = 0.30;
/// Default HashEmbedder dimension.
const DEFAULT_DIM: usize = 512;
/// Separation margin between loop mean and progress mean in statistical tests.
const SEPARATION_MARGIN: f32 = 0.10;
/// Tolerance for cosine-symmetry floating-point comparisons.
const COS_TOL: f32 = 1e-5;
/// Tolerance for L2-norm unit-vector checks.
const NORM_TOL: f32 = 1e-4;

#[derive(Default)]
struct CountingBus(AtomicU64);
impl EventBus for CountingBus {
    fn publish(&self, topic: &str, _k: &str, _v: &Value) -> Result<PublishAck, BusError> {
        Ok(PublishAck {
            topic: topic.to_owned(),
            partition: 0,
            offset: self.0.fetch_add(1, Ordering::AcqRel),
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

fn app_with_breaker(cfg: BreakerConfig) -> Arc<AppState> {
    let dir = tempfile::tempdir().unwrap();
    let mut config = HarnessConfig::for_tests(
        "http://127.0.0.1:9",
        &dir.path().to_string_lossy(),
        &dir.path().to_string_lossy(),
    );
    config.breaker = cfg;
    std::mem::forget(dir);
    Arc::new(
        AppState::new(
            config,
            Arc::new(InMemoryStore::new()),
            Arc::new(Sandbox::new(SandboxConfig::default(), Vec::new()).unwrap()),
            Arc::new(CountingBus::default()),
            None,
            Arc::new(Ed25519Signer::from_seed(&[55; 32])),
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

fn chat(content: &str) -> Value {
    json!({"model": "m", "messages": [{"role": "user", "content": content}]})
}

// ---------------------------------------------------------------------------
// 1. After a breaker trip, prepare_chat must return a Blocked or Abort
//    error — the session must not be dispatched upstream.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pipeline_blocks_dispatch_when_breaker_is_open() {
    // Use a very low token floor so the breaker trips quickly.
    let state = app_with_breaker(BreakerConfig {
        min_tokens: 0,
        window: 2,
        delta_epsilon: EPSILON,
        action: ab_loopdetect::BreakerAction::Reject,
    });
    let h = signed_headers("breaker-block");
    let content = "I should check the inventory service for stock level of SKU 12345";
    // Feed 4 identical messages; the pipeline trip happens in the worker
    // AFTER the first response, but the NEXT prepare_chat after the session
    // is Open should be blocked. We simulate by directly manipulating the
    // session loop state.
    state.prepare_chat(&h, chat(content)).unwrap();
    let sess = state.sessions.get("breaker-block").unwrap();
    // Manually trip the breaker so the next prepare_chat sees Open state.
    let e = HashEmbedder::default();
    let embedding = e.embed(content);
    sess.loop_state.observe_embedding(embedding.clone(), 0);
    sess.loop_state.observe_embedding(embedding.clone(), 0);
    sess.loop_state.observe_embedding(embedding.clone(), 0); // streak 2 → Tripped
    assert_eq!(sess.loop_state.state(), ab_loopdetect::BreakerState::Open);
    // Next prepare_chat must be blocked.
    let result = state.prepare_chat(&h, chat("anything"));
    assert!(
        result.is_err(),
        "prepare_chat should be blocked when breaker is Open"
    );
}

// ---------------------------------------------------------------------------
// 2. Custom HashEmbedder dimensions produce L2-normalized vectors in all dims.
// ---------------------------------------------------------------------------

#[test]
fn custom_dim_hash_embedder_always_produces_unit_vectors() {
    for dim in [8, 16, 64, 128, 256, 512, 1024, 2048] {
        let e = HashEmbedder::new(dim);
        assert_eq!(e.dim(), dim);
        let v = e.embed("hello world");
        assert_eq!(v.len(), dim);
        let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!(
            (norm - 1.0).abs() < NORM_TOL || norm == 0.0,
            "dim={dim} norm={norm}"
        );
    }
}

// ---------------------------------------------------------------------------
// 3. Custom-dim embedder delta properties: same text → low delta, different
//    text → higher delta, regardless of dimension.
// ---------------------------------------------------------------------------

#[test]
fn custom_dim_embedder_preserves_delta_separation() {
    let same_a = "check the database for pending records";
    let same_b = "check the database for pending records";
    let diff = "entirely different topic about image classification algorithms";
    for dim in [32, 64, 256, 512] {
        let e = HashEmbedder::new(dim);
        let delta_same = 1.0 - cosine(&e.embed(same_a), &e.embed(same_b));
        let delta_diff = 1.0 - cosine(&e.embed(same_a), &e.embed(diff));
        assert!(
            delta_same < 0.01,
            "dim={dim} identical text delta {delta_same} too high"
        );
        assert!(
            delta_diff > EPSILON,
            "dim={dim} different text delta {delta_diff} below threshold"
        );
    }
}

// ---------------------------------------------------------------------------
// 4. HashEmbedder is deterministic across calls and across clones.
// ---------------------------------------------------------------------------

#[test]
fn hash_embedder_is_fully_deterministic() {
    let e1 = HashEmbedder::default();
    let e2 = e1.clone();
    let text = "some text for determinism check";
    assert_eq!(e1.embed(text), e2.embed(text));
    // Same instance, repeated calls.
    assert_eq!(e1.embed(text), e1.embed(text));
    // try_embed delegates to embed.
    assert_eq!(e1.try_embed(text).unwrap(), e1.embed(text));
}

// ---------------------------------------------------------------------------
// 5. NoopVectorSink satisfies the VectorSink contract: record succeeds and
//    nearest_similarity returns None (Noop has no memory).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn noop_vector_sink_satisfies_the_contract() {
    let sink = NoopVectorSink;
    // record must not fail.
    sink.record("sess", &[0.0f32; 512]).await.unwrap();
    sink.record("sess", &[1.0f32; 512]).await.unwrap();
    // nearest_similarity must return None (no stored vectors).
    let sim = sink.nearest_similarity("sess", &[1.0f32; 512]).await;
    assert!(sim.unwrap().is_none());
}

// ---------------------------------------------------------------------------
// 6. Statistical delta distribution: 50 paraphrase-loop steps must have
//    mean delta < epsilon; 15 genuinely progressing steps must have mean
//    delta > epsilon.
// ---------------------------------------------------------------------------

#[test]
fn statistical_delta_distribution_separates_loop_from_progress() {
    let e = HashEmbedder::default();
    let paraphrase_base = "retry the database query for the pending orders now";
    let paraphrase_variants: Vec<String> = (0..50_u32)
        .map(|i| format!("retry the database query for the pending orders now step{i}"))
        .collect();
    let mut base_vec = e.embed(paraphrase_base);
    let mut loop_deltas = Vec::with_capacity(50);
    for text in &paraphrase_variants {
        let v = e.embed(text);
        loop_deltas.push(1.0_f32 - cosine(&base_vec, &v));
        base_vec = v;
    }
    let progress_steps: &[&str] = &[
        "Parsed the user's CSV file: 12 columns detected, header row validated successfully",
        "Inferred column types from first 200 rows: 4 numeric, 6 text, 2 date fields",
        "Built the SQL migration script targeting the production schema v2.4",
        "Smoke-tested the migration on a staging clone; zero data-type conflicts found",
        "Applied migration to production; monitoring error rates and latency SLOs",
        "All SLOs green after migration; notifying the team via Slack and closing the ticket",
        "Writing the post-mortem document with root cause and remediation timeline",
        "Root cause analysis complete: schema drift introduced in PR #4721 by the infra team",
        "Retrospective scheduled for Thursday; action items assigned to the on-call rotation",
        "Archiving the incident report to Confluence and updating the runbook for future reference",
        "JWT authentication service upgraded to RS256; all service accounts re-signed",
        "Load test completed: p99 latency improved from 240 ms to 87 ms after cache warm-up",
        "Database index rebuild finished; query planner now prefers the composite index on (user_id, created_at)",
        "Feature flag 'new_checkout_flow' enabled for 10% of users in region us-east-1",
        "A/B test metrics: conversion +3.2%, bounce rate -1.8%; confidence interval 97%",
    ];
    let mut prev = e.embed("initial baseline for progress step comparison");
    let mut prog_deltas = Vec::with_capacity(progress_steps.len());
    for text in progress_steps {
        let v = e.embed(text);
        prog_deltas.push(1.0_f32 - cosine(&prev, &v));
        prev = v;
    }

    let loop_mean: f32 = loop_deltas.iter().sum::<f32>() / loop_deltas.len() as f32;
    let prog_mean: f32 = prog_deltas.iter().sum::<f32>() / prog_deltas.len() as f32;

    assert!(
        loop_mean < EPSILON,
        "loop mean delta {loop_mean:.3} should be below ε={EPSILON}"
    );
    assert!(
        prog_mean > EPSILON,
        "progress mean delta {prog_mean:.3} should be above ε={EPSILON}"
    );
    assert!(
        prog_mean > loop_mean + SEPARATION_MARGIN,
        "separation margin too small: loop={loop_mean:.3} prog={prog_mean:.3}"
    );
}

// ---------------------------------------------------------------------------
// 7. Cosine symmetry: cos(a, b) == cos(b, a) for all pairs.
// ---------------------------------------------------------------------------

#[test]
fn cosine_is_symmetric() {
    let e = HashEmbedder::default();
    let long_a = "x".repeat(200);
    let long_b = "y".repeat(200);
    let all_pairs: &[(&str, &str)] = &[
        ("hello world", "retry the database query"),
        ("", "something"),
        (long_a.as_str(), long_b.as_str()),
    ];
    for (a, b) in all_pairs {
        let va = e.embed(a);
        let vb = e.embed(b);
        let ab = cosine(&va, &vb);
        let ba = cosine(&vb, &va);
        assert!(
            (ab - ba).abs() < COS_TOL,
            "cosine not symmetric: cos(a,b)={ab} cos(b,a)={ba}"
        );
    }
}

// ---------------------------------------------------------------------------
// 8. Breaker action carries through the session state: when Inject is
//    configured, the pipeline injects a corrective message and resets the
//    breaker automatically rather than blocking the request.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pipeline_auto_resets_breaker_on_inject_action() {
    let state = app_with_breaker(BreakerConfig {
        min_tokens: 0,
        window: 2,
        delta_epsilon: EPSILON,
        action: ab_loopdetect::BreakerAction::Inject,
    });
    let h = signed_headers("inject-sess");
    let content = "same loop step again";
    state.prepare_chat(&h, chat(content)).unwrap();
    let sess = state.sessions.get("inject-sess").unwrap();
    let e = HashEmbedder::default();
    let embedding = e.embed(content);
    sess.loop_state.observe_embedding(embedding.clone(), 0);
    sess.loop_state.observe_embedding(embedding.clone(), 0);
    sess.loop_state.observe_embedding(embedding.clone(), 0); // Open
    assert_eq!(sess.loop_state.state(), ab_loopdetect::BreakerState::Open);
    // The harness pipeline should inject a corrective message and reset,
    // so prepare_chat succeeds (returns Ok) rather than blocking.
    let result = state.prepare_chat(&h, chat("fresh request after correction"));
    assert!(
        result.is_ok(),
        "Inject action should reset and allow the next request"
    );
    assert_eq!(
        sess.loop_state.state(),
        ab_loopdetect::BreakerState::Closed,
        "breaker must be Closed after Inject auto-reset"
    );
}

// ---------------------------------------------------------------------------
// 9. try_embed is infallible for the hash embedder on any UTF-8 input.
// ---------------------------------------------------------------------------

#[test]
fn try_embed_is_infallible_for_the_hash_embedder() {
    let e = HashEmbedder::default();
    let big = "a".repeat(1_000_000);
    let cases: &[&str] = &["", "hello", "\u{feff}", "🎉🚀𝓗", big.as_str()];
    for text in cases {
        assert!(e.try_embed(text).is_ok(), "try_embed failed on {text:?}");
    }
}

// ---------------------------------------------------------------------------
// 10. VectorSearchFuture / nearest_similarity on NoopVectorSink is async-safe
//     when polled on a multi-thread runtime.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn noop_vector_sink_nearest_similarity_is_async_safe() {
    let sink = Arc::new(NoopVectorSink);
    let mut tasks = Vec::new();
    for i in 0..16 {
        let sink = Arc::clone(&sink);
        tasks.push(tokio::spawn(async move {
            let v: Vec<f32> = (0..DEFAULT_DIM).map(|j| (i * DEFAULT_DIM + j) as f32).collect();
            sink.record("sess", &v).await.unwrap();
            let sim = sink.nearest_similarity("sess", &v).await.unwrap();
            assert!(sim.is_none()); // Noop never stores
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
}
