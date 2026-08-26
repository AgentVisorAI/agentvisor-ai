//! Multi-feature edge cases: scenarios where two or more subsystems must
//! interact correctly. A bug in the interaction is invisible when each
//! feature is tested individually.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

use av_bridge::{BridgeManifest, EmbeddedBroker, EventBus};
use av_events::{AgentIdentity, CharterFile};
use av_harness::pipeline::PipelineError;
use av_harness::AppState;
use av_receipts::{
    CostSummary, Ed25519Signer, Keyring, Receipt, ReceiptBody, ReceiptSubject, Signer, ToolCallSummary,
};
use av_sandbox::{NativePolicy, PolicyDecision, PolicyEngine, Sandbox, SandboxConfig, ToolVerdict};
use av_state::{ActionBudget, BudgetDecision, BudgetSpec, InMemoryStore};
use axum::http::HeaderValue;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

mod common;
use common::{chat_payload, signed_headers, tools_call};

// ------------------------------------------------------------------
// Test scaffolding.
// ------------------------------------------------------------------

fn state_with(sandbox: Sandbox, budget: BudgetSpec) -> Arc<AppState> {
    let mut config = common::leaked_test_config();
    config.breaker.min_tokens = u64::MAX;
    config.budget = budget;
    common::app_state(config, sandbox, Arc::new(common::CountingBus::default()), 9)
}

// ------------------------------------------------------------------
// 1. Session binding: cross-workflow rejection (an open session refuses a
//    workflow flip; identity cannot be swapped by headers — see
//    e2e_adversarial_mcp's hijack test for that half).
// ------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn session_binding_refuses_workflow_change_after_open() {
    let state = state_with(
        Sandbox::new(SandboxConfig::default(), Vec::new()).unwrap(),
        BudgetSpec::default(),
    );
    // Open with signed workflow.
    let signed = signed_headers("sess-A");
    state.prepare_chat(&signed, chat_payload()).unwrap();
    // Try to reuse the same session with the unsigned workflow.
    let mut unsigned = signed.clone();
    unsigned.insert("x-av-workflow", HeaderValue::from_static("unsigned"));
    let Err(err) = state.prepare_chat(&unsigned, chat_payload()) else {
        panic!("workflow change must be refused");
    };
    assert!(
        matches!(err, PipelineError::BadRequest { .. }),
        "expected BadRequest for workflow change, got {err:?}"
    );
}

// ------------------------------------------------------------------
// 2. Sandbox 4-gate cascade: exact stage attribution.
// ------------------------------------------------------------------

fn schema_for(name: &str) -> HashMap<String, Value> {
    let mut m = HashMap::new();
    m.insert(
        name.to_owned(),
        json!({
            "type": "object",
            "required": ["q"],
            "properties": {"q": {"type": "string"}}
        }),
    );
    m
}

#[test]
fn sandbox_gate_cascade_attributes_the_exact_first_failure() {
    // Same fully-loaded sandbox for all cases: schema for `search` requires
    // {"q": string}; policy denies `hostile`; budget caps `db_write` to 0.
    let sandbox = || {
        let cfg = SandboxConfig {
            schemas: schema_for("search"),
            budget: BudgetSpec {
                max_tool_calls: {
                    let mut m = BTreeMap::new();
                    m.insert("db_write".to_owned(), 0u64);
                    m
                },
                ..BudgetSpec::default()
            },
            payout_field: "amount_usd".to_owned(),
            require_schema: false,
        };
        Sandbox::new(cfg, vec![Box::new(NativePolicy::deny_tools(&["hostile"]))]).unwrap()
    };
    let store = InMemoryStore::new();

    // Case A: parse fails first, even though nothing else applies.
    let sb = sandbox();
    let verdict = sb.check(&store, "s", b"not json rpc at all");
    match verdict {
        ToolVerdict::Blocked { stage, .. } => assert_eq!(stage, "parse", "expected parse first"),
        ToolVerdict::Allowed { .. } => panic!("malformed must not be allowed"),
        _ => panic!("unhandled ToolVerdict variant in test"),
    }

    // Case B: parse OK, schema fails (arguments.q is a number, must be string).
    let sb = sandbox();
    let raw = tools_call("search", json!({"q": 42}));
    match sb.check(&store, "s", &raw) {
        ToolVerdict::Blocked { stage, .. } => assert_eq!(stage, "schema"),
        ToolVerdict::Allowed { .. } => panic!("schema violation must not be allowed"),
        _ => panic!("unhandled ToolVerdict variant in test"),
    }

    // Case C: parse OK, schema OK (unknown schema tolerated), policy denies.
    let sb = sandbox();
    let raw = tools_call("hostile", json!({"whatever": true}));
    match sb.check(&store, "s", &raw) {
        ToolVerdict::Blocked { stage, .. } => assert_eq!(stage, "policy"),
        ToolVerdict::Allowed { .. } => panic!("policy-denied must not be allowed"),
        _ => panic!("unhandled ToolVerdict variant in test"),
    }

    // Case D: parse OK, schema OK (no schema for db_write), policy OK, budget=0.
    let sb = sandbox();
    let raw = tools_call("db_write", json!({}));
    match sb.check(&store, "s", &raw) {
        ToolVerdict::Blocked { stage, .. } => assert_eq!(stage, "budget"),
        ToolVerdict::Allowed { .. } => panic!("cap=0 must block first call"),
        _ => panic!("unhandled ToolVerdict variant in test"),
    }

    // Case E: everything passes — allowed.
    let sb = sandbox();
    let raw = tools_call("search", json!({"q": "hello"}));
    assert!(sb.check(&store, "s", &raw).is_allowed());
}

// ------------------------------------------------------------------
// 3. Concurrent budget race: 32 threads for per-tool cap of 5.
// ------------------------------------------------------------------

#[test]
fn per_tool_cap_of_five_admits_exactly_five_under_32_way_race() {
    const N: usize = 32;
    const CAP: u64 = 5;
    let store = Arc::new(InMemoryStore::new());
    let mut per = BTreeMap::new();
    per.insert("payout".to_owned(), CAP);
    let spec = BudgetSpec {
        max_tool_calls: per,
        ..BudgetSpec::default()
    };
    let barrier = Arc::new(std::sync::Barrier::new(N));
    let mut handles = Vec::with_capacity(N);
    for _ in 0..N {
        let store = Arc::clone(&store);
        let spec = spec.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            let budget = ActionBudget::new(store.as_ref(), "race-session", &spec);
            barrier.wait();
            budget.try_tool_call("payout", 0)
        }));
    }
    let mut allowed = 0usize;
    let mut refused = 0usize;
    for h in handles {
        match h.join().unwrap().unwrap() {
            BudgetDecision::Allowed { .. } => allowed += 1,
            BudgetDecision::Refused { .. } => refused += 1,
        }
    }
    let cap_usize = usize::try_from(CAP).unwrap();
    assert_eq!(allowed, cap_usize);
    assert_eq!(refused, N - cap_usize);
}

// ------------------------------------------------------------------
// 4. Policy chain: first-deny wins, regardless of order.
// ------------------------------------------------------------------

struct AlwaysAllow;
impl PolicyEngine for AlwaysAllow {
    fn name(&self) -> &str {
        "always-allow"
    }
    fn evaluate(&self, _tool: &str, _args: &Value) -> PolicyDecision {
        PolicyDecision::Allow
    }
}

#[test]
fn policy_chain_first_deny_wins_regardless_of_order() {
    let store = InMemoryStore::new();
    let raw = tools_call("hostile", json!({}));

    // Chain: [Deny, Allow] — Deny fires first.
    let sb = Sandbox::new(
        SandboxConfig::default(),
        vec![
            Box::new(NativePolicy::deny_tools(&["hostile"])),
            Box::new(AlwaysAllow),
        ],
    )
    .unwrap();
    match sb.check(&store, "s", &raw) {
        ToolVerdict::Blocked { stage, .. } => assert_eq!(stage, "policy"),
        ToolVerdict::Allowed { .. } => panic!("policy chain must block hostile"),
        _ => panic!("unhandled ToolVerdict variant in test"),
    }

    // Chain: [Allow, Deny] — Allow is not final; Deny still fires.
    let sb = Sandbox::new(
        SandboxConfig::default(),
        vec![
            Box::new(AlwaysAllow),
            Box::new(NativePolicy::deny_tools(&["hostile"])),
        ],
    )
    .unwrap();
    match sb.check(&store, "s", &raw) {
        ToolVerdict::Blocked { stage, .. } => assert_eq!(stage, "policy"),
        ToolVerdict::Allowed { .. } => panic!("later Deny must still fire"),
        _ => panic!("unhandled ToolVerdict variant in test"),
    }
}

// ------------------------------------------------------------------
// 5. Broker: publish_idempotent + retention — a re-publish after the
//    original expired lands on a FRESH offset (the dedup entry is dropped
//    with the expired record; returning the stale offset would point at
//    expired data).
// ------------------------------------------------------------------

fn min_manifest() -> BridgeManifest {
    let mut m = BridgeManifest::default_for("multi");
    for topic in &mut m.topics {
        topic.schema_ref = None;
        topic.partitions = 1;
    }
    m
}

#[test]
fn publish_idempotent_dedup_expires_with_retention() {
    let dir = tempfile::tempdir().unwrap();
    let cold = tempfile::tempdir().unwrap();
    let mut m = min_manifest();
    for topic in &mut m.topics {
        topic.retention.hot_hours = 1;
        topic.retention.cold_uri = Some(cold.path().to_string_lossy().into_owned());
    }
    let broker = EmbeddedBroker::provision(dir.path(), &m).unwrap();
    let value = json!({"metadata": {"uid": "durable-dedup"}, "n": 1});
    let ack1 = broker
        .publish_idempotent("agent.tool_call", "inst", &value, "durable-dedup")
        .unwrap();
    // Force retention past cutoff — the hot record is evicted.
    let record = broker.fetch("agent.tool_call", 0, 0, 1).unwrap()[0].clone();
    let now = record.stored_at + u64::from(m.topics[0].retention.hot_hours) * 3_600_000 + 1;
    let expired = broker.enforce_retention(now).unwrap();
    assert_eq!(expired, 1);
    // Re-publish the same UID: after retention purged the original record,
    // the idempotency map must NOT return the stale offset — a follow-up
    // fetch(old_offset) would return either nothing or an unrelated event.
    // The correct behavior is to append fresh; the new ack points at a
    // record that actually exists.
    let ack2 = broker
        .publish_idempotent("agent.tool_call", "inst", &value, "durable-dedup")
        .unwrap();
    assert!(
        ack2.offset > ack1.offset,
        "post-retention republish must land on a fresh offset (old={} new={}); \
         returning the stale offset would point at expired data",
        ack1.offset,
        ack2.offset,
    );
    // The fresh ack points at a real record.
    let refetched = broker.fetch("agent.tool_call", 0, ack2.offset, 1).unwrap();
    assert_eq!(refetched.len(), 1);
    assert_eq!(refetched[0].offset, ack2.offset);
}

// ------------------------------------------------------------------
// 6. Receipt verify against a rotated trusted keyring.
// ------------------------------------------------------------------

fn signed_receipt_for(seed: [u8; 32]) -> Receipt {
    let signer = Ed25519Signer::from_seed(&seed);
    let body = ReceiptBody {
        receipt_version: 1,
        receipt_id: "rot".to_owned(),
        session_id: "s".to_owned(),
        issued_at: 0,
        issued_at_iso: "1970-01-01T00:00:00.000Z".to_owned(),
        ai_agent: AgentIdentity {
            version: "1".to_owned(),
            charter: CharterFile::from("c"),
            instance_uid: "i".to_owned(),
            ttl_remaining_s: None,
        },
        subject: ReceiptSubject::EventChain {
            chain_head: "00".repeat(32),
            event_count: 1,
        },
        tool_calls: ToolCallSummary::default(),
        cost: CostSummary::default(),
        stop_reason_id: 1,
        stop_reason: "SessionClosed".to_owned(),
        key_id: String::new(),
        public_key_b64: String::new(),
    };
    Receipt::issue(body, &signer).unwrap()
}

#[test]
fn receipt_verifies_against_multi_key_ring_after_rotation() {
    let a = Ed25519Signer::from_seed(&[1; 32]);
    let b = Ed25519Signer::from_seed(&[2; 32]);
    let receipt = signed_receipt_for([1; 32]);

    // ring={B only}: fails.
    let mut ring_b = Keyring::new();
    ring_b.add_key_bytes(&Signer::public_key_bytes(&b)).unwrap();
    receipt
        .verify(&ring_b)
        .expect_err("ring without signer key must reject");

    // ring={A only}: succeeds.
    let mut ring_a = Keyring::new();
    ring_a.add_key_bytes(&Signer::public_key_bytes(&a)).unwrap();
    receipt.verify(&ring_a).unwrap();

    // ring={A, B}: rotation-window verify still succeeds.
    let mut ring_ab = Keyring::new();
    ring_ab.add_key_bytes(&Signer::public_key_bytes(&a)).unwrap();
    ring_ab.add_key_bytes(&Signer::public_key_bytes(&b)).unwrap();
    receipt.verify(&ring_ab).unwrap();
}

// ------------------------------------------------------------------
// 7. Session close + subsequent intercept_tool must refuse.
// ------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tool_intercept_after_session_close_refuses() {
    let state = state_with(
        Sandbox::new(SandboxConfig::default(), Vec::new()).unwrap(),
        BudgetSpec::default(),
    );
    let headers = signed_headers("close-then-tool");
    state.prepare_chat(&headers, chat_payload()).unwrap();
    let session = state.sessions.get("close-then-tool").unwrap();
    state
        .finalizer
        .close_session(session.clone(), av_events::StopReason::SessionClosed)
        .await
        .unwrap();
    assert!(session.is_closed());
    let raw = tools_call("anything", json!({}));
    let Err(err) = state.intercept_tool(&headers, &raw) else {
        panic!("intercept after close must fail");
    };
    assert!(
        matches!(err, PipelineError::BadRequest { .. }),
        "expected BadRequest after close, got {err:?}"
    );
}

// ------------------------------------------------------------------
// 8. Sandbox 4-gate ordering under load: a caller pumping bad payloads at
//    varied stages of failure must never see the wrong stage attribution.
// ------------------------------------------------------------------

#[test]
fn sandbox_stage_attribution_is_stable_under_concurrent_mixed_input() {
    let cfg = SandboxConfig {
        schemas: schema_for("search"),
        budget: BudgetSpec::default(),
        payout_field: "amount_usd".to_owned(),
        require_schema: false,
    };
    let sandbox =
        Arc::new(Sandbox::new(cfg, vec![Box::new(NativePolicy::deny_tools(&["hostile"]))]).unwrap());
    let store = Arc::new(InMemoryStore::new());
    let cases: Vec<(Vec<u8>, &'static str)> = vec![
        (b"garbage".to_vec(), "parse"),
        (tools_call("search", json!({"q": 1})), "schema"),
        (tools_call("hostile", json!({})), "policy"),
    ];
    let mut handles = Vec::new();
    for _ in 0..8 {
        for (raw, expected_stage) in &cases {
            let sandbox = Arc::clone(&sandbox);
            let store = Arc::clone(&store);
            let raw = raw.clone();
            let expected_stage = *expected_stage;
            handles.push(std::thread::spawn(move || {
                let verdict = sandbox.check(store.as_ref(), "sess-mix", &raw);
                match verdict {
                    ToolVerdict::Blocked { stage, .. } => {
                        assert_eq!(stage, expected_stage, "stage attribution drifted");
                    }
                    ToolVerdict::Allowed { .. } => panic!("bad payload was allowed"),
                    _ => panic!("unhandled ToolVerdict variant in test"),
                }
            }));
        }
    }
    for h in handles {
        h.join().unwrap();
    }
}
