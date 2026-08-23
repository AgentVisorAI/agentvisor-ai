//! Advanced crafted attacks — combinations of primitives that a single-gate
//! test wouldn't catch. Every test in this file targets a defense boundary
//! where two or more attack techniques are chained.
//!
//! Threat sources for each test are cited inline.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::cast_possible_truncation
)]

use av_receipts::{canonicalize, Ed25519Signer, EventChain, Keyring, Receipt, Signer};
use av_sandbox::{PolicyDecision, PolicyEngine, Sandbox, SandboxConfig, ToolVerdict};
use av_state::{BudgetSpec, InMemoryStore, StateStore};
use base64::Engine as _;
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

mod common;
use common::tools_call;

// ---------------------------------------------------------------------------
// Attack 1. TOCTOU on payout: race N sandbox `check` calls at exactly the
// remaining budget. If the ordering is loose, the last-N submitters would
// each see remaining budget and each spend, blowing the cap. AgentVisor AI's
// defense is `try_spend_many` atomicity.
//
// Threat: bank-run TOCTOU (classic double-spend), applied to LLM payouts.
// ---------------------------------------------------------------------------

#[test]
fn concurrent_payout_calls_at_the_budget_ceiling_never_overspend() {
    const LIMIT_USD: u64 = 100;
    const AGENTS: u64 = 32;
    let sandbox = Arc::new(
        Sandbox::new(
            SandboxConfig {
                budget: BudgetSpec {
                    max_payout_usd_micros: Some(LIMIT_USD * 1_000_000),
                    ..BudgetSpec::default()
                },
                payout_field: "amount_usd".into(),
                ..SandboxConfig::default()
            },
            vec![],
        )
        .unwrap(),
    );
    let store: Arc<dyn StateStore + Send + Sync> = Arc::new(InMemoryStore::new());
    let barrier = Arc::new(Barrier::new(AGENTS as usize));
    let allowed = Arc::new(AtomicU64::new(0));
    let handles: Vec<_> = (0..AGENTS)
        .map(|i| {
            let sandbox = Arc::clone(&sandbox);
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            let allowed = Arc::clone(&allowed);
            thread::spawn(move || {
                barrier.wait();
                let raw = tools_call("payout", json!({"amount_usd": 5, "n": i}));
                if let ToolVerdict::Allowed { .. } = sandbox.check(&*store, "sess-race", &raw) {
                    allowed.fetch_add(5, Ordering::Relaxed);
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    let spent = allowed.load(Ordering::Relaxed);
    assert!(
        spent <= LIMIT_USD,
        "overspent under contention: {spent} > {LIMIT_USD}"
    );
    // We should be at the ceiling (no phantom denials).
    assert!(
        spent >= LIMIT_USD - 4,
        "underspent — sandbox denied too aggressively: {spent}"
    );
}

// ---------------------------------------------------------------------------
// Attack 2. Cross-session collusion: two malicious sessions coordinate to
// drain a per-tool ceiling that was scoped per-session. AgentVisor AI's
// defense: budgets are keyed by session id, so collusion cannot combine
// budgets. This proves each session's counter is isolated.
//
// Threat: LinkedIn / X.com abuse pattern (many burner accounts).
// ---------------------------------------------------------------------------

#[test]
fn cross_session_collusion_cannot_pool_budget_ceilings() {
    let sandbox = Sandbox::new(
        SandboxConfig {
            budget: BudgetSpec {
                max_total_tool_calls: Some(3),
                ..BudgetSpec::default()
            },
            ..SandboxConfig::default()
        },
        vec![],
    )
    .unwrap();
    let store = InMemoryStore::new();
    // Session A uses its full 3-call budget.
    for _ in 0..3 {
        let raw = tools_call("t", json!({}));
        assert!(matches!(
            sandbox.check(&store, "sess-A", &raw),
            ToolVerdict::Allowed { .. }
        ));
    }
    // Fourth call from A is denied — session A is exhausted.
    let raw = tools_call("t", json!({}));
    assert!(matches!(
        sandbox.check(&store, "sess-A", &raw),
        ToolVerdict::Blocked { .. }
    ));
    // Session B still has its full budget — the collusion attempt fails
    // because the counter is per-session, not per-tool.
    for i in 0..3 {
        let raw = tools_call("t", json!({"i": i}));
        assert!(matches!(
            sandbox.check(&store, "sess-B", &raw),
            ToolVerdict::Allowed { .. }
        ));
    }
}

// ---------------------------------------------------------------------------
// Attack 3. Receipt reflection: attacker submits a JCS-canonicalized
// receipt-shaped payload as a tool argument, hoping to trigger self-
// referential verification. AgentVisor AI's defense: sandbox validates
// against per-tool schemas, not against receipt-schema, so receipt bytes
// are just data and never re-parsed as a receipt.
//
// Threat: object-injection class (Ruby/PHP RCE lineage), adapted for LLMs.
// ---------------------------------------------------------------------------

#[test]
fn receipt_shaped_tool_argument_is_treated_as_opaque_data() {
    let s = Ed25519Signer::from_seed(&[201; 32]);
    // Real, valid receipt body serialized as an argument.
    let honest_body = av_receipts::ReceiptBody {
        receipt_version: 1,
        receipt_id: "attacker-crafted".to_owned(),
        session_id: "victim-sess".to_owned(),
        issued_at: 1,
        issued_at_iso: "1970-01-01T00:00:00.001Z".to_owned(),
        ai_agent: av_events::AgentIdentity {
            version: "1".to_owned(),
            charter: av_events::CharterFile::from("c"),
            instance_uid: "i".to_owned(),
            ttl_remaining_s: None,
        },
        subject: av_receipts::ReceiptSubject::EventChain {
            chain_head: "aa".repeat(32),
            event_count: 999,
        },
        tool_calls: av_receipts::ToolCallSummary::default(),
        cost: av_receipts::CostSummary::default(),
        stop_reason_id: 1,
        stop_reason: "SessionClosed".to_owned(),
        key_id: String::new(),
        public_key_b64: String::new(),
    };
    let signed = Receipt::issue(honest_body, &s).unwrap();
    let mut schemas: HashMap<String, Value> = HashMap::new();
    schemas.insert(
        "audit_log".to_owned(),
        json!({
            "type": "object",
            "properties": {"note": {"type": "string"}},
            "required": ["note"],
            "additionalProperties": false,
        }),
    );
    let sandbox = Sandbox::new(
        SandboxConfig {
            schemas,
            require_schema: true,
            ..SandboxConfig::default()
        },
        vec![],
    )
    .unwrap();
    let store = InMemoryStore::new();
    // Attacker packs the signed receipt as a tool argument.
    let raw = tools_call("audit_log", json!({"receipt": signed, "note": "hi"}));
    // The schema forbids additional properties: `receipt` is refused.
    match sandbox.check(&store, "sess", &raw) {
        ToolVerdict::Blocked { stage, .. } => assert_eq!(stage, "schema"),
        ToolVerdict::Allowed { .. } => panic!("receipt-shaped payload passed the schema gate"),
    }
}

// ---------------------------------------------------------------------------
// Attack 4. Chain-continuation forgery: given a public head hash, attacker
// tries to craft an event whose canonical JCS bytes reproduce the target
// next head. Because SHA-256 is preimage-resistant and JCS constrains the
// legal byte set of an event, no crafted event can match.
//
// Threat: crypto-primitive misuse (would-be birthday attack).
// ---------------------------------------------------------------------------

#[test]
fn attacker_cannot_extend_chain_with_a_crafted_next_event() {
    let honest = EventChain::compute("sess", &[json!({"seq": 0, "ok": true})]).unwrap();
    let target_head = honest.head_hex();
    // Attacker's synthesized "continuation" event: try many variants and
    // check none accidentally reproduce the same head. This is a smoke test
    // of preimage-resistance rather than a full search.
    let mut collisions = 0;
    for i in 0u32..10_000 {
        let ev = json!({"seq": 0, "payload": i, "attacker": true});
        let forged_chain = EventChain::compute("sess", &[ev]).unwrap();
        if forged_chain.head_hex() == target_head {
            collisions += 1;
        }
    }
    assert_eq!(
        collisions, 0,
        "collision found under 10 000 crafted attempts (preimage-resistance likely broken)"
    );
}

// ---------------------------------------------------------------------------
// Attack 5. JCS parser-differential smuggling: attacker sends a tool call
// whose JSON has duplicate keys where one is safe and the other hostile.
// A permissive last-wins parser would see the hostile value; JCS +
// serde_json takes last-wins by default too, but any downstream consumer
// that used first-wins would disagree.
//
// AgentVisor AI's defense: the sandbox parses ONCE and hands the parsed value
// to every gate downstream, so parser disagreement cannot open a split-view
// window between schema and policy.
// ---------------------------------------------------------------------------

#[test]
fn duplicate_key_parser_differential_cannot_split_schema_from_policy() {
    struct RecipientPolicy;
    impl PolicyEngine for RecipientPolicy {
        fn name(&self) -> &str {
            "recipient"
        }
        fn evaluate(&self, tool: &str, args: &Value) -> PolicyDecision {
            if tool != "send" {
                return PolicyDecision::Allow;
            }
            let rcpt = args.get("to").and_then(Value::as_str).unwrap_or("");
            if rcpt.contains("attacker") {
                PolicyDecision::Deny {
                    reason: "hostile recipient".into(),
                }
            } else {
                PolicyDecision::Allow
            }
        }
    }
    let sandbox = Sandbox::new(SandboxConfig::default(), vec![Box::new(RecipientPolicy)]).unwrap();
    let store = InMemoryStore::new();
    // Manually build a duplicate-key JSON payload.
    let raw = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"send","arguments":{"to":"attacker@evil.com","to":"user@example.com"}}}"#;
    // Duplicate keys are rejected at the RPC parser, ahead
    // of both gates. A previous version accepted the parser's
    // (implementation-defined) last-wins pick and RELIED on threading
    // it consistently to schema and policy — but the raw body is
    // forwarded unchanged to the tool upstream, whose JSON decoder
    // may pick first-wins (jackson, some Go decoders), producing a
    // permissions-model split with the harness attesting one thing
    // and the upstream executing another. Refuse ambiguity.
    match sandbox.check(&store, "sess", raw) {
        ToolVerdict::Blocked { stage, reason, .. } => {
            assert_eq!(
                stage, "parse",
                "duplicate keys must be rejected at parse, got stage={stage} reason={reason}",
            );
            assert!(
                reason.contains("duplicate"),
                "parse rejection must cite the duplicate key, got: {reason}"
            );
        }
        ToolVerdict::Allowed { .. } => {
            panic!("duplicate-key payload must be refused, not allowed");
        }
    }
}

// ---------------------------------------------------------------------------
// Attack 6. Cost-model desync: attacker sends a tool call with `amount_usd`
// as a string that COULD be interpreted as either 0 or 50 by different
// parsers. The sandbox must parse strictly via serde_json — a `String`
// where a `Number` is expected must be either coerced to 0 (safe) or
// refused outright (safer). Never silently ignored.
// ---------------------------------------------------------------------------

#[test]
fn stringified_payout_amount_does_not_bypass_the_budget_gate() {
    let sandbox = Sandbox::new(
        SandboxConfig {
            budget: BudgetSpec {
                max_payout_usd_micros: Some(10 * 1_000_000),
                ..BudgetSpec::default()
            },
            payout_field: "amount_usd".into(),
            ..SandboxConfig::default()
        },
        vec![],
    )
    .unwrap();
    let store = InMemoryStore::new();
    // Attacker sends a huge amount as a string.
    let raw = tools_call("payout", json!({"amount_usd": "9999999"}));
    let verdict = sandbox.check(&store, "sess", &raw);
    // Either refused, or the amount charged was 0 (safe interpretation).
    // Under NO circumstance can the string be interpreted as 9 999 999
    // that would blow the $10 cap silently while still allowing the call.
    if let ToolVerdict::Allowed { .. } = verdict {
        // If allowed, the stored payout must remain within the budget cap.
        // Read the real budget key: budget:{sha256(session)[..32]}:payout.
        let digest = av_core::digest::sha256_hex(b"sess");
        let key = format!("budget:{{{}}}:payout", digest.get(..32).unwrap());
        let spent = store.get(&key).unwrap_or(0);
        assert!(
            spent <= 10 * 1_000_000,
            "stringified amount slipped past the budget: spent={spent}"
        );
    }
}

// ---------------------------------------------------------------------------
// Attack 7. Signature-oracle amplification: attacker collects many receipts
// with the same signer and same key_id but slightly-different bodies,
// hoping to reveal something about the signing key via statistical
// analysis. Because Ed25519 is deterministic (RFC 8032) and each body is
// unique, two receipts over identical bodies produce IDENTICAL signatures
// — no oracle. Two receipts over different bodies produce two independent
// unforgeable signatures. Assert both properties simultaneously.
// ---------------------------------------------------------------------------

#[test]
fn signature_oracle_reveals_nothing_that_would_forge_a_new_receipt() {
    let s = Ed25519Signer::from_seed(&[42; 32]);
    let ring = {
        let mut r = Keyring::new();
        r.add_key_bytes(&Signer::public_key_bytes(&s)).unwrap();
        r
    };
    let sigs = Mutex::new(HashMap::<Vec<u8>, String>::new());
    // Collect signatures over 200 receipts.
    for i in 0..200_u64 {
        let body = av_receipts::ReceiptBody {
            receipt_version: 1,
            receipt_id: format!("r-{i}"),
            session_id: format!("s-{i}"),
            issued_at: i,
            issued_at_iso: format!("1970-01-01T00:00:00.{i:03}Z"),
            ai_agent: av_events::AgentIdentity {
                version: "1".to_owned(),
                charter: av_events::CharterFile::from("c"),
                instance_uid: "i".to_owned(),
                ttl_remaining_s: None,
            },
            subject: av_receipts::ReceiptSubject::EventChain {
                chain_head: "00".repeat(32),
                event_count: i,
            },
            tool_calls: av_receipts::ToolCallSummary::default(),
            cost: av_receipts::CostSummary::default(),
            stop_reason_id: 1,
            stop_reason: "SessionClosed".to_owned(),
            key_id: String::new(),
            public_key_b64: String::new(),
        };
        let receipt = Receipt::issue(body.clone(), &s).unwrap();
        // canonicalized body must uniquely determine the signature.
        let canon = canonicalize(&serde_json::to_value(&receipt.body).unwrap())
            .unwrap()
            .into_bytes();
        let prev = sigs.lock().insert(canon.clone(), receipt.signature_b64.clone());
        if let Some(prev_sig) = prev {
            assert_eq!(
                prev_sig, receipt.signature_b64,
                "same canonical body yielded different signatures — non-determinism"
            );
        }
        receipt.verify(&ring).unwrap();
    }
    // 200 distinct canonicalized bodies must yield 200 distinct signatures.
    assert_eq!(sigs.lock().len(), 200);
    // Determinism arm: the loop's bodies are all distinct, so
    // the insert-collision branch above can never fire — force one true
    // identical-body pair here. RFC 8032 Ed25519 is deterministic: same
    // canonical body under the same key must yield the identical signature.
    {
        let make_body = |receipt_id: &str| av_receipts::ReceiptBody {
            receipt_version: 1,
            receipt_id: receipt_id.to_owned(),
            session_id: "det".to_owned(),
            issued_at: 7,
            issued_at_iso: "1970-01-01T00:00:00.007Z".to_owned(),
            ai_agent: av_events::AgentIdentity {
                version: "1".to_owned(),
                charter: av_events::CharterFile::from("c"),
                instance_uid: "i".to_owned(),
                ttl_remaining_s: None,
            },
            subject: av_receipts::ReceiptSubject::EventChain {
                chain_head: "00".repeat(32),
                event_count: 7,
            },
            tool_calls: av_receipts::ToolCallSummary::default(),
            cost: av_receipts::CostSummary::default(),
            stop_reason_id: 1,
            stop_reason: "SessionClosed".to_owned(),
            key_id: String::new(),
            public_key_b64: String::new(),
        };
        let first = Receipt::issue(make_body("r-det"), &s).unwrap();
        let second = Receipt::issue(make_body("r-det"), &s).unwrap();
        assert_eq!(
            first.signature_b64, second.signature_b64,
            "identical canonical bodies must yield identical signatures (RFC 8032 determinism)"
        );
    }
    // Cross-check: try to reuse any one signature under a fresh forged
    // body — must fail. HashMap iteration order is arbitrary; any stolen
    // signature must fail equally.
    let stolen_sig: String = sigs.lock().values().next().unwrap().clone();
    let mut forged_body = av_receipts::ReceiptBody {
        receipt_version: 1,
        receipt_id: "forged".to_owned(),
        session_id: "victim".to_owned(),
        issued_at: 0,
        issued_at_iso: "1970-01-01T00:00:00.000Z".to_owned(),
        ai_agent: av_events::AgentIdentity {
            version: "1".to_owned(),
            charter: av_events::CharterFile::from("c"),
            instance_uid: "i".to_owned(),
            ttl_remaining_s: None,
        },
        subject: av_receipts::ReceiptSubject::EventChain {
            chain_head: "00".repeat(32),
            event_count: 0,
        },
        tool_calls: av_receipts::ToolCallSummary::default(),
        cost: av_receipts::CostSummary::default(),
        stop_reason_id: 1,
        stop_reason: "SessionClosed".to_owned(),
        key_id: Signer::key_id(&s).to_owned(),
        public_key_b64: base64::engine::general_purpose::STANDARD.encode(Signer::public_key_bytes(&s)),
    };
    forged_body.stop_reason = "Forged".to_owned();
    let forged = Receipt {
        body: forged_body,
        signature_b64: stolen_sig,
    };
    assert!(
        forged.verify(&ring).is_err(),
        "reused signature verified against a forged body"
    );
}
