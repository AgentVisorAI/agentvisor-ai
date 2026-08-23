//! End-to-end confusion-matrix scenarios (TP/TN/FP/FN).
//!
//! Each scenario declares:
//!   - a natural-language description
//!   - `Expected`: whether a well-behaved harness must **block** or **allow**
//!   - a driver closure that exercises the real gates
//!
//! The runner classifies the observed outcome into the confusion matrix
//! against the expected label:
//!   TP: expected=Block, observed=Blocked      (policy caught a real threat)
//!   TN: expected=Allow, observed=Allowed      (legitimate work proceeded)
//!   FP: expected=Allow, observed=Blocked      (false alarm)
//!   FN: expected=Block, observed=Allowed      (missed detection — security-critical)
//!
//! At the end of the suite the runner asserts **zero FPs and zero FNs**. Any
//! FN aborts the process with a security-critical message.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::too_many_lines
)]

use av_harness::AppState;
use av_sandbox::{NativePolicy, Sandbox, SandboxConfig, ToolVerdict};
use av_state::BudgetSpec;
use axum::http::{HeaderMap, HeaderValue};
use serde_json::json;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

mod common;
use common::{signed_headers, tools_call};

/// Whether a well-behaved harness must block or allow the observed action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expected {
    Block,
    Allow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Observed {
    Blocked,
    Allowed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    TP,
    TN,
    FP,
    FN,
}

fn classify(expected: Expected, observed: Observed) -> Class {
    match (expected, observed) {
        (Expected::Block, Observed::Blocked) => Class::TP,
        (Expected::Allow, Observed::Allowed) => Class::TN,
        (Expected::Allow, Observed::Blocked) => Class::FP,
        (Expected::Block, Observed::Allowed) => Class::FN,
    }
}

fn build_state(sandbox: Sandbox, budget: BudgetSpec) -> Arc<AppState> {
    let mut config = common::leaked_test_config();
    // Keep the loop-detector out of the way of these gate tests.
    config.breaker.min_tokens = u64::MAX;
    config.budget = budget;
    common::app_state(config, sandbox, Arc::new(common::CountingBus::default()), 7)
}

fn observed_from_verdict(v: &ToolVerdict) -> Observed {
    match v {
        ToolVerdict::Allowed { .. } => Observed::Allowed,
        ToolVerdict::Blocked { .. } => Observed::Blocked,
    }
}

struct Scenario {
    name: &'static str,
    expected: Expected,
    /// Returns `Observed` when the drive succeeds. Never panics: any error is
    /// treated as `Blocked` (the request was refused before reaching upstream).
    run: Box<dyn Fn() -> Observed + Send + Sync>,
}

fn scenarios() -> Vec<Scenario> {
    let mut suite: Vec<Scenario> = Vec::new();

    // -------------------- CHAT-PATH SCENARIOS --------------------

    // TN: fresh legitimate chat request must be allowed.
    suite.push(Scenario {
        name: "chat: fresh legitimate request is allowed",
        expected: Expected::Allow,
        run: Box::new(|| {
            let state = build_state(
                Sandbox::new(SandboxConfig::default(), Vec::new()).unwrap(),
                BudgetSpec::default(),
            );
            let headers = signed_headers("scn-chat-tn");
            let ok = state
                .prepare_chat(
                    &headers,
                    json!({
                        "model": "gpt-x",
                        "messages": [{"role": "user", "content": "hello"}]
                    }),
                )
                .is_ok();
            if ok {
                Observed::Allowed
            } else {
                Observed::Blocked
            }
        }),
    });

    // TP: max_tokens budget exceeded → chat blocked.
    suite.push(Scenario {
        name: "chat: max_tokens budget exceeded is blocked",
        expected: Expected::Block,
        run: Box::new(|| {
            let budget = BudgetSpec {
                max_tokens: Some(4),
                ..BudgetSpec::default()
            };
            let state = build_state(
                Sandbox::new(SandboxConfig::default(), Vec::new()).unwrap(),
                budget,
            );
            let headers = signed_headers("scn-chat-tp-budget");
            // A long-enough prompt to blow past the 4-token cap.
            let ok = state
                .prepare_chat(
                    &headers,
                    json!({
                        "model": "gpt-x",
                        "messages": [{
                            "role": "user",
                            "content": "one two three four five six seven eight nine ten \
                                        eleven twelve thirteen fourteen fifteen sixteen"
                        }]
                    }),
                )
                .is_ok();
            if ok {
                Observed::Allowed
            } else {
                Observed::Blocked
            }
        }),
    });

    // TP: malformed chat (no messages) is refused as BadRequest.
    suite.push(Scenario {
        name: "chat: payload without messages is blocked",
        expected: Expected::Block,
        run: Box::new(|| {
            let state = build_state(
                Sandbox::new(SandboxConfig::default(), Vec::new()).unwrap(),
                BudgetSpec::default(),
            );
            let headers = signed_headers("scn-chat-tp-nomsg");
            let ok = state.prepare_chat(&headers, json!({"model": "gpt-x"})).is_ok();
            if ok {
                Observed::Allowed
            } else {
                Observed::Blocked
            }
        }),
    });

    // TN: chat without an X-AV-Session header is allowed — the harness
    // auto-generates a fresh UUID session id (documented behavior).
    suite.push(Scenario {
        name: "chat: missing session header auto-generates a session (allowed)",
        expected: Expected::Allow,
        run: Box::new(|| {
            let state = build_state(
                Sandbox::new(SandboxConfig::default(), Vec::new()).unwrap(),
                BudgetSpec::default(),
            );
            let mut headers = HeaderMap::new();
            headers.insert("x-av-workflow", HeaderValue::from_static("signed"));
            let ok = state
                .prepare_chat(
                    &headers,
                    json!({
                        "model": "gpt-x",
                        "messages": [{"role": "user", "content": "hi"}]
                    }),
                )
                .is_ok();
            if ok {
                Observed::Allowed
            } else {
                Observed::Blocked
            }
        }),
    });

    // TP: session id containing a space fails SessionId::parse (visible-ASCII only).
    suite.push(Scenario {
        name: "chat: session id with a space is blocked",
        expected: Expected::Block,
        run: Box::new(|| {
            let state = build_state(
                Sandbox::new(SandboxConfig::default(), Vec::new()).unwrap(),
                BudgetSpec::default(),
            );
            let mut headers = HeaderMap::new();
            headers.insert(
                "x-av-session",
                HeaderValue::from_bytes(b"bad session id").unwrap(),
            );
            headers.insert("x-av-workflow", HeaderValue::from_static("signed"));
            let ok = state
                .prepare_chat(
                    &headers,
                    json!({
                        "model": "gpt-x",
                        "messages": [{"role": "user", "content": "hi"}]
                    }),
                )
                .is_ok();
            if ok {
                Observed::Allowed
            } else {
                Observed::Blocked
            }
        }),
    });

    // -------------------- TOOL-PATH SCENARIOS --------------------

    // TN: allow-listed benign tool call goes through all four gates cleanly.
    suite.push(Scenario {
        name: "tool: allow-listed benign call is allowed",
        expected: Expected::Allow,
        run: Box::new(|| {
            let sandbox = Sandbox::new(
                SandboxConfig::default(),
                vec![Box::new(NativePolicy::allow_only(&["search"]))],
            )
            .unwrap();
            let state = build_state(sandbox, BudgetSpec::default());
            let headers = signed_headers("scn-tool-tn");
            let raw = tools_call("search", json!({"q": "cats"}));
            match state.intercept_tool(&headers, &raw) {
                Ok(v) => observed_from_verdict(&v),
                Err(_) => Observed::Blocked,
            }
        }),
    });

    // TP: allow-list rejects an unknown tool at the policy gate.
    suite.push(Scenario {
        name: "tool: allow-list rejects unknown tool",
        expected: Expected::Block,
        run: Box::new(|| {
            let sandbox = Sandbox::new(
                SandboxConfig::default(),
                vec![Box::new(NativePolicy::allow_only(&["search"]))],
            )
            .unwrap();
            let state = build_state(sandbox, BudgetSpec::default());
            let headers = signed_headers("scn-tool-tp-notallowlisted");
            let raw = tools_call("drop_database", json!({}));
            match state.intercept_tool(&headers, &raw) {
                Ok(v) => observed_from_verdict(&v),
                Err(_) => Observed::Blocked,
            }
        }),
    });

    // TP: deny-list rejects a dangerous tool by name.
    suite.push(Scenario {
        name: "tool: deny-list rejects dangerous tool",
        expected: Expected::Block,
        run: Box::new(|| {
            let sandbox = Sandbox::new(
                SandboxConfig::default(),
                vec![Box::new(NativePolicy::deny_tools(&["exfiltrate"]))],
            )
            .unwrap();
            let state = build_state(sandbox, BudgetSpec::default());
            let headers = signed_headers("scn-tool-tp-denylist");
            let raw = tools_call("exfiltrate", json!({"blob": "secret"}));
            match state.intercept_tool(&headers, &raw) {
                Ok(v) => observed_from_verdict(&v),
                Err(_) => Observed::Blocked,
            }
        }),
    });

    // TP: schema-required + unknown tool schema → blocked.
    suite.push(Scenario {
        name: "tool: require_schema blocks unknown-schema tool",
        expected: Expected::Block,
        run: Box::new(|| {
            let cfg = SandboxConfig {
                schemas: HashMap::new(),
                budget: BudgetSpec::default(),
                payout_field: "amount_usd".to_owned(),
                require_schema: true,
            };
            let sandbox = Sandbox::new(cfg, Vec::new()).unwrap();
            let state = build_state(sandbox, BudgetSpec::default());
            let headers = signed_headers("scn-tool-tp-schema");
            let raw = tools_call("mystery_tool", json!({"x": 1}));
            match state.intercept_tool(&headers, &raw) {
                Ok(v) => observed_from_verdict(&v),
                Err(_) => Observed::Blocked,
            }
        }),
    });

    // TN: schema-required + a registered schema that matches arguments.
    suite.push(Scenario {
        name: "tool: valid arguments against registered schema are allowed",
        expected: Expected::Allow,
        run: Box::new(|| {
            let mut schemas = HashMap::new();
            schemas.insert(
                "search".to_owned(),
                json!({
                    "type": "object",
                    "required": ["q"],
                    "properties": {"q": {"type": "string"}}
                }),
            );
            let cfg = SandboxConfig {
                schemas,
                budget: BudgetSpec::default(),
                payout_field: "amount_usd".to_owned(),
                require_schema: true,
            };
            let sandbox = Sandbox::new(cfg, Vec::new()).unwrap();
            let state = build_state(sandbox, BudgetSpec::default());
            let headers = signed_headers("scn-tool-tn-schema-ok");
            let raw = tools_call("search", json!({"q": "cats"}));
            match state.intercept_tool(&headers, &raw) {
                Ok(v) => observed_from_verdict(&v),
                Err(_) => Observed::Blocked,
            }
        }),
    });

    // TP: schema-required + wrong argument type → blocked at schema gate.
    suite.push(Scenario {
        name: "tool: wrong argument type is blocked by schema",
        expected: Expected::Block,
        run: Box::new(|| {
            let mut schemas = HashMap::new();
            schemas.insert(
                "search".to_owned(),
                json!({
                    "type": "object",
                    "required": ["q"],
                    "properties": {"q": {"type": "string"}}
                }),
            );
            let cfg = SandboxConfig {
                schemas,
                budget: BudgetSpec::default(),
                payout_field: "amount_usd".to_owned(),
                require_schema: true,
            };
            let sandbox = Sandbox::new(cfg, Vec::new()).unwrap();
            let state = build_state(sandbox, BudgetSpec::default());
            let headers = signed_headers("scn-tool-tp-schema-bad");
            let raw = tools_call("search", json!({"q": 42})); // q must be string
            match state.intercept_tool(&headers, &raw) {
                Ok(v) => observed_from_verdict(&v),
                Err(_) => Observed::Blocked,
            }
        }),
    });

    // TP: payout above the max_payout_usd_micros cap is blocked at budget gate.
    suite.push(Scenario {
        name: "tool: payout above budget cap is blocked",
        expected: Expected::Block,
        run: Box::new(|| {
            let budget = BudgetSpec {
                max_payout_usd_micros: Some(50_000_000), // $50 hard cap
                ..BudgetSpec::default()
            };
            let cfg = SandboxConfig {
                schemas: HashMap::new(),
                budget: budget.clone(),
                payout_field: "amount_usd".to_owned(),
                require_schema: false,
            };
            let sandbox = Sandbox::new(cfg, Vec::new()).unwrap();
            let state = build_state(sandbox, budget);
            let headers = signed_headers("scn-tool-tp-payout");
            let raw = tools_call("payout", json!({"amount_usd": 500.0}));
            match state.intercept_tool(&headers, &raw) {
                Ok(v) => observed_from_verdict(&v),
                Err(_) => Observed::Blocked,
            }
        }),
    });

    // TN: payout under the cap is allowed.
    suite.push(Scenario {
        name: "tool: payout under budget cap is allowed",
        expected: Expected::Allow,
        run: Box::new(|| {
            let budget = BudgetSpec {
                max_payout_usd_micros: Some(50_000_000),
                ..BudgetSpec::default()
            };
            let cfg = SandboxConfig {
                schemas: HashMap::new(),
                budget: budget.clone(),
                payout_field: "amount_usd".to_owned(),
                require_schema: false,
            };
            let sandbox = Sandbox::new(cfg, Vec::new()).unwrap();
            let state = build_state(sandbox, budget);
            let headers = signed_headers("scn-tool-tn-payout");
            let raw = tools_call("payout", json!({"amount_usd": 5.0}));
            match state.intercept_tool(&headers, &raw) {
                Ok(v) => observed_from_verdict(&v),
                Err(_) => Observed::Blocked,
            }
        }),
    });

    // TP: per-tool cap tripped on second call.
    suite.push(Scenario {
        name: "tool: per-tool call cap tripped on second call",
        expected: Expected::Block,
        run: Box::new(|| {
            let mut per_tool = BTreeMap::new();
            per_tool.insert("db_write".to_owned(), 1);
            let budget = BudgetSpec {
                max_tool_calls: per_tool,
                ..BudgetSpec::default()
            };
            let cfg = SandboxConfig {
                schemas: HashMap::new(),
                budget: budget.clone(),
                payout_field: "amount_usd".to_owned(),
                require_schema: false,
            };
            let sandbox = Sandbox::new(cfg, Vec::new()).unwrap();
            let state = build_state(sandbox, budget);
            let headers = signed_headers("scn-tool-tp-percap");
            let raw = tools_call("db_write", json!({"row": 1}));
            // First call: should pass.
            let _ = state.intercept_tool(&headers, &raw);
            // Second call: should trip the per-tool cap of 1.
            match state.intercept_tool(&headers, &raw) {
                Ok(v) => observed_from_verdict(&v),
                Err(_) => Observed::Blocked,
            }
        }),
    });

    // TP: malformed JSON-RPC (not tools/call) is blocked at parse gate.
    suite.push(Scenario {
        name: "tool: non-tools/call JSON-RPC is blocked at parse gate",
        expected: Expected::Block,
        run: Box::new(|| {
            let sandbox = Sandbox::new(SandboxConfig::default(), Vec::new()).unwrap();
            let state = build_state(sandbox, BudgetSpec::default());
            let headers = signed_headers("scn-tool-tp-parse");
            let raw = br#"{"jsonrpc":"2.0","method":"resources/read","id":1}"#.to_vec();
            match state.intercept_tool(&headers, &raw) {
                Ok(v) => observed_from_verdict(&v),
                Err(_) => Observed::Blocked,
            }
        }),
    });

    // TP: garbage bytes are blocked at parse gate.
    suite.push(Scenario {
        name: "tool: garbage bytes are blocked at parse gate",
        expected: Expected::Block,
        run: Box::new(|| {
            let sandbox = Sandbox::new(SandboxConfig::default(), Vec::new()).unwrap();
            let state = build_state(sandbox, BudgetSpec::default());
            let headers = signed_headers("scn-tool-tp-garbage");
            let raw = b"not-json-at-all".to_vec();
            match state.intercept_tool(&headers, &raw) {
                Ok(v) => observed_from_verdict(&v),
                Err(_) => Observed::Blocked,
            }
        }),
    });

    suite
}

/// Runs the confusion-matrix suite, prints the per-scenario table, and
/// asserts zero false positives / false negatives.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn end_to_end_confusion_matrix_has_no_false_negatives_or_false_positives() {
    let mut tp = 0u32;
    let mut tn = 0u32;
    let mut fp: Vec<&'static str> = Vec::new();
    let mut fn_: Vec<&'static str> = Vec::new();
    println!(
        "\n{:<3} {:<64} {:<8} {:<8} class",
        "#", "scenario", "expected", "observed"
    );
    println!("{}", "-".repeat(100));
    for (idx, scn) in scenarios().into_iter().enumerate() {
        let observed = (scn.run)();
        let class = classify(scn.expected, observed);
        println!(
            "{:<3} {:<64} {:<8} {:<8} {:?}",
            idx + 1,
            scn.name,
            format!("{:?}", scn.expected),
            format!("{:?}", observed),
            class
        );
        match class {
            Class::TP => tp += 1,
            Class::TN => tn += 1,
            Class::FP => fp.push(scn.name),
            Class::FN => fn_.push(scn.name),
        }
    }
    println!("{}", "-".repeat(100));
    println!("Totals: TP={tp}  TN={tn}  FP={}  FN={}\n", fp.len(), fn_.len());

    assert!(
        fn_.is_empty(),
        "SECURITY: {} false negative(s) — policy failed to block: {:?}",
        fn_.len(),
        fn_
    );
    assert!(
        fp.is_empty(),
        "REGRESSION: {} false positive(s) — legitimate work was blocked: {:?}",
        fp.len(),
        fp
    );
    // Sanity: we must exercise both positives and negatives, otherwise the
    // matrix is degenerate.
    assert!(tp >= 3, "expected several TP scenarios, got {tp}");
    assert!(tn >= 3, "expected several TN scenarios, got {tn}");
}
