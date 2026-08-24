//! The sandbox pipeline: parse → schema → policy → budget, with timing.

use crate::policy::{PolicyDecision, PolicyEngine};
use crate::rpc::{authorization_error, parse_tool_call, RpcError};
use av_state::{ActionBudget, BudgetDecision, BudgetSpec, StateStore};
use serde_json::Value;
use std::collections::HashMap;

/// Sandbox configuration.
pub struct SandboxConfig {
    /// Per-tool JSON Schemas for argument validation.
    pub schemas: HashMap<String, Value>,
    /// Action budget spec applied per session.
    pub budget: BudgetSpec,
    /// Argument field carrying a payout amount in USD (e.g. `amount_usd`).
    /// When present on a call, it is charged against `max_payout_usd_micros`.
    pub payout_field: String,
    /// Reject tools without a configured schema.
    pub require_schema: bool,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            schemas: HashMap::new(),
            budget: BudgetSpec::default(),
            payout_field: "amount_usd".into(),
            require_schema: false,
        }
    }
}

/// Verdict for one intercepted tool call.
#[derive(Debug)]
pub enum ToolVerdict {
    /// Forward to the downstream tool server.
    Allowed {
        /// Tool name.
        tool: String,
        /// Remaining headroom under the binding budget dimension.
        budget_remaining: u64,
        /// Decision latency in microseconds (SLA surface, R23).
        elapsed_us: u64,
        /// Payout amount (USD micros) that
        /// `ActionBudget::try_tool_call` debited on this call. Threaded
        /// out so a lost `execution.claim()` race in the harness can
        /// call [`ActionBudget::refund_tool_call`] with the exact same
        /// amount, closing the concurrent-MCP budget
        /// double-spend.
        payout_micros: u64,
        /// Principal id whose ledger was ALSO debited (when a
        /// principal-scoped budget is bound). Threaded out so every
        /// harness failure path that refunds the session ledger can
        /// mirror the refund on the principal ledger — without this,
        /// each lost claim race / saturated worker permanently consumed
        /// principal quota with zero tools executed.
        principal_id: Option<String>,
    },
    /// Block; respond to the agent with `response`.
    Blocked {
        /// Tool name (`<unparsed>` when the payload never parsed).
        tool: String,
        /// Which gate blocked: `parse` | `schema` | `policy` | `budget`.
        stage: &'static str,
        /// Human/machine-readable reason.
        reason: String,
        /// Ready-to-send JSON-RPC authorization error.
        response: Value,
        /// Decision latency in microseconds.
        elapsed_us: u64,
    },
}

impl ToolVerdict {
    /// True when the call may proceed.
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed { .. })
    }

    /// Decision latency in microseconds.
    pub fn elapsed_us(&self) -> u64 {
        match self {
            Self::Allowed { elapsed_us, .. } | Self::Blocked { elapsed_us, .. } => *elapsed_us,
        }
    }
}

/// The sandbox: compiled schemas + policy chain + budget spec.
pub struct Sandbox {
    validators: HashMap<String, jsonschema::Validator>,
    policies: Vec<Box<dyn PolicyEngine>>,
    config: SandboxConfig,
}

impl Sandbox {
    /// Build a sandbox, compiling every tool schema up front (a schema that
    /// fails to compile is a configuration error surfaced at boot, not a
    /// silently-skipped validation at request time).
    pub fn new(config: SandboxConfig, policies: Vec<Box<dyn PolicyEngine>>) -> Result<Self, String> {
        let mut validators = HashMap::new();
        for (tool, schema) in &config.schemas {
            // Enforce `format` keywords. In
            // jsonschema 0.49 / draft 2020-12, `format` is
            // annotation-only unless opted in — an operator writing
            // `"format": "uri"` into a tool-argument schema expected an
            // enforced gate, not a no-op.
            let v = jsonschema::options()
                .should_validate_formats(true)
                .build(schema)
                .map_err(|e| format!("schema for tool {tool:?} does not compile: {e}"))?;
            validators.insert(tool.clone(), v);
        }
        Ok(Self {
            validators,
            policies,
            config,
        })
    }

    /// Evaluate a raw MCP payload for `session`.
    pub fn check(&self, store: &dyn StateStore, session: &str, raw: &[u8]) -> ToolVerdict {
        self.check_with_principal(store, session, None, raw)
    }

    /// Same as [`Self::check`] but layers a principal-scoped budget check
    /// on top of the session-scoped one. When `principal` is `Some(spec)`,
    /// the tool call is refused unless BOTH ledgers admit the spend; the
    /// principal ledger persists across every session belonging to the
    /// same identity, which is what makes header-rotation attacks
    /// (resetting the session bucket by minting a new session id)
    /// visible.
    ///
    /// The two ledgers commit independently: if the principal check
    /// passes and the session check fails, the principal debit is
    /// refunded on the same dimensions before returning. Both budgets
    /// must use identical `BudgetSpec` shapes so the refund is exact.
    pub fn check_with_principal(
        &self,
        store: &dyn StateStore,
        session: &str,
        principal: Option<(&str, &BudgetSpec)>,
        raw: &[u8],
    ) -> ToolVerdict {
        let started = std::time::Instant::now();
        let elapsed = |s: std::time::Instant| u64::try_from(s.elapsed().as_micros()).unwrap_or(u64::MAX);

        // Gate 1: parse.
        let req = match parse_tool_call(raw) {
            Ok(r) => r,
            Err(e) => {
                let (stage, reason) = match &e {
                    // Passthrough refusal parsed fine as JSON-RPC — a
                    // deliberate policy choice, distinct HTTP class
                    // (403) from true protocol failures (400).
                    RpcError::NotToolCall(_) => ("passthrough", format!("passthrough refused: {e}")),
                    _ => ("parse", e.to_string()),
                };
                // Protocol-level failures
                // get the reserved JSON-RPC codes (-32700/-32600/
                // -32602), not the -32001 policy code — the request
                // never reached an authorization decision. The id is
                // echoed whenever the envelope made it detectable
                // (JSON-RPC 2.0 §5; see `detectable_error_id`).
                let id = crate::rpc::detectable_error_id(raw, &e);
                return ToolVerdict::Blocked {
                    tool: "<unparsed>".into(),
                    stage,
                    reason,
                    response: crate::rpc::protocol_error(id.as_ref(), &e),
                    elapsed_us: elapsed(started),
                };
            }
        };

        // Gate 2: schema.
        if let Some(validator) = self.validators.get(&req.tool) {
            // Bounded work: a hostile client cannot force unbounded String
            // allocation by sending pathologically-invalid arguments.
            let errors: Vec<String> = validator
                .iter_errors(&req.arguments)
                .take(3)
                .map(|e| e.to_string())
                .collect();
            if !errors.is_empty() {
                let reason = format!("schema validation failed: {}", errors.join("; "));
                return ToolVerdict::Blocked {
                    tool: req.tool.clone(),
                    stage: "schema",
                    reason: reason.clone(),
                    response: authorization_error(req.id.as_ref(), &reason),
                    elapsed_us: elapsed(started),
                };
            }
        } else if self.config.require_schema {
            let reason = format!("no argument schema configured for tool {:?}", req.tool);
            return ToolVerdict::Blocked {
                tool: req.tool.clone(),
                stage: "schema",
                reason: reason.clone(),
                response: authorization_error(req.id.as_ref(), &reason),
                elapsed_us: elapsed(started),
            };
        }

        // Gate 3: policy chain (first deny wins).
        for policy in &self.policies {
            if let PolicyDecision::Deny { reason } = policy.evaluate(&req.tool, &req.arguments) {
                let reason = format!("policy {:?}: {reason}", policy.name());
                return ToolVerdict::Blocked {
                    tool: req.tool.clone(),
                    stage: "policy",
                    reason: reason.clone(),
                    response: authorization_error(req.id.as_ref(), &reason),
                    elapsed_us: elapsed(started),
                };
            }
        }

        // Gate 4: budget (atomic check-and-spend).
        let payout_micros = match extract_payout_micros(&req.arguments, &self.config.payout_field) {
            Ok(m) => m,
            Err(reason) => {
                return ToolVerdict::Blocked {
                    tool: req.tool.clone(),
                    stage: "budget",
                    reason: reason.clone(),
                    response: authorization_error(req.id.as_ref(), &reason),
                    elapsed_us: elapsed(started),
                }
            }
        };
        let budget = ActionBudget::new(store, session, &self.config.budget);
        // Principal-scoped pre-check. Debit the principal ledger
        // first — a header-rotation attack that resets the session bucket
        // still charges the same principal. If the principal ledger admits
        // the spend but the session ledger refuses, we refund the principal
        // debit before returning so the failed call consumed no quota
        // anywhere.
        if let Some((principal_id, principal_spec)) = principal {
            let principal_budget = ActionBudget::for_principal(store, principal_id, principal_spec);
            match principal_budget.try_tool_call(&req.tool, payout_micros) {
                Ok(BudgetDecision::Allowed { .. }) => {}
                Ok(BudgetDecision::Refused { limit, cap }) => {
                    let reason = format!("principal action budget exceeded: {limit} (cap {cap})");
                    return ToolVerdict::Blocked {
                        tool: req.tool.clone(),
                        stage: "budget",
                        reason: reason.clone(),
                        response: authorization_error(req.id.as_ref(), &reason),
                        elapsed_us: elapsed(started),
                    };
                }
                Err(e) => {
                    let reason = format!("principal budget check failed closed: {e}");
                    return ToolVerdict::Blocked {
                        tool: req.tool.clone(),
                        stage: "budget",
                        reason: reason.clone(),
                        response: authorization_error(req.id.as_ref(), &reason),
                        elapsed_us: elapsed(started),
                    };
                }
            }
            match budget.try_tool_call(&req.tool, payout_micros) {
                Ok(BudgetDecision::Allowed { remaining }) => {
                    return ToolVerdict::Allowed {
                        tool: req.tool,
                        budget_remaining: remaining,
                        elapsed_us: elapsed(started),
                        payout_micros,
                        principal_id: Some(principal_id.to_owned()),
                    };
                }
                Ok(BudgetDecision::Refused { limit, cap }) => {
                    // Session refused; unwind the principal debit so a
                    // failed call is fully non-consumptive.
                    principal_budget.refund_tool_call(&req.tool, payout_micros);
                    let reason = format!("action budget exceeded: {limit} (cap {cap})");
                    return ToolVerdict::Blocked {
                        tool: req.tool.clone(),
                        stage: "budget",
                        reason: reason.clone(),
                        response: authorization_error(req.id.as_ref(), &reason),
                        elapsed_us: elapsed(started),
                    };
                }
                Err(e) => {
                    principal_budget.refund_tool_call(&req.tool, payout_micros);
                    let reason = format!("budget check failed closed: {e}");
                    return ToolVerdict::Blocked {
                        tool: req.tool.clone(),
                        stage: "budget",
                        reason: reason.clone(),
                        response: authorization_error(req.id.as_ref(), &reason),
                        elapsed_us: elapsed(started),
                    };
                }
            }
        }
        match budget.try_tool_call(&req.tool, payout_micros) {
            Ok(BudgetDecision::Allowed { remaining }) => ToolVerdict::Allowed {
                tool: req.tool,
                budget_remaining: remaining,
                elapsed_us: elapsed(started),
                // Thread the actual debited amount so the
                // harness can refund exactly this much on a lost
                // execution.claim() race.
                payout_micros,
                principal_id: None,
            },
            Ok(BudgetDecision::Refused { limit, cap }) => {
                let reason = format!("action budget exceeded: {limit} (cap {cap})");
                ToolVerdict::Blocked {
                    tool: req.tool.clone(),
                    stage: "budget",
                    reason: reason.clone(),
                    response: authorization_error(req.id.as_ref(), &reason),
                    elapsed_us: elapsed(started),
                }
            }
            Err(e) => {
                // State-store failure fails closed.
                let reason = format!("budget check failed closed: {e}");
                ToolVerdict::Blocked {
                    tool: req.tool.clone(),
                    stage: "budget",
                    reason: reason.clone(),
                    response: authorization_error(req.id.as_ref(), &reason),
                    elapsed_us: elapsed(started),
                }
            }
        }
    }

    /// Evaluate an arbitrary operation payload against the configured native
    /// and WASM policy chain. Used for chat sanitization before compression.
    pub fn sanitize(&self, operation: &str, payload: &Value) -> Result<(), String> {
        for policy in &self.policies {
            if let PolicyDecision::Deny { reason } = policy.evaluate(operation, payload) {
                return Err(format!("policy {:?}: {reason}", policy.name()));
            }
        }
        Ok(())
    }
}

/// Extract a payout amount (USD float or integer) as micro-USD. Rejects
/// negatives, NaN/Inf, and absurd magnitudes rather than truncating silently.
fn extract_payout_micros(arguments: &Value, field: &str) -> Result<u64, String> {
    let Some(v) = arguments.get(field) else {
        return Ok(0);
    };
    let usd = v.as_f64().ok_or_else(|| format!("{field} must be a number"))?;
    if !usd.is_finite() || usd < 0.0 {
        return Err(format!("{field} must be a finite non-negative number, got {usd}"));
    }
    if usd > 1.0e12 {
        return Err(format!("{field} of {usd} exceeds sanity bounds"));
    }
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    Ok((usd * av_core::units::USD_MICROS_PER_DOLLAR as f64).round() as u64)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]

    use super::*;
    use crate::policy::NativePolicy;
    use av_state::InMemoryStore;
    use serde_json::json;

    fn raw_call(tool: &str, args: Value) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": tool, "arguments": args}
        }))
        .unwrap()
    }

    fn sandbox() -> Sandbox {
        let mut schemas = HashMap::new();
        schemas.insert(
            "db_write".to_owned(),
            json!({
                "type": "object",
                "required": ["table", "row"],
                "properties": {
                    "table": {"type": "string", "minLength": 1},
                    "row": {"type": "object"}
                },
                "additionalProperties": false
            }),
        );
        let budget = BudgetSpec {
            max_tool_calls: [("db_write".to_owned(), 3)].into_iter().collect(),
            max_payout_usd_micros: Some(50_000_000),
            max_total_tool_calls: Some(100),
            max_tokens: None,
        };
        Sandbox::new(
            SandboxConfig {
                schemas,
                budget,
                payout_field: "amount_usd".into(),
                require_schema: false,
            },
            vec![Box::new(NativePolicy::deny_tools(&["rm_rf"]))],
        )
        .unwrap()
    }

    #[test]
    fn valid_call_allowed_with_latency() {
        let store = InMemoryStore::new();
        let sandbox = sandbox();
        let v = sandbox.check(
            &store,
            "s",
            &raw_call("db_write", json!({"table": "t", "row": {}})),
        );
        assert!(v.is_allowed(), "{v:?}");
        // R23: block/allow decision < 5ms = 5000µs. A single debug-profile
        // sample flakes under full-suite load (scheduler preemption between
        // the two Instant reads), so take the minimum over several runs:
        // one clean time slice is enough for a genuinely fast decision,
        // while a real regression stays slow on every sample. Distinct
        // sessions keep the per-session db_write budget (3) out of play.
        // The release SLA gate and criterion bench own the authoritative
        // measurement.
        let min_elapsed_us = (0..10)
            .map(|i| {
                let verdict = sandbox.check(
                    &store,
                    &format!("s-latency-{i}"),
                    &raw_call("db_write", json!({"table": "t", "row": {}})),
                );
                assert!(verdict.is_allowed(), "{verdict:?}");
                verdict.elapsed_us()
            })
            .min()
            .unwrap_or(u64::MAX);
        assert!(min_elapsed_us < 5_000, "fastest decision took {min_elapsed_us}µs");
    }

    #[test]
    fn schema_invalid_blocked() {
        let store = InMemoryStore::new();
        let s = sandbox();
        // Missing required field.
        let v = s.check(&store, "s", &raw_call("db_write", json!({"table": "t"})));
        match &v {
            ToolVerdict::Blocked { stage, response, .. } => {
                assert_eq!(*stage, "schema");
                assert_eq!(response["error"]["code"], -32001);
            }
            other => panic!("{other:?}"),
        }
        // Type confusion.
        let v = s.check(
            &store,
            "s",
            &raw_call("db_write", json!({"table": 42, "row": {}})),
        );
        assert!(!v.is_allowed());
        // Extra field (additionalProperties: false).
        let v = s.check(
            &store,
            "s",
            &raw_call("db_write", json!({"table": "t", "row": {}, "backdoor": true})),
        );
        assert!(!v.is_allowed());
    }

    #[test]
    fn policy_denied_blocked() {
        let store = InMemoryStore::new();
        let v = sandbox().check(&store, "s", &raw_call("rm_rf", json!({})));
        match v {
            ToolVerdict::Blocked { stage, reason, .. } => {
                assert_eq!(stage, "policy");
                assert!(reason.contains("deny-listed"), "{reason}");
            }
            other => panic!("{other:?}"),
        }
    }

    /// JSON-RPC 2.0 §5: parse-gate refusals of a WELL-FORMED envelope
    /// must echo the request id in the error response. Pre-fix the
    /// blocked-response body always carried `id: null`, so SDK
    /// correlation tables never matched and the pending call hung.
    #[test]
    fn blocked_parse_verdict_echoes_the_request_id() {
        let store = InMemoryStore::new();
        let raw = br#"{"jsonrpc":"2.0","id":42,"method":"initialize","params":{}}"#;
        match sandbox().check(&store, "s", raw) {
            ToolVerdict::Blocked {
                response,
                stage,
                reason,
                ..
            } => {
                assert_eq!(response["id"], json!(42), "{response}");
                // Mutation-run hardening (round 8): the passthrough
                // stage label was unpinned — deleting the NotToolCall
                // match arm reclassified passthrough refusals as
                // "parse" failures, corrupting the stage-keyed metrics
                // and events operators alert on.
                assert_eq!(stage, "passthrough");
                assert!(reason.contains("passthrough refused"), "{reason}");
            }
            other => panic!("{other:?}"),
        }
        // Unparseable JSON: the id is undetectable — null stands.
        match sandbox().check(&store, "s", b"not json") {
            ToolVerdict::Blocked { response, stage, .. } => {
                assert_eq!(response["id"], serde_json::Value::Null, "{response}");
                assert_eq!(stage, "parse");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn budget_enforced_across_calls() {
        let store = InMemoryStore::new();
        let s = sandbox();
        let args = json!({"table": "t", "row": {}});
        for _ in 0..3 {
            assert!(s
                .check(&store, "sess", &raw_call("db_write", args.clone()))
                .is_allowed());
        }
        let v = s.check(&store, "sess", &raw_call("db_write", args));
        match v {
            ToolVerdict::Blocked { stage, reason, .. } => {
                assert_eq!(stage, "budget");
                assert!(reason.contains("db_write"), "{reason}");
            }
            other => panic!("{other:?}"),
        }
    }

    /// An `Allowed` verdict must thread the bound principal id out so the
    /// harness's failure paths (lost claim race, saturated worker, close
    /// race) can mirror the session-ledger refund on the principal ledger.
    /// Without it, every failed claim permanently consumed principal quota
    /// with zero tools executed — and the principal ledger persists across
    /// sessions, so that leak never healed. The refund round-trip below is
    /// exactly the compensation the harness performs.
    #[test]
    fn allowed_verdict_threads_principal_id_and_refund_restores_the_ledger() {
        let store = InMemoryStore::new();
        let s = sandbox();
        let args = json!({"amount_usd": 1.0});
        let principal_spec = BudgetSpec {
            max_tool_calls: std::collections::BTreeMap::new(),
            max_payout_usd_micros: Some(50_000_000),
            max_total_tool_calls: Some(1),
            max_tokens: None,
        };
        // No principal bound: field is None.
        match s.check(&store, "sess-a", &raw_call("payout", args.clone())) {
            ToolVerdict::Allowed { principal_id, .. } => assert_eq!(principal_id, None),
            other => panic!("{other:?}"),
        }
        // Principal bound: the verdict carries the id and payout the
        // harness needs for compensation.
        let verdict = s.check_with_principal(
            &store,
            "sess-b",
            Some(("principal-1", &principal_spec)),
            &raw_call("payout", args.clone()),
        );
        let (tool, payout_micros, principal_id) = match verdict {
            ToolVerdict::Allowed {
                tool,
                payout_micros,
                principal_id,
                ..
            } => (tool, payout_micros, principal_id),
            other => panic!("{other:?}"),
        };
        assert_eq!(principal_id.as_deref(), Some("principal-1"));
        assert_eq!(payout_micros, 1_000_000);
        // Simulate the harness failure path: refund BOTH ledgers with the
        // threaded values. With max_total_tool_calls = 1, the next call
        // only admits if the principal refund actually landed.
        ActionBudget::new(&store, "sess-b", &s.config.budget).refund_tool_call(&tool, payout_micros);
        ActionBudget::for_principal(&store, "principal-1", &principal_spec)
            .refund_tool_call(&tool, payout_micros);
        let retry = s.check_with_principal(
            &store,
            "sess-b",
            Some(("principal-1", &principal_spec)),
            &raw_call("payout", args),
        );
        assert!(
            retry.is_allowed(),
            "principal ledger did not heal after the compensating refund: {retry:?}"
        );
    }

    #[test]
    fn payout_cap_enforced_and_hostile_amounts_rejected() {
        let store = InMemoryStore::new();
        let s = sandbox();
        assert!(s
            .check(&store, "p", &raw_call("payout", json!({"amount_usd": 49.5})))
            .is_allowed());
        // Would cross $50 total.
        let v = s.check(&store, "p", &raw_call("payout", json!({"amount_usd": 1.0})));
        assert!(!v.is_allowed(), "{v:?}");
        // Hostile numerics.
        for bad in [
            json!({"amount_usd": -5}),
            json!({"amount_usd": "1e9"}),
            json!({"amount_usd": 1e15}),
        ] {
            let v = s.check(&store, "p2", &raw_call("payout", bad));
            assert!(!v.is_allowed(), "hostile payout accepted: {v:?}");
        }
    }

    #[test]
    fn unparsable_payload_blocked_at_parse() {
        let store = InMemoryStore::new();
        let v = sandbox().check(&store, "s", b"\xff\xfe not json");
        match v {
            ToolVerdict::Blocked { stage, tool, .. } => {
                assert_eq!(stage, "parse");
                assert_eq!(tool, "<unparsed>");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn tools_without_schema_pass_schema_gate() {
        let store = InMemoryStore::new();
        let v = sandbox().check(&store, "s", &raw_call("search", json!({"anything": [1, 2]})));
        assert!(v.is_allowed(), "{v:?}");
    }

    #[test]
    fn required_schema_mode_blocks_unknown_tools() {
        let sandbox = Sandbox::new(
            SandboxConfig {
                require_schema: true,
                ..SandboxConfig::default()
            },
            Vec::new(),
        )
        .unwrap();
        let verdict = sandbox.check(&InMemoryStore::new(), "session", &raw_call("unknown", json!({})));
        assert!(matches!(verdict, ToolVerdict::Blocked { stage: "schema", .. }));
    }

    #[test]
    fn bad_boot_schema_is_a_boot_error() {
        let mut schemas = HashMap::new();
        schemas.insert("t".to_owned(), json!({"type": "not-a-type"}));
        let err = Sandbox::new(
            SandboxConfig {
                schemas,
                ..SandboxConfig::default()
            },
            vec![],
        );
        assert!(err.is_err(), "invalid schema must fail at boot, not be skipped");
    }

    #[test]
    fn chat_payload_uses_the_same_policy_chain() {
        let sandbox = Sandbox::new(
            SandboxConfig::default(),
            vec![Box::new(NativePolicy::new("no-secret", |operation, payload| {
                if operation == "chat/completions" && payload.to_string().contains("secret") {
                    PolicyDecision::Deny {
                        reason: "secret content".into(),
                    }
                } else {
                    PolicyDecision::Allow
                }
            }))],
        )
        .unwrap();
        assert!(sandbox
            .sanitize("chat/completions", &json!({"messages": ["safe"]}))
            .is_ok());
        assert!(sandbox
            .sanitize("chat/completions", &json!({"messages": ["secret"]}))
            .is_err());
    }
}

#[cfg(test)]
mod payout_boundary_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use serde_json::json;

    /// Mutation-run hardening: pin the payout parser's exact
    /// bounds. `usd < 0.0` -> `<=` would refuse a legitimate zero payout;
    /// `usd > 1.0e12` -> `>=`/`==` shift or invert the sanity ceiling.
    #[test]
    fn payout_bounds_are_exact() {
        let extract = |v: serde_json::Value| extract_payout_micros(&json!({"amount_usd": v}), "amount_usd");
        assert_eq!(extract(json!(0.0)).unwrap(), 0, "zero payout is legitimate");
        assert_eq!(
            extract(json!(1.0e12)).unwrap(),
            1_000_000_000_000_u64 * av_core::units::USD_MICROS_PER_DOLLAR,
            "the sanity ceiling itself is accepted"
        );
        let over = extract(json!(2.0e12));
        assert!(
            matches!(over, Err(ref m) if m.contains("sanity")),
            "past the ceiling must be refused, got {over:?}"
        );
        let negative = extract(json!(-0.25));
        assert!(matches!(negative, Err(ref m) if m.contains("non-negative")));
    }
}
