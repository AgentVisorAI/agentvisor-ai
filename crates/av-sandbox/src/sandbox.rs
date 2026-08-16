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
        /// Round-33 F1: payout amount (USD micros) that
        /// `ActionBudget::try_tool_call` debited on this call. Threaded
        /// out so a lost `execution.claim()` race in the harness can
        /// call [`ActionBudget::refund_tool_call`] with the exact same
        /// amount, closing the round-32 F3 concurrent-MCP budget
        /// double-spend.
        payout_micros: u64,
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
            let v = jsonschema::validator_for(schema)
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
        let started = std::time::Instant::now();
        let elapsed = |s: std::time::Instant| u64::try_from(s.elapsed().as_micros()).unwrap_or(u64::MAX);

        // Gate 1: parse.
        let req = match parse_tool_call(raw) {
            Ok(r) => r,
            Err(e) => {
                let (stage, reason) = match &e {
                    RpcError::NotToolCall(_) => ("parse", format!("passthrough refused: {e}")),
                    _ => ("parse", e.to_string()),
                };
                return ToolVerdict::Blocked {
                    tool: "<unparsed>".into(),
                    stage,
                    reason: reason.clone(),
                    response: authorization_error(None, &reason),
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
        match budget.try_tool_call(&req.tool, payout_micros) {
            Ok(BudgetDecision::Allowed { remaining }) => ToolVerdict::Allowed {
                tool: req.tool,
                budget_remaining: remaining,
                elapsed_us: elapsed(started),
                // Round-33 F1: thread the actual debited amount so the
                // harness can refund exactly this much on a lost
                // execution.claim() race.
                payout_micros,
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
        let v = sandbox().check(
            &store,
            "s",
            &raw_call("db_write", json!({"table": "t", "row": {}})),
        );
        assert!(v.is_allowed(), "{v:?}");
        // R23: block/allow decision < 5ms = 5000µs.
        assert!(v.elapsed_us() < 5_000, "decision took {}µs", v.elapsed_us());
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
