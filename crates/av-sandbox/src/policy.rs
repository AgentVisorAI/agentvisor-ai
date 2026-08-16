//! Policy engines: the trait + native Rust rules.

use serde_json::Value;

/// A policy verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    /// Allow the call.
    Allow,
    /// Deny with a reason (returned to the agent in the authorization error).
    Deny {
        /// Machine-readable reason.
        reason: String,
    },
}

/// A policy engine evaluates (tool, arguments) → decision. Engines must be
/// total: any internal failure is a `Deny` (fail-closed), never a panic.
pub trait PolicyEngine: Send + Sync {
    /// Engine name (for events/metrics).
    fn name(&self) -> &str;
    /// Evaluate a tool call.
    fn evaluate(&self, tool: &str, arguments: &Value) -> PolicyDecision;
}

/// Native policy: closure-based rules (the zero-dependency default).
pub struct NativePolicy {
    name: String,
    #[allow(clippy::type_complexity)]
    rule: Box<dyn Fn(&str, &Value) -> PolicyDecision + Send + Sync>,
}

impl NativePolicy {
    /// Build from a rule closure.
    pub fn new(
        name: impl Into<String>,
        rule: impl Fn(&str, &Value) -> PolicyDecision + Send + Sync + 'static,
    ) -> Self {
        Self {
            name: name.into(),
            rule: Box::new(rule),
        }
    }

    /// Deny-list policy: block the named tools outright.
    pub fn deny_tools(tools: &[&str]) -> Self {
        let denied: Vec<String> = tools.iter().map(|s| (*s).to_owned()).collect();
        Self::new("deny_tools", move |tool, _| {
            if denied.iter().any(|d| d == tool) {
                PolicyDecision::Deny {
                    reason: format!("tool {tool:?} is deny-listed"),
                }
            } else {
                PolicyDecision::Allow
            }
        })
    }

    /// Allow-list policy: only the named tools may run.
    pub fn allow_only(tools: &[&str]) -> Self {
        let allowed: Vec<String> = tools.iter().map(|s| (*s).to_owned()).collect();
        Self::new("allow_only", move |tool, _| {
            if allowed.iter().any(|a| a == tool) {
                PolicyDecision::Allow
            } else {
                PolicyDecision::Deny {
                    reason: format!("tool {tool:?} is not allow-listed"),
                }
            }
        })
    }
}

impl PolicyEngine for NativePolicy {
    fn name(&self) -> &str {
        &self.name
    }

    fn evaluate(&self, tool: &str, arguments: &Value) -> PolicyDecision {
        (self.rule)(tool, arguments)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use serde_json::json;

    #[test]
    fn deny_list() {
        let p = NativePolicy::deny_tools(&["drop_database", "send_wire"]);
        assert_eq!(p.evaluate("search", &json!({})), PolicyDecision::Allow);
        assert!(matches!(
            p.evaluate("drop_database", &json!({})),
            PolicyDecision::Deny { .. }
        ));
    }

    #[test]
    fn allow_list() {
        let p = NativePolicy::allow_only(&["search", "read_file"]);
        assert_eq!(p.evaluate("search", &json!({})), PolicyDecision::Allow);
        assert!(matches!(
            p.evaluate("db_write", &json!({})),
            PolicyDecision::Deny { .. }
        ));
    }

    #[test]
    fn custom_argument_rule() {
        let p = NativePolicy::new("payout_ceiling", |tool, args| {
            if tool == "payout" && args.get("amount_usd").and_then(Value::as_f64).unwrap_or(0.0) > 50.0 {
                PolicyDecision::Deny {
                    reason: "single payout above $50".into(),
                }
            } else {
                PolicyDecision::Allow
            }
        });
        assert_eq!(
            p.evaluate("payout", &json!({"amount_usd": 49.0})),
            PolicyDecision::Allow
        );
        assert!(matches!(
            p.evaluate("payout", &json!({"amount_usd": 51.0})),
            PolicyDecision::Deny { .. }
        ));
    }

    #[test]
    fn native_policy_name_returns_the_registered_string() {
        // Catches `name -> ""` and `name -> "xyzzy"` stubs: the returned
        // string must match what the constructor was given.
        let a = NativePolicy::deny_tools(&["x"]);
        assert_eq!(a.name(), "deny_tools");
        let b = NativePolicy::allow_only(&["x"]);
        assert_eq!(b.name(), "allow_only");
        let c = NativePolicy::new("payout_ceiling", |_, _| PolicyDecision::Allow);
        assert_eq!(c.name(), "payout_ceiling");
    }
}
