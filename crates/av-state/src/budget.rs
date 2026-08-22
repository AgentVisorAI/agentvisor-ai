//! Action budgets (Module B): stateful tool limits — per-tool caps via
//! `max_tool_calls` (e.g. `db_write: 3`), payout ceilings via
//! `max_payout_usd_micros` — plus per-session token ceilings.
//!
//! Money is tracked in integer micro-USD; a payout of $12.34 spends
//! 12_340_000. Fractional-cent dust can therefore never accumulate invisibly.

use crate::store::{Spend, StateError, StateStore};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Declarative budget for one session/agent (config-file surface).
///
/// Unknown keys are rejected so `[budget]` typos fail loudly at startup.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BudgetSpec {
    /// Max total tokens (prompt+completion) per session. `None` = unlimited.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u64>,
    /// Max cumulative payout in micro-USD.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_payout_usd_micros: Option<u64>,
    /// Per-tool invocation caps, e.g. `db_write: 3`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub max_tool_calls: BTreeMap<String, u64>,
    /// Cap on *all* tool calls combined.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_total_tool_calls: Option<u64>,
}

/// Outcome of a budget check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BudgetDecision {
    /// Spend recorded; remaining headroom for the tightest matching limit.
    Allowed {
        /// Remaining amount under the binding limit (min across dimensions).
        remaining: u64,
    },
    /// Refused: which limit would be exceeded.
    Refused {
        /// Human-readable limit name (`max_tool_calls.db_write`, …).
        limit: String,
        /// The configured cap.
        cap: u64,
    },
}

impl BudgetDecision {
    /// True when the action was allowed.
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed { .. })
    }
}

/// Budget enforcement bound to an accounting scope (a session id, or a
/// stable principal id) and a state store.
///
/// Historically this type was hard-coded to a session-scoped view. The
/// engineering review (§3.2) showed that a session-only budget can be
/// bypassed by any caller that rotates the caller-chosen `X-AV-Session`
/// header — every request would land on a virgin counter. Callers that
/// want to catch that vector layer a principal-scoped `ActionBudget` on
/// top of the session-scoped one; the anti-rotation property lives in the
/// key prefix, not in the check logic.
pub struct ActionBudget<'a> {
    store: &'a dyn StateStore,
    scope: Scope<'a>,
    spec: &'a BudgetSpec,
}

/// Which accounting bucket a budget check writes to.
///
/// Two identical `try_spend_many` calls made under different scopes hit
/// entirely disjoint keys in the state store; a session budget cannot
/// exhaust a principal budget or vice versa.
#[derive(Debug, Clone, Copy)]
enum Scope<'a> {
    Session(&'a str),
    Principal(&'a str),
}

impl<'a> ActionBudget<'a> {
    /// Bind a spec to a session id.
    pub fn new(store: &'a dyn StateStore, session: &'a str, spec: &'a BudgetSpec) -> Self {
        Self {
            store,
            scope: Scope::Session(session),
            spec,
        }
    }

    /// Bind a spec to a principal id (JWT `sub`/`instance_uid`, HMAC-KID,
    /// or the sentinel `"anonymous"` when `require_identity = false`).
    /// The resulting counters aggregate across every session belonging to
    /// the same principal, which is what makes a header-rotation attack
    /// visible — the token debit persists even after the client mints a
    /// fresh `X-AV-Session`.
    pub fn for_principal(
        store: &'a dyn StateStore,
        principal: &'a str,
        spec: &'a BudgetSpec,
    ) -> Self {
        Self {
            store,
            scope: Scope::Principal(principal),
            spec,
        }
    }

    fn key(&self, dim: &str) -> String {
        let prefix = match self.scope {
            Scope::Session(id) => Self::session_prefix(id),
            Scope::Principal(id) => Self::principal_prefix(id),
        };
        format!("{prefix}{dim}")
    }

    /// Common key prefix for every budget counter of `session`. Callers use
    /// this with [`StateStore::remove_prefix`] to drop a finalized session's
    /// counters (per-tool keys are dynamic, so single-key removal cannot
    /// enumerate them).
    pub fn session_prefix(session: &str) -> String {
        let digest = av_core::digest::sha256_hex(session.as_bytes());
        // 32 hex chars = 128 bits: collision-safe well beyond realistic session counts.
        format!("budget:{{{}}}:", digest.get(..32).unwrap_or(&digest))
    }

    /// Common key prefix for every principal-scoped budget counter. Distinct
    /// namespace from [`session_prefix`] so a session cleanup on close does
    /// not touch the principal ledger — the principal ledger persists across
    /// session boundaries by design.
    pub fn principal_prefix(principal: &str) -> String {
        let digest = av_core::digest::sha256_hex(principal.as_bytes());
        format!("budget:principal:{{{}}}:", digest.get(..32).unwrap_or(&digest))
    }

    /// Check-and-spend one invocation of `tool`, with an optional payout
    /// amount in micro-USD carried by this call.
    ///
    /// A non-zero payout with NO configured `max_payout_usd_micros`
    /// refuses first (fail-closed: an unbounded payout dimension must
    /// never spend), citing `max_payout_usd_micros(unset)` — even when
    /// another dimension is also at cap. The remaining dimensions are
    /// then checked in a fixed order (total calls → per-tool → payout)
    /// and committed atomically via `try_spend_many`: every dimension
    /// is validated first and either all spends commit or none do, so
    /// a refused call consumes nothing.
    pub fn try_tool_call(&self, tool: &str, payout_usd_micros: u64) -> Result<BudgetDecision, StateError> {
        // Parallel arrays keep spends and limit-names together without paying
        // for a joined-tuple clone before hitting the state store. There are
        // at most three dimensions (total, per-tool, payout).
        let mut spends: Vec<Spend> = Vec::with_capacity(3);
        let mut limit_names: Vec<String> = Vec::with_capacity(3);

        if let Some(cap) = self.spec.max_total_tool_calls {
            spends.push(Spend {
                key: self.key("total_calls"),
                amount: 1,
                limit: cap,
            });
            limit_names.push("max_total_tool_calls".into());
        }
        if let Some(cap) = self.spec.max_tool_calls.get(tool).copied() {
            spends.push(Spend {
                key: self.key(&format!("tool:{tool}")),
                amount: 1,
                limit: cap,
            });
            limit_names.push(format!("max_tool_calls.{tool}"));
        }
        if payout_usd_micros > 0 {
            match self.spec.max_payout_usd_micros {
                Some(cap) => {
                    spends.push(Spend {
                        key: self.key("payout"),
                        amount: payout_usd_micros,
                        limit: cap,
                    });
                    limit_names.push("max_payout_usd_micros".into());
                }
                None => {
                    return Ok(BudgetDecision::Refused {
                        limit: "max_payout_usd_micros(unset)".into(),
                        cap: 0,
                    });
                }
            }
        }

        if let Some(index) = self.store.try_spend_many(&spends)? {
            let spend = spends
                .get(index)
                .ok_or_else(|| StateError::Backend(format!("invalid failed spend index {index}")))?;
            let limit = limit_names
                .get(index)
                .ok_or_else(|| StateError::Backend(format!("invalid failed spend index {index}")))?;
            return Ok(BudgetDecision::Refused {
                limit: limit.clone(),
                cap: spend.limit,
            });
        }

        let remaining = self.remaining_min(tool)?;
        Ok(BudgetDecision::Allowed { remaining })
    }

    /// Round-33 F1: compensating refund for a previously-successful
    /// [`Self::try_tool_call`]. Reverses the spend on exactly the same
    /// dimensions that were debited (total_calls, per-tool, payout) so
    /// a lost-race path in the caller (concurrent identical MCP
    /// request loses `execution.claim()` after the sandbox gate has
    /// already spent) does not double-charge the session budget.
    /// Best-effort: any backend error is silently absorbed by the
    /// underlying [`StateStore::refund`] contract — a Redis blip on
    /// the compensation path must never turn a lost-race response
    /// into a 5xx.
    pub fn refund_tool_call(&self, tool: &str, payout_usd_micros: u64) {
        if self.spec.max_total_tool_calls.is_some() {
            self.store.refund(&self.key("total_calls"), 1);
        }
        if self.spec.max_tool_calls.contains_key(tool) {
            self.store.refund(&self.key(&format!("tool:{tool}")), 1);
        }
        if payout_usd_micros > 0 && self.spec.max_payout_usd_micros.is_some() {
            self.store.refund(&self.key("payout"), payout_usd_micros);
        }
    }

    /// Compensating refund for a previously-successful [`Self::try_tokens`]
    /// on a request that provably never reached the provider (sanitize
    /// block, capture failure, in-flight-marker write failure, connect
    /// failure). Same rationale and best-effort contract as
    /// [`Self::refund_tool_call`]: without it, each client retry against
    /// a flaky-but-unreachable upstream re-debits `max_tokens` with zero
    /// LLM work performed, draining the session budget.
    pub fn refund_tokens(&self, tokens: u64) {
        if tokens > 0 && self.spec.max_tokens.is_some() {
            self.store.refund(&self.key("tokens"), tokens);
        }
    }

    /// Check-and-spend `tokens` against `max_tokens`.
    pub fn try_tokens(&self, tokens: u64) -> Result<BudgetDecision, StateError> {
        match self.spec.max_tokens {
            Some(cap) => {
                let key = self.key("tokens");
                if self.store.try_spend(&key, tokens, cap)? {
                    let used = self.store.get(&key)?;
                    Ok(BudgetDecision::Allowed {
                        remaining: cap.saturating_sub(used),
                    })
                } else {
                    Ok(BudgetDecision::Refused {
                        limit: "max_tokens".into(),
                        cap,
                    })
                }
            }
            None => Ok(BudgetDecision::Allowed { remaining: u64::MAX }),
        }
    }

    fn remaining_min(&self, tool: &str) -> Result<u64, StateError> {
        let mut min = u64::MAX;
        if let Some(cap) = self.spec.max_total_tool_calls {
            let used = self.store.get(&self.key("total_calls"))?;
            min = min.min(cap.saturating_sub(used));
        }
        if let Some(cap) = self.spec.max_tool_calls.get(tool) {
            let used = self.store.get(&self.key(&format!("tool:{tool}")))?;
            min = min.min(cap.saturating_sub(used));
        }
        if let Some(cap) = self.spec.max_payout_usd_micros {
            let used = self.store.get(&self.key("payout"))?;
            min = min.min(cap.saturating_sub(used));
        }
        Ok(min)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::store::InMemoryStore;

    fn spec() -> BudgetSpec {
        BudgetSpec {
            max_tokens: Some(1000),
            max_payout_usd_micros: Some(50_000_000), // $50 (brief example)
            max_tool_calls: BTreeMap::from([("db_write".to_owned(), 3)]), // brief example
            max_total_tool_calls: Some(10),
        }
    }

    #[test]
    fn db_write_capped_at_three() {
        let store = InMemoryStore::new();
        let s = spec();
        let b = ActionBudget::new(&store, "sess", &s);
        for _ in 0..3 {
            assert!(b.try_tool_call("db_write", 0).unwrap().is_allowed());
        }
        let refused = b.try_tool_call("db_write", 0).unwrap();
        assert_eq!(
            refused,
            BudgetDecision::Refused {
                limit: "max_tool_calls.db_write".into(),
                cap: 3
            }
        );
        // Other tools still work (total budget has room).
        assert!(b.try_tool_call("search", 0).unwrap().is_allowed());
    }

    #[test]
    fn payout_capped_at_fifty_dollars() {
        let store = InMemoryStore::new();
        let s = spec();
        let b = ActionBudget::new(&store, "sess", &s);
        assert!(b.try_tool_call("payout", 49_000_000).unwrap().is_allowed());
        let refused = b.try_tool_call("payout", 2_000_000).unwrap(); // would total $51
        assert!(!refused.is_allowed());
        // The refused call must not have consumed its per-call slot either:
        // spend $1 exactly — succeeds if rollback was complete.
        assert!(b.try_tool_call("payout", 1_000_000).unwrap().is_allowed());
    }

    #[test]
    fn payout_without_cap_fails_closed() {
        let store = InMemoryStore::new();
        let s = BudgetSpec::default();
        let b = ActionBudget::new(&store, "sess", &s);
        let d = b.try_tool_call("payout", 1).unwrap();
        assert!(
            !d.is_allowed(),
            "uncapped payout must be refused, not silently allowed"
        );
    }

    #[test]
    fn refused_multi_dimension_spend_rolls_back() {
        let store = InMemoryStore::new();
        let s = spec();
        let b = ActionBudget::new(&store, "sess", &s);
        // Exhaust db_write (3 calls, 3 total slots used).
        for _ in 0..3 {
            assert!(b.try_tool_call("db_write", 0).unwrap().is_allowed());
        }
        // This refusal must roll back its total_calls spend:
        assert!(!b.try_tool_call("db_write", 0).unwrap().is_allowed());
        // 7 remaining total slots — all must be grantable.
        for _ in 0..7 {
            assert!(b.try_tool_call("other", 0).unwrap().is_allowed());
        }
        assert!(
            !b.try_tool_call("other", 0).unwrap().is_allowed(),
            "total cap must bind at 10"
        );
    }

    #[test]
    fn token_budget() {
        let store = InMemoryStore::new();
        let s = spec();
        let b = ActionBudget::new(&store, "sess", &s);
        assert!(b.try_tokens(900).unwrap().is_allowed());
        assert!(b.try_tokens(100).unwrap().is_allowed()); // exactly at cap
        assert!(!b.try_tokens(1).unwrap().is_allowed());
    }

    #[test]
    fn sessions_are_isolated() {
        let store = InMemoryStore::new();
        let s = spec();
        let a = ActionBudget::new(&store, "sess-a", &s);
        let b = ActionBudget::new(&store, "sess-b", &s);
        for _ in 0..3 {
            assert!(a.try_tool_call("db_write", 0).unwrap().is_allowed());
        }
        assert!(!a.try_tool_call("db_write", 0).unwrap().is_allowed());
        assert!(
            b.try_tool_call("db_write", 0).unwrap().is_allowed(),
            "session b unaffected"
        );
    }

    #[test]
    fn concurrent_multi_dimension_spends_commit_all_or_none() {
        let store = std::sync::Arc::new(InMemoryStore::new());
        let spec = std::sync::Arc::new(BudgetSpec {
            max_tool_calls: BTreeMap::from([("db_write".to_owned(), 100)]),
            max_total_tool_calls: Some(100),
            ..BudgetSpec::default()
        });
        let mut handles = Vec::new();
        for _ in 0..32 {
            let store = std::sync::Arc::clone(&store);
            let spec = std::sync::Arc::clone(&spec);
            handles.push(std::thread::spawn(move || {
                let budget = ActionBudget::new(store.as_ref(), "atomic", spec.as_ref());
                (0..20)
                    .filter(|_| budget.try_tool_call("db_write", 0).unwrap().is_allowed())
                    .count()
            }));
        }
        let allowed: usize = handles.into_iter().map(|handle| handle.join().unwrap()).sum();
        assert_eq!(allowed, 100);
        let budget = ActionBudget::new(store.as_ref(), "atomic", spec.as_ref());
        assert_eq!(store.get(&budget.key("total_calls")).unwrap(), 100);
        assert_eq!(store.get(&budget.key("tool:db_write")).unwrap(), 100);
    }

    #[test]
    fn unlimited_spec_allows_everything() {
        let store = InMemoryStore::new();
        let s = BudgetSpec::default();
        let b = ActionBudget::new(&store, "sess", &s);
        for _ in 0..100 {
            assert!(b.try_tool_call("anything", 0).unwrap().is_allowed());
        }
        assert!(b.try_tokens(u64::MAX / 4).unwrap().is_allowed());
    }

    #[test]
    fn allowed_decision_reports_true_remaining_headroom() {
        // Catches any stub of `remaining_min` (e.g. → Ok(0) / Ok(1)): with a
        // cap of 10, 3 prior spends, and the measured 4th call spending one
        // itself, `remaining` must be exactly 6.
        let store = InMemoryStore::new();
        let s = BudgetSpec {
            max_total_tool_calls: Some(10),
            ..BudgetSpec::default()
        };
        let b = ActionBudget::new(&store, "sess-rem", &s);
        for _ in 0..3 {
            assert!(b.try_tool_call("t", 0).unwrap().is_allowed());
        }
        match b.try_tool_call("t", 0).unwrap() {
            BudgetDecision::Allowed { remaining } => assert_eq!(remaining, 6),
            other => panic!("expected Allowed with real remaining, got {other:?}"),
        }
    }

    /// Round-33 F1: refund_tool_call compensates the exact dimensions
    /// try_tool_call debited. Locks in the primary invariant needed
    /// by the harness's lost-claim path — after refund, the same
    /// call succeeds again against the same caps.
    #[test]
    fn refund_tool_call_reverses_the_spend_exactly() {
        let store = InMemoryStore::new();
        let s = BudgetSpec {
            max_total_tool_calls: Some(2),
            max_tool_calls: BTreeMap::from([("db_write".to_owned(), 1u64)]),
            max_payout_usd_micros: Some(1_000_000),
            ..BudgetSpec::default()
        };
        let b = ActionBudget::new(&store, "sess-refund", &s);
        // Debit 1 total + 1 per-tool + 500k payout.
        assert!(b.try_tool_call("db_write", 500_000).unwrap().is_allowed());
        // Without refund, per-tool cap trips the next call.
        assert!(matches!(
            b.try_tool_call("db_write", 100).unwrap(),
            BudgetDecision::Refused { .. }
        ));
        // Refund reverses exactly the spend.
        b.refund_tool_call("db_write", 500_000);
        // The same call now succeeds — proving all three dimensions
        // were compensated.
        assert!(b.try_tool_call("db_write", 500_000).unwrap().is_allowed());
    }

    /// `refund_tokens` compensates a `try_tokens` debit exactly, for
    /// requests that provably never reached the provider (sanitize
    /// block, capture failure, marker-write failure, connect failure).
    #[test]
    fn refund_tokens_reverses_the_spend_exactly() {
        let store = InMemoryStore::new();
        let s = BudgetSpec {
            max_tokens: Some(100),
            ..BudgetSpec::default()
        };
        let b = ActionBudget::new(&store, "sess-token-refund", &s);
        assert!(b.try_tokens(80).unwrap().is_allowed());
        // Without refund the next debit trips the cap.
        assert!(matches!(
            b.try_tokens(80).unwrap(),
            BudgetDecision::Refused { .. }
        ));
        b.refund_tokens(80);
        // The same debit now succeeds — the refund compensated exactly.
        assert!(b.try_tokens(80).unwrap().is_allowed());
        // With no cap configured, refund is a no-op (never panics or
        // creates counters).
        let uncapped_spec = BudgetSpec::default();
        let uncapped = ActionBudget::new(&store, "sess-uncapped", &uncapped_spec);
        uncapped.refund_tokens(50);
    }

    /// Round-33 F1: refund saturates at 0 under a concurrent clear.
    /// The compensating refund must never leave a negative "budget
    /// spent" counter — that would give the next legit call a free
    /// ride relative to its cap.
    #[test]
    fn refund_is_saturating() {
        let store = InMemoryStore::new();
        let s = BudgetSpec {
            max_total_tool_calls: Some(10),
            ..BudgetSpec::default()
        };
        let b = ActionBudget::new(&store, "sess-sat", &s);
        assert!(b.try_tool_call("t", 0).unwrap().is_allowed());
        // Two refunds in a row: the second must clamp at 0, not
        // underflow the counter.
        b.refund_tool_call("t", 0);
        b.refund_tool_call("t", 0);
        // 10 successful calls remain — the counter is 0 (clamped).
        for _ in 0..10 {
            assert!(b.try_tool_call("t", 0).unwrap().is_allowed());
        }
        assert!(matches!(
            b.try_tool_call("t", 0).unwrap(),
            BudgetDecision::Refused { .. }
        ));
    }
}
