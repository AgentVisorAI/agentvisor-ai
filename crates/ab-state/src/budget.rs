//! Action budgets (Module B): stateful tool limits like `max_db_writes: 3`,
//! `max_payout_usd: 50`, plus per-session token ceilings.
//!
//! Money is tracked in integer micro-USD; a payout of $12.34 spends
//! 12_340_000. Fractional-cent dust can therefore never accumulate invisibly.

use crate::store::{StateError, StateStore};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Declarative budget for one session/agent (config-file surface).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
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

/// Budget enforcement bound to a session id and a state store.
pub struct ActionBudget<'a> {
    store: &'a dyn StateStore,
    session: &'a str,
    spec: &'a BudgetSpec,
}

impl<'a> ActionBudget<'a> {
    /// Bind a spec to a session.
    pub fn new(store: &'a dyn StateStore, session: &'a str, spec: &'a BudgetSpec) -> Self {
        Self { store, session, spec }
    }

    fn key(&self, dim: &str) -> String {
        format!("budget:{}:{dim}", self.session)
    }

    /// Check-and-spend one invocation of `tool`, with an optional payout
    /// amount in micro-USD carried by this call.
    ///
    /// Dimensions are checked in a fixed order (total calls → per-tool →
    /// payout); on refusal, earlier-dimension spends are rolled back so a
    /// refused call consumes nothing (atomicity across dimensions is
    /// enforced by compensation, which is exact because refusals record
    /// nothing and grants are integers).
    pub fn try_tool_call(&self, tool: &str, payout_usd_micros: u64) -> Result<BudgetDecision, StateError> {
        let mut spent: Vec<(String, u64)> = Vec::new();

        if let Some(cap) = self.spec.max_total_tool_calls {
            let key = self.key("total_calls");
            if !self.store.try_spend(&key, 1, cap)? {
                return Ok(BudgetDecision::Refused { limit: "max_total_tool_calls".into(), cap });
            }
            spent.push((key, 1));
        }
        if let Some(cap) = self.spec.max_tool_calls.get(tool).copied() {
            let key = self.key(&format!("tool:{tool}"));
            if !self.store.try_spend(&key, 1, cap)? {
                self.rollback(&spent);
                return Ok(BudgetDecision::Refused { limit: format!("max_tool_calls.{tool}"), cap });
            }
            spent.push((key, 1));
        }
        if payout_usd_micros > 0 {
            match self.spec.max_payout_usd_micros {
                Some(cap) => {
                    let key = self.key("payout");
                    if !self.store.try_spend(&key, payout_usd_micros, cap)? {
                        self.rollback(&spent);
                        return Ok(BudgetDecision::Refused { limit: "max_payout_usd_micros".into(), cap });
                    }
                    spent.push((key, payout_usd_micros));
                }
                // A payout with no configured payout cap is refused outright:
                // fail-closed beats a silent unlimited-money path.
                None => {
                    self.rollback(&spent);
                    return Ok(BudgetDecision::Refused { limit: "max_payout_usd_micros(unset)".into(), cap: 0 });
                }
            }
        }

        let remaining = self.remaining_min(tool)?;
        Ok(BudgetDecision::Allowed { remaining })
    }

    /// Check-and-spend `tokens` against `max_tokens`.
    pub fn try_tokens(&self, tokens: u64) -> Result<BudgetDecision, StateError> {
        match self.spec.max_tokens {
            Some(cap) => {
                let key = self.key("tokens");
                if self.store.try_spend(&key, tokens, cap)? {
                    let used = self.store.get(&key)?;
                    Ok(BudgetDecision::Allowed { remaining: cap.saturating_sub(used) })
                } else {
                    Ok(BudgetDecision::Refused { limit: "max_tokens".into(), cap })
                }
            }
            None => Ok(BudgetDecision::Allowed { remaining: u64::MAX }),
        }
    }

    fn rollback(&self, spent: &[(String, u64)]) {
        for (key, amount) in spent {
            // Compensating subtraction: refused multi-dimension spends must
            // not leak partial consumption.
            let _ = self.store.get(key).map(|current| {
                let target = current.saturating_sub(*amount);
                self.store.remove(key);
                let _ = self.store.add(key, target);
            });
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
            BudgetDecision::Refused { limit: "max_tool_calls.db_write".into(), cap: 3 }
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
        assert!(!d.is_allowed(), "uncapped payout must be refused, not silently allowed");
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
        assert!(!b.try_tool_call("other", 0).unwrap().is_allowed(), "total cap must bind at 10");
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
        assert!(b.try_tool_call("db_write", 0).unwrap().is_allowed(), "session b unaffected");
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
}
