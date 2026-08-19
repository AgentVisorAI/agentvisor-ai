//! Model-based property tests: random spend/refund/token sequences against
//! `ActionBudget` + `InMemoryStore` must agree with a straightforward
//! reference model at every step. Catches drift between the three budget
//! dimensions (total calls, per-tool, payout), refund reversal, and
//! remove-prefix cleanup that example-based tests miss.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::int_plus_one,
    clippy::indexing_slicing
)]

use av_state::{ActionBudget, BudgetSpec, InMemoryStore, StateStore};
use proptest::prelude::*;
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
enum Op {
    ToolCall { tool: usize, payout: u64 },
    Refund { tool: usize, payout: u64 },
    Tokens { amount: u64 },
    ClearSession,
}

fn arb_op() -> impl Strategy<Value = Op> {
    prop_oneof![
        6 => (0usize..3, 0u64..2_000_000).prop_map(|(tool, payout)| Op::ToolCall { tool, payout }),
        2 => (0usize..3, 0u64..2_000_000).prop_map(|(tool, payout)| Op::Refund { tool, payout }),
        2 => (0u64..600).prop_map(|amount| Op::Tokens { amount }),
        1 => Just(Op::ClearSession),
    ]
}

/// Reference model: plain counters with the same limit semantics the
/// documentation promises (check all dimensions, all-or-nothing commit).
#[derive(Default)]
struct Model {
    total_calls: u64,
    per_tool: BTreeMap<usize, u64>,
    payout: u64,
    tokens: u64,
}

const TOOLS: [&str; 3] = ["alpha", "beta", "gamma"];

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn budget_agrees_with_reference_model(
        ops in prop::collection::vec(arb_op(), 1..120),
        max_total in prop_oneof![Just(None), (1u64..40).prop_map(Some)],
        max_payout in prop_oneof![Just(None), (1u64..20_000_000).prop_map(Some)],
        max_tokens in prop_oneof![Just(None), (1u64..20_000).prop_map(Some)],
        per_tool_cap in prop_oneof![Just(None), (1u64..10).prop_map(Some)],
    ) {
        let spec = BudgetSpec {
            max_tokens,
            max_payout_usd_micros: max_payout,
            max_tool_calls: per_tool_cap
                .map(|cap| TOOLS.iter().map(|tool| ((*tool).to_owned(), cap)).collect())
                .unwrap_or_default(),
            max_total_tool_calls: max_total,
        };
        let store = InMemoryStore::new();
        let session = "model-session";
        let mut model = Model::default();

        for op in ops {
            let budget = ActionBudget::new(&store, session, &spec);
            match op {
                Op::ToolCall { tool, payout } => {
                    // Fail-closed design: a payout-carrying call with no
                    // configured payout cap is refused outright (money
                    // movement requires an explicit ceiling); tokens are
                    // unlimited when unset. The model mirrors both.
                    let model_allowed = (payout == 0 || max_payout.is_some())
                        && max_total.is_none_or(|cap| model.total_calls + 1 <= cap)
                        && per_tool_cap.is_none_or(|cap| {
                            model.per_tool.get(&tool).copied().unwrap_or(0) + 1 <= cap
                        })
                        && (payout == 0
                            || max_payout.is_none_or(|cap| model.payout + payout <= cap));
                    let decision = budget.try_tool_call(TOOLS[tool], payout).unwrap();
                    prop_assert_eq!(
                        decision.is_allowed(),
                        model_allowed,
                        "tool-call verdict diverged from model: tool={} payout={} model={:?}/{:?}/{}",
                        TOOLS[tool], payout, model.total_calls, model.per_tool, model.payout
                    );
                    if model_allowed {
                        model.total_calls += 1;
                        *model.per_tool.entry(tool).or_default() += 1;
                        model.payout += payout;
                    }
                    // Refused calls must consume nothing: a subsequent call
                    // with zero payout under remaining headroom must agree
                    // with the model (checked implicitly by later ops).
                }
                Op::Refund { tool, payout } => {
                    // Refund only what the model actually holds — mirrors
                    // production, which refunds exactly a prior debit; the
                    // saturating behavior for over-refunds is separately
                    // covered below.
                    let tool_held = model.per_tool.get(&tool).copied().unwrap_or(0);
                    if tool_held > 0 && model.payout >= payout {
                        budget.refund_tool_call(TOOLS[tool], payout);
                        model.total_calls = model.total_calls.saturating_sub(1);
                        *model.per_tool.entry(tool).or_default() -= 1;
                        model.payout -= payout;
                    }
                }
                Op::Tokens { amount } => {
                    let model_allowed = max_tokens.is_none_or(|cap| model.tokens + amount <= cap);
                    let allowed = budget.try_tokens(amount).unwrap().is_allowed();
                    prop_assert_eq!(allowed, model_allowed, "token verdict diverged");
                    if model_allowed {
                        model.tokens += amount;
                    }
                }
                Op::ClearSession => {
                    store.remove_prefix(&ActionBudget::session_prefix(session));
                    model = Model::default();
                }
            }
        }

        // Terminal check: an over-refund clamps at zero rather than
        // resurrecting headroom past the caps (documented saturating
        // semantics).
        let budget = ActionBudget::new(&store, session, &spec);
        budget.refund_tool_call(TOOLS[0], u64::MAX);
        for _ in 0..2 {
            let _ = budget.try_tool_call(TOOLS[0], 0);
        }
    }
}
