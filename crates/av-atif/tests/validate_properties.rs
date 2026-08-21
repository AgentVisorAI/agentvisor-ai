//! Randomized differential tests: the strict validator and typed
//! deserialization must agree (validator-clean JSON must deserialize),
//! and the validator must be total over arbitrary JSON.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use proptest::prelude::*;
use serde_json::{json, Value};

fn arb_json() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(Value::from),
        any::<f64>()
            .prop_filter("finite", |f| f.is_finite())
            .prop_map(Value::from),
        "[a-zA-Z0-9_.:-]{0,12}".prop_map(Value::String),
        Just(json!("1")),
        Just(json!(1)),
        Just(json!("agent")),
        Just(json!("user")),
        Just(json!("system")),
    ];
    leaf.prop_recursive(4, 64, 6, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..4).prop_map(Value::Array),
            prop::collection::btree_map(
                prop_oneof![
                    // Bias toward real field names so mutations explore the
                    // validator's actual branches, not just unknown-field
                    // rejection.
                    Just("schema_version".to_owned()),
                    Just("session_id".to_owned()),
                    Just("trajectory_id".to_owned()),
                    Just("agent".to_owned()),
                    Just("steps".to_owned()),
                    Just("step_id".to_owned()),
                    Just("source".to_owned()),
                    Just("message".to_owned()),
                    Just("metrics".to_owned()),
                    Just("observation".to_owned()),
                    Just("results".to_owned()),
                    Just("content".to_owned()),
                    Just("tool_calls".to_owned()),
                    Just("tool_call_id".to_owned()),
                    Just("function_name".to_owned()),
                    Just("arguments".to_owned()),
                    Just("source_call_id".to_owned()),
                    Just("llm_call_count".to_owned()),
                    Just("timestamp".to_owned()),
                    Just("name".to_owned()),
                    Just("version".to_owned()),
                    Just("final_metrics".to_owned()),
                    Just("prompt_tokens".to_owned()),
                    Just("completion_tokens".to_owned()),
                    Just("cached_tokens".to_owned()),
                    Just("cost_usd".to_owned()),
                    Just("extra".to_owned()),
                    "[a-z_]{1,10}",
                ],
                inner,
                0..6
            )
            .prop_map(|map| Value::Object(map.into_iter().collect())),
        ]
    })
}

/// Splice random JSON into a valid trajectory skeleton so the validator's
/// deep branches are exercised, not just top-level shape rejection.
fn arb_trajectory_mutant() -> impl Strategy<Value = Value> {
    (arb_json(), arb_json(), arb_json()).prop_map(|(a, b, c)| {
        json!({
            "schema_version": "ATIF-v1.7",
            "session_id": "s",
            "agent": {"name": "a", "version": "1", "extra": a},
            "steps": [{
                "step_id": 1,
                "source": "agent",
                "message": "hi",
                "llm_call_count": 1,
                "metrics": {"prompt_tokens": 1, "completion_tokens": 1, "cached_tokens": 0},
                "tool_calls": [{"tool_call_id": "c1", "function_name": "f", "arguments": b}],
                "observation": {"results": [{"content": "ok", "source_call_id": "c1", "extra": c}]},
            }],
        })
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    /// The validator never panics on arbitrary JSON.
    #[test]
    fn validate_value_is_total(value in arb_json()) {
        let _ = av_atif::validate_value(&value, av_atif::Mode::Strict);
        let _ = av_atif::validate_value(&value, av_atif::Mode::Compat);
    }

    /// Differential: strict-clean JSON must deserialize to the typed
    /// Trajectory (the validator's stated contract). A mismatch means a
    /// wrong-typed field slipped past strict validation.
    #[test]
    fn strict_clean_json_deserializes(value in arb_trajectory_mutant()) {
        let issues = av_atif::validate_value(&value, av_atif::Mode::Strict);
        if issues.is_empty() {
            prop_assert!(
                serde_json::from_value::<av_atif::Trajectory>(value.clone()).is_ok(),
                "strict-clean value failed typed deserialization: {value}"
            );
        }
    }
}
