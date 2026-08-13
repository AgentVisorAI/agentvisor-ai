//! Golden-file and adversarial validation tests for the ATIF implementation,
//! pinned to the Harbor spec (validator error phrasing follows the published
//! example: "trajectory.steps.0.step_id: expected 1 (sequential from 1), got 0").
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use ab_atif::{validate_value, Mode, Trajectory};
use serde_json::{json, Value};

fn golden() -> Value {
    serde_json::from_str(include_str!("golden/valid_v17.json")).unwrap()
}

#[test]
fn golden_v17_is_valid_strict() {
    let issues = validate_value(&golden(), Mode::Strict);
    assert!(issues.is_empty(), "{issues:#?}");
}

#[test]
fn golden_v17_matches_shipped_json_schema() {
    let schema: Value = serde_json::from_str(include_str!("../../../schemas/atif-v1.7.schema.json")).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let value = golden();
    let errors: Vec<_> = validator.iter_errors(&value).collect();
    assert!(errors.is_empty(), "{errors:?}");
}

#[test]
fn golden_roundtrips_through_typed_model() {
    let t: Trajectory = serde_json::from_value(golden()).unwrap();
    assert_eq!(t.schema_version, "ATIF-v1.7");
    assert_eq!(t.steps.len(), 3);
    // R17 fidelity: cached_tokens survive the typed round trip bit-exactly.
    let m = t.steps[1].metrics.as_ref().unwrap();
    assert_eq!(m.cached_tokens, Some(200));
    let back = serde_json::to_value(&t).unwrap();
    assert_eq!(back, golden(), "typed round-trip must be lossless");
}

#[test]
fn strict_v17_requires_complete_agent_token_metrics() {
    let mut missing_block = golden();
    missing_block["steps"][1]
        .as_object_mut()
        .unwrap()
        .remove("metrics");
    let issues = validate_value(&missing_block, Mode::Strict);
    assert!(issues
        .iter()
        .any(|issue| issue.path == "trajectory.steps.1.metrics"));

    let mut missing_cached = golden();
    missing_cached["steps"][1]["metrics"]
        .as_object_mut()
        .unwrap()
        .remove("cached_tokens");
    let issues = validate_value(&missing_cached, Mode::Strict);
    assert!(issues
        .iter()
        .any(|issue| issue.path == "trajectory.steps.1.metrics.cached_tokens"));
}

#[test]
fn nonsequential_step_id_harbor_message() {
    let mut v = golden();
    v["steps"][0]["step_id"] = json!(0);
    let issues = validate_value(&v, Mode::Strict);
    let msg = issues
        .iter()
        .find(|i| i.path == "trajectory.steps.0.step_id")
        .expect("issue expected");
    assert_eq!(msg.message, "expected 1 (sequential from 1), got 0");
}

#[test]
fn missing_agent_name_reported() {
    let mut v = golden();
    v["agent"].as_object_mut().unwrap().remove("name");
    let issues = validate_value(&v, Mode::Strict);
    assert!(
        issues
            .iter()
            .any(|i| i.path == "trajectory.agent.name" && i.message.contains("missing")),
        "{issues:#?}"
    );
}

#[test]
fn collects_all_errors_not_just_first() {
    let mut v = golden();
    v["steps"][0]["step_id"] = json!(7);
    v["agent"].as_object_mut().unwrap().remove("name");
    v["steps"][1]["timestamp"] = json!("yesterday");
    let issues = validate_value(&v, Mode::Strict);
    assert!(issues.len() >= 3, "collect-all violated: {issues:#?}");
}

#[test]
fn agent_only_fields_rejected_on_user_and_system_steps() {
    for field in ["reasoning_content", "model_name", "metrics", "tool_calls"] {
        let mut v = golden();
        let val = match field {
            "metrics" => json!({"prompt_tokens": 1}),
            "tool_calls" => json!([{"tool_call_id": "c1", "function_name": "f", "arguments": {}}]),
            _ => json!("x"),
        };
        v["steps"][0][field] = val;
        let issues = validate_value(&v, Mode::Strict);
        assert!(
            issues
                .iter()
                .any(|i| i.path == format!("trajectory.steps.0.{field}") && i.message.contains("agent-only")),
            "field {field} not flagged: {issues:#?}"
        );
    }
}

#[test]
fn llm_call_count_is_valid_on_any_v17_step() {
    let mut v = golden();
    v["steps"][0]["llm_call_count"] = json!(0);
    let issues = validate_value(&v, Mode::Strict);
    assert!(
        !issues
            .iter()
            .any(|issue| issue.path == "trajectory.steps.0.llm_call_count"),
        "{issues:#?}"
    );
}

#[test]
fn observation_source_call_id_must_reference_same_step_tool_call() {
    let mut v = golden();
    v["steps"][1]["observation"]["results"][0]["source_call_id"] = json!("call_nonexistent");
    let issues = validate_value(&v, Mode::Strict);
    assert!(
        issues
            .iter()
            .any(|i| i.path.ends_with("source_call_id") && i.message.contains("unknown tool_call_id")),
        "{issues:#?}"
    );
}

#[test]
fn duplicate_tool_call_ids_rejected() {
    let mut v = golden();
    v["steps"][1]["tool_calls"] = json!([
        {"tool_call_id": "dup", "function_name": "a", "arguments": {}},
        {"tool_call_id": "dup", "function_name": "b", "arguments": {}}
    ]);
    v["steps"][1]["observation"]["results"][0]["source_call_id"] = json!("dup");
    let issues = validate_value(&v, Mode::Strict);
    assert!(
        issues.iter().any(|i| i.message.contains("duplicate id")),
        "{issues:#?}"
    );
}

#[test]
fn bad_timestamps_rejected() {
    for ts in ["2025-01-15 10:30:00Z", "2025-02-30T10:00:00Z", "nope", ""] {
        let mut v = golden();
        v["steps"][0]["timestamp"] = json!(ts);
        let issues = validate_value(&v, Mode::Strict);
        assert!(
            issues.iter().any(|i| i.path == "trajectory.steps.0.timestamp"),
            "timestamp {ts:?} slipped through"
        );
    }
}

#[test]
fn unsupported_version_rejected() {
    for ver in ["ATIF-v2.0", "ATIF-v0.9", "1.7", "atif-v1.7", ""] {
        let mut v = golden();
        v["schema_version"] = json!(ver);
        let issues = validate_value(&v, Mode::Strict);
        assert!(
            issues.iter().any(|i| i.path == "trajectory.schema_version"),
            "version {ver:?} slipped through"
        );
    }
}

#[test]
fn version_gating_v17_fields_rejected_in_older_files() {
    // trajectory_id + llm_call_count + session_id-optionality are all v1.7 features.
    let mut v = golden();
    v["schema_version"] = json!("ATIF-v1.5");
    let issues = validate_value(&v, Mode::Strict);
    assert!(
        issues
            .iter()
            .any(|i| i.path == "trajectory.trajectory_id" && i.message.contains("v1.7+")),
        "{issues:#?}"
    );
    assert!(
        issues
            .iter()
            .any(|i| i.path == "trajectory.steps.1.llm_call_count"),
        "{issues:#?}"
    );
}

#[test]
fn version_gating_session_id_required_before_v17() {
    let mut v = golden();
    v["schema_version"] = json!("ATIF-v1.6");
    v.as_object_mut().unwrap().remove("session_id");
    v.as_object_mut().unwrap().remove("trajectory_id");
    v["steps"][1].as_object_mut().unwrap().remove("llm_call_count");
    let issues = validate_value(&v, Mode::Strict);
    assert!(
        issues.iter().any(|i| i.path == "trajectory.session_id"),
        "session_id must be required pre-v1.7: {issues:#?}"
    );
}

#[test]
fn version_gating_tool_definitions_pre_v15() {
    let mut v = golden();
    v["schema_version"] = json!("ATIF-v1.4");
    v.as_object_mut().unwrap().remove("trajectory_id");
    v["steps"][1].as_object_mut().unwrap().remove("llm_call_count");
    v["agent"]["tool_definitions"] = json!([{"name": "financial_search"}]);
    let issues = validate_value(&v, Mode::Strict);
    assert!(
        issues
            .iter()
            .any(|i| i.path == "trajectory.agent.tool_definitions"),
        "{issues:#?}"
    );
}

#[test]
fn strict_rejects_unknown_fields_compat_tolerates() {
    let mut v = golden();
    v["steps"][0]["from_the_future"] = json!(true);
    let strict = validate_value(&v, Mode::Strict);
    assert!(
        strict
            .iter()
            .any(|i| i.path == "trajectory.steps.0.from_the_future"),
        "{strict:#?}"
    );
    let compat = validate_value(&v, Mode::Compat);
    assert!(
        compat.is_empty(),
        "compat mode must tolerate unknown fields: {compat:#?}"
    );
}

#[test]
fn extra_fields_are_legal_everywhere_in_v17() {
    let mut v = golden();
    v["extra"] = json!({"custom": 1});
    v["agent"]["extra"] = json!({"agent_class": "CodeActAgent"});
    v["steps"][0]["extra"] = json!({"k": "v"});
    v["steps"][1]["tool_calls"][0]["extra"] = json!({"latency_ms": 12});
    v["steps"][1]["observation"]["results"][0]["extra"] = json!({"exit_code": 0});
    let issues = validate_value(&v, Mode::Strict);
    assert!(issues.is_empty(), "{issues:#?}");
}

#[test]
fn subagent_trajectories_recurse() {
    let mut v = golden();
    let mut sub = golden();
    sub["steps"][0]["step_id"] = json!(5); // corrupt the subagent
    v["subagent_trajectories"] = json!([sub]);
    let issues = validate_value(&v, Mode::Strict);
    assert!(
        issues
            .iter()
            .any(|i| i.path == "trajectory.subagent_trajectories.0.steps.0.step_id"),
        "{issues:#?}"
    );
}

#[test]
fn embedded_subagents_require_unique_trajectory_ids() {
    let mut root = golden();
    let mut first = golden();
    first.as_object_mut().unwrap().remove("trajectory_id");
    let second = golden();
    let third = golden();
    root["subagent_trajectories"] = json!([first, second, third]);
    let issues = validate_value(&root, Mode::Strict);
    assert!(issues.iter().any(|issue| {
        issue.path == "trajectory.subagent_trajectories.0.trajectory_id" && issue.message.contains("required")
    }));
    assert!(issues.iter().any(|issue| {
        issue.path == "trajectory.subagent_trajectories.2.trajectory_id"
            && issue.message.contains("duplicate")
    }));
}

#[test]
fn subagent_references_must_be_resolvable() {
    let mut trajectory = golden();
    trajectory["steps"][1]["observation"]["results"][0]["subagent_trajectory_ref"] =
        json!([{"session_id": "informational-only"}]);
    let issues = validate_value(&trajectory, Mode::Strict);
    assert!(issues.iter().any(|issue| {
        issue.path.ends_with("subagent_trajectory_ref.0")
            && issue.message.contains("trajectory_id or trajectory_path")
    }));
}

#[test]
fn torn_file_rejected_not_miscounted() {
    // Simulates a truncated write (silent-error D13.16): parse fails, so the
    // reconciler counts it as an error, never a valid-but-shorter trajectory.
    let full = serde_json::to_string(&golden()).unwrap();
    let torn = &full[..full.len() / 2];
    assert!(serde_json::from_str::<Value>(torn).is_err());
}

#[test]
fn non_object_roots_rejected() {
    for v in [json!([]), json!("string"), json!(42), json!(null)] {
        let issues = validate_value(&v, Mode::Strict);
        assert!(!issues.is_empty(), "root {v} slipped through");
    }
}
