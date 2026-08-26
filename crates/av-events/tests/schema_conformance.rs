//! Cross-validation of emitted events against the shipped JSON Schema
//! (schemas/ocsf-agent-event.schema.json). Guarantees the Rust model and the
//! published schema never drift (silent-error class D13.3/17).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
#![allow(clippy::type_complexity)]

use av_events::{
    AgentIdentity, EventClass, EventMetrics, Fingerprint, OcsfEventBuilder, StatusId, StopReason,
};

fn schema() -> jsonschema::Validator {
    let raw = include_str!("../../../schemas/ocsf-agent-event.schema.json");
    let doc: serde_json::Value = serde_json::from_str(raw).expect("schema file parses");
    jsonschema::options()
        .should_validate_formats(true)
        .build(&doc)
        .expect("schema compiles")
}

fn identity() -> AgentIdentity {
    AgentIdentity {
        version: "3.2.1".into(),
        charter: "support-triage".into(),
        instance_uid: "inst-00042".into(),
        ttl_remaining_s: Some(540),
    }
}

fn assert_valid(v: &serde_json::Value, schema: &jsonschema::Validator) {
    let errors: Vec<String> = schema.iter_errors(v).map(|e| format!("{e}")).collect();
    assert!(errors.is_empty(), "schema violations for {v:#}:\n{errors:#?}");
}

#[test]
fn every_event_class_validates_against_shipped_schema() {
    let schema = schema();
    for (i, class) in EventClass::all().iter().enumerate() {
        let ev = OcsfEventBuilder::new(*class, format!("sess-{i}"), identity(), i as u64)
            .payload(serde_json::json!({"probe": true}))
            .build()
            .expect("build");
        assert_valid(&serde_json::to_value(&ev).expect("serialize"), &schema);
    }
}

#[test]
fn stop_reason_event_with_metrics_validates() {
    let schema = schema();
    let ev = OcsfEventBuilder::new(EventClass::StopReason, "sess-loop", identity(), 42)
        .stop_reason(StopReason::LoopDetected)
        .status(StatusId::Failure)
        .severity(4)
        .payload(serde_json::json!({
            "semantic_delta": 0.004,
            "window": 3,
            "tokens_consumed": 18211
        }))
        .metrics(EventMetrics {
            prompt_tokens: Some(17000),
            completion_tokens: Some(1211),
            cached_tokens: Some(9000),
            ..Default::default()
        })
        .build()
        .expect("build");
    assert_valid(&serde_json::to_value(&ev).expect("serialize"), &schema);
}

#[test]
fn inventory_fingerprint_roadmap_shape_validates() {
    let schema = schema();
    let digest_a = av_core::digest::sha256_hex(b"tool-schemas-v1");
    let digest_b = av_core::digest::sha256_hex(b"tool-schemas-v0");
    let ev = OcsfEventBuilder::new(EventClass::ToolCall, "sess-fp", identity(), 3)
        .payload(serde_json::json!({"tool": "db_write"}))
        .inventory(
            Fingerprint::sha256_jcs(digest_a),
            Some(Fingerprint::sha256_jcs(digest_b)),
        )
        .build()
        .expect("build");
    let v = serde_json::to_value(&ev).expect("serialize");
    assert_valid(&v, &schema);
    assert_eq!(v["inventory"]["serialization"], "JCS");
    assert_eq!(v["inventory"]["algorithm_id"], 3);
}

#[test]
fn schema_rejects_tampered_events() {
    let schema = schema();
    let ev = OcsfEventBuilder::new(EventClass::Session, "sess-x", identity(), 1)
        .build()
        .expect("build");
    let good = serde_json::to_value(&ev).expect("serialize");

    // Each mutation must be caught by the schema — no silent pass.
    let mutations: Vec<(&str, Box<dyn Fn(&mut serde_json::Value)>)> = vec![
        (
            "wrong ocsf version",
            Box::new(|v| v["metadata"]["version"] = "9.9.9".into()),
        ),
        (
            "empty instance_uid",
            Box::new(|v| v["ai_agent"]["instance_uid"] = "".into()),
        ),
        (
            "unknown class",
            Box::new(|v| v["class_name"] = "agent.bogus".into()),
        ),
        (
            "orphan stop_reason_id",
            Box::new(|v| v["stop_reason_id"] = 90.into()),
        ),
        ("severity 0", Box::new(|v| v["severity_id"] = 0.into())),
        ("status 9", Box::new(|v| v["status_id"] = 9.into())),
        ("zero time", Box::new(|v| v["time"] = 0.into())),
        (
            "bad iso format",
            Box::new(|v| v["time_iso"] = "2026-08-10 17:00:00".into()),
        ),
        (
            "missing identity block",
            Box::new(|v| {
                v.as_object_mut().map(|o| o.remove("ai_agent"));
            }),
        ),
    ];
    for (name, mutate) in mutations {
        let mut bad = good.clone();
        mutate(&mut bad);
        assert!(
            !schema.is_valid(&bad),
            "mutation `{name}` slipped through the schema"
        );
    }
}

/// R52: pin the shipped schema's `time.maximum` to the Rust
/// validator's `SCHEMA_TIME_MAX_MS` constant so a future edit that
/// changes one side without the other fails CI. R51 initially set
/// the schema max to `2^53 = JCS_SAFE_MAX`, but the Rust validator
/// applies a tighter year-10000 cap first (`SCHEMA_TIME_MAX_MS =
/// 253402300799999`), so any `time` in the gap band passed the
/// shipped schema but was rejected by `validate_event` — exactly
/// the split-brain the alignment closes.
#[test]
fn shipped_schema_time_max_matches_rust_validator() {
    let raw = include_str!("../../../schemas/ocsf-agent-event.schema.json");
    let doc: serde_json::Value = serde_json::from_str(raw).expect("schema file parses");
    let schema_max = doc
        .pointer("/properties/time/maximum")
        .and_then(serde_json::Value::as_u64)
        .expect("shipped schema must declare a maximum on properties.time");
    assert_eq!(
        schema_max,
        av_events::SCHEMA_TIME_MAX_MS,
        "shipped schema time.maximum ({schema_max}) diverged from \
         av_events::SCHEMA_TIME_MAX_MS ({}); R51/R52 split-brain drift class",
        av_events::SCHEMA_TIME_MAX_MS
    );
}
