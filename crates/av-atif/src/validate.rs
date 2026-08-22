//! ATIF validator, mirroring Harbor's trajectory-validator semantics:
//! validates required fields, types and constraints, sequential step ids
//! (starting from 1), tool-call references in observations, ISO-8601
//! timestamps, agent-only field placement — and collects errors as it goes
//! (not just the first), up to [`MAX_VALIDATION_ISSUES`], after which a
//! truncation notice is appended.
//!
//! Two modes ([`Mode`]): `Strict` additionally rejects unknown fields outside
//! the spec's `extra` escape hatches (outbound gate for files we produce);
//! `Compat` tolerates unknown fields (inbound tolerance for files produced by
//! newer or third-party writers).

use crate::model::SUPPORTED_VERSIONS;
use serde_json::Value;

/// Validation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Reject unknown fields (files we emit must be exactly spec-shaped).
    Strict,
    /// Tolerate unknown fields (accept newer/foreign writers).
    Compat,
}

/// One validation problem, with a Harbor-style dotted path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationIssue {
    /// Dotted location, e.g. `trajectory.steps.0.step_id`.
    pub path: String,
    /// Human-readable message.
    pub message: String,
}

impl std::fmt::Display for ValidationIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.path, self.message)
    }
}

/// Parse `"ATIF-vX.Y"` into `(X, Y)`.
fn parse_version(v: &str) -> Option<(u32, u32)> {
    let rest = v.strip_prefix("ATIF-v")?;
    let (maj, min) = rest.split_once('.')?;
    Some((maj.parse().ok()?, min.parse().ok()?))
}

/// Validate a typed trajectory (serializes then defers to [`validate_value`]).
pub fn validate_trajectory(t: &crate::model::Trajectory, mode: Mode) -> Vec<ValidationIssue> {
    match serde_json::to_value(t) {
        Ok(v) => validate_value(&v, mode),
        Err(e) => vec![ValidationIssue {
            path: "trajectory".into(),
            message: format!("serialization failed: {e}"),
        }],
    }
}

/// Round-23 F2 (av-atif ingest): validate an ATIF trajectory from
/// its RAW BYTES. This is the correct entry point for every path
/// that receives operator/attacker-supplied ATIF content (CLI
/// `avctl atif-validate`, reconciler recovery + promotion). Unlike
/// `serde_json::from_slice::<Trajectory>()` + `validate_trajectory`,
/// the bytes path:
///
///   1. Refuses duplicate JSON keys anywhere in the payload
///      (parallel to `av_receipts::Receipt::from_json_slice`'s
///      strict pre-scan added in round-16 F5), so the auditor cannot
///      be shown a document whose "last wins" reading differs from
///      the "first wins" reading.
///   2. Runs `validate_value` on the parsed `serde_json::Value` — the
///      untyped path exercises `check_unknown_fields`, which the
///      typed `Trajectory` (no `deny_unknown_fields`) silently drops.
///
/// Returns `Err(reason)` on duplicate-key or parse failure; returns
/// `Ok(issues)` on successful parse (issues may be empty).
pub fn validate_bytes(bytes: &[u8], mode: Mode) -> Result<Vec<ValidationIssue>, String> {
    refuse_duplicate_json_keys(bytes)?;
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|error| format!("parse JSON: {error}"))?;
    Ok(validate_value(&value, mode))
}

/// Refuse any JSON object with duplicate keys anywhere in the payload.
/// Mirrors the internal check in `av-receipts::Receipt::from_json_slice`
/// and `av-sandbox::refuse_duplicate_json_keys`; exposed here to give
/// ATIF ingest a single strict-parse primitive without cross-crate
/// coupling.
fn refuse_duplicate_json_keys(raw: &[u8]) -> Result<(), String> {
    use serde::de::{Deserializer as _, MapAccess, SeqAccess, Visitor};
    use std::fmt;

    struct NoDupKeys;
    impl<'de> Visitor<'de> for NoDupKeys {
        type Value = ();
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("any JSON value without duplicate object keys")
        }
        fn visit_bool<E>(self, _: bool) -> Result<(), E> {
            Ok(())
        }
        fn visit_i64<E>(self, _: i64) -> Result<(), E> {
            Ok(())
        }
        fn visit_u64<E>(self, _: u64) -> Result<(), E> {
            Ok(())
        }
        fn visit_f64<E>(self, _: f64) -> Result<(), E> {
            Ok(())
        }
        fn visit_str<E>(self, _: &str) -> Result<(), E> {
            Ok(())
        }
        fn visit_string<E>(self, _: String) -> Result<(), E> {
            Ok(())
        }
        fn visit_none<E>(self) -> Result<(), E> {
            Ok(())
        }
        fn visit_unit<E>(self) -> Result<(), E> {
            Ok(())
        }
        fn visit_some<D: serde::de::Deserializer<'de>>(self, deser: D) -> Result<(), D::Error> {
            deser.deserialize_any(NoDupKeys)
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
            while seq.next_element::<NoDupWrap>()?.is_some() {}
            Ok(())
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
            let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
            while let Some(key) = map.next_key::<String>()? {
                if !seen.insert(key.clone()) {
                    return Err(serde::de::Error::custom(format!(
                        "duplicate object key `{}` in ATIF",
                        key.escape_debug()
                    )));
                }
                let _: NoDupWrap = map.next_value()?;
            }
            Ok(())
        }
    }
    struct NoDupWrap;
    impl<'de> serde::Deserialize<'de> for NoDupWrap {
        fn deserialize<D: serde::de::Deserializer<'de>>(deser: D) -> Result<Self, D::Error> {
            deser.deserialize_any(NoDupKeys)?;
            Ok(NoDupWrap)
        }
    }
    let mut de = serde_json::Deserializer::from_slice(raw);
    de.deserialize_any(NoDupKeys).map_err(|error| error.to_string())
}

macro_rules! issue {
    ($issues:expr, $path:expr, $($msg:tt)*) => {
        // Round-20: cap issue collection so a pathological
        // trajectory cannot allocate millions of ValidationIssue
        // structs. We allow ONE extra slot past MAX so
        // `truncate_issues_with_marker` can detect the overflow
        // and emit a synthetic truncation notice.
        if $issues.len() <= MAX_VALIDATION_ISSUES {
            $issues.push(ValidationIssue { path: $path.to_string(), message: format!($($msg)*) })
        }
    };
}

const TRAJECTORY_FIELDS: &[&str] = &[
    "schema_version",
    "session_id",
    "trajectory_id",
    "agent",
    "steps",
    "notes",
    "final_metrics",
    "continued_trajectory_ref",
    "subagent_trajectories",
    "extra",
];
const AGENT_FIELDS: &[&str] = &["name", "version", "model_name", "tool_definitions", "extra"];
const STEP_FIELDS: &[&str] = &[
    "step_id",
    "timestamp",
    "source",
    "message",
    "reasoning_effort",
    "reasoning_content",
    "model_name",
    "tool_calls",
    "observation",
    "metrics",
    "is_copied_context",
    "llm_call_count",
    "extra",
];
const AGENT_ONLY_STEP_FIELDS: &[&str] = &[
    "reasoning_content",
    "reasoning_effort",
    "model_name",
    "tool_calls",
    "metrics",
];
const TOOL_CALL_FIELDS: &[&str] = &["tool_call_id", "function_name", "arguments", "extra"];
const OBS_RESULT_FIELDS: &[&str] = &["source_call_id", "content", "subagent_trajectory_ref", "extra"];
const SUBAGENT_REF_FIELDS: &[&str] = &["trajectory_id", "session_id", "trajectory_path", "extra"];
const METRICS_FIELDS: &[&str] = &[
    "prompt_tokens",
    "completion_tokens",
    "cached_tokens",
    "cost_usd",
    "logprobs",
    "completion_token_ids",
    "prompt_token_ids",
    "extra",
];
const FINAL_METRICS_FIELDS: &[&str] = &[
    "total_prompt_tokens",
    "total_completion_tokens",
    "total_cached_tokens",
    "total_cost_usd",
    "total_steps",
    "extra",
];

/// Cap on the number of issues collected by `validate_value`.
///
/// Round-20: a maliciously crafted trajectory sitting inside
/// MAX_ATIF_BYTES (64 MiB) can legitimately trigger millions of
/// validation issues. Each `ValidationIssue` allocates two owned
/// Strings (path + message); five million entries → ~500 MiB
/// Vec, hitting OOM before the caller ever renders a bounded
/// error message (see reconciler round-19 F6). Cap the collection
/// so the memory bound is O(cap), independent of the input's
/// pathological branching.
///
/// When the cap fires, a synthetic tail issue is emitted so
/// downstream consumers know the truncation happened.
pub const MAX_VALIDATION_ISSUES: usize = 4096;

/// Round-25 F4: mirror the `av_receipts::MAX_NESTED_DEPTH = 128`
/// bound (round-16). ATIF's public [`validate_value`] accepts any
/// programmatically-constructed `Value` at unbounded depth, and
/// each recursion frame of [`validate_trajectory_obj`] allocates
/// heavily (locals + `format!` on `path`), so stack overflow is
/// reachable well before serde_json's default 128-frame parser
/// ceiling would help. The reconciler's `from_slice::<Trajectory>`
/// path is bounded by serde_json today, but any future call site
/// that parses ATIF via `Deserializer::disable_recursion_limit()`
/// (for shallow-but-huge files) silently reopens a crash. Cap
/// here so no such caller can reopen it.
const MAX_NESTED_DEPTH: usize = 128;

/// Round-38 F4: upper bound for USD-denominated cost fields
/// (`total_cost_usd` in `final_metrics`, `cost_usd` per step). Strict
/// mode's original floor at 0.0 was asymmetric — no ceiling — so a
/// hostile trajectory carrying `total_cost_usd: 1.7e308` passed
/// strict validation and flowed into promotion, dashboards, and
/// receipt subject payloads. Not a signing hazard (receipt subject
/// uses the ATIF file hash, not the cost fields) but a metrics-
/// poisoning primitive: Prometheus histograms of av_session_cost_usd
/// would blow up their bucketing; downstream billing exporters might
/// saturate their accumulators. `1e12` (one trillion USD) is
/// operationally absurd for any real agent run — 1000x the whole
/// LLM industry's annual spend — while being 1e296 below f64::MAX,
/// safe for any arithmetic combination downstream.
pub(crate) const MAX_COST_USD: f64 = 1e12;

/// Validate a raw JSON value as an ATIF trajectory.
///
/// Returns at most [`MAX_VALIDATION_ISSUES`] issues plus a
/// trailing synthetic entry noting truncation when the cap fires.
pub fn validate_value(root: &Value, mode: Mode) -> Vec<ValidationIssue> {
    let mut issues = Vec::new();
    // Round-40 F3: track the ancestor `trajectory_id` chain across
    // recursion frames so a cycle A -> B -> A can be detected even
    // when B is a great-grandchild of A. The prior per-frame
    // HashSet only caught duplicates among direct siblings; a
    // trajectory can claim to be a re-invocation of any ancestor
    // and downstream analysis would treat the tree as a genuine
    // recursive call.
    let mut ancestors: std::collections::HashSet<String> = std::collections::HashSet::new();
    validate_trajectory_obj(root, "trajectory", mode, &mut issues, true, 0, &mut ancestors);
    // Strict mode additionally enforces the two schema semantics the
    // field-wise walker's null-tolerant type checks (`!v.is_null()`
    // escapes, mirroring serde `Option`) could not express, and whose
    // absence let strict-valid documents fail the shipped schema:
    //   1. explicit `null` is not schema-valid for any typed field
    //      (JSON Schema types never include null here);
    //   2. `extra` is pinned `{"type":"object"}` everywhere EXCEPT the
    //      free-form root/agent/step/tool-call positions (`"extra": {}`).
    if mode == Mode::Strict {
        strict_null_and_extra_conformance(root, "", "trajectory", &mut issues, 0);
    }
    truncate_issues_with_marker(issues)
}

/// See the call site in [`validate_value`]: strict-mode schema-parity
/// pass for explicit nulls and object-typed `extra` fields. `parent_key`
/// is the property name of the containing object with array indices
/// skipped ("" for the document root; nested subagent trajectory roots
/// carry "subagent_trajectories", whose rules match the root's).
fn strict_null_and_extra_conformance(
    value: &Value,
    parent_key: &str,
    path: &str,
    issues: &mut Vec<ValidationIssue>,
    depth: usize,
) {
    if depth > MAX_NESTED_DEPTH || issues.len() > MAX_VALIDATION_ISSUES {
        return;
    }
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let child_path = format!("{path}.{key}");
                if key == "extra" {
                    // Free-form (`"extra": {}`) positions accept any
                    // value, null included; every other `extra` is
                    // schema-pinned `{"type":"object"}`.
                    let free_form = matches!(
                        parent_key,
                        "" | "agent" | "steps" | "subagent_trajectories" | "tool_calls"
                    );
                    if !free_form && !child.is_object() {
                        issue!(issues, child_path, "must be an object (schema type)");
                    }
                    // Interiors of `extra` are unconstrained either way.
                    continue;
                }
                // Unconstrained interiors (bare `array` / string-or-array
                // `oneOf`): the container value itself must not be null,
                // but its contents are schema-free.
                if key == "tool_calls" || key == "message" || (key == "content" && parent_key == "results") {
                    if child.is_null() {
                        issue!(
                            issues,
                            child_path,
                            "explicit null is not schema-valid; omit the field instead"
                        );
                    }
                    continue;
                }
                if child.is_null() {
                    issue!(
                        issues,
                        child_path,
                        "explicit null is not schema-valid; omit the field instead"
                    );
                    continue;
                }
                strict_null_and_extra_conformance(child, key, &child_path, issues, depth + 1);
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                let child_path = format!("{path}[{index}]");
                if child.is_null() {
                    issue!(
                        issues,
                        child_path,
                        "explicit null is not schema-valid inside this array"
                    );
                    continue;
                }
                strict_null_and_extra_conformance(child, parent_key, &child_path, issues, depth + 1);
            }
        }
        _ => {}
    }
}

/// Round-20: after a validation pass, cap the number of issues
/// returned so downstream consumers never see a >>bounded Vec.
/// The `issue!` macro allows ONE slot past MAX so this function
/// can detect the overflow and swap in a synthetic truncation
/// notice.
fn truncate_issues_with_marker(mut issues: Vec<ValidationIssue>) -> Vec<ValidationIssue> {
    if issues.len() > MAX_VALIDATION_ISSUES {
        issues.truncate(MAX_VALIDATION_ISSUES);
        issues.push(ValidationIssue {
            path: "trajectory".into(),
            message: format!(
                "validator hit the {MAX_VALIDATION_ISSUES}-issue cap; additional issues suppressed"
            ),
        });
    }
    issues
}

fn check_unknown_fields(
    obj: &serde_json::Map<String, Value>,
    allowed: &[&str],
    path: &str,
    mode: Mode,
    issues: &mut Vec<ValidationIssue>,
) {
    if mode == Mode::Strict {
        for k in obj.keys() {
            if !allowed.contains(&k.as_str()) {
                issue!(issues, format!("{path}.{k}"), "unknown field (strict mode)");
            }
        }
    }
}

#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
fn validate_trajectory_obj(
    root: &Value,
    path: &str,
    mode: Mode,
    issues: &mut Vec<ValidationIssue>,
    top_level: bool,
    depth: usize,
    ancestors: &mut std::collections::HashSet<String>,
) {
    // Round-25 F4: cap recursion depth. `subagent_trajectories`
    // recurses; adversarial nesting could otherwise stack-overflow
    // the validator. Return without adding the whole subtree's
    // findings — one clear message beats a stack unwind.
    if depth > MAX_NESTED_DEPTH {
        issue!(
            issues,
            path,
            "trajectory nesting exceeds {MAX_NESTED_DEPTH}; refusing to recurse further"
        );
        return;
    }
    let Some(obj) = root.as_object() else {
        issue!(issues, path, "trajectory must be a JSON object");
        return;
    };
    check_unknown_fields(obj, TRAJECTORY_FIELDS, path, mode, issues);

    // Round-40 F3: ancestor-cycle detection. Insert this frame's
    // trajectory_id (if any) into the shared ancestor set BEFORE
    // recursing into `subagent_trajectories`. If the id is already
    // in the set, an ancestor already claimed it — the tree encodes
    // a false recursive self-call. On the way out, we remove the id
    // so a subtree A -> B -> C at one branch does not also flag
    // A -> D -> C at a sibling branch. `inserted_id` records
    // whether we actually added an id (empty / missing ids are
    // ignored so they don't accidentally clash).
    let inserted_id: Option<String> = obj
        .get("trajectory_id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .and_then(|id| {
            if ancestors.insert(id.to_owned()) {
                Some(id.to_owned())
            } else {
                issue!(
                    issues,
                    format!("{path}.trajectory_id"),
                    "trajectory_id {id:?} appears as one of its own ancestors (cycle)"
                );
                None
            }
        });

    // schema_version
    let version = match obj.get("schema_version").and_then(Value::as_str) {
        Some(v) if SUPPORTED_VERSIONS.contains(&v) => parse_version(v),
        Some(v) => {
            issue!(
                issues,
                format!("{path}.schema_version"),
                "unsupported version {v:?} (supported: v1.0-v1.7)"
            );
            None
        }
        None => {
            issue!(
                issues,
                format!("{path}.schema_version"),
                "required field is missing"
            );
            None
        }
    };
    let ver = version.unwrap_or((1, 7));

    // Version gates on root fields.
    if obj.contains_key("extra") && ver < (1, 1) {
        issue!(
            issues,
            format!("{path}.extra"),
            "field requires ATIF-v1.1+, file is v{}.{}",
            ver.0,
            ver.1
        );
    }
    for f in ["trajectory_id", "subagent_trajectories"] {
        if obj.contains_key(f) && ver < (1, 7) {
            issue!(
                issues,
                format!("{path}.{f}"),
                "field requires ATIF-v1.7+, file is v{}.{}",
                ver.0,
                ver.1
            );
        }
    }
    // Optional string fields: `and_then(Value::as_str)` elsewhere treats
    // a wrong-typed value like an absent one, so e.g. `"notes": 42`
    // passed Strict validation with zero issues yet fails typed
    // deserialization. Flag the type mismatch explicitly (null stays
    // legal — serde maps it to None).
    for f in ["session_id", "trajectory_id", "notes", "continued_trajectory_ref"] {
        if obj.get(f).is_some_and(|v| !v.is_string() && !v.is_null()) {
            issue!(issues, format!("{path}.{f}"), "must be a string");
        }
    }
    // session_id optionality was relaxed in v1.7; older files must carry it.
    // A present-but-wrong-typed value is a type error (flagged above), not
    // a missing field.
    if top_level && ver < (1, 7) && obj.get("session_id").is_none_or(Value::is_null) {
        issue!(
            issues,
            format!("{path}.session_id"),
            "required field is missing (optional only since v1.7)"
        );
    }

    // agent
    match obj.get("agent") {
        Some(Value::Object(agent)) => {
            check_unknown_fields(agent, AGENT_FIELDS, &format!("{path}.agent"), mode, issues);
            for req in ["name", "version"] {
                match agent.get(req).and_then(Value::as_str) {
                    Some(s) if !s.is_empty() => {}
                    Some(_) => issue!(issues, format!("{path}.agent.{req}"), "must be non-empty"),
                    None => issue!(issues, format!("{path}.agent.{req}"), "required field is missing"),
                }
            }
            // Round-16 F2: optional-string type check parity with the
            // trajectory-root optional strings above. `Trajectory` types
            // `model_name` as `Option<String>`, so a wrong-typed value
            // (`model_name: 123`) would fail typed deserialization but
            // used to pass Strict — the schema at
            // `schemas/atif-v1.7.schema.json` also declares it as
            // `string`. Flag the type mismatch so the strict validator
            // does not silently accept documents the schema refuses.
            if agent
                .get("model_name")
                .is_some_and(|v| !v.is_string() && !v.is_null())
            {
                issue!(issues, format!("{path}.agent.model_name"), "must be a string");
            }
            if agent.contains_key("tool_definitions") && ver < (1, 5) {
                issue!(
                    issues,
                    format!("{path}.agent.tool_definitions"),
                    "field requires ATIF-v1.5+, file is v{}.{}",
                    ver.0,
                    ver.1
                );
            }
            // Round-6 (hunt2 F1): `Agent.tool_definitions` is
            // `Option<Vec<Map>>` on the typed model — an array-of-object
            // shape. STEP_FIELDS-style presence gating alone let a
            // wrong-typed value pass the strict validator while
            // deserialization then failed.
            if let Some(defs) = agent.get("tool_definitions") {
                match defs.as_array() {
                    Some(items) => {
                        // Schema: `maxItems: 512`, items `maxProperties:
                        // 128`. Without these the strict validator
                        // accepted documents the shipped schema rejects,
                        // breaking the declared strict-valid ⇒
                        // schema-valid invariant (golden.rs).
                        if items.len() > 512 {
                            issue!(
                                issues,
                                format!("{path}.agent.tool_definitions"),
                                "must not contain more than 512 definitions (schema maxItems)"
                            );
                        }
                        for (index, item) in items.iter().enumerate() {
                            match item.as_object() {
                                Some(map) if map.len() > 128 => issue!(
                                    issues,
                                    format!("{path}.agent.tool_definitions[{index}]"),
                                    "must not carry more than 128 properties (schema maxProperties)"
                                ),
                                Some(_) => {}
                                None => issue!(
                                    issues,
                                    format!("{path}.agent.tool_definitions[{index}]"),
                                    "must be an object"
                                ),
                            }
                        }
                    }
                    None if !defs.is_null() => issue!(
                        issues,
                        format!("{path}.agent.tool_definitions"),
                        "must be an array of objects"
                    ),
                    None => {}
                }
            }
        }
        Some(_) => issue!(issues, format!("{path}.agent"), "must be an object"),
        None => issue!(issues, format!("{path}.agent"), "required field is missing"),
    }

    // Round-24 F1 (av-atif validate): pre-collect embedded
    // `subagent_trajectories[*].trajectory_id` so we can cross-check
    // step-level `subagent_trajectory_ref` entries against them.
    // Historically the ref shape was only "must have trajectory_id
    // or trajectory_path"; a producer could emit `trajectory_id:
    // "does-not-exist"` and it would pass validation, giving
    // unverifiable delegation provenance. Collect the id set here so
    // `validate_step` (via observation.results processing) can flag
    // dangling refs.
    let embedded_trajectory_ids: std::collections::HashSet<String> =
        match obj.get("subagent_trajectories").and_then(Value::as_array) {
            Some(subs) => subs
                .iter()
                .filter_map(|sub| {
                    sub.get("trajectory_id")
                        .and_then(Value::as_str)
                        .filter(|id| !id.is_empty())
                        .map(str::to_owned)
                })
                .collect(),
            None => std::collections::HashSet::new(),
        };

    // steps
    match obj.get("steps") {
        Some(Value::Array(steps)) => {
            if steps.is_empty() {
                issue!(issues, format!("{path}.steps"), "must contain at least one step");
            }
            for (i, step) in steps.iter().enumerate() {
                validate_step(
                    step,
                    &format!("{path}.steps.{i}"),
                    i,
                    ver,
                    mode,
                    issues,
                    &embedded_trajectory_ids,
                );
            }
        }
        Some(_) => issue!(issues, format!("{path}.steps"), "must be an array"),
        None => issue!(issues, format!("{path}.steps"), "required field is missing"),
    }

    // final_metrics
    if let Some(fm) = obj.get("final_metrics") {
        match fm.as_object() {
            Some(m) => {
                check_unknown_fields(
                    m,
                    FINAL_METRICS_FIELDS,
                    &format!("{path}.final_metrics"),
                    mode,
                    issues,
                );
                for f in [
                    "total_prompt_tokens",
                    "total_completion_tokens",
                    "total_cached_tokens",
                    "total_steps",
                ] {
                    if let Some(v) = m.get(f) {
                        if !v.is_u64() {
                            issue!(
                                issues,
                                format!("{path}.final_metrics.{f}"),
                                "must be a non-negative integer"
                            );
                        }
                    }
                }
                if let Some(v) = m.get("total_cost_usd") {
                    match v.as_f64() {
                        Some(n) if n.is_finite() && (0.0..=MAX_COST_USD).contains(&n) => {}
                        Some(_) => issue!(
                            issues,
                            format!("{path}.final_metrics.total_cost_usd"),
                            "must be a finite non-negative number ≤ {MAX_COST_USD:e}"
                        ),
                        None => issue!(
                            issues,
                            format!("{path}.final_metrics.total_cost_usd"),
                            "must be a number"
                        ),
                    }
                }
            }
            None => issue!(issues, format!("{path}.final_metrics"), "must be an object"),
        }
    }

    // subagent trajectories recurse with the same rules.
    match obj.get("subagent_trajectories") {
        Some(Value::Array(subs)) => {
            let mut trajectory_ids = std::collections::HashSet::new();
            for (i, sub) in subs.iter().enumerate() {
                let id = sub
                    .get("trajectory_id")
                    .and_then(Value::as_str)
                    .filter(|id| !id.is_empty());
                match id {
                    Some(id) if trajectory_ids.insert(id.to_owned()) => {}
                    Some(id) => issue!(
                        issues,
                        format!("{path}.subagent_trajectories.{i}.trajectory_id"),
                        "duplicate embedded trajectory_id {id:?}"
                    ),
                    None => issue!(
                        issues,
                        format!("{path}.subagent_trajectories.{i}.trajectory_id"),
                        "required for embedded subagent trajectories"
                    ),
                }
                validate_trajectory_obj(
                    sub,
                    &format!("{path}.subagent_trajectories.{i}"),
                    mode,
                    issues,
                    false,
                    depth + 1,
                    ancestors,
                );
            }
        }
        // A non-array value previously slipped through (no else-arm) yet
        // fails typed deserialization. Null stays legal (serde -> None).
        Some(v) if !v.is_null() => issue!(
            issues,
            format!("{path}.subagent_trajectories"),
            "must be an array"
        ),
        _ => {}
    }

    // Round-40 F3: remove this frame's id so sibling branches (a
    // different subtree at the same ancestor) can legitimately
    // reuse the id without triggering a false-positive cycle.
    if let Some(id) = inserted_id {
        ancestors.remove(&id);
    }
}

fn validate_step(
    step: &Value,
    path: &str,
    index: usize,
    ver: (u32, u32),
    mode: Mode,
    issues: &mut Vec<ValidationIssue>,
    embedded_trajectory_ids: &std::collections::HashSet<String>,
) {
    let Some(obj) = step.as_object() else {
        issue!(issues, path, "step must be an object");
        return;
    };
    check_unknown_fields(obj, STEP_FIELDS, path, mode, issues);

    // step_id: sequential from 1.
    let expected = index as u64 + 1;
    match obj.get("step_id").and_then(Value::as_u64) {
        Some(id) if id == expected => {}
        Some(id) => {
            issue!(
                issues,
                format!("{path}.step_id"),
                "expected {expected} (sequential from 1), got {id}"
            );
        }
        None => issue!(
            issues,
            format!("{path}.step_id"),
            "required field is missing or not an integer"
        ),
    }

    // timestamp: optional ISO 8601.
    if let Some(timestamp) = obj.get("timestamp") {
        match timestamp.as_str() {
            Some(ts) if is_iso8601(ts) => {}
            Some(ts) => issue!(
                issues,
                format!("{path}.timestamp"),
                "invalid ISO-8601 timestamp {ts:?}"
            ),
            None => issue!(issues, format!("{path}.timestamp"), "must be a string"),
        }
    }

    // source.
    let source = obj.get("source").and_then(Value::as_str);
    match source {
        Some("system" | "user" | "agent") => {}
        Some(s) => issue!(
            issues,
            format!("{path}.source"),
            "invalid source {s:?} (system|user|agent)"
        ),
        None => issue!(issues, format!("{path}.source"), "required field is missing"),
    }

    match obj.get("message") {
        Some(Value::String(_) | Value::Array(_)) => {}
        Some(_) => issue!(
            issues,
            format!("{path}.message"),
            "must be a string or content-part array"
        ),
        None => issue!(issues, format!("{path}.message"), "required field is missing"),
    }

    if obj
        .get("reasoning_effort")
        .is_some_and(|value| !value.is_string() && !value.is_number())
    {
        issue!(
            issues,
            format!("{path}.reasoning_effort"),
            "must be a string or number"
        );
    }

    // Round-16 F2: `Step.model_name` is `Option<String>` on the typed
    // model; a wrong-typed value (`"model_name": 123`) fails typed
    // deserialisation but used to pass Strict.
    if obj
        .get("model_name")
        .is_some_and(|v| !v.is_string() && !v.is_null())
    {
        issue!(issues, format!("{path}.model_name"), "must be a string");
    }

    // Round-6 (hunt2 F1): `Step.is_copied_context` is `Option<bool>`
    // on the typed model. It was only listed in STEP_FIELDS (so
    // check_unknown_fields let it through) but never type-checked, so
    // a wrong-typed value (`"is_copied_context": "yes"`) diverged the
    // CLI validator ("valid") from the typed deserializer ("invalid").
    if obj
        .get("is_copied_context")
        .is_some_and(|v| !v.is_boolean() && !v.is_null())
    {
        issue!(issues, format!("{path}.is_copied_context"), "must be a boolean");
    }

    // Agent-only fields.
    if let Some(src) = source {
        if src != "agent" {
            for f in AGENT_ONLY_STEP_FIELDS {
                if obj.contains_key(*f) {
                    issue!(
                        issues,
                        format!("{path}.{f}"),
                        "agent-only field present on {src} step"
                    );
                }
            }
            // observation: agent always; system since v1.2; never user.
            if obj.contains_key("observation") {
                let ok = src == "system" && ver >= (1, 2);
                if !ok {
                    issue!(
                        issues,
                        format!("{path}.observation"),
                        "observation not allowed on {src} step (system steps require v1.2+)"
                    );
                }
            }
        }
    }

    if obj.contains_key("llm_call_count") && ver < (1, 7) {
        issue!(
            issues,
            format!("{path}.llm_call_count"),
            "field requires ATIF-v1.7+"
        );
    }
    // Wrong-typed values must be flagged, not silently treated as absent:
    // `and_then(Value::as_u64)` below maps `"llm_call_count": "1"` to None,
    // which passed Strict validation while typed deserialization fails
    // (same class as the optional-string fields at the trajectory root).
    if obj
        .get("llm_call_count")
        .is_some_and(|v| !v.is_u64() && !v.is_null())
    {
        issue!(
            issues,
            format!("{path}.llm_call_count"),
            "must be a non-negative integer"
        );
    }
    if source == Some("agent") && obj.get("llm_call_count").and_then(Value::as_u64) == Some(0) {
        for field in ["metrics", "reasoning_content"] {
            if obj.contains_key(field) {
                issue!(
                    issues,
                    format!("{path}.{field}"),
                    "must be absent when llm_call_count is 0"
                );
            }
        }
    }

    // Multimodal content-part arrays require v1.6+.
    if ver < (1, 6) {
        if let Some(Value::Array(_)) = obj.get("message") {
            issue!(
                issues,
                format!("{path}.message"),
                "content-part arrays require ATIF-v1.6+"
            );
        }
    }

    // tool_calls + observation cross-references.
    //
    // `HashSet<String>` instead of `Vec<String>` so duplicate detection
    // AND the observation source-id lookup below run in O(N + M)
    // instead of O(N² + N·M). A `trajectory.json` with 100k tool calls
    // and 100k observation results used to burn ~10¹⁰ string
    // comparisons in the CLI validator (used by CI, promotion, and
    // external auditors on untrusted files).
    let mut call_ids: std::collections::HashSet<String> = std::collections::HashSet::new();
    if let Some(tc) = obj.get("tool_calls") {
        match tc.as_array() {
            Some(calls) => {
                for (j, call) in calls.iter().enumerate() {
                    let cpath = format!("{path}.tool_calls.{j}");
                    let Some(c) = call.as_object() else {
                        issue!(issues, cpath, "tool call must be an object");
                        continue;
                    };
                    check_unknown_fields(c, TOOL_CALL_FIELDS, &cpath, mode, issues);
                    if c.contains_key("extra") && ver < (1, 7) {
                        issue!(issues, format!("{cpath}.extra"), "field requires ATIF-v1.7+");
                    }
                    match c.get("tool_call_id").and_then(Value::as_str) {
                        Some(id) if !id.is_empty() => {
                            if !call_ids.insert(id.to_owned()) {
                                issue!(issues, format!("{cpath}.tool_call_id"), "duplicate id {id:?}");
                            }
                        }
                        _ => issue!(
                            issues,
                            format!("{cpath}.tool_call_id"),
                            "required field is missing"
                        ),
                    }
                    if c.get("function_name")
                        .and_then(Value::as_str)
                        .is_none_or(str::is_empty)
                    {
                        issue!(
                            issues,
                            format!("{cpath}.function_name"),
                            "required field is missing"
                        );
                    }
                    match c.get("arguments") {
                        Some(Value::Object(_)) => {}
                        Some(_) => issue!(issues, format!("{cpath}.arguments"), "must be an object"),
                        None => issue!(issues, format!("{cpath}.arguments"), "required field is missing"),
                    }
                }
            }
            None => issue!(issues, format!("{path}.tool_calls"), "must be an array"),
        }
    }

    if let Some(observation) = obj.get("observation") {
        let opath = format!("{path}.observation");
        match observation.as_object() {
            Some(o) => {
                check_unknown_fields(o, &["results"], &opath, mode, issues);
                match o.get("results").and_then(Value::as_array) {
                    Some(results) => {
                        for (j, r) in results.iter().enumerate() {
                            let rpath = format!("{opath}.results.{j}");
                            let Some(res) = r.as_object() else {
                                issue!(issues, rpath, "result must be an object");
                                continue;
                            };
                            check_unknown_fields(res, OBS_RESULT_FIELDS, &rpath, mode, issues);
                            if res.contains_key("extra") && ver < (1, 7) {
                                issue!(issues, format!("{rpath}.extra"), "field requires ATIF-v1.7+");
                            }
                            if let Some(content) = res.get("content") {
                                if !content.is_string() && !content.is_array() {
                                    issue!(
                                        issues,
                                        format!("{rpath}.content"),
                                        "must be a string or content-part array"
                                    );
                                } else if ver < (1, 6) && content.is_array() {
                                    issue!(
                                        issues,
                                        format!("{rpath}.content"),
                                        "content-part arrays require ATIF-v1.6+"
                                    );
                                }
                            }
                            // Wrong-typed refs must be flagged, not silently
                            // treated as absent (`and_then(Value::as_array)`
                            // maps an object/string here to None).
                            if res
                                .get("subagent_trajectory_ref")
                                .is_some_and(|v| !v.is_array() && !v.is_null())
                            {
                                issue!(
                                    issues,
                                    format!("{rpath}.subagent_trajectory_ref"),
                                    "must be an array"
                                );
                            }
                            if let Some(references) =
                                res.get("subagent_trajectory_ref").and_then(Value::as_array)
                            {
                                // Round-33 F3: version gate parity with
                                // the sibling root-level
                                // `subagent_trajectories` (v1.7-only).
                                // Both were introduced in v1.7 per the
                                // shipped schema; without this check an
                                // ATIF-v1.0 file carrying the ref field
                                // inside observation.results[] slipped
                                // past both Strict and Compat modes
                                // silently.
                                if ver < (1, 7) {
                                    issue!(
                                        issues,
                                        format!("{rpath}.subagent_trajectory_ref"),
                                        "field requires ATIF-v1.7+, file is v{}.{}",
                                        ver.0,
                                        ver.1
                                    );
                                }
                                for (k, reference) in references.iter().enumerate() {
                                    let ref_path = format!("{rpath}.subagent_trajectory_ref.{k}");
                                    let Some(reference) = reference.as_object() else {
                                        issue!(issues, ref_path, "must be an object");
                                        continue;
                                    };
                                    check_unknown_fields(
                                        reference,
                                        SUBAGENT_REF_FIELDS,
                                        &ref_path,
                                        mode,
                                        issues,
                                    );
                                    // Round-16 F2: each SubagentTrajectoryRef
                                    // typed member is `Option<String>` in
                                    // model.rs. Wrong-typed values would
                                    // fail typed deserialisation but used
                                    // to only surface as the misleading
                                    // "must set trajectory_id or
                                    // trajectory_path" — because the
                                    // has_id/has_path check maps a bad
                                    // type to None via `as_str`.
                                    for field in ["trajectory_id", "session_id", "trajectory_path"] {
                                        if reference
                                            .get(field)
                                            .is_some_and(|v| !v.is_string() && !v.is_null())
                                        {
                                            issue!(issues, format!("{ref_path}.{field}"), "must be a string");
                                        }
                                    }
                                    let has_id = reference
                                        .get("trajectory_id")
                                        .and_then(Value::as_str)
                                        .is_some_and(|value| !value.is_empty());
                                    let has_path = reference
                                        .get("trajectory_path")
                                        .and_then(Value::as_str)
                                        .is_some_and(|value| !value.is_empty());
                                    if !has_id && !has_path {
                                        issue!(issues, ref_path, "must set trajectory_id or trajectory_path");
                                    }
                                    // Round-24 F1 (av-atif validate):
                                    // if `trajectory_id` names an
                                    // embedded delegation, it MUST
                                    // resolve. A dangling id is
                                    // unverifiable delegation
                                    // provenance — a producer could
                                    // point downstream auditors at
                                    // "sub-999" that never existed.
                                    // `trajectory_path` remains
                                    // uncheckable at strict-validate
                                    // time (external ref) and is not
                                    // subject to this rule.
                                    if let Some(id) = reference
                                        .get("trajectory_id")
                                        .and_then(Value::as_str)
                                        .filter(|v| !v.is_empty())
                                    {
                                        if !embedded_trajectory_ids.contains(id) {
                                            issue!(
                                                issues,
                                                format!("{ref_path}.trajectory_id"),
                                                "references trajectory_id {id:?} that is not present in \
                                                 the outer trajectory's `subagent_trajectories` array"
                                            );
                                        }
                                    }
                                }
                            }
                            match res.get("source_call_id") {
                                None | Some(Value::Null) => {}
                                Some(Value::String(src_id)) => {
                                    if !call_ids.contains(src_id.as_str()) {
                                        issue!(
                                            issues,
                                            format!("{rpath}.source_call_id"),
                                            "references unknown tool_call_id {src_id:?} (must match a tool call in the same step)"
                                        );
                                    }
                                }
                                // Wrong-typed ids must be flagged, not silently
                                // skipped: `and_then(Value::as_str)` mapped
                                // `"source_call_id": 123` to None, bypassing
                                // the same-step linkage check entirely.
                                Some(_) => {
                                    issue!(issues, format!("{rpath}.source_call_id"), "must be a string")
                                }
                            }
                        }
                    }
                    None => issue!(
                        issues,
                        format!("{opath}.results"),
                        "required field is missing or not an array"
                    ),
                }
            }
            None => issue!(issues, opath, "must be an object"),
        }
    }

    if mode == Mode::Strict
        && ver >= (1, 7)
        && source == Some("agent")
        && obj.get("llm_call_count").and_then(Value::as_u64) != Some(0)
    {
        match obj.get("metrics").and_then(Value::as_object) {
            Some(metrics) => {
                for field in ["prompt_tokens", "completion_tokens", "cached_tokens"] {
                    if !metrics.contains_key(field) {
                        issue!(
                            issues,
                            format!("{path}.metrics.{field}"),
                            "required for strict ATIF-v1.7 agent-step fidelity"
                        );
                    }
                }
            }
            None => issue!(
                issues,
                format!("{path}.metrics"),
                "required for strict ATIF-v1.7 agent-step fidelity"
            ),
        }
    }

    // metrics.
    if let Some(metrics) = obj.get("metrics") {
        let mpath = format!("{path}.metrics");
        match metrics.as_object() {
            Some(m) => {
                check_unknown_fields(m, METRICS_FIELDS, &mpath, mode, issues);
                for f in ["prompt_tokens", "completion_tokens", "cached_tokens"] {
                    if let Some(v) = m.get(f) {
                        if !v.is_u64() {
                            issue!(issues, format!("{mpath}.{f}"), "must be a non-negative integer");
                        }
                    }
                }
                if let Some(v) = m.get("cost_usd") {
                    match v.as_f64() {
                        Some(n) if n.is_finite() && (0.0..=MAX_COST_USD).contains(&n) => {}
                        Some(_) => issue!(
                            issues,
                            format!("{mpath}.cost_usd"),
                            "must be a finite non-negative number ≤ {MAX_COST_USD:e}"
                        ),
                        None => issue!(issues, format!("{mpath}.cost_usd"), "must be a number"),
                    }
                }
                if m.contains_key("completion_token_ids") && ver < (1, 3) {
                    issue!(
                        issues,
                        format!("{mpath}.completion_token_ids"),
                        "field requires ATIF-v1.3+"
                    );
                }
                if m.contains_key("prompt_token_ids") && ver < (1, 4) {
                    issue!(
                        issues,
                        format!("{mpath}.prompt_token_ids"),
                        "field requires ATIF-v1.4+"
                    );
                }
                // Round-6 (hunt2 F1): strict-mode type checks for
                // fields the round-16 F2 sweep missed. The typed model
                // rejects a wrong type at deserialize (e.g. logprobs =
                // "x"), but validate_bytes/validate_value(Strict)
                // previously only presence-gated these — so the CLI
                // said "valid" while the harness reconciler's typed
                // path said "invalid", diverging the two verdicts on
                // the same file.
                if let Mode::Strict = mode {
                    for numeric_array_field in ["logprobs", "completion_token_ids", "prompt_token_ids"] {
                        if let Some(v) = m.get(numeric_array_field) {
                            match v.as_array() {
                                Some(items) => {
                                    for (index, item) in items.iter().enumerate() {
                                        if !item.is_number() {
                                            issue!(
                                                issues,
                                                format!("{mpath}.{numeric_array_field}[{index}]"),
                                                "must be a number"
                                            );
                                        }
                                    }
                                }
                                None => issue!(
                                    issues,
                                    format!("{mpath}.{numeric_array_field}"),
                                    "must be an array of numbers"
                                ),
                            }
                        }
                    }
                }
            }
            None => issue!(issues, mpath, "must be an object"),
        }
    }
}

/// Minimal-but-strict ISO-8601 validation: `YYYY-MM-DDTHH:MM:SS[.fff...][Z|±HH:MM]`.
fn is_iso8601(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() < 19 {
        return false;
    }
    let digits = |range: std::ops::Range<usize>| -> Option<u32> {
        let slice = b.get(range)?;
        let mut n: u32 = 0;
        for &c in slice {
            if !c.is_ascii_digit() {
                return None;
            }
            n = n.checked_mul(10)?.checked_add(u32::from(c - b'0'))?;
        }
        Some(n)
    };
    let sep = |i: usize, ch: u8| b.get(i) == Some(&ch);
    let (Some(year), Some(month), Some(day)) = (digits(0..4), digits(5..7), digits(8..10)) else {
        return false;
    };
    if !(sep(4, b'-') && sep(7, b'-') && (sep(10, b'T') || sep(10, b't'))) {
        return false;
    }
    let (Some(hour), Some(min), Some(sec)) = (digits(11..13), digits(14..16), digits(17..19)) else {
        return false;
    };
    if !(sep(13, b':') && sep(16, b':')) {
        return false;
    }
    if !(1..=12).contains(&month) || hour > 23 || min > 59 || sec > 60 {
        return false;
    }
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let dim = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ => {
            if leap {
                29
            } else {
                28
            }
        }
    };
    if day == 0 || day > dim {
        return false;
    }
    // Fraction + timezone tail.
    let mut i = 19;
    if b.get(i) == Some(&b'.') {
        i += 1;
        let start = i;
        while b.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
        if i == start {
            return false; // dot with no digits
        }
    }
    match b.get(i) {
        // Naive timestamps (no timezone) are valid bare ISO-8601, but
        // the shipped schema pins `format: date-time` (RFC 3339), which
        // REQUIRES an offset — a naive timestamp passing strict here
        // while failing external schema tooling broke the strict-valid
        // ⇒ schema-valid invariant.
        None => false,
        Some(b'Z' | b'z') => i + 1 == b.len(),
        Some(b'+' | b'-') => {
            let (Some(oh), Some(om)) = (digits(i + 1..i + 3), digits(i + 4..i + 6)) else {
                return false;
            };
            sep(i + 3, b':') && oh <= 14 && om <= 59 && i + 6 == b.len()
        }
        _ => false,
    }
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

    /// Round-20: a maliciously crafted trajectory containing tens of
    /// thousands of unknown fields must NOT allocate an unbounded
    /// Vec<ValidationIssue>. The cap fires and a synthetic
    /// truncation marker signals the tail.
    #[test]
    fn issue_collection_is_bounded_and_marks_truncation() {
        // Build a trajectory-shaped Value with thousands of unknown
        // fields at the top level. Each triggers one issue in strict
        // mode. Well past the MAX_VALIDATION_ISSUES cap.
        let mut map = serde_json::Map::new();
        map.insert("schema_version".into(), Value::String("1.7".into()));
        map.insert("session_id".into(), Value::String("s".into()));
        map.insert("agent".into(), serde_json::json!({"name": "a", "version": "1"}));
        map.insert(
            "steps".into(),
            serde_json::json!([{
                "step_id": 1,
                "source": "user",
                "message": "hi",
            }]),
        );
        for i in 0..(MAX_VALIDATION_ISSUES + 500) {
            map.insert(format!("unknown_{i}"), Value::Null);
        }
        let value = Value::Object(map);
        let issues = validate_value(&value, Mode::Strict);
        assert!(
            issues.len() <= MAX_VALIDATION_ISSUES + 1,
            "issue Vec is unbounded: {}",
            issues.len()
        );
        // Last entry must be the synthetic truncation marker.
        let last = issues.last().expect("at least one issue");
        assert!(
            last.message.contains("hit the ") && last.message.contains("issue cap"),
            "expected truncation marker, got: {:?}",
            last.message
        );
    }

    #[test]
    fn iso8601_accepts_valid_forms() {
        for ts in [
            "2025-01-15T10:30:00Z",
            "2025-01-15T10:30:00.123Z",
            "2024-02-29T23:59:59Z",
            "2025-06-30T23:59:60Z",
            "2025-01-15T10:30:00+05:30",
            "2025-01-15T10:30:00.999999-08:00",
        ] {
            assert!(is_iso8601(ts), "should accept {ts}");
        }
    }

    #[test]
    fn iso8601_rejects_invalid_forms() {
        for ts in [
            "",
            "2025-01-15 10:30:00Z",
            "2025-13-01T00:00:00Z",
            "2025-02-29T00:00:00Z",
            "2025-01-32T00:00:00Z",
            // Naive (offset-less) timestamps are valid bare ISO-8601 but
            // NOT RFC 3339 — the shipped schema's `format: date-time`
            // rejects them, so strict must too (strict ⇒ schema-valid).
            "2025-01-15T10:30:00",
            "2025-01-15T24:00:00Z",
            "2025-01-15T10:61:00Z",
            "2025-01-15T10:30:00.Z",
            "2025-01-15T10:30:00ZZ",
            "2025-01-15T10:30:00+5:30",
            "not-a-date",
        ] {
            assert!(!is_iso8601(ts), "should reject {ts}");
        }
    }

    #[test]
    fn version_parse() {
        assert_eq!(parse_version("ATIF-v1.7"), Some((1, 7)));
        assert_eq!(parse_version("ATIF-v1.0"), Some((1, 0)));
        assert_eq!(parse_version("v1.7"), None);
        assert_eq!(parse_version("ATIF-v1"), None);
    }

    /// Wrong-typed optional fields must be flagged: `and_then(Value::as_str)`
    /// used to skip them silently, so documents that fail typed
    /// deserialization passed Strict validation with zero issues.
    #[test]
    fn wrong_typed_optional_fields_are_flagged() {
        let value = serde_json::json!({
            "schema_version": "ATIF-v1.7",
            "session_id": 123,
            "trajectory_id": 42,
            "notes": 42,
            "continued_trajectory_ref": {},
            "subagent_trajectories": "nope",
            "agent": {"name": "a", "version": "1"},
            "steps": [{"step_id": 1, "source": "user", "message": "hi"}],
        });
        let issues = validate_value(&value, Mode::Strict);
        for f in ["session_id", "trajectory_id", "notes", "continued_trajectory_ref"] {
            assert!(
                issues
                    .iter()
                    .any(|i| i.path == format!("trajectory.{f}") && i.message == "must be a string"),
                "expected type issue for {f}: {issues:?}"
            );
        }
        assert!(
            issues
                .iter()
                .any(|i| i.path == "trajectory.subagent_trajectories" && i.message == "must be an array"),
            "expected array issue: {issues:?}"
        );
        // Validator and serde must agree: typed deserialization also rejects.
        assert!(serde_json::from_value::<crate::model::Trajectory>(value).is_err());
    }

    /// Wrong-typed step-level optional fields must be flagged, not silently
    /// treated as absent: `llm_call_count`, `source_call_id`, and
    /// `subagent_trajectory_ref` all used `and_then(as_*)`, which mapped a
    /// wrong-typed value to `None` and passed Strict validation while typed
    /// deserialization fails.
    #[test]
    fn wrong_typed_step_fields_are_flagged() {
        let value = serde_json::json!({
            "schema_version": "ATIF-v1.7",
            "session_id": "s",
            "agent": {"name": "a", "version": "1"},
            "steps": [{
                "step_id": 1,
                "source": "agent",
                "message": "hi",
                "llm_call_count": "1",
                "metrics": {"prompt_tokens": 1, "completion_tokens": 1, "cached_tokens": 0},
                "observation": {"results": [{
                    "source_call_id": 123,
                    "subagent_trajectory_ref": {"trajectory_id": "x"},
                }]},
            }],
        });
        let issues = validate_value(&value, Mode::Strict);
        let results_path = "trajectory.steps.0.observation.results.0";
        for (path, message) in [
            (
                "trajectory.steps.0.llm_call_count",
                "must be a non-negative integer",
            ),
            (&format!("{results_path}.source_call_id"), "must be a string"),
            (
                &format!("{results_path}.subagent_trajectory_ref"),
                "must be an array",
            ),
        ] {
            assert!(
                issues.iter().any(|i| i.path == path && i.message == message),
                "expected {message:?} at {path}: {issues:?}"
            );
        }
        // Null means absent for the typed model and for compat mode;
        // strict mode rejects it for schema parity (strict ⇒
        // schema-valid).
        let value = serde_json::json!({
            "schema_version": "ATIF-v1.7",
            "session_id": "s",
            "agent": {"name": "a", "version": "1"},
            "steps": [{
                "step_id": 1,
                "source": "agent",
                "message": "hi",
                "llm_call_count": null,
                "metrics": {"prompt_tokens": 1, "completion_tokens": 1, "cached_tokens": 0},
                "observation": {"results": [{
                    "source_call_id": null,
                    "subagent_trajectory_ref": null,
                }]},
            }],
        });
        let issues = validate_value(&value, Mode::Compat);
        assert!(issues.is_empty(), "compat must tolerate nulls: {issues:?}");
        let issues = validate_value(&value, Mode::Strict);
        assert_eq!(issues.len(), 3, "strict must reject the nulls: {issues:?}");
    }

    /// Mutation-run hardening: the `llm_call_count == 0` consistency
    /// rule (agent steps with zero LLM calls must not carry `metrics`
    /// or `reasoning_content`) had no test — flipping its `==` to `!=`
    /// survived. Pin both sides: 0 + metrics is flagged, nonzero +
    /// metrics is not.
    #[test]
    fn zero_llm_call_count_forbids_metrics_and_reasoning() {
        let step_with = |llm_calls: u64| {
            serde_json::json!({
                "schema_version": "ATIF-v1.7",
                "session_id": "s",
                "agent": {"name": "a", "version": "1"},
                "steps": [{
                    "step_id": 1,
                    "source": "agent",
                    "message": "hi",
                    "llm_call_count": llm_calls,
                    "reasoning_content": "thinking",
                    "metrics": {"prompt_tokens": 1, "completion_tokens": 1, "cached_tokens": 0},
                }],
            })
        };
        let issues = validate_value(&step_with(0), Mode::Strict);
        for field in ["metrics", "reasoning_content"] {
            assert!(
                issues.iter().any(|i| {
                    i.path == format!("trajectory.steps.0.{field}")
                        && i.message.contains("llm_call_count is 0")
                }),
                "expected {field} flagged when llm_call_count is 0: {issues:?}"
            );
        }
        let issues = validate_value(&step_with(1), Mode::Strict);
        assert!(
            !issues.iter().any(|i| i.message.contains("llm_call_count is 0")),
            "nonzero llm_call_count must not trip the zero-call rule: {issues:?}"
        );
    }

    /// Explicit nulls deserialize to `None` for optional fields, so the
    /// type checks must not flag them.
    #[test]
    fn null_optional_fields_remain_valid() {
        let value = serde_json::json!({
            "schema_version": "ATIF-v1.7",
            "session_id": null,
            "notes": null,
            "continued_trajectory_ref": null,
            "subagent_trajectories": null,
            "agent": {"name": "a", "version": "1"},
            "steps": [{"step_id": 1, "source": "user", "message": "hi"}],
        });
        // Compat mode keeps the serde-Option tolerance (null ≡ absent);
        // strict mode now rejects explicit nulls because the shipped
        // schema does (strict ⇒ schema-valid, pinned by golden.rs).
        let issues = validate_value(&value, Mode::Compat);
        assert!(issues.is_empty(), "compat must tolerate nulls: {issues:?}");
        let issues = validate_value(&value, Mode::Strict);
        assert_eq!(
            issues.len(),
            4,
            "strict must reject each explicit null: {issues:?}"
        );
        assert!(serde_json::from_value::<crate::model::Trajectory>(value).is_ok());
    }

    /// Round-23 F2: `validate_bytes` refuses duplicate JSON keys at
    /// any nesting level. Serde-typed parse alone would silently keep
    /// the last value, letting a hostile issuer sign under one
    /// interpretation while an auditor's raw-bytes reader sees the
    /// other.
    #[test]
    fn validate_bytes_rejects_duplicate_top_level_key() {
        let bytes =
            br#"{"schema_version":"ATIF-v9.9","schema_version":"ATIF-v1.7","agent":{"name":"a","version":"1"},"steps":[{"step_id":1,"source":"user","message":"hi"}]}"#;
        let outcome = validate_bytes(bytes, Mode::Strict);
        assert!(
            matches!(&outcome, Err(reason) if reason.contains("schema_version") && reason.contains("duplicate")),
            "expected duplicate-key rejection at bytes level, got {outcome:?}"
        );
    }

    #[test]
    fn validate_bytes_rejects_duplicate_key_inside_step() {
        let bytes = br#"{"schema_version":"ATIF-v1.7","agent":{"name":"a","version":"1"},"steps":[{"step_id":1,"source":"agent","message":"x","message":"y"}]}"#;
        let outcome = validate_bytes(bytes, Mode::Strict);
        assert!(
            matches!(&outcome, Err(reason) if reason.contains("message") && reason.contains("duplicate")),
            "expected duplicate-key rejection inside step, got {outcome:?}"
        );
    }

    /// Round-23 F2 partner: even when the bytes are legit, the
    /// `validate_bytes` path also runs `validate_value` on the
    /// untyped form, exercising `check_unknown_fields` — a rejection
    /// class the typed `validate_trajectory` path silently drops.
    #[test]
    fn validate_bytes_flags_unknown_fields_that_typed_path_would_drop() {
        let bytes = br#"{"schema_version":"ATIF-v1.7","agent":{"name":"a","version":"1"},"steps":[{"step_id":1,"source":"user","message":"hi"}],"future_experimental_field":"planted"}"#;
        let issues = validate_bytes(bytes, Mode::Strict).expect("parses ok");
        assert!(
            issues
                .iter()
                .any(|i| i.message.contains("unknown field")
                    || i.message.contains("future_experimental_field")),
            "unknown field must be flagged in Strict mode: {issues:?}"
        );
    }

    /// Round-24 F1: a `subagent_trajectory_ref` with a `trajectory_id`
    /// must resolve against the outer trajectory's embedded
    /// `subagent_trajectories` array. A dangling id gives
    /// unverifiable delegation provenance — the auditor is pointed at
    /// a subagent trajectory that doesn't exist in the document.
    #[test]
    fn dangling_subagent_trajectory_ref_is_flagged() {
        // Reference an embedded id that DOES NOT appear in
        // subagent_trajectories.
        let value = serde_json::json!({
            "schema_version": "ATIF-v1.7",
            "session_id": "s",
            "agent": {"name": "a", "version": "1"},
            "steps": [{
                "step_id": 1,
                "source": "agent",
                "message": "delegating",
                "tool_calls": [{"tool_call_id": "c1", "function_name": "delegate", "arguments": {}}],
                "observation": {"results": [{
                    "source_call_id": "c1",
                    "subagent_trajectory_ref": [{"trajectory_id": "sub-does-not-exist"}]
                }]},
            }],
            "subagent_trajectories": [{
                "trajectory_id": "sub-actual",
                "agent": {"name": "sub-a", "version": "1"},
                "steps": [{"step_id": 1, "source": "agent", "message": "sub"}]
            }],
        });
        let issues = validate_value(&value, Mode::Strict);
        assert!(
            issues
                .iter()
                .any(|i| i.message.contains("sub-does-not-exist")
                    && i.message.contains("subagent_trajectories")),
            "dangling trajectory_id must be flagged, got {issues:?}"
        );

        // A resolvable ref passes.
        let value = serde_json::json!({
            "schema_version": "ATIF-v1.7",
            "session_id": "s",
            "agent": {"name": "a", "version": "1"},
            "steps": [{
                "step_id": 1,
                "source": "agent",
                "message": "delegating",
                "tool_calls": [{"tool_call_id": "c1", "function_name": "delegate", "arguments": {}}],
                "observation": {"results": [{
                    "source_call_id": "c1",
                    "subagent_trajectory_ref": [{"trajectory_id": "sub-actual"}]
                }]},
            }],
            "subagent_trajectories": [{
                "trajectory_id": "sub-actual",
                "agent": {"name": "sub-a", "version": "1"},
                "steps": [{"step_id": 1, "source": "agent", "message": "sub"}]
            }],
        });
        let issues = validate_value(&value, Mode::Strict);
        assert!(
            !issues
                .iter()
                .any(|i| i.message.contains("not present in the outer")),
            "resolvable subagent_trajectory_ref must not be flagged: {issues:?}"
        );

        // trajectory_path (external ref) is not subject to the check.
        let value = serde_json::json!({
            "schema_version": "ATIF-v1.7",
            "session_id": "s",
            "agent": {"name": "a", "version": "1"},
            "steps": [{
                "step_id": 1,
                "source": "agent",
                "message": "delegating",
                "tool_calls": [{"tool_call_id": "c1", "function_name": "delegate", "arguments": {}}],
                "observation": {"results": [{
                    "source_call_id": "c1",
                    "subagent_trajectory_ref": [{"trajectory_path": "external://s3/bucket/traj.json"}]
                }]},
            }],
        });
        let issues = validate_value(&value, Mode::Strict);
        assert!(
            !issues
                .iter()
                .any(|i| i.message.contains("not present in the outer")),
            "external trajectory_path refs must not be flagged as dangling: {issues:?}"
        );
    }

    /// Pre-1.7 files require `session_id`; a present-but-wrong-typed value
    /// is a type error, not the misleading "required field is missing".
    #[test]
    fn pre_v17_session_id_distinguishes_missing_from_wrong_type() {
        let base = |session_id: Option<Value>| {
            let mut map = serde_json::Map::new();
            map.insert("schema_version".into(), Value::String("ATIF-v1.0".into()));
            if let Some(v) = session_id {
                map.insert("session_id".into(), v);
            }
            map.insert("agent".into(), serde_json::json!({"name": "a", "version": "1"}));
            map.insert(
                "steps".into(),
                serde_json::json!([{"step_id": 1, "source": "user", "message": "hi"}]),
            );
            Value::Object(map)
        };
        let issues = validate_value(&base(None), Mode::Strict);
        assert!(
            issues.iter().any(|i| i.path == "trajectory.session_id"
                && i.message.contains("required field is missing")),
            "missing session_id must be reported: {issues:?}"
        );
        let issues = validate_value(&base(Some(serde_json::json!(123))), Mode::Strict);
        assert!(
            issues
                .iter()
                .any(|i| i.path == "trajectory.session_id" && i.message == "must be a string"),
            "wrong-typed session_id must be a type error: {issues:?}"
        );
        assert!(
            !issues.iter().any(|i| i.path == "trajectory.session_id"
                && i.message.contains("required field is missing")),
            "wrong type must not be reported as missing: {issues:?}"
        );
    }
}
