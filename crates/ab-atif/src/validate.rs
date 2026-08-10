//! ATIF validator, mirroring Harbor's trajectory-validator semantics:
//! validates required fields, types and constraints, sequential step ids
//! (starting from 1), tool-call references in observations, ISO-8601
//! timestamps, agent-only field placement — and collects **all** errors before
//! returning, not just the first.
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

macro_rules! issue {
    ($issues:expr, $path:expr, $($msg:tt)*) => {
        $issues.push(ValidationIssue { path: $path.to_string(), message: format!($($msg)*) })
    };
}

const TRAJECTORY_FIELDS: &[&str] = &[
    "schema_version",
    "session_id",
    "trajectory_id",
    "agent",
    "steps",
    "final_metrics",
    "subagent_trajectories",
    "extra",
];
const AGENT_FIELDS: &[&str] = &["name", "version", "model_name", "tool_definitions", "extra"];
const STEP_FIELDS: &[&str] = &[
    "step_id",
    "timestamp",
    "source",
    "message",
    "reasoning_content",
    "model_name",
    "tool_calls",
    "observation",
    "metrics",
    "llm_call_count",
    "extra",
];
const AGENT_ONLY_STEP_FIELDS: &[&str] =
    &["reasoning_content", "model_name", "tool_calls", "metrics", "llm_call_count"];
const TOOL_CALL_FIELDS: &[&str] = &["tool_call_id", "function_name", "arguments", "extra"];
const OBS_RESULT_FIELDS: &[&str] = &["source_call_id", "content", "extra"];
const METRICS_FIELDS: &[&str] = &[
    "prompt_tokens",
    "completion_tokens",
    "cached_tokens",
    "cost_usd",
    "logprobs",
    "completion_token_ids",
    "prompt_token_ids",
];
const FINAL_METRICS_FIELDS: &[&str] = &[
    "total_prompt_tokens",
    "total_completion_tokens",
    "total_cached_tokens",
    "total_cost_usd",
    "total_steps",
];

/// Validate a raw JSON value as an ATIF trajectory.
pub fn validate_value(root: &Value, mode: Mode) -> Vec<ValidationIssue> {
    let mut issues = Vec::new();
    validate_trajectory_obj(root, "trajectory", mode, &mut issues, true);
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

#[allow(clippy::too_many_lines)]
fn validate_trajectory_obj(
    root: &Value,
    path: &str,
    mode: Mode,
    issues: &mut Vec<ValidationIssue>,
    top_level: bool,
) {
    let Some(obj) = root.as_object() else {
        issue!(issues, path, "trajectory must be a JSON object");
        return;
    };
    check_unknown_fields(obj, TRAJECTORY_FIELDS, path, mode, issues);

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
            issue!(issues, format!("{path}.schema_version"), "required field is missing");
            None
        }
    };
    let ver = version.unwrap_or((1, 7));

    // Version gates on root fields.
    if obj.contains_key("extra") && ver < (1, 1) {
        issue!(issues, format!("{path}.extra"), "field requires ATIF-v1.1+, file is v{}.{}", ver.0, ver.1);
    }
    for f in ["trajectory_id", "subagent_trajectories"] {
        if obj.contains_key(f) && ver < (1, 7) {
            issue!(issues, format!("{path}.{f}"), "field requires ATIF-v1.7+, file is v{}.{}", ver.0, ver.1);
        }
    }
    // session_id optionality was relaxed in v1.7; older files must carry it.
    if top_level && ver < (1, 7) && obj.get("session_id").and_then(Value::as_str).is_none() {
        issue!(issues, format!("{path}.session_id"), "required field is missing (optional only since v1.7)");
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
            if agent.contains_key("tool_definitions") && ver < (1, 5) {
                issue!(
                    issues,
                    format!("{path}.agent.tool_definitions"),
                    "field requires ATIF-v1.5+, file is v{}.{}",
                    ver.0,
                    ver.1
                );
            }
        }
        Some(_) => issue!(issues, format!("{path}.agent"), "must be an object"),
        None => issue!(issues, format!("{path}.agent"), "required field is missing"),
    }

    // steps
    match obj.get("steps") {
        Some(Value::Array(steps)) => {
            for (i, step) in steps.iter().enumerate() {
                validate_step(step, &format!("{path}.steps.{i}"), i, ver, mode, issues);
            }
        }
        Some(_) => issue!(issues, format!("{path}.steps"), "must be an array"),
        None => issue!(issues, format!("{path}.steps"), "required field is missing"),
    }

    // final_metrics
    if let Some(fm) = obj.get("final_metrics") {
        match fm.as_object() {
            Some(m) => {
                check_unknown_fields(m, FINAL_METRICS_FIELDS, &format!("{path}.final_metrics"), mode, issues);
                for f in [
                    "total_prompt_tokens",
                    "total_completion_tokens",
                    "total_cached_tokens",
                    "total_steps",
                ] {
                    if let Some(v) = m.get(f) {
                        if !v.is_u64() {
                            issue!(issues, format!("{path}.final_metrics.{f}"), "must be a non-negative integer");
                        }
                    }
                }
                if let Some(v) = m.get("total_cost_usd") {
                    if !v.is_number() {
                        issue!(issues, format!("{path}.final_metrics.total_cost_usd"), "must be a number");
                    }
                }
            }
            None => issue!(issues, format!("{path}.final_metrics"), "must be an object"),
        }
    }

    // subagent trajectories recurse with the same rules.
    if let Some(Value::Array(subs)) = obj.get("subagent_trajectories") {
        for (i, sub) in subs.iter().enumerate() {
            validate_trajectory_obj(sub, &format!("{path}.subagent_trajectories.{i}"), mode, issues, false);
        }
    }
}

fn validate_step(
    step: &Value,
    path: &str,
    index: usize,
    ver: (u32, u32),
    mode: Mode,
    issues: &mut Vec<ValidationIssue>,
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
            issue!(issues, format!("{path}.step_id"), "expected {expected} (sequential from 1), got {id}");
        }
        None => issue!(issues, format!("{path}.step_id"), "required field is missing or not an integer"),
    }

    // timestamp: ISO 8601.
    match obj.get("timestamp").and_then(Value::as_str) {
        Some(ts) if is_iso8601(ts) => {}
        Some(ts) => issue!(issues, format!("{path}.timestamp"), "invalid ISO-8601 timestamp {ts:?}"),
        None => issue!(issues, format!("{path}.timestamp"), "required field is missing"),
    }

    // source.
    let source = obj.get("source").and_then(Value::as_str);
    match source {
        Some("system" | "user" | "agent") => {}
        Some(s) => issue!(issues, format!("{path}.source"), "invalid source {s:?} (system|user|agent)"),
        None => issue!(issues, format!("{path}.source"), "required field is missing"),
    }

    // Agent-only fields.
    if let Some(src) = source {
        if src != "agent" {
            for f in AGENT_ONLY_STEP_FIELDS {
                if obj.contains_key(*f) {
                    issue!(issues, format!("{path}.{f}"), "agent-only field present on {src} step");
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
        issue!(issues, format!("{path}.llm_call_count"), "field requires ATIF-v1.7+");
    }

    // Multimodal content-part arrays require v1.6+.
    if ver < (1, 6) {
        if let Some(Value::Array(_)) = obj.get("message") {
            issue!(issues, format!("{path}.message"), "content-part arrays require ATIF-v1.6+");
        }
    }

    // tool_calls + observation cross-references.
    let mut call_ids: Vec<String> = Vec::new();
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
                            if call_ids.iter().any(|existing| existing == id) {
                                issue!(issues, format!("{cpath}.tool_call_id"), "duplicate id {id:?}");
                            }
                            call_ids.push(id.to_owned());
                        }
                        _ => issue!(issues, format!("{cpath}.tool_call_id"), "required field is missing"),
                    }
                    if c.get("function_name").and_then(Value::as_str).is_none_or(str::is_empty) {
                        issue!(issues, format!("{cpath}.function_name"), "required field is missing");
                    }
                    if c.get("arguments").is_none() {
                        issue!(issues, format!("{cpath}.arguments"), "required field is missing");
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
                            if res.get("content").is_none() {
                                issue!(issues, format!("{rpath}.content"), "required field is missing");
                            } else if ver < (1, 6) {
                                if let Some(Value::Array(_)) = res.get("content") {
                                    issue!(
                                        issues,
                                        format!("{rpath}.content"),
                                        "content-part arrays require ATIF-v1.6+"
                                    );
                                }
                            }
                            if let Some(src_id) = res.get("source_call_id").and_then(Value::as_str) {
                                if !call_ids.iter().any(|c| c == src_id) {
                                    issue!(
                                        issues,
                                        format!("{rpath}.source_call_id"),
                                        "references unknown tool_call_id {src_id:?} (must match a tool call in the same step)"
                                    );
                                }
                            }
                        }
                    }
                    None => issue!(issues, format!("{opath}.results"), "required field is missing or not an array"),
                }
            }
            None => issue!(issues, opath, "must be an object"),
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
                if m.get("cost_usd").is_some_and(|v| !v.is_number()) {
                    issue!(issues, format!("{mpath}.cost_usd"), "must be a number");
                }
                if m.contains_key("completion_token_ids") && ver < (1, 3) {
                    issue!(issues, format!("{mpath}.completion_token_ids"), "field requires ATIF-v1.3+");
                }
                if m.contains_key("prompt_token_ids") && ver < (1, 4) {
                    issue!(issues, format!("{mpath}.prompt_token_ids"), "field requires ATIF-v1.4+");
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
        None => true, // naive timestamps accepted (Harbor examples use Z, but naive is valid ISO)
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
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

    use super::*;

    #[test]
    fn iso8601_accepts_valid_forms() {
        for ts in [
            "2025-01-15T10:30:00Z",
            "2025-01-15T10:30:00.123Z",
            "2024-02-29T23:59:59Z",
            "2025-06-30T23:59:60Z",
            "2025-01-15T10:30:00+05:30",
            "2025-01-15T10:30:00.999999-08:00",
            "2025-01-15T10:30:00",
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
}
