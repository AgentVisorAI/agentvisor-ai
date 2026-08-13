//! Compression passes over OpenAI-shape chat payloads.

use ab_core::tokens::approx_tokens;
use serde_json::{json, Value};

/// Tuning knobs (config-file surface; defaults follow the brief).
#[derive(Debug, Clone)]
pub struct CompressionConfig {
    /// Never touch the last N messages (short-term memory preservation).
    pub keep_tail: usize,
    /// Tool outputs older than the tail are stubbed when longer than this
    /// many approximate tokens.
    pub tool_output_stub_threshold: u64,
    /// Also collapse exact-duplicate non-system messages.
    pub collapse_duplicates: bool,
    /// Normalize whitespace inside JSON-looking tool content.
    pub normalize_json: bool,
    /// Only bother when the payload reaches at least this many approximate
    /// tokens (compressing tiny payloads wastes hot-path time).
    pub min_tokens_to_engage: u64,
    /// Enable audited middle-history stubbing when other passes cannot reach
    /// the target on very large histories. Only engages when the payload
    /// reaches at least 50 000 approximate tokens (hardcoded floor; trumps
    /// `min_tokens_to_engage` for this pass).
    pub summarize_middle: bool,
    /// Minimum target reduction ratio times 1000.
    pub target_reduction_millis: u64,
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            keep_tail: 8,
            tool_output_stub_threshold: 128,
            collapse_duplicates: true,
            normalize_json: true,
            min_tokens_to_engage: 512,
            summarize_middle: true,
            target_reduction_millis: 300,
        }
    }
}

/// Result of a compression run.
#[derive(Debug, Clone)]
pub struct CompressionOutcome {
    /// The (possibly) compressed payload.
    pub payload: Value,
    /// Approximate tokens before.
    pub tokens_before: u64,
    /// Approximate tokens after.
    pub tokens_after: u64,
    /// Whether any pass modified the payload.
    pub changed: bool,
}

impl CompressionOutcome {
    /// Pruned token count.
    pub fn pruned_tokens(&self) -> u64 {
        self.tokens_before.saturating_sub(self.tokens_after)
    }

    /// Reduction ratio ×1000 (350 = 35.0 %), integer for JCS-exact metrics.
    pub fn pruning_ratio_millis(&self) -> u64 {
        if self.tokens_before == 0 {
            return 0;
        }
        self.pruned_tokens().saturating_mul(1000) / self.tokens_before
    }
}

/// Compress a chat payload. Non-chat or unparsable payloads are returned
/// unchanged (`changed = false`) — this function must never fail the hot path.
pub fn compress(payload: &Value, cfg: &CompressionConfig) -> CompressionOutcome {
    let tokens_before = approx_tokens(&payload.to_string());
    let Some(messages) = payload.get("messages").and_then(Value::as_array) else {
        return CompressionOutcome {
            payload: payload.clone(),
            tokens_before,
            tokens_after: tokens_before,
            changed: false,
        };
    };
    if tokens_before < cfg.min_tokens_to_engage || messages.is_empty() {
        return CompressionOutcome {
            payload: payload.clone(),
            tokens_before,
            tokens_after: tokens_before,
            changed: false,
        };
    }

    let mut out = messages.clone();
    let tail_start = out.len().saturating_sub(cfg.keep_tail);

    let mut changed = false;
    changed |= collapse_duplicate_system(&mut out, tail_start);
    if cfg.collapse_duplicates {
        changed |= collapse_duplicate_messages(&mut out, tail_start);
    }
    changed |= stub_stale_tool_outputs(&mut out, tail_start, cfg.tool_output_stub_threshold);
    if cfg.normalize_json {
        changed |= normalize_json_content(&mut out, tail_start);
    }
    if cfg.summarize_middle && tokens_before >= 50_000 {
        changed |= stub_middle_to_target(
            payload,
            &mut out,
            tail_start,
            tokens_before,
            cfg.target_reduction_millis,
        );
    }

    if !changed {
        return CompressionOutcome {
            payload: payload.clone(),
            tokens_before,
            tokens_after: tokens_before,
            changed: false,
        };
    }
    let mut new_payload = payload.clone();
    if let Some(obj) = new_payload.as_object_mut() {
        obj.insert("messages".to_owned(), Value::Array(out));
    }
    let tokens_after = approx_tokens(&new_payload.to_string());
    // Guard: a pass must never grow the payload; if it somehow did, keep the original.
    if tokens_after > tokens_before {
        return CompressionOutcome {
            payload: payload.clone(),
            tokens_before,
            tokens_after: tokens_before,
            changed: false,
        };
    }
    CompressionOutcome {
        payload: new_payload,
        tokens_before,
        tokens_after,
        changed: true,
    }
}

fn stub_middle_to_target(
    payload: &Value,
    messages: &mut [Value],
    tail_start: usize,
    tokens_before: u64,
    target_reduction_millis: u64,
) -> bool {
    if messages.iter().any(|message| {
        msg_content_str(message).is_some_and(|content| content.contains("reason: middle history]"))
    }) {
        return false;
    }
    let target_tokens =
        tokens_before.saturating_mul(1000u64.saturating_sub(target_reduction_millis.min(1000))) / 1000;
    let mut changed = false;
    for index in 0..tail_start {
        if payload_tokens_with_messages(payload, messages) <= target_tokens {
            break;
        }
        let Some(message) = messages.get_mut(index) else {
            continue;
        };
        let role = msg_role(message);
        if role == "system" || role == "tool" || message.get("tool_calls").is_some() {
            continue;
        }
        let Some(content) = msg_content_str(message) else {
            continue;
        };
        if content.starts_with("[pruned:") {
            continue;
        }
        let tokens = approx_tokens(content);
        if tokens < 32 {
            continue;
        }
        let digest = ab_core::digest::sha256_hex(content.as_bytes());
        if let Some(object) = message.as_object_mut() {
            object.insert(
                "content".to_owned(),
                Value::String(format!(
                    "[pruned: {tokens} tokens, sha256:{digest}, reason: middle history]"
                )),
            );
            changed = true;
        }
    }
    changed
}

fn payload_tokens_with_messages(payload: &Value, messages: &[Value]) -> u64 {
    let mut value = payload.clone();
    if let Some(object) = value.as_object_mut() {
        object.insert("messages".to_owned(), Value::Array(messages.to_vec()));
    }
    approx_tokens(&value.to_string())
}

fn msg_role(m: &Value) -> &str {
    m.get("role").and_then(Value::as_str).unwrap_or("")
}

fn msg_content_str(m: &Value) -> Option<&str> {
    m.get("content").and_then(Value::as_str)
}

/// Keep the first system message; collapse later *identical* system messages
/// (duplicate re-injection is a common agent-framework bug).
fn collapse_duplicate_system(messages: &mut [Value], tail_start: usize) -> bool {
    let Some(first_system) = messages.iter().position(|m| msg_role(m) == "system") else {
        return false;
    };
    let reference = messages.get(first_system).cloned();
    let Some(reference) = reference else { return false };
    let mut changed = false;
    for (i, m) in messages.iter_mut().enumerate() {
        if i <= first_system || i >= tail_start {
            continue;
        }
        if msg_role(m) == "system" && *m == reference {
            let tokens = approx_tokens(&reference.to_string());
            *m = json!({
                "role": "system",
                "content": audit_stub("duplicate system message", tokens, &reference),
            });
            changed = true;
        }
    }
    changed
}

/// Collapse exact-duplicate user/assistant messages outside the tail
/// (identical retries / framework echoes).
fn collapse_duplicate_messages(messages: &mut [Value], tail_start: usize) -> bool {
    let mut seen: Vec<Value> = Vec::new();
    let mut changed = false;
    for (i, m) in messages.iter_mut().enumerate() {
        if i >= tail_start {
            break;
        }
        let role = msg_role(m);
        if role != "user" && role != "assistant" {
            continue;
        }
        // Only collapse pure-content messages — never anything carrying tool_calls.
        if m.get("tool_calls").is_some() || msg_content_str(m).is_none() {
            continue;
        }
        // Never re-collapse audit stubs (stub-of-stub would break idempotence).
        if msg_content_str(m).is_some_and(|c| c.starts_with("[pruned:")) {
            continue;
        }
        if seen.contains(m) {
            let tokens = approx_tokens(&m.to_string());
            let stub = audit_stub("duplicate message", tokens, m);
            *m = json!({ "role": role, "content": stub });
            changed = true;
        } else {
            seen.push(m.clone());
        }
    }
    changed
}

/// Replace large, stale tool outputs with audit stubs (the brief's "stale tool
/// responses"). The `tool_call_id` linkage field is preserved so the
/// conversation graph stays intact.
fn stub_stale_tool_outputs(messages: &mut [Value], tail_start: usize, threshold: u64) -> bool {
    let mut changed = false;
    for (i, m) in messages.iter_mut().enumerate() {
        if i >= tail_start {
            break;
        }
        if msg_role(m) != "tool" {
            continue;
        }
        let Some(content) = msg_content_str(m) else {
            continue;
        };
        if content.starts_with("[pruned:") {
            continue; // already stubbed — idempotence
        }
        let tokens = approx_tokens(content);
        if tokens <= threshold {
            continue;
        }
        let digest = ab_core::digest::sha256_hex(content.as_bytes());
        let stub = format!("[pruned: {tokens} tokens, sha256:{digest}]");
        if let Some(obj) = m.as_object_mut() {
            obj.insert("content".to_owned(), Value::String(stub));
            changed = true;
        }
    }
    changed
}

/// Minify JSON-formatted string content (strip redundant JSON formatting per
/// the brief) outside the tail.
fn normalize_json_content(messages: &mut [Value], tail_start: usize) -> bool {
    let mut changed = false;
    for (i, m) in messages.iter_mut().enumerate() {
        if i >= tail_start {
            break;
        }
        let role = msg_role(m);
        if role != "tool" && role != "assistant" {
            continue;
        }
        let Some(content) = msg_content_str(m) else {
            continue;
        };
        let trimmed = content.trim_start();
        if !(trimmed.starts_with('{') || trimmed.starts_with('[')) {
            continue;
        }
        let Ok(parsed) = serde_json::from_str::<Value>(content) else {
            continue;
        };
        let Ok(minified) = serde_json::to_string(&parsed) else {
            continue;
        };
        if minified.len() < content.len() {
            if let Some(obj) = m.as_object_mut() {
                obj.insert("content".to_owned(), Value::String(minified));
                changed = true;
            }
        }
    }
    changed
}

fn audit_stub(reason: &str, tokens: u64, original: &Value) -> String {
    let digest = ab_core::digest::sha256_hex(original.to_string().as_bytes());
    format!("[pruned: {tokens} tokens ({reason}), sha256:{digest}]")
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

    fn engage_all() -> CompressionConfig {
        CompressionConfig {
            min_tokens_to_engage: 0,
            ..CompressionConfig::default()
        }
    }

    fn payload(messages: Vec<Value>) -> Value {
        json!({"model": "gpt-4o", "messages": messages, "stream": true})
    }

    #[test]
    fn non_chat_payload_untouched() {
        let v = json!({"not_messages": [1, 2, 3]});
        let out = compress(&v, &engage_all());
        assert!(!out.changed);
        assert_eq!(out.payload, v);
    }

    #[test]
    fn small_payload_not_engaged() {
        let v = payload(vec![json!({"role": "user", "content": "hi"})]);
        let out = compress(&v, &CompressionConfig::default());
        assert!(!out.changed, "512-token floor must skip tiny payloads");
    }

    #[test]
    fn duplicate_system_collapsed_first_kept() {
        let sys = json!({"role": "system", "content": "You are a helpful agent. ".repeat(20)});
        let mut msgs = vec![sys.clone()];
        for i in 0..10 {
            msgs.push(json!({"role": "user", "content": format!("q{i}")}));
            msgs.push(sys.clone());
        }
        let out = compress(&payload(msgs), &engage_all());
        assert!(out.changed);
        let result = out.payload["messages"].as_array().unwrap();
        // First system byte-identical.
        assert_eq!(result[0], sys, "first system message must be untouched");
        // Later duplicates (outside tail) stubbed.
        let stubbed = result
            .iter()
            .skip(1)
            .filter(|m| {
                msg_role(m) == "system" && msg_content_str(m).is_some_and(|c| c.starts_with("[pruned:"))
            })
            .count();
        assert!(stubbed > 0, "no duplicate system messages were stubbed");
        assert!(out.tokens_after < out.tokens_before);
    }

    #[test]
    fn stale_tool_outputs_stubbed_with_digest_tail_preserved() {
        let big = "x ".repeat(4000);
        let mut msgs = vec![json!({"role": "system", "content": "sys"})];
        for i in 0..6 {
            msgs.push(json!({"role": "assistant", "content": null, "tool_calls": [{"id": format!("c{i}"), "type": "function", "function": {"name": "search", "arguments": "{}"}}]}));
            msgs.push(json!({"role": "tool", "tool_call_id": format!("c{i}"), "content": big}));
        }
        let tail_tool = json!({"role": "tool", "tool_call_id": "c5", "content": big});
        msgs.push(tail_tool.clone());
        let out = compress(&payload(msgs), &engage_all());
        assert!(out.changed);
        let result = out.payload["messages"].as_array().unwrap();
        // Early tool output stubbed with digest of the original.
        let first_tool = result.iter().find(|m| msg_role(m) == "tool").unwrap();
        let stub = msg_content_str(first_tool).unwrap();
        assert!(stub.starts_with("[pruned:"), "{stub}");
        let expected_digest = ab_core::digest::sha256_hex(big.as_bytes());
        assert!(
            stub.contains(&expected_digest),
            "audit digest must reference the original"
        );
        // tool_call_id linkage preserved.
        assert!(first_tool.get("tool_call_id").is_some());
        // Tail messages byte-identical.
        assert_eq!(*result.last().unwrap(), tail_tool);
    }

    #[test]
    fn json_content_minified() {
        let pretty = serde_json::to_string_pretty(&json!({"a": [1, 2, 3], "b": {"c": "d"}})).unwrap();
        let mut msgs = vec![json!({"role": "system", "content": "sys"})];
        for i in 0..12 {
            msgs.push(json!({"role": "user", "content": format!("q{i} {}", "pad ".repeat(50))}));
            msgs.push(json!({"role": "assistant", "content": pretty.clone()}));
        }
        let out = compress(&payload(msgs), &engage_all());
        assert!(out.changed);
        let result = out.payload["messages"].as_array().unwrap();
        let minified = result
            .iter()
            .skip(1)
            .find(|m| msg_role(m) == "assistant")
            .unwrap();
        let c = msg_content_str(minified).unwrap();
        assert!(!c.contains('\n'), "not minified: {c}");
        assert_eq!(
            serde_json::from_str::<Value>(c).unwrap(),
            json!({"a": [1,2,3], "b": {"c": "d"}})
        );
    }

    #[test]
    fn idempotent() {
        let big = "data ".repeat(2000);
        let mut msgs = vec![json!({"role": "system", "content": "sys"})];
        for i in 0..10 {
            msgs.push(json!({"role": "user", "content": "same question"}));
            msgs.push(json!({"role": "tool", "tool_call_id": format!("c{i}"), "content": big}));
        }
        let once = compress(&payload(msgs), &engage_all());
        assert!(once.changed);
        let twice = compress(&once.payload, &engage_all());
        assert_eq!(once.payload, twice.payload, "compress must be idempotent");
        assert_eq!(twice.tokens_after, once.tokens_after);
    }

    #[test]
    fn output_never_larger() {
        let out = compress(
            &payload(vec![json!({"role": "user", "content": "abc ".repeat(500)})]),
            &engage_all(),
        );
        assert!(out.tokens_after <= out.tokens_before);
    }

    /// Success criterion R7/R24: ≥ 30 % reduction on a ≥ 50 k-token agent history.
    #[test]
    fn fifty_k_token_history_reduced_at_least_30_percent() {
        let sys = json!({"role": "system", "content": format!("You are an autonomous agent. {}", "Rules. ".repeat(100))});
        let tool_blob = serde_json::to_string_pretty(
            &json!({"rows": (0..200).map(|i| json!({"id": i, "name": format!("row-{i}"), "status": "ok", "payload": "z".repeat(40)})).collect::<Vec<_>>()}),
        )
        .unwrap();
        let mut msgs = vec![sys.clone()];
        for i in 0..40 {
            msgs.push(sys.clone()); // framework re-injects the system prompt (real-world pattern)
            msgs.push(json!({"role": "user", "content": format!("step {i}: continue the plan")}));
            msgs.push(json!({"role": "assistant", "content": null, "tool_calls": [{"id": format!("c{i}"), "type": "function", "function": {"name": "db_read", "arguments": "{\"q\": 1}"}}]}));
            msgs.push(json!({"role": "tool", "tool_call_id": format!("c{i}"), "content": tool_blob}));
        }
        let p = payload(msgs);
        let out = compress(&p, &CompressionConfig::default());
        assert!(
            out.tokens_before >= 50_000,
            "corpus too small: {}",
            out.tokens_before
        );
        let ratio = out.pruning_ratio_millis();
        assert!(ratio >= 300, "reduction {}.{}% < 30%", ratio / 10, ratio % 10);
        // Metric names mirror ATIF (Module C requirement).
        assert!(out.pruned_tokens() > 0);
    }

    #[test]
    fn unique_fifty_k_history_reaches_target_without_touching_tail() {
        let mut messages = vec![json!({"role": "system", "content": "stable system prompt"})];
        for index in 0..80 {
            messages.push(json!({
                "role": if index % 2 == 0 { "user" } else { "assistant" },
                "content": format!(
                    "unique-{index} {}",
                    (0..900)
                        .map(|word| format!("token-{index}-{word}"))
                        .collect::<Vec<_>>()
                        .join(" ")
                )
            }));
        }
        let input = payload(messages);
        let original_tail = input["messages"].as_array().unwrap()[73..].to_vec();
        let output = compress(&input, &CompressionConfig::default());
        assert!(output.tokens_before >= 50_000);
        assert!(output.pruning_ratio_millis() >= 300);
        assert_eq!(
            &output.payload["messages"].as_array().unwrap()[73..],
            original_tail.as_slice()
        );
        assert_eq!(
            compress(&output.payload, &CompressionConfig::default()).payload,
            output.payload
        );
    }

    #[test]
    fn tool_calls_messages_never_collapsed() {
        // Messages carrying tool_calls must never be deduplicated even if identical.
        let call = json!({"role": "assistant", "content": null, "tool_calls": [{"id": "c1", "type": "function", "function": {"name": "f", "arguments": "{}"}}]});
        let mut msgs = vec![json!({"role": "system", "content": "s"})];
        for _ in 0..12 {
            msgs.push(call.clone());
            msgs.push(json!({"role": "user", "content": "pad ".repeat(100)}));
        }
        let out = compress(&payload(msgs), &engage_all());
        let result = out.payload["messages"].as_array().unwrap();
        let intact = result.iter().filter(|m| **m == call).count();
        assert_eq!(intact, 12, "tool_calls messages must survive verbatim");
    }
}
