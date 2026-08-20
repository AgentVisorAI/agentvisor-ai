//! Compression passes over OpenAI-shape chat payloads.

use av_core::tokens::approx_tokens;
use serde_json::{json, Value};

/// Tuning knobs (config-file surface; defaults follow the brief).
#[derive(Debug, Clone)]
pub struct CompressionConfig {
    /// Never touch the last N messages (short-term memory preservation).
    pub keep_tail: usize,
    /// Tool outputs older than the tail are stubbed when longer than this
    /// many approximate tokens.
    pub tool_output_stub_threshold: u64,
    /// Also collapse exact-duplicate user/assistant messages
    /// (tool messages are never collapsed).
    pub collapse_duplicates: bool,
    /// Normalize whitespace inside JSON-looking tool/assistant string content.
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
    // Bound the idempotence scan to the middle range only. A legitimate tail
    // message that happens to quote the marker (a follow-up assistant reply
    // summarizing a prior compression, or user-controlled content) would
    // otherwise permanently disable this pass on that conversation.
    //
    // TODO(compression-marker): the marker itself is still an
    // unauthenticated literal substring, so a hostile MIDDLE-range
    // message can still spoof it and skip stubbing of surrounding
    // messages. Fixing that requires switching to a keyed marker
    // (HMAC over prior content) or an out-of-band per-payload
    // flag — both are larger refactors.
    //
    // Round-19 F8: tracked as a known limitation (see the
    // compression-marker entry in SECURITY-AUDIT.md). Attack requires
    // an already-compromised prior turn (either an operator who
    // pasted attacker content verbatim, or a system prompt
    // hardening bypass) — real-world exploitability is bounded to
    // "attacker who already has message-content control can force
    // compression pass to skip." A keyed-marker
    // scheme remains future work, currently unscheduled.
    let scan_end = tail_start.min(messages.len());
    // Round-18 F1 (av-compress): the prior check refused to run a
    // second pass if ANY pre-tail message content contained the
    // literal substring "reason: middle history]" — but a
    // user/assistant message that legitimately quotes that phrase
    // (or a compromised prior turn that includes it as free text)
    // could silently disable compression. Narrow the check to
    // exactly what the marker produces: content must START with
    // "[pruned:" AND contain the marker tail. A user quoting the
    // phrase in free text no longer matches (their content will
    // start with their own words, not "[pruned:"). This is not
    // the full keyed-marker fix (round-19 F8 known limitation) —
    // but the spoofing surface shrinks from "any message contains
    // the substring" to "any message perfectly mimics the marker
    // prefix + tail." Realistic user text does not shape like a
    // machine-emitted `[pruned: N tokens, sha256:HEX, reason: middle
    // history]`.
    if messages.get(..scan_end).into_iter().flatten().any(|message| {
        msg_content_str(message).is_some_and(|content| {
            content.starts_with("[pruned:") && content.contains("reason: middle history]")
        })
    }) {
        return false;
    }
    let target_tokens =
        tokens_before.saturating_mul(1000u64.saturating_sub(target_reduction_millis.min(1000))) / 1000;
    let mut changed = false;
    // Round-32 F3 (av-compress): the prior loop called
    // `payload_tokens_with_messages(payload, messages)` on every
    // iteration — each call clones the entire payload AND the
    // entire messages Vec, then serializes to string. For a 4 MiB
    // payload with N messages that's O(N²) work AND O(N) transient
    // allocations per iteration. Instead track a running
    // `current_tokens` counter that is decremented by the message's
    // pre-stub token count and incremented by the stub's on each
    // successful substitution. `payload_tokens_with_messages` is
    // still called once at loop entry to seed the counter (the
    // envelope's token count includes non-messages fields like
    // `model` and `stream`, which the incremental delta preserves).
    let mut current_tokens = payload_tokens_with_messages(payload, messages);
    for index in 0..tail_start {
        if current_tokens <= target_tokens {
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
        let digest = av_core::digest::sha256_hex(content.as_bytes());
        let stub_content = format!("[pruned: {tokens} tokens, sha256:{digest}, reason: middle history]");
        let stub_tokens = approx_tokens(&stub_content);
        if let Some(object) = message.as_object_mut() {
            object.insert("content".to_owned(), Value::String(stub_content));
            // Update the running counter: original message content
            // contributed `tokens`, new stub contributes `stub_tokens`.
            // Everything else in the payload envelope is unchanged.
            current_tokens = current_tokens.saturating_sub(tokens).saturating_add(stub_tokens);
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
///
/// Round-32 F2 (av-compress): the prior implementation used
/// `Vec<Value>` + `Vec::contains` (linear per-lookup, O(n²) total)
/// AND cloned every non-duplicate message into the seen-list on push.
/// On a 4 MiB payload with hundreds of messages this dominated
/// compression latency and could momentarily hold ~2× the payload
/// in RAM. Now uses a `HashSet<u64>` keyed by a stable content hash
/// derived from `(role, content_str)` — the ONLY two components
/// `contains` used to compare, since the guards above already
/// exclude tool_calls-carrying and pre-stubbed messages. O(1)
/// average lookup, and no message clone.
fn collapse_duplicate_messages(messages: &mut [Value], tail_start: usize) -> bool {
    use std::collections::HashSet;
    use std::hash::{DefaultHasher, Hash, Hasher};
    let mut seen: HashSet<u64> = HashSet::new();
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
        if m.get("tool_calls").is_some() {
            continue;
        }
        let Some(content) = msg_content_str(m) else {
            continue;
        };
        // Never re-collapse audit stubs (stub-of-stub would break idempotence).
        if content.starts_with("[pruned:") {
            continue;
        }
        // Composite hash of (role, content) — the two fields the
        // prior `Vec::contains` on Value compared. Guards above
        // exclude every other field that could vary between
        // otherwise-identical duplicates.
        let mut hasher = DefaultHasher::new();
        role.hash(&mut hasher);
        content.hash(&mut hasher);
        let key = hasher.finish();
        if !seen.insert(key) {
            let tokens = approx_tokens(content);
            let stub = audit_stub("duplicate message", tokens, m);
            *m = json!({ "role": role, "content": stub });
            changed = true;
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
        let digest = av_core::digest::sha256_hex(content.as_bytes());
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
    let digest = av_core::digest::sha256_hex(original.to_string().as_bytes());
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
        let expected_digest = av_core::digest::sha256_hex(big.as_bytes());
        assert!(
            stub.contains(&expected_digest),
            "audit digest must reference the original"
        );
        // tool_call_id linkage preserved.
        assert!(first_tool.get("tool_call_id").is_some());
        // Tail messages byte-identical.
        assert_eq!(*result.last().unwrap(), tail_tool);
    }

    /// Mutation-run hardening: `collapse_duplicate_messages` had no
    /// behavioral coverage at all — replacing the whole function with a
    /// constant `true`/`false` survived the suite. Pin its contract:
    /// exact user/assistant duplicates outside the tail collapse to audit
    /// stubs, the first occurrence and the tail stay byte-identical, and
    /// tool-role messages are never collapsed even when identical.
    #[test]
    fn duplicate_user_and_assistant_messages_collapse_outside_tail() {
        let dup_user = json!({"role": "user", "content": "please retry the exact same thing ".repeat(8)});
        let dup_tool = json!({"role": "tool", "tool_call_id": "c1", "content": "identical tool payload"});
        let mut msgs = vec![json!({"role": "system", "content": "sys"})];
        for _ in 0..6 {
            msgs.push(dup_user.clone());
            msgs.push(dup_tool.clone());
        }
        let tail = json!({"role": "user", "content": "fresh tail question"});
        msgs.push(tail.clone());
        let out = compress(&payload(msgs.clone()), &engage_all());
        assert!(out.changed);
        let result = out.payload["messages"].as_array().unwrap();
        // First occurrence byte-identical.
        let first_user = result.iter().find(|m| msg_role(m) == "user").unwrap();
        assert_eq!(*first_user, dup_user, "first duplicate must be kept verbatim");
        // Later duplicates outside the tail become audit stubs that keep
        // the role and reference the original via digest.
        let expected_digest = av_core::digest::sha256_hex(dup_user.to_string().as_bytes());
        let stubbed = result
            .iter()
            .filter(|m| {
                msg_role(m) == "user"
                    && msg_content_str(m)
                        .is_some_and(|c| c.starts_with("[pruned:") && c.contains(&expected_digest))
            })
            .count();
        assert!(stubbed >= 1, "no duplicate user message was stubbed: {result:?}");
        // Tool messages are never collapsed, even when identical.
        assert!(
            result
                .iter()
                .filter(|m| msg_role(m) == "tool")
                .all(|m| *m == dup_tool),
            "tool messages must never be collapsed by the duplicate pass"
        );
        // Tail untouched.
        assert_eq!(*result.last().unwrap(), tail);
        // And the whole pass is disable-able: collapse_duplicates=false
        // leaves every user duplicate verbatim.
        let cfg = CompressionConfig {
            collapse_duplicates: false,
            normalize_json: false,
            summarize_middle: false,
            tool_output_stub_threshold: u64::MAX,
            ..engage_all()
        };
        let untouched = compress(&payload(msgs), &cfg);
        let kept = untouched.payload["messages"].as_array().unwrap();
        assert!(
            kept.iter().filter(|m| **m == dup_user).count() == 6,
            "collapse_duplicates=false must keep every duplicate verbatim"
        );
    }

    /// Mutation-run hardening: the middle-history stub pass's role
    /// exclusions (`role == "system" || role == "tool" || tool_calls`)
    /// and its `tokens < 32` floor survived operator mutations. Pin them:
    /// system/tool/tool-calls/small messages in the middle range survive
    /// verbatim while large plain messages are stubbed, and stubbing
    /// stops once the target reduction is reached.
    #[test]
    fn middle_stub_skips_protected_roles_and_small_messages() {
        let big = "long analysis paragraph ".repeat(600); // well past 50k total below
        let protected_system = json!({"role": "system", "content": big.clone()});
        let protected_tool = json!({"role": "tool", "tool_call_id": "c1", "content": big.clone()});
        let protected_calls = json!({"role": "assistant", "content": big.clone(),
            "tool_calls": [{"id": "c1", "type": "function", "function": {"name": "f", "arguments": "{}"}}]});
        let small = json!({"role": "user", "content": "tiny"});
        let mut msgs = vec![
            protected_system.clone(),
            protected_tool.clone(),
            protected_calls.clone(),
            small.clone(),
        ];
        for _ in 0..40 {
            msgs.push(json!({"role": "assistant", "content": big.clone()}));
        }
        let cfg = CompressionConfig {
            collapse_duplicates: false,
            normalize_json: false,
            tool_output_stub_threshold: u64::MAX,
            ..engage_all()
        };
        let out = compress(&payload(msgs), &cfg);
        assert!(out.changed, "large history must engage the middle stub pass");
        let result = out.payload["messages"].as_array().unwrap();
        assert_eq!(result[0], protected_system, "system messages must survive");
        assert_eq!(result[1], protected_tool, "tool messages must survive");
        assert_eq!(result[2], protected_calls, "tool-call carriers must survive");
        assert_eq!(result[3], small, "sub-32-token messages must survive");
        let stubbed = result
            .iter()
            .filter(|m| msg_content_str(m).is_some_and(|c| c.contains("reason: middle history]")))
            .count();
        assert!(stubbed > 0, "large plain middle messages must be stubbed");
        // The pass stops at the target: with the default 30% target on a
        // uniform history it must NOT stub everything eligible.
        let eligible = result
            .iter()
            .filter(|m| msg_role(m) == "assistant" && m.get("tool_calls").is_none())
            .count();
        assert!(
            stubbed < eligible,
            "stubbing must stop at the target reduction, not consume the whole middle"
        );
        // Reduction reached the configured target ratio.
        assert!(
            out.pruning_ratio_millis() >= cfg.target_reduction_millis,
            "reduction {} must reach the target {}",
            out.pruning_ratio_millis(),
            cfg.target_reduction_millis
        );
    }

    /// Round-18 F1 regression: a message that legitimately QUOTES the
    /// marker tail phrase in free text must NOT disable the middle
    /// pass. The prior check refused to run if any pre-tail message
    /// content contained the literal substring; the round-18 fix
    /// narrowed the check to require the message to also START WITH
    /// `[pruned:`. A user turn that says `"the log said 'reason:
    /// middle history]'"` is normal text; compression must still run.
    #[test]
    fn quoted_marker_phrase_in_normal_text_does_not_disable_compression() {
        let mut msgs = vec![
            json!({"role": "system", "content": "sys"}),
            // The quoted-marker phrase — no `[pruned:` prefix, so
            // the narrowed check should NOT match it.
            json!({"role": "user", "content": "the log said 'reason: middle history]' earlier"}),
        ];
        // Make each assistant message unique so the duplicate pass
        // doesn't consume them before the middle pass runs. The
        // middle pass has a 50_000 token entry threshold; size each
        // message to comfortably clear it in aggregate.
        for i in 0..80 {
            msgs.push(json!({
                "role": "assistant",
                "content": format!("unique analysis paragraph {i} {}", "detail ".repeat(1200))
            }));
        }
        // Disable the duplicate + normalize passes so we specifically
        // exercise the middle-pass kill-switch narrowing.
        let cfg = CompressionConfig {
            collapse_duplicates: false,
            normalize_json: false,
            tool_output_stub_threshold: u64::MAX,
            ..engage_all()
        };
        let out = compress(&payload(msgs), &cfg);
        assert!(
            out.changed,
            "middle pass must run despite the user quoting the marker phrase in free text"
        );
        let result = out.payload["messages"].as_array().unwrap();
        // The quoted message is preserved verbatim (it's below the
        // 32-token floor and it's a `user` role — no pass touches it).
        assert_eq!(
            msg_content_str(&result[1]).unwrap(),
            "the log said 'reason: middle history]' earlier",
            "the quoted user message must be preserved verbatim"
        );
        // Middle-pass stubs are produced for the large assistant
        // messages.
        let stubbed = result
            .iter()
            .filter(|m| {
                msg_content_str(m)
                    .is_some_and(|c| c.starts_with("[pruned:") && c.contains("reason: middle history]"))
            })
            .count();
        assert!(
            stubbed > 0,
            "large plain middle messages must still be stubbed, got {result:#?}"
        );
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

#[cfg(test)]
mod ratio_tests {
    /// Mutation-run hardening (round 12): pin the R7 metric arithmetic —
    /// `/` -> `%`/`*` in `pruning_ratio_millis` would corrupt the
    /// pruning-ratio field that mirrors ATIF metrics.
    #[test]
    fn pruning_ratio_millis_is_exact() {
        let outcome = super::CompressionOutcome {
            payload: serde_json::Value::Null,
            tokens_before: 1000,
            tokens_after: 650,
            changed: true,
        };
        assert_eq!(outcome.pruning_ratio_millis(), 350, "350 = 35.0%");
        let zero = super::CompressionOutcome {
            payload: serde_json::Value::Null,
            tokens_before: 0,
            tokens_after: 0,
            changed: false,
        };
        assert_eq!(zero.pruning_ratio_millis(), 0, "0/0 guard");
    }
}
