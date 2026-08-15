//! JSON-RPC 2.0 / MCP `tools/call` parsing. Total: never panics on arbitrary
//! bytes (property-tested), returns typed errors for every malformed shape.

use serde_json::Value;

/// A parsed MCP tool-call request.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolCallRequest {
    /// JSON-RPC id (absent for notifications).
    pub id: Option<Value>,
    /// Tool name (`params.name`).
    pub tool: String,
    /// Tool arguments (`params.arguments`, defaults to `{}`).
    pub arguments: Value,
}

/// Parse failures.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum RpcError {
    /// Not valid JSON at all.
    #[error("invalid JSON: {0}")]
    Json(String),
    /// Valid JSON but not a JSON-RPC 2.0 object.
    #[error("not a JSON-RPC 2.0 request: {0}")]
    NotJsonRpc(String),
    /// A method other than `tools/call` (passthrough, not an error verdict —
    /// the caller decides what to do with non-tool traffic).
    #[error("method {0:?} is not tools/call")]
    NotToolCall(String),
    /// `tools/call` missing/invalid params.
    #[error("invalid tools/call params: {0}")]
    BadParams(String),
    /// Payload exceeds the configured size bound (DoS guard).
    #[error("payload of {0} bytes exceeds the {1}-byte bound")]
    TooLarge(usize, usize),
}

/// Hard byte bound applied before parsing (attacker-controlled input).
pub const MAX_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;

/// Depth bound applied post-parse (deeply nested JSON as a DoS vector).
pub const MAX_JSON_DEPTH: usize = 64;

/// Parse raw bytes as an MCP `tools/call`.
pub fn parse_tool_call(raw: &[u8]) -> Result<ToolCallRequest, RpcError> {
    if raw.len() > MAX_PAYLOAD_BYTES {
        return Err(RpcError::TooLarge(raw.len(), MAX_PAYLOAD_BYTES));
    }
    let v: Value = serde_json::from_slice(raw).map_err(|e| RpcError::Json(e.to_string()))?;
    if depth_of(&v, 0) > MAX_JSON_DEPTH {
        return Err(RpcError::NotJsonRpc("nesting exceeds depth bound".into()));
    }
    let obj = v
        .as_object()
        .ok_or_else(|| RpcError::NotJsonRpc("root is not an object".into()))?;
    match obj.get("jsonrpc").and_then(Value::as_str) {
        Some("2.0") => {}
        other => {
            return Err(RpcError::NotJsonRpc(format!(
                "jsonrpc field is {other:?}, need \"2.0\""
            )))
        }
    }
    let method = obj
        .get("method")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::NotJsonRpc("method missing or not a string".into()))?;
    if method != "tools/call" {
        return Err(RpcError::NotToolCall(method.to_owned()));
    }
    let params = obj
        .get("params")
        .and_then(Value::as_object)
        .ok_or_else(|| RpcError::BadParams("params missing or not an object".into()))?;
    let tool = params
        .get("name")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| RpcError::BadParams("params.name missing or empty".into()))?;
    if ab_core::text::contains_bidi_or_zero_width(tool) {
        return Err(RpcError::BadParams(
            "params.name carries a bidi/zero-width spoofing character".into(),
        ));
    }
    // Reject ASCII control characters and inner whitespace: without this a
    // request for `"db_write\n"` would slip past exact-string matchers for
    // per-tool schemas, per-tool policy deny-lists, per-tool budgets, and
    // the harness consequential-tools workflow veto, then be normalized by
    // most downstream MCP servers to `"db_write"`. Also cover the same
    // trailing/leading whitespace shape.
    if tool.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(RpcError::BadParams(
            "params.name contains a control character or whitespace".into(),
        ));
    }
    // JSON-RPC 2.0 §4 requires `id` to be a string, number, or null: reject
    // objects/arrays/bool up front so downstream correlation tables that key
    // on id-as-string cannot be confused by structured ids.
    let id = obj.get("id").cloned();
    match id.as_ref() {
        None => {}
        Some(Value::String(_) | Value::Number(_) | Value::Null) => {}
        Some(_) => {
            return Err(RpcError::BadParams(
                "id must be a string, number, or null per JSON-RPC 2.0 §4".into(),
            ));
        }
    }
    // Per JSON-RPC 2.0 §4.1 a request with no `id` is a notification: a
    // notification MUST NOT elicit a response. Refusing them here keeps
    // attackers from fire-and-forgetting `tools/call` to drain budget
    // (max_total_tool_calls, payout) without needing to consume responses.
    if id.is_none() {
        return Err(RpcError::BadParams(
            "tools/call requires an id; JSON-RPC notifications are not accepted".into(),
        ));
    }
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| Value::Object(Default::default()));
    if !arguments.is_object() {
        return Err(RpcError::BadParams("params.arguments must be an object".into()));
    }
    Ok(ToolCallRequest {
        id,
        tool: tool.to_owned(),
        arguments,
    })
}

fn depth_of(v: &Value, current: usize) -> usize {
    if current > MAX_JSON_DEPTH {
        return current; // early-out: no need to recurse further
    }
    match v {
        Value::Array(items) => items
            .iter()
            .map(|i| depth_of(i, current + 1))
            .max()
            .unwrap_or(current + 1),
        Value::Object(map) => map
            .values()
            .map(|i| depth_of(i, current + 1))
            .max()
            .unwrap_or(current + 1),
        _ => current,
    }
}

/// Build the JSON-RPC error response for a blocked call (the "immediate
/// authorization error back to the agent loop" from the brief).
pub fn authorization_error(id: Option<&Value>, reason: &str) -> Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id.cloned().unwrap_or(Value::Null),
        "error": {
            "code": -32001,
            "message": "tool call blocked by AgentBridge policy",
            "data": { "reason": reason }
        }
    })
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
    use proptest::prelude::*;
    use serde_json::json;

    fn call(tool: &str, args: Value) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": { "name": tool, "arguments": args }
        }))
        .unwrap()
    }

    #[test]
    fn parses_valid_call() {
        let req = parse_tool_call(&call("db_write", json!({"table": "users"}))).unwrap();
        assert_eq!(req.tool, "db_write");
        assert_eq!(req.arguments["table"], "users");
        assert_eq!(req.id, Some(json!(7)));
    }

    #[test]
    fn missing_arguments_defaults_to_empty_object() {
        let raw = serde_json::to_vec(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "t"}
        }))
        .unwrap();
        assert_eq!(parse_tool_call(&raw).unwrap().arguments, json!({}));
    }

    #[test]
    fn rejects_malformed_shapes() {
        assert!(matches!(parse_tool_call(b"not json"), Err(RpcError::Json(_))));
        assert!(matches!(
            parse_tool_call(b"[1,2,3]"),
            Err(RpcError::NotJsonRpc(_))
        ));
        assert!(matches!(
            parse_tool_call(br#"{"jsonrpc":"1.0","method":"tools/call"}"#),
            Err(RpcError::NotJsonRpc(_))
        ));
        assert!(matches!(
            parse_tool_call(br#"{"jsonrpc":"2.0"}"#),
            Err(RpcError::NotJsonRpc(_))
        ));
        assert!(matches!(
            parse_tool_call(br#"{"jsonrpc":"2.0","method":"resources/read"}"#),
            Err(RpcError::NotToolCall(_))
        ));
        assert!(matches!(
            parse_tool_call(br#"{"jsonrpc":"2.0","method":"tools/call"}"#),
            Err(RpcError::BadParams(_))
        ));
        assert!(matches!(
            parse_tool_call(br#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":""}}"#),
            Err(RpcError::BadParams(_))
        ));
        assert!(matches!(
            parse_tool_call(
                br#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"t","arguments":[1]}}"#
            ),
            Err(RpcError::BadParams(_))
        ));
    }

    #[test]
    fn oversized_payload_rejected_before_parse() {
        let huge = vec![b'x'; MAX_PAYLOAD_BYTES + 1];
        assert!(matches!(parse_tool_call(&huge), Err(RpcError::TooLarge(..))));
    }

    #[test]
    fn max_payload_bytes_is_pinned_at_4_mib() {
        // The DoS-guard cap is part of the public API. A `*` -> `+` mutation
        // in `4 * 1024 * 1024` would slip past size-relative asserts because
        // both sides self-reference the constant; pin the absolute value.
        assert_eq!(MAX_PAYLOAD_BYTES, 4_194_304);
    }

    #[test]
    fn deep_nesting_rejected() {
        let mut nested = String::from("1");
        for _ in 0..200 {
            nested = format!("[{nested}]");
        }
        let raw = format!(
            r#"{{"jsonrpc":"2.0","method":"tools/call","params":{{"name":"t","arguments":{{"x":{nested}}}}}}}"#
        );
        assert!(parse_tool_call(raw.as_bytes()).is_err());
    }

    #[test]
    fn authorization_error_shape() {
        let e = authorization_error(Some(&json!(9)), "budget exceeded");
        assert_eq!(e["id"], 9);
        assert_eq!(e["error"]["code"], -32001);
        assert_eq!(e["error"]["data"]["reason"], "budget exceeded");
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// The parser must never panic on arbitrary bytes (D13 total-parser).
        #[test]
        fn never_panics(bytes in prop::collection::vec(any::<u8>(), 0..2048)) {
            let _ = parse_tool_call(&bytes);
        }

        /// Nor on arbitrary *valid JSON* of hostile shape.
        #[test]
        fn never_panics_on_arbitrary_json(s in "\\PC{0,500}") {
            let _ = parse_tool_call(s.as_bytes());
        }
    }

    /// Tool names carrying a Trojan-Source RLO or any zero-width character
    /// must be rejected. Otherwise a hostile agent could send a payload
    /// whose `params.name` renders as `db_write` on an operator's terminal
    /// while the raw bytes read as a completely different tool identifier,
    /// spoofing audit chains and receipts.
    #[test]
    fn tool_name_carrying_a_bidi_or_zero_width_character_is_rejected() {
        for spoof in [
            "db_write\u{202E}etirw_bd",
            "\u{202E}db_write",
            "db\u{200B}_write",
            "db_write\u{200E}",
            "db_write\u{2066}suffix",
            "db_write\u{FEFF}",
        ] {
            let raw = call(spoof, json!({}));
            match parse_tool_call(&raw) {
                Err(RpcError::BadParams(reason)) => {
                    assert!(reason.contains("spoofing"), "wrong reason: {reason}");
                }
                other => panic!("must reject {spoof:?}, got {other:?}"),
            }
        }
    }

    /// A tool name carrying ANY ASCII control character or whitespace must
    /// be rejected. Otherwise `"db_write\n"` slips past exact-string matchers
    /// for per-tool schemas, per-tool policy deny-lists, per-tool budget
    /// caps, AND the harness consequential-tools workflow veto — and most
    /// downstream MCP servers then normalize whitespace back to `"db_write"`,
    /// completing the bypass.
    #[test]
    fn tool_name_with_control_char_or_whitespace_is_rejected() {
        for hostile in [
            "db_write\n",
            "db_write\r",
            "db_write\t",
            "db_write\0",
            "db_write ",
            " db_write",
            "db write",
            "db_write\u{000B}",
            "db_write\x7f",
        ] {
            let raw = call(hostile, json!({}));
            match parse_tool_call(&raw) {
                Err(RpcError::BadParams(reason)) => {
                    assert!(
                        reason.contains("control character or whitespace"),
                        "wrong reason: {reason}",
                    );
                }
                other => panic!("must reject {hostile:?}, got {other:?}"),
            }
        }
    }

    /// `tools/call` without an id is a JSON-RPC 2.0 notification. Accepting
    /// one would let an attacker fire-and-forget consequential calls to drain
    /// `max_total_tool_calls` and payout budget with no response to consume.
    /// Notifications must be refused at the parse gate.
    #[test]
    fn tools_call_without_id_is_rejected_as_a_notification() {
        let raw = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "safe_tool", "arguments": {}}
        }))
        .unwrap();
        match parse_tool_call(&raw) {
            Err(RpcError::BadParams(reason)) => {
                assert!(reason.contains("notification"), "wrong reason: {reason}");
            }
            other => panic!("notification must be rejected, got {other:?}"),
        }
    }

    /// JSON-RPC 2.0 §4 restricts `id` to a String, Number, or Null.
    /// Downstream correlation tables that key on id-as-string cannot survive
    /// a structured id.
    #[test]
    fn tools_call_with_structured_id_is_rejected() {
        for hostile_id in [
            json!({"nested": true}),
            json!([1, 2, 3]),
            json!(true),
            json!(false),
        ] {
            let raw = serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "id": hostile_id,
                "method": "tools/call",
                "params": {"name": "safe_tool", "arguments": {}}
            }))
            .unwrap();
            match parse_tool_call(&raw) {
                Err(RpcError::BadParams(reason)) => {
                    assert!(reason.contains("JSON-RPC 2.0"), "wrong reason: {reason}");
                }
                other => panic!("hostile id {hostile_id:?} must be rejected, got {other:?}"),
            }
        }
    }

    /// String, number, and null ids are all accepted (§4 spec shape).
    #[test]
    fn valid_id_shapes_are_accepted() {
        for good_id in [json!("uuid-123"), json!(42), json!(-7), json!(null)] {
            let raw = serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "id": good_id,
                "method": "tools/call",
                "params": {"name": "safe_tool", "arguments": {}}
            }))
            .unwrap();
            let parsed = parse_tool_call(&raw).unwrap_or_else(|e| panic!("{good_id:?}: {e:?}"));
            assert_eq!(parsed.id, Some(good_id));
        }
    }
}
