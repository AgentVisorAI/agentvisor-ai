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
    // Duplicate-key rejection: `serde_json` silently keeps the LAST value
    // on duplicate keys, but the raw body is forwarded unchanged to the
    // configured tool upstream. If the upstream's JSON decoder is
    // first-wins (jackson, some Go decoders) or exposes both values, a
    // request like
    //   {"params":{"name":"safe_read","name":"db_write","arguments":{}}}
    // parses here as `tool = "db_write"` (last-wins), passes the
    // safe_read policy/budget gate, then executes `db_write` upstream —
    // a permissions-model split with full audit-trail mismatch. Reject
    // duplicates so gate and upstream see the same request or neither
    // does. RFC 8259 §4 makes duplicate-name handling "implementation-
    // defined", so the trust-boundary policy is: refuse ambiguity.
    reject_duplicate_keys(raw)?;
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
    if av_core::text::contains_bidi_or_zero_width(tool) {
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
    // Refuse any non-ASCII byte in the tool name. Every downstream
    // comparison — per-tool schema lookup, deny-list matching, per-tool
    // budget key — is raw byte-equality. A caller supplying
    // `de\u{0301}lete` (decomposed) or `𝐝𝐛_𝐰𝐫𝐢𝐭𝐞` (mathematical
    // bold, NFKC-folds to `db_write`) sees a different byte string
    // than a policy that lists `delete` / `db_write`, but most MCP
    // servers apply NFC/NFKC before dispatch — so the visually
    // "different" name resolves to the same tool downstream.
    // Restricting to ASCII collapses the Unicode-normalization attack
    // surface without adding a runtime `unicode-normalization`
    // dependency to the parse gate.
    if !tool.is_ascii() {
        return Err(RpcError::BadParams(
            "params.name must be ASCII: non-ASCII tool names introduce a Unicode-normalization mismatch \
             between this proxy's exact-byte matching and downstream MCP servers that fold NFC/NFKC"
                .into(),
        ));
    }
    // Refuse any uppercase byte. Downstream tool-name comparisons are
    // exact-byte, but most MCP servers apply ASCII case folding. A
    // policy that denies `db_write` sees `DB_write` slip through the
    // deny-list byte-eq check while the server executes the same
    // tool. Requiring the caller to normalize to lowercase up front
    // eliminates the class.
    if tool.chars().any(|c| c.is_ascii_uppercase()) {
        return Err(RpcError::BadParams(
            "params.name must be lowercase: mixed-case tool names bypass policy deny-lists that use \
             exact-byte matching while downstream MCP servers apply ASCII case folding"
                .into(),
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

/// The general-purpose duplicate-key
/// rejection primitive, exposed for callers outside this crate (chat
/// completions ingress, admin body parsers) that want the same
/// trust-boundary "refuse ambiguous JSON" semantics without pulling in
/// `RpcError`.
///
/// Returns `Ok(())` if `raw` contains no duplicate keys at any nesting
/// level; otherwise a description of the offending key.
pub fn refuse_duplicate_json_keys(raw: &[u8]) -> Result<(), String> {
    reject_duplicate_keys(raw).map_err(|error| error.to_string())
}

/// Refuse any JSON object with duplicate keys anywhere in the payload.
/// `serde_json` silently keeps the last value; downstream MCP servers may
/// keep the first, expose both, or interpret the collapse differently.
/// The trust-boundary policy is "refuse ambiguity" — see the call-site
/// comment in `parse_tool_call`.
///
/// Distinguish scanner-created "duplicate key"
/// errors from underlying `serde_json` parse errors (EOF, unbalanced
/// braces, invalid escape, recursion limit). The prior blanket
/// `.map_err(|e| RpcError::Json(format!("duplicate JSON key rejected:
/// {e}")))` gave EVERY scanner error the same misleading
/// "duplicate JSON key rejected" prefix, so operator triage on
/// dup-key alerts fired on any malformed JSON. Mirrors the
/// sentinel fix in `av_receipts::check_no_duplicate_keys`.
///
/// Also refuse trailing garbage AFTER a
/// valid JSON value. `deserialize_any` returns after the first
/// complete value, so an input like `{"ok":1}garbage` was silently
/// accepted. `Deserializer::end()` returns Err if any non-whitespace
/// bytes remain, closing the class of "smuggled second document"
/// attacks (JSON body-splitting through a proxy that only inspected
/// the first value).
fn reject_duplicate_keys(raw: &[u8]) -> Result<(), RpcError> {
    use serde::de::{Deserializer, MapAccess, SeqAccess, Visitor};
    use std::fmt;

    const DUP_KEY_SENTINEL: &str = "__av_sandbox_dup:";

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

        fn visit_some<D>(self, deserializer: D) -> Result<(), D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_any(NoDupKeys)
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<(), A::Error>
        where
            A: SeqAccess<'de>,
        {
            while seq.next_element::<NoDupWrap>()?.is_some() {}
            Ok(())
        }

        fn visit_map<A>(self, mut map: A) -> Result<(), A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
            while let Some(key) = map.next_key::<String>()? {
                if !seen.insert(key.clone()) {
                    return Err(serde::de::Error::custom(format!(
                        "{DUP_KEY_SENTINEL}duplicate object key `{}`",
                        key.escape_debug()
                    )));
                }
                let _: NoDupWrap = map.next_value()?;
            }
            Ok(())
        }
    }

    // Wrapper so nested structures use the same visitor.
    struct NoDupWrap;
    impl<'de> serde::Deserialize<'de> for NoDupWrap {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_any(NoDupKeys)?;
            Ok(NoDupWrap)
        }
    }

    let mut de = serde_json::Deserializer::from_slice(raw);
    if let Err(error) = de.deserialize_any(NoDupKeys) {
        let msg = error.to_string();
        return if let Some(rest) = msg.strip_prefix(DUP_KEY_SENTINEL) {
            Err(RpcError::Json(format!("duplicate JSON key rejected: {rest}")))
        } else {
            // Not a duplicate-key error — the underlying serde_json
            // error (EOF, unbalanced braces, invalid escape,
            // recursion limit) surfaces with its own prefix so
            // triage doesn't misattribute the class.
            Err(RpcError::Json(msg))
        };
    }
    // Refuse trailing content after the first complete
    // JSON value. `de.end()` returns Err on any non-whitespace
    // trailing bytes.
    de.end()
        .map_err(|error| RpcError::Json(format!("trailing content after JSON value: {error}")))?;
    Ok(())
}

/// Build the JSON-RPC error response for a blocked call (the "immediate
/// authorization error back to the agent loop" from the brief).
pub fn authorization_error(id: Option<&Value>, reason: &str) -> Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id.cloned().unwrap_or(Value::Null),
        "error": {
            "code": -32001,
            "message": "tool call blocked by AgentVisor AI policy",
            "data": { "reason": reason }
        }
    })
}

/// JSON-RPC 2.0 reserves -32700 (parse
/// error), -32600 (invalid request), and -32602 (invalid params) for
/// requests that never reached application logic. Reporting those as
/// -32001 "blocked by policy" (with HTTP 403) falsely told clients an
/// authorization decision was made about a request that never parsed.
pub fn protocol_error(id: Option<&Value>, error: &RpcError) -> Value {
    let (code, message) = match error {
        RpcError::Json(_) => (-32700, "parse error"),
        RpcError::NotJsonRpc(_) | RpcError::TooLarge(..) => (-32600, "invalid request"),
        RpcError::BadParams(_) => (-32602, "invalid params"),
        // Passthrough refusal is an application-level policy choice.
        RpcError::NotToolCall(_) => {
            return authorization_error(id, &error.to_string());
        }
    };
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id.cloned().unwrap_or(Value::Null),
        "error": {
            "code": code,
            "message": message,
            "data": { "reason": error.to_string() }
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

    /// Mutation-run hardening: the public wrapper `refuse_duplicate_json_keys`
    /// — the exact gate the harness chat ingress calls before serde ever sees
    /// a request body — had no direct test, so a mutant replacing its body
    /// with `Ok(())` survived this crate's suite. Pin: duplicates refused at
    /// every nesting position, trailing garbage refused, clean bodies pass.
    #[test]
    fn refuse_duplicate_json_keys_covers_nesting_and_trailing_garbage() {
        assert!(refuse_duplicate_json_keys(br#"{"a":1,"a":2}"#).is_err());
        assert!(refuse_duplicate_json_keys(br#"{"outer":{"a":1,"a":2}}"#).is_err());
        assert!(refuse_duplicate_json_keys(br#"{"arr":[{"a":1,"a":2}]}"#).is_err());
        assert!(refuse_duplicate_json_keys(br#"{"ok":1}garbage"#).is_err());
        assert!(refuse_duplicate_json_keys(br#"{"a":1,"b":{"a":1},"c":[1,"a"]}"#).is_ok());
        assert!(refuse_duplicate_json_keys(b"[1,2,3]").is_ok());
    }

    /// Mutation-run hardening: the reserved JSON-RPC error codes are wire
    /// contract (-32700 parse / -32600 invalid request / -32602 invalid
    /// params); a mutant deleting the sign survived. Also pin that a
    /// non-`tools/call` method routes to the application-level
    /// authorization error rather than a protocol code.
    #[test]
    fn protocol_error_pins_reserved_jsonrpc_codes() {
        let cases = [
            (RpcError::Json("x".into()), -32700),
            (RpcError::NotJsonRpc("x".into()), -32600),
            (RpcError::TooLarge(9, 1), -32600),
            (RpcError::BadParams("x".into()), -32602),
        ];
        for (error, expected) in cases {
            let response = protocol_error(None, &error);
            assert_eq!(response["error"]["code"].as_i64(), Some(expected), "{error:?}");
        }
        let passthrough = protocol_error(None, &RpcError::NotToolCall("initialize".into()));
        assert_eq!(passthrough["error"]["code"].as_i64(), Some(-32001));
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

    /// Tool-name case-sensitivity bypass: downstream deny-list /
    /// budget-key / schema-lookup are byte-exact, but most MCP servers
    /// apply ASCII case folding — so `DB_write` would bypass a policy
    /// that denies `db_write` while executing the same tool. The parse
    /// gate now requires lowercase up front.
    #[test]
    fn tools_call_with_uppercase_letters_in_name_is_rejected() {
        for hostile in ["DB_write", "Delete", "readFile", "PING"] {
            let raw = serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "id": "case-attack",
                "method": "tools/call",
                "params": {"name": hostile, "arguments": {}}
            }))
            .unwrap();
            let err = parse_tool_call(&raw).unwrap_err();
            assert!(
                matches!(err, RpcError::BadParams(ref msg) if msg.contains("lowercase")),
                "expected lowercase-refusal for {hostile:?}, got {err:?}"
            );
        }
    }

    /// Unicode-normalization bypass: `de\u{0301}lete` (decomposed) is
    /// visually identical to `délete` (precomposed) but has a different
    /// byte string. NFKC-fold variants like `𝐝𝐛_𝐰𝐫𝐢𝐭𝐞` collapse to
    /// `db_write` on the server side while the proxy sees a distinct
    /// name. Requiring ASCII bytes collapses this attack surface.
    #[test]
    fn tools_call_with_non_ascii_bytes_in_name_is_rejected() {
        for hostile in [
            "d\u{0301}elete",
            "de\u{0301}lete",
            "délete",
            "𝐝𝐛_𝐰𝐫𝐢𝐭𝐞",
            "read_ｆile",
        ] {
            let raw = serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "id": "unicode-attack",
                "method": "tools/call",
                "params": {"name": hostile, "arguments": {}}
            }))
            .unwrap();
            let err = parse_tool_call(&raw).unwrap_err();
            assert!(
                matches!(err, RpcError::BadParams(ref msg) if msg.contains("ASCII")),
                "expected ASCII-only refusal for {hostile:?}, got {err:?}"
            );
        }
    }
    /// `reject_duplicate_keys`
    /// used to wrap EVERY scanner error with the "duplicate JSON key
    /// rejected: ..." prefix — misleading operator triage on
    /// dup-key alerts because malformed JSON, EOF, and recursion
    /// limits were all reported as if they were duplicate-key
    /// rejections. Mirror the sentinel fix from
    /// `av_receipts`: real duplicate-key errors still get the
    /// dup-key prefix; parse errors surface their own class.
    #[test]
    fn duplicate_key_class_distinguished_from_generic_parse_error() {
        // Duplicate top-level key → "duplicate JSON key rejected: ..."
        let real_dup = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": "dup",
            "method": "tools/call",
            "params": {"name": "read", "arguments": {}}
        }))
        .unwrap();
        // Inject a duplicate by hand — serde_json's default parser
        // would take last-wins.
        let dup_raw: Vec<u8> = {
            let mut v = real_dup.clone();
            // Insert a second `"jsonrpc": "2.0"` right after the
            // opening brace.
            let insertion = br#""jsonrpc":"2.0","#;
            v.splice(1..1, insertion.iter().copied());
            v
        };
        let err = parse_tool_call(&dup_raw).unwrap_err();
        assert!(
            matches!(&err, RpcError::Json(msg) if msg.contains("duplicate JSON key rejected")),
            "real dup-key must carry the dup-key prefix, got {err:?}"
        );

        // Malformed JSON (unbalanced brace) → NO dup-key prefix.
        let malformed: &[u8] = b"{\"jsonrpc\":\"2.0\",\"id\":1,";
        let err = parse_tool_call(malformed).unwrap_err();
        match &err {
            RpcError::Json(msg) => assert!(
                !msg.contains("duplicate JSON key rejected"),
                "malformed JSON must not be labeled as duplicate-key, got {msg:?}"
            ),
            other => panic!("expected RpcError::Json for malformed input, got {other:?}"),
        }

        // Empty input → NO dup-key prefix.
        let err = parse_tool_call(b"").unwrap_err();
        if let RpcError::Json(msg) = &err {
            assert!(
                !msg.contains("duplicate JSON key rejected"),
                "empty input must not be labeled as duplicate-key, got {msg:?}"
            );
        }
    }

    /// The scanner used
    /// `deserialize_any`, which returns after the first complete JSON
    /// value — so `{"ok":1}garbage` was silently accepted. A proxy
    /// that inspected only the first value could disagree with a
    /// downstream that concatenated the buffer differently
    /// ("smuggled second document"). `Deserializer::end()` after
    /// the scan closes this class.
    #[test]
    fn trailing_garbage_after_valid_json_is_refused() {
        // A well-formed tools/call followed by trailing bytes.
        let valid = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": "trail",
            "method": "tools/call",
            "params": {"name": "read", "arguments": {}}
        }))
        .unwrap();
        let mut with_trail = valid.clone();
        with_trail.extend_from_slice(b"garbage");
        let err = parse_tool_call(&with_trail).unwrap_err();
        assert!(
            matches!(&err, RpcError::Json(msg) if msg.contains("trailing content")),
            "trailing bytes must be refused, got {err:?}"
        );
        // A well-formed value with only trailing whitespace is
        // still accepted — that's benign network padding.
        let mut with_ws = valid.clone();
        with_ws.extend_from_slice(b"   \n\t");
        assert!(
            parse_tool_call(&with_ws).is_ok(),
            "trailing whitespace must be allowed"
        );
    }
}

#[cfg(test)]
mod depth_boundary_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    /// Mutation-run hardening: the depth cap was only proven far
    /// past the limit, so boundary mutants (`current + 1` -> `current * 1`,
    /// deleting the Array arm) survived. Pin the exact boundary through the
    /// public parser for BOTH container kinds. Depth accounting: the
    /// envelope contributes 3 levels (root -> params -> arguments), and each
    /// wrapper inside `arguments.k` adds one, so 61 wrappers sit exactly at
    /// MAX_JSON_DEPTH = 64 and 62 exceed it.
    #[test]
    fn json_depth_boundary_is_exact_for_arrays_and_objects() {
        let build = |inner: String| {
            format!(
                r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"t","arguments":{{"k":{inner}}}}}}}"#
            )
        };
        let arrays = |n: usize| format!("{}0{}", "[".repeat(n), "]".repeat(n));
        let objects = |n: usize| format!("{}0{}", "{\"x\":".repeat(n), "}".repeat(n));
        for shape in [&arrays as &dyn Fn(usize) -> String, &objects] {
            let at_limit = build(shape(MAX_JSON_DEPTH - 3));
            assert!(
                parse_tool_call(at_limit.as_bytes()).is_ok(),
                "depth exactly at MAX_JSON_DEPTH must parse"
            );
            let past = build(shape(MAX_JSON_DEPTH - 2));
            let outcome = parse_tool_call(past.as_bytes());
            assert!(
                matches!(outcome, Err(RpcError::NotJsonRpc(ref m)) if m.contains("depth")),
                "one past MAX_JSON_DEPTH must be refused, got {outcome:?}"
            );
        }
        // Empty containers exercise the `unwrap_or(current + 1)` fallback
        // arms — an empty object/array is still one level deep, so one
        // sitting past the cap must be refused too.
        for leaf in ["{}", "[]"] {
            let wrappers = "{\"x\":".repeat(MAX_JSON_DEPTH - 3);
            let closers = "}".repeat(MAX_JSON_DEPTH - 3);
            let past = build(format!("{wrappers}{leaf}{closers}"));
            let outcome = parse_tool_call(past.as_bytes());
            assert!(
                matches!(outcome, Err(RpcError::NotJsonRpc(ref m)) if m.contains("depth")),
                "empty {leaf} leaf past MAX_JSON_DEPTH must be refused, got {outcome:?}"
            );
        }
    }
}
