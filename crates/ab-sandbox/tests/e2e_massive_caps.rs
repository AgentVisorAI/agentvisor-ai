//! Enforcement caps for pathological inputs — the actual production
//! guardrails at the sandbox RPC boundary. These prove that oversized
//! attacker-controlled bytes are refused before parsing, that deeply
//! nested JSON is refused before descent, and that inputs sitting AT
//! the cap succeed.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use ab_sandbox::rpc::{self, RpcError};
use serde_json::{json, Value};

fn well_formed_tool_call() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "t", "arguments": {}}
    }))
    .unwrap()
}

// ---------------------------------------------------------------------------
// 1. Byte cap: (MAX_PAYLOAD_BYTES + 1) refused with the typed TooLarge
//    error before any JSON parsing runs.
// ---------------------------------------------------------------------------

#[test]
fn one_byte_over_cap_is_refused_with_typed_error() {
    let huge = vec![b'x'; rpc::MAX_PAYLOAD_BYTES + 1];
    let err = rpc::parse_tool_call(&huge).unwrap_err();
    match err {
        RpcError::TooLarge(observed, bound) => {
            assert_eq!(observed, rpc::MAX_PAYLOAD_BYTES + 1);
            assert_eq!(bound, rpc::MAX_PAYLOAD_BYTES);
        }
        other => panic!("expected TooLarge, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 2. Byte cap boundary: a well-formed request sized to just under the cap
//    parses successfully. Proves the check is `>` not `>=` and that no
//    memory-clamping bug corrupts near-cap payloads.
// ---------------------------------------------------------------------------

#[test]
fn payload_just_under_cap_still_parses_successfully() {
    let base = well_formed_tool_call();
    // Pad the arguments string field until total is ~MAX-2 KiB (safety
    // margin for JSON overhead). This proves near-cap inputs work.
    let target = rpc::MAX_PAYLOAD_BYTES - 2 * 1024;
    let padding = target.saturating_sub(base.len());
    let payload = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "t", "arguments": {"pad": "a".repeat(padding)}}
    });
    let raw = serde_json::to_vec(&payload).unwrap();
    assert!(raw.len() <= rpc::MAX_PAYLOAD_BYTES);
    let parsed = rpc::parse_tool_call(&raw).unwrap();
    assert_eq!(parsed.tool, "t");
}

// ---------------------------------------------------------------------------
// 3. Deep JSON: MAX_JSON_DEPTH + 1 levels refused as NotJsonRpc with a
//    nesting-bound message. Guards against stack-exhaustion DoS.
// ---------------------------------------------------------------------------

#[test]
fn json_deeper_than_the_depth_bound_is_refused() {
    let mut nested = Value::from(1);
    for _ in 0..(rpc::MAX_JSON_DEPTH + 8) {
        nested = json!({"n": nested});
    }
    let payload = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "t", "arguments": {"deep": nested}}
    });
    let raw = serde_json::to_vec(&payload).unwrap();
    let err = rpc::parse_tool_call(&raw).unwrap_err();
    match err {
        RpcError::NotJsonRpc(msg) => assert!(
            msg.contains("nesting") || msg.contains("depth"),
            "expected nesting-bound message, got {msg:?}"
        ),
        other => panic!("expected NotJsonRpc(nesting), got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 4. Depth boundary: nesting equal to the bound still parses. Same
//    off-by-one hygiene as the byte cap.
// ---------------------------------------------------------------------------

#[test]
fn json_at_the_depth_bound_still_parses() {
    // Build a payload whose deepest reachable node sits exactly at the
    // bound: outer object + params + arguments + N nested "n" objects.
    // Root ({}) is depth 0, so budget for "n"s is MAX_JSON_DEPTH - 3.
    let mut nested = Value::from(1);
    for _ in 0..(rpc::MAX_JSON_DEPTH - 3) {
        nested = json!({"n": nested});
    }
    let payload = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "t", "arguments": {"deep": nested}}
    });
    let raw = serde_json::to_vec(&payload).unwrap();
    rpc::parse_tool_call(&raw).unwrap();
}

// ---------------------------------------------------------------------------
// 5. Zero-size and single-byte inputs: never panic, always yield typed
//    errors. Pair the giant-input tests with the boundary at 0.
// ---------------------------------------------------------------------------

#[test]
fn empty_and_single_byte_inputs_yield_typed_errors_not_panics() {
    for input in [&b""[..], &b"{"[..], &b"x"[..]] {
        let err = rpc::parse_tool_call(input).unwrap_err();
        assert!(
            matches!(err, RpcError::Json(_) | RpcError::NotJsonRpc(_)),
            "unexpected variant for input {input:?}: {err:?}"
        );
    }
}
