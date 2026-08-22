#![no_main]
//! JSON-RPC 2.0 tool-call parser. Must be total: an adversarial MCP
//! client can send any bytes into the /mcp route, and the parser
//! must return RpcError rather than panic. The strict duplicate-key
//! refusal (`refuse_duplicate_json_keys`) is exercised by every
//! nested object.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = av_sandbox::parse_tool_call(data);
});
