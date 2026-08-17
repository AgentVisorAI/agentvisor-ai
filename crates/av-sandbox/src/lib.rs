//! MCP Tool-Call & Action Sandbox (brief Module B).
//!
//! Intercepts JSON-RPC / MCP `tools/call` payloads inline, before they reach
//! downstream tool servers, and produces an allow/deny verdict from four
//! chained gates (all must pass, evaluated cheapest-first):
//!
//! 1. **Parse gate** — strict JSON-RPC 2.0 shape (a parser that never panics
//!    on arbitrary bytes, property-tested);
//! 2. **Schema gate** — per-tool JSON Schema argument validation
//!    (schema-invalid payloads are blocked with an authorization error);
//! 3. **Policy gate** — native Rust rules and/or WebAssembly policy modules
//!    executed in wasmtime with fuel + memory bounds (a hung or hostile
//!    policy cannot stall the pipeline);
//! 4. **Budget gate** — atomic action budgets (per-tool
//!    `max_tool_calls["db_write"]: 3`, `max_payout_usd_micros:
//!    50_000_000` = $50) via `av-state`.
//!
//! Every verdict is returned with machine-readable context so the harness can
//! emit the per-call OCSF event (allowed or blocked, with budget consumption).

pub mod policy;
pub mod rpc;
pub mod sandbox;

pub use policy::{NativePolicy, PolicyDecision, PolicyEngine};
pub use rpc::{parse_tool_call, RpcError, ToolCallRequest};
pub use sandbox::{Sandbox, SandboxConfig, ToolVerdict};

#[cfg(feature = "wasm")]
pub mod wasm_policy;
#[cfg(feature = "wasm")]
pub use wasm_policy::WasmPolicy;
