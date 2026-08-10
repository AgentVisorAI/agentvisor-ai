//! WebAssembly policy modules via wasmtime (brief §8 sandboxing engine).
//!
//! ABI (documented for policy authors):
//! - export `memory` (linear memory) and `alloc(len: i32) -> ptr: i32`;
//! - export `evaluate(ptr: i32, len: i32) -> code: i32`;
//! - the host writes the UTF-8 JSON `{"tool": …, "arguments": …}` at `ptr`;
//! - return `0` to allow, any other code to deny.
//!
//! Containment: every evaluation runs in a fresh `Store` with a fuel budget
//! and a linear-memory cap. Traps, missing exports, fuel exhaustion, and
//! memory overruns all fail **closed** (deny) — a hostile or buggy policy can
//! neither hang the pipeline nor allow by accident.

use crate::policy::{PolicyDecision, PolicyEngine};
use serde_json::Value;
use wasmtime::{Config, Engine, Instance, Module, Store, StoreLimits, StoreLimitsBuilder};

/// Fuel budget per evaluation (~millions of instructions; a policy should use
/// a tiny fraction of this).
const FUEL_PER_CALL: u64 = 50_000_000;

/// Linear memory cap per evaluation.
const MAX_MEMORY_BYTES: usize = 16 * 1024 * 1024;

/// A compiled WASM policy.
pub struct WasmPolicy {
    name: String,
    engine: Engine,
    module: Module,
}

impl WasmPolicy {
    /// Compile a policy from `.wasm` bytes or WAT text.
    pub fn from_bytes(name: impl Into<String>, bytes: &[u8]) -> Result<Self, String> {
        let mut config = Config::new();
        config.consume_fuel(true);
        let engine = Engine::new(&config).map_err(|e| e.to_string())?;
        let module = Module::new(&engine, bytes).map_err(|e| e.to_string())?;
        Ok(Self { name: name.into(), engine, module })
    }

    fn run(&self, payload: &[u8]) -> Result<i32, String> {
        let limits = StoreLimitsBuilder::new().memory_size(MAX_MEMORY_BYTES).build();
        let mut store: Store<StoreLimits> = Store::new(&self.engine, limits);
        store.limiter(|l| l);
        store.set_fuel(FUEL_PER_CALL).map_err(|e| e.to_string())?;

        let instance =
            Instance::new(&mut store, &self.module, &[]).map_err(|e| format!("instantiate: {e}"))?;
        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| "policy exports no `memory`".to_owned())?;
        let alloc = instance
            .get_typed_func::<i32, i32>(&mut store, "alloc")
            .map_err(|e| format!("missing alloc: {e}"))?;
        let evaluate = instance
            .get_typed_func::<(i32, i32), i32>(&mut store, "evaluate")
            .map_err(|e| format!("missing evaluate: {e}"))?;

        let len = i32::try_from(payload.len()).map_err(|_| "payload too large".to_owned())?;
        let ptr = alloc.call(&mut store, len).map_err(|e| format!("alloc trapped: {e}"))?;
        let ptr_usize = usize::try_from(ptr).map_err(|_| "alloc returned negative ptr".to_owned())?;
        memory
            .write(&mut store, ptr_usize, payload)
            .map_err(|e| format!("payload write out of bounds: {e}"))?;
        evaluate.call(&mut store, (ptr, len)).map_err(|e| format!("evaluate trapped/exhausted: {e}"))
    }
}

impl PolicyEngine for WasmPolicy {
    fn name(&self) -> &str {
        &self.name
    }

    fn evaluate(&self, tool: &str, arguments: &Value) -> PolicyDecision {
        let payload = serde_json::json!({ "tool": tool, "arguments": arguments });
        let bytes = match serde_json::to_vec(&payload) {
            Ok(b) => b,
            Err(e) => {
                return PolicyDecision::Deny { reason: format!("policy input serialization failed: {e}") }
            }
        };
        match self.run(&bytes) {
            Ok(0) => PolicyDecision::Allow,
            Ok(code) => {
                PolicyDecision::Deny { reason: format!("wasm policy {:?} denied (code {code})", self.name) }
            }
            // Fail closed: any trap/fuel/memory/ABI failure is a deny.
            Err(e) => PolicyDecision::Deny { reason: format!("wasm policy {:?} failed closed: {e}", self.name) },
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use serde_json::json;

    /// Bump allocator + "deny when payload longer than 256 bytes".
    const SIZE_CAP_POLICY: &str = r#"
    (module
      (memory (export "memory") 4)
      (global $next (mut i32) (i32.const 1024))
      (func (export "alloc") (param $len i32) (result i32)
        (local $ptr i32)
        (local.set $ptr (global.get $next))
        (global.set $next (i32.add (global.get $next) (local.get $len)))
        (local.get $ptr))
      (func (export "evaluate") (param $ptr i32) (param $len i32) (result i32)
        (if (result i32) (i32.gt_s (local.get $len) (i32.const 256))
          (then (i32.const 1))
          (else (i32.const 0)))))
    "#;

    /// Scans the payload for the byte sequence "drop_" and denies on match.
    const SUBSTRING_DENY_POLICY: &str = r#"
    (module
      (memory (export "memory") 4)
      (global $next (mut i32) (i32.const 4096))
      (func (export "alloc") (param $len i32) (result i32)
        (local $ptr i32)
        (local.set $ptr (global.get $next))
        (global.set $next (i32.add (global.get $next) (local.get $len)))
        (local.get $ptr))
      (func (export "evaluate") (param $ptr i32) (param $len i32) (result i32)
        (local $i i32)
        (local $end i32)
        (local.set $end (i32.sub (i32.add (local.get $ptr) (local.get $len)) (i32.const 5)))
        (local.set $i (local.get $ptr))
        (block $done
          (loop $scan
            (br_if $done (i32.gt_s (local.get $i) (local.get $end)))
            (if (i32.and
                  (i32.and
                    (i32.eq (i32.load8_u (local.get $i)) (i32.const 100))            ;; d
                    (i32.eq (i32.load8_u (i32.add (local.get $i) (i32.const 1))) (i32.const 114))) ;; r
                  (i32.and
                    (i32.and
                      (i32.eq (i32.load8_u (i32.add (local.get $i) (i32.const 2))) (i32.const 111))  ;; o
                      (i32.eq (i32.load8_u (i32.add (local.get $i) (i32.const 3))) (i32.const 112))) ;; p
                    (i32.eq (i32.load8_u (i32.add (local.get $i) (i32.const 4))) (i32.const 95))))   ;; _
              (then (return (i32.const 2))))
            (local.set $i (i32.add (local.get $i) (i32.const 1)))
            (br $scan)))
        (i32.const 0)))
    "#;

    /// Infinite loop: must be stopped by fuel, not hang the test suite.
    const HOSTILE_LOOP_POLICY: &str = r#"
    (module
      (memory (export "memory") 1)
      (func (export "alloc") (param i32) (result i32) (i32.const 64))
      (func (export "evaluate") (param i32 i32) (result i32)
        (loop $forever (br $forever))
        (i32.const 0)))
    "#;

    #[test]
    fn size_cap_policy_allows_and_denies() {
        let p = WasmPolicy::from_bytes("size_cap", SIZE_CAP_POLICY.as_bytes()).unwrap();
        assert_eq!(p.evaluate("t", &json!({"small": true})), PolicyDecision::Allow);
        let big = json!({"blob": "x".repeat(500)});
        assert!(matches!(p.evaluate("t", &big), PolicyDecision::Deny { .. }));
    }

    #[test]
    fn substring_policy_blocks_dangerous_tools() {
        let p = WasmPolicy::from_bytes("no_drop", SUBSTRING_DENY_POLICY.as_bytes()).unwrap();
        assert_eq!(p.evaluate("search", &json!({"q": "cats"})), PolicyDecision::Allow);
        let d = p.evaluate("drop_database", &json!({}));
        assert!(matches!(d, PolicyDecision::Deny { .. }), "{d:?}");
        // Also catches it inside arguments.
        let d = p.evaluate("sql", &json!({"stmt": "drop_table users"}));
        assert!(matches!(d, PolicyDecision::Deny { .. }), "{d:?}");
    }

    #[test]
    fn hostile_infinite_loop_fails_closed_via_fuel() {
        let p = WasmPolicy::from_bytes("hostile", HOSTILE_LOOP_POLICY.as_bytes()).unwrap();
        let started = std::time::Instant::now();
        let d = p.evaluate("anything", &json!({}));
        assert!(started.elapsed().as_secs() < 10, "fuel failed to bound the loop");
        match d {
            PolicyDecision::Deny { reason } => assert!(reason.contains("failed closed"), "{reason}"),
            PolicyDecision::Allow => panic!("hostile policy allowed"),
        }
    }

    #[test]
    fn missing_exports_fail_closed() {
        let p = WasmPolicy::from_bytes("empty", b"(module)").unwrap();
        assert!(matches!(p.evaluate("t", &json!({})), PolicyDecision::Deny { .. }));
    }

    #[test]
    fn invalid_wasm_rejected_at_load() {
        assert!(WasmPolicy::from_bytes("garbage", b"\x00asm garbage").is_err());
        assert!(WasmPolicy::from_bytes("not wat", b"(module (broken").is_err());
    }
}
