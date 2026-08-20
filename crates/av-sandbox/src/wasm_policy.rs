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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use wasmtime::{Config, Engine, Instance, Module, Store, StoreLimits, StoreLimitsBuilder};

/// Fuel budget per evaluation (~millions of instructions; a policy should use
/// a tiny fraction of this).
const FUEL_PER_CALL: u64 = 50_000_000;

/// Linear memory cap per evaluation.
const MAX_MEMORY_BYTES: usize = 16 * 1024 * 1024;

/// Round-15 F1 (av-sandbox): host-memory DoS caps for guest-visible
/// resource growth. `StoreLimitsBuilder::memory_size` bounds one
/// `Memory`, but a hostile policy could:
///
/// * declare many `(memory ...)` sections and reach ~10k×16 MiB of
///   allocation before fuel meaningfully activates;
/// * `table.grow` a table by millions of function-reference slots
///   (each `Option<Func>` ≈ 16 bytes on 64-bit), forcing a huge host
///   allocation on the growth step;
/// * declare many tables per module to multiply the above.
///
/// Fuel/epoch help only against runtime-bounded exploits — allocation
/// pressure lands at instantiation or on a single `memory.grow` /
/// `table.grow` instruction. Cap every dimension explicitly.
const MAX_MEMORIES: usize = 1;
const MAX_TABLES: usize = 4;
const MAX_TABLE_ELEMENTS: usize = 65_536;
const MAX_INSTANCES: usize = 4;

/// Maximum wall time is approximately this many 1 ms epoch ticks.
const EPOCH_DEADLINE_TICKS: u64 = 25;

/// A compiled WASM policy.
pub struct WasmPolicy {
    name: String,
    engine: Engine,
    module: Module,
    epoch_stop: Arc<AtomicBool>,
}

impl WasmPolicy {
    /// Compile a policy from `.wasm` bytes or WAT text.
    pub fn from_bytes(name: impl Into<String>, bytes: &[u8]) -> Result<Self, String> {
        let mut config = Config::new();
        config.consume_fuel(true);
        config.epoch_interruption(true);
        let engine = Engine::new(&config).map_err(|e| e.to_string())?;
        let module = Module::new(&engine, bytes).map_err(|e| e.to_string())?;
        let epoch_stop = Arc::new(AtomicBool::new(false));
        let ticker_stop = Arc::clone(&epoch_stop);
        let ticker_engine = engine.clone();
        std::thread::spawn(move || {
            while !ticker_stop.load(Ordering::Acquire) {
                std::thread::sleep(std::time::Duration::from_millis(1));
                ticker_engine.increment_epoch();
            }
        });
        Ok(Self {
            name: name.into(),
            engine,
            module,
            epoch_stop,
        })
    }

    fn run(&self, payload: &[u8]) -> Result<i32, String> {
        let limits = StoreLimitsBuilder::new()
            .memory_size(MAX_MEMORY_BYTES)
            .memories(MAX_MEMORIES)
            .tables(MAX_TABLES)
            .table_elements(MAX_TABLE_ELEMENTS)
            .instances(MAX_INSTANCES)
            .build();
        let mut store: Store<StoreLimits> = Store::new(&self.engine, limits);
        store.limiter(|l| l);
        store.set_fuel(FUEL_PER_CALL).map_err(|e| e.to_string())?;
        store.set_epoch_deadline(EPOCH_DEADLINE_TICKS);

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
        let ptr = alloc
            .call(&mut store, len)
            .map_err(|e| format!("alloc trapped: {e}"))?;
        let ptr_usize = usize::try_from(ptr).map_err(|_| "alloc returned negative ptr".to_owned())?;
        memory
            .write(&mut store, ptr_usize, payload)
            .map_err(|e| format!("payload write out of bounds: {e}"))?;
        evaluate
            .call(&mut store, (ptr, len))
            .map_err(|e| format!("evaluate trapped/exhausted: {e}"))
    }
}

impl Drop for WasmPolicy {
    fn drop(&mut self) {
        self.epoch_stop.store(true, Ordering::Release);
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
                return PolicyDecision::Deny {
                    reason: format!("policy input serialization failed: {e}"),
                }
            }
        };
        match self.run(&bytes) {
            Ok(0) => PolicyDecision::Allow,
            Ok(code) => PolicyDecision::Deny {
                reason: format!("wasm policy {:?} denied (code {code})", self.name),
            },
            // Fail closed: any trap/fuel/memory/ABI failure is a deny.
            Err(e) => PolicyDecision::Deny {
                reason: format!("wasm policy {:?} failed closed: {e}", self.name),
            },
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
    fn hostile_infinite_loop_fails_closed_via_fuel_and_epoch() {
        let p = WasmPolicy::from_bytes("hostile", HOSTILE_LOOP_POLICY.as_bytes()).unwrap();
        let started = std::time::Instant::now();
        let d = p.evaluate("anything", &json!({}));
        assert!(
            started.elapsed() < std::time::Duration::from_millis(100),
            "fuel/epoch deadline failed to bound the loop"
        );
        match d {
            PolicyDecision::Deny { reason } => assert!(reason.contains("failed closed"), "{reason}"),
            PolicyDecision::Allow => panic!("hostile policy allowed"),
        }
    }

    #[test]
    fn valid_policy_does_not_false_trip_under_parallel_load() {
        let policy =
            Arc::new(WasmPolicy::from_bytes("parallel_size_cap", SIZE_CAP_POLICY.as_bytes()).unwrap());
        std::thread::scope(|scope| {
            for _ in 0..16 {
                let policy = Arc::clone(&policy);
                scope.spawn(move || {
                    for _ in 0..50 {
                        assert_eq!(
                            policy.evaluate("chat/completions", &json!({"small": true})),
                            PolicyDecision::Allow
                        );
                    }
                });
            }
        });
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

    /// Adversarial: a policy module that tries to grow linear memory past the
    /// StoreLimits cap must fail closed. This exercises the same enforcement
    /// path targeted by the RUSTSEC-2026-0088 class ("data leakage between
    /// pooling allocator instances") — we don't use the pooling allocator,
    /// and StoreLimits caps memory before growth can escape.
    #[test]
    fn memory_bomb_policy_fails_closed_via_store_limits() {
        // Attempts to grow the guest memory 4096 pages (256 MiB) — well above
        // MAX_MEMORY_BYTES = 16 MiB. StoreLimits must refuse.
        const MEMORY_BOMB: &str = r#"
        (module
          (memory (export "memory") 1)
          (func (export "alloc") (param i32) (result i32)
            (drop (memory.grow (i32.const 4096)))
            (i32.const 0))
          (func (export "evaluate") (param i32 i32) (result i32)
            (i32.const 0)))
        "#;
        let p = WasmPolicy::from_bytes("memory-bomb", MEMORY_BOMB.as_bytes()).unwrap();
        // Ensure the module loads (parse succeeds) but the evaluation fails
        // closed once memory.grow is denied.
        let decision = p.evaluate("anything", &json!({}));
        match decision {
            PolicyDecision::Allow => {
                // The memory.grow can legally return -1 (denied) without
                // trapping. That's fine — the module correctly declined to
                // exceed the limit. The proof that the guest can NOT
                // actually use memory past the cap is the companion test
                // `memory_grow_past_cap_leaves_grown_region_inaccessible`,
                // which stores at a beyond-cap address and must fail closed.
            }
            PolicyDecision::Deny { reason } => {
                assert!(
                    reason.contains("out of bounds")
                        || reason.contains("trapped")
                        || reason.contains("failed closed"),
                    "expected memory-cap failure, got {reason}"
                );
            }
        }
    }

    /// Round 41 (fourth-model QC): the companion proof the memory-bomb
    /// test's Allow arm defers to. After a beyond-cap `memory.grow`, the
    /// guest tries to STORE at an address inside the would-be grown
    /// region (page 512 = 32 MiB, past the 16 MiB cap). StoreLimits must
    /// have refused the growth, so the store is out of bounds and the
    /// evaluation must fail closed (Deny) — the grown region is
    /// inaccessible, not silently usable.
    #[test]
    fn memory_grow_past_cap_leaves_grown_region_inaccessible() {
        const GROW_THEN_TOUCH: &str = r#"
        (module
          (memory (export "memory") 1)
          (func (export "alloc") (param i32) (result i32)
            (i32.const 0))
          (func (export "evaluate") (param i32 i32) (result i32)
            (drop (memory.grow (i32.const 4096)))
            ;; store at 32 MiB — inside the grown region iff growth succeeded
            (i32.store (i32.const 33554432) (i32.const 1))
            (i32.const 0)))
        "#;
        let p = WasmPolicy::from_bytes("grow-then-touch", GROW_THEN_TOUCH.as_bytes()).unwrap();
        match p.evaluate("anything", &json!({})) {
            PolicyDecision::Deny { reason } => {
                assert!(
                    reason.contains("out of bounds")
                        || reason.contains("trapped")
                        || reason.contains("failed closed"),
                    "beyond-cap store must fail closed with a containment reason, got: {reason}"
                );
            }
            PolicyDecision::Allow => {
                panic!("store at 32 MiB succeeded — the memory cap did not hold")
            }
        }
    }

    /// Adversarial: a policy module whose evaluate returns a wildly-negative
    /// or wildly-positive code must be treated as Deny (fail closed on any
    /// non-zero output), never Allow.
    #[test]
    fn hostile_return_codes_all_deny() {
        for code in [i32::MIN, -1, 1, 42, i32::MAX] {
            let wat = format!(
                r#"(module
                    (memory (export "memory") 1)
                    (func (export "alloc") (param i32) (result i32) (i32.const 64))
                    (func (export "evaluate") (param i32 i32) (result i32) (i32.const {code})))"#
            );
            let p = WasmPolicy::from_bytes("hostile-code", wat.as_bytes()).unwrap();
            let d = p.evaluate("t", &json!({}));
            assert!(
                matches!(d, PolicyDecision::Deny { .. }),
                "code={code} should deny, got {d:?}"
            );
        }
    }
}
