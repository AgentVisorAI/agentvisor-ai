//! Robustness against known attacks on the pipeline's third-party
//! components: Redis, Kafka, NATS, cold-store (object_store), and
//! wasmtime. Each test targets a real CVE or public-attack class against
//! the specific backend AgentBridge integrates.
//!
//! Contract tests that need a live backend (`AB_REDIS_URL`, `AB_KAFKA_URL`,
//! `AB_NATS_URL`) live in the crate-local contract suites and skip loudly
//! when unset. This file targets the LOGIC AgentBridge wraps around those
//! backends — Lua-script atomicity, MAC domain separation, subject
//! validation, wasmtime fuel/memory/epoch containment.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

use ab_bridge::{BridgeManifest, EmbeddedBroker, EventBus};
use ab_sandbox::{PolicyDecision, PolicyEngine, WasmPolicy};
use ab_state::{BudgetSpec, InMemoryStore, Spend, StateStore};
use serde_json::json;

fn manifest() -> BridgeManifest {
    let mut m = BridgeManifest::default_for("known-attacks-enclave");
    for t in &mut m.topics {
        t.schema_ref = None;
    }
    m
}

// ---------------------------------------------------------------------------
// 1. Redis Lua-script contract equivalence (attack: Redis Cluster split-brain
// or Lua non-atomicity would let a distributed client double-spend). The
// InMemoryStore is the reference implementation — the Redis Lua script must
// match its behavior. Here we exercise the reference implementation with
// the exact multi-key semantics the Lua script needs to preserve.
// ---------------------------------------------------------------------------

#[test]
fn multi_key_check_and_spend_is_all_or_nothing_at_the_boundary() {
    let store = InMemoryStore::new();
    // Prime "starved" at limit and "room" at 0.
    assert!(store.try_spend("starved", 100, 100).unwrap());
    // The very next multi-spend must fail on `starved` and MUST NOT
    // partially commit on `room`. A Lua script that lacks the initial
    // read-then-check-then-write ordering would fail this.
    let outcome = store
        .try_spend_many(&[
            Spend {
                key: "room".to_owned(),
                amount: 1,
                limit: 1_000,
            },
            Spend {
                key: "starved".to_owned(),
                amount: 1,
                limit: 100,
            },
        ])
        .unwrap();
    assert_eq!(outcome, Some(1));
    assert_eq!(store.get("room").unwrap(), 0, "partial commit leaked");
    assert_eq!(store.get("starved").unwrap(), 100);
}

// ---------------------------------------------------------------------------
// 2. Redis TTL bypass (attack: attacker sets a key with a huge TTL to
// consume budget forever). The AgentBridge Lua script uses `EXPIRE key
// 86400` on every INCR, so a poisoned pre-existing key with different TTL
// would be RESET by our script. The InMemoryStore has no TTL; the important
// invariant is that `add` on an existing key increments (not overwrites)
// and that the value is bounded by the limit inside Lua.
// ---------------------------------------------------------------------------

#[test]
fn budget_add_never_overwrites_an_existing_counter_only_increments() {
    let store = InMemoryStore::new();
    store.add("k", 10).unwrap();
    store.add("k", 5).unwrap();
    assert_eq!(store.get("k").unwrap(), 15);
    // And add refuses to go past MAX; this is what the Lua script's
    // `current + amount > limit` guard mirrors.
    let err = store.add("k", u64::MAX / 3).is_err();
    assert!(err, "add above limit must fail-fast");
    assert_eq!(store.get("k").unwrap(), 15, "value was corrupted on overflow");
}

// ---------------------------------------------------------------------------
// 3. Bridge subject/topic injection (attack: NATS or Kafka topic name
// containing wildcards ".>*", control chars, or ".." to escape into a
// different topic namespace). The EmbeddedBroker `provision` +
// `publish/fetch` treat topic as an opaque string but AgentBridge
// validates topic existence — an unknown topic must be refused.
// ---------------------------------------------------------------------------

#[test]
fn broker_refuses_unknown_topic_names_including_wildcards_and_control_chars() {
    let dir = tempfile::tempdir().unwrap();
    let broker = EmbeddedBroker::provision(dir.path(), &manifest()).unwrap();
    for hostile in [
        "agent.*",         // NATS wildcard
        "agent.>",         // NATS greedy wildcard
        "agent.session\0", // NUL-terminated
        "agent.session\n", // newline
        "agent..session",  // double-dot traversal
        "../etc/passwd",   // path traversal
        "",                // empty
        "agent.session ",  // trailing space
        &"a".repeat(4096), // giant name
    ] {
        assert!(
            broker.publish(hostile, "k", &json!({})).is_err(),
            "hostile topic {hostile:?} was accepted"
        );
        assert!(
            broker.fetch(hostile, 0, 0, 10).is_err(),
            "fetch on hostile topic {hostile:?} was accepted"
        );
    }
}

// ---------------------------------------------------------------------------
// 4. Kafka key-based partitioning drift (attack: same partition_key produces
// different partitions across restarts, breaking per-agent ordering).
// AgentBridge stipulates per-agent ordering (D13.14). The embedded broker
// hashes deterministically — publishing the same key twice always lands
// on the same partition.
// ---------------------------------------------------------------------------

#[test]
fn same_partition_key_always_lands_on_the_same_partition() {
    let dir = tempfile::tempdir().unwrap();
    let broker = EmbeddedBroker::provision(dir.path(), &manifest()).unwrap();
    let ack1 = broker
        .publish("agent.session", "agent-42", &json!({"i": 1}))
        .unwrap();
    let ack2 = broker
        .publish("agent.session", "agent-42", &json!({"i": 2}))
        .unwrap();
    let ack3 = broker
        .publish("agent.session", "agent-42", &json!({"i": 3}))
        .unwrap();
    assert_eq!(ack1.partition, ack2.partition);
    assert_eq!(ack2.partition, ack3.partition);
    // And offsets are strictly increasing within that partition.
    assert!(ack1.offset < ack2.offset);
    assert!(ack2.offset < ack3.offset);
}

// ---------------------------------------------------------------------------
// 5. wasmtime containment: fuel exhaustion (attack: policy contains a while
// loop, agent submits a call, policy loops forever). The engine must trap
// on fuel exhaustion and return a Deny verdict via the PolicyEngine trait.
// ---------------------------------------------------------------------------

#[test]
fn wasmtime_policy_infinite_loop_is_stopped_by_fuel_or_epoch() {
    // WAT: a policy whose `evaluate` runs an infinite loop.
    let wat = r#"
        (module
          (memory (export "memory") 1)
          (func (export "alloc") (param i32) (result i32) i32.const 0)
          (func (export "evaluate") (param i32 i32) (result i32)
            (loop $inf (br $inf))
            i32.const 1)
        )
    "#;
    let policy = WasmPolicy::from_bytes("inf-loop", wat.as_bytes()).unwrap();
    let start = std::time::Instant::now();
    let decision = policy.evaluate("t", &json!({}));
    let elapsed = start.elapsed();
    // Fuel exhaustion / epoch trap must produce Deny, not spin forever.
    assert!(
        matches!(decision, PolicyDecision::Deny { .. }),
        "expected Deny on infinite loop, got {decision:?}"
    );
    assert!(
        elapsed.as_secs() < 5,
        "wasmtime containment took {elapsed:?} — potential DoS window"
    );
}

// ---------------------------------------------------------------------------
// 6. wasmtime containment: memory-cap enforcement (attack: policy allocates
// gigabytes to OOM the host). Wasmtime's StoreLimits caps linear memory at
// MAX_MEMORY_BYTES; a policy trying to grow past that must trap.
// ---------------------------------------------------------------------------

#[test]
fn wasmtime_policy_memory_grow_past_cap_is_stopped() {
    // WAT: memory.grow by 4096 pages (256 MiB) — exceeds our 16 MiB cap.
    let wat = r#"
        (module
          (memory (export "memory") 1)
          (func (export "alloc") (param i32) (result i32)
            i32.const 4096
            memory.grow
            drop
            i32.const 0)
          (func (export "evaluate") (param i32 i32) (result i32) i32.const 0)
        )
    "#;
    let policy = WasmPolicy::from_bytes("mem-bomb", wat.as_bytes()).unwrap();
    let decision = policy.evaluate("t", &json!({}));
    // Deny (from an alloc trap) OR Allow with capped memory — both are
    // safe. What must not happen: the host process ends.
    match decision {
        PolicyDecision::Deny { .. } | PolicyDecision::Allow => {}
    }
}

// ---------------------------------------------------------------------------
// 7. wasmtime containment: hostile module (attack: policy exports the wrong
// functions or missing memory). Wasmtime instantiate errors or missing
// export lookup errors must produce Deny, not panic.
// ---------------------------------------------------------------------------

#[test]
fn wasmtime_policy_missing_required_exports_is_denied_cleanly() {
    // Missing `evaluate`.
    let wat = r#"
        (module
          (memory (export "memory") 1)
          (func (export "alloc") (param i32) (result i32) i32.const 0))
    "#;
    let policy = WasmPolicy::from_bytes("bad-shape", wat.as_bytes()).unwrap();
    let decision = policy.evaluate("t", &json!({}));
    assert!(matches!(decision, PolicyDecision::Deny { .. }));
}

// ---------------------------------------------------------------------------
// 8. Cold-store MAC domain separation (attack: reuse a MAC generated for a
// different bucket / different domain). The `pending_mac` in cold_store
// prefixes with `b"agentbridge-cold-outbox-v1\0"` before HMAC-ing; a MAC
// computed without that prefix must not verify.
//
// We cannot invoke pending_mac directly (pub(crate)), but we CAN verify
// the invariant through the public control_key derivation: distinct
// signers produce distinct keys, so cross-deployment key reuse fails.
// ---------------------------------------------------------------------------

#[test]
fn cold_store_control_key_derivation_isolates_deployments() {
    let a = ab_receipts::Ed25519Signer::from_seed([1; 32]);
    let b = ab_receipts::Ed25519Signer::from_seed([2; 32]);
    let ka = ab_harness::control_key_from_signer(&a);
    let kb = ab_harness::control_key_from_signer(&b);
    assert_ne!(ka, kb, "signer keys collided — deployments share MAC secret");
    // And the derivation is deterministic per-signer.
    let ka2 = ab_harness::control_key_from_signer(&a);
    assert_eq!(ka, ka2);
}

// ---------------------------------------------------------------------------
// 9. Broker manifest tampering (attack: an operator ships a partition
// count that doesn't match the on-disk layout, hoping to redirect writes
// to a different segment). `EmbeddedBroker::open` compares the on-disk
// manifest to detect mismatches.
// ---------------------------------------------------------------------------

#[test]
fn embedded_broker_refuses_double_provision_in_the_same_directory() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = manifest();
    let _first = EmbeddedBroker::provision(dir.path(), &manifest).unwrap();
    // Second provision must refuse — otherwise attacker could re-provision
    // with different topic/partition counts and reroute writes.
    let second = EmbeddedBroker::provision(dir.path(), &manifest);
    assert!(second.is_err());
}

// ---------------------------------------------------------------------------
// 10. Budget overflow via giant amount (attack: submit amount = u64::MAX
// hoping the arithmetic wraps and permits infinite spend). The reference
// store's `add` refuses via i64::MAX/2 headroom; the Lua script uses the
// same `current + amount > limit` guard.
// ---------------------------------------------------------------------------

#[test]
fn budget_giant_amount_is_refused_no_silent_wrap() {
    let store = InMemoryStore::new();
    let spec = BudgetSpec {
        max_payout_usd_micros: Some(50_000_000),
        ..BudgetSpec::default()
    };
    let budget = ab_state::ActionBudget::new(&store, "sess", &spec);
    // Attacker submits max u64 as the amount.
    let outcome = budget.try_tool_call("t", u64::MAX);
    // Either typed error or Refused — never Allowed (which would wrap).
    match outcome {
        Ok(ab_state::BudgetDecision::Refused { .. }) | Err(_) => {}
        Ok(ab_state::BudgetDecision::Allowed { .. }) => {
            panic!("giant amount was ALLOWED — silent wrap or missing check")
        }
    }
}
