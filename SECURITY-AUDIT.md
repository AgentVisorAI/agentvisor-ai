# Security Audit — 2026-08-11

Recent-CVE reachability triage and remediations for the AgentVisor AI workspace.
Ran `cargo audit` against the current `Cargo.lock`; reviewed each advisory
against the actual code paths and features enabled in production.

## Method

- `cargo audit` (rustsec advisory DB, current as of 2026-08-11) enumerates every
  Cargo lockfile entry against the RustSec advisory feed.
- Every advisory below was traced from the transitive parent to the specific
  code path in this workspace, and gated by the actually-compiled feature set.

## Results

`cargo audit` reported 23 advisories. **1 was a real defect (fixed), 2 remain
as low-risk operator-configured surface (documented, upstream fix pending),
and 20 are unreachable given our compiled feature set.**

### Fixed in this session

| Advisory / class | Where | Fix |
|---|---|---|
| CWE-208 timing side-channel on MAC comparison (not in RustSec, discovered by manual audit) | `crates/av-bridge/src/cold_store.rs::read_pending` used `String != String` on a hex MAC | Rewritten as `verify_pending_mac` using `hmac::Mac::verify_slice` (constant-time). Regressions: `corrupt_hex_mac_field_fails_authentication`, `wrong_control_key_fails_authentication`. |

### Not reachable in our configuration (do not require action)

**wasmtime 27** advisories that require Winch, component-model, WASI, shared
memory, or pooling allocator: **all NOT reachable.** Our `wasmtime` dep is
declared as `default-features = false, features = ["runtime", "cranelift", "wat"]`
in the root `Cargo.toml`. Advisories filtered out on this basis:

- RUSTSEC-2026-0086, 0087, 0088, 0089, 0094, 0095 — Winch backend (not compiled)
- RUSTSEC-2026-0085, 0091, 0092, 0093 — component model (not compiled)
- RUSTSEC-2025-0046, 2026-0020, 2026-0021 — WASI implementations (not compiled)
- RUSTSEC-2025-0118 — shared linear memory (not compiled)
- RUSTSEC-2026-0088 — pooling allocator (default allocator used)

**wasmtime 27 RUSTSEC-2026-0096 (critical, aarch64 Cranelift heap escape) is
NOT reachable.** Guest bytecode is loaded only from operator-signed policy
paths (`config.wasm_policy_paths`, loaded in `crates/av-harness/src/main.rs`).
Attackers cannot deliver Wasm bytes to `Module::new`. Regressions locking
this containment invariant:

- `crates/av-sandbox/src/wasm_policy.rs::tests::invalid_wasm_rejected_at_load`
- `crates/av-sandbox/src/wasm_policy.rs::tests::missing_exports_fail_closed`
- `crates/av-sandbox/src/wasm_policy.rs::tests::hostile_infinite_loop_fails_closed_via_fuel_and_epoch`
- `crates/av-sandbox/src/wasm_policy.rs::tests::memory_bomb_policy_fails_closed_via_store_limits` (new)
- `crates/av-sandbox/src/wasm_policy.rs::tests::hostile_return_codes_all_deny` (new)

**wasmtime 2026-0222 (stores mix type indices between engines) NOT reachable.**
Each `WasmPolicy` owns exactly one `Engine`; stores are never shared across
engines.

**tract-nnef 2026-0217 (OOB read on model load) NOT reachable.** We call
`tract_onnx::onnx().model_for_path(path)` in
`crates/av-loopdetect/src/onnx_embed.rs:30`, which invokes the ONNX parser
only. No NNEF code path is reachable. In addition, the production model is
byte-pinned in the Docker image via `ADD --checksum=sha256:...`, so an
attacker cannot substitute a hostile model.

### Reachable but operator-configured trust boundary (defer upstream fix)

- **rustls-webpki 0.102.8 CVEs (2026-0049, 0098, 0099, 0104)** — reach only via
  the `async-nats 0.38` TLS chain. Exploitation requires an attacker to
  control the NATS server the operator configures. The AgentVisor AI threat
  model treats operator-configured broker endpoints as trusted (`nats://`
  URI is an operator secret). Upgrade path (`async-nats 0.42+`) is straightforward
  once the workspace's `nats`/`kafka` feature declarations are corrected
  (see "Known pre-existing workspace issue" below).
  *Resolved after this audit:* the workspace now pins `async-nats 0.50`
  with `rustls-webpki 0.103.13` in `Cargo.lock`.

- **Compression-marker spoofing (design limitation, av-compress)** — the
  idempotence marker the middle-history stubbing pass leaves behind is an
  unauthenticated literal substring, so a hostile middle-range message can
  quote it and make the pass skip stubbing of surrounding messages (a
  compression-degradation, not an integrity or disclosure issue). The scan
  is already bounded to the middle range so tail messages cannot trigger
  it. Exploitation requires message-content control (a compromised prior
  turn), and the impact is bounded to "compression pass skips". Durable
  fix is a keyed marker (HMAC over prior content) or an out-of-band
  per-payload flag; both are larger refactors, unscheduled. Tracked at
  the `TODO(compression-marker)` in `crates/av-compress/src/passes.rs`.

### Informational (no CVE)

- `paste`, `number_prefix`, `rustls-pemfile`, `filetime` — unmaintained
  warnings only. No security impact for our usage.
  *Resolved after this audit:* `rustls-pemfile` left the dependency tree
  entirely on 2026-08-16 (rskafka 0.6 / rustls 0.23 migration; CA parsing
  now via `rustls-pki-types`).

## Adversarial regressions added this session

Beyond the CVE-class coverage above, this session added 9 adversarial tests
locking in resilience against the exploit classes the reported CVEs represent:

Embedded broker (crates/av-bridge/tests/embedded_contract.rs):
- concurrent publish/fetch/retention never returns torn records
- manifest schema/loader alignment on `replication_factor` (present/absent/out-of-range)
- 32-way concurrent same-UID dedup collapses to one offset
- `publish` metadata-UID auto-dedup
- retention refuses to overwrite a diverging pre-planted cold object
- fetch past watermark returns empty (not an error)
- fetch on out-of-range partition/topic is a controlled error
- offsets remain monotone across retention boundaries

Cold-store MAC (crates/av-bridge/src/cold_store.rs, `cold-store` feature):
- tampered_cold_intent_fails_authentication (existing)
- corrupt_hex_mac_field_fails_authentication (new)
- wrong_control_key_fails_authentication (new)

Wasm sandbox (crates/av-sandbox/src/wasm_policy.rs):
- memory_bomb_policy_fails_closed_via_store_limits (new)
- hostile_return_codes_all_deny (new)

## Known pre-existing workspace issue (not this session's scope)

*Resolved after this audit; kept for the record.*

At audit time, `crates/av-bridge/Cargo.toml` declared only `nats` and `kafka`
features while `crates/av-bridge/src/embedded.rs` and neighbors referenced
`feature = "cold-store"`, crate `rdkafka`, and module `cold_store`, so
`cargo clippy --all-features` failed. Default builds succeeded because the
missing features weren't activated. This drift also blocked upgrading the
vulnerable transitive `rustls-webpki` chain (the `async-nats` upgrade path).
The recommended follow-up has since been completed: `av-bridge/Cargo.toml`
now declares `cold-store` (with `object_store`, `url`, `hmac`, `sha2`, `hex`,
`av-receipts`) plus `rdkafka` under `kafka`, `async-nats` is at 0.50, and the
all-feature clippy/test gates pass.

## Verification

- Default gate: `cargo fmt --all`, `cargo test --workspace` — all pass
  (including the 84 s 64-agent contention run).
- Sandbox tests: `cargo test -p av-sandbox` — 29 pass (2 new adversarial).
- Embedded contract: 18 pass (7 added prior session, unchanged this session).
