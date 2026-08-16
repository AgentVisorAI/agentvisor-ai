# AgentVisor AI — Engineering Plan

Source of truth: `AgentBridge.docx` v2.0 ("Technical Architecture Brief: The Agent Event Bridge & Harness (MVP)").
External specs verified against primary sources on 2026-08-10:

- ATIF v1.7 — harborframework.com/docs/agents/trajectory-format (field model, validator rules, version history v1.0-v1.7).
- OCSF `stop_reason_id` config-state binding — github.com/Levaj2000/ocsf-schema PR #1 (merged; aligned with upstream ocsf/ocsf-schema #1704, targeted v1.10.0; JCS canonical-JSON Fingerprint follow-on).

Environment (verified): Rust 1.90 + clippy/rustfmt/miri, 14-core Apple Silicon, 24 GB RAM, git 2.50, brew present.
Docker CLI present but daemon NOT running (no Redpanda locally). No redis-server / nats-server installed (brew-installable).
No wasm32 rustup targets (not needed: WAT text modules compile in-process via wasmtime).

---

## 1. What we are building

A Cargo workspace, `agentvisor-ai`, delivering:

1. **The Harness** (`agentvisor-ai` binary): an Axum/Tokio inline proxy exposing an OpenAI-compatible
   `POST /v1/chat/completions` route (LiteLLM-compatible), an MCP JSON-RPC intercept route, and admin/ops
   routes. Hot path stays under a strict per-stage budget; heavy work is offloaded to async workers over
   bounded channels; every action emits an OCSF event onto the Bridge.
2. **The Bridge** (`av-bridge` crate + embedded broker): a portable, self-hostable event bus with a
   declarative topic-schema manifest, partition-by-`instance_uid` ordered replay, retention + cold-tier
   export, and pluggable backends (embedded file-backed reference implementation; NATS JetStream and
   Kafka-wire/Redpanda connectors behind features).
3. **Receipts** (`av-receipts`): JCS (RFC 8785) canonicalization, SHA-256 event-chain hashing, Ed25519
   session receipts, fully offline verification, key rotation via key ids.
4. **ATIF export** (`av-atif`): schema-faithful ATIF v1.7 writer + strict validator (Harbor semantics),
   reader accepting v1.0-v1.7, atomic spool files, reconciler promotion to retroactive Receipts.
5. **Enforcement modules**: semantic loop breaker (Module A), MCP tool sandbox with WASM policies and
   action budgets (Module B), in-flight context compression (Module C), NHI identity validation with
   scope-inheritance delegation (Module D).
6. **`avctl` CLI**: keygen, receipt verify, ATIF validate, manifest validate/provision, event tail,
   session promote, config validate, loadgen (SLA measurement).

Non-goals carried from the brief: no web UI (Prometheus + raw event stream only), no multi-region
consensus, no model training, no SFT/RL consumer. Additional documented MVP deviations, § 8.

---

## 2. Workspace layout

```
llm_proxy/
├── Cargo.toml                 # workspace, workspace.dependencies, lints
├── rust-toolchain.toml        # pinned toolchain
├── .rustfmt.toml  deny.toml  .gitignore
├── PLAN.md  README.md  ARCHITECTURE.md  BENCHMARKS.md  CHANGELOG.md  SECURITY.md  EVOLUTION.md
├── Makefile                   # canonical dev commands (fmt, lint, test, bench, sla, ci)
├── schemas/                   # JSON Schemas: OCSF ai_operation profile events, ATIF v1.7, manifest, receipt
├── manifests/bridge.example.yaml
├── config/harness.example.toml
├── docker/Dockerfile  docker-compose.yml  vector.toml
├── .github/workflows/ci.yml
└── crates/
    ├── av-core        # ids (UUIDv7), time, approx tokenizer, digests, metrics registry, errors, config primitives
    ├── av-events      # OCSF event model (ai_operation profile), stop_reason ids, schema validation, seq numbering
    ├── av-atif        # ATIF v1.7 model, writer, strict validator, v1.0–v1.7 reader, golden files
    ├── av-receipts    # JCS canonicalization, event-chain hash, Ed25519 sign/verify, keyring, Signer trait
    ├── av-state       # StateStore trait: atomic counters, token velocity, rate limits, action budgets; InMemory + Redis(feature)
    ├── av-bridge      # EventBus trait; embedded file-backed broker; manifest model + provisioner; NATS/Kafka connectors (features)
    ├── av-identity    # NHI JWT validation (EdDSA/HS256), TTL cap, scope inheritance, delegation chains, JWKS sources
    ├── av-compress    # chat-payload parser, pruning passes, invariants, metrics mirroring ATIF token fields
    ├── av-loopdetect  # Embedder trait (HashEmbedder default; tract-onnx behind feature), delta window, circuit breaker
    ├── av-sandbox     # JSON-RPC/MCP parse, JSON Schema arg validation, native policy engine, wasmtime WASM policies, budgets
    ├── av-harness     # Axum app: hot path pipeline, worker pool, session registry, receipt/ATIF issuance, reconciler, /metrics
    └── av-cli         # avctl
```

Crate DAG (build order; no cycles):
`av-core` → `av-events` → `av-atif` → `av-receipts` → `av-state` → `av-identity` → `av-compress` →
`av-loopdetect` → `av-bridge` → `av-sandbox` → `av-harness` → `av-cli`.

---

## 3. Key design decisions (iterated)

### D1. Hot path vs. workers
Stage order per the brief's data-flow: identity → quota → sanitize (WASM) → compress → dispatch copy to
worker (non-blocking `try_send` on bounded channels) → forward upstream → stream chunks back.
Workers do: embedding, loop delta, OCSF emission, bridge publish, ATIF append. **Nothing on the hot path
ever awaits a worker.** Loop-breaker verdicts feed back through shared session state consulted at the
next request/chunk boundary (enforcement is inline; computation is off-path). Any stage instrumented via
a per-stage histogram; a strict mode (`AV_STRICT_BUDGET`) flags stages > 2.0 ms.

### D2. Channel overflow is never silent
`try_send` failure increments `av_events_dropped_total{stage}` and logs at WARN with session id. Tests
force overflow and assert the counter. Drop policy: drop-newest for telemetry events (hot path never
blocks); ATIF-bearing work reserves worker capacity before quota mutation, so overflow fails the
request closed at admission instead of dropping audit steps mid-flight (fidelity criterion).

### D3. Embedded broker is the reference Bridge backend
Redpanda requires Docker (daemon down) and NATS is an external binary. To make the Bridge contract
*hermetically testable* — and to honestly serve the brief's "single container/binary + manifest,
air-gapped" portability contract — `av-bridge` ships an embedded, file-backed, Kafka-like log:
topics → partitions → append-only JSONL segments with offsets, consumer offset tracking, per-topic
retention, partition key = `ai_agent.instance_uid` (ordered per-agent replay). NATS JetStream
(`async-nats`) and Kafka-wire (`rskafka`, works against Redpanda) connectors compile behind `nats` /
`kafka` features with contract tests gated on `AV_NATS_URL` / `AV_KAFKA_BROKER` (attempted live via brew
`nats-server` during verification; skipped-with-notice otherwise — a skipped gate prints, never silently passes).

### D4. Canonicalization = RFC 8785 (JCS)
Receipts hash `JCS(event)`; chain: `h[0] = SHA256("av-genesis" ‖ session_id)`,
`h[i] = SHA256(h[i-1] ‖ JCS(event_i))`. JCS chosen because the OCSF Fingerprint object already
standardizes JCS for canonical JSON (per the PR thread). Numbers: JCS mandates IEEE-754 doubles →
all counters validated ≤ 2^53 (guard + test; silently-lossy integers are a classic silent error).
NaN/Inf unrepresentable (rejected at type level). Implementation validated against RFC 8785 test
vectors (unicode ordering, -0, 1e21 exponent form).

### D5. Receipt subjects are an enum, versioned
`receipt_version: 1`; subject = `EventChain { chain_head, event_count }` or
`AtifTrajectory { trajectory_digest, step_count, retroactive: true }`. Payload carries session id, agent
identity block (version/charter/instance_uid), tool-call summary, cost, stop reason, key id, issued_at,
signature over JCS of the payload-minus-signature. Verification is offline given the public key. `Signer`
is a trait (Ed25519 in-process now; KMS post-MVP per brief).

### D6. Embedder: pinned ONNX production path, deterministic fallback
`tract-onnx` loads the checksum-pinned MiniLM deployment model and tokenizer in the production image
(pure Rust, no PyTorch/Python runtime). The full loop and false-positive SLA suites run against that real
model, and its 384-dimensional output passes the live Qdrant contract. `HashEmbedder` remains a
deterministic, zero-artifact fallback for minimal embedded tests and explicitly configured deployments.

### D7. WASM policies are real, tests need no external toolchain
`av-sandbox` embeds wasmtime; policy modules receive the tool-call JSON + budget state and return
allow/deny + reason via a tiny ABI (linear memory in/out). Tests compile policies from WAT text
in-process (wasmtime's `wat` feature) — no wasm32 target, no npm/clang. A native (Rust closure) policy
engine is the default for zero-dependency deployments; WASM is on by default in the workspace build.
Fuel metering + epoch deadlines bound policy runtime (a hung policy must not stall the pipeline).

### D8. Identity
JWTs via `jsonwebtoken`: EdDSA (primary) + HS256 (dev). Claims: `sub`, `iss`, `aud`, `iat`, `nbf`,
`exp` (**enforced ≤ 15 min after `iat`**), `jti`, `instance_uid`, `charter`, `version`, `scopes[]`,
`parent` (delegation). Delegation rules: child scopes ⊆ parent scopes, `child.exp ≤ parent.exp`, chain
depth ≤ 4, every link signature-verified. Keyring by `kid`; JWKS sources: static file / inline / URL
(boot fetch + periodic refresh). Adversarial suite: `alg=none`, algorithm confusion, expired, `nbf`
future, scope escalation, truncated/tampered tokens, wrong `kid`, oversized TTL.

### D9. Compression is auditable, never semantically destructive
Passes (in order): exact-duplicate system-message collapse → stale tool-output stubbing
(`[pruned: N tokens, sha256:…]` keeps an audit trail) → duplicate message collapse → intra-JSON
whitespace normalization inside tool content → optional middle-window summarizing stub. Invariants
(property-tested): first system prompt byte-identical; last K messages byte-identical; remaining JSON
parses; no orphaned `tool_call_id`; compression idempotent (`c(c(x)) == c(x)`); output tokens ≤ input
tokens. Metrics mirror ATIF names (`prompt_tokens`, `completion_tokens`, `cached_tokens`) per Module C.

### D10. Token counting
Deterministic approximate tokenizer in `av-core` (word/punct/CJK-aware; documented as an approximation,
property-tested for monotonicity ­— more text never fewer tokens — and Unicode safety). Used for budgets,
velocity, compression ratios. Exact provider counts, when present in responses, are recorded alongside.

### D11. Session lifecycle
`X-AV-Session` (or generated UUIDv7), `X-AV-Workflow: signed|unsigned` (default unsigned),
`Authorization: Bearer <NHI JWT>`. Close: explicit `POST /v1/sessions/{id}/close`, idle sweep, or client
abort (stream-drop still finalizes — silent-error #12). Signed close → receipt issued async (< 2 ms
sign; measured). Unsigned close → ATIF spool (atomic tmp+rename). Promotion:
`POST /v1/sessions/{id}/promote` or `avctl session-promote` → reconciler (5 s tick) issues retroactive
receipt ≤ 60 s (measured); promotion idempotent (double-promote = one receipt).

### D12. Evolution with time (explicit user requirement) — see EVOLUTION.md
- **Inbound tolerant, outbound strict**: parsers accept unknown fields (captured into `unmapped`/`extra`),
  emitters always produce the newest schema; validators have strict + compat modes.
- **Versions everywhere**: OCSF `metadata.version` = "1.10.0"; ATIF `schema_version` = "ATIF-v1.7"
  (reader: v1.0-v1.7 with per-version gating tests); `receipt_version`; `manifest_version`;
  `config_version`. Every versioned surface has a dedicated compatibility test module.
- **Traits at every boundary that will move**: `EventBus`, `StateStore`, `Embedder`, `Signer`,
  `PolicyEngine`, `ColdStore`, `VectorSink` — connectors can be added without touching the core.
- `#[non_exhaustive]` on public enums (stop reasons, event classes, receipt subjects); SemVer + CHANGELOG;
  Cargo.lock committed; `deny.toml` for licenses/advisories; MSRV pinned.
- Key rotation: receipts name `key_id`; verifier accepts a keyring; old receipts stay verifiable.
- OCSF Fingerprint (roadmap in brief): types + optional `inventory` / `prev_inventory` chaining fields
  implemented and JCS-hashed behind config flag, default off — the upgrade path is coded, not promised.

### D13. Silent-error inventory (each with a dedicated test)
1. Full telemetry channel drops events → counter + WARN asserted under forced overflow.
2. ATIF steps lost under backpressure → pre-admission worker reservation fails the request closed;
   fidelity test = 100 % steps present.
3. Unknown/missing JSON fields silently ignored → strict validator modes + round-trip property tests.
4. Integer > 2^53 corrupts JCS hashing → guard rejects; test.
5. Float `-0.0`/`1e21` canonicalization drift → RFC 8785 vectors.
6. Clock skew / non-monotonic time breaks chain order → per-session `seq` is authoritative; test with
   deliberately reversed wall-clock.
7. Wrong-key / tampered / reordered / dropped event → verification fails each case (mutation suite).
8. JWT `alg` confusion & `none` → rejected; TTL > 15 min → rejected.
9. Budget counter races (concurrent tool calls) → atomic check-and-spend; 64-thread stress test proves
   no over-spend.
10. Compression corrupts semantics → invariant property tests (D9).
11. Loop-detector false positive on progressing work → progressing-content suite must not trip;
    false-negative on paraphrase loop → paraphrase suite must trip (100 % catch SLA).
12. Client abort mid-stream orphans session → drop-guard finalization test.
13. Reconciler crash/restart double-issues → idempotency test.
14. Per-partition ordering violated → interleaved-publish replay test asserts per-`instance_uid` order.
15. Worker panic kills pipeline → supervisor restarts, `av_worker_panics_total` increments, hot path
    unaffected (test kills a worker mid-flight).
16. Torn ATIF file on crash → atomic tmp+rename; partial-file test rejected by validator, not counted.
17. Metrics endpoint drift → scrape test parses Prometheus text and asserts required series exist.
18. Counter overflow / negative cost → checked arithmetic; property tests.
19. Unicode (emoji, CJK, RTL) in prompts → tokenizer/canonicalization/compression fuzz-light property tests.
20. Duplicate/out-of-order ATIF `step_id`s → validator rejects (Harbor rule: sequential from 1).
21. Skipped/ignored tests hiding failures → gated live tests print an explicit `SKIPPED (reason)` notice;
    `make ci` fails if a *default* suite was filtered out.

### D14. Dependencies (lean, pinned via committed Cargo.lock)
tokio, axum, hyper, tower, futures; serde, serde_json; ed25519-dalek 2, sha2, hex, base64, rand;
jsonwebtoken; jsonschema; uuid (v7); dashmap, parking_lot; bounded Tokio mpsc shards (per
brief); thiserror (libs), anyhow (bins); tracing (+subscriber); serde_yaml (manifest), toml (config);
clap (CLI); reqwest (CLI/JWKS/loadgen); criterion, proptest, tempfile (dev). Feature-gated: `redis`,
`async-nats`, `rskafka`, `tract-onnx`, wasmtime (default-on). Metrics registry is hand-rolled in
`av-core` (atomic counters/histograms → Prometheus text) — zero dep churn on a hot-path surface.

### D15. Lint & correctness gates
Workspace lints: `unsafe_code = "forbid"`, `warnings = "deny"` in CI, clippy `pedantic` (curated),
`unwrap_used`/`expect_used`/`panic` denied in lib code (allowed in tests/benches/bins via scoped
`allow`). `cargo fmt --check`, `cargo clippy --all-targets --all-features -D warnings`,
`cargo test --workspace` (+ `--all-features` compile pass), doc build with `-D rustdoc::broken_intra_doc_links`.

---

## 4. Requirements Traceability Matrix (brief → artifact → proof)

This is the implementation traceability record, not a test report. Current measured evidence and environment limits live in `VERIFICATION.md` and `BENCHMARKS.md`.

| # | Brief requirement | Where implemented | Proof (test/bench/doc) |
|---|---|---|---|
| R1 | §2 signed hot-path added latency p95 ≤ 5 ms, p99 ≤ 8 ms | av-harness pipeline | release `sla_core_metrics`; scope and limits in BENCHMARKS.md |
| R2 | §2 > 2 ms work must be off the async request runtime | blocking-pool middleware + bounded sharded workers | all-feature lint/tests; stage histograms |
| R3 | §2 receipts batched off hot path, finalized once at session close | av-harness session close → av-receipts | test: no signing occurs per-chunk (call-count probe); close issues exactly one |
| R4 | §2 ATIF path separate from signed hot path | authenticated journals + snapshot writer | write-failure retry, torn-tail, tamper, and restart tests |
| R5 | A: loop detect via embeddings, Δ≈0 over 3 steps + N tokens → 429/inject, OCSF event with stop_reason_id | av-loopdetect + harness enforcement | synthetic loop suite: 100 % catch ≤ 3 cycles; progressing suite: 0 false trips; emitted event schema-validated |
| R6 | B: MCP JSON-RPC intercept, WASM policies (wasmtime), action budgets (max_db_writes, max_payout_usd), schema-invalid blocked, < 5 ms | av-sandbox (+av-state) | block-latency bench < 5 ms; budget stress; WAT policy tests; JSON-schema negative suite; per-call OCSF event w/ budget consumption |
| R7 | C: parse payloads, prune, 30-50 % reduction on ≥ 50 k-token histories, metrics mirror ATIF fields | av-compress | 50 k synthetic corpus test asserts ≥ 30 %; invariant property tests; metric name parity test |
| R8 | D: short-lived JWT/HMAC, IdP-bound, scope inheritance, 15-min TTL, instance_uid+TTL in event identity block | av-identity + av-events | adversarial JWT suite; delegation property tests; event identity-block content test |
| R9 | E: events carry ai_agent.version/charter/instance_uid + stop_reason_id per PR #1; metadata v1.10.0 | av-events | golden events validated against shipped JSON Schemas; field-presence tests |
| R10 | E roadmap: Fingerprint observable (tool schemas + sampling params), JCS | av-events model/schema only | roadmap shape test; not an MVP gate |
| R11 | F: broker Redpanda ref + NATS alt; topic per event class; partition by instance_uid; ordered replay | av-bridge (embedded + `kafka`/`nats` features) | embedded contract suite (ordering, replay, offsets); connector contract tests (live-gated) |
| R12 | F: portability = single binary + declarative manifest; schema-validated provisioning | av-bridge manifest + `avctl bridge-provision` | provision-from-manifest-alone integration test (fresh dir), events schema-validated, wall-time recorded (≪ 15 min) |
| R13 | F: retention 30 d default + cold-tier export to customer storage | broker retention + `ColdArchive` retry outbox | embedded expiry and object-store contract tests |
| R14 | G: session-close JCS canonicalization + Ed25519 receipt; offline verify; payload fields per brief | av-receipts | RFC 8785 vectors; tamper/mutation suite; offline verify (no bridge handle in scope); payload field test; sign latency bench < 2 ms |
| R15 | G: signing reserved for consequential actions by policy | harness config (`signed` workflow opt-in) | default-unsigned test; per-workflow policy test |
| R16 | H: ATIF v1.7 capture: root object, agent config, ordered steps, aggregate metrics | av-atif | golden trajectories; strict validator (Harbor rules: sequential ids, agent-only fields, source_call_id refs, ISO-8601) |
| R17 | H: cached-token metrics intact → replayable checkpoint | av-atif metrics | fidelity test: 100 % steps carry prompt/completion/cached counts through export |
| R18 | H: reconciler promotes → retroactive receipt, never blocking hot path | av-harness reconciler | promotion ≤ 60 s test (measured); hot-path isolation test; idempotency test |
| R19 | H: Harbor interop | real HTTP harness ATIF export | CI invokes Harbor's pinned reference validator |
| R20 | §8 stack: Rust+Axum/Tokio, wasmtime, Redis, ONNX-capable, Ed25519, OTLP/Vector | workspace | all-feature build, live OTLP protocol check, Vector config |
| R21 | §9 data-flow sequence order | av-harness pipeline | integration test asserts stage order via tracing span capture |
| R22 | §10 loop SLA 100 % ≤ 3 cycles | av-loopdetect | R5 suite |
| R23 | §10 tool block < 5 ms | av-sandbox | R6 bench |
| R24 | §10 context ≥ 30 % @ ≥ 50 k | av-compress | R7 test |
| R25 | §10 10 k concurrent connections per node | release socket-level SLA | mandatory CI run at 10,000 on every `main` push; BENCHMARKS.md |
| R26 | §10 publish overhead ≤ 0.5 ms p99 | av-bridge enqueue | criterion bench + in-test p99 measurement |
| R27 | §10 receipt sign < 2 ms async | av-receipts | bench + async-issuance test |
| R28 | §10 ATIF fidelity 100 % valid v1.7 | av-atif | R17 + validator pass on every exported file in integration runs |
| R29 | §10 reconciliation ≤ 60 s | harness | R18 |
| R30 | §10 bridge provision < 15 min from manifest alone | av-bridge/avctl | R12 |
| R31 | Non-goals respected (no UI/consensus/training/RL consumer) | — | README scope section |

Anything in the brief not matching a row is a deviation listed in § 8. This matrix is re-audited at the
end of the build (final pass re-reads the docx top-to-bottom against the matrix).

---

## 5. Test plan (summary)

- **Unit**: per module, including every error path constructible without I/O.
- **Property (proptest)**: JCS stability & ordering; chain integrity under arbitrary event lists;
  tokenizer monotonicity/Unicode; compressor invariants incl. idempotence; ATIF round-trip; JSON-RPC
  parser never panics on arbitrary bytes.
- **Golden files**: ATIF trajectories (valid + each validator violation), OCSF events per class,
  a receipt + its verification bundle, bridge manifest.
- **Adversarial**: JWT suite (D8), receipt mutation suite (D13.7), tool-call schema attacks
  (type confusion, extra fields, oversized payloads, deep nesting), budget race stress.
- **Concurrency**: state counter stress (64 threads × 10 k ops), bridge ordering under interleaved
  publishers, worker-panic supervision.
- **Integration** (av-harness/tests): full proxy flow against in-process mock provider (streaming SSE +
  non-streaming), stage order, session close both workflows, promotion, metrics scrape, malformed-input
  handling, client-abort finalization.
- **SLA measurements** (opt-in heavy + CI-scale default): R1, R22-R30 as measured numbers written to
  BENCHMARKS.md.
- **Benches (criterion)**: canonicalize+hash, sign, verify, enqueue publish, identity validate, quota
  check, compress 50 k, sandbox decision, hash-embed + delta.
- **Feature matrix compile checks**: `--no-default-features`, default, `--all-features`.

Definition of done per crate: fmt + clippy clean, tests green, docs on public items, no `unwrap` in lib
paths, silent-error rows covered.

## 6. Milestones

M0 scaffold+CI → M1 core+events+atif → M2 receipts+state+identity → M3 compress+loopdetect →
M4 bridge+sandbox → M5 harness+cli → M6 integration+SLA+bench → M7 docs+final audit (re-read brief,
re-check RTM, record BENCHMARKS.md, memory notes).

## 7. Operational notes

- macOS fd limits: heavy loadgen requires `ulimit -n 65536`; Linux CI uses the same 10,000 target.
- Live-broker/Redis/ONNX tests: env-gated, loudly skipped, never silently green.
- Docker image construction is a mandatory CI gate on every `main` push (pull-request runs skip it to conserve CI minutes). Local Docker API availability is recorded in VERIFICATION.md.

## 8. Documented deviations from the brief (with rationale)

1. **Qdrant optional at runtime**: the Qdrant connector, collection provisioning, and Compose service ship,
   while embedded deployments may select the in-process session window without external vector storage.
2. **TCP RST**: raw RST isn't portably expressible at the Axum layer; we implement HTTP 429, corrective
   payload injection, and hard connection abort — the three enforceable equivalents (config-selectable).
3. **stop_reason_id numeric values**: upstream enum values are not independently relied upon; we ship our
   authored profile's documented mapping (core 0-4, 99 Other; extension 90-94) in the JSON Schema +
   EVOLUTION.md re-mapping policy.
4. **Sections 4-7 absent in the source docx** (numbering jumps 3→8); not an omission here.

---

*Proofread checklist applied: every brief section (§1, §2, §3 A-H incl. E/F/G/H, §8, §9, §10) appears in
the RTM; every RTM row names a concrete artifact and proof; every silent-error row has a test; every
"evolves with time" surface has a version field, a trait boundary, or both; environment constraints
(Docker down, no local brokers, no ONNX model) each have an explicit strategy.*
