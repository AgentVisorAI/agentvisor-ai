# Structural Refactor Design Notes

This document captures the three structural changes flagged in
engineering review round 51 (§5.1-§5.3) that are correctness-neutral
and value-positive but too large to land in a single incident-scale
sprint. Each entry names the current state, the target state, the
migration path, and the tests that must remain green throughout.

These notes exist so a future implementer can pick up the work
without re-deriving the trade-offs.

## S1 — Reconciler decomposition

### Current state

`crates/av-harness/src/reconciler.rs` is ~6500 lines and does:

* Recovery scans (5 phases per tick, single method
  `recover_spooled_sessions`)
* Session close and promote (`close_session_locked`,
  `promote_session`)
* Retention pruning (`prune_sealed_atif`)
* Orphan quarantine (`archive_conflicting_atif`,
  `archive_conflicting_receipt`)
* Per-session lifecycle locking (`acquire_lifecycle`, lock table
  pruning)
* Finalize observer (metrics + drop-guard)
* Bridge emit + retry
* Receipt sign + verify

Each concern is currently a method on the `Finalizer` struct. There
is no interface boundary between them, so a bug in one silently
affects the others (see round-42 F3 for the seal-before-insert race
that spanned recovery + close).

### Target state

A `RecoveryPass` trait:

```rust
trait RecoveryPass: Sync + Send {
    fn name(&self) -> &'static str;
    async fn run(&self, ctx: &ReconcilerContext) -> Result<PassOutcome, FinalizeError>;
}
```

with concrete implementations:

* `ConsolidateStepJournalsPass`
* `ReapSignedCandidatesPass`
* `RetryMarkedPromotionsPass`
* `QuarantineOrphanJsonPass`
* `EmitPendingCloseSweepPass`

A unified `ActionJournalRecord::apply(&mut Session)` method that
each of the three current accounting folds (recovery, close,
promote) call. Today the folds are hand-rolled and diverge on
edge cases (round-32 F2 fixed one such divergence in token
accounting).

The `Finalizer` struct keeps its public API (close_session,
promote_session, recover_spooled_sessions) but delegates to the
pass registry internally.

### Migration path

1. **Extract `ActionJournalRecord::apply` first.** ✅ LANDED
   (round-51 pass 10): `ActiveJournalRecord::fold_into` /
   `apply_to_totals` + `RecoveredTotals::{validate_tool_accounting,
   store_on}` in `worker.rs` are now the single accounting rule; the
   live path and both recovery folds call them, and the
   `unified_fold_matches_live_path` proof harness pins the two
   applications to identical results. This also unblocks the
   provider prompt-token reconciliation (a correction record now has
   ONE fold to teach).
2. **Extract the QuarantineOrphanJsonPass second.** ✅ LANDED
   (round-51 pass 12): `crates/av-harness/src/recovery.rs` hosts the
   `RecoveryPass` trait, the narrow `ReconcilerContext` (spool dir,
   metrics, known-stems snapshot, warn-once dedupe — passes cannot
   reach locks/signer/bridge unless a field is deliberately added),
   the `passes()` registry, and the first extracted pass: the §8.5
   orphan-JSON quarantine with its live-stem and MIN_ORPHAN_AGE
   guards. `recover_spooled_sessions` runs the registry before its
   adoption scan; the adoption loop keeps only the cheap
   "never parse unauthenticated bytes" skip. Pass-level unit tests
   pin the contract independently of the Finalizer wiring.
3. **Extract each other pass one at a time**, keeping the
   `recover_spooled_sessions` method as a thin loop over the pass
   registry. Do NOT combine steps: each pass extraction is one PR
   with its own regression tests.
   * ✅ `QuarantineIncompleteEffectsPass` (round-51 pass 15): the
     incomplete-effects marker scan (in-flight responses +
     unresolved tool executions) moved to `recovery.rs` with its
     live-session retain and warn-once dedupe. Extracted passes are
     invoked explicitly at their historical positions via
     `recovery::run_pass` — ordering against the not-yet-extracted
     phases is load-bearing (this pass must see the registry BEFORE
     journal recovery adopts sessions; the orphan-JSON pass
     snapshots stems AFTER), so the flat registry loop only becomes
     possible at step 4. `ReconcilerContext` gained sessions /
     journal_key / quarantined_sessions; `known_stems` moved from a
     caller-provided snapshot to a run-time snapshot inside the
     orphan pass (fresher, and the context is narrower).
   * ✅ `ReplayLifecycleOutboxesPass` (round-51 pass 16): publish +
     ack of unacked lifecycle outboxes. The loop body stays in
     `reconciler.rs` as `replay_lifecycle_outboxes_in` next to the
     rest of the outbox subsystem (`LifecycleOutbox`,
     `persist_outbox`, `resolve_lifecycle_ack`, shared with the
     close/emit paths); the pass owns identity, ordering and
     observability. `ReconcilerContext` gained the optional bridge
     handle; bridge-less contexts make the pass a no-op.
   * ✅ `RecoverSignedJournalsPass`, `ConsolidateStepJournalsPass`,
     `AdoptStrictAtifPass` (round-51 pass 17): the three heavyweight
     phases are Finalizer-backed passes — closing, promoting and
     signing are the Finalizer's competency, so these pass structs
     carry `&Finalizer` while leaf passes stay on the narrow
     context. The adoption tail left `recover_spooled_sessions` into
     its own method (`adopt_strict_atif_artifacts`).
4. **Once the pass registry is stable**, move the retention sweep
   from main.rs into the same registry (it's currently spawned
   separately because the reconciler didn't have a home for it).
   * ✅ Flat runner (round-51 pass 17): `recover_spooled_sessions`
     is now a thin ordered loop over six `RecoveryPass`es, with the
     load-bearing order documented at the runner (markers before
     adoption, outbox replay before re-adoption, signed before
     step-journal consolidation, stem snapshot after adoption,
     strict-ATIF adoption last). Remaining (optional): fold the
     retention sweep into the same registry.

### Tests that must remain green

* All reconciler unit tests (currently 45 in reconciler::tests)
* All e2e_workflows integration tests (currently 7)
* The Round-44/44/49/51 seal-before-insert races
  (`recovery_tick_does_not_quarantine_live_sessions_with_inflight_markers`
  and friends)
* The live crash-recovery gate documented in `VERIFICATION.md`

### Estimated scope

Two engineer-months. Not a single PR — 8-12 PRs, each with its own
tests and rollout window.

---

## S2 — Session lifecycle state machine

### Current state

`Session` carries six independent atomic flags:

| Flag | Set by | Read by |
| --- | --- | --- |
| `closed` | `try_close` at close entry | `is_closed` on the request hot path |
| `artifact_committed` | close success (or capture-failed seal) | pending_close_sessions, evict_finalized |
| `close_complete` | close-tail success | evict_finalized, get_or_open |
| `capture_failed` | many hot-path sites | close_session_locked, evict_finalized, pending_close_sessions |
| `receipt_verified` (unsigned) | promote path | promote-idempotency |
| `admission_open` | admission_guard RAII | admission validation |

Correctness rests on operators knowing that certain transitions
must happen in a specific order (artifact_committed BEFORE
close_complete, capture_failed at any time, admission_open only
before try_close, etc.). Every new call site has to consult the
Round-N history to know which flag to touch.

### Target state

A single `SessionState` enum:

```rust
enum SessionState {
    Open,
    Draining,          // try_close ran; streams still active
    Sealed,            // artifact_committed = true; close-tail pending
    Complete,          // close_complete = true
    CaptureFailed,     // any-time terminal
    Quarantined,       // recovery-adopted with inconsistencies
}
```

held in a single `AtomicU8` on `Session`. Every transition is a CAS
that names the expected source state; illegal transitions return an
error rather than silently corrupting.

Keep `admission_open` as a separate flag — it's a lease counter,
not a lifecycle marker.

### Migration path

1. Introduce the enum + AtomicU8 field alongside the six existing
   flags. Every setter of the flags also updates the enum. Every
   test that reads a flag also asserts the enum matches. Land this
   as one PR — it changes no observable behavior.
   * ✅ LANDED (round-51 pass 18): `SessionState { Open, Draining,
     Sealed, Complete }` in one `AtomicU8`, advanced only by
     `shadow_transition` CAS calls inside `try_close`/`reset_close`/
     `mark_artifact_committed`/`mark_close_complete` (and the two
     recovery constructors, which now claim the close instead of
     storing the flag). Illegal transitions panic in debug builds,
     so the whole suite validates the model — and it already caught
     three refinements to this document's original enum: (a) the
     `closed` flag is a CLAIM that legitimately toggles after seal
     (failed close-tail retries) while the chain stays Sealed, so
     transitions at-or-past their target are no-ops; (b) signed
     recovery seals adopted sessions without a prior claim
     (Open→Sealed is legal); (c) `capture_failed` is NOT a chain
     state — capture-failed sessions still seal and complete (the
     capture-failed seal path), so it stays an orthogonal property
     alongside `promoted` and `admission_open`. `Quarantined` is
     registry-level (the reconciler's quarantine set), not a
     Session state.
2. Migrate one flag at a time: `capture_failed → SessionState::CaptureFailed`
   is the simplest since it's a terminal state, then
   `close_complete → SessionState::Complete`, etc. Each migration
   is a PR; the old flag stays until the new enum is authoritative.
   * ✅ `artifact_committed` + `close_complete` readers (round-51
     pass 19): every reader of the two chain flags (the accessor
     pair, `is_empty_unsigned_quarantine`, `evict_finalized`, the
     latched-retention filter, `pending_close_sessions`, and the
     artifact half of `is_closed`) now reads the enum; the setters
     advance the enum FIRST so readers never observe a mirror flag
     ahead of the state. The two flags are write-only mirrors
     awaiting step-3 deletion. (`capture_failed` was reclassified
     in step 1 as an orthogonal property, not a chain state, so it
     does not migrate.) Remaining: the `closed` claim flag — a
     claim lock, not a chain position; it either stays (like
     `admission_open`) or becomes its own two-state claim cell in
     step 3.
3. Delete the flags in reverse order once every reader/writer uses
   the enum.
   * ✅ LANDED (round-51 pass 20): the `artifact_committed` and
     `close_complete` fields are deleted; the enum is the single
     holder of chain state, `transition` (no longer a shadow)
     REFUSES illegal transitions in release and panics in debug.
     S2 is complete. Kept outside the chain, per the step-1
     findings: the `closed` claim flag (a claim lock that toggles
     after seal during failed close-tail retries — analogous to the
     plan's `admission_open` exception), `capture_failed` and
     `promoted` (orthogonal properties, all combinations
     reachable).

### Tests that must remain green

* All session unit tests
* The Round-44 F2 empty-unsigned-quarantine gate
  (`is_empty_unsigned_quarantine`) — this is a special case that
  needs `SessionState::Quarantined` with a discriminant on
  workflow. Watch it.
* The Round-42 F3 seal-before-insert order
  (`try_insert_recovered` sequence). Reordering here is bug bait.
* Every capture_failed-related test — D7 explicitly narrows the
  hot-path callers of `mark_capture_failed` but doesn't change the
  reader semantics.

### Estimated scope

Three engineer-weeks. High-risk because the flags are read on the
request hot path (pipeline.rs:750 `capture_failed()` check) — a
subtle atomic-ordering change would surface only under load.

---

## S3 — Provider adapter trait

### Current state

The upstream is treated as OpenAI-shaped. Most of the shape is
already externalized via config:

* `upstream_chat_path` (route)
* `upstream_auth_header` and `upstream_auth_scheme`
  (Anthropic-friendly)
* `parse_provider_chunk` handles OpenAI + vLLM + LiteLLM SSE
  variants heuristically (BOM, `[DONE]`, `usage: null`)

Direct OpenAI coupling that would break on a different provider:

* Response body shape (`choices[0].message.content` vs Anthropic's
  `content[].text` blocks)
* Tool-call schema (OpenAI's `tool_calls` array vs Anthropic's
  `tool_use` block vs Google's `functionCall` object)
* Usage accounting field names (`prompt_tokens` vs `input_tokens`
  vs `promptTokenCount`)
* Streaming delta shape (OpenAI's `delta` vs Anthropic's
  `content_block_delta` vs Google's `candidates[].content.parts`)

### Target state

A `ProviderAdapter` trait:

```rust
trait ProviderAdapter: Send + Sync {
    fn parse_response_body(&self, bytes: &[u8]) -> Result<ParsedResponse, AdapterError>;
    fn parse_sse_chunk(&self, raw: &str) -> Result<Option<ParsedProviderChunk>, AdapterError>;
    fn usage_from_response(&self, resp: &ParsedResponse) -> UsageAccounting;
    fn tool_calls_from_response(&self, resp: &ParsedResponse) -> Vec<ToolCall>;
}
```

with concrete implementations:

* `OpenAiAdapter` (also fits vLLM, LiteLLM, Groq, Together,
  DeepSeek, OpenRouter, Ollama, LMStudio, llamacpp, xAI, Mistral,
  Azure OpenAI)
* `AnthropicAdapter`
* `GoogleGeminiAdapter`

Selected via a new `provider` config key (default `"openai"` for
back-compat). The `parse_provider_chunk` module keeps the OpenAI
adapter's implementation verbatim.

### Migration path

1. Extract the trait with only the OpenAI adapter. All callers of
   `parse_provider_chunk` go through
   `state.provider_adapter.parse_sse_chunk`. This is a pure
   refactor — no behavior change.
   * ✅ LANDED (round-51 pass 21): `crates/av-harness/src/provider.rs`
     hosts the `ProviderAdapter` trait, `OpenAiAdapter` (a
     transparent shim over the battle-tested `parse_provider_chunk`,
     which stays in `routes.rs` verbatim next to its SSE-framing
     helpers), `adapter_for` and `SUPPORTED_PROVIDERS`. The new
     `provider` config key (default `"openai"`) selects the adapter
     at boot; unsupported values fail `validate()` naming the
     supported set. `AppState.provider_adapter` carries the
     selection; the response stream parses through it. The fuzz
     shim keeps pinning parser totality.
2. Add `AnthropicAdapter`. Gate under `provider = "anthropic"` in
   config. Land integration tests that hit a mock Anthropic server
   and prove the audit chain records the same shape as an OpenAI
   session (down to `event_uid` and `subject.event_count`).
3. Add `GoogleGeminiAdapter`. Same pattern.
4. Update `docs/reference/OPENAI-COMPATIBILITY.md` to a broader
   "provider compatibility" doc.

### Tests that must remain green

* All routes::tests parser tests (they exercise the OpenAI shape
  and must continue to pass verbatim through the OpenAI adapter)
* All e2e_workflows tests (they cover the full audit chain and
  must round-trip receipts and ATIF trajectories against the
  OpenAI adapter unchanged)
* fuzz/parse_provider_chunk (must remain total after the trait
  extraction)

### Estimated scope

One engineer-month for the trait extraction + OpenAI adapter (the
correctness-neutral refactor). Then one engineer-week per additional
provider. Total: two engineer-months to ship Anthropic and Google.

---

## Deferred: W3 group-commit

Documented in the todo tracker for completeness. Not a correctness
gap; the current per-event `sync_data()` delivers p95 33 µs at 10k
connections (`BENCHMARKS.md`). Group-commit trades audit-chain
durability granularity for latency and needs a careful design
before implementation. Revisit when profiling shows fsync is the
top-of-flame-graph cost.

## Deferred: smaller round-51 items awaiting a natural vehicle

* **`validate()` first-error-only (§5.4).** 64 `return Err` sites in
  one 381-line function; converting to error accumulation is
  mechanical but each site needs a judgment call about whether later
  checks depend on it (URL parse before scheme check, etc.). Best
  landed as part of the §4.2 config-enum refactor
  (`#[serde(tag = "kind")]` backend enums), which removes many of
  the sites outright.
* **String-payload error enums (§5.2).** 137
  `Error::Variant(x.to_string())` conversions destroy `ErrorKind`
  and `source()` chains. The review calls this the single
  highest-leverage debuggability change; it is also a
  workspace-wide signature-touching change. Land per-crate, starting
  with `FinalizeError` (the reconciler's) during S1.
* **Test scaffolding dedup (§5.4).** 21 `impl EventBus` doubles and
  6 `fn signer()` definitions across 12 files; a `tests/common/`
  module is straightforward but touches every integration test.
* **Receipt signature domain separation (§3.5).** Signing
  `b"agentvisor-receipt-v1\0" + len + JCS(body)` (mirroring
  `journal.rs`) is the right long-term shape but is a WIRE FORMAT
  BREAK: every existing receipt would fail verification. Requires
  `receipt_version = 2` (the verifier now refuses unknown versions,
  so the rollout is at least safe), dual-version verification in
  `avctl`, and a migration window. Do it before any second artifact
  is signed under the same key, not after.
