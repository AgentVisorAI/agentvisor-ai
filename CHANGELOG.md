# Changelog

All notable changes are documented here. The project follows Semantic Versioning.

## Unreleased

### Bug-hunt round 32: Qdrant cross-session contamination + compression O(n²) → O(n) (2026-08-20)

Applied three surgical fixes from a user-supplied list of deferred
items. Verified that item #1 in the list (**ATIF strict-validator
type gaps on `agent.model_name` / `step.model_name` /
`SubagentTrajectoryRef` typed members**) is already fixed in
round-16 F2 (`validate.rs:460, 705` and elsewhere).

- **loopdetect (medium, false loop signals):** the Qdrant vector
  sink filtered `nearest_similarity` by `session_id` only. When a
  session id is recycled (`SessionRegistry::get_or_open` returns a
  fresh Session under the same key after finalize), the new
  session's queries returned the PRIOR incarnation's vectors —
  causing false semantic-loop signals from an unrelated past
  session. Fixed by adding `Session::session_scope`, a UUID
  scoped as `format!("{id}#{generation_uid}")` where
  `generation_uid` is a fresh `av_core::new_event_uid()` per
  `Session::new`. Every vector record and query in
  `worker.rs` now uses `session.session_scope` instead of
  `session.id`. Recycled ids land in a distinct scope. The bare
  `id` remains the primary key for on-disk artifacts (spool
  paths, journal filenames) which use crash-safe generation logic
  of their own.
- **compress (medium, O(n²) → O(n) allocation):**
  `collapse_duplicate_messages` used `Vec<Value>` + `Vec::contains`
  for duplicate detection, giving O(N²) lookup on N messages AND
  cloning every non-duplicate into the seen-list. Now uses a
  `HashSet<u64>` keyed by a stable content hash derived from
  `(role, content_str)` — the two components `contains` used to
  compare, since the guards above already exclude tool_calls-
  carrying and pre-stubbed messages. O(1) average lookup and no
  message clone.
- **compress (medium, O(n²) → O(n) work):** `stub_middle_to_target`
  called `payload_tokens_with_messages(payload, messages)` on
  every loop iteration — each call clones the entire payload AND
  the entire messages Vec, then serializes to string. On a 4 MiB
  payload with hundreds of messages that's O(N²) work and O(N)
  transient allocations per iteration. Now tracks a running
  `current_tokens` counter that is decremented by the message's
  pre-stub token count and incremented by the stub's on each
  successful substitution. Single seed call at loop entry.

Verified already-fixed (from the user's deferred-item list):
- **ATIF strict-validator type gaps** on `agent.model_name`,
  `step.model_name`, and `SubagentTrajectoryRef.{trajectory_id,
  session_id, trajectory_path}` — all covered by round-16 F2's
  strict-validator type checks. No further action needed.

### Bug-hunt round 31: silent-bug hunt — ONNX zero-vector fallback poisons breaker (2026-08-20)

Three focused deep-dives on SILENT bugs (the worst class — they
don't fail loudly, they drop data / corrupt state / produce
plausible-but-wrong output): silent error swallowing, silent
numeric behavior, silent state corruption. Combined: ~25
candidate silent bugs identified. 1 applied; the rest are either
documented best-effort (Redis refund/remove warns from prior
rounds), astronomically rare (u64 sequence overflow at
2^64 events), or design items requiring cross-cutting change.

- **loopdetect (medium, silent breaker poison):** `OnnxEmbedder::embed`
  returned a **zero vector** on ONNX inference failure. The
  `Embedder` trait doc says "zero vector is allowed for
  empty/degenerate input", so the breaker
  (`SessionLoopState::observe_embedding_with_similarity`) treated
  a real ONNX outage as if the agent had emitted degenerate
  input — and consecutive zero-vector observations register as a
  near-perfect duplicate signal (`delta ≈ 0`), tripping the loop
  breaker mid-flight on repeated ONNX outages. Same class as
  round-13 F5's response-side fix (zero-vector poisoning from
  empty text). Fixed by falling back to a deterministic
  `HashEmbedder` over the same text on failure: same text still
  produces the same vector (breaker stability preserved), the
  vector is derived from content (not a false-duplicate signal),
  and the failure is still logged for operator triage.

Not actionable this round (deferred / documented):
- **fsutil `write_atomic` post-rename dir fsync warn+Ok**: documented
  round-6 F5 rationale — the rename already succeeded so the file is
  observable; failing the caller would trigger wrong "file not there"
  retry logic. Real durability gap acknowledged.
- **Redis `refund`/`remove` warn-only**: intentional per
  StateStore trait contract (best-effort compensation on
  lost-race paths; documented round-9 F2 and round-15 F2).
- **Kafka fetch offset sign-wrap**: fixed in round-30 F1.
- **Sequence u64 overflow via `saturating_add`**: 2^64 events per
  session is astronomically improbable; defensive but not a
  practical concern.
- **Choice-index BTreeMap key merge on duplicate provider indices**:
  requires a within-chunk uniqueness check; malformed provider
  responses would be rare.
- **Float→micros drift for money**: money is stored as u64 micros
  everywhere for JCS-safety; the drift is upstream of ingestion
  and outside the harness's canonicalization boundary.
- **Recovery defaults missing counters to zero**: documented
  round-N behavior; recovered session is under-attributed on the
  first tick and self-corrects.
- **`.ok()` on MAC-verified intent decode**: defense-in-depth —
  unauthenticated intents legitimately don't belong to any
  session, so per-session cleanup can't reach them; age-based
  sweep is a separate feature.

### Bug-hunt round 30: Kafka offset sign-wrap refusal (2026-08-20)

Two fresh deep-dives — code-review of round-29 (clean), final
catch-all sweep across `unsafe`, `extern`, `static mut`, `mem::forget`,
integer overflow, DST, and build-time behavior. **Final sweep found
1 real fix; all other classes came back clean.**

- **bridge (medium, replay divergence):** the Kafka fetch path
  cast `offset as i64` unconditionally. The Kafka wire protocol
  reserves negative offsets as sentinels (-1 = latest, -2 =
  earliest), so a `u64` value above `i64::MAX` would sign-wrap
  into a negative number and silently redirect the fetch to the
  log tail (or head, depending on the exact wrap value) instead
  of the requested offset — a very hard-to-diagnose replay
  divergence. In practice legitimate offsets stay well below
  `2^63`, but crash-recovery from a manifest whose offset field
  was tampered on disk could supply a value in `(i64::MAX,
  u64::MAX]`. Now uses `i64::try_from(offset)` and returns
  `BusError::Backend` with a clear message on overflow.

Final-sweep classes all clean:
- No workspace `unsafe`, `extern`, `static mut`, `unsafe impl
  Send/Sync`, or `#[repr(C)]` blocks.
- No `git=` or `*` Cargo dependencies.
- No local-time/DST-dependent timestamp logic.
- `mem::forget` uses are test-only.
- Build scripts are benign.

### Bug-hunt round 29: round-28 primary-path fix + config UX polish + panic docs (2026-08-20)

Four fresh deep-dives — code-review of round-28 (caught a HIGH-severity
regression I introduced), config UX audit (5 findings; 2 applied),
doc-code drift (5 findings; 1 applied), dead-code audit (mostly
intentional defense-in-depth).

- **harness (HIGH, regression self-fix from round-28):** the
  round-28 BusError classification fix updated only 2 of the 4
  BusError→FinalizeError conversion sites. The two missed sites
  live in `resolve_lifecycle_ack`, which is the emission path
  taken by the PRIMARY HTTP `close_session` and
  `promote_session` handlers. Round-28's fix therefore did nothing
  for the request path that motivated it — the exact retry-storm
  it claimed to eliminate was still active. Both sites now use
  `.map_err(FinalizeError::from)`. **This fix ships in the same
  round because round-28 is not yet released and the
  primary-path miss would defeat its stated goal.**
- **config (medium, UX):** `HarnessConfig::validate` refused
  ambiguity and dangling for `tool_upstream_bearer_env/_file` but
  did NOT refuse explicit empty strings; an operator setting
  `tool_upstream_bearer_env = ""` would fail only at first tool
  call with a less actionable error. Now caught at config load
  with a specific "must not be empty when set" error.
- **cli (medium, UX):** `avctl doctor` did not probe
  `tool_upstream_bearer_env/_file` — a mis-permissioned bearer
  file or unset env var would pass doctor and fail at first MCP
  call. Now applies the same
  `require_owner_only_secret` posture to the tool bearer that
  round-14 F1 applied to the upstream API key.
- **core (low, docs):** `Registry::histogram_with_bounds` panics
  on metric-type conflicts but lacked a `# Panics` section in
  its doc comment. Sibling `Registry::histogram` did have it.
  Now consistent.

Not actionable this round:
- **docs (deferred):** `OcsfEventBuilder` claim "enforces
  invariants" is overstated — build() JCS-checks integers and now
  range-checks pruning_ratio_millis, but doesn't validate
  severity/activity/status. Round-38 F3 documented the
  workaround; docstring rewording deferred.
- **docs (deferred):** README overstates "every session ends
  with a signed receipt" — the unsigned workflow exists too.
  Text change deferred pending decision on which flow is the
  primary customer-facing default.
- **config UX (deferred):** `dashboard_enabled=true` unauthed
  dashboard default is real; would need auth infra to change
  safely.
- **dead code (deferred):** three `pub` items with no callers
  (`data_dir`, `from_json_str`, `scopes_cover`) could be
  demoted to `pub(crate)` or removed, but that's cosmetic and
  might break unreleased API expectations.

### Bug-hunt round 28: permanent vs transient bridge error classification (2026-08-20)

Round-27 flagged BusError classification as a deferred design item.
This round applies it — a well-scoped, non-breaking fix.

- **bridge/harness (medium, retry semantics):** `BusError::UnknownTopic`
  (topic not provisioned via the manifest) is a permanent
  misconfiguration — retrying without operator action cannot
  succeed. Historically it flowed through
  `FinalizeError::Bridge(String)` and mapped to HTTP 503 +
  `Retry-After`, so SDKs retried pointlessly and pagers fired on
  what was really an operator config error, not a transient
  outage.
  1. New `BusError::is_permanent()` method: `true` for
     `UnknownTopic` and `Serde` (permanent for that payload;
     retry can't fix a wire-shape violation), `false` for
     `Io`/`Backend` (transient by default).
  2. New `FinalizeError::BridgeConfig(String)` variant for
     permanent lifecycle-publish failures; `Bridge(String)` keeps
     the transient semantic. `impl From<BusError> for
     FinalizeError` routes automatically based on
     `is_permanent()`.
  3. `finalize_error_response` in routes.rs maps
     `BridgeConfig` → HTTP 400 (no `Retry-After`), `Bridge` →
     HTTP 503 (with `Retry-After: 5`). SDKs that respect
     Retry-After now stop retrying on permanent errors.
  4. Two conversion call sites in reconciler.rs
     (`find_event_by_uid`, `publish_idempotent`) switched from
     `.map_err(|e| Bridge(e.to_string()))` to
     `.map_err(FinalizeError::from)`.

Regression test: `bus_error_is_permanent_split`.

### Bug-hunt round 27: emitter/validator parity for pruning_ratio range + specialist security review (2026-08-20)

Three fresh deep-dives — code-review of round-26 (caught a real
emitter/validator drift I just introduced), a specialist
security-review pass on the full workspace (**0 HIGH-severity
findings**), and BusError variant classification (design item;
deferred).

- **events (MEDIUM, regression self-fix from round-26):**
  round-26 added `pruning_ratio_millis > 1000` refusal to
  `OcsfEventBuilder::build`, but did NOT mirror it in the
  sibling wire-side `validate_event`. Round-17 F2 introduced
  `validate_event` specifically as the deserialize-path backstop
  for build's guards, so leaving the range check only on build
  reopens the exact class of emitter/validator drift the two
  fixes were meant to close. `validate_event` now emits a new
  `ValidationError::OutOfSchemaRange` variant when
  `pruning_ratio_millis > 1000`. Regression test:
  `out_of_schema_pruning_ratio_is_flagged_on_validate`. **This
  fix ships in the same round because round-26 is not yet
  released and shipping build-but-not-validate parity would be
  worse than shipping neither.**

- **specialist security review:** a dedicated security-review
  agent performed a full-workspace pass focused on
  cryptographic-signature bypass, JWT bypass, path traversal,
  SSRF, XSS, sandbox escape, timing attacks, budget
  double-spend races, deserialization DoS, and disk-poisoning
  state corruption. **0 HIGH-severity findings** — 27 rounds of
  bug hunting have hardened the codebase to the point that a
  specialist security agent finds nothing new.

Not actionable this round:
- **BusError classification (deferred):** the audit confirmed
  that `BusError::UnknownTopic` (permanent misconfiguration) is
  currently returned to clients as retryable HTTP 503 with a
  `Retry-After` header — SDKs retry pointlessly. The minimal fix
  requires adding a permanence flag to `FinalizeError::Bridge`
  and routing at `routes.rs::finalize_error_response`. It's a
  clean fix but not surgical enough for a mid-round application;
  scheduled for a dedicated error-classification pass.

### Bug-hunt round 26: schema range check for pruning_ratio_millis at build (2026-08-20)

Four fresh deep-dives — code-review of round-25 (clean), CHANGELOG
accuracy audit (0 substantive inaccuracies), `av-events` builder
(1 real range-check gap applied), integration smoke-test coverage
(5 gaps flagged, all Large-effort, deferred).

- **events (medium, schema range gap):** the JSON Schema declares
  `pruning_ratio_millis` as an integer in `[0, 1000]` (permille
  representation of 0.0%–100.0%). `OcsfEventBuilder::build` only
  enforced JCS-safety, so `Some(5000)` (500%) built successfully
  and only failed at strict-validate ingest time downstream — an
  emitter/validator disagreement that shipped invalid events onto
  the audit chain before rejection. Now caught at build. Boundary
  test at `pruning_ratio_millis == 1000` still passes; `> 1000`
  fails build. Regression test:
  `build_refuses_pruning_ratio_millis_above_1000`.

Not actionable this round:
- **events builder (deferred):** `build()` doesn't call
  `validate_event`; a caller can construct an event with
  `severity_id=0` that build accepts but every reader rejects.
  Fix would require every caller to handle a broader error set;
  larger refactor.
- **events builder (deferred):** `.stop_reason_native(...).stop_reason(...)`
  leaves a stale native caption. Fix would require enforcing
  invariant at set time or clearing native on stop_reason set.
- **events builder (deferred):** `payload` has no maxProperties cap.
- **events builder (deferred):** `Fingerprint` chain has no
  digest/algorithm shape checks. All these deferred as
  builder-completeness work.
- **integration coverage (all Large):** full signed+unsigned
  operator round-trip, crash-recover, SIGTERM drain, concurrent
  external-client stress, malicious-ingress matrix. All flagged
  by the test-coverage audit; each is a Large-effort epic.
- **CHANGELOG (0 findings):** the audit found rounds 12-25
  entries match code correctly. Older `Round-XX F#` comments in
  source (rounds 26+) predate this session's numbering and refer
  to a different bug-hunt scheme.

### Bug-hunt round 25: sandbox scanner classification + trailing-content refusal (2026-08-20)

Four fresh deep-dives — code-review of round-24 (clean), av-bridge JSON
ingest surface (1 finding; deferred), av-sandbox scanner classification
(2 real findings applied), NHI identity claims (2 design-level items).

- **sandbox (medium, misleading triage):** `reject_duplicate_keys`
  wrapped EVERY scanner error with the "duplicate JSON key
  rejected: ..." prefix. Malformed JSON (unbalanced brace), EOF,
  recursion-limit exceeded, and invalid escapes ALL surfaced as
  if they were duplicate-key rejections — operators paged on
  "dup-key spike" alerts saw noise from ordinary malformed
  broker payloads. Mirrors round-16 F6's sentinel fix in
  `av_receipts::check_no_duplicate_keys`: a `DUP_KEY_SENTINEL`
  prefix internal to the scanner tags real dup-key errors, and
  the map-err arm strips it and preserves the class. Parse
  errors now surface with their own class (`RpcError::Json(msg)`
  with the underlying serde_json message, no fake prefix).
  Regression test: `duplicate_key_class_distinguished_from_generic_parse_error`.
- **sandbox (medium, smuggled-second-value refusal):** the
  scanner used `deserialize_any`, which returns after the first
  complete JSON value. An input like `{"ok":1}garbage` was
  silently accepted. A proxy that inspected only the first value
  could disagree with a downstream that concatenated the buffer
  differently — a classic "smuggled second document" surface.
  Added `Deserializer::end()` after the scan; trailing whitespace
  is still accepted (benign network padding). Regression test:
  `trailing_garbage_after_valid_json_is_refused`.

Not actionable this round:
- **bridge (deferred):** `nats_bus`/`kafka_bus` deserialize
  broker payloads without duplicate-key pre-scan; a compromised
  emitter can publish malformed JSON that keeps consumers stuck
  at that offset until retention or manual cleanup. Kafka has a
  16 MiB byte cap; NATS has no app-level byte cap. Requires
  topic-schema decisions to fix.
- **identity (deferred):** no explicit NHI type discriminator
  (`token_type=nhi` claim). Any JWT with the required custom
  claims that verifies against the trusted issuer/audience is
  accepted as an NHI. Design intent (broad deployment
  flexibility); operator IdP config is the current lever.
- **identity (deferred):** session/tool binding uses only
  `{version, charter, instance_uid}`; two valid tokens with
  different `sub` but the same triple bind as the same
  principal. Design item; may want `sub` binding in a future
  major.

### Bug-hunt round 24: dangling subagent refs + ATIF writer durability parity (2026-08-20)

Four fresh deep-dives — code-review of round-23 (clean), duplicate-key
consistency across scanners (2 real gaps flagged, 1 fixed),
middleware chain (0 actionable), ATIF writer (4 findings; 2 applied).

- **atif (medium, unverifiable delegation):** ATIF strict validation
  refused a `subagent_trajectory_ref` that omitted both
  `trajectory_id` and `trajectory_path`, but did NOT check that a
  supplied `trajectory_id` actually names an embedded
  `subagent_trajectories[*]`. A hostile producer could emit
  `subagent_trajectory_ref: [{"trajectory_id": "sub-does-not-exist"}]`
  and it passed validation — the auditor is then pointed at a
  subagent trajectory that doesn't exist in the document, giving
  unverifiable delegation provenance. Fixed by pre-collecting the
  embedded `trajectory_id` set and cross-checking each step's
  `subagent_trajectory_ref` against it. `trajectory_path` (external
  refs) remain uncheckable at strict-validate time and are excluded
  from the rule. Regression test:
  `dangling_subagent_trajectory_ref_is_flagged`.
- **atif (medium, durability parity):** `av_atif::write_atomic` used
  `create_dir_all` (not `create_dir_all_synced`) for the parent —
  the same class round-23 fixed in `av_core::fsutil::write_atomic`.
  Now goes through `av_core::fsutil::create_dir_all_synced` so a
  first ATIF write into a new subtree also fsyncs the newly-created
  ancestor dirents. The helper's fast path (single stat) makes the
  hot-path cost negligible.

Not actionable this round:
- **dup-key consistency (deferred):** the three duplicate-key
  scanners (av-receipts, av-sandbox, av-atif) diverge on
  null-handling (receipts refuses, others accept), nesting-depth
  cap (receipts caps at 128, others uncapped), and error message
  format. Consolidation into a shared `av_core` helper with
  per-caller policy flags is possible but requires design input.
- **dup-key consistency (deferred):** `av-sandbox`'s scanner
  misclassifies malformed JSON as "duplicate key rejected"
  because the sentinel-map at `reject_duplicate_keys`'s return
  wraps ALL scanner errors under the DuplicateKey class. Same
  class as receipts round-16 F6 — fix would extract a
  `check_no_duplicate_keys`-style sentinel-vs-parse-error
  discriminator.
- **dup-key (deferred):** `av-bridge` (nats_bus/kafka_bus/embedded)
  ingests JSON from external brokers without dup-key pre-scan.
  Real potential attack surface for topic emitters. Adding pre-scan
  requires topic-schema decisions.
- **atif writer (medium, deferred):** `TrajectoryBuilder::finish`
  computes final_metrics but `write_atomic` accepts any Trajectory,
  so a caller bypassing the builder can emit a trajectory whose
  final_metrics disagrees with per-step sums. Round-16 flagged this;
  fix requires validator-completeness pass.
- **atif writer (deferred):** producers CAN emit older schema
  versions to bypass v1.7-only fidelity checks. Design intent
  (compat).
- **middleware (deferred):** no request rate-limiting, no custom
  404/405 fallback, no explicit HTTP/2 hardening knobs. All
  design items requiring operator-configurable policy.

### Bug-hunt round 23: ATIF ingest malleability + fsutil durability gap (2026-08-20)

Four fresh deep-dives — code-review of round-22 (clean),
`av-core::fsutil` (2 findings; 1 applied), ATIF ingest fuzz-thinking
(2 real findings applied), panic reachability sweep (0 wire-reachable
panics across the workspace).

- **atif (HIGH, ingest malleability):** ATIF trajectory ingest
  accepted duplicate JSON keys silently (serde_json's default is
  last-wins). Verified by running `avctl atif-validate` on a
  crafted file with two `schema_version` keys — it reported
  "valid". A hostile issuer could sign under one version-reading
  while an auditor's raw-bytes reader sees the other. Same class
  as round-15 F3 for receipts and round-22 F1 for chat, now
  applied at the ATIF surface. New primitive
  `av_atif::validate_bytes(bytes, mode) -> Result<Vec<Issue>, String>`
  that (a) refuses duplicate keys via a strict pre-scan, (b) runs
  `validate_value` on the parsed untyped form. Both `avctl
  atif-validate` and `av-harness::reconciler::promote` +
  `recover_spooled_sessions` now go through it. Three regression
  tests.
- **atif (medium, strict/typed drift):** `Trajectory` doesn't
  derive `deny_unknown_fields`, so serde silently dropped unknown
  fields before strict validation ran on the typed form. The
  bytes path via `validate_bytes` now exercises
  `check_unknown_fields` on the untyped `Value`, catching
  unknown fields that the typed path drops. Regression test:
  `validate_bytes_flags_unknown_fields_that_typed_path_would_drop`.
- **core (medium, durability gap):** `av_core::fsutil::write_atomic`
  used `create_dir_all` (not `create_dir_all_synced`) for the
  parent directory. The FIRST write into a new spool subtree
  (`spool/outbox/`, `spool/receipts/`, `spool/tool-executions/`,
  …) created the subdir, fsynced the leaf, but left the ancestor
  dirents volatile — a power loss between the initial `mkdir`
  and any ambient dirent sync could drop the entire subtree
  losing the marker even though its bytes were fsynced. Switched
  to `create_dir_all_synced`. The helper's fast path (skip fsync
  when the directory already exists) means the extra cost is
  only paid on FIRST writes.

Not actionable this round:
- **core (deferred):** `std::fs::rename` on Windows was flagged as
  possibly-not-overwrite-safe; the Rust stdlib implementation
  actually uses `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING`,
  so overwrite works. False positive.
- **panic (audit clean):** 0 `unwrap`/`expect`/`unreachable!` in
  non-test code reachable from external input; `clippy::unwrap_used`
  is `deny` workspace-wide. Excellent defensive posture.

### Bug-hunt round 22: chat duplicate-key rejection + self-fix of round-21 double-observation + quarantine filename (2026-08-20)

Four fresh deep-dives — code-review of round-21 (caught TWO real
regressions I introduced), adversarial-input audit (1 finding
applied), cross-crate error handling (3 findings; deferred),
cancellation semantics (1 finding, already deferred).

- **routes (HIGH, ingress dup-key malleability):** `POST
  /v1/chat/completions` accepted duplicate top-level or nested JSON
  keys silently (serde_json's default is last-wins). A hostile
  client could send `{"messages":[safe],"messages":[hostile]}` —
  the harness saw the hostile array while any auditor reading the
  raw request bytes saw an ambiguous document, violating the
  "same signature ⇔ same bytes" invariant. Same class as
  round-15 F3's receipt-null malleability, applied at chat
  ingress. Now uses the newly-exposed
  `av_sandbox::refuse_duplicate_json_keys` helper (extracted from
  `parse_tool_call`'s existing check) before parsing. Regression
  test: `chat_completions_refuses_duplicate_json_keys`.
- **harness (HIGH, self-fix of round-21):** the round-21 F2 Drop
  observer for `av_session_finalize_duration_seconds` was added
  WITHOUT removing the pre-existing terminal-line observation.
  Every successful `close_session_locked` recorded the histogram
  TWICE — inflating rate/QPS by ~2× and distorting error-ratio
  alerting exactly opposite to the intent. Removed the terminal
  observation; the Drop observer is now the sole record site
  (also covers all `?` early-Err paths, keeping the round-21 F2
  intent).
- **routes (MEDIUM, self-fix of round-21):** the round-21 F4
  `.intent.torn` defense-in-depth was a silent no-op — the
  quarantine writer at `routes.rs:1150` used
  `path.with_extension("intent.torn")` which on a
  `<key>.intent.json` path produces `<key>.intent.intent.torn`,
  not `<key>.intent.torn`. Fixed the writer to build the
  quarantine name explicitly (`{key}.intent.torn`) so
  `remove_tool_executions`'s cleanup entry matches.

Not actionable this round:
- **receipts (medium, deferred):** the round-15 F3
  null-rejection uses the `DUP_KEY_SENTINEL` prefix, so
  null-rejection errors are classified as
  `ReceiptError::DuplicateKey` — misleading for triage. Fix
  requires a new error variant (breaking change on the
  `#[non_exhaustive]` enum's match sites).
- **cross-crate (medium, deferred):** all `BusError` variants
  collapse to `FinalizeError::Bridge(String)` → HTTP 503.
  `BusError::UnknownTopic` is a permanent config error but
  client sees retryable 503; SDKs retry pointlessly. Fix
  requires structured variant preservation through Finalize/
  Pipeline error layers.
- **cross-crate (medium, deferred):** `StateError::Backend`
  (transient Redis outage) maps to `PipelineError::Blocked` →
  HTTP 403 (policy refusal). Client can't distinguish transient
  from permanent. Needs distinct pipeline variant.
- **cancel (deferred):** spawn_blocking budget-task race on
  disconnect — known from prior rounds.

### Bug-hunt round 21: metrics-on-failure + tool-cleanup crash safety (2026-08-20)

Four fresh deep-dives — code-review of round-20 (clean, all 10
concerns verified), metrics accuracy (5 findings; 3 applied),
concurrency race audit (0 findings — well-defended), spool
paths + tool-execution cleanup (5 findings; 2 applied).

- **harness (medium, metrics accuracy):** three histograms were
  observed only on the success branch, hiding failure-latency
  regressions from alerting:
  1. `av_receipt_sign_duration_seconds` in
     `close_session_locked` (Receipt::issue error skipped observe).
     Moved observe BEFORE the `?`-propagation.
  2. `av_receipt_sign_duration_seconds` in `retry_marked_promotions`
     (same shape). Same fix.
  3. `av_session_finalize_duration_seconds` observed only at the
     terminal success line — every `?`-propagation earlier in the
     function skipped it. Now observed via a `FinalizeObserver`
     scope guard whose `Drop` records duration on every exit
     including early Err returns.
- **harness (medium, crash safety):** `remove_tool_executions`
  deleted `.intent.json` FIRST, then `.outcome.json`, then
  `.audited.json`. Recovery invariant is "outcome exists only if
  intent exists"; a crash between the intent removal and outcome
  removal left an orphaned outcome that startup recovery treats
  as fatal (`routes.rs::from_request` refuses
  outcome-without-intent), and `main.rs` bubbles that up as a
  startup failure. Reversed the order to AUDITED → OUTCOME →
  INTENT so the invariant holds under any crash timing.
- **harness (low, defense-in-depth):** tool-execution cleanup also
  removes any `.intent.torn` twin for the same key (defense in
  depth against the rare case where a torn intent coexists with
  a re-created `.intent.json`).

Not actionable this round:
- **metrics (deferred):** `av_stage_duration_seconds` misses
  failure exits in `prepare_chat` at four `return Err(...)` sites.
  Fix requires per-stage RAII scope guards; deferred.
- **metrics (deferred):** `av_lifecycle_event_errors_total` and
  `av_reconcile_errors_total` cover only some code paths and
  overload multiple subsystems respectively. Fix requires
  per-subsystem counter split (breaking change for dashboards).
- **spool (deferred):** `av_core::fsutil::write_atomic` uses
  `create_dir_all` (not `create_dir_all_synced`) — a first
  post-cold-start write followed by a power loss can lose the
  newly-created subdir dirent. Fix touches every write_atomic
  caller in the workspace.
- **spool (deferred):** signer/journal key rotation has no
  migration path; leftover in-flight MAC-sealed markers become
  unverifiable. Requires a keyring/journal-key versioning scheme.
- **spool (deferred):** no cross-process spool lockfile — a
  second harness process on the same spool would race sequence
  allocation and marker journaling. Known deferred design item.
- **spool (deferred):** orphan `.intent.torn` files (whose
  companion `.intent.json` was quarantined by rename) accumulate
  indefinitely — preserved as forensic evidence by design.
  Operator sweep by age is the recommended remedy.
- **race audit:** 0 concurrency invariant violations. This area
  is well-defended after rounds 8-19.

### Bug-hunt round 20: self-audit caught object-shape argument bug + config sanity + regression tests (2026-08-20)

Four fresh deep-dives — code-review of round-19 (caught a
MEDIUM-severity bug I introduced in the loop-breaker request-side
fix), `av-harness/src/config.rs` (2 real findings applied), AppState
+ session lifecycle (2 findings; deferred), and test-coverage audit
(3 tests added filling round-17/18/19 regression gaps).

- **harness (MEDIUM, regression self-fix from round-19):** the
  round-19 `last_message_text` synthesis extracted `function.arguments`
  via `.and_then(Value::as_str)`, which returned `None` on
  object-shaped arguments (bare JSON object on the wire — the
  Anthropic-shaped variant that some gateways use). The synthesized
  text then collapsed to `tool_name()`, and two DIFFERENT tool
  calls to the same tool produced IDENTICAL synthesized text →
  false loop trips. Fix mirrors the tolerant pattern already used
  in `atif_capture_from_request` in the same file: render the raw
  Value via `serde_json::to_string` when it isn't a stringified
  JSON. Two regression tests added:
  `last_message_text_tool_call_synthesis_varies_with_object_arguments`
  (asserts distinct output for `{"path":"a"}` vs `{"path":"b"}`)
  and `last_message_text_tool_call_with_empty_arguments_still_synthesizes`.
  **This fix ships in the same round because round-19 is not yet
  released and a false loop-trip regression would ship with it.**
- **config (medium, silent breakage):** `max_request_bytes = 0`
  passed validate and forwarded to axum's `DefaultBodyLimit::max(0)`,
  silently rejecting every non-empty POST body. Now refused at
  validate with a specific error message.
- **config (medium, false-positive & false-negative):**
  `state_endpoint` field docstring documents it as a
  comma-separated list of URLs for Redis Cluster mode, but the
  scheme allowlist was a prefix check on the WHOLE string. So
  `redis://a:6379,http://b:6379` passed (the check saw `redis://`
  prefix) and only failed at connect. Also `redis+unix:` — a
  legitimate Unix-socket form the redis crate accepts, and one the
  round-14 doctor already recognizes — was rejected. Now splits
  on `,` and validates each member independently; the scheme
  allowlist includes `redis+unix:`.

Regression tests added (filling coverage gaps identified by the
test-coverage audit):
- `av-compress::passes::tests::quoted_marker_phrase_in_normal_text_does_not_disable_compression`
  — round-18 F1 pin.
- `av-events::validate::tests::jcs_unsafe_integer_flagged_on_every_deserialize_carrier`
  — round-17 F2 pin covering `time`, `metadata.sequence`, and all
  five `EventMetrics` counters.

Not actionable this round:
- **harness (medium, deferred):** `AppState.tool_audits_emitted` is
  an unbounded HashSet keyed by `sha256(session_id:jsonrpc_id)`.
  A `mark_audited` disk write failure leaves the key set forever;
  if session id is later recycled AND the same jsonrpc_id
  reappears, the new call is falsely deduped. Fix requires either
  a bounded LRU (memory-visible) or an on-disk `.audited` presence
  check as the primary gate (I/O per request). Deferred for design
  input.
- **harness (medium, deferred):** delayed/retried `/close` for an
  OLD session generation closes whatever session id is CURRENTLY
  mapped (get_or_open recycles ids). Fix requires generation
  tracking; deferred.
- **config (deferred):** feature-gated backends (redis, kafka,
  nats, onnx, qdrant) are accepted at validate but rejected at
  startup when the feature is not compiled in. Arguably design
  intent (validate is compile-agnostic).

### Bug-hunt round 19: request-side loop-breaker false trip + duplicate lifecycle events on outbox unsync (2026-08-20)

Four fresh deep-dives — code-review of round-18 (clean, all 10
concerns verified), `av-identity` (0 HIGH; 3 medium design items),
`av-harness/src/reconciler.rs` (3 findings; 1 applied, 2 deferred),
`av-harness/src/worker.rs` (1 real REQUEST-side loop-breaker false
trip — the mirror of round-13's response-side fix).

- **harness (medium, correctness):** the request-side path in
  `PreparedRequest::prepare_chat` set `analyze_loop =
  (source == Agent)` and got its text from
  `last_message_text`, which only reads string `content`. For an
  assistant tool-call turn (`content: null`, has `tool_calls`), the
  text was `""` → zero-vector embedding → breaker treats as hostile
  duplicate. Round-13 fixed the RESPONSE-side path but the REQUEST
  side had the same shape. Two-part fix:
  1. `last_message_text` now falls back to synthesizing
     `tool_name(arguments)` per tool call (same wire-order rule as
     the response-side synthesis in
     `routes.rs::AbortFinalizingStream::submit_response_capture`),
     and also handles multimodal `content: [{text: ...}, ...]` parts.
  2. `analyze_loop` is now gated on `!text.is_empty()` so a truly
     empty message doesn't feed a zero vector into the breaker.
- **reconciler (medium, non-idempotency):** `remove_outbox`
  returned `Err` if the file was deleted successfully but the
  parent-directory fsync then failed. From the caller's perspective
  the file is GONE — its inode is released once the last handle
  closes; only the dirent removal is unsync. Callers that infer
  state from outbox presence (`recover_signed_journals` around
  reconciler.rs:2778-2793) would retry and re-emit duplicate
  lifecycle events on the retry, because the first pass had
  already moved state forward. The dirent unsync survives normal
  shutdown and the reconciler retries on the next tick if a crash
  truly loses it. Now logs a structured warn and returns Ok.

Not actionable this round:
- **reconciler (medium, deferred):** acked-outbox GC race —
  `recover_signed_journals` removes a session on transient close-tail
  failure; `remove_acked_lifecycle_outboxes` then deletes its acked
  outboxes because `sessions.get(...)` is None; next successful
  recovery re-emits receipt/close with fresh UIDs, producing
  duplicate lifecycle events. Fix requires ordering the
  session-removal and outbox-GC decisions on ONE atomic view; a
  broader refactor than fits round-19.
- **reconciler (low, deferred):** `persist_receipt` /
  `persist_outbox` / `persist_marker` rely on `write_atomic`
  which uses `create_dir_all` (not the round-3
  `create_dir_all_synced`). Cold/missing `receipts/` or `outbox/`
  can be created without ancestor-dir fsync. On a crash before
  the next ambient dirent sync, the file may be reachable only
  after fsck — the receipt itself is still fsync'd by
  write_atomic. Fix: switch these callers to
  `create_dir_all_synced` (av-core/fsutil.rs already exposes it).
  Deferred: needs to verify no perf regression from the extra
  sync on hot paths.
- **identity (0 HIGH):** issuer/audience/JTI checks are all
  operator-configurable but default-permissive. Design intent
  (deployment-flexibility); operator documentation is the
  remedy, not code.

### Bug-hunt round 18: stop_reason over-strict regression fix + MCP Content-Type + compression marker (2026-08-20)

Four fresh deep-dives — code-review of round-17 (caught a
HIGH-severity regression I introduced in the round-17 stop-reason
check), `av-compress` (2 findings; 1 hardening applied),
`av-harness/src/routes.rs` (1 spec-conformance fix; 3 deferred), and
supply-chain (2 RUSTSEC-flagged crates in the tree).

- **events (HIGH, regression fix):** Round-17's
  `StopReasonCaptionMismatch` required
  `StopReason::from_id(id).caption() == stop_reason` whenever the
  id was known — but the `stop_reason` field docstring and the
  builder API `OcsfEventBuilder::stop_reason_native` both document
  the field as carrying the provider's NATIVE finish_reason
  (`"stop"`, `"end_turn"`, `"length"`, `"tool_calls"`,
  `"content_filter"`, `"function_call"`, etc.). The over-strict
  check rejected the vast majority of production events. Round-18
  narrows the check to the specific cross-wiring case: caption is
  ITSELF a canonical caption for a DIFFERENT known variant. `id=93
  (PolicyBlocked)` + `caption="Loop Detected"` (canonical for
  id=91) is flagged; `id=1 + caption="stop"` (OpenAI native) is
  not. Two regression tests added:
  `stop_reason_provider_native_captions_are_accepted` and
  `stop_reason_cross_wired_captions_are_flagged`. **This fix
  ships in the same round because round-17 is not yet released and
  a broken validator would ship with it.**
- **routes (medium, spec conformance):** `/v1/mcp` accepted any
  inbound `Content-Type`. MCP is JSON-RPC 2.0 (spec: MUST be
  `application/json`); a client sending `Content-Type:
  multipart/form-data` with a JSON body would process
  successfully — a spec-violation surface with no defensible use
  case. The handler now rejects any Content-Type that is not
  `application/json` (missing Content-Type is tolerated as some
  minimal clients skip it).
- **compress (medium, marker robustness):** the middle-pass
  compression's idempotency check refused to run if any pre-tail
  message content contained the literal substring `"reason:
  middle history]"` — but a user/assistant message legitimately
  quoting that phrase could silently disable compression. Narrowed
  the check to messages whose content START WITH `"[pruned:"` AND
  contain the marker tail — the actual machine-emitted marker
  shape. This is not the full keyed-marker fix (round-19 F8
  known limitation) but shrinks the spoofing surface from "any
  substring occurrence" to "exact marker shape."

Not actionable this round:
- **supply chain (HIGH, upstream-blocked):** `rsa 0.9.10` has
  **RUSTSEC-2023-0071** (Marvin timing side-channel attack) and no
  patched version exists upstream. Pulled in via `jsonwebtoken
  11.0.0` in `av-identity`. The RSA code path is only exercised
  when a JWKS advertises an RS256/RS384/RS512 key — Ed25519 (EdDSA)
  and HS256 paths do not exercise it. **Deferred: needs upstream
  jsonwebtoken to drop RSA or migrate to a JWT library that lets
  us disable RSA at compile time (e.g., `josekit` with feature
  selection).**
- **supply chain (low):** `paste 1.0.15` (RUSTSEC-2024-0436,
  unmaintained) and `number_prefix 0.4.0` (RUSTSEC-2025-0119,
  unmaintained) enter the tree ONLY when the `onnx` feature is
  enabled on `av-loopdetect`. Neither has a known active
  vulnerability; both are unmaintained-status advisories.
  Deferred until the ONNX toolchain upgrades its dep tree.
- **routes (medium, deferred):** `/dashboard` and
  `/api/v1/dashboard/*` are mounted without route-layer auth when
  `dashboard_enabled=true`. Real for a misconfigured operator but
  the endpoint defaults to disabled. Adding auth is a design
  change (currently no auth infrastructure for dashboard); tracked.
- **routes (medium, deferred):** completion-budget refusal
  produces `200 + broken body` because streaming commits the
  upstream status before the budget check runs. Known design
  tradeoff — SSE requires headers-first; the audit trail
  compensates via `AbortFinalizingStream::Drop`.
- **routes (low, deferred):** on client disconnect, a
  `spawn_blocking` budget task's cancellation is best-effort; a
  small window between disconnect and task abort could still
  debit tokens.
- **compress (medium, deferred):** duplicate/middle passes are
  O(n²) allocation. Known deferred item from round-13.
- **compress (medium, deferred):** duplicate-stub replacement
  drops `name`, `refusal`, and other structural fields from the
  original message. Not structure-lossless. Fix requires
  understanding downstream reader expectations.

### Bug-hunt round 17: cold_uri path escape + event/stop-reason consistency + JCS-safe deserialize guard (2026-08-20)

Four fresh deep-dives — code-review of round-16 (clean, all 10 concerns
verified), `av-events` (2 real findings applied), `av-bridge::cold_store`
+ embedded (1 real path escape + 1 provision-atomicity finding
applied), and `av-loopdetect` (1 false-positive already-guarded, 3 low
severity).

- **bridge (HIGH, path escape):** a local (non-scheme) `cold_uri` was
  used directly as a filesystem root at retention enforcement time
  (`Path::new(cold).join(topic).join(partition)` in embedded.rs). A
  manifest with `cold_uri: "data/../../etc/foo"` would land cold
  objects outside the intended prefix — CWE-22 class. Fixed at
  manifest validation: `BridgeManifest::validate` now refuses any
  `..` component in a non-scheme cold_uri, and both absolute and
  relative shapes are checked. Scheme URIs (`s3://`, `gs://`,
  `file://`) skip the check — they are handled by the cold-store
  feature layer. Regression test:
  `validate_refuses_cold_uri_with_parent_directory_escape`.
- **bridge (medium, provision atomicity):** the `cold-store`
  feature-gate check `reject_cold_uri_without_feature` ran in
  `EmbeddedBroker::open` — AFTER `provision` had already written
  `manifest.yaml`, per-topic dirs, and schema copies to disk. When
  provision-then-open failed here, the operator saw "bridge already
  provisioned" on retry after fixing the manifest, because the
  botched files still sat in `data_dir`. Moved the check to the top
  of `provision` so a rejection leaves `data_dir` untouched and
  retry-clean.
- **events (medium, analytics split):** `validate_event` checked
  that `stop_reason_id` and `stop_reason` were both present or both
  absent, but did not check that they AGREED. An event with
  `stop_reason_id=93` (PolicyBlocked) but `stop_reason="Loop
  Detected"` passed validation, splitting downstream analytics
  between id-groupers and caption-groupers. Now cross-checks that
  `StopReason::from_id(id).caption() == stop_reason` whenever the
  id maps to a known variant. Unknown ids remain forward-compatible
  (round-29 F7's `#[serde(other)]` rationale).
- **events (medium, JCS integer bypass):**
  `OcsfEventBuilder::build` already refused values above
  `av_core::error::JCS_SAFE_MAX` (2^53), but the deserialize path
  (`serde_json::from_slice::<OcsfEvent>`) bypassed the guard. An
  issuer sending `prompt_tokens = 2^53+1` would round-trip through
  JS-based JSON auditors (`JSON.parse`) as a silently-truncated
  value, breaking any receipt hash computed by JS consumers.
  `validate_event` now applies the same JCS-safe check to `time`,
  `metadata.sequence`, and every `EventMetrics` counter — matching
  the builder's coverage.

Not actionable this round:
- **cold-store (medium, deferred):** no bounded retry/backoff on
  persistent cold-store export failure — 403 forever. No DLQ /
  poison-quarantine. Head-of-line blocking in retry queue: one bad
  entry stalls later ones. All three are known deferred design
  items from prior rounds.
- **loopdetect (false positive):** `window == 0` finding — the
  harness's `HarnessConfig::validate` already refuses this at
  config load. A direct crate consumer (not via harness) could
  still hit it, so the finding is a defense-in-depth note; not
  fixed to preserve the crate's minimal invariant surface.
- **loopdetect (low):** short-text (`len < 3`) `HashEmbedder`
  collisions are inherent to the fallback embedder. Real agent
  reasoning does not produce sub-3-char steps. `Qdrant` unbounded
  retention: deferred design item from round-13.

### Bug-hunt round 16: upstream credential-header leak + ATIF strict/schema drift (2026-08-20)

Four fresh deep-dives — code-review of round-15 (clean, all 10 concerns
verified), `av-atif` strict validator (2 real drift findings + several
deferred), `av-harness::pipeline` (1 real API-key leak + 1 slot-pin
DoS), and harness startup ordering (1 signal-handling race + 3 design
items). One production-severity fix applied (upstream credential
header leak).

- **routes (HIGH, credential leak):** `is_forwardable_upstream_header`
  was a denylist that stripped RFC 7235 `Authorization` but no
  provider-custom API-key header names. Every LLM provider uses a
  distinct custom header — `api-key` (Azure), `x-api-key` (Amazon
  Bedrock, Together AI), `x-goog-api-key` (Google), `anthropic-api-key`
  (Anthropic). A malicious or compromised upstream that echoed its
  request's auth header in the response would then leak the operator's
  outbound provider credential straight to the caller. Two-layer
  fix: (a) added every well-known API-key header name to the static
  denylist, AND (b) the filter now takes the runtime
  `upstream_auth_header` string and refuses any header that matches
  it case-insensitively — so operator-picked exotic header names are
  also covered. Regression test extended with all 7 provider names +
  the operator-configured case.
- **atif (medium, strict/schema drift):** `validate_value(Strict)`
  did not type-check three fields that the JSON Schema declares as
  strings — `agent.model_name`, `steps[*].model_name`, and each
  typed field on `SubagentTrajectoryRef` (`trajectory_id`,
  `session_id`, `trajectory_path`). A payload with
  `model_name: 123` passed Strict but failed typed
  deserialization and failed the shipped schema — a validator
  that accepts documents the reader will reject is worse than
  useless. All three now emit `"must be a string"` when
  wrong-typed. `SubagentTrajectoryRef`'s misleading
  `"must set trajectory_id or trajectory_path"` (fired even when
  trajectory_id existed but was the wrong type) is now preceded by
  the actual type-mismatch issue.

Not actionable this round:
- **pipeline (medium, DoS):** no total upstream request lifetime cap
  — only connect_timeout + per-read timeout. A slow-drip upstream
  can hold a `SessionLease` + `ResponsePermit` indefinitely.
  Deferred: needs coordinated design across the streaming state
  machine and the existing `session_idle_close_s` semantics.
- **startup (medium):** shutdown signal handler installed AFTER
  spool recovery. A SIGTERM during recovery is handled by the
  default signal action (kill) rather than the graceful drain
  path. Real but only visible during operator-initiated shutdown
  in the recovery window (typically <1s). Deferred: a proper fix
  needs a cancellable recovery future.
- **atif (low):** no timestamp monotonicity across steps, no
  aggregate consistency (final_metrics = sum of step metrics), no
  cross-step tool_call_id uniqueness. All three are trust-but-verify
  gaps for external ATIF ingestion; the harness's own emissions
  are correct by construction. Deferred to a future
  validator-completeness pass.
- **atif (low):** promotion validates the typed model, not the raw
  wire JSON. Unknown fields / explicit-null-Options / duplicate-key
  ambiguity get lost before strict validation runs. Same class as
  the round-15-F3 receipts fix, but applied at a different layer
  (typed deserialize → validate vs. bytes → strict validate);
  deferred pending a decision on whether promotion should re-hash
  the raw ATIF bytes or the canonicalized re-serialization.

### Bug-hunt round 15: signature malleability + sandbox host-DoS caps + state cleanup observability (2026-08-20)

Four fresh deep-dives — code-review of round-14 (clean), `av-receipts`
(1 high-severity finding), `av-sandbox` (2 host-DoS caps missing), and
`av-state` (silent-failure observability gaps + cluster-mode caller
invariant to document).

- **receipts (HIGH, signature malleability):** `Receipt::from_json_slice`
  accepted `"ttl_remaining_s": null` (and every other
  `Option<T>`-with-`skip_serializing_if="Option::is_none"` field on
  `ReceiptBody` / `AgentIdentity` / `EventMetrics` / …) as a
  synonym for the field being absent. But `Receipt::verify` (and
  `verify_embedded`) re-canonicalises via
  `serde_json::to_value(&self.body)`, which drops `None` again. The
  consequence: a valid signature over TWO byte-different wire
  encodings. An intermediary could toggle `"field": null` on/off in
  the stored bytes without invalidating the signature — a violation
  of the "same signature ⇔ same bytes" auditor invariant that
  underpins receipts. The strict pre-scanner `check_no_duplicate_keys`
  now also refuses explicit JSON `null` anywhere in the payload
  (receipts contain no legitimate JSON null — top level is an
  object, every field is a value-type or omit-on-none). Regression
  test added: `from_json_slice_rejects_explicit_null_option_field`.
- **sandbox (medium, host-DoS):** `StoreLimitsBuilder` set only
  `memory_size(16 MiB)` — no caps on the number of `Memory`
  instances, `Table` instances, table element count, or instance
  count. A hostile policy could:
  - declare many `(memory ...)` sections and reach thousands of
    16 MiB allocations before fuel/epoch meaningfully activates,
  - `table.grow` a table by millions of function-reference slots
    (each `Option<Func>` ≈ 16 bytes on 64-bit), forcing a huge
    host allocation on the growth step, or
  - declare many tables per module to multiply the above.
  Fuel and epoch protect only runtime-bounded exploits; allocation
  pressure lands at instantiation or on a single `memory.grow` /
  `table.grow` instruction. Added: `memories(1)`, `tables(4)`,
  `table_elements(65_536)`, `instances(4)`.
- **state (medium, observability):** round-10 added a `tracing::warn!`
  on silent `refund` failures. The parallel silent-failure paths in
  `RedisStore::remove` and both `scan_and_delete_single` /
  `scan_and_delete_cluster` (SCAN failure + DEL failure) had no
  telemetry — an operator watching `av_state::redis::warn` for
  cleanup issues saw nothing when Redis slowdowns or connection-pool
  exhaustion left stale counters behind. All four paths now emit
  structured warns naming the operation, error kind, batch size
  (where applicable), and consequence (24 h TTL survival + recycled-
  session inheritance risk).
- **state (low, doc-only):** documented the caller-side invariant
  that `remove_prefix` in Redis Cluster mode routes to ONE hash
  slot derived from the prefix, so callers MUST include a Redis
  Cluster hash tag (`{...}`) in the prefix or their non-tagged
  keys will silently persist in other slots. `ActionBudget::session_prefix`
  is already tagged, so this is not a live bug — but a future caller
  adding a non-tagged prefix would silently regress.

### Bug-hunt round 14: doctor drift + CLI terminal-injection surface (2026-08-20)

Four fresh deep-dives — code-review of round-13's loop-breaker fix (clean),
`av-core/` primitives (metrics wrap-on-overflow is theoretical only,
no other findings), `av-harness::journal` sealed-envelope primitive
(clean — HMAC-SHA256, domain-separated with length prefixes, MAC-first
verify, 128-byte cap, unique domain strings, unique outbox kinds), and
`av-cli` operator surface (four real findings).

- **cli (medium, doctor false-negative):** `avctl doctor`'s
  `upstream_api_key_file` check called only `std::fs::metadata` and
  reported PASS on files the harness itself would refuse at startup —
  a symlink, a mode-0644 file, or an empty file all snuck past
  doctor and then failed `avctl start` with a stale-cache-looking
  error. Doctor now mirrors
  `av_harness::pipeline::require_owner_only_secret` posture exactly:
  symlink refusal, regular-file, `mode & 0o077 == 0` on Unix, and
  non-empty content.
- **cli (medium, doctor path drift + no content check):** the
  signing-seed check probed `AV_SIGNING_SEED_FILE || config/signing.seed`,
  but `avctl start` overrides that env var to
  `<user_config_dir>/signing.seed` when the resolved config is at
  `av_harness::config::user_config_path()`. So on a stock
  `~/.agentvisor/agentvisor.toml` deployment, doctor probed a
  never-touched `config/signing.seed` and reported "will be
  generated on first run" while the real seed sat elsewhere. Doctor
  now computes the same path start would use. It also validates
  seed content the way `av_harness::main::read_signer` will —
  hex-decoded, exactly 32 bytes, and not a known-weak seed (all-0
  or all-0xFF) — so a truncated or textbook-wrong seed no longer
  passes doctor.
- **cli (medium, doctor false-positive):** the endpoint TCP probe
  rejected two config forms `HarnessConfig::validate` accepts as
  valid: Redis `unix:` (UDS socket, no host:port) and Kafka
  bootstrap lists (`k1:9092,k2:9092,...`). Both would produce
  spurious "unreachable" doctor failures with correct configs.
  `probe_endpoint_any` now stat-probes the UDS path for `unix:`
  and treats a comma-separated bootstrap list as reachable if any
  single member is reachable (which matches the runtime — Kafka
  only needs one contactable bootstrap).
- **cli (low, terminal-control injection):** `manifest_validate`
  and `bridge_provision` printed `manifest.name` verbatim to stdout;
  `av-bridge::manifest::validate` only refuses YAML anchor markers
  (`&`/`*`) and does not restrict control bytes in `name`. A crafted
  manifest with ANSI CSI in the name field could reprogram the
  operator's terminal (same CVE-2003-0063 class as receipts and
  ATIF issues fixed in round-28 F3). Both prints now flow through
  `sanitize_for_terminal`.

Not actionable this round:
- **`av-core::metrics` u64 wrap-on-overflow** — real in theory
  (`Counter::add(u64::MAX); .inc()` wraps to 0), unreachable in
  practice: sane microsecond durations and request rates would take
  ~585,000 years to reach 2^64, and every callsite passes constants
  or clock deltas from `Instant::elapsed().as_micros()`. Prometheus
  rate math already handles counter resets. Deferred as a
  hardening item, not a bug.

### Bug-hunt round 13: fix false loop-breaker trips on tool-only responses; three 0-actionable deep-dives (2026-08-20)

Four fresh line-by-line deep-dives — a code-review of the round-12
identity + CI cleanup commits (came back clean; workspace builds
verified), and audits of `av-atif/`, `av-events/`, and
`av-loopdetect/` + `av-compress/`. One real production bug found in
loop detection; the other three deep-dives surfaced either
false-positives or defensible-by-design behaviors.

- **harness (high, correctness):** `AbortFinalizingStream::submit_response_capture`
  computed `analysis_text = reasoning || response_message` and always
  passed `analyze_loop: true`. For tool-call-only responses (a
  legitimate agent mode — "return only `tool_calls`, no assistant
  text"), both are empty. `av_loopdetect::embed` collapses empty
  input to a zero-vector embedding; the breaker at `breaker.rs:174-179`
  treats non-finite/all-zero embeddings as hostile duplicates
  (`delta = 0`), so every tool-only turn grew the loop streak until
  `min_tokens` was met and the breaker tripped — silently blocking
  healthy tool-driven agents as "looping". `analysis_text` now falls
  back to synthesizing `"tool_name(arguments)"` for each of the
  response's tool calls, and `analyze_loop` is skipped entirely when
  every input is empty.

Not actionable this round:
- **ATIF strict-validator type-check gaps** on `agent.model_name`,
  `step.model_name`, `subagent_trajectory_ref` typed members —
  real for third-party ATIF ingestion, low impact for the harness's
  own emissions (which are typed at construction). Full typed check
  deferred as a validator-completeness pass.
- **Loop-detect Qdrant cross-session vector contamination** —
  `vector_sink` searches by `session_id` only; recycled session ids
  inherit old vectors. Real but production-Qdrant only; needs
  vector-time TTL or session-close cleanup.
- **Compression O(n²) work** in the duplicate and middle passes on
  large payloads (up to `max_request_bytes = 4 MiB`). Bounded but
  noticeable; refactor to O(n) via HashSet + one-shot payload walk
  deferred.

False positives:
- **OCSF class/type_uid linkage** — the deep-dive claimed
  `validate_event` isn't called on the publish path, so linkage
  could break. But `OcsfEventBuilder::build()` derives
  `type_uid = class_uid × 100 + activity_id` (model.rs:408), so the
  linkage is enforced by construction. The harness has no path that
  bypasses the builder.

### Bug-hunt round 12: two identity fixes + round-11 doc fix; one 0-finding-actionable deep-dive (2026-08-20)

Four fresh line-by-line deep-dives this round — a code-review of round
11's Ed25519 malleability fix (caught one low-sev doc reference to a
non-existent function), and exhaustive audits of `av-identity/`,
`av-sandbox/`, and `av-receipts::jcs`. Two real functional bugs found
in identity; sandbox and JCS both surfaced only defensible-by-design
behaviors.

- **identity (medium):** the delegation-chain scope-subset check at
  `validator.rs:348-352` used exact string equality, but the runtime
  authorization check `pipeline::scope_allows` (harness) uses wildcard
  semantics (`*`, `prefix:*`). A legitimately-delegated narrower child
  scope (parent `["tool:*"]`, child `["tool:db_write"]`) was rejected
  as `ScopeEscalation("tool:db_write")` even though the runtime gate
  would authorize it — so the delegation gate was strictly stricter
  than the authorization gate, making wildcard-parent tokens
  effectively unusable for narrowing delegation (their canonical use
  case). Now uses the same wildcard-aware `scope_covered_by`.
- **identity (low):** JWKS `x` field (Ed25519 pubkey material) was
  only checked for non-empty at `add_jwks` time. A malformed
  base64url `x` or a wrong-length key installed silently; every JWT
  with that `kid` then failed at verify time with a confusing "bad
  JWK for kid" message — while the operator saw no signal at boot.
  Now base64url-decoded and length-checked (must be exactly 32
  bytes) during `add_jwks`, so config errors surface at boot/JWKS
  refresh.
- **receipts (docs, round-11 self-audit correction):** the round-11
  `from_seed` caveat comment referenced
  `av-harness::main::load_signer_from_file`, which doesn't exist —
  the actual production caller is `av-harness::main::read_signer`.
  A future maintainer greping for the referenced symbol would find
  nothing and might not identify the correct site to preserve the
  weak-seed pre-validation. Doc reference corrected.

Not actionable (defensible-by-design):
- **Sandbox policy/budget config-key case mismatch:** operator-error
  class where deny-list `["DB_WRITE"]` misses lowercase-only tool
  requests. Real UX issue but not a security bypass; needs
  normalization design decision. Deferred.
- **JCS finite-number rejection above 2^53 and 128-depth cap:** both
  are defensive additions stricter than RFC 8785. The receipts this
  crate generates never contain such values by construction (bounded
  by `JCS_SAFE_MAX`), so this only affects interop with external
  peers producing receipts we would need to verify — not a current
  target use case.

### Bug-hunt round 11: Ed25519 signature malleability fixed; three 0-finding-actionable audits (2026-08-20)

Four fresh lenses this round — a code-review of round 10's own commit
(came back clean, 3rd consecutive), a protocol-spec compliance audit
(6 findings, most either interop-only or defensible), a receipts
deep-dive line-by-line (found one critical signature malleability),
and a combined-failures audit (4 findings, most deferred as design work).

- **receipts (high, cryptographic):** `Keyring::verify` used
  ed25519-dalek's non-strict `verify` API, which accepts signatures
  whose R component OR the verifying key itself is a small-order
  Curve25519 point. In that regime a SINGLE signature can validate
  against MULTIPLE distinct canonical bodies — an attacker who could
  register a small-order pubkey (via any downstream path that admits
  external verification keys) could mutate receipt bodies while
  keeping the signature intact, and `verify_embedded()` would still
  return `Ok(())`. Now uses `verify_strict` (ed25519-dalek
  verifying.rs:367-390 in 3.0.0), which rejects small-order R and
  small-order pubkeys. Documented Ed25519 signature-malleability class
  fix.
- **receipts (docs, defense-in-depth):** `Ed25519Signer::from_seed`
  does not reject the all-zero or all-0xFF seeds. Production seed
  loading in `av-harness::main::load_signer_from_file` already
  refuses both before reaching this function, but a future refactor
  could silently drop that pre-validation. The contract is now
  documented in-signature so the caveat cannot be forgotten.

Deferred to design cycle (real but need bigger changes):
- **NATS retry HOL blocking:** one bad cold-outbox intent's
  `find_event_by_uid` transient error aborts the whole retry pass;
  later intents accumulate. Bounded by TTL; needs a per-intent
  backoff + skip-and-continue policy (feeds into the DoS-audit
  cold-outbox backoff+DLQ item from round 8).
- **Signer rotation + in-flight promotion:** an unsigned session
  mid-promotion whose old on-disk receipt was signed by a
  now-rotated key can livelock — retries keep hitting the same
  wrong-key error. Needs a multi-key verification ring or an
  on-rotation receipt-migration pass.

Not actionable (defensible-by-design):
- **JSON-RPC notification MUST-NOT-reply:** the harness rejects
  notifications with an error response. Compliance would allow
  fire-and-forget tool calls to drain budget without observable
  responses — refuse-with-error is more secure.
- **Bridge down + Redis refund correlation:** round 10's
  observability fix now surfaces the Redis-refund failure; the
  capture-failed side is already observable via
  `av_events_dropped_total{stage=response_slot}`.
- **Disk-full close-complete marker fallback:** documented behavior
  in CloseCompleteMarker (round 4 explicitly acknowledged the
  at-most-one duplicate-per-restart trade-off).

### Bug-hunt round 10: one observability fix + one test-quality doc + two 0-finding audits (2026-08-20)

Four fresh lenses this round — a code-review of round 9's own commit
(came back clean — 2nd consecutive clean self-audit), a graceful-
shutdown audit (found only the by-design 30s hard drain deadline),
a test-integrity deep-dive on round-N regression tests (4 findings,
1 addressed), and an observability completeness audit (one silent-
failure gap, fixed).

- **state (medium, observability):** `RedisStore::refund` swallowed
  every Redis error silently (best-effort by trait contract), so an
  operator seeing budget depletion during a Redis outage had NO
  signal that per-key compensation had been failing — logs still
  said "refunding budget" without indicating the refund never
  landed. Now emits a `tracing::warn!` with structured error fields
  (`error.kind`, `error.detail`, target `av_state::redis`) on every
  refund failure. The response path stays 200 OK so the caller
  never learns compensation failure as a 5xx (preserving the
  best-effort contract).
- **tests (docs):** the round-41 F1 regression test
  (`round_41_f1_corrupt_signed_sidecar_does_not_block_other_signed_recovery`)
  was flagged as unable to catch a regression that skips ALL
  signed sessions rather than just the poisoned one. A meaningful
  strengthening would need a healthy signed session fixture — but
  the live `close_session` path fully removes the journal on
  success, so recovery has nothing to re-adopt. Attempting to add
  a healthy neighbor legitimately failed at the assertion, so the
  test now documents the limitation inline and holds the outer
  `Ok(())` invariant (the round-41 F1 fix's exact regression
  target).

Investigated with no code change needed:
- **Graceful-shutdown audit:** the 30 s hard drain deadline can
  cut off long-running requests on SIGTERM; that trade-off is
  intentional (K8s rolling updates require a bounded stop, longer
  deadlines would exceed pod-termination timeouts). Documented in
  `main.rs:159-163` already.
- **Test-integrity audit:** two timing-based tests
  (`routes.rs:4407`, `worker.rs:1567`) use `sleep(10ms)` without
  a barrier that the slow path has actually entered — brittle but
  hard to fix generically without introducing test-only APIs on the
  code under test. Deferred.
- **Dashboard receipt visibility test** (`dashboard.rs:666`) uses
  `restore_receipt` directly rather than going through recovery;
  this test's stated purpose is dashboard serialization, not
  recovery, so the shortcut is defensible.

### Bug-hunt round 9: three fixes + one deferred design item; one 0-finding audit (2026-08-20)

Four fresh lenses this round — a code-review of round 8's own commit
(came back clean), a realistic end-to-end scenario audit (found one
dual-harness misconfiguration scenario, deferred), an error-handling
audit (three findings, all fixed), and an input-validation
completeness audit (one gap, fixed).

- **harness (medium, input validation):** `read_broker_ack` at
  `worker.rs:1329` used unbounded `tokio::fs::read` before feeding
  bytes to `journal::open`. A local fs-tamper plant of a
  hundreds-of-MB file at `spool/broker-acks/<hash>/<hash>.json`
  would blow up memory during finalize/recovery before MAC
  rejection. Now capped at `MAX_CONTROL_BYTES` (1 MiB) via
  `av_core::fsutil::read_capped` — matches the policy every other
  sealed marker in the spool uses (close-complete, promotion,
  response, ATIF sidecar).
- **harness (medium, error classification):** `ToolExecution::claim`
  mapped every failure — genuine race (`create_new` →
  `AlreadyExists`) and infrastructure faults alike (StorageFull,
  PermissionDenied, ReadOnlyFilesystem) — to the same `String`
  error, and `mcp_call_inner` answered every one with `409
  TOOL_OUTCOME_UNCERTAIN`. Real disk faults were reported to
  clients as if they had lost a concurrent race, so retries looped
  on the underlying infra problem while the client learned nothing
  useful. Split into a `ClaimError { Race, Backend }` enum; the
  caller now answers 409 only for Race and 503 with a fresh budget
  refund for Backend.
- **harness (medium, error consistency):** `release_unexecuted` (the
  connect-failure release path for tool intents) returned Err on any
  post-remove directory-fsync failure. `mcp_call_inner`'s
  connect-failure branch then skipped the budget refund, leaving
  the key unclaimed on disk AND the budget debited — the exact
  budget-stuck state the release-then-refund ordering was designed
  to prevent. Now treats "remove_file succeeded but dir fsync
  failed" as still-released (with a warn); a crash before fsync
  makes the intent resurrect on recovery, at which point
  `unresolved_tool_sessions` correctly quarantines the session
  fail-closed.

Deferred to design cycle:
- **e2e scenario audit — dual-harness misconfiguration:** two
  harness instances running against the same spool independently
  finalize the same recovered session, publishing duplicate
  `RECEIPT_ISSUED` / `SESSION_CLOSE` events with distinct UIDs
  that bypass every dedup path. Needs a spool-root lockfile at
  startup (fcntl F_SETLK). Operational-safety feature, not a
  bug fix — deferred.

### Bug-hunt round 8: monotonic idle clock, comment correction, two audits with actionable follow-up items (2026-08-20)

Four fresh lenses this round — a code-review of round 7's own commit
(caught false claims in my atomic-ordering comment — the lifecycle
mutex already serialized the writer and reader), a time/clock audit
(one real production bug: wall-clock used as monotonic for idle
tracking), a DoS-via-legitimate-operations audit (11 findings across
critical/high/medium, most requiring design changes), and a
version-compatibility audit (7 findings, mostly fail-safe-by-design
behaviors + one doc-vs-code drift on signer rotation).

- **harness (high, clock correctness):** `SessionRegistry`'s
  `idle_sessions` and `evict_finalized` used wall-clock
  `last_activity_ms` for idle decisions. A forward wall-clock jump
  (VM resume from a long pause, NTP correction) could make every
  active session look premature-idle and close them mid-conversation.
  `Session` now carries a parallel `Mutex<Instant>` for monotonic
  last-activity tracking; the wall clock is retained only for
  dashboard display. Test suite migrated to a new
  `set_idle_for_testing` helper that ages both anchors atomically.
- **harness (docs, round-7 self-audit correction):** the round-7
  atomic-ordering "fix" comment and CHANGELOG entry claimed that
  `restore_receipt` runs outside the per-session lifecycle mutex and
  that `retry_marked_promotions` races `recover_spooled_sessions` —
  both false. `restore_receipt` is only called from
  `recover_spooled_sessions` inside the `acquire_lifecycle` guard
  block (`reconciler.rs:1126`), and both main.rs and the reconciler
  tick await recovery to completion before invoking
  `retry_marked_promotions`. The reordering itself remains as
  preemptive hardening against a future refactor that could shrink
  the lifecycle-lock scope; the comment now describes it as such
  rather than as a fix for an observable bug.

Deferred to future work — audit findings captured but not yet
addressed:
- **DoS audit (11 findings):** session registry admission cap;
  tool-execution spool per-session cap + TTL; cold-outbox
  retry-count + exponential-backoff + dead-letter directory;
  dashboard `/api/v1/dashboard/*` auth or caching + change of
  `dashboard_enabled` default; distinct `response_capacity` config
  knob; HTTP 503 with `Retry-After` on `SubmitError::Full`;
  per-session journal size cap. Each requires a real design
  decision beyond a mechanical bug fix.
- **Version-compat audit (7 findings):** signer rotation doc-vs-code
  drift in EVOLUTION.md (recovery uses only the configured signer,
  so old receipts fail verify after rotation) — will address as a
  documentation update. Other findings (ReceiptSubject and manifest
  strict-parse-on-unknown-variant, StoredEvent breaking changes on
  Kafka/NATS) are fail-safe-by-design and acceptable.

### Bug-hunt round 7: two fixes, two 0-finding audits (2026-08-20)

Four fresh lenses this round — a code-review of round 6's own commit
(caught a real gap I introduced), an atomic-memory-ordering audit on
weakly-ordered architectures (found one visibility bug), a config-
boundary audit (0 findings — every numeric field bounded, every URL
scheme allowlisted, every auth-mode combination checked), and a
serialization roundtrip audit (0 findings — receipt custom-Deserialize
duplicate-key check at every depth, JCS rejects ±2⁵³ on all three
number paths, OCSF flatten collision-free by construction).

- **harness (medium):** the round-6 metrics HELP unification for
  `av_dashboard_requests_total` missed the actual firing site at
  `dashboard.rs:51`, which still passed the old `"Dashboard endpoint
  requests"` HELP. Masked today because `AppState::new` pre-registers
  every `{endpoint,status}` combination in `pipeline.rs`, but a future
  endpoint or status that sorted earlier lexicographically would win
  the family HELP with the stale string — the exact first-wins
  fragility round 6 was meant to eliminate. Fixed to the unified
  `"Dashboard endpoint requests, labeled by status"`.
- **harness (medium):** `promote()` read `session.receipt` under the
  parking_lot mutex BEFORE checking `session.is_promoted()`. On
  AArch64 (weakly-ordered), a concurrent `restore_receipt` (called
  from `recover_spooled_sessions` for freshly-inserted sessions,
  outside the per-session lifecycle mutex; `retry_marked_promotions`
  runs on the same registry with no shared lock) could write the
  receipt and `finish_promotion` after this thread's mutex-read of
  `receipt = None` but before its `is_promoted()` load — the Acquire
  on `is_promoted` synchronizes-with the writer's Release-store, so
  we'd see `promoted = 2` while holding a stale `None` receipt read.
  Result: a spurious `"promoted session has no persisted receipt"`
  error that self-healed on the next reconciler tick but polluted
  the promotion-retry error signal with a false positive. Fixed by
  checking `is_promoted()` FIRST so any subsequent mutex lock
  observes writes released before the Release-store.

### Bug-hunt round 6: three metrics fixes; three 0-finding audits (2026-08-20)

Four fresh lenses this round — a code-review of round 5's own commit
(came back clean, 2nd clean self-audit in a row), an exhaustive panic-
reachability trace from every attacker-controlled ingress (0 findings —
`SessionId::parse` / `read_capped` / `is_char_boundary` backoff cover
every panic-capable op), a resource-leak audit under adversarial load
(0 findings — every allocation site cited a release path or a
design-documented retention), and a metrics-accuracy audit. Three fixes:

- **harness (low, observability):** `av_dashboard_requests_total`
  registered `status="ok"` with HELP "requests served" and
  `status="not_found"` with HELP "requests that could not be served".
  Prometheus renders one HELP per family/base name, so whichever
  label registered first became the family's HELP — operators reading
  the family as failures-only misdiagnosed healthy traffic spikes.
  Both variants now share a stage-agnostic HELP.
- **harness (low, observability):** same pattern in
  `av_events_dropped_total`: `worker_queue` and `worker_closed`
  registered "Worker jobs dropped", `response_slot` registered
  "Response-slot reservations that failed". Whichever stage
  registered first won the family HELP. All four firing sites now
  share a HELP that names every stage.
- **harness (medium, observability):** `av_receipt_sign_duration_seconds`
  was observed only in `close_session_locked` (signed close path);
  the `promote()` receipt path called `Receipt::issue` without an
  observation, so retroactive-promotion signing latency regressions
  were invisible while the metric stayed flat. Now observed in both
  paths.

### Bug-hunt round 5: NATS retry parity, doc drift, and known-limitation docs (2026-08-20)

Four fresh lenses this round — a code-review of round 4's own commit
(came back clean — first no-findings self-audit in the streak), a
dedicated security-review (0 findings; every attack surface carries its
specific hardening), an idempotency audit tracing every retry path, and
a documentation-vs-code drift audit. Two production fixes plus one
known-limitation doc:

- **bridge (medium):** `NatsBus::maintenance` blindly re-published
  pending cold-store intents whose `offset` was `None` (crash between
  publish and commit), relying on the `Nats-Msg-Id` dedupe window
  bounded by `retention` — a retry landing after retention expiry (or
  after a stream reset) escaped dedupe and duplicated the event on the
  audit stream. Kafka's `maintenance` already consulted
  `find_event_by_uid` before re-producing (round-1 F2 established the
  paged NATS lookup); NATS now uses the same guard.
- **docs (medium):** `ARCHITECTURE.md` claimed "Chat and MCP effects
  wait until their request or authorization event is journaled and
  published" — but `mcp_call` uses `intercept_tool_nonblocking` (which
  explicitly does NOT wait for broker publish), and chat gates run
  inline unless a token budget is configured. Reality: durability
  comes from the local response-marker / tool-intent files (which the
  reconciler reasons about on crash recovery); OCSF broker publish is
  fire-and-forget on the worker pool. Doc rewritten to state what
  the code actually delivers.
- **state (known-limitation doc):** Redis `try_spend_many` / `add`
  are atomic Lua scripts server-side, but a connection drop between
  the server's INCRBY commit and the client's response read makes the
  outcome ambiguous — a client retry with the same intent overcharges
  the budget by the retry amount. Documented in `RedisStore`'s
  docstring: 24 h counter TTL bounds unbounded growth and
  `refund_tool_call` covers common cases; strict idempotency would
  need a client-supplied request nonce and is deferred as a design
  change.

### Bug-hunt round 4: three fixes across cluster routing, tool-execution replay, and a filesystem re-scan bug (2026-08-20)

Four fresh lenses this round — code-review of round-3's own commit,
filesystem atomicity across every rename+fsync site, an exhaustive
state-machine enumeration, and audit-trail integrity. Three production
fixes and one deferred (documented) finding:

- **state (high, round-3 self-audit regression):** the round-3
  `remove_prefix` cluster branch used `Commands::scan_match` on the
  sync `ClusterConnection`, but bare `SCAN` has no key argument —
  `RoutingInfo::for_routable` returns `None`, `ClusterConnection::
  request` treats that as `UNROUTABLE_ERROR`, and cluster cleanup
  silently deleted nothing (round-2's Lua+`KEYS` routed via `EVAL`
  had actually worked; round-3 broke it). Now uses `route_command`
  with an explicit `RoutingInfo::SingleNode(SpecificNode(...))`
  routed to the slot the prefix's hash-tag pins every match to. TTL
  still bounds counter growth, but immediate cleanup is restored.
- **harness (medium, audit-integrity):** the audit-integrity audit
  found that `mcp_call_inner`'s tool-execution key = `sha256(
  "{session_id}:{jsonrpc_id}")` was silently reused across session
  recycling. A client reusing `(session_id, jsonrpc_id, body,
  identity)` after close hit `Completed` fast-path and got the prior
  incarnation's cached response with NO new audit event on the
  recycled session's chain — an audit gap. The close tail now runs
  `remove_tool_executions(session_id)` to drop the on-disk
  intent/outcome/audited files; the underlying tool-completed audit
  event is already durably on the bridge before this cleanup, so
  the files are pure idempotency markers and safe to drop.
- **harness (high, fs-atomicity):** `archive_conflicting_atif`
  renamed a colliding `.promote` marker to
  `{stem}.archived-{suffix}.promote` — whose `Path::extension()`
  still evaluates to `"promote"`, so it re-entered
  `retry_marked_promotions`' scan filter, MAC-verified against the
  unchanged bytes, looked up the recycled session's live entry, and
  triggered an unrequested promotion (minting a receipt and
  emitting a receipt event no operator asked for). The archived
  marker also stayed on disk forever, re-firing every tick. Now
  renamed to `{stem}.archived-{suffix}.promote-archived`, outside
  the scan filter — mirrors the round-1 fix that excluded `.` from
  the ATIF suffix for the same reason (`.json` re-scan).

### Bug-hunt round 3: fixes across parsers, numerics, wiring, and a round-2 self-audit (2026-08-20)

Four fresh lenses — a code-review agent auditing my own round-2 commit,
a parser adversarial audit (GPT-5.3-Codex), numerics and unit-suffix
audit, and a startup/wiring audit. Seven production fixes:

- **round-2 self-audit (high):** `ResponseCaptureGuard` was declared
  AFTER `SessionLease` in `PreparedRequest` / `ForwardedResponse`, so a
  cancelled request future dropped the lease first — releasing the
  close barrier's `wait_for_streams` notify — before the guard could
  register its terminal job. The close's `pending_jobs == 0` load could
  win the race, finalize proceeded, and the guard's job landed after
  the receipt was sealed (chain/receipt divergence for signed;
  resurrected step journal for unsigned). Field order corrected so the
  guard drops first, matching the invariant `AbortFinalizingStream`
  already documents.
- **round-2 self-audit (medium):** `abandon_prepared` defused the guard
  BEFORE the fallible `permit.submit`, and ignored the result — the
  submit-full safety net that every sibling path uses to fail the
  session closed was unreachable. Reordered: defuse only on success,
  fall through to `mark_capture_failed` on failure.
- **state (medium):** the round-2 Redis `remove_prefix` used
  `redis.call('KEYS', pattern)` inside Lua — O(entire keyspace) AND
  blocking the Redis event loop atomically for every session close.
  Replaced with cursor-based SCAN outside Lua (bounded per-call,
  yields between batches). Cluster mode uses `Commands::scan_match`.
- **sandbox (medium):** `parse_tool_call` accepted the JSON parser's
  implementation-defined last-wins pick on duplicate keys. The raw
  body is forwarded unchanged to the tool upstream — a first-wins
  decoder there produces a permissions-model split (harness attests
  one tool, upstream executes another). A streaming visitor now
  rejects any duplicate key anywhere in the payload before the parse
  succeeds. Existing differential test tightened to enforce it.
- **harness (medium):** ATIF recovery re-parsed and re-strict-validated
  provenance-failing files every reconciler tick forever (a strict-
  valid attacker-planted trajectory paired with a bogus-MAC sidecar
  burns O(N × file_size) CPU per tick with `warn_once` only bounding
  logs). Now quarantines after `MIN_ORPHAN_AGE` (the same guard the
  sidecar-less branch uses to avoid corrupting in-flight closes).
- **harness (medium):** authoritative provider usage frames used
  `max(current, reported)` to update `completion_tokens` — a chunk-
  estimate accumulated before the first usage frame could exceed the
  true count and get attested in the signed receipt / ATIF / session
  totals. Authoritative frames now override; the regression check
  above already guarantees monotonicity across authoritative frames.
- **bridge (medium):** a manifest with a scheme-URI `cold_uri` in a
  `--no-default-features` (no `cold-store`) build accepted the value
  at boot and failed on the first retention tick (up to `hot_hours`
  = 168 h later); the `?`-propagation halted retention for every
  topic ordered after it. Boot-time refusal matches the fail-fast
  policy of every other feature-gated backend.
- **cli (low):** `avctl init`'s generated `atif_spool_dir` /
  `bridge_data_dir` defaults now match the harness's `default_spool`
  / `default_bridge`, so removing an explicit key from the generated
  config does not silently relocate the spool.

### Bug-hunt round 2: cancellation safety, backend parity, and a round-1 correction (2026-08-20)

A second sweep with fresh lenses — cancellation safety (axum drops
request futures on client disconnect; the codebase modeled crashes and
explicit errors meticulously but never modeled cancellation), cross-crate
contract seams, an adversarial review of round 1's own commit, and a
tests-that-cannot-fail audit. Six production fixes, three test fixes:

- **harness (high):** dropping an in-flight `/v1/chat/completions`
  request future stranded the durable response marker and left a
  dangling non-terminal response attempt in the signed journal — the
  session later closed "cleanly" over an unresolved capture, then its
  id was re-quarantined every reconciler tick after eviction. A new
  `ResponseCaptureGuard` (RAII, armed at admission, handed from
  `PreparedRequest` → `ForwardedResponse` → `AbortFinalizingStream`)
  submits the same terminal failure job every explicit refusal path
  uses. Consequence: every admitted attempt now resolves, so a
  prepared-then-dropped request contributes two chain events —
  integration tests updated accordingly.
- **harness (high):** a client disconnect during `/promote` left the
  promotion claim permanently at "in progress" (every retry 409'd until
  restart). `PromotionClaim` now mirrors `CloseClaim`: reset on drop
  unless committed.
- **harness (medium):** a client disconnect inside `/mcp` stranded a
  claimed-but-unresolved execution key (every retry answered 409
  TOOL_OUTCOME_UNCERTAIN while the session lived) and burned the
  debited budget. The whole tool path now runs on a spawned task that
  completes regardless of the caller's fate.
- **state (medium):** `RedisStore` never implemented `remove_prefix`
  (silent trait-default no-op), so a recycled session id inherited the
  prior incarnation's budget counters for up to 24 h in production
  while dev/CI (in-memory) started fresh. Implemented via a Lua
  script routed by the hash-tagged prefix (cluster-safe: all of a
  session's keys share one slot by construction).
- **harness (medium, round-1 correction):** for ATIF-adopted sessions
  whose close-complete marker verifies, the SESSION_CLOSE already
  consumed sequence `steps.len()`; recovery now advances past it so a
  retroactive receipt cannot collide with the published close.
- **tests:** `partition_assignment_is_stable` compared a value to
  itself (pinned FNV-1a literals now anchor the hash); the budget
  model's over-refund terminal check asserted nothing (now checked
  against the reference model); two `?`-style manual error arms in
  `promote()` simplified.

### Full-codebase bug hunt: eight fixes across bridge, harness, and dashboard (2026-08-20)

A four-agent parallel sweep of all twelve crates (~58k lines) after the
round-42 close. Eight verified findings, all fixed:

- **embedded bus (high):** a failure after retention's hot-segment
  rename (directory sync, sidecar rewrite, or writer reopen) left the
  append handle on the unlinked pre-rewrite inode without poisoning the
  partition — every subsequent publish was acked as durable but written
  to freed disk. Post-rename failures now poison the partition
  (fail-closed until restart), matching the append-truncation posture.
- **Kafka bus (medium-high):** `find_event_by_uid` ran the whole
  earliest→latest scan inside one 10 s executor window, so lookups on
  large partitions timed out on every attempt forever — blocking cold
  intent draining and crash-recovery UID lookups. Now pages one fetch
  per executor call, the shape the NATS implementation already
  documented as required.
- **embedded bus (medium):** `fetch` hard-errored on the first
  unparseable segment line while retention keeps such lines forever and
  recovery deliberately tolerates them — one corrupt line bricked the
  read side permanently while publishes kept acking. `fetch` now skips
  the line with a warning, consistent with `recover_segment`.
- **harness (medium):** ATIF-adopted unsigned sessions never restored
  their event sequence (both sibling recovery paths do), so a
  post-crash SESSION_CLOSE or retroactive-receipt event was minted with
  `metadata.sequence = 0`, colliding with step event 0 already on the
  bridge. `Session::recover_unsigned` now takes and restores the
  published-event count.
- **bridge (low-medium):** cold exports and the cold outbox fsynced
  only the leaf directory; newly created ancestor dirents were
  volatile, so a power loss after the hot rewrite could drop the only
  remaining copy. New `fsutil::create_dir_all_synced` syncs the parent
  of every directory it creates.
- **harness (low):** `archive_conflicting_atif` admitted `'.'` in the
  untrusted archived-name suffix, so a planted `trajectory_id` ending
  in `.json` produced an archive the recovery scan re-adopts and then
  quarantines, splitting the archived evidence pair. Dots are now
  stripped.
- **dashboard (low):** the footer linked `/dashboard/api/help`, which
  no route serves (404); the link is removed. `fmtAge` rounded past
  its unit boundary ("60m ago", "24h ago"); it now floors.

### Review round 42: the audit catches its own round-38 artifact (2026-08-16)

The fourth model's final src tranche (events, loopdetect, compress,
all lib.rs docs — 100 % fourth-model src coverage). One finding, the
program's most instructive: a comment introduced BY this session's
round-38 fixes claimed `OcsfEvent`'s field is "`#[non_exhaustive]` and
constructable directly" — the struct carries no such attribute, and
the attribute would prevent precisely the construction described. An
earlier reviewer had adjudicated the phrasing as acceptable; the
fourth model correctly overturned that. Both sites now state the true
mechanism (all-pub fields on a non-`non_exhaustive` struct bypass the
builder). Every pairing claim in the tranche chased to its partner,
including the twice-relied-on all-zero ONNX error fallback and the
proptest-backed "property-tested" claim.

### Review round 41: phantom proof made real; serde_json claim disproven (2026-08-16)

The fourth model's security-remainder tranche (21 files, ~5,900 lines;
sixteen fully clean including av-core's primitive set minus fsutil and
the full ATIF validator). The standout: wasm_policy's memory-bomb test
accepted `Allow` citing a follow-up write-at-grown-address
verification that did not exist — it exists now
(`memory_grow_past_cap_leaves_grown_region_inaccessible`: grow 4096
pages, store at 32 MiB past the 16 MiB cap, StoreLimits refuses, the
store faults, evaluation fails closed) and passes. Also: writer.rs's
"serde_json refuses to serialize non-finite floats" was empirically
false (`to_string(NAN) == Ok("null")` — it silently nulls them, which
is exactly why the writer's rejection guard matters); fsutil justified
a missing counter with an impossible dependency cycle (fsutil IS an
av-core module — the real constraint is the instance-scoped Registry);
keys.rs called a 128-bit id "128-bit collision resistance"
(~2^64 birthday bound, as its own test states); one stale line-ref
symbolized. Rounds 40–41's lesson: the residual after three
reading-models concentrates in claims only execution can check.

### Review round 40: fourth-model tranche closes a real guard bypass (2026-08-16)

The fourth model's mid-size-file tranche (eleven files, ~5,200 lines)
produced the program's most significant find since the doctor
credential leak: the manifest billion-laughs guard's anchor-name
predicate (alphanumeric | `_`) omitted `-`, which libyaml's IS_ALPHA
anchor class accepts — empirically confirmed against the workspace's
serde_yaml 0.9.34 (`x: &-a [1,2]` / `y: *-a` parses and expands), so a
bomb built from hyphen-led anchor names walked past the refusal while
the comment claimed the scan "catches every case that serde_yaml would
actually expand". The predicate now matches libyaml, the round-14
name-class regression test pins `&-a`/`*-a` refusal, no shipped
manifest false-positives, and the full CI pipeline is green on the
fix. Two smaller finds: a CLI test doc describing a tmp-path
simulation the test cannot perform (it exercises hard_link's
AlreadyExists on the seed path, as its own inline comment concedes),
and the last `ab-` brand residue in any identifier (a test fixture CA
path). Notable adjudication: the reviewer empirically CONFIRMED
jcs.rs's claim that Rust's `{:e}` float formatting is
shortest-but-not-always-correctly-rounded (bits 0x43143ff3c1cb0959),
validating the ryu justification. Eight of eleven files fully clean,
including validator.rs, jcs.rs, and journal.rs.

### Review rounds 37–39: fourth-model residual measurement (2026-08-16)

A fourth reviewer model measured the residual after three on the three
historically richest files: seven findings, all prose, several
empirically disproven in the fixing (numeric IPv6 zone ids parse on
stable rustc 1.97.1 — `sa.ip()` is what discards the scope, contrary
to three comments; the single-winner provision primitive is
`hard_link(2)` EEXIST, not `create_new`/O_EXCL; the recovery-scan
256 MiB constant only classifies the `too_large` metric while the
64 MiB read cap does the buffering defence; a cited `write_config`
guard and a `write_cold_object_exclusive` function never existed; and
round 28's own edit had orphaned `probe_endpoint`'s doc line onto the
redactor). Sixteen borderlines adjudicated and rejected on the record.

Rounds 38–39 extended the measurement to eleven more files (pipeline,
session, cold_store, receipt; then routes, worker, config, main —
~18k lines): yields of 2 and 2, with routes.rs, main.rs, session.rs,
cold_store.rs and receipt.rs fully clean. All four finds were stale
shadows of earlier behavior changes: an accept-and-warn identity
bullet the shipped 401 rejection superseded (contradicted by its own
comment's closing paragraph), a phantom next-tick retry on the
response-slot drop path, a `None`-disables-timeout claim that
round-32 F4's unconditional 60 s floor had obsoleted, and a
Drop-ordering guarantee named bindings never provided.
Marginal-yield curve across the QC program: model 2: 40, model 3: 18,
model 4: 7→2→2 with rejection ratios near 10:1; every find since
round 27 has been prose, with the code correct at every site.

### Review round 36: third-model test-suite QC — three-model coverage complete (2026-08-16)

The third reviewer finished the integration-test suites, closing the
program at three independent models over every file in the repository.
Nine findings; the important ones were resolved by strengthening tests
rather than weakening docs: the CLI "help mentions every subcommand"
lists were missing five of the fourteen subcommands
(setup/start/init/doctor/health — both the discoverability and the
per-subcommand `--help` loops now cover all 14); the
Ed25519-determinism assertion was unreachable (all 200 oracle bodies
distinct — an explicit identical-body pair now proves RFC 8032
determinism); the 2^53-boundary receipt is verified, not just signed;
the tiny-inputs test now actually covers a single character. Prose
fixes: the all-zero Ed25519 key is the order-4 small-order point
(y = 0), not "the identity"; deep nesting lives in `stop_reason`, not
the receipt subject; "cross-workflow AND cross-identity" had no
cross-identity half here; the breaker coverage list promised "loop
convergence" where the design keeps the breaker Open until manual
reset (the mislabeled near-epsilon test is now
`progressing_content_never_falsely_trips`). Twenty-five borderline
candidates adjudicated and rejected on the record.

Program totals across rounds 17–36: three models × 100 % of src and
tests; ≈ 90 prose corrections, 7 strengthened assertions, 4 new tests,
3 code fixes (both halves of the doctor credential leak; a Drop-timing
release that a named `_`-binding could not deliver), ≈ 80 borderlines
adjudicated with recorded reasons, all echo families extinguished.

### Review rounds 33–35: third-model QC (2026-08-16)

Escalated the QC program to a third independent reviewer model on the
highest-stakes files. Fifteen findings across fourteen files, severity
still declining but nonzero — including the session's second genuine
code fix: `ResponsePermit::submit` documented an early permit release
that a named `_`-prefixed binding cannot deliver (named bindings live
to end of scope; NLL shortens borrows, not `Drop` timing) — the code
now performs the explicit `drop()` the comment always described.
Other notable corrections: `enforce_retention`'s headline claimed
unconditional cold export over a `cold_uri` guard (unset means expired
records drop without export — both arms now documented);
`verify()`'s numbered checklist was in reverse execution order; the
JWT validation checklist omitted its own first check (pre-auth 8 KiB
cap) and the `exp > iat` guard; a cited "manifest override" for the
cold outbox never existed; `budget.max_tokens` was mislabeled a
completion budget; seven stale absolute line references were
symbolized to rot-proof anchors. The reviewers also adjudicated and
rejected 33 borderline candidates with recorded reasons so future
audits do not relitigate them. Round 35 closed the doctor leak's other
half — the upstream-failure line still printed the configured URL
verbatim (reqwest additionally embeds it in the error Display); it now
redacts userinfo and strips the error's URL copy — and extinguished
the last two claim echoes (the 429 in the breaker *field* doc; the
phantom budget keys in av-sandbox's module doc, whose `$50` literal
would have meant 50 micro-USD under the real `_micros` field). A
dedicated pairing-claims sweep ("partner"/"mirrors"/"must match"/
"lockstep") then verified every such cross-reference in the workspace
intact.

### Review rounds 30–32: test-suite QC, self-review closure, echo sweep (2026-08-16)

The cross-model QC program's final surface: the standalone integration
test suites (~14k lines, 36 files). 13 test docs claimed things their
assertions do not check — banners describing retention-dedup behavior
the test (correctly) asserts the opposite of, a "hijack is refused"
test where nothing is refused (the real invariant: headers cannot swap
identity), a wasm "must trap" over a Deny-or-Allow assertion, and
loop-breaker docs promising strictness the embedder-tolerant
assertions deliberately avoid. Two tests were strengthened to match
their docs instead (receipt-verify stdout pinned to the documented
`verified <id>` shape; tampered-signature errors pinned to the opaque
`Verification` variant), and one QC finding was rejected as a
tooling artifact (byte-level inspection proved the "vacuous
bearer-leak test" really sends the secret; the session's masking had
redacted the reviewer's view). Self-review of the rewrites then caught
one over-claim of ours — a banner deferring unicode-tag byte-survival
to golden tests that contained no tag characters — resolved by adding
the missing test: tag-smuggled messages survive the typed round trip
bit-exactly and pass both validators. A final echo sweep re-grepped
every corrected claim across the prose docs and found two survivors in
PLAN.md (the brief's illustrative budget keys presented as the config
surface; the top-level-only `unmapped` nuance), both aligned with the
code-comment fixes they echoed.

Final certification: fmt, workspace clippy -D warnings all-features,
cargo-deny (4 checks), and the full 69-binary / 895-test all-features
suite green locally; the full CI pipeline (live services, release SLA,
container build, Harbor interop) green on the same commit.

### Review rounds 18–29: runtime-prose sweeps and the cross-model QC program (2026-08-16)

Rounds 18–25 extended the audit beyond code comments to every other
claim-bearing surface, each swept as an explicit class: the round-17
fixes themselves (self-review caught one overreach), TODO/promise
markers (the compression-marker limitation is now tracked in
SECURITY-AUDIT.md instead of only in its own comment), runtime error
strings (the zero-config quick start recommended the nonexistent
`agentvisor-ai` binary; five feature-gate bails named it too — all now
name `agentvisord` with the rebuild command), the generated
`avctl init` config template and clap help (verified drift-proof via
the from_toml round-trip), Prometheus HELP text (one divergent family
unified), `avctl doctor` diagnostics (no-schema warnings now state the
configured posture's real consequence), and the issue template
(`avctl --version` instead of a command that never existed).

Rounds 26–29 ran an independent cross-model QC program: a second
model re-reviewed every source file in the workspace (~50 files, four
tranches). It found 25 genuine misses, all in headline doc summaries —
rounded-off conditionals ("all"/"every"/"never" where the code has
caps, role filters, or opt-ins), mechanisms that had been refactored
away (a render()-panics claim, a global-lock test narrative, a p50/3×
bound that is actually aggregate 10×N), self-contradicting quantile
docs, and one promise that produced a real fix: `avctl doctor` said it
never prints secrets, but its *success* lines printed configured
endpoints verbatim — a `redis://user:pass@host` state endpoint leaked
credentials on every healthy run. A new `redact_userinfo()` display
helper (unit-tested across all doctor display shapes) now backs the
stronger, true promise. Also: NATS ack offsets documented as JetStream
stream sequences rather than partition-local offsets, and the
loop-detect Δ formula now documents the nearest-prior-step tightening.

### Review round 17: full-codebase comment↔code audit (2026-08-16)

Four parallel reviewers read every comment in all 12 crates (54k lines,
9.2k comment lines) and verified each checkable claim against the code;
a fifth pass covered the non-Rust surfaces (Dockerfile, Cargo.toml,
configs, deploy). 17 stale or false comments fixed — none reflected a
code bug; in every case the code was right and the prose had drifted:

- **False security/behavior claims**: `/metrics` described as
  authenticated and surfacing a nonexistent `av_build_info` metric
  (routes.rs — no harness endpoint exposes build info; the version
  appears only in the outbound upstream User-Agent); metrics label
  values attributed to a nonexistent render-time escaper
  (`escape_prom_label_value` never existed — the real guard is
  registration-time byte refusal in `validate_metric_key`, twice);
  `ResponsePermit` claimed admission "whenever the shard has room"
  (a global worker-capacity slot is also required — the adjacent test
  proves it); `worker_channel_capacity` cap justified by a tokio mpsc
  preallocation-OOM that tokio does not do (contradicting the
  authoritative const doc four lines up).
- **Stale after refactors**: reconciler test docs still described the
  removed global `lifecycle_lock` (now per-session `SessionLockTable`,
  three sites); recovery-scan cost rationale predated round-44 F1's
  refuse-before-read sidecar check; depth-bomb test called the
  round-40 F5 recursion cap "a valid future hardening" (it shipped);
  `dispatch` stage described as covering 15-90 s upstream streaming
  (it times only local job assembly); "up to 16 shards" (always
  exactly 16); "Fold gives min/max" over a plain for-loop; duplicate
  X-AV-Session refusal described as a 503 (it is a 400); Dockerfile
  build-stage `COPY config` justified by an `include_str!` that
  round-45 moved inside the crate — the COPY is gone (compile
  independence proven by building a tree with `config/` deleted) and
  av-harness/build.rs no longer claims the assets live outside the
  crate root.
- **Drifted line-number references** (9 sites): replaced absolute
  `L1308`/`:578`-style references — every one already pointing at the
  wrong line — with function-name or grep-able anchors in
  reconciler.rs, pipeline.rs, setup.rs, and av-atif's golden tests;
  receipt nesting-boundary doc now states the true off-by-one
  (`MAX_NESTED_DEPTH - 1` parses, `MAX_NESTED_DEPTH` refused).
- **Rebrand stragglers** (identifiers, not comments): pipeline test
  names `x_ab_*` → `x_av_*`; internal `DUP_KEY_SENTINEL` `"__ab_dup:"`
  → `"__av_dup:"` (never persisted or exposed — stripped before the
  error maps to `ReceiptError`).
- Race-suite module doc no longer claims retention-rollover coverage
  that lives in `embedded_contract.rs` (pointer added instead).

Verified-correct highlights from the same audit: all cross-crate
constant mirrors (4 MiB payload, 16 MiB provider capture, 2^53 JCS
bound, depth 128/64, JWKS 256, JWT 8 KiB, breaker ε=0.30), the
MAC-before-index journal order, seal-before-insert recovery race fix,
genesis-hash domain tag, Redis Lua TTLs, and every `AV_*` env name a
comment mentions.

### Review round 16: ATIF dual-validator agreement contract (2026-08-16)

A consistency sweep of schema surfaces found that the shipped
`schemas/atif-v1.7.schema.json` was only ever exercised against the
single golden trajectory, while the Rust strict validator is a separate
hand-rolled implementation — the two could silently diverge on any
other document, and external consumers validate our exports with the
JSON Schema. Added
`rust_strict_valid_v17_documents_always_pass_the_shipped_schema`
(av-atif golden suite): a seven-document corpus (minimal, root `extra`,
`tool_definitions`, system observation, multimodal message, omitted
`session_id`, golden) must be accepted by *both* validators. The
inverse direction is intentionally unenforced — strict mode checks
Harbor semantics JSON Schema cannot express (sequential step ids,
version-gated fields). The other three shipped schemas need no such
contract: bridge manifests are validated *by* the JSON Schema itself
(single source of truth), and receipts/OCSF events are machine-generated
shapes already covered by golden schema-conformance tests.

### Review round 15: fix the red CI supply-chain gate (2026-08-16)

The first CI run on the renamed repo failed `cargo-deny --all-features`:
the round-1 `ssl-vendored` addition to rdkafka violated the workspace's
rustls-only ban, and the rskafka 0.5 TLS stack pinned an EOL rustls 0.21
line carrying RUSTSEC-2026-0098 (rustls-webpki URI name constraints) and
the archived rustls-pemfile (RUSTSEC-2025-0134). Fixed properly:

- **rskafka 0.5 → 0.6**: the Kafka event path now uses rustls 0.23
  (shared line with async-nats; vulnerable webpki 0.101 and
  rustls-pemfile dropped from the lock entirely; CA parsing via
  rustls-pki-types). rskafka 0.6 brings native SASL SCRAM support:
  new `AV_KAFKA_SASL_MECHANISM` (`SCRAM-SHA-256` default — Redpanda's
  native credential store — `SCRAM-SHA-512`, or `PLAIN`; unsupported
  values refused loudly), applied consistently to both the rskafka
  event path and the librdkafka admin path. Live-validated against
  Redpanda TLS+SASL: SCRAM-256 default, explicit PLAIN, loud failure
  for a server-side-unconfigured SCRAM-512, plaintext regression.
- **deny.toml**: `openssl-sys` ban scoped with `wrappers =
  ["rdkafka-sys"]` — the vendored librdkafka admin client (topic
  provisioning + retention verification) is the single sanctioned
  OpenSSL surface; every other parent still fails the gate. All four
  cargo-deny checks green under `--all-features`.

### Review round 8: soak test findings (2026-08-16)

A 15,600-session soak (release daemon, live Kafka bridge + 3-node Redis
Cluster + mock upstream, `avctl loadgen` waves) surfaced two cold-tier
defects; memory and fd behavior were otherwise clean (fds stable, RSS
reclaimed from 72 MB to 29 MB once the idle sweep finalized sessions —
retention by design, not a leak; zero failed requests across all waves).

- **Shipped example manifest could never cold-export outside the
  container** — `manifests/bridge.example.yaml` hardcoded
  `file:///app/data/cold` (container-absolute). A local run with the
  documented default accumulated an unbounded durable retry outbox
  (13,314 intents / 52 MB in one soak) with a WARN per event, forever.
  The manifest now uses the portable relative `data/cold`, which
  resolves identically in the container (`WORKDIR /app`).
- **Relative `cold_uri` never worked** — `cold_url` created the
  directory and then failed provisioning, because
  `Url::from_directory_path` rejects relative paths. It now
  canonicalizes against the CWD first (same resolution rule as the
  cold-outbox default). Post-fix soak: 0 retry warnings, cold objects
  land on disk, outbox drains to 0.

### Review round 4: supply chain + NATS credential downgrade (2026-08-16)

- **quick-xml RUSTSEC advisory (unbounded allocation)** — the `aws` feature
  of `object_store` 0.12 pinned quick-xml 0.38, which `cargo deny` flags.
  Upgraded workspace `object_store` to 0.14 (quick-xml 0.41, fixed),
  adapting to its API (`ObjectStoreExt` import, `Path::join`). Live
  MinIO S3 contract re-validated on the new client; `cargo deny check`
  fully green (advisories, bans, licenses, sources).
- **NATS credentials could still cross plaintext** (independent-review
  finding): `require_tls(true)` was only forced when a CA file was
  pinned, so `AV_NATS_USER`/`AV_NATS_PASSWORD` with a `nats://` URL and
  no CA (e.g. WebPKI endpoints) sent the CONNECT password over a
  plaintext socket and stayed MITM-downgradeable. Credentials now force
  `require_tls(true)` too — live-tested: refused against a plaintext
  server, works against TLS.

### Connector-security review fixes (2026-08-16)

Implementation review of the secured-transport work surfaced three defects:

- **Kafka bootstrap lists actually work on the event path** — config
  documents `bridge_endpoint` as `host:port[,host:port]` and the rdkafka
  admin client accepts that, but the rskafka event path received the joined
  string as a single address, so every multi-broker bootstrap list failed
  to connect. The list is now split per-entry (live-tested single and
  multi-entry forms).
- **NATS partial credentials failed silently** — setting only one of
  `AV_NATS_USER`/`AV_NATS_PASSWORD` silently connected anonymously
  (a D13 silent-error violation, and inconsistent with the Kafka
  connector). Now refused loudly, unit- and live-tested.
- **NATS plaintext downgrade on endpoint typo** — a pinned
  `AV_NATS_CA_FILE` with a `nats://` (instead of `tls://`) URL could
  yield a plaintext connection. A pinned CA now forces
  `require_tls(true)`; live-tested to negotiate TLS on `nats://`.
- **Cold-store env over-capture** — lowercasing the whole environment for
  `object_store::parse_url_opts` let generic variable names (`ENDPOINT`,
  `REGION`, `TIMEOUT`, `TOKEN`, `PROXY_URL`) silently reconfigure the
  S3 client. Only `AWS_*`-prefixed variables are honored now
  (`aws_env_options`, unit-tested).

Also: `KafkaSecurity` gained a testable `from_lookup` seam (harness
`apply_env_overrides_from` pattern) plus unit tests for credential
pairing, the SASL-requires-TLS guard, protocol selection, and CA-file
error paths — deliberately without `derive(Debug)`, which would have
made the SASL password printable.

### Rebrand: AgentBridge → AgentVisor AI (2026-08-15)

Full pre-release rename; entries below this one keep the historical names.

- **Brand** — all docs, CLI text, dashboards, and crate descriptions now say
  AgentVisor AI. References to the source brief keep its original filename
  (`AgentBridge.docx`).
- **Binaries** — the daemon is `agentvisord` (was `agentbridged`); the CLI is
  `avctl` (was `abctl`). `find_server_binary` prefers `agentvisord` and
  falls back to the legacy `agentbridged` / `agent-bridge` names so
  source-built older installs keep working.
- **Crates** — all 12 workspace crates renamed `ab-*` → `av-*`
  (`av-core`, `av-events`, `av-atif`, `av-receipts`, `av-state`,
  `av-bridge`, `av-identity`, `av-compress`, `av-loopdetect`, `av-sandbox`,
  `av-harness`, `av-cli`). Nothing had been published to crates.io yet.
- **Wire protocol** — HTTP headers `X-AB-Session` / `X-AB-Workflow` (and the
  `x-ab-agent-version`, `x-ab-instance-uid`, `x-ab-middleware-us` response
  headers) renamed to `X-AV-*` / `x-av-*`. The event-chain genesis
  domain-separation tag changed `"ab-genesis"` → `"av-genesis"`, so receipts
  issued by pre-rename builds do not verify against post-rename chains
  (pre-release, nothing published).
- **Persisted formats** — further pre-release breaks carried by the rename:
  NATS JetStream stream names are now `av_<topic>` (old `ab_*` streams are
  orphaned, re-provisioned fresh); the cold-outbox HMAC domain changed to
  `agentvisor-cold-outbox-v1`, so pre-rename pending intents fail
  authentication loudly (drain the outbox before upgrading); Kafka records
  carry the dedupe header `agentvisor-event-uid` (was `agentbridge-…`); the
  OCSF `metadata.product.name` is `agentvisor-ai`; the default NHI JWT
  `audience` is `agentvisor-ai`, so tokens minted for the old audience are
  rejected until re-issued.
- **Env vars** — `AB_*` → `AV_*` (e.g. `AV_UPSTREAM_URL`, `AV_REDIS_URL`,
  `AV_KAFKA_CA_FILE`, `AV_NATS_CA_FILE`, `AV_COLD_S3_URL`, `AV_SLA_*`).
- **Metrics** — Prometheus names `ab_*` → `av_*`
  (e.g. `av_events_dropped_total`).
- **Paths & deploy** — setup root is `~/.agentvisor/`; systemd unit and
  Kubernetes manifest renamed to `agentvisor-ai.service` /
  `agentvisor-ai.yaml`; Docker/Compose, release archives, and the publish
  workflow updated. Repository URLs now point at `agentvisor-ai` (the
  GitHub repo must be renamed to match before the next release).

### Secured-transport and cluster live coverage (2026-08-15)

Closed the three environment limits recorded in VERIFICATION.md:

- **Kafka TLS/SASL** — `KafkaBus::provision` now honors `AB_KAFKA_CA_FILE`
  (private-CA TLS on both the rskafka event path and the librdkafka admin
  path; rskafka gains `transport-tls`, rdkafka gains `ssl-vendored`) and
  `AB_KAFKA_SASL_USERNAME`/`AB_KAFKA_SASL_PASSWORD` (SASL/PLAIN). Credentials
  without a CA are refused client-side — PLAIN must not cross the wire
  without TLS. Live contract passed against Redpanda with a
  `sasl`-authenticated TLS listener; plaintext path regression-tested
  unchanged.
- **NATS TLS/auth** — `NatsBus::provision` now honors `AB_NATS_CA_FILE` and
  `AB_NATS_USER`/`AB_NATS_PASSWORD`. Live contract passed over `tls://`
  against nats-server requiring TLS + user/password.
- **S3-compatible cold tier** — new `cold-store-aws` feature enables
  `s3://` `cold_uri` targets. Fixed a latent bug where
  `ColdArchive::from_manifest` passed raw `std::env::vars()` to
  `object_store::parse_url_opts`, which only parses lowercase config keys —
  standard `AWS_ACCESS_KEY_ID`/`AWS_ENDPOINT`/… were silently ignored; keys
  are now lowercased. New `AB_COLD_S3_URL`-gated live contract
  (`ab-bridge/tests/cold_store_live.rs`) passed against MinIO, covering the
  staged intent → conditional put → idempotent re-put path.
- **Redis Cluster** — new `AB_REDIS_URL` contract test drives the multi-key
  `try_spend_many` Lua script with the production `budget:{hash-tag}:` key
  shape; passed against a live 3-master cluster (CROSSSLOT safety and
  cross-key atomicity of a refused spend on a real slot map).

### Distribution

- **crates.io publishing** — added `.github/workflows/publish-crates.yml`
  which packages and uploads all 12 workspace crates in topological
  dependency order on every `v[0-9]+.[0-9]+.[0-9]+` tag push. A
  `workflow_dispatch` trigger with `dry_run=true` (default) smoke-tests
  the packaging without uploading. `CARGO_REGISTRY_TOKEN` secret must
  be set on the repo before the first tag lands.
- **Binary rename `agent-bridge` → `agentbridged`** — the name
  `agent-bridge` on crates.io is taken by an unrelated project (a
  Codex/Claude/Gemini CLI). To avoid `cargo install agent-bridge`
  installing someone else's tool, the harness binary is now
  `agentbridged` (daemon-style suffix) and the crate remains
  `ab-harness`. `abctl` and `ab-cli` are unchanged. `find_server_binary`
  in setup.rs prefers `agentbridged` and falls back to the legacy
  `agent-bridge` for smooth upgrades. Dockerfile ENTRYPOINT, systemd
  ExecStart, and CI release archives updated to match.
- **Embedded WAT relocation** — `crates/ab-harness/src/main.rs` used
  `include_str!("../../../config/policies/payload_limit.wat")`, which
  reaches outside the crate root and would fail on a crates.io
  consumer build (`cargo package` excludes parent-directory paths).
  Relocated to `crates/ab-harness/policies/payload_limit.wat`
  (packaged with the crate); the operator-facing mirror at
  `<repo>/config/policies/payload_limit.wat` stays for
  Docker/systemd/k8s deploy-time editing.
- **Workspace crate metadata** — every crate now inherits
  `repository`, `homepage`, `documentation`, `keywords`, and
  `categories` from `[workspace.package]` so crates.io landing pages
  render cleanly on first publish.

Post-0.1.0 hardening across rounds 11–32 of a systematic bug audit.
Highlights, grouped by class:

### Security

- **CVE-2026-25537** — bumped `jsonwebtoken` 9.3 → 10.4 to close the
  `nbf`/`exp` string-type-confusion bypass (round-11).
- **Signing-seed hardening** — refuse known-weak Ed25519 seeds
  (all-zero, all-0xFF); ed25519-dalek `zeroize` feature enabled;
  `Ed25519Signer::seed()` returns `Zeroizing<[u8; 32]>` and
  `from_seed(&[u8; 32])` takes a reference so no bare temp slot
  lingers (rounds 14, 18, 19).
- **Duplicate-header refusal** — `X-AB-Session`, `X-AB-Workflow`,
  and `Authorization` are all refused when multi-valued
  (identity split-brain hardening; rounds 13, 14).
- **RFC 7235 §2.1 Bearer scheme** — case-insensitive scheme match
  + SP/HTAB separator (round-15).
- **Receipt strict-load** — `Receipt::from_json_slice` walks the
  JSON with a bounded-depth visitor that refuses duplicate keys
  at any nesting level; `verify_semantic_invariants` enforces
  `AtifTrajectory.retroactive == true` (rounds 15, 16).
- **JWKS body cap** — 4 MiB Content-Length + streamed-body cap +
  256-key outer-array cap; case-insensitive scheme match; intra-
  document duplicate-`kid` refusal (rounds 12, 14, 15).
- **Docker + k8s signing-seed relocation** — moved off shared
  volumes into a docker secret (mode 0400) and a k8s Secret
  copied via non-root initContainer into an in-memory emptyDir
  (rounds 15, 17).
- **Systemd hardening** — `TimeoutStopSec=125s`,
  `KillMode=mixed`, `StartLimitBurst=5`,
  `StartLimitIntervalSec=60s`; signing seed moved to
  `/etc/agent-bridge/signing.seed` outside `ReadWritePaths`
  (rounds 17, 18, 19).

### Resource caps

- `MAX_RECEIPT_BYTES` (16 MiB), `MAX_ATIF_BYTES` (64 MiB), and
  `MAX_CONTROL_BYTES` (1 MiB) in `ab_core::fsutil`; TOCTOU-hardened
  `read_capped` / `read_capped_string` used by every CLI file
  loader and every hot-path reconciler / worker read (rounds 17,
  18).
- `abctl loadgen` cap 100k → 10k (matches the stated SLA gate;
  round 11).
- Reconciler `warned_artifacts` bounded by a constructor-bound
  FIFO (VecDeque + HashSet) so a rotating-timestamp attacker
  cannot force a log storm (rounds 17, 18, 19).
- Prometheus `HELP` text is now escape-encoded (backslash and LF)
  so a stray newline cannot corrupt scrape output (round 19).

### Reliability

- **Recovery no longer HOL-blocks** on a single bad
  `journal_version` sidecar (round 15).
- **Torn journal quarantine** — refuse to silently truncate a
  no-newline journal; move to `<path>.corrupt-<uid>` and preserve
  the sealed metadata sidecar via `quarantine_sibling_exists`
  (rounds 13, 14).
- **Worker shutdown supervision** — `PendingGuard` RAII so a
  panic in `process_envelope` cannot leak `worker_pending`;
  `catch_unwind` widened around JWKS refresh; JWKS
  `JoinHandle` aborted on shutdown; bridge maintenance error +
  join counters (rounds 11, 12).
- **Journal metadata durability** — `TempPathGuard` RAII prevents
  `.tmp` orphan class; `write_atomic`'s post-rename dirent fsync
  is best-effort with a warn (rounds 11, 12).
- **Journal HMAC field cap** — `hex::decode` refuses len > 128
  in both `journal.rs` and `cold_store.rs` (round 17).
- **Metric registry base-kind guard** — Prometheus TYPE conflicts
  panic at registration; every stage uses the wide-latency
  histogram bounds (round 10).

### Diagnostics

- **Dashboard JSON** — `no_store_json_response` on
  `list_sessions` / `session_detail` / `stats` sets
  `Cache-Control: no-store`, `Pragma: no-cache`, and
  `Vary: Authorization` (round 17).
- **`atif_capture_from_request` diagnostics** discriminate
  missing / wrong-type / empty `messages` (round 11).
- **Receipt duplicate-key error** — sentinel-based mapping so
  malformed JSON is `Serde`, not misattributed to `DuplicateKey`;
  offending key names are `escape_debug`'d (round 16).
- **ATIF validation error rendering** capped to the first 16
  issues + total (round 19).
- **Trace-span session id** sanitized through `SessionId::parse`
  before the span binds it; the rejected-value sentinel starts
  with `\x20` (outside the visible-ASCII predicate) so no client
  value can collide (rounds 13, 14).

### Documentation

- **Deploy install docs** — systemd instructs `abctl keygen`
  before daemon-reload; k8s instructs `kubectl create secret
  generic agent-bridge-signing-seed`; docker-compose.minimal.yml
  banner explains that its tmpfs seed regenerates on every
  restart (rounds 17, 18).

### Rounds 20–32 (highlights)

- **Cross-backend consistency** — `try_spend_many` (round-21 F1)
  and `COUNTER_MAX` (round-20 F1/F7) share a `JCS_SAFE_MAX`
  ceiling across `InMemoryStore` and `RedisStore` so a config
  typo cannot succeed in dev and fail in prod.
- **Cold outbox integrity** — `ColdArchive::set_control_key`
  refuses `[0; 32]` / `[0xFF; 32]` (round-21 F3) and
  `pending_mac` / `verify_pending_mac` refuse those patterns at
  sign/verify time so the constructor's default-init window
  cannot produce a forgeable envelope (round-22 F2). All
  cold-outbox rewrites now use `TempPathGuard` so a transient
  ENOSPC/EIO cannot leave a `.tmp` orphan with signed material
  on disk (round-22 F3, round-23 F1, round-27 F3).
- **Kafka fetch surfaces decode errors** — parity with NatsBus /
  EmbeddedBroker; a corrupt record no longer creates a silent
  offset gap in the audit trail (round-22 F1).
- **Deploy hardening** — `docker-compose.yml` `vector` service
  no longer mounts `/var/run/docker.sock`; all services now
  carry `restart: unless-stopped`; redpanda/nats moved to
  persistent named volumes; docker-compose.minimal.yml gained
  `cap_drop: [ALL]` / `pids_limit` / `security_opt`; the k8s
  ATIF spool moved from `emptyDir` to a `subPath` on the
  durable PVC and the initContainer gained
  `seccompProfile: RuntimeDefault` (rounds 24, 26).
- **Bridge maintenance shutdown** — cooperative
  `tokio::sync::Notify` replaces `JoinHandle::abort()` so the
  `spawn_blocking` closure quiesces before process exit
  (round-24 F5).
- **JWKS strictness** — refuses `use=enc` and non-EdDSA `alg` on
  OKP/Ed25519 (round-25 F1); `add_key` refuses to shadow
  JWKS-tracked kids (round-25 F2).
- **SSE detection is case-insensitive + parameter-tolerant**
  (round-25 F3); ATIF validator bounded by
  `MAX_NESTED_DEPTH = 128` (round-25 F4).
- **ATIF schema strictness** — `additionalProperties: false` on
  `metrics` and `agent` closes a smuggle path into the signed
  digest (round-26 F1, F2). Journal `open` verifies MAC before
  comparing positions to close the position oracle
  (round-26 F3). Prometheus HELP escaper now scrubs DEL and C1
  controls (round-26 F4). `TokenVelocity` uses
  `saturating_add` (round-26 F5).
- **Recovery robustness** — `recover_spooled_sessions` and
  `retry_marked_promotions` no longer abort the whole scan on
  one bad file; orphan `.promote` markers are cleaned up on
  the `is_promoted()` early-return; `promote_session` on a
  still-open session additionally requires `session_close_scope`
  (round-27 F1, F2, F3, F4). `BridgeManifest` /
  `TopicSpec` / `RetentionSpec` gained `deny_unknown_fields` +
  numeric caps (partitions ≤ 1024, hot_hours ≤ 10 years); the
  dashboard `session_detail` returns `atif_filename` instead
  of the absolute path (round-27 F5, F6).
- **CLI + Dashboard** — `probe_endpoint` uses scheme-driven
  default ports and strips userinfo (round-28 F1, F5);
  dashboard responses now carry a strict CSP + `X-Frame-
  Options: DENY` + `Referrer-Policy: no-referrer`
  (round-28 F2); attacker-influencable strings run through
  `sanitize_for_terminal` before println (round-28 F3);
  `session_promote` and `loadgen` stream response bodies with
  hard caps (round-28 F4); `abctl event-tail --max` capped at
  100 000 (round-24 F7).
- **Upstream relay** — non-JSON upstream error bodies no longer
  collapse to 502; the true status + `Retry-After` propagate to
  the client so SDK backoff works (round-29 F1). Every
  upstream-relayed response now carries
  `X-Content-Type-Options: nosniff` (round-29 F4). `/health`
  no longer discloses `CARGO_PKG_VERSION` to unauthenticated
  callers (round-29 F6). `StopReason` gained
  `#[serde(other)]` fallback for forward-compat during
  heterogeneous cluster upgrades (round-29 F7).
- **CI supply chain** — every third-party action pinned to a
  commit SHA; pydantic/shortuuid pinned to exact versions with
  transitive closure (round-29 F2, F3).
- **Config validate** — refuses
  `enforce_identity_scopes = true && require_identity = false`
  (round-30 F1); per-backend URL scheme allowlist on
  `identity_jwks_url` / `qdrant_url` / `state_endpoint` /
  `bridge_endpoint` (round-30 F2); `atif_spool_dir` /
  `bridge_data_dir` reject empty strings; scope names require
  non-empty visible-ASCII (round-31 F1, F2).
- **CORS deny** — explicit `cors_deny` OPTIONS handler on every
  mutating route: `204 No Content` with NO
  `Access-Control-Allow-*` headers; browsers correctly refuse
  cross-origin requests. Test guards against a future
  `CorsLayer::permissive()` regression (round-31 F5).
- **MCP tool-call Content-Type preserved** — the upstream tool
  response's `Content-Type` now round-trips through the on-
  disk `ToolOutcome` journal and re-emits on cached-outcome
  replay, so strict JSON-RPC 2.0 clients see
  `application/json` instead of the axum default
  `application/octet-stream` (round-32 F2).
- **Upstream read-timeout floor** — a 60 s read timeout is now
  applied to the shared reqwest client unconditionally (was
  opt-in), so a hung tool upstream cannot pin a session lease
  + WorkerPermit + tool-intent claim indefinitely
  (round-32 F4).

## 0.1.0 - 2026-08-10

### Added

- OpenAI-compatible Axum proxy and MCP interception routes.
- Bounded asynchronous workers with loop detection, OCSF emission, Bridge publication, ATIF capture, and signed chains.
- Idempotent session close, client-abort finalization, idle reconciliation, and retroactive receipts.
- Embedded, Kafka/Redpanda, and NATS Bridge backends with manifest provisioning.
- In-memory and Redis atomic state backends.
- Hash and ONNX embedding backends plus optional Qdrant persistence.
- Ed25519 JWKS refresh and HS256 development identity support.
- `abctl` operations, load generation, schemas, Docker Compose, and Vector configuration.
- Bounded byte-oriented SSE/non-SSE capture with fragmented UTF-8 and tool-call reassembly.
- Authenticated, torn-tail-tolerant signed and unsigned crash journals with exact receipt reuse.
- Durable lifecycle and cold-export outboxes with persisted acknowledgments.
- JSON-RPC-id tool execution claims, cached outcomes, and close-through-completion leases.
- Session-ordered parallel worker shards and concurrent deadline-bounded broker connectors.
- Qdrant similarity participation, masked ONNX mean pooling, and strict output-shape checks.
- Kafka retention verification, AOF-backed Redis, customer-volume cold tier, and object-store retries.
- Batched OTLP/HTTP traces to Vector with request/worker parent propagation and bounded shutdown.
- Harbor reference-validator CI over a trajectory emitted by the real HTTP harness flow.
- Mandatory CI image build, live backend contracts, and a true 10,000-connection release gate.
