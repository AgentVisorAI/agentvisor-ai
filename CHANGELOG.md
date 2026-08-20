# Changelog

All notable changes are documented here. The project follows Semantic Versioning.

## Unreleased

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
