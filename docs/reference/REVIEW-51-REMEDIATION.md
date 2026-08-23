# Round-51 Engineering Review — Remediation Record

Finding-by-finding closure map for the round-51 external engineering
review (43 pages, 18 August 2026). Each row names the mechanism that
closed the finding and where it is pinned by tests. Two items are
deliberately deferred with rationale, listed last — a trust product
that publishes its own open items is more credible than one that
doesn't.

Status legend: ✅ fixed · 🔶 deferred with documented rationale.

## §3 Security

| Finding | Status | Mechanism |
| --- | --- | --- |
| 3.1 Non-strict Ed25519 verification enables universal receipt forgery | ✅ | `verify_strict` everywhere; `add_key_bytes` rejects weak/small-order keys; mutation suite asserts typed error variants |
| 3.2 No configured budget binds (caller-chosen `X-AV-Session`) | ✅ | Principal-keyed budgets: counters key on the authenticated principal, not the caller-chosen header |
| 3.3 Shipped config binds all interfaces with no identity | ✅ | `listen` defaults to loopback; `0.0.0.0` without identity refuses to boot unless `allow_wildcard_bind` |
| 3.4 Unauthenticated requests mint durable signed sessions | ✅ | Static-key auth rule + `ignore_client_authorization`; hero snippet works and is tested |
| 3.5 A,B,A,B alternation defeats the breaker | ✅ | Alternation window over the deltas ring (which is now read); inject floor no longer resets `tokens_consumed` |
| 3.5 `validate_trajectory(Strict)` cannot see unknown fields / duplicate keys | ✅ | Bytes-level `validate_bytes(Strict)` gates both the reconciler and `avctl atif-validate` before the typed parse |
| 3.5 Response capture dropped on backpressure while returning 200 | ✅ | Worker permits are reserved at admission; the terminal capture submits through the reserved permit and errors propagate |

## §4–5 Architecture and code quality

| Finding | Status | Mechanism |
| --- | --- | --- |
| 4.2 Same accounting fold implemented three times | ✅ | S1 step 1: `ActiveJournalRecord::fold_into`/`apply_to_totals` is THE fold; live + both recovery paths call it; proof harness pins live==recovery |
| 4.2 Session lifecycle is flag-soup | ✅ | S2 complete: `SessionState` in one `AtomicU8`, CAS `transition(from, to)`, mirror flags deleted; illegal transitions impossible (refused) and debug-asserted |
| 4.2 Reconciler re-scans the flat spool every tick | ✅ | O(1) steady-state stem skip, sidecar-check-first ordering, quarantine renames, retention pruning (`atif_retention_days`) |
| 4.2 Reconciler god-module | ✅ | S1 steps 2–4: six named `RecoveryPass`es behind a narrow `ReconcilerContext`; `recover_spooled_sessions` is a flat ordered runner |
| 4.3 A second provider would be painful | ✅ | S3 complete: `ProviderAdapter` trait; OpenAI, Anthropic, Gemini adapters; `provider` config key; per-dialect full-chain integration tests |
| 5.1 `validate()` reports only the first error | ✅ | All checks accumulate; single error keeps the bare shape, multiple return a numbered aggregate |
| 5.3 Round-N F-M tags | ✅ | Comments rewritten as narrated why-comments; tag conventions documented |
| 5.4 Stale comments, duplicated atomic-write recipes, `SessionId` at the door | ✅ | Comments corrected; `rewrite_atomic` canonicalized (embedded divergence fixed); remaining items tracked in STRUCTURAL-REFACTORS.md |
| 5.5 Onboarding: spool/recovery model undocumented | ✅ | `docs/reference/SPOOL-AND-RECOVERY.md` (artifact table: who writes, who deletes, what absence means; recovery-pass table) |

## §6 Correctness

| Finding | Status | Mechanism |
| --- | --- | --- |
| 6.1 Recycled session id destroys prior artifact, wedges forever | ✅ | Archive-on-collision (`archived-<uid>` pairs) + live-stem guard; `avctl receipt-locate` finds archived incarnations |
| 6.2 One bad upstream frame bricks the session | ✅ | Per-response capture scoping: a bad frame fails THAT response, session remains usable; named-event keepalives skipped, not fatal |
| 6.3 Budget charged pre-compression, receipt records post-compression | ✅ | Post-compression charging composed with the enforcement latch |
| 6.4 Truncated streams attested as complete | ✅ | Truncation attestation: no finish_reason/no [DONE] streams are not `Stop` |
| 6.4 Failed upstream calls charge with no refund | ✅ | Refunds on upstream-error paths |
| 6.4 Provider prompt_tokens discarded (heuristic 3–4× over CJK) | ✅ | Signed `prompt_token_correction` on the terminal record through the unified fold + session-ledger refund of the over-charge |
| 6.4 Client disconnect force-closes the session | ✅ | Disconnect aborts the turn, not the session; idle sweeper owns closure |
| 6.4 Named SSE events rejected rather than skipped | ✅ | Dataless named frames are keepalives; only attributable data is refused |

## §7 Performance

| Finding | Status | Mechanism |
| --- | --- | --- |
| 7.1 `cargo bench` does not run (queue overflow in warm-up) | ✅ | `iter_custom` bounded batches with untimed drains; suite completes; BENCHMARKS.md states figure provenance |
| 7.1 Benchmarked config disables three stages | ✅ | BENCHMARKS.md scope column names exactly what each figure covers |
| 7.3 ~9 durable syncs, ~30 IOPS/request | 🔶/✅ | EEXIST mkdirs eliminated (~5/request → 0); broker acks folded into per-session `{stem}.acks.ndjson` (2 fsyncs → 1, no per-request dir, no leftover file). **Deferred:** the batching writer (below) |
| 7.3 One session monopolises 1/16 capacity; shards hardcoded at 16 | 🔶/✅ | Shard count now `max(16, available_parallelism)`. **Deferred:** intra-shard cross-session concurrency (below) |
| 7.3 CPU-bound work inline, switch keys off the wrong thing | ✅ | Body-size-keyed blocking switch (16 KiB), not budget presence |
| 7.3 Unsigned sessions retain every turn in RAM (1.35 GB @ 10k) | ✅ | Steps spilled to the events journal (which already carried them); RAM keeps a counter; close rebuilds from disk |
| 7.3 Metric observations take two global mutexes | ✅ | `HotMetrics` pre-resolved handles; `AV_STRICT_BUDGET` read once at construction |
| 7.3 Quadratic compression blowups | ✅ | Incremental token counter in `stub_middle_to_target`; hash-map dedup in `collapse_duplicate_messages` |

## §8 Operability

| Finding | Status | Mechanism |
| --- | --- | --- |
| 8.1 Spool append-only forever, re-read every tick | ✅ | `atif_retention_days` pruning + O(1) steady-state scan + quarantine renames |
| 8.2 Restart re-adopts every closed session | ✅ | Close-complete markers; adoption skips finalized sessions; process-level SIGKILL/restart e2e proves idempotence |
| 8.3 `/health` is a constant | ✅ | `/livez` + `/readyz` with real readiness (spool writability probed at boot; fail-closed 503s) |
| 8.4 Missing seed silently mints a new trust anchor | ✅ | WARN with key id + path at generation; `avctl pubkey`; documented as a compliance incident |
| 8.5 Quarantine races an in-progress close | ✅ | Live-stem snapshot + `MIN_ORPHAN_AGE` clock-skew-safe gate (now in `QuarantineOrphanJsonPass`) |
| 8.6 Two replicas silently split the audit trail | ✅ | Exclusive spool lock (`.agentvisord.lock`): second daemon refuses to boot; OS releases on any exit; e2e proves all three properties |
| 8.7 No data-plane metrics, no gauge type | ✅ | Gauge type + request/stream/upstream metrics |
| 8.8 Drain budget hardcoded and exceeded by shipped configs | ✅ | `shutdown_drain_timeout_s` config |
| 8.9 SIGKILL mid-request bricks the session id | ✅ | Recovery quarantines with evidence; id recyclable after close-complete; restart e2e covers |
| 8.10 config_version / journal-version stranding invisible | ✅ | `av_journal_version_stranded_total` counter + per-branch warn-once |
| 8.10 Key rotation unoperationalized | ✅ | Multi-key `receipt-verify` (hex/base64), `avctl pubkey`, rotation runbook in OPERATIONS.md |
| 8.10 doctor blind to disk-full and compiled-out backends | ✅ | 4 KiB data-write probe; `unsupported_backend_requirements()` fails doctor AND config-validate AND daemon boot |
| 8.10 No agentvisord CLI | ✅ | Fail-closed args: `--config`, `--help`, `--version`; unrecognized args refuse to start |
| 8.10 Idle detection uses wall clock | ✅ | Monotonic `Instant` for the sweeper; wall clock kept for display |
| 8.10 Fatal startup errors bypass the structured logger | ✅ | Fatal errors route through `tracing::error!` JSON; exit 1 |
| 8.10 Bridge retention silently deletes at 30 days | ✅ | Boot warning when `cold_uri` unset; retention documented |
| 8.10 No sizing guidance | ✅ | K8s manifest sizing derivation comments + LIMITS.md numbers |

## §9 Documentation

| Finding | Status | Mechanism |
| --- | --- | --- |
| 9.1/9.2 Hero snippet 401s; no receipts by default; no pubkey path | ✅ | Static-key rule; wizard sets signed workflow; `avctl pubkey`; README quickstart tested end-to-end |
| 9.3 Error bodies break the JSON contract | ✅ | OpenAI error shape everywhere, including the body-limit 413 (names `max_request_bytes` + limit) |
| 9.4 Config-resolution order defeats the wizard | ✅ | Example file removed from the search path |
| 9.4 Doctor missing checkout-path checks | ✅ | Non-loopback listen, unsigned-workflow, dashboard-exposure warnings |
| 9.4 No config reference; env vars undocumented | ✅ | CONFIGURATION.md (every key + all env vars incl. `AV_SIGNING_SEED_FILE`) |
| 9.4 `avctl health` prints transport noise | ✅ | Connect failure names the fix (`avctl start`); timeout names the hang |
| 9.4 Feature flags invisible at install | ✅ | README install note; av-cli passthrough features; pre-flight refusals |
| 9.5 The five missing documents | ✅ | VERIFYING-A-RECEIPT.md, CONFIGURATION.md, OPENAI-COMPATIBILITY.md (now provider-dialect aware), OPERATIONS.md, LIMITS.md |

## §10 Testing and supply chain

| Finding | Status | Mechanism |
| --- | --- | --- |
| 10.2 Nothing ever runs agentvisord | ✅ | Process-level e2e: SIGKILL/restart idempotence, spool-outage fail-closed/recover, two-daemon lock |
| 10.2 No SSE frame split across chunks | ✅ | `sse_frame_split_across_chunks_reassembles_before_capture` |
| 10.2 Three vacuous crypto tests | ✅ | Typed error-variant assertions |
| 10.2 ENOSPC/EIO untested | ✅ | Unwritable-spool fault injection (recursive chmod) e2e |
| 10.2 Untested guards (JWKS bomb, cost overflow, `from_json_str`) | ✅ | Each has a dedicated test |
| 10.2 Two daemons on one spool untested | ✅ | Enforced + tested (see §8.6) |
| 10.3 Flaky wasm epoch test; backtrace-string assertion | ✅ | Work-based deadline / assertion narrowed to exit status |
| 10.4 Fuzzing absent | ✅ | Canonicalizer differential fuzz + SSE framer + `parse_provider_chunk` totality targets (idempotence asserted) |
| 10.5 StateStore contract drift (TTL, remove_prefix) | ✅ | One `state_store_contract()` invoked by both backends; `counter_ttl_secs` in the trait |

## Deferred — with rationale

| Item | Rationale |
| --- | --- |
| §7.3 group-commit batching writer (one fdatasync per batch per shard) | Per-event fsync measures p95 33 µs at 10k connections — well inside SLA. Batching couples unrelated sessions' completion latency and demands a crash-consistency proof over the batch window (which jobs' effects may be visible when). Revisit when profiling on production storage shows fsync at the top of the flame graph. The free halves are landed (mkdir elimination, ack-journal fold). |
| §7.3 intra-shard head-of-line blocking (one session stalls 1/16 of the id space) | Requires a per-session sub-queue scheduler inside each shard while preserving per-session ordering, drain semantics, and the shutdown budget. Aggregate throughput is CPU-bound long before this binds (§7.4); single-tenant latency under a pathological neighbor is the real cost. Design sketch belongs in STRUCTURAL-REFACTORS.md if multi-tenant latency SLOs arrive. |
