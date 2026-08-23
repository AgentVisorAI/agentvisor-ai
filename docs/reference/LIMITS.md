# Limits, Bounds, and Refusal Points

This document enumerates every hard limit the harness enforces. If
you're hitting one, the fix is almost always in
`docs/reference/CONFIGURATION.md` — but you need to know the ceiling
before you know the knob.

## Request sizes

| Limit | Default | Enforced at | Refusal |
| --- | --- | --- | --- |
| Request body bytes | 1 MiB (`max_request_bytes`) | Axum body limit middleware | `413 Payload Too Large` before parse |
| Provider response bytes captured | 16 MiB (`MAX_PROVIDER_CAPTURE_BYTES`) | `AbortFinalizingStream` | Stream abort + audit chain records truncation |
| Provider single-field bytes (message/reasoning) | 8 MiB (`MAX_PROVIDER_FIELD_BYTES`) | `absorb_frame` | Stream abort |
| Tool calls per response | 128 (`MAX_PROVIDER_TOOL_CALLS`) | `absorb_frame` | Stream abort |
| SSE frame bytes (single event) | 8 MiB | `parse_provider_chunk` | `Err("unterminated provider SSE frame exceeds limit")` |

## Session and identity

| Limit | Default | Notes |
| --- | --- | --- |
| Session id length | 128 UTF-8 code points | Longer ids are refused with 400. |
| Bearer TTL | provider-supplied | Tokens whose `exp` has passed are refused with 401 even if the JWKS still has the key. |
| Identity charter length | 256 UTF-8 code points | Longer are refused with 400. |
| Concurrent sessions per process | unbounded (RAM-limited) | Idle sweeper reaps at `session_idle_close_s`. |
| Concurrent worker slots | 1024 (16 shards × 64) | Additional concurrency queues in the request pipeline. |
| Concurrent response slots | 1024 | Backpressure surfaces as `av_events_dropped_total{stage="response_slot"}`. |

## Budgets

Budgets are two-ledger (session + optional principal). Each ledger
tracks four axes:

| Axis | Refill | Config key |
| --- | --- | --- |
| Tokens per minute | 60s sliding window | `per_min_tokens` |
| Tokens per hour | 3600s sliding window | `hourly_tokens` |
| Requests per minute | 60s sliding window | `per_min_requests` |
| Requests per hour | 3600s sliding window | `hourly_requests` |

* Both ledgers are checked **after** compression against
  `compression.tokens_after`. Compression runs at 50k prompt tokens
  with a floor of 512 tokens (see round 51 §6.3).
* **Backend counter TTL**: the Redis backend expires every budget
  counter after 24 hours of key inactivity (`counter_ttl_secs()` on
  the `StateStore` trait; logged at startup as
  `state_counter_ttl_s`). A session ACTIVE past that window has its
  budget silently reset — against Redis only; the in-memory backend
  never expires. Bound session lifetimes to the TTL or close/reopen
  long-running conversations.
* The principal ledger is checked FIRST; the session ledger is
  checked second. If the session refuses, the principal debit is
  refunded so a client rotating session ids can't drain the
  principal.
* On upstream failure, both ledgers are refunded.
* Refusal returns 429 with a `metadata.limit` field naming the axis
  and cap.

## Loop detection

Configured under `[breaker]`. Defaults:

| Knob | Default | Purpose |
| --- | --- | --- |
| `min_tokens_to_engage` | 512 | Below this the breaker never trips (avoids false positives on short responses). |
| `streak_threshold` | 3 | Consecutive duplicate steps to trip. |
| `open_action` | `Inject` | On trip: inject a corrective message. Alternative actions: `Reject` (429), `Abort` (client disconnect). |
| `cooldown_s` | 60 | How long the breaker stays open once tripped. |

Tuning these is deployment-specific; the defaults are what round 51's
tests exercised.

## Compression

| Knob | Default | Notes |
| --- | --- | --- |
| Engagement floor | 512 tokens | Requests smaller than this bypass compression entirely. |
| `summarize_middle` engagement | 50k prompt tokens | The stub-middle summarization only engages above this. |
| Content-hash duplicate window | current session's assembled prompt | O(n) via HashSet; round-32 F2 fix. |
| Stub target ratio | 50% | Middle is stubbed until `current_tokens` falls to half the pre-compression count. |

## Reconciler ceilings

| Limit | Default | Notes |
| --- | --- | --- |
| Orphan file bytes to read during recovery | 16 MiB (`MAX_ATIF_RECOVERY_BYTES`) | Larger files are refused with `av_atif_recovery_skipped_total{reason="too_large"}` and left in place for operator inspection. |
| Orphan age gate | 60s | Files newer than this are skipped this tick (defense against quarantining in-progress closes). |
| Live-session-stem check | on always | Sidecar-less .json files whose stem matches a currently-open session are skipped even if aged (round 51 §8.5). |
| Retention max sleep between prunes | 1 hour | Fixed. |
| Reconcile tick | `reconcile_tick_s` (5s) | Configurable. |

## Broker and Bridge

| Limit | Default | Notes |
| --- | --- | --- |
| Kafka payload | 1 MiB per record | Set by broker; the harness never emits records larger than 512 KiB. |
| NATS payload | 1 MiB per message | Set by broker. |
| Embedded Bridge partition file size | 1 GiB per segment | Rolled over automatically. |

## HTTP and TLS

| Limit | Default | Notes |
| --- | --- | --- |
| Concurrent HTTP/2 streams (server-side) | 128 | Hyper default. |
| Concurrent HTTP/2 streams (upstream) | 100 | Hyper default. |
| Client request read timeout | none | Rely on upstream to terminate stuck streams. |
| Upstream request read timeout | `upstream_read_timeout_s` | Unset = no bound; set this to your SLO. |

## Cryptography

| Property | Value |
| --- | --- |
| Signature scheme | Ed25519 (RFC 8032) |
| Verification | `verify_strict` — refuses low/mixed-order keys and non-canonical `s` scalars |
| Weak-seed refusal | `[0u8;32]` and `[0xffu8;32]` refused at seed load AND at `Keyring::add_key_bytes` (round 51 §3.1 H1) |
| Canonicalization | RFC 8785 JCS |
| Hash for `key_id` | Blake3, 128-bit truncation (16 bytes → 32 hex chars) |
| Hash for spool stems | SHA-256, 128-bit truncation (16 bytes → 32 hex chars) |
| Hash for content dedup during compression | Blake3, 64-bit truncation (`HashSet<u64>` keys) |

## Recovery guarantees

Under crash (SIGKILL) and restart, exactly-once semantics hold for:

* Signed receipts on the broker (idempotent adopt via journal).
* ATIF trajectories (idempotent adopt via `close-complete` marker).
* SESSION_CLOSE bridge events (idempotent adopt via `promote-*`
  markers; concurrent finalize is serialized via the per-session
  lifecycle lock).

Repeated restarts do NOT duplicate any of these; they DO extend the
window during which `av_atif_recovery_skipped_total{reason="unauthenticated"}`
ticks by 60s per orphan (the MIN_ORPHAN_AGE gate). This is
intentional (round 51 §8.5).

## Audit-fidelity notes

* **`n > 1` responses concatenate.** Multi-choice completions relay
  verbatim to the client, and tool-call deltas are keyed per choice
  in the audit record — but the recorded response *text* is the
  concatenation of every choice's content (round-51 §9.3). If your
  compliance story requires per-choice message attribution, use
  `n = 1` (the near-universal default).

## What the harness will NEVER limit

* Number of turns in a session — sessions are RAM-cost bounded but
  have no hard turn cap.
* Number of ATIF steps per session — bounded by
  `MAX_PROVIDER_CAPTURE_BYTES` × turn count, not by a counter.
* Model choice — the harness forwards `model` verbatim; the upstream
  decides which are supported.

If you want caps on any of the above, add them at the identity
scope layer (JWT claims → policy) or at an ingress layer above the
harness. Adding them to the harness would break the "cryptographic
audit of what actually happened" posture.
