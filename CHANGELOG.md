# Changelog

All notable changes are documented here. The project follows Semantic Versioning.

## Unreleased

Post-0.1.0 hardening across rounds 11–19 of a systematic bug audit.
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
