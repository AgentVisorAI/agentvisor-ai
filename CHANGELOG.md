# Changelog

All notable changes are documented here. The project follows Semantic Versioning.

## Unreleased

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
