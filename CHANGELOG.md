# Changelog

All notable changes are documented here. The project follows Semantic Versioning.

## Unreleased

Ahead of this release, a comprehensive third-party engineering review
(August 2026) covered the full codebase, deployment artifacts, and
documentation. All critical and high-severity findings were remediated,
and the headline security properties — offline receipt verification with
tamper and forgery refusal, and the documented SDK quickstart — are
exercised against release binaries in CI on every push
(`scripts/live-verify.sh`).

### Breaking changes

- **Rebrand: AgentBridge → AgentVisor AI.** The daemon is `agentvisord`
  (was `agentbridged`), the CLI is `avctl` (was `abctl`), and all twelve
  workspace crates are renamed `ab-*` → `av-*`. Wire and persisted
  surfaces changed with the brand: HTTP headers `X-AB-*` → `X-AV-*`,
  environment variables `AB_*` → `AV_*`, Prometheus metrics `ab_*` →
  `av_*`, the event-chain genesis domain tag (`av-genesis`), NATS
  JetStream stream names (`av_<topic>`), the cold-outbox HMAC domain,
  the Kafka dedupe header (`agentvisor-event-uid`), the OCSF product
  name (`agentvisor-ai`), and the default JWT audience (`agentvisor-ai`).
  Receipts, streams, and pending outbox intents produced by pre-rename
  builds do not carry over; nothing had been published, so no migration
  path is provided. Setup root is `~/.agentvisor/`; the systemd unit and
  Kubernetes manifest are renamed accordingly. `find_server_binary`
  still falls back to the legacy binary names for source-built installs.
- **Minimum supported Rust version raised to 1.94.**

### Security

- Receipt verification uses Ed25519 `verify_strict` everywhere, and key
  registration refuses small-order and known-weak public keys — closing
  a receipt-forgery vector in which a single signature could validate
  against multiple distinct receipt bodies.
- Receipts are now issued as `receipt_version = 2`, signed with domain
  separation (context tag + length framing); version 1 receipts continue
  to verify.
- Budget counters key on the authenticated principal rather than the
  caller-chosen `X-AV-Session` header, so a client cannot escape its
  budget by rotating session ids.
- Receipt, ATIF-trajectory, and chat-completion ingress refuse duplicate
  JSON keys at any nesting depth, explicit JSON `null` on optional
  receipt fields, and trailing content after a complete JSON document —
  eliminating "same signature, different bytes" and smuggled-document
  ambiguity between the proxy and downstream readers.
- Upstream credential headers are never relayed to clients: the response
  filter strips `Authorization` plus every well-known provider API-key
  header (`api-key`, `x-api-key`, `x-goog-api-key`, `anthropic-api-key`)
  and whatever header name the operator configured.
- Signing-seed handling hardened: known-weak seeds (all-zero, all-0xFF)
  are refused, seed material is zeroized in memory, and deployment
  templates move the seed out of shared volumes (Docker secret,
  Kubernetes Secret via init container, systemd path outside
  `ReadWritePaths`).
- Duplicate `X-AV-Session`, `X-AV-Workflow`, and `Authorization` headers
  are refused, preventing identity split-brain between the proxy and the
  upstream.
- JWKS ingestion hardened: 4 MiB body cap, 256-key cap, Ed25519 key
  material validated (base64url decode + 32-byte length) at load time,
  `use=enc` and non-EdDSA `alg` on Ed25519 keys refused, and locally
  added keys cannot shadow JWKS-tracked key ids.
- Bridge manifests refuse `..` path components in local `cold_uri`
  values (path escape, CWE-22), carry `deny_unknown_fields` plus numeric
  caps, and the YAML anchor-expansion ("billion laughs") guard now
  matches the anchor-name class the YAML parser actually accepts.
- The WASM policy sandbox caps memory instances, tables, table elements,
  and instances per module, so a hostile policy cannot exhaust host
  memory at instantiation or via `memory.grow`/`table.grow`.
- Broker credentials cannot cross plaintext: Kafka SASL and NATS
  user/password each force TLS, partial NATS credentials are refused
  loudly, and the S3 cold-store client honors only `AWS_*`-prefixed
  environment variables.
- A second daemon pointed at the same spool refuses to boot (exclusive
  advisory lock on `.agentvisord.lock`), preventing duplicate
  finalization and duplicate audit events.
- HTTP responses hardened: dashboard responses carry a strict CSP,
  `X-Frame-Options: DENY`, and `Referrer-Policy: no-referrer`; every
  mutating route answers cross-origin preflight with an explicit CORS
  deny; upstream-relayed responses carry `X-Content-Type-Options:
  nosniff`; `/health` no longer discloses the build version to
  unauthenticated callers.
- CLI output is sanitized against terminal-control injection, and
  `avctl doctor` redacts credentials and URL userinfo in all output,
  including error paths.

### Added

- **Provider adapters.** New `provider` config key selects the upstream
  wire dialect: `"openai"` (the default; also fits vLLM, LiteLLM, Groq,
  Together, DeepSeek, OpenRouter, Ollama, LM Studio, llama.cpp, xAI,
  Mistral, and Azure OpenAI), `"anthropic"`, and `"gemini"`. Each
  adapter is pinned by full-chain integration tests proving the audit
  chain records the same shape across dialects.
- **Health endpoints.** `/livez` (liveness, constant 200) and `/readyz`
  (readiness; 503 while draining or while the spool is unreadable) for
  Kubernetes-style probes.
- **`avctl pubkey`** derives the verifying public key from a signing
  seed, for offline receipt verification and key rotation.
- **`avctl receipt-locate`** maps a session id to its on-disk receipt
  and trajectory artifact paths, including quarantined variants.
- **`principal_budget`** config key: an optional budget layered on the
  validated identity, stable across session-id rotation. Refused-by-
  session refunds restore the principal ledger.
  `allow_anonymous_principal_budget` gates its use without identity
  validation (anonymous callers would share one key).
- **`atif_retention_days`** config key: an hourly sweep removes sealed
  ATIF trajectory pairs older than N days.
- **`shutdown_drain_timeout_s`** config key: the graceful-shutdown drain
  window, derived from `upstream_read_timeout_s` when unset so a live
  long request no longer outlasts the drain and fails the rollout.
  `0` is refused at config load.
- **`allow_wildcard_bind`** config key: explicit opt-in required to bind
  `0.0.0.0` without identity validation (the container image opts in and
  expects an ingress ACL).
- **`ignore_client_authorization`** config key: accepts and discards the
  `Authorization` header that stock OpenAI SDKs always send, so the
  documented quickstart works against a dev harness with no identity
  validator. The header is never forwarded upstream; refused in
  combination with `require_identity` or
  `upstream_authorization_passthrough`.
- **`AV_KAFKA_SASL_MECHANISM`**: SASL SCRAM support for Kafka
  (`SCRAM-SHA-256` default, `SCRAM-SHA-512`, or `PLAIN`), applied to
  both the event and admin paths.
- Kafka TLS/SASL (`AV_KAFKA_CA_FILE`, SASL credentials), NATS TLS/auth
  (`AV_NATS_CA_FILE`, `AV_NATS_USER`/`AV_NATS_PASSWORD`), and an
  S3-compatible cold tier (`cold-store-aws` feature, `s3://` targets),
  each validated against live backends (Redpanda, nats-server, MinIO)
  plus a live Redis Cluster contract test.
- crates.io publishing workflow: all workspace crates packaged and
  uploaded in dependency order on version tags, with a dry-run mode.

### Fixed

- Loop detection no longer produces false trips: tool-call-only turns
  (request and response side) synthesize text from the tool name and
  arguments instead of feeding an empty string to the embedder,
  multimodal message parts are read, embedding-backend outages fall back
  to a deterministic hash embedder rather than a zero vector, and
  recycled session ids no longer inherit a prior session's vectors in
  the Qdrant sink.
- Client disconnects are handled safely end to end: a dropped chat
  request resolves its response capture instead of stranding the session
  in permanent quarantine, a dropped `/promote` no longer wedges the
  promotion claim, and tool calls complete on a detached task so the
  budget and execution claim are not stranded.
- Budget accounting: the Redis backend implements per-session counter
  cleanup on close (cluster-safe), counters carry a 24-hour TTL so
  recycled session ids cannot inherit stale budgets, budget limits share
  one ceiling across in-memory and Redis backends, and best-effort
  refund or cleanup failures emit structured warnings instead of
  vanishing.
- Crash recovery hardened across many paths: newly created directories
  are fsynced up the ancestor chain, torn journals are quarantined
  rather than silently truncated, one bad artifact no longer aborts a
  whole recovery scan, recovered sessions restore their event sequence
  (no sequence-0 collisions), archived conflict markers can no longer
  re-trigger promotion, and tool-execution artifacts are removed in a
  crash-safe order.
- Bridge backends: multi-broker Kafka bootstrap lists connect on the
  event path, event-UID lookups page instead of timing out on large
  partitions, out-of-range Kafka offsets are refused instead of
  sign-wrapping to the wrong log position, corrupt records surface
  decode errors instead of silent offset gaps, NATS retries dedupe
  against the stream like Kafka does, the embedded bus fails closed when
  a retention rewrite leaves the writer on an unlinked file, and
  relative `cold_uri` values resolve correctly (the shipped example
  manifest is now portable outside the container).
- Error classification: permanent misconfiguration (for example an
  unprovisioned topic) returns HTTP 400 without `Retry-After`, while
  transient failures keep 503 + `Retry-After`; infrastructure faults
  during tool-execution claims return 503 with a budget refund instead
  of a misleading 409; non-JSON upstream error bodies propagate the true
  status and `Retry-After` instead of collapsing to 502.
- MCP endpoint conformance: non-`application/json` request Content-Type
  is rejected, and the upstream tool response's Content-Type round-trips
  through the outcome journal so cached replays are typed correctly.
- Idle-session tracking uses a monotonic clock, so wall-clock jumps (VM
  resume, NTP correction) no longer close active sessions mid-flight.
- Identity: delegation-chain scope narrowing uses the same wildcard
  semantics as runtime authorization, so a wildcard parent scope can
  delegate a narrower child scope.
- ATIF validation: strict validation runs on raw bytes (duplicate keys
  and unknown fields caught before typed parsing drops them), dangling
  `subagent_trajectory_ref` ids are refused, type checks cover all
  schema-declared string fields, and the Rust strict validator and the
  shipped JSON Schema are held in agreement by a shared test corpus.
- Event validation: JCS-unsafe integers (above 2^53) and cross-wired
  `stop_reason`/`stop_reason_id` pairs are refused on both the build and
  deserialize paths; `pruning_ratio_millis` is range-checked in both.
- Config validation catches more misconfiguration at load: empty or
  contradictory secret sources, `max_request_bytes = 0`, per-member
  scheme checks on comma-separated endpoint lists (including
  `redis+unix:`), and conflicting identity flags.
- `avctl doctor` matches runtime behavior: secret files are checked with
  the same permissions/content rules the daemon enforces, the signing
  seed is probed at the path the daemon actually uses, and Unix-socket
  and multi-endpoint bootstrap forms probe correctly.
- Metrics accuracy: sign/finalize latency histograms record on failure
  paths as well as success, and duplicate metric families share one
  HELP string.

### Performance

- Group commit on the durability path: a same-session backlog appends N
  records under a single fdatasync, broker acknowledgments fold into a
  per-session journal, and redundant mkdir calls (~5 per request) are
  eliminated — while preserving the invariant that no job's effects are
  visible before its record is durable.
- Worker shards are dispatchers over per-session FIFO queues: up to
  eight sessions per shard progress concurrently with strict per-session
  ordering, removing head-of-line blocking between sessions.
- ATIF steps spill to the events journal instead of accumulating in RAM;
  memory per session is now O(1) (previously up to ~1.35 GB for large
  sessions), rebuilt from disk at close.
- Prompt-compression passes reduced from O(n²) to O(n) in both work and
  allocation on large payloads.
- A 60-second upstream read-timeout floor applies unconditionally, so a
  hung upstream cannot pin session leases and worker permits
  indefinitely.

### Operability

- Graceful shutdown drains in-flight requests within the configured
  window (`/readyz` flips to 503 at SIGTERM), and restart behavior is
  covered by process-level tests (kill/restart idempotence, spool-outage
  fail-closed-then-recover, second-daemon lock refusal).
- Untrusted inputs are size-capped everywhere: receipts at 16 MiB, ATIF
  documents at 64 MiB, control/marker files at 1 MiB, with capped reads
  on every CLI and reconciler path.
- Deployment templates hardened: no Docker socket mount, restart
  policies and persistent volumes for brokers, `cap_drop`/`pids_limit`/
  seccomp defaults, durable ATIF spool on the Kubernetes PVC, and
  systemd stop/restart limits aligned with the drain window.
- Validation errors, quarantine events, and best-effort cleanup failures
  emit structured, bounded diagnostics (first 16 issues + total; no
  unbounded log storms from repeated bad artifacts).

### Documentation

- Added an interactive product console (`docs/app/`, published at
  `/app/` on the site): a self-contained client-side simulation of the
  full operator flow — setup wizard, one-line integration, a live
  session with budget refusals and a loop-breaker trip, the fleet
  dashboard, offline receipt verification, and the on-disk evidence
  layout. Content is display-only and mirrors the shipped surfaces
  (config keys, `avctl` commands, HTTP status semantics, and the
  receipt v2 schema). A captioned guided tour is available behind
  `?tour=1`.
- Corrected `docs/reference/LIMITS.md`: budget refusals return 403 —
  deliberately not 429, which mainstream SDKs auto-retry — matching
  `PipelineError::status`. The doc previously claimed 429 with a
  `metadata.limit` field that does not exist.
- Reference documentation expanded for operators: configuration
  reference, operations guide (probes, drain, key rotation), offline
  receipt verification walkthrough, spool-and-recovery semantics, and
  limits.
- Architecture documentation corrected to describe the actual durability
  model (local durable markers plus asynchronous broker publication).
- Known limitations documented: budget-spend idempotency across Redis
  connection drops, the bounded shutdown drain, and best-effort refund
  semantics.
- Removed internal planning and review-tracking documents (PLAN.md,
  docs/reference/REVIEW-51-REMEDIATION.md,
  docs/reference/STRUCTURAL-REFACTORS.md) from the repository; reference
  documentation under docs/reference/ is now exclusively operator- and
  developer-facing.

### Dependencies

- `ed25519-dalek` 3.0 with the `zeroize` feature (strict verification,
  seed zeroization).
- `jsonwebtoken` upgraded to 11.0, closing CVE-2026-25537 (`nbf`/`exp`
  string-type-confusion validation bypass).
- `h2` bumped to a patched release, closing RUSTSEC-2026-0258.
- `rskafka` 0.5 → 0.6, moving the Kafka event path to rustls 0.23 and
  dropping the EOL rustls 0.21 line (RUSTSEC-2026-0098,
  RUSTSEC-2025-0134); brings native SASL SCRAM support.
- `object_store` 0.12 → 0.14, closing the quick-xml unbounded-allocation
  advisory.
- `wasmtime` 47.0.3 → 47.0.4, closing RUSTSEC-2026-0269 (filesystem
  sandbox escape via trailing-slash paths/symlinks, high) and
  RUSTSEC-2026-0268 (guest-controlled host heap allocation through
  WASIp3 streams); yanked `chacha20` 0.10.1 replaced with 0.10.2 in
  both lockfiles.
- Known accepted advisory: RUSTSEC-2023-0071 (`rsa`, Marvin timing
  side-channel) enters the tree transitively via `jsonwebtoken`; the JWT
  validator accepts only EdDSA and HS256, so the RSA code path is
  unreachable. Documented in `deny.toml` and mirrored in
  `.cargo/audit.toml` so plain `cargo audit` runs reach the same verdict.
- CI supply chain: every third-party GitHub Action pinned to a commit
  SHA; Python helper dependencies pinned exactly with their transitive
  closure.

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
