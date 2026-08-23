# AgentVisor AI Verification

Verified against `AgentBridge.docx` v2.0 on 2026-08-11 with Rust 1.97.1 on Apple Silicon macOS.

## Verdict

The functional MVP is implemented and the executable local correctness gates pass. The production route uses bounded nonblocking audit reservation and authenticates request/terminal response attempt pairs in the active journal, so crash recovery quarantines incomplete sessions without adding journal or broker fsync to admission.

## Requirement Status

| Surface | Status | Evidence or limitation |
| --- | --- | --- |
| Signed 5 ms latency | Pass | Actual production wrapper p95 33 us, p99 62 us; 10k p95 0.865 ms, p99 1.742 ms |
| Heavy work isolation | Pass | 16 session-ordered shards, global capacity, blocking-pool ONNX/broker work, async stream budget state |
| Loop detection | Pass | 20/20 loop families trip within three cycles; 0/10 progressing sessions trip; response-side analysis and Qdrant search are wired |
| MCP sandbox and effects | Pass | HTTP denial p99 54 us; parse/schema/WASM/budget gates, exact-request HMAC intent, no redirects, at-most-once outcome cache |
| Context compression | Pass | >=30% tests at >=50k estimated tokens; first system and tail invariants |
| NHI identity | Pass | Adversarial JWT/delegation suite, issuer/scope/TTL binding, retired JWKS removal |
| OCSF event profile | Pass | Every class validates; identity and normalized stop state are present |
| Inventory fingerprint | Roadmap | Model/schema shape exists; DOCX labels per-forward inventory as roadmap, not MVP |
| Portable Bridge | Pass locally | Embedded ordering/recovery plus live Kafka/NATS provisioning and replay contracts, including TLS+SASL Kafka and TLS+auth NATS endpoints |
| Retention and cold tier | Pass locally | Manifest retention/replication, authenticated pre-ack cold intents, conditional objects; live S3-compatible export verified against MinIO (`AV_COLD_S3_URL` contract) |
| Receipts | Pass | RFC 8785 vectors, trusted-key CLI verification, signer-pinned recovery, authenticated journals/outboxes |
| ATIF v1.7 | Pass | Strict/golden tests, retry-safe parent-fsynced writer, recovered accounting/TTL, real HTTP trajectory accepted by Harbor |
| Required runtime stack | Pass locally | Pinned MiniLM runs in tract, passes loop SLA, and feeds live Qdrant; live Redis/Kafka/NATS contracts pass, including a 3-master Redis Cluster (multi-key atomic budget spend on a real slot map) |
| OTLP/Vector | Pass locally | Real server emitted a nonempty 1,244-byte OTLP trace batch and flushed on SIGTERM |
| 10,000 connections | Pass | 10,000 active client/upstream streams; p95 0.865 ms, p99 1.742 ms; details in BENCHMARKS.md |
| Non-goals | Pass | No UI, multi-region consensus, model training, or general SFT/RL consumer |

## Executed Gates

- Rust formatting: pass.
- Strict all-target, all-feature clippy with warnings denied: pass.
- Default workspace test matrix: pass.
- All-feature workspace test matrix: pass, including 64-agent contention; endpoint-gated live tests only count as live when their environment variables are set.
- Warning-denied all-feature rustdoc: pass.
- JSON schemas, example TOML, and Bridge manifest: pass.
- Compose rendering: pass.
- Harbor pinned reference validator over a real HTTP harness trajectory: pass.
- Live crash-recovery (2026-08-16): release daemon on live Kafka + Redis SIGKILLed mid-load (300 sessions in flight); restart quarantined all 300 incomplete sessions, served fresh traffic with zero failures, and a second SIGKILL + restart re-quarantined the same set idempotently (no duplication, no re-execution, zero ERROR lines). Reproducible artifact (round-51 §11 — attestations need pointers): the same SIGKILL→restart→SIGKILL→restart idempotence property is now pinned in CI by `crates/av-harness/tests/e2e_process_restart.rs` (`sigkill_restart_recovers_and_is_idempotent`, plus the spool-outage and two-daemon-lock siblings), which spawns the real `agentvisord` binary; the live-brokers variant remains an operator attestation.
- Offline receipt verification (2026-08-16): a receipt produced by the crash-recovered daemon, consumed from the live Kafka `agent.receipt` topic, verified offline via `avctl receipt-verify` with the independently extracted public key; a single-byte tamper was rejected. Reproducible artifact (round-51 §11): `scripts/live-verify.sh` runs the same chain — hero snippet → close → promote → `avctl pubkey` extraction → offline verify → tamper refusal — plus the §3.1 forgery PoC (identity-point public key + small-order signature refused at `add_key_bytes`), against release binaries with a scripted mock upstream, in ~2 seconds. Six live checks; no live broker required.
- Release core SLA: pass using production-route and HTTP-level timing; optional durable admission reported separately.
- Release 10,000-stream production-feature gate with live Kafka/Redis environment: pass.

## Environment Limits

Real cloud object-store credentials and an external upstream OCSF conformance service were not available locally. The local production image and live single-node Kafka, Redis, NATS, Qdrant, MiniLM, and Harbor paths were executed.

Closed on 2026-08-15 (previously listed here as untested):

Round-51 §11 (attestations need pointers): the S3 cold-tier row runs
in CI on every push (`cold_store_live.rs` against the compose MinIO —
see the CI workflow's contract step), so its evidence is the CI run
for any given commit. The Redis Cluster and broker TLS/SASL rows
remain point-in-time operator attestations: their gated contract
suites (`redis_contract.rs` under a cluster `AV_REDIS_URL`;
`live_contract.rs` under TLS/SASL env) are in-tree and re-runnable,
but CI provisions single-node/plaintext services, so re-attestation
requires the topology described in each row.

- **Redis Cluster topology** — a live 3-master cluster (redis 8, ports 7000-7002) passed the `AV_REDIS_URL` contract suite, including a new multi-key `try_spend_many` test using the production `budget:{hash-tag}:` key shape (proves CROSSSLOT safety on a real slot map, plus cross-key atomicity of a refused spend).
- **S3-compatible cold tier** — the two-phase cold export (staged intent → conditional `PutMode::Create` put → idempotent re-put) passed live against MinIO via the new `AV_COLD_S3_URL`-gated contract; the object landed with the deterministic `topic/pN/offset.json` key. Standard `AWS_*` env credentials are now honored (keys are lowercased before `object_store::parse_url_opts`, which only parses lowercase config names).
- **Broker TLS/SASL** — the Kafka connector now reads `AV_KAFKA_CA_FILE` + `AV_KAFKA_SASL_USERNAME`/`AV_KAFKA_SASL_PASSWORD` (mechanism via `AV_KAFKA_SASL_MECHANISM`: `SCRAM-SHA-256` default, `SCRAM-SHA-512`, or `PLAIN` — upgraded from PLAIN-only on 2026-08-16 with rskafka 0.6/rustls 0.23; credentials refused without TLS) on both the rskafka event path and the librdkafka admin path; the live contract passed against Redpanda with a `sasl`-authenticated TLS listener (private CA) for SCRAM-SHA-256 and PLAIN, an unauthenticated client was rejected by the broker, credentials-without-CA was refused client-side, and the plaintext path is regression-tested unchanged. The NATS connector reads `AV_NATS_CA_FILE` + `AV_NATS_USER`/`AV_NATS_PASSWORD`; the live contract passed over `tls://` against nats-server with TLS + user/password required.

## Receipt Verification Protocol (independent implementation)

README and the project site link here for "verifying a receipt from
scratch". The following is the complete, normative recipe an
independent verifier must implement — no AgentVisor code required. A
receipt is a single JSON object; the reference implementation is
`crates/av-receipts/src/receipt.rs` (`Receipt::verify`) and the CLI
wrapper is `avctl receipt-verify <file> --public-key-hex <64-hex>`.

### Inputs

- The receipt bytes (UTF-8 JSON).
- The trusted Ed25519 public key (32 bytes), obtained out of band —
  e.g. from the operator's key distribution, NOT from the receipt
  itself (the embedded copy is cross-checked, never trusted alone).

### Steps

1. **Strict parse.** Reject the document if any JSON object at ANY
   nesting level contains a duplicate key (serde/JS parsers silently
   keep one — a signed duplicate is evidence-splitting), if any field
   carries an explicit JSON `null` (absent options are omitted, never
   null), if nesting reaches depth 128 (127 levels parse; 128 is
   refused), or if the top level contains any key outside
   this exact set: `receipt_version`, `receipt_id`, `session_id`,
   `issued_at`, `issued_at_iso`, `ai_agent`, `subject`, `tool_calls`,
   `cost`, `stop_reason_id`, `stop_reason`, `key_id`,
   `public_key_b64`, `signature_b64`.
2. **Semantic invariants.** `receipt_version` must be `1`.
   `ai_agent.charter.type_id` must be `1` (OCSF Regular File). When
   `subject.kind == "atif_trajectory"`, `subject.retroactive` must be
   `true` and `subject.trajectory_digest` must be exactly 64 lowercase
   hex characters; when `subject.kind == "event_chain"`,
   `subject.chain_head` must be exactly 64 lowercase hex characters.
   `issued_at_iso` must equal the RFC 3339 UTC rendering of
   `issued_at` (epoch milliseconds) with exactly millisecond precision
   and a `Z` suffix (e.g. `1970-01-01T00:00:00.000Z`). When
   `stop_reason_id` names a known reason, `stop_reason` must not be
   the canonical caption of a *different* known reason (provider-native
   free-text captions are permitted; cross-wired canonical captions
   are refused).
3. **Key binding.** Base64-decode `public_key_b64` (standard alphabet,
   padded); it must be exactly 32 bytes and a valid Ed25519 point.
   Compute `SHA-256(public_key_bytes)`; the first 32 lowercase hex
   characters must equal `key_id`. The key bytes must ALSO equal your
   independently trusted public key — a receipt that binds
   consistently to an attacker's key is consistent, not trustworthy.
4. **Canonical bytes.** Remove `signature_b64` from the object. The
   remaining 13 fields are the signed body. Serialize it with
   RFC 8785 (JCS): objects sorted by UTF-16 code units, no
   whitespace, shortest-round-trip number rendering, integers
   restricted to |n| ≤ 2^53. The signed message is the UTF-8 bytes of
   that canonical form.
5. **Signature.** Base64-decode `signature_b64` (64 bytes) and verify
   with Ed25519 in **strict** mode (reject small-order components and
   non-canonical scalars — RFC 8032 `verify` alone admits malleable
   encodings; the reference uses ed25519-dalek `verify_strict`).

Any step failing means the receipt does not attest anything. For
`subject.kind == "atif_trajectory"`, additionally compare
`subject.trajectory_digest` against `SHA-256(file bytes)` of the ATIF
artifact you hold; for `subject.kind == "event_chain"`, the
`chain_head`/`event_count` bind the OCSF event-chain replay. The chain
construction is: `h0 = SHA-256("av-genesis" || session_id)`,
`h(i) = SHA-256(h(i-1) || JCS(event_i))` with events ordered by
`metadata.sequence`; `chain_head` is the final hash rendered as
lowercase hex and `event_count` the number of events folded in.
