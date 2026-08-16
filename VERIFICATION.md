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
- Release core SLA: pass using production-route and HTTP-level timing; optional durable admission reported separately.
- Release 10,000-stream production-feature gate with live Kafka/Redis environment: pass.

## Environment Limits

Real cloud object-store credentials and an external upstream OCSF conformance service were not available locally. The local production image and live single-node Kafka, Redis, NATS, Qdrant, MiniLM, and Harbor paths were executed.

Closed on 2026-08-15 (previously listed here as untested):

- **Redis Cluster topology** — a live 3-master cluster (redis 8, ports 7000-7002) passed the `AV_REDIS_URL` contract suite, including a new multi-key `try_spend_many` test using the production `budget:{hash-tag}:` key shape (proves CROSSSLOT safety on a real slot map, plus cross-key atomicity of a refused spend).
- **S3-compatible cold tier** — the two-phase cold export (staged intent → conditional `PutMode::Create` put → idempotent re-put) passed live against MinIO via the new `AV_COLD_S3_URL`-gated contract; the object landed with the deterministic `topic/pN/offset.json` key. Standard `AWS_*` env credentials are now honored (keys are lowercased before `object_store::parse_url_opts`, which only parses lowercase config names).
- **Broker TLS/SASL** — the Kafka connector now reads `AV_KAFKA_CA_FILE` + `AV_KAFKA_SASL_USERNAME`/`AV_KAFKA_SASL_PASSWORD` (SASL/PLAIN, refused without TLS) on both the rskafka event path and the librdkafka admin path; the live contract passed against Redpanda with a `sasl`-authenticated TLS listener (private CA), an unauthenticated client was rejected by the broker, credentials-without-CA was refused client-side, and the plaintext path is regression-tested unchanged. The NATS connector reads `AV_NATS_CA_FILE` + `AV_NATS_USER`/`AV_NATS_PASSWORD`; the live contract passed over `tls://` against nats-server with TLS + user/password required.
