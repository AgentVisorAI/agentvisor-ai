# Benchmarks

Measured on 2026-08-11 on Apple Silicon macOS with Rust 1.97.1. Results are release-mode acceptance evidence for this machine, not cross-machine promises.

## Results

| Criterion | Target | Result | Scope |
| --- | ---: | ---: | --- |
| Production signed admission | p95 <= 5 ms, p99 <= 8 ms | p95 33 us, p99 62 us | Actual async route wrapper: identity, quota, policy, compression, and two bounded audit reservations |
| Optional durable admission diagnostic | not an original async-path target | p95 78.447 ms, p99 98.378 ms | Explicit `prepare_chat_durable`; not used by the production route |
| Loop interruption | 100% within 3 cycles | 20/20 loop families; 0/10 progressing sessions tripped | Both deterministic tests and the pinned MiniLM ONNX model pass |
| MCP denial | < 5 ms | p99 54 us | Actual HTTP route with shipped schema and WAT policy |
| Context reduction | >= 30% at >= 50k tokens | Pass | Duplicate-heavy and unique histories; tail preserved |
| Event enqueue | p99 <= 0.5 ms | p99 5 us | Global bounded reservation/submission; broker I/O remains off-path |
| Ed25519 receipt signing | < 2 ms | p99 histogram bucket 250 us | Signing occurs only in close/promotion tasks |
| Retroactive receipt | <= 60 s | 29 ms | Strict ATIF validation, persistence, signing |
| Manifest-only embedded Bridge provision | < 15 min | 31 ms | Six schema-bound topics |
| Concurrent streaming connections | 10,000 | Pass; p95 0.865 ms, p99 1.742 ms | 10,000 client and upstream streams with production features and live Kafka/Redis environment |

The final 10,000-stream run printed `completed_ms=858` and completed in 3.72 s. It used the production 32,768 global audit capacity, 16 session-ordered shards, all production features, and live Kafka/Redis endpoints. The fixture's token ceiling is unlimited, so it does not make a 10,000-way Redis quota-round-trip claim.

## Other Evidence

- A real HTTP request/response trajectory passed Harbor's pinned v1.7 validator.
- A live local OTLP/HTTP receiver accepted a 1,244-byte `/v1/traces` protobuf batch after graceful SIGTERM.
- Live Kafka, NATS, Redis, and Qdrant contracts passed together. Qdrant stored and retrieved an actual 384-dimensional MiniLM vector.
- The checksum-pinned MiniLM model passed all 20 loop families within three cycles and produced no false trip across 10 progressing sessions.
- The production container built successfully, validated its in-image config, and contained no project seed/key material.

## Commands

```bash
cargo test -p av-harness --release --features full --test sla sla_core_metrics -- --ignored --nocapture

ulimit -n 65536
RUN_HEAVY_PERF=1 AV_SLA_CONNECTIONS=10000 AV_SLA_ARRIVAL_TIMEOUT_S=900 \
	cargo test -p av-harness --release --features full --test sla \
	sla_10k_streaming_connections -- --ignored --nocapture
```
