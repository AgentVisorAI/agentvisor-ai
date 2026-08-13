# Architecture

## Request flow

```mermaid
flowchart LR
    A[Agent] --> H[Axum Harness]
    H --> I[NHI validation]
    I --> Q[Atomic quota]
    Q --> P[WASM and schema policy]
    P --> C[Context compression]
    C --> W[Reserved audit worker]
    W --> J[Authenticated fsynced journal]
    J --> B[Embedded, Redpanda, or NATS Bridge]
    B --> U[Upstream provider]
    U --> H
    H -. bounded framed response capture .-> W
    W --> L[Loop breaker]
    W --> V[Qdrant similarity or local window]
    W --> E[OCSF event]
    E --> B
    W --> T[ATIF trajectory or signed event chain]
    T --> R[Finalizer, lifecycle outbox, receipt]
```

Production routes reserve bounded worker capacity before mutating quotas. Chat and MCP effects wait until their request or authorization event is journaled and published; synchronous quota, WASM, and compression work runs on Tokio's blocking pool. Provider responses have a pre-reserved capture slot. Non-SSE responses are bounded and validated before delivery; SSE uses a bounded byte-oriented decoder.

Receipt signing and ATIF serialization remain off the request path. Worker overload fails before quota mutation and is counted in `ab_events_dropped_total`.

## Crates

- `ab-core`: identifiers, time, token estimates, digests, metrics.
- `ab-events`: OCSF agent event model and validation.
- `ab-atif`: ATIF v1.0-v1.7 reader, strict v1.7 writer, atomic persistence.
- `ab-receipts`: RFC 8785 canonicalization, hash chains, Ed25519 receipts.
- `ab-state`: atomic counters and multi-dimensional budgets, memory and Redis.
- `ab-bridge`: EventBus, embedded log, Kafka/Redpanda, NATS JetStream.
- `ab-identity`: EdDSA/HS256 NHI validation, delegation, JWKS refresh.
- `ab-compress`: auditable, idempotent context reduction.
- `ab-loopdetect`: hash or ONNX embeddings, circuit breaker, Qdrant sink.
- `ab-sandbox`: JSON-RPC parsing, JSON Schema, native and WASM policy.
- `ab-harness`: proxy, routes, workers, sessions, reconciliation.
- `ab-cli`: operational commands and load generation.

## Session lifecycle

A session is opened on first use and assigned `signed` or `unsigned` once. Close first blocks new work, drains accepted worker jobs, then:

- Signed: verifies the authenticated event journal, snapshots the event-chain head, and signs one receipt in `spawn_blocking`.
- Unsigned: snapshots, validates, atomically writes, and parent-fsyncs ATIF v1.7 without consuming retry state.
- Promotion: validates persisted ATIF, hashes it, and signs one idempotent retroactive receipt.
- Receipt and close events use deterministic fsynced outboxes with persisted broker acknowledgments.

Tool forwarding holds a session lease through bounded response capture and completion auditing. JSON-RPC ids back durable execution claims; uncertain crash outcomes are never re-executed automatically. Shutdown bounds HTTP drain, worker drain, and OTLP flush independently.

## Portability

The manifest declares topics, partitions, retention, cold storage, and JSON Schema references. Embedded provisioning copies and compiles referenced schemas. Kafka verifies partitions and `retention.ms`; NATS configures stream age. Cold writes use deterministic object keys plus a local durable retry outbox, independently of broker acknowledgment.
