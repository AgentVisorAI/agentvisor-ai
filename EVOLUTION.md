# Evolution Policy

## Compatibility

AgentVisor AI follows inbound-tolerant, outbound-current behavior:

- OCSF events preserve unknown inbound fields and emit metadata version 1.10.0.
- ATIF accepts v1.0 through v1.7 and always writes v1.7.
- Receipts carry `receipt_version`.
- Bridge manifests carry `manifest_version`.
- Harness configuration carries `config_version` and tolerates additive unknown fields.

Breaking wire-format changes require a major version or a new explicit format version. Additive fields remain optional for older readers.

## Stable boundaries

Backends evolve through `EventBus`, `StateStore`, `Embedder`, `VectorSink`, `Signer`, and `PolicyEngine`. New connectors must satisfy the same contract tests before becoming selectable in configuration.

## Key rotation

Receipts embed a derived key id and public key. Verifiers may retain multiple public keys. Rotating the active signer does not invalidate old receipts.

## Schema changes

Schema changes require:

1. Updated JSON Schema.
2. Golden or conformance tests for old and new input.
3. A changelog entry.
4. Migration notes when strict validation behavior changes.

The optional OCSF inventory fingerprint uses SHA-256 over JCS and can chain `prev_inventory` without changing receipt semantics.
