# Evolution Policy

## Compatibility

AgentVisor AI follows inbound-tolerant, outbound-current behavior:

- OCSF events preserve unknown inbound fields and emit metadata version 1.10.0.
- ATIF accepts v1.0 through v1.7 and always writes v1.7.
- Receipts carry `receipt_version`.
- Bridge manifests carry `manifest_version`.
- Harness configuration carries `config_version` and **rejects unknown keys** (`deny_unknown_fields` — a typo must fail at boot, not silently disable a control). Forward compatibility is handled by `config_version` gating, not by tolerating unrecognized keys.

Breaking wire-format changes require a major version or a new explicit format version. Additive fields remain optional for older readers.

## Stable boundaries

Backends evolve through `EventBus`, `StateStore`, `Embedder`, `VectorSink`, `Signer`, and `PolicyEngine`. New connectors must satisfy the same contract tests before becoming selectable in configuration — see `crates/av-state/src/lib.rs::state_store_contract` (round-51 §10.5: consumed by both the `InMemoryStore` and `RedisStore` suites so a divergence cannot silently ship) and the analogous `embedded_contract` / `live_contract` fixtures in `av-bridge`.

## Key rotation

Receipts embed a derived key id and public key. Verifiers may retain multiple public keys. Rotating the active signer does not invalidate old receipts.

Operational protocol (§8.10 was previously an unoperationalized claim): the [`OPERATIONS.md#key-rotation`](docs/reference/OPERATIONS.md) runbook drives the rollover with `avctl pubkey` (extracts the public key of a running deployment) and `avctl receipt-verify --public-key-hex <hex> [--public-key-hex <old>]…` (accepts multiple keys, pin every historical trust anchor an auditor may see). Receipts carry their `key_id`; `av-receipts::Keyring` fingerprints and dispatches automatically.

## Schema changes

Schema changes require:

1. Updated JSON Schema.
2. Golden or conformance tests for old and new input.
3. A changelog entry.
4. Migration notes when strict validation behavior changes.

The optional OCSF inventory fingerprint uses SHA-256 over JCS and can chain `prev_inventory` without changing receipt semantics.
