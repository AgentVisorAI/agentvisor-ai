# AgentBridge

AgentBridge is an inline Rust harness for OpenAI-compatible agent traffic and MCP tool calls. It applies identity, quota, policy, compression, and loop controls; emits OCSF-shaped events; writes ATIF v1.7 trajectories; and issues offline-verifiable Ed25519 receipts.

## Run locally

```bash
cargo run -p ab-harness --bin agent-bridge
```

The server reads `config/harness.example.toml` by default. Override it with `AB_CONFIG`. The example forwards chat requests to `http://host.docker.internal:4000` and listens on port 8484.

```bash
curl http://127.0.0.1:8484/health
curl http://127.0.0.1:8484/metrics
```

## Routes

- `POST /v1/chat/completions`: OpenAI-compatible streaming proxy.
- `POST /v1/mcp` and `POST /mcp`: JSON-RPC tool interception and optional forwarding.
- `POST /v1/sessions/{id}/close`: finalize a signed receipt or unsigned ATIF file.
- `POST /v1/sessions/{id}/promote`: issue a retroactive receipt for an ATIF trajectory.
- `GET /health`: liveness.
- `GET /metrics`: Prometheus text exposition.

Request headers:

- `X-AB-Session`: caller-selected header-safe id; UUIDv7 is generated when absent.
- `X-AB-Workflow`: `signed` or `unsigned`.
- `Authorization: Bearer <JWT>`: required when identity enforcement is enabled.

## CLI

```bash
cargo run -p ab-cli -- --help
cargo run -p ab-cli -- keygen --output config/signing.seed
cargo run -p ab-cli -- config-validate config/harness.example.toml
cargo run -p ab-cli -- manifest-validate manifests/bridge.example.yaml
cargo run -p ab-cli -- bridge-provision --manifest manifests/bridge.example.yaml --data-dir data/bridge
cargo run -p ab-cli -- atif-validate trajectory.json
cargo run -p ab-cli -- receipt-verify receipt.json --public-key-hex "$TRUSTED_ED25519_PUBLIC_KEY_HEX"
cargo run -p ab-cli -- loadgen --connections 500
```

When identity enforcement is enabled, pass `--bearer-token-file /path/to/token` to `session-promote` and `loadgen`, or set `AB_BEARER_TOKEN_FILE`. Token contents are never accepted as command-line values.

## Container deployment

```bash
docker secret create identity_hmac /path/to/identity-hmac-secret
docker compose -f docker/docker-compose.yml up --build
```

The external `identity_hmac` secret is required by the production profile. The reference stack contains AgentBridge, Redpanda, AOF-backed Redis, Qdrant, and Vector with an OTLP receiver. Bridge data, cold exports, Redis state, and Qdrant data use persistent volumes. The embedded Bridge remains available for single-binary and air-gapped deployments.

The production image checksum-pins `sentence-transformers/all-MiniLM-L6-v2` at revision `1110a243fdf4706b3f48f1d95db1a4f5529b4d41`, validates the model/tokenizer hashes during build, and selects the ONNX backend. Air-gapped builds can mirror those immutable URLs or mount equivalent verified artifacts and update the configured paths.

## Development gates

```bash
make ci
make test-all
make sla
```

See [ARCHITECTURE.md](ARCHITECTURE.md), [SECURITY.md](SECURITY.md), [EVOLUTION.md](EVOLUTION.md), and [BENCHMARKS.md](BENCHMARKS.md).

## Scope

The MVP intentionally excludes a web analytics UI, multi-region consensus, base-model training, and a general-purpose SFT/RL consumer.
