# AgentBridge

[![CI](https://github.com/AgentVisorAI/agent-bridge/actions/workflows/ci.yml/badge.svg)](https://github.com/AgentVisorAI/agent-bridge/actions/workflows/ci.yml)
[![Supply chain](https://github.com/AgentVisorAI/agent-bridge/actions/workflows/deny.yml/badge.svg)](https://github.com/AgentVisorAI/agent-bridge/actions/workflows/deny.yml)
[![Docs](https://github.com/AgentVisorAI/agent-bridge/actions/workflows/pages.yml/badge.svg)](https://agentvisorai.github.io/agent-bridge/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**AI agents you can hand to an auditor.**

AgentBridge is a small Rust server you drop in front of your agent's
LLM and tool calls. Every request is recorded, every limit you set is
enforced before the call goes out, and every session ends with a signed
receipt anyone can verify offline with just a public key. Change one
line in your OpenAI client. Nothing else in your app moves.

```python
client = OpenAI(
    api_key=os.environ["OPENAI_API_KEY"],
    base_url="http://127.0.0.1:8484/v1",   # <-- the only change
)
```

- **[Landing page](https://agentvisorai.github.io/agent-bridge/)** — the story, in
  three concrete examples.
- **[Releases](https://github.com/AgentVisorAI/agent-bridge/releases)** —
  pre-built binaries with SHA-256 checksums.
- **[Security model](SECURITY.md)** — trust boundaries, controls, and how
  to deploy safely. Report vulnerabilities privately via the
  [advisory form](https://github.com/AgentVisorAI/agent-bridge/security/advisories/new).
- **[Architecture](ARCHITECTURE.md)** · **[Benchmarks](BENCHMARKS.md)** ·
  **[Verification protocol](VERIFICATION.md)** — going deeper.
- **[API docs](https://agentvisorai.github.io/agent-bridge/api/)** — Rust crate
  reference. Skip unless you're embedding AgentBridge as a library.

---

## Easiest start (no config, no exports)

```bash
cargo install ab-harness ab-cli    # installs `agentbridged` + `abctl` binaries
abctl
```

> The two crates land on crates.io from `v0.1.0` onwards; until that
> release is published, use the `--path` variants shown in
> [Install from source](#install-from-source) below.

Bare `abctl` launches a guided setup: pick your AI provider from a
numbered list, paste your API key once (typed hidden, stored
owner-only under `~/.agentbridge/keys/`), and it writes
`~/.agentbridge/agentbridge.toml` for you. Answer "yes" at the end —
or run `abctl start` later — and AgentBridge is running with a
friendly banner telling you exactly what URL to paste into your app.
`Ctrl-C` stops it cleanly. No files to edit, no environment
variables, no terminal knowledge beyond typing a number.

## 60-second start

Pick the row that matches your provider, then run two commands.

```bash
cargo install ab-harness ab-cli    # or see "Install from source" below
```

```bash
abctl init --preset openai     # writes agentbridge.toml + prints next steps
export OPENAI_API_KEY=sk-...
agentbridged                   # http://127.0.0.1:8484
```

Point any OpenAI-compatible SDK at `http://127.0.0.1:8484/v1` and use it as normal. Receipts, events, and trajectories appear under `data/`.

No config file at all also works — built-in defaults plus one env var:

```bash
AB_UPSTREAM_URL=http://127.0.0.1:11434 agentbridged   # e.g. Ollama
```

### Install from source

Cloning the repo works too — useful for development, or before the
first crates.io release lands:

```bash
git clone https://github.com/AgentVisorAI/agent-bridge && cd agent-bridge
cargo install --path crates/ab-harness   # installs `agentbridged`
cargo install --path crates/ab-cli       # installs `abctl`
```

### Why the binary is `agentbridged`, not `agent-bridge`

The name `agent-bridge` on crates.io is taken by an unrelated
project (a Codex/Claude/Gemini CLI). To avoid collision, our server
binary is `agentbridged` (daemon suffix, `d`) and the crate is
`ab-harness`. The `abctl` CLI is unchanged and lives in `ab-cli`.

### Provider presets

| Preset | Endpoint | Key env |
|---|---|---|
| `openai` | api.openai.com | `OPENAI_API_KEY` |
| `azure` | your-resource.openai.azure.com | `AZURE_OPENAI_API_KEY` |
| `anthropic` | api.anthropic.com | `ANTHROPIC_API_KEY` |
| `gemini` | generativelanguage.googleapis.com | `GEMINI_API_KEY` |
| `groq` | api.groq.com | `GROQ_API_KEY` |
| `mistral` | api.mistral.ai | `MISTRAL_API_KEY` |
| `openrouter` | openrouter.ai | `OPENROUTER_API_KEY` |
| `together` | api.together.xyz | `TOGETHER_API_KEY` |
| `deepseek` | api.deepseek.com | `DEEPSEEK_API_KEY` |
| `xai` | api.x.ai | `XAI_API_KEY` |
| `ollama` | 127.0.0.1:11434 | none |
| `lmstudio` | 127.0.0.1:1234 | none |
| `vllm` | 127.0.0.1:8000 | none |
| `llamacpp` | 127.0.0.1:8080 | none |
| `litellm` | 127.0.0.1:4000 | `LITELLM_MASTER_KEY` |
| `custom` | `--upstream-url ...` | `--key-env NAME` |

`abctl doctor` diagnoses the environment (config resolution, key presence, upstream reachability, data dirs, backends) without printing secrets. `abctl health` probes a running instance. `abctl start` launches the server for you (logs to `~/.agentbridge/agent-bridge.log`) and waits until it answers.

### Configuration resolution

1. `AB_CONFIG=/path/to.toml` (error if missing)
2. `./agentbridge.toml`
3. `./config/harness.toml`
4. `./config/harness.example.toml`
5. `~/.agentbridge/agentbridge.toml` (written by the `abctl` guided setup)
6. built-in defaults (requires `AB_UPSTREAM_URL`)

Environment overrides beat file values: `AB_LISTEN`, `AB_UPSTREAM_URL`, `AB_UPSTREAM_CHAT_PATH`, `AB_UPSTREAM_AUTH_HEADER`, `AB_UPSTREAM_AUTH_SCHEME`, `AB_STATE_ENDPOINT`, `AB_BRIDGE_ENDPOINT`, `AB_QDRANT_URL`. Exporting `AB_UPSTREAM_API_KEY` selects itself as the key source when the file doesn't name one; `AB_UPSTREAM_KEY_FILE=/run/secrets/api_key` points at a mounted secret file (Docker/Kubernetes secrets) instead. Key *values* are only ever read from the environment or `0600` files — never from the command line.

### Upstream authentication

The proxy injects the provider credential itself (clients never hold provider keys):

```toml
upstream_api_key_env = "OPENAI_API_KEY"        # or upstream_api_key_file = "/run/secrets/key"
upstream_auth_header = "authorization"          # azure: "api-key"
upstream_auth_scheme = "Bearer"                 # azure: "" (raw key)
upstream_chat_path = "/v1/chat/completions"     # azure/gemini: custom paths
```

Alternatively `upstream_authorization_passthrough = true` relays each client's own `Authorization` header (multi-tenant gateways; mutually exclusive with static keys and `require_identity`). MCP tool upstreams take `tool_upstream_bearer_env`/`_file`.

## Run from a checkout

```bash
cargo run -p ab-harness --bin agentbridged     # finds config/harness.example.toml
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
- `GET /dashboard`: read-only operator dashboard (HTML). Disable via
  `dashboard_enabled = false` in the harness config.
- `GET /api/v1/dashboard/{stats,sessions,sessions/{id}}`: JSON view of the
  in-memory session registry the dashboard consumes.

The dashboard shows sessions currently in the registry, their cost, tokens,
tool-call allow/block counts, and stop reason, with a session drawer that
renders the latest receipt as JSON. It is unauthenticated — front the
harness with the same ingress control you already use for `/metrics`, or
turn it off.

Request headers:

- `X-AB-Session`: caller-selected header-safe id; UUIDv7 is generated when absent.
- `X-AB-Workflow`: `signed` or `unsigned`.
- `Authorization: Bearer <JWT>`: required when identity enforcement is enabled.

## CLI

```bash
abctl init --preset ollama                # write a provider config
abctl doctor                              # diagnose the environment
abctl health                              # probe a running harness
abctl keygen --output config/signing.seed
abctl config-validate agentbridge.toml
abctl manifest-validate manifests/bridge.example.yaml
abctl bridge-provision --manifest manifests/bridge.example.yaml --data-dir data/bridge
abctl atif-validate trajectory.json
abctl receipt-verify receipt.json --public-key-hex "$TRUSTED_ED25519_PUBLIC_KEY_HEX"
abctl loadgen --connections 500
```

When identity enforcement is enabled, pass `--bearer-token-file /path/to/token` to `session-promote` and `loadgen`, or set `AB_BEARER_TOKEN_FILE`. Token contents are never accepted as command-line values.

## Container deployment

Minimal (one container, embedded bridge, in-memory state):

```bash
AB_UPSTREAM_URL=https://api.openai.com AB_UPSTREAM_API_KEY=sk-... \
  docker compose -f docker/docker-compose.minimal.yml up --build
```

Full reference stack (Redpanda, AOF-backed Redis, Qdrant, Vector/OTLP):

```bash
docker secret create identity_hmac /path/to/identity-hmac-secret
docker compose -f docker/docker-compose.yml up --build
```

The external `identity_hmac` secret is required by the production profile. Bridge data, cold exports, Redis state, and Qdrant data use persistent volumes. The embedded Bridge remains available for single-binary and air-gapped deployments. Container healthchecks use `abctl health` (real liveness, not config parsing).

The production image checksum-pins `sentence-transformers/all-MiniLM-L6-v2` at revision `1110a243fdf4706b3f48f1d95db1a4f5529b4d41`, validates the model/tokenizer hashes during build, and selects the ONNX backend. Air-gapped builds can mirror those immutable URLs or mount equivalent verified artifacts and update the configured paths.

## Kubernetes and systemd

- `deploy/kubernetes/agent-bridge.yaml`: single-replica starter (ConfigMap + PVC + probes + Secret-mounted key). Scale horizontally by switching to kafka/nats + redis backends.
- `deploy/systemd/agent-bridge.service`: hardened unit with `EnvironmentFile` for the key; install steps in the file header.

## Development gates

```bash
make ci
make test-all
make sla
```

See [ARCHITECTURE.md](ARCHITECTURE.md), [SECURITY.md](SECURITY.md), [EVOLUTION.md](EVOLUTION.md), and [BENCHMARKS.md](BENCHMARKS.md).

## Scope

The MVP intentionally excludes a web analytics UI, multi-region consensus, base-model training, and a general-purpose SFT/RL consumer.
