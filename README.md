<p align="center">
  <img src="assets/logo.png" width="128" alt="AgentVisor AI logo">
</p>

# AgentVisor AI

[![CI](https://github.com/AgentVisorAI/agentvisor-ai/actions/workflows/ci.yml/badge.svg)](https://github.com/AgentVisorAI/agentvisor-ai/actions/workflows/ci.yml)
[![Supply chain](https://github.com/AgentVisorAI/agentvisor-ai/actions/workflows/deny.yml/badge.svg)](https://github.com/AgentVisorAI/agentvisor-ai/actions/workflows/deny.yml)
[![Docs](https://github.com/AgentVisorAI/agentvisor-ai/actions/workflows/pages.yml/badge.svg)](https://agentvisorai.github.io/agentvisor-ai/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**AI agents you can hand to an auditor.**

AgentVisor AI is a small Rust server you drop in front of your agent's
LLM and tool calls. Every request is recorded, every limit you set is
enforced before the call goes out, and every session can end with a
signed receipt anyone can verify offline with just a public key
(out of the box sessions record unsigned trajectories; set
`default_workflow = "signed"` or promote a session via `/promote` to
mint the receipt). Change one line in your OpenAI client. Nothing else
in your app moves.

```python
client = OpenAI(
    api_key=os.environ["OPENAI_API_KEY"],
    base_url="http://127.0.0.1:8484/v1",   # <-- the only change
)
```

- **[Landing page](https://agentvisorai.github.io/agentvisor-ai/)** — the story, in
  three concrete examples.
- **[Releases](https://github.com/AgentVisorAI/agentvisor-ai/releases)** —
  pre-built binaries with SHA-256 checksums.
- **[Security model](SECURITY.md)** — trust boundaries, controls, and how
  to deploy safely. Report vulnerabilities privately via the
  [advisory form](https://github.com/AgentVisorAI/agentvisor-ai/security/advisories/new).
- **[Architecture](ARCHITECTURE.md)** · **[Benchmarks](BENCHMARKS.md)** ·
  **[Conformance status](CONFORMANCE-STATUS.md)** — going deeper.
- **[Reference docs](docs/reference/)** — configuration, operations,
  OpenAI compatibility, limits, and offline receipt verification.
- **[API docs](https://agentvisorai.github.io/agentvisor-ai/api/)** — Rust crate
  reference. Skip unless you're embedding AgentVisor AI as a library.

---

## Easiest start (no config, no exports)

```bash
cargo install av-harness av-cli    # installs `agentvisord` + `avctl` binaries
avctl
```

> `cargo install` builds **default features only**: the embedded
> bridge, in-memory state, hash embedder and in-memory vector store
> all work, but `redis`/`kafka`/`nats`/`onnx`/`qdrant`/`otel` are
> compiled out. To use those backends install with
> `cargo install av-harness av-cli --features full` (or the specific
> feature). Both pre-flight tools (`avctl config-validate`,
> `avctl doctor`) fail loudly when a config selects a backend the
> build cannot run.

> The two crates land on crates.io from `v0.1.0` onwards; until that
> release is published, use the `--path` variants shown in
> [Install from source](#install-from-source) below.

Bare `avctl` launches a guided setup: pick your AI provider from a
numbered list, paste your API key once (typed hidden, stored
owner-only under `~/.agentvisor/keys/`), and it writes
`~/.agentvisor/agentvisor.toml` for you. Answer "yes" at the end —
or run `avctl start` later — and AgentVisor AI is running with a
friendly banner telling you exactly what URL to paste into your app.
`Ctrl-C` stops it cleanly. No files to edit, no environment
variables, no terminal knowledge beyond typing a number.

## 60-second start

Pick the row that matches your provider, then run two commands.

```bash
cargo install av-harness av-cli    # or see "Install from source" below
```

```bash
avctl init --preset openai     # writes agentvisor.toml + prints next steps
export OPENAI_API_KEY=sk-...
agentvisord                   # http://127.0.0.1:8484
```

Point any OpenAI-compatible SDK at `http://127.0.0.1:8484/v1` and use it as normal. Trajectories and receipts land under `spool/atif/` (receipts in `spool/atif/receipts/`); bridge events land under `data/bridge`.

> **Note:** context compression is on by default and may rewrite long
> or repetitive message histories before forwarding (duplicate
> collapse from ~512 tokens, middle summarization from ~50k). Stubs
> record the pruned token count and content hash in the audit trail.
> Set `compression_enabled = false` to forward payloads verbatim —
> details in [docs/reference/OPENAI-COMPATIBILITY.md](docs/reference/OPENAI-COMPATIBILITY.md).

No config file at all also works — built-in defaults plus one env var:

```bash
AV_UPSTREAM_URL=http://127.0.0.1:11434 agentvisord   # e.g. Ollama
```

### Install from source

Cloning the repo works too — useful for development, or before the
first crates.io release lands:

```bash
git clone https://github.com/AgentVisorAI/agentvisor-ai && cd agentvisor-ai
cargo install --path crates/av-harness   # installs `agentvisord`
cargo install --path crates/av-cli       # installs `avctl`
```

### Provider presets

| Preset | Endpoint | Key env |
|---|---|---|
| `openai` | api.openai.com | `OPENAI_API_KEY` |
| `azure` | your-resource.openai.azure.com | `AZURE_OPENAI_API_KEY` |
| `anthropic` | api.anthropic.com | `ANTHROPIC_API_KEY` |
| `gemini` | generativelanguage.googleapis.com/v1beta/openai | `GEMINI_API_KEY` |
| `groq` | api.groq.com/openai | `GROQ_API_KEY` |
| `mistral` | api.mistral.ai | `MISTRAL_API_KEY` |
| `openrouter` | openrouter.ai/api | `OPENROUTER_API_KEY` |
| `together` | api.together.xyz | `TOGETHER_API_KEY` |
| `deepseek` | api.deepseek.com | `DEEPSEEK_API_KEY` |
| `xai` | api.x.ai | `XAI_API_KEY` |
| `ollama` | 127.0.0.1:11434 | none |
| `lmstudio` | 127.0.0.1:1234 | none |
| `vllm` | 127.0.0.1:8000 | none |
| `llamacpp` | 127.0.0.1:8080 | none |
| `litellm` | 127.0.0.1:4000 | `LITELLM_MASTER_KEY` |
| `custom` | `--upstream-url ...` | `--key-env NAME` |

`avctl doctor` diagnoses the environment (config resolution, key presence, upstream reachability, data dirs, backends, budget posture) without printing secrets. `avctl health` probes a running instance. `avctl start` launches the server for you (logs to `~/.agentvisor/agentvisor-ai.log`) and waits until it answers.

### Configuration resolution

1. `AV_CONFIG=/path/to.toml` (error if missing)
2. `./agentvisor.toml`
3. `./config/harness.toml`
4. `~/.agentvisor/agentvisor.toml` (written by the `avctl` guided setup)
5. built-in defaults (requires `AV_UPSTREAM_URL`)

`config/harness.example.toml` is documentation only — it is NOT
searched. Copy it to one of the paths above to use it.

Environment overrides beat file values: `AV_LISTEN`, `AV_UPSTREAM_URL`, `AV_UPSTREAM_CHAT_PATH`, `AV_UPSTREAM_AUTH_HEADER`, `AV_UPSTREAM_AUTH_SCHEME`, `AV_STATE_ENDPOINT`, `AV_BRIDGE_ENDPOINT`, `AV_QDRANT_URL`. Exporting `AV_UPSTREAM_API_KEY` selects itself as the key source when the file doesn't name one; `AV_UPSTREAM_KEY_FILE=/run/secrets/api_key` points at a mounted secret file (Docker/Kubernetes secrets) instead. Key *values* are only ever read from the environment or `0600` files — never from the command line.

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
cp config/harness.example.toml config/harness.toml   # the example is a template, never auto-loaded
OPENAI_API_KEY=sk-... cargo run -p av-harness --bin agentvisord
curl http://127.0.0.1:8484/health
curl http://127.0.0.1:8484/metrics
```

The copy is deliberate: `config/harness.toml` is on the search path,
the example file is not (so editing documentation can never
reconfigure a running deployment). Uncomment `upstream_api_key_env`
in the copy — or point `upstream_url` at a local keyless server and
uncomment `ignore_client_authorization` — before sending traffic.

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

- `X-AV-Session`: caller-selected header-safe id; UUIDv7 is generated when absent.
- `X-AV-Workflow`: `signed` or `unsigned`.
- `Authorization: Bearer <JWT>`: required when identity enforcement is enabled.

## CLI

```bash
avctl init --preset ollama                # write a provider config
avctl doctor                              # diagnose the environment
avctl health                              # probe a running harness
avctl keygen --output config/signing.seed
avctl config-validate agentvisor.toml
avctl manifest-validate manifests/bridge.example.yaml
avctl bridge-provision --manifest manifests/bridge.example.yaml --data-dir data/bridge
avctl atif-validate trajectory.json
avctl receipt-locate my-session-id --spool spool/atif   # session id -> artifact paths
avctl receipt-verify receipt.json --public-key-hex "$TRUSTED_ED25519_PUBLIC_KEY_HEX"  # repeatable; hex or base64
avctl loadgen --connections 500
```

When identity enforcement is enabled, pass `--bearer-token-file /path/to/token` to `session-promote` and `loadgen`, or set `AV_BEARER_TOKEN_FILE`. Token contents are never accepted as command-line values.

## Container deployment

Minimal (one container, embedded bridge, in-memory state):

```bash
AV_UPSTREAM_URL=https://api.openai.com AV_UPSTREAM_API_KEY=sk-... \
  docker compose -f docker/docker-compose.minimal.yml up --build
```

Full reference stack (Redpanda, AOF-backed Redis, Qdrant, Vector/OTLP):

```bash
docker secret create identity_hmac /path/to/identity-hmac-secret
docker compose -f docker/docker-compose.yml up --build
```

The external `identity_hmac` secret is required by the production profile. Bridge data, cold exports, Redis state, and Qdrant data use persistent volumes. The embedded Bridge remains available for single-binary and air-gapped deployments. Container healthchecks use `avctl health` (real liveness, not config parsing).

The production image checksum-pins `sentence-transformers/all-MiniLM-L6-v2` at revision `1110a243fdf4706b3f48f1d95db1a4f5529b4d41`, validates the model/tokenizer hashes during build, and selects the ONNX backend. Air-gapped builds can mirror those immutable URLs or mount equivalent verified artifacts and update the configured paths.

## Kubernetes and systemd

- `deploy/kubernetes/agentvisor-ai.yaml`: single-replica starter (ConfigMap + PVC + probes + Secret-mounted key). Scale horizontally by switching to kafka/nats + redis backends.
- `deploy/systemd/agentvisor-ai.service`: hardened unit with `EnvironmentFile` for the key; install steps in the file header.

### Running multiple instances

A single AgentVisor AI process is the default and the tested-at-scale
configuration (10k concurrent streams, p95 0.865 ms — see
`BENCHMARKS.md`). Running two or more replicas is safe **only** when
every backend below is external — the embedded defaults are strictly
single-instance:

| Subsystem | Single-instance default | Multi-instance requirement |
| --- | --- | --- |
| Signer seed | file on disk | same seed mounted at each replica (or a rotation you accept per replica) |
| State store (budgets, ratelimits) | `state_backend = "memory"` | `state_backend = "redis"` with `state_endpoint = "redis://..."` and identical `AV_STATE_ENDPOINT` at each replica |
| Bridge (event bus) | `bridge_backend = "embedded"` (per-pod data-dir) | `bridge_backend = "kafka"` or `"nats"` with shared endpoints |
| ATIF spool | pod-local `atif_spool_dir` (enforced: the daemon holds an exclusive lock on `.agentvisord.lock` in the spool and a second instance refuses to boot) | one replica per spool volume — sharing a spool is refused at startup because the reconciler's per-file lifecycle lock is process-local and two replicas would race on close |
| Session registry | in-memory only | client stickiness (LB session affinity on `X-AV-Session`) OR accept that a session's audit chain lives on one pod for its lifetime and doesn't survive that pod's eviction |

Concretely: a two-replica deployment with `state_backend = "memory"`
lets a client rotate through both pods and effectively bypass every
per-session budget. A two-replica deployment sharing an ATIF spool
without session affinity will race on session close and land one
audit event on the broker twice. If you're not sure which subsystem
is on which side of the line, run one replica.

See [docs/reference/OPERATIONS.md](docs/reference/OPERATIONS.md) for
the full per-subsystem checklist and
[docs/reference/CONFIGURATION.md](docs/reference/CONFIGURATION.md) for
the exact TOML keys.

## Development gates

```bash
make ci
make test-all
make sla
```

See [ARCHITECTURE.md](ARCHITECTURE.md), [SECURITY.md](SECURITY.md), [EVOLUTION.md](EVOLUTION.md), and [BENCHMARKS.md](BENCHMARKS.md).

## Scope

The MVP intentionally excludes a web analytics UI, multi-region consensus, base-model training, and a general-purpose SFT/RL consumer.
