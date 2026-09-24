<p align="center">
  <img src="assets/logo.png" width="128" alt="AgentVisor AI logo">
</p>

# AgentVisor AI

[![CI](https://github.com/AgentVisorAI/agentvisor-ai/actions/workflows/ci.yml/badge.svg)](https://github.com/AgentVisorAI/agentvisor-ai/actions/workflows/ci.yml)
[![Console + API](https://github.com/AgentVisorAI/agentvisor-ai/actions/workflows/console-api.yml/badge.svg)](https://github.com/AgentVisorAI/agentvisor-ai/actions/workflows/console-api.yml)
[![Deploy](https://github.com/AgentVisorAI/agentvisor-ai/actions/workflows/deploy.yml/badge.svg)](https://github.com/AgentVisorAI/agentvisor-ai/actions/workflows/deploy.yml)
[![Supply chain](https://github.com/AgentVisorAI/agentvisor-ai/actions/workflows/deny.yml/badge.svg)](https://github.com/AgentVisorAI/agentvisor-ai/actions/workflows/deny.yml)
[![Docs](https://github.com/AgentVisorAI/agentvisor-ai/actions/workflows/pages.yml/badge.svg)](https://agentvisorai.me/)
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

- **[Landing page](https://agentvisorai.me/)** — the story, in
  three concrete examples.
- **[Console](https://agentvisorai.me/app/)** — the
  product, clickable in your browser: setup, one-line integration, a live
  capped session, the fleet overview, and offline receipt verification.
  Client-side simulation with representative data; nothing leaves the page.
- **[Releases](https://github.com/AgentVisorAI/agentvisor-ai/releases)** —
  pre-built binaries with SHA-256 checksums.
- **[Security model](SECURITY.md)** — trust boundaries, controls, and how
  to deploy safely. Report vulnerabilities privately via the
  [advisory form](https://github.com/AgentVisorAI/agentvisor-ai/security/advisories/new).
- **[Architecture](ARCHITECTURE.md)** · **[Benchmarks](BENCHMARKS.md)** ·
  **[Conformance status](CONFORMANCE-STATUS.md)** — going deeper.
- **[Current validation record](docs/PRODUCTION-VALIDATION.md)** — tested
  behavior, reproducible checks, and remaining deployment-specific validation.
- **[Reference docs](docs/reference/)** — configuration, operations,
  OpenAI compatibility, limits, and offline receipt verification.
- **[API docs](https://agentvisorai.me/api/)** — Rust crate
  reference. Skip unless you're embedding AgentVisor AI as a library.

---

## Easiest start (no config, no exports)

```bash
curl -fsSL https://agentvisorai.me/install.sh | sh    # installs `agentvisord` + `avctl`
avctl
```

Prebuilt static binaries cover Linux (x86_64/aarch64, any libc) and
macOS (both architectures); other Unix targets build from source —
the verified matrix, including 32-bit ARM, riscv64, ppc64le and
big-endian s390x, is in [docs/PLATFORMS.md](docs/PLATFORMS.md).
Windows runs via WSL.

Or install straight from this repository (same thing the script runs):

```bash
cargo install --locked --git https://github.com/AgentVisorAI/agentvisor av-harness
cargo install --locked --git https://github.com/AgentVisorAI/agentvisor av-cli
avctl
```

> `cargo install` builds **default features only**: the embedded
> bridge, in-memory state, hash embedder and in-memory vector store
> all work, but `redis`/`kafka`/`nats`/`onnx`/`qdrant`/`otel` are
> compiled out. To use those backends add `--features full` (or the
> specific feature) to the `av-harness` install line. Both pre-flight
> tools (`avctl config-validate`, `avctl doctor`) fail loudly when a
> config selects a backend the build cannot run.

> Plain `cargo install av-harness av-cli` (crates.io, no `--git`)
> starts working when the first tagged release is published; until
> then the registry does not know these crates — use the `--git`
> lines above or [Install from source](#install-from-source).

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
curl -fsSL https://agentvisorai.me/install.sh | sh    # or the --git lines above
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
- `POST /v1/token`: RFC 8693 token exchange for a backend-scoped token
  (opt-in via `token_exchange_enabled`).
- `POST /v1/revoke`: RFC 7009 revocation of an NHI or exchanged token (available when an
  identity validator is configured).
- `POST /v1/introspect`: authenticated backend checks for token expiry and revocation.
- `POST /admin/v1/revocations`: operator revocation by token id or agent instance (opt-in).
- `GET /.well-known/jwks.json`: public key that verifies exchanged tokens
  and intent tokens.
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
avctl spool-prune --spool spool/atif --retention-days 30  # one-off sealed-ATIF retention sweep
avctl receipt-verify receipt.json --public-key-hex "$TRUSTED_ED25519_PUBLIC_KEY_HEX"  # repeatable; hex or base64
avctl loadgen --connections 500
```

When identity enforcement is enabled, pass `--bearer-token-file /path/to/token` to `session-promote` and `loadgen`, or set `AV_BEARER_TOKEN_FILE`. Token contents are never accepted as command-line values.

## Container deployment

Local demonstration (one container, embedded bridge, in-memory state):

```bash
AV_UPSTREAM_URL=https://api.openai.com AV_UPSTREAM_API_KEY=sk-... \
  docker compose -f docker/docker-compose.minimal.yml up --build
```

The minimal configuration accepts anonymous callers and loses revocations on restart. Use authenticated identity and persistent Redis for production, including single-instance deployments.

Full reference stack (Redpanda, AOF-backed Redis, Qdrant, Vector/OTLP):

```bash
install -m 0600 /path/to/identity-hmac-secret docker/secrets/identity_hmac
install -m 0600 /path/to/signing.seed docker/secrets/signing.seed
docker compose -f docker/docker-compose.yml up --build
```

Both source files are required. The committed files contain deliberately invalid placeholders. For a new deployment, generate an identity secret with `openssl rand -hex 32` and a signing seed with `avctl keygen --output /path/to/signing.seed`. Preserve and back up the signing seed across deployments so existing receipts retain their trust anchor. Plain Docker Compose preserves the host ownership of file secrets, so the `install-secrets` service checks their owner-only permissions and copies them into a dedicated volume owned by UID 65532. The daemon mounts those copies read-only. Bridge data, cold exports, Redis state, and Qdrant data use separate persistent volumes. The embedded Bridge remains available for single-binary and air-gapped deployments. Container healthchecks use `avctl health` against `/readyz`.

The full stack disables the unauthenticated operator dashboard. Identity validation protects proxy operations, but it does not protect dashboard routes, and other containers can reach the listener directly without using the host's loopback port mapping. Keep the dashboard disabled unless a separate access control protects every path to those routes. The minimal configuration remains a local development and evaluation example.

After building the image, run `python3 scripts/container-smoke.py --image agentvisor-ai:local` to check startup, a real streaming request, signed receipt verification, and restart persistence using isolated local containers.

Signed receipts remain in the durable spool and event bridge after restart. Session control endpoints, including `/promote`, are not a historical receipt lookup API: a closed signed session can return `404` after eviction or restart. Retained unsigned trajectories can still be recovered for later promotion.

The broker pins target new installations. Existing Redpanda 25.2 data requires sequential upgrades through 25.3 and 26.1 before 26.2; follow the [Redpanda upgrade procedure](https://docs.redpanda.com/streaming/current/upgrade/rolling-upgrade/) before starting the updated image against an existing volume. Review the [NATS upgrade guides](https://docs.nats.io/release-notes) before reusing older JetStream data. The isolated contract tests use fresh broker data and do not certify an existing deployment's migration.

Production cold storage must use a maintained S3-compatible service. The bundled MinIO container is a local test fixture behind the `local-test` profile because the [community repository and legacy binaries are no longer maintained](https://github.com/minio/minio). CI starts that service explicitly for its S3 contract tests; it is excluded from the default stack.

The production image checksum-pins `sentence-transformers/all-MiniLM-L6-v2` at revision `1110a243fdf4706b3f48f1d95db1a4f5529b4d41` and validates the model/tokenizer hashes during build. The full reference stack selects the ONNX backend; the standalone container uses the hash embedder. Air-gapped builds can mirror those immutable URLs or mount equivalent verified artifacts and update the configured paths.

## Kubernetes and systemd

- [Kubernetes template](deploy/kubernetes/README.md): authenticated single-replica deployment with a ConfigMap, PVC, probes, and private signing and identity credentials. Configure the issuer and Secrets before applying it. Horizontal scaling requires shared bridge, state, and revocation backends.
- `deploy/systemd/agentvisor-ai.service`: hardened unit with `EnvironmentFile` for the key; install steps in the file header.

### Running multiple instances

A single AgentVisor AI process is the default. [Benchmarks](BENCHMARKS.md)
records the tested concurrency, measurement boundaries, and fixture settings.
Production revocation persistence requires durable Redis even for one replica;
the in-memory default is suitable for local evaluation. Running two or more replicas is safe **only** when
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
