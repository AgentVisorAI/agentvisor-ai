# AgentVisor AI Configuration Reference

The harness reads its TOML from the first path that exists in this
order:

1. `$AV_CONFIG` (an absolute path to a specific file)
2. `./agentvisor.toml`
3. `./config/harness.toml`
4. `$HOME/.agentvisor/agentvisor.toml`
5. built-in defaults

`config/harness.example.toml` is documentation only and is NOT
searched — see engineering review round 51 §9.4. If you were relying
on that rank swap, copy it to one of the searched paths.

`avctl config-validate path/to/harness.toml` runs the same parser,
`validate()` gates, and JSON-schema fidelity checks that `agentvisord`
runs at startup and fails with the same diagnostics.

## Environment variables

Round-51 §9.4: these were previously documented nowhere outside the
source. All are optional.

| Variable | Read by | Meaning |
| --- | --- | --- |
| `AV_SIGNING_SEED_FILE` | `agentvisord` | Path to the 32-byte Ed25519 signing seed — **the root of the entire trust story**. Default `config/signing.seed` relative to the working directory. If the file is missing, a fresh seed is generated and a WARN names the new key id: every receipt signed after an unintended regeneration verifies only against the NEW key, so mount this from a Secret in production and treat the WARN as a compliance incident outside first boot. |
| `AV_CONFIG` | `agentvisord`, `avctl` | Absolute path to the config file; rank 1 in the search order above. |
| `AV_UPSTREAM_URL` | `agentvisord` | Overrides `upstream_url` (useful in containers where the config file is baked). |
| `AV_BEARER_TOKEN_FILE` | `avctl` | Path to a file holding the NHI bearer used by `avctl loadgen`/probe commands. |
| `RUST_LOG` | `agentvisord` | Tracing filter (default `info`). A parse failure falls back to `info` with a warning. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` / `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` | `agentvisord` | OTLP trace export target. Requires a build with `--features otel`; a default-features binary warns loudly instead of silently ignoring them. |


## Networking

| Key | Default | Notes |
| --- | --- | --- |
| `listen` | `127.0.0.1:8484` | Bind address:port for HTTP. The 127.0.0.1 default is *deliberate*: the harness refuses to boot on a `0.0.0.0` bind when identity is not required (see below). |
| `allow_wildcard_bind` | `false` | Opt-in for `listen = "0.0.0.0:*"` when `require_identity = false`. Only set this when a network layer above the harness — Kubernetes NetworkPolicy, a service-mesh mTLS gateway, a corporate proxy ACL — controls who can reach the port. The container image sets this to `true`; it is expected that container users provide their own ingress ACL. |
| `require_identity` | `false` | Refuse any request without a valid NHI bearer. The **default is off** (development posture): the shipped safety net is the loopback `listen` default plus the wildcard-bind refusal. Set to `true` (with a JWKS/HMAC source) for any deployment reachable by anyone but the operator. |
| `identity_jwks_url` | none | JWKS URL for validating NHI tokens. Rotated JWKS entries are recognized within `identity_jwks_refresh_s` (default 300). |
| `identity_allowed_issuers` | `[]` | If non-empty, only tokens whose `iss` matches one of these are accepted. |
| `audience` | `agentvisor-ai` | Required token audience. |
| `enforce_identity_scopes` | `false` | Requires per-route scope claims. Applies only when `require_identity = true`. |
| `allowed_hosts` | `[]` (disabled) | Host-header allowlist (DNS-rebinding defense). Non-empty: requests whose `Host` (port stripped, case-insensitive) isn't listed are refused 403 before any handler. Leave empty for loopback binds or when the ingress enforces Host. |
| `chat_scope` / `session_close_scope` / `session_promote_scope` | `chat:write` / `session:close` / `session:promote` | Scope claims required on each route. |

## Dashboard

| Key | Default | Notes |
| --- | --- | --- |
| `dashboard_enabled` | `true` | Serves `/dashboard*` and `/api/v1/dashboard/*`. These endpoints are **unauthenticated** and mirror the in-memory session registry. The default-on posture is safe only because the `listen` default is loopback and config validation refuses a wildcard bind without identity; front the harness with the same ingress control you use for `/metrics` before exposing it. |

## Upstream

| Key | Default | Notes |
| --- | --- | --- |
| `config_version` | `1` | Config format version; unknown versions are refused at boot. |
| `upstream_url` | required | Base URL of the model backend (OpenAI, vLLM, LiteLLM, Ollama, Anthropic via a shim, …). |
| `upstream_chat_path` | `/v1/chat/completions` | Path appended to `upstream_url` for chat traffic. |
| `provider` | `openai` | Upstream wire dialect; selects the `ProviderAdapter` that parses bodies and SSE chunks. `openai` also fits vLLM, LiteLLM, Groq, Together, DeepSeek, OpenRouter, Ollama, LM Studio, llama.cpp, xAI, Mistral and Azure OpenAI; `anthropic` and `gemini` select the native adapters. |
| `upstream_authorization_passthrough` | `false` | Forward the client's `Authorization` header verbatim to the upstream. **Only valid when `require_identity = true`** — otherwise the harness would forward an unvalidated attacker-controlled header. |
| `ignore_client_authorization` | `false` | Accept and DISCARD a client `Authorization` bearer when no identity validator is configured (stock OpenAI SDKs always send a placeholder key; without this a keyless dev upstream 401s the documented quickstart on request one). The header never reaches the upstream. Refused in combination with `require_identity = true` or `upstream_authorization_passthrough = true`. |
| `upstream_http2_prior_knowledge` | `false` | Skip HTTP/1 → HTTP/2 upgrade negotiation on the outbound connection. |
| `upstream_read_timeout_s` | none | Per-request read timeout. Unset means "no timeout beyond the client's". |
| `shutdown_drain_timeout_s` | `max(30, upstream_read_timeout_s + 5)` | Graceful-shutdown drain budget. |
| `shutdown_ready_drain_s` | `0` | Readiness-controlled pre-drain window: on SIGTERM, `/readyz` serves 503 while the listener keeps accepting for this long before the drain begins. Needed for non-Kubernetes LBs (K8s gets this from the preStop sleep). |
| `upstream_api_key_env` / `upstream_api_key_file` | none | Where to pull the outbound API key from. `_file` wins over `_env` when both are set. |
| `upstream_auth_header` | `authorization` | Header carrying the upstream API key — `authorization` (OpenAI), `api-key` (Azure), `x-api-key` (Anthropic). |
| `upstream_auth_scheme` | `Bearer` | Prefix inserted before the key in the auth header; an empty string sends the raw key (Azure style). |
| `max_request_bytes` | `4194304` (4 MiB) | Maximum request body accepted on `/v1/chat/completions` and `/mcp`, matching the sandbox's payload cap so both routes carry the same effective limit. Raise for very-long-context models. |

## Workflows and receipts

| Key | Default | Notes |
| --- | --- | --- |
| `default_workflow` | `unsigned` | Workflow when the `X-AV-Workflow` header is absent. **`unsigned` produces ATIF trajectories but NO signed receipts** — every shipped config (example, container, docker, K8s) overrides this to `signed`; set it explicitly if you need verifiable receipts and cannot send the header. |
| `consequential_tools` | `["db_write", "payout", "merge", "deploy"]` | Tool names that require a signed workflow because they have real-world consequences. |

## Identity (development HMAC)

| Key | Default | Notes |
| --- | --- | --- |
| `identity_hmac_secret_file` | none | File containing an HS256 development secret (owner-only permissions enforced). Development alternative to `identity_jwks_url`. |
| `identity_hmac_kid` | `dev-hmac` | Key id assigned to the development HMAC secret. |

## Tool proxy (`/v1/mcp`)

| Key | Default | Notes |
| --- | --- | --- |
| `tool_upstream_url` | none | Downstream MCP/REST tool server. When absent, `/v1/mcp` operates as a policy decision endpoint (allow/deny + audit, no forwarding). |
| `tool_upstream_bearer_env` / `tool_upstream_bearer_file` | none | Bearer credential for `tool_upstream_url` requests; `_file` is enforced owner-only on Unix. `avctl doctor` checks whichever is configured. |
| `tool_schema_dir` | `config/tool-schemas` | Directory of one JSON Schema per tool, named `<tool>.json`. |
| `require_tool_schema` | `true` | Reject tool calls with no matching schema (fail closed). `false` skips the schema gate — policy and budget gates still apply. |
| `payout_field` | `amount_usd` | Tool-call argument field carrying a payout in USD, charged against `max_payout_usd_micros`. Set this to match YOUR tool schema — the cap only fires on calls carrying this exact field. |
| `wasm_policy_paths` | `["config/policies/payload_limit.wat"]` | WASM/WAT policy modules, evaluated in order. The default path resolves to an embedded built-in when no file exists on disk. |

## Budgets

There are **two** budget ledgers. Both share the same `av_state::BudgetSpec`
shape (`{ max_tokens, max_tool_calls, max_total_tool_calls,
max_payout_usd_micros }`).

| Key | Default | Notes |
| --- | --- | --- |
| `budget` | permissive | Session-scoped budget. Debited per accepted request, refunded on upstream failure, checked **after** compression (see round 51 §6.3). |
| `principal_budget` | unset | Optional principal-scoped budget layered on top. Its key is derived from the validated NHI identity — same principal, same key across session-id rotation (round 51 §3.2). Refused-by-session refunds bring the principal ledger back to whole. |
| `allow_anonymous_principal_budget` | `false` | Opt-in for setting `principal_budget` while `require_identity = false`. Otherwise the harness refuses to boot — anonymous callers all share one key and DoS each other. |

## Storage

| Key | Default | Notes |
| --- | --- | --- |
| `atif_spool_dir` | `spool/atif` (relative to the working directory) | Where ATIF trajectories and their `.atif-auth` sidecars land. Backup with the same discipline you use for receipts. |
| `atif_retention_days` | unset | When set, an hourly sweep removes **sealed** ATIF pairs (`.json` + `.atif-auth`) whose mtime is older than N days. Unpaired remnants are left for the reconciler's quarantine sweep. See round 51 §8.1. |
| `bridge_data_dir` / `bridge_backend` / `bridge_endpoint` | see docs | Broker configuration; either the embedded Bridge or an external one. |
| `bridge_manifest_path` | `manifests/bridge.example.yaml` | Declarative topic-schema manifest used by every Bridge backend; resolves to an embedded built-in when the default path has no file on disk. |
| `state_backend` / `state_endpoint` | see docs | State store: embedded or Redis. |

## Reconciler

| Key | Default | Notes |
| --- | --- | --- |
| `reconcile_tick_s` | `5` | How often the reconciler sweeps the spool for pending-close, orphan, and retention work. |
| `session_idle_close_s` | `900` | Idle-timeout after which an open session is force-closed. |

## Loop detection and embeddings

| Key | Default | Notes |
| --- | --- | --- |
| `[breaker]` | see `av_loopdetect::BreakerConfig` | Loop-detection circuit-breaker thresholds. Tune only after reviewing `docs/reference/OPERATIONS.md`. |
| `embedder_backend` | `hash` | Embedding backend for loop detection: `hash` (dependency-free) or `onnx`. |
| `onnx_model_path` / `onnx_tokenizer_path` | none | Customer-supplied ONNX model and its paired Hugging Face `tokenizer.json`; required when `embedder_backend = "onnx"` (build with `--features onnx`). |
| `onnx_dimension` | `384` | ONNX model output width. |
| `vector_backend` | `memory` | Reasoning-vector persistence: `memory` or `qdrant` (build with `--features qdrant`). |
| `qdrant_url` | none | Qdrant base URL; required when `vector_backend = "qdrant"`. |
| `qdrant_collection` | `agent_steps` | Qdrant collection receiving reasoning vectors. |

## Performance

| Key | Default | Notes |
| --- | --- | --- |
| `compression_enabled` | `true` | Context-compression pipeline on the chat path. |
| `worker_channel_capacity` | `32768` | Bounded audit-worker channel; overflow is counted (`av_events_dropped_total`), never blocking. |
| `strict_stage_budget` | `false` | Strict per-stage latency assertions (`AV_STRICT_BUDGET=1` also enables). Development diagnostics, not a production knob. |

## Development-only knobs

The following flags are safe **only** for local development and are
refused by `validate()` in combination with production settings.

| Combination | Refused with |
| --- | --- |
| `listen = "0.0.0.0:*"` + `require_identity = false` + `allow_wildcard_bind = false` | Explicit boot refusal. |
| `principal_budget = {…}` + `require_identity = false` + `allow_anonymous_principal_budget = false` | Explicit boot refusal. |
| `upstream_authorization_passthrough = true` + `require_identity = false` | Explicit boot refusal. |
| `ignore_client_authorization = true` + `require_identity = true` | Explicit boot refusal (the validator must see the header). |
| `ignore_client_authorization = true` + `upstream_authorization_passthrough = true` | Explicit boot refusal (cannot both discard and forward). |

If `validate()` rejects your config, the error message names the exact
key combination — do NOT try to bypass it; the guard exists to stop the
"I forgot to turn on identity and pushed a wildcard bind" incident.
