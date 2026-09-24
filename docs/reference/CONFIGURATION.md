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
| `upstream_authorization_passthrough` | `false` | Forward the client's `Authorization` header verbatim to the upstream. **Incompatible with `require_identity = true`** (the header carries the NHI identity token there, not an upstream credential) and with the static upstream key options — boot refuses those combinations. |
| `ignore_client_authorization` | `false` | Accept and DISCARD a client `Authorization` bearer when no identity validator is configured (stock OpenAI SDKs always send a placeholder key; without this a keyless dev upstream 401s the documented quickstart on request one). The header never reaches the upstream. Refused in combination with `require_identity = true` or `upstream_authorization_passthrough = true`. |
| `upstream_http2_prior_knowledge` | `false` | Skip HTTP/1 → HTTP/2 upgrade negotiation on the outbound connection. |
| `upstream_read_timeout_s` | `60` | Read-idle timeout for upstream requests. Each successful read restarts it; this does not limit total streamed-chat duration. The allowed range is 1–86400 seconds. |
| `mcp_request_timeout_s` | `60` | Total deadline for each outbound MCP HTTP request, from connection establishment through response-body completion, including after caller cancellation. The allowed range is 1–86400 seconds. It does not bound admission, audit work, or streamed chat. A timeout after response headers is recorded and audited as a replayable 502; a timeout before response headers leaves the execution uncertain, so a retry cannot repeat possible tool effects. |
| `shutdown_drain_timeout_s` | `max(30, max(upstream_read_timeout_s, mcp_request_timeout_s) + 5)` | Graceful-shutdown drain budget, using the network settings' defaults when unset. Long chat streams and audit work can exceed this budget; an explicit value overrides the derivation. |
| `shutdown_ready_drain_s` | `0` | Readiness-controlled pre-drain window: on SIGTERM, `/readyz` serves 503 while the listener keeps accepting for this long before the drain begins. Needed for every deployment target where the LB polls `/readyz` — this includes Kubernetes distroless images (no `/bin/sh` for a `preStop` sleep hook), docker-compose, systemd, and bare-VM LBs. The shipped k8s manifest sets this to `5`. |
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
| `atif_retention_days` | unset | When set to a positive N, an hourly sweep removes **sealed** ATIF pairs (`.json` + `.atif-auth`) whose mtime is older than N days. Unpaired remnants are left for the reconciler's quarantine sweep. Leave the key unset (or set to `None` in TOML by omitting it) to disable in-process retention entirely; `0` is rejected by config validation because a zero-day window would prune every sealed pair on the first tick. See round 51 §8.1. |
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

## Delegation and token exchange

| Key | Default | Notes |
| --- | --- | --- |
| `max_delegation_depth` | `4` | Maximum combined depth of `parent_token` chain links and `act` claim nesting. Tokens exceeding this depth are rejected. |
| `token_exchange_enabled` | `false` | Enable the RFC 8693 token exchange endpoint at `/v1/token`. Boot refuses it unless `token_exchange_seed_file`, an identity source (`identity_jwks_url` or `identity_hmac_secret_file`), and at least one `[[backends]]` entry are configured. |
| `token_exchange_seed_file` | none | Ed25519 signing seed file for exchanged tokens and intent tokens (owner-only permissions enforced; must be distinct from the receipt signing seed). Its public key is served at `/.well-known/jwks.json` so backends can verify both kinds of token. |
| `token_exchange_ttl_s` | `300` | TTL in seconds for exchanged tokens. Capped at 900 to prevent indefinite delegation. |

The exchange signs tokens only for audiences that name a configured
backend. A request for any other audience, or any request while no
backends exist, is refused with the RFC 8693 `invalid_target` error. A
subject token that fails validation is refused with `invalid_request`, and
the description is deliberately generic: it never names key ids, issuers,
or algorithms. When the revocation list cannot be read, the endpoint
answers `503` with `temporarily_unavailable` and `Retry-After`.

## Token revocation (`POST /v1/revoke`)

Send a form field `token=<jwt>` to revoke an inbound NHI token or a token
issued by this gateway. The optional `token_type_hint` is ignored. The
route is available when an identity validator is configured. Possession
of the token permits its revocation; invalid and already revoked tokens
receive the same empty `200` response with `Cache-Control: no-store`.
The gateway verifies the signature before writing any revocation entry.
Inbound delegation chains embed complete parent bearer tokens. A delegate
can therefore extract and use or revoke its parent token, which also
revokes sibling chains. Use this format only between mutually trusted
delegates; it does not isolate a parent credential from its delegates.
Exchanged tokens embed ancestor identifiers instead of parent credentials.
A correctly signed token scheduled to become valid within the bounded
15-minute scheduling window can also be revoked before activation.
An unknown signing key receives `503` so the caller can retry after key
rotation, rather than being told that a revocation succeeded.

An NHI revocation covers the token's full expiry tolerance. It also blocks
every child that includes the token in its delegation chain. Exchanged
tokens carry signed identifiers of their original ancestors, without
embedding their bearer credentials. Revoking an ancestor makes its
exchanged tokens inactive when a backend checks introspection.

With `state_backend = "redis"`, revocation entries and instance cutoffs
are shared across replicas and retained for 24 hours. With `"memory"`,
they belong to one process and are lost on restart. Memory entries are
swept after their final acceptance time. A storage failure returns `503`
with `Retry-After`; it never silently treats an unreadable list as empty.

Use a `rediss://` endpoint for certificate-verified Redis TLS. The hostname
must match the server certificate. The native trust store is used by default;
set `SSL_CERT_FILE` to a readable PEM CA bundle when Redis uses a private CA.
Include public roots needed by other clients that honor this environment
variable. Insecure TLS URLs are refused. All comma-separated Redis Cluster
seeds must use the same transport. The `redis` Cargo feature includes TLS
support; the production container enables it.

Redis revocation reads allow at most 32 concurrent calls per token namespace.
After three consecutive storage errors, a circuit breaker refuses reads
immediately for one second. One caller then checks whether storage has
recovered. A bounded local cache holds up to 100,000 known revocations per
namespace; it never caches permission to use a token. Known revoked tokens
remain refused during an outage. A locally requested revocation enters this
cache before the shared write, but a failed write still returns `503` and
must be retried to reach other replicas.

Monitor `av_revocation_lookups_total{namespace,outcome}`,
`av_revocation_breaker_opened_total{namespace}`,
`av_revocation_list_available{namespace}`, and
`av_revocation_local_entries{namespace}`. The `/readyz` response reports
`checks.revocation_available` and `checks.revocation_local_entries` without
changing its HTTP status for a revocation outage. Requests still fail
closed while storage is unavailable; reporting the outage does not remove
all replicas from service at once.

Each new holder revocation creates an `agent.identity` event and an
ordinary signed receipt. The event records the action, token identifier,
issuer, subject, and lifetime, but never the token or its parent tokens.
Repeated holder revocations do not create duplicate receipts. The receipt
can be checked with `avctl receipt-verify` and the independent receipt
public key. The revocation takes effect even if audit capacity is
exhausted. Alert on `av_tokens_revoked_unaudited_total{reason=...}` and
`av_revocation_audit_close_failures_total`; these identify missing capture
and delayed receipt finalization. There is no atomic transaction between
the revocation store and the journal, so a process failure between those
writes can leave a revocation without a receipt.

| Key | Default | Notes |
| --- | --- | --- |
| `revocation_audit_per_minute` | `600` | Maximum revocation audit records per process per minute, from 1 to 100000. This budget is separate from rejected-identity sampling. |
| `operator_tokens` | `[]` | Named SHA-256 digests of independent operator bearer secrets. Enables the administrative route described below. |
| `introspection_tokens` | `[]` | SHA-256 digests of independent backend bearer secrets, each bound to one configured backend name. Enables introspection. |

### Backend introspection (`POST /v1/introspect`)

A backend sends `token=<jwt>` as a form body and authenticates with its
own bearer secret. Store only the secret's SHA-256 digest in config:

```toml
[[introspection_tokens]]
backend = "customer-service"
sha256 = "<64 hexadecimal characters: SHA-256 of a random backend secret>"
```

The response follows [RFC 7662](https://www.rfc-editor.org/rfc/rfc7662.html).
It returns `active: false` for a revoked, expired, forged, or wrong-audience
token. Only a token addressed to the authenticated backend may expose
claims. An unavailable revocation store returns `503`, which the backend
must treat as a refusal until it can retry. Use TLS for this endpoint
outside loopback, including when TLS terminates at an ingress proxy.

Backends that verify JWTs offline still accept a revoked token until its
expiry. Immediate revocation requires introspection on every call; caching
an active answer delays revocation by the cache duration. Backends must
also validate their intended token profile and the requested tool scope.
Forwarded MCP credentials use JWT header `typ = "av-tool+jwt"`. Tokens
from the optional public exchange endpoint use `typ = "JWT"`; intent
proofs use `typ = "av-intent+jwt"`. A tool backend must require the first
profile and must reject the other two as tool credentials. Checking only
the signature and audience is insufficient. Restrict network access to
tool backends to the gateway as an additional control.

### Operator revocation (`POST /admin/v1/revocations`)

The route exists only when `operator_tokens` is nonempty. Each operator
uses a separate random bearer secret of at least 32 characters. Agent
credentials and introspection credentials do not authorize this route.

```toml
[[operator_tokens]]
name = "incident-response"
sha256 = "<64 hexadecimal characters: SHA-256 of a random operator secret>"
```

Send exactly one target in a JSON body: `{"jti":"token-id"}` to revoke an
NHI token by identifier, `{"jti":"token-id","token_kind":"exchanged"}` to
revoke a gateway token, or `{"instance_uid":"agent-instance"}` to revoke
all tokens issued for that instance at or before the current time plus
the validator's clock tolerance. The cutoff only moves forward. Tokens
issued later remain usable. The operator does not need the original JWT. Identifier revocations are retained
for 24 hours; an issuer must never reuse a token identifier.
An instance cutoff also invalidates exchanged descendants through
introspection.

A successful response contains `revoked: true` and `audited`. If `audited`
is false, the revocation still took effect but its signed receipt was not
completed; inspect the audit metrics and logs. Every operator action, including a repeat of an earlier command, identifies
the configured operator in its signed event. There is no undo operation.

The CLI exposes `avctl token-revoke` and `avctl instance-revoke`. It reads
an owner-only credential file from `--operator-token-file` or
`AV_OPERATOR_TOKEN_FILE`, or falls back to `AV_OPERATOR_TOKEN`. It trims
surrounding whitespace before hashing the bearer; configure the digest of
the secret itself, without a trailing newline.

```sh
avctl token-revoke --jti token-id --operator-token-file /run/secrets/operator-token \
  --url https://gateway.example.com
avctl token-revoke --jti exchanged-token-id --token-kind exchanged \
  --operator-token-file /run/secrets/operator-token --url https://gateway.example.com
avctl instance-revoke --instance-uid agent-instance \
  --operator-token-file /run/secrets/operator-token --url https://gateway.example.com
```

The CLI refuses redirects and HTTP destinations outside loopback. Repeat
`--url` to contact each independent memory-backed replica; one failed
replica makes the command fail even if others succeeded. A Redis-backed
fleet shares its revocation state, so one healthy replica suffices. Use
TLS outside loopback and keep the administrative route behind the
operator network. Never pass the bearer itself as a command-line argument.

## Intent mapping and missions

| Key | Default | Notes |
| --- | --- | --- |
| `intent_map` | `{}` | Maps tool names to business intents (TOML `[intent_map]`, e.g. `db_write = "data.mutate"`). When `require_intent_mapping` is true, tools not in the map are denied with `UNMAPPED_TOOL`. |
| `require_intent_mapping` | `false` | When true, every tool call must have a configured intent mapping. |
| `mission` | none | Active mission constraint (TOML `[mission]`). Contains `id`, `allowed_intents`, and `expires_at`. Only narrows static policy, never widens. |
| `intent_token_ttl_s` | `60` | TTL in seconds for per-call intent tokens issued by the local PDP. |

The policy decision point runs before the tool budget is charged, in every
mode, including verdict-only mode (no `tool_upstream_url` and no
`[[backends]]`). A denied call consumes no budget, and its audit event
records `allowed: false` with the denial code and a `policy` name of
`pdp.intent_map` or `pdp.mission`. The JSON-RPC error echoes the request
`id` and carries the machine-readable code in `error.data.code` (for
example `UNMAPPED_TOOL`, `MISSION_EXPIRED`, `MISSION_DENIED`).

When `token_exchange_seed_file` is set, every forwarded tool call carries a
signed intent token in the `x-av-intent-token` header. It is an EdDSA JWT
with the header `typ: av-intent+jwt`, so a backend can tell it apart from
an access token signed by the same key. Its claims are `iss` (the harness
`audience`), `aud` (the receiving backend's `name`, or `default` for
`tool_upstream_url`), `sub` (the calling agent's `instance_uid`), `tool`,
`intent`, `iat`, `exp`, and a unique `jti`. Backends should check `typ`,
`aud`, and `exp`, and may reject a repeated `jti`.

## Backend routing

| Key | Default | Notes |
| --- | --- | --- |
| `backends` | `[]` | Per-backend MCP server routing (TOML `[[backends]]`). Each entry has `name`, `url`, `auth`, and `tools`. An entry with an empty `tools` list is the default for unmapped tools (at most one). When `backends` is empty, `tool_upstream_url` becomes an implicit backend named `default`, and it carries the `tool_upstream_bearer_env` / `tool_upstream_bearer_file` credential. |

A tool that maps to no backend, when there is no default backend, is sent
to `tool_upstream_url` with its bearer if that is set. Otherwise the call
is decided (allowed or denied, and audited) but not forwarded. The
caller's own `Authorization` header is never forwarded to any backend.

### Backend `auth` modes

Each `[[backends]]` entry accepts an `auth` field selecting how the harness authenticates
to that MCP server:

| `auth` value | Description |
| --- | --- |
| `"none"` (default) | No credential is sent. |
| `{ static_env = "VAR" }` | Bearer token read from the named environment variable at boot. Surrounding whitespace is trimmed; an unset or empty variable refuses boot. |
| `{ static_file = "path" }` | Bearer token read from a file at boot (owner-only permissions and no symlinks, enforced on Unix). Surrounding whitespace is trimmed; an empty file refuses boot. |
| `"exchange"` | On-the-fly RFC 8693 token exchange for every call: the caller's NHI bearer is exchanged for a short-lived token whose `aud` is this backend's `name` and whose only scope is `tool:<called tool>`. The caller's token must hold that scope (directly or through a wildcard such as `tool:*`); otherwise the call is refused with `403` before anything reaches the backend or charges the budget. `sub` stays the human principal, and `azp` and `act.sub` carry the caller's `instance_uid`. Requires `require_identity = true` and `token_exchange_seed_file`; boot refuses the combination otherwise. |

Static credentials are marked as sensitive header values, so they are kept
out of debug output and HTTP/2 header compression tables.

## Tenant observability and redaction

| Key | Default | Notes |
| --- | --- | --- |
| `otel_tenant_endpoint` | none | Tenant OTLP/HTTP trace endpoint (including `/v1/traces`), exported alongside any operational collector. Requires the `otel` build feature. Operational authentication headers are not forwarded to this endpoint. |
| `otel_tenant_auth_file` | none | Bearer token file for the tenant OTEL endpoint (owner-only permissions enforced). |
| `redaction_patterns` | `[]` | Regex patterns for sensitive-data stripping. Applied to event payloads and ATIF step fields before journal write. Setting either patterns or pointer paths also enables the builtin patterns (API keys, email, SSN, cards, and IPv4 addresses). |
| `redaction_paths` | `[]` | JSON pointer paths to always redact in event payloads and their ATIF observation copies. Configuring paths also enables builtins. |

## Performance

| Key | Default | Notes |
| --- | --- | --- |
| `compression_enabled` | `true` | Context-compression pipeline on the chat path. |
| `worker_channel_capacity` | `32768` | Bounded audit-worker channel; overflow is counted (`av_events_dropped_total`), never blocking. |
| `mcp_concurrency` | `128` | Max concurrent `mcp_call_inner` executions. Each admitted call can buffer up to `MAX_TOOL_RESPONSE_BYTES = 16 MiB` in `read_limited_tool_response`, so this cap bounds worst-case MCP resident memory (default: ~2 GiB). Refused admissions increment `av_mcp_admission_refusals_total` and respond `503` with `Retry-After: 1` — a server-side capacity signal (mirrors the breaker-open discipline). |
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
