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

## Networking

| Key | Default | Notes |
| --- | --- | --- |
| `listen` | `127.0.0.1:8484` | Bind address:port for HTTP. The 127.0.0.1 default is *deliberate*: the harness refuses to boot on a `0.0.0.0` bind when identity is not required (see below). |
| `allow_wildcard_bind` | `false` | Opt-in for `listen = "0.0.0.0:*"` when `require_identity = false`. Only set this when a network layer above the harness — Kubernetes NetworkPolicy, a service-mesh mTLS gateway, a corporate proxy ACL — controls who can reach the port. The container image sets this to `true`; it is expected that container users provide their own ingress ACL. |
| `require_identity` | `true` | Refuse any request without a valid NHI bearer. Turning this off is a **development-only** switch and permanently disables audience/scope/TTL checks. |
| `identity_jwks_url` | none | JWKS URL for validating NHI tokens. Rotated JWKS entries are recognized within `identity_jwks_refresh_s` (default 300). |
| `identity_allowed_issuers` | `[]` | If non-empty, only tokens whose `iss` matches one of these are accepted. |
| `audience` | `agentvisor-ai` | Required token audience. |
| `enforce_identity_scopes` | `true` | Requires per-route scope claims. Applies only when `require_identity = true`. |
| `chat_scope` / `session_close_scope` / `session_promote_scope` | `chat:write` / `session:close` / `session:promote` | Scope claims required on each route. |

## Dashboard

| Key | Default | Notes |
| --- | --- | --- |
| `dashboard_enabled` | `false` | Serves `/dashboard*` and `/api/v1/dashboard/*`. These endpoints are **unauthenticated** and mirror the in-memory session registry. Front the harness with the same ingress control you use for `/metrics` before turning this on. Was previously default-true; changed to default-false in round 51 §3.3. |

## Upstream

| Key | Default | Notes |
| --- | --- | --- |
| `upstream_url` | required | Base URL of the model backend (OpenAI, vLLM, LiteLLM, Ollama, Anthropic via a shim, …). |
| `upstream_chat_path` | `/v1/chat/completions` | Path appended to `upstream_url` for chat traffic. |
| `upstream_authorization_passthrough` | `false` | Forward the client's `Authorization` header verbatim to the upstream. **Only valid when `require_identity = true`** — otherwise the harness would forward an unvalidated attacker-controlled header. |
| `upstream_http2_prior_knowledge` | `false` | Skip HTTP/1 → HTTP/2 upgrade negotiation on the outbound connection. |
| `upstream_read_timeout_s` | none | Per-request read timeout. Unset means "no timeout beyond the client's". |
| `upstream_api_key_env` / `upstream_api_key_file` | none | Where to pull the outbound API key from. `_file` wins over `_env` when both are set. |

## Budgets

There are **two** budget ledgers. Both share the same `av_state::BudgetSpec`
shape (`{ per_min_tokens, hourly_tokens, per_min_requests, hourly_requests }`).

| Key | Default | Notes |
| --- | --- | --- |
| `budget` | permissive | Session-scoped budget. Debited per accepted request, refunded on upstream failure, checked **after** compression (see round 51 §6.3). |
| `principal_budget` | unset | Optional principal-scoped budget layered on top. Its key is derived from the validated NHI identity — same principal, same key across session-id rotation (round 51 §3.2). Refused-by-session refunds bring the principal ledger back to whole. |
| `allow_anonymous_principal_budget` | `false` | Opt-in for setting `principal_budget` while `require_identity = false`. Otherwise the harness refuses to boot — anonymous callers all share one key and DoS each other. |

## Storage

| Key | Default | Notes |
| --- | --- | --- |
| `atif_spool_dir` | `./data/atif` | Where ATIF trajectories and their `.atif-auth` sidecars land. Backup with the same discipline you use for receipts. |
| `atif_retention_days` | unset | When set, an hourly sweep removes **sealed** ATIF pairs (`.json` + `.atif-auth`) whose mtime is older than N days. Unpaired remnants are left for the reconciler's quarantine sweep. See round 51 §8.1. |
| `bridge_data_dir` / `bridge_backend` / `bridge_endpoint` | see docs | Broker configuration; either the embedded Bridge or an external one. |
| `state_backend` / `state_endpoint` | see docs | State store: embedded or Redis. |

## Reconciler

| Key | Default | Notes |
| --- | --- | --- |
| `reconcile_tick_s` | `5` | How often the reconciler sweeps the spool for pending-close, orphan, and retention work. |
| `session_idle_close_s` | `900` | Idle-timeout after which an open session is force-closed. |

## Loop detection

| Key | Default | Notes |
| --- | --- | --- |
| `[breaker]` | see `av_loopdetect::BreakerConfig` | Loop-detection circuit-breaker thresholds. Tune only after reviewing `docs/reference/OPERATIONS.md`. |

## Development-only knobs

The following flags are safe **only** for local development and are
refused by `validate()` in combination with production settings.

| Combination | Refused with |
| --- | --- |
| `listen = "0.0.0.0:*"` + `require_identity = false` + `allow_wildcard_bind = false` | Explicit boot refusal. |
| `principal_budget = {…}` + `require_identity = false` + `allow_anonymous_principal_budget = false` | Explicit boot refusal. |
| `upstream_authorization_passthrough = true` + `require_identity = false` | Explicit boot refusal. |

If `validate()` rejects your config, the error message names the exact
key combination — do NOT try to bypass it; the guard exists to stop the
"I forgot to turn on identity and pushed a wildcard bind" incident.
