//! Harness configuration (TOML surface, versioned).

use serde::{Deserialize, Serialize};

/// Config format version (evolution surface).
pub const CONFIG_VERSION: u32 = 1;

/// Upper bound on `worker_channel_capacity`. `tokio::sync::mpsc::channel`
/// does not preallocate slots (it links chunks lazily under a Semaphore),
/// but an oversized value still lets the per-shard buffers grow
/// unboundedly under overload and hides real backpressure signals. 1M
/// is orders of magnitude above realistic capacity — this bound is
/// defence-in-depth against a fat-finger, not a hard OOM prevention.
pub const MAX_WORKER_CHANNEL_CAPACITY: usize = 1_000_000;

/// Upper bound on `max_request_bytes` (512 MiB). A single request body
/// should never legitimately need more; lifting this defeats the
/// sandbox payload guard and lets one request pin half a GB of RAM.
pub const MAX_REQUEST_BYTES_CAP: usize = 512 * 1024 * 1024;

/// Upper bound on `onnx_dimension`. Most sentence-transformer models
/// have <= 4096 dims (Nomic Embed v1.5 = 768, MiniLM = 384, e5-mistral
/// = 4096, Ada-002 = 1536). 16k is a comfortable ceiling.
pub const MAX_ONNX_DIMENSION: usize = 16_384;

/// Upper bound on any `_s` seconds interval. 1 day is already far
/// beyond any reasonable value; anything larger is almost certainly a
/// unit-conversion error (someone thought the field was in ms).
pub const MAX_SECONDS_INTERVAL: u64 = 24 * 60 * 60;

/// Per-phase timeout applied to both the worker `wait_idle` drain and
/// the `finalize_sessions` sweep in `finish_shutdown`. Exposed on the
/// public surface so the deployment-manifest pin tests below can
/// compute the total shutdown budget from the SAME source of truth
/// `main.rs` uses — a bump here that isn't matched by a bump in the
/// K8s / compose grace periods trips CI at build time.
pub const WORKER_FINALIZE_PHASE_SECS: u64 = 30;

/// Deadline the OpenTelemetry provider gets to flush pending spans on
/// shutdown when the `otel` feature is enabled. Same "single source of
/// truth" purpose as [`WORKER_FINALIZE_PHASE_SECS`].
pub const OTEL_FLUSH_SECS: u64 = 5;

/// Default upstream read timeout (per-chunk) when `upstream_read_timeout_s`
/// is unset. Public because [`HarnessConfig::effective_drain_timeout`]
/// needs it to preserve the "one in-flight request cannot outlive the
/// drain window" invariant its doc-comment promises — using two
/// separate defaults (30 in the derivation, 60 in the pipeline) let a
/// legitimate 60 s upstream read outlast a 30 s drain when both were
/// left unset in the config.
pub const DEFAULT_UPSTREAM_READ_TIMEOUT_S: u64 = 60;

/// Top-level harness configuration.
///
/// Unknown keys are rejected (`deny_unknown_fields`) so a typo like
/// `idel_timeout_s` fails loudly at startup instead of being silently
/// ignored. Forward compatibility is handled by `config_version` gating,
/// not by tolerating unrecognized keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HarnessConfig {
    /// Config format version.
    #[serde(default = "default_config_version")]
    pub config_version: u32,
    /// Listen address, e.g. `127.0.0.1:8484`.
    #[serde(default = "default_listen")]
    pub listen: String,
    /// Upstream LLM provider base URL (OpenAI-compatible).
    pub upstream_url: String,
    /// Optional downstream MCP/REST tool server URL. When absent, `/v1/mcp`
    /// operates as a policy decision endpoint.
    #[serde(default)]
    pub tool_upstream_url: Option<String>,
    /// Use cleartext HTTP/2 prior knowledge for trusted h2c upstreams.
    #[serde(default)]
    pub upstream_http2_prior_knowledge: bool,
    /// Optional provider read-idle timeout override. When unset the
    /// pipeline applies its 60 s default unconditionally
    /// — streams cannot be held indefinitely; widen this to extend it
    /// (capped at one day like every `_s` interval).
    #[serde(default)]
    pub upstream_read_timeout_s: Option<u64>,
    /// Graceful-shutdown drain budget in seconds. When unset the
    /// effective budget is `max(30, upstream_read_timeout_s + 5)` so a
    /// single legitimate in-flight request cannot outlive the drain
    /// window by construction (this budget was once
    /// a hardcoded 30 s while shipped configs set a 300 s read timeout
    /// — every rollout with one live long request exited 1 and paged).
    /// Kubernetes users must keep `terminationGracePeriodSeconds`
    /// above this value or the kubelet SIGKILLs mid-drain.
    #[serde(default)]
    pub shutdown_drain_timeout_s: Option<u64>,
    /// Readiness-controlled pre-drain window in seconds (default 0).
    /// On SIGTERM/SIGINT the harness flips `/readyz` to 503 and then
    /// KEEPS ACCEPTING connections for this long before the graceful
    /// drain begins, so an external load balancer polling `/readyz`
    /// can stop routing before the listener closes. Without it the
    /// listener stops accepting the instant the signal lands and a
    /// fresh readiness probe sees connection-refused, never the 503.
    /// Set it to your LB's readiness poll interval plus one
    /// reconciliation. Counts against the orchestrator's kill grace
    /// period ON TOP of the drain budget.
    ///
    /// Kubernetes note: a preStop `sleep` hook can theoretically
    /// provide the same window BEFORE SIGTERM lands, but only if
    /// the runtime image contains a shell + `sleep`. The shipped
    /// manifest at `deploy/kubernetes/agentvisor-ai.yaml` uses a
    /// distroless base (chainguard/glibc-dynamic) that has neither,
    /// so it sets this key instead and omits the preStop hook.
    /// Bare-VM, systemd, and docker-compose deployments also need
    /// this key because they have no preStop equivalent at all.
    #[serde(default)]
    pub shutdown_ready_drain_s: u64,
    /// Chat-completions path appended to `upstream_url`. Override for
    /// providers with non-standard layouts (Azure deployments, Gemini's
    /// OpenAI-compatible surface).
    #[serde(default = "default_chat_path")]
    pub upstream_chat_path: String,
    /// The upstream provider's wire dialect.
    /// Selects the `ProviderAdapter` that parses response bodies and
    /// SSE chunks. `"openai"` (the default) also fits vLLM, LiteLLM,
    /// Groq, Together, DeepSeek, OpenRouter, Ollama, LM Studio,
    /// llama.cpp, xAI, Mistral and Azure OpenAI.
    #[serde(default = "default_provider")]
    pub provider: String,
    /// Name of an environment variable holding the upstream API key. The
    /// key value itself never appears in this file or on the command line.
    #[serde(default)]
    pub upstream_api_key_env: Option<String>,
    /// File containing the upstream API key (owner-only permissions are
    /// enforced on Unix). Mutually exclusive with `upstream_api_key_env`.
    #[serde(default)]
    pub upstream_api_key_file: Option<String>,
    /// Header carrying the upstream API key, e.g. `authorization` (OpenAI),
    /// `api-key` (Azure), or `x-api-key`.
    #[serde(default = "default_auth_header")]
    pub upstream_auth_header: String,
    /// Prefix inserted before the key in the auth header. `"Bearer"` yields
    /// `Bearer <key>`; an empty string sends the raw key (Azure style).
    #[serde(default = "default_auth_scheme")]
    pub upstream_auth_scheme: String,
    /// Forward each client's own `Authorization` header to the upstream
    /// instead of injecting a server-side key. Incompatible with
    /// `require_identity` (the header would carry the NHI token) and with
    /// the static key options above.
    #[serde(default)]
    pub upstream_authorization_passthrough: bool,
    /// Accept and DISCARD a client `Authorization` header when no identity
    /// validator is configured. This is the "hero snippet" mode: every
    /// stock OpenAI SDK requires an `api_key` and sends
    /// `Authorization: Bearer <it>` unconditionally, but a dev harness
    /// with no validator used to hard-401 that request — making the
    /// documented one-line quickstart fail on request one. With this
    /// flag the header is treated as if absent: the request proceeds
    /// anonymously, the header is NEVER forwarded upstream (the
    /// server-side key is injected instead), and nothing is recorded
    /// from it. Refused in combination with `require_identity = true`
    /// (the validator must see the header) and with
    /// `upstream_authorization_passthrough = true` (contradictory:
    /// cannot both discard and forward). `avctl init` writes this for
    /// dev presets so the README quickstart works out of the box.
    #[serde(default)]
    pub ignore_client_authorization: bool,
    /// Name of an environment variable holding a bearer token for
    /// `tool_upstream_url` requests.
    #[serde(default)]
    pub tool_upstream_bearer_env: Option<String>,
    /// File containing a bearer token for `tool_upstream_url` requests
    /// (owner-only permissions enforced on Unix).
    #[serde(default)]
    pub tool_upstream_bearer_file: Option<String>,
    /// Identity enforcement. When `false` (dev), requests without a token get
    /// an anonymous identity; when `true`, unauthenticated requests are 401s.
    #[serde(default)]
    pub require_identity: bool,
    /// Explicit opt-in for binding to a wildcard address (`0.0.0.0` / `[::]`)
    /// while `require_identity = false`. Set this only when a network layer
    /// outside the harness — a container port map, a service mesh, an
    /// ingress ACL — controls who can reach the listener. Startup validation
    /// otherwise refuses the combination so a bare-metal `cargo run` on a
    /// developer laptop cannot silently expose an anonymous provider proxy
    /// to a corporate LAN.
    #[serde(default)]
    pub allow_wildcard_bind: bool,
    /// Deployment audience for NHI tokens.
    #[serde(default = "default_audience")]
    pub audience: String,
    /// Corporate IdP JWKS endpoint for Ed25519 verification keys.
    #[serde(default)]
    pub identity_jwks_url: Option<String>,
    /// JWKS refresh interval in seconds.
    #[serde(default = "default_jwks_refresh")]
    pub identity_jwks_refresh_s: u64,
    /// Optional issuer allowlist (for example Okta or Entra tenant URLs).
    #[serde(default)]
    pub identity_allowed_issuers: Vec<String>,
    /// Optional file containing an HS256 development secret.
    #[serde(default)]
    pub identity_hmac_secret_file: Option<String>,
    /// Key id assigned to the development HMAC secret.
    #[serde(default = "default_hmac_kid")]
    pub identity_hmac_kid: String,
    /// Enforce operation scopes on validated identities.
    ///
    /// Default flipped from `true` to `false` so it
    /// matches the also-default-`false` posture of
    /// [`Self::require_identity`]. When `require_identity = false`,
    /// unauthenticated requests short-circuit to the anonymous
    /// identity BEFORE the scope gate runs — an operator who reads
    /// `enforce_identity_scopes = true` in the config would
    /// reasonably conclude "you need the scope to reach /v1/chat",
    /// but in the default posture curl-with-no-header still
    /// proceeds as anonymous. `validate()` now rejects the
    /// `enforce_identity_scopes = true && require_identity = false`
    /// combination outright; keeping the two defaults aligned makes
    /// the shipped `harness.example.toml` and `harness.container.toml`
    /// pass validate without extra changes. Operators turning on
    /// identity enforcement in production set both flags to `true`
    /// explicitly (see `harness.docker.toml`).
    #[serde(default)]
    pub enforce_identity_scopes: bool,
    /// Scope required for chat completion requests.
    #[serde(default = "default_chat_scope")]
    pub chat_scope: String,
    /// Scope required to close sessions.
    #[serde(default = "default_close_scope")]
    pub session_close_scope: String,
    /// Scope required to promote unsigned sessions.
    #[serde(default = "default_promote_scope")]
    pub session_promote_scope: String,
    /// Default workflow when `X-AV-Workflow` is absent: signed workflows are
    /// opt-in by policy (brief Module G).
    #[serde(default = "default_workflow")]
    pub default_workflow: String,
    /// Tools that require a signed workflow because they have real-world
    /// consequences.
    #[serde(default = "default_consequential_tools")]
    pub consequential_tools: Vec<String>,
    /// Directory containing one JSON Schema per tool, named `<tool>.json`.
    #[serde(default = "default_tool_schema_dir")]
    pub tool_schema_dir: Option<String>,
    /// Reject tool calls when no matching schema was loaded.
    #[serde(default = "default_true")]
    pub require_tool_schema: bool,
    /// Tool-call argument field carrying a payout amount in USD, charged
    /// against `budget.max_payout_usd_micros`. This was a
    /// hardcoded `"amount_usd"` buried in the sandbox constructor — a
    /// tool using `amount`, `value`, or `total_usd` silently bypassed
    /// the payout cap with no warning. Set this to match YOUR tool
    /// schema; the cap only fires on calls that carry this exact field.
    #[serde(default = "default_payout_field")]
    pub payout_field: String,
    /// WASM or WAT policy module paths, evaluated in order.
    #[serde(default = "default_wasm_policies")]
    pub wasm_policy_paths: Vec<String>,
    /// Idle seconds after which a session is swept closed.
    #[serde(default = "default_idle")]
    pub session_idle_close_s: u64,
    /// Directory for ATIF trajectory spool files.
    #[serde(default = "default_spool")]
    pub atif_spool_dir: String,
    /// Bridge data directory (embedded broker).
    #[serde(default = "default_bridge")]
    pub bridge_data_dir: String,
    /// Bridge backend: `embedded`, `kafka`, or `nats`.
    #[serde(default = "default_bridge_backend")]
    pub bridge_backend: String,
    /// Declarative topic-schema manifest used by every Bridge backend.
    #[serde(default = "default_bridge_manifest")]
    pub bridge_manifest_path: String,
    /// Kafka broker (`host:port[,host:port]`) or NATS URL (`nats://`/`tls://`)
    /// for network Bridge backends. Secured endpoints read their material
    /// from the environment: `AV_KAFKA_CA_FILE` + `AV_KAFKA_SASL_USERNAME`/
    /// `AV_KAFKA_SASL_PASSWORD` (+ optional `AV_KAFKA_SASL_MECHANISM`:
    /// `SCRAM-SHA-256` default, `SCRAM-SHA-512`, or `PLAIN`; credentials
    /// are refused without the CA), and `AV_NATS_CA_FILE` (forces TLS) +
    /// `AV_NATS_USER`/`AV_NATS_PASSWORD`.
    #[serde(default)]
    pub bridge_endpoint: Option<String>,
    /// State backend: `memory` or `redis`.
    #[serde(default = "default_state_backend")]
    pub state_backend: String,
    /// Redis URL for the distributed state backend. A comma-separated list
    /// of URLs selects Redis Cluster mode.
    #[serde(default)]
    pub state_endpoint: Option<String>,
    /// Embedding backend: `hash` or `onnx`.
    #[serde(default = "default_embedder_backend")]
    pub embedder_backend: String,
    /// Customer-supplied ONNX model path.
    #[serde(default)]
    pub onnx_model_path: Option<String>,
    /// Hugging Face tokenizer.json paired with the ONNX model.
    #[serde(default)]
    pub onnx_tokenizer_path: Option<String>,
    /// ONNX model output width.
    #[serde(default = "default_onnx_dimension")]
    pub onnx_dimension: usize,
    /// Vector persistence backend: `memory` or `qdrant`.
    #[serde(default = "default_vector_backend")]
    pub vector_backend: String,
    /// Qdrant base URL.
    #[serde(default)]
    pub qdrant_url: Option<String>,
    /// Qdrant collection receiving reasoning vectors.
    #[serde(default = "default_qdrant_collection")]
    pub qdrant_collection: String,
    /// Worker channel capacity (bounded; overflow is counted, never blocking).
    #[serde(default = "default_channel_cap")]
    pub worker_channel_capacity: usize,
    /// Strict per-stage budget assertions (AV_STRICT_BUDGET also enables).
    #[serde(default)]
    pub strict_stage_budget: bool,
    /// Loop breaker configuration.
    #[serde(default)]
    pub breaker: av_loopdetect::BreakerConfig,
    /// Compression configuration.
    #[serde(default = "default_compression")]
    pub compression_enabled: bool,
    /// Token budget per session (compression/velocity accounting).
    #[serde(default)]
    pub budget: av_state::BudgetSpec,
    /// Optional principal-scoped budget layered on top of [`Self::budget`].
    ///
    /// The default `[budget]` counters are keyed on the request's session
    /// id — a header the caller chooses (see [`Self::require_identity`]).
    /// A client that rotates `X-AV-Session` per request lands on a virgin
    /// counter every time, so `budget.max_tokens` and friends never bind.
    /// Setting `[principal_budget]` layers a second budget keyed on the
    /// authenticated principal (the JWT `sub` / `instance_uid`, or the
    /// HMAC key id); the counters accumulate across every session belonging
    /// to that principal, so header rotation debits the same ledger.
    ///
    /// Startup validation refuses this section when
    /// `require_identity = false` unless `allow_anonymous_principal_budget
    /// = true` is also set: without a stable principal every request folds
    /// into a single `"anonymous"` bucket, which is only useful in a
    /// single-tenant appliance deployment where that is the desired
    /// behaviour.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_budget: Option<av_state::BudgetSpec>,
    /// Opt-in for `[principal_budget]` while `require_identity = false`.
    /// See the field-level doc on [`Self::principal_budget`].
    #[serde(default)]
    pub allow_anonymous_principal_budget: bool,
    /// Reconciler tick interval (seconds).
    #[serde(default = "default_reconcile_tick")]
    pub reconcile_tick_s: u64,
    /// Days after which sealed ATIF trajectories and their `.atif-auth`
    /// provenance sidecars are pruned from the spool. `None` (the shipping
    /// default) preserves prior behaviour — the ATIF spool grows without
    /// bound, matching an on-prem deployment that manages retention with
    /// an external cron. Setting a positive value enables a periodic
    /// prune sweep that removes pairs older than the window, keeping the
    /// reconciler's per-tick scan cost bounded even for high-throughput
    /// deployments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub atif_retention_days: Option<u32>,
    /// Maximum request body size accepted on `/v1/chat/completions` and
    /// `/mcp`. Defaults to 4 MiB, matching the sandbox's `MAX_PAYLOAD_BYTES`
    /// so both routes carry the same effective limit — axum's own
    /// `DefaultBodyLimit::MAX` is 2 MiB by default and would silently
    /// reject legitimate large-context chat requests before the sandbox
    /// even saw the payload. Operators serving very-long-context models
    /// (Claude 200k, GPT-4 128k on maximally-verbose inputs) may need to
    /// raise this.
    #[serde(default = "default_max_request_bytes")]
    pub max_request_bytes: usize,

    /// Whether the built-in read-only operator dashboard is enabled.
    ///
    /// When true (the default), the harness serves:
    ///   * `GET /dashboard` — an HTML/CSS/JS single-page dashboard,
    ///   * `GET /dashboard/{style.css,app.js}` — the bundled assets,
    ///   * `GET /api/v1/dashboard/{stats,sessions,sessions/:id}` — read-only
    ///     JSON that mirrors the in-memory session registry.
    ///
    /// The endpoints are unauthenticated: they expose the same data that
    /// already lands on disk (receipts) and in `/metrics`. Front the
    /// harness with the same ingress control you use for `/metrics` if
    /// this is a concern, or set this to `false` to disable them.
    #[serde(default = "default_dashboard_enabled")]
    pub dashboard_enabled: bool,

    /// Host-header allowlist (DNS-rebinding defense).
    ///
    /// Empty (the default) disables the check — correct for
    /// loopback-only binds and for deployments whose ingress already
    /// enforces Host. When non-empty, every request whose `Host`
    /// header (port stripped) is not in this list is refused with 403
    /// BEFORE any handler runs. DNS rebinding lets a hostile page's
    /// JavaScript reach a loopback-adjacent service under a hostname
    /// the attacker controls; browser CSRF protections don't apply
    /// because the resolved IP is ours while the Host is theirs —
    /// pinning the expected hostnames closes it. Example:
    /// `allowed_hosts = ["localhost", "127.0.0.1", "agentvisor.internal"]`.
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
}

fn default_config_version() -> u32 {
    CONFIG_VERSION
}
fn default_listen() -> String {
    "127.0.0.1:8484".to_owned()
}
fn default_audience() -> String {
    "agentvisor-ai".to_owned()
}
fn default_chat_path() -> String {
    "/v1/chat/completions".to_owned()
}
fn default_auth_header() -> String {
    "authorization".to_owned()
}
fn default_auth_scheme() -> String {
    "Bearer".to_owned()
}
fn default_jwks_refresh() -> u64 {
    300
}
fn default_hmac_kid() -> String {
    "dev-hmac".to_owned()
}
fn default_chat_scope() -> String {
    "chat:write".to_owned()
}
fn default_close_scope() -> String {
    "session:close".to_owned()
}
fn default_promote_scope() -> String {
    "session:promote".to_owned()
}
fn default_workflow() -> String {
    crate::session::Workflow::Unsigned.as_str().to_owned()
}
fn default_consequential_tools() -> Vec<String> {
    ["db_write", "payout", "merge", "deploy"]
        .into_iter()
        .map(str::to_owned)
        .collect()
}
fn default_tool_schema_dir() -> Option<String> {
    Some("config/tool-schemas".to_owned())
}
fn default_true() -> bool {
    true
}
fn default_payout_field() -> String {
    "amount_usd".to_owned()
}
fn default_wasm_policies() -> Vec<String> {
    vec!["config/policies/payload_limit.wat".to_owned()]
}
fn default_idle() -> u64 {
    900
}
fn default_spool() -> String {
    "spool/atif".to_owned()
}
fn default_bridge() -> String {
    "data/bridge".to_owned()
}
fn default_bridge_backend() -> String {
    "embedded".to_owned()
}
fn default_provider() -> String {
    "openai".to_owned()
}
fn default_bridge_manifest() -> String {
    "manifests/bridge.example.yaml".to_owned()
}
fn default_state_backend() -> String {
    "memory".to_owned()
}
fn default_embedder_backend() -> String {
    "hash".to_owned()
}
fn default_onnx_dimension() -> usize {
    384
}
fn default_vector_backend() -> String {
    "memory".to_owned()
}
fn default_qdrant_collection() -> String {
    "agent_steps".to_owned()
}
fn default_channel_cap() -> usize {
    32_768
}
fn default_compression() -> bool {
    true
}
fn default_reconcile_tick() -> u64 {
    5
}
fn default_max_request_bytes() -> usize {
    4 * 1024 * 1024
}
fn default_dashboard_enabled() -> bool {
    true
}

/// Typed bridge backend selection, resolved from the flat TOML fields.
///
/// The TOML wire format deliberately keeps the shipped flat keys
/// (`bridge_backend = "kafka"` + `bridge_endpoint = …`): this is a
/// public tool with configs in the field, and a `config_version` bump
/// that strands them is a hazard. Everything downstream of parsing
/// works with these enums instead — each variant carries its required
/// companions, so "kafka without an endpoint" is unrepresentable once
/// resolved. The per-selector accessors on [`HarnessConfig`]
/// ([`HarnessConfig::bridge`] and friends) are the SINGLE site that
/// owns the legal-value vocabulary and the required-companion rules;
/// `validate()` and the daemon's backend factories both delegate to
/// them (previously the four selectors were `String`s whose
/// legal values were enumerated twice, with companion rules spread
/// across four more sites).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BridgeBackend {
    /// Embedded broker persisting under `bridge_data_dir`.
    Embedded,
    /// Kafka/Redpanda; `endpoint` is the `host:port[,host:port]`
    /// bootstrap list (not a URL — no scheme check applies).
    Kafka {
        /// Bootstrap list, `host:port[,host:port]`.
        endpoint: String,
    },
    /// NATS JetStream; `endpoint` is a `nats://` or `tls://` URL.
    Nats {
        /// `nats://` or `tls://` URL.
        endpoint: String,
    },
}

/// Typed state backend selection. See [`BridgeBackend`] for why the
/// TOML surface stays flat while the resolved form is an enum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateBackend {
    /// Process-local, non-durable counters.
    Memory,
    /// Redis / Redis Cluster; `endpoint` is one URL or a
    /// comma-separated list (cluster mode).
    Redis {
        /// Redis URL, or a comma-separated list for cluster mode.
        endpoint: String,
    },
}

/// Typed embedding backend selection. See [`BridgeBackend`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmbedderBackend {
    /// Deterministic hash embedder (no model files).
    Hash,
    /// Customer-supplied ONNX model plus its Hugging Face tokenizer.
    Onnx {
        /// Path to the ONNX model file.
        model_path: String,
        /// Path to the paired Hugging Face `tokenizer.json`.
        tokenizer_path: String,
    },
}

/// Typed vector persistence backend selection. See [`BridgeBackend`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VectorBackend {
    /// No persistence (in-memory no-op sink).
    Memory,
    /// Qdrant; `url` is the http(s) base URL.
    Qdrant {
        /// Qdrant base URL (http:// or https://).
        url: String,
    },
}

/// All four backend selections resolved into their typed forms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedBackends {
    /// Resolved bridge (event bus) backend.
    pub bridge: BridgeBackend,
    /// Resolved state store backend.
    pub state: StateBackend,
    /// Resolved embedding backend.
    pub embedder: EmbedderBackend,
    /// Resolved vector persistence backend.
    pub vector: VectorBackend,
}

/// Where the effective configuration came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigSource {
    /// Loaded from a TOML file on disk.
    File(std::path::PathBuf),
    /// Built-in defaults (zero-config mode; requires `AV_UPSTREAM_URL`).
    BuiltIn,
}

impl std::fmt::Display for ConfigSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::File(path) => write!(f, "{}", path.display()),
            Self::BuiltIn => f.write_str("built-in defaults (zero-config)"),
        }
    }
}

/// Well-known config locations probed in order when `AV_CONFIG` is unset.
/// Project-local files (current directory) beat the per-user file the
/// `avctl` setup wizard writes (see [`user_config_path`]).
///
/// Note: `config/harness.example.toml` is deliberately NOT in this list.
/// The example config is a template intended to be *copied* to a real
/// `agentvisor.toml` or `config/harness.toml`; auto-discovering it from
/// a working checkout silently defeats the wizard-written per-user file
/// (developers who ran `avctl init` still saw the example's settings
/// because the example outranked the wizard file).
pub const CONFIG_SEARCH_PATHS: [&str; 2] = ["agentvisor.toml", "config/harness.toml"];

/// Per-user config file inside `home`, as written by the `avctl` wizard.
pub fn user_config_path_from(home: &std::path::Path) -> std::path::PathBuf {
    home.join(".agentvisor").join("agentvisor.toml")
}

/// Per-user config file (`~/.agentvisor/agentvisor.toml`), if the home
/// directory is known.
pub fn user_config_path() -> Option<std::path::PathBuf> {
    #[allow(deprecated)] // undeprecated in Rust 1.86; MSRV is 1.88
    std::env::home_dir().map(|home| user_config_path_from(&home))
}

/// Resolve the configuration source without reading it.
///
/// Order: `AV_CONFIG` (must exist — a typo must never silently fall
/// through to another file), then [`CONFIG_SEARCH_PATHS`], then the
/// per-user wizard file, then built-in defaults driven by
/// `AV_UPSTREAM_URL`.
pub fn resolve_config_source() -> Result<ConfigSource, String> {
    if let Some(path) = std::env::var_os("AV_CONFIG") {
        // Empty means unset: compose files commonly render
        // `AV_CONFIG: ${AV_CONFIG:-}` which must not become a hard error.
        if !path.is_empty() {
            let path = std::path::PathBuf::from(path);
            if !path.is_file() {
                return Err(format!(
                    "AV_CONFIG points to {} which does not exist or is not a file",
                    path.display()
                ));
            }
            return Ok(ConfigSource::File(path));
        }
    }
    for candidate in CONFIG_SEARCH_PATHS {
        let path = std::path::Path::new(candidate);
        if path.is_file() {
            return Ok(ConfigSource::File(path.to_path_buf()));
        }
    }
    if let Some(path) = user_config_path() {
        if path.is_file() {
            return Ok(ConfigSource::File(path));
        }
    }
    Ok(ConfigSource::BuiltIn)
}

/// Load, apply environment overrides, and validate the effective config.
pub fn load_config() -> Result<(HarnessConfig, ConfigSource), String> {
    load_config_with_override(None)
}

/// [`load_config`] with an explicit config path (e.g. from `--config`)
/// taking precedence over `$AV_CONFIG` and the search paths. The explicit
/// path must exist — a dangling operator-supplied path is a hard error,
/// never a silent fallback to a different config.
pub fn load_config_with_override(
    explicit: Option<std::path::PathBuf>,
) -> Result<(HarnessConfig, ConfigSource), String> {
    let source = match explicit {
        Some(path) => {
            if !path.is_file() {
                return Err(format!(
                    "--config points to {} which does not exist or is not a file",
                    path.display()
                ));
            }
            ConfigSource::File(path)
        }
        None => resolve_config_source()?,
    };
    let mut config = match &source {
        ConfigSource::File(path) => {
            // Same MAX_CONTROL_BYTES cap as `avctl config-validate`, so
            // the offline validator and the daemon reach the same verdict
            // on the same file (and a mispointed path at a huge file
            // cannot balloon boot memory).
            let text = av_core::fsutil::read_capped_string(
                std::path::Path::new(path),
                av_core::fsutil::MAX_CONTROL_BYTES,
            )
            .map_err(|error| format!("read harness config {}: {error}", path.display()))?;
            HarnessConfig::from_toml_unvalidated(&text)
                .map_err(|error| format!("{}: {error}", path.display()))?
        }
        ConfigSource::BuiltIn => HarnessConfig::builtin()?,
    };
    config.apply_env_overrides();
    if config.upstream_url.is_empty() && source == ConfigSource::BuiltIn {
        return Err(format!(
            "no configuration found and AV_UPSTREAM_URL is not set.\n\
             Quick start (pick one):\n\
             \x20 avctl                              # guided setup\n\
             \x20 avctl init --preset openai        # write an annotated agentvisor.toml\n\
             \x20 AV_UPSTREAM_URL=http://127.0.0.1:11434 agentvisord   # zero-config\n\
             Searched: $AV_CONFIG, {}, ~/.agentvisor/agentvisor.toml",
            CONFIG_SEARCH_PATHS.join(", ")
        ));
    }
    config.validate().map_err(|error| format!("{source}: {error}"))?;
    Ok((config, source))
}

impl HarnessConfig {
    /// Parse from TOML, validating the version and structural sanity.
    pub fn from_toml(s: &str) -> Result<Self, String> {
        Self::check_declared_version(s)?;
        let cfg: Self = toml::from_str(s).map_err(|e| format!("config parse: {e}"))?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Parse from TOML without validating, so environment overrides can be
    /// applied first (`main` validates after [`Self::apply_env_overrides`]).
    pub fn from_toml_unvalidated(s: &str) -> Result<Self, String> {
        Self::check_declared_version(s)?;
        toml::from_str(s).map_err(|e| format!("config parse: {e}"))
    }

    /// Pre-pass on the loosely-parsed document so a config written for a
    /// newer format version reports "unsupported config_version N" instead
    /// of tripping the strict unknown-field rejection on whatever new key
    /// appears first.
    fn check_declared_version(s: &str) -> Result<(), String> {
        let loose: toml::Value = toml::from_str(s).map_err(|e| format!("config parse: {e}"))?;
        if let Some(version) = loose.get("config_version") {
            let declared = version.as_integer().unwrap_or(-1);
            if declared != i64::from(CONFIG_VERSION) {
                return Err(format!(
                    "unsupported config_version {version} (this build supports {CONFIG_VERSION})",
                ));
            }
        }
        Ok(())
    }

    /// A config of pure built-in defaults for zero-config startup. The
    /// caller must supply `upstream_url` (typically `AV_UPSTREAM_URL`)
    /// before validation.
    pub fn builtin() -> Result<Self, String> {
        toml::from_str("upstream_url = \"\"").map_err(|e| format!("built-in config: {e}"))
    }

    /// True when `bridge_manifest_path` is the compiled-in default, i.e.
    /// the operator never chose a manifest. Only then may the binary fall
    /// back to its embedded manifest when the file is absent; an explicit
    /// path that is missing must stay a hard error.
    pub fn uses_default_manifest_path(&self) -> bool {
        self.bridge_manifest_path == default_bridge_manifest()
    }

    /// True when `tool_schema_dir` is the compiled-in default (see
    /// [`Self::uses_default_manifest_path`] for the fallback rationale).
    pub fn uses_default_tool_schema_dir(&self) -> bool {
        self.tool_schema_dir == default_tool_schema_dir()
    }

    /// True when `path` is the compiled-in default WASM policy entry (see
    /// [`Self::uses_default_manifest_path`] for the fallback rationale).
    pub fn is_default_policy_path(path: &str) -> bool {
        default_wasm_policies().iter().any(|entry| entry == path)
    }

    /// Effective graceful-shutdown drain budget. Explicit
    /// `shutdown_drain_timeout_s` wins; otherwise derive
    /// `max(30, upstream_read_timeout_s + 5)` — falling back to the
    /// pipeline's own [`DEFAULT_UPSTREAM_READ_TIMEOUT_S`] when the
    /// field is unset — so one legitimate in-flight request cannot
    /// exceed the drain window (§8.8). Two different defaults here (30
    /// in the derivation, 60 in the pipeline) previously let a 60 s
    /// upstream read outlive a 30 s drain and get truncated by the
    /// drain deadline while the config was still `None` on both sides.
    pub fn effective_drain_timeout(&self) -> std::time::Duration {
        let read_timeout_s = self
            .upstream_read_timeout_s
            .unwrap_or(DEFAULT_UPSTREAM_READ_TIMEOUT_S);
        let seconds = self
            .shutdown_drain_timeout_s
            .unwrap_or_else(|| read_timeout_s.saturating_add(5).max(30));
        std::time::Duration::from_secs(seconds)
    }

    /// Detect the classic footgun of `upstream_url` already ending with the
    /// first segment of `upstream_chat_path` (for example a base URL of
    /// `https://api.openai.com/v1` joined with `/v1/chat/completions`
    /// produces `/v1/v1/...` and a confusing provider 404). Returns the
    /// duplicated segment for warning messages.
    pub fn duplicated_chat_path_segment(&self) -> Option<&str> {
        // The worst variant first: the base URL embeds the entire chat path
        // (a pasted full endpoint URL), so the join repeats all of it.
        if !self.upstream_chat_path.is_empty()
            && self
                .upstream_url
                .trim_end_matches('/')
                .ends_with(&self.upstream_chat_path)
        {
            return Some(self.upstream_chat_path.trim_start_matches('/'));
        }
        let first_segment = self
            .upstream_chat_path
            .trim_start_matches('/')
            .split('/')
            .next()?;
        if first_segment.is_empty() {
            return None;
        }
        let base = self.upstream_url.trim_end_matches('/');
        let last_segment = base.rsplit('/').next()?;
        // A bare scheme+host has no path segments; ignore the host itself.
        if last_segment.contains('.') || last_segment.contains(':') || base.ends_with("//") {
            return None;
        }
        (last_segment == first_segment).then_some(first_segment)
    }

    /// Apply `AV_*` environment overrides from the process environment.
    /// Environment beats file for these scalars (12-factor container
    /// deployments override without editing mounted files). Key *values*
    /// are still never read here — only `AV_UPSTREAM_API_KEY` presence
    /// selects itself as the key source.
    pub fn apply_env_overrides(&mut self) {
        self.apply_env_overrides_from(|name| std::env::var(name).ok());
    }

    /// Testable core of [`Self::apply_env_overrides`].
    pub fn apply_env_overrides_from(&mut self, get: impl Fn(&str) -> Option<String>) {
        let non_empty = |value: String| if value.is_empty() { None } else { Some(value) };
        if let Some(listen) = get("AV_LISTEN").and_then(non_empty) {
            self.listen = listen;
        }
        if let Some(url) = get("AV_UPSTREAM_URL").and_then(non_empty) {
            self.upstream_url = url;
        }
        if let Some(path) = get("AV_UPSTREAM_CHAT_PATH").and_then(non_empty) {
            self.upstream_chat_path = path;
        }
        if let Some(header) = get("AV_UPSTREAM_AUTH_HEADER").and_then(non_empty) {
            self.upstream_auth_header = header;
        }
        // Empty string is meaningful here: raw-key (schemeless) headers.
        if let Some(scheme) = get("AV_UPSTREAM_AUTH_SCHEME") {
            self.upstream_auth_scheme = scheme;
        }
        if let Some(endpoint) = get("AV_STATE_ENDPOINT").and_then(non_empty) {
            self.state_endpoint = Some(endpoint);
        }
        if let Some(endpoint) = get("AV_BRIDGE_ENDPOINT").and_then(non_empty) {
            self.bridge_endpoint = Some(endpoint);
        }
        if let Some(url) = get("AV_QDRANT_URL").and_then(non_empty) {
            self.qdrant_url = Some(url);
        }
        // Docker/Kubernetes secrets arrive as mounted files; let those
        // deployments point at one without editing config. File beats the
        // AV_UPSTREAM_API_KEY convenience below but never a config-file
        // key source (validate() rejects env+file ambiguity anyway).
        if self.upstream_api_key_env.is_none()
            && self.upstream_api_key_file.is_none()
            && !self.upstream_authorization_passthrough
        {
            if let Some(path) = get("AV_UPSTREAM_KEY_FILE").and_then(non_empty) {
                self.upstream_api_key_file = Some(path);
            }
        }
        // Convenience: exporting AV_UPSTREAM_API_KEY selects itself as the
        // key source unless the file already chose one (file wins so a
        // stray environment variable cannot silently replace a configured
        // source; validate() still rejects genuinely ambiguous configs).
        if self.upstream_api_key_env.is_none()
            && self.upstream_api_key_file.is_none()
            && !self.upstream_authorization_passthrough
            && get("AV_UPSTREAM_API_KEY").and_then(non_empty).is_some()
        {
            self.upstream_api_key_env = Some("AV_UPSTREAM_API_KEY".to_owned());
        }
    }

    /// A required companion field for a non-default backend: present and
    /// non-empty, or the caller's named error.
    fn required_companion<'a>(value: Option<&'a str>, error: &str) -> Result<&'a str, String> {
        value.filter(|v| !v.is_empty()).ok_or_else(|| error.to_owned())
    }

    /// Resolve `bridge_backend` + `bridge_endpoint` into the typed
    /// [`BridgeBackend`]. This is the single site owning the legal-value
    /// vocabulary and the required-companion rule for the bridge
    /// selector; `validate()` and the daemon's bridge factory both
    /// delegate here, so "kafka without an endpoint" cannot survive
    /// parsing.
    pub fn bridge(&self) -> Result<BridgeBackend, String> {
        const ENDPOINT_REQUIRED: &str = "bridge_endpoint is required for kafka and nats backends";
        match self.bridge_backend.as_str() {
            "embedded" => Ok(BridgeBackend::Embedded),
            "kafka" => Ok(BridgeBackend::Kafka {
                endpoint: Self::required_companion(self.bridge_endpoint.as_deref(), ENDPOINT_REQUIRED)?
                    .to_owned(),
            }),
            "nats" => Ok(BridgeBackend::Nats {
                endpoint: Self::required_companion(self.bridge_endpoint.as_deref(), ENDPOINT_REQUIRED)?
                    .to_owned(),
            }),
            other => Err(format!(
                "bridge_backend must be embedded|kafka|nats, got {other:?}"
            )),
        }
    }

    /// Resolve `state_backend` + `state_endpoint` into the typed
    /// [`StateBackend`] (see [`Self::bridge`] for the single-parse-site
    /// rationale).
    pub fn state(&self) -> Result<StateBackend, String> {
        match self.state_backend.as_str() {
            "memory" => Ok(StateBackend::Memory),
            "redis" => Ok(StateBackend::Redis {
                endpoint: Self::required_companion(
                    self.state_endpoint.as_deref(),
                    "state_endpoint is required for the redis backend",
                )?
                .to_owned(),
            }),
            other => Err(format!("state_backend must be memory|redis, got {other:?}")),
        }
    }

    /// Resolve `embedder_backend` + the ONNX companion paths into the
    /// typed [`EmbedderBackend`] (see [`Self::bridge`]).
    pub fn embedder(&self) -> Result<EmbedderBackend, String> {
        const PATHS_REQUIRED: &str =
            "onnx_model_path and onnx_tokenizer_path are required for the onnx backend";
        match self.embedder_backend.as_str() {
            "hash" => Ok(EmbedderBackend::Hash),
            "onnx" => Ok(EmbedderBackend::Onnx {
                model_path: Self::required_companion(self.onnx_model_path.as_deref(), PATHS_REQUIRED)?
                    .to_owned(),
                tokenizer_path: Self::required_companion(
                    self.onnx_tokenizer_path.as_deref(),
                    PATHS_REQUIRED,
                )?
                .to_owned(),
            }),
            other => Err(format!("embedder_backend must be hash|onnx, got {other:?}")),
        }
    }

    /// Resolve `vector_backend` + `qdrant_url` into the typed
    /// [`VectorBackend`] (see [`Self::bridge`]).
    pub fn vector(&self) -> Result<VectorBackend, String> {
        match self.vector_backend.as_str() {
            "memory" => Ok(VectorBackend::Memory),
            "qdrant" => Ok(VectorBackend::Qdrant {
                url: Self::required_companion(
                    self.qdrant_url.as_deref(),
                    "qdrant_url is required for the qdrant vector backend",
                )?
                .to_owned(),
            }),
            other => Err(format!("vector_backend must be memory|qdrant, got {other:?}")),
        }
    }

    /// Resolve all four backend selectors at once. Errors accumulate —
    /// one entry per selector that fails to resolve — matching
    /// `validate()`'s report-everything behaviour.
    pub fn backends(&self) -> Result<ResolvedBackends, Vec<String>> {
        let mut errors = Vec::new();
        let bridge = self.bridge().map_err(|error| errors.push(error)).ok();
        let state = self.state().map_err(|error| errors.push(error)).ok();
        let embedder = self.embedder().map_err(|error| errors.push(error)).ok();
        let vector = self.vector().map_err(|error| errors.push(error)).ok();
        match (bridge, state, embedder, vector) {
            (Some(bridge), Some(state), Some(embedder), Some(vector)) => Ok(ResolvedBackends {
                bridge,
                state,
                embedder,
                vector,
            }),
            _ => Err(errors),
        }
    }

    /// Backends this configuration selects that the *current build*
    /// cannot run because the required cargo feature was compiled out
    /// (`avctl config-validate` once reported "valid" for
    /// `bridge_backend = "kafka"` on a default-features binary; the
    /// daemon then hard-failed at boot — neither pre-flight tool knew
    /// what the binary could actually run). Returns one message per
    /// unsatisfiable selection; empty means every configured backend
    /// is compiled in. `validate()` deliberately does NOT fold this
    /// in: shape validity and build capability are different
    /// questions (a config can be valid for a `--features full`
    /// daemon while the avctl doing the pre-flight was built lean).
    /// Selections that fail to resolve into their typed backend are
    /// skipped here — `validate()` already refuses them, and every
    /// caller (daemon boot, doctor, config-validate) validates first.
    #[must_use]
    pub fn unsupported_backend_requirements(&self) -> Vec<String> {
        let mut missing = Vec::new();
        let mut require = |enabled: bool, field: &str, value: &str, feature: &str| {
            if !enabled {
                missing.push(format!(
                    "{field} = {value:?} requires the `{feature}` cargo feature, \
                     which this build was compiled without (rebuild with \
                     --features {feature} or full)"
                ));
            }
        };
        match self.bridge() {
            Ok(BridgeBackend::Kafka { .. }) => {
                require(cfg!(feature = "kafka"), "bridge_backend", "kafka", "kafka");
            }
            Ok(BridgeBackend::Nats { .. }) => {
                require(cfg!(feature = "nats"), "bridge_backend", "nats", "nats");
            }
            Ok(BridgeBackend::Embedded) | Err(_) => {}
        }
        if matches!(self.state(), Ok(StateBackend::Redis { .. })) {
            require(cfg!(feature = "redis"), "state_backend", "redis", "redis");
        }
        if matches!(self.embedder(), Ok(EmbedderBackend::Onnx { .. })) {
            require(cfg!(feature = "onnx"), "embedder_backend", "onnx", "onnx");
        }
        if matches!(self.vector(), Ok(VectorBackend::Qdrant { .. })) {
            require(cfg!(feature = "qdrant"), "vector_backend", "qdrant", "qdrant");
        }
        missing
    }

    /// Structural validation. Returns the single violation verbatim
    /// (historical error shape) or, for multiple violations, a
    /// numbered aggregate naming all of them.
    pub fn validate(&self) -> Result<(), String> {
        if self.config_version != CONFIG_VERSION {
            // Short-circuit: a config written for a different format
            // version makes every other check meaningless noise.
            return Err(format!(
                "unsupported config_version {} (this build supports {CONFIG_VERSION})",
                self.config_version
            ));
        }
        let mut errors = Vec::new();
        self.collect_validation_errors(&mut errors);
        if errors.len() > 1 {
            return Err(format!(
                "{} config errors:\n  - {}",
                errors.len(),
                errors.join("\n  - ")
            ));
        }
        match errors.pop() {
            None => Ok(()),
            Some(error) => Err(error),
        }
    }

    /// Structural validation, one push per violation:
    /// every check reports independently so a single `avctl
    /// config-validate` run surfaces the complete list — previously
    /// only the first of 60+ checks was reported per round-trip.
    /// Checks after a failed one still run; they operate on owned
    /// string/number fields, so a prior violation can at worst add a
    /// redundant message, never a panic.
    fn collect_validation_errors(&self, errors: &mut Vec<String>) {
        if self.listen.is_empty() {
            errors.push("listen is required (host:port, e.g. 127.0.0.1:8484)".into());
        }
        // Shape-only check: hostnames are resolved at bind time, but a missing
        // or non-numeric port would otherwise pass validation and only fail at
        // server startup, defeating pre-flight `avctl config-validate`/doctor.
        match self.listen.rsplit_once(':') {
            Some((host, port)) if !host.is_empty() && port.parse::<u16>().is_ok() => {}
            _ => {
                errors.push(format!(
                    "listen {:?} must be host:port with a port in 0-65535",
                    self.listen
                ));
            }
        }
        // Refuse an all-interfaces bind with no authentication. `0.0.0.0` /
        // `[::]` / `*` on a machine reachable by anyone but the operator
        // gives every peer a fully-authenticated proxy against the operator's
        // provider key, plus the unauthenticated dashboard when it is on.
        // The escape hatch is explicit: set `require_identity = true` (and
        // configure a JWKS/HMAC source), pin `listen` to a loopback address,
        // or set `allow_wildcard_bind = true` — the last is for container /
        // service-mesh deployments where an outer network layer already
        // controls who reaches the listener.
        if !self.require_identity && !self.allow_wildcard_bind {
            let host = self
                .listen
                .rsplit_once(':')
                .map(|(h, _)| h.trim_start_matches('[').trim_end_matches(']'))
                .unwrap_or("");
            let is_wildcard = matches!(host, "0.0.0.0" | "::" | "*" | "");
            if is_wildcard {
                errors.push(format!(
                    "listen {:?} binds every interface while require_identity = false: any \
                     peer reaching this host would speak to the proxy anonymously with the \
                     operator's provider credentials. Either pin listen to a loopback / \
                     private-network address, set require_identity = true with an \
                     identity_jwks_url / identity_hmac_secret_file, or set \
                     allow_wildcard_bind = true if an outer network layer (container port \
                     map, service mesh, ingress ACL) controls who reaches the listener.",
                    self.listen
                ));
            }
        }
        if self.reconcile_tick_s == 0 {
            errors.push("reconcile_tick_s must be greater than zero".into());
        }
        if self.session_idle_close_s == 0 {
            errors.push(
                "session_idle_close_s must be greater than zero (0 would close every open session at each reconcile tick)"
                    .into(),
            );
        }
        // `atif_retention_days = Some(0)` would deploy a daemon whose
        // hourly sweep computes `max_age = Duration::ZERO`; the sweep
        // predicate is `age < max_age`, which is false for every sealed
        // pair, so every sealed `<stem>.json` + `.atif-auth` +
        // `.close-complete` triple is deleted on the first tick — total
        // loss of the pre-signing evidence chain. `None` (the ship
        // default) disables retention; the CLI `avctl spool-prune
        // --retention-days 0` path is a separate, one-off decommission
        // command and is intentionally not gated here.
        if self.atif_retention_days == Some(0) {
            errors.push(
                "atif_retention_days = 0 would delete every sealed ATIF pair on the first hourly sweep; \
                 omit the field to disable retention, or set >= 1 to enable an N-day window"
                    .into(),
            );
        }
        if self.upstream_url.is_empty() {
            errors.push("upstream_url is required".into());
        }
        if !self.upstream_chat_path.starts_with('/') {
            errors.push(format!(
                "upstream_chat_path must start with '/', got {:?}",
                self.upstream_chat_path
            ));
        }
        if self.upstream_api_key_env.as_deref().is_some_and(str::is_empty) {
            errors.push("upstream_api_key_env must not be empty when set".into());
        }
        if self.upstream_api_key_file.as_deref().is_some_and(str::is_empty) {
            errors.push("upstream_api_key_file must not be empty when set".into());
        }
        if self.upstream_api_key_env.is_some() && self.upstream_api_key_file.is_some() {
            errors.push(
                "set only one of upstream_api_key_env or upstream_api_key_file (ambiguous key source)".into(),
            );
        }
        let has_static_key = self.upstream_api_key_env.is_some() || self.upstream_api_key_file.is_some();
        if self.upstream_authorization_passthrough && has_static_key {
            errors.push(
                "upstream_authorization_passthrough conflicts with upstream_api_key_env/file: choose one auth mode"
                    .into(),
            );
        }
        if self.upstream_authorization_passthrough && self.require_identity {
            errors.push(
                "upstream_authorization_passthrough cannot be combined with require_identity: the \
                 Authorization header carries the NHI token, which must never be sent upstream"
                    .into(),
            );
        }
        if self.ignore_client_authorization && self.require_identity {
            errors.push(
                "ignore_client_authorization cannot be combined with require_identity: the \
                 identity validator must see the Authorization header, not discard it"
                    .into(),
            );
        }
        if self.ignore_client_authorization && self.upstream_authorization_passthrough {
            errors.push(
                "ignore_client_authorization conflicts with upstream_authorization_passthrough: \
                 a client Authorization header cannot be both discarded and forwarded upstream"
                    .into(),
            );
        }
        if axum::http::HeaderName::try_from(self.upstream_auth_header.as_str()).is_err() {
            errors.push(format!(
                "upstream_auth_header {:?} is not a valid HTTP header name",
                self.upstream_auth_header
            ));
        }
        if self
            .upstream_auth_scheme
            .bytes()
            .any(|byte| !(0x21..=0x7e).contains(&byte))
        {
            errors.push(
                "upstream_auth_scheme must contain only visible ASCII with no spaces (use \"\" for a raw key)"
                    .into(),
            );
        }
        if self.tool_upstream_bearer_env.is_some() && self.tool_upstream_bearer_file.is_some() {
            errors.push(
                "set only one of tool_upstream_bearer_env or tool_upstream_bearer_file (ambiguous token source)"
                    .into(),
            );
        }
        // Parity with the
        // `upstream_api_key_env`/`_file` non-empty checks above.
        // The prior code refused ambiguity (both set) and refused
        // dangling (bearer without tool URL), but a caller supplying
        // an explicit empty string would fail only at first tool
        // call — at which point `resolve_upstream_bearer` returns
        // the same "environment variable {name} is not set (or
        // empty)" error the harness surfaces for a missing key.
        // Catch it here so the actionable message reaches the
        // operator at config load.
        if self
            .tool_upstream_bearer_env
            .as_deref()
            .is_some_and(str::is_empty)
        {
            errors.push("tool_upstream_bearer_env must not be empty when set".into());
        }
        if self
            .tool_upstream_bearer_file
            .as_deref()
            .is_some_and(str::is_empty)
        {
            errors.push("tool_upstream_bearer_file must not be empty when set".into());
        }
        if (self.tool_upstream_bearer_env.is_some() || self.tool_upstream_bearer_file.is_some())
            && self.tool_upstream_url.as_deref().is_none_or(str::is_empty)
        {
            errors.push("tool_upstream_bearer_env/file requires tool_upstream_url to be set".into());
        }
        if crate::session::Workflow::parse(&self.default_workflow).is_none() {
            errors.push(format!(
                "default_workflow must be signed|unsigned, got {:?}",
                self.default_workflow
            ));
        }
        // Refuse a principal-scoped budget while identity is optional. Without
        // require_identity=true, every unauthenticated request folds into a
        // single `"anonymous"` principal and the principal ledger becomes a
        // fleet-shared bucket that any caller can drain — the opposite of the
        // anti-rotation property the section is meant to provide. Operators
        // running a single-tenant appliance can flip
        // `allow_anonymous_principal_budget = true` to acknowledge the shape.
        if self.principal_budget.is_some() && !self.require_identity && !self.allow_anonymous_principal_budget
        {
            errors.push(
                "principal_budget was set but require_identity = false: every unauthenticated \
                 request would share a single `anonymous` principal ledger, making the budget \
                 a fleet-wide bucket instead of the per-principal cap it appears to be. Either \
                 set require_identity = true, or set allow_anonymous_principal_budget = true to \
                 acknowledge single-tenant / trusted-network semantics."
                    .into(),
            );
        }
        if self.require_identity
            && self.identity_jwks_url.as_deref().is_none_or(str::is_empty)
            && self
                .identity_hmac_secret_file
                .as_deref()
                .is_none_or(str::is_empty)
        {
            errors.push("require_identity=true needs identity_jwks_url or identity_hmac_secret_file".into());
        }
        // Reject the silent-anonymous-bypass posture.
        // `enforce_identity_scopes = true` looks like it's guarding
        // routes with `chat_scope` / `session_close_scope` / `tool:*`
        // — but the scope check lives INSIDE the `(Some bearer, Some
        // validator)` arm of `Pipeline::resolve_identity`. When
        // `require_identity = false` (the shipped default), a request
        // with no `Authorization` header short-circuits to the
        // anonymous fallback and never sees the scope gate. The
        // operator reads `enforce_identity_scopes = true` in
        // `agentvisor.toml` and reasonably concludes "you need the
        // chat scope to reach /v1/chat/completions" — in fact curl
        // with no header proceeds as `anonymous`, producing the
        // exact repudiation vector the Bearer-case fix
        // documented. Refuse the combo so operators either turn
        // enforcement off (making the posture explicit) or turn
        // identity on.
        if self.enforce_identity_scopes && !self.require_identity {
            errors.push(
                "enforce_identity_scopes=true has no effect while require_identity=false: \
                 unauthenticated requests fall through to the anonymous identity and bypass \
                 the scope gate entirely. Either set require_identity=true, or set \
                 enforce_identity_scopes=false to make the posture explicit."
                    .into(),
            );
        }
        if self.identity_jwks_refresh_s == 0 {
            errors.push("identity_jwks_refresh_s must be greater than zero".into());
        }
        // `tokio::time::interval(Duration::from_secs(0))` panics. Guard
        // against a value that squeaks past the > 0 check via overflow
        // arithmetic elsewhere by requiring a minimum plausible cadence
        // — a JWKS refresh below 30 s hammers the IdP and offers no
        // real benefit at NHI TTLs measured in minutes.
        if self.identity_jwks_refresh_s < 30 {
            errors.push(format!(
                "identity_jwks_refresh_s {} is too aggressive; a value below 30 s hammers the IdP \
                 without benefit given NHI TTLs measured in minutes",
                self.identity_jwks_refresh_s
            ));
        }
        if self.identity_hmac_kid.is_empty() {
            errors.push("identity_hmac_kid must not be empty".into());
        }
        // Scope names must be visible-ASCII non-empty
        // tokens. An empty `chat_scope = ""` under
        // `enforce_identity_scopes = true` + `require_identity =
        // true` used to silently reduce the check to
        // `identity.scopes.contains("")` — some IdPs emit empty
        // scope entries after tokenizing a stray whitespace claim,
        // so tokens without any real scope would satisfy the gate.
        // Also reject whitespace/control bytes (OAuth scope
        // tokens must not be re-tokenizable at any layer).
        for (field, value) in [
            ("chat_scope", &self.chat_scope),
            ("session_close_scope", &self.session_close_scope),
            ("session_promote_scope", &self.session_promote_scope),
        ] {
            if value.is_empty() {
                errors.push(format!("{field} must not be empty"));
            }
            if value.bytes().any(|byte| !(0x21..=0x7e).contains(&byte)) {
                errors.push(format!(
                    "{field} {value:?} must be visible ASCII with no whitespace or control bytes"
                ));
            }
        }
        if self.worker_channel_capacity == 0 {
            errors.push("worker_channel_capacity must be > 0".into());
        }
        if crate::provider::adapter_for(&self.provider).is_none() {
            errors.push(format!(
                "provider must be one of {:?}, got {:?} (Anthropic/Gemini adapters are planned)",
                crate::provider::SUPPORTED_PROVIDERS,
                self.provider
            ));
        }
        if self.bridge_manifest_path.is_empty() {
            errors.push("bridge_manifest_path is required".into());
        }
        // Refuse empty local-fs path fields. If an
        // operator overrides `atif_spool_dir = ""` in TOML (e.g. by
        // accidentally interpolating an unset env variable through a
        // template), every ATIF spool op used to run on Path::new("")
        // whose joins degrade to CWD-relative writes — receipts land
        // in the process CWD instead of the expected volume, recovery
        // scans miss them on the next boot. Same shape for
        // `bridge_data_dir` (embedded broker segments in CWD).
        if self.atif_spool_dir.is_empty() {
            errors.push("atif_spool_dir must not be empty".into());
        }
        if self.bridge_data_dir.is_empty() {
            errors.push("bridge_data_dir must not be empty".into());
        }
        // Refuse any payout_field that isn't visible ASCII. This closes:
        //   - empty and whitespace-only cases
        //   - leading/trailing whitespace
        //   - control characters
        //   - non-ASCII (accents, smart quotes)
        //   - AND the invisible-format class (BOM `\u{FEFF}`, zero-width
        //     space `\u{200B}`, U+2060 word-joiner, ...) that Rust's
        //     `trim()` misses because Unicode `White_Space` does not
        //     include them.
        // The invisible-format class is precisely what a browser or
        // rich-editor paste can inject into a config value, and
        // precisely the class where `serde_json::Value::get(field)`
        // silently misses the real JSON key — the same silent-bypass
        // class this field exists to prevent (see the field-level
        // doc-comment). Real tool schemas' payout field names are
        // always plain identifiers, so operator UX cost is zero.
        // `is_ascii_graphic()` is the visible-ASCII predicate
        // (0x21..=0x7E) shared with `SessionId::parse` and
        // `InstanceUid::parse`.
        if self.payout_field.is_empty() || !self.payout_field.chars().all(|c| c.is_ascii_graphic()) {
            errors.push(
                "payout_field must be non-empty visible ASCII (letters, digits, and \
                 common punctuation only). An empty, whitespace, or invisible-format \
                 (BOM / zero-width) value would match no argument key, silently disabling \
                 max_payout_usd_micros — the very silent-bypass class this field exists \
                 to prevent. Omit the key to use the default, or set it to your tool \
                 schema's payout argument name."
                    .into(),
            );
        }
        // Backend selectors: the typed accessors (`bridge()`, `state()`,
        // `embedder()`, `vector()`) are the single site owning the
        // legal-value vocabulary and the required-companion rules —
        // previously the four String
        // selectors were enumerated twice. The scheme
        // allowlists below run against the *resolved* companion, so
        // they can never fire on a missing value. The TOML wire
        // format is unchanged: shipped flat-key configs keep parsing.
        match self.bridge() {
            Err(error) => errors.push(error),
            Ok(BridgeBackend::Nats { endpoint }) => {
                if !(endpoint.starts_with("nats://") || endpoint.starts_with("tls://")) {
                    errors.push(format!(
                        "bridge_endpoint (nats backend) must be nats:// or tls://, got {endpoint:?}"
                    ));
                }
            }
            // Kafka bridge_endpoint is a `host:port[,host:port]` bootstrap
            // list, not a URL — no scheme check applies. rdkafka rejects
            // malformed values on connect.
            Ok(BridgeBackend::Embedded | BridgeBackend::Kafka { .. }) => {}
        }
        match self.state() {
            Err(error) => errors.push(error),
            Ok(StateBackend::Redis { endpoint }) => {
                // The state_endpoint
                // field is docstring-documented as a comma-separated
                // list of URLs for Redis Cluster mode (see the field
                // doc above). The scheme allowlist used to be a
                // prefix check on the WHOLE string, so
                // `redis://a:6379,http://b` passed validate (the
                // check saw the `redis://` prefix) and only failed
                // at connect. `redis+unix:` was also rejected here
                // even though it's a legitimate Unix-socket form the
                // redis crate accepts and the doctor's
                // `probe_endpoint_any` already recognizes. Split on
                // ',' and validate each member independently.
                for member in endpoint.split(',').map(str::trim).filter(|m| !m.is_empty()) {
                    let ok = member.starts_with("redis://")
                        || member.starts_with("rediss://")
                        || member.starts_with("unix:")
                        || member.starts_with("redis+unix:");
                    if !ok {
                        errors.push(format!(
                            "state_endpoint (redis backend) member {member:?} must be \
                             redis://, rediss://, unix:, or redis+unix: (got {member:?} in {endpoint:?})"
                        ));
                    }
                }
            }
            Ok(StateBackend::Memory) => {}
        }
        if let Err(error) = self.embedder() {
            errors.push(error);
        }
        match self.vector() {
            Err(error) => errors.push(error),
            Ok(VectorBackend::Qdrant { url }) => {
                if !(url.starts_with("http://") || url.starts_with("https://")) {
                    errors.push(format!("qdrant_url must be http:// or https://, got {url:?}"));
                }
            }
            Ok(VectorBackend::Memory) => {}
        }
        if self.onnx_dimension == 0 {
            errors.push("onnx_dimension must be greater than zero".into());
        }
        if self.qdrant_collection.is_empty() {
            errors.push("qdrant_collection must not be empty".into());
        }
        if self.breaker.window == 0 {
            errors.push(
                "breaker.window must be greater than zero (0 trips on token count alone, ignoring semantic similarity)"
                    .into(),
            );
        }
        if !self.breaker.delta_epsilon.is_finite() || self.breaker.delta_epsilon <= 0.0 {
            errors.push(format!(
                "breaker.delta_epsilon must be a finite number greater than zero, got {}",
                self.breaker.delta_epsilon
            ));
        }
        // Upper bounds so a fat-finger in TOML cannot OOM the process
        // before the runtime feels the misconfiguration. Values are
        // deliberately loose: they only reject genuinely absurd numbers.
        if self.worker_channel_capacity > MAX_WORKER_CHANNEL_CAPACITY {
            errors.push(format!(
                "worker_channel_capacity {} exceeds the safety cap of {} — oversized channels hide real backpressure and let per-shard buffers grow unboundedly under overload",
                self.worker_channel_capacity, MAX_WORKER_CHANNEL_CAPACITY
            ));
        }
        if self.max_request_bytes == 0 {
            errors.push(
                "max_request_bytes must be > 0 — a 0 cap forwards to DefaultBodyLimit::max(0), \
                 rejecting every non-empty POST body silently"
                    .into(),
            );
        }
        if self.max_request_bytes > MAX_REQUEST_BYTES_CAP {
            errors.push(format!(
                "max_request_bytes {} exceeds the safety cap of {} (512 MiB) — a single request should never legitimately need more, and lifting this defeats the sandbox payload guard",
                self.max_request_bytes, MAX_REQUEST_BYTES_CAP
            ));
        }
        if self.onnx_dimension > MAX_ONNX_DIMENSION {
            errors.push(format!(
                "onnx_dimension {} exceeds the safety cap of {} — most sentence-transformer models are <= 4096",
                self.onnx_dimension, MAX_ONNX_DIMENSION
            ));
        }
        // 1 day is already unreasonably long for either an idle window
        // or a JWKS refresh cadence; anything larger is almost certainly
        // a unit-conversion error (someone thought the field was in ms).
        let mut interval_fields: Vec<(&'static str, u64)> = vec![
            ("reconcile_tick_s", self.reconcile_tick_s),
            ("session_idle_close_s", self.session_idle_close_s),
            ("identity_jwks_refresh_s", self.identity_jwks_refresh_s),
        ];
        if let Some(read_timeout) = self.upstream_read_timeout_s {
            // 0 passes the cap check below but makes reqwest's
            // read_timeout fire immediately — every upstream request
            // fails before the first byte arrives.
            if read_timeout == 0 {
                errors.push(
                    "upstream_read_timeout_s = 0 would time out every upstream read immediately — omit the key to use the built-in 60 s default".into(),
                );
            }
            interval_fields.push(("upstream_read_timeout_s", read_timeout));
        }
        if let Some(drain) = self.shutdown_drain_timeout_s {
            if drain == 0 {
                errors.push(
                    "shutdown_drain_timeout_s = 0 would abandon every in-flight request at shutdown — omit the key to derive it from upstream_read_timeout_s".into(),
                );
            }
            interval_fields.push(("shutdown_drain_timeout_s", drain));
        }
        if self.shutdown_ready_drain_s > 0 {
            interval_fields.push(("shutdown_ready_drain_s", self.shutdown_ready_drain_s));
        }
        for (field, value) in interval_fields {
            if value > MAX_SECONDS_INTERVAL {
                errors.push(format!(
                    "{field} = {value} exceeds the safety cap of {MAX_SECONDS_INTERVAL} seconds (1 day) — did you mean milliseconds?"
                ));
            }
        }
        // Shape-only URL check: reject `upstream_url` that lacks a
        // scheme, so an operator setting e.g. `upstream_url =
        // "openai.internal"` (missing `https://`) does not silently
        // concatenate into a broken url. Full url::Url::parse is
        // deferred to reqwest at request time.
        //
        // Tighten to a strict http/https allowlist so
        // this matches the posture applied to
        // `identity_jwks_url`, `qdrant_url`, etc. The old
        // `contains("://")` check accepted `file:///etc/passwd`,
        // `gopher://…`, and other schemes even though the error text
        // claimed "must be http:// or https://" — a config-injection
        // primitive or a templating typo (`${UPSTREAM:-file:///…}`)
        // used to pass `avctl config-validate` and only fail at
        // request time. Now every URL field's shape is preflighted
        // by the same rule.
        if !(self.upstream_url.starts_with("http://") || self.upstream_url.starts_with("https://")) {
            errors.push(format!(
                "upstream_url must be http:// or https://, got {:?}",
                self.upstream_url
            ));
        }
        // A scheme with no host (`http://`, `https:///path`) passed the
        // prefix check above, booted, and validated cleanly, failing
        // only at request time with a 502 — exactly the class this
        // preflight exists to catch at startup.
        {
            let rest = self
                .upstream_url
                .split_once("://")
                .map(|(_, rest)| rest)
                .unwrap_or_default();
            let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
            if host.is_empty() {
                errors.push(format!("upstream_url has no host, got {:?}", self.upstream_url));
            }
        }
        if let Some(tool_upstream) = &self.tool_upstream_url {
            // Empty is rejected rather than treated as unset: routing gates
            // tool forwarding on `is_some()` (routes.rs), so an empty string
            // would silently enable the tool-upstream branches and only fail
            // at the first request with a reqwest URL error. Fail loudly at
            // startup like every other config-shape problem.
            if tool_upstream.is_empty() {
                errors.push(
                    "tool_upstream_url must not be empty; omit the field to disable tool forwarding"
                        .to_owned(),
                );
            }
            if !(tool_upstream.starts_with("http://") || tool_upstream.starts_with("https://")) {
                errors.push(format!(
                    "tool_upstream_url must be http:// or https://, got {tool_upstream:?}"
                ));
            }
            // Same hostless-URL preflight as `upstream_url` above: a
            // scheme with no host (`http://`, `https:///mcp`) passed
            // validation, booted, then failed every tool call at
            // request-build time — a fail-late shape that also leaves
            // claimed executions churning TOOL_OUTCOME_UNCERTAIN.
            let rest = tool_upstream
                .split_once("://")
                .map(|(_, rest)| rest)
                .unwrap_or_default();
            let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
            if !tool_upstream.is_empty() && host.is_empty() {
                errors.push(format!("tool_upstream_url has no host, got {tool_upstream:?}"));
            }
        }
        // Extend the scheme allowlist to every URL
        // field. `identity_jwks_url`, `qdrant_url`, `bridge_endpoint`
        // (when NATS), and `state_endpoint` (when Redis) all used to
        // be handed to their respective clients without preflight.
        // A typo like `identity_jwks_url = "auth.internal/jwks"`
        // (missing scheme) would pass `avctl config-validate` and
        // only fail at first fetch — after the process was already
        // serving traffic with an empty validator (every token ->
        // UnknownKid). A hostile config-injection
        // `identity_jwks_url = "file:///etc/passwd"` used to be
        // just as invisible. Reject shape early.
        if let Some(url) = self
            .identity_jwks_url
            .as_deref()
            .filter(|value| !value.is_empty())
        {
            if !(url.starts_with("http://") || url.starts_with("https://")) {
                errors.push(format!(
                    "identity_jwks_url must be http:// or https://, got {url:?}"
                ));
            }
        }
        // The qdrant_url / state_endpoint / bridge_endpoint scheme
        // allowlists live in the typed-backend block above, running
        // against the resolved companion values.
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    /// Register item 25: docs/reference/CONFIGURATION.md claims to be
    /// the configuration reference, yet 29 of 63 fields (including
    /// `default_workflow` and `ignore_client_authorization` — the two
    /// knobs at the center of the onboarding story) shipped
    /// undocumented. Every `HarnessConfig` field must appear in the
    /// reference; adding a config key without documenting it now
    /// fails CI by design.
    #[test]
    fn configuration_reference_documents_every_config_field() {
        let source = include_str!("config.rs");
        let reference = include_str!("../../../docs/reference/CONFIGURATION.md");
        let body = source
            .split_once("pub struct HarnessConfig {")
            .map(|(_, rest)| rest)
            .and_then(|rest| rest.split_once("\n}"))
            .map(|(body, _)| body)
            .unwrap();
        let fields: Vec<&str> = body
            .lines()
            .filter_map(|line| line.trim().strip_prefix("pub "))
            .filter_map(|rest| rest.split_once(':'))
            .map(|(name, _)| name.trim())
            .collect();
        assert!(
            fields.len() >= 60,
            "field extraction broke — found only {} fields",
            fields.len()
        );
        for field in fields {
            assert!(
                reference.contains(&format!("`{field}`")) || reference.contains(&format!("`[{field}]`")),
                "config field `{field}` is not documented in docs/reference/CONFIGURATION.md"
            );
        }
    }

    use super::*;

    #[test]
    fn minimal_toml_parses_with_defaults() {
        let cfg = HarnessConfig::from_toml(r#"upstream_url = "https://api.openai.com""#).unwrap();
        assert_eq!(cfg.config_version, CONFIG_VERSION);
        assert_eq!(cfg.default_workflow, "unsigned");
        assert_eq!(cfg.session_idle_close_s, 900);
        assert!(cfg.compression_enabled);
        assert_eq!(cfg.upstream_chat_path, "/v1/chat/completions");
        assert_eq!(cfg.upstream_auth_header, "authorization");
        assert_eq!(cfg.upstream_auth_scheme, "Bearer");
        assert!(cfg.upstream_api_key_env.is_none());
        assert!(!cfg.upstream_authorization_passthrough);
    }

    /// Validation must surface EVERY violation in one
    /// run, not one per `avctl config-validate` round-trip.
    #[test]
    fn validate_reports_all_errors_at_once() {
        let mut cfg = HarnessConfig::from_toml(r#"upstream_url = "https://api.openai.com""#).unwrap();
        cfg.listen = String::new();
        cfg.bridge_backend = "carrier-pigeon".to_owned();
        cfg.state_backend = "abacus".to_owned();
        let error = cfg.validate().unwrap_err();
        assert!(
            error.contains("config errors"),
            "aggregate header missing: {error}"
        );
        for needle in ["listen", "bridge_backend", "state_backend"] {
            assert!(error.contains(needle), "missing {needle} in: {error}");
        }
    }

    /// A single violation keeps the historical bare-message shape
    /// (no aggregate header) so existing tooling that string-matches
    /// one error keeps working.
    #[test]
    fn validate_single_error_keeps_bare_message() {
        let mut cfg = HarnessConfig::from_toml(r#"upstream_url = "https://api.openai.com""#).unwrap();
        cfg.state_backend = "abacus".to_owned();
        let error = cfg.validate().unwrap_err();
        assert!(
            !error.contains("config errors"),
            "single error must not aggregate: {error}"
        );
        assert!(error.contains("state_backend"), "must name the field: {error}");
    }

    /// An unsupported provider dialect fails
    /// pre-flight, naming the supported set — never mid-stream.
    #[test]
    fn unsupported_provider_is_refused_at_validation() {
        let mut cfg = HarnessConfig::from_toml(r#"upstream_url = "https://api.openai.com""#).unwrap();
        assert_eq!(cfg.provider, "openai");
        cfg.provider = "google".to_owned();
        let error = cfg.validate().unwrap_err();
        assert!(error.contains("provider"), "must name the field: {error}");
        assert!(error.contains("openai"), "must name the supported set: {error}");
        cfg.provider = "anthropic".to_owned();
        assert!(
            cfg.validate().is_ok(),
            "anthropic is a supported dialect (S3 step 2)"
        );
    }

    /// The default backends (embedded/memory/hash/
    /// memory) require no cargo feature and must always be runnable.
    #[test]
    fn default_backends_never_report_unsupported_requirements() {
        let cfg = HarnessConfig::from_toml(r#"upstream_url = "https://api.openai.com""#).unwrap();
        assert!(cfg.unsupported_backend_requirements().is_empty());
    }

    /// Each feature-gated backend is reported exactly
    /// when its cargo feature is compiled out — written against
    /// `cfg!` so the same assertion holds under default features AND
    /// `--all-features` CI runs. Companions are set because feature
    /// detection now runs over the typed backends: a selection that
    /// cannot resolve is `validate()`'s problem, not this method's.
    #[test]
    fn unsupported_backend_requirements_track_build_features() {
        let mut cfg = HarnessConfig::from_toml(r#"upstream_url = "https://api.openai.com""#).unwrap();
        cfg.bridge_backend = "kafka".to_owned();
        cfg.bridge_endpoint = Some("broker:9092".to_owned());
        cfg.state_backend = "redis".to_owned();
        cfg.state_endpoint = Some("redis://cache:6379".to_owned());
        cfg.embedder_backend = "onnx".to_owned();
        cfg.onnx_model_path = Some("model.onnx".to_owned());
        cfg.onnx_tokenizer_path = Some("tokenizer.json".to_owned());
        cfg.vector_backend = "qdrant".to_owned();
        cfg.qdrant_url = Some("http://vectors:6333".to_owned());
        let missing = cfg.unsupported_backend_requirements();
        for (enabled, feature) in [
            (cfg!(feature = "kafka"), "kafka"),
            (cfg!(feature = "redis"), "redis"),
            (cfg!(feature = "onnx"), "onnx"),
            (cfg!(feature = "qdrant"), "qdrant"),
        ] {
            let reported = missing
                .iter()
                .any(|message| message.contains(&format!("`{feature}`")));
            assert_eq!(
                reported, !enabled,
                "feature {feature}: enabled={enabled} but reported={reported} in {missing:?}"
            );
        }
    }

    /// Each backend selector with a missing required companion fails
    /// with an error naming the companion field — the typed accessors
    /// make the invalid combination unrepresentable past parsing.
    #[test]
    fn backend_missing_companion_fails_with_named_error() {
        for (extra, companion) in [
            ("bridge_backend = \"kafka\"", "bridge_endpoint"),
            ("bridge_backend = \"nats\"", "bridge_endpoint"),
            (
                "bridge_backend = \"kafka\"\nbridge_endpoint = \"\"",
                "bridge_endpoint",
            ),
            ("state_backend = \"redis\"", "state_endpoint"),
            ("vector_backend = \"qdrant\"", "qdrant_url"),
            ("embedder_backend = \"onnx\"", "onnx_model_path"),
            (
                // One companion present, the other absent: still refused.
                "embedder_backend = \"onnx\"\nonnx_model_path = \"model.onnx\"",
                "onnx_tokenizer_path",
            ),
        ] {
            let err =
                HarnessConfig::from_toml(&format!("upstream_url = \"https://api\"\n{extra}")).unwrap_err();
            assert!(
                err.contains(companion) && err.contains("required"),
                "{extra}: error must name {companion}: {err}"
            );
        }
    }

    /// An unknown backend value fails naming the exhaustive legal set,
    /// so a typo in `avctl config-validate` output tells the operator
    /// exactly what the field accepts.
    #[test]
    fn unknown_backend_value_names_legal_set() {
        for (field, bogus, legal_set) in [
            ("bridge_backend", "carrier-pigeon", "embedded|kafka|nats"),
            ("state_backend", "abacus", "memory|redis"),
            ("embedder_backend", "vibes", "hash|onnx"),
            ("vector_backend", "faiss", "memory|qdrant"),
        ] {
            let err =
                HarnessConfig::from_toml(&format!("upstream_url = \"https://api\"\n{field} = \"{bogus}\""))
                    .unwrap_err();
            assert!(err.contains(field), "must name the field: {err}");
            assert!(err.contains(legal_set), "must name the legal set: {err}");
            assert!(err.contains(bogus), "must echo the typo: {err}");
        }
    }

    /// A valid full-feature config resolves to the expected typed
    /// backend values, each variant carrying its companion.
    #[test]
    fn full_feature_config_resolves_to_typed_backends() {
        let cfg = HarnessConfig::from_toml(
            r#"upstream_url = "https://api"
               bridge_backend = "kafka"
               bridge_endpoint = "broker-1:9092,broker-2:9092"
               state_backend = "redis"
               state_endpoint = "redis://cache:6379"
               embedder_backend = "onnx"
               onnx_model_path = "models/model.onnx"
               onnx_tokenizer_path = "models/tokenizer.json"
               vector_backend = "qdrant"
               qdrant_url = "http://vectors:6333""#,
        )
        .unwrap();
        let backends = cfg.backends().unwrap();
        assert_eq!(
            backends.bridge,
            BridgeBackend::Kafka {
                endpoint: "broker-1:9092,broker-2:9092".to_owned()
            }
        );
        assert_eq!(
            backends.state,
            StateBackend::Redis {
                endpoint: "redis://cache:6379".to_owned()
            }
        );
        assert_eq!(
            backends.embedder,
            EmbedderBackend::Onnx {
                model_path: "models/model.onnx".to_owned(),
                tokenizer_path: "models/tokenizer.json".to_owned()
            }
        );
        assert_eq!(
            backends.vector,
            VectorBackend::Qdrant {
                url: "http://vectors:6333".to_owned()
            }
        );
        // The defaults resolve to the no-companion variants.
        let cfg = HarnessConfig::from_toml(r#"upstream_url = "https://api""#).unwrap();
        let backends = cfg.backends().unwrap();
        assert_eq!(backends.bridge, BridgeBackend::Embedded);
        assert_eq!(backends.state, StateBackend::Memory);
        assert_eq!(backends.embedder, EmbedderBackend::Hash);
        assert_eq!(backends.vector, VectorBackend::Memory);
    }

    /// `backends()` accumulates one error per unresolvable selector
    /// instead of stopping at the first, mirroring `validate()`.
    #[test]
    fn backends_accumulates_all_resolution_errors() {
        let mut cfg = HarnessConfig::from_toml(r#"upstream_url = "https://api""#).unwrap();
        cfg.bridge_backend = "carrier-pigeon".to_owned();
        cfg.state_backend = "redis".to_owned(); // missing state_endpoint
        cfg.vector_backend = "faiss".to_owned();
        let errors = cfg.backends().unwrap_err();
        assert_eq!(errors.len(), 3, "{errors:?}");
        let joined = errors.join("\n");
        for needle in ["bridge_backend", "state_endpoint", "vector_backend"] {
            assert!(joined.contains(needle), "missing {needle} in {errors:?}");
        }
    }

    /// A typo'd key must fail loudly (naming the offender) instead of being
    /// silently ignored; `config_version` handles forward compatibility.
    #[test]
    fn unknown_config_key_is_rejected_with_its_name() {
        let err = HarnessConfig::from_toml(
            r#"upstream_url = "https://api.openai.com"
               idel_timeout_s = 10"#,
        )
        .unwrap_err();
        assert!(err.contains("idel_timeout_s"), "error must name the key: {err}");
    }

    /// The auth surface must reject every ambiguous or unsafe combination
    /// loudly at startup instead of picking one silently.
    #[test]
    fn upstream_auth_invariants_enforced() {
        // Both key sources set: ambiguous.
        assert!(HarnessConfig::from_toml(
            r#"upstream_url = "https://api.openai.com"
               upstream_api_key_env = "OPENAI_API_KEY"
               upstream_api_key_file = "/etc/key""#
        )
        .is_err());
        // Passthrough plus static key: ambiguous.
        assert!(HarnessConfig::from_toml(
            r#"upstream_url = "https://api.openai.com"
               upstream_api_key_env = "OPENAI_API_KEY"
               upstream_authorization_passthrough = true"#
        )
        .is_err());
        // Passthrough would forward the NHI token upstream.
        assert!(HarnessConfig::from_toml(
            r#"upstream_url = "https://api.openai.com"
               upstream_authorization_passthrough = true
               require_identity = true
               identity_hmac_secret_file = "/run/secrets/hmac""#
        )
        .is_err());
        // Invalid header name.
        assert!(HarnessConfig::from_toml(
            r#"upstream_url = "https://api.openai.com"
               upstream_auth_header = "not a header""#
        )
        .is_err());
        // Scheme with embedded space.
        assert!(HarnessConfig::from_toml(
            r#"upstream_url = "https://api.openai.com"
               upstream_auth_scheme = "Bearer extra""#
        )
        .is_err());
        // Chat path must be absolute.
        assert!(HarnessConfig::from_toml(
            r#"upstream_url = "https://api.openai.com"
               upstream_chat_path = "v1/chat/completions""#
        )
        .is_err());
        // Tool bearer without a tool upstream is a misconfiguration.
        assert!(HarnessConfig::from_toml(
            r#"upstream_url = "https://api.openai.com"
               tool_upstream_bearer_env = "MCP_TOKEN""#
        )
        .is_err());
        // Azure-style raw key header is valid.
        let azure = HarnessConfig::from_toml(
            r#"upstream_url = "https://res.openai.azure.com"
               upstream_chat_path = "/openai/deployments/gpt-4o/chat/completions?api-version=2024-10-21"
               upstream_api_key_env = "AZURE_OPENAI_API_KEY"
               upstream_auth_header = "api-key"
               upstream_auth_scheme = """#,
        )
        .unwrap();
        assert_eq!(azure.upstream_auth_scheme, "");
    }

    #[test]
    fn env_overrides_apply_with_documented_precedence() {
        let mut cfg = HarnessConfig::for_tests("http://file-upstream", "spool", "bridge");
        let env = |name: &str| -> Option<String> {
            match name {
                "AV_LISTEN" => Some("0.0.0.0:9999".into()),
                "AV_UPSTREAM_URL" => Some("http://env-upstream".into()),
                "AV_UPSTREAM_CHAT_PATH" => Some("/openai/v1/chat/completions".into()),
                "AV_UPSTREAM_API_KEY" => Some("sk-secret".into()),
                "AV_STATE_ENDPOINT" => Some("redis://redis:6379".into()),
                _ => None,
            }
        };
        cfg.apply_env_overrides_from(env);
        assert_eq!(cfg.listen, "0.0.0.0:9999");
        assert_eq!(cfg.upstream_url, "http://env-upstream");
        assert_eq!(cfg.upstream_chat_path, "/openai/v1/chat/completions");
        assert_eq!(cfg.state_endpoint.as_deref(), Some("redis://redis:6379"));
        // AV_UPSTREAM_API_KEY presence selects itself as the key source...
        assert_eq!(cfg.upstream_api_key_env.as_deref(), Some("AV_UPSTREAM_API_KEY"));

        // ...but never displaces an explicitly configured source.
        let mut cfg = HarnessConfig::for_tests("http://file-upstream", "spool", "bridge");
        cfg.upstream_api_key_env = Some("OPENAI_API_KEY".into());
        cfg.apply_env_overrides_from(env);
        assert_eq!(cfg.upstream_api_key_env.as_deref(), Some("OPENAI_API_KEY"));

        // Empty environment values are ignored rather than blanking fields.
        let mut cfg = HarnessConfig::for_tests("http://file-upstream", "spool", "bridge");
        cfg.apply_env_overrides_from(|name| (name == "AV_UPSTREAM_URL").then(String::new));
        assert_eq!(cfg.upstream_url, "http://file-upstream");
    }

    #[test]
    fn env_key_file_override_precedence() {
        // AV_UPSTREAM_KEY_FILE selects the mounted-secret file...
        let env = |name: &str| -> Option<String> {
            match name {
                "AV_UPSTREAM_KEY_FILE" => Some("/run/secrets/api_key".into()),
                "AV_UPSTREAM_API_KEY" => Some("sk-secret".into()),
                _ => None,
            }
        };
        let mut cfg = HarnessConfig::for_tests("http://u", "spool", "bridge");
        cfg.apply_env_overrides_from(env);
        assert_eq!(cfg.upstream_api_key_file.as_deref(), Some("/run/secrets/api_key"));
        // ...and beats the AV_UPSTREAM_API_KEY self-selection (no ambiguity).
        assert_eq!(cfg.upstream_api_key_env, None);

        // But never displaces a config-file key source.
        let mut cfg = HarnessConfig::for_tests("http://u", "spool", "bridge");
        cfg.upstream_api_key_env = Some("OPENAI_API_KEY".into());
        cfg.apply_env_overrides_from(env);
        assert_eq!(cfg.upstream_api_key_env.as_deref(), Some("OPENAI_API_KEY"));
        assert_eq!(cfg.upstream_api_key_file, None);

        // And is ignored entirely in passthrough mode.
        let mut cfg = HarnessConfig::for_tests("http://u", "spool", "bridge");
        cfg.upstream_authorization_passthrough = true;
        cfg.apply_env_overrides_from(env);
        assert_eq!(cfg.upstream_api_key_file, None);
        assert_eq!(cfg.upstream_api_key_env, None);
    }

    #[test]
    fn builtin_config_validates_once_upstream_is_set() {
        let mut cfg = HarnessConfig::builtin().unwrap();
        assert!(cfg.validate().is_err(), "must not pass without an upstream");
        cfg.apply_env_overrides_from(|name| {
            (name == "AV_UPSTREAM_URL").then(|| "http://127.0.0.1:11434".to_owned())
        });
        cfg.validate().unwrap();
        assert_eq!(cfg.bridge_backend, "embedded");
        assert_eq!(cfg.state_backend, "memory");
        assert_eq!(cfg.embedder_backend, "hash");
        assert_eq!(cfg.vector_backend, "memory");
    }

    #[test]
    fn validate_rejects_unbindable_listen_and_zero_intervals() {
        let base = || HarnessConfig::for_tests("http://u", "spool", "bridge");

        let mut cfg = base();
        cfg.listen = String::new();
        assert!(cfg.validate().unwrap_err().contains("listen is required"));

        cfg = base();
        cfg.listen = "no-port-here".into();
        assert!(cfg.validate().unwrap_err().contains("host:port"));

        cfg = base();
        cfg.listen = "127.0.0.1:70000".into();
        assert!(cfg.validate().unwrap_err().contains("host:port"));

        // Hostnames and OS-assigned port 0 stay legal (bind resolves them).
        cfg = base();
        cfg.listen = "localhost:8484".into();
        cfg.validate().unwrap();
        cfg.listen = "[::1]:0".into();
        cfg.validate().unwrap();

        cfg = base();
        cfg.reconcile_tick_s = 0;
        assert!(cfg.validate().unwrap_err().contains("reconcile_tick_s"));

        cfg = base();
        cfg.session_idle_close_s = 0;
        assert!(cfg.validate().unwrap_err().contains("session_idle_close_s"));

        // `atif_retention_days = Some(0)` would nuke every sealed pair
        // on the first hourly sweep (max_age = 0 → `age < 0` false for
        // all mtimes → all pruned). Validate must reject it; `None`
        // (disable) and `Some(1)`+ (real windows) stay legal.
        cfg = base();
        cfg.atif_retention_days = Some(0);
        assert!(
            cfg.validate().unwrap_err().contains("atif_retention_days = 0"),
            "atif_retention_days = 0 should be rejected"
        );
        cfg.atif_retention_days = None;
        cfg.validate().unwrap();
        cfg.atif_retention_days = Some(1);
        cfg.validate().unwrap();

        cfg = base();
        cfg.breaker.window = 0;
        assert!(cfg.validate().unwrap_err().contains("breaker.window"));

        cfg = base();
        cfg.breaker.delta_epsilon = f32::NAN;
        assert!(cfg.validate().unwrap_err().contains("delta_epsilon"));
        cfg.breaker.delta_epsilon = -0.5;
        assert!(cfg.validate().unwrap_err().contains("delta_epsilon"));
    }

    /// Register item 25 sub-clause: "`AV_SIGNING_SEED_FILE` is in zero
    /// .md files" — the exact drift the reference table was supposed to
    /// prevent. Pass 18 pinned config-file field completeness, but env
    /// vars had no completeness guard, so `AV_SIGNING_SEED_FILE` could
    /// silently vanish again on a future edit. Every operator-facing
    /// `AV_*` env var must appear in at least one reference document.
    /// The test-only `AV_HARBOR_INTEROP_OUT` (a Harbor-interop escape
    /// hatch scoped to `full_chat_close_and_promotion_flow`) is not
    /// operator-facing and is deliberately excluded.
    #[test]
    fn operator_env_vars_are_documented() {
        let refs = [
            include_str!("../../../docs/reference/CONFIGURATION.md"),
            include_str!("../../../docs/reference/OPERATIONS.md"),
            include_str!("../../../docs/reference/OPENAI-COMPATIBILITY.md"),
            include_str!("../../../docs/reference/LIMITS.md"),
        ]
        .concat();
        for var in [
            // Config resolution (zero-config startup and file override).
            "AV_CONFIG",
            "AV_UPSTREAM_URL",
            // Trust anchor path — the register item-25 explicit callout.
            "AV_SIGNING_SEED_FILE",
            // Bearer token loader used by `avctl session-promote`.
            "AV_BEARER_TOKEN_FILE",
        ] {
            assert!(
                refs.contains(var),
                "operator-facing env var `{var}` is not documented in any \
                 docs/reference/*.md — register item 25 explicitly names the \
                 undocumented AV_ env var class as the drift signature."
            );
        }
    }

    #[test]
    fn user_config_path_is_stable() {
        let path = user_config_path_from(std::path::Path::new("/home/pat"));
        assert_eq!(
            path,
            std::path::Path::new("/home/pat/.agentvisor/agentvisor.toml")
        );
    }

    /// Pin the register-item-6 fix behaviorally. The original register
    /// complained: "Wizard-then-`avctl start` inside a checkout silently
    /// loads the example config: wrong bind, dead upstream, no API key,
    /// no error." The fix was to REMOVE `config/harness.example.toml`
    /// from the auto-discovery list entirely (better than the register's
    /// requested rank swap): the example is a template, not a config.
    /// If someone adds it back — well-meaning "make the example work
    /// out of the box" — every developer with a wizard-written
    /// `~/.agentvisor/agentvisor.toml` silently regresses to the
    /// example's settings the moment they `cd` into a checkout.
    #[test]
    fn config_search_paths_never_include_the_example_config() {
        for path in CONFIG_SEARCH_PATHS {
            assert!(
                !path.contains("example"),
                "CONFIG_SEARCH_PATHS must not auto-discover a `*example*` file: {path:?}. \
                 See the doc-comment on CONFIG_SEARCH_PATHS — the example is a template, \
                 not a config, and auto-loading it defeats the wizard-written per-user file."
            );
        }
        // Also pin: the per-user wizard file must sit at the documented
        // location, so `avctl init --output ~/.agentvisor/agentvisor.toml`
        // (the wizard's actual write path) is what `resolve_config_source`
        // will find in the fall-through arm.
        assert_eq!(
            user_config_path_from(std::path::Path::new("/h")),
            std::path::PathBuf::from("/h/.agentvisor/agentvisor.toml"),
            "the wizard-written path is contract; changing it breaks every operator \
             whose home already has this file"
        );
    }

    /// The `/v1` suffix footgun must be detected exactly: flagged when the
    /// base URL already ends with the first chat-path segment, silent for
    /// bare hosts, ports, and provider paths that do not overlap.
    #[test]
    fn duplicated_chat_path_segment_detection() {
        let cfg = |url: &str| HarnessConfig::for_tests(url, "spool", "bridge");
        assert_eq!(
            cfg("https://api.openai.com/v1").duplicated_chat_path_segment(),
            Some("v1")
        );
        assert_eq!(
            cfg("https://api.openai.com/v1/").duplicated_chat_path_segment(),
            Some("v1")
        );
        assert_eq!(
            cfg("http://localhost:8080/v1").duplicated_chat_path_segment(),
            Some("v1")
        );
        assert_eq!(cfg("https://api.openai.com").duplicated_chat_path_segment(), None);
        assert_eq!(cfg("http://127.0.0.1:11434").duplicated_chat_path_segment(), None);
        // Gemini-style base path that does not repeat the chat path.
        let mut gemini = cfg("https://generativelanguage.googleapis.com/v1beta/openai");
        gemini.upstream_chat_path = "/chat/completions".into();
        assert_eq!(gemini.duplicated_chat_path_segment(), None);
        // Azure-style custom path with a matching base suffix still flags.
        let mut azure = cfg("https://r.openai.azure.com/openai");
        azure.upstream_chat_path = "/openai/deployments/d/chat/completions".into();
        assert_eq!(azure.duplicated_chat_path_segment(), Some("openai"));
        // A pasted full endpoint URL embeds the entire chat path.
        assert_eq!(
            cfg("http://10.0.0.5:8000/v1/chat/completions").duplicated_chat_path_segment(),
            Some("v1/chat/completions")
        );
        assert_eq!(
            cfg("http://10.0.0.5:8000/v1/chat/completions/").duplicated_chat_path_segment(),
            Some("v1/chat/completions")
        );
    }

    #[test]
    fn bad_configs_rejected() {
        assert!(HarnessConfig::from_toml("").is_err()); // missing upstream
        assert!(HarnessConfig::from_toml(
            r#"upstream_url = "https://api"
               config_version = 99"#
        )
        .is_err());
        // Each case below must reach the check it names, not fall
        // through to `upstream_url` scheme validation — otherwise
        // deleting the specific validator here still leaves the outer
        // is_err() true. Use a valid upstream_url and pin the actual
        // rejection reason.
        let bad_workflow = HarnessConfig::from_toml(
            r#"upstream_url = "https://api"
               default_workflow = "sometimes""#,
        )
        .unwrap_err();
        assert!(
            bad_workflow.contains("default_workflow"),
            "the default_workflow allowlist must be what refuses this config, \
             not the upstream_url scheme check via fallthrough; got {bad_workflow}"
        );
        let bad_capacity = HarnessConfig::from_toml(
            r#"upstream_url = "https://api"
               worker_channel_capacity = 0"#,
        )
        .unwrap_err();
        assert!(
            bad_capacity.contains("worker_channel_capacity"),
            "the worker_channel_capacity bounds check must be what refuses this \
             config, not the upstream_url scheme check via fallthrough; got {bad_capacity}"
        );
    }

    /// A config from a newer format version must be refused by its declared
    /// `config_version` — not by whichever unknown key the strict parser
    /// happens to trip on first.
    #[test]
    fn future_version_config_reports_version_not_unknown_field() {
        let err = HarnessConfig::from_toml(
            r#"config_version = 2
               upstream_url = "https://api"
               future_option_from_v2 = true"#,
        )
        .unwrap_err();
        assert!(err.contains("unsupported config_version 2"), "{err}");
        assert!(!err.contains("future_option_from_v2"), "{err}");
    }

    /// Cap on `worker_channel_capacity` rejects the fat-finger config
    /// before it reaches the runtime (defence-in-depth; tokio's mpsc
    /// does not preallocate — see the `MAX_WORKER_CHANNEL_CAPACITY` doc).
    #[test]
    fn worker_channel_capacity_cap_rejects_oversized_values() {
        let err = HarnessConfig::from_toml(&format!(
            "upstream_url = \"https://api\"\nworker_channel_capacity = {}",
            MAX_WORKER_CHANNEL_CAPACITY + 1
        ))
        .unwrap_err();
        assert!(
            err.contains("worker_channel_capacity"),
            "err should name the offending field: {err}"
        );
    }

    /// `upstream_url` without a scheme is rejected at load — otherwise
    /// the request-time concat would silently misroute to a bogus host.
    /// The shape check was tightened from `contains("://")` to
    /// the strict `http://` / `https://` allowlist, matching the
    /// posture on every other URL field.
    #[test]
    fn upstream_url_without_scheme_is_rejected() {
        let err = HarnessConfig::from_toml(r#"upstream_url = "openai.internal""#).unwrap_err();
        assert!(err.contains("upstream_url"), "{err}");
        assert!(err.contains("http"), "{err}");
    }

    /// Schemes other than http/https are rejected. The
    /// prior `contains("://")` shape check accepted `file:///…` and
    /// other schemes even though the error text claimed http/https;
    /// a config-injection primitive could have pointed the harness
    /// at `file:///etc/passwd`. `avctl config-validate` now refuses.
    #[test]
    fn upstream_url_non_http_scheme_is_rejected() {
        let err = HarnessConfig::from_toml(r#"upstream_url = "file:///etc/passwd""#).unwrap_err();
        assert!(err.contains("upstream_url"), "{err}");
        let err = HarnessConfig::from_toml(r#"upstream_url = "gopher://x""#).unwrap_err();
        assert!(err.contains("upstream_url"), "{err}");
        // http and https are the only accepted schemes.
        assert!(HarnessConfig::from_toml(r#"upstream_url = "https://api.openai.com""#).is_ok());
        assert!(HarnessConfig::from_toml(r#"upstream_url = "http://gw.local""#).is_ok());
    }

    /// A scheme with no host (`http://`, `https:///v1`) passed the
    /// prefix preflight, booted, and validated cleanly, failing only at
    /// request time with a 502. Refuse it at startup like every other
    /// URL-shape defect.
    #[test]
    fn upstream_url_without_host_is_rejected() {
        for url in [r#"upstream_url = "http://""#, r#"upstream_url = "https:///v1""#] {
            let err = HarnessConfig::from_toml(url).unwrap_err();
            assert!(err.contains("no host"), "{err}");
        }
    }

    /// The shipped example config must PARSE AND VALIDATE, and must
    /// pin the register-#4 posture: loopback bind, dashboard off, and
    /// every uncommented value acceptable to the strict loader. This
    /// is the file the README tells checkout users to copy — nothing
    /// exercised it before, which is exactly how the README's
    /// checkout section drifted stale. All three shipped configs must
    /// also opt into the signed workflow: the serde default is
    /// "unsigned" (zero-config ergonomics), so any shipped config
    /// that omits the key silently produces ZERO signed receipts on
    /// clean traffic — the register's item-19 observation, found
    /// live in the container/docker configs and the K8s ConfigMap.
    #[test]
    fn shipped_example_config_parses_and_pins_safe_posture() {
        let raw = include_str!("../../../config/harness.example.toml");
        let config = HarnessConfig::from_toml(raw)
            .unwrap_or_else(|error| panic!("shipped example config must validate: {error}"));
        assert_eq!(config.listen, "127.0.0.1:8484", "example must bind loopback");
        assert!(!config.dashboard_enabled, "example must ship dashboard-off");
        assert_eq!(
            config.budget.max_tokens,
            Some(200_000),
            "example must bind a token budget"
        );
        assert_eq!(config.default_workflow, "signed");
        for (name, raw) in [
            (
                "container",
                include_str!("../../../config/harness.container.toml"),
            ),
            ("docker", include_str!("../../../config/harness.docker.toml")),
        ] {
            let config = HarnessConfig::from_toml(raw)
                .unwrap_or_else(|error| panic!("shipped {name} config must validate: {error}"));
            assert_eq!(
                config.default_workflow, "signed",
                "{name} config must opt into the signed workflow"
            );
        }
    }

    /// Register pass 35 finding — the four shipped tool schemas under
    /// config/tool-schemas/ are the daemon's boot-time contract: at
    /// startup `load_sandbox` reads each `.json` file and parses it
    /// with `serde_json::from_slice`, using the file stem as the tool
    /// name. Any parse failure with default `tool_schema_dir =
    /// "config/tool-schemas"` errors out the daemon with
    /// "parse tool schema {path}: ..." — a CrashLoopBackOff on
    /// Kubernetes, an immediate exit on bare-metal.
    ///
    /// Only db_write.json was parse-tested before this pass (via
    /// `tests/sla.rs:33`, which include_str!s it). The other three —
    /// payout.json, deploy.json, merge.json — shipped and were
    /// referenced by config/harness.example.toml + the K8s ConfigMap,
    /// but nothing exercised them at CI time.
    #[test]
    fn shipped_tool_schemas_parse_as_json() {
        for (name, raw) in [
            (
                "payout.json",
                include_str!("../../../config/tool-schemas/payout.json"),
            ),
            (
                "db_write.json",
                include_str!("../../../config/tool-schemas/db_write.json"),
            ),
            (
                "deploy.json",
                include_str!("../../../config/tool-schemas/deploy.json"),
            ),
            (
                "merge.json",
                include_str!("../../../config/tool-schemas/merge.json"),
            ),
        ] {
            let value: serde_json::Value = serde_json::from_str(raw).unwrap_or_else(|error| {
                panic!(
                    "shipped tool schema {name} must parse as JSON — the daemon calls \
                     serde_json::from_slice on each .json file under tool_schema_dir at \
                     boot; a parse failure here CrashLoopBackOffs the pod. Error: {error}"
                )
            });
            // The schema must be an object at the top level — that is
            // what jsonschema treats as a "schema for a value"; a bare
            // array or scalar would compile as "any input matches",
            // silently gating nothing. Fail-closed at CI, not at
            // request time.
            assert!(
                value.is_object(),
                "shipped tool schema {name} must be a JSON object at the top level \
                 (JSON Schema convention); a bare array/scalar would silently accept \
                 every tool call"
            );
        }
    }

    /// Register pass 34 finding — the K8s ConfigMap embeds a full
    /// TOML block for the daemon at deploy/kubernetes/agentvisor-ai.
    /// yaml. It ships with the shipped `.toml` files pinned above
    /// but the ConfigMap's OWN copy of the config was never
    /// parse-tested. If it drifts (typo in a field name, unknown
    /// key from a rebase, a rename in HarnessConfig with no matching
    /// yaml edit), `kubectl apply` succeeds — YAML syntax is fine —
    /// but every pod CrashLoopBackOffs on boot with the classic
    /// "unknown field `X`, expected one of ..." serde error. The
    /// operator debugging this can't tell the daemon from the config
    /// apart without shell access to the pod.
    ///
    /// This test extracts the embedded TOML at compile time,
    /// un-indents it (each line has a 4-space YAML block indent),
    /// runs it through the same strict loader `agentvisord` uses at
    /// boot, and pins the same safe-posture invariants as the
    /// shipped configs above.
    #[test]
    fn shipped_kubernetes_configmap_toml_parses_and_pins_safe_posture() {
        let yaml = include_str!("../../../deploy/kubernetes/agentvisor-ai.yaml");
        // Find the block scalar. The ConfigMap's `agentvisor.toml: |`
        // header opens a literal block; the block continues while
        // subsequent lines are indented at the block's level or
        // deeper (or blank). The next YAML-level key or `---`
        // separator ends it.
        let block_header = "agentvisor.toml: |";
        let block_start = yaml
            .find(block_header)
            .unwrap_or_else(|| panic!("K8s manifest must embed a `{block_header}` block"))
            + block_header.len();
        let after = &yaml[block_start..];
        let after = after.trim_start_matches('\n');
        // Every line of the block is indented at least 4 spaces
        // (see the ConfigMap in the manifest). Take lines until we
        // hit a non-blank line whose indent is smaller.
        let mut toml = String::new();
        for line in after.lines() {
            if line.is_empty() || line.trim().is_empty() {
                toml.push('\n');
                continue;
            }
            if let Some(stripped) = line.strip_prefix("    ") {
                toml.push_str(stripped);
                toml.push('\n');
            } else {
                break;
            }
        }
        assert!(
            toml.contains("config_version"),
            "extracted ConfigMap TOML looks empty; did the block indent change?"
        );

        let config = HarnessConfig::from_toml(&toml).unwrap_or_else(|error| {
            panic!(
                "K8s ConfigMap agentvisor.toml block must parse and validate under \
                 the same strict loader agentvisord uses; a rename/typo here \
                 CrashLoopBackOffs every pod at boot. Error: {error}\n\n\
                 Extracted TOML:\n{toml}"
            )
        });

        // Same safe-posture pins as the shipped configs. Adding the
        // K8s ConfigMap to the roster the register's item 4 concern
        // covers.
        assert_eq!(
            config.default_workflow, "signed",
            "K8s ConfigMap must opt into the signed workflow (register item 19); \
             the serde default `unsigned` silently mints zero receipts on clean \
             traffic"
        );
        assert!(
            !config.dashboard_enabled,
            "K8s ConfigMap must ship dashboard-off — the pod binds 0.0.0.0 for \
             cluster network reachability, so any workload with Service access \
             could otherwise enumerate sessions/costs/receipts (register item 4)"
        );
        assert!(
            config.allow_wildcard_bind,
            "K8s ConfigMap MUST carry allow_wildcard_bind = true (paired with \
             the 0.0.0.0 listen + require_identity = false posture); config \
             validation refuses the combination otherwise and the daemon \
             CrashLoopBackOffs at boot"
        );
    }

    /// The K8s manifest ships a specific `terminationGracePeriodSeconds`
    /// that must cover the daemon's worst-case shutdown budget for the
    /// ConfigMap TOML it also ships. If the ConfigMap's
    /// `shutdown_drain_timeout_s` (or its derivation from
    /// `upstream_read_timeout_s`) pushes the total above the grace, a
    /// rolling deploy under a long-tail request SIGKILLs mid-finalize
    /// and drops receipts — the exact outcome the graceful-shutdown
    /// machinery exists to prevent. Compute both from the SAME
    /// manifest so a future edit that touches only one is caught here.
    #[test]
    fn shipped_kubernetes_configmap_total_shutdown_fits_termination_grace() {
        let yaml = include_str!("../../../deploy/kubernetes/agentvisor-ai.yaml");
        // Parse the ConfigMap TOML the same way the sibling test does.
        let block_header = "agentvisor.toml: |";
        let block_start = yaml.find(block_header).unwrap() + block_header.len();
        let after = yaml[block_start..].trim_start_matches('\n');
        let mut toml = String::new();
        for line in after.lines() {
            if line.trim().is_empty() {
                toml.push('\n');
                continue;
            }
            if let Some(stripped) = line.strip_prefix("    ") {
                toml.push_str(stripped);
                toml.push('\n');
            } else {
                break;
            }
        }
        let config = HarnessConfig::from_toml(&toml).unwrap();
        assert_total_shutdown_fits(
            "K8s manifest ConfigMap",
            &config,
            extract_yaml_int(yaml, "terminationGracePeriodSeconds:").unwrap(),
            // K8s runs preStop synchronously BEFORE SIGTERM and both
            // count against the grace period. If the manifest has a
            // preStop hook, its sleep MUST be parseable — a silent
            // `unwrap_or(0)` here defeats the pin whenever the hook is
            // reformatted (YAML block form, single-quoted strings, a
            // mechanism other than `sleep`), which is exactly the drift
            // class the test exists to catch.
            require_prestop_sleep_seconds(yaml),
        );
    }

    /// docker-compose.yml + config/harness.docker.toml pair (the
    /// hardened stack). Same drift class as the K8s test above: a
    /// tightening of `stop_grace_period` (or a bump in
    /// `shutdown_drain_timeout_s`) that individually looks safe can
    /// push the sum over the grace and silently start dropping
    /// receipts on `docker compose down`.
    #[test]
    fn shipped_docker_compose_stop_grace_fits_harness_docker_shutdown() {
        let compose = include_str!("../../../docker/docker-compose.yml");
        let toml = include_str!("../../../config/harness.docker.toml");
        let config = HarnessConfig::from_toml(toml).unwrap();
        assert_total_shutdown_fits(
            "docker-compose.yml / harness.docker.toml",
            &config,
            extract_yaml_grace_seconds(compose, "stop_grace_period:").unwrap(),
            // Docker compose has no preStop equivalent.
            0,
        );
    }

    /// docker-compose.minimal.yml + config/harness.container.toml pair
    /// (the evaluator on-ramp). Advertised in the README as the
    /// zero-friction try-it flow, so an unclean `docker stop` here is
    /// exactly the shape a prospect encounters when they Ctrl-C.
    #[test]
    fn shipped_docker_compose_minimal_stop_grace_fits_container_shutdown() {
        let compose = include_str!("../../../docker/docker-compose.minimal.yml");
        let toml = include_str!("../../../config/harness.container.toml");
        let config = HarnessConfig::from_toml(toml).unwrap();
        assert_total_shutdown_fits(
            "docker-compose.minimal.yml / harness.container.toml",
            &config,
            extract_yaml_grace_seconds(compose, "stop_grace_period:").unwrap(),
            0,
        );
    }

    /// Shared budget check. The four shutdown phases in finish_shutdown
    /// run sequentially, so the worst-case wall time is the sum of
    /// each phase's cap plus any pre-drain wall time the deployment
    /// requires BEFORE the phases start.
    ///   1. HTTP drain: `effective_drain_timeout()` (config-derived).
    ///   2. Worker wait_idle: [`WORKER_FINALIZE_PHASE_SECS`] — imported
    ///      from the same source of truth `main.rs`'s `finish_shutdown`
    ///      call site uses, so a bump there without matching bumps in
    ///      the deployment manifests trips this test at CI time.
    ///   3. finalize_sessions: same [`WORKER_FINALIZE_PHASE_SECS`].
    ///   4. OTel telemetry flush: [`OTEL_FLUSH_SECS`] when the `otel`
    ///      feature is on (which it is in the default `--features full`
    ///      container image the shipped configs assume).
    ///   5. Pre-drain wall time: `shutdown_ready_drain_s` counts
    ///      against the grace period BEFORE the drain starts (see the
    ///      field's own doc comment), and a K8s `preStop` hook counts
    ///      against the grace period BEFORE SIGTERM is even delivered.
    fn assert_total_shutdown_fits(
        label: &str,
        config: &HarnessConfig,
        grace_seconds: u64,
        pre_signal_seconds: u64,
    ) {
        let drain = config.effective_drain_timeout().as_secs();
        let total = drain
            .saturating_add(WORKER_FINALIZE_PHASE_SECS)
            .saturating_add(WORKER_FINALIZE_PHASE_SECS)
            .saturating_add(OTEL_FLUSH_SECS)
            .saturating_add(config.shutdown_ready_drain_s)
            .saturating_add(pre_signal_seconds);
        assert!(
            total <= grace_seconds,
            "{label}: worst-case shutdown budget {total}s (drain {drain}s + \
             worker {WORKER_FINALIZE_PHASE_SECS}s + finalize {WORKER_FINALIZE_PHASE_SECS}s + \
             OTel {OTEL_FLUSH_SECS}s + shutdown_ready_drain_s {}s + pre-signal {}s) \
             exceeds the grace period {grace_seconds}s — \
             kubelet/dockerd will SIGKILL mid-finalize and drop receipts on \
             rolling deploy. Either lower shutdown_drain_timeout_s / \
             shutdown_ready_drain_s / the preStop sleep in the config or raise \
             the grace period in the deployment manifest.",
            config.shutdown_ready_drain_s,
            pre_signal_seconds,
        );
    }

    fn extract_yaml_int(yaml: &str, key: &str) -> Option<u64> {
        for line in yaml.lines() {
            let trimmed = line.trim_start();
            if let Some(rest) = trimmed.strip_prefix(key) {
                return rest.trim().parse().ok();
            }
        }
        None
    }

    /// Parses the shipped K8s manifest's `preStop.exec.command`
    /// `sleep <n>` argument, accepting the three shapes YAML idiomatically
    /// admits so a cosmetic reformat can't defeat the pin:
    ///   1. inline flow list, double-quoted: `command: ["sh", "-c", "sleep 5"]`
    ///   2. inline flow list, single-quoted: `command: ['sh', '-c', 'sleep 5']`
    ///   3. block-scalar list — used elsewhere in the same manifest:
    ///      ```yaml
    ///      command:
    ///        - sh
    ///        - -c
    ///        - sleep 5
    ///      ```
    /// Returns `None` when there is no preStop hook at all (no `preStop:`
    /// key). Returns `None` when a preStop DOES exist but the shape is
    /// unrecognized — the caller must panic on that so the drift is
    /// caught at build time, not papered over with `unwrap_or(0)`.
    fn extract_prestop_sleep_seconds(yaml: &str) -> Option<u64> {
        // Locate the FIRST non-comment `preStop:` occurrence. A future
        // manifest edit that adds `# don't use preStop:` above the real
        // hook would otherwise anchor our scope to the comment and
        // trawl the rest of the file for any `sleep`.
        let (prestop_line_idx, prestop_indent) = yaml.lines().enumerate().find_map(|(i, line)| {
            let trimmed = line.trim_start();
            if trimmed.starts_with('#') {
                return None;
            }
            if trimmed.starts_with("preStop:") {
                Some((i, line.len() - trimmed.len()))
            } else {
                None
            }
        })?;
        // Scope: from the preStop line to the FIRST line whose indent
        // is ≤ the preStop line's indent (that line starts a sibling
        // key, ending the preStop block). Blank lines and comments
        // don't end the block. The previous heuristic (`\nresources:`)
        // never fired in real manifests where `resources:` is
        // indented, so the parser trawled the whole rest of the file
        // and returned `sleep` values from unrelated containers /
        // probes / sidecars. Verified by the R8 review's mutation
        // cases: block-form preStop `sleep 60` + downstream container
        // `command: ["sh","-c","sleep 3"]` used to return 3, not 60.
        let mut scope = String::new();
        for (i, line) in yaml.lines().enumerate().skip(prestop_line_idx) {
            if i == prestop_line_idx {
                scope.push_str(line);
                scope.push('\n');
                continue;
            }
            let trimmed = line.trim_start();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                scope.push_str(line);
                scope.push('\n');
                continue;
            }
            let indent = line.len() - trimmed.len();
            if indent <= prestop_indent {
                break;
            }
            scope.push_str(line);
            scope.push('\n');
        }
        // Shape 1 & 2: same-line inline list. Look for either
        // "sleep <n>" or 'sleep <n>' anywhere in the scoped block.
        for quote in ['"', '\''] {
            let marker = format!("{quote}sleep ");
            if let Some(hit) = scope.find(&marker) {
                let rest = &scope[hit + marker.len()..];
                let n: String = rest.chars().take_while(char::is_ascii_digit).collect();
                if let Ok(seconds) = n.parse() {
                    return Some(seconds);
                }
            }
        }
        // Shape 3: block-scalar list. A line whose non-indent content
        // is `- sleep <n>`. YAML also allows `- sh` / `- -c` / `- sleep 5`
        // on separate lines; we only need the sleep line.
        for line in scope.lines() {
            let stripped = line.trim_start().trim_start_matches('-').trim();
            if let Some(rest) = stripped.strip_prefix("sleep ") {
                let n: String = rest.chars().take_while(char::is_ascii_digit).collect();
                if let Ok(seconds) = n.parse() {
                    return Some(seconds);
                }
            }
        }
        None
    }

    /// Caller-side companion for [`extract_prestop_sleep_seconds`]: a
    /// shipped manifest with a `preStop:` hook MUST have a parseable
    /// sleep, or the pin cannot compute the grace budget accurately
    /// and silently green-lights a hook whose wall time it ignores.
    /// The R7 review agent caught this exact class: a YAML block-form
    /// reformat + `sleep 60` bump pushed total shutdown to 190 s
    /// against the 150 s grace, and the previous `.unwrap_or(0)` let
    /// the test pass.
    fn require_prestop_sleep_seconds(yaml: &str) -> u64 {
        // Only count a REAL preStop line (`preStop:` at the start of a
        // non-comment line), not the substring inside a comment like
        // `# don't use preStop:`. Same class of bug the scope-cut
        // rewrite fixes below.
        let has_prestop = yaml.lines().any(|line| {
            let trimmed = line.trim_start();
            !trimmed.starts_with('#') && trimmed.starts_with("preStop:")
        });
        if !has_prestop {
            return 0;
        }
        extract_prestop_sleep_seconds(yaml).expect(
            "shipped K8s manifest has a preStop hook but extract_prestop_sleep_seconds \
             could not parse its sleep duration — either update the parser to handle \
             the new shape (inline vs block YAML, quoting style), or if preStop no \
             longer uses `sleep`, delete this test and its helper. Silently returning \
             0 would defeat the pin's own purpose: catching a preStop-time bump that \
             pushes total shutdown past the grace period.",
        )
    }

    /// Direct regression tests for the parser — pinning the exact
    /// mutation cases the R8 review agent proved defeated the previous
    /// scope-cut heuristic. If these ever regress, the shipped
    /// K8s pin above no longer measures what its comment claims.
    #[test]
    fn extract_prestop_scope_ignores_downstream_sleep_after_the_block() {
        // Block-form preStop `sleep 60` in one container followed by
        // an unrelated inline container command with `"sleep 3"` in a
        // real sibling later in the YAML. Previous version returned
        // 3 (first inline match anywhere after preStop:), silently
        // making the pin under-count preStop time by 57 s.
        let yaml = "\
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
      - name: main
        lifecycle:
          preStop:
            exec:
              command:
                - sh
                - -c
                - sleep 60
        resources:
          limits:
            cpu: \"2\"
      - name: sidecar
        command: [\"sh\", \"-c\", \"sleep 3\"]
";
        assert_eq!(
            extract_prestop_sleep_seconds(yaml),
            Some(60),
            "the parser must scope to the preStop block and ignore \
             downstream containers' inline sleep commands"
        );
    }

    #[test]
    fn extract_prestop_scope_ignores_downstream_probe_sleep() {
        // Inline preStop `sleep 3` next to a downstream livenessProbe
        // exec `command: ["sh", "-c", "sleep 300"]`. The key
        // differentiator is quote-style ordering: Shape-1 scanning
        // walks `['"', '\'']` and returns on the first hit, so a
        // single-quoted preStop + double-quoted probe forces the
        // old (unscoped) parser to hit the probe's `"sleep 300"`
        // FIRST — returning 300 → pin FALSELY reported "grace
        // exceeded" for a config that was actually fine. With the
        // indent-scoped scan, only the preStop's `'sleep 3'` is in
        // range and the answer is 3. Reviewer note: an earlier
        // version of this test used matching double quotes for both
        // hooks, which the OLD parser also happened to return 3 for
        // (double-quote scan hits the preStop's `"sleep 3"` first),
        // making the test hollow — it asserted the same value both
        // implementations produced.
        let yaml = "\
spec:
  containers:
  - name: main
    lifecycle:
      preStop:
        exec:
          command: ['sh', '-c', 'sleep 3']
    livenessProbe:
      exec:
        command: [\"sh\", \"-c\", \"sleep 300\"]
";
        assert_eq!(extract_prestop_sleep_seconds(yaml), Some(3));
    }

    #[test]
    fn require_prestop_skips_commented_out_prestop_line() {
        // A YAML comment mentioning preStop must not fool the parser
        // into thinking a hook exists — nor into returning an
        // unrelated sleep from a downstream probe.
        let yaml = "\
spec:
  containers:
  - name: main
    # NOTE: do not add preStop: to this container, see runbook.
    livenessProbe:
      exec:
        command: [\"sh\", \"-c\", \"sleep 90\"]
";
        assert_eq!(
            require_prestop_sleep_seconds(yaml),
            0,
            "a comment mentioning preStop: is NOT a real hook; require_prestop \
             must return 0, not the downstream probe's sleep"
        );
    }

    /// Parses `stop_grace_period: 180s` (compose accepts a `s`/`m`/`h`
    /// suffix). We only ship an `s` suffix, so a bare int and `<n>s`
    /// are the two shapes to accept.
    fn extract_yaml_grace_seconds(yaml: &str, key: &str) -> Option<u64> {
        for line in yaml.lines() {
            let trimmed = line.trim_start();
            if let Some(rest) = trimmed.strip_prefix(key) {
                let raw = rest.trim().trim_end_matches('s');
                return raw.parse().ok();
            }
        }
        None
    }

    /// `tool_upstream_url = ""` used to pass validation while runtime
    /// routing gates tool forwarding on `is_some()` — the empty string
    /// silently enabled the tool-upstream branches and only failed at the
    /// first request with a reqwest URL error. Reject it at startup.
    #[test]
    fn empty_tool_upstream_url_is_rejected() {
        let err =
            HarnessConfig::from_toml("upstream_url = \"https://api\"\ntool_upstream_url = \"\"").unwrap_err();
        assert!(err.contains("tool_upstream_url"), "{err}");
        assert!(err.contains("omit"), "should point at omitting the field: {err}");
        assert!(HarnessConfig::from_toml(
            "upstream_url = \"https://api\"\ntool_upstream_url = \"http://tools/mcp\"",
        )
        .is_ok());
    }

    /// `payout_field = ""` silently disabled the payout cap: the empty
    /// string matches no argument key, `extract_payout_micros` returned
    /// 0, and `ActionBudget::try_tool_call` skipped the payout dimension
    /// entirely — including the fail-closed "unbounded payout must
    /// never spend" refusal. Every peer field in the same class
    /// (atif_spool_dir, bridge_data_dir, upstream_auth_header, …) is
    /// checked non-empty; this was the outlier. Refuse at startup.
    /// Whitespace, control, non-ASCII, and invisible-format (BOM,
    /// zero-width space) variants are the same class — extremely
    /// unlikely to match a real tool's JSON key and almost certainly
    /// a paste typo from a rich-editor or Windows/UTF-8 signature.
    /// `is_ascii_graphic()` covers all of these in one check.
    #[test]
    fn empty_or_whitespace_payout_field_is_rejected() {
        for hostile in [
            "",
            " ",
            "  ",
            "\t",
            " amount_usd",
            "amount_usd ",
            // Invisible-format class — the exact one browser paste
            // injects and that `trim()` misses because Unicode's
            // White_Space property does not cover these.
            "\u{FEFF}amount_usd", // BOM at start (UTF-8 signature)
            "amount_usd\u{FEFF}", // BOM at end
            "\u{200B}amount_usd", // zero-width space
            "amount\u{200B}_usd", // zero-width space in the middle
            "\u{2060}amount_usd", // word-joiner
            "amount_usd\u{00A0}", // NBSP (a Unicode whitespace)
            // Non-ASCII: smart quotes / accents / emoji / RTL text.
            "amount_usd\u{201D}", // right double-quote
            "amóunt_usd",         // accented Latin
        ] {
            // Interpolate the RAW hostile bytes into the TOML — not
            // `{:?}` Debug format, which emits Rust's `\u{feff}`
            // escape that TOML doesn't accept (only `\uXXXX` /
            // `\UXXXXXXXX`, no braces). The prior version parse-
            // failed at the toml crate for every invisible-format
            // case, so the payout_field check never actually ran on
            // the class the fix targets: the R12 review agent proved
            // that reverting the check to R11's `trim()`-based
            // predicate still passed 6 of the 8 test cases.
            //
            // The `[` / `]` / `{` / `}` / `#` in `hostile` cannot
            // appear here (all our fixtures are payout-key shapes),
            // and TOML basic strings interpret embedded `\` and `"`
            // — but our fixtures contain neither. Raw interpolation
            // is therefore safe AND correct for THIS test.
            let toml = format!("upstream_url = \"https://api.openai.com\"\npayout_field = \"{hostile}\"\n");
            let err = match HarnessConfig::from_toml(&toml) {
                Err(e) => e,
                Ok(_) => panic!("must refuse payout_field = {hostile:?}"),
            };
            assert!(err.contains("payout_field"), "{hostile:?} => {err}");
        }
        // The default (omitted key) is fine.
        assert!(HarnessConfig::from_toml(r#"upstream_url = "https://api.openai.com""#).is_ok());
        // An explicit clean name is fine.
        assert!(HarnessConfig::from_toml(
            r#"upstream_url = "https://api.openai.com"
               payout_field = "amount_usd""#,
        )
        .is_ok());
    }

    /// The hostless preflight `upstream_url` gets must cover
    /// `tool_upstream_url` too: `tool_upstream_url = "http://"` passed
    /// validation, booted, then failed EVERY tool call at request-build
    /// time — with claimed executions churning TOOL_OUTCOME_UNCERTAIN.
    #[test]
    fn hostless_tool_upstream_url_is_rejected() {
        for url in ["http://", "https:///mcp", "http://?x=1"] {
            let err = HarnessConfig::from_toml(&format!(
                "upstream_url = \"https://api\"\ntool_upstream_url = \"{url}\""
            ))
            .unwrap_err();
            assert!(
                err.contains("tool_upstream_url") && err.contains("no host"),
                "{url}: {err}"
            );
        }
    }

    /// A seconds interval > 1 day is almost certainly a unit-conversion
    /// error (someone thought the field was in milliseconds).
    #[test]
    fn seconds_intervals_reject_absurdly_large_values() {
        let err = HarnessConfig::from_toml(&format!(
            "upstream_url = \"https://api\"\nsession_idle_close_s = {}",
            MAX_SECONDS_INTERVAL + 1
        ))
        .unwrap_err();
        assert!(
            err.contains("session_idle_close_s"),
            "err should name the offending field: {err}"
        );
        assert!(err.contains("milliseconds"), "hint should mention ms: {err}");
    }

    /// `upstream_read_timeout_s = 0` would make every upstream request
    /// time out before its first byte; reject it with a pointer at the
    /// omit-for-default posture.
    #[test]
    fn upstream_read_timeout_rejects_zero() {
        let err = HarnessConfig::from_toml(
            r#"upstream_url = "https://api"
               upstream_read_timeout_s = 0"#,
        )
        .unwrap_err();
        assert!(
            err.contains("upstream_read_timeout_s"),
            "err should name the offending field: {err}"
        );
        assert!(err.contains("omit"), "err should point at the default: {err}");
        // Any positive value under the 1-day cap remains valid.
        assert!(HarnessConfig::from_toml(
            r#"upstream_url = "https://api"
               upstream_read_timeout_s = 1"#,
        )
        .is_ok());
    }

    /// Refuse `enforce_identity_scopes = true` while
    /// `require_identity = false`. The combo silently falls through
    /// to the anonymous identity on unauthenticated requests,
    /// making the scope config a fig leaf.
    #[test]
    fn round_30_f1_scope_enforcement_requires_identity_requirement() {
        let err = HarnessConfig::from_toml(
            r#"upstream_url = "https://api.openai.com"
               require_identity = false
               enforce_identity_scopes = true"#,
        )
        .unwrap_err();
        assert!(
            err.contains("enforce_identity_scopes"),
            "err should name the flag: {err}"
        );
        assert!(
            err.contains("require_identity"),
            "err should name the correlate: {err}"
        );
        // Both `false` = clean dev posture, still passes.
        assert!(HarnessConfig::from_toml(
            r#"upstream_url = "https://api.openai.com"
               require_identity = false
               enforce_identity_scopes = false"#,
        )
        .is_ok());
    }

    /// §8.8: the graceful-drain budget must key off the longest
    /// legitimate in-flight request instead of a hardcoded 30 s.
    #[test]
    fn drain_timeout_derives_from_upstream_read_timeout() {
        // Unset drain + unset read timeout: falls back to the pipeline's
        // DEFAULT_UPSTREAM_READ_TIMEOUT_S (60 s) so a legitimate
        // in-flight request cannot outlive the derived drain. Using
        // separate defaults (30 in the derivation, 60 in the pipeline)
        // let a live 60 s read get truncated by a 30 s drain — the
        // exact "one in-flight request cannot exceed the drain window"
        // invariant this function's doc-comment promises.
        let base = HarnessConfig::for_tests("http://127.0.0.1:9", "/tmp", "/tmp");
        assert_eq!(
            base.effective_drain_timeout().as_secs(),
            DEFAULT_UPSTREAM_READ_TIMEOUT_S.saturating_add(5),
            "unset drain must derive from the SAME default the pipeline uses"
        );
        // Unset drain + 300 s read timeout → 305 s (one in-flight
        // request can never legitimately outlive the drain window).
        let mut derived = HarnessConfig::for_tests("http://127.0.0.1:9", "/tmp", "/tmp");
        derived.upstream_read_timeout_s = Some(300);
        assert_eq!(derived.effective_drain_timeout().as_secs(), 305);
        // Unset drain + very small read timeout → 30 s floor (the
        // documented lower bound; a 5 s read + 5 s doesn't leave enough
        // slack for shutdown-side work).
        let mut short = HarnessConfig::for_tests("http://127.0.0.1:9", "/tmp", "/tmp");
        short.upstream_read_timeout_s = Some(10);
        assert_eq!(short.effective_drain_timeout().as_secs(), 30);
        // Explicit value always wins.
        let mut explicit = HarnessConfig::for_tests("http://127.0.0.1:9", "/tmp", "/tmp");
        explicit.upstream_read_timeout_s = Some(300);
        explicit.shutdown_drain_timeout_s = Some(110);
        assert_eq!(explicit.effective_drain_timeout().as_secs(), 110);
        // Zero is refused at validate.
        let mut zero = HarnessConfig::for_tests("http://127.0.0.1:9", "/tmp", "/tmp");
        zero.shutdown_drain_timeout_s = Some(0);
        assert!(zero.validate().unwrap_err().contains("shutdown_drain_timeout_s"));
    }

    /// Refuse a wildcard bind (`0.0.0.0` / `[::]`) when identity is off
    /// unless an operator has explicitly acknowledged that an outer network
    /// layer controls exposure via `allow_wildcard_bind = true`. This
    /// prevents an unauthenticated proxy from silently reaching a
    /// developer's corporate LAN because a checked-in example config
    /// happened to bind wildcards.
    #[test]
    fn wildcard_bind_without_identity_is_refused_unless_explicitly_allowed() {
        // 0.0.0.0 with require_identity=false and no opt-in → refuse.
        let err = HarnessConfig::from_toml(
            r#"upstream_url = "https://api.openai.com"
               listen = "0.0.0.0:8484"
               require_identity = false"#,
        )
        .unwrap_err();
        assert!(err.contains("every interface"), "err should name the risk: {err}");
        assert!(
            err.contains("allow_wildcard_bind"),
            "err should name the escape hatch: {err}"
        );

        // IPv6 wildcard likewise refused.
        let err = HarnessConfig::from_toml(
            r#"upstream_url = "https://api.openai.com"
               listen = "[::]:8484"
               require_identity = false"#,
        )
        .unwrap_err();
        assert!(err.contains("every interface"), "IPv6 wildcard: {err}");

        // Loopback remains legal.
        HarnessConfig::from_toml(
            r#"upstream_url = "https://api.openai.com"
               listen = "127.0.0.1:8484"
               require_identity = false"#,
        )
        .unwrap()
        .validate()
        .unwrap();

        // Explicit opt-in (container / service-mesh deployments) passes.
        HarnessConfig::from_toml(
            r#"upstream_url = "https://api.openai.com"
               listen = "0.0.0.0:8484"
               require_identity = false
               allow_wildcard_bind = true"#,
        )
        .unwrap()
        .validate()
        .unwrap();

        // require_identity=true with a JWKS / HMAC source likewise passes.
        HarnessConfig::from_toml(
            r#"upstream_url = "https://api.openai.com"
               listen = "0.0.0.0:8484"
               require_identity = true
               identity_jwks_url = "https://idp/keys.json""#,
        )
        .unwrap()
        .validate()
        .unwrap();
    }

    /// Refuse URL fields that omit the scheme or use a
    /// scheme the client library will not accept. Preflight beats a
    /// runtime failure after the process is already serving traffic.
    #[test]
    fn round_30_f2_url_scheme_allowlist_enforced() {
        // JWKS URL: missing scheme.
        let err = HarnessConfig::from_toml(
            r#"upstream_url = "https://api"
               identity_jwks_url = "auth.internal/jwks""#,
        )
        .unwrap_err();
        assert!(err.contains("identity_jwks_url"), "{err}");
        assert!(err.contains("http://") || err.contains("https://"), "{err}");
        // JWKS URL: file scheme is a config-injection surface.
        let err = HarnessConfig::from_toml(
            r#"upstream_url = "https://api"
               identity_jwks_url = "file:///etc/passwd""#,
        )
        .unwrap_err();
        assert!(err.contains("identity_jwks_url"), "{err}");
        // Redis state_endpoint: bad scheme.
        let err = HarnessConfig::from_toml(
            r#"upstream_url = "https://api"
               state_backend = "redis"
               state_endpoint = "http://cache""#,
        )
        .unwrap_err();
        assert!(err.contains("state_endpoint"), "{err}");
        // Redis state_endpoint cluster list — one bad
        // member must fail validation even if the FIRST member has
        // an allowed scheme (the prior prefix-on-whole-string check
        // passed on any list beginning with `redis://`).
        let err = HarnessConfig::from_toml(
            r#"upstream_url = "https://api"
               state_backend = "redis"
               state_endpoint = "redis://a:6379,http://b:6379""#,
        )
        .unwrap_err();
        assert!(err.contains("state_endpoint"), "{err}");
        // Valid cluster list of two Redis URLs passes.
        HarnessConfig::from_toml(
            r#"upstream_url = "https://api"
               state_backend = "redis"
               state_endpoint = "redis://a:6379,rediss://b:6380""#,
        )
        .unwrap();
        // redis+unix: is a legitimate Unix-socket form
        // the redis crate accepts; validate must not reject it.
        HarnessConfig::from_toml(
            r#"upstream_url = "https://api"
               state_backend = "redis"
               state_endpoint = "redis+unix:/tmp/redis.sock""#,
        )
        .unwrap();
        // max_request_bytes = 0 is a silent-breakage
        // config (DefaultBodyLimit::max(0) rejects every non-empty
        // POST body); validate must refuse it.
        let err = HarnessConfig::from_toml(
            r#"upstream_url = "https://api"
               max_request_bytes = 0"#,
        )
        .unwrap_err();
        assert!(err.contains("max_request_bytes"), "{err}");
        // NATS bridge_endpoint: bad scheme.
        let err = HarnessConfig::from_toml(
            r#"upstream_url = "https://api"
               bridge_backend = "nats"
               bridge_endpoint = "http://bus""#,
        )
        .unwrap_err();
        assert!(err.contains("bridge_endpoint"), "{err}");
        // Qdrant: missing scheme.
        let err = HarnessConfig::from_toml(
            r#"upstream_url = "https://api"
               vector_backend = "qdrant"
               qdrant_url = "vectors.internal:6333""#,
        )
        .unwrap_err();
        assert!(err.contains("qdrant_url"), "{err}");
        // Legit values pass.
        assert!(HarnessConfig::from_toml(
            r#"upstream_url = "https://api"
               identity_jwks_url = "https://auth.internal/jwks"
               state_backend = "redis"
               state_endpoint = "redis://cache:6379"
               bridge_backend = "nats"
               bridge_endpoint = "nats://bus:4222"
               vector_backend = "qdrant"
               qdrant_url = "https://vectors.internal:6333""#,
        )
        .is_ok());
    }

    /// Empty `atif_spool_dir` / `bridge_data_dir` are
    /// rejected. Without the check they default to `Path::new("")`,
    /// making every spool op write to the process CWD instead of the
    /// expected volume.
    #[test]
    fn round_31_f1_local_fs_paths_empty_rejected() {
        let err = HarnessConfig::from_toml(
            r#"upstream_url = "https://api"
               atif_spool_dir = """#,
        )
        .unwrap_err();
        assert!(err.contains("atif_spool_dir"), "{err}");
        let err = HarnessConfig::from_toml(
            r#"upstream_url = "https://api"
               bridge_data_dir = """#,
        )
        .unwrap_err();
        assert!(err.contains("bridge_data_dir"), "{err}");
    }

    /// Identity scope names must be visible ASCII, no
    /// whitespace, no empty strings. Some IdPs tokenize an empty
    /// "scope" claim into an empty string; without this check the
    /// gate becomes `scopes.contains("")` and any token satisfies it.
    #[test]
    fn round_31_f2_scope_names_rejected_empty_or_whitespaced() {
        // Empty chat_scope.
        let err = HarnessConfig::from_toml(
            r#"upstream_url = "https://api"
               require_identity = true
               identity_hmac_secret_file = "/tmp/secret"
               enforce_identity_scopes = true
               chat_scope = """#,
        )
        .unwrap_err();
        assert!(err.contains("chat_scope"), "{err}");
        // Whitespace in scope.
        let err = HarnessConfig::from_toml(
            r#"upstream_url = "https://api"
               require_identity = true
               identity_hmac_secret_file = "/tmp/secret"
               enforce_identity_scopes = true
               chat_scope = "chat write""#,
        )
        .unwrap_err();
        assert!(err.contains("chat_scope"), "{err}");
        // Control byte in scope.
        let err = HarnessConfig::from_toml(
            r#"upstream_url = "https://api"
               require_identity = true
               identity_hmac_secret_file = "/tmp/secret"
               enforce_identity_scopes = true
               session_close_scope = "close\tsession""#,
        )
        .unwrap_err();
        assert!(err.contains("session_close_scope"), "{err}");
        // A well-formed scope passes.
        assert!(HarnessConfig::from_toml(
            r#"upstream_url = "https://api"
               require_identity = true
               identity_hmac_secret_file = "/tmp/secret"
               enforce_identity_scopes = true
               chat_scope = "chat:write"
               session_close_scope = "session:close"
               session_promote_scope = "session:promote""#,
        )
        .is_ok());
    }
}

// The permissive test constructor lives in its own
// FILE so a grep through config.rs finds only production defaults —
// `for_tests`'s test values fooled three independent reviewers. A
// child module (not a sibling) so it can reach the private
// `default_*` helpers without widening their visibility.
// Gated OUT of production builds entirely (Action Register item 7):
// `test` covers this crate's unit tests; the `test-support` feature is
// enabled only by the self dev-dependency, so integration tests and
// benches see it while `cargo build`/`--release`/`--features full`
// artifacts cannot even name it.
#[cfg(any(test, feature = "test-support"))]
#[path = "config_testkit.rs"]
mod testkit;
