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
    /// pipeline applies its 60 s default unconditionally (round-32 F4)
    /// — streams cannot be held indefinitely; widen this to extend it
    /// (capped at one day like every `_s` interval).
    #[serde(default)]
    pub upstream_read_timeout_s: Option<u64>,
    /// Chat-completions path appended to `upstream_url`. Override for
    /// providers with non-standard layouts (Azure deployments, Gemini's
    /// OpenAI-compatible surface).
    #[serde(default = "default_chat_path")]
    pub upstream_chat_path: String,
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
    /// Round-30 F1: default flipped from `true` to `false` so it
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
    /// Optional principal-scoped budget layered on top of [`budget`].
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
    /// deployments. See engineering review §8.1 and §8.2.
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
/// because the example outranked the wizard file — see engineering
/// review §9.4).
pub const CONFIG_SEARCH_PATHS: [&str; 2] = [
    "agentvisor.toml",
    "config/harness.toml",
];

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

    /// Structural validation.
    pub fn validate(&self) -> Result<(), String> {
        if self.config_version != CONFIG_VERSION {
            return Err(format!(
                "unsupported config_version {} (this build supports {CONFIG_VERSION})",
                self.config_version
            ));
        }
        if self.listen.is_empty() {
            return Err("listen is required (host:port, e.g. 127.0.0.1:8484)".into());
        }
        // Shape-only check: hostnames are resolved at bind time, but a missing
        // or non-numeric port would otherwise pass validation and only fail at
        // server startup, defeating pre-flight `avctl config-validate`/doctor.
        match self.listen.rsplit_once(':') {
            Some((host, port)) if !host.is_empty() && port.parse::<u16>().is_ok() => {}
            _ => {
                return Err(format!(
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
                return Err(format!(
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
            return Err("reconcile_tick_s must be greater than zero".into());
        }
        if self.session_idle_close_s == 0 {
            return Err(
                "session_idle_close_s must be greater than zero (0 would close every open session at each reconcile tick)"
                    .into(),
            );
        }
        if self.upstream_url.is_empty() {
            return Err("upstream_url is required".into());
        }
        if !self.upstream_chat_path.starts_with('/') {
            return Err(format!(
                "upstream_chat_path must start with '/', got {:?}",
                self.upstream_chat_path
            ));
        }
        if self.upstream_api_key_env.as_deref().is_some_and(str::is_empty) {
            return Err("upstream_api_key_env must not be empty when set".into());
        }
        if self.upstream_api_key_file.as_deref().is_some_and(str::is_empty) {
            return Err("upstream_api_key_file must not be empty when set".into());
        }
        if self.upstream_api_key_env.is_some() && self.upstream_api_key_file.is_some() {
            return Err(
                "set only one of upstream_api_key_env or upstream_api_key_file (ambiguous key source)".into(),
            );
        }
        let has_static_key = self.upstream_api_key_env.is_some() || self.upstream_api_key_file.is_some();
        if self.upstream_authorization_passthrough && has_static_key {
            return Err(
                "upstream_authorization_passthrough conflicts with upstream_api_key_env/file: choose one auth mode"
                    .into(),
            );
        }
        if self.upstream_authorization_passthrough && self.require_identity {
            return Err(
                "upstream_authorization_passthrough cannot be combined with require_identity: the \
                 Authorization header carries the NHI token, which must never be sent upstream"
                    .into(),
            );
        }
        if self.ignore_client_authorization && self.require_identity {
            return Err(
                "ignore_client_authorization cannot be combined with require_identity: the \
                 identity validator must see the Authorization header, not discard it"
                    .into(),
            );
        }
        if self.ignore_client_authorization && self.upstream_authorization_passthrough {
            return Err(
                "ignore_client_authorization conflicts with upstream_authorization_passthrough: \
                 a client Authorization header cannot be both discarded and forwarded upstream"
                    .into(),
            );
        }
        if axum::http::HeaderName::try_from(self.upstream_auth_header.as_str()).is_err() {
            return Err(format!(
                "upstream_auth_header {:?} is not a valid HTTP header name",
                self.upstream_auth_header
            ));
        }
        if self
            .upstream_auth_scheme
            .bytes()
            .any(|byte| !(0x21..=0x7e).contains(&byte))
        {
            return Err(
                "upstream_auth_scheme must contain only visible ASCII with no spaces (use \"\" for a raw key)"
                    .into(),
            );
        }
        if self.tool_upstream_bearer_env.is_some() && self.tool_upstream_bearer_file.is_some() {
            return Err(
                "set only one of tool_upstream_bearer_env or tool_upstream_bearer_file (ambiguous token source)"
                    .into(),
            );
        }
        // Round-29 F1 (av-harness config): parity with the
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
            return Err("tool_upstream_bearer_env must not be empty when set".into());
        }
        if self
            .tool_upstream_bearer_file
            .as_deref()
            .is_some_and(str::is_empty)
        {
            return Err("tool_upstream_bearer_file must not be empty when set".into());
        }
        if (self.tool_upstream_bearer_env.is_some() || self.tool_upstream_bearer_file.is_some())
            && self.tool_upstream_url.as_deref().is_none_or(str::is_empty)
        {
            return Err("tool_upstream_bearer_env/file requires tool_upstream_url to be set".into());
        }
        if crate::session::Workflow::parse(&self.default_workflow).is_none() {
            return Err(format!(
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
        if self.principal_budget.is_some()
            && !self.require_identity
            && !self.allow_anonymous_principal_budget
        {
            return Err(
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
            return Err("require_identity=true needs identity_jwks_url or identity_hmac_secret_file".into());
        }
        // Round-30 F1: reject the silent-anonymous-bypass posture.
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
        // exact repudiation vector round-15 F3's Bearer-case fix
        // documented. Refuse the combo so operators either turn
        // enforcement off (making the posture explicit) or turn
        // identity on.
        if self.enforce_identity_scopes && !self.require_identity {
            return Err(
                "enforce_identity_scopes=true has no effect while require_identity=false: \
                 unauthenticated requests fall through to the anonymous identity and bypass \
                 the scope gate entirely. Either set require_identity=true, or set \
                 enforce_identity_scopes=false to make the posture explicit."
                    .into(),
            );
        }
        if self.identity_jwks_refresh_s == 0 {
            return Err("identity_jwks_refresh_s must be greater than zero".into());
        }
        // `tokio::time::interval(Duration::from_secs(0))` panics. Guard
        // against a value that squeaks past the > 0 check via overflow
        // arithmetic elsewhere by requiring a minimum plausible cadence
        // — a JWKS refresh below 30 s hammers the IdP and offers no
        // real benefit at NHI TTLs measured in minutes.
        if self.identity_jwks_refresh_s < 30 {
            return Err(format!(
                "identity_jwks_refresh_s {} is too aggressive; a value below 30 s hammers the IdP \
                 without benefit given NHI TTLs measured in minutes",
                self.identity_jwks_refresh_s
            ));
        }
        if self.identity_hmac_kid.is_empty() {
            return Err("identity_hmac_kid must not be empty".into());
        }
        // Round-31 F2: scope names must be visible-ASCII non-empty
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
                return Err(format!("{field} must not be empty"));
            }
            if value.bytes().any(|byte| !(0x21..=0x7e).contains(&byte)) {
                return Err(format!(
                    "{field} {value:?} must be visible ASCII with no whitespace or control bytes"
                ));
            }
        }
        if self.worker_channel_capacity == 0 {
            return Err("worker_channel_capacity must be > 0".into());
        }
        if !matches!(self.bridge_backend.as_str(), "embedded" | "kafka" | "nats") {
            return Err(format!(
                "bridge_backend must be embedded|kafka|nats, got {:?}",
                self.bridge_backend
            ));
        }
        if self.bridge_manifest_path.is_empty() {
            return Err("bridge_manifest_path is required".into());
        }
        // Round-31 F1: refuse empty local-fs path fields. If an
        // operator overrides `atif_spool_dir = ""` in TOML (e.g. by
        // accidentally interpolating an unset env variable through a
        // template), every ATIF spool op used to run on Path::new("")
        // whose joins degrade to CWD-relative writes — receipts land
        // in the process CWD instead of the expected volume, recovery
        // scans miss them on the next boot. Same shape for
        // `bridge_data_dir` (embedded broker segments in CWD).
        if self.atif_spool_dir.is_empty() {
            return Err("atif_spool_dir must not be empty".into());
        }
        if self.bridge_data_dir.is_empty() {
            return Err("bridge_data_dir must not be empty".into());
        }
        if self.bridge_backend != "embedded" && self.bridge_endpoint.as_deref().is_none_or(str::is_empty) {
            return Err("bridge_endpoint is required for kafka and nats backends".into());
        }
        if !matches!(self.state_backend.as_str(), "memory" | "redis") {
            return Err(format!(
                "state_backend must be memory|redis, got {:?}",
                self.state_backend
            ));
        }
        if self.state_backend == "redis" && self.state_endpoint.as_deref().is_none_or(str::is_empty) {
            return Err("state_endpoint is required for the redis backend".into());
        }
        if !matches!(self.embedder_backend.as_str(), "hash" | "onnx") {
            return Err(format!(
                "embedder_backend must be hash|onnx, got {:?}",
                self.embedder_backend
            ));
        }
        if self.embedder_backend == "onnx"
            && (self.onnx_model_path.as_deref().is_none_or(str::is_empty)
                || self.onnx_tokenizer_path.as_deref().is_none_or(str::is_empty))
        {
            return Err("onnx_model_path and onnx_tokenizer_path are required for the onnx backend".into());
        }
        if self.onnx_dimension == 0 {
            return Err("onnx_dimension must be greater than zero".into());
        }
        if !matches!(self.vector_backend.as_str(), "memory" | "qdrant") {
            return Err(format!(
                "vector_backend must be memory|qdrant, got {:?}",
                self.vector_backend
            ));
        }
        if self.vector_backend == "qdrant" && self.qdrant_url.as_deref().is_none_or(str::is_empty) {
            return Err("qdrant_url is required for the qdrant vector backend".into());
        }
        if self.qdrant_collection.is_empty() {
            return Err("qdrant_collection must not be empty".into());
        }
        if self.breaker.window == 0 {
            return Err(
                "breaker.window must be greater than zero (0 trips on token count alone, ignoring semantic similarity)"
                    .into(),
            );
        }
        if !self.breaker.delta_epsilon.is_finite() || self.breaker.delta_epsilon <= 0.0 {
            return Err(format!(
                "breaker.delta_epsilon must be a finite number greater than zero, got {}",
                self.breaker.delta_epsilon
            ));
        }
        // Upper bounds so a fat-finger in TOML cannot OOM the process
        // before the runtime feels the misconfiguration. Values are
        // deliberately loose: they only reject genuinely absurd numbers.
        if self.worker_channel_capacity > MAX_WORKER_CHANNEL_CAPACITY {
            return Err(format!(
                "worker_channel_capacity {} exceeds the safety cap of {} — oversized channels hide real backpressure and let per-shard buffers grow unboundedly under overload",
                self.worker_channel_capacity, MAX_WORKER_CHANNEL_CAPACITY
            ));
        }
        if self.max_request_bytes == 0 {
            return Err(
                "max_request_bytes must be > 0 — a 0 cap forwards to DefaultBodyLimit::max(0), \
                 rejecting every non-empty POST body silently"
                    .into(),
            );
        }
        if self.max_request_bytes > MAX_REQUEST_BYTES_CAP {
            return Err(format!(
                "max_request_bytes {} exceeds the safety cap of {} (512 MiB) — a single request should never legitimately need more, and lifting this defeats the sandbox payload guard",
                self.max_request_bytes, MAX_REQUEST_BYTES_CAP
            ));
        }
        if self.onnx_dimension > MAX_ONNX_DIMENSION {
            return Err(format!(
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
                return Err(
                    "upstream_read_timeout_s = 0 would time out every upstream read immediately — omit the key to use the built-in 60 s default".into(),
                );
            }
            interval_fields.push(("upstream_read_timeout_s", read_timeout));
        }
        for (field, value) in interval_fields {
            if value > MAX_SECONDS_INTERVAL {
                return Err(format!(
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
        // Round-38 F1: tighten to a strict http/https allowlist so
        // this matches the round-30 F2 posture applied to
        // `identity_jwks_url`, `qdrant_url`, etc. The old
        // `contains("://")` check accepted `file:///etc/passwd`,
        // `gopher://…`, and other schemes even though the error text
        // claimed "must be http:// or https://" — a config-injection
        // primitive or a templating typo (`${UPSTREAM:-file:///…}`)
        // used to pass `avctl config-validate` and only fail at
        // request time. Now every URL field's shape is preflighted
        // by the same rule.
        if !(self.upstream_url.starts_with("http://") || self.upstream_url.starts_with("https://")) {
            return Err(format!(
                "upstream_url must be http:// or https://, got {:?}",
                self.upstream_url
            ));
        }
        // A scheme with no host (`http://`, `https:///path`) passed the
        // prefix check above, booted, and validated cleanly, failing
        // only at request time with a 502 — exactly the class the
        // round-38 preflight exists to catch at startup.
        {
            let rest = self
                .upstream_url
                .split_once("://")
                .map(|(_, rest)| rest)
                .unwrap_or_default();
            let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
            if host.is_empty() {
                return Err(format!("upstream_url has no host, got {:?}", self.upstream_url));
            }
        }
        if let Some(tool_upstream) = &self.tool_upstream_url {
            // Empty is rejected rather than treated as unset: routing gates
            // tool forwarding on `is_some()` (routes.rs), so an empty string
            // would silently enable the tool-upstream branches and only fail
            // at the first request with a reqwest URL error. Fail loudly at
            // startup like every other config-shape problem.
            if tool_upstream.is_empty() {
                return Err(
                    "tool_upstream_url must not be empty; omit the field to disable tool forwarding"
                        .to_owned(),
                );
            }
            if !(tool_upstream.starts_with("http://") || tool_upstream.starts_with("https://")) {
                return Err(format!(
                    "tool_upstream_url must be http:// or https://, got {tool_upstream:?}"
                ));
            }
        }
        // Round-30 F2: extend the scheme allowlist to every URL
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
                return Err(format!(
                    "identity_jwks_url must be http:// or https://, got {url:?}"
                ));
            }
        }
        if self.vector_backend == "qdrant" {
            if let Some(url) = self.qdrant_url.as_deref().filter(|value| !value.is_empty()) {
                if !(url.starts_with("http://") || url.starts_with("https://")) {
                    return Err(format!("qdrant_url must be http:// or https://, got {url:?}"));
                }
            }
        }
        if self.state_backend == "redis" {
            if let Some(url) = self.state_endpoint.as_deref().filter(|value| !value.is_empty()) {
                // Round-20 F2 (av-harness config): the state_endpoint
                // field is docstring-documented as a comma-separated
                // list of URLs for Redis Cluster mode (see the field
                // doc above). The scheme allowlist used to be a
                // prefix check on the WHOLE string, so
                // `redis://a:6379,http://b` passed validate (the
                // check saw the `redis://` prefix) and only failed
                // at connect. `redis+unix:` was also rejected here
                // even though it's a legitimate Unix-socket form the
                // redis crate accepts and the round-14 doctor
                // `probe_endpoint_any` already recognizes. Split on
                // ',' and validate each member independently.
                for member in url.split(',').map(str::trim).filter(|m| !m.is_empty()) {
                    let ok = member.starts_with("redis://")
                        || member.starts_with("rediss://")
                        || member.starts_with("unix:")
                        || member.starts_with("redis+unix:");
                    if !ok {
                        return Err(format!(
                            "state_endpoint (redis backend) member {member:?} must be \
                             redis://, rediss://, unix:, or redis+unix: (got {member:?} in {url:?})"
                        ));
                    }
                }
            }
        }
        if self.bridge_backend == "nats" {
            if let Some(url) = self.bridge_endpoint.as_deref().filter(|value| !value.is_empty()) {
                if !(url.starts_with("nats://") || url.starts_with("tls://")) {
                    return Err(format!(
                        "bridge_endpoint (nats backend) must be nats:// or tls://, got {url:?}"
                    ));
                }
            }
        }
        // Kafka bridge_endpoint is a `host:port[,host:port]` bootstrap
        // list, not a URL — no scheme check applies. rdkafka rejects
        // malformed values on connect.
        Ok(())
    }

    /// A config suitable for tests (temp dirs supplied by the caller).
    ///
    /// # Round-35 F3 — TESTS AND BENCHES ONLY
    ///
    /// The defaults here are DELIBERATELY permissive: `require_identity
    /// = false`, `require_tool_schema = false`, `enforce_identity_
    /// scopes = false`, `strict_stage_budget = false`. That posture is
    /// safe for a test harness but MUST NOT be shipped into a
    /// production boot path. This function is `#[doc(hidden)]` so it
    /// does not appear in the public API surface (rustdoc, editor
    /// completion) and cannot be discovered by a future "smoke boot"
    /// helper looking for a quick config constructor. Any production
    /// caller must build a `HarnessConfig` explicitly from
    /// [`Self::from_toml`] so the deliberate posture flags are
    /// operator-visible in the config file.
    #[doc(hidden)]
    pub fn for_tests(upstream_url: &str, spool: &str, bridge: &str) -> Self {
        Self {
            config_version: CONFIG_VERSION,
            listen: "127.0.0.1:0".into(),
            upstream_url: upstream_url.to_owned(),
            tool_upstream_url: None,
            upstream_http2_prior_knowledge: false,
            upstream_read_timeout_s: None,
            upstream_chat_path: default_chat_path(),
            upstream_api_key_env: None,
            upstream_api_key_file: None,
            upstream_auth_header: default_auth_header(),
            upstream_auth_scheme: default_auth_scheme(),
            upstream_authorization_passthrough: false,
            ignore_client_authorization: false,
            tool_upstream_bearer_env: None,
            tool_upstream_bearer_file: None,
            require_identity: false,
            allow_wildcard_bind: false,
            audience: default_audience(),
            identity_jwks_url: None,
            identity_jwks_refresh_s: default_jwks_refresh(),
            identity_allowed_issuers: Vec::new(),
            identity_hmac_secret_file: None,
            identity_hmac_kid: default_hmac_kid(),
            enforce_identity_scopes: false,
            chat_scope: default_chat_scope(),
            session_close_scope: default_close_scope(),
            session_promote_scope: default_promote_scope(),
            default_workflow: "unsigned".into(),
            consequential_tools: default_consequential_tools(),
            tool_schema_dir: None,
            require_tool_schema: false,
            wasm_policy_paths: Vec::new(),
            session_idle_close_s: 900,
            atif_spool_dir: spool.to_owned(),
            bridge_data_dir: bridge.to_owned(),
            bridge_backend: "embedded".into(),
            bridge_manifest_path: default_bridge_manifest(),
            bridge_endpoint: None,
            state_backend: "memory".into(),
            state_endpoint: None,
            embedder_backend: "hash".into(),
            onnx_model_path: None,
            onnx_tokenizer_path: None,
            onnx_dimension: default_onnx_dimension(),
            vector_backend: "memory".into(),
            qdrant_url: None,
            qdrant_collection: default_qdrant_collection(),
            worker_channel_capacity: 1024,
            strict_stage_budget: false,
            breaker: av_loopdetect::BreakerConfig::default(),
            compression_enabled: true,
            budget: av_state::BudgetSpec::default(),
            principal_budget: None,
            allow_anonymous_principal_budget: false,
            reconcile_tick_s: 1,
            atif_retention_days: None,
            max_request_bytes: default_max_request_bytes(),
            dashboard_enabled: default_dashboard_enabled(),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

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

        cfg = base();
        cfg.breaker.window = 0;
        assert!(cfg.validate().unwrap_err().contains("breaker.window"));

        cfg = base();
        cfg.breaker.delta_epsilon = f32::NAN;
        assert!(cfg.validate().unwrap_err().contains("delta_epsilon"));
        cfg.breaker.delta_epsilon = -0.5;
        assert!(cfg.validate().unwrap_err().contains("delta_epsilon"));
    }

    #[test]
    fn user_config_path_is_stable() {
        let path = user_config_path_from(std::path::Path::new("/home/pat"));
        assert_eq!(
            path,
            std::path::Path::new("/home/pat/.agentvisor/agentvisor.toml")
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
            r#"upstream_url = "x"
               config_version = 99"#
        )
        .is_err());
        assert!(HarnessConfig::from_toml(
            r#"upstream_url = "x"
               default_workflow = "sometimes""#
        )
        .is_err());
        assert!(HarnessConfig::from_toml(
            r#"upstream_url = "x"
               worker_channel_capacity = 0"#
        )
        .is_err());
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
    /// Round-38 F1 tightened the shape check from `contains("://")` to
    /// the strict `http://` / `https://` allowlist, matching the
    /// round-30 F2 posture on every other URL field.
    #[test]
    fn upstream_url_without_scheme_is_rejected() {
        let err = HarnessConfig::from_toml(r#"upstream_url = "openai.internal""#).unwrap_err();
        assert!(err.contains("upstream_url"), "{err}");
        assert!(err.contains("http"), "{err}");
    }

    /// Round-38 F1: schemes other than http/https are rejected. The
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

    /// Round-30 F1: refuse `enforce_identity_scopes = true` while
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
        assert!(err.contains("allow_wildcard_bind"), "err should name the escape hatch: {err}");

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

    /// Round-30 F2: refuse URL fields that omit the scheme or use a
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
        // Round-20 F2: Redis state_endpoint cluster list — one bad
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
        // Round-20 F2: valid cluster list of two Redis URLs passes.
        HarnessConfig::from_toml(
            r#"upstream_url = "https://api"
               state_backend = "redis"
               state_endpoint = "redis://a:6379,rediss://b:6380""#,
        )
        .unwrap();
        // Round-20 F2: redis+unix: is a legitimate Unix-socket form
        // the redis crate accepts; validate must not reject it.
        HarnessConfig::from_toml(
            r#"upstream_url = "https://api"
               state_backend = "redis"
               state_endpoint = "redis+unix:/tmp/redis.sock""#,
        )
        .unwrap();
        // Round-20 F1: max_request_bytes = 0 is a silent-breakage
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

    /// Round-31 F1: empty `atif_spool_dir` / `bridge_data_dir` are
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

    /// Round-31 F2: identity scope names must be visible ASCII, no
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
