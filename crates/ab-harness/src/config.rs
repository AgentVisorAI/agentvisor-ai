//! Harness configuration (TOML surface, versioned).

use serde::{Deserialize, Serialize};

/// Config format version (evolution surface).
pub const CONFIG_VERSION: u32 = 1;

/// Top-level harness configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// Optional provider read-idle timeout. `None` permits intentionally held streams.
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
    #[serde(default = "default_true")]
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
    /// Default workflow when `X-AB-Workflow` is absent: signed workflows are
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
    /// Kafka broker or NATS URL for network Bridge backends.
    #[serde(default)]
    pub bridge_endpoint: Option<String>,
    /// State backend: `memory` or `redis`.
    #[serde(default = "default_state_backend")]
    pub state_backend: String,
    /// Redis URL for the distributed state backend.
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
    /// Strict per-stage budget assertions (AB_STRICT_BUDGET also enables).
    #[serde(default)]
    pub strict_stage_budget: bool,
    /// Loop breaker configuration.
    #[serde(default)]
    pub breaker: ab_loopdetect::BreakerConfig,
    /// Compression configuration.
    #[serde(default = "default_compression")]
    pub compression_enabled: bool,
    /// Token budget per session (compression/velocity accounting).
    #[serde(default)]
    pub budget: ab_state::BudgetSpec,
    /// Reconciler tick interval (seconds).
    #[serde(default = "default_reconcile_tick")]
    pub reconcile_tick_s: u64,
}

fn default_config_version() -> u32 {
    CONFIG_VERSION
}
fn default_listen() -> String {
    "127.0.0.1:8484".to_owned()
}
fn default_audience() -> String {
    "agent-bridge".to_owned()
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

/// Where the effective configuration came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigSource {
    /// Loaded from a TOML file on disk.
    File(std::path::PathBuf),
    /// Built-in defaults (zero-config mode; requires `AB_UPSTREAM_URL`).
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

/// Well-known config locations probed in order when `AB_CONFIG` is unset.
pub const CONFIG_SEARCH_PATHS: [&str; 3] = [
    "agentbridge.toml",
    "config/harness.toml",
    "config/harness.example.toml",
];

/// Resolve the configuration source without reading it.
///
/// Order: `AB_CONFIG` (must exist — a typo must never silently fall
/// through to another file), then [`CONFIG_SEARCH_PATHS`], then built-in
/// defaults driven by `AB_UPSTREAM_URL`.
pub fn resolve_config_source() -> Result<ConfigSource, String> {
    if let Some(path) = std::env::var_os("AB_CONFIG") {
        let path = std::path::PathBuf::from(path);
        if !path.is_file() {
            return Err(format!(
                "AB_CONFIG points to {} which does not exist or is not a file",
                path.display()
            ));
        }
        return Ok(ConfigSource::File(path));
    }
    for candidate in CONFIG_SEARCH_PATHS {
        let path = std::path::Path::new(candidate);
        if path.is_file() {
            return Ok(ConfigSource::File(path.to_path_buf()));
        }
    }
    Ok(ConfigSource::BuiltIn)
}

/// Load, apply environment overrides, and validate the effective config.
pub fn load_config() -> Result<(HarnessConfig, ConfigSource), String> {
    let source = resolve_config_source()?;
    let mut config = match &source {
        ConfigSource::File(path) => {
            let text = std::fs::read_to_string(path)
                .map_err(|error| format!("read harness config {}: {error}", path.display()))?;
            HarnessConfig::from_toml_unvalidated(&text)
                .map_err(|error| format!("{}: {error}", path.display()))?
        }
        ConfigSource::BuiltIn => HarnessConfig::builtin()?,
    };
    config.apply_env_overrides();
    if config.upstream_url.is_empty() && source == ConfigSource::BuiltIn {
        return Err(format!(
            "no configuration found and AB_UPSTREAM_URL is not set.\n\
             Quick start (pick one):\n\
             \x20 abctl init --preset openai        # write an annotated agentbridge.toml\n\
             \x20 AB_UPSTREAM_URL=http://127.0.0.1:11434 agent-bridge   # zero-config\n\
             Searched: $AB_CONFIG, {}",
            CONFIG_SEARCH_PATHS.join(", ")
        ));
    }
    config.validate().map_err(|error| format!("{source}: {error}"))?;
    Ok((config, source))
}

impl HarnessConfig {
    /// Parse from TOML, validating the version and structural sanity.
    pub fn from_toml(s: &str) -> Result<Self, String> {
        let cfg: Self = toml::from_str(s).map_err(|e| format!("config parse: {e}"))?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Parse from TOML without validating, so environment overrides can be
    /// applied first (`main` validates after [`Self::apply_env_overrides`]).
    pub fn from_toml_unvalidated(s: &str) -> Result<Self, String> {
        toml::from_str(s).map_err(|e| format!("config parse: {e}"))
    }

    /// A config of pure built-in defaults for zero-config startup. The
    /// caller must supply `upstream_url` (typically `AB_UPSTREAM_URL`)
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

    /// Apply `AB_*` environment overrides from the process environment.
    /// Environment beats file for these scalars (12-factor container
    /// deployments override without editing mounted files). Key *values*
    /// are still never read here — only `AB_UPSTREAM_API_KEY` presence
    /// selects itself as the key source.
    pub fn apply_env_overrides(&mut self) {
        self.apply_env_overrides_from(|name| std::env::var(name).ok());
    }

    /// Testable core of [`Self::apply_env_overrides`].
    pub fn apply_env_overrides_from(&mut self, get: impl Fn(&str) -> Option<String>) {
        let non_empty = |value: String| if value.is_empty() { None } else { Some(value) };
        if let Some(listen) = get("AB_LISTEN").and_then(non_empty) {
            self.listen = listen;
        }
        if let Some(url) = get("AB_UPSTREAM_URL").and_then(non_empty) {
            self.upstream_url = url;
        }
        if let Some(path) = get("AB_UPSTREAM_CHAT_PATH").and_then(non_empty) {
            self.upstream_chat_path = path;
        }
        if let Some(header) = get("AB_UPSTREAM_AUTH_HEADER").and_then(non_empty) {
            self.upstream_auth_header = header;
        }
        // Empty string is meaningful here: raw-key (schemeless) headers.
        if let Some(scheme) = get("AB_UPSTREAM_AUTH_SCHEME") {
            self.upstream_auth_scheme = scheme;
        }
        if let Some(endpoint) = get("AB_STATE_ENDPOINT").and_then(non_empty) {
            self.state_endpoint = Some(endpoint);
        }
        if let Some(endpoint) = get("AB_BRIDGE_ENDPOINT").and_then(non_empty) {
            self.bridge_endpoint = Some(endpoint);
        }
        if let Some(url) = get("AB_QDRANT_URL").and_then(non_empty) {
            self.qdrant_url = Some(url);
        }
        // Convenience: exporting AB_UPSTREAM_API_KEY selects itself as the
        // key source unless the file already chose one (file wins so a
        // stray environment variable cannot silently replace a configured
        // source; validate() still rejects genuinely ambiguous configs).
        if self.upstream_api_key_env.is_none()
            && self.upstream_api_key_file.is_none()
            && !self.upstream_authorization_passthrough
            && get("AB_UPSTREAM_API_KEY").and_then(non_empty).is_some()
        {
            self.upstream_api_key_env = Some("AB_UPSTREAM_API_KEY".to_owned());
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
        if self.require_identity
            && self.identity_jwks_url.as_deref().is_none_or(str::is_empty)
            && self
                .identity_hmac_secret_file
                .as_deref()
                .is_none_or(str::is_empty)
        {
            return Err("require_identity=true needs identity_jwks_url or identity_hmac_secret_file".into());
        }
        if self.identity_jwks_refresh_s == 0 {
            return Err("identity_jwks_refresh_s must be greater than zero".into());
        }
        if self.identity_hmac_kid.is_empty() {
            return Err("identity_hmac_kid must not be empty".into());
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
        Ok(())
    }

    /// A config suitable for tests (temp dirs supplied by the caller).
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
            tool_upstream_bearer_env: None,
            tool_upstream_bearer_file: None,
            require_identity: false,
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
            breaker: ab_loopdetect::BreakerConfig::default(),
            compression_enabled: true,
            budget: ab_state::BudgetSpec::default(),
            reconcile_tick_s: 1,
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
                "AB_LISTEN" => Some("0.0.0.0:9999".into()),
                "AB_UPSTREAM_URL" => Some("http://env-upstream".into()),
                "AB_UPSTREAM_CHAT_PATH" => Some("/openai/v1/chat/completions".into()),
                "AB_UPSTREAM_API_KEY" => Some("sk-secret".into()),
                "AB_STATE_ENDPOINT" => Some("redis://redis:6379".into()),
                _ => None,
            }
        };
        cfg.apply_env_overrides_from(env);
        assert_eq!(cfg.listen, "0.0.0.0:9999");
        assert_eq!(cfg.upstream_url, "http://env-upstream");
        assert_eq!(cfg.upstream_chat_path, "/openai/v1/chat/completions");
        assert_eq!(cfg.state_endpoint.as_deref(), Some("redis://redis:6379"));
        // AB_UPSTREAM_API_KEY presence selects itself as the key source...
        assert_eq!(cfg.upstream_api_key_env.as_deref(), Some("AB_UPSTREAM_API_KEY"));

        // ...but never displaces an explicitly configured source.
        let mut cfg = HarnessConfig::for_tests("http://file-upstream", "spool", "bridge");
        cfg.upstream_api_key_env = Some("OPENAI_API_KEY".into());
        cfg.apply_env_overrides_from(env);
        assert_eq!(cfg.upstream_api_key_env.as_deref(), Some("OPENAI_API_KEY"));

        // Empty environment values are ignored rather than blanking fields.
        let mut cfg = HarnessConfig::for_tests("http://file-upstream", "spool", "bridge");
        cfg.apply_env_overrides_from(|name| (name == "AB_UPSTREAM_URL").then(String::new));
        assert_eq!(cfg.upstream_url, "http://file-upstream");
    }

    #[test]
    fn builtin_config_validates_once_upstream_is_set() {
        let mut cfg = HarnessConfig::builtin().unwrap();
        assert!(cfg.validate().is_err(), "must not pass without an upstream");
        cfg.apply_env_overrides_from(|name| {
            (name == "AB_UPSTREAM_URL").then(|| "http://127.0.0.1:11434".to_owned())
        });
        cfg.validate().unwrap();
        assert_eq!(cfg.bridge_backend, "embedded");
        assert_eq!(cfg.state_backend, "memory");
        assert_eq!(cfg.embedder_backend, "hash");
        assert_eq!(cfg.vector_backend, "memory");
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

    #[test]
    fn unknown_fields_tolerated_inbound() {
        // Older harnesses must boot with configs written for newer versions
        // that only add fields.
        let cfg = HarnessConfig::from_toml(
            r#"upstream_url = "https://api"
               future_option_from_v2 = true"#,
        );
        assert!(cfg.is_ok(), "{cfg:?}");
    }
}
