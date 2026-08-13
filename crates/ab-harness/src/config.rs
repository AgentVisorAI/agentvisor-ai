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

impl HarnessConfig {
    /// Parse from TOML, validating the version and structural sanity.
    pub fn from_toml(s: &str) -> Result<Self, String> {
        let cfg: Self = toml::from_str(s).map_err(|e| format!("config parse: {e}"))?;
        cfg.validate()?;
        Ok(cfg)
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
