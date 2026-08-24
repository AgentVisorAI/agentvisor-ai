//! Test-support constructors for [`HarnessConfig`], kept OUT of
//! `config.rs` on purpose: the permissive test
//! defaults in `for_tests` fooled three independent reviewers,
//! because a grep for a config default finds the test value in the
//! same file as the production one. With this file, the production
//! defaults are the only ones a reader finds in `config.rs`.

use super::*;

impl HarnessConfig {
    /// A config suitable for tests (temp dirs supplied by the caller).
    ///
    /// # TESTS AND BENCHES ONLY
    ///
    /// The defaults here are DELIBERATELY permissive: `require_identity
    /// = false`, `require_tool_schema = false`, `enforce_identity_
    /// scopes = false`, `strict_stage_budget = false`. That posture is
    /// safe for a test harness but MUST NOT be shipped into a
    /// production boot path. This module only compiles under
    /// `cfg(test)` or the `test-support` cargo feature (enabled solely
    /// by the self dev-dependency), so production artifacts cannot
    /// even name this function. It is additionally `#[doc(hidden)]` so
    /// it does not appear in the public API surface (rustdoc, editor
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
            shutdown_drain_timeout_s: None,
            upstream_chat_path: default_chat_path(),
            provider: default_provider(),
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
            payout_field: default_payout_field(),
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
            allowed_hosts: Vec::new(),
        }
    }
}
