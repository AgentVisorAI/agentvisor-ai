//! Per-backend credential routing and network isolation (pillar 4).
//!
//! Each backend has a name, URL, authentication policy, and a set of tools
//! it serves. The router resolves a tool name to its backend and constructs
//! the appropriate credential header. Backend URLs come only from config;
//! redirects are not followed.

use crate::config::{BackendAuth, BackendConfig};
use axum::http::{HeaderName, HeaderValue};
use std::collections::HashMap;

/// Name of the implicit backend built from `tool_upstream_url`. It is
/// also the audience of intent tokens sent to that upstream.
pub const DEFAULT_BACKEND_NAME: &str = "default";

/// Validate an HTTP endpoint before constructing a network request.
pub(crate) fn validate_http_endpoint(url: &str, field: &str) -> Result<(), String> {
    let authority = url
        .split_once("://")
        .map(|(_, rest)| rest.split(['/', '?', '#']).next().unwrap_or_default());
    if url.trim() != url || authority.is_none_or(str::is_empty) {
        return Err(format!(
            "{field} must be a non-empty http:// or https:// URL with a host"
        ));
    }
    let parsed = reqwest::Url::parse(url).map_err(|_| format!("{field} is not a valid URL"))?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none_or(str::is_empty) {
        return Err(format!("{field} must be an http:// or https:// URL with a host"));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(format!(
            "{field} must not contain credentials; configure authentication separately"
        ));
    }
    Ok(())
}

/// Validate routing structure without reading credentials or contacting services.
pub(crate) fn validate_configs(configs: &[BackendConfig]) -> Vec<String> {
    let mut errors = Vec::new();
    let mut names = std::collections::HashSet::new();
    let mut tools = std::collections::HashSet::new();
    let mut default_seen = false;
    for backend in configs {
        if backend.name.trim().is_empty() || backend.name.chars().any(|c| c.is_whitespace() || c.is_control())
        {
            errors.push("backend name must not be empty or contain whitespace/control characters".into());
        }
        if backend.name == DEFAULT_BACKEND_NAME {
            errors.push("backend name \"default\" is reserved for tool_upstream_url".into());
        }
        if !names.insert(&backend.name) {
            errors.push(format!("duplicate backend name {:?}", backend.name));
        }
        if let Err(error) = validate_http_endpoint(&backend.url, &format!("backend {:?} url", backend.name)) {
            errors.push(error);
        }
        if backend.tools.is_empty() {
            if default_seen {
                errors.push("multiple backends with empty tools list (only one default allowed)".into());
            }
            default_seen = true;
        }
        for tool in &backend.tools {
            if tool.is_empty()
                || !tool.is_ascii()
                || tool
                    .bytes()
                    .any(|b| b.is_ascii_uppercase() || b.is_ascii_whitespace() || b.is_ascii_control())
            {
                errors.push(format!("backend {:?}: tool {tool:?} must be non-empty lowercase ASCII without whitespace or controls", backend.name));
            }
            if !tools.insert(tool) {
                errors.push(format!(
                    "tool {tool:?} mapped to multiple backends or repeated in backend {:?}",
                    backend.name
                ));
            }
        }
        match &backend.auth {
            BackendAuth::StaticEnv(value) | BackendAuth::StaticFile(value) if value.trim().is_empty() => {
                errors.push(format!(
                    "backend {:?}: authentication source must not be empty",
                    backend.name
                ));
            }
            _ => {}
        }
    }
    errors
}

/// Resolved backend with its credential.
#[derive(Debug, Clone)]
pub struct ResolvedBackend {
    /// Backend name (for metrics and logging).
    pub name: String,
    /// Base URL.
    pub url: String,
    /// Pre-resolved auth header (name + value), if any.
    pub auth_header: Option<(HeaderName, HeaderValue)>,
    /// Auth mode (for token exchange decisions).
    pub auth_mode: BackendAuthMode,
}

/// Simplified auth mode for runtime decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendAuthMode {
    /// No credentials attached.
    None,
    /// Static credential (env var or file).
    Static,
    /// Credential obtained via RFC 8693 token exchange.
    Exchange,
}

/// Routes tool names to backends. Built once at startup from config.
pub struct BackendRouter {
    tool_to_backend: HashMap<String, usize>,
    backends: Vec<ResolvedBackend>,
    default_idx: Option<usize>,
}

impl BackendRouter {
    /// Build from config. Resolves static credentials at construction time
    /// so the hot path does no I/O. `fallback_auth` is the credential for
    /// `fallback_url` (the `tool_upstream_bearer_*` setting); it rides on
    /// the implicit default backend so every call to that upstream carries it.
    pub fn new(
        configs: &[BackendConfig],
        fallback_url: Option<&str>,
        fallback_auth: Option<HeaderValue>,
    ) -> Result<Self, String> {
        let errors = validate_configs(configs);
        if !errors.is_empty() {
            return Err(errors.join("; "));
        }
        if let Some(url) = fallback_url {
            validate_http_endpoint(url, "tool_upstream_url")?;
        }
        let mut backends = Vec::new();
        let mut tool_to_backend = HashMap::new();
        let mut default_idx = None;

        for (idx, cfg) in configs.iter().enumerate() {
            let what = format!("backend {:?} bearer token", cfg.name);
            let secret = match &cfg.auth {
                BackendAuth::None | BackendAuth::Exchange => None,
                BackendAuth::StaticEnv(var) => {
                    crate::pipeline::read_secret(Some(var), None, &what).map_err(|e| e.to_string())?
                }
                BackendAuth::StaticFile(path) => {
                    crate::pipeline::read_secret(None, Some(path), &what).map_err(|e| e.to_string())?
                }
            };
            let auth_header = match secret {
                Some(token) => {
                    let mut value = HeaderValue::from_str(&format!("Bearer {token}"))
                        .map_err(|_| format!("{what} contains bytes that cannot appear in an HTTP header"))?;
                    value.set_sensitive(true);
                    Some((HeaderName::from_static("authorization"), value))
                }
                None => None,
            };
            let auth_mode = match &cfg.auth {
                BackendAuth::None => BackendAuthMode::None,
                BackendAuth::StaticEnv(_) | BackendAuth::StaticFile(_) => BackendAuthMode::Static,
                BackendAuth::Exchange => BackendAuthMode::Exchange,
            };
            backends.push(ResolvedBackend {
                name: cfg.name.clone(),
                url: cfg.url.clone(),
                auth_header,
                auth_mode,
            });
            if cfg.tools.is_empty() {
                if default_idx.is_some() {
                    return Err(format!(
                        "backend {:?}: multiple backends with empty tools list (only one default allowed)",
                        cfg.name
                    ));
                }
                default_idx = Some(idx);
            }
            for tool in &cfg.tools {
                if tool_to_backend.contains_key(tool) {
                    return Err(format!(
                        "tool {tool:?} mapped to multiple backends (backend {:?} conflicts)",
                        cfg.name
                    ));
                }
                tool_to_backend.insert(tool.clone(), idx);
            }
        }

        // If no backends are configured, create an implicit default from
        // the fallback URL (backward compatibility with tool_upstream_url).
        if backends.is_empty() {
            if let Some(url) = fallback_url {
                let auth_mode = if fallback_auth.is_some() {
                    BackendAuthMode::Static
                } else {
                    BackendAuthMode::None
                };
                backends.push(ResolvedBackend {
                    name: DEFAULT_BACKEND_NAME.into(),
                    url: url.to_owned(),
                    auth_header: fallback_auth.map(|value| (HeaderName::from_static("authorization"), value)),
                    auth_mode,
                });
                default_idx = Some(0);
            }
        }

        Ok(Self {
            tool_to_backend,
            backends,
            default_idx,
        })
    }

    /// Resolve a tool name to its backend. Returns `None` when no backend
    /// is configured for this tool and no default exists.
    pub fn resolve(&self, tool: &str) -> Option<&ResolvedBackend> {
        let idx = self.tool_to_backend.get(tool).copied().or(self.default_idx)?;
        self.backends.get(idx)
    }

    /// Number of configured backends.
    pub fn len(&self) -> usize {
        self.backends.len()
    }

    /// True when no backends are configured.
    pub fn is_empty(&self) -> bool {
        self.backends.is_empty()
    }

    /// Iterator over all configured backends.
    pub fn iter(&self) -> impl Iterator<Item = &ResolvedBackend> {
        self.backends.iter()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn backend(name: &str, url: &str, tools: &[&str]) -> BackendConfig {
        BackendConfig {
            name: name.into(),
            url: url.into(),
            auth: BackendAuth::None,
            tools: tools.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    #[test]
    fn explicit_tool_routing() {
        let router = BackendRouter::new(
            &[
                backend("db", "http://db:8080", &["db_write", "db_read"]),
                backend("search", "http://search:8080", &["search"]),
            ],
            None,
            None,
        )
        .unwrap();
        assert_eq!(router.resolve("db_write").unwrap().name, "db");
        assert_eq!(router.resolve("search").unwrap().name, "search");
        assert!(router.resolve("unknown").is_none());
    }

    #[test]
    fn router_rejects_invalid_names_urls_and_duplicate_audiences() {
        for config in [
            backend("", "http://db", &["read"]),
            backend("default", "http://db", &["read"]),
            backend("db", "https:///mcp", &["read"]),
            backend("db", "file:///mcp", &["read"]),
            backend("db", "http://db:invalid", &["read"]),
        ] {
            assert!(BackendRouter::new(&[config], None, None).is_err());
        }
        assert!(BackendRouter::new(
            &[
                backend("db", "http://db", &["read"]),
                backend("db", "http://other", &["write"]),
            ],
            None,
            None
        )
        .err()
        .unwrap()
        .contains("duplicate backend name"));
        assert!(BackendRouter::new(&[], Some("http:///mcp"), None).is_err());
    }

    #[test]
    fn default_backend_catches_unmapped_tools() {
        let router = BackendRouter::new(
            &[
                backend("db", "http://db:8080", &["db_write"]),
                backend("fallback", "http://fallback:8080", &[]),
            ],
            None,
            None,
        )
        .unwrap();
        assert_eq!(router.resolve("db_write").unwrap().name, "db");
        assert_eq!(router.resolve("anything").unwrap().name, "fallback");
    }

    #[test]
    fn implicit_default_from_fallback_url() {
        let router = BackendRouter::new(&[], Some("http://tool:8080"), None).unwrap();
        assert_eq!(router.resolve("any_tool").unwrap().name, "default");
        assert_eq!(router.resolve("any_tool").unwrap().url, "http://tool:8080");
    }

    #[test]
    fn duplicate_tool_mapping_refused() {
        let result = BackendRouter::new(
            &[
                backend("a", "http://a:8080", &["shared_tool"]),
                backend("b", "http://b:8080", &["shared_tool"]),
            ],
            None,
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn multiple_default_backends_refused() {
        let result = BackendRouter::new(
            &[
                backend("a", "http://a:8080", &[]),
                backend("b", "http://b:8080", &[]),
            ],
            None,
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn no_backends_and_no_fallback() {
        let router = BackendRouter::new(&[], None, None).unwrap();
        assert!(router.is_empty());
        assert!(router.resolve("anything").is_none());
    }

    #[test]
    fn credential_isolation_between_backends() {
        std::env::set_var("TEST_BACKEND_A_KEY", "secret-a");
        let router = BackendRouter::new(
            &[
                BackendConfig {
                    name: "a".into(),
                    url: "http://a:8080".into(),
                    auth: BackendAuth::StaticEnv("TEST_BACKEND_A_KEY".into()),
                    tools: vec!["tool_a".into()],
                },
                backend("b", "http://b:8080", &["tool_b"]),
            ],
            None,
            None,
        )
        .unwrap();
        let a = router.resolve("tool_a").unwrap();
        assert!(a.auth_header.is_some());
        let b = router.resolve("tool_b").unwrap();
        assert!(b.auth_header.is_none());
        std::env::remove_var("TEST_BACKEND_A_KEY");
    }

    fn static_env_backend(name: &str, var: &str) -> BackendConfig {
        BackendConfig {
            name: name.into(),
            url: format!("http://{name}:8080"),
            auth: BackendAuth::StaticEnv(var.into()),
            tools: vec![format!("{name}_tool")],
        }
    }

    #[test]
    fn implicit_default_carries_the_tool_upstream_bearer() {
        let bearer = HeaderValue::from_static("Bearer tool-secret");
        let router = BackendRouter::new(&[], Some("http://tool:8080/mcp"), Some(bearer)).unwrap();
        let default = router.resolve("anything").unwrap();
        assert_eq!(default.name, DEFAULT_BACKEND_NAME);
        assert_eq!(default.auth_mode, BackendAuthMode::Static);
        let (name, value) = default
            .auth_header
            .as_ref()
            .expect("tool bearer must ride on the default");
        assert_eq!(name.as_str(), "authorization");
        assert_eq!(value.to_str().unwrap(), "Bearer tool-secret");
    }

    #[test]
    fn explicit_backends_never_inherit_the_tool_upstream_bearer() {
        let bearer = HeaderValue::from_static("Bearer tool-secret");
        let router = BackendRouter::new(
            &[backend("plain", "http://plain:8080", &["plain_tool"])],
            Some("http://tool:8080/mcp"),
            Some(bearer),
        )
        .unwrap();
        assert!(router.resolve("plain_tool").unwrap().auth_header.is_none());
        assert!(
            router.resolve("unmapped").is_none(),
            "with explicit backends, unmapped tools fall back to tool_upstream_url outside the router"
        );
    }

    #[test]
    fn static_credentials_are_sensitive_and_trimmed() {
        std::env::set_var("AV_TEST_BACKEND_TRIM_KEY", "  padded-secret \n");
        let router = BackendRouter::new(
            &[static_env_backend("trim", "AV_TEST_BACKEND_TRIM_KEY")],
            None,
            None,
        )
        .unwrap();
        std::env::remove_var("AV_TEST_BACKEND_TRIM_KEY");
        let (_, value) = router.resolve("trim_tool").unwrap().auth_header.clone().unwrap();
        assert_eq!(value.to_str().unwrap(), "Bearer padded-secret");
        assert!(
            value.is_sensitive(),
            "credential headers must be excluded from logs and HPACK indexing"
        );
    }

    #[test]
    fn empty_or_missing_static_secrets_refuse_to_boot() {
        std::env::set_var("AV_TEST_BACKEND_EMPTY_KEY", "   ");
        let empty = BackendRouter::new(
            &[static_env_backend("empty", "AV_TEST_BACKEND_EMPTY_KEY")],
            None,
            None,
        );
        std::env::remove_var("AV_TEST_BACKEND_EMPTY_KEY");
        let error = empty.err().expect("whitespace-only secret must be refused");
        assert!(error.contains("empty"), "got: {error}");

        let missing = BackendRouter::new(
            &[static_env_backend("missing", "AV_TEST_BACKEND_NEVER_SET_KEY")],
            None,
            None,
        );
        let error = missing.err().expect("unset env var must be refused");
        assert!(error.contains("AV_TEST_BACKEND_NEVER_SET_KEY"), "got: {error}");
    }

    #[cfg(unix)]
    #[test]
    fn static_file_secret_is_trimmed_and_must_be_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("backend.token");
        std::fs::write(&path, "file-secret\n").unwrap();
        let config = |p: &std::path::Path| BackendConfig {
            name: "filed".into(),
            url: "http://filed:8080".into(),
            auth: BackendAuth::StaticFile(p.to_string_lossy().into_owned()),
            tools: vec!["filed_tool".into()],
        };

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            BackendRouter::new(&[config(&path)], None, None).is_err(),
            "a world-readable secret file must be refused"
        );

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let router = BackendRouter::new(&[config(&path)], None, None).unwrap();
        let (_, value) = router.resolve("filed_tool").unwrap().auth_header.clone().unwrap();
        assert_eq!(value.to_str().unwrap(), "Bearer file-secret");
    }
}
