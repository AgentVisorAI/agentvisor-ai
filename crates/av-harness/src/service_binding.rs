//! Cloud-platform service binding discovery.
//!
//! Discovers AgentVisor connection parameters from Cloud Foundry
//! [`VCAP_SERVICES`](https://docs.cloudfoundry.org/devguide/deploy-apps/environment-variable.html#VCAP-SERVICES)
//! or from Kubernetes-style
//! [service binding files](https://servicebinding.io/spec/core/1.0.0/).
//!
//! Activated by the `service-binding` cargo feature. Not compiled into
//! production artifacts by default. This is client discovery metadata; the
//! gateway does not use a binding to configure its own identity validator.

use std::path::Path;

/// Credentials extracted from a platform service binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceBinding {
    /// The AgentVisor gateway URL that the application should proxy
    /// requests through.
    pub gateway_url: String,
    /// The OAuth audience the gateway expects on tokens.
    pub audience: String,
    /// An optional JWKS URL for identity verification.
    pub identity_jwks_url: Option<String>,
}

/// Errors that can occur while reading a service binding.
#[derive(Debug, thiserror::Error)]
pub enum ServiceBindingError {
    /// The `VCAP_SERVICES` value is not valid JSON.
    #[error("VCAP_SERVICES is not valid JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),

    /// JSON has an invalid platform binding structure.
    #[error("invalid VCAP_SERVICES structure: {0}")]
    InvalidStructure(&'static str),

    /// A credential has an invalid type or contains an ASCII control character.
    #[error("invalid binding field: {field}")]
    InvalidField {
        /// The name of the invalid field.
        field: &'static str,
    },

    /// More than one matching service entry was found, creating
    /// ambiguity about which binding to use.
    #[error("ambiguous binding: found {count} matching agentvisor entries")]
    Ambiguous {
        /// How many matching entries were found.
        count: usize,
    },

    /// A matched binding is missing a required credential field.
    #[error("binding is missing required field: {field}")]
    MissingField {
        /// The name of the missing field.
        field: &'static str,
    },

    /// A required credential field is present but empty after trimming.
    #[error("binding field is empty: {field}")]
    EmptyField {
        /// The name of the empty field.
        field: &'static str,
    },

    /// An I/O error occurred while reading binding files.
    #[error("failed to read binding file: {0}")]
    Io(#[from] std::io::Error),
}

/// The default directory where Kubernetes-style service bindings are
/// mounted (Cloud Native Buildpacks convention).
const DEFAULT_BINDING_ROOT: &str = "/platform/bindings";

/// Tries to discover an AgentVisor service binding from the
/// environment.
///
/// The function checks `VCAP_SERVICES` first. If that variable is not
/// set, it falls back to file-based bindings under the directory named
/// by `SERVICE_BINDING_ROOT` (defaulting to `/platform/bindings`).
///
/// Returns `Ok(None)` when no binding is found. Returns an error when
/// a binding is present but malformed (missing or empty required
/// fields, ambiguous matches, invalid JSON).
pub fn try_from_env() -> Result<Option<ServiceBinding>, ServiceBindingError> {
    try_from_env_with(|key| std::env::var(key))
}

/// Inner implementation that accepts a lookup closure so tests can
/// supply synthetic environment variables without mutating global
/// process state.
fn try_from_env_with<F>(lookup: F) -> Result<Option<ServiceBinding>, ServiceBindingError>
where
    F: Fn(&str) -> Result<String, std::env::VarError>,
{
    // VCAP_SERVICES takes precedence. If a match is found (or an error
    // occurs), return immediately. If no match is found (`Ok(None)`),
    // fall through to file-based bindings. On CF, VCAP_SERVICES is
    // always set (often to `{}`), so returning on every non-empty value
    // would prevent file-based bindings from ever being discovered.
    if let Ok(vcap) = lookup("VCAP_SERVICES") {
        if !vcap.trim().is_empty() {
            if let Some(binding) = from_vcap_services(&vcap)? {
                return Ok(Some(binding));
            }
            // No match in VCAP — fall through to file-based bindings.
        }
    }

    // Fall back to file-based bindings.
    let root = lookup("SERVICE_BINDING_ROOT")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_BINDING_ROOT.to_string());

    from_binding_root(Path::new(&root))
}

/// Parses `VCAP_SERVICES` JSON and extracts an AgentVisor binding.
///
/// A service entry matches if any of the following are true:
/// - The top-level key equals `"agentvisor"` (managed service).
/// - The entry's `"label"` equals `"agentvisor"`.
/// - The entry's `"tags"` array contains `"agentvisor"`.
/// - The entry's `"name"` equals `"agentvisor"`.
///
/// User-provided services (created with `cf cups`) appear under the
/// `"user-provided"` top-level key, so matching by label, tag, or name
/// is needed to find them.
pub fn from_vcap_services(json: &str) -> Result<Option<ServiceBinding>, ServiceBindingError> {
    let root: serde_json::Value = serde_json::from_str(json)?;
    let obj = match root.as_object() {
        Some(o) => o,
        None => return Err(ServiceBindingError::InvalidStructure("root must be an object")),
    };

    let mut matches = Vec::new();

    for (key, entries) in obj {
        let arr = match entries.as_array() {
            Some(a) => a,
            None => {
                return Err(ServiceBindingError::InvalidStructure(
                    "service values must be arrays",
                ));
            }
        };
        let key_match = key == "agentvisor";

        for entry in arr {
            if !entry.is_object() {
                return Err(ServiceBindingError::InvalidStructure(
                    "service entries must be objects",
                ));
            }
            if key_match || entry_matches(entry) {
                matches.push(entry.clone());
            }
        }
    }

    match matches.len() {
        0 => Ok(None),
        1 => {
            let entry = matches
                .first()
                .and_then(|e| e.get("credentials"))
                .and_then(|c| c.as_object());
            let creds = match entry {
                Some(c) => c,
                None => {
                    // The entry matched but has no credentials object.
                    return Err(ServiceBindingError::MissingField { field: "credentials" });
                }
            };
            binding_from_creds(creds)
        }
        n => Err(ServiceBindingError::Ambiguous { count: n }),
    }
}

/// Checks whether a single VCAP service entry matches by label, tag,
/// or name.
fn entry_matches(entry: &serde_json::Value) -> bool {
    if entry
        .get("label")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|l| l == "agentvisor")
    {
        return true;
    }
    if entry
        .get("name")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|n| n == "agentvisor")
    {
        return true;
    }
    if let Some(tags) = entry.get("tags").and_then(serde_json::Value::as_array) {
        if tags.iter().any(|t| t.as_str().is_some_and(|s| s == "agentvisor")) {
            return true;
        }
    }
    false
}

/// Extracts binding fields from a credentials object.
fn binding_from_creds(
    creds: &serde_json::Map<String, serde_json::Value>,
) -> Result<Option<ServiceBinding>, ServiceBindingError> {
    let gateway_url = required_string(creds, "gateway_url")?;
    let audience = required_string(creds, "audience")?;
    let identity_jwks_url = optional_string(creds, "identity_jwks_url")?;

    Ok(Some(ServiceBinding {
        gateway_url,
        audience,
        identity_jwks_url,
    }))
}

/// Reads a required string field, returning an error if it is missing
/// or empty after trimming.
fn required_string(
    creds: &serde_json::Map<String, serde_json::Value>,
    field: &'static str,
) -> Result<String, ServiceBindingError> {
    let val = creds
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or(ServiceBindingError::MissingField { field })?;

    let trimmed = val.trim();
    if trimmed.is_empty() {
        return Err(ServiceBindingError::EmptyField { field });
    }
    validate_value(trimmed, field)?;
    Ok(trimmed.to_string())
}

/// Reads an optional string field, returning `None` if it is absent or
/// empty after trimming.
fn optional_string(
    creds: &serde_json::Map<String, serde_json::Value>,
    field: &'static str,
) -> Result<Option<String>, ServiceBindingError> {
    match creds.get(field) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(value)) => {
            let value = value.trim();
            validate_value(value, field)?;
            Ok((!value.is_empty()).then(|| value.to_string()))
        }
        Some(_) => Err(ServiceBindingError::InvalidField { field }),
    }
}

fn validate_value(value: &str, field: &'static str) -> Result<(), ServiceBindingError> {
    if value.chars().any(|c| c.is_ascii_control()) {
        return Err(ServiceBindingError::InvalidField { field });
    }
    Ok(())
}

/// Scans the binding root directory for a subdirectory whose `type`
/// file contains `agentvisor`.
///
/// Binding directories that start with `.` are skipped. The root
/// directory itself may be absent, which returns `Ok(None)`.
pub fn from_binding_root(root: &Path) -> Result<Option<ServiceBinding>, ServiceBindingError> {
    let entries = match std::fs::read_dir(root) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };

    let mut matching_dirs: Vec<std::path::PathBuf> = Vec::new();

    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // Skip hidden entries.
        if name_str.starts_with('.') {
            continue;
        }

        let binding_dir = entry.path();

        // Follow symlinks: use `fs::metadata` instead of
        // `entry.file_type()`, because Kubernetes projects bindings
        // through symlinks.
        let meta = match std::fs::metadata(&binding_dir) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if !meta.is_dir() {
            continue;
        }

        let type_path = binding_dir.join("type");
        let type_val = match std::fs::read_to_string(&type_path) {
            Ok(v) => v,
            Err(_) => continue,
        };

        if type_val.trim() == "agentvisor" {
            matching_dirs.push(binding_dir);
        }
    }

    match matching_dirs.len() {
        0 => Ok(None),
        1 => {
            // Safe: length was just checked.
            let dir = matching_dirs
                .first()
                .ok_or(ServiceBindingError::MissingField { field: "type" })?;
            binding_from_files(dir)
        }
        n => Err(ServiceBindingError::Ambiguous { count: n }),
    }
}

/// Reads credential fields from individual files in a binding
/// directory.
fn binding_from_files(dir: &Path) -> Result<Option<ServiceBinding>, ServiceBindingError> {
    let gateway_url = required_file(dir, "gateway_url")?;
    let audience = required_file(dir, "audience")?;
    let identity_jwks_url = optional_file(dir, "identity_jwks_url")?;

    Ok(Some(ServiceBinding {
        gateway_url,
        audience,
        identity_jwks_url,
    }))
}

/// Reads a required credential from a file, returning an error if the
/// file is missing or its trimmed content is empty.
fn required_file(dir: &Path, field: &'static str) -> Result<String, ServiceBindingError> {
    let path = dir.join(field);
    let content = std::fs::read_to_string(&path).map_err(|_| ServiceBindingError::MissingField { field })?;
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Err(ServiceBindingError::EmptyField { field });
    }
    validate_value(trimmed, field)?;
    Ok(trimmed.to_string())
}

/// Reads an optional credential from a file. Returns `None` if the
/// file is absent or its trimmed content is empty.
fn optional_file(dir: &Path, field: &'static str) -> Result<Option<String>, ServiceBindingError> {
    let path = dir.join(field);
    match std::fs::read_to_string(&path) {
        Ok(content) => {
            let trimmed = content.trim();
            validate_value(trimmed, field)?;
            if trimmed.is_empty() {
                Ok(None)
            } else {
                Ok(Some(trimmed.to_string()))
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use std::collections::HashMap;

    /// Helper: build a lookup closure from a map.
    fn lookup_from(
        map: HashMap<&'static str, String>,
    ) -> impl Fn(&str) -> Result<String, std::env::VarError> {
        move |key: &str| map.get(key).cloned().ok_or(std::env::VarError::NotPresent)
    }

    // ---- VCAP_SERVICES tests ----

    #[test]
    fn vcap_managed_service_by_key() {
        let vcap = r#"{
            "agentvisor": [{
                "credentials": {
                    "gateway_url": "https://gw.example.com",
                    "audience": "my-app",
                    "identity_jwks_url": "https://auth.example.com/.well-known/jwks.json"
                },
                "label": "agentvisor",
                "name": "my-agentvisor"
            }]
        }"#;

        let result = from_vcap_services(vcap).unwrap().unwrap();
        assert_eq!(result.gateway_url, "https://gw.example.com");
        assert_eq!(result.audience, "my-app");
        assert_eq!(
            result.identity_jwks_url.as_deref(),
            Some("https://auth.example.com/.well-known/jwks.json")
        );
    }

    #[test]
    fn vcap_user_provided_matched_by_tag() {
        let vcap = r#"{
            "user-provided": [{
                "credentials": {
                    "gateway_url": "https://gw.example.com",
                    "audience": "tagged-app"
                },
                "label": "user-provided",
                "name": "my-custom-svc",
                "tags": ["agentvisor", "ai"]
            }]
        }"#;

        let result = from_vcap_services(vcap).unwrap().unwrap();
        assert_eq!(result.audience, "tagged-app");
        assert!(result.identity_jwks_url.is_none());
    }

    #[test]
    fn vcap_user_provided_matched_by_name() {
        let vcap = r#"{
            "user-provided": [{
                "credentials": {
                    "gateway_url": "https://gw.example.com",
                    "audience": "named-app"
                },
                "label": "user-provided",
                "name": "agentvisor"
            }]
        }"#;

        let result = from_vcap_services(vcap).unwrap().unwrap();
        assert_eq!(result.audience, "named-app");
    }

    #[test]
    fn vcap_user_provided_matched_by_label() {
        let vcap = r#"{
            "user-provided": [{
                "credentials": {
                    "gateway_url": "https://gw.example.com",
                    "audience": "labeled-app"
                },
                "label": "agentvisor",
                "name": "something-else"
            }]
        }"#;

        let result = from_vcap_services(vcap).unwrap().unwrap();
        assert_eq!(result.audience, "labeled-app");
    }

    #[test]
    fn vcap_no_match_returns_none() {
        let vcap = r#"{
            "postgres": [{
                "credentials": { "uri": "postgres://..." },
                "label": "postgres"
            }]
        }"#;

        assert!(from_vcap_services(vcap).unwrap().is_none());
    }

    #[test]
    fn vcap_invalid_json_is_error() {
        let result = from_vcap_services("{not valid json}");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ServiceBindingError::InvalidJson(_)));
    }

    #[test]
    fn vcap_ambiguous_entries_is_error() {
        let vcap = r#"{
            "agentvisor": [
                {
                    "credentials": { "gateway_url": "https://a.example.com", "audience": "a" },
                    "name": "first"
                },
                {
                    "credentials": { "gateway_url": "https://b.example.com", "audience": "b" },
                    "name": "second"
                }
            ]
        }"#;

        let result = from_vcap_services(vcap);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ServiceBindingError::Ambiguous { count: 2 }));
    }

    #[test]
    fn vcap_missing_required_field_is_error() {
        let vcap = r#"{
            "agentvisor": [{
                "credentials": {
                    "gateway_url": "https://gw.example.com"
                },
                "name": "incomplete"
            }]
        }"#;

        let result = from_vcap_services(vcap);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(
            err,
            ServiceBindingError::MissingField { field: "audience" }
        ));
    }

    #[test]
    fn vcap_empty_required_field_is_error() {
        let vcap = r#"{
            "agentvisor": [{
                "credentials": {
                    "gateway_url": "   ",
                    "audience": "my-app"
                },
                "name": "empty-gw"
            }]
        }"#;

        let result = from_vcap_services(vcap);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(
            err,
            ServiceBindingError::EmptyField { field: "gateway_url" }
        ));
    }

    #[test]
    fn vcap_missing_credentials_is_error() {
        let vcap = r#"{
            "agentvisor": [{ "name": "no-creds" }]
        }"#;

        let result = from_vcap_services(vcap);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(
            err,
            ServiceBindingError::MissingField { field: "credentials" }
        ));
    }

    #[test]
    fn vcap_optional_jwks_absent_is_none() {
        let vcap = r#"{
            "agentvisor": [{
                "credentials": {
                    "gateway_url": "https://gw.example.com",
                    "audience": "my-app"
                },
                "name": "no-jwks"
            }]
        }"#;

        let result = from_vcap_services(vcap).unwrap().unwrap();
        assert!(result.identity_jwks_url.is_none());
    }

    // ---- File-based binding tests ----

    #[test]
    fn binding_files_full() {
        let tmp = tempfile::tempdir().unwrap();
        let binding = tmp.path().join("agentvisor");
        std::fs::create_dir_all(&binding).unwrap();
        std::fs::write(binding.join("type"), "agentvisor\n").unwrap();
        std::fs::write(binding.join("gateway_url"), "https://gw.example.com\n").unwrap();
        std::fs::write(binding.join("audience"), "file-app\n").unwrap();
        std::fs::write(
            binding.join("identity_jwks_url"),
            "https://auth.example.com/jwks\n",
        )
        .unwrap();

        let result = from_binding_root(tmp.path()).unwrap().unwrap();
        assert_eq!(result.gateway_url, "https://gw.example.com");
        assert_eq!(result.audience, "file-app");
        assert_eq!(
            result.identity_jwks_url.as_deref(),
            Some("https://auth.example.com/jwks")
        );
    }

    #[test]
    fn binding_files_trailing_newline_trimmed() {
        let tmp = tempfile::tempdir().unwrap();
        let binding = tmp.path().join("my-binding");
        std::fs::create_dir_all(&binding).unwrap();
        std::fs::write(binding.join("type"), "agentvisor\n").unwrap();
        std::fs::write(binding.join("gateway_url"), "  https://gw.example.com  \n").unwrap();
        std::fs::write(binding.join("audience"), "trimmed\n").unwrap();

        let result = from_binding_root(tmp.path()).unwrap().unwrap();
        assert_eq!(result.gateway_url, "https://gw.example.com");
        assert_eq!(result.audience, "trimmed");
    }

    #[test]
    fn binding_files_wrong_type_skipped() {
        let tmp = tempfile::tempdir().unwrap();
        let binding = tmp.path().join("postgres");
        std::fs::create_dir_all(&binding).unwrap();
        std::fs::write(binding.join("type"), "postgres\n").unwrap();
        std::fs::write(binding.join("host"), "localhost").unwrap();

        assert!(from_binding_root(tmp.path()).unwrap().is_none());
    }

    #[test]
    fn binding_files_missing_root_returns_none() {
        let result = from_binding_root(Path::new("/nonexistent/path/that/does/not/exist"));
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn binding_files_missing_required_field_is_error() {
        let tmp = tempfile::tempdir().unwrap();
        let binding = tmp.path().join("agentvisor");
        std::fs::create_dir_all(&binding).unwrap();
        std::fs::write(binding.join("type"), "agentvisor").unwrap();
        std::fs::write(binding.join("gateway_url"), "https://gw.example.com").unwrap();
        // audience is missing

        let result = from_binding_root(tmp.path());
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ServiceBindingError::MissingField { field: "audience" }
        ));
    }

    #[test]
    fn binding_files_hidden_dir_skipped() {
        let tmp = tempfile::tempdir().unwrap();
        let hidden = tmp.path().join(".hidden");
        std::fs::create_dir_all(&hidden).unwrap();
        std::fs::write(hidden.join("type"), "agentvisor").unwrap();
        std::fs::write(hidden.join("gateway_url"), "https://gw.example.com").unwrap();
        std::fs::write(hidden.join("audience"), "hidden").unwrap();

        assert!(from_binding_root(tmp.path()).unwrap().is_none());
    }

    // ---- try_from_env_with precedence test ----

    #[test]
    fn vcap_takes_precedence_over_files() {
        let tmp = tempfile::tempdir().unwrap();
        let binding = tmp.path().join("agentvisor");
        std::fs::create_dir_all(&binding).unwrap();
        std::fs::write(binding.join("type"), "agentvisor").unwrap();
        std::fs::write(binding.join("gateway_url"), "https://file-gw.example.com").unwrap();
        std::fs::write(binding.join("audience"), "file-app").unwrap();

        let mut env = HashMap::new();
        env.insert(
            "VCAP_SERVICES",
            r#"{"agentvisor": [{"credentials": {"gateway_url": "https://vcap-gw.example.com", "audience": "vcap-app"}, "name": "test"}]}"#.to_string(),
        );
        env.insert("SERVICE_BINDING_ROOT", tmp.path().to_string_lossy().to_string());

        let result = try_from_env_with(lookup_from(env)).unwrap().unwrap();
        assert_eq!(result.gateway_url, "https://vcap-gw.example.com");
        assert_eq!(result.audience, "vcap-app");
    }

    #[test]
    fn falls_back_to_files_when_vcap_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let binding = tmp.path().join("agentvisor");
        std::fs::create_dir_all(&binding).unwrap();
        std::fs::write(binding.join("type"), "agentvisor").unwrap();
        std::fs::write(binding.join("gateway_url"), "https://file-gw.example.com").unwrap();
        std::fs::write(binding.join("audience"), "file-app").unwrap();

        let mut env = HashMap::new();
        env.insert("SERVICE_BINDING_ROOT", tmp.path().to_string_lossy().to_string());

        let result = try_from_env_with(lookup_from(env)).unwrap().unwrap();
        assert_eq!(result.gateway_url, "https://file-gw.example.com");
    }

    #[test]
    fn no_binding_anywhere_returns_none() {
        let tmp = tempfile::tempdir().unwrap();
        let env = HashMap::from([("SERVICE_BINDING_ROOT", tmp.path().to_string_lossy().to_string())]);

        assert!(try_from_env_with(lookup_from(env)).unwrap().is_none());
    }

    #[test]
    fn vcap_no_match_falls_through_to_files() {
        let tmp = tempfile::tempdir().unwrap();
        let binding = tmp.path().join("agentvisor");
        std::fs::create_dir_all(&binding).unwrap();
        std::fs::write(binding.join("type"), "agentvisor").unwrap();
        std::fs::write(binding.join("gateway_url"), "https://file-gw.example.com").unwrap();
        std::fs::write(binding.join("audience"), "file-app").unwrap();

        let env = HashMap::from([
            (
                "VCAP_SERVICES",
                r#"{"postgres": [{"credentials": {"uri": "postgres://..."}, "label": "postgres"}]}"#
                    .to_string(),
            ),
            ("SERVICE_BINDING_ROOT", tmp.path().to_string_lossy().to_string()),
        ]);

        let result = try_from_env_with(lookup_from(env)).unwrap().unwrap();
        assert_eq!(result.gateway_url, "https://file-gw.example.com");
        assert_eq!(result.audience, "file-app");
    }

    #[test]
    fn empty_vcap_falls_through_to_files() {
        let tmp = tempfile::tempdir().unwrap();
        let binding = tmp.path().join("agentvisor");
        std::fs::create_dir_all(&binding).unwrap();
        std::fs::write(binding.join("type"), "agentvisor").unwrap();
        std::fs::write(binding.join("gateway_url"), "https://file-gw.example.com").unwrap();
        std::fs::write(binding.join("audience"), "file-app").unwrap();

        let env = HashMap::from([
            ("VCAP_SERVICES", "{}".to_string()),
            ("SERVICE_BINDING_ROOT", tmp.path().to_string_lossy().to_string()),
        ]);

        let result = try_from_env_with(lookup_from(env)).unwrap().unwrap();
        assert_eq!(result.gateway_url, "https://file-gw.example.com");
    }

    #[test]
    fn binding_files_ambiguous_is_error() {
        let tmp = tempfile::tempdir().unwrap();

        let binding_a = tmp.path().join("agentvisor-a");
        std::fs::create_dir_all(&binding_a).unwrap();
        std::fs::write(binding_a.join("type"), "agentvisor").unwrap();
        std::fs::write(binding_a.join("gateway_url"), "https://a.example.com").unwrap();
        std::fs::write(binding_a.join("audience"), "app-a").unwrap();

        let binding_b = tmp.path().join("agentvisor-b");
        std::fs::create_dir_all(&binding_b).unwrap();
        std::fs::write(binding_b.join("type"), "agentvisor").unwrap();
        std::fs::write(binding_b.join("gateway_url"), "https://b.example.com").unwrap();
        std::fs::write(binding_b.join("audience"), "app-b").unwrap();

        let result = from_binding_root(tmp.path());
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ServiceBindingError::Ambiguous { count: 2 }
        ));
    }
    #[test]
    fn vcap_rejects_invalid_structure_and_optional_types() {
        for invalid in ["null", "[]", r#"{"agentvisor":{}}"#, r#"{"agentvisor":[null]}"#] {
            assert!(from_vcap_services(invalid).is_err(), "{invalid}");
        }
        for optional in ["123", "true", "{}", "[]"] {
            let invalid = format!(
                r#"{{"agentvisor":[{{"credentials":{{"gateway_url":"https://gw.example","audience":"app","identity_jwks_url":{optional}}}}}]}}"#
            );
            assert!(from_vcap_services(&invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn bindings_reject_embedded_control_characters() {
        let invalid = r#"{"agentvisor":[{"credentials":{"gateway_url":"https://gw.example","audience":"app\u0000injected"}}]}"#;
        assert!(matches!(
            from_vcap_services(invalid),
            Err(ServiceBindingError::InvalidField { field: "audience" })
        ));
        let tmp = tempfile::tempdir().unwrap();
        let binding = tmp.path().join("agentvisor");
        std::fs::create_dir(&binding).unwrap();
        std::fs::write(binding.join("type"), "agentvisor").unwrap();
        std::fs::write(binding.join("gateway_url"), "https://gw.example").unwrap();
        std::fs::write(binding.join("audience"), "app\ninjected").unwrap();
        assert!(matches!(
            from_binding_root(tmp.path()),
            Err(ServiceBindingError::InvalidField { field: "audience" })
        ));
    }
}
