//! Declarative topic-schema manifest + provisioning (the Module F
//! portability contract: "a customer stands up an identical bridge in a new
//! region or air-gapped enclave from that manifest alone").

use serde::{Deserialize, Serialize};
#[cfg(any(feature = "nats", feature = "kafka"))]
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Manifest format version (evolution surface).
pub const MANIFEST_VERSION: u32 = 1;

/// Retention policy for one topic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionSpec {
    /// Hot retention window in hours (default 720 = 30 days, per the brief).
    pub hot_hours: u32,
    /// Optional cold-tier export directory/bucket URI (customer-owned storage).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cold_uri: Option<String>,
}

impl Default for RetentionSpec {
    fn default() -> Self {
        Self {
            hot_hours: 720,
            cold_uri: None,
        }
    }
}

/// One topic declaration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopicSpec {
    /// Topic name (`agent.tool_call`, …).
    pub name: String,
    /// Partition count (partitioned by `ai_agent.instance_uid`).
    pub partitions: u32,
    /// Retention policy.
    #[serde(default)]
    pub retention: RetentionSpec,
    /// JSON Schema reference events on this topic must satisfy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_ref: Option<String>,
}

/// The Bridge manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeManifest {
    /// Manifest format version.
    pub manifest_version: u32,
    /// Deployment name (region/enclave label).
    pub name: String,
    /// Broker replication factor for managed Kafka/NATS deployments.
    #[serde(default = "default_replication_factor")]
    pub replication_factor: u32,
    /// Topic declarations.
    pub topics: Vec<TopicSpec>,
}

fn default_replication_factor() -> u32 {
    1
}

/// Manifest validation errors.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ManifestError {
    /// Unsupported version.
    #[error("unsupported manifest_version {0} (this build supports {MANIFEST_VERSION})")]
    Version(u32),
    /// YAML/JSON parse failure.
    #[error("manifest parse: {0}")]
    Parse(String),
    /// Structural problem.
    #[error("manifest invalid: {0}")]
    Invalid(String),
}

impl BridgeManifest {
    /// The default manifest covering every OCSF event class topic.
    pub fn default_for(name: &str) -> Self {
        Self {
            manifest_version: MANIFEST_VERSION,
            name: name.to_owned(),
            replication_factor: default_replication_factor(),
            topics: ab_events::EventClass::all()
                .iter()
                .map(|c| TopicSpec {
                    name: c.topic().to_owned(),
                    partitions: 8,
                    retention: RetentionSpec::default(),
                    schema_ref: Some("schemas/ocsf-agent-event.schema.json".to_owned()),
                })
                .collect(),
        }
    }

    /// Parse from YAML.
    ///
    /// Enforces a 256 KiB input cap and rejects any document containing
    /// YAML anchors (`&`) or aliases (`*`). Together these close the
    /// billion-laughs attack surface: `serde_yaml` 0.9 expands aliases
    /// eagerly with no depth or expansion cap, so a maliciously crafted
    /// manifest of a few KiB would OOM the process at parse time.
    /// Legitimate bridge manifests never need aliases — reject rather
    /// than trying to bound expansion, which would require a fork.
    pub fn from_yaml(yaml: &str) -> Result<Self, ManifestError> {
        const MAX_YAML_BYTES: usize = 256 * 1024;
        if yaml.len() > MAX_YAML_BYTES {
            return Err(ManifestError::Parse(format!(
                "manifest is {} bytes, exceeds cap of {MAX_YAML_BYTES}",
                yaml.len()
            )));
        }
        // Cheap syntactic scan for YAML aliases. Legitimate anchors/
        // aliases would need explicit `&name`/`*name` syntax; a naive
        // string search catches every case that serde_yaml would
        // actually expand. False positives on strings that happen to
        // contain `&` or `*` are avoided by checking that the char
        // precedes a valid anchor name character (alphanumeric or `_`).
        for (marker, kind) in [('&', "anchor"), ('*', "alias")] {
            let mut chars = yaml.char_indices().peekable();
            while let Some((_, ch)) = chars.next() {
                if ch != marker {
                    continue;
                }
                if let Some(&(_, next)) = chars.peek() {
                    if next.is_ascii_alphanumeric() || next == '_' {
                        return Err(ManifestError::Parse(format!(
                            "manifest contains a YAML {kind} ('{marker}<name>'); \
                             AgentBridge refuses anchor/alias syntax to close the \
                             billion-laughs attack surface (serde_yaml expands aliases \
                             with no cap). Rewrite the document without &/* references."
                        )));
                    }
                }
            }
        }
        let m: Self = serde_yaml::from_str(yaml).map_err(|e| ManifestError::Parse(e.to_string()))?;
        m.validate()?;
        Ok(m)
    }

    /// Serialize to YAML.
    pub fn to_yaml(&self) -> Result<String, ManifestError> {
        serde_yaml::to_string(self).map_err(|e| ManifestError::Parse(e.to_string()))
    }

    /// Validate structural invariants.
    pub fn validate(&self) -> Result<(), ManifestError> {
        if self.manifest_version != MANIFEST_VERSION {
            return Err(ManifestError::Version(self.manifest_version));
        }
        if self.name.is_empty() {
            return Err(ManifestError::Invalid("name is empty".into()));
        }
        if self.topics.is_empty() {
            return Err(ManifestError::Invalid("no topics declared".into()));
        }
        if !(1..=5).contains(&self.replication_factor) {
            return Err(ManifestError::Invalid(
                "replication_factor must be between 1 and 5".to_owned(),
            ));
        }
        let mut names: Vec<&str> = self.topics.iter().map(|t| t.name.as_str()).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        if names.len() != before {
            return Err(ManifestError::Invalid("duplicate topic names".into()));
        }
        for t in &self.topics {
            if t.name.is_empty()
                || !t
                    .name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
                || t.name == "."
                || t.name == ".."
            {
                return Err(ManifestError::Invalid(format!("unsafe topic name {:?}", t.name)));
            }
            if t.partitions == 0 {
                return Err(ManifestError::Invalid(format!(
                    "topic {:?} has 0 partitions",
                    t.name
                )));
            }
            if t.retention.hot_hours == 0 {
                return Err(ManifestError::Invalid(format!(
                    "topic {:?} has 0h retention",
                    t.name
                )));
            }
            if let Some(reference) = &t.schema_ref {
                let path = Path::new(reference);
                if path.is_absolute()
                    || path
                        .components()
                        .any(|component| !matches!(component, std::path::Component::Normal(_)))
                {
                    return Err(ManifestError::Invalid(format!("unsafe schema_ref {reference:?}")));
                }
            }
        }
        Ok(())
    }
}

#[cfg(any(feature = "nats", feature = "kafka"))]
pub(crate) fn compile_topic_validators(
    manifest: &BridgeManifest,
) -> Result<HashMap<String, jsonschema::Validator>, crate::BusError> {
    let mut validators = HashMap::new();
    for topic in &manifest.topics {
        let Some(reference) = &topic.schema_ref else {
            continue;
        };
        let schema = schema_document(reference)?;
        let validator = jsonschema::validator_for(&schema)
            .map_err(|error| crate::BusError::Backend(format!("invalid schema {reference:?}: {error}")))?;
        validators.insert(topic.name.clone(), validator);
    }
    Ok(validators)
}

#[cfg(any(feature = "nats", feature = "kafka"))]
pub(crate) fn validate_topic_event(
    validators: &HashMap<String, jsonschema::Validator>,
    topic: &str,
    value: &serde_json::Value,
) -> Result<(), crate::BusError> {
    let Some(validator) = validators.get(topic) else {
        return Ok(());
    };
    let errors: Vec<String> = validator
        .iter_errors(value)
        .take(3)
        .map(|error| error.to_string())
        .collect();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(crate::BusError::Backend(format!(
            "event rejected by schema for topic {topic:?}: {}",
            errors.join("; ")
        )))
    }
}

pub(crate) fn schema_document(reference: &str) -> Result<serde_json::Value, crate::BusError> {
    if reference == "schemas/ocsf-agent-event.schema.json" {
        return serde_json::from_str(include_str!("../../../schemas/ocsf-agent-event.schema.json"))
            .map_err(crate::BusError::from);
    }
    let direct = PathBuf::from(reference);
    if direct.exists() {
        return serde_json::from_slice(&std::fs::read(direct)?).map_err(crate::BusError::from);
    }
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(reference);
    if workspace.exists() {
        serde_json::from_slice(&std::fs::read(workspace)?).map_err(crate::BusError::from)
    } else {
        Err(crate::BusError::Backend(format!(
            "schema reference {reference:?} could not be resolved"
        )))
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]

    use super::*;

    #[test]
    fn default_manifest_covers_all_event_classes() {
        let m = BridgeManifest::default_for("us-east-lab");
        m.validate().unwrap();
        assert_eq!(m.topics.len(), ab_events::EventClass::all().len());
        assert!(m.topics.iter().any(|t| t.name == "agent.tool_call"));
        assert!(m.topics.iter().any(|t| t.name == "agent.receipt"));
        assert_eq!(m.topics[0].retention.hot_hours, 720, "default 30 days per brief");
    }

    #[test]
    fn yaml_roundtrip() {
        let m = BridgeManifest::default_for("enclave-1");
        let yaml = m.to_yaml().unwrap();
        let back = BridgeManifest::from_yaml(&yaml).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn rejects_bad_manifests() {
        let mut m = BridgeManifest::default_for("x");
        m.manifest_version = 99;
        assert_eq!(m.validate(), Err(ManifestError::Version(99)));

        let mut m = BridgeManifest::default_for("x");
        m.topics[0].partitions = 0;
        assert!(matches!(m.validate(), Err(ManifestError::Invalid(_))));

        let mut m = BridgeManifest::default_for("x");
        m.topics[0].name = "../escape".to_owned();
        assert!(matches!(m.validate(), Err(ManifestError::Invalid(_))));

        let mut m = BridgeManifest::default_for("x");
        m.topics[0].schema_ref = Some("../outside.json".to_owned());
        assert!(matches!(m.validate(), Err(ManifestError::Invalid(_))));

        let mut m = BridgeManifest::default_for("x");
        let dup = m.topics[0].clone();
        m.topics.push(dup);
        assert!(matches!(m.validate(), Err(ManifestError::Invalid(_))));

        let m = BridgeManifest {
            manifest_version: MANIFEST_VERSION,
            name: String::new(),
            replication_factor: 1,
            topics: vec![],
        };
        assert!(m.validate().is_err());
    }

    #[test]
    fn malformed_yaml_is_a_parse_error() {
        assert!(matches!(
            BridgeManifest::from_yaml(":\n  - not: [valid"),
            Err(ManifestError::Parse(_))
        ));
    }

    #[test]
    fn default_manifest_matches_shipped_json_schema() {
        let schema: serde_json::Value =
            serde_json::from_str(include_str!("../../../schemas/bridge-manifest.schema.json")).unwrap();
        let validator = jsonschema::validator_for(&schema).unwrap();
        let value = serde_json::to_value(BridgeManifest::default_for("schema-test")).unwrap();
        let errors: Vec<_> = validator.iter_errors(&value).collect();
        assert!(errors.is_empty(), "{errors:?}");
    }
}
