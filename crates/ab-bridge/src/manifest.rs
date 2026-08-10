//! Declarative topic-schema manifest + provisioning (the Module F
//! portability contract: "a customer stands up an identical bridge in a new
//! region or air-gapped enclave from that manifest alone").

use serde::{Deserialize, Serialize};

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
        Self { hot_hours: 720, cold_uri: None }
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
    /// Topic declarations.
    pub topics: Vec<TopicSpec>,
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
    pub fn from_yaml(yaml: &str) -> Result<Self, ManifestError> {
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
        let mut names: Vec<&str> = self.topics.iter().map(|t| t.name.as_str()).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        if names.len() != before {
            return Err(ManifestError::Invalid("duplicate topic names".into()));
        }
        for t in &self.topics {
            if t.name.is_empty() {
                return Err(ManifestError::Invalid("empty topic name".into()));
            }
            if t.partitions == 0 {
                return Err(ManifestError::Invalid(format!("topic {:?} has 0 partitions", t.name)));
            }
            if t.retention.hot_hours == 0 {
                return Err(ManifestError::Invalid(format!("topic {:?} has 0h retention", t.name)));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

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
        let dup = m.topics[0].clone();
        m.topics.push(dup);
        assert!(matches!(m.validate(), Err(ManifestError::Invalid(_))));

        let m = BridgeManifest { manifest_version: MANIFEST_VERSION, name: String::new(), topics: vec![] };
        assert!(m.validate().is_err());
    }

    #[test]
    fn malformed_yaml_is_a_parse_error() {
        assert!(matches!(
            BridgeManifest::from_yaml(":\n  - not: [valid"),
            Err(ManifestError::Parse(_))
        ));
    }
}
