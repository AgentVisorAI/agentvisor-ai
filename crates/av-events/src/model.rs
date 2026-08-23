//! Event envelope, agent identity block, event classes, metrics, fingerprints.

use av_core::error::check_jcs_safe;
use serde::{Deserialize, Serialize};

/// OCSF schema version stamped in every event's metadata (upstream release the
/// authored profile targets, per the brief).
pub const OCSF_VERSION: &str = "1.10.0";

/// Product name stamped in metadata.
pub const PRODUCT_NAME: &str = "agentvisor-ai";

/// OCSF Application Activity category uid.
pub const CATEGORY_UID: u8 = 6;

/// Event classes. One Bridge topic exists per class (Module F topic layout).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum EventClass {
    /// MCP / REST tool-call verdicts (Module B).
    #[serde(rename = "agent.tool_call")]
    ToolCall,
    /// Stop-reason emissions incl. loop halts (Modules A/E).
    #[serde(rename = "agent.stop_reason")]
    StopReason,
    /// Receipt issuance notifications (Module G).
    #[serde(rename = "agent.receipt")]
    Receipt,
    /// Context-compression metrics (Module C).
    #[serde(rename = "agent.compression")]
    Compression,
    /// NHI identity validation verdicts (Module D).
    #[serde(rename = "agent.identity")]
    Identity,
    /// Session lifecycle (open/close/promote).
    #[serde(rename = "agent.session")]
    Session,
}

impl EventClass {
    /// Extension-range class uid (documented in schemas/ocsf-agent-event.schema.json).
    pub fn class_uid(self) -> u32 {
        match self {
            Self::ToolCall => 9901,
            Self::StopReason => 9902,
            Self::Receipt => 9903,
            Self::Compression => 9904,
            Self::Identity => 9905,
            Self::Session => 9906,
        }
    }

    /// Topic name for the Bridge (`agent.<class>`).
    pub fn topic(self) -> &'static str {
        match self {
            Self::ToolCall => "agent.tool_call",
            Self::StopReason => "agent.stop_reason",
            Self::Receipt => "agent.receipt",
            Self::Compression => "agent.compression",
            Self::Identity => "agent.identity",
            Self::Session => "agent.session",
        }
    }

    /// All classes (used by the manifest provisioner).
    pub fn all() -> &'static [EventClass] {
        &[
            Self::ToolCall,
            Self::StopReason,
            Self::Receipt,
            Self::Compression,
            Self::Identity,
            Self::Session,
        ]
    }
}

/// Outcome status (OCSF convention: 0 unknown, 1 success, 2 failure).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum StatusId {
    /// Not determined.
    Unknown,
    /// Action allowed / completed.
    Success,
    /// Action blocked / failed.
    Failure,
}

impl StatusId {
    /// Numeric wire value.
    pub fn id(self) -> u8 {
        match self {
            Self::Unknown => 0,
            Self::Success => 1,
            Self::Failure => 2,
        }
    }
}

/// The agent config-state identity block bound into every event (Module E,
/// PR #1 pattern: version + charter + instance_uid).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CharterFile {
    /// Charter document file name.
    pub name: String,
    /// OCSF File type id 1, Regular File.
    pub type_id: u8,
}

impl From<String> for CharterFile {
    fn from(name: String) -> Self {
        Self { name, type_id: 1 }
    }
}

impl From<&str> for CharterFile {
    fn from(name: &str) -> Self {
        Self::from(name.to_owned())
    }
}

/// OCSF Product object embedded in event metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Product {
    /// Product name.
    pub name: String,
    /// Product vendor.
    pub vendor_name: String,
    /// Product version.
    pub version: String,
}

/// Agent configuration state bound into every emitted event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentIdentity {
    /// Deployed agent version (changes on deploy).
    pub version: String,
    /// Agent charter — the operating mandate/config name (changes on deploy).
    pub charter: CharterFile,
    /// Unique id of this running instance.
    pub instance_uid: String,
    /// Remaining identity-token TTL at emission time, seconds (Module D binds
    /// TTL scope into the identity block).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_remaining_s: Option<u64>,
}

/// Token metrics mirroring ATIF's `prompt/completion/cached` fields (Module C
/// mandates the mirror for downstream compatibility).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventMetrics {
    /// Prompt tokens (approximate unless provider-reported).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt_tokens: Option<u64>,
    /// Completion tokens.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completion_tokens: Option<u64>,
    /// Provider-cached tokens.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cached_tokens: Option<u64>,
    /// Tokens pruned by compression (Module C emission).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pruned_tokens: Option<u64>,
    /// Compression ratio ×1000 (integer to stay JCS-exact; 350 = 35.0 %).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pruning_ratio_millis: Option<u64>,
}

/// OCSF Fingerprint observable (id 30) — roadmap: per-forward-pass inventory
/// fingerprinting of tool schemas + sampling params, chained via `prev_inventory`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fingerprint {
    /// Hash algorithm id (3 = SHA-256 per OCSF).
    pub algorithm_id: u8,
    /// Algorithm caption.
    pub algorithm: String,
    /// Serialization id (2 = JCS canonical JSON).
    pub serialization_id: u8,
    /// Serialization caption.
    pub serialization: String,
    /// Hex digest value.
    pub value: String,
}

impl Fingerprint {
    /// SHA-256-over-JCS fingerprint of a JSON value.
    pub fn sha256_jcs(value_hex: String) -> Self {
        Self {
            algorithm_id: 3,
            algorithm: "SHA-256".to_owned(),
            serialization_id: 2,
            serialization: "JCS".to_owned(),
            value: value_hex,
        }
    }
}

/// Event metadata (OCSF `metadata` object).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    /// OCSF schema version.
    pub version: String,
    /// Unique event uid (UUIDv7).
    pub uid: String,
    /// Emitting product.
    pub product: Product,
    /// Per-session sequence number — the authoritative intra-session order
    /// (wall clocks are never trusted for ordering).
    pub sequence: u64,
}

/// A schema-conformant agent event.
///
/// Unknown inbound fields at the TOP LEVEL are preserved in
/// [`Self::unmapped`] (never silently dropped); outbound serialization
/// is always the current schema shape.
///
/// Round-6 (hunt2 F11): the tolerance is **inbound-only** — an event
/// whose `unmapped` is non-empty is refused by `validate_event` (and
/// would be refused by the broker's schema gate, which declares
/// `additionalProperties: false`). Consumers may parse newer-node
/// events; they may not republish them carrying unknown fields.
///
/// # Round-34 F3 — additive tolerance is TOP-LEVEL ONLY
///
/// The `deny_unknown_fields` attribute on every nested struct
/// ([`Metadata`], [`AgentIdentity`], [`Product`], [`CharterFile`],
/// [`EventMetrics`], [`Fingerprint`]) means an unknown field INSIDE
/// one of those objects fails deserialization for the whole event —
/// it does NOT flow into `unmapped`. Cross-version replay of a
/// mixed-fleet stream during a rolling upgrade therefore requires
/// that nested-object shape additions bump `config_version` in
/// lockstep with the schema; only newly-added TOP-LEVEL fields are
/// safe to deploy incrementally. This asymmetry is deliberate:
/// nested types are the audit-trail schema surface consumers commit
/// to (SIEM ingestion pipelines depend on their exact shape), while
/// the top-level union tolerates additive OCSF evolution so
/// consumers can continue to parse events emitted by newer nodes
/// during a rolling deploy of the harness itself.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OcsfEvent {
    /// Event metadata.
    pub metadata: Metadata,
    /// Class enum (serialized as `agent.<class>`).
    pub class_name: EventClass,
    /// Numeric class uid.
    pub class_uid: u32,
    /// OCSF Application Activity category uid.
    pub category_uid: u8,
    /// Activity within the class (1 = default activity).
    pub activity_id: u8,
    /// `class_uid * 100 + activity_id` per OCSF convention.
    pub type_uid: u64,
    /// Epoch milliseconds.
    pub time: u64,
    /// ISO-8601 mirror of `time` for human consumers.
    pub time_iso: String,
    /// Severity (1 = informational … 6 = fatal).
    pub severity_id: u8,
    /// Outcome status.
    pub status_id: u8,
    /// Session this event belongs to.
    pub session_uid: String,
    /// Agent config-state identity block.
    pub ai_agent: AgentIdentity,
    /// Stop reason id, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop_reason_id: Option<u8>,
    /// Stop reason text: the provider's native value when captured,
    /// otherwise the normalized [`crate::StopReason`] caption.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop_reason: Option<String>,
    /// Class-specific payload.
    pub payload: serde_json::Value,
    /// Token metrics (ATIF-mirrored names).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics: Option<EventMetrics>,
    /// Per-forward-pass inventory fingerprint (roadmap, flag-gated).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inventory: Option<Fingerprint>,
    /// Previous inventory fingerprint in the chain (see `inventory`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_inventory: Option<Fingerprint>,
    /// Unknown fields captured on inbound parse (evolution tolerance).
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty", flatten)]
    pub unmapped: serde_json::Map<String, serde_json::Value>,
}

/// Builder for [`OcsfEvent`] enforcing invariants at construction.
#[derive(Debug)]
pub struct OcsfEventBuilder {
    class: EventClass,
    session_uid: String,
    ai_agent: AgentIdentity,
    seq: u64,
    activity_id: u8,
    severity_id: u8,
    status: StatusId,
    stop_reason: Option<crate::StopReason>,
    native_stop_reason: Option<String>,
    payload: serde_json::Value,
    metrics: Option<EventMetrics>,
    inventory: Option<Fingerprint>,
    prev_inventory: Option<Fingerprint>,
}

impl OcsfEventBuilder {
    /// Start building an event of `class` for `session_uid` with sequence `seq`.
    pub fn new(class: EventClass, session_uid: impl Into<String>, ai_agent: AgentIdentity, seq: u64) -> Self {
        Self {
            class,
            session_uid: session_uid.into(),
            ai_agent,
            seq,
            activity_id: 1,
            severity_id: 1,
            status: StatusId::Success,
            stop_reason: None,
            native_stop_reason: None,
            payload: serde_json::Value::Null,
            metrics: None,
            inventory: None,
            prev_inventory: None,
        }
    }

    /// Set severity (default 1 = informational).
    pub fn severity(mut self, id: u8) -> Self {
        self.severity_id = id;
        self
    }

    /// Set outcome status (default success).
    pub fn status(mut self, s: StatusId) -> Self {
        self.status = s;
        self
    }

    /// Attach a stop reason.
    pub fn stop_reason(mut self, r: crate::StopReason) -> Self {
        self.stop_reason = Some(r);
        self
    }

    /// Attach a normalized reason and the provider's source-native value.
    pub fn stop_reason_native(mut self, reason: crate::StopReason, native: impl Into<String>) -> Self {
        self.stop_reason = Some(reason);
        self.native_stop_reason = Some(native.into());
        self
    }

    /// Attach a class-specific payload.
    pub fn payload(mut self, p: serde_json::Value) -> Self {
        self.payload = p;
        self
    }

    /// Attach token metrics.
    pub fn metrics(mut self, m: EventMetrics) -> Self {
        self.metrics = Some(m);
        self
    }

    /// Attach inventory fingerprints (roadmap feature).
    pub fn inventory(mut self, current: Fingerprint, previous: Option<Fingerprint>) -> Self {
        self.inventory = Some(current);
        self.prev_inventory = previous;
        self
    }

    /// Build, validating JCS-safety of all counters.
    pub fn build(self) -> Result<OcsfEvent, av_core::CoreError> {
        check_jcs_safe(self.seq)?;
        if let Some(m) = &self.metrics {
            for v in [
                m.prompt_tokens,
                m.completion_tokens,
                m.cached_tokens,
                m.pruned_tokens,
                m.pruning_ratio_millis,
            ]
            .into_iter()
            .flatten()
            {
                check_jcs_safe(v)?;
            }
            // Round-26 F1 (av-events builder): schema declares
            // `pruning_ratio_millis` as an integer in `[0, 1000]`
            // (0.0%–100.0%). The prior build path only enforced
            // JCS-safety, so a caller could construct an event
            // with `pruning_ratio_millis: 5000` (500%) that later
            // failed strict schema validation on ingest. Cap here
            // so both emitter and validator agree at build time.
            if let Some(ratio) = m.pruning_ratio_millis {
                if ratio > 1000 {
                    // The schema's declared max is 1000 (100.0 %);
                    // reuse the JCS-unsafe error variant here since
                    // both classes represent "out-of-declared-range
                    // integer that would silently misrepresent at
                    // the wire boundary."
                    return Err(av_core::CoreError::UnsafeInteger(ratio));
                }
            }
        }
        // Round-6 (hunt2 F1): mirror the JCS-safety guard for
        // ai_agent.ttl_remaining_s at build time so signed emits from
        // this crate can never produce an event that the wire-side
        // validator would refuse.
        if let Some(ttl) = self.ai_agent.ttl_remaining_s {
            check_jcs_safe(ttl)?;
        }
        // Round-6 (hunt1 F5): the JSON schema (`schemas/ocsf-agent-event.schema.json`)
        // and the Rust validator both declare `severity_id` in 1..=6.
        // The builder previously accepted any u8, so a caller passing
        // `.severity(0)` or `.severity(7)` produced a signed/journaled
        // event that then failed the embedded broker's schema validator
        // at publish — surfacing as an opaque Backend error and marking
        // the session capture-failed. Refuse at build time, matching
        // the round-26 pruning_ratio_millis fix pattern above.
        if !(1..=6).contains(&self.severity_id) {
            return Err(av_core::CoreError::UnsafeInteger(u64::from(self.severity_id)));
        }
        let now = av_core::time::now_ms();
        check_jcs_safe(now)?;
        let class_uid = self.class.class_uid();
        Ok(OcsfEvent {
            metadata: Metadata {
                version: OCSF_VERSION.to_owned(),
                uid: av_core::new_event_uid(),
                product: Product {
                    name: PRODUCT_NAME.to_owned(),
                    vendor_name: "AgentVisor AI".to_owned(),
                    version: env!("CARGO_PKG_VERSION").to_owned(),
                },
                sequence: self.seq,
            },
            class_name: self.class,
            class_uid,
            category_uid: CATEGORY_UID,
            activity_id: self.activity_id,
            type_uid: u64::from(class_uid) * 100 + u64::from(self.activity_id),
            time: now,
            time_iso: av_core::time::iso8601_ms(now),
            severity_id: self.severity_id,
            status_id: self.status.id(),
            session_uid: self.session_uid,
            ai_agent: self.ai_agent,
            stop_reason_id: self.stop_reason.map(crate::StopReason::id),
            stop_reason: self
                .native_stop_reason
                .or_else(|| self.stop_reason.map(|reason| reason.caption().to_owned())),
            payload: self.payload,
            metrics: self.metrics,
            inventory: self.inventory,
            prev_inventory: self.prev_inventory,
            unmapped: serde_json::Map::new(),
        })
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
    use crate::StopReason;

    fn identity() -> AgentIdentity {
        AgentIdentity {
            version: "2.1.0".into(),
            charter: "billing-support".into(),
            instance_uid: "agent-inst-42".into(),
            ttl_remaining_s: Some(731),
        }
    }

    #[test]
    fn build_binds_config_state() {
        let ev = OcsfEventBuilder::new(EventClass::StopReason, "sess-1", identity(), 7)
            .stop_reason(StopReason::LoopDetected)
            .status(StatusId::Failure)
            .build()
            .unwrap();
        assert_eq!(ev.ai_agent.version, "2.1.0");
        assert_eq!(ev.ai_agent.charter.name, "billing-support");
        assert_eq!(ev.ai_agent.instance_uid, "agent-inst-42");
        assert_eq!(ev.stop_reason_id, Some(91));
        assert_eq!(ev.stop_reason.as_deref(), Some("Loop Detected"));
        assert_eq!(ev.class_uid, 9902);
        assert_eq!(ev.type_uid, 990_201);
        assert_eq!(ev.metadata.sequence, 7);
        assert_eq!(ev.category_uid, CATEGORY_UID);
        assert_eq!(ev.metadata.product.name, PRODUCT_NAME);
        assert_eq!(ev.metadata.version, OCSF_VERSION);
    }

    /// Round-26 F1: `pruning_ratio_millis` is a permille ratio
    /// (0..=1000 → 0.0%..=100.0%). Round-15 F3 (schema declares
    /// the max) but the builder used to only enforce JCS-safety,
    /// so `Some(5000)` (500%) built successfully and only failed
    /// at strict-validate time downstream. Now caught at build.
    #[test]
    fn build_refuses_pruning_ratio_millis_above_1000() {
        let outcome = OcsfEventBuilder::new(EventClass::ToolCall, "sess-x", identity(), 1)
            .metrics(EventMetrics {
                prompt_tokens: Some(10),
                completion_tokens: Some(10),
                cached_tokens: Some(0),
                pruned_tokens: Some(5),
                pruning_ratio_millis: Some(5000),
            })
            .build();
        assert!(outcome.is_err(), "over-cap ratio must fail build");
        // At the boundary, 1000 (100.0 %) still builds.
        let outcome = OcsfEventBuilder::new(EventClass::ToolCall, "sess-x", identity(), 1)
            .metrics(EventMetrics {
                pruning_ratio_millis: Some(1000),
                ..EventMetrics::default()
            })
            .build();
        assert!(outcome.is_ok(), "boundary ratio 1000 must still build");
    }

    #[test]
    fn serialized_shape_has_required_fields() {
        let ev = OcsfEventBuilder::new(EventClass::ToolCall, "sess-2", identity(), 1)
            .payload(serde_json::json!({"tool": "db_write", "allowed": false}))
            .status(StatusId::Failure)
            .build()
            .unwrap();
        let v = serde_json::to_value(&ev).unwrap();
        for key in [
            "metadata",
            "class_name",
            "class_uid",
            "type_uid",
            "time",
            "time_iso",
            "severity_id",
            "status_id",
            "session_uid",
            "ai_agent",
            "payload",
        ] {
            assert!(v.get(key).is_some(), "missing {key}: {v}");
        }
        assert_eq!(v["class_name"], "agent.tool_call");
        assert_eq!(v["ai_agent"]["instance_uid"], "agent-inst-42");
        // Absent optionals must be omitted, not null (schema strictness).
        assert!(v.get("stop_reason_id").is_none());
    }

    #[test]
    fn unsafe_counter_rejected() {
        let m = EventMetrics {
            prompt_tokens: Some((1 << 53) + 1),
            ..Default::default()
        };
        let err = OcsfEventBuilder::new(EventClass::Compression, "s", identity(), 1)
            .metrics(m)
            .build();
        assert!(err.is_err(), "2^53+1 must be rejected for JCS safety");
    }

    #[test]
    fn unknown_inbound_fields_preserved() {
        let ev = OcsfEventBuilder::new(EventClass::Session, "s", identity(), 1)
            .build()
            .unwrap();
        let mut v = serde_json::to_value(&ev).unwrap();
        v["future_field_from_v2"] = serde_json::json!({"x": 1});
        let parsed: OcsfEvent = serde_json::from_value(v).unwrap();
        assert!(
            parsed.unmapped.contains_key("future_field_from_v2"),
            "unknown fields must be captured: {:?}",
            parsed.unmapped
        );
    }

    #[test]
    fn roundtrip_preserves_equality() {
        let ev = OcsfEventBuilder::new(EventClass::Identity, "sess-9", identity(), 3)
            .metrics(EventMetrics {
                prompt_tokens: Some(120),
                completion_tokens: Some(30),
                cached_tokens: Some(64),
                ..Default::default()
            })
            .build()
            .unwrap();
        let json = serde_json::to_string(&ev).unwrap();
        let back: OcsfEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(ev, back);
    }

    #[test]
    fn all_classes_have_unique_uids_and_topics() {
        let classes = EventClass::all();
        // Concrete lower bound catches an `all() -> empty slice` stub.
        assert!(
            classes.len() >= 6,
            "EventClass::all shrank unexpectedly: {}",
            classes.len()
        );
        let mut uids: Vec<u32> = classes.iter().map(|c| c.class_uid()).collect();
        let mut topics: Vec<&str> = classes.iter().map(|c| c.topic()).collect();
        uids.sort_unstable();
        uids.dedup();
        topics.sort_unstable();
        topics.dedup();
        assert_eq!(uids.len(), classes.len());
        assert_eq!(topics.len(), classes.len());
    }

    #[test]
    fn status_id_wire_values_are_ocsf_conformant() {
        // OCSF: 0 unknown, 1 success, 2 failure. Concrete numeric asserts
        // detect any `id() -> constant` stub of the mapping.
        assert_eq!(StatusId::Unknown.id(), 0);
        assert_eq!(StatusId::Success.id(), 1);
        assert_eq!(StatusId::Failure.id(), 2);
    }
}
