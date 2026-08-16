//! OCSF `ai_operation`-profile event model (Module E of the brief).
//!
//! Every event binds agent config state — `ai_agent.version`, `ai_agent.charter`,
//! `ai_agent.instance_uid` — alongside `stop_reason_id`, per the pattern authored
//! in Levaj2000/ocsf-schema PR #1 (merged, aligned with upstream ocsf#1704 /
//! v1.10.0). The roadmap Fingerprint chaining (per-forward-pass inventory) is
//! implemented behind [`OcsfEvent::inventory`] fields, default `None`.
//!
//! Evolution policy (EVOLUTION.md): inbound-tolerant (top-level unknown
//! fields land in `unmapped`; nested objects stay strict), outbound-strict
//! (emitters always produce the current schema).

pub mod model;
pub mod stop_reason;
pub mod validate;

pub use model::{
    AgentIdentity, CharterFile, EventClass, EventMetrics, Fingerprint, Metadata, OcsfEvent, OcsfEventBuilder,
    Product, StatusId, CATEGORY_UID, OCSF_VERSION, PRODUCT_NAME,
};
pub use stop_reason::StopReason;
pub use validate::{validate_event, ValidationError};
