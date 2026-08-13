//! The Portable Event Bridge (brief Module F).
//!
//! A common bus for agent events that customers own, localize, and run
//! air-gapped. The [`EventBus`] trait is the portability boundary:
//!
//! - [`embedded::EmbeddedBroker`] — the reference implementation: a
//!   file-backed, Kafka-shaped log (topics → partitions → append-only JSONL
//!   segments with offsets), partitioned by `ai_agent.instance_uid` for
//!   ordered per-agent replay. Zero external dependencies: this is what makes
//!   the single-binary air-gapped deployment real.
//! - `nats` feature — NATS JetStream connector (edge/single-node alternative).
//! - `kafka` feature — Kafka wire protocol connector (Redpanda is the
//!   reference self-hosted target).
//!
//! Provisioning is declarative: a [`manifest::BridgeManifest`] fully describes
//! topics, partitions, retention, and schema references; `provision()` stands
//! up an identical bridge from the manifest alone (success criterion R12/R30).

pub mod bus;
#[cfg(feature = "cold-store")]
pub(crate) mod cold_store;
pub mod embedded;
pub mod manifest;

pub use bus::{BusError, EventBus, PublishAck, StoredEvent};
pub use embedded::EmbeddedBroker;
pub use manifest::{BridgeManifest, ManifestError, RetentionSpec, TopicSpec, MANIFEST_VERSION};

#[cfg(feature = "kafka")]
pub mod kafka_bus;
#[cfg(feature = "nats")]
pub mod nats_bus;
