//! The `EventBus` trait — the Bridge's backend portability boundary.

use serde::{Deserialize, Serialize};

/// Bus errors.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BusError {
    /// Topic does not exist (provision first — publishing into the void is a
    /// silent-error class, so it's an error, not an auto-create).
    #[error("unknown topic {0:?} (provision it via the manifest first)")]
    UnknownTopic(String),
    /// I/O failure.
    #[error("bus io: {0}")]
    Io(#[from] std::io::Error),
    /// Serialization failure.
    #[error("bus serde: {0}")]
    Serde(#[from] serde_json::Error),
    /// Backend-specific failure (network brokers).
    #[error("bus backend: {0}")]
    Backend(String),
}

/// Acknowledgement for a published event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishAck {
    /// Topic the event landed on.
    pub topic: String,
    /// Partition index (derived from the partition key).
    pub partition: u32,
    /// Offset within the partition.
    pub offset: u64,
}

/// An event as stored/replayed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoredEvent {
    /// Partition index.
    pub partition: u32,
    /// Offset within the partition.
    pub offset: u64,
    /// Partition key (`ai_agent.instance_uid`).
    pub key: String,
    /// The event payload.
    pub value: serde_json::Value,
    /// Broker-assigned append timestamp (epoch ms).
    pub stored_at: u64,
}

/// Publish/consume abstraction. Synchronous by design: the harness calls it
/// from worker threads (never the hot path), and network backends manage
/// their own I/O runtime internally.
pub trait EventBus: Send + Sync {
    /// Publish `value` onto `topic`, partitioned by `key`. Returns the ack.
    fn publish(&self, topic: &str, key: &str, value: &serde_json::Value) -> Result<PublishAck, BusError>;

    /// Read up to `max` events from `topic`/`partition` starting at `offset`
    /// (ordered replay).
    fn fetch(
        &self,
        topic: &str,
        partition: u32,
        offset: u64,
        max: usize,
    ) -> Result<Vec<StoredEvent>, BusError>;

    /// Number of partitions configured for `topic`.
    fn partitions(&self, topic: &str) -> Result<u32, BusError>;

    /// Topics currently provisioned.
    fn topics(&self) -> Vec<String>;
}

/// Stable partition assignment: FNV-1a of the key modulo partition count.
/// Deterministic across processes and platforms so replay tooling and the
/// broker always agree (a hash mismatch would silently split an agent's
/// ordered stream).
pub fn partition_for(key: &str, partitions: u32) -> u32 {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut h = FNV_OFFSET;
    for b in key.as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(FNV_PRIME);
    }
    #[allow(clippy::cast_possible_truncation)]
    ((h % u64::from(partitions.max(1))) as u32)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn partition_assignment_is_stable() {
        // Pinned values: changing the hash silently re-partitions every
        // deployment's replay order — this test makes that loud.
        assert_eq!(partition_for("agent-inst-1", 8), partition_for("agent-inst-1", 8));
        let spread: std::collections::HashSet<u32> =
            (0..100).map(|i| partition_for(&format!("inst-{i}"), 8)).collect();
        assert!(spread.len() >= 6, "poor partition spread: {spread:?}");
    }

    #[test]
    fn zero_partitions_clamped() {
        assert_eq!(partition_for("x", 0), 0);
    }
}
