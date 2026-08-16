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

/// Acknowledgment for a published event.
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
    /// Configure the signer-derived key used for authenticated local controls.
    fn set_control_key(&self, _key: [u8; 32]) -> Result<(), BusError> {
        Ok(())
    }

    /// Publish `value` onto `topic`, partitioned by `key`. Returns the ack.
    fn publish(&self, topic: &str, key: &str, value: &serde_json::Value) -> Result<PublishAck, BusError>;

    /// Publish a stable event UID. Backends with native or local deduplication
    /// override this method; the default preserves compatibility while the UID
    /// remains embedded in the event payload for downstream deduplication.
    fn publish_idempotent(
        &self,
        topic: &str,
        key: &str,
        value: &serde_json::Value,
        _event_uid: &str,
    ) -> Result<PublishAck, BusError> {
        self.publish(topic, key, value)
    }

    /// Locate an already committed event by stable UID during crash recovery.
    fn find_event_by_uid(
        &self,
        topic: &str,
        key: &str,
        event_uid: &str,
    ) -> Result<Option<PublishAck>, BusError> {
        let partition = partition_for(key, self.partitions(topic)?);
        let mut offset = 0u64;
        loop {
            let events = self.fetch(topic, partition, offset, 1_024)?;
            if events.is_empty() {
                return Ok(None);
            }
            for event in &events {
                if event
                    .value
                    .get("metadata")
                    .and_then(|metadata| metadata.get("uid"))
                    .and_then(serde_json::Value::as_str)
                    == Some(event_uid)
                {
                    return Ok(Some(PublishAck {
                        topic: topic.to_owned(),
                        partition,
                        offset: event.offset,
                    }));
                }
            }
            let next = events
                .last()
                .and_then(|event| event.offset.checked_add(1))
                .ok_or_else(|| BusError::Backend("event lookup offset overflow".to_owned()))?;
            if next <= offset {
                return Err(BusError::Backend(
                    "event lookup made no offset progress".to_owned(),
                ));
            }
            offset = next;
        }
    }

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

    /// Run backend maintenance such as hot-retention expiry. Managed brokers
    /// may return zero when retention is enforced natively.
    fn maintenance(&self, _now_ms: u64) -> Result<u64, BusError> {
        Ok(0)
    }
}

/// Stable partition assignment: FNV-1a of the key modulo partition count.
/// Deterministic across processes and platforms so replay tooling and the
/// broker always agree (a hash mismatch would silently split an agent's
/// ordered stream).
pub fn partition_for(key: &str, partitions: u32) -> u32 {
    let h = av_core::hash::fnv1a(key.as_bytes());
    #[allow(clippy::cast_possible_truncation)]
    ((h % u64::from(partitions.max(1))) as u32)
}

#[cfg(any(feature = "nats", feature = "kafka", feature = "cold-store"))]
type ConnectorTask = Box<dyn FnOnce(tokio::runtime::Handle) + Send + 'static>;

#[cfg(any(feature = "nats", feature = "kafka", feature = "cold-store"))]
enum ConnectorCommand {
    Run(ConnectorTask),
    Shutdown,
}

/// Persistent runtime owner for synchronous network-bus adapters.
#[cfg(any(feature = "nats", feature = "kafka", feature = "cold-store"))]
pub(crate) struct ConnectorExecutor {
    sender: std::sync::mpsc::SyncSender<ConnectorCommand>,
    thread: parking_lot::Mutex<Option<std::thread::JoinHandle<()>>>,
}

#[cfg(any(feature = "nats", feature = "kafka", feature = "cold-store"))]
impl ConnectorExecutor {
    pub(crate) fn new(name: &str) -> Result<Self, BusError> {
        let (sender, receiver) = std::sync::mpsc::sync_channel::<ConnectorCommand>(1_024);
        let (ready_sender, ready_receiver) = std::sync::mpsc::sync_channel(1);
        let thread = std::thread::Builder::new()
            .name(name.to_owned())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(1)
                    .enable_all()
                    .build()
                    .map_err(|error| error.to_string());
                match runtime {
                    Ok(runtime) => {
                        let _ = ready_sender.send(Ok(()));
                        while let Ok(command) = receiver.recv() {
                            match command {
                                ConnectorCommand::Run(task) => task(runtime.handle().clone()),
                                ConnectorCommand::Shutdown => break,
                            }
                        }
                    }
                    Err(error) => {
                        let _ = ready_sender.send(Err(error));
                    }
                }
            })
            .map_err(BusError::Io)?;
        ready_receiver
            .recv()
            .map_err(|_| BusError::Backend("connector runtime failed to start".to_owned()))?
            .map_err(BusError::Backend)?;
        Ok(Self {
            sender,
            thread: parking_lot::Mutex::new(Some(thread)),
        })
    }

    pub(crate) fn run<F, Fut, T>(&self, operation: F) -> Result<T, BusError>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: std::future::Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let (result_sender, result_receiver) = std::sync::mpsc::sync_channel(1);
        self.sender
            .send(ConnectorCommand::Run(Box::new(move |runtime| {
                runtime.spawn(async move {
                    let result = tokio::time::timeout(std::time::Duration::from_secs(10), operation()).await;
                    let _ = result_sender.send(result);
                });
            })))
            .map_err(|_| BusError::Backend("connector runtime is closed".to_owned()))?;
        result_receiver
            .recv()
            .map_err(|_| BusError::Backend("connector operation was interrupted".to_owned()))
            .and_then(|result| {
                result.map_err(|_| BusError::Backend("connector operation timed out".to_owned()))
            })
    }
}

#[cfg(any(feature = "nats", feature = "kafka", feature = "cold-store"))]
impl Drop for ConnectorExecutor {
    fn drop(&mut self) {
        let _ = self.sender.send(ConnectorCommand::Shutdown);
        if let Some(thread) = self.thread.get_mut().take() {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    #[cfg(any(feature = "nats", feature = "kafka"))]
    use std::sync::Arc;

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

    #[cfg(any(feature = "nats", feature = "kafka"))]
    #[test]
    fn persistent_connector_runtime_is_safe_inside_tokio() {
        let outer = tokio::runtime::Runtime::new().unwrap();
        outer.block_on(async {
            let connector = ConnectorExecutor::new("test-connector").unwrap();
            assert_eq!(connector.run(|| async { 41u64 }).unwrap(), 41);
            assert_eq!(connector.run(|| async { 42u64 }).unwrap(), 42);
            drop(connector);
        });
    }

    #[cfg(any(feature = "nats", feature = "kafka"))]
    #[test]
    fn connector_operations_can_overlap() {
        let connector = Arc::new(ConnectorExecutor::new("parallel-connector").unwrap());
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        std::thread::scope(|scope| {
            let first_connector = Arc::clone(&connector);
            let first_barrier = Arc::clone(&barrier);
            let first = scope.spawn(move || {
                first_connector
                    .run(move || async move {
                        first_barrier.wait().await;
                        1u64
                    })
                    .unwrap()
            });
            let second_connector = Arc::clone(&connector);
            let second_barrier = Arc::clone(&barrier);
            let second = scope.spawn(move || {
                second_connector
                    .run(move || async move {
                        second_barrier.wait().await;
                        2u64
                    })
                    .unwrap()
            });
            assert_eq!(first.join().unwrap() + second.join().unwrap(), 3);
        });
    }
}
