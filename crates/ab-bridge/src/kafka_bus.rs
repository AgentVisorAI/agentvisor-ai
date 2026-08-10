//! Kafka-wire connector (feature `kafka`), targeting Redpanda as the reference
//! self-hosted broker (brief Module F). Uses rskafka (pure Rust, no librdkafka
//! system dependency). Contract tests gate on `AB_KAFKA_BROKER`.

use crate::bus::{partition_for, BusError, EventBus, PublishAck, StoredEvent};
use crate::manifest::BridgeManifest;
use rskafka::client::partition::{Compression, UnknownTopicHandling};
use rskafka::client::{Client, ClientBuilder};
use rskafka::record::Record;
use std::collections::HashMap;

/// Kafka/Redpanda bus.
pub struct KafkaBus {
    rt: tokio::runtime::Runtime,
    client: Client,
    topics: HashMap<String, u32>,
}

impl KafkaBus {
    /// Connect to `broker` (host:port) and provision topics per the manifest.
    pub fn provision(broker: &str, manifest: &BridgeManifest) -> Result<Self, BusError> {
        manifest.validate().map_err(|e| BusError::Backend(e.to_string()))?;
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .map_err(|e| BusError::Backend(e.to_string()))?;
        let client = rt
            .block_on(ClientBuilder::new(vec![broker.to_owned()]).build())
            .map_err(|e| BusError::Backend(e.to_string()))?;
        let mut topics = HashMap::new();
        for t in &manifest.topics {
            let controller = client.controller_client().map_err(|e| BusError::Backend(e.to_string()))?;
            // Idempotent create: "already exists" is fine.
            let created = rt.block_on(controller.create_topic(
                t.name.clone(),
                t.partitions as i32,
                1, // replication factor: single-node reference deployment
                5_000,
            ));
            if let Err(e) = created {
                let msg = e.to_string();
                if !msg.contains("already exists") && !msg.contains("TopicAlreadyExists") {
                    return Err(BusError::Backend(msg));
                }
            }
            topics.insert(t.name.clone(), t.partitions);
        }
        Ok(Self { rt, client, topics })
    }
}

impl EventBus for KafkaBus {
    fn publish(&self, topic: &str, key: &str, value: &serde_json::Value) -> Result<PublishAck, BusError> {
        let partitions =
            *self.topics.get(topic).ok_or_else(|| BusError::UnknownTopic(topic.to_owned()))?;
        let partition = partition_for(key, partitions);
        let record = StoredEvent {
            partition,
            offset: 0,
            key: key.to_owned(),
            value: value.clone(),
            stored_at: ab_core::time::now_ms(),
        };
        let payload = serde_json::to_vec(&record)?;
        let offset = self
            .rt
            .block_on(async {
                let pc = self
                    .client
                    .partition_client(topic, partition as i32, UnknownTopicHandling::Error)
                    .await?;
                let offsets = pc
                    .produce(
                        vec![Record {
                            key: Some(key.as_bytes().to_vec()),
                            value: Some(payload),
                            headers: Default::default(),
                            timestamp: chrono_now(),
                        }],
                        Compression::NoCompression,
                    )
                    .await?;
                Ok::<_, rskafka::client::error::Error>(offsets.first().copied().unwrap_or(0))
            })
            .map_err(|e| BusError::Backend(e.to_string()))?;
        #[allow(clippy::cast_sign_loss)]
        Ok(PublishAck { topic: topic.to_owned(), partition, offset: offset as u64 })
    }

    fn fetch(
        &self,
        topic: &str,
        partition: u32,
        offset: u64,
        max: usize,
    ) -> Result<Vec<StoredEvent>, BusError> {
        if !self.topics.contains_key(topic) {
            return Err(BusError::UnknownTopic(topic.to_owned()));
        }
        self.rt
            .block_on(async {
                let pc = self
                    .client
                    .partition_client(topic, partition as i32, UnknownTopicHandling::Error)
                    .await?;
                #[allow(clippy::cast_possible_wrap)]
                let (records, _high_watermark) =
                    pc.fetch_records(offset as i64, 1..(16 * 1024 * 1024), 500).await?;
                let mut out = Vec::new();
                for r in records {
                    if let Some(value) = r.record.value {
                        if let Ok(mut ev) = serde_json::from_slice::<StoredEvent>(&value) {
                            #[allow(clippy::cast_sign_loss)]
                            {
                                ev.offset = r.offset as u64;
                            }
                            out.push(ev);
                        }
                    }
                    if out.len() >= max {
                        break;
                    }
                }
                Ok::<_, rskafka::client::error::Error>(out)
            })
            .map_err(|e| BusError::Backend(e.to_string()))
    }

    fn partitions(&self, topic: &str) -> Result<u32, BusError> {
        self.topics.get(topic).copied().ok_or_else(|| BusError::UnknownTopic(topic.to_owned()))
    }

    fn topics(&self) -> Vec<String> {
        let mut t: Vec<String> = self.topics.keys().cloned().collect();
        t.sort();
        t
    }
}

fn chrono_now() -> chrono::DateTime<chrono::Utc> {
    chrono::Utc::now()
}
