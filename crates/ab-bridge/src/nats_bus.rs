//! NATS JetStream connector (brief Module F: "lighter-weight edge/embedded
//! alternative"). Feature `nats`. One JetStream stream per topic
//! (`ab_<topic>` with dots mapped to underscores), one subject per partition
//! (`<topic>.p<N>`), giving the same partitioned-ordered-replay contract as
//! the embedded broker.
//!
//! Contract tests gate on `AB_NATS_URL` and skip loudly when unset.

use crate::bus::{partition_for, BusError, EventBus, PublishAck, StoredEvent};
use crate::manifest::BridgeManifest;
use std::collections::HashMap;

/// NATS JetStream bus.
pub struct NatsBus {
    rt: tokio::runtime::Runtime,
    js: async_nats::jetstream::Context,
    topics: HashMap<String, u32>,
}

fn stream_name(topic: &str) -> String {
    format!("ab_{}", topic.replace('.', "_"))
}

impl NatsBus {
    /// Connect and provision streams per the manifest.
    pub fn provision(url: &str, manifest: &BridgeManifest) -> Result<Self, BusError> {
        manifest.validate().map_err(|e| BusError::Backend(e.to_string()))?;
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .map_err(|e| BusError::Backend(e.to_string()))?;
        let client = rt
            .block_on(async_nats::connect(url))
            .map_err(|e| BusError::Backend(e.to_string()))?;
        let js = async_nats::jetstream::new(client);
        let mut topics = HashMap::new();
        for t in &manifest.topics {
            let subjects: Vec<String> = (0..t.partitions).map(|p| format!("{}.p{p}", t.name)).collect();
            rt.block_on(js.get_or_create_stream(async_nats::jetstream::stream::Config {
                name: stream_name(&t.name),
                subjects,
                max_age: std::time::Duration::from_secs(u64::from(t.retention.hot_hours) * 3600),
                ..Default::default()
            }))
            .map_err(|e| BusError::Backend(e.to_string()))?;
            topics.insert(t.name.clone(), t.partitions);
        }
        Ok(Self { rt, js, topics })
    }
}

impl EventBus for NatsBus {
    fn publish(&self, topic: &str, key: &str, value: &serde_json::Value) -> Result<PublishAck, BusError> {
        let partitions =
            *self.topics.get(topic).ok_or_else(|| BusError::UnknownTopic(topic.to_owned()))?;
        let partition = partition_for(key, partitions);
        let record = StoredEvent {
            partition,
            offset: 0, // assigned below from the JetStream sequence
            key: key.to_owned(),
            value: value.clone(),
            stored_at: ab_core::time::now_ms(),
        };
        let payload = serde_json::to_vec(&record)?;
        let subject = format!("{topic}.p{partition}");
        let ack = self
            .rt
            .block_on(async {
                self.js.publish(subject, payload.into()).await?.await
            })
            .map_err(|e| BusError::Backend(e.to_string()))?;
        Ok(PublishAck { topic: topic.to_owned(), partition, offset: ack.sequence })
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
        let stream_name = stream_name(topic);
        let subject = format!("{topic}.p{partition}");
        self.rt
            .block_on(async {
                let stream = self.js.get_stream(&stream_name).await?;
                let consumer = stream
                    .create_consumer(async_nats::jetstream::consumer::pull::Config {
                        deliver_policy: async_nats::jetstream::consumer::DeliverPolicy::ByStartSequence {
                            start_sequence: offset.max(1),
                        },
                        filter_subject: subject,
                        ..Default::default()
                    })
                    .await?;
                let mut out = Vec::new();
                let mut batch = consumer
                    .batch()
                    .max_messages(max)
                    .expires(std::time::Duration::from_millis(500))
                    .messages()
                    .await?;
                use futures::StreamExt as _;
                while let Some(Ok(msg)) = batch.next().await {
                    if let Ok(mut ev) = serde_json::from_slice::<StoredEvent>(&msg.payload) {
                        if let Ok(info) = msg.info() {
                            ev.offset = info.stream_sequence;
                        }
                        out.push(ev);
                    }
                    if out.len() >= max {
                        break;
                    }
                }
                Ok::<_, async_nats::Error>(out)
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
