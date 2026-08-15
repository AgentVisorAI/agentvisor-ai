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
    cold_archive: Option<crate::cold_store::ColdArchive>,
    js: async_nats::jetstream::Context,
    executor: crate::bus::ConnectorExecutor,
    topics: HashMap<String, u32>,
    validators: HashMap<String, jsonschema::Validator>,
}

fn stream_name(topic: &str) -> String {
    format!("ab_{}", topic.replace('.', "_"))
}

impl NatsBus {
    /// Connect and provision streams per the manifest.
    pub fn provision(url: &str, manifest: &BridgeManifest) -> Result<Self, BusError> {
        manifest
            .validate()
            .map_err(|e| BusError::Backend(e.to_string()))?;
        let validators = crate::manifest::compile_topic_validators(manifest)?;
        let cold_archive = crate::cold_store::ColdArchive::from_manifest(manifest)?;
        let executor = crate::bus::ConnectorExecutor::new("agent-bridge-nats")?;
        let url = url.to_owned();
        let client = executor
            .run(move || async move { async_nats::connect(url).await })?
            .map_err(|e| BusError::Backend(e.to_string()))?;
        // `async_nats::jetstream::new` must be called from within a Tokio
        // runtime — the constructor eagerly calls `Handle::current()` and
        // panics otherwise (async-nats 0.50, jetstream/context.rs:129).
        // Route it through the executor so the sync `provision` entrypoint
        // stays runtime-agnostic for callers.
        let js = executor.run({
            let client = client.clone();
            move || async move { async_nats::jetstream::new(client) }
        })?;
        let mut topics = HashMap::new();
        for t in &manifest.topics {
            let subjects: Vec<String> = (0..t.partitions).map(|p| format!("{}.p{p}", t.name)).collect();
            let context = js.clone();
            // Round-21 F8: match the KafkaBus retention arithmetic
            // discipline. Today `hot_hours: u32` × 3600 fits in
            // u64, but a future field-widening (e.g., u64 for
            // very-long-retention research clusters) would
            // silently wrap here and surface as `Overflow` on the
            // Kafka path — the same cross-backend divergence
            // round-20 F1 closed for counters. Use checked_mul
            // now so a future widening surfaces the error
            // consistently.
            let retention_secs = u64::from(t.retention.hot_hours)
                .checked_mul(3600)
                .ok_or_else(|| BusError::Backend("NATS retention overflow".to_owned()))?;
            let retention = std::time::Duration::from_secs(retention_secs);
            let config = async_nats::jetstream::stream::Config {
                name: stream_name(&t.name),
                subjects: subjects.clone(),
                max_age: retention,
                duplicate_window: retention,
                num_replicas: usize::try_from(manifest.replication_factor)
                    .map_err(|_| BusError::Backend("NATS replication factor exceeds usize".to_owned()))?,
                ..Default::default()
            };
            executor
                .run(move || async move {
                    context
                        .get_or_create_stream(config.clone())
                        .await
                        .map_err(|error| error.to_string())?;
                    context
                        .update_stream(config.clone())
                        .await
                        .map_err(|error| error.to_string())?;
                    let mut stream = context
                        .get_stream(&config.name)
                        .await
                        .map_err(|error| error.to_string())?;
                    let actual = stream
                        .info()
                        .await
                        .map_err(|error| error.to_string())?
                        .config
                        .clone();
                    if actual.subjects != subjects
                        || actual.max_age != retention
                        || actual.duplicate_window != retention
                        || actual.num_replicas != config.num_replicas
                    {
                        return Err("JetStream stream does not match Bridge manifest".to_owned());
                    }
                    Ok::<_, String>(())
                })?
                .map_err(BusError::Backend)?;
            topics.insert(t.name.clone(), t.partitions);
        }
        Ok(Self {
            cold_archive,
            js,
            executor,
            topics,
            validators,
        })
    }

    fn publish_with_uid(
        &self,
        topic: &str,
        key: &str,
        value: &serde_json::Value,
        event_uid: Option<&str>,
    ) -> Result<PublishAck, BusError> {
        crate::manifest::validate_topic_event(&self.validators, topic, value)?;
        let partitions = *self
            .topics
            .get(topic)
            .ok_or_else(|| BusError::UnknownTopic(topic.to_owned()))?;
        let partition = partition_for(key, partitions);
        let event_uid = event_uid.map_or_else(ab_core::new_event_uid, str::to_owned);
        let stored_at = ab_core::time::now_ms();
        let record = StoredEvent {
            partition,
            offset: 0,
            key: key.to_owned(),
            value: value.clone(),
            stored_at,
        };
        if let Some(archive) = &self.cold_archive {
            archive.stage(topic, &record, &event_uid)?;
        }
        let ack = self.publish_broker_only(topic, key, value, stored_at, &event_uid)?;
        if let Some(archive) = &self.cold_archive {
            archive.commit(topic, &event_uid, ack.offset)?;
        }
        Ok(ack)
    }

    fn publish_broker_only(
        &self,
        topic: &str,
        key: &str,
        value: &serde_json::Value,
        stored_at: u64,
        event_uid: &str,
    ) -> Result<PublishAck, BusError> {
        crate::manifest::validate_topic_event(&self.validators, topic, value)?;
        let partitions = *self
            .topics
            .get(topic)
            .ok_or_else(|| BusError::UnknownTopic(topic.to_owned()))?;
        let partition = partition_for(key, partitions);
        let record = StoredEvent {
            partition,
            offset: 0,
            key: key.to_owned(),
            value: value.clone(),
            stored_at,
        };
        let payload = serde_json::to_vec(&record)?;
        let subject = format!("{topic}.p{partition}");
        let context = self.js.clone();
        let event_uid = event_uid.to_owned();
        let ack = self
            .executor
            .run(move || async move {
                let mut headers = async_nats::HeaderMap::new();
                headers.insert("Nats-Msg-Id", event_uid);
                context
                    .publish_with_headers(subject, headers, payload.into())
                    .await?
                    .await
            })?
            .map_err(|e| BusError::Backend(e.to_string()))?;
        Ok(PublishAck {
            topic: topic.to_owned(),
            partition,
            offset: ack.sequence,
        })
    }
}

impl EventBus for NatsBus {
    fn set_control_key(&self, key: [u8; 32]) -> Result<(), BusError> {
        if let Some(archive) = &self.cold_archive {
            archive.set_control_key(key)?;
        }
        Ok(())
    }

    fn publish(&self, topic: &str, key: &str, value: &serde_json::Value) -> Result<PublishAck, BusError> {
        let event_uid = value
            .get("metadata")
            .and_then(|metadata| metadata.get("uid"))
            .and_then(serde_json::Value::as_str);
        self.publish_with_uid(topic, key, value, event_uid)
    }

    fn publish_idempotent(
        &self,
        topic: &str,
        key: &str,
        value: &serde_json::Value,
        event_uid: &str,
    ) -> Result<PublishAck, BusError> {
        self.publish_with_uid(topic, key, value, Some(event_uid))
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
        let context = self.js.clone();
        self.executor
            .run(move || async move {
                let stream = context.get_stream(&stream_name).await?;
                let consumer = stream
                    .create_consumer(async_nats::jetstream::consumer::pull::Config {
                        deliver_policy: async_nats::jetstream::consumer::DeliverPolicy::ByStartSequence {
                            start_sequence: offset.max(1),
                        },
                        filter_subject: subject,
                        // Ephemeral consumers without an inactive_threshold
                        // linger on the JetStream server until the client
                        // disconnects. Since our async_nats client stays
                        // connected for the lifetime of the process, every
                        // fetch call otherwise leaks a consumer.
                        inactive_threshold: std::time::Duration::from_secs(30),
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
                while let Some(next) = batch.next().await {
                    // Surface the error instead of silently continuing on:
                    // an audit-trail consumer that sees a shorter list than
                    // expected with no error is an evidence gap. The bad
                    // record stays on JetStream as forensic evidence.
                    let msg = next?;
                    let mut ev: StoredEvent = serde_json::from_slice(&msg.payload).map_err(|error| {
                        async_nats::Error::from(std::io::Error::other(format!("fetch decode: {error}")))
                    })?;
                    if let Ok(info) = msg.info() {
                        ev.offset = info.stream_sequence;
                    }
                    out.push(ev);
                    if out.len() >= max {
                        break;
                    }
                }
                Ok::<_, async_nats::Error>(out)
            })?
            .map_err(|e| BusError::Backend(e.to_string()))
    }

    fn partitions(&self, topic: &str) -> Result<u32, BusError> {
        self.topics
            .get(topic)
            .copied()
            .ok_or_else(|| BusError::UnknownTopic(topic.to_owned()))
    }

    fn topics(&self) -> Vec<String> {
        let mut t: Vec<String> = self.topics.keys().cloned().collect();
        t.sort();
        t
    }

    fn maintenance(&self, _now_ms: u64) -> Result<u64, BusError> {
        self.cold_archive.as_ref().map_or(Ok(0), |archive| {
            archive.retry_pending_with(|pending| {
                self.publish_broker_only(
                    &pending.topic,
                    &pending.key,
                    &pending.value,
                    pending.stored_at,
                    &pending.event_uid,
                )
            })
        })
    }
}
