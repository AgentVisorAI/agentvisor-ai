//! NATS JetStream connector (brief Module F: "lighter-weight edge/embedded
//! alternative"). Feature `nats`. One JetStream stream per topic
//! (`av_<topic>` with dots mapped to underscores), one subject per partition
//! (`<topic>.p<N>`), giving the same partitioned-ordered-replay contract as
//! the embedded broker.
//!
//! Contract tests gate on `AV_NATS_URL` and skip loudly when unset.

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
    format!("av_{}", topic.replace('.', "_"))
}

/// Pair up broker credentials, refusing half-configured auth loudly. A
/// typo'd or unexported password must not silently downgrade the
/// connection to anonymous (D13: a dropped credential is a silent error;
/// same contract as the Kafka connector's `KafkaSecurity`).
fn nats_credentials(
    user: Option<String>,
    password: Option<String>,
) -> Result<Option<(String, String)>, BusError> {
    match (user, password) {
        (Some(user), Some(password)) => Ok(Some((user, password))),
        (None, None) => Ok(None),
        _ => Err(BusError::Backend(
            "AV_NATS_USER and AV_NATS_PASSWORD must be set together".to_owned(),
        )),
    }
}

impl NatsBus {
    /// Connect and provision streams per the manifest.
    pub fn provision(url: &str, manifest: &BridgeManifest) -> Result<Self, BusError> {
        manifest
            .validate()
            .map_err(|e| BusError::Backend(e.to_string()))?;
        let validators = crate::manifest::compile_topic_validators(manifest)?;
        let cold_archive = crate::cold_store::ColdArchive::from_manifest(manifest)?;
        let executor = crate::bus::ConnectorExecutor::new("agentvisor-ai-nats")?;
        // rustls 0.23 resolves its process-level CryptoProvider lazily and
        // panics on first TLS use when more than one provider feature is
        // compiled in (all-feature workspace builds carry both `ring` and
        // `aws-lc-rs`) and none has been installed. Pin `ring` here; if the
        // embedding application already installed one, keep theirs.
        let _ = rustls_tls::crypto::ring::default_provider().install_default();
        let url = url.to_owned();
        // TLS/auth material comes from the environment so `tls://` endpoints
        // work against private-CA deployments without new constructor
        // surface: `AV_NATS_CA_FILE` pins a root CA (self-hosted enclaves
        // rarely use WebPKI certs), `AV_NATS_USER`/`AV_NATS_PASSWORD` supply
        // broker auth. Values are paths/identifiers, never logged.
        let ca_file = std::env::var_os("AV_NATS_CA_FILE").map(std::path::PathBuf::from);
        let credentials = nats_credentials(
            std::env::var("AV_NATS_USER").ok(),
            std::env::var("AV_NATS_PASSWORD").ok(),
        )?;
        let client = executor
            .run(move || async move {
                let mut options = async_nats::ConnectOptions::new();
                // A pinned CA or supplied credentials both state intent:
                // this connection must be TLS. Forcing the requirement means
                // a `nats://` (instead of `tls://`) endpoint typo cannot
                // silently downgrade to plaintext, and an active MITM
                // cannot strip `tls_required` from INFO to capture the
                // CONNECT password in cleartext. A CA file is deliberately
                // not required for credentials — WebPKI-certified `tls://`
                // endpoints are legitimate.
                let secured = ca_file.is_some() || credentials.is_some();
                if let Some(ca) = ca_file {
                    options = options.add_root_certificates(ca);
                }
                if secured {
                    options = options.require_tls(true);
                }
                if let Some((user, password)) = credentials {
                    options = options.user_and_password(user, password);
                }
                options.connect(url).await
            })?
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
            // Match the KafkaBus retention arithmetic
            // discipline. Today `hot_hours: u32` × 3600 fits in
            // u64, but a future field-widening (e.g., u64 for
            // very-long-retention research clusters) would
            // silently wrap here and surface as `Overflow` on the
            // Kafka path — the same cross-backend divergence
            // already closed for counters. Use checked_mul
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
        let event_uid = event_uid.map_or_else(av_core::new_event_uid, str::to_owned);
        let stored_at = av_core::time::now_ms();
        let record = StoredEvent {
            partition,
            offset: 0,
            key: key.to_owned(),
            value: value.clone(),
            stored_at,
        };
        if let Some(archive) = &self.cold_archive {
            let already_staged = archive.stage(topic, &record, &event_uid)?;
            if already_staged {
                // A prior attempt for this UID staged the intent and may
                // have produced to the broker before its commit step
                // failed (ENOSPC persisting the resolved offset, MAC
                // refusal, crash). JetStream's Nats-Msg-Id dedup only
                // covers the stream's duplicate_window, so a retry
                // outside that window would append a second record for
                // the same logical event — a duplicate in the audit
                // stream. Consult the stream first, exactly like the
                // maintenance retry path does.
                if let Some(existing) = self.find_event_by_uid(topic, key, &event_uid)? {
                    // The event is durably on the broker; resolving the
                    // cold intent is best-effort here. On failure the
                    // durable intent stays queued for the maintenance
                    // pass — do not fail a publish that succeeded.
                    if let Err(error) = archive.commit(topic, &event_uid, existing.offset) {
                        tracing::warn!(
                            %error,
                            topic,
                            event_uid = %event_uid,
                            "cold intent commit failed after idempotent dedup hit; left for maintenance retry"
                        );
                    }
                    return Ok(existing);
                }
            }
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

    /// JetStream-aware UID lookup. The default trait implementation
    /// treats an empty `fetch` as proof of absence, but a NATS batch
    /// with a 500 ms `expires` can legitimately deliver zero messages
    /// before expiry on a loaded server even when matching messages
    /// exist — and a false "absent" makes crash-recovery maintenance
    /// re-produce an already-committed event (a duplicate in the audit
    /// stream once outside the JetStream dedup window). Use the
    /// consumer's server-computed `num_pending` instead: zero pending
    /// on a freshly-created filtered consumer proves absence; an empty
    /// batch with pending remaining is a timing artifact and retries
    /// bounded, then fails the pass (callers retry later — the cold
    /// intent is durable).
    fn find_event_by_uid(
        &self,
        topic: &str,
        key: &str,
        event_uid: &str,
    ) -> Result<Option<PublishAck>, BusError> {
        let partitions = *self
            .topics
            .get(topic)
            .ok_or_else(|| BusError::UnknownTopic(topic.to_owned()))?;
        let partition = partition_for(key, partitions);
        let stream_name = stream_name(topic);
        let subject = format!("{topic}.p{partition}");
        // One page per `executor.run` call: the executor imposes a hard
        // 10 s timeout per operation, so running the whole from-sequence-1
        // scan inside a single call would make lookups on large streams
        // fail with a timeout on every attempt, forever (each retry
        // restarts from sequence 1 under the same cap). Paging gives each
        // bounded step its own budget — the same shape as the default
        // trait implementation's per-`fetch` paging.
        enum Page {
            Found(u64),
            Absent,
            Advanced(u64),
            Empty,
        }
        let mut offset = 1u64;
        let mut empty_batches = 0u32;
        loop {
            let context = self.js.clone();
            let page_stream = stream_name.clone();
            let page_subject = subject.clone();
            let page_uid = event_uid.to_owned();
            let page = self
                .executor
                .run(move || async move {
                    let stream = context.get_stream(&page_stream).await?;
                    let consumer = stream
                        .create_consumer(async_nats::jetstream::consumer::pull::Config {
                            deliver_policy: async_nats::jetstream::consumer::DeliverPolicy::ByStartSequence {
                                start_sequence: offset,
                            },
                            filter_subject: page_subject,
                            // See `fetch`: ephemeral consumers without an
                            // inactive_threshold linger server-side for the
                            // lifetime of the connection.
                            inactive_threshold: std::time::Duration::from_secs(30),
                            ..Default::default()
                        })
                        .await?;
                    if consumer.cached_info().num_pending == 0 {
                        // Server-attested: no messages at or after `offset`
                        // match the filter — genuinely absent.
                        return Ok::<_, async_nats::Error>(Page::Absent);
                    }
                    let mut batch = consumer
                        .batch()
                        .max_messages(1_024)
                        .expires(std::time::Duration::from_millis(500))
                        .messages()
                        .await?;
                    let mut next_offset = offset;
                    let mut delivered = false;
                    use futures::StreamExt as _;
                    while let Some(next) = batch.next().await {
                        let msg = next?;
                        delivered = true;
                        let info = msg.info().map_err(|error| {
                            async_nats::Error::from(std::io::Error::other(format!(
                                "uid lookup info: {error}"
                            )))
                        })?;
                        // `publish_broker_only` stamps the (possibly freshly
                        // generated) uid only as the `Nats-Msg-Id` header;
                        // for events without `metadata.uid` the payload scan
                        // below can never find the record this bus produced,
                        // so crash recovery re-published a duplicate once
                        // outside the JetStream dedup window. Consult the
                        // header first — same parity fix as KafkaBus's
                        // `agentvisor-event-uid` header check.
                        if msg
                            .headers
                            .as_ref()
                            .and_then(|headers| headers.get("Nats-Msg-Id"))
                            .is_some_and(|value| value.as_str() == page_uid.as_str())
                        {
                            return Ok(Page::Found(info.stream_sequence));
                        }
                        let stored: StoredEvent = serde_json::from_slice(&msg.payload).map_err(|error| {
                            async_nats::Error::from(std::io::Error::other(format!(
                                "uid lookup decode at sequence {}: {error}",
                                info.stream_sequence
                            )))
                        })?;
                        if stored
                            .value
                            .get("metadata")
                            .and_then(|metadata| metadata.get("uid"))
                            .and_then(serde_json::Value::as_str)
                            == Some(page_uid.as_str())
                        {
                            return Ok(Page::Found(info.stream_sequence));
                        }
                        next_offset = info.stream_sequence.checked_add(1).ok_or_else(|| {
                            async_nats::Error::from(std::io::Error::other("uid lookup sequence overflow"))
                        })?;
                    }
                    Ok(if delivered {
                        Page::Advanced(next_offset)
                    } else {
                        Page::Empty
                    })
                })?
                .map_err(|e| BusError::Backend(e.to_string()))?;
            match page {
                Page::Found(sequence) => {
                    return Ok(Some(PublishAck {
                        topic: topic.to_owned(),
                        partition,
                        offset: sequence,
                    }));
                }
                Page::Absent => return Ok(None),
                Page::Advanced(next_offset) => {
                    offset = next_offset;
                    empty_batches = 0;
                }
                Page::Empty => {
                    // Messages are pending past `offset` but the 500 ms
                    // batch delivered nothing — a timing artifact, NOT
                    // proof of absence. Retry bounded, then fail the
                    // lookup so the caller retries the whole pass later.
                    empty_batches += 1;
                    if empty_batches >= 8 {
                        return Err(BusError::Backend(format!(
                            "uid lookup stalled: messages pending past sequence {offset} but batches deliver nothing"
                        )));
                    }
                }
            }
        }
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
        // Contract: "read up to `max` events". `max_messages(0)` has
        // server-defined semantics and the loop below checks the cap only
        // after pushing; return the embedded broker's answer directly.
        if max == 0 {
            return Ok(Vec::new());
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
                    // Surface an info() failure like the payload-decode
                    // path above: silently keeping the offset-0
                    // placeholder would break offset-based pagination
                    // (reconcilers resume from `last.offset + 1`, so a
                    // zeroed offset restarts the scan from the head).
                    let info = msg.info().map_err(|error| {
                        async_nats::Error::from(std::io::Error::other(format!("fetch info: {error}")))
                    })?;
                    ev.offset = info.stream_sequence;
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
                // Same rationale as `KafkaBus::maintenance`: a crash or
                // executor timeout between a successful publish and the
                // subsequent `commit()` leaves the intent offset-None
                // while the event IS already on the stream. Blindly
                // re-producing here would double the audit stream. NATS
                // dedupe via `Nats-Msg-Id` catches this only inside the
                // stream's `duplicate_window == retention` — a retry
                // after retention expiry (or after a per-consumer
                // stream reset) escapes it. Consult the stream first
                // and only publish when the UID is genuinely absent.
                if let Some(ack) = self.find_event_by_uid(&pending.topic, &pending.key, &pending.event_uid)? {
                    return Ok(ack);
                }
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::nats_credentials;

    #[test]
    fn credentials_pair_or_fail_loudly() {
        assert!(nats_credentials(None, None).unwrap().is_none());
        assert_eq!(
            nats_credentials(Some("u".into()), Some("p".into())).unwrap(),
            Some(("u".into(), "p".into()))
        );
        for (user, password) in [(Some("u".to_owned()), None), (None, Some("p".to_owned()))] {
            let error = nats_credentials(user, password).unwrap_err();
            assert!(
                error.to_string().contains("must be set together"),
                "partial credentials must fail loudly, got: {error}"
            );
        }
    }
}
