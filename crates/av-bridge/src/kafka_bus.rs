//! Kafka-wire connector (feature `kafka`), targeting Redpanda as the reference
//! self-hosted broker (brief Module F). The event path uses rskafka; a statically
//! linked librdkafka admin client provisions and verifies topic retention.
//!
//! TLS/SASL comes from the environment so secured endpoints need no new
//! constructor surface: `AV_KAFKA_CA_FILE` pins a root CA (PEM) and enables
//! TLS on both the admin and event paths; `AV_KAFKA_SASL_USERNAME` /
//! `AV_KAFKA_SASL_PASSWORD` enable SASL with the mechanism from
//! `AV_KAFKA_SASL_MECHANISM` (`SCRAM-SHA-256` by default — Redpanda's
//! native credential store — or `SCRAM-SHA-512` / `PLAIN`). Credentials
//! are only accepted together with TLS: PLAIN would ship the password in
//! the clear, and even SCRAM without TLS is exposed to MITM relay. Use
//! hostname (not bare-IP) broker endpoints with TLS: certificate
//! verification runs against the dialed name, and IP-SAN support varies
//! across rustls versions.

use crate::bus::{partition_for, BusError, EventBus, PublishAck, StoredEvent};
use crate::manifest::BridgeManifest;
use rdkafka::admin::{AdminClient, AdminOptions, NewTopic, ResourceSpecifier, TopicReplication};
use rdkafka::client::DefaultClientContext;
use rdkafka::config::ClientConfig;
use rdkafka::types::RDKafkaErrorCode;
use rskafka::client::partition::{Compression, OffsetAt, UnknownTopicHandling};
use rskafka::client::{ClientBuilder, SaslConfig};
use rskafka::record::Record;
use std::collections::HashMap;
use std::sync::Arc;

/// Broker security material resolved from the environment (module docs).
struct KafkaSecurity {
    ca_file: Option<std::path::PathBuf>,
    credentials: Option<(String, String)>,
    mechanism: SaslMechanism,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SaslMechanism {
    Plain,
    ScramSha256,
    ScramSha512,
}

impl SaslMechanism {
    fn parse(value: &str) -> Result<Self, BusError> {
        match value {
            "PLAIN" => Ok(Self::Plain),
            "SCRAM-SHA-256" => Ok(Self::ScramSha256),
            "SCRAM-SHA-512" => Ok(Self::ScramSha512),
            other => Err(BusError::Backend(format!(
                "AV_KAFKA_SASL_MECHANISM {other:?} is not supported \
                 (use PLAIN, SCRAM-SHA-256, or SCRAM-SHA-512)"
            ))),
        }
    }

    /// librdkafka's `sasl.mechanism` spelling.
    fn librdkafka_name(self) -> &'static str {
        match self {
            Self::Plain => "PLAIN",
            Self::ScramSha256 => "SCRAM-SHA-256",
            Self::ScramSha512 => "SCRAM-SHA-512",
        }
    }
}

impl KafkaSecurity {
    fn from_env() -> Result<Self, BusError> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    /// Testable core of [`Self::from_env`] (same pattern as the harness
    /// config's `apply_env_overrides_from`): `get` returns the value of a
    /// named environment variable, or `None` when unset.
    fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, BusError> {
        let ca_file = get("AV_KAFKA_CA_FILE").map(std::path::PathBuf::from);
        let credentials = match (get("AV_KAFKA_SASL_USERNAME"), get("AV_KAFKA_SASL_PASSWORD")) {
            (Some(username), Some(password)) => Some((username, password)),
            (None, None) => None,
            _ => {
                return Err(BusError::Backend(
                    "AV_KAFKA_SASL_USERNAME and AV_KAFKA_SASL_PASSWORD must be set together".to_owned(),
                ))
            }
        };
        let mechanism = match get("AV_KAFKA_SASL_MECHANISM") {
            Some(value) => SaslMechanism::parse(&value)?,
            None => SaslMechanism::ScramSha256,
        };
        if credentials.is_some() && ca_file.is_none() {
            return Err(BusError::Backend(
                "Kafka SASL credentials require AV_KAFKA_CA_FILE: PLAIN ships the password in \
                 the clear and even SCRAM without TLS is exposed to MITM relay"
                    .to_owned(),
            ));
        }
        Ok(Self {
            ca_file,
            credentials,
            mechanism,
        })
    }

    /// librdkafka admin-client settings mirroring the rskafka event path.
    fn apply_admin(&self, config: &mut ClientConfig) {
        let protocol = match (&self.ca_file, &self.credentials) {
            (Some(_), Some(_)) => "sasl_ssl",
            (Some(_), None) => "ssl",
            (None, _) => return,
        };
        config.set("security.protocol", protocol);
        if let Some(ca) = &self.ca_file {
            config.set("ssl.ca.location", ca.to_string_lossy().as_ref());
        }
        if let Some((username, password)) = &self.credentials {
            config.set("sasl.mechanism", self.mechanism.librdkafka_name());
            config.set("sasl.username", username);
            config.set("sasl.password", password);
        }
    }

    /// Root-pinned rustls config for the rskafka event path.
    fn rskafka_tls(&self) -> Result<Option<Arc<rustls_tls::ClientConfig>>, BusError> {
        let Some(ca) = &self.ca_file else {
            return Ok(None);
        };
        // Same provider discipline as NatsBus::provision: rustls 0.23
        // resolves its process CryptoProvider lazily and panics when both
        // `ring` and `aws-lc-rs` are compiled in with none installed.
        let _ = rustls_tls::crypto::ring::default_provider().install_default();
        let pem = std::fs::read(ca)
            .map_err(|error| BusError::Backend(format!("Kafka CA file {}: {error}", ca.display())))?;
        use rustls_pki_types::pem::PemObject as _;
        let mut roots = rustls_tls::RootCertStore::empty();
        let mut certs = 0usize;
        for cert in rustls_pki_types::CertificateDer::pem_slice_iter(&pem) {
            let cert = cert
                .map_err(|error| BusError::Backend(format!("Kafka CA file {}: {error:?}", ca.display())))?;
            roots
                .add(cert)
                .map_err(|error| BusError::Backend(format!("Kafka CA file {}: {error}", ca.display())))?;
            certs = certs.saturating_add(1);
        }
        if certs == 0 {
            return Err(BusError::Backend(format!(
                "Kafka CA file {} contains no PEM certificates",
                ca.display()
            )));
        }
        let config = rustls_tls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Some(Arc::new(config)))
    }

    fn rskafka_sasl(&self) -> Option<SaslConfig> {
        self.credentials.as_ref().map(|(username, password)| {
            let credentials = rskafka::client::Credentials::new(username.clone(), password.clone());
            match self.mechanism {
                SaslMechanism::Plain => SaslConfig::Plain(credentials),
                SaslMechanism::ScramSha256 => SaslConfig::ScramSha256(credentials),
                SaslMechanism::ScramSha512 => SaslConfig::ScramSha512(credentials),
            }
        })
    }
}

/// Kafka/Redpanda bus.
pub struct KafkaBus {
    cold_archive: Option<crate::cold_store::ColdArchive>,
    executor: crate::bus::ConnectorExecutor,
    /// Per-(topic, partition) clients built once at provision. rskafka's
    /// `Client::partition_client` performs metadata discovery and broker
    /// connection setup; constructing one per publish flooded the broker
    /// under 10k-connection load until audit publishes stalled admission
    /// past the upstream timeout (observed as 502s in the 10k SLA gate).
    /// The `Client` itself is not retained: partition clients hold their
    /// own broker references, and every post-provision operation goes
    /// through this cache.
    partition_clients: HashMap<(String, u32), Arc<rskafka::client::partition::PartitionClient>>,
    topics: HashMap<String, u32>,
    validators: HashMap<String, jsonschema::Validator>,
}

impl KafkaBus {
    /// Connect to `broker` (host:port) and provision topics per the manifest.
    pub fn provision(broker: &str, manifest: &BridgeManifest) -> Result<Self, BusError> {
        manifest
            .validate()
            .map_err(|e| BusError::Backend(e.to_string()))?;
        let validators = crate::manifest::compile_topic_validators(manifest)?;
        let cold_archive = crate::cold_store::ColdArchive::from_manifest(manifest)?;
        let executor = crate::bus::ConnectorExecutor::new("agentvisor-ai-kafka")?;
        let security = KafkaSecurity::from_env()?;
        let mut admin_config = ClientConfig::new();
        admin_config
            .set("bootstrap.servers", broker)
            .set("socket.timeout.ms", "10000");
        security.apply_admin(&mut admin_config);
        let admin: AdminClient<DefaultClientContext> = admin_config
            .create()
            .map_err(|error| BusError::Backend(error.to_string()))?;
        let admin = Arc::new(admin);
        for topic in &manifest.topics {
            let admin = Arc::clone(&admin);
            let name = topic.name.clone();
            let partitions = topic.partitions;
            let replication_factor = manifest.replication_factor;
            let retention_ms = u64::from(topic.retention.hot_hours)
                .checked_mul(av_core::units::MS_PER_HOUR)
                .ok_or_else(|| BusError::Backend("Kafka retention overflow".to_owned()))?
                .to_string();
            executor
                .run(move || provision_topic(admin, name, partitions, replication_factor, retention_ms))?
                .map_err(BusError::Backend)?;
        }
        drop(admin);
        // `broker` is a bootstrap list (`host:port[,host:port]`, the same
        // format rdkafka's `bootstrap.servers` takes above). rskafka wants
        // one address per element — passing the joined string as a single
        // entry made every multi-broker list fail to connect.
        let brokers: Vec<String> = broker
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .map(str::to_owned)
            .collect();
        if brokers.is_empty() {
            return Err(BusError::Backend("Kafka bootstrap list is empty".to_owned()));
        }
        let tls_config = security.rskafka_tls()?;
        let sasl_config = security.rskafka_sasl();
        let client = executor
            .run(move || async move {
                let mut builder = ClientBuilder::new(brokers);
                if let Some(tls) = tls_config {
                    builder = builder.tls_config(tls);
                }
                if let Some(sasl) = sasl_config {
                    builder = builder.sasl_config(sasl);
                }
                builder.build().await
            })?
            .map_err(|e| BusError::Backend(e.to_string()))?;
        let client = Arc::new(client);
        let mut topics = HashMap::new();
        for t in &manifest.topics {
            topics.insert(t.name.clone(), t.partitions);
        }
        let metadata_client = Arc::clone(&client);
        let metadata = executor
            .run(move || async move { metadata_client.list_topics().await })?
            .map_err(|error| BusError::Backend(error.to_string()))?;
        for expected in &manifest.topics {
            let actual = metadata
                .iter()
                .find(|topic| topic.name == expected.name)
                .ok_or_else(|| BusError::Backend(format!("Kafka topic {:?} is missing", expected.name)))?;
            if actual.partitions.len() != expected.partitions as usize {
                return Err(BusError::Backend(format!(
                    "Kafka topic {:?} has {} partitions, manifest requires {}",
                    expected.name,
                    actual.partitions.len(),
                    expected.partitions
                )));
            }
        }
        let mut partition_clients = HashMap::new();
        for t in &manifest.topics {
            for p in 0..t.partitions {
                let pc_client = Arc::clone(&client);
                let name = t.name.clone();
                let pc = executor
                    .run(move || async move {
                        pc_client
                            .partition_client(name, p as i32, UnknownTopicHandling::Error)
                            .await
                    })?
                    .map_err(|error| BusError::Backend(error.to_string()))?;
                partition_clients.insert((t.name.clone(), p), Arc::new(pc));
            }
        }
        Ok(Self {
            cold_archive,
            executor,
            partition_clients,
            topics,
            validators,
        })
    }

    /// Cached per-partition client (built at provision; see struct docs).
    fn partition_client(
        &self,
        topic: &str,
        partition: u32,
    ) -> Result<Arc<rskafka::client::partition::PartitionClient>, BusError> {
        self.partition_clients
            .get(&(topic.to_owned(), partition))
            .cloned()
            .ok_or_else(|| BusError::UnknownTopic(topic.to_owned()))
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
        let pc = self.partition_client(topic, partition)?;
        let key_bytes = event_uid.as_bytes().to_vec();
        let mut headers = std::collections::BTreeMap::new();
        headers.insert("agentvisor-event-uid".to_owned(), event_uid.as_bytes().to_vec());
        let offset = self
            .executor
            .run(move || async move {
                let offsets = pc
                    .produce(
                        vec![Record {
                            key: Some(key_bytes),
                            value: Some(payload),
                            headers,
                            timestamp: chrono_now(),
                        }],
                        Compression::NoCompression,
                    )
                    .await?;
                // One record in => exactly one offset out. An empty response
                // is a broker anomaly; fabricating offset 0 here would persist
                // a legitimate-looking ack that dedupe/recovery then trusts.
                Ok::<_, rskafka::client::error::Error>(offsets.first().copied())
            })?
            .map_err(|e| BusError::Backend(e.to_string()))?;
        let offset = offset.ok_or_else(|| {
            BusError::Backend("Kafka produce succeeded but returned no offset for the record".to_owned())
        })?;
        let offset = u64::try_from(offset)
            .map_err(|_| BusError::Backend(format!("Kafka returned negative offset {offset}")))?;
        Ok(PublishAck {
            topic: topic.to_owned(),
            partition,
            offset,
        })
    }
}

async fn provision_topic(
    admin: Arc<AdminClient<DefaultClientContext>>,
    name: String,
    partitions: u32,
    replication_factor: u32,
    retention_ms: String,
) -> Result<(), String> {
    let partitions = i32::try_from(partitions)
        .map_err(|_| format!("partition count for Kafka topic {name:?} exceeds i32"))?;
    let replication_factor = i32::try_from(replication_factor)
        .map_err(|_| format!("replication factor for Kafka topic {name:?} exceeds i32"))?;
    let topic = NewTopic::new(&name, partitions, TopicReplication::Fixed(replication_factor))
        .set("retention.ms", &retention_ms);
    let results = admin
        .create_topics(
            [&topic],
            &AdminOptions::new().operation_timeout(Some(std::time::Duration::from_secs(5))),
        )
        .await
        .map_err(|error| error.to_string())?;
    match results.into_iter().next() {
        Some(Ok(_)) | Some(Err((_, RDKafkaErrorCode::TopicAlreadyExists))) => {}
        Some(Err((_, error))) => return Err(format!("create Kafka topic {name:?}: {error}")),
        None => return Err(format!("create Kafka topic {name:?} returned no result")),
    }

    let resource = ResourceSpecifier::Topic(&name);
    let results = admin
        .describe_configs([&resource], &AdminOptions::new())
        .await
        .map_err(|error| error.to_string())?;
    let configuration = results
        .into_iter()
        .next()
        .ok_or_else(|| format!("describe Kafka topic {name:?} returned no result"))?
        .map_err(|error| format!("describe Kafka topic {name:?}: {error}"))?;
    let actual = configuration
        .get("retention.ms")
        .and_then(|entry| entry.value.as_deref());
    if actual != Some(retention_ms.as_str()) {
        return Err(format!(
            "Kafka topic {name:?} retention.ms is {actual:?}, manifest requires {retention_ms:?}"
        ));
    }
    Ok(())
}

impl EventBus for KafkaBus {
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
        let partition_client = self.partition_client(topic, partition)?;
        let event_uid = event_uid.to_owned();
        // One page per `executor.run` call: the executor imposes a hard
        // 10 s timeout per operation, so running the whole earliest→latest
        // scan inside a single call made lookups on partitions larger than
        // one timeout's worth of fetches time out on every attempt, forever
        // (each retry restarted from earliest under the same cap). Paging
        // gives each bounded step its own budget — the same shape as the
        // NATS implementation and the default trait implementation's
        // per-`fetch` paging.
        enum Page {
            Found(i64),
            Advanced(i64),
            Empty,
        }
        let (mut offset, latest) = {
            let client = Arc::clone(&partition_client);
            self.executor
                .run(move || async move {
                    let earliest = client
                        .get_offset(OffsetAt::Earliest)
                        .await
                        .map_err(|error| error.to_string())?;
                    let latest = client
                        .get_offset(OffsetAt::Latest)
                        .await
                        .map_err(|error| error.to_string())?;
                    Ok::<_, String>((earliest, latest))
                })?
                .map_err(BusError::Backend)?
        };
        let mut empty_fetches = 0u32;
        let found = loop {
            if offset >= latest {
                break None;
            }
            let client = Arc::clone(&partition_client);
            let page_uid = event_uid.clone();
            let page = self
                .executor
                .run(move || async move {
                    let (records, _) = client
                        .fetch_records(offset, 1..(16 * 1024 * 1024), 500)
                        .await
                        .map_err(|error| error.to_string())?;
                    if records.is_empty() {
                        return Ok::<_, String>(Page::Empty);
                    }
                    for record in &records {
                        // `publish_with_uid` stamps the (possibly freshly
                        // generated) uid into the `agentvisor-event-uid`
                        // header even when the payload lacks
                        // `metadata.uid`. Crash recovery for such an
                        // event previously scanned only the payload
                        // field, could never find the record it had in
                        // fact produced, and re-published a duplicate.
                        // Consult the header first, then the payload.
                        if record
                            .record
                            .headers
                            .get("agentvisor-event-uid")
                            .is_some_and(|uid| uid.as_slice() == page_uid.as_bytes())
                        {
                            return Ok(Page::Found(record.offset));
                        }
                        if let Some(payload) = record.record.value.as_deref() {
                            let stored: StoredEvent =
                                serde_json::from_slice(payload).map_err(|error| error.to_string())?;
                            if stored
                                .value
                                .get("metadata")
                                .and_then(|metadata| metadata.get("uid"))
                                .and_then(serde_json::Value::as_str)
                                == Some(page_uid.as_str())
                            {
                                return Ok(Page::Found(record.offset));
                            }
                        }
                    }
                    let next = records
                        .last()
                        .and_then(|record| record.offset.checked_add(1))
                        .ok_or_else(|| "Kafka event lookup offset overflow".to_owned())?;
                    Ok(Page::Advanced(next))
                })?
                .map_err(BusError::Backend)?;
            match page {
                Page::Found(found_offset) => break Some(found_offset),
                Page::Advanced(next) => {
                    empty_fetches = 0;
                    offset = next;
                }
                Page::Empty => {
                    // `offset < latest` proves the broker still holds
                    // records we have not seen; an empty response here is
                    // a timing artifact (the 500 ms max_wait expired on a
                    // loaded/rebalancing broker), NOT proof of absence.
                    // Returning Ok(None) would let maintenance re-produce
                    // an already-committed event — a duplicate in the
                    // audit stream, the exact outcome this lookup exists
                    // to prevent. Retry bounded, then fail the lookup so
                    // the caller retries the whole pass later (the cold
                    // intent is durable).
                    empty_fetches += 1;
                    if empty_fetches >= 8 {
                        return Err(BusError::Backend(format!(
                            "Kafka event lookup stalled: empty fetch at offset {offset} below latest {latest}"
                        )));
                    }
                }
            }
        };
        found
            .map(|offset| {
                u64::try_from(offset)
                    .map(|offset| PublishAck {
                        topic: topic.to_owned(),
                        partition,
                        offset,
                    })
                    .map_err(|_| BusError::Backend(format!("Kafka returned negative offset {offset}")))
            })
            .transpose()
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
        let pc = self.partition_client(topic, partition)?;
        // Reject offsets above
        // `i64::MAX` explicitly rather than let `as i64` sign-wrap
        // into a negative Kafka offset. The Kafka wire protocol
        // treats -1 as "latest" and -2 as "earliest" (its own
        // sentinel semantics), so a wrap could silently redirect
        // the fetch to the log tail instead of the requested
        // offset — a hard-to-diagnose replay divergence. In
        // practice `u64` offsets that survive our provisioning
        // stay well below 2^63, but crash recovery from a
        // manifest whose offset field was tampered on disk could
        // still supply a value in `(i64::MAX, u64::MAX]`.
        let signed_offset = i64::try_from(offset).map_err(|_| {
            BusError::Backend(format!(
                "kafka fetch offset {offset} exceeds i64::MAX and would wrap to a negative \
                 sentinel; refusing the fetch"
            ))
        })?;
        // Contract: "read up to `max` events". The loop below checks the
        // cap only AFTER pushing, so `max == 0` returned one event —
        // diverging from the embedded broker, which returns an empty vec.
        if max == 0 {
            return Ok(Vec::new());
        }
        self.executor
            .run(move || async move {
                let (records, _high_watermark) = pc
                    .fetch_records(signed_offset, 1..(16 * 1024 * 1024), 500)
                    .await
                    .map_err(|e| e.to_string())?;
                let mut out = Vec::new();
                for r in records {
                    // Surface the error instead of silently
                    // dropping a corrupt record. Parity with NatsBus and
                    // EmbeddedBroker. An auditor or reconciler that sees a
                    // shorter list than expected — with no error and no
                    // offset gap — is an evidence gap. Because reconcilers
                    // advance offset by `events.last().offset + 1`, a
                    // silently-skipped corrupt record at offset N causes
                    // the caller to bypass it entirely; keep the record on
                    // the partition as forensic evidence.
                    let value = r
                        .record
                        .value
                        .ok_or_else(|| format!("fetch: null record value at offset {}", r.offset))?;
                    let mut ev: StoredEvent = serde_json::from_slice(&value)
                        .map_err(|e| format!("fetch decode at offset {}: {e}", r.offset))?;
                    // Kafka offsets are non-negative by contract; a broken
                    // or hostile broker returning a negative i64 must fail
                    // the fetch instead of sign-wrapping into a huge u64
                    // that corrupts the caller's offset ledger.
                    ev.offset = u64::try_from(r.offset)
                        .map_err(|_| format!("fetch: negative broker offset {}", r.offset))?;
                    out.push(ev);
                    if out.len() >= max {
                        break;
                    }
                }
                Ok::<_, String>(out)
            })?
            .map_err(BusError::Backend)
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
                // A crash/timeout between a successful produce and
                // `commit()` leaves the intent offset-None while the event
                // IS already on the partition; blindly re-producing here
                // would append a duplicate to the audit stream. Consult the
                // partition first and only publish when the UID is
                // genuinely absent.
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

fn chrono_now() -> chrono::DateTime<chrono::Utc> {
    chrono::Utc::now()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn lookup<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |name| {
            pairs
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| (*value).to_owned())
        }
    }

    #[test]
    fn no_security_env_means_plaintext_with_no_admin_overrides() {
        let security = KafkaSecurity::from_lookup(lookup(&[])).unwrap();
        assert!(security.ca_file.is_none() && security.credentials.is_none());
        let mut config = ClientConfig::new();
        security.apply_admin(&mut config);
        assert!(config.get("security.protocol").is_none());
        assert!(security.rskafka_tls().unwrap().is_none());
        assert!(security.rskafka_sasl().is_none());
    }

    #[test]
    fn partial_credentials_fail_loudly_not_anonymously() {
        for pairs in [
            &[("AV_KAFKA_SASL_USERNAME", "u")][..],
            &[("AV_KAFKA_SASL_PASSWORD", "p")][..],
        ] {
            // No `unwrap_err`: that would require `Debug` on `KafkaSecurity`,
            // and a derived `Debug` would make the SASL password printable.
            let Err(error) = KafkaSecurity::from_lookup(lookup(pairs)) else {
                panic!("partial credentials must be refused");
            };
            assert!(
                error.to_string().contains("must be set together"),
                "wrong error: {error}"
            );
        }
    }

    #[test]
    fn sasl_plain_without_tls_is_refused() {
        let Err(error) = KafkaSecurity::from_lookup(lookup(&[
            ("AV_KAFKA_SASL_USERNAME", "u"),
            ("AV_KAFKA_SASL_PASSWORD", "p"),
        ])) else {
            panic!("SASL without TLS must be refused");
        };
        assert!(error.to_string().contains("AV_KAFKA_CA_FILE"), "{error}");
    }

    #[test]
    fn ca_only_selects_ssl_and_ca_plus_credentials_selects_sasl_ssl() {
        let ssl_only = KafkaSecurity::from_lookup(lookup(&[("AV_KAFKA_CA_FILE", "/tmp/ca.crt")])).unwrap();
        let mut config = ClientConfig::new();
        ssl_only.apply_admin(&mut config);
        assert_eq!(config.get("security.protocol"), Some("ssl"));
        assert_eq!(config.get("ssl.ca.location"), Some("/tmp/ca.crt"));
        assert!(config.get("sasl.mechanism").is_none());

        let full = KafkaSecurity::from_lookup(lookup(&[
            ("AV_KAFKA_CA_FILE", "/tmp/ca.crt"),
            ("AV_KAFKA_SASL_USERNAME", "u"),
            ("AV_KAFKA_SASL_PASSWORD", "p"),
        ]))
        .unwrap();
        let mut config = ClientConfig::new();
        full.apply_admin(&mut config);
        assert_eq!(config.get("security.protocol"), Some("sasl_ssl"));
        // SCRAM-SHA-256 is the default mechanism (Redpanda's native store).
        assert_eq!(config.get("sasl.mechanism"), Some("SCRAM-SHA-256"));
        assert_eq!(config.get("sasl.username"), Some("u"));
        match full.rskafka_sasl() {
            Some(SaslConfig::ScramSha256(credentials)) => {
                assert_eq!(credentials.username, "u");
                assert_eq!(credentials.password, "p");
            }
            other => panic!("expected SCRAM-SHA-256 sasl config, got {other:?}"),
        }
    }

    /// Every supported mechanism maps consistently onto both client stacks,
    /// and unknown mechanisms fail loudly instead of downgrading.
    #[test]
    fn sasl_mechanism_selection_is_explicit_and_validated() {
        for (name, is_match) in [
            (
                "PLAIN",
                (|s| matches!(s, Some(SaslConfig::Plain(_)))) as fn(Option<SaslConfig>) -> bool,
            ),
            ("SCRAM-SHA-256", |s| matches!(s, Some(SaslConfig::ScramSha256(_)))),
            ("SCRAM-SHA-512", |s| matches!(s, Some(SaslConfig::ScramSha512(_)))),
        ] {
            let security = KafkaSecurity::from_lookup(lookup(&[
                ("AV_KAFKA_CA_FILE", "/tmp/ca.crt"),
                ("AV_KAFKA_SASL_USERNAME", "u"),
                ("AV_KAFKA_SASL_PASSWORD", "p"),
                ("AV_KAFKA_SASL_MECHANISM", name),
            ]))
            .unwrap();
            let mut config = ClientConfig::new();
            security.apply_admin(&mut config);
            assert_eq!(config.get("sasl.mechanism"), Some(name));
            assert!(is_match(security.rskafka_sasl()), "{name} must map on rskafka");
        }
        let Err(error) = KafkaSecurity::from_lookup(lookup(&[
            ("AV_KAFKA_CA_FILE", "/tmp/ca.crt"),
            ("AV_KAFKA_SASL_USERNAME", "u"),
            ("AV_KAFKA_SASL_PASSWORD", "p"),
            ("AV_KAFKA_SASL_MECHANISM", "GSSAPI"),
        ])) else {
            panic!("unsupported mechanism must be refused");
        };
        assert!(error.to_string().contains("not supported"), "{error}");
    }

    #[test]
    fn missing_or_empty_ca_file_fails_loudly() {
        let missing = KafkaSecurity {
            ca_file: Some(std::path::PathBuf::from("/nonexistent/av-ca.crt")),
            credentials: None,
            mechanism: SaslMechanism::ScramSha256,
        };
        assert!(missing.rskafka_tls().is_err(), "missing CA file must error");

        let dir = tempfile::tempdir().unwrap();
        let empty = dir.path().join("empty.pem");
        std::fs::write(&empty, b"not a pem").unwrap();
        let security = KafkaSecurity {
            ca_file: Some(empty),
            credentials: None,
            mechanism: SaslMechanism::ScramSha256,
        };
        let error = security.rskafka_tls().unwrap_err();
        assert!(
            error.to_string().contains("no PEM certificates"),
            "wrong error: {error}"
        );
    }
}
