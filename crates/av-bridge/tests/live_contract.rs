//! Live-broker contract tests, env-gated (AV_NATS_URL / AV_KAFKA_BROKER) and
//! loudly skipped otherwise (D13.21). The same behavioral contract as the
//! embedded suite: publish → ack, offset-ordered fetch, unknown-topic error.
//!
//! Secured-endpoint material (all optional): `AV_KAFKA_CA_FILE` +
//! `AV_KAFKA_SASL_USERNAME`/`AV_KAFKA_SASL_PASSWORD` for TLS+SASL/PLAIN
//! Kafka; `AV_NATS_CA_FILE` (forces TLS) + `AV_NATS_USER`/`AV_NATS_PASSWORD`
//! for NATS. `AV_KAFKA_BROKER` accepts a `host:port[,host:port]` bootstrap
//! list. Use hostname endpoints with TLS (certificate name verification).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use av_bridge::BridgeManifest;
#[allow(unused_imports)]
use av_bridge::EventBus;
use serde_json::json;

#[allow(dead_code)]
fn contract(bus: &dyn EventBus) {
    let key = format!("inst-{}", av_core::new_event_uid());
    let mut offsets = Vec::new();
    for i in 0..5 {
        let event = av_events::OcsfEventBuilder::new(
            av_events::EventClass::ToolCall,
            "live-contract",
            av_events::AgentIdentity {
                version: "1".into(),
                charter: "contract".into(),
                instance_uid: key.clone(),
                ttl_remaining_s: Some(60),
            },
            i,
        )
        .payload(json!({"i": i}))
        .build()
        .unwrap();
        let ack = bus
            .publish("agent.tool_call", &key, &serde_json::to_value(event).unwrap())
            .unwrap();
        offsets.push(ack.offset);
    }
    assert!(
        offsets.windows(2).all(|w| w[1] > w[0]),
        "offsets not increasing: {offsets:?}"
    );
    let partition = av_bridge::bus::partition_for(&key, bus.partitions("agent.tool_call").unwrap());
    let events = bus.fetch("agent.tool_call", partition, offsets[0], 50).unwrap();
    let mine: Vec<_> = events.iter().filter(|e| e.key == key).collect();
    assert_eq!(mine.len(), 5, "lost events for {key}");
    for (i, e) in mine.iter().enumerate() {
        assert_eq!(e.value["payload"]["i"], i);
    }
    // Start-offset semantics: a fetch from the middle must not replay this
    // key's earlier records (kills a deliver-policy regression where the
    // backend silently falls back to delivering from the beginning).
    let tail = bus.fetch("agent.tool_call", partition, offsets[3], 50).unwrap();
    let mine_tail: Vec<_> = tail.iter().filter(|e| e.key == key).collect();
    assert_eq!(
        mine_tail.len(),
        2,
        "fetch from offsets[3] must return exactly the last two records for {key}, got {mine_tail:?}"
    );
    assert_eq!(mine_tail[0].value["payload"]["i"], 3);
    // Partition isolation: records published to a different partition must
    // never surface in this partition's fetch (kills a filter regression
    // where the backend reads the whole stream instead of one partition).
    let partitions = bus.partitions("agent.tool_call").unwrap();
    if partitions > 1 {
        let other_key = (0..u32::MAX)
            .map(|i| format!("other-{i}-{key}"))
            .find(|candidate| av_bridge::bus::partition_for(candidate, partitions) != partition)
            .unwrap();
        let other_event = av_events::OcsfEventBuilder::new(
            av_events::EventClass::ToolCall,
            "live-contract",
            av_events::AgentIdentity {
                version: "1".into(),
                charter: "contract".into(),
                instance_uid: other_key.clone(),
                ttl_remaining_s: Some(60),
            },
            0,
        )
        .payload(json!({"other": true}))
        .build()
        .unwrap();
        bus.publish(
            "agent.tool_call",
            &other_key,
            &serde_json::to_value(other_event).unwrap(),
        )
        .unwrap();
        let after = bus.fetch("agent.tool_call", partition, offsets[0], 100).unwrap();
        assert!(
            after.iter().all(|e| e.key != other_key),
            "record for {other_key} leaked across partitions into partition {partition}"
        );
    }
    // At-most-once dedupe primitive: crash recovery resolves committed
    // events by stable UID. A regression returning None here would make
    // recovery re-publish (duplicate effects); a wrong match would ack
    // the wrong offset.
    let probe_uid = av_core::new_event_uid();
    let probe = av_events::OcsfEventBuilder::new(
        av_events::EventClass::ToolCall,
        "live-contract",
        av_events::AgentIdentity {
            version: "1".into(),
            charter: "contract".into(),
            instance_uid: key.clone(),
            ttl_remaining_s: Some(60),
        },
        99,
    )
    .payload(json!({"probe": true}))
    .build()
    .unwrap();
    let mut probe_value = serde_json::to_value(probe).unwrap();
    probe_value["metadata"]["uid"] = json!(probe_uid);
    let probe_ack = bus.publish("agent.tool_call", &key, &probe_value).unwrap();
    let found = bus
        .find_event_by_uid("agent.tool_call", &key, &probe_uid)
        .unwrap()
        .expect("committed event must be found by uid");
    assert_eq!(found.partition, probe_ack.partition);
    assert_eq!(found.offset, probe_ack.offset);
    assert!(
        bus.find_event_by_uid("agent.tool_call", &key, "uid-that-never-existed")
            .unwrap()
            .is_none(),
        "unknown uid must resolve to None, not a fabricated ack"
    );
    assert!(bus.publish("agent.bogus", &key, &json!({})).is_err());
}

#[test]
#[cfg(feature = "nats")]
fn nats_contract() {
    let Ok(url) = std::env::var("AV_NATS_URL") else {
        eprintln!("SKIPPED (AV_NATS_URL unset): NATS contract test requires a live server");
        return;
    };
    let bus = av_bridge::nats_bus::NatsBus::provision(&url, &BridgeManifest::default_for("nats-test"))
        .expect("nats provision");
    contract(&bus);
}

#[test]
#[cfg(feature = "kafka")]
fn kafka_contract() {
    let Ok(broker) = std::env::var("AV_KAFKA_BROKER") else {
        eprintln!("SKIPPED (AV_KAFKA_BROKER unset): Kafka contract test requires a live broker");
        return;
    };
    let bus = av_bridge::kafka_bus::KafkaBus::provision(&broker, &BridgeManifest::default_for("kafka-test"))
        .expect("kafka provision");
    contract(&bus);
}

#[test]
fn manifest_is_the_full_provisioning_input() {
    // Portability sanity that runs everywhere: the manifest alone describes
    // everything a backend needs (validated fields only, no side channels).
    let m = BridgeManifest::default_for("portability");
    let yaml = m.to_yaml().unwrap();
    let back = BridgeManifest::from_yaml(&yaml).unwrap();
    assert_eq!(m, back);
    for t in &back.topics {
        assert!(t.partitions > 0 && t.retention.hot_hours > 0);
    }
}
