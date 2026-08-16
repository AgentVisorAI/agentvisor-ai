//! Live-broker contract tests, env-gated (AV_NATS_URL / AV_KAFKA_BROKER) and
//! loudly skipped otherwise (D13.21). The same behavioral contract as the
//! embedded suite: publish → ack, offset-ordered fetch, unknown-topic error.
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
