//! Embedded broker contract suite: provisioning-from-manifest-alone (R12),
//! ordered per-agent replay (R11), crash recovery incl. torn tails (D13.16),
//! retention + cold export (R13), and per-partition ordering under
//! interleaved publishers (D13.14).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use ab_bridge::{BridgeManifest, EmbeddedBroker, EventBus};
use serde_json::json;
use std::io::Write;

fn manifest() -> BridgeManifest {
    BridgeManifest::default_for("test-enclave")
}

#[test]
fn provision_from_manifest_alone_and_reopen_identically() {
    let dir = tempfile::tempdir().unwrap();
    let started = std::time::Instant::now();
    let broker = EmbeddedBroker::provision(dir.path(), &manifest()).unwrap();
    let elapsed = started.elapsed();
    // R30 says < 15 minutes; the embedded path must be near-instant.
    assert!(elapsed.as_secs() < 60, "provisioning took {elapsed:?}");
    assert_eq!(broker.topics().len(), manifest().topics.len());

    // A second bridge provisioned elsewhere from the same manifest is identical.
    let dir2 = tempfile::tempdir().unwrap();
    let broker2 = EmbeddedBroker::provision(dir2.path(), &manifest()).unwrap();
    assert_eq!(broker.topics(), broker2.topics());
    assert_eq!(broker.manifest(), broker2.manifest());

    // Double-provision refused.
    assert!(EmbeddedBroker::provision(dir.path(), &manifest()).is_err());

    // Reopen recovers the same shape.
    drop(broker);
    let reopened = EmbeddedBroker::open(dir.path()).unwrap();
    assert_eq!(reopened.topics(), broker2.topics());
}

#[test]
fn publish_fetch_roundtrip_with_offsets() {
    let dir = tempfile::tempdir().unwrap();
    let broker = EmbeddedBroker::provision(dir.path(), &manifest()).unwrap();
    for i in 0..10 {
        let ack = broker.publish("agent.tool_call", "inst-A", &json!({"i": i})).unwrap();
        assert_eq!(ack.offset, i, "offsets must be dense and ordered");
    }
    let partition = broker.publish("agent.tool_call", "inst-A", &json!({"i": 10})).unwrap().partition;
    let events = broker.fetch("agent.tool_call", partition, 0, 100).unwrap();
    assert_eq!(events.len(), 11);
    for (i, e) in events.iter().enumerate() {
        assert_eq!(e.offset, i as u64);
        assert_eq!(e.value["i"], i);
        assert_eq!(e.key, "inst-A");
    }
    // Offset-based resume.
    let tail = broker.fetch("agent.tool_call", partition, 8, 100).unwrap();
    assert_eq!(tail.len(), 3);
    assert_eq!(tail[0].offset, 8);
    // max cap respected.
    let capped = broker.fetch("agent.tool_call", partition, 0, 4).unwrap();
    assert_eq!(capped.len(), 4);
}

#[test]
fn unknown_topic_is_an_error_not_autocreate() {
    let dir = tempfile::tempdir().unwrap();
    let broker = EmbeddedBroker::provision(dir.path(), &manifest()).unwrap();
    assert!(broker.publish("agent.nonexistent", "k", &json!({})).is_err());
    assert!(broker.fetch("agent.nonexistent", 0, 0, 10).is_err());
}

/// D13.14: interleaved publishers across many agents — each agent's stream
/// must replay in publish order from its partition.
#[test]
fn per_agent_ordering_survives_interleaving() {
    let dir = tempfile::tempdir().unwrap();
    let broker = std::sync::Arc::new(EmbeddedBroker::provision(dir.path(), &manifest()).unwrap());
    let mut handles = Vec::new();
    for agent in 0..8 {
        let broker = std::sync::Arc::clone(&broker);
        handles.push(std::thread::spawn(move || {
            let key = format!("inst-{agent}");
            for seq in 0..50u64 {
                broker.publish("agent.stop_reason", &key, &json!({"agent": agent, "seq": seq})).unwrap();
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    // Replay every partition; per-key seq must be strictly increasing.
    let nparts = broker.partitions("agent.stop_reason").unwrap();
    let mut per_agent_last: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
    let mut total = 0;
    for p in 0..nparts {
        let events = broker.fetch("agent.stop_reason", p, 0, 10_000).unwrap();
        for e in events {
            let seq = e.value["seq"].as_i64().unwrap();
            let last = per_agent_last.entry(e.key.clone()).or_insert(-1);
            assert!(seq > *last, "agent {} replayed out of order: {seq} after {last}", e.key);
            *last = seq;
            total += 1;
        }
    }
    assert_eq!(total, 8 * 50, "events lost");
}

#[test]
fn crash_recovery_preserves_offsets_and_truncates_torn_tail() {
    let dir = tempfile::tempdir().unwrap();
    let partition;
    {
        let broker = EmbeddedBroker::provision(dir.path(), &manifest()).unwrap();
        for i in 0..5 {
            broker.publish("agent.session", "inst-X", &json!({"i": i})).unwrap();
        }
        partition = broker.publish("agent.session", "inst-X", &json!({"i": 5})).unwrap().partition;
    } // "crash"

    // Simulate a torn write: append half a record with no newline.
    let seg = dir.path().join("topics").join("agent.session").join(format!("p{partition}.jsonl"));
    {
        let mut f = std::fs::OpenOptions::new().append(true).open(&seg).unwrap();
        f.write_all(br#"{"partition":0,"offset":6,"key":"inst-X","va"#).unwrap();
    }

    let reopened = EmbeddedBroker::open(dir.path()).unwrap();
    assert_eq!(reopened.recovered_torn_lines, 1, "torn tail must be counted, not silent");
    // Next publish continues at offset 6 (the torn 6 was discarded).
    let ack = reopened.publish("agent.session", "inst-X", &json!({"i": "after-crash"})).unwrap();
    assert_eq!(ack.offset, 6);
    let events = reopened.fetch("agent.session", partition, 0, 100).unwrap();
    assert_eq!(events.len(), 7);
    assert_eq!(events[6].value["i"], "after-crash");
}

#[test]
fn retention_expires_to_cold_tier() {
    let dir = tempfile::tempdir().unwrap();
    let cold = tempfile::tempdir().unwrap();
    let mut m = manifest();
    for t in &mut m.topics {
        t.retention.hot_hours = 1;
        t.retention.cold_uri = Some(cold.path().to_string_lossy().to_string());
    }
    let broker = EmbeddedBroker::provision(dir.path(), &m).unwrap();
    let p = broker.publish("agent.receipt", "inst-R", &json!({"old": true})).unwrap().partition;

    // Two hours later, the record is beyond the 1h hot window.
    let later = ab_core::time::now_ms() + 2 * 3_600_000;
    let expired = broker.enforce_retention(later).unwrap();
    assert_eq!(expired, 1);

    // Gone from hot…
    let hot = broker.fetch("agent.receipt", p, 0, 10).unwrap();
    assert!(hot.is_empty(), "expired record still hot: {hot:?}");
    // …present in cold.
    let cold_file = cold.path().join("agent.receipt").join(format!("p{p}.jsonl"));
    let cold_content = std::fs::read_to_string(&cold_file).unwrap();
    assert!(cold_content.contains("\"old\":true"), "{cold_content}");

    // Fresh records survive retention.
    broker.publish("agent.receipt", "inst-R", &json!({"fresh": true})).unwrap();
    let expired = broker.enforce_retention(ab_core::time::now_ms()).unwrap();
    assert_eq!(expired, 0);
}

#[test]
fn schema_validated_provisioning_rejects_invalid_manifest() {
    let dir = tempfile::tempdir().unwrap();
    let mut m = manifest();
    m.topics[0].partitions = 0;
    assert!(EmbeddedBroker::provision(dir.path(), &m).is_err());
    assert!(!dir.path().join("manifest.yaml").exists(), "invalid manifest must not be persisted");
}
