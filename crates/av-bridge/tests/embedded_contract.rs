//! Embedded broker contract suite: provisioning-from-manifest-alone (R12),
//! ordered per-agent replay (R11), crash recovery incl. torn tails (D13.16),
//! retention + cold export (R13), and per-partition ordering under
//! interleaved publishers (D13.14).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use av_bridge::{BridgeManifest, EmbeddedBroker, EventBus};
use serde_json::json;
use std::io::Write;

fn manifest() -> BridgeManifest {
    let mut manifest = BridgeManifest::default_for("test-enclave");
    for topic in &mut manifest.topics {
        topic.schema_ref = None;
    }
    manifest
}

#[test]
fn provision_from_manifest_alone_and_reopen_identically() {
    let dir = tempfile::tempdir().unwrap();
    let portable_manifest = BridgeManifest::default_for("test-enclave");
    let started = std::time::Instant::now();
    let broker = EmbeddedBroker::provision(dir.path(), &portable_manifest).unwrap();
    let elapsed = started.elapsed();
    // R30 says < 15 minutes; the embedded path must be near-instant.
    assert!(elapsed.as_secs() < 60, "provisioning took {elapsed:?}");
    assert_eq!(broker.topics().len(), portable_manifest.topics.len());
    assert!(dir.path().join("schemas/ocsf-agent-event.schema.json").exists());

    // A second bridge provisioned elsewhere from the same manifest is identical.
    let dir2 = tempfile::tempdir().unwrap();
    let broker2 = EmbeddedBroker::provision(dir2.path(), &portable_manifest).unwrap();
    assert_eq!(broker.topics(), broker2.topics());
    assert_eq!(broker.manifest(), broker2.manifest());

    // Double-provision refused.
    assert!(EmbeddedBroker::provision(dir.path(), &portable_manifest).is_err());

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
        let ack = broker
            .publish("agent.tool_call", "inst-A", &json!({"i": i}))
            .unwrap();
        assert_eq!(ack.offset, i, "offsets must be dense and ordered");
    }
    let partition = broker
        .publish("agent.tool_call", "inst-A", &json!({"i": 10}))
        .unwrap()
        .partition;
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
fn event_uid_publication_is_idempotent_across_restart() {
    let dir = tempfile::tempdir().unwrap();
    let value = json!({
        "metadata": {"uid": "event-uid-1"},
        "payload": {"value": 1}
    });
    let first = {
        let broker = EmbeddedBroker::provision(dir.path(), &manifest()).unwrap();
        let first = broker
            .publish_idempotent("agent.session", "inst-A", &value, "event-uid-1")
            .unwrap();
        let retry = broker
            .publish_idempotent("agent.session", "inst-A", &value, "event-uid-1")
            .unwrap();
        assert_eq!(retry, first);
        assert_eq!(
            broker
                .fetch("agent.session", first.partition, first.offset, 10)
                .unwrap()
                .len(),
            1
        );
        first
    };

    let reopened = EmbeddedBroker::open(dir.path()).unwrap();
    let retry = reopened
        .publish_idempotent("agent.session", "inst-A", &value, "event-uid-1")
        .unwrap();
    assert_eq!(retry, first);
    assert_eq!(
        reopened
            .fetch("agent.session", first.partition, first.offset, 10)
            .unwrap()
            .len(),
        1
    );
}

/// The idempotency UID must MATCH the event's embedded `metadata.uid`
/// — a mismatch means the dedupe key and the recovery scan would
/// disagree about the event's identity (crash recovery rebuilds the
/// sidecar from `metadata.uid`, so an event published under a
/// different dedupe UID would stop deduplicating after a restart).
/// Mutation-run hardening (round 9): the mismatch guard had a
/// surviving guard→false mutant — the refusal was never asserted.
#[test]
fn mismatched_metadata_uid_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let broker = EmbeddedBroker::provision(dir.path(), &manifest()).unwrap();
    let error = broker
        .publish_idempotent(
            "agent.session",
            "inst-A",
            &json!({"metadata": {"uid": "uid-embedded"}, "value": 1}),
            "uid-argument",
        )
        .unwrap_err();
    assert!(
        error.to_string().contains("does not match"),
        "mismatched dedupe/metadata UIDs must be refused: {error}"
    );
}

/// `maintenance` returns the number of hot records it expired — the
/// count feeds operator metrics. Mutation-run hardening (round 9):
/// constant-return mutants (Ok(0)/Ok(1)) survived because no test
/// asserted the count, only side effects. Age two of three records
/// past the retention window and pin the exact count.
#[test]
fn maintenance_reports_the_exact_expiry_count() {
    let dir = tempfile::tempdir().unwrap();
    let broker = EmbeddedBroker::provision(dir.path(), &manifest()).unwrap();
    for i in 0..3 {
        broker
            .publish_idempotent(
                "agent.session",
                "inst-A",
                &json!({"metadata": {"uid": format!("exp-uid-{i}")}, "value": i}),
                &format!("exp-uid-{i}"),
            )
            .unwrap();
    }
    // Nothing is old yet: a maintenance pass expires zero.
    let now = av_core::time::now_ms();
    assert_eq!(broker.maintenance(now).unwrap(), 0, "fresh records must survive");
    // Pretend the clock jumped past the hot window for ALL records,
    // then verify the count is exactly 3 (not a constant).
    let hot_ms = 720u64 * 3600 * 1000;
    assert_eq!(
        broker.maintenance(now + hot_ms + 60_000).unwrap(),
        3,
        "every expired record must be counted"
    );
}

/// A retention crash-gap must not resurrect an already-published
/// event: when a record vanishes from the segment (rewrite crash
/// between segment and sidecar) but its offset lies INSIDE the
/// surviving records' offset range, the sidecar's UID→offset entry is
/// deliberately RETAINED so `publish_idempotent` still short-circuits
/// to the original ack instead of appending a duplicate audit event.
/// Mutation-run hardening (round 9): the `offset <= hi` half of the
/// range check had a surviving mutant — nothing exercised the
/// gap-offset shape.
#[test]
fn crash_gap_inside_offset_range_keeps_idempotency() {
    let dir = tempfile::tempdir().unwrap();
    let acks = {
        let broker = EmbeddedBroker::provision(dir.path(), &manifest()).unwrap();
        (0..3)
            .map(|i| {
                broker
                    .publish_idempotent(
                        "agent.session",
                        "inst-A",
                        &json!({"metadata": {"uid": format!("gap-uid-{i}")}, "value": i}),
                        &format!("gap-uid-{i}"),
                    )
                    .unwrap()
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(acks[1].offset, 1);

    // Simulate the crash: the MIDDLE record is gone from the segment,
    // the sidecar still remembers it.
    let segment = dir
        .path()
        .join("topics")
        .join("agent.session")
        .join(format!("p{}.jsonl", acks[0].partition));
    let surviving: Vec<String> = std::fs::read_to_string(&segment)
        .unwrap()
        .lines()
        .enumerate()
        .filter(|(i, _)| *i != 1)
        .map(|(_, line)| line.to_owned())
        .collect();
    std::fs::write(&segment, format!("{}\n", surviving.join("\n"))).unwrap();

    let reopened = EmbeddedBroker::open(dir.path()).unwrap();
    let retry = reopened
        .publish_idempotent(
            "agent.session",
            "inst-A",
            &json!({"metadata": {"uid": "gap-uid-1"}, "value": 1}),
            "gap-uid-1",
        )
        .unwrap();
    assert_eq!(
        retry, acks[1],
        "a gap-offset UID inside the surviving range must keep deduplicating \
         (a republish would mint a duplicate audit event)"
    );
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
                broker
                    .publish("agent.stop_reason", &key, &json!({"agent": agent, "seq": seq}))
                    .unwrap();
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
            assert!(
                seq > *last,
                "agent {} replayed out of order: {seq} after {last}",
                e.key
            );
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
            broker
                .publish("agent.session", "inst-X", &json!({"i": i}))
                .unwrap();
        }
        partition = broker
            .publish("agent.session", "inst-X", &json!({"i": 5}))
            .unwrap()
            .partition;
    } // "crash"

    // Simulate a torn write: append half a record with no newline.
    let seg = dir
        .path()
        .join("topics")
        .join("agent.session")
        .join(format!("p{partition}.jsonl"));
    {
        let mut f = std::fs::OpenOptions::new().append(true).open(&seg).unwrap();
        f.write_all(br#"{"partition":0,"offset":6,"key":"inst-X","va"#)
            .unwrap();
    }

    let reopened = EmbeddedBroker::open(dir.path()).unwrap();
    assert_eq!(
        reopened.recovered_torn_lines, 1,
        "torn tail must be counted, not silent"
    );
    // Next publish continues at offset 6 (the torn 6 was discarded).
    let ack = reopened
        .publish("agent.session", "inst-X", &json!({"i": "after-crash"}))
        .unwrap();
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
    let p = broker
        .publish("agent.receipt", "inst-R", &json!({"old": true}))
        .unwrap()
        .partition;

    // Two hours later, the record is beyond the 1h hot window.
    let later = av_core::time::now_ms() + 2 * 3_600_000;
    let expired = broker.enforce_retention(later).unwrap();
    assert_eq!(expired, 1);

    // Gone from hot…
    let hot = broker.fetch("agent.receipt", p, 0, 10).unwrap();
    assert!(hot.is_empty(), "expired record still hot: {hot:?}");
    // …present in cold.
    let cold_file = cold
        .path()
        .join("agent.receipt")
        .join(format!("p{p}"))
        .join("00000000000000000000.json");
    let cold_content = std::fs::read_to_string(&cold_file).unwrap();
    assert!(cold_content.contains("\"old\":true"), "{cold_content}");

    // Restart with an empty hot segment still resumes after offset 0.
    drop(broker);
    let broker = EmbeddedBroker::open(dir.path()).unwrap();
    let fresh = broker
        .publish("agent.receipt", "inst-R", &json!({"fresh": true}))
        .unwrap();
    assert_eq!(fresh.offset, 1, "full retention reset the high-watermark");
    let expired = broker.enforce_retention(av_core::time::now_ms()).unwrap();
    assert_eq!(expired, 0);
    drop(broker);
    let reopened = EmbeddedBroker::open(dir.path()).unwrap();
    let next = reopened
        .publish("agent.receipt", "inst-R", &json!({"after-restart": true}))
        .unwrap();
    assert_eq!(next.offset, 2, "retention restart reused an existing offset");
}

#[test]
fn schema_validated_provisioning_rejects_invalid_manifest() {
    let dir = tempfile::tempdir().unwrap();
    let mut m = manifest();
    m.topics[0].partitions = 0;
    assert!(EmbeddedBroker::provision(dir.path(), &m).is_err());
    assert!(
        !dir.path().join("manifest.yaml").exists(),
        "invalid manifest must not be persisted"
    );
}

#[test]
fn declared_event_schema_is_enforced_on_publish() {
    let dir = tempfile::tempdir().unwrap();
    let broker =
        EmbeddedBroker::provision(dir.path(), &BridgeManifest::default_for("schema-enforced")).unwrap();
    let identity = av_events::AgentIdentity {
        version: "1".into(),
        charter: "test".into(),
        instance_uid: "instance-1".into(),
        ttl_remaining_s: Some(60),
    };
    let event = av_events::OcsfEventBuilder::new(av_events::EventClass::ToolCall, "session-1", identity, 0)
        .payload(json!({"allowed": true}))
        .build()
        .unwrap();
    let value = serde_json::to_value(event).unwrap();
    broker.publish("agent.tool_call", "instance-1", &value).unwrap();
    assert!(broker
        .publish("agent.tool_call", "instance-1", &json!({"not": "ocsf"}))
        .is_err());
}

/// Adversarial: publishers, readers, and retention run concurrently on the same
/// partition. Every fetched record must decode cleanly — a retention rewrite
/// racing a fetch must never expose a torn or half-written segment.
#[test]
fn concurrent_publish_fetch_and_retention_never_torn() {
    let dir = tempfile::tempdir().unwrap();
    let cold = tempfile::tempdir().unwrap();
    let mut manifest = manifest();
    for topic in &mut manifest.topics {
        topic.retention.hot_hours = 1;
        topic.retention.cold_uri = Some(cold.path().to_string_lossy().to_string());
    }
    let broker = std::sync::Arc::new(EmbeddedBroker::provision(dir.path(), &manifest).unwrap());
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut handles = Vec::new();
    for publisher in 0..4 {
        let broker = std::sync::Arc::clone(&broker);
        let stop = std::sync::Arc::clone(&stop);
        handles.push(std::thread::spawn(move || {
            let mut n = 0u64;
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                broker
                    .publish(
                        "agent.tool_call",
                        "inst-hot",
                        &json!({
                            "metadata": {"uid": format!("uid-{publisher}-{n}")},
                            "n": n,
                        }),
                    )
                    .unwrap();
                n += 1;
            }
        }));
    }
    for _ in 0..4 {
        let broker = std::sync::Arc::clone(&broker);
        let stop = std::sync::Arc::clone(&stop);
        handles.push(std::thread::spawn(move || {
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                for p in 0..broker.partitions("agent.tool_call").unwrap() {
                    let fetched = broker.fetch("agent.tool_call", p, 0, 4_096).unwrap();
                    for event in fetched {
                        // Torn writes would fail this parse (line missing braces).
                        assert!(event.value.get("metadata").is_some());
                    }
                }
            }
        }));
    }
    let retention_broker = std::sync::Arc::clone(&broker);
    let retention_stop = std::sync::Arc::clone(&stop);
    handles.push(std::thread::spawn(move || {
        while !retention_stop.load(std::sync::atomic::Ordering::Relaxed) {
            let now = av_core::time::now_ms() + 2 * 3_600_000;
            let _ = retention_broker.enforce_retention(now);
        }
    }));
    std::thread::sleep(std::time::Duration::from_millis(400));
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    for handle in handles {
        handle.join().unwrap();
    }
}

/// Adversarial: the loader must accept a manifest that omits
/// `replication_factor` (the schema was relaxed to match the serde default of 1).
#[test]
fn manifest_without_replication_factor_defaults_to_one() {
    let yaml = "manifest_version: 1\n\
                name: adversarial\n\
                topics:\n  \
                  - name: agent.tool_call\n    \
                    partitions: 2\n    \
                    retention:\n      \
                      hot_hours: 24\n";
    let manifest = BridgeManifest::from_yaml(yaml).unwrap();
    assert_eq!(manifest.replication_factor, 1);
    let dir = tempfile::tempdir().unwrap();
    // Provisioning succeeds with the default.
    let _ = EmbeddedBroker::provision(dir.path(), &manifest).unwrap();
}

/// Adversarial: `replication_factor` outside 1..=5 is rejected on validate.
#[test]
fn manifest_rejects_out_of_range_replication_factor() {
    let yaml_hi = "manifest_version: 1\n\
                   name: hi\n\
                   replication_factor: 6\n\
                   topics: [{name: agent.tool_call, partitions: 1, retention: {hot_hours: 1}}]\n";
    assert!(BridgeManifest::from_yaml(yaml_hi).is_err());
    let yaml_lo = "manifest_version: 1\n\
                   name: lo\n\
                   replication_factor: 0\n\
                   topics: [{name: agent.tool_call, partitions: 1, retention: {hot_hours: 1}}]\n";
    assert!(BridgeManifest::from_yaml(yaml_lo).is_err());
}

/// Adversarial: repeated publishes with the same `event_uid` from many threads
/// must all resolve to a single offset (dedup wins over race).
#[test]
fn publish_with_same_uid_from_many_threads_dedups_to_one_offset() {
    let dir = tempfile::tempdir().unwrap();
    let broker = std::sync::Arc::new(EmbeddedBroker::provision(dir.path(), &manifest()).unwrap());
    let uid = "uid-shared-1".to_string();
    let value = json!({"metadata": {"uid": uid.clone()}, "n": 1});
    let mut handles = Vec::new();
    for _ in 0..32 {
        let broker = std::sync::Arc::clone(&broker);
        let uid = uid.clone();
        let value = value.clone();
        handles.push(std::thread::spawn(move || {
            broker
                .publish_idempotent("agent.tool_call", "inst-1", &value, &uid)
                .unwrap()
        }));
    }
    let acks: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    // All 32 acks must have identical topic, partition, offset.
    let head = acks[0].clone();
    for ack in &acks {
        assert_eq!(ack.topic, head.topic);
        assert_eq!(ack.partition, head.partition);
        assert_eq!(ack.offset, head.offset);
    }
    // A different UID with the same key must land at a strictly later offset.
    let other = broker
        .publish_idempotent(
            "agent.tool_call",
            "inst-1",
            &json!({"metadata": {"uid": "uid-shared-2"}, "n": 2}),
            "uid-shared-2",
        )
        .unwrap();
    assert!(other.offset > head.offset);
}

/// Adversarial: `publish` (which pulls UID from the event `metadata.uid`) must
/// also dedup — resubmitting the same value returns the original offset, not
/// a new one.
#[test]
fn publish_pulls_uid_from_metadata_and_dedups() {
    let dir = tempfile::tempdir().unwrap();
    let broker = EmbeddedBroker::provision(dir.path(), &manifest()).unwrap();
    let value = json!({"metadata": {"uid": "meta-uid-1"}, "n": 1});
    let first = broker.publish("agent.tool_call", "inst-1", &value).unwrap();
    let second = broker.publish("agent.tool_call", "inst-1", &value).unwrap();
    assert_eq!(first.offset, second.offset);
    assert_eq!(first.partition, second.partition);
}

/// Adversarial: pre-plant a byte-different file at the exact cold-object path
/// that retention will target; the export must refuse to overwrite it.
#[test]
fn retention_refuses_to_overwrite_a_diverging_pre_existing_cold_object() {
    use av_bridge::EventBus as _;
    let dir = tempfile::tempdir().unwrap();
    let cold = tempfile::tempdir().unwrap();
    let mut m = manifest();
    for topic in &mut m.topics {
        topic.retention.hot_hours = 1;
        topic.retention.cold_uri = Some(cold.path().to_string_lossy().to_string());
    }
    let broker = EmbeddedBroker::provision(dir.path(), &m).unwrap();
    // Publish enough events that retention has something to expire.
    for n in 0..8 {
        broker
            .publish(
                "agent.tool_call",
                "inst-1",
                &json!({"metadata": {"uid": format!("uid-{n}")}, "n": n}),
            )
            .unwrap();
    }
    // Plant a diverging file at every partition's offset-0 cold path.
    let parts = broker.partitions("agent.tool_call").unwrap();
    for p in 0..parts {
        let planted = cold.path().join("agent.tool_call").join(format!("p{p}"));
        std::fs::create_dir_all(&planted).unwrap();
        let mut f = std::fs::File::create(planted.join(format!("{:020}.json", 0u64))).unwrap();
        f.write_all(b"{\"tampered\":true}").unwrap();
    }
    // Expire everything (retention window is 1h; jump forward two hours).
    let now = av_core::time::now_ms() + 2 * 3_600_000;
    let err = broker.enforce_retention(now).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("already exists with different content"), "{msg}");
}

/// Adversarial: fetch with an offset past the current watermark must return
/// an empty vec (never an error, never records from a different partition).
#[test]
fn fetch_at_offset_past_watermark_returns_empty() {
    use av_bridge::EventBus as _;
    let dir = tempfile::tempdir().unwrap();
    let broker = EmbeddedBroker::provision(dir.path(), &manifest()).unwrap();
    broker
        .publish(
            "agent.tool_call",
            "inst-1",
            &json!({"metadata": {"uid": "uid-1"}, "n": 1}),
        )
        .unwrap();
    let parts = broker.partitions("agent.tool_call").unwrap();
    for p in 0..parts {
        let fetched = broker.fetch("agent.tool_call", p, 1_000_000, 128).unwrap();
        assert!(fetched.is_empty());
    }
}

/// Adversarial: fetch on a partition index that doesn't exist is a controlled
/// error, not a panic or a cross-partition read.
#[test]
fn fetch_on_out_of_range_partition_is_a_controlled_error() {
    use av_bridge::EventBus as _;
    let dir = tempfile::tempdir().unwrap();
    let broker = EmbeddedBroker::provision(dir.path(), &manifest()).unwrap();
    let parts = broker.partitions("agent.tool_call").unwrap();
    // Pin the class of error, not just "some error" — a refactor that
    // misclassifies an out-of-range partition as UnknownTopic (or that
    // makes every partition >= 1 refuse) still fails is_err() but for
    // the wrong reason. The sibling assertion below already uses
    // matches!() on UnknownTopic; the partition case should match it.
    let partition_err = broker
        .fetch("agent.tool_call", parts + 100, 0, 16)
        .expect_err("out-of-range partition must be refused");
    assert!(
        matches!(partition_err, av_bridge::bus::BusError::Backend(ref msg) if msg.contains("partition")),
        "out-of-range partition must surface as BusError::Backend(\"partition ... out of range\"), \
         not any other variant; got {partition_err:?}"
    );
    assert!(matches!(
        broker.fetch("agent.nonexistent.topic", 0, 0, 16),
        Err(av_bridge::bus::BusError::UnknownTopic(_))
    ));
}

/// Adversarial: after retention drains a partition, offsets must remain
/// monotone across the retention boundary — publishing again must not reuse
/// an expired offset.
#[test]
fn offsets_stay_monotone_across_retention_boundaries() {
    use av_bridge::EventBus as _;
    let dir = tempfile::tempdir().unwrap();
    let cold = tempfile::tempdir().unwrap();
    let mut m = manifest();
    for topic in &mut m.topics {
        topic.retention.hot_hours = 1;
        topic.retention.cold_uri = Some(cold.path().to_string_lossy().to_string());
    }
    let broker = EmbeddedBroker::provision(dir.path(), &m).unwrap();
    for n in 0..4 {
        broker
            .publish(
                "agent.tool_call",
                "inst-1",
                &json!({"metadata": {"uid": format!("pre-{n}")}, "n": n}),
            )
            .unwrap();
    }
    let now = av_core::time::now_ms() + 2 * 3_600_000;
    broker.enforce_retention(now).unwrap();
    let ack = broker
        .publish(
            "agent.tool_call",
            "inst-1",
            &json!({"metadata": {"uid": "post"}, "n": 99}),
        )
        .unwrap();
    // The invariant is DENSE offsets — every
    // other test in this suite pins them exactly, and the retention
    // crossing is the one place the watermark is re-persisted and could
    // drift. `>= 4` would let a watermark jump (permanent fetch gaps,
    // misaligned cold-object names) pass; all 4 pre-events share the
    // "inst-1" partition key, so the post-retention offset is exactly 4.
    assert_eq!(
        ack.offset, 4,
        "post-retention publish drifted from the dense-offset invariant"
    );
}

/// Mutation-run hardening: the trait-default
/// `find_event_by_uid` — the at-most-once primitive crash recovery uses
/// to decide whether an effect already committed — had no test on any
/// backend. Ok(None) regressions mean duplicated effects after a crash;
/// a wrong match acks the wrong offset. Exercise it through the embedded
/// broker including the pagination path (fetch pages are 1,024 events).
#[test]
fn find_event_by_uid_resolves_committed_events_exactly() {
    let dir = tempfile::tempdir().unwrap();
    let broker = EmbeddedBroker::provision(dir.path(), &manifest()).unwrap();
    let key = "inst-uid-probe";
    let mut acks = Vec::new();
    for i in 0..1_500u32 {
        let ack = broker
            .publish(
                "agent.tool_call",
                key,
                &json!({"metadata": {"uid": format!("uid-{i}")}, "i": i}),
            )
            .unwrap();
        acks.push(ack);
    }
    // First page, deep into the second page, and the exact page edge.
    for probe in [0usize, 1_400, 1_023, 1_024] {
        let found = broker
            .find_event_by_uid("agent.tool_call", key, &format!("uid-{probe}"))
            .unwrap()
            .unwrap_or_else(|| panic!("uid-{probe} must be found"));
        assert_eq!(found.offset, acks[probe].offset, "uid-{probe} offset");
        assert_eq!(found.partition, acks[probe].partition);
    }
    assert!(
        broker
            .find_event_by_uid("agent.tool_call", key, "uid-missing")
            .unwrap()
            .is_none(),
        "unknown uid must be None"
    );
    assert!(
        broker.find_event_by_uid("agent.bogus", key, "uid-0").is_err(),
        "unknown topic must error"
    );
}

/// Mutation-run hardening: in-process UID dedupe was tested,
/// but the `recover_event_uids` restart path wasn't — a mutant returning
/// an empty map made every crash-restart re-publish acked events
/// (duplicate records in the audit stream). Publish, reopen, republish
/// the same UID: the ack must be identical and the partition must hold
/// exactly one copy — including after a torn sidecar tail (the incomplete
/// line is discarded; intact lines keep deduping).
#[test]
fn uid_dedupe_survives_restart_and_torn_sidecar_tail() {
    let dir = tempfile::tempdir().unwrap();
    let value = json!({"metadata": {"uid": "uid-restart"}, "n": 1});
    let first = {
        let broker = EmbeddedBroker::provision(dir.path(), &manifest()).unwrap();
        broker.publish("agent.tool_call", "inst-r", &value).unwrap()
    };
    let reopened = EmbeddedBroker::open(dir.path()).unwrap();
    let again = reopened.publish("agent.tool_call", "inst-r", &value).unwrap();
    assert_eq!(
        again.offset, first.offset,
        "restart must not re-publish an acked uid"
    );
    let events = reopened
        .fetch("agent.tool_call", first.partition, 0, 100)
        .unwrap();
    assert_eq!(events.len(), 1, "exactly one copy after restart republish");
    drop(reopened);

    // Torn tail: garbage half-line at the sidecar end is discarded on the
    // next open; the intact mapping must still dedupe.
    let sidecar = dir
        .path()
        .join("topics/agent.tool_call")
        .join(format!("p{}.event-uids.jsonl", first.partition));
    {
        use std::io::Write as _;
        let mut f = std::fs::OpenOptions::new().append(true).open(&sidecar).unwrap();
        f.write_all(br#"{"uid":"torn-"#).unwrap();
    }
    let recovered = EmbeddedBroker::open(dir.path()).unwrap();
    let third = recovered.publish("agent.tool_call", "inst-r", &value).unwrap();
    assert_eq!(
        third.offset, first.offset,
        "dedupe must survive a torn sidecar tail"
    );
    assert_eq!(
        recovered
            .fetch("agent.tool_call", first.partition, 0, 100)
            .unwrap()
            .len(),
        1
    );
}

/// The embedded broker's maintenance must drain cold-export intents that
/// `ColdArchive::commit` queued after a transient remote failure. Retention
/// deletes the record from the hot segment on the "queued for retry"
/// promise; before this fix only the Kafka/NATS maintenance paths ever
/// called `retry_pending_with`, so the embedded promise was never
/// fulfilled — a silent permanent cold-tier gap. Simulate the transient
/// failure by making the cold target unwritable for the first export.
#[cfg(all(feature = "cold-store", unix))]
#[test]
fn maintenance_retries_queued_cold_export_intents() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().unwrap();
    let cold = tempfile::tempdir().unwrap();
    let mut m = manifest();
    for topic in &mut m.topics {
        topic.retention.hot_hours = 1;
        // A scheme URI routes retention exports through the ColdArchive
        // two-phase (stage/commit) path instead of write_cold_event_once.
        topic.retention.cold_uri = Some(format!("file://{}", cold.path().display()));
    }
    let broker = EmbeddedBroker::provision(dir.path(), &m).unwrap();
    broker.set_control_key([7u8; 32]).unwrap();
    let ack = broker
        .publish(
            "agent.receipt",
            "inst-R",
            &json!({"metadata": {"uid": "cold-retry-1"}, "old": true}),
        )
        .unwrap();

    // Transient remote outage: the cold target refuses writes.
    std::fs::set_permissions(cold.path(), std::fs::Permissions::from_mode(0o555)).unwrap();
    let later = av_core::time::now_ms() + 2 * 3_600_000;
    let expired = broker.enforce_retention(later).unwrap();
    assert_eq!(
        expired, 1,
        "commit converts the remote failure into a durable intent"
    );
    let outbox = dir.path().join("cold-outbox");
    assert_eq!(
        std::fs::read_dir(&outbox).unwrap().count(),
        1,
        "the failed export must be queued for retry"
    );
    let cold_object = cold
        .path()
        .join("agent.receipt")
        .join(format!("p{}", ack.partition))
        .join(format!("{:020}.json", ack.offset));
    assert!(!cold_object.exists(), "nothing landed during the outage");

    // Outage over: maintenance must fulfill the retry promise.
    std::fs::set_permissions(cold.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    broker.maintenance(later).unwrap();
    assert_eq!(
        std::fs::read_dir(&outbox).unwrap().count(),
        0,
        "maintenance must drain the cold-export retry queue"
    );
    let stored: av_bridge::StoredEvent =
        serde_json::from_slice(&std::fs::read(&cold_object).unwrap()).unwrap();
    assert_eq!(stored.offset, ack.offset);
    assert_eq!(stored.value["metadata"]["uid"], "cold-retry-1");
}

/// `fetch_read_only` is the CLI's beside-a-live-daemon read path: it
/// must return the same events as the broker's own `fetch` and must
/// mutate NOTHING — in particular it must not "repair" a torn trailing
/// line, because what looks torn to a second process may be the
/// daemon's in-flight append, and truncating it destroys bytes the
/// daemon then acks as durable.
#[test]
fn fetch_read_only_matches_fetch_and_never_mutates_a_torn_tail() {
    let dir = tempfile::tempdir().unwrap();
    let broker = EmbeddedBroker::provision(dir.path(), &manifest()).unwrap();
    let mut partition = 0u32;
    for i in 0..5 {
        partition = broker
            .publish("agent.tool_call", "inst-A", &json!({"i": i}))
            .unwrap()
            .partition;
    }
    let via_broker = broker.fetch("agent.tool_call", partition, 0, 100).unwrap();
    assert_eq!(via_broker.len(), 5);
    drop(broker);

    // Simulate the daemon mid-append: record bytes written, trailing
    // newline not yet. A concurrent read-only tail must return the
    // five complete events and leave the file byte-identical.
    let segment = dir
        .path()
        .join("topics/agent.tool_call")
        .join(format!("p{partition}.jsonl"));
    let mut file = std::fs::OpenOptions::new().append(true).open(&segment).unwrap();
    file.write_all(b"{\"partition\":0,\"offset\":5,\"key\":\"inst-A\",\"va")
        .unwrap();
    drop(file);
    let before = std::fs::read(&segment).unwrap();

    let events = EmbeddedBroker::fetch_read_only(dir.path(), "agent.tool_call", partition, 0, 100).unwrap();
    assert_eq!(events.len(), 5);
    for (fetched, expected) in events.iter().zip(via_broker.iter()) {
        assert_eq!(fetched.offset, expected.offset);
        assert_eq!(fetched.value, expected.value);
    }
    let after = std::fs::read(&segment).unwrap();
    assert_eq!(
        before, after,
        "a read-only fetch must not repair/truncate the segment"
    );

    // Offset paging and the max cap behave like `fetch`.
    let tail = EmbeddedBroker::fetch_read_only(dir.path(), "agent.tool_call", partition, 3, 100).unwrap();
    assert_eq!(tail.first().map(|e| e.offset), Some(3));
    let capped = EmbeddedBroker::fetch_read_only(dir.path(), "agent.tool_call", partition, 0, 2).unwrap();
    assert_eq!(capped.len(), 2);

    // Failure modes preserved for the CLI contract: unknown topic and
    // out-of-range partition are refused, a non-provisioned dir errors.
    assert!(matches!(
        EmbeddedBroker::fetch_read_only(dir.path(), "agent.does_not_exist", 0, 0, 10),
        Err(av_bridge::bus::BusError::UnknownTopic(_))
    ));
    let partition_err = EmbeddedBroker::fetch_read_only(dir.path(), "agent.tool_call", 99, 0, 10)
        .expect_err("out-of-range partition must be refused by the read-only path too");
    assert!(
        matches!(partition_err, av_bridge::bus::BusError::Backend(ref msg) if msg.contains("partition")),
        "read-only fetch must classify out-of-range partition as BusError::Backend, \
         matching the writer-side fetch(); got {partition_err:?}"
    );
    let empty = tempfile::tempdir().unwrap();
    assert!(EmbeddedBroker::fetch_read_only(empty.path(), "agent.tool_call", 0, 0, 10).is_err());
}
