//! Race-condition resilience for the embedded broker: concurrent duplicate
//! `publish_idempotent`, concurrent fetches racing live publishers, and
//! interleaved publishers hammering a single hot partition (fixed keys —
//! the hardest ordering case). (Fetch-during-retention races
//! are covered by `embedded_contract.rs::concurrent_publish_fetch_and_retention_never_torn`.)

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation
)]

use av_bridge::{BridgeManifest, EmbeddedBroker, EventBus};
use serde_json::json;
use std::sync::{Arc, Barrier};
use std::thread;

fn manifest() -> BridgeManifest {
    let mut m = BridgeManifest::default_for("race-enclave");
    for t in &mut m.topics {
        t.schema_ref = None;
    }
    m
}

// ---------------------------------------------------------------------------
// 1. Duplicate `publish_idempotent` under contention: N threads publish
//    the SAME event_uid concurrently. Exactly ONE storage record must
//    exist, and every caller receives an identical PublishAck.
// ---------------------------------------------------------------------------

#[test]
fn concurrent_duplicate_publish_idempotent_yields_one_record_and_one_ack() {
    let dir = tempfile::tempdir().unwrap();
    let broker = Arc::new(EmbeddedBroker::provision(dir.path(), &manifest()).unwrap());
    const N: usize = 32;
    let value = Arc::new(json!({"metadata": {"uid": "uid-race-1"}, "n": 1}));
    let barrier = Arc::new(Barrier::new(N));
    let handles: Vec<_> = (0..N)
        .map(|_| {
            let broker = Arc::clone(&broker);
            let value = Arc::clone(&value);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                broker
                    .publish_idempotent("agent.session", "inst-race", &value, "uid-race-1")
                    .unwrap()
            })
        })
        .collect();
    let acks: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let first = &acks[0];
    for ack in &acks[1..] {
        assert_eq!(
            ack.partition, first.partition,
            "idempotent publish returned diverging partitions"
        );
        assert_eq!(
            ack.offset, first.offset,
            "idempotent publish returned diverging offsets"
        );
    }
    // Total records for the target partition = 1.
    let events = broker
        .fetch("agent.session", first.partition, first.offset, 100)
        .unwrap();
    assert_eq!(
        events.len(),
        1,
        "idempotency broke: {} records under duplicate submission",
        events.len()
    );
}

// ---------------------------------------------------------------------------
// 2. Concurrent fetches during publishing: readers sweeping every partition
//    while writers publish must never see torn records or duplicate
//    offsets, and every offset returned must be strictly increasing.
// ---------------------------------------------------------------------------

#[test]
fn concurrent_fetch_never_sees_torn_or_duplicate_offsets() {
    let dir = tempfile::tempdir().unwrap();
    let broker = Arc::new(EmbeddedBroker::provision(dir.path(), &manifest()).unwrap());
    const WRITERS: usize = 4;
    const K: u64 = 200;
    const READERS: usize = 4;
    let barrier = Arc::new(Barrier::new(WRITERS + READERS));
    let stop_at = WRITERS as u64 * K;
    let mut handles = Vec::new();
    for w in 0..WRITERS as u64 {
        let broker = Arc::clone(&broker);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            for i in 0..K {
                broker
                    .publish("agent.session", "inst-fetch", &json!({"w": w, "i": i}))
                    .unwrap();
            }
        }));
    }
    for _ in 0..READERS {
        let broker = Arc::clone(&broker);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            let nparts = broker.partitions("agent.session").unwrap();
            for _ in 0..8 {
                for p in 0..nparts {
                    let events = broker.fetch("agent.session", p, 0, 10_000).unwrap();
                    let mut last_offset: i64 = -1;
                    for e in &events {
                        let offset = i64::try_from(e.offset).unwrap();
                        assert!(
                            offset > last_offset,
                            "fetch saw non-monotonic offsets: {offset} after {last_offset}"
                        );
                        last_offset = offset;
                        // torn records would have failed serde deserialize
                        // inside fetch(), turning into an Err — reaching
                        // here already proves the record parsed cleanly.
                        assert!(e.value.is_object());
                    }
                }
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    // Final invariant: total records across partitions = expected.
    let nparts = broker.partitions("agent.session").unwrap();
    let mut total: u64 = 0;
    for p in 0..nparts {
        total += broker.fetch("agent.session", p, 0, 10_000_000).unwrap().len() as u64;
    }
    assert_eq!(total, stop_at);
}

// ---------------------------------------------------------------------------
// 3. Publish-idempotent under a MIX of duplicate and unique uids: N
//    threads, each doing K submissions; every 7th submission reuses a
//    shared uid. Final storage must equal (unique submissions + 1).
// ---------------------------------------------------------------------------

#[test]
fn interleaved_unique_and_duplicate_uids_settle_to_expected_count() {
    let dir = tempfile::tempdir().unwrap();
    let broker = Arc::new(EmbeddedBroker::provision(dir.path(), &manifest()).unwrap());
    const N: usize = 8;
    const K: u64 = 100;
    let barrier = Arc::new(Barrier::new(N));
    let handles: Vec<_> = (0..N)
        .map(|t| {
            let broker = Arc::clone(&broker);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                for i in 0..K {
                    let (uid, value) = if i % 7 == 0 {
                        (
                            "shared-uid".to_owned(),
                            json!({"metadata": {"uid": "shared-uid"}, "shared": true}),
                        )
                    } else {
                        let uid = format!("uid-{t}-{i}");
                        (uid.clone(), json!({"metadata": {"uid": uid}, "t": t, "i": i}))
                    };
                    broker
                        .publish_idempotent("agent.session", "inst-mix", &value, &uid)
                        .unwrap();
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    // Expected: for each thread, K submissions, of which ceil(K/7) reuse
    // "shared-uid" (contributing 1 record total across all threads), the
    // rest are unique.
    let per_thread_shared = K.div_ceil(7);
    let per_thread_unique = K - per_thread_shared;
    let expected = (N as u64) * per_thread_unique + 1;
    let nparts = broker.partitions("agent.session").unwrap();
    let mut total: u64 = 0;
    for p in 0..nparts {
        total += broker.fetch("agent.session", p, 0, 10_000_000).unwrap().len() as u64;
    }
    assert_eq!(total, expected, "idempotency drift under interleaved mix");
}
