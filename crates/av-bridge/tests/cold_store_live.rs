//! Live S3-compatible cold-tier contract, env-gated on `AV_COLD_S3_URL`
//! (e.g. `s3://bucket/prefix`) plus standard `AWS_*` credentials
//! (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_ENDPOINT`,
//! `AWS_ALLOW_HTTP=true` for local MinIO). Skips loudly otherwise (D13.21).
//!
//! Exercises the full two-phase export: publish → hot expiry → staged
//! intent → conditional `PutMode::Create` upload → idempotent re-put.
#![cfg(feature = "cold-store")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use av_bridge::{BridgeManifest, EmbeddedBroker, EventBus};
use serde_json::json;

#[test]
fn s3_cold_tier_receives_expired_events_and_reput_is_idempotent() {
    let Ok(cold_url) = std::env::var("AV_COLD_S3_URL") else {
        eprintln!("SKIPPED (AV_COLD_S3_URL unset): live S3 cold-tier contract requires an object store");
        return;
    };
    // Unique per-run prefix so reruns never collide with a prior run's
    // conditional-put objects.
    let cold_url = format!("{}/{}", cold_url.trim_end_matches('/'), av_core::new_event_uid());

    let dir = tempfile::tempdir().unwrap();
    let mut manifest = BridgeManifest::default_for("s3-cold-live");
    for topic in &mut manifest.topics {
        topic.schema_ref = None;
        topic.retention.hot_hours = 1;
        topic.retention.cold_uri = Some(cold_url.clone());
    }
    let broker = EmbeddedBroker::provision(dir.path(), &manifest).unwrap();
    broker.set_control_key([0x5A; 32]).unwrap();
    let ack = broker
        .publish("agent.receipt", "inst-s3", &json!({"cold": "live"}))
        .unwrap();

    // Two hours later the record is beyond the 1 h hot window and must be
    // exported through the staged-intent path to the live object store.
    let later = av_core::time::now_ms() + 2 * 3_600_000;
    let expired = broker.enforce_retention(later).unwrap();
    assert_eq!(expired, 1, "the published record must expire to cold");

    // Verify the object landed, via an independent client (not the archive).
    let url = url::Url::parse(&cold_url).unwrap();
    let options = std::env::vars().map(|(key, value)| (key.to_ascii_lowercase(), value));
    let (store, prefix) = object_store::parse_url_opts(&url, options).unwrap();
    let location = prefix
        .child("agent.receipt")
        .child(format!("p{}", ack.partition))
        .child(format!("{:020}.json", ack.offset));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let bytes = runtime
        .block_on(async { store.get(&location).await.unwrap().bytes().await })
        .unwrap();
    let stored: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(stored["value"]["cold"], "live");
    assert_eq!(stored["key"], "inst-s3");
    assert_eq!(stored["offset"], ack.offset);

    // A second retention pass must not fail on the already-present object
    // (conditional put + same-content tolerance), and must export nothing new.
    let expired_again = broker.enforce_retention(later).unwrap();
    assert_eq!(expired_again, 0, "re-run must be a no-op, not a conflict");
}
