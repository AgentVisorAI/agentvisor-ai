//! Shared scaffolding for the av-harness integration suites.
//!
//! Each file under `tests/` compiles to its own binary and pulls in only
//! the pieces it uses; the remainder is dead code from that binary's
//! point of view, hence the file-level allow.
#![allow(dead_code)]

use av_bridge::{BusError, EventBus, PublishAck, StoredEvent};
use av_events::EventClass;
use av_harness::{AppState, HarnessConfig};
use av_receipts::{Ed25519Signer, Keyring, Signer};
use av_sandbox::Sandbox;
use av_state::InMemoryStore;
use axum::http::{HeaderMap, HeaderValue};
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

fn all_topics() -> Vec<String> {
    EventClass::all().iter().map(|c| c.topic().to_owned()).collect()
}

/// In-memory bus double that acks every publish with a monotonically
/// increasing offset and counts the publishes.
#[derive(Default)]
pub struct CountingBus {
    /// Number of successful publishes so far.
    pub published: AtomicU64,
}

impl EventBus for CountingBus {
    fn publish(&self, topic: &str, _key: &str, _value: &Value) -> Result<PublishAck, BusError> {
        Ok(PublishAck {
            topic: topic.to_owned(),
            partition: 0,
            offset: self.published.fetch_add(1, Ordering::AcqRel),
        })
    }
    fn fetch(&self, _t: &str, _p: u32, _o: u64, _m: usize) -> Result<Vec<StoredEvent>, BusError> {
        Ok(Vec::new())
    }
    fn partitions(&self, _t: &str) -> Result<u32, BusError> {
        Ok(1)
    }
    fn topics(&self) -> Vec<String> {
        all_topics()
    }
}

/// Counting bus that additionally records every published payload,
/// per-topic publish counts, and any `metadata.uid` values it sees, so
/// tests can assert on exactly what reached the bus.
#[derive(Default)]
pub struct RecordingBus {
    /// Number of successful publishes so far.
    pub published: AtomicU64,
    /// Every published payload, in publish order.
    pub payloads: Mutex<Vec<Value>>,
    /// Publish count per topic.
    pub per_topic: Mutex<HashMap<String, u64>>,
    /// `metadata.uid` of every payload that carried one, in publish order.
    pub seen_uids: Mutex<Vec<String>>,
}

impl EventBus for RecordingBus {
    fn publish(&self, topic: &str, _key: &str, value: &Value) -> Result<PublishAck, BusError> {
        let offset = self.published.fetch_add(1, Ordering::AcqRel);
        self.payloads.lock().push(value.clone());
        *self.per_topic.lock().entry(topic.to_owned()).or_default() += 1;
        if let Some(uid) = value
            .get("metadata")
            .and_then(|m| m.get("uid"))
            .and_then(Value::as_str)
        {
            self.seen_uids.lock().push(uid.to_owned());
        }
        Ok(PublishAck {
            topic: topic.to_owned(),
            partition: 0,
            offset,
        })
    }
    fn fetch(&self, _t: &str, _p: u32, _o: u64, _m: usize) -> Result<Vec<StoredEvent>, BusError> {
        Ok(Vec::new())
    }
    fn partitions(&self, _t: &str) -> Result<u32, BusError> {
        Ok(1)
    }
    fn topics(&self) -> Vec<String> {
        all_topics()
    }
}

/// Publish-and-forget bus for latency-sensitive runs: no counters, no
/// recording, constant ack.
pub struct NullBus;

impl EventBus for NullBus {
    fn publish(&self, topic: &str, _key: &str, _value: &Value) -> Result<PublishAck, BusError> {
        Ok(PublishAck {
            topic: topic.to_owned(),
            partition: 0,
            offset: 0,
        })
    }
    fn fetch(&self, _t: &str, _p: u32, _o: u64, _m: usize) -> Result<Vec<StoredEvent>, BusError> {
        Ok(Vec::new())
    }
    fn partitions(&self, _t: &str) -> Result<u32, BusError> {
        Ok(1)
    }
    fn topics(&self) -> Vec<String> {
        all_topics()
    }
}

/// Deterministic test signer from a repeated one-byte seed.
pub fn signer(seed: u8) -> Ed25519Signer {
    Ed25519Signer::from_seed(&[seed; 32])
}

/// Keyring holding the public keys of the given signers.
pub fn ring(signers: &[&Ed25519Signer]) -> Keyring {
    let mut r = Keyring::new();
    for s in signers {
        r.add_key_bytes(&Signer::public_key_bytes(*s)).unwrap();
    }
    r
}

/// Tempdir-backed test config pointing at an unreachable upstream. The
/// tempdir is leaked so its paths stay valid for the life of the process
/// (the AppState built from the config holds paths into it).
pub fn leaked_test_config() -> HarnessConfig {
    let dir = tempfile::tempdir().unwrap();
    let config = HarnessConfig::for_tests(
        "http://127.0.0.1:9",
        &dir.path().to_string_lossy(),
        &dir.path().to_string_lossy(),
    );
    std::mem::forget(dir);
    config
}

/// Assemble an `AppState` from the standard test parts: in-memory store,
/// the given sandbox and bus, no identity validator, and a signer seeded
/// with `signer_seed`.
pub fn app_state(
    config: HarnessConfig,
    sandbox: Sandbox,
    bus: Arc<dyn EventBus>,
    signer_seed: u8,
) -> Arc<AppState> {
    Arc::new(
        AppState::new(
            config,
            Arc::new(InMemoryStore::new()),
            Arc::new(sandbox),
            bus,
            None,
            Arc::new(signer(signer_seed)),
        )
        .unwrap(),
    )
}

/// Session headers for the given workflow.
pub fn headers(session: &str, workflow: &'static str) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert("x-av-session", HeaderValue::from_str(session).unwrap());
    h.insert("x-av-workflow", HeaderValue::from_static(workflow));
    h
}

/// Session headers for the signed workflow.
pub fn signed_headers(session: &str) -> HeaderMap {
    headers(session, "signed")
}

/// Serialized JSON-RPC `tools/call` request for the given tool.
pub fn tools_call(tool: &str, args: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool, "arguments": args}
    }))
    .unwrap()
}

/// Minimal single-message chat payload with the given user content.
pub fn chat(content: &str) -> Value {
    json!({"model": "m", "messages": [{"role": "user", "content": content}]})
}

/// Minimal single-message chat payload.
pub fn chat_payload() -> Value {
    chat("hi")
}
