//! Session event-chain hashing.
//!
//! `h₀ = SHA-256("ab-genesis" ‖ session_id)`;
//! `hᵢ = SHA-256(hᵢ₋₁ ‖ JCS(eventᵢ))`.
//!
//! Ordering is driven by the per-session sequence number (events are fed in
//! seq order) — never by wall-clock timestamps (D13.6). Any tamper, drop,
//! reorder, or substitution changes the head hash and breaks verification.

use crate::jcs::{canonicalize, JcsError};
use sha2::{Digest, Sha256};

/// Incrementally computed hash chain over a session's OCSF events.
#[derive(Debug, Clone)]
pub struct EventChain {
    head: [u8; 32],
    count: u64,
}

impl EventChain {
    /// Start a chain for `session_id`.
    pub fn new(session_id: &str) -> Self {
        let mut h = Sha256::new();
        h.update(b"ab-genesis");
        h.update(session_id.as_bytes());
        Self {
            head: h.finalize().into(),
            count: 0,
        }
    }

    /// Append an event (as JSON) to the chain.
    pub fn append(&mut self, event: &serde_json::Value) -> Result<(), JcsError> {
        let canon = canonicalize(event)?;
        let mut h = Sha256::new();
        h.update(self.head);
        h.update(canon.as_bytes());
        self.head = h.finalize().into();
        self.count += 1;
        Ok(())
    }

    /// Current head hash, hex-encoded.
    pub fn head_hex(&self) -> String {
        hex::encode(self.head)
    }

    /// Number of appended events.
    pub fn count(&self) -> u64 {
        self.count
    }

    /// Recompute a chain from scratch over `events` (offline verification).
    pub fn compute(session_id: &str, events: &[serde_json::Value]) -> Result<Self, JcsError> {
        let mut chain = Self::new(session_id);
        for e in events {
            chain.append(e)?;
        }
        Ok(chain)
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]

    use super::*;
    use serde_json::json;

    fn events() -> Vec<serde_json::Value> {
        (0..5)
            .map(|i| json!({"seq": i, "payload": format!("event-{i}")}))
            .collect()
    }

    #[test]
    fn deterministic() {
        let a = EventChain::compute("sess", &events()).unwrap();
        let b = EventChain::compute("sess", &events()).unwrap();
        assert_eq!(a.head_hex(), b.head_hex());
        assert_eq!(a.count(), 5);
    }

    #[test]
    fn session_id_binds_the_genesis() {
        let a = EventChain::compute("sess-1", &events()).unwrap();
        let b = EventChain::compute("sess-2", &events()).unwrap();
        assert_ne!(a.head_hex(), b.head_hex());
    }

    #[test]
    fn tamper_any_event_changes_head() {
        let baseline = EventChain::compute("s", &events()).unwrap().head_hex();
        for i in 0..5 {
            let mut evs = events();
            evs[i]["payload"] = json!("tampered");
            let h = EventChain::compute("s", &evs).unwrap().head_hex();
            assert_ne!(h, baseline, "tamper at index {i} undetected");
        }
    }

    #[test]
    fn reorder_detected() {
        let baseline = EventChain::compute("s", &events()).unwrap().head_hex();
        let mut evs = events();
        evs.swap(1, 3);
        assert_ne!(EventChain::compute("s", &evs).unwrap().head_hex(), baseline);
    }

    #[test]
    fn drop_detected() {
        let baseline = EventChain::compute("s", &events()).unwrap().head_hex();
        let mut evs = events();
        evs.remove(2);
        assert_ne!(EventChain::compute("s", &evs).unwrap().head_hex(), baseline);
    }

    #[test]
    fn key_order_of_event_json_is_irrelevant() {
        let a = vec![serde_json::from_str::<serde_json::Value>(r#"{"x":1,"y":2}"#).unwrap()];
        let b = vec![serde_json::from_str::<serde_json::Value>(r#"{"y":2,"x":1}"#).unwrap()];
        assert_eq!(
            EventChain::compute("s", &a).unwrap().head_hex(),
            EventChain::compute("s", &b).unwrap().head_hex(),
            "JCS must make key order irrelevant"
        );
    }

    #[test]
    fn empty_chain_is_genesis_only() {
        let c = EventChain::new("s");
        assert_eq!(c.count(), 0);
        assert_eq!(c.head_hex().len(), 64);
    }
}
