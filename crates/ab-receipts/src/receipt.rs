//! The Receipt: an offline-verifiable, Ed25519-signed record of a session.
//!
//! Payload per the brief Module G: session id, agent identity block
//! (version/charter/instance_uid), tool-call summary, cost, stop reason,
//! event-chain hash, signature, signer public-key reference. Subjects are an
//! enum so the same envelope covers signed-workflow chains and retroactive
//! ATIF promotions (Module H reconciliation).
//!
//! Money is carried as integer micro-USD — floats never touch a signed field.

use crate::jcs::canonicalize;
use crate::keys::{KeyError, Keyring, Signer};
use base64::Engine as _;
use serde::{Deserialize, Serialize};

/// Version of the receipt format itself (evolution surface).
pub const RECEIPT_VERSION: u32 = 1;

/// What this receipt attests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum ReceiptSubject {
    /// A signed-workflow session: the OCSF event chain.
    EventChain {
        /// Head hash of the session event chain (hex).
        chain_head: String,
        /// Number of events in the chain.
        event_count: u64,
    },
    /// An unsigned-workflow trajectory promoted retroactively (Module H).
    AtifTrajectory {
        /// SHA-256 of the exported trajectory file bytes (hex).
        trajectory_digest: String,
        /// Number of steps in the trajectory.
        step_count: u64,
        /// Always true for promotions; kept explicit for auditability.
        retroactive: bool,
    },
}

/// Aggregate tool-call statistics for the session.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolCallSummary {
    /// Total tool calls observed.
    pub total: u64,
    /// Calls allowed by policy.
    pub allowed: u64,
    /// Calls blocked by policy/budget/schema.
    pub blocked: u64,
}

/// Aggregate cost for the session (integers only — JCS-exact).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CostSummary {
    /// Total prompt tokens.
    pub prompt_tokens: u64,
    /// Total completion tokens.
    pub completion_tokens: u64,
    /// Total provider-cached tokens.
    pub cached_tokens: u64,
    /// Cost in micro-USD (1_000_000 = $1).
    pub cost_usd_micros: u64,
}

/// The signed body (everything except the signature itself).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReceiptBody {
    /// Receipt format version.
    pub receipt_version: u32,
    /// Unique receipt id (UUIDv7).
    pub receipt_id: String,
    /// Session this receipt covers.
    pub session_id: String,
    /// Issuance time, epoch ms.
    pub issued_at: u64,
    /// Issuance time, ISO-8601.
    pub issued_at_iso: String,
    /// Agent config-state identity block.
    pub ai_agent: ab_events::AgentIdentity,
    /// What is attested.
    pub subject: ReceiptSubject,
    /// Tool-call summary.
    pub tool_calls: ToolCallSummary,
    /// Cost summary.
    pub cost: CostSummary,
    /// Final stop reason id.
    pub stop_reason_id: u8,
    /// Final stop reason caption.
    pub stop_reason: String,
    /// Signer key id.
    pub key_id: String,
    /// Signer public key, base64 (self-contained offline verification).
    pub public_key_b64: String,
}

/// A complete receipt: body + detached signature over `JCS(body)`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Receipt {
    /// Signed body.
    #[serde(flatten)]
    pub body: ReceiptBody,
    /// Ed25519 signature over the JCS canonicalization of the body, base64.
    pub signature_b64: String,
}

/// Receipt errors.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ReceiptError {
    /// Canonicalization failed (unsafe numbers in body).
    #[error("canonicalization: {0}")]
    Jcs(#[from] crate::jcs::JcsError),
    /// Serialization failed.
    #[error("serialization: {0}")]
    Serde(#[from] serde_json::Error),
    /// Key/signature failure.
    #[error("key: {0}")]
    Key(#[from] KeyError),
    /// Signature or public key not valid base64.
    #[error("invalid base64 in receipt")]
    Base64,
    /// The receipt's embedded public key does not match the keyring entry for
    /// its key id (substitution attempt).
    #[error("embedded public key mismatches keyring entry for {0:?}")]
    KeyMismatch(String),
}

impl Receipt {
    /// Issue (sign) a receipt over `body` with `signer`.
    ///
    /// The `key_id` and `public_key_b64` fields of the body are overwritten
    /// from the signer — a caller can never claim someone else's key identity.
    pub fn issue(mut body: ReceiptBody, signer: &dyn Signer) -> Result<Self, ReceiptError> {
        body.key_id = signer.key_id().to_owned();
        body.public_key_b64 = base64::engine::general_purpose::STANDARD.encode(signer.public_key_bytes());
        let canon = canonicalize(&serde_json::to_value(&body)?)?;
        let sig = signer.sign(canon.as_bytes());
        Ok(Self {
            body,
            signature_b64: base64::engine::general_purpose::STANDARD.encode(sig),
        })
    }

    /// Verify offline against a keyring. Checks:
    /// 1. the embedded public key matches the ring's key for `key_id`
    ///    (anti-substitution);
    /// 2. the signature verifies over `JCS(body)`.
    pub fn verify(&self, ring: &Keyring) -> Result<(), ReceiptError> {
        let embedded = base64::engine::general_purpose::STANDARD
            .decode(&self.body.public_key_b64)
            .map_err(|_| ReceiptError::Base64)?;
        let embedded: [u8; 32] = embedded.try_into().map_err(|_| ReceiptError::Base64)?;
        // Re-derive the ring id for the embedded key; it must equal the stated
        // key id AND exist in the ring with the same bytes.
        let mut probe = Keyring::new();
        let derived_id = probe.add_key_bytes(&embedded)?;
        if derived_id != self.body.key_id {
            return Err(ReceiptError::KeyMismatch(self.body.key_id.clone()));
        }
        let canon = canonicalize(&serde_json::to_value(&self.body)?)?;
        let sig = base64::engine::general_purpose::STANDARD
            .decode(&self.signature_b64)
            .map_err(|_| ReceiptError::Base64)?;
        ring.verify(&self.body.key_id, canon.as_bytes(), &sig)?;
        Ok(())
    }

    /// Verify self-contained (trusting the embedded public key). Suitable when
    /// the verifier obtained the receipt over an authenticated channel or
    /// pins key ids separately. Prefer [`Receipt::verify`] with a ring.
    pub fn verify_embedded(&self) -> Result<(), ReceiptError> {
        let embedded = base64::engine::general_purpose::STANDARD
            .decode(&self.body.public_key_b64)
            .map_err(|_| ReceiptError::Base64)?;
        let embedded: [u8; 32] = embedded.try_into().map_err(|_| ReceiptError::Base64)?;
        let mut ring = Keyring::new();
        let id = ring.add_key_bytes(&embedded)?;
        if id != self.body.key_id {
            return Err(ReceiptError::KeyMismatch(self.body.key_id.clone()));
        }
        let canon = canonicalize(&serde_json::to_value(&self.body)?)?;
        let sig = base64::engine::general_purpose::STANDARD
            .decode(&self.signature_b64)
            .map_err(|_| ReceiptError::Base64)?;
        ring.verify(&id, canon.as_bytes(), &sig)?;
        Ok(())
    }
}

/// Convenience constructor filling issuance time and ids.
#[allow(clippy::too_many_arguments)]
pub fn new_body(
    session_id: String,
    ai_agent: ab_events::AgentIdentity,
    subject: ReceiptSubject,
    tool_calls: ToolCallSummary,
    cost: CostSummary,
    stop_reason: ab_events::StopReason,
) -> ReceiptBody {
    let now = ab_core::time::now_ms();
    ReceiptBody {
        receipt_version: RECEIPT_VERSION,
        receipt_id: ab_core::new_event_uid(),
        session_id,
        issued_at: now,
        issued_at_iso: ab_core::time::iso8601_ms(now),
        ai_agent,
        subject,
        tool_calls,
        cost,
        stop_reason_id: stop_reason.id(),
        stop_reason: stop_reason.caption().to_owned(),
        key_id: String::new(),       // filled by issue()
        public_key_b64: String::new(), // filled by issue()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

    use super::*;
    use crate::keys::Ed25519Signer;

    fn body() -> ReceiptBody {
        new_body(
            "sess-77".into(),
            ab_events::AgentIdentity {
                version: "2.0.1".into(),
                charter: "payments".into(),
                instance_uid: "inst-9".into(),
                ttl_remaining_s: None,
            },
            ReceiptSubject::EventChain {
                chain_head: "ab".repeat(32),
                event_count: 41,
            },
            ToolCallSummary { total: 12, allowed: 10, blocked: 2 },
            CostSummary {
                prompt_tokens: 52_000,
                completion_tokens: 9_000,
                cached_tokens: 30_000,
                cost_usd_micros: 137_500,
            },
            ab_events::StopReason::SessionClosed,
        )
    }

    #[test]
    fn issue_verify_roundtrip() {
        let signer = Ed25519Signer::generate();
        let mut ring = Keyring::new();
        ring.add_signer(&signer).unwrap();
        let receipt = Receipt::issue(body(), &signer).unwrap();
        receipt.verify(&ring).unwrap();
        receipt.verify_embedded().unwrap();
    }

    #[test]
    fn verification_survives_json_roundtrip() {
        // Receipts travel as JSON; key order may change en route. JCS must
        // make verification independent of transport-layer reserialization.
        let signer = Ed25519Signer::generate();
        let mut ring = Keyring::new();
        ring.add_signer(&signer).unwrap();
        let receipt = Receipt::issue(body(), &signer).unwrap();
        let json = serde_json::to_string(&receipt).unwrap();
        let back: Receipt = serde_json::from_str(&json).unwrap();
        back.verify(&ring).unwrap();
    }

    #[test]
    fn every_field_tamper_detected() {
        let signer = Ed25519Signer::generate();
        let mut ring = Keyring::new();
        ring.add_signer(&signer).unwrap();
        let receipt = Receipt::issue(body(), &signer).unwrap();
        let good = serde_json::to_value(&receipt).unwrap();

        let tampers: Vec<(&str, serde_json::Value)> = vec![
            ("session_id", "sess-OTHER".into()),
            ("stop_reason_id", 1.into()),
            ("receipt_id", "forged".into()),
            ("issued_at", 1.into()),
        ];
        for (field, val) in tampers {
            let mut bad = good.clone();
            bad[field] = val;
            let parsed: Receipt = serde_json::from_value(bad).unwrap();
            assert!(parsed.verify(&ring).is_err(), "tampered {field} passed verification");
        }
        // Nested tampers.
        let mut bad = good.clone();
        bad["cost"]["cost_usd_micros"] = 1.into();
        let parsed: Receipt = serde_json::from_value(bad).unwrap();
        assert!(parsed.verify(&ring).is_err(), "tampered cost passed");

        let mut bad = good.clone();
        bad["ai_agent"]["charter"] = "swapped-charter".into();
        let parsed: Receipt = serde_json::from_value(bad).unwrap();
        assert!(parsed.verify(&ring).is_err(), "tampered charter passed");

        let mut bad = good;
        bad["subject"]["chain_head"] = "00".repeat(32).into();
        let parsed: Receipt = serde_json::from_value(bad).unwrap();
        assert!(parsed.verify(&ring).is_err(), "tampered chain head passed");
    }

    #[test]
    fn key_substitution_detected() {
        // Attacker re-signs a modified receipt with their own key but keeps
        // the victim's key id.
        let victim = Ed25519Signer::generate();
        let attacker = Ed25519Signer::generate();
        let mut ring = Keyring::new();
        ring.add_signer(&victim).unwrap();

        let mut receipt = Receipt::issue(body(), &attacker).unwrap();
        receipt.body.key_id = victim.key_id().to_owned(); // lie about identity
        assert!(matches!(receipt.verify(&ring), Err(ReceiptError::KeyMismatch(_))));

        // Variant: also swap in the victim's public key (signature then fails).
        receipt.body.public_key_b64 =
            base64::engine::general_purpose::STANDARD.encode(victim.public_key_bytes());
        assert!(receipt.verify(&ring).is_err());
    }

    #[test]
    fn caller_cannot_forge_key_fields() {
        let signer = Ed25519Signer::generate();
        let mut b = body();
        b.key_id = "attacker-chosen".into();
        b.public_key_b64 = "AAAA".into();
        let receipt = Receipt::issue(b, &signer).unwrap();
        // issue() must have overwritten both.
        assert_eq!(receipt.body.key_id, signer.key_id());
        receipt.verify_embedded().unwrap();
    }

    #[test]
    fn retroactive_atif_subject() {
        let signer = Ed25519Signer::generate();
        let mut ring = Keyring::new();
        ring.add_signer(&signer).unwrap();
        let mut b = body();
        b.subject = ReceiptSubject::AtifTrajectory {
            trajectory_digest: "cd".repeat(32),
            step_count: 18,
            retroactive: true,
        };
        let receipt = Receipt::issue(b, &signer).unwrap();
        receipt.verify(&ring).unwrap();
        let v = serde_json::to_value(&receipt).unwrap();
        assert_eq!(v["subject"]["kind"], "atif_trajectory");
        assert_eq!(v["subject"]["retroactive"], true);
    }

    #[test]
    fn unknown_key_id_fails_ring_verification() {
        let signer = Ed25519Signer::generate();
        let receipt = Receipt::issue(body(), &signer).unwrap();
        let ring = Keyring::new(); // empty
        assert!(receipt.verify(&ring).is_err());
    }
}
