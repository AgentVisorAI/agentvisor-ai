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
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
///
/// The wire shape is intentionally flat (13 body fields + `signature_b64`
/// at the top level) — the schema at `schemas/receipt-v1.schema.json`
/// commits to it and downstream verifiers (`abctl receipt-verify`,
/// external tools) consume it that way.
///
/// `#[serde(flatten)]` normally silently disables `deny_unknown_fields`
/// on the inner struct, which would let a hostile issuer add extra
/// top-level fields ("claim_extra": "grant admin") that the human
/// reviewer sees but `verify()` accepts (the field never survives the
/// round-trip to `ReceiptBody` used inside `canonicalize`). To close
/// that gap without breaking the wire shape, the [`Deserialize`] impl
/// is written by hand and rejects any top-level key outside the
/// declared whitelist. See the `allowed_list_covers_body_fields_exactly`
/// test for the compile-time-ish drift guard.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Receipt {
    /// Signed body.
    #[serde(flatten)]
    pub body: ReceiptBody,
    /// Ed25519 signature over the JCS canonicalization of the body, base64.
    pub signature_b64: String,
}

/// The 14 top-level keys a receipt is allowed to carry over the wire:
/// the 13 fields of [`ReceiptBody`] plus [`Receipt::signature_b64`].
///
/// Kept in lockstep with [`ReceiptBody`] by
/// `tests::allowed_receipt_top_level_keys_cover_body_fields_exactly`
/// — adding a field to `ReceiptBody` without updating this list breaks
/// that test at CI time.
const ALLOWED_RECEIPT_TOP_LEVEL_KEYS: &[&str] = &[
    "receipt_version",
    "receipt_id",
    "session_id",
    "issued_at",
    "issued_at_iso",
    "ai_agent",
    "subject",
    "tool_calls",
    "cost",
    "stop_reason_id",
    "stop_reason",
    "key_id",
    "public_key_b64",
    "signature_b64",
];

impl<'de> Deserialize<'de> for Receipt {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::{Error as _, MapAccess, Visitor};
        // Custom visitor so we can reject duplicate keys explicitly.
        // `serde_json::Map::deserialize` silently collapses duplicate
        // keys (last-wins) — RFC 8259 leaves the behaviour undefined
        // and other JSON parsers (jq's `--sort-keys`, some strict
        // Python configs, several audit tools) pick first-wins.
        // A hostile issuer could sign under the last-wins interpretation
        // while an auditor reading with a first-wins parser saw the
        // friendly value; the signature would verify but the audit
        // would show a different receipt.
        struct ReceiptVisitor;
        impl<'de> Visitor<'de> for ReceiptVisitor {
            type Value = Receipt;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an AgentBridge Receipt JSON object")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Receipt, M::Error> {
                let mut raw = serde_json::Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if !ALLOWED_RECEIPT_TOP_LEVEL_KEYS.contains(&key.as_str()) {
                        return Err(M::Error::custom(format!(
                            "unknown field `{key}` in Receipt; a signed receipt \
                             may only carry the fields declared in ReceiptBody + \
                             signature_b64. Extra fields would be visible to a raw \
                             JSON reader but not covered by the signature — treat \
                             as tampering."
                        )));
                    }
                    if raw.contains_key(&key) {
                        return Err(M::Error::custom(format!(
                            "duplicate field `{key}` in Receipt; JSON parsers \
                             disagree on duplicate-key semantics (last-wins vs \
                             first-wins), so accepting duplicates would let a \
                             hostile issuer sign under one interpretation while an \
                             auditor's parser reports the other"
                        )));
                    }
                    let value: serde_json::Value = map.next_value()?;
                    raw.insert(key, value);
                }
                let signature_value = raw
                    .remove("signature_b64")
                    .ok_or_else(|| M::Error::missing_field("signature_b64"))?;
                let signature_b64: String =
                    serde_json::from_value(signature_value).map_err(M::Error::custom)?;
                let body: ReceiptBody =
                    serde_json::from_value(serde_json::Value::Object(raw)).map_err(M::Error::custom)?;
                Ok(Receipt { body, signature_b64 })
            }
        }
        deserializer.deserialize_map(ReceiptVisitor)
    }
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
    /// Round-15 F4: a JSON object at some nesting level carried a
    /// duplicate key. Rejecting these closes the last-wins vs
    /// first-wins auditor split-brain that would otherwise let a
    /// hostile issuer sign under one interpretation while an
    /// external audit tool displayed the other.
    #[error("duplicate JSON key `{0}` at nesting; strict receipt parsers refuse this")]
    DuplicateKey(String),
}

impl Receipt {
    /// Deserialize a receipt from wire bytes, rejecting any duplicate
    /// key at ANY nesting level.
    ///
    /// The custom `Deserialize` impl for `Receipt` (below) already
    /// rejects duplicate top-level keys, but nested structs
    /// (`ai_agent`, `tool_calls`, `cost`, `subject`) went through
    /// serde's default derive which relies on `serde_json::Map` /
    /// `IndexMap` — both silently collapse duplicate keys with
    /// last-wins semantics. A hostile issuer could then sign a
    /// receipt whose `ai_agent.instance_uid` appeared twice
    /// (`"a"` then `"b"`); JCS canonicalisation saw only `"b"` so
    /// the signature verified, but a first-wins auditor tool (jq's
    /// default, some Python configs) displayed `"a"` — the exact
    /// split-brain the top-level guard was written to prevent, one
    /// level deeper.
    ///
    /// Round-15 F4: pre-scan the JSON with a strict duplicate-key
    /// checker (`check_no_duplicate_keys`) before deserialising into
    /// `Receipt`. Callers verifying a receipt off the wire should
    /// prefer this over `serde_json::from_slice::<Receipt>`.
    pub fn from_json_slice(bytes: &[u8]) -> Result<Self, ReceiptError> {
        check_no_duplicate_keys(bytes)?;
        serde_json::from_slice(bytes).map_err(ReceiptError::Serde)
    }

    /// Same as [`Receipt::from_json_slice`] for owned/borrowed strings.
    pub fn from_json_str(s: &str) -> Result<Self, ReceiptError> {
        Self::from_json_slice(s.as_bytes())
    }

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

/// Walk a JSON document and reject any object whose keys contain a
/// duplicate at ANY nesting level.
///
/// Used by [`Receipt::from_json_slice`] as a strict pre-parse gate.
/// serde_json's default `Value` / `Map` uses `IndexMap` (with
/// `preserve_order`), which silently keeps only the LAST value for a
/// duplicate key at deserialize time — collapsing evidence that a
/// hostile issuer signed a document with two spellings of the same
/// key and a first-wins auditor would see the earlier one. This
/// walk runs upfront so the collapse never happens.
fn check_no_duplicate_keys(bytes: &[u8]) -> Result<(), ReceiptError> {
    use serde::Deserializer as _;
    let mut deser = serde_json::Deserializer::from_slice(bytes);
    deser
        .deserialize_any(NoDupVisitor)
        .map_err(|error| ReceiptError::DuplicateKey(error.to_string()))
}

struct NoDupVisitor;

impl<'de> serde::de::Visitor<'de> for NoDupVisitor {
    type Value = ();
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("any JSON value (strict-mode duplicate-key check)")
    }
    fn visit_bool<E>(self, _: bool) -> Result<(), E> { Ok(()) }
    fn visit_i64<E>(self, _: i64) -> Result<(), E> { Ok(()) }
    fn visit_u64<E>(self, _: u64) -> Result<(), E> { Ok(()) }
    fn visit_f64<E>(self, _: f64) -> Result<(), E> { Ok(()) }
    fn visit_i128<E>(self, _: i128) -> Result<(), E> { Ok(()) }
    fn visit_u128<E>(self, _: u128) -> Result<(), E> { Ok(()) }
    fn visit_str<E>(self, _: &str) -> Result<(), E> { Ok(()) }
    fn visit_string<E>(self, _: String) -> Result<(), E> { Ok(()) }
    fn visit_none<E>(self) -> Result<(), E> { Ok(()) }
    fn visit_unit<E>(self) -> Result<(), E> { Ok(()) }
    fn visit_seq<S: serde::de::SeqAccess<'de>>(self, mut seq: S) -> Result<(), S::Error> {
        while seq.next_element_seed(NoDupSeed)?.is_some() {}
        Ok(())
    }
    fn visit_map<M: serde::de::MapAccess<'de>>(self, mut map: M) -> Result<(), M::Error> {
        use serde::de::Error as _;
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(M::Error::custom(format!(
                    "duplicate key `{key}` in JSON object"
                )));
            }
            map.next_value_seed(NoDupSeed)?;
        }
        Ok(())
    }
}

struct NoDupSeed;

impl<'de> serde::de::DeserializeSeed<'de> for NoDupSeed {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(self, deser: D) -> Result<(), D::Error> {
        deser.deserialize_any(NoDupVisitor)
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
        key_id: String::new(),         // filled by issue()
        public_key_b64: String::new(), // filled by issue()
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
            ToolCallSummary {
                total: 12,
                allowed: 10,
                blocked: 2,
            },
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

    /// Round-15 F4: `Receipt::from_json_slice` rejects duplicate keys
    /// at ANY nesting level (top-level, nested inside `ai_agent`,
    /// nested inside `subject`, deep inside an array element). This
    /// closes the last-wins vs first-wins auditor split-brain that
    /// would otherwise let a hostile issuer sign under one
    /// interpretation while an external audit tool showed the other.
    #[test]
    fn from_json_slice_rejects_duplicate_top_level_key() {
        let bytes = br#"{"receipt_version":1,"receipt_version":2,"receipt_id":"x"}"#;
        let outcome = Receipt::from_json_slice(bytes);
        assert!(
            matches!(outcome, Err(ReceiptError::DuplicateKey(ref msg)) if msg.contains("receipt_version")),
            "expected DuplicateKey rejection, got {outcome:?}"
        );
    }

    #[test]
    fn from_json_slice_rejects_duplicate_key_inside_ai_agent() {
        let bytes = br#"{"ai_agent":{"instance_uid":"a","instance_uid":"b"}}"#;
        let outcome = Receipt::from_json_slice(bytes);
        assert!(
            matches!(outcome, Err(ReceiptError::DuplicateKey(ref msg)) if msg.contains("instance_uid")),
            "expected DuplicateKey rejection for nested field, got {outcome:?}"
        );
    }

    #[test]
    fn from_json_slice_rejects_duplicate_key_inside_array_element() {
        // Rare shape but valid JSON that would slip past the top-level
        // guard historically. Deep nesting → the walker recurses.
        let bytes = br#"{"weird":[{"dup":1,"dup":2}]}"#;
        let outcome = Receipt::from_json_slice(bytes);
        assert!(
            matches!(outcome, Err(ReceiptError::DuplicateKey(ref msg)) if msg.contains("dup")),
            "expected DuplicateKey rejection deep in an array, got {outcome:?}"
        );
    }

    /// The happy path (well-formed receipt) still deserializes as
    /// before — the duplicate-key gate is a strict filter, not a
    /// disruption.
    #[test]
    fn from_json_slice_accepts_a_well_formed_receipt() {
        let signer = Ed25519Signer::generate();
        let receipt = Receipt::issue(body(), &signer).unwrap();
        let bytes = serde_json::to_vec(&receipt).unwrap();
        let restored = Receipt::from_json_slice(&bytes).unwrap();
        assert_eq!(restored.body.session_id, "sess-77");
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
    fn issued_receipt_matches_shipped_schema() {
        let signer = Ed25519Signer::from_seed([13; 32]);
        let receipt = Receipt::issue(body(), &signer).unwrap();
        let schema: serde_json::Value =
            serde_json::from_str(include_str!("../../../schemas/receipt-v1.schema.json")).unwrap();
        let validator = jsonschema::validator_for(&schema).unwrap();
        let value = serde_json::to_value(receipt).unwrap();
        let errors: Vec<_> = validator.iter_errors(&value).collect();
        assert!(errors.is_empty(), "{errors:?}");
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
            assert!(
                parsed.verify(&ring).is_err(),
                "tampered {field} passed verification"
            );
        }
        // Nested tampers.
        let mut bad = good.clone();
        bad["cost"]["cost_usd_micros"] = 1.into();
        let parsed: Receipt = serde_json::from_value(bad).unwrap();
        assert!(parsed.verify(&ring).is_err(), "tampered cost passed");

        let mut bad = good.clone();
        bad["ai_agent"]["charter"]["name"] = "swapped-charter".into();
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

    #[test]
    fn attacker_receipt_does_not_pass_a_ring_seeded_with_only_a_different_key() {
        let attacker = Ed25519Signer::generate();
        let honest = Ed25519Signer::generate();
        assert_ne!(attacker.key_id(), honest.key_id());
        let forged = Receipt::issue(body(), &attacker).unwrap();
        let mut ring = Keyring::new();
        ring.add_signer(&honest).unwrap();
        assert!(matches!(
            forged.verify(&ring),
            Err(ReceiptError::Key(KeyError::UnknownKeyId(_)))
        ));
    }

    #[test]
    fn verify_embedded_rejects_a_tampered_body() {
        // verify_embedded MUST NOT be reducible to Ok(()): tamper the
        // session_id and require Err. Catches any stub or short-circuit
        // that would silently accept every receipt.
        let signer = Ed25519Signer::generate();
        let receipt = Receipt::issue(body(), &signer).unwrap();
        let mut raw = serde_json::to_value(&receipt).unwrap();
        raw["session_id"] = serde_json::Value::from("attacker");
        let tampered: Receipt = serde_json::from_value(raw).unwrap();
        assert!(tampered.verify_embedded().is_err());
    }

    #[test]
    fn verify_embedded_rejects_a_swapped_public_key() {
        // Substitute the embedded pubkey for someone else's — the id/key
        // binding inside verify_embedded must catch this.
        let honest = Ed25519Signer::generate();
        let attacker = Ed25519Signer::generate();
        let mut receipt = Receipt::issue(body(), &honest).unwrap();
        receipt.body.public_key_b64 =
            base64::engine::general_purpose::STANDARD.encode(attacker.public_key_bytes());
        assert!(receipt.verify_embedded().is_err());
    }

    /// Stress: for every wall-clock instant sampled during issuance, the
    /// integer `issued_at` and the human-readable `issued_at_iso` must be
    /// mutually consistent. If they ever drift, downstream consumers that
    /// parse only one field could reconstruct a different timestamp than
    /// the signer intended, and the signature's coverage of both fields
    /// would still verify (since the signer produced them together).
    #[test]
    fn issued_at_and_issued_at_iso_are_always_consistent() {
        let signer = Ed25519Signer::generate();
        for _ in 0..64 {
            let receipt = Receipt::issue(body(), &signer).unwrap();
            let derived = ab_core::time::iso8601_ms(receipt.body.issued_at);
            assert_eq!(
                derived, receipt.body.issued_at_iso,
                "iso/ms mismatch: {} vs {}",
                receipt.body.issued_at, receipt.body.issued_at_iso,
            );
        }
    }

    /// Cross-machine stress: two independently-issued receipts (simulating
    /// two harness replicas whose wall clocks drift within a normal
    /// tolerance) must both verify against the same keyring and carry
    /// UTC-Z timestamps regardless of what timezone the issuing process
    /// was configured with.
    #[test]
    fn receipts_issued_by_two_machines_both_verify_and_use_utc_zulu() {
        let signer_a = Ed25519Signer::generate();
        let signer_b = Ed25519Signer::generate();
        let mut ring = Keyring::new();
        ring.add_signer(&signer_a).unwrap();
        ring.add_signer(&signer_b).unwrap();
        let ra = Receipt::issue(body(), &signer_a).unwrap();
        let rb = Receipt::issue(body(), &signer_b).unwrap();
        ra.verify(&ring).unwrap();
        rb.verify(&ring).unwrap();
        assert!(ra.body.issued_at_iso.ends_with('Z'), "{}", ra.body.issued_at_iso,);
        assert!(rb.body.issued_at_iso.ends_with('Z'), "{}", rb.body.issued_at_iso,);
        // Both timestamps must be within a minute of each other on the
        // same physical host running the test.
        let diff_ms = ra.body.issued_at.abs_diff(rb.body.issued_at);
        assert!(diff_ms < 60_000, "clocks {diff_ms} ms apart");
    }

    /// A receipt with an extra top-level field that the signer did not
    /// include in the signed body would appear in a raw-JSON audit
    /// reader but be invisible to `verify()` (the field silently drops
    /// during the ReceiptBody round-trip inside canonicalize). Our
    /// custom `Deserialize` rejects it at parse time — a corrupted /
    /// tampered receipt fails before it can be trusted.
    #[test]
    fn receipt_with_unknown_top_level_field_is_rejected_on_parse() {
        let signer = Ed25519Signer::generate();
        let receipt = Receipt::issue(body(), &signer).unwrap();
        let mut value: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&receipt).unwrap()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("claim_extra".to_owned(), serde_json::json!("grant admin"));
        let tampered = serde_json::to_string(&value).unwrap();
        let error = serde_json::from_str::<Receipt>(&tampered).unwrap_err();
        assert!(
            error.to_string().contains("claim_extra"),
            "error should name the offending field: {error}"
        );
    }

    /// The manual whitelist must stay in lockstep with the field set of
    /// [`ReceiptBody`]. If a new field is added there without updating
    /// [`ALLOWED_RECEIPT_TOP_LEVEL_KEYS`], parsing that field silently
    /// fails (or worse, drops it back into the same class of bug we
    /// fixed). Serializing a canonical body and cross-checking is the
    /// mechanical guard.
    #[test]
    fn allowed_receipt_top_level_keys_cover_body_fields_exactly() {
        let value = serde_json::to_value(body()).unwrap();
        let object = value.as_object().unwrap();
        let mut body_keys: Vec<&str> = object.keys().map(String::as_str).collect();
        body_keys.push("signature_b64");
        body_keys.sort_unstable();
        let mut allowed: Vec<&str> = ALLOWED_RECEIPT_TOP_LEVEL_KEYS.to_vec();
        allowed.sort_unstable();
        assert_eq!(
            body_keys, allowed,
            "ALLOWED_RECEIPT_TOP_LEVEL_KEYS drift vs ReceiptBody serialization"
        );
    }

    /// A hostile issuer could sign under one JSON parser's
    /// duplicate-key semantics (usually last-wins) while an auditor
    /// reads the same wire bytes under a different parser
    /// (first-wins). Both parses "succeed" but see different receipt
    /// contents. Our custom Deserialize now rejects duplicates
    /// outright, closing the parser-disagreement audit-spoofing gap.
    #[test]
    fn receipt_with_duplicate_top_level_key_is_rejected_on_parse() {
        // Hand-craft the JSON so both `session_id` entries land at the
        // top level and are seen in order by the map visitor. Rust's
        // `format!` guarantees a fixed byte sequence.
        let signer = Ed25519Signer::generate();
        let receipt = Receipt::issue(body(), &signer).unwrap();
        let good = serde_json::to_string(&receipt).unwrap();
        // Inject a second `session_id` right before the closing `}`.
        assert!(good.ends_with('}'));
        let tampered = format!(
            "{},\"session_id\":\"forged-second-copy\"}}",
            &good[..good.len() - 1]
        );
        let error = serde_json::from_str::<Receipt>(&tampered).unwrap_err();
        assert!(
            error.to_string().contains("duplicate field"),
            "expected duplicate-key rejection, got: {error}"
        );
        assert!(
            error.to_string().contains("session_id"),
            "error should name the offending field, got: {error}"
        );
    }
}
