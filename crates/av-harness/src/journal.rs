//! Authenticated envelopes for active-workflow crash journals.

use hmac::{Hmac, KeyInit as _, Mac as _};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Journal-domain prefixes used by `seal` / `open` to bind an envelope to its
/// intended purpose. Callers pass one of these to prevent cross-domain replay.
pub const LIFECYCLE_OUTBOX_DOMAIN: &str = "lifecycle-outbox";
pub const TOOL_INTENT_DOMAIN: &str = "tool-intent";
pub const TOOL_OUTCOME_DOMAIN: &str = "tool-outcome";
pub const TOOL_AUDITED_DOMAIN: &str = "tool-audited";

/// Lifecycle-outbox kinds (`receipt`, `session-close`) that appear in the
/// on-disk file name and in the outbox filter.
pub const RECEIPT_OUTBOX_KIND: &str = "receipt";
pub const SESSION_CLOSE_OUTBOX_KIND: &str = "session-close";

#[derive(Serialize, Deserialize)]
struct Envelope {
    index: u64,
    payload: serde_json::Value,
    mac: String,
}

/// Derive the deployment-local HMAC key used for authenticated control files.
pub fn key_from_signer(signer: &dyn av_receipts::Signer) -> [u8; 32] {
    let signature = signer.sign(b"agentvisor-active-journal-key-v1");
    let mut key = [0u8; 32];
    key.copy_from_slice(&signature[..32]);
    key
}

pub(crate) fn seal<T: Serialize>(
    key: &[u8; 32],
    domain: &str,
    index: u64,
    value: &T,
) -> Result<Vec<u8>, String> {
    let payload = serde_json::to_value(value).map_err(|error| error.to_string())?;
    let mac = build_mac(key, domain, index, &payload)?.finalize().into_bytes();
    serde_json::to_vec(&Envelope {
        index,
        payload,
        mac: hex::encode(mac),
    })
    .map_err(|error| error.to_string())
}

pub(crate) fn open<T: DeserializeOwned>(
    key: &[u8; 32],
    domain: &str,
    expected_index: u64,
    bytes: &[u8],
) -> Result<T, String> {
    let envelope: Envelope = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    // Round-17 F9: HMAC-SHA256 renders as exactly 64 hex chars. A
    // fs-tamper attacker with a multi-MB mac field would otherwise
    // force `hex::decode` to allocate half the string length on
    // every recovery-scan tick. Cap at 128 (twice the legitimate
    // length to allow one round of format experimentation).
    if envelope.mac.len() > 128 {
        return Err(format!(
            "journal mac field is {} chars; refusing (HMAC-SHA256 is 64 hex chars)",
            envelope.mac.len()
        ));
    }
    let claimed = hex::decode(&envelope.mac).map_err(|error| error.to_string())?;
    // Round-26 F3: verify the MAC BEFORE any index-mismatch branch.
    // The old order (index check first, MAC last) meant that an
    // fs-tamper attacker with read access to the journal directory
    // could probe `expected_index` for every position and learn the
    // reconciler's on-disk cursor via the disclosed `envelope.index`
    // and `expected_index` in the error text. Not a forgery hole —
    // the MAC still guards authenticity — but it's a position
    // oracle that lets an adversary map the state machine and craft
    // targeted quarantine denial-of-restore attacks. Verify first,
    // then compare positions with a generic error.
    let verifier = build_mac(key, domain, envelope.index, &envelope.payload)?;
    verifier
        .verify_slice(&claimed)
        .map_err(|_| "journal authentication failed".to_owned())?;
    if envelope.index != expected_index {
        return Err("journal position mismatch".to_owned());
    }
    serde_json::from_value(envelope.payload).map_err(|error| error.to_string())
}

fn build_mac(
    key: &[u8; 32],
    domain: &str,
    index: u64,
    payload: &serde_json::Value,
) -> Result<HmacSha256, String> {
    let canonical = av_receipts::canonicalize(payload).map_err(|error| error.to_string())?;
    let mut mac = HmacSha256::new_from_slice(key).map_err(|error| error.to_string())?;
    mac.update(b"agentvisor-journal-v1\0");
    mac.update(&(domain.len() as u64).to_be_bytes());
    mac.update(domain.as_bytes());
    mac.update(&index.to_be_bytes());
    mac.update(&(canonical.len() as u64).to_be_bytes());
    mac.update(canonical.as_bytes());
    Ok(mac)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::indexing_slicing, clippy::unwrap_used)]

    use super::*;

    /// The journal HMAC key must be a per-deployment derivation from
    /// the signer — a constant key would give every deployment one
    /// shared forgery key, and NO round-trip test can catch that
    /// (seal and open would agree on the wrong constant). Pin the
    /// uniqueness property directly: distinct signers derive distinct
    /// keys, the same signer derives the same key, and the key is
    /// never a degenerate constant.
    #[test]
    fn journal_key_is_derived_per_signer() {
        let a = av_receipts::Ed25519Signer::from_seed(&[3; 32]);
        let b = av_receipts::Ed25519Signer::from_seed(&[4; 32]);
        let key_a = key_from_signer(&a);
        let key_b = key_from_signer(&b);
        assert_ne!(key_a, key_b, "distinct signers must derive distinct journal keys");
        assert_eq!(key_a, key_from_signer(&a), "derivation must be deterministic");
        assert_ne!(key_a, [0u8; 32]);
        assert_ne!(key_a, [1u8; 32]);
        assert_ne!(key_b, [0u8; 32]);
        assert_ne!(key_b, [1u8; 32]);
    }

    /// The mac field length cap (128 chars) refuses oversized values
    /// before hex-decode allocates; exactly 128 still verifies the MAC
    /// path (and fails authentication, since it's not a real MAC).
    #[test]
    fn oversized_mac_field_is_refused_at_the_cap() {
        let key = [7; 32];
        let sealed = seal(&key, "session:signed", 0, &serde_json::json!({"v": 1})).unwrap();
        let mut envelope: serde_json::Value = serde_json::from_slice(&sealed).unwrap();
        envelope["mac"] = serde_json::json!("a".repeat(129));
        let oversized = serde_json::to_vec(&envelope).unwrap();
        assert!(open::<serde_json::Value>(&key, "session:signed", 0, &oversized).is_err());
        envelope["mac"] = serde_json::json!("a".repeat(128));
        let at_cap = serde_json::to_vec(&envelope).unwrap();
        assert!(open::<serde_json::Value>(&key, "session:signed", 0, &at_cap).is_err());
    }

    #[test]
    fn mutation_and_reordering_fail_authentication() {
        let key = [7; 32];
        let sealed = seal(&key, "session:signed", 3, &serde_json::json!({"value": 1})).unwrap();
        let value: serde_json::Value = open(&key, "session:signed", 3, &sealed).unwrap();
        assert_eq!(value["value"], 1);
        assert!(open::<serde_json::Value>(&key, "session:signed", 2, &sealed).is_err());
        let mut envelope: serde_json::Value = serde_json::from_slice(&sealed).unwrap();
        envelope["payload"]["value"] = serde_json::json!(2);
        assert!(open::<serde_json::Value>(
            &key,
            "session:signed",
            3,
            &serde_json::to_vec(&envelope).unwrap()
        )
        .is_err());
    }

    /// Every MAC byte mutated in isolation must produce the SAME error
    /// message. A variable-time comparator that short-circuits on the
    /// first mismatching byte would leak, via the error text or via
    /// timing, which byte failed — the classic CWE-208 timing side
    /// channel. We rely on `hmac::Mac::verify_slice` for constant-time
    /// comparison; this test locks the observable behavior.
    #[test]
    fn mac_tamper_at_any_byte_returns_the_same_error() {
        let key = [11; 32];
        let sealed = seal(&key, "domain", 0, &serde_json::json!({"k": "v"})).unwrap();
        let envelope: serde_json::Value = serde_json::from_slice(&sealed).unwrap();
        let mac_hex = envelope["mac"].as_str().unwrap().to_owned();
        let mut errors = std::collections::HashSet::new();
        // Mutate each hex character in turn (32 bytes of MAC = 64 hex chars).
        for i in 0..mac_hex.len() {
            let mut bytes: Vec<u8> = mac_hex.as_bytes().to_vec();
            // Flip a nibble to something guaranteed different.
            bytes[i] = if bytes[i] == b'0' { b'f' } else { b'0' };
            let tampered_hex = String::from_utf8(bytes).unwrap();
            let mut tampered_envelope = envelope.clone();
            tampered_envelope["mac"] = serde_json::json!(tampered_hex);
            let tampered = serde_json::to_vec(&tampered_envelope).unwrap();
            let err = open::<serde_json::Value>(&key, "domain", 0, &tampered).unwrap_err();
            errors.insert(err);
        }
        assert_eq!(
            errors.len(),
            1,
            "MAC verification must return a single error text regardless of which byte failed \
             (got {} distinct error texts, i.e. an oracle): {errors:?}",
            errors.len()
        );
    }

    /// Journal `open` rejects an envelope missing the `mac` field with the
    /// SAME error surface as any other malformed input — the presence or
    /// absence of the MAC must not distinguish itself from a bad MAC.
    #[test]
    fn journal_open_treats_missing_mac_as_malformed_not_as_a_verification_failure() {
        let sealed = serde_json::json!({"index": 0, "payload": {"k": "v"}}).to_string();
        let key = [3; 32];
        let err = open::<serde_json::Value>(&key, "domain", 0, sealed.as_bytes())
            .expect_err("must reject an envelope missing mac");
        assert!(
            !err.contains("authentication"),
            "missing-mac error {err:?} must not leak MAC-verification status",
        );
    }

    /// Round-26 F3: an fs-tamper attacker with read access to the
    /// journal directory used to be able to probe `expected_index`
    /// by feeding any envelope with a wrong index and reading both
    /// values out of the disclosed error text — a position oracle
    /// for the reconciler's on-disk cursor. Now MAC is verified
    /// first; a wrong-index envelope with a real MAC returns a
    /// generic "position mismatch"; a wrong-index envelope with a
    /// forged MAC returns "authentication failed"; neither reveals
    /// `envelope.index` or `expected_index`.
    #[test]
    fn round_26_f3_index_mismatch_error_does_not_disclose_position() {
        let key = [17; 32];
        // Envelope legitimately sealed at index=3.
        let sealed_at_3 = seal(&key, "domain", 3, &serde_json::json!({"k": "v"})).unwrap();
        // Caller expects index=99 — the check now fires AFTER MAC verify
        // succeeds, and the error must not carry either number.
        let err = open::<serde_json::Value>(&key, "domain", 99, &sealed_at_3).unwrap_err();
        assert!(
            !err.contains("3") && !err.contains("99"),
            "position mismatch error must not disclose either index; got {err:?}"
        );
        assert!(
            !err.contains("authentication"),
            "mismatch on a genuine envelope must not be labelled an auth failure; got {err:?}"
        );
        // A wrong-index envelope with a forged MAC should be labelled
        // authentication (the MAC check fires first now, so a probe
        // never reaches the position compare on a forgery).
        let mut envelope: serde_json::Value = serde_json::from_slice(&sealed_at_3).unwrap();
        envelope["mac"] = serde_json::json!("00".repeat(32));
        let forged = serde_json::to_vec(&envelope).unwrap();
        let err = open::<serde_json::Value>(&key, "domain", 99, &forged).unwrap_err();
        assert!(
            err.contains("authentication"),
            "forged MAC must fail as authentication, not position mismatch; got {err:?}"
        );
    }
}
