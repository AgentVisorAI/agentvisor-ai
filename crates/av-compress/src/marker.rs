//! Keyed authentication tags for machine-emitted compression stubs.
//!
//! Every pruning pass leaves an audit stub so a reviewer can prove what was
//! removed. The stub shape is a plain string, so without authentication any
//! message whose text happens to look like a stub could impersonate one —
//! and the middle-history pass treats "a stub is already present" as a
//! reason to skip. This module signs each stub with an HMAC under a key
//! derived from the journal key, so only the gateway can mint a real stub.
//!
//! The tag covers the stub body (which already commits to the pruned
//! content through its SHA-256), so a tag cannot be moved from one stub to
//! another. Verification needs only the stub text; the original content is
//! already gone.

use hmac::{Hmac, KeyInit as _, Mac as _};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Truncated HMAC tag length (128 bits), matching the MCP session signer.
const TAG_BYTES: usize = 16;

/// Domain separation for the stub-tag MAC.
const MAC_CONTEXT: &[u8] = b"agentvisor-compress-marker-v1";

/// Domain separation for the marker-key derivation.
const KEY_CONTEXT: &[u8] = b"agentvisor-compress-marker-key-v1";

/// Separator between the stub body and its tag. The three stub bodies the
/// passes build never contain this text, so `rsplit_once` is unambiguous.
const TAG_SEPARATOR: &str = " tag:";

/// Machine-stub prefix shared by every pass.
pub(crate) const STUB_PREFIX: &str = "[pruned:";

/// Derive a dedicated marker key from the journal key (itself derived
/// from the persistent receipt signer), so stubs survive restarts and
/// share no key material with any other use.
pub fn derive_marker_key(journal_key: &[u8; 32]) -> [u8; 32] {
    let mut key = [0u8; 32];
    if let Ok(mut mac) = HmacSha256::new_from_slice(journal_key) {
        mac.update(KEY_CONTEXT);
        key.copy_from_slice(&mac.finalize().into_bytes());
    }
    key
}

/// Append a keyed tag to a stub body. A `None` key leaves the body
/// unauthenticated (legacy behaviour for callers without key material).
pub(crate) fn tag_stub(key: Option<&[u8; 32]>, body: String) -> String {
    let Some(key) = key else {
        return body;
    };
    let Some(tag) = sign(key, &body) else {
        return body;
    };
    format!("{body}{TAG_SEPARATOR}{tag}")
}

/// True when `content` is a machine-emitted stub.
///
/// With a key, the tag must verify. Without a key, any `[pruned:` prefix
/// counts (legacy unauthenticated behaviour).
pub(crate) fn is_machine_stub(key: Option<&[u8; 32]>, content: &str) -> bool {
    if !content.starts_with(STUB_PREFIX) {
        return false;
    }
    match key {
        Some(key) => verify(key, content),
        None => true,
    }
}

/// True when `content` is a machine-emitted middle-history stub.
pub(crate) fn is_middle_history_stub(key: Option<&[u8; 32]>, content: &str) -> bool {
    if !content.starts_with(STUB_PREFIX) || !content.contains("reason: middle history]") {
        return false;
    }
    match key {
        Some(key) => verify(key, content),
        None => true,
    }
}

fn sign(key: &[u8; 32], body: &str) -> Option<String> {
    let mut mac = HmacSha256::new_from_slice(key).ok()?;
    mac.update(MAC_CONTEXT);
    mac.update(body.as_bytes());
    let tag = mac.finalize().into_bytes();
    Some(hex::encode(tag.get(..TAG_BYTES)?))
}

fn verify(key: &[u8; 32], content: &str) -> bool {
    let Some((body, tag_hex)) = content.rsplit_once(TAG_SEPARATOR) else {
        return false;
    };
    let Some(expected) = sign(key, body) else {
        return false;
    };
    // Fixed-length hex; compare without early exit.
    expected.len() == tag_hex.len()
        && expected
            .bytes()
            .zip(tag_hex.bytes())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_marker_key_is_deterministic_and_domain_separated() {
        let journal = [9u8; 32];
        assert_eq!(derive_marker_key(&journal), derive_marker_key(&journal));
        let mut other = journal;
        other[0] = 8;
        assert_ne!(derive_marker_key(&journal), derive_marker_key(&other));
        // The derived key must not equal the journal key itself.
        assert_ne!(derive_marker_key(&journal), journal);
    }

    #[test]
    fn tagged_stub_verifies_only_under_the_same_key() {
        let key = [7u8; 32];
        let other = [8u8; 32];
        let body = "[pruned: 12 tokens, sha256:ab, reason: middle history]".to_owned();
        let stub = tag_stub(Some(&key), body.clone());
        assert!(stub.starts_with("[pruned:"));
        assert!(stub.contains("reason: middle history]"));
        assert!(is_machine_stub(Some(&key), &stub));
        assert!(is_middle_history_stub(Some(&key), &stub));
        assert!(!is_machine_stub(Some(&other), &stub), "a foreign key must reject");
    }

    #[test]
    fn unkeyed_stub_is_recognized_only_without_a_key() {
        let body = "[pruned: 12 tokens, sha256:ab]".to_owned();
        let stub = tag_stub(None, body.clone());
        assert_eq!(stub, body, "a None key must leave the body unchanged");
        assert!(is_machine_stub(None, &stub));
        assert!(
            !is_machine_stub(Some(&[1u8; 32]), &stub),
            "an untagged stub is not machine-authenticated"
        );
    }

    #[test]
    fn a_tampered_body_breaks_the_tag() {
        let key = [7u8; 32];
        let stub = tag_stub(
            Some(&key),
            "[pruned: 12 tokens, sha256:ab, reason: middle history]".to_owned(),
        );
        let tampered = stub.replace("12 tokens", "13 tokens");
        assert!(!is_machine_stub(Some(&key), &tampered));
    }

    #[test]
    fn a_forged_tag_is_rejected() {
        let key = [7u8; 32];
        let forged =
            "[pruned: 12 tokens, sha256:ab, reason: middle history] tag:00000000000000000000000000000000";
        assert!(!is_machine_stub(Some(&key), forged));
        assert!(!is_middle_history_stub(Some(&key), forged));
    }

    #[test]
    fn quoted_marker_text_without_a_tag_is_not_a_middle_stub() {
        // A user pasting a stub-shaped quote must not trip the
        // middle-history kill switch.
        let quoted = "[pruned: 999 tokens, sha256:deadbeef, reason: middle history]";
        assert!(is_middle_history_stub(None, quoted));
        assert!(!is_middle_history_stub(Some(&[7u8; 32]), quoted));
    }
}
