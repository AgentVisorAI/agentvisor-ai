//! Signing keys: the `Signer` trait (in-process Ed25519 now, KMS post-MVP) and
//! an offline `Keyring` for verification with key rotation via key ids.

use ed25519_dalek::{Signature, Signer as DalekSigner, SigningKey, Verifier, VerifyingKey};
use std::collections::HashMap;

/// Abstract signer — the KMS integration point (brief Module G, post-MVP).
pub trait Signer: Send + Sync {
    /// Stable identifier for the signing key (embedded in receipts).
    fn key_id(&self) -> &str;
    /// Sign `msg`, returning the 64-byte Ed25519 signature.
    fn sign(&self, msg: &[u8]) -> [u8; 64];
    /// The corresponding public key (32 bytes).
    fn public_key_bytes(&self) -> [u8; 32];
}

/// In-process Ed25519 signer.
pub struct Ed25519Signer {
    key_id: String,
    key: SigningKey,
}

impl std::fmt::Debug for Ed25519Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print secret key material.
        f.debug_struct("Ed25519Signer")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

impl Ed25519Signer {
    /// Generate a fresh keypair. The key id is derived from the public key
    /// (first 16 hex chars of its SHA-256) so ids are collision-resistant and
    /// never chosen by an attacker.
    pub fn generate() -> Self {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let key_id = derive_key_id(&key.verifying_key());
        Self { key_id, key }
    }

    /// Load from a 32-byte secret seed.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let key = SigningKey::from_bytes(&seed);
        let key_id = derive_key_id(&key.verifying_key());
        Self { key_id, key }
    }

    /// Export the 32-byte secret seed (for `abctl keygen` persistence).
    pub fn seed(&self) -> [u8; 32] {
        self.key.to_bytes()
    }
}

/// `sha256(pubkey)[..16]` hex — 32 chars (128-bit collision resistance).
///
/// 64 bits would put birthday attacks at ~2^32, cheap on modern hardware;
/// 128 bits pushes the birthday bound to ~2^64, comfortably infeasible.
fn derive_key_id(vk: &VerifyingKey) -> String {
    let digest = ab_core::digest::sha256_hex(vk.as_bytes());
    digest.chars().take(32).collect()
}

impl Signer for Ed25519Signer {
    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.key.sign(msg).to_bytes()
    }

    fn public_key_bytes(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }
}

/// Verification keyring: key id → public key. Old receipts stay verifiable
/// after rotation as long as their key remains in the ring.
#[derive(Debug, Default, Clone)]
pub struct Keyring {
    keys: HashMap<String, VerifyingKey>,
}

/// Keyring / verification errors.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KeyError {
    /// Public key bytes malformed.
    #[error("invalid public key: {0}")]
    InvalidKey(String),
    /// Signature bytes malformed.
    #[error("invalid signature encoding")]
    InvalidSignature,
    /// No key with this id.
    #[error("unknown key id {0:?}")]
    UnknownKeyId(String),
    /// Signature did not verify.
    #[error("signature verification failed for key id {0:?}")]
    BadSignature(String),
    /// Two distinct public keys derived the same key id.
    #[error("key id {0:?} is already registered to a different public key")]
    KeyMismatch(String),
}

impl Keyring {
    /// Empty ring.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a key by raw public bytes; returns its derived key id.
    ///
    /// If the derived id already exists with a different public key, refuses
    /// silently overwriting it and returns `KeyMismatch` — otherwise an
    /// attacker who found a 128-bit collision could substitute their key for
    /// an honest signer's.
    pub fn add_key_bytes(&mut self, bytes: &[u8; 32]) -> Result<String, KeyError> {
        let vk = VerifyingKey::from_bytes(bytes).map_err(|e| KeyError::InvalidKey(e.to_string()))?;
        let id = derive_key_id(&vk);
        if let Some(existing) = self.keys.get(&id) {
            if existing.as_bytes() != vk.as_bytes() {
                return Err(KeyError::KeyMismatch(id));
            }
            return Ok(id);
        }
        self.keys.insert(id.clone(), vk);
        Ok(id)
    }

    /// Add the public half of a signer.
    pub fn add_signer(&mut self, signer: &dyn Signer) -> Result<String, KeyError> {
        self.add_key_bytes(&signer.public_key_bytes())
    }

    /// Verify `sig` over `msg` with the key identified by `key_id`.
    pub fn verify(&self, key_id: &str, msg: &[u8], sig: &[u8]) -> Result<(), KeyError> {
        let vk = self
            .keys
            .get(key_id)
            .ok_or_else(|| KeyError::UnknownKeyId(key_id.to_owned()))?;
        let sig_bytes: [u8; 64] = sig.try_into().map_err(|_| KeyError::InvalidSignature)?;
        let signature = Signature::from_bytes(&sig_bytes);
        vk.verify(msg, &signature)
            .map_err(|_| KeyError::BadSignature(key_id.to_owned()))
    }

    /// Number of keys in the ring.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// True if the ring holds no keys.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let signer = Ed25519Signer::generate();
        let mut ring = Keyring::new();
        let id = ring.add_signer(&signer).unwrap();
        assert_eq!(id, signer.key_id());
        let sig = signer.sign(b"hello");
        ring.verify(&id, b"hello", &sig).unwrap();
    }

    #[test]
    fn wrong_message_fails() {
        let signer = Ed25519Signer::generate();
        let mut ring = Keyring::new();
        let id = ring.add_signer(&signer).unwrap();
        let sig = signer.sign(b"hello");
        assert!(matches!(
            ring.verify(&id, b"HELLO", &sig),
            Err(KeyError::BadSignature(_))
        ));
    }

    #[test]
    fn wrong_key_fails() {
        let a = Ed25519Signer::generate();
        let b = Ed25519Signer::generate();
        let mut ring = Keyring::new();
        ring.add_signer(&b).unwrap();
        let sig = a.sign(b"msg");
        // b's ring doesn't know a's key id.
        assert!(matches!(
            ring.verify(a.key_id(), b"msg", &sig),
            Err(KeyError::UnknownKeyId(_))
        ));
    }

    #[test]
    fn truncated_signature_rejected() {
        let signer = Ed25519Signer::generate();
        let mut ring = Keyring::new();
        let id = ring.add_signer(&signer).unwrap();
        let sig = signer.sign(b"msg");
        assert!(matches!(
            ring.verify(&id, b"msg", &sig[..63]),
            Err(KeyError::InvalidSignature)
        ));
    }

    #[test]
    fn seed_roundtrip_preserves_identity() {
        let a = Ed25519Signer::generate();
        let b = Ed25519Signer::from_seed(a.seed());
        assert_eq!(a.key_id(), b.key_id());
        assert_eq!(a.public_key_bytes(), b.public_key_bytes());
    }

    #[test]
    fn rotation_keeps_old_receipts_verifiable() {
        let old = Ed25519Signer::generate();
        let new = Ed25519Signer::generate();
        let mut ring = Keyring::new();
        ring.add_signer(&old).unwrap();
        ring.add_signer(&new).unwrap();
        let old_sig = old.sign(b"old receipt");
        let new_sig = new.sign(b"new receipt");
        ring.verify(old.key_id(), b"old receipt", &old_sig).unwrap();
        ring.verify(new.key_id(), b"new receipt", &new_sig).unwrap();
        assert_eq!(ring.len(), 2);
    }

    #[test]
    fn debug_never_leaks_secret() {
        let signer = Ed25519Signer::generate();
        let dbg = format!("{signer:?}");
        let seed_hex = hex::encode(signer.seed());
        assert!(!dbg.contains(&seed_hex), "Debug output leaked the seed");
        // Debug must contain something identifying (the key_id label).
        assert!(dbg.contains(signer.key_id()));
    }

    #[test]
    fn keyring_is_empty_reflects_the_ring_state() {
        let mut ring = Keyring::new();
        assert!(ring.is_empty(), "fresh ring must be empty");
        assert_eq!(ring.len(), 0);
        let s = Ed25519Signer::generate();
        ring.add_signer(&s).unwrap();
        assert!(!ring.is_empty(), "ring with one key must not be empty");
        assert_eq!(ring.len(), 1);
    }

    #[test]
    fn key_id_is_128_bits_wide() {
        let signer = Ed25519Signer::generate();
        assert_eq!(
            signer.key_id().len(),
            32,
            "key_id must be 32 hex chars (128 bits) so birthday collisions cost ~2^64"
        );
    }

    #[test]
    fn keyring_refuses_to_overwrite_colliding_id_with_different_key() {
        let mut ring = Keyring::new();
        let honest = Ed25519Signer::generate();
        let id = ring.add_signer(&honest).unwrap();
        // Simulate a colliding attacker key by forcing a distinct verifying key
        // into the same slot the honest key occupies.
        let attacker = Ed25519Signer::generate();
        assert_ne!(honest.public_key_bytes(), attacker.public_key_bytes());
        ring.keys.insert(
            id.clone(),
            VerifyingKey::from_bytes(&honest.public_key_bytes()).unwrap(),
        );
        // Now try to add the attacker's bytes under the colliding id (rewrite id).
        // We can't manufacture an SHA-256 collision, so we invoke the low-level
        // path directly: the ring's guard MUST refuse the different bytes.
        let mut hostile = ring.clone();
        // Manually place the attacker's key under the honest id.
        let attacker_vk = VerifyingKey::from_bytes(&attacker.public_key_bytes()).unwrap();
        hostile.keys.insert(id.clone(), attacker_vk);
        // A subsequent add of the honest key under the (now-hostile) id must fail.
        // Reproduce the collision by rewriting the id-derivation for the test.
        let mut fresh = Keyring::new();
        fresh.keys.insert(id.clone(), attacker_vk);
        let err = fresh
            .add_key_bytes(&honest.public_key_bytes())
            .expect_err("must refuse overwrite of a colliding id");
        assert!(matches!(err, KeyError::KeyMismatch(_)), "got {err:?}");
    }

    #[test]
    fn keyring_add_is_idempotent_for_the_same_key() {
        let mut ring = Keyring::new();
        let signer = Ed25519Signer::generate();
        let id1 = ring.add_signer(&signer).unwrap();
        let id2 = ring.add_signer(&signer).unwrap();
        assert_eq!(id1, id2);
        assert_eq!(ring.len(), 1);
    }
}
