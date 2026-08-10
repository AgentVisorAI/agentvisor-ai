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
        f.debug_struct("Ed25519Signer").field("key_id", &self.key_id).finish_non_exhaustive()
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

/// `sha256(pubkey)[..8]` hex — 16 chars.
fn derive_key_id(vk: &VerifyingKey) -> String {
    let digest = ab_core::digest::sha256_hex(vk.as_bytes());
    digest.chars().take(16).collect()
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
}

impl Keyring {
    /// Empty ring.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a key by raw public bytes; returns its derived key id.
    pub fn add_key_bytes(&mut self, bytes: &[u8; 32]) -> Result<String, KeyError> {
        let vk = VerifyingKey::from_bytes(bytes).map_err(|e| KeyError::InvalidKey(e.to_string()))?;
        let id = derive_key_id(&vk);
        self.keys.insert(id.clone(), vk);
        Ok(id)
    }

    /// Add the public half of a signer.
    pub fn add_signer(&mut self, signer: &dyn Signer) -> Result<String, KeyError> {
        self.add_key_bytes(&signer.public_key_bytes())
    }

    /// Verify `sig` over `msg` with the key identified by `key_id`.
    pub fn verify(&self, key_id: &str, msg: &[u8], sig: &[u8]) -> Result<(), KeyError> {
        let vk = self.keys.get(key_id).ok_or_else(|| KeyError::UnknownKeyId(key_id.to_owned()))?;
        let sig_bytes: [u8; 64] = sig.try_into().map_err(|_| KeyError::InvalidSignature)?;
        let signature = Signature::from_bytes(&sig_bytes);
        vk.verify(msg, &signature).map_err(|_| KeyError::BadSignature(key_id.to_owned()))
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
        assert!(matches!(ring.verify(&id, b"HELLO", &sig), Err(KeyError::BadSignature(_))));
    }

    #[test]
    fn wrong_key_fails() {
        let a = Ed25519Signer::generate();
        let b = Ed25519Signer::generate();
        let mut ring = Keyring::new();
        ring.add_signer(&b).unwrap();
        let sig = a.sign(b"msg");
        // b's ring doesn't know a's key id.
        assert!(matches!(ring.verify(a.key_id(), b"msg", &sig), Err(KeyError::UnknownKeyId(_))));
    }

    #[test]
    fn truncated_signature_rejected() {
        let signer = Ed25519Signer::generate();
        let mut ring = Keyring::new();
        let id = ring.add_signer(&signer).unwrap();
        let sig = signer.sign(b"msg");
        assert!(matches!(ring.verify(&id, b"msg", &sig[..63]), Err(KeyError::InvalidSignature)));
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
    }
}
