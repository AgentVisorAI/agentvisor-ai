//! Signing keys: the `Signer` trait (in-process Ed25519 now, KMS post-MVP) and
//! an offline `Keyring` for verification with key rotation via key ids.

use ed25519_dalek::{Signature, Signer as DalekSigner, SigningKey, VerifyingKey};
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
    /// (first 32 hex chars of its SHA-256) so ids are collision-resistant and
    /// never chosen by an attacker.
    ///
    /// Round-20 F5: defense-in-depth against a compromised
    /// `getrandom` (VM without entropy, cloud image with a broken
    /// `/dev/urandom`) — regenerate rather than accept an
    /// all-zero or all-0xFF seed. Reader-side already refuses
    /// these known-weak seeds (round-14); this closes the gap
    /// for generator-side. Astronomically unlikely from a healthy
    /// OsRng, but the failure mode is silent installation of a
    /// globally-predictable keypair — cheap to guard.
    pub fn generate() -> Self {
        use rand::TryRng;
        loop {
            // rand 0.9+ removed the infallible `OsRng` that
            // `SigningKey::generate` (rand_core 0.6) accepted; draw the
            // seed through the fallible `SysRng` interface instead and
            // build the key from bytes.
            //
            // Round-21 F2: wrap the raw seed buffer in `Zeroizing` so the
            // stack slot zeroes on scope exit. A bare `[u8; 32]` has no
            // Drop, so it lingers in freed stack memory (recoverable from
            // a core dump).
            let mut bytes = zeroize::Zeroizing::new([0u8; 32]);
            // An OS entropy failure is unrecoverable for key generation;
            // the pre-0.9 `OsRng` path aborted here too (it panicked
            // inside `getrandom`). Panicking keeps the infallible API.
            #[allow(clippy::expect_used)]
            rand::rngs::SysRng
                .try_fill_bytes(&mut *bytes)
                .expect("OS random source unavailable");
            if *bytes == [0u8; 32] || *bytes == [0xFFu8; 32] {
                continue;
            }
            let key = SigningKey::from_bytes(&bytes);
            let key_id = derive_key_id(&key.verifying_key());
            return Self { key_id, key };
        }
    }

    /// Load from a 32-byte secret seed.
    ///
    /// Round-19 F2: takes `&[u8; 32]` (borrow), not by value. Passing
    /// the seed by value materializes a caller-owned temp slot on
    /// the stack that Rust does not guarantee to zeroize on drop —
    /// the round-18 F5 `Zeroizing<[u8; 32]>` wrapper only zeroizes
    /// the slot IT owns, not the copy the callee received. By taking
    /// a reference we let the caller keep the seed inside a
    /// `Zeroizing` and never lose control of the memory.
    ///
    /// # Caveat: caller must reject known-weak seeds
    ///
    /// This constructor does NOT reject the all-zero or all-0xFF seeds
    /// (both produce globally-predictable keypairs). The production
    /// seed-loading path in `av-harness::main::read_signer` refuses
    /// both before reaching this function (see the `[0u8; 32]` /
    /// `[0xFFu8; 32]` guard in `av-harness/src/main.rs`); every OTHER
    /// caller (tests, `avctl keygen`) must apply the same policy or
    /// use [`Ed25519Signer::generate`] which loops until a non-weak
    /// seed is drawn. Round-51 F2 documents this contract in-signature
    /// so a future refactor cannot silently drop the pre-validation.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let key = SigningKey::from_bytes(seed);
        let key_id = derive_key_id(&key.verifying_key());
        Self { key_id, key }
    }

    /// Export the 32-byte secret seed (for `avctl keygen` persistence).
    ///
    /// Round-19 F2: returns `Zeroizing<[u8; 32]>` so the caller's
    /// receiving slot zeroes on drop — historically the bare
    /// `[u8; 32]` return let a copy linger in freed stack/heap.
    pub fn seed(&self) -> zeroize::Zeroizing<[u8; 32]> {
        zeroize::Zeroizing::new(self.key.to_bytes())
    }
}

/// `sha256(pubkey)[..16]` hex — 32 chars (a 128-bit id; ~2^64 birthday bound).
///
/// 64 bits would put birthday attacks at ~2^32, cheap on modern hardware;
/// 128 bits pushes the birthday bound to ~2^64, comfortably infeasible.
fn derive_key_id(vk: &VerifyingKey) -> String {
    let digest = av_core::digest::sha256_hex(vk.as_bytes());
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
    /// Public key is a small-order Curve25519 point (identity or a torsion
    /// element). Such keys let any 64-byte value verify as a signature over
    /// almost every message — always refused at add time so a compromised
    /// keyring cannot be constructed.
    #[error("public key is small-order (weak); refused to add to keyring")]
    WeakKey,
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
    ///
    /// Refuses small-order (weak) public keys — the identity point and the
    /// order-2/order-4 torsion elements. `Keyring::verify` already routes
    /// through `verify_strict`, which denies them at verification time; this
    /// is defense-in-depth so a poisoned ring cannot even be constructed
    /// and so no other consumer of the ring (e.g. `Receipt::verify_embedded`)
    /// can be tricked by relying on a non-strict verify. See ed25519-dalek
    /// 3.0 `VerifyingKey::is_weak` / `verify_strict`.
    pub fn add_key_bytes(&mut self, bytes: &[u8; 32]) -> Result<String, KeyError> {
        let vk = VerifyingKey::from_bytes(bytes).map_err(|e| KeyError::InvalidKey(e.to_string()))?;
        if vk.is_weak() {
            return Err(KeyError::WeakKey);
        }
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
    ///
    /// Uses `verify_strict` (ed25519-dalek), NOT `verify`. Round-51 F1:
    /// non-strict `verify` accepts signatures whose R component or the
    /// verifying key itself is a small-order Curve25519 point. In that
    /// regime a single signature can validate against multiple distinct
    /// messages, so a mutated receipt body whose signature is untouched
    /// can still verify. `verify_strict` rejects small-order R AND
    /// small-order pubkeys (dalek verifying.rs:367-390 in 3.0.0) and is
    /// the documented recommendation for new protocols.
    pub fn verify(&self, key_id: &str, msg: &[u8], sig: &[u8]) -> Result<(), KeyError> {
        let vk = self
            .keys
            .get(key_id)
            .ok_or_else(|| KeyError::UnknownKeyId(key_id.to_owned()))?;
        let sig_bytes: [u8; 64] = sig.try_into().map_err(|_| KeyError::InvalidSignature)?;
        let signature = Signature::from_bytes(&sig_bytes);
        vk.verify_strict(msg, &signature)
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
        let b = Ed25519Signer::from_seed(&a.seed());
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
        let attacker = Ed25519Signer::generate();
        assert_ne!(honest.public_key_bytes(), attacker.public_key_bytes());
        // We can't manufacture a real SHA-256 collision, so simulate one at
        // the low-level map: a ring already holding the ATTACKER's key under
        // the honest key's id. Adding the honest key (whose derived id now
        // collides with different bytes) must be refused, not overwritten.
        let attacker_vk = VerifyingKey::from_bytes(&attacker.public_key_bytes()).unwrap();
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
