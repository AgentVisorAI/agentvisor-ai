//! JTI-based token revocation.
//!
//! Revoked token identifiers are stored in a backend that supports TTL-based
//! expiry. Retention must include the verifier's clock leeway, including
//! its final accepted second.

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Signature-verified identity needed to check an ancestor's revocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationIdentity {
    /// Original issuer. Required so independently issued JTIs cannot collide.
    pub iss: String,
    /// Token identifier within this issuer's namespace.
    pub jti: String,
    /// Issuing agent instance.
    pub instance_uid: String,
    /// Original issued-at time, retained across token exchange.
    pub iat: u64,
}

impl From<&crate::NhiClaims> for RevocationIdentity {
    fn from(claims: &crate::NhiClaims) -> Self {
        Self {
            iss: claims.iss.clone(),
            jti: claims.jti.clone(),
            instance_uid: claims.instance_uid.clone(),
            iat: claims.iat,
        }
    }
}

/// The rule which revoked a validated token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevokedBy {
    /// Its unique token identifier was revoked.
    Jti,
    /// Its instance was revoked through this issued-at cutoff (inclusive).
    Instance {
        /// Last refused issued-at second.
        cutoff: u64,
    },
}

/// Whether a revoke request created a new entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevokeOutcome {
    /// This request first recorded the revocation.
    Revoked,
    /// The token was already revoked; retention was extended if necessary.
    AlreadyRevoked,
}

/// Local, nonblocking health of a revocation dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevocationHealth {
    /// Whether dependency reads are currently admitted by the circuit breaker.
    pub available: bool,
    /// Number of cached entries known to be revoked; never live-token entries.
    pub local_entries: usize,
    /// Elapsed monotonic seconds since the last successful dependency call.
    pub seconds_since_last_success: Option<u64>,
}

/// Trait for pluggable revocation backends. The harness wires this to
/// the `StateStore` (Redis for distributed deployments, in-memory otherwise).
pub trait RevocationStore: Send + Sync {
    /// Read local health without contacting storage. `None` means the backend
    /// does not expose a fallible dependency or availability guard.
    fn health(&self) -> Option<RevocationHealth> {
        None
    }

    /// Mark a JTI as revoked across issuers for an authorized operator. Holder
    /// requests must use `try_revoke_token`. `expires_at` is the epoch second at which the
    /// entry is last required (the token's `exp` plus verifier leeway). An error
    /// means the caller cannot confirm that the write succeeded.
    fn revoke(&self, jti: &str, expires_at: u64) -> Result<(), String>;

    /// `Ok(true)` if an operator-wide JTI rule is present. Identity validation
    /// must use `check_token` to include issuer-scoped rules. An error means the store
    /// could not answer; the validator then refuses the token.
    fn is_revoked(&self, jti: &str) -> Result<bool, String>;

    /// Reclaim entries past their retention period when the backend needs an
    /// explicit sweep. Distributed stores normally use their native TTL.
    fn sweep_expired(&self, _now_s: u64) {}

    /// Atomically record a revocation and report whether it is new.
    /// Backends overriding this method can deduplicate audit records.
    fn try_revoke(&self, jti: &str, expires_at: u64) -> Result<RevokeOutcome, String> {
        self.revoke(jti, expires_at)?;
        Ok(RevokeOutcome::Revoked)
    }

    /// Revoke tokens of an instance issued at or before `issued_at_or_before`.
    /// Repeated writes must never lower either the cutoff or retention time.
    fn revoke_instance(
        &self,
        _instance_uid: &str,
        _issued_at_or_before: u64,
        _expires_at: u64,
    ) -> Result<(), String> {
        Err("instance revocation is not supported by this backend".into())
    }

    /// Revoke a holder-authenticated token only within its verified issuer.
    /// This must use a separate key domain from operator-wide JTI rules.
    /// Backends without scoped storage fail closed instead of widening the
    /// holder's authority to every issuer.
    fn try_revoke_token(&self, _issuer: &str, _jti: &str, _expires_at: u64) -> Result<RevokeOutcome, String> {
        Err("issuer-scoped token revocation is not supported by this backend".into())
    }

    /// Check an issuer-scoped holder rule and the explicit operator-wide rules.
    /// The default preserves global checks for older implementations, which
    /// cannot accept scoped writes until they override both methods.
    fn check_token(
        &self,
        _issuer: &str,
        jti: &str,
        instance_uid: &str,
        iat: u64,
    ) -> Result<Option<RevokedBy>, String> {
        self.check(jti, instance_uid, iat)
    }

    /// Check both the operator-wide token identifier and instance cutoff.
    fn check(&self, jti: &str, _instance_uid: &str, _iat: u64) -> Result<Option<RevokedBy>, String> {
        Ok(self.is_revoked(jti)?.then_some(RevokedBy::Jti))
    }
}

/// In-memory revocation store with lazy expiry sweeps. Suitable for
/// single-instance deployments and testing.
pub struct InMemoryRevocationStore {
    entries: RwLock<HashMap<String, u64>>,
    issued_entries: RwLock<HashMap<(String, String), u64>>,
    instances: RwLock<HashMap<String, (u64, u64)>>,
}

impl InMemoryRevocationStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            issued_entries: RwLock::new(HashMap::new()),
            instances: RwLock::new(HashMap::new()),
        }
    }

    /// Remove entries whose `expires_at` is in the past.
    pub fn sweep(&self, now_s: u64) {
        self.entries.write().retain(|_, exp| *exp >= now_s);
        self.issued_entries.write().retain(|_, exp| *exp >= now_s);
        self.instances.write().retain(|_, (_, exp)| *exp >= now_s);
    }

    /// Number of entries currently stored (for metrics/testing).
    pub fn len(&self) -> usize {
        self.entries.read().len() + self.issued_entries.read().len() + self.instances.read().len()
    }

    /// True when the store is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.read().is_empty()
            && self.issued_entries.read().is_empty()
            && self.instances.read().is_empty()
    }
}

impl Default for InMemoryRevocationStore {
    fn default() -> Self {
        Self::new()
    }
}

impl RevocationStore for InMemoryRevocationStore {
    fn sweep_expired(&self, now_s: u64) {
        self.sweep(now_s);
    }

    fn revoke(&self, jti: &str, expires_at: u64) -> Result<(), String> {
        self.try_revoke(jti, expires_at).map(|_| ())
    }

    fn try_revoke(&self, jti: &str, expires_at: u64) -> Result<RevokeOutcome, String> {
        let mut entries = self.entries.write();
        match entries.entry(jti.to_owned()) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(expires_at);
                Ok(RevokeOutcome::Revoked)
            }
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                *entry.get_mut() = (*entry.get()).max(expires_at);
                Ok(RevokeOutcome::AlreadyRevoked)
            }
        }
    }

    fn is_revoked(&self, jti: &str) -> Result<bool, String> {
        Ok(self.entries.read().contains_key(jti))
    }

    fn try_revoke_token(&self, issuer: &str, jti: &str, expires_at: u64) -> Result<RevokeOutcome, String> {
        let mut entries = self.issued_entries.write();
        match entries.entry((issuer.to_owned(), jti.to_owned())) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(expires_at);
                Ok(RevokeOutcome::Revoked)
            }
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                *entry.get_mut() = (*entry.get()).max(expires_at);
                Ok(RevokeOutcome::AlreadyRevoked)
            }
        }
    }

    fn check_token(&self, issuer: &str, jti: &str, uid: &str, iat: u64) -> Result<Option<RevokedBy>, String> {
        if self
            .issued_entries
            .read()
            .contains_key(&(issuer.to_owned(), jti.to_owned()))
        {
            return Ok(Some(RevokedBy::Jti));
        }
        self.check(jti, uid, iat)
    }

    fn revoke_instance(&self, instance_uid: &str, cutoff: u64, expires_at: u64) -> Result<(), String> {
        let mut entries = self.instances.write();
        let entry = entries
            .entry(instance_uid.to_owned())
            .or_insert((cutoff, expires_at));
        entry.0 = entry.0.max(cutoff);
        entry.1 = entry.1.max(expires_at);
        Ok(())
    }

    fn check(&self, jti: &str, instance_uid: &str, iat: u64) -> Result<Option<RevokedBy>, String> {
        if self.is_revoked(jti)? {
            return Ok(Some(RevokedBy::Jti));
        }
        Ok(self
            .instances
            .read()
            .get(instance_uid)
            .filter(|(cutoff, _)| iat <= *cutoff)
            .map(|(cutoff, _)| RevokedBy::Instance { cutoff: *cutoff }))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn revoke_and_query() {
        let store = InMemoryRevocationStore::new();
        assert!(!store.is_revoked("jti-1").unwrap());
        store.revoke("jti-1", 1000).unwrap();
        assert!(store.is_revoked("jti-1").unwrap());
        assert!(!store.is_revoked("jti-2").unwrap());
    }

    #[test]
    fn sweep_removes_expired() {
        let store = InMemoryRevocationStore::new();
        store.revoke("old", 100).unwrap();
        store.revoke("fresh", 2000).unwrap();
        assert_eq!(store.len(), 2);
        store.sweep(500);
        assert_eq!(store.len(), 1);
        assert!(!store.is_revoked("old").unwrap());
        assert!(store.is_revoked("fresh").unwrap());
    }

    #[test]
    fn re_revoking_never_shortens_the_retention_window() {
        let store = InMemoryRevocationStore::new();
        store.revoke("jti", 2000).unwrap();
        store.revoke("jti", 100).unwrap();
        store.sweep(500);
        assert!(
            store.is_revoked("jti").unwrap(),
            "a second revoke with an earlier expiry must not let the sweep drop the entry early"
        );
    }

    #[test]
    fn empty_store() {
        let store = InMemoryRevocationStore::new();
        assert!(store.is_empty());
        store.revoke("x", 100).unwrap();
        assert!(!store.is_empty());
    }
}
