//! Token revocation list kept in the harness state store (pillar 1).
//!
//! With `state_backend = "redis"`, every replica reads the same list, so a
//! token revoked through one replica is refused by all of them on the next
//! request. The single-process backend keeps
//! [`av_identity::InMemoryRevocationStore`] instead, whose sweep bounds its
//! memory; see `agentvisord`'s startup wiring.

use av_identity::{RevocationStore, RevokeOutcome, RevokedBy};
use av_state::StateStore;
use std::sync::Arc;

/// Revocation list backed by a [`StateStore`]. Each revoked JTI is one
/// counter; the Redis backend expires it 24 h after the write, far past the
/// 15-minute NHI lifetime, so the list cleans itself up.
pub struct StateRevocationStore {
    store: Arc<dyn StateStore>,
    prefix: String,
    instance_prefix: String,
}

impl StateRevocationStore {
    /// Wrap the harness state store.
    pub fn new(store: Arc<dyn StateStore>) -> Self {
        Self {
            store,
            prefix: "av:revoked:".into(),
            instance_prefix: "av:revoked-instance:".into(),
        }
    }

    /// Isolate a harness-issued token namespace from upstream token IDs.
    /// Namespace names are supplied by the application, never by token claims.
    pub fn with_namespace(store: Arc<dyn StateStore>, namespace: &str) -> Self {
        Self {
            store,
            prefix: format!("av:revoked-{namespace}:"),
            instance_prefix: format!("av:revoked-{namespace}-instance:"),
        }
    }

    /// The key holds a digest of the JTI, not the JTI itself: the issuer
    /// controls the claim's length and characters, the key must not.
    fn key(&self, jti: &str) -> String {
        format!("{}{}", self.prefix, av_core::digest::sha256_hex(jti.as_bytes()))
    }

    fn issued_key(&self, issuer: &str, jti: &str) -> String {
        // Separate from the global key's 64-digit suffix. Hash each component
        // independently so no delimiter in either claim can alias another pair.
        format!(
            "{}issuer:{}:{}",
            self.prefix,
            av_core::digest::sha256_hex(issuer.as_bytes()),
            av_core::digest::sha256_hex(jti.as_bytes())
        )
    }

    fn instance_key(&self, instance_uid: &str) -> String {
        format!(
            "{}{}",
            self.instance_prefix,
            av_core::digest::sha256_hex(instance_uid.as_bytes())
        )
    }
}

/// Identity validation runs on tokio workers in several handlers, and a
/// Redis lookup is a synchronous network round-trip that must never stall
/// a worker (the rule `prepare_chat_nonblocking` enforces for budgets). On
/// a multi-thread worker, `block_in_place` first hands the worker's other
/// tasks to another thread. Anywhere else (the blocking pool, no runtime,
/// or a current-thread runtime, where `block_in_place` would panic) the
/// call just runs.
fn off_the_reactor<T>(call: impl FnOnce() -> T) -> T {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(call)
        }
        _ => call(),
    }
}

impl RevocationStore for StateRevocationStore {
    fn revoke(&self, jti: &str, expires_at: u64) -> Result<(), String> {
        self.try_revoke(jti, expires_at).map(|_| ())
    }

    fn try_revoke(&self, jti: &str, _expires_at: u64) -> Result<RevokeOutcome, String> {
        off_the_reactor(|| self.store.add(&self.key(jti), 1))
            .map(|marks| {
                if marks == 1 {
                    RevokeOutcome::Revoked
                } else {
                    RevokeOutcome::AlreadyRevoked
                }
            })
            .map_err(|error| error.to_string())
    }

    fn try_revoke_token(&self, issuer: &str, jti: &str, _expires_at: u64) -> Result<RevokeOutcome, String> {
        off_the_reactor(|| self.store.add(&self.issued_key(issuer, jti), 1))
            .map(|marks| {
                if marks == 1 {
                    RevokeOutcome::Revoked
                } else {
                    RevokeOutcome::AlreadyRevoked
                }
            })
            .map_err(|error| error.to_string())
    }

    fn check_token(&self, issuer: &str, jti: &str, uid: &str, iat: u64) -> Result<Option<RevokedBy>, String> {
        let marks = off_the_reactor(|| self.store.get(&self.issued_key(issuer, jti)))
            .map_err(|error| error.to_string())?;
        if marks > 0 {
            return Ok(Some(RevokedBy::Jti));
        }
        self.check(jti, uid, iat)
    }

    fn is_revoked(&self, jti: &str) -> Result<bool, String> {
        off_the_reactor(|| self.store.get(&self.key(jti)))
            .map(|marks| marks > 0)
            .map_err(|error| error.to_string())
    }

    fn revoke_instance(&self, instance_uid: &str, cutoff: u64, _expires_at: u64) -> Result<(), String> {
        // Encode cutoff+1 so a revocation through epoch zero remains distinct
        // from StateStore::get's missing-key sentinel of zero.
        let encoded = cutoff
            .checked_add(1)
            .ok_or_else(|| "instance cutoff overflow".to_owned())?;
        off_the_reactor(|| self.store.fetch_max(&self.instance_key(instance_uid), encoded))
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    fn check(&self, jti: &str, instance_uid: &str, iat: u64) -> Result<Option<RevokedBy>, String> {
        if self.is_revoked(jti)? {
            return Ok(Some(RevokedBy::Jti));
        }
        let encoded = off_the_reactor(|| self.store.get(&self.instance_key(instance_uid)))
            .map_err(|error| error.to_string())?;
        Ok(encoded
            .checked_sub(1)
            .filter(|cutoff| iat <= *cutoff)
            .map(|cutoff| RevokedBy::Instance { cutoff }))
    }
}

/// Three consecutive dependency failures open the revocation circuit.
const BREAKER_FAILURE_THRESHOLD: u32 = 3;
/// An open circuit permits one recovery probe each second.
const BREAKER_OPEN_TIME: std::time::Duration = std::time::Duration::from_secs(1);
/// Bound memory independently of the number of token identifiers an issuer creates.
const LOCAL_REVOKED_MAX: usize = 100_000;
/// Bound simultaneous synchronous storage calls even before the first failures return.
const MAX_IN_FLIGHT_READS: usize = 32;

trait RevocationClock: Send + Sync {
    fn monotonic(&self) -> std::time::Instant;
    fn epoch_seconds(&self) -> u64;
}

struct SystemRevocationClock;
impl RevocationClock for SystemRevocationClock {
    fn monotonic(&self) -> std::time::Instant {
        std::time::Instant::now()
    }
    fn epoch_seconds(&self) -> u64 {
        av_core::time::now_ms() / 1000
    }
}

#[derive(Clone, Copy)]
struct CachedRevocation {
    cutoff: Option<u64>,
    expires_at: u64,
}

#[derive(Default)]
struct GuardState {
    failures: u32,
    open_until: Option<std::time::Instant>,
    probe: Option<u64>,
    next_probe: u64,
    in_flight: usize,
    last_success: Option<std::time::Instant>,
    revoked: std::collections::HashMap<String, CachedRevocation>,
}

struct GuardMetrics {
    ok: Arc<av_core::metrics::Counter>,
    failed: Arc<av_core::metrics::Counter>,
    short_circuited: Arc<av_core::metrics::Counter>,
    local_revoked: Arc<av_core::metrics::Counter>,
    opened: Arc<av_core::metrics::Counter>,
    available: Arc<av_core::metrics::Gauge>,
    entries: Arc<av_core::metrics::Gauge>,
}

/// Fail-closed protection for distributed revocation storage. Only confirmed
/// revocations and locally requested revocations are cached. A successful
/// "not revoked" answer is never cached, so replicas see later revocations on
/// the next request. Failed writes still return errors to their callers.
///
/// Reads are limited to 32 concurrent dependency calls. After three consecutive
/// errors, reads fail immediately for one second; then one caller probes
/// recovery. Writes always reach the backing store, even while the circuit is
/// open. Positive JTI and instance entries share a strict 100,000-entry bound.
pub struct GuardedRevocationStore {
    inner: Arc<dyn RevocationStore>,
    state: parking_lot::Mutex<GuardState>,
    metrics: GuardMetrics,
    namespace: &'static str,
    clock: Arc<dyn RevocationClock>,
}

impl GuardedRevocationStore {
    /// Wrap a Redis-backed store. Namespace is `nhi` or `exchanged`; any other
    /// caller-supplied name shares the fixed `other` metric label.
    pub fn new(
        inner: Arc<dyn RevocationStore>,
        metrics: &av_core::metrics::Registry,
        namespace: &'static str,
    ) -> Self {
        Self::with_clock(inner, metrics, namespace, Arc::new(SystemRevocationClock))
    }

    fn with_clock(
        inner: Arc<dyn RevocationStore>,
        registry: &av_core::metrics::Registry,
        namespace: &'static str,
        clock: Arc<dyn RevocationClock>,
    ) -> Self {
        let namespace = match namespace {
            "nhi" => "nhi",
            "exchanged" => "exchanged",
            _ => "other",
        };
        let lookup = |outcome: &str| {
            registry.counter(
                &format!("av_revocation_lookups_total{{namespace=\"{namespace}\",outcome=\"{outcome}\"}}"),
                "Revocation dependency lookup outcomes",
            )
        };
        let metrics = GuardMetrics {
            ok: lookup("ok"),
            failed: lookup("failed"),
            short_circuited: lookup("short_circuited"),
            local_revoked: lookup("local_revoked"),
            opened: registry.counter(
                &format!("av_revocation_breaker_opened_total{{namespace=\"{namespace}\"}}"),
                "Revocation dependency circuit openings",
            ),
            available: registry.gauge(
                &format!("av_revocation_list_available{{namespace=\"{namespace}\"}}"),
                "Whether the revocation dependency circuit is closed",
            ),
            entries: registry.gauge(
                &format!("av_revocation_local_entries{{namespace=\"{namespace}\"}}"),
                "Locally cached known revocations",
            ),
        };
        metrics.available.set(1);
        metrics.entries.set(0);
        Self {
            inner,
            state: parking_lot::Mutex::new(GuardState::default()),
            metrics,
            namespace,
            clock,
        }
    }

    fn cache_key(kind: &str, id: &str) -> String {
        format!("{kind}:{}", av_core::digest::sha256_hex(id.as_bytes()))
    }

    fn issued_cache_key(issuer: &str, jti: &str) -> String {
        format!(
            "issuer:{}:{}",
            av_core::digest::sha256_hex(issuer.as_bytes()),
            av_core::digest::sha256_hex(jti.as_bytes())
        )
    }

    fn cached(&self, key: &str) -> Option<CachedRevocation> {
        let now = self.clock.epoch_seconds();
        let mut state = self.state.lock();
        match state.revoked.get(key).copied() {
            Some(entry) if entry.expires_at >= now => Some(entry),
            Some(_) => {
                state.revoked.remove(key);
                self.metrics.entries.set(state.revoked.len() as u64);
                None
            }
            None => None,
        }
    }

    fn remember(&self, key: String, cutoff: Option<u64>, expires_at: u64) {
        if expires_at < self.clock.epoch_seconds() {
            return;
        }
        let mut state = self.state.lock();
        if let Some(entry) = state.revoked.get_mut(&key) {
            entry.expires_at = entry.expires_at.max(expires_at);
            entry.cutoff = entry.cutoff.max(cutoff);
        } else if state.revoked.len() < LOCAL_REVOKED_MAX {
            state.revoked.insert(key, CachedRevocation { cutoff, expires_at });
        }
        self.metrics.entries.set(state.revoked.len() as u64);
    }

    fn retention_from_read(&self) -> u64 {
        self.clock
            .epoch_seconds()
            .saturating_add(av_identity::MAX_TTL_SECS)
            .saturating_add(2 * av_identity::validator::DEFAULT_LEEWAY_SECS)
    }

    fn begin_lookup(&self) -> Result<LookupPermit<'_>, String> {
        let now = self.clock.monotonic();
        let mut state = self.state.lock();
        if state.in_flight >= MAX_IN_FLIGHT_READS
            || state
                .open_until
                .is_some_and(|until| now < until || state.probe.is_some())
        {
            self.metrics.short_circuited.inc();
            return Err("revocation dependency temporarily unavailable".into());
        }
        let probe = if state.open_until.is_some() {
            state.next_probe = state.next_probe.wrapping_add(1);
            let probe = state.next_probe;
            state.probe = Some(probe);
            Some(probe)
        } else {
            None
        };
        state.in_flight += 1;
        Ok(LookupPermit {
            guard: self,
            probe,
            finished: false,
        })
    }

    fn record_result(&self, success: bool, probe: Option<u64>) {
        let now = self.clock.monotonic();
        let mut state = self.state.lock();
        let owns_probe = probe.is_some() && state.probe == probe;
        if owns_probe {
            state.probe = None;
        }
        if success {
            let recovered = state.open_until.take().is_some();
            state.failures = 0;
            state.last_success = Some(now);
            self.metrics.available.set(1);
            if recovered {
                tracing::info!(
                    namespace = self.namespace,
                    "revocation dependency reachable again"
                );
            }
        } else {
            state.failures = state.failures.saturating_add(1);
            if state.failures >= BREAKER_FAILURE_THRESHOLD || owns_probe {
                if state.open_until.is_none() {
                    self.metrics.opened.inc();
                    tracing::error!(
                        namespace = self.namespace,
                        "revocation dependency circuit opened after repeated errors"
                    );
                }
                state.open_until = Some(now + BREAKER_OPEN_TIME);
                self.metrics.available.set(0);
            }
        }
    }

    fn lookup<T>(&self, read: impl FnOnce(&dyn RevocationStore) -> Result<T, String>) -> Result<T, String> {
        let mut permit = self.begin_lookup()?;
        let result = read(self.inner.as_ref());
        if result.is_ok() {
            self.metrics.ok.inc();
        } else {
            self.metrics.failed.inc();
        }
        self.record_result(result.is_ok(), permit.probe);
        permit.finished = true;
        result
    }
}

struct LookupPermit<'a> {
    guard: &'a GuardedRevocationStore,
    probe: Option<u64>,
    finished: bool,
}

impl Drop for LookupPermit<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.guard.metrics.failed.inc();
            self.guard.record_result(false, self.probe);
        }
        let mut state = self.guard.state.lock();
        state.in_flight = state.in_flight.saturating_sub(1);
    }
}

impl RevocationStore for GuardedRevocationStore {
    fn health(&self) -> Option<av_identity::RevocationHealth> {
        let state = self.state.lock();
        Some(av_identity::RevocationHealth {
            available: state.open_until.is_none(),
            local_entries: state.revoked.len(),
            seconds_since_last_success: state
                .last_success
                .map(|last| self.clock.monotonic().saturating_duration_since(last).as_secs()),
        })
    }

    fn sweep_expired(&self, now_s: u64) {
        {
            let mut state = self.state.lock();
            state.revoked.retain(|_, entry| entry.expires_at >= now_s);
            self.metrics.entries.set(state.revoked.len() as u64);
        }
        self.inner.sweep_expired(now_s);
    }

    fn revoke(&self, jti: &str, expires_at: u64) -> Result<(), String> {
        self.try_revoke(jti, expires_at).map(|_| ())
    }

    fn try_revoke(&self, jti: &str, expires_at: u64) -> Result<RevokeOutcome, String> {
        self.remember(Self::cache_key("jti", jti), None, expires_at);
        let result = self.inner.try_revoke(jti, expires_at);
        self.record_result(result.is_ok(), None);
        result
    }

    fn try_revoke_token(&self, issuer: &str, jti: &str, expiry: u64) -> Result<RevokeOutcome, String> {
        self.remember(Self::issued_cache_key(issuer, jti), None, expiry);
        let result = self.inner.try_revoke_token(issuer, jti, expiry);
        self.record_result(result.is_ok(), None);
        result
    }

    fn check_token(&self, issuer: &str, jti: &str, uid: &str, iat: u64) -> Result<Option<RevokedBy>, String> {
        let scoped = Self::issued_cache_key(issuer, jti);
        let global = Self::cache_key("jti", jti);
        if self.cached(&scoped).is_some() || self.cached(&global).is_some() {
            self.metrics.local_revoked.inc();
            return Ok(Some(RevokedBy::Jti));
        }
        let instance = Self::cache_key("instance", uid);
        if let Some(cutoff) = self
            .cached(&instance)
            .and_then(|entry| entry.cutoff)
            .filter(|cutoff| iat <= *cutoff)
        {
            self.metrics.local_revoked.inc();
            return Ok(Some(RevokedBy::Instance { cutoff }));
        }
        let revoked = self.lookup(|inner| inner.check_token(issuer, jti, uid, iat))?;
        match revoked {
            // The backing result may be scoped or global. Cache it only for
            // this issuer, because widening a scoped denial would cross trust
            // boundaries. Global writes still populate the global cache above.
            Some(RevokedBy::Jti) => self.remember(scoped, None, self.retention_from_read()),
            Some(RevokedBy::Instance { cutoff }) => {
                self.remember(instance, Some(cutoff), self.retention_from_read())
            }
            None => {}
        }
        Ok(revoked)
    }

    fn is_revoked(&self, jti: &str) -> Result<bool, String> {
        let key = Self::cache_key("jti", jti);
        if self.cached(&key).is_some() {
            self.metrics.local_revoked.inc();
            return Ok(true);
        }
        let revoked = self.lookup(|inner| inner.is_revoked(jti))?;
        if revoked {
            self.remember(key, None, self.retention_from_read());
        }
        Ok(revoked)
    }

    fn revoke_instance(&self, uid: &str, cutoff: u64, expires_at: u64) -> Result<(), String> {
        self.remember(Self::cache_key("instance", uid), Some(cutoff), expires_at);
        let result = self.inner.revoke_instance(uid, cutoff, expires_at);
        self.record_result(result.is_ok(), None);
        result
    }

    fn check(&self, jti: &str, uid: &str, iat: u64) -> Result<Option<RevokedBy>, String> {
        let jti_key = Self::cache_key("jti", jti);
        if self.cached(&jti_key).is_some() {
            self.metrics.local_revoked.inc();
            return Ok(Some(RevokedBy::Jti));
        }
        let instance_key = Self::cache_key("instance", uid);
        if let Some(cutoff) = self
            .cached(&instance_key)
            .and_then(|entry| entry.cutoff)
            .filter(|cutoff| iat <= *cutoff)
        {
            self.metrics.local_revoked.inc();
            return Ok(Some(RevokedBy::Instance { cutoff }));
        }
        let revoked = self.lookup(|inner| inner.check(jti, uid, iat))?;
        match revoked {
            Some(RevokedBy::Jti) => self.remember(jti_key, None, self.retention_from_read()),
            Some(RevokedBy::Instance { cutoff }) => {
                self.remember(instance_key, Some(cutoff), self.retention_from_read())
            }
            None => {}
        }
        Ok(revoked)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use av_state::{InMemoryStore, Spend, StateError, TrySpendOutcome};

    #[test]
    fn revoked_jti_is_visible_through_every_handle_on_the_same_store() {
        let shared: Arc<dyn StateStore> = Arc::new(InMemoryStore::new());
        let replica_a = StateRevocationStore::new(Arc::clone(&shared));
        let replica_b = StateRevocationStore::new(Arc::clone(&shared));
        assert!(!replica_b.is_revoked("jti-1").unwrap());
        replica_a.revoke("jti-1", 0).unwrap();
        assert!(
            replica_b.is_revoked("jti-1").unwrap(),
            "a revocation must reach every replica"
        );
        assert!(!replica_b.is_revoked("jti-2").unwrap());
    }

    fn round_trip(store: &StateRevocationStore, jti: &str) {
        assert!(!store.is_revoked(jti).unwrap());
        store.revoke(jti, 0).unwrap();
        assert!(store.is_revoked(jti).unwrap());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn lookups_are_safe_on_a_multi_thread_worker_and_its_blocking_pool() {
        let store = Arc::new(StateRevocationStore::new(Arc::new(InMemoryStore::new())));
        round_trip(&store, "on-worker");
        let pooled = Arc::clone(&store);
        tokio::task::spawn_blocking(move || round_trip(&pooled, "on-blocking-pool"))
            .await
            .unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn lookups_are_safe_on_a_current_thread_runtime() {
        let store = StateRevocationStore::new(Arc::new(InMemoryStore::new()));
        round_trip(&store, "current-thread");
    }

    #[test]
    fn lookups_are_safe_outside_any_runtime() {
        let store = StateRevocationStore::new(Arc::new(InMemoryStore::new()));
        round_trip(&store, "no-runtime");
    }

    #[test]
    fn revoking_twice_is_harmless() {
        let store = StateRevocationStore::new(Arc::new(InMemoryStore::new()));
        store.revoke("jti", 0).unwrap();
        store.revoke("jti", 0).unwrap();
        assert!(store.is_revoked("jti").unwrap());
    }

    #[test]
    fn keys_are_bounded_digests_of_the_jti() {
        let store = StateRevocationStore::new(Arc::new(InMemoryStore::new()));
        let long_jti = "x".repeat(10_000);
        let key = store.key(&long_jti);
        assert!(key.starts_with("av:revoked:"));
        assert_eq!(key.len(), "av:revoked:".len() + 64);
        assert_ne!(store.key("a"), store.key("b"));
        assert_eq!(
            store.instance_key(&long_jti).len(),
            "av:revoked-instance:".len() + 64
        );
    }

    struct FailingStore;

    impl StateStore for FailingStore {
        fn add(&self, _key: &str, _delta: u64) -> Result<u64, StateError> {
            Err(StateError::Backend("redis unreachable".into()))
        }
        fn get(&self, _key: &str) -> Result<u64, StateError> {
            Err(StateError::Backend("redis unreachable".into()))
        }
        fn try_spend_many(&self, _spends: &[Spend]) -> Result<TrySpendOutcome, StateError> {
            Err(StateError::Backend("redis unreachable".into()))
        }
        fn remove(&self, _key: &str) {}
    }

    #[test]
    fn backend_failures_surface_as_errors_not_as_not_revoked() {
        let store = StateRevocationStore::new(Arc::new(FailingStore));
        assert!(
            store.revoke("jti", 0).is_err(),
            "a lost revocation must be reported"
        );
        assert!(
            store.is_revoked("jti").is_err(),
            "an unreadable list must not read as 'not revoked'"
        );
        assert!(store.revoke_instance("instance", 1000, 2000).is_err());
        assert!(store.check("jti", "instance", 999).is_err());
    }

    #[test]
    fn instance_revocation_is_monotonic_shared_and_inclusive() {
        let shared: Arc<dyn StateStore> = Arc::new(InMemoryStore::new());
        let writer = StateRevocationStore::new(shared.clone());
        let reader = StateRevocationStore::new(shared);
        assert_eq!(reader.check("jti", "instance", 0).unwrap(), None);
        writer.revoke_instance("instance", 1000, 2000).unwrap();
        writer.revoke_instance("instance", 900, 1900).unwrap();
        assert_eq!(
            reader.check("jti", "instance", 1000).unwrap(),
            Some(RevokedBy::Instance { cutoff: 1000 })
        );
        assert_eq!(reader.check("jti", "instance", 1001).unwrap(), None);
        assert_eq!(reader.check("jti", "another", 1000).unwrap(), None);
        writer.revoke_instance("epoch-zero", 0, 2000).unwrap();
        assert_eq!(
            reader.check("jti", "epoch-zero", 0).unwrap(),
            Some(RevokedBy::Instance { cutoff: 0 })
        );
        assert!(writer.revoke_instance("overflow", u64::MAX, u64::MAX).is_err());
    }

    #[test]
    fn revocation_namespaces_do_not_collide_and_repeated_writes_are_deduplicated() {
        let shared: Arc<dyn StateStore> = Arc::new(InMemoryStore::new());
        let upstream = StateRevocationStore::new(shared.clone());
        let exchanged = StateRevocationStore::with_namespace(shared, "exchanged");
        assert_eq!(
            upstream.try_revoke("same-jti", 2000).unwrap(),
            RevokeOutcome::Revoked
        );
        assert_eq!(
            upstream.try_revoke("same-jti", 2000).unwrap(),
            RevokeOutcome::AlreadyRevoked
        );
        assert!(!exchanged.is_revoked("same-jti").unwrap());
        assert_eq!(
            exchanged.try_revoke("same-jti", 2000).unwrap(),
            RevokeOutcome::Revoked
        );
    }
    struct TestClock {
        epoch: std::time::Instant,
        millis: std::sync::atomic::AtomicU64,
    }
    impl TestClock {
        fn new() -> Self {
            Self {
                epoch: std::time::Instant::now(),
                millis: std::sync::atomic::AtomicU64::new(0),
            }
        }
        fn advance(&self, millis: u64) {
            self.millis.fetch_add(millis, std::sync::atomic::Ordering::SeqCst);
        }
    }
    impl RevocationClock for TestClock {
        fn monotonic(&self) -> std::time::Instant {
            self.epoch
                + std::time::Duration::from_millis(self.millis.load(std::sync::atomic::Ordering::SeqCst))
        }
        fn epoch_seconds(&self) -> u64 {
            1000 + self.millis.load(std::sync::atomic::Ordering::SeqCst) / 1000
        }
    }

    type PausedLookup = (std::sync::mpsc::Sender<()>, Arc<std::sync::Barrier>);

    #[derive(Default)]
    struct TestDependency {
        store: av_identity::InMemoryRevocationStore,
        offline: std::sync::atomic::AtomicBool,
        panic_next: std::sync::atomic::AtomicBool,
        reads: std::sync::atomic::AtomicUsize,
        writes: std::sync::atomic::AtomicUsize,
        pause_next: parking_lot::Mutex<Option<PausedLookup>>,
    }
    impl TestDependency {
        fn read(&self) -> Result<(), String> {
            use std::sync::atomic::Ordering::SeqCst;
            self.reads.fetch_add(1, SeqCst);
            if let Some((entered, resume)) = self.pause_next.lock().take() {
                entered.send(()).unwrap();
                resume.wait();
            }
            assert!(!self.panic_next.swap(false, SeqCst), "injected dependency panic");
            if self.offline.load(SeqCst) {
                Err("dependency offline".into())
            } else {
                Ok(())
            }
        }
        fn write(&self) -> Result<(), String> {
            use std::sync::atomic::Ordering::SeqCst;
            self.writes.fetch_add(1, SeqCst);
            if self.offline.load(SeqCst) {
                Err("dependency offline".into())
            } else {
                Ok(())
            }
        }
    }
    impl RevocationStore for TestDependency {
        fn is_revoked(&self, jti: &str) -> Result<bool, String> {
            self.read()?;
            self.store.is_revoked(jti)
        }
        fn revoke(&self, jti: &str, expiry: u64) -> Result<(), String> {
            self.try_revoke(jti, expiry).map(|_| ())
        }
        fn try_revoke(&self, jti: &str, expiry: u64) -> Result<RevokeOutcome, String> {
            self.write()?;
            self.store.try_revoke(jti, expiry)
        }
        fn try_revoke_token(&self, issuer: &str, jti: &str, expiry: u64) -> Result<RevokeOutcome, String> {
            self.write()?;
            self.store.try_revoke_token(issuer, jti, expiry)
        }
        fn check_token(
            &self,
            issuer: &str,
            jti: &str,
            uid: &str,
            iat: u64,
        ) -> Result<Option<RevokedBy>, String> {
            self.read()?;
            self.store.check_token(issuer, jti, uid, iat)
        }
        fn check(&self, jti: &str, uid: &str, iat: u64) -> Result<Option<RevokedBy>, String> {
            self.read()?;
            self.store.check(jti, uid, iat)
        }
        fn revoke_instance(&self, uid: &str, cutoff: u64, expiry: u64) -> Result<(), String> {
            self.write()?;
            self.store.revoke_instance(uid, cutoff, expiry)
        }
    }

    fn guarded() -> (
        Arc<GuardedRevocationStore>,
        Arc<TestDependency>,
        Arc<TestClock>,
        av_core::metrics::Registry,
    ) {
        let inner = Arc::new(TestDependency::default());
        let clock = Arc::new(TestClock::new());
        let registry = av_core::metrics::Registry::new();
        let guard = Arc::new(GuardedRevocationStore::with_clock(
            inner.clone(),
            &registry,
            "nhi",
            clock.clone(),
        ));
        (guard, inner, clock, registry)
    }

    #[test]
    fn availability_guard_opens_after_three_errors_and_recovers_after_one_probe() {
        use std::sync::atomic::Ordering::SeqCst;
        let (guard, inner, clock, _) = guarded();
        inner.offline.store(true, SeqCst);
        for _ in 0..3 {
            assert!(guard.is_revoked("live").is_err());
        }
        assert_eq!(inner.reads.load(SeqCst), 3);
        assert!(!guard.health().unwrap().available);
        assert_eq!(guard.health().unwrap().seconds_since_last_success, None);
        for _ in 0..20 {
            assert!(guard.is_revoked("live").is_err());
        }
        assert_eq!(inner.reads.load(SeqCst), 3);
        clock.advance(999);
        assert!(guard.is_revoked("live").is_err());
        clock.advance(1);
        assert!(guard.is_revoked("live").is_err());
        assert_eq!(inner.reads.load(SeqCst), 4);
        inner.offline.store(false, SeqCst);
        clock.advance(999);
        assert!(guard.is_revoked("live").is_err());
        clock.advance(1);
        assert!(!guard.is_revoked("live").unwrap());
        assert_eq!(inner.reads.load(SeqCst), 5);
        assert!(guard.health().unwrap().available);
        assert_eq!(guard.health().unwrap().seconds_since_last_success, Some(0));
        assert_eq!(guard.metrics.failed.get(), 4);
        assert_eq!(guard.metrics.opened.get(), 1);
    }

    #[test]
    fn availability_guard_never_caches_a_live_answer_and_retains_positive_results() {
        use std::sync::atomic::Ordering::SeqCst;
        let (guard, inner, _, _) = guarded();
        assert!(!guard.is_revoked("token").unwrap());
        inner.store.revoke("token", 2000).unwrap();
        assert!(guard.is_revoked("token").unwrap());
        assert_eq!(inner.reads.load(SeqCst), 2);
        inner.offline.store(true, SeqCst);
        for _ in 0..4 {
            assert!(guard.is_revoked("another").is_err());
        }
        assert!(guard.is_revoked("token").unwrap());
        assert_eq!(inner.reads.load(SeqCst), 5);
        assert_eq!(guard.metrics.local_revoked.get(), 1);
        assert_eq!(guard.health().unwrap().local_entries, 1);
    }

    #[test]
    fn failed_writes_still_deny_locally_but_never_report_success_and_writes_bypass_breaker() {
        use std::sync::atomic::Ordering::SeqCst;
        let (guard, inner, _, _) = guarded();
        inner.offline.store(true, SeqCst);
        assert!(guard.try_revoke("token", 2000).is_err());
        assert!(guard.revoke_instance("instance", 1000, 2000).is_err());
        assert!(guard.is_revoked("unrevoked").is_err());
        assert!(!guard.health().unwrap().available);
        assert!(guard.is_revoked("token").unwrap());
        assert_eq!(
            guard.check("other", "instance", 1000).unwrap(),
            Some(RevokedBy::Instance { cutoff: 1000 })
        );
        assert!(guard.check("other", "instance", 1001).is_err());
        inner.offline.store(false, SeqCst);
        assert_eq!(guard.try_revoke("token", 2000).unwrap(), RevokeOutcome::Revoked);
        assert_eq!(inner.writes.load(SeqCst), 3);
        assert!(guard.health().unwrap().available);
        assert_eq!(
            guard.try_revoke("token", 2000).unwrap(),
            RevokeOutcome::AlreadyRevoked
        );
    }

    #[test]
    fn availability_guard_admits_exactly_one_half_open_probe() {
        use std::sync::atomic::Ordering::SeqCst;
        let (guard, inner, clock, _) = guarded();
        inner.offline.store(true, SeqCst);
        for _ in 0..3 {
            assert!(guard.is_revoked("a").is_err());
        }
        clock.advance(1000);
        inner.offline.store(false, SeqCst);
        let (entered, receiver) = std::sync::mpsc::channel();
        let barrier = Arc::new(std::sync::Barrier::new(2));
        *inner.pause_next.lock() = Some((entered, barrier.clone()));
        let probe_guard = guard.clone();
        let probe = std::thread::spawn(move || probe_guard.is_revoked("probe"));
        receiver.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
        for _ in 0..10 {
            assert!(guard.is_revoked("waiting").is_err());
        }
        assert_eq!(inner.reads.load(SeqCst), 4);
        barrier.wait();
        assert!(!probe.join().unwrap().unwrap());
        assert!(guard.health().unwrap().available);
    }

    #[test]
    fn panic_does_not_strand_a_probe_or_its_concurrency_permit() {
        use std::sync::atomic::Ordering::SeqCst;
        let (guard, inner, clock, _) = guarded();
        inner.offline.store(true, SeqCst);
        for _ in 0..3 {
            assert!(guard.is_revoked("a").is_err());
        }
        clock.advance(1000);
        inner.panic_next.store(true, SeqCst);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| guard.is_revoked("probe"))).is_err()
        );
        assert_eq!(guard.state.lock().in_flight, 0);
        assert!(guard.state.lock().probe.is_none());
        clock.advance(1000);
        inner.offline.store(false, SeqCst);
        assert!(!guard.is_revoked("recovery").unwrap());
    }

    #[test]
    fn positive_cache_is_bounded_and_expiry_retains_the_last_accepted_second() {
        let (guard, _, clock, _) = guarded();
        for i in 0..LOCAL_REVOKED_MAX {
            guard.remember(format!("jti:{i}"), None, 1010);
        }
        guard.remember("overflow".into(), None, 1010);
        assert_eq!(guard.health().unwrap().local_entries, LOCAL_REVOKED_MAX);
        assert!(!guard.state.lock().revoked.contains_key("overflow"));
        guard.remember("jti:0".into(), None, 1011);
        clock.advance(10_000);
        guard.sweep_expired(1010);
        assert_eq!(guard.health().unwrap().local_entries, LOCAL_REVOKED_MAX);
        clock.advance(1000);
        guard.sweep_expired(1011);
        assert_eq!(guard.health().unwrap().local_entries, 1);
        clock.advance(1000);
        guard.sweep_expired(1012);
        assert_eq!(guard.health().unwrap().local_entries, 0);
    }

    #[test]
    fn known_instance_cutoffs_remain_monotonic_and_namespaces_have_separate_health() {
        let (guard, inner, _, registry) = guarded();
        inner.store.revoke_instance("instance", 1000, 2000).unwrap();
        assert_eq!(
            guard.check("token", "instance", 999).unwrap(),
            Some(RevokedBy::Instance { cutoff: 1000 })
        );
        guard.revoke_instance("instance", 900, 1900).unwrap();
        assert_eq!(
            guard.check("other", "instance", 1000).unwrap(),
            Some(RevokedBy::Instance { cutoff: 1000 })
        );
        let other = GuardedRevocationStore::new(Arc::new(TestDependency::default()), &registry, "exchanged");
        inner.offline.store(true, std::sync::atomic::Ordering::SeqCst);
        for _ in 0..3 {
            assert!(guard.is_revoked("unknown").is_err());
        }
        assert!(!guard.health().unwrap().available);
        assert!(other.health().unwrap().available);
        assert_eq!(guard.metrics.available.get(), 0);
        assert_eq!(other.metrics.available.get(), 1);
    }

    #[test]
    fn simultaneous_backend_reads_are_bounded_before_the_circuit_opens() {
        let (guard, _, _, _) = guarded();
        let permits: Vec<_> = (0..MAX_IN_FLIGHT_READS)
            .map(|_| guard.begin_lookup().unwrap())
            .collect();
        assert!(guard.begin_lookup().is_err());
        assert_eq!(guard.state.lock().in_flight, MAX_IN_FLIGHT_READS);
        for mut permit in permits {
            permit.finished = true;
            drop(permit);
        }
        assert_eq!(guard.state.lock().in_flight, 0);
        assert!(guard.health().unwrap().available);
    }

    #[test]
    fn scoped_rules_keep_issuer_and_global_domains_separate_in_shared_storage() {
        let shared: Arc<dyn StateStore> = Arc::new(InMemoryStore::new());
        let writer = StateRevocationStore::new(shared.clone());
        let reader = StateRevocationStore::new(shared);
        assert_eq!(
            writer.try_revoke_token("issuer-a", "same-jti", 2000).unwrap(),
            RevokeOutcome::Revoked
        );
        assert_eq!(
            writer.try_revoke_token("issuer-a", "same-jti", 2000).unwrap(),
            RevokeOutcome::AlreadyRevoked
        );
        assert_eq!(
            reader.check_token("issuer-a", "same-jti", "uid", 1000).unwrap(),
            Some(RevokedBy::Jti)
        );
        assert_eq!(
            reader.check_token("issuer-b", "same-jti", "uid", 1000).unwrap(),
            None
        );
        assert!(!reader.is_revoked("same-jti").unwrap());
        assert_ne!(reader.issued_key("a:b", "c"), reader.issued_key("a", "b:c"));
        writer.revoke("same-jti", 2000).unwrap();
        assert_eq!(
            reader.check_token("issuer-b", "same-jti", "uid", 1000).unwrap(),
            Some(RevokedBy::Jti)
        );
    }

    #[test]
    fn scoped_cache_never_widens_local_or_remote_revocations_to_other_issuers() {
        use std::sync::atomic::Ordering::SeqCst;
        let (guard, inner, _, _) = guarded();
        assert_eq!(
            guard.check_token("issuer-a", "same-jti", "uid", 1000).unwrap(),
            None
        );
        inner
            .store
            .try_revoke_token("issuer-a", "same-jti", 2000)
            .unwrap();
        assert_eq!(
            guard.check_token("issuer-a", "same-jti", "uid", 1000).unwrap(),
            Some(RevokedBy::Jti)
        );
        assert_eq!(
            guard.check_token("issuer-b", "same-jti", "uid", 1000).unwrap(),
            None
        );
        assert!(!guard.is_revoked("same-jti").unwrap());
        inner.offline.store(true, SeqCst);
        assert!(guard.try_revoke_token("issuer-c", "failed-write", 2000).is_err());
        assert_eq!(
            guard
                .check_token("issuer-c", "failed-write", "uid", 1000)
                .unwrap(),
            Some(RevokedBy::Jti)
        );
        assert!(guard
            .check_token("issuer-d", "failed-write", "uid", 1000)
            .is_err());
        assert_eq!(
            guard.check_token("issuer-a", "same-jti", "uid", 1000).unwrap(),
            Some(RevokedBy::Jti)
        );
        assert!(guard.check_token("issuer-b", "same-jti", "uid", 1000).is_err());
        assert!(!guard.health().unwrap().available);
        inner.offline.store(false, SeqCst);
        guard.revoke("same-jti", 2000).unwrap();
        assert_eq!(
            guard.check_token("issuer-b", "same-jti", "uid", 1000).unwrap(),
            Some(RevokedBy::Jti)
        );
    }
}
