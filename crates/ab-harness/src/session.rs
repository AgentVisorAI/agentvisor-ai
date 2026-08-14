//! Per-session state: sequence numbers, event chain, ATIF builder, loop state,
//! lifecycle (open → active → closed/promoted), and finalization products.

use ab_events::{AgentIdentity, StopReason};
use ab_receipts::EventChain;
use parking_lot::{Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Workflow kind (brief Modules G/H).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Workflow {
    /// Consequential actions: event chain + receipt at close.
    Signed,
    /// Exploratory: ATIF capture, receipt only on promotion.
    Unsigned,
}

impl Workflow {
    /// Canonical wire name (`x-ab-workflow` header, config, journal metadata).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Signed => "signed",
            Self::Unsigned => "unsigned",
        }
    }

    /// Parse a wire name back into a `Workflow` (`None` on unknown input).
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "signed" => Some(Self::Signed),
            "unsigned" => Some(Self::Unsigned),
            _ => None,
        }
    }
}

/// A live session.
pub struct Session {
    /// Session id.
    pub id: String,
    /// Workflow kind.
    pub workflow: Workflow,
    /// Agent identity bound at open (from NHI validation).
    pub identity: AgentIdentity,
    /// Most recently validated identity, including current TTL.
    latest_identity: Mutex<AgentIdentity>,
    /// Monotonic per-session event sequence (authoritative order).
    seq: AtomicU64,
    /// Monotonic authenticated-journal record index.
    journal_index: AtomicU64,
    /// Loop-breaker state.
    pub loop_state: ab_loopdetect::SessionLoopState,
    /// Signed workflow: incremental event chain.
    pub chain: Mutex<EventChain>,
    /// Unsigned workflow: ATIF steps.
    pub atif: Mutex<ab_atif::TrajectoryBuilder>,
    /// Aggregates for the receipt.
    pub totals: Totals,
    /// Last-activity timestamp (idle sweeping), epoch ms.
    pub last_activity_ms: AtomicU64,
    /// Last normalized provider or enforcement stop reason id.
    last_stop_reason_id: AtomicU64,
    /// Set once closed (idempotent close).
    pub closed: AtomicU64,
    /// Set once a receipt or ATIF artifact is durably committed.
    artifact_committed: AtomicU64,
    /// Serializes close against request admission.
    admission: RwLock<()>,
    /// Forwarded chat responses that have not completed or aborted.
    active_streams: AtomicU64,
    /// Notification used by finalization to await active response completion.
    streams_drained: tokio::sync::Notify,
    /// Issued signed or retroactive receipt.
    pub receipt: Mutex<Option<ab_receipts::Receipt>>,
    /// Persisted unsigned ATIF artifact.
    pub atif_path: Mutex<Option<PathBuf>>,
    /// Set once an unsigned artifact is promoted.
    promoted: AtomicU64,
    /// Worker jobs accepted but not yet fully captured.
    pending_jobs: AtomicU64,
    /// Notification used by finalization to await a drained worker queue.
    jobs_drained: tokio::sync::Notify,
    /// Set when an upstream action could not be captured completely.
    capture_failed: AtomicU64,
}

/// Aggregate counters for receipts (atomics: workers update concurrently).
#[derive(Debug, Default)]
pub struct Totals {
    /// Tool calls observed.
    pub tool_calls: AtomicU64,
    /// Tool calls allowed.
    pub tool_allowed: AtomicU64,
    /// Tool calls blocked.
    pub tool_blocked: AtomicU64,
    /// Prompt tokens.
    pub prompt_tokens: AtomicU64,
    /// Completion tokens.
    pub completion_tokens: AtomicU64,
    /// Cached tokens.
    pub cached_tokens: AtomicU64,
    /// Cost in micro-USD.
    pub cost_usd_micros: AtomicU64,
}

impl Session {
    /// Open a session.
    pub fn new(
        id: String,
        workflow: Workflow,
        identity: AgentIdentity,
        breaker: ab_loopdetect::BreakerConfig,
    ) -> Self {
        let agent = ab_atif::Agent {
            name: "agent-bridge-harness".into(),
            version: identity.version.clone(),
            model_name: None,
            tool_definitions: None,
            extra: Some(serde_json::json!({
                "charter": identity.charter,
                "instance_uid": identity.instance_uid,
                "ttl_remaining_s": identity.ttl_remaining_s,
            })),
        };
        Self {
            chain: Mutex::new(EventChain::new(&id)),
            atif: Mutex::new(ab_atif::TrajectoryBuilder::new(agent, Some(id.clone()))),
            id,
            workflow,
            identity: identity.clone(),
            latest_identity: Mutex::new(identity.clone()),
            seq: AtomicU64::new(0),
            journal_index: AtomicU64::new(0),
            loop_state: ab_loopdetect::SessionLoopState::new(breaker),
            totals: Totals::default(),
            last_activity_ms: AtomicU64::new(ab_core::time::now_ms()),
            last_stop_reason_id: AtomicU64::new(0),
            closed: AtomicU64::new(0),
            artifact_committed: AtomicU64::new(0),
            admission: RwLock::new(()),
            active_streams: AtomicU64::new(0),
            streams_drained: tokio::sync::Notify::new(),
            receipt: Mutex::new(None),
            atif_path: Mutex::new(None),
            promoted: AtomicU64::new(0),
            pending_jobs: AtomicU64::new(0),
            jobs_drained: tokio::sync::Notify::new(),
            capture_failed: AtomicU64::new(0),
        }
    }

    /// Next event sequence number.
    pub fn next_seq(&self) -> u64 {
        self.seq.fetch_add(1, Ordering::AcqRel)
    }

    /// Peek at the sequence number that `next_seq` would return without
    /// consuming it. Used by lifecycle emitters that may fail to persist —
    /// a burned seq would misalign the journal on retry, since recovery
    /// checks `event.metadata.sequence == journal position`.
    pub(crate) fn peek_seq(&self) -> u64 {
        self.seq.load(Ordering::Acquire)
    }

    /// Commit a previously peeked seq. Callers hold the lifecycle_lock and
    /// have drained worker jobs, so no concurrent updater can race the store.
    pub(crate) fn advance_seq_past(&self, seq: u64) {
        self.seq.store(seq.saturating_add(1), Ordering::Release);
    }

    pub(crate) fn restore_next_seq(&self, next: u64) {
        self.seq.store(next, Ordering::Release);
    }

    pub(crate) fn journal_index(&self) -> u64 {
        self.journal_index.load(Ordering::Acquire)
    }

    pub(crate) fn commit_journal_index(&self, index: u64) -> Result<(), String> {
        self.journal_index
            .compare_exchange(
                index,
                index.saturating_add(1),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map(|_| ())
            .map_err(|actual| format!("journal index changed from {index} to {actual}"))
    }

    pub(crate) fn restore_journal_index(&self, next: u64) {
        self.journal_index.store(next, Ordering::Release);
    }

    /// Touch the activity clock.
    pub fn touch(&self) {
        self.last_activity_ms
            .store(ab_core::time::now_ms(), Ordering::Release);
    }

    /// Attempt to claim the close transition. Only one caller can hold the
    /// claim at a time; a failed finalize resets it (`reset_close`) so the
    /// close can be retried.
    pub fn try_close(&self) -> bool {
        self.closed
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// True when closed.
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire) != 0 || self.artifact_committed.load(Ordering::Acquire) != 0
    }

    pub(crate) fn admission_guard(&self) -> RwLockReadGuard<'_, ()> {
        self.admission.read()
    }

    pub(crate) fn try_lease(self: &Arc<Self>) -> Option<SessionLease> {
        let admission = self.admission.read();
        if self.is_closed() {
            return None;
        }
        let lease = SessionLease::new(Arc::clone(self));
        drop(admission);
        Some(lease)
    }

    pub(crate) fn close_guard(&self) -> RwLockWriteGuard<'_, ()> {
        self.admission.write()
    }

    pub(crate) fn reset_close(&self) {
        self.closed.store(0, Ordering::Release);
    }

    pub(crate) fn mark_artifact_committed(&self) {
        self.artifact_committed.store(1, Ordering::Release);
    }

    pub(crate) async fn wait_for_streams(&self) {
        loop {
            // Subscribe first (via enable), then check the guard; the same Notified
            // must remain pinned through the await, or notify_waiters() firing in
            // the interval between drop and re-subscribe is lost forever.
            let notified = self.streams_drained.notified();
            let mut notified = std::pin::pin!(notified);
            notified.as_mut().enable();
            if self.active_streams.load(Ordering::Acquire) == 0 {
                return;
            }
            notified.await;
        }
    }

    /// Atomically claim promotion. Only one caller can hold the claim at a
    /// time; failed receipt persistence resets it (`reset_promotion`) so
    /// promotion can be retried.
    pub fn try_promote(&self) -> bool {
        self.promoted
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// True after promotion has completed (receipt persisted), not merely
    /// been claimed.
    pub fn is_promoted(&self) -> bool {
        self.promoted.load(Ordering::Acquire) == 2
    }

    pub(crate) fn finish_promotion(&self) {
        self.promoted.store(2, Ordering::Release);
    }

    pub(crate) fn reset_promotion(&self) {
        let _ = self
            .promoted
            .compare_exchange(1, 0, Ordering::AcqRel, Ordering::Acquire);
    }

    pub(crate) fn restore_receipt(&self, receipt: ab_receipts::Receipt) {
        *self.receipt.lock() = Some(receipt);
        self.finish_promotion();
    }

    pub(crate) fn restore_pending_receipt(&self, receipt: ab_receipts::Receipt) {
        *self.receipt.lock() = Some(receipt);
    }

    /// Recreate a closed unsigned session from a persisted ATIF trajectory.
    pub fn recover_unsigned(
        id: String,
        identity: AgentIdentity,
        breaker: ab_loopdetect::BreakerConfig,
        path: PathBuf,
        metrics: Option<&ab_atif::FinalMetrics>,
    ) -> Result<Self, String> {
        let session = Self::new(id, Workflow::Unsigned, identity, breaker);
        session.closed.store(1, Ordering::Release);
        session.mark_artifact_committed();
        *session.atif_path.lock() = Some(path);
        if let Some(metrics) = metrics {
            let prompt_tokens = recovered_counter(metrics.total_prompt_tokens, "prompt tokens")?;
            let completion_tokens = recovered_counter(metrics.total_completion_tokens, "completion tokens")?;
            let cached_tokens = recovered_counter(metrics.total_cached_tokens, "cached tokens")?;
            session
                .totals
                .prompt_tokens
                .store(prompt_tokens, Ordering::Release);
            session
                .totals
                .completion_tokens
                .store(completion_tokens, Ordering::Release);
            session
                .totals
                .cached_tokens
                .store(cached_tokens, Ordering::Release);
            if let Some(extra) = metrics.extra.as_ref() {
                let cost_usd_micros = recovered_counter(
                    extra.get("cost_usd_micros").and_then(serde_json::Value::as_u64),
                    "cost",
                )?;
                session
                    .totals
                    .cost_usd_micros
                    .store(cost_usd_micros, Ordering::Release);
                let tool_calls = recovered_counter(
                    extra.get("tool_calls").and_then(serde_json::Value::as_u64),
                    "tool calls",
                )?;
                let tool_allowed = recovered_counter(
                    extra.get("tool_allowed").and_then(serde_json::Value::as_u64),
                    "allowed tools",
                )?;
                let tool_blocked = recovered_counter(
                    extra.get("tool_blocked").and_then(serde_json::Value::as_u64),
                    "blocked tools",
                )?;
                if tool_allowed
                    .checked_add(tool_blocked)
                    .is_none_or(|classified| classified > tool_calls)
                {
                    return Err("recovered tool accounting is inconsistent".to_owned());
                }
                session.totals.tool_calls.store(tool_calls, Ordering::Release);
                session.totals.tool_allowed.store(tool_allowed, Ordering::Release);
                session.totals.tool_blocked.store(tool_blocked, Ordering::Release);
                if let Some(id) = extra.get("stop_reason_id").and_then(serde_json::Value::as_u64) {
                    if id > u64::from(u8::MAX) {
                        return Err("recovered stop reason exceeds u8".to_owned());
                    }
                    session.last_stop_reason_id.store(id, Ordering::Release);
                }
            } else if let Some(cost) = metrics.total_cost_usd {
                if !cost.is_finite() || cost < 0.0 {
                    return Err("recovered cost is not finite and nonnegative".to_owned());
                }
                let micros = (cost * ab_core::units::USD_MICROS_PER_DOLLAR as f64).round();
                if micros > ab_core::error::JCS_SAFE_MAX as f64 {
                    return Err("recovered cost exceeds JCS-safe bounds".to_owned());
                }
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                session
                    .totals
                    .cost_usd_micros
                    .store(micros as u64, Ordering::Release);
            }
        }
        Ok(session)
    }

    /// Consume the current ATIF builder and replace it with an empty one.
    pub fn take_trajectory(&self) -> ab_atif::Trajectory {
        let identity = self.current_identity();
        let agent = ab_atif::Agent {
            name: "agent-bridge-harness".into(),
            version: identity.version.clone(),
            model_name: None,
            tool_definitions: None,
            extra: Some(serde_json::json!({
                "charter": identity.charter,
                "instance_uid": identity.instance_uid,
                "ttl_remaining_s": identity.ttl_remaining_s,
            })),
        };
        let replacement = ab_atif::TrajectoryBuilder::new(agent, Some(self.id.clone()));
        let builder = std::mem::replace(&mut *self.atif.lock(), replacement);
        builder.finish()
    }

    pub(crate) fn snapshot_trajectory(&self) -> ab_atif::Trajectory {
        self.atif.lock().clone().finish()
    }

    pub(crate) fn worker_job_started(&self) {
        self.pending_jobs.fetch_add(1, Ordering::AcqRel);
    }

    pub(crate) fn worker_job_finished(&self) {
        if self.pending_jobs.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.jobs_drained.notify_waiters();
        }
    }

    pub(crate) async fn wait_for_worker_jobs(&self) {
        loop {
            let notified = self.jobs_drained.notified();
            let mut notified = std::pin::pin!(notified);
            notified.as_mut().enable();
            if self.pending_jobs.load(Ordering::Acquire) == 0 {
                return;
            }
            notified.await;
        }
    }

    pub(crate) fn mark_capture_failed(&self) {
        self.capture_failed.store(1, Ordering::Release);
    }

    pub(crate) fn capture_failed(&self) -> bool {
        self.capture_failed.load(Ordering::Acquire) != 0
    }

    /// Refresh token-derived fields after successful validation.
    pub fn refresh_identity(&self, identity: &AgentIdentity) {
        *self.latest_identity.lock() = identity.clone();
    }

    /// Current validated identity snapshot.
    pub fn current_identity(&self) -> AgentIdentity {
        self.latest_identity.lock().clone()
    }

    pub(crate) fn record_stop_reason(&self, reason: StopReason) {
        self.last_stop_reason_id
            .store(u64::from(reason.id()), Ordering::Release);
    }

    pub(crate) fn recorded_stop_reason_id(&self) -> u64 {
        self.last_stop_reason_id.load(Ordering::Acquire)
    }

    /// Build the receipt body for this session (signed close or promotion).
    pub fn receipt_body(
        &self,
        subject: ab_receipts::ReceiptSubject,
        stop: StopReason,
    ) -> ab_receipts::ReceiptBody {
        let recorded =
            StopReason::from_id(u8::try_from(self.last_stop_reason_id.load(Ordering::Acquire)).unwrap_or(0));
        let stop = if recorded == StopReason::Unknown {
            stop
        } else {
            recorded
        };
        ab_receipts::receipt::new_body(
            self.id.clone(),
            self.current_identity(),
            subject,
            ab_receipts::ToolCallSummary {
                total: self.totals.tool_calls.load(Ordering::Acquire),
                allowed: self.totals.tool_allowed.load(Ordering::Acquire),
                blocked: self.totals.tool_blocked.load(Ordering::Acquire),
            },
            ab_receipts::CostSummary {
                prompt_tokens: self.totals.prompt_tokens.load(Ordering::Acquire),
                completion_tokens: self.totals.completion_tokens.load(Ordering::Acquire),
                cached_tokens: self.totals.cached_tokens.load(Ordering::Acquire),
                cost_usd_micros: self.totals.cost_usd_micros.load(Ordering::Acquire),
            },
            stop,
        )
    }
}

fn recovered_counter(value: Option<u64>, field: &str) -> Result<u64, String> {
    let value = value.unwrap_or(0);
    if value > ab_core::error::JCS_SAFE_MAX {
        return Err(format!("recovered {field} exceeds JCS-safe bounds"));
    }
    Ok(value)
}

/// RAII claim keeping a forwarded response active until completion or abort.
pub struct SessionLease {
    session: Arc<Session>,
}

impl SessionLease {
    pub(crate) fn new(session: Arc<Session>) -> Self {
        session.active_streams.fetch_add(1, Ordering::AcqRel);
        Self { session }
    }
}

impl Drop for SessionLease {
    fn drop(&mut self) {
        if self.session.active_streams.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.session.streams_drained.notify_waiters();
        }
    }
}

/// The session registry.
#[derive(Default)]
pub struct SessionRegistry {
    sessions: dashmap::DashMap<String, Arc<Session>>,
}

impl SessionRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get or open a session.
    pub fn get_or_open(
        &self,
        id: &str,
        workflow: Workflow,
        identity: &AgentIdentity,
        breaker: &ab_loopdetect::BreakerConfig,
    ) -> Arc<Session> {
        self.sessions
            .entry(id.to_owned())
            .or_insert_with(|| {
                Arc::new(Session::new(
                    id.to_owned(),
                    workflow,
                    identity.clone(),
                    breaker.clone(),
                ))
            })
            .clone()
    }

    /// Look up a session.
    pub fn get(&self, id: &str) -> Option<Arc<Session>> {
        self.sessions.get(id).map(|s| s.clone())
    }

    /// Insert a session reconstructed from durable spool state.
    pub fn insert_recovered(&self, session: Session) -> Arc<Session> {
        let id = session.id.clone();
        self.sessions
            .entry(id)
            .or_insert_with(|| Arc::new(session))
            .clone()
    }

    /// Insert a recovered session only if the id is not already registered.
    /// Returns `Err(existing)` on collision so recovery does not clobber a
    /// concurrently-opened active session — the recovery loop must not run
    /// finalize on the returned Arc when it happens to be the live one.
    pub fn try_insert_recovered(&self, session: Session) -> Result<Arc<Session>, Arc<Session>> {
        use dashmap::mapref::entry::Entry;
        match self.sessions.entry(session.id.clone()) {
            Entry::Occupied(existing) => Err(existing.get().clone()),
            Entry::Vacant(slot) => {
                let arc = Arc::new(session);
                slot.insert(Arc::clone(&arc));
                Ok(arc)
            }
        }
    }

    /// Remove a session (after finalization).
    pub fn remove(&self, id: &str) {
        self.sessions.remove(id);
    }

    /// Sessions idle longer than `idle_s` (for the sweeper).
    pub fn idle_sessions(&self, idle_s: u64) -> Vec<Arc<Session>> {
        let cutoff =
            ab_core::time::now_ms().saturating_sub(idle_s.saturating_mul(ab_core::units::MS_PER_SEC));
        self.sessions
            .iter()
            .filter(|e| {
                e.last_activity_ms.load(Ordering::Acquire) < cutoff
                    && !e.is_closed()
                    // A session with a live forwarded response is not idle even
                    // when its admission clock is stale: `last_activity_ms` is
                    // refreshed only at request admission, so a stream that
                    // outlives the idle window would otherwise let the sweeper
                    // claim the close (sealing the session mid-conversation)
                    // and then park inside `wait_for_streams` while holding
                    // the shared lifecycle lock until the client's stream ends.
                    && e.active_streams.load(Ordering::Acquire) == 0
            })
            .map(|e| e.clone())
            .collect()
    }

    /// Snapshot every session still accepting work.
    pub fn open_sessions(&self) -> Vec<Arc<Session>> {
        self.sessions
            .iter()
            .filter(|entry| !entry.is_closed())
            .map(|entry| entry.clone())
            .collect()
    }

    /// Number of registered sessions (includes closed sessions not yet removed).
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// True when no sessions are registered (closed or open).
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn identity() -> AgentIdentity {
        AgentIdentity {
            version: "1".into(),
            charter: "c".into(),
            instance_uid: "i".into(),
            ttl_remaining_s: None,
        }
    }

    #[test]
    fn seq_is_monotonic_under_concurrency() {
        let s = Arc::new(Session::new(
            "s".into(),
            Workflow::Unsigned,
            identity(),
            ab_loopdetect::BreakerConfig::default(),
        ));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let s = Arc::clone(&s);
            handles.push(std::thread::spawn(move || {
                (0..1000).map(|_| s.next_seq()).collect::<Vec<_>>()
            }));
        }
        let mut all: Vec<u64> = handles.into_iter().flat_map(|h| h.join().unwrap()).collect();
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), 8000, "sequence numbers must be unique");
    }

    #[test]
    fn close_is_idempotent() {
        let s = Session::new("s".into(), Workflow::Signed, identity(), Default::default());
        assert!(s.try_close());
        assert!(!s.try_close(), "second close must be refused");
        assert!(s.is_closed());
    }

    #[test]
    fn registry_reuses_sessions() {
        let r = SessionRegistry::new();
        let a = r.get_or_open("x", Workflow::Unsigned, &identity(), &Default::default());
        let b = r.get_or_open("x", Workflow::Unsigned, &identity(), &Default::default());
        assert!(Arc::ptr_eq(&a, &b));
        assert_eq!(r.len(), 1);
    }

    /// A signed-recovery loop that discovers a stale journal for session X
    /// must not clobber a live session X that raced its way into the
    /// registry (client retries with the same id after a crash are a real
    /// production case). `try_insert_recovered` returns `Err(existing)` so
    /// the recovery loop can `continue` instead of running
    /// `close_session_locked` on the active Arc and force-closing it.
    #[test]
    fn try_insert_recovered_returns_err_on_collision_and_leaves_active_untouched() {
        let r = SessionRegistry::new();
        let active = r.get_or_open("race", Workflow::Signed, &identity(), &Default::default());
        assert!(!active.is_closed(), "precondition: active session is open");
        let recovered = Session::new("race".into(), Workflow::Signed, identity(), Default::default());
        let existing = match r.try_insert_recovered(recovered) {
            Ok(_) => panic!("collision must be reported as Err, not Ok"),
            Err(existing) => existing,
        };
        assert!(
            Arc::ptr_eq(&active, &existing),
            "Err must carry the pre-existing active Arc, not a fresh one",
        );
        assert!(
            !active.is_closed(),
            "the active session must remain open after a discarded recovery insert",
        );
        assert_eq!(r.len(), 1, "no duplicate entry must be added");
    }

    #[test]
    fn try_insert_recovered_returns_ok_when_registry_is_vacant() {
        let r = SessionRegistry::new();
        let recovered = Session::new("fresh".into(), Workflow::Signed, identity(), Default::default());
        let inserted = match r.try_insert_recovered(recovered) {
            Ok(inserted) => inserted,
            Err(_) => panic!("vacant slot must accept the recovered session"),
        };
        assert_eq!(inserted.id, "fresh");
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn idle_detection() {
        let r = SessionRegistry::new();
        let s = r.get_or_open("idle", Workflow::Unsigned, &identity(), &Default::default());
        s.last_activity_ms
            .store(ab_core::time::now_ms() - 10_000, Ordering::Release);
        assert_eq!(r.idle_sessions(5).len(), 1);
        assert!(r.idle_sessions(60).is_empty());
        s.try_close();
        assert!(
            r.idle_sessions(5).is_empty(),
            "closed sessions are not idle candidates"
        );
    }

    /// `last_activity_ms` is refreshed only at request admission, so a chat
    /// stream that outlives the idle window makes its session *look* idle
    /// while a response is actively relaying. The sweeper must skip it:
    /// otherwise `try_close` seals the session mid-conversation (every new
    /// request gets "session is already closed") and `close_session_locked`
    /// then parks inside `wait_for_streams` while holding the shared
    /// lifecycle lock until the client's stream ends.
    #[test]
    fn idle_sweep_skips_sessions_with_active_streams() {
        let r = SessionRegistry::new();
        let s = r.get_or_open("streaming", Workflow::Unsigned, &identity(), &Default::default());
        s.last_activity_ms
            .store(ab_core::time::now_ms() - 10_000, Ordering::Release);
        let lease = SessionLease::new(Arc::clone(&s));
        assert!(
            r.idle_sessions(5).is_empty(),
            "a session with an active response stream must not be reaped as idle",
        );
        drop(lease);
        assert_eq!(
            r.idle_sessions(5).len(),
            1,
            "once the stream lease drops, the stale session becomes an idle candidate again",
        );
    }

    /// If the wall clock jumps backward (NTP correction, VM pause/resume,
    /// unsynchronized replicas), `now_ms()` may return a value below a
    /// session's stored `last_activity_ms`. `idle_sessions` must never
    /// flag the session as idle in that case — a saturating_sub in the
    /// cutoff calculation keeps the comparison well-defined and the
    /// session survives until the clock catches back up.
    #[test]
    fn idle_reap_is_safe_when_clock_runs_backward() {
        let r = SessionRegistry::new();
        let s = r.get_or_open("backward", Workflow::Unsigned, &identity(), &Default::default());
        // Simulate: session's activity stamp is FUTURE relative to `now_ms()`.
        s.last_activity_ms.store(
            ab_core::time::now_ms() + ab_core::units::MS_PER_HOUR,
            Ordering::Release,
        );
        for idle_s in [0u64, 1, 60, 3_600, ab_core::units::SECS_PER_DAY] {
            assert!(
                r.idle_sessions(idle_s).is_empty(),
                "session with future last_activity must not be reaped at idle_s={idle_s}",
            );
        }
    }

    /// A pathologically large `idle_s` (e.g., attacker-controlled config that
    /// gets past validation, or `u64::MAX`) must saturate the cutoff at 0
    /// instead of wrapping, causing no session to be reaped.
    #[test]
    fn idle_reap_saturates_on_pathological_idle_secs() {
        let r = SessionRegistry::new();
        let _s = r.get_or_open(
            "pathological",
            Workflow::Unsigned,
            &identity(),
            &Default::default(),
        );
        assert!(
            r.idle_sessions(u64::MAX).is_empty(),
            "idle_s = u64::MAX must saturate rather than reap everything",
        );
        // Something halfway through the multiplication path still triggers
        // saturation because `idle_s * 1000` overflows.
        assert!(r.idle_sessions(u64::MAX / 500).is_empty());
    }

    /// A session touched millions of times a second under normal operation
    /// must never observe `last_activity_ms` moving backward — the wall
    /// clock underpinning `touch()` is monotone under a healthy kernel and
    /// the store uses Release ordering so a later reader always sees a
    /// value ≥ every prior stamp.
    #[test]
    fn touch_never_regresses_last_activity() {
        let r = SessionRegistry::new();
        let s = r.get_or_open("touched", Workflow::Unsigned, &identity(), &Default::default());
        let mut previous = s.last_activity_ms.load(Ordering::Acquire);
        for _ in 0..10_000 {
            s.touch();
            let current = s.last_activity_ms.load(Ordering::Acquire);
            assert!(
                current >= previous,
                "touch() moved last_activity backward: {previous} -> {current}",
            );
            previous = current;
        }
    }
}
