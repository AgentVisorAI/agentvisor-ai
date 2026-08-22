//! Per-session state: sequence numbers, event chain, ATIF builder, loop state,
//! lifecycle (open → active → closed/promoted), and finalization products.

use av_events::{AgentIdentity, StopReason};
use av_receipts::EventChain;
use parking_lot::{Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Workflow kind (brief Modules G/H).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Workflow {
    /// Consequential actions: event chain + receipt at close.
    Signed,
    /// Exploratory: ATIF capture, receipt only on promotion.
    Unsigned,
}

impl Workflow {
    /// Canonical wire name (`x-av-workflow` header, config, journal metadata).
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
    /// Round-32 F1 (av-loopdetect): a per-open UUID that disambiguates
    /// recycled session ids in the off-path vector store. Client
    /// callers may reuse the same `id` after a finalize; the
    /// `SessionRegistry::get_or_open` path historically returned a
    /// fresh `Session` under the same key. A Qdrant vector search
    /// filtered ONLY on `session_id` would then return the prior
    /// incarnation's vectors, causing false semantic-loop signals
    /// from an unrelated past session. Every vector record and
    /// query is now scoped by
    /// `session_scope = "{id}#{generation_uid}"` — the UUID is
    /// fresh for every `Session::new`, so a recycled id lands in
    /// a distinct scope. The bare `id` remains the primary key for
    /// on-disk artifacts (spool paths, journal filenames), which
    /// use crash-safe generation logic of their own.
    pub session_scope: String,
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
    pub loop_state: av_loopdetect::SessionLoopState,
    /// Signed workflow: incremental event chain.
    pub chain: Mutex<EventChain>,
    /// Unsigned workflow: ATIF steps.
    pub atif: Mutex<av_atif::TrajectoryBuilder>,
    /// Aggregates for the receipt.
    pub totals: Totals,
    /// Last-activity timestamp (dashboard/display only), epoch ms.
    /// Wall-clock time subject to VM/NTP jumps; not safe to use for
    /// idle-eviction decisions — the private `last_activity_instant`
    /// field carries a monotonic anchor the idle sweeper uses instead.
    pub last_activity_ms: AtomicU64,
    /// Monotonic last-activity instant. Used by the idle sweeper so a
    /// forward wall-clock jump (VM resume, NTP correction) cannot make
    /// active sessions look premature-idle: `Instant` is bounded by
    /// real elapsed time on the system's monotonic clock.
    last_activity_instant: Mutex<Instant>,
    /// Last normalized provider or enforcement stop reason id.
    last_stop_reason_id: AtomicU64,
    /// Sticky enforcement latch (0 = never tripped, else the enforcement
    /// stop-reason id). Set ONLY at genuine enforcement-refusal sites
    /// (chat token-budget refusal, mid-stream budget refusal, loop-
    /// breaker open refusal) — never by the last-write-wins
    /// `last_stop_reason_id`, which later successful responses
    /// overwrite and which quota-BACKEND failures and blocked tool
    /// calls also write, making it an unreliable proxy for "enforcement
    /// caused this session's end" (false lockouts and losable refusals,
    /// both verified). Gates same-id recycling after close.
    enforcement_tripped: AtomicU64,
    /// Set once closed (idempotent close).
    pub closed: AtomicU64,
    /// Set once a receipt or ATIF artifact is durably committed.
    artifact_committed: AtomicU64,
    /// Set only when a close ran to full completion: artifact committed,
    /// lifecycle events published, and the on-disk journal removed. Gates
    /// registry eviction — `artifact_committed` alone is set *before* the
    /// fallible bridge emits and journal removal, so a failed or in-flight
    /// close must not look evictable.
    close_complete: AtomicU64,
    /// Serializes close against request admission.
    admission: RwLock<()>,
    /// Forwarded chat responses that have not completed or aborted.
    active_streams: AtomicU64,
    /// Notification used by finalization to await active response completion.
    streams_drained: tokio::sync::Notify,
    /// Issued signed or retroactive receipt.
    pub receipt: Mutex<Option<av_receipts::Receipt>>,
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
        breaker: av_loopdetect::BreakerConfig,
    ) -> Self {
        let agent = av_atif::Agent {
            name: "agentvisor-ai-harness".into(),
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
            atif: Mutex::new(av_atif::TrajectoryBuilder::new(agent, Some(id.clone()))),
            // Round-32 F1: fresh generation UUID per Session::new so
            // recycled ids get a distinct vector-sink scope.
            session_scope: format!("{id}#{}", av_core::new_event_uid()),
            id,
            workflow,
            identity: identity.clone(),
            latest_identity: Mutex::new(identity.clone()),
            seq: AtomicU64::new(0),
            journal_index: AtomicU64::new(0),
            loop_state: av_loopdetect::SessionLoopState::new(breaker),
            totals: Totals::default(),
            last_activity_ms: AtomicU64::new(av_core::time::now_ms()),
            last_activity_instant: Mutex::new(Instant::now()),
            last_stop_reason_id: AtomicU64::new(0),
            enforcement_tripped: AtomicU64::new(0),
            closed: AtomicU64::new(0),
            artifact_committed: AtomicU64::new(0),
            close_complete: AtomicU64::new(0),
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

    /// Touch the activity clock. Both the wall-clock and the monotonic
    /// anchors are updated: the wall-clock feeds dashboard display, the
    /// monotonic feeds the idle sweeper.
    pub fn touch(&self) {
        self.last_activity_ms
            .store(av_core::time::now_ms(), Ordering::Release);
        *self.last_activity_instant.lock() = Instant::now();
    }

    /// Duration elapsed since this session's last touch, measured on
    /// the monotonic clock. Safe against wall-clock jumps.
    pub(crate) fn idle_duration(&self) -> Duration {
        self.last_activity_instant.lock().elapsed()
    }

    /// Test-only: age a session so the idle sweeper (which uses the
    /// monotonic clock) treats it as idle by `ago_seconds`. Production
    /// code refreshes both anchors via `touch()`.
    #[cfg(test)]
    pub(crate) fn set_idle_for_testing(&self, ago_seconds: u64) {
        let ago = Duration::from_secs(ago_seconds);
        self.last_activity_ms.store(
            av_core::time::now_ms().saturating_sub(ago_seconds.saturating_mul(av_core::units::MS_PER_SEC)),
            Ordering::Release,
        );
        // `Instant::checked_sub` fails if the resulting Instant would
        // predate the platform monotonic zero — in that case, fall back
        // to the earliest available Instant so the test still expresses
        // "as idle as possible".
        let now = Instant::now();
        *self.last_activity_instant.lock() = now.checked_sub(ago).unwrap_or(now);
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

    /// True once the receipt/ATIF artifact is durably persisted.
    pub fn artifact_committed_flag(&self) -> bool {
        self.artifact_committed.load(Ordering::Acquire) != 0
    }

    /// True once the close ran to full completion (journal removed).
    pub fn close_complete_flag(&self) -> bool {
        self.close_complete.load(Ordering::Acquire) != 0
    }

    pub(crate) fn mark_artifact_committed(&self) {
        self.artifact_committed.store(1, Ordering::Release);
    }

    /// Record that a close ran to full completion (journal and outboxes
    /// removed). Only such sessions may be evicted from the registry.
    pub(crate) fn mark_close_complete(&self) {
        self.close_complete.store(1, Ordering::Release);
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

    pub(crate) fn restore_receipt(&self, receipt: av_receipts::Receipt) {
        *self.receipt.lock() = Some(receipt);
        self.finish_promotion();
    }

    pub(crate) fn restore_pending_receipt(&self, receipt: av_receipts::Receipt) {
        *self.receipt.lock() = Some(receipt);
    }

    /// Recreate a closed unsigned session from a persisted ATIF trajectory.
    ///
    /// `next_seq` is the number of per-session events already published to
    /// the bridge for this session (steps ↔ journal records are 1:1, so the
    /// step count is exact). Without restoring it, an adopted session
    /// reports `peek_seq() == 0` and a post-crash SESSION_CLOSE or
    /// retroactive-receipt event is minted with `metadata.sequence = 0`,
    /// colliding with the session's first step event already on the bridge
    /// (both sibling recovery paths call `restore_next_seq`; this one used
    /// to be the exception).
    pub fn recover_unsigned(
        id: String,
        identity: AgentIdentity,
        breaker: av_loopdetect::BreakerConfig,
        path: PathBuf,
        metrics: Option<&av_atif::FinalMetrics>,
        next_seq: u64,
    ) -> Result<Self, String> {
        let session = Self::new(id, Workflow::Unsigned, identity, breaker);
        session.restore_next_seq(next_seq);
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
                    // Best-effort latch restoration across restart: the
                    // sticky enforcement flag is in-memory only. Seed it
                    // ONLY from a persisted LoopDetected — the single
                    // stop reason with exactly one recording source (the
                    // worker's breaker-trip verdict, which also latches
                    // live). BudgetExceeded is deliberately NOT seeded:
                    // it has three recording sources (genuine refusal,
                    // quota-backend outage, blocked tool call) and only
                    // the first latches live, so seeding it would lock
                    // out ids the live process never locked. Cost: a
                    // budget-latched unsigned id forgets its refusal
                    // across a restart — the same bounded degradation
                    // already accepted for signed workflows.
                    if id == u64::from(StopReason::LoopDetected.id()) {
                        session.enforcement_tripped.store(id, Ordering::Release);
                    }
                }
            } else if let Some(cost) = metrics.total_cost_usd {
                if !cost.is_finite() || cost < 0.0 {
                    return Err("recovered cost is not finite and nonnegative".to_owned());
                }
                let micros = (cost * av_core::units::USD_MICROS_PER_DOLLAR as f64).round();
                if micros > av_core::error::JCS_SAFE_MAX as f64 {
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
    pub fn take_trajectory(&self) -> av_atif::Trajectory {
        let identity = self.current_identity();
        let agent = av_atif::Agent {
            name: "agentvisor-ai-harness".into(),
            version: identity.version.clone(),
            model_name: None,
            tool_definitions: None,
            extra: Some(serde_json::json!({
                "charter": identity.charter,
                "instance_uid": identity.instance_uid,
                "ttl_remaining_s": identity.ttl_remaining_s,
            })),
        };
        let replacement = av_atif::TrajectoryBuilder::new(agent, Some(self.id.clone()));
        let builder = std::mem::replace(&mut *self.atif.lock(), replacement);
        builder.finish()
    }

    pub(crate) fn snapshot_trajectory(&self) -> av_atif::Trajectory {
        self.atif.lock().clone().finish()
    }

    /// Release the trajectory builder's memory after a durable close.
    /// Round-6 (hunt4 R2): SUCCESSFUL unsigned closes previously kept
    /// the full trajectory (every captured Step, up to 8 MiB each) in
    /// RAM for the process lifetime because `evict_finalized` only
    /// evicts Signed sessions. Drain the builder AFTER the artifact +
    /// sidecar are durable, so a failed write can still be retried (it
    /// re-uses the still-populated builder) but a succeeded close
    /// promptly reclaims the memory.
    pub(crate) fn drain_trajectory_builder(&self) {
        let identity = self.current_identity();
        let agent = av_atif::Agent {
            name: "agentvisor-ai-harness".into(),
            version: identity.version.clone(),
            model_name: None,
            tool_definitions: None,
            extra: Some(serde_json::json!({
                "charter": identity.charter,
                "instance_uid": identity.instance_uid,
                "ttl_remaining_s": identity.ttl_remaining_s,
            })),
        };
        *self.atif.lock() = av_atif::TrajectoryBuilder::new(agent, Some(self.id.clone()));
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

    /// Number of forwarded chat responses currently streaming.
    pub fn active_streams_count(&self) -> u64 {
        self.active_streams.load(Ordering::Acquire)
    }

    /// Number of worker jobs accepted but not yet fully captured.
    pub fn pending_jobs_count(&self) -> u64 {
        self.pending_jobs.load(Ordering::Acquire)
    }

    /// Round-44 F2: distinguish the "empty unsigned session close
    /// was rejected" quarantine (the reconciler's "no captured steps"
    /// refusal) from a
    /// successfully-persisted unsigned session. The reject path sets
    /// `artifact_committed = 1` (so `is_closed()` stays true) but
    /// never writes an ATIF file, never sets `atif_path`, and never
    /// calls `mark_capture_failed`. Without this predicate the
    /// round-43 F1 `pending_close_sessions()` filter picks it up and
    /// drives the finalization tail — which emits a spurious
    /// SESSION_CLOSE bridge event for a session that has no receipt
    /// and no ATIF, breaking downstream OCSF consumers' invariant
    /// that a close event follows an artifact event. It also marks
    /// `close_complete = 1`, which lets `get_or_open` (reopen=true)
    /// silently replace the quarantined Session with a fresh one on
    /// the next chat request, losing the incident evidence.
    pub(crate) fn is_empty_unsigned_quarantine(&self) -> bool {
        self.workflow == Workflow::Unsigned
            && self.artifact_committed.load(Ordering::Acquire) != 0
            && self.atif_path.lock().is_none()
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

    /// Latch an enforcement refusal (sticky; see the field doc).
    pub(crate) fn latch_enforcement(&self, reason: StopReason) {
        self.enforcement_tripped
            .store(u64::from(reason.id()), Ordering::Release);
    }

    /// True when an enforcement refusal was latched on this session.
    pub(crate) fn enforcement_tripped(&self) -> bool {
        self.enforcement_tripped.load(Ordering::Acquire) != 0
    }

    /// Build the receipt body for this session (signed close or promotion).
    pub fn receipt_body(
        &self,
        subject: av_receipts::ReceiptSubject,
        stop: StopReason,
    ) -> av_receipts::ReceiptBody {
        let recorded =
            StopReason::from_id(u8::try_from(self.last_stop_reason_id.load(Ordering::Acquire)).unwrap_or(0));
        let stop = if recorded == StopReason::Unknown {
            stop
        } else {
            recorded
        };
        av_receipts::receipt::new_body(
            self.id.clone(),
            self.current_identity(),
            subject,
            av_receipts::ToolCallSummary {
                total: self.totals.tool_calls.load(Ordering::Acquire),
                allowed: self.totals.tool_allowed.load(Ordering::Acquire),
                blocked: self.totals.tool_blocked.load(Ordering::Acquire),
            },
            av_receipts::CostSummary {
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
    if value > av_core::error::JCS_SAFE_MAX {
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
    ///
    /// If an entry exists but has completed close (receipt/ATIF durably
    /// committed, journal removed) and has not yet been reaped by the
    /// idle sweeper, treat the id as free and open a fresh session —
    /// otherwise a well-behaved client that reuses a session id after a
    /// server-side close (retry after a 5xx, network partition, TTL
    /// refresh) would see `400 session is already closed` for the entire
    /// eviction window. A session that started close but has not yet
    /// finished it (`close_complete = 0`) is *not* replaced: reopening
    /// would race the in-flight close and split the audit trail.
    ///
    /// This is the right shape for **chat requests**: the client is
    /// starting a new turn and it's fine to give them a fresh state
    /// under the same id. For **tool interception**, use
    /// [`Self::get_or_open_no_reopen`] — a tool call references an
    /// in-progress conversation, and silently resurrecting a closed
    /// session would let the client extend the audit trail past its
    /// signed receipt.
    pub fn get_or_open(
        &self,
        id: &str,
        workflow: Workflow,
        identity: &AgentIdentity,
        breaker: &av_loopdetect::BreakerConfig,
    ) -> Arc<Session> {
        self.get_or_open_inner(
            id, workflow, identity, breaker, /* reopen_after_close */ true,
        )
    }

    /// Like [`Self::get_or_open`] but hand back the existing session
    /// **without** recycling completed-close entries — the caller then
    /// sees `is_closed() == true` and can refuse with `BadRequest`.
    /// Use this on paths where the caller is trying to extend an
    /// existing session (tool interception, session-scoped mutations).
    pub fn get_or_open_no_reopen(
        &self,
        id: &str,
        workflow: Workflow,
        identity: &AgentIdentity,
        breaker: &av_loopdetect::BreakerConfig,
    ) -> Arc<Session> {
        self.get_or_open_inner(
            id, workflow, identity, breaker, /* reopen_after_close */ false,
        )
    }

    fn get_or_open_inner(
        &self,
        id: &str,
        workflow: Workflow,
        identity: &AgentIdentity,
        breaker: &av_loopdetect::BreakerConfig,
        reopen_after_close: bool,
    ) -> Arc<Session> {
        use dashmap::mapref::entry::Entry;
        match self.sessions.entry(id.to_owned()) {
            Entry::Occupied(mut occupied) => {
                if reopen_after_close && occupied.get().close_complete_flag() {
                    // Enforcement-triggered closes must NOT silently
                    // recycle: a session closed because its token budget
                    // was exhausted (or its loop breaker aborted) would
                    // otherwise reopen under the SAME id with a fresh
                    // budget and fresh breaker — verified live as a
                    // strict 200/403/200/403 alternation that rides the
                    // per-session cap at ~50% duty forever. Per-session
                    // budgets cannot stop a client spreading across NEW
                    // ids (inherent to per-session semantics), but the
                    // same id must stay terminally refused so each
                    // incarnation is an explicit, distinct audit entity.
                    // Keyed on the sticky enforcement latch, not the
                    // last-write-wins stop reason — later responses
                    // overwrite that record, and non-enforcement
                    // failures (quota-backend errors, blocked tool
                    // calls) also write it, making it an unreliable
                    // proxy in both directions.
                    if occupied.get().enforcement_tripped() {
                        return occupied.get().clone();
                    }
                    let fresh = Arc::new(Session::new(
                        id.to_owned(),
                        workflow,
                        identity.clone(),
                        breaker.clone(),
                    ));
                    occupied.insert(Arc::clone(&fresh));
                    fresh
                } else {
                    occupied.get().clone()
                }
            }
            Entry::Vacant(vacant) => {
                let fresh = Arc::new(Session::new(
                    id.to_owned(),
                    workflow,
                    identity.clone(),
                    breaker.clone(),
                ));
                vacant.insert(Arc::clone(&fresh));
                fresh
            }
        }
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

    /// Evict signed sessions whose close ran to full completion and that
    /// have been idle longer than `idle_s`, returning the evicted sessions.
    ///
    /// Only signed sessions whose close *fully completed* are eligible: a
    /// completed close removed the on-disk journal, so nothing re-inserts
    /// them, and a later request or lifecycle call for the id behaves
    /// exactly as it would after a process restart. `close_complete` (not
    /// `artifact_committed`, which is set before the fallible bridge emits
    /// and journal removal) is the gate — a failed or in-flight close must
    /// stay resident, or a client reusing the id could open a fresh session
    /// whose journal appends collide with the still-on-disk records.
    /// Unsigned sessions must stay resident — the recovery scan re-inserts
    /// them from their spool artifact on the next tick anyway, and evicting
    /// one lets a client reuse its id against the still-present artifact and
    /// provenance files, poisoning the new incarnation's close. Capture-failed
    /// (quarantined) sessions also stay: they are bounded by real crash
    /// events and their in-registry seal is what keeps the fail-closed
    /// refusal cheap. Without eviction the registry grows by one entry per
    /// client-chosen session id for the process lifetime.
    pub fn evict_finalized(&self, idle_s: u64) -> Vec<Arc<Session>> {
        // Round-49 F1: idle comparison uses the monotonic clock so a
        // forward wall-clock jump (VM resume, NTP correction) cannot
        // make finalized sessions look premature-idle. Wall-clock
        // `last_activity_ms` stays available for dashboard display.
        let idle_duration = Duration::from_secs(idle_s);
        let mut evicted = Vec::new();
        self.sessions.retain(|_, session| {
            let evict = session.workflow == Workflow::Signed
                && session.close_complete.load(Ordering::Acquire) != 0
                && !session.capture_failed()
                // Enforcement-latched sessions are retained like
                // capture-failed ones: evicting them vacated the id, and
                // the next get_or_open built a fresh session with a
                // fresh budget/breaker — the same-id refusal silently
                // expired after idle_s for signed workflows. Bounded by
                // the overflow pass below (unlike capture_failed, the
                // latch is client-mintable at line rate — one over-cap
                // request per fresh id — so retention needs a cap).
                && !session.enforcement_tripped()
                && session.active_streams.load(Ordering::Acquire) == 0
                && session.pending_jobs.load(Ordering::Acquire) == 0
                && session.idle_duration() >= idle_duration;
            if evict {
                evicted.push(Arc::clone(session));
            }
            !evict
        });
        // Overflow pass: cap latched-retained signed sessions. Beyond the
        // cap, evict oldest-first — the same-id refusal expires for the
        // evicted ids (degraded to the pre-latch idle-bounded behavior),
        // which is the accepted cost of bounding client-mintable registry
        // growth. Unsigned latched sessions are governed by the existing
        // unsigned retention posture and are not evicted here.
        const MAX_LATCHED_RETAINED: usize = 4096;
        let mut latched: Vec<Arc<Session>> = self
            .sessions
            .iter()
            .filter(|entry| {
                entry.workflow == Workflow::Signed
                    && entry.close_complete.load(Ordering::Acquire) != 0
                    && entry.enforcement_tripped()
                    && !entry.capture_failed()
                    && entry.active_streams.load(Ordering::Acquire) == 0
                    && entry.pending_jobs.load(Ordering::Acquire) == 0
            })
            .map(|entry| Arc::clone(&entry))
            .collect();
        if latched.len() > MAX_LATCHED_RETAINED {
            latched.sort_by_key(|session| std::cmp::Reverse(session.idle_duration()));
            let excess = latched.len() - MAX_LATCHED_RETAINED;
            tracing::warn!(
                excess,
                cap = MAX_LATCHED_RETAINED,
                "latched-retained signed sessions exceed the cap; evicting oldest \
                 (their same-id enforcement refusal expires)"
            );
            for session in latched.into_iter().take(excess) {
                self.sessions.remove(&session.id);
                evicted.push(session);
            }
        }
        evicted
    }

    /// Round-43 F1: sessions where `close_session_locked` marked
    /// `artifact_committed = 1` but crashed / failed before running
    /// the finalization tail (`emit_bridge_event(SESSION_CLOSE)` +
    /// `remove_step_journal` + `remove_lifecycle_outbox` +
    /// `mark_close_complete`). Without this recovery hook such
    /// sessions accumulate in the registry forever: `is_closed()` is
    /// true so the idle sweeper skips them; `close_complete = 0` so
    /// `evict_finalized` refuses them; recovery scans skip them via
    /// the "already in registry" short-circuit. Capture-failed and
    /// empty-unsigned quarantines are excluded — they intentionally
    /// stay in the registry as evidence of the incident.
    ///
    /// Round-44 F2: the empty-unsigned quarantine (the reconciler's
    /// "no captured steps" refusal) does NOT set `capture_failed = 1` (it
    /// is a distinct semantic — "no work was captured" rather than
    /// "capture was lost mid-flight"), so `!capture_failed()` alone
    /// let the sweep pick it up and emit a spurious SESSION_CLOSE
    /// bridge event for a session that had no other events on the
    /// wire. `is_empty_unsigned_quarantine()` closes that gap.
    pub fn pending_close_sessions(&self) -> Vec<Arc<Session>> {
        self.sessions
            .iter()
            .filter(|entry| {
                entry.artifact_committed.load(Ordering::Acquire) != 0
                    && entry.close_complete.load(Ordering::Acquire) == 0
                    && !entry.capture_failed()
                    && !entry.is_empty_unsigned_quarantine()
            })
            .map(|entry| entry.clone())
            .collect()
    }

    /// Sessions idle longer than `idle_s` (for the sweeper).
    pub fn idle_sessions(&self, idle_s: u64) -> Vec<Arc<Session>> {
        // Round-49 F1: monotonic idle math — see `evict_finalized`.
        let idle_duration = Duration::from_secs(idle_s);
        self.sessions
            .iter()
            .filter(|e| {
                e.idle_duration() >= idle_duration
                    && !e.is_closed()
                    // A session with a live forwarded response is not idle even
                    // when its admission clock is stale: the last-activity
                    // clock is refreshed only at request admission, so a
                    // stream that outlives the idle window would otherwise
                    // let the sweeper claim the close (sealing the session
                    // mid-conversation) and then park inside `wait_for_streams`
                    // while holding the shared lifecycle lock until the
                    // client's stream ends.
                    && e.active_streams.load(Ordering::Acquire) == 0
            })
            .map(|e| e.clone())
            .collect()
    }

    /// Snapshot every session in the registry — open, closed, or
    /// capture-failed. Used by the dashboard to show recent activity
    /// including sessions that have just been sealed but not yet evicted.
    pub fn open_sessions_including_closed(&self) -> Vec<Arc<Session>> {
        self.sessions.iter().map(|entry| entry.clone()).collect()
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
            av_loopdetect::BreakerConfig::default(),
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

    /// A client that reuses a session id after the server-side close
    /// completes (retry after a 5xx, TTL refresh, network partition
    /// recovery) must get a fresh session instead of the closed one —
    /// otherwise every request until the idle sweep would return
    /// `400 session is already closed`. Only sessions with
    /// `close_complete = true` are recycled; a session mid-close must
    /// still be treated as the same one so the ongoing close is not
    /// raced.
    #[test]
    fn get_or_open_recycles_id_after_close_complete() {
        let registry = SessionRegistry::new();
        let breaker = av_loopdetect::BreakerConfig::default();

        // First open. Simulate a full close (artifact committed +
        // close_complete flipped) so the next get_or_open sees a
        // fully-sealed session.
        let first = registry.get_or_open("reused", Workflow::Signed, &identity(), &breaker);
        assert!(first.try_close(), "first close must land");
        first.mark_artifact_committed();
        first.mark_close_complete();

        let second = registry.get_or_open("reused", Workflow::Signed, &identity(), &breaker);
        assert!(
            !Arc::ptr_eq(&first, &second),
            "closed session must be replaced by a fresh one"
        );
        assert!(!second.is_closed(), "reopened session must accept new work");
        assert_eq!(registry.len(), 1, "id remains a single registry entry");
    }

    /// Enforcement-latched sessions are terminal for the session id:
    /// recycling would hand the SAME id a fresh budget and fresh
    /// breaker — verified live as a 200/403 alternation riding the
    /// per-session token cap at ~50% duty forever. Keyed on the sticky
    /// latch: a LATER recorded stop reason (post-refusal success, a
    /// concurrent stream's provider finish) must not reclassify the
    /// close as natural, and a recorded-but-unlatched enforcement
    /// reason (blocked tool call, quota-backend outage) must not lock
    /// out a naturally-closed id.
    #[test]
    fn get_or_open_refuses_to_recycle_enforcement_latched_sessions() {
        let registry = SessionRegistry::new();
        let breaker = av_loopdetect::BreakerConfig::default();
        for (reason, workflow) in [
            (StopReason::BudgetExceeded, Workflow::Unsigned),
            (StopReason::LoopDetected, Workflow::Unsigned),
            // Signed sessions must refuse identically (they also must
            // not be evicted out of the refusal — covered below).
            (StopReason::BudgetExceeded, Workflow::Signed),
        ] {
            let id = format!("enforced-{}-{}", reason.id(), workflow.as_str());
            let first = registry.get_or_open(&id, workflow, &identity(), &breaker);
            first.latch_enforcement(reason);
            // A later provider stop reason must NOT un-latch.
            first.record_stop_reason(StopReason::Stop);
            assert!(first.try_close());
            first.mark_artifact_committed();
            first.mark_close_complete();
            let second = registry.get_or_open(&id, workflow, &identity(), &breaker);
            assert!(
                Arc::ptr_eq(&first, &second),
                "enforcement-latched session must NOT be recycled ({reason:?}/{workflow:?})"
            );
            assert!(second.is_closed(), "the id must stay refused ({reason:?})");
        }
        // Latched signed sessions are excluded from eviction — evicting
        // vacated the id and the refusal silently expired after idle_s.
        assert!(
            registry.evict_finalized(0).is_empty(),
            "latched sessions must not be evicted"
        );
        // A RECORDED enforcement reason without the latch (blocked tool
        // call, quota-backend outage) must not lock out a naturally
        // closed id.
        let first = registry.get_or_open("natural", Workflow::Unsigned, &identity(), &breaker);
        first.record_stop_reason(StopReason::BudgetExceeded);
        assert!(first.try_close());
        first.mark_artifact_committed();
        first.mark_close_complete();
        let second = registry.get_or_open("natural", Workflow::Unsigned, &identity(), &breaker);
        assert!(
            !Arc::ptr_eq(&first, &second),
            "recorded-but-unlatched reasons must keep recycling"
        );
    }

    /// A session that has *started* close but has not completed it
    /// must not be replaced — reopening would race the finaliser and
    /// split the audit trail across two artifacts for the same id.
    #[test]
    fn get_or_open_preserves_session_mid_close() {
        let registry = SessionRegistry::new();
        let breaker = av_loopdetect::BreakerConfig::default();
        let first = registry.get_or_open("closing", Workflow::Signed, &identity(), &breaker);
        assert!(first.try_close());
        // close_complete NOT set — this is the in-flight close state.
        let second = registry.get_or_open("closing", Workflow::Signed, &identity(), &breaker);
        assert!(
            Arc::ptr_eq(&first, &second),
            "mid-close session must be handed back unchanged"
        );
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
        s.set_idle_for_testing(10);
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
        s.set_idle_for_testing(10);
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

    /// Idle sweeping now uses the monotonic anchor
    /// (`monotonic_ns_since_start`), so wall-clock jumps in EITHER
    /// direction — backward (NTP correction, VM pause/resume) or
    /// forward (VM resume after a long pause) — cannot flip a fresh
    /// session into the idle set. The monotonic elapsed time is
    /// bounded by real wall time since process start and is immune
    /// to `SystemTime` jumps.
    #[test]
    fn idle_reap_is_safe_across_wall_clock_jumps() {
        let r = SessionRegistry::new();
        let s = r.get_or_open("clock-jump", Workflow::Unsigned, &identity(), &Default::default());
        // Simulate wall-clock chaos in BOTH directions on the display
        // clock — the monotonic anchor is untouched and the sweeper
        // reads only the monotonic side.
        s.last_activity_ms.store(
            av_core::time::now_ms() + av_core::units::MS_PER_HOUR,
            Ordering::Release,
        );
        for idle_s in [1u64, 60, 3_600, av_core::units::SECS_PER_DAY] {
            assert!(
                r.idle_sessions(idle_s).is_empty(),
                "fresh session must not be reaped after a wall-clock jump at idle_s={idle_s}",
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

    /// `evict_finalized` removes only signed, fully committed, quiescent,
    /// idle sessions — and leaves unsigned, capture-failed, active-stream,
    /// and recently-active sessions resident.
    #[test]
    fn evict_finalized_removes_only_quiescent_committed_signed_sessions() {
        let r = SessionRegistry::new();

        let eligible = r.get_or_open("evict-me", Workflow::Signed, &identity(), &Default::default());
        eligible.try_close();
        eligible.mark_artifact_committed();
        eligible.mark_close_complete();
        eligible.set_idle_for_testing(10);

        // Artifact committed but the close never completed (bridge emit or
        // journal removal failed): the journal may still be on disk, so a
        // reused id must find this sealed session, not a fresh one.
        let incomplete = r.get_or_open(
            "keep-incomplete",
            Workflow::Signed,
            &identity(),
            &Default::default(),
        );
        incomplete.try_close();
        incomplete.mark_artifact_committed();
        incomplete.set_idle_for_testing(10);

        let unsigned = r.get_or_open(
            "keep-unsigned",
            Workflow::Unsigned,
            &identity(),
            &Default::default(),
        );
        unsigned.try_close();
        unsigned.mark_artifact_committed();
        unsigned.mark_close_complete();
        unsigned.set_idle_for_testing(10);

        let failed = r.get_or_open("keep-failed", Workflow::Signed, &identity(), &Default::default());
        failed.try_close();
        failed.mark_artifact_committed();
        failed.mark_close_complete();
        failed.mark_capture_failed();
        failed.set_idle_for_testing(10);

        let streaming = r.get_or_open(
            "keep-streaming",
            Workflow::Signed,
            &identity(),
            &Default::default(),
        );
        streaming.try_close();
        streaming.mark_artifact_committed();
        streaming.mark_close_complete();
        streaming.set_idle_for_testing(10);
        let lease = SessionLease::new(Arc::clone(&streaming));

        let fresh = r.get_or_open("keep-fresh", Workflow::Signed, &identity(), &Default::default());
        fresh.try_close();
        fresh.mark_artifact_committed();
        fresh.mark_close_complete();

        let open = r.get_or_open("keep-open", Workflow::Signed, &identity(), &Default::default());
        open.set_idle_for_testing(10);

        let evicted = r.evict_finalized(5);
        assert_eq!(
            evicted.iter().map(|s| s.id.as_str()).collect::<Vec<_>>(),
            vec!["evict-me"],
            "only the committed, quiescent, idle signed session may be evicted",
        );
        assert!(r.get("evict-me").is_none());
        for id in [
            "keep-incomplete",
            "keep-unsigned",
            "keep-failed",
            "keep-streaming",
            "keep-fresh",
            "keep-open",
        ] {
            assert!(r.get(id).is_some(), "{id} must stay resident");
        }
        drop(lease);
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
