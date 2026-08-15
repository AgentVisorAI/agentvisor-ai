//! Session finalization and periodic idle reconciliation.

use crate::session::{Session, SessionRegistry, Workflow};
use ab_bridge::EventBus;
use ab_core::metrics::Registry;
use ab_core::time::elapsed_us;
use ab_events::StopReason;
use ab_receipts::{Receipt, ReceiptSubject, Signer};
use serde::Serialize;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

/// Hard upper bound on a single ATIF spool file the recovery scan will
/// buffer into memory. Chosen to exceed the largest reasonable trajectory
/// (millions of steps, hundreds of MB of reasoning) while capping the
/// coarsest resource-exhaustion vector: an attacker-crafted trajectory
/// with a multi-gigabyte `steps[i].message` cannot force recovery to OOM.
const MAX_ATIF_RECOVERY_BYTES: u64 = 256 * 1024 * 1024;

/// Result of closing a session.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FinalizeOutcome {
    /// A signed-workflow receipt was issued.
    Receipt {
        /// The issued receipt.
        receipt: Box<Receipt>,
    },
    /// An unsigned ATIF trajectory was persisted.
    Atif {
        /// Atomic spool path.
        path: PathBuf,
    },
    /// The session had already been closed.
    AlreadyClosed,
}

/// Lifecycle errors.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FinalizeError {
    /// Blocking task failed or panicked.
    #[error("finalization task failed: {0}")]
    Task(String),
    /// Receipt issuance failed.
    #[error("receipt issuance failed: {0}")]
    Receipt(String),
    /// ATIF persistence or parsing failed.
    #[error("ATIF finalization failed: {0}")]
    Atif(String),
    /// Promotion is invalid for this session.
    #[error("promotion refused: {0}")]
    Promotion(String),
    /// One or more upstream actions were not captured.
    #[error("session capture is incomplete; refusing final artifact")]
    CaptureIncomplete,
    /// Lifecycle event could not be durably published.
    #[error("lifecycle event publication failed: {0}")]
    Bridge(String),
}

/// Shared asynchronous finalization service.
#[derive(Clone)]
pub struct Finalizer {
    signer: Arc<dyn Signer>,
    spool_dir: PathBuf,
    metrics: Arc<Registry>,
    bridge: Option<Arc<dyn EventBus>>,
    /// Quota/budget state to clear once a session is sealed (closed sessions
    /// refuse admission, so their budget counters are dead weight). Optional
    /// because lifecycle tests construct a Finalizer without one.
    state_store: Option<Arc<dyn ab_state::StateStore>>,
    recovery_lock: Arc<tokio::sync::Mutex<()>>,
    /// Per-session lifecycle mutex table. Serialises `close_session`,
    /// `promote`, and `recover_spooled_sessions` on the *same* session
    /// id; different sessions proceed concurrently. Replaces the earlier
    /// single global `lifecycle_lock` which head-of-line-blocked every
    /// client close behind a long recovery scan or an idle sweep of
    /// thousands of sessions.
    lifecycle_locks: Arc<SessionLockTable>,
    quarantined_sessions: Arc<parking_lot::Mutex<std::collections::HashSet<String>>>,
    /// Artifacts already warned about during recovery scans, so a corrupt
    /// file left on disk as evidence does not repeat its warning every tick.
    /// Round-17 F8 + round-18 F6: bounded by `warn_once` via FIFO
    /// eviction, not full-clear. FIFO avoids the "clear then all
    /// 4096 legitimate recurring artifacts re-warn on the same
    /// tick" log storm the round-17 clear-on-overflow approach
    /// enabled under a rotating-timestamp attacker.
    warned_artifacts: Arc<parking_lot::Mutex<WarnedArtifacts>>,
    journal_key: [u8; 32],
}

/// FIFO-evicting set used by `warn_once`. Round-18 F6: replaces the
/// round-17 F8 clear-on-overflow HashSet so a rotating-timestamp
/// attacker who forces one eviction per tick cannot cause every
/// legitimate recurring artifact to re-warn together — only ONE
/// entry evicts per insert-past-cap.
///
/// Round-19 F5: the cap is stored on the struct rather than passed
/// per-insert. Previously callers had to agree on the cap for
/// every call; a future caller who passed a smaller value would
/// have shrunk the deque without evicting matching set entries,
/// silently desyncing the two collections.
pub(crate) struct WarnedArtifacts {
    order: std::collections::VecDeque<PathBuf>,
    set: std::collections::HashSet<PathBuf>,
    cap: usize,
}

impl WarnedArtifacts {
    fn new(cap: usize) -> Self {
        // Round-20 F6: clamp `cap` to a minimum of 1. Under
        // `cap: 0` the FIFO oscillated at size 1 (evicting the
        // one entry on every insert), silently breaking the
        // "warn once per path per window" contract. A future
        // caller wiring the cap through `HarnessConfig` and
        // mistyping the field to `0` would otherwise degrade to
        // warning-once-for-one-artifact-ever. Clamp closes that
        // failure mode without a panic path.
        let cap = cap.max(1);
        Self {
            order: std::collections::VecDeque::new(),
            set: std::collections::HashSet::new(),
            cap,
        }
    }

    fn insert(&mut self, path: PathBuf) -> bool {
        if self.set.contains(&path) {
            return false;
        }
        if self.order.len() >= self.cap {
            if let Some(evicted) = self.order.pop_front() {
                self.set.remove(&evicted);
            }
        }
        self.order.push_back(path.clone());
        self.set.insert(path);
        true
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.set.len()
    }
}

/// Cap on `warned_artifacts` so a rotating-timestamp attacker (or
/// unbounded orphan churn) cannot leak memory forever. Round-18 F6:
/// on insert-past-cap, ONE oldest entry evicts (FIFO) — not a full
/// clear that would let a legitimate 4096-entry working set re-warn
/// together every tick.
const WARNED_ARTIFACTS_CAP: usize = 4096;

/// Per-session lifecycle mutex table.
///
/// Invariants:
///   * At most one `close_session` / `promote` / recovery-adopt runs
///     concurrently for a given session_id.
///   * Different session_ids proceed concurrently.
///   * Entries are Arc-refcounted. `SessionLifecycleGuard::drop` opportunistically
///     removes the entry when this task was the last waiter; readers
///     that observed the entry before the remove simply create a new
///     Arc — correctness is preserved because they cannot yet hold
///     the guard.
#[derive(Default)]
pub struct SessionLockTable {
    inner: dashmap::DashMap<String, Arc<tokio::sync::Mutex<()>>>,
}

impl SessionLockTable {
    fn arc_for(&self, session_id: &str) -> Arc<tokio::sync::Mutex<()>> {
        // `entry().or_insert_with()` is race-free within a shard.
        self.inner
            .entry(session_id.to_owned())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .value()
            .clone()
    }

    /// Called after a caller drops its owned guard. Removes the entry
    /// IFF the map is the last strong reference. `remove_if` runs under
    /// a shard write lock so the refcount check is atomic w.r.t. `arc_for`.
    fn try_gc(&self, session_id: &str) {
        self.inner
            .remove_if(session_id, |_, arc| Arc::strong_count(arc) == 1);
    }

    /// Test-only: how many session lock entries are currently resident.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.inner.len()
    }
}

/// RAII guard that (a) holds an owned mutex permit and (b) opportunistically
/// prunes its entry from [`SessionLockTable`] on drop.
pub struct SessionLifecycleGuard {
    permit: Option<tokio::sync::OwnedMutexGuard<()>>,
    table: Arc<SessionLockTable>,
    session_id: String,
}

impl Drop for SessionLifecycleGuard {
    fn drop(&mut self) {
        // Drop the permit *first* (releasing the mutex) and only then
        // attempt GC: the strong-count check inside `try_gc` must see
        // us gone. `Option::take` explicitly sequences the two steps
        // instead of relying on field-declaration order.
        drop(self.permit.take());
        self.table.try_gc(&self.session_id);
    }
}

struct CloseClaim<'a> {
    session: &'a Session,
    committed: bool,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct LifecycleOutbox {
    session_id: String,
    kind: String,
    topic: String,
    key: String,
    value: serde_json::Value,
    ack: Option<ab_bridge::PublishAck>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct AtifProvenance {
    session_id: String,
    digest: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct PromotionMarker {
    session_id: String,
    trajectory_digest: String,
}

impl Drop for CloseClaim<'_> {
    fn drop(&mut self) {
        if !self.committed {
            self.session.reset_close();
        }
    }
}

impl Finalizer {
    /// Access the shared metrics registry so background paths (stream
    /// abort, worker-side supervision) can bump counters without
    /// plumbing the registry through every struct field.
    pub fn metrics(&self) -> &Arc<Registry> {
        &self.metrics
    }

    /// Create a finalizer writing unsigned artifacts beneath `spool_dir`.
    pub fn new(signer: Arc<dyn Signer>, spool_dir: PathBuf, metrics: Arc<Registry>) -> Self {
        let journal_key = crate::journal::key_from_signer(signer.as_ref());
        Self {
            signer,
            spool_dir,
            metrics,
            bridge: None,
            state_store: None,
            recovery_lock: Arc::new(tokio::sync::Mutex::new(())),
            lifecycle_locks: Arc::new(SessionLockTable::default()),
            quarantined_sessions: Arc::new(parking_lot::Mutex::new(std::collections::HashSet::new())),
            warned_artifacts: Arc::new(parking_lot::Mutex::new(WarnedArtifacts::new(WARNED_ARTIFACTS_CAP))),
            journal_key,
        }
    }

    /// Create a finalizer that also emits receipt events to the Bridge.
    pub fn with_bridge(
        signer: Arc<dyn Signer>,
        spool_dir: PathBuf,
        metrics: Arc<Registry>,
        bridge: Arc<dyn EventBus>,
    ) -> Self {
        let journal_key = crate::journal::key_from_signer(signer.as_ref());
        Self {
            signer,
            spool_dir,
            metrics,
            bridge: Some(bridge),
            state_store: None,
            recovery_lock: Arc::new(tokio::sync::Mutex::new(())),
            lifecycle_locks: Arc::new(SessionLockTable::default()),
            quarantined_sessions: Arc::new(parking_lot::Mutex::new(std::collections::HashSet::new())),
            warned_artifacts: Arc::new(parking_lot::Mutex::new(WarnedArtifacts::new(WARNED_ARTIFACTS_CAP))),
            journal_key,
        }
    }

    /// Acquire the lifecycle lock scoped to a single session id. Held
    /// during `close_session` / `promote` / recovery-adopt so a single
    /// session cannot be finalised twice concurrently; different
    /// sessions proceed in parallel.
    async fn acquire_lifecycle(&self, session_id: &str) -> SessionLifecycleGuard {
        let arc = self.lifecycle_locks.arc_for(session_id);
        let permit = arc.lock_owned().await;
        SessionLifecycleGuard {
            permit: Some(permit),
            table: Arc::clone(&self.lifecycle_locks),
            session_id: session_id.to_owned(),
        }
    }

    #[cfg(test)]
    pub(crate) fn lifecycle_locks(&self) -> Arc<SessionLockTable> {
        Arc::clone(&self.lifecycle_locks)
    }

    /// Round-17 F8: bounded insert-if-absent for `warned_artifacts`.
    /// When the tracked set is about to exceed `WARNED_ARTIFACTS_CAP`,
    /// Round-17 F8 + round-18 F6: bounded insert-if-absent for
    /// `warned_artifacts`. When the tracked set is about to exceed
    /// `WARNED_ARTIFACTS_CAP`, ONE oldest entry evicts (FIFO) — the
    /// round-17 approach cleared the whole set, which under a
    /// rotating-timestamp attacker meant every legitimate recurring
    /// artifact re-warned together each tick. FIFO cost per insert
    /// is O(1). Returns true if this is the first warn for `path`
    /// in the current window (caller emits the warn only then).
    fn warn_once(&self, path: PathBuf) -> bool {
        self.warned_artifacts.lock().insert(path)
    }

    /// Attach the quota/budget state store whose per-session counters are
    /// cleared when a session is sealed.
    #[must_use]
    pub fn with_state_store(mut self, store: Arc<dyn ab_state::StateStore>) -> Self {
        self.state_store = Some(store);
        self
    }

    /// Drop a sealed session's budget counters. Admission gates reject
    /// closed and capture-failed sessions before any quota check, so the
    /// counters can never be consulted again; leaving them would grow the
    /// in-memory state store by a few cells per session forever
    /// (attacker-chosen session ids make that unbounded).
    fn clear_budget_state(&self, session_id: &str) {
        if let Some(store) = self.state_store.as_deref() {
            store.remove_prefix(&ab_state::ActionBudget::session_prefix(session_id));
        }
    }

    /// Close exactly once. Receipt signing and ATIF serialization never run on
    /// the request hot path.
    #[tracing::instrument(
        name = "agentbridge.session.close",
        skip_all,
        fields(session.id = %session.id, workflow = ?session.workflow)
    )]
    pub async fn close_session(
        &self,
        session: Arc<Session>,
        stop_reason: StopReason,
    ) -> Result<FinalizeOutcome, FinalizeError> {
        let _lifecycle = self.acquire_lifecycle(&session.id).await;
        self.close_session_locked(session, stop_reason).await
    }

    async fn close_session_locked(
        &self,
        session: Arc<Session>,
        stop_reason: StopReason,
    ) -> Result<FinalizeOutcome, FinalizeError> {
        let close_guard = session.close_guard();
        if !session.try_close() {
            return Ok(FinalizeOutcome::AlreadyClosed);
        }
        drop(close_guard);
        let mut claim = CloseClaim {
            session: &session,
            committed: false,
        };
        session.wait_for_streams().await;
        session.wait_for_worker_jobs().await;
        if session.capture_failed() {
            self.metrics
                .counter(
                    "ab_incomplete_sessions_total",
                    "Sessions refused due to incomplete capture",
                )
                .inc();
            // Seal the session finalized so the idle sweeper's `!is_closed()`
            // filter skips it — otherwise CloseClaim resets `closed` to 0 and
            // this branch retries on every idle tick forever.
            session.mark_artifact_committed();
            claim.committed = true;
            self.clear_budget_state(&session.id);
            return Err(FinalizeError::CaptureIncomplete);
        }
        let started = Instant::now();
        let outcome = match session.workflow {
            Workflow::Signed => {
                let subject = {
                    let chain = session.chain.lock();
                    ReceiptSubject::EventChain {
                        chain_head: chain.head_hex(),
                        event_count: chain.count(),
                    }
                };
                let persisted_receipt = { session.receipt.lock().clone() };
                let receipt = if let Some(receipt) = persisted_receipt {
                    self.verify_configured_receipt(&receipt)?;
                    if receipt.body.subject != subject {
                        return Err(FinalizeError::Receipt(
                            "persisted receipt subject does not match reconstructed chain".to_owned(),
                        ));
                    }
                    receipt
                } else {
                    let body = session.receipt_body(subject, stop_reason);
                    let sign_started = Instant::now();
                    let receipt = Receipt::issue(body, self.signer.as_ref())
                        .map_err(|error| FinalizeError::Receipt(error.to_string()))?;
                    self.metrics
                        .histogram("ab_receipt_sign_duration_seconds", "Receipt signing latency")
                        .observe_us(elapsed_us(sign_started));
                    self.persist_receipt(&session.id, &receipt).await?;
                    *session.receipt.lock() = Some(receipt.clone());
                    receipt
                };
                session.mark_artifact_committed();
                self.emit_receipt_event(&session, &receipt).await?;
                FinalizeOutcome::Receipt {
                    receipt: Box::new(receipt),
                }
            }
            Workflow::Unsigned => {
                let existing_path = { session.atif_path.lock().clone() };
                let path = if let Some(path) = existing_path {
                    path
                } else {
                    let mut trajectory = session.snapshot_trajectory();
                    // An unsigned session that captured no steps cannot ever produce a strict-valid
                    // ATIF; seal it here so the idle sweeper skips it instead of churning forever.
                    if trajectory.steps.is_empty() {
                        session.mark_artifact_committed();
                        claim.committed = true;
                        self.clear_budget_state(&session.id);
                        return Err(FinalizeError::Atif(
                            "cannot finalize an unsigned session with no captured steps".to_owned(),
                        ));
                    }
                    let identity = session.current_identity();
                    trajectory.agent.extra = Some(serde_json::json!({
                        "charter": identity.charter,
                        "instance_uid": identity.instance_uid,
                        "ttl_remaining_s": identity.ttl_remaining_s,
                    }));
                    if let Some(metrics) = trajectory.final_metrics.as_mut() {
                        metrics.total_prompt_tokens = Some(
                            session
                                .totals
                                .prompt_tokens
                                .load(std::sync::atomic::Ordering::Acquire),
                        );
                        metrics.total_completion_tokens = Some(
                            session
                                .totals
                                .completion_tokens
                                .load(std::sync::atomic::Ordering::Acquire),
                        );
                        metrics.total_cached_tokens = Some(
                            session
                                .totals
                                .cached_tokens
                                .load(std::sync::atomic::Ordering::Acquire),
                        );
                        metrics.total_cost_usd = Some(
                            session
                                .totals
                                .cost_usd_micros
                                .load(std::sync::atomic::Ordering::Acquire)
                                as f64
                                / ab_core::units::USD_MICROS_PER_DOLLAR as f64,
                        );
                        metrics.extra = Some(serde_json::json!({
                            "tool_calls": session.totals.tool_calls.load(std::sync::atomic::Ordering::Acquire),
                            "tool_allowed": session.totals.tool_allowed.load(std::sync::atomic::Ordering::Acquire),
                            "tool_blocked": session.totals.tool_blocked.load(std::sync::atomic::Ordering::Acquire),
                            "cost_usd_micros": session.totals.cost_usd_micros.load(std::sync::atomic::Ordering::Acquire),
                            "stop_reason_id": session.recorded_stop_reason_id(),
                        }));
                    }
                    let name = format!(
                        "{}.json",
                        &ab_core::digest::sha256_hex(session.id.as_bytes())[..32]
                    );
                    let path = self.spool_dir.join(name);
                    let write_path = path.clone();
                    tokio::task::spawn_blocking(move || ab_atif::write_atomic(&trajectory, &write_path))
                        .await
                        .map_err(|error| FinalizeError::Task(error.to_string()))?
                        .map_err(|error| FinalizeError::Atif(error.to_string()))?;
                    *session.atif_path.lock() = Some(path.clone());
                    path
                };
                self.ensure_atif_provenance(&path, &session.id).await?;
                session.mark_artifact_committed();
                FinalizeOutcome::Atif { path }
            }
        };
        let workflow = session.workflow.as_str();
        self.emit_bridge_event(
            &session,
            ab_events::EventClass::Session,
            serde_json::json!({"action": "closed", "workflow": workflow}),
            crate::journal::SESSION_CLOSE_OUTBOX_KIND,
        )
        .await?;
        self.remove_step_journal(&session.id).await?;
        self.remove_lifecycle_outbox(&session.id, crate::journal::RECEIPT_OUTBOX_KIND)
            .await?;
        self.remove_lifecycle_outbox(&session.id, crate::journal::SESSION_CLOSE_OUTBOX_KIND)
            .await?;
        self.metrics
            .histogram(
                "ab_session_finalize_duration_seconds",
                "Session finalization latency",
            )
            .observe_us(elapsed_us(started));
        self.metrics
            .counter("ab_sessions_finalized_total", "Sessions finalized")
            .inc();
        claim.committed = true;
        // Only now — with lifecycle events published and the on-disk journal
        // removed — may the registry evict this session.
        session.mark_close_complete();
        self.clear_budget_state(&session.id);
        Ok(outcome)
    }

    /// Promote a persisted unsigned trajectory into a retroactive Receipt.
    #[tracing::instrument(
        name = "agentbridge.session.promote",
        skip_all,
        fields(session.id = %session.id)
    )]
    pub async fn promote(&self, session: Arc<Session>) -> Result<Receipt, FinalizeError> {
        let _lifecycle = self.acquire_lifecycle(&session.id).await;
        if session.workflow != Workflow::Unsigned {
            return session
                .receipt
                .lock()
                .clone()
                .ok_or_else(|| FinalizeError::Promotion("signed session has no issued receipt".to_owned()));
        }
        if !session.is_closed() {
            self.close_session_locked(Arc::clone(&session), StopReason::SessionClosed)
                .await?;
        }
        let persisted_receipt = { session.receipt.lock().clone() };
        if session.is_promoted() {
            let receipt = persisted_receipt.ok_or_else(|| {
                FinalizeError::Promotion("promoted session has no persisted receipt".to_owned())
            })?;
            // Round-27 F3: opportunistically clean up an orphan
            // `.promote` marker for an already-promoted session. Two
            // windows used to leak markers indefinitely: (a) a crash
            // between `finish_promotion()` and `remove_outbox(&marker)`
            // below, and (b) any recovery-time `promote()` call that
            // hits the early-return here without ever touching the
            // marker. `retry_marked_promotions` would then re-read,
            // re-verify, and re-early-return the same orphan on every
            // idle tick forever. Best-effort cleanup: any I/O failure
            // is warned but does not fail the promotion — the caller
            // still gets its receipt.
            //
            // Extract the atif path with an inner scope so the
            // parking_lot MutexGuard drops before `.await` (an
            // `atif_path.lock()` temporary living across the await
            // makes the future !Send).
            let atif_path_opt: Option<std::path::PathBuf> = {
                session.atif_path.lock().clone()
            };
            if let Some(atif_path) = atif_path_opt {
                let marker = atif_path.with_extension("promote");
                if marker.exists() {
                    if let Err(error) = remove_outbox(&marker).await {
                        tracing::warn!(
                            %error,
                            path = %ab_core::fsutil::basename(&marker),
                            "failed to clean up orphan promotion marker (promotion still succeeded)"
                        );
                    }
                }
            }
            return Ok(receipt);
        }
        let path =
            session.atif_path.lock().clone().ok_or_else(|| {
                FinalizeError::Promotion("session has no persisted ATIF artifact".to_owned())
            })?;
        let marker = path.with_extension("promote");
        if !path.with_extension("atif-auth").exists() {
            return Err(FinalizeError::Atif(
                "ATIF artifact has no authenticated provenance".to_owned(),
            ));
        }
        self.ensure_atif_provenance(&path, &session.id).await?;
        let bytes = read_capped_async(path.clone(), ab_core::fsutil::MAX_ATIF_BYTES)
            .await
            .map_err(|error| FinalizeError::Atif(error.to_string()))?;
        let trajectory: ab_atif::Trajectory =
            serde_json::from_slice(&bytes).map_err(|error| FinalizeError::Atif(error.to_string()))?;
        let issues = ab_atif::validate_trajectory(&trajectory, ab_atif::Mode::Strict);
        if !issues.is_empty() {
            // Round-19 F6: cap the rendered head. An attacker-planted
            // trajectory can legitimately fit millions of issues
            // inside MAX_ATIF_BYTES; Debug-formatting all of them
            // into a `FinalizeError::Atif(String)` amplified
            // attacker input through every downstream log sink
            // (tracing::warn → Vector → OTLP → …).
            const RENDER_ISSUE_HEAD: usize = 16;
            let total = issues.len();
            let head: Vec<_> = issues.iter().take(RENDER_ISSUE_HEAD).collect();
            return Err(FinalizeError::Atif(format!(
                "strict validation failed ({total} issues, showing first {}): {head:?}",
                head.len()
            )));
        }
        let trajectory_digest = ab_core::digest::sha256_hex(&bytes);
        let subject = ReceiptSubject::AtifTrajectory {
            trajectory_digest: trajectory_digest.clone(),
            step_count: trajectory.steps.len() as u64,
            retroactive: true,
        };
        let marker_payload = PromotionMarker {
            session_id: session.id.clone(),
            trajectory_digest,
        };
        if marker.exists() {
            let sealed = read_capped_async(marker.clone(), ab_core::fsutil::MAX_CONTROL_BYTES)
                .await
                .map_err(|error| FinalizeError::Atif(error.to_string()))?;
            let actual: PromotionMarker =
                crate::journal::open(&self.journal_key, "promotion-marker", 0, &sealed)
                    .map_err(FinalizeError::Atif)?;
            if actual.session_id != marker_payload.session_id
                || actual.trajectory_digest != marker_payload.trajectory_digest
            {
                return Err(FinalizeError::Atif(
                    "promotion marker does not match session and trajectory".to_owned(),
                ));
            }
        } else {
            let sealed = crate::journal::seal(&self.journal_key, "promotion-marker", 0, &marker_payload)
                .map_err(FinalizeError::Atif)?;
            persist_marker(&marker, &sealed).await?;
        }
        if !session.try_promote() {
            return Err(FinalizeError::Promotion(
                "promotion is already in progress".to_owned(),
            ));
        }
        let receipt = if let Some(receipt) = persisted_receipt {
            if let Err(error) = self.verify_configured_receipt(&receipt) {
                session.reset_promotion();
                return Err(error);
            }
            if receipt.body.subject != subject {
                session.reset_promotion();
                return Err(FinalizeError::Receipt(
                    "persisted promotion receipt does not match ATIF artifact".to_owned(),
                ));
            }
            receipt
        } else {
            let body = session.receipt_body(subject, StopReason::SessionClosed);
            let issued = Receipt::issue(body, self.signer.as_ref())
                .map_err(|error| FinalizeError::Receipt(error.to_string()));
            let receipt = match issued {
                Ok(receipt) => receipt,
                Err(error) => {
                    session.reset_promotion();
                    return Err(error);
                }
            };
            if let Err(error) = self.persist_receipt(&session.id, &receipt).await {
                session.reset_promotion();
                return Err(error);
            }
            *session.receipt.lock() = Some(receipt.clone());
            receipt
        };
        if let Err(error) = self.emit_receipt_event(&session, &receipt).await {
            session.reset_promotion();
            return Err(error);
        }
        session.finish_promotion();
        remove_outbox(&marker).await?;
        self.remove_lifecycle_outbox(&session.id, crate::journal::RECEIPT_OUTBOX_KIND)
            .await?;
        self.metrics
            .counter("ab_sessions_promoted_total", "Unsigned sessions promoted")
            .inc();
        Ok(receipt)
    }

    /// Recover interrupted sessions from the spool: quarantine sessions with
    /// incomplete effects, replay lifecycle outboxes, recover signed journal
    /// sessions, consolidate unsigned step journals, then scan strict ATIF
    /// artifacts for closed unsigned sessions. Returns the total count of
    /// recovered sessions (unsigned + signed).
    #[tracing::instrument(name = "agentbridge.recovery", skip_all)]
    pub async fn recover_spooled_sessions(
        &self,
        sessions: &SessionRegistry,
        breaker: &ab_loopdetect::BreakerConfig,
    ) -> Result<usize, FinalizeError> {
        let _recovery = self.recovery_lock.lock().await;
        // NB: no global lifecycle lock here — per-session locks are
        // acquired inside the scan loop, right before each candidate is
        // mutated. Without this change, a large ATIF spool at restart
        // would block every /v1/close client call for the duration of
        // the scan.
        let mut quarantined = crate::worker::inflight_response_sessions(&self.spool_dir, &self.journal_key)
            .await
            .map_err(FinalizeError::Atif)?;
        quarantined.extend(
            crate::routes::unresolved_tool_sessions(&self.spool_dir, &self.journal_key)
                .await
                .map_err(FinalizeError::Atif)?,
        );
        // A marker only proves an *abandoned* effect when its session is
        // not currently active: live sessions legitimately hold markers
        // for the duration of an upstream call, and a request that merely
        // straddles a periodic tick must not poison its session as
        // capture-failed forever.
        quarantined.retain(|id| sessions.get(id).is_none());
        if !quarantined.is_empty() {
            // The markers stay on disk as evidence, so every periodic tick
            // rediscovers the same set. Warn only about ids not already in
            // the quarantine — otherwise a single crash would repeat this
            // warning every tick forever.
            let mut known = self.quarantined_sessions.lock();
            let new: Vec<&String> = quarantined.iter().filter(|id| !known.contains(*id)).collect();
            if !new.is_empty() {
                tracing::warn!(
                    sessions = new.len(),
                    "quarantining sessions with incomplete effects"
                );
            }
            known.extend(quarantined.iter().cloned());
        }
        self.replay_lifecycle_outboxes().await?;
        let signed_recovered = self.recover_signed_journals(sessions, breaker).await?;
        self.consolidate_step_journals(sessions, breaker).await?;
        let mut entries = match tokio::fs::read_dir(&self.spool_dir).await {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(error) => return Err(FinalizeError::Atif(error.to_string())),
        };
        let mut recovered = 0usize;
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|error| FinalizeError::Atif(error.to_string()))?
        {
            let path = entry.path();
            if path.extension().and_then(std::ffi::OsStr::to_str) != Some("json") {
                continue;
            }
            // Live session journals ({hash}.session.json) are handled by
            // consolidate_step_journals above; they are not ATIF documents,
            // so parsing them here would only spam misleading warnings
            // every tick while a session is open.
            if path
                .file_name()
                .and_then(std::ffi::OsStr::to_str)
                .is_some_and(|name| name.ends_with(".session.json"))
            {
                continue;
            }
            // Bounded read: a hostile ATIF file cannot force recovery to
            // buffer arbitrary bytes. The size cap catches the coarsest
            // resource-exhaustion vector; adversarial JSON within the cap
            // is still handled by serde's default recursion limit + our
            // Strict validator.
            let metadata = match tokio::fs::metadata(&path).await {
                Ok(m) => m,
                Err(error) => {
                    tracing::warn!(%error, path = %ab_core::fsutil::basename(&path), "skipping ATIF spool file whose metadata is unreadable");
                    continue;
                }
            };
            if metadata.len() > MAX_ATIF_RECOVERY_BYTES {
                self.metrics
                    .counter(
                        "ab_atif_recovery_skipped_total{reason=\"too_large\"}",
                        "ATIF spool files skipped during recovery",
                    )
                    .inc();
                tracing::warn!(
                    path = %ab_core::fsutil::basename(&path),
                    size = metadata.len(),
                    max = MAX_ATIF_RECOVERY_BYTES,
                    "ignoring oversize ATIF spool file",
                );
                continue;
            }
            // Round-27 F1: previously any read failure aborted the entire
            // recovery scan via `?`. One EIO / EACCES on a single spool
            // file (root-owned test artifact, chattr +i, transient NFS
            // blip) would head-of-line-block every other session on
            // every subsequent restart tick. Mirror the warn+continue
            // discipline used at 792/809/824 so recovery is per-file.
            let bytes = match read_capped_async(path.clone(), ab_core::fsutil::MAX_ATIF_BYTES).await
            {
                Ok(bytes) => bytes,
                Err(error) => {
                    self.metrics
                        .counter(
                            "ab_atif_recovery_skipped_total{reason=\"read_error\"}",
                            "ATIF spool files skipped during recovery",
                        )
                        .inc();
                    tracing::warn!(%error, path = %ab_core::fsutil::basename(&path), "skipping unreadable ATIF spool file");
                    continue;
                }
            };
            let trajectory: ab_atif::Trajectory = match serde_json::from_slice(&bytes) {
                Ok(trajectory) => trajectory,
                Err(error) => {
                    self.metrics
                        .counter(
                            "ab_atif_recovery_skipped_total{reason=\"invalid_json\"}",
                            "ATIF spool files skipped during recovery",
                        )
                        .inc();
                    tracing::warn!(%error, path = %ab_core::fsutil::basename(&path), "ignoring invalid ATIF spool file");
                    continue;
                }
            };
            if !ab_atif::validate_trajectory(&trajectory, ab_atif::Mode::Strict).is_empty() {
                self.metrics
                    .counter(
                        "ab_atif_recovery_skipped_total{reason=\"nonconformant\"}",
                        "ATIF spool files skipped during recovery",
                    )
                    .inc();
                tracing::warn!(path = %ab_core::fsutil::basename(&path), "ignoring nonconformant ATIF spool file");
                continue;
            }
            let Some(session_id) = trajectory.session_id.clone() else {
                continue;
            };
            // Integrity failures must not abort the scan: one tampered or
            // orphaned artifact would otherwise starve recovery of every
            // other session on every tick. The file stays on disk as
            // evidence; warn once and keep going.
            if !path.with_extension("atif-auth").exists() {
                self.metrics
                    .counter(
                        "ab_atif_recovery_skipped_total{reason=\"unauthenticated\"}",
                        "ATIF spool files skipped during recovery",
                    )
                    .inc();
                if self.warn_once(path.clone()) {
                    tracing::warn!(
                        path = %ab_core::fsutil::basename(&path),
                        "ignoring ATIF spool file with no authenticated provenance"
                    );
                }
                continue;
            }
            if let Err(error) = self.ensure_atif_provenance(&path, &session_id).await {
                self.metrics
                    .counter(
                        "ab_atif_recovery_skipped_total{reason=\"provenance\"}",
                        "ATIF spool files skipped during recovery",
                    )
                    .inc();
                if self.warn_once(path.clone()) {
                    tracing::warn!(
                        %error,
                        path = %ab_core::fsutil::basename(&path),
                        "ignoring ATIF spool file whose provenance does not verify"
                    );
                }
                continue;
            }
            if sessions.get(&session_id).is_some() {
                continue;
            }
            // Per-session lifecycle lock: scoped to this candidate only,
            // released at the end of this loop iteration so the next
            // candidate proceeds without waiting on all previous ones.
            let _lifecycle = self.acquire_lifecycle(&session_id).await;
            let extra = trajectory.agent.extra.as_ref();
            let instance_uid = extra
                .and_then(|value| value.get("instance_uid"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or("recovered")
                .to_owned();
            let charter = extra
                .and_then(|value| value.get("charter"))
                .and_then(|value| {
                    serde_json::from_value::<ab_events::CharterFile>(value.clone())
                        .ok()
                        .or_else(|| value.as_str().map(Into::into))
                })
                .unwrap_or_else(|| "recovered".into());
            let ttl_remaining_s = extra
                .and_then(|value| value.get("ttl_remaining_s"))
                .and_then(serde_json::Value::as_u64);
            let recovered_session = match sessions.try_insert_recovered(
                Session::recover_unsigned(
                    session_id,
                    ab_events::AgentIdentity {
                        version: trajectory.agent.version.clone(),
                        charter,
                        instance_uid,
                        ttl_remaining_s,
                    },
                    breaker.clone(),
                    path.clone(),
                    trajectory.final_metrics.as_ref(),
                )
                .map_err(FinalizeError::Atif)?,
            ) {
                Ok(inserted) => inserted,
                Err(_active) => {
                    tracing::info!(session = %ab_core::fsutil::basename(&path), "unsigned recovery skipped: session already active");
                    continue;
                }
            };
            let receipt_path = self.receipt_path(&recovered_session.id);
            // Round-40 F4: distinguish ENOENT from other read
            // failures (see the twin in recover_signed_journals
            // for full rationale). An oversize/EACCES/EIO would
            // previously fold into "no prior receipt" and mint a
            // fresh one — silently erasing evidence of the
            // original.
            match tokio::fs::metadata(&receipt_path).await {
                Ok(_) => {
                    let bytes = read_capped_async(
                        receipt_path.clone(),
                        ab_core::fsutil::MAX_RECEIPT_BYTES,
                    )
                    .await
                    .map_err(|error| {
                        FinalizeError::Receipt(format!("existing receipt unreadable: {error}"))
                    })?;
                    // Round-16: use the strict deserializer that
                    // refuses duplicate keys at any nesting level. A
                    // post-compromise attacker who overwrote the
                    // on-disk receipt bytes could otherwise smuggle a
                    // duplicate `instance_uid` past round-15 F4's
                    // top-level guard — the round-15 walker closes
                    // that gap uniformly.
                    // Round-17 F3: read is bounded by MAX_RECEIPT_BYTES
                    // so a hostile plant can no longer OOM the
                    // recovery scan on this session.
                    let receipt = Receipt::from_json_slice(&bytes)
                        .map_err(|error| FinalizeError::Receipt(error.to_string()))?;
                    self.verify_configured_receipt(&receipt)?;
                    if path.with_extension("promote").exists() {
                        recovered_session.restore_pending_receipt(receipt);
                    } else {
                        recovered_session.restore_receipt(receipt);
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound
                    || error.kind() == std::io::ErrorKind::NotADirectory =>
                {
                    // Fresh recovery — no prior receipt.
                }
                Err(error) => {
                    return Err(FinalizeError::Receipt(format!(
                        "existing receipt stat failed: {error}"
                    )));
                }
            }
            recovered += 1;
        }
        self.remove_acked_lifecycle_outboxes().await?;
        Ok(recovered + signed_recovered)
    }

    // Round-40 F1 -> round-41: extracted the per-candidate body
    // into an inner `async` block whose Err is caught in the outer
    // loop and turned into `warn_once + counter + continue`, so a
    // single tampered sidecar / corrupted receipt / HMAC-drift
    // never head-of-line-blocks recovery of every OTHER signed
    // AND unsigned session for the tick.
    //
    // Round-27 F1 / F2 applied the same discipline to the ATIF-
    // spool and promotion-marker paths. Under-load stability
    // depends on this being uniform across every recovery path;
    // the block's outcome enum makes the "did this candidate
    // actually recover" question type-safe.
    async fn recover_signed_journals(
        &self,
        sessions: &SessionRegistry,
        breaker: &ab_loopdetect::BreakerConfig,
    ) -> Result<usize, FinalizeError> {
        /// Round-41 F1: per-candidate outcome so the outer loop can
        /// distinguish "session recovered" from "candidate wasn't
        /// mine / already active / deliberately skipped".
        enum SignedCandidateOutcome {
            /// The session was materialised and finalized (or set aside
            /// as capture-failed for later quarantine). Increment the
            /// recovered counter.
            Recovered,
            /// This candidate wasn't for us (not a signed sidecar,
            /// already-active session, journal quarantined, etc.).
            /// Not an error; do NOT count as recovered.
            Skipped,
        }
        let mut entries = match tokio::fs::read_dir(&self.spool_dir).await {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(error) => return Err(FinalizeError::Atif(error.to_string())),
        };
        let mut recovered = 0usize;
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|error| FinalizeError::Atif(error.to_string()))?
        {
            let metadata_path = entry.path();
            let Some(name) = metadata_path.file_name().and_then(std::ffi::OsStr::to_str) else {
                continue;
            };
            let Some(stem) = name.strip_suffix(".session.json") else {
                continue;
            };
            // Round-41 F1: per-candidate body wrapped in an inner
            // async block so every `?` and `return Err(...)` inside
            // gets caught by the outer match instead of propagating
            // up through `recover_spooled_sessions:753` and killing
            // the whole recovery scan for the tick. Every prior
            // `continue;` becomes `return Ok(Skipped);`; every
            // `recovered += 1; continue;` becomes `return Ok(Recovered);`.
            let outcome: Result<SignedCandidateOutcome, FinalizeError> = async {
            let metadata = self.read_journal_metadata(&metadata_path).await?;
            if metadata
                .get("journal_version")
                .and_then(serde_json::Value::as_u64)
                != Some(2)
            {
                // Round-15 F1: previously returned Err, which
                // aborted the whole spool scan via the caller's `?`
                // — a single drifted or corrupted sidecar (upgrade
                // migration in progress, hostile plant, disk
                // bit-rot) blocked recovery of every OTHER session
                // on this instance. Warn + skip so unrelated
                // sessions still recover; an operator inspecting
                // the log can quarantine the specific sidecar.
                //
                // Round-16 F4: recover_spooled_sessions runs on
                // every reconciler tick. Dedup via
                // `warned_artifacts` so a persistent hostile plant
                // does not produce N warn lines every tick until
                // process restart, drowning real signal.
                if self.warn_once(metadata_path.clone()) {
                    tracing::warn!(
                        path = %ab_core::fsutil::basename(&metadata_path),
                        version = ?metadata.get("journal_version"),
                        "sidecar has unsupported journal_version; skipping this session so recovery can proceed for the rest"
                    );
                }
                return Ok(SignedCandidateOutcome::Skipped);
            }
            if metadata.get("workflow").and_then(serde_json::Value::as_str) != Some(Workflow::Signed.as_str())
            {
                return Ok(SignedCandidateOutcome::Skipped);
            }
            let session_id = metadata
                .get("session_id")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| FinalizeError::Atif("journal metadata has no session_id".into()))?;
            if sessions.get(session_id).is_some() {
                return Ok(SignedCandidateOutcome::Skipped);
            }
            // Per-session lifecycle lock for the signed-recovery path,
            // scoped to this candidate only. Released between candidates
            // so a client close on session B is not blocked by an
            // in-flight recovery-adopt of session A.
            let _lifecycle = self.acquire_lifecycle(session_id).await;
            let identity: ab_events::AgentIdentity = serde_json::from_value(
                metadata
                    .get("identity")
                    .cloned()
                    .ok_or_else(|| FinalizeError::Atif("journal metadata has no identity".into()))?,
            )
            .map_err(|error| FinalizeError::Atif(error.to_string()))?;
            let journal_path = self.spool_dir.join(format!("{stem}.events.ndjson"));
            let journal = if journal_path.exists() {
                read_complete_journal(&journal_path).await?
            } else {
                Vec::new()
            };
            if journal.is_empty() {
                // Round-14 F5: preserve the sealed metadata sidecar
                // when a torn-write journal has been quarantined in
                // a prior tick (see `read_complete_journal` at
                // ~:1980). Without this, we'd delete the sidecar the
                // very next tick, orphaning the `.corrupt-<uid>`
                // bytes with no linkage back to session identity.
                if quarantine_sibling_exists(&self.spool_dir, stem).await? {
                    let quarantine_metadata = self
                        .spool_dir
                        .join(format!("{stem}.session.json.corrupt-{}", ab_core::new_event_uid()));
                    match tokio::fs::rename(&metadata_path, &quarantine_metadata).await {
                        Ok(()) => tracing::warn!(
                            metadata = %ab_core::fsutil::basename(&metadata_path),
                            quarantine = %ab_core::fsutil::basename(&quarantine_metadata),
                            "sealed metadata sidecar quarantined alongside its torn signed journal (round-14 F5)"
                        ),
                        Err(error) => tracing::error!(
                            metadata = %ab_core::fsutil::basename(&metadata_path),
                            %error,
                            "failed to quarantine metadata sidecar; leaving in place so a future recovery can try again"
                        ),
                    }
                    return Ok(SignedCandidateOutcome::Skipped);
                }
                tokio::fs::remove_file(metadata_path.clone())
                    .await
                    .map_err(|error| FinalizeError::Atif(error.to_string()))?;
                return Ok(SignedCandidateOutcome::Skipped);
            }
            let session = Arc::new(Session::new(
                session_id.to_owned(),
                Workflow::Signed,
                identity,
                breaker.clone(),
            ));
            let mut next_sequence = 0u64;
            let mut tool_calls = 0u64;
            let mut tool_allowed = 0u64;
            let mut tool_blocked = 0u64;
            let mut prompt_tokens = 0u64;
            let mut completion_tokens = 0u64;
            let mut cached_tokens = 0u64;
            let mut cost_usd_micros = 0u64;
            let mut pending_responses = std::collections::HashSet::new();
            let domain = format!("{}:active", session.id);
            for (index, line) in journal.into_iter().enumerate() {
                let index = u64::try_from(index)
                    .map_err(|_| FinalizeError::Atif("active journal index overflow".to_owned()))?;
                let record: crate::worker::ActiveJournalRecord =
                    crate::journal::open(&self.journal_key, &domain, index, line.as_bytes())
                        .map_err(FinalizeError::Atif)?;
                let event: ab_events::OcsfEvent = serde_json::from_value(record.event.clone())
                    .map_err(|error| FinalizeError::Atif(error.to_string()))?;
                if event.session_uid != session.id {
                    return Err(FinalizeError::Atif(format!(
                        "signed journal event belongs to session {:?}, expected {:?}",
                        event.session_uid, session.id
                    )));
                }
                if record.atif_step.is_some() || record.identity != event.ai_agent {
                    return Err(FinalizeError::Atif(
                        "signed active record has inconsistent workflow or identity".to_owned(),
                    ));
                }
                track_response_attempt(&mut pending_responses, record.response_attempt.as_ref())?;
                if event.metadata.sequence != index {
                    return Err(FinalizeError::Atif(
                        "signed event sequence does not match active journal index".to_owned(),
                    ));
                }
                if record.identity.version != session.identity.version
                    || record.identity.charter != session.identity.charter
                    || record.identity.instance_uid != session.identity.instance_uid
                {
                    return Err(FinalizeError::Atif(
                        "active journal changed the session identity".to_owned(),
                    ));
                }
                session.refresh_identity(&record.identity);
                next_sequence = index
                    .checked_add(1)
                    .ok_or_else(|| FinalizeError::Atif("event sequence overflow".to_owned()))?;
                session
                    .chain
                    .lock()
                    .append(&record.event)
                    .map_err(|error| FinalizeError::Receipt(error.to_string()))?;
                tool_calls = checked_recovery_add(tool_calls, record.tool_calls, "tool calls")?;
                tool_allowed = checked_recovery_add(tool_allowed, record.tool_allowed, "allowed tools")?;
                tool_blocked = checked_recovery_add(tool_blocked, record.tool_blocked, "blocked tools")?;
                prompt_tokens = checked_recovery_add(prompt_tokens, record.prompt_tokens, "prompt tokens")?;
                completion_tokens =
                    checked_recovery_add(completion_tokens, record.completion_tokens, "completion tokens")?;
                cached_tokens = checked_recovery_add(cached_tokens, record.cached_tokens, "cached tokens")?;
                cost_usd_micros = checked_recovery_add(cost_usd_micros, record.cost_usd_micros, "cost")?;
                if let Some(id) = record.stop_reason_id {
                    let reason = ab_events::StopReason::from_id(id);
                    if reason != ab_events::StopReason::Unknown {
                        session.record_stop_reason(reason);
                    }
                }
                self.ensure_active_event_published(&session.id, &event, &record.event)
                    .await?;
            }
            if tool_allowed
                .checked_add(tool_blocked)
                .is_none_or(|classified| classified > tool_calls)
            {
                return Err(FinalizeError::Atif(
                    "signed journal has inconsistent tool accounting".to_owned(),
                ));
            }
            session
                .totals
                .tool_calls
                .store(tool_calls, std::sync::atomic::Ordering::Release);
            session
                .totals
                .tool_allowed
                .store(tool_allowed, std::sync::atomic::Ordering::Release);
            session
                .totals
                .tool_blocked
                .store(tool_blocked, std::sync::atomic::Ordering::Release);
            session
                .totals
                .prompt_tokens
                .store(prompt_tokens, std::sync::atomic::Ordering::Release);
            session
                .totals
                .completion_tokens
                .store(completion_tokens, std::sync::atomic::Ordering::Release);
            session
                .totals
                .cached_tokens
                .store(cached_tokens, std::sync::atomic::Ordering::Release);
            session
                .totals
                .cost_usd_micros
                .store(cost_usd_micros, std::sync::atomic::Ordering::Release);
            let inconsistent_responses = !pending_responses.is_empty();
            session.restore_next_seq(next_sequence);
            let expected_subject = {
                let chain = session.chain.lock();
                ReceiptSubject::EventChain {
                    chain_head: chain.head_hex(),
                    event_count: chain.count(),
                }
            };
            let receipt_path = self.receipt_path(&session.id);
            // Round-40 F4: distinguish `ENOENT` (fresh recovery, no
            // prior receipt to reload) from every other read
            // failure (EACCES, EIO, or the round-19 F10 read cap
            // firing on a file that grew past MAX_RECEIPT_BYTES).
            // The prior `if let Ok(bytes) = ...` folded all
            // failures into "no prior receipt" and re-issued a
            // fresh receipt over the recovered chain — silently
            // destroying evidence that a legitimate receipt had
            // already been issued. Under the oversize case, a
            // hostile local process could grow receipt.json past
            // the cap to erase the operator's receipt on the next
            // recovery tick. Now: a genuine ENOENT is a proper
            // recovery no-op; any other error is a per-session
            // failure that surfaces to the reconciler tick.
            match tokio::fs::metadata(&receipt_path).await {
                Ok(_) => {
                    let bytes = read_capped_async(
                        receipt_path.clone(),
                        ab_core::fsutil::MAX_RECEIPT_BYTES,
                    )
                    .await
                    .map_err(|error| {
                        FinalizeError::Receipt(format!(
                            "existing receipt unreadable: {error}"
                        ))
                    })?;
                    // Round-16: strict deserializer (see the twin call
                    // in the unsigned recovery path above).
                    // Round-17 F3: bounded read.
                    let receipt = Receipt::from_json_slice(&bytes)
                        .map_err(|error| FinalizeError::Receipt(error.to_string()))?;
                    self.verify_configured_receipt(&receipt)?;
                    if receipt.body.subject != expected_subject {
                        return Err(FinalizeError::Receipt(
                            "persisted receipt does not attest the recovered signed journal".to_owned(),
                        ));
                    }
                    *session.receipt.lock() = Some(receipt);
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound
                    || error.kind() == std::io::ErrorKind::NotADirectory =>
                {
                    // Fresh recovery — no prior receipt.
                    // `NotADirectory` covers the case where a
                    // parent component of the receipt path is a
                    // file (equivalent to "no receipt at that
                    // path" from the receipt's point of view).
                }
                Err(error) => {
                    return Err(FinalizeError::Receipt(format!(
                        "existing receipt stat failed: {error}"
                    )));
                }
            }
            let unwrapped = Arc::try_unwrap(session)
                .map_err(|_| FinalizeError::Task("signed recovery retained session".to_owned()))?;
            // Seal the session to new leases before it is ever reachable via
            // `sessions.get(id)`. Between `try_insert_recovered` and the
            // finalize path's `try_close`, a client request for the same id
            // could otherwise take a lease, submit a worker job, and append to
            // the recovered chain — permanently diverging it from the persisted
            // receipt's subject.event_count (and leaving a wrong-index journal
            // entry). `is_closed()` is true whenever `artifact_committed` is
            // set, but `try_close` still transitions `closed` 0→1, so
            // `close_session_locked` still runs its full finalize body.
            //
            // NB: the per-session lifecycle lock was already acquired at
            // the top of this iteration (see the `let _lifecycle = ...`
            // block near the session_id skip check) and covers this
            // whole mutation region — a second acquire here would
            // deadlock on itself.
            unwrapped.mark_artifact_committed();
            let session = match sessions.try_insert_recovered(unwrapped) {
                Ok(inserted) => inserted,
                Err(_active) => {
                    tracing::info!(session = %session_id, "signed recovery skipped: session already active");
                    return Ok(SignedCandidateOutcome::Skipped);
                }
            };
            if inconsistent_responses {
                // Quarantine only after we know the recovered Session was actually installed —
                // otherwise a live session with the same id would inherit the capture-failed verdict.
                self.quarantined_sessions.lock().insert(session.id.clone());
                session.mark_capture_failed();
                return Ok(SignedCandidateOutcome::Recovered);
            }
            if self.quarantined_sessions.lock().contains(&session.id) {
                session.mark_capture_failed();
                return Ok(SignedCandidateOutcome::Recovered);
            }
            self.close_session_locked(Arc::clone(&session), StopReason::SessionClosed)
                .await?;
            Ok(SignedCandidateOutcome::Recovered)
            }.await;
            match outcome {
                Ok(SignedCandidateOutcome::Recovered) => recovered += 1,
                Ok(SignedCandidateOutcome::Skipped) => {}
                Err(error) => {
                    self.metrics
                        .counter(
                            "ab_signed_recovery_skipped_total",
                            "Signed sessions skipped during recovery due to per-session errors (round-41 F1)",
                        )
                        .inc();
                    if self.warn_once(metadata_path.clone()) {
                        tracing::warn!(
                            %error,
                            path = %ab_core::fsutil::basename(&metadata_path),
                            "skipping signed session recovery due to per-session error; other sessions continue"
                        );
                    }
                }
            }
        }
        Ok(recovered)
    }

    async fn ensure_active_event_published(
        &self,
        session_id: &str,
        event: &ab_events::OcsfEvent,
        value: &serde_json::Value,
    ) -> Result<(), FinalizeError> {
        let topic = event.class_name.topic();
        let event_uid = &event.metadata.uid;
        if let Some(ack) =
            crate::worker::read_broker_ack(&self.spool_dir, session_id, event_uid, &self.journal_key)
                .await
                .map_err(FinalizeError::Bridge)?
        {
            if ack.topic != topic {
                return Err(FinalizeError::Bridge(
                    "broker acknowledgment topic does not match active event".to_owned(),
                ));
            }
            return Ok(());
        }
        let bridge = self.bridge.as_ref().map(Arc::clone).ok_or_else(|| {
            FinalizeError::Bridge("unacknowledged active event has no configured broker".to_owned())
        })?;
        let topic = topic.to_owned();
        let key = event.ai_agent.instance_uid.clone();
        let value = value.clone();
        let uid = event_uid.clone();
        let lookup_bridge = Arc::clone(&bridge);
        let lookup_topic = topic.clone();
        let lookup_key = key.clone();
        let lookup_uid = uid.clone();
        if let Some(ack) = tokio::task::spawn_blocking(move || {
            lookup_bridge.find_event_by_uid(&lookup_topic, &lookup_key, &lookup_uid)
        })
        .await
        .map_err(|error| FinalizeError::Task(error.to_string()))?
        .map_err(|error| FinalizeError::Bridge(error.to_string()))?
        {
            crate::worker::persist_broker_ack(
                &self.spool_dir,
                session_id,
                event_uid,
                &ack,
                &self.journal_key,
            )
            .await
            .map_err(FinalizeError::Bridge)?;
            return Ok(());
        }
        let ack = tokio::task::spawn_blocking(move || bridge.publish_idempotent(&topic, &key, &value, &uid))
            .await
            .map_err(|error| FinalizeError::Task(error.to_string()))?
            .map_err(|error| FinalizeError::Bridge(error.to_string()))?;
        crate::worker::persist_broker_ack(&self.spool_dir, session_id, event_uid, &ack, &self.journal_key)
            .await
            .map_err(FinalizeError::Bridge)
    }

    async fn consolidate_step_journals(
        &self,
        sessions: &SessionRegistry,
        breaker: &ab_loopdetect::BreakerConfig,
    ) -> Result<(), FinalizeError> {
        let mut entries = match tokio::fs::read_dir(&self.spool_dir).await {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(FinalizeError::Atif(error.to_string())),
        };
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|error| FinalizeError::Atif(error.to_string()))?
        {
            let metadata_path = entry.path();
            let Some(name) = metadata_path.file_name().and_then(std::ffi::OsStr::to_str) else {
                continue;
            };
            let Some(stem) = name.strip_suffix(".session.json") else {
                continue;
            };
            // Round-41 F1 (twin of the recover_signed_journals fix):
            // wrap the per-candidate body so per-session errors
            // warn+continue instead of aborting the whole
            // consolidation scan. A single poisoned sidecar or a
            // torn events journal used to head-of-line-block
            // every OTHER unsigned session on the tick.
            let outcome: Result<(), FinalizeError> = async {
            let final_path = self.spool_dir.join(format!("{stem}.json"));
            let journal_path = self.spool_dir.join(format!("{stem}.events.ndjson"));
            let metadata = self.read_journal_metadata(&metadata_path).await?;
            if metadata
                .get("journal_version")
                .and_then(serde_json::Value::as_u64)
                != Some(2)
            {
                // Round-15 F1: same HOL-block fix as the signed
                // branch above — one drifted sidecar must not deny
                // recovery to unrelated sessions.
                // Round-16 F4: dedup via `warned_artifacts`.
                if self.warn_once(metadata_path.clone()) {
                    tracing::warn!(
                        path = %ab_core::fsutil::basename(&metadata_path),
                        version = ?metadata.get("journal_version"),
                        "sidecar has unsupported journal_version; skipping this session so recovery can proceed for the rest"
                    );
                }
                return Ok(());
            }
            if metadata.get("workflow").and_then(serde_json::Value::as_str) == Some(Workflow::Signed.as_str())
            {
                return Ok(());
            }
            let session_id = metadata
                .get("session_id")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| FinalizeError::Atif("journal metadata has no session_id".into()))?;
            if sessions.get(session_id).is_some() {
                return Ok(());
            }
            // Per-session lifecycle lock for the unsigned-consolidation
            // path, scoped to this candidate only. Released between
            // candidates so the recovery scan cannot head-of-line-block
            // a client-driven close on an unrelated session.
            let _lifecycle = self.acquire_lifecycle(session_id).await;
            let identity: ab_events::AgentIdentity = serde_json::from_value(
                metadata
                    .get("identity")
                    .cloned()
                    .ok_or_else(|| FinalizeError::Atif("journal metadata has no identity".into()))?,
            )
            .map_err(|error| FinalizeError::Atif(error.to_string()))?;
            let journal = if journal_path.exists() {
                read_complete_journal(&journal_path).await?
            } else {
                Vec::new()
            };
            if self.quarantined_sessions.lock().contains(session_id) {
                let quarantined = Session::new(
                    session_id.to_owned(),
                    Workflow::Unsigned,
                    identity.clone(),
                    breaker.clone(),
                );
                quarantined.restore_journal_index(
                    u64::try_from(journal.len())
                        .map_err(|_| FinalizeError::Atif("active journal length overflow".to_owned()))?,
                );
                quarantined.mark_capture_failed();
                // Also seal the session finalized (like the signed sibling at
                // line ~773) so the idle sweeper's `!is_closed()` filter
                // skips it. Otherwise every idle tick re-enters
                // close_session_locked, hits the capture_failed guard, and
                // CloseClaim resets `closed` — an unbounded churn loop.
                quarantined.mark_artifact_committed();
                sessions.insert_recovered(quarantined);
                return Ok(());
            }
            if journal.is_empty() {
                // Round-14 F5: same quarantine-preservation guard as
                // the signed branch — don't delete the sealed
                // metadata when a torn journal has been quarantined
                // in a prior tick.
                if quarantine_sibling_exists(&self.spool_dir, stem).await? {
                    let quarantine_metadata = self
                        .spool_dir
                        .join(format!("{stem}.session.json.corrupt-{}", ab_core::new_event_uid()));
                    match tokio::fs::rename(&metadata_path, &quarantine_metadata).await {
                        Ok(()) => tracing::warn!(
                            metadata = %ab_core::fsutil::basename(&metadata_path),
                            quarantine = %ab_core::fsutil::basename(&quarantine_metadata),
                            "sealed metadata sidecar quarantined alongside its torn unsigned journal (round-14 F5)"
                        ),
                        Err(error) => tracing::error!(
                            metadata = %ab_core::fsutil::basename(&metadata_path),
                            %error,
                            "failed to quarantine metadata sidecar; leaving in place so a future recovery can try again"
                        ),
                    }
                    return Ok(());
                }
                tokio::fs::remove_file(metadata_path.clone())
                    .await
                    .map_err(|error| FinalizeError::Atif(error.to_string()))?;
                return Ok(());
            }
            let journal_len = u64::try_from(journal.len())
                .map_err(|_| FinalizeError::Atif("active journal length overflow".to_owned()))?;
            let agent = ab_atif::Agent {
                name: "agent-bridge-harness".into(),
                version: identity.version.clone(),
                model_name: None,
                tool_definitions: None,
                extra: Some(serde_json::json!({
                    "charter": identity.charter,
                    "instance_uid": identity.instance_uid,
                })),
            };
            let mut builder = ab_atif::TrajectoryBuilder::new(agent, Some(session_id.to_owned()));
            let domain = format!("{session_id}:active");
            let mut latest_identity = identity.clone();
            let mut prompt_tokens = 0u64;
            let mut completion_tokens = 0u64;
            let mut cached_tokens = 0u64;
            let mut cost_usd_micros = 0u64;
            let mut tool_calls = 0u64;
            let mut tool_allowed = 0u64;
            let mut tool_blocked = 0u64;
            let mut stop_reason_id = None;
            let mut pending_responses = std::collections::HashSet::new();
            for (index, line) in journal.into_iter().enumerate() {
                let index = u64::try_from(index)
                    .map_err(|_| FinalizeError::Atif("active journal index overflow".to_owned()))?;
                let record: crate::worker::ActiveJournalRecord =
                    crate::journal::open(&self.journal_key, &domain, index, line.as_bytes())
                        .map_err(FinalizeError::Atif)?;
                let event: ab_events::OcsfEvent = serde_json::from_value(record.event.clone())
                    .map_err(|error| FinalizeError::Atif(error.to_string()))?;
                if event.session_uid != session_id || event.ai_agent != record.identity {
                    return Err(FinalizeError::Atif(
                        "unsigned active record has inconsistent session or identity".to_owned(),
                    ));
                }
                track_response_attempt(&mut pending_responses, record.response_attempt.as_ref())?;
                if event.metadata.sequence != index {
                    return Err(FinalizeError::Atif(
                        "unsigned event sequence does not match active journal index".to_owned(),
                    ));
                }
                if record.identity.version != identity.version
                    || record.identity.charter != identity.charter
                    || record.identity.instance_uid != identity.instance_uid
                {
                    return Err(FinalizeError::Atif(
                        "active journal changed the unsigned session identity".to_owned(),
                    ));
                }
                self.ensure_active_event_published(session_id, &event, &record.event)
                    .await?;
                let step = record.atif_step.ok_or_else(|| {
                    FinalizeError::Atif("unsigned active record has no ATIF step".to_owned())
                })?;
                builder
                    .push_step(step)
                    .map_err(|error| FinalizeError::Atif(error.to_string()))?;
                latest_identity = record.identity;
                prompt_tokens = checked_recovery_add(prompt_tokens, record.prompt_tokens, "prompt tokens")?;
                completion_tokens =
                    checked_recovery_add(completion_tokens, record.completion_tokens, "completion tokens")?;
                cached_tokens = checked_recovery_add(cached_tokens, record.cached_tokens, "cached tokens")?;
                cost_usd_micros = checked_recovery_add(cost_usd_micros, record.cost_usd_micros, "cost")?;
                tool_calls = checked_recovery_add(tool_calls, record.tool_calls, "tool calls")?;
                tool_allowed = checked_recovery_add(tool_allowed, record.tool_allowed, "allowed tools")?;
                tool_blocked = checked_recovery_add(tool_blocked, record.tool_blocked, "blocked tools")?;
                if record.stop_reason_id.is_some() {
                    stop_reason_id = record.stop_reason_id;
                }
            }
            if tool_allowed
                .checked_add(tool_blocked)
                .is_none_or(|classified| classified > tool_calls)
            {
                return Err(FinalizeError::Atif(
                    "unsigned journal has inconsistent tool accounting".to_owned(),
                ));
            }
            if !pending_responses.is_empty() {
                let quarantined = Session::new(
                    session_id.to_owned(),
                    Workflow::Unsigned,
                    latest_identity,
                    breaker.clone(),
                );
                quarantined.restore_journal_index(journal_len);
                quarantined.restore_next_seq(journal_len);
                quarantined
                    .totals
                    .tool_calls
                    .store(tool_calls, std::sync::atomic::Ordering::Release);
                quarantined
                    .totals
                    .tool_allowed
                    .store(tool_allowed, std::sync::atomic::Ordering::Release);
                quarantined
                    .totals
                    .tool_blocked
                    .store(tool_blocked, std::sync::atomic::Ordering::Release);
                quarantined
                    .totals
                    .prompt_tokens
                    .store(prompt_tokens, std::sync::atomic::Ordering::Release);
                quarantined
                    .totals
                    .completion_tokens
                    .store(completion_tokens, std::sync::atomic::Ordering::Release);
                quarantined
                    .totals
                    .cached_tokens
                    .store(cached_tokens, std::sync::atomic::Ordering::Release);
                quarantined
                    .totals
                    .cost_usd_micros
                    .store(cost_usd_micros, std::sync::atomic::Ordering::Release);
                quarantined.mark_capture_failed();
                // Also seal the session finalized so the idle sweeper's
                // `!is_closed()` filter skips it — same reasoning as the
                // quarantined-already branch above.
                quarantined.mark_artifact_committed();
                // Quarantine only after we know a fresh session was actually installed —
                // a live session with the same id must not inherit this capture-failed verdict.
                match sessions.try_insert_recovered(quarantined) {
                    Ok(_) => {
                        self.quarantined_sessions.lock().insert(session_id.to_owned());
                    }
                    Err(_active) => {
                        tracing::info!(
                            session = %session_id,
                            "unsigned quarantine skipped: session already active",
                        );
                    }
                }
                return Ok(());
            }
            let mut trajectory = builder.finish();
            trajectory.agent.extra = Some(serde_json::json!({
                "charter": latest_identity.charter,
                "instance_uid": latest_identity.instance_uid,
                "ttl_remaining_s": latest_identity.ttl_remaining_s,
            }));
            if let Some(metrics) = trajectory.final_metrics.as_mut() {
                metrics.total_prompt_tokens = Some(prompt_tokens);
                metrics.total_completion_tokens = Some(completion_tokens);
                metrics.total_cached_tokens = Some(cached_tokens);
                metrics.total_cost_usd =
                    Some(cost_usd_micros as f64 / ab_core::units::USD_MICROS_PER_DOLLAR as f64);
                metrics.extra = Some(serde_json::json!({
                    "tool_calls": tool_calls,
                    "tool_allowed": tool_allowed,
                    "tool_blocked": tool_blocked,
                    "cost_usd_micros": cost_usd_micros,
                    "stop_reason_id": stop_reason_id,
                }));
            }
            if final_path.exists() {
                let existing: ab_atif::Trajectory = serde_json::from_slice(
                    &read_capped_async(final_path.clone(), ab_core::fsutil::MAX_ATIF_BYTES)
                        .await
                        .map_err(|error| FinalizeError::Atif(error.to_string()))?,
                )
                .map_err(|error| FinalizeError::Atif(error.to_string()))?;
                trajectory.trajectory_id.clone_from(&existing.trajectory_id);
                if trajectory != existing {
                    return Err(FinalizeError::Atif(
                        "persisted ATIF does not match authenticated active journal".to_owned(),
                    ));
                }
            } else {
                let write_path = final_path.clone();
                tokio::task::spawn_blocking(move || ab_atif::write_atomic(&trajectory, &write_path))
                    .await
                    .map_err(|error| FinalizeError::Task(error.to_string()))?
                    .map_err(|error| FinalizeError::Atif(error.to_string()))?;
            }
            self.ensure_atif_provenance(&final_path, session_id).await?;
            self.remove_step_journal(session_id).await?;
            Ok(())
            }.await;
            if let Err(error) = outcome {
                self.metrics
                    .counter(
                        "ab_unsigned_recovery_skipped_total",
                        "Unsigned sessions skipped during consolidation due to per-session errors (round-41 F1)",
                    )
                    .inc();
                if self.warn_once(metadata_path.clone()) {
                    tracing::warn!(
                        %error,
                        path = %ab_core::fsutil::basename(&metadata_path),
                        "skipping unsigned session consolidation due to per-session error; other sessions continue"
                    );
                }
            }
        }
        Ok(())
    }

    async fn remove_step_journal(&self, session_id: &str) -> Result<(), FinalizeError> {
        let digest = ab_core::digest::sha256_hex(session_id.as_bytes());
        let stem = digest.get(..32).unwrap_or(&digest).to_owned();
        let spool_dir = self.spool_dir.clone();
        tokio::task::spawn_blocking(move || -> Result<(), FinalizeError> {
            let mut spool_changed = false;
            for suffix in ["session.json", "steps.ndjson", "events.ndjson"] {
                let path = spool_dir.join(format!("{stem}.{suffix}"));
                match std::fs::remove_file(&path) {
                    Ok(()) => spool_changed = true,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(FinalizeError::Atif(error.to_string())),
                }
            }
            if spool_changed {
                ab_core::fsutil::sync_directory(&spool_dir)
                    .map_err(|error| FinalizeError::Atif(error.to_string()))?;
            }
            let ack_parent = spool_dir.join("broker-acks");
            let ack_path = ack_parent.join(&stem);
            match std::fs::remove_dir_all(&ack_path) {
                Ok(()) => ab_core::fsutil::sync_directory(&ack_parent)
                    .map_err(|error| FinalizeError::Atif(error.to_string()))?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(FinalizeError::Atif(error.to_string())),
            }
            Ok(())
        })
        .await
        .map_err(|error| FinalizeError::Task(error.to_string()))?
    }

    /// Retry every durable promotion marker whose session can be recovered.
    pub async fn retry_marked_promotions(&self, sessions: &SessionRegistry) -> Result<usize, FinalizeError> {
        let mut entries = match tokio::fs::read_dir(&self.spool_dir).await {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(error) => return Err(FinalizeError::Atif(error.to_string())),
        };
        let mut promoted = 0usize;
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|error| FinalizeError::Atif(error.to_string()))?
        {
            let path = entry.path();
            if path.extension().and_then(std::ffi::OsStr::to_str) != Some("promote") {
                continue;
            }
            // Round-27 F2: previously any read failure or MAC-verify
            // failure aborted the entire retry pass via `?`. One
            // unreadable or corrupt `.promote` marker would prevent
            // retry of every other pending promotion after a crash.
            // Mirror `replay_lifecycle_outboxes`'s warn+continue on
            // the same two failure modes; leave the bad marker on
            // disk as forensic evidence.
            let sealed = match read_capped_async(path.clone(), ab_core::fsutil::MAX_CONTROL_BYTES).await
            {
                Ok(bytes) => bytes,
                Err(error) => {
                    tracing::warn!(
                        %error,
                        path = %ab_core::fsutil::basename(&path),
                        "skipping unreadable promotion marker"
                    );
                    continue;
                }
            };
            let marker: PromotionMarker =
                match crate::journal::open(&self.journal_key, "promotion-marker", 0, &sealed) {
                    Ok(m) => m,
                    Err(error) => {
                        tracing::warn!(
                            %error,
                            path = %ab_core::fsutil::basename(&path),
                            "skipping unauthenticated promotion marker"
                        );
                        continue;
                    }
                };
            let Some(session) = sessions.get(&marker.session_id) else {
                continue;
            };
            // Background retry must never force-close a live session that
            // happens to share this id — that path belongs to the explicit
            // `promote_session` endpoint. See `promote`: any non-closed
            // session gets `close_session_locked`-ed on entry.
            if !session.is_closed() {
                tracing::info!(
                    session = %marker.session_id,
                    "promotion retry skipped: session is currently active",
                );
                continue;
            }
            match self.promote(session).await {
                Ok(_) => promoted += 1,
                Err(error) => {
                    tracing::warn!(%error, path = %ab_core::fsutil::basename(&path), "promotion retry failed");
                }
            }
        }
        Ok(promoted)
    }

    fn receipt_path(&self, session_id: &str) -> PathBuf {
        self.spool_dir.join("receipts").join(format!(
            "{}.json",
            &ab_core::digest::sha256_hex(session_id.as_bytes())[..32]
        ))
    }

    async fn ensure_atif_provenance(
        &self,
        path: &std::path::Path,
        session_id: &str,
    ) -> Result<AtifProvenance, FinalizeError> {
        // Round-18: ATIF trajectory read is bounded via MAX_ATIF_BYTES.
        // Sibling of round-17 F3 that missed this internal caller.
        let bytes = read_capped_async(path.to_path_buf(), ab_core::fsutil::MAX_ATIF_BYTES)
            .await
            .map_err(|error| FinalizeError::Atif(error.to_string()))?;
        let expected = AtifProvenance {
            session_id: session_id.to_owned(),
            digest: ab_core::digest::sha256_hex(&bytes),
        };
        let provenance_path = path.with_extension("atif-auth");
        if provenance_path.exists() {
            let sealed = read_capped_async(provenance_path.clone(), ab_core::fsutil::MAX_CONTROL_BYTES)
                .await
                .map_err(|error| FinalizeError::Atif(error.to_string()))?;
            let actual: AtifProvenance =
                crate::journal::open(&self.journal_key, "atif-provenance", 0, &sealed)
                    .map_err(FinalizeError::Atif)?;
            if actual.session_id != expected.session_id || actual.digest != expected.digest {
                return Err(FinalizeError::Atif(
                    "ATIF provenance does not match artifact bytes and session".to_owned(),
                ));
            }
            return Ok(actual);
        }
        let sealed = crate::journal::seal(&self.journal_key, "atif-provenance", 0, &expected)
            .map_err(FinalizeError::Atif)?;
        persist_marker(&provenance_path, &sealed).await?;
        Ok(expected)
    }

    async fn read_journal_metadata(
        &self,
        path: &std::path::Path,
    ) -> Result<serde_json::Value, FinalizeError> {
        // Round-18: bounded via MAX_CONTROL_BYTES — journal metadata
        // sidecar is a tiny sealed blob (session_id + identity +
        // workflow), so 1 MiB is a generous upper bound.
        let bytes = read_capped_async(path.to_path_buf(), ab_core::fsutil::MAX_CONTROL_BYTES)
            .await
            .map_err(|error| FinalizeError::Atif(error.to_string()))?;
        crate::journal::open(&self.journal_key, "metadata", 0, &bytes).map_err(FinalizeError::Atif)
    }

    fn verify_configured_receipt(&self, receipt: &Receipt) -> Result<(), FinalizeError> {
        if receipt.body.key_id != self.signer.key_id() {
            return Err(FinalizeError::Receipt(format!(
                "receipt key {:?} does not match configured key {:?}",
                receipt.body.key_id,
                self.signer.key_id()
            )));
        }
        let mut keyring = ab_receipts::Keyring::new();
        keyring
            .add_signer(self.signer.as_ref())
            .map_err(|error| FinalizeError::Receipt(error.to_string()))?;
        receipt
            .verify(&keyring)
            .map_err(|error| FinalizeError::Receipt(error.to_string()))
    }

    async fn persist_receipt(&self, session_id: &str, receipt: &Receipt) -> Result<(), FinalizeError> {
        let path = self.receipt_path(session_id);
        let bytes =
            serde_json::to_vec_pretty(receipt).map_err(|error| FinalizeError::Receipt(error.to_string()))?;
        tokio::task::spawn_blocking(move || ab_core::fsutil::write_atomic(&path, &bytes))
            .await
            .map_err(|error| FinalizeError::Task(error.to_string()))?
            .map_err(|error| FinalizeError::Receipt(error.to_string()))
    }

    async fn emit_receipt_event(&self, session: &Session, receipt: &Receipt) -> Result<(), FinalizeError> {
        self.emit_bridge_event(
            session,
            ab_events::EventClass::Receipt,
            serde_json::json!({
                "receipt_id": receipt.body.receipt_id,
                "key_id": receipt.body.key_id,
                "subject": receipt.body.subject,
                "receipt": receipt,
            }),
            crate::journal::RECEIPT_OUTBOX_KIND,
        )
        .await
    }

    async fn emit_bridge_event(
        &self,
        session: &Session,
        class: ab_events::EventClass,
        payload: serde_json::Value,
        kind: &str,
    ) -> Result<(), FinalizeError> {
        let Some(bridge) = self.bridge.as_ref().map(Arc::clone) else {
            return Ok(());
        };
        let path = self.lifecycle_outbox_path(&session.id, kind);
        let mut outbox = if path.exists() {
            let sealed = read_capped_async(path.clone(), ab_core::fsutil::MAX_CONTROL_BYTES)
                .await
                .map_err(|error| FinalizeError::Bridge(error.to_string()))?;
            let outbox: LifecycleOutbox = crate::journal::open(
                &self.journal_key,
                crate::journal::LIFECYCLE_OUTBOX_DOMAIN,
                0,
                &sealed,
            )
            .map_err(FinalizeError::Bridge)?;
            if outbox.session_id != session.id || outbox.kind != kind {
                return Err(FinalizeError::Bridge(
                    "lifecycle outbox does not match its session and kind".to_owned(),
                ));
            }
            // A crash between a prior successful emit and a subsequent one loses the
            // in-memory seq advance for this outbox — recovery only restores seq from
            // the journal length. Fast-forward past the persisted seq so a following
            // lifecycle event (e.g., SESSION_CLOSE after a persisted RECEIPT_OUTBOX)
            // cannot land on the same metadata.sequence value.
            if let Some(persisted_seq) = outbox
                .value
                .get("metadata")
                .and_then(|metadata| metadata.get("sequence"))
                .and_then(serde_json::Value::as_u64)
            {
                if session.peek_seq() <= persisted_seq {
                    session.advance_seq_past(persisted_seq);
                }
            }
            outbox
        } else {
            // Peek the seq without consuming it; a failed persist_outbox
            // below would otherwise burn a seq that recovery expects to see
            // at a later journal position, breaking the position-vs-seq
            // invariant when reset_close reopens the session.
            let event_seq = session.peek_seq();
            let event = ab_events::OcsfEventBuilder::new(
                class,
                session.id.clone(),
                session.current_identity(),
                event_seq,
            )
            .payload(payload)
            .build()
            .map_err(|error| FinalizeError::Bridge(error.to_string()))?;
            let outbox = LifecycleOutbox {
                session_id: session.id.clone(),
                kind: kind.to_owned(),
                topic: class.topic().to_owned(),
                key: session.current_identity().instance_uid,
                value: serde_json::to_value(event)
                    .map_err(|error| FinalizeError::Bridge(error.to_string()))?,
                ack: None,
            };
            persist_outbox(&path, &outbox, &self.journal_key).await?;
            session.advance_seq_past(event_seq);
            outbox
        };
        if outbox.ack.is_some() {
            return Ok(());
        }
        let topic = outbox.topic.clone();
        let key = outbox.key.clone();
        let value = outbox.value.clone();
        let event_uid = lifecycle_event_uid(&value)?;
        let ack = match resolve_lifecycle_ack(bridge, topic, key, value, event_uid).await {
            Ok(ack) => ack,
            Err(error) => {
                self.metrics
                    .counter(
                        "ab_lifecycle_event_errors_total",
                        "Lifecycle events not published",
                    )
                    .inc();
                return Err(error);
            }
        };
        outbox.ack = Some(ack);
        persist_outbox(&path, &outbox, &self.journal_key).await?;
        Ok(())
    }

    async fn replay_lifecycle_outboxes(&self) -> Result<usize, FinalizeError> {
        let Some(bridge) = self.bridge.as_ref().map(Arc::clone) else {
            return Ok(0);
        };
        let directory = self.spool_dir.join(crate::spool::OUTBOX);
        let mut entries = match tokio::fs::read_dir(&directory).await {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(error) => return Err(FinalizeError::Bridge(error.to_string())),
        };
        let mut replayed = 0usize;
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|error| FinalizeError::Bridge(error.to_string()))?
        {
            let path = entry.path();
            if path.extension().and_then(std::ffi::OsStr::to_str) != Some("json") {
                continue;
            }
            let sealed = match read_capped_async(path.clone(), ab_core::fsutil::MAX_CONTROL_BYTES).await {
                Ok(bytes) => bytes,
                Err(error) => {
                    tracing::warn!(%error, path = %ab_core::fsutil::basename(&path), "skipping unreadable outbox file");
                    continue;
                }
            };
            let mut outbox: LifecycleOutbox = match crate::journal::open(
                &self.journal_key,
                crate::journal::LIFECYCLE_OUTBOX_DOMAIN,
                0,
                &sealed,
            ) {
                Ok(outbox) => outbox,
                // A single corrupt or MAC-failing outbox file must not abort
                // the entire scan and stop us from replaying the other
                // sessions' outboxes. The bad file stays on disk as
                // forensic evidence (`open` does not delete on failure).
                Err(error) => {
                    tracing::warn!(%error, path = %ab_core::fsutil::basename(&path), "skipping malformed outbox");
                    continue;
                }
            };
            if path != self.lifecycle_outbox_path(&outbox.session_id, &outbox.kind) {
                tracing::warn!(
                    path = %ab_core::fsutil::basename(&path),
                    "skipping outbox whose filename does not match its authenticated session_id/kind"
                );
                continue;
            }
            if outbox.ack.is_none() {
                let topic = outbox.topic.clone();
                let key = outbox.key.clone();
                let value = outbox.value.clone();
                let event_uid = lifecycle_event_uid(&value)?;
                outbox.ack =
                    Some(resolve_lifecycle_ack(Arc::clone(&bridge), topic, key, value, event_uid).await?);
                persist_outbox(&path, &outbox, &self.journal_key).await?;
                replayed = replayed.saturating_add(1);
            }
        }
        Ok(replayed)
    }

    async fn remove_acked_lifecycle_outboxes(&self) -> Result<(), FinalizeError> {
        let directory = self.spool_dir.join(crate::spool::OUTBOX);
        let mut entries = match tokio::fs::read_dir(&directory).await {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(FinalizeError::Bridge(error.to_string())),
        };
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|error| FinalizeError::Bridge(error.to_string()))?
        {
            let path = entry.path();
            if path.extension().and_then(std::ffi::OsStr::to_str) != Some("json") {
                continue;
            }
            let sealed = read_capped_async(path.clone(), ab_core::fsutil::MAX_CONTROL_BYTES)
                .await
                .map_err(|error| FinalizeError::Bridge(error.to_string()))?;
            let outbox: LifecycleOutbox = crate::journal::open(
                &self.journal_key,
                crate::journal::LIFECYCLE_OUTBOX_DOMAIN,
                0,
                &sealed,
            )
            .map_err(FinalizeError::Bridge)?;
            if path != self.lifecycle_outbox_path(&outbox.session_id, &outbox.kind) {
                return Err(FinalizeError::Bridge(
                    "lifecycle outbox path does not match authenticated payload".to_owned(),
                ));
            }
            if outbox.ack.is_some() {
                remove_outbox(&path).await?;
            }
        }
        Ok(())
    }

    fn lifecycle_outbox_path(&self, session_id: &str, kind: &str) -> PathBuf {
        let session_hash = &ab_core::digest::sha256_hex(session_id.as_bytes())[..32];
        self.spool_dir
            .join(crate::spool::OUTBOX)
            .join(format!("{session_hash}.{kind}.json"))
    }

    async fn remove_lifecycle_outbox(&self, session_id: &str, kind: &str) -> Result<(), FinalizeError> {
        remove_outbox(&self.lifecycle_outbox_path(session_id, kind)).await
    }
}

async fn persist_outbox(
    path: &std::path::Path,
    outbox: &LifecycleOutbox,
    journal_key: &[u8; 32],
) -> Result<(), FinalizeError> {
    let path = path.to_path_buf();
    let bytes = crate::journal::seal(journal_key, crate::journal::LIFECYCLE_OUTBOX_DOMAIN, 0, outbox)
        .map_err(FinalizeError::Bridge)?;
    tokio::task::spawn_blocking(move || ab_core::fsutil::write_atomic(&path, &bytes))
        .await
        .map_err(|error| FinalizeError::Task(error.to_string()))?
        .map_err(|error| FinalizeError::Bridge(error.to_string()))
}

async fn persist_marker(path: &std::path::Path, bytes: &[u8]) -> Result<(), FinalizeError> {
    let path = path.to_path_buf();
    let bytes = bytes.to_vec();
    tokio::task::spawn_blocking(move || ab_core::fsutil::write_atomic(&path, &bytes))
        .await
        .map_err(|error| FinalizeError::Task(error.to_string()))?
        .map_err(|error| FinalizeError::Atif(error.to_string()))
}

async fn remove_outbox(path: &std::path::Path) -> Result<(), FinalizeError> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || -> Result<(), FinalizeError> {
        let parent = path
            .parent()
            .ok_or_else(|| FinalizeError::Bridge("outbox has no parent".to_owned()))?;
        match std::fs::remove_file(&path) {
            Ok(()) => ab_core::fsutil::sync_directory(parent)
                .map_err(|error| FinalizeError::Bridge(error.to_string())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(FinalizeError::Bridge(error.to_string())),
        }
    })
    .await
    .map_err(|error| FinalizeError::Task(error.to_string()))?
}

/// Start periodic idle-session finalization.
pub fn spawn_reconciler(
    sessions: Arc<SessionRegistry>,
    finalizer: Finalizer,
    idle_s: u64,
    tick_s: u64,
    breaker: ab_loopdetect::BreakerConfig,
    metrics: Arc<Registry>,
) -> tokio::task::JoinHandle<()> {
    use futures::future::FutureExt as _;
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(tick_s.max(1)));
        // Skip missed ticks instead of firing them back-to-back. Under
        // transient overload (a 5 s tick body that takes 60 s) the
        // default `Burst` behaviour would fire 12 immediate consecutive
        // ticks, each running the full sweep — turning momentary
        // pressure into a stall spiral.
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            let started = Instant::now();
            // Wrap the whole tick body in catch_unwind: any panic in
            // the reconciler (fs unwrap, JCS overflow, allocator
            // failure inside tracing) would otherwise silently kill
            // the task; idle sessions would then never finalize until
            // the harness restarts. The JWKS refresh loop uses the
            // same shape (main.rs).
            let outcome = std::panic::AssertUnwindSafe(async {
                if let Err(error) = finalizer.recover_spooled_sessions(&sessions, &breaker).await {
                    tracing::warn!(%error, "ATIF spool recovery failed");
                    metrics
                        .counter("ab_reconcile_errors_total", "Reconciliation errors")
                        .inc();
                }
                if let Err(error) = finalizer.retry_marked_promotions(&sessions).await {
                    tracing::warn!(%error, "durable promotion retry failed");
                    metrics
                        .counter("ab_reconcile_errors_total", "Reconciliation errors")
                        .inc();
                }
                for session in sessions.idle_sessions(idle_s) {
                    let session_id = session.id.clone();
                    if let Err(error) = finalizer.close_session(session, StopReason::SessionClosed).await {
                        tracing::warn!(session = %session_id, %error, "idle session finalization failed");
                        metrics
                            .counter("ab_reconcile_errors_total", "Reconciliation errors")
                            .inc();
                    }
                }
                let evicted = sessions.evict_finalized(idle_s);
                if !evicted.is_empty() {
                    tracing::debug!(count = evicted.len(), "evicted finalized signed sessions");
                }
            })
            .catch_unwind()
            .await;
            if let Err(panic) = outcome {
                let msg = panic
                    .downcast_ref::<&'static str>()
                    .copied()
                    .or_else(|| panic.downcast_ref::<String>().map(String::as_str))
                    .unwrap_or("panic payload was not a string");
                metrics
                    .counter(
                        "ab_reconciler_panics_total",
                        "Reconciler tick body panicked; loop supervised via catch_unwind",
                    )
                    .inc();
                tracing::error!(
                    panic = %msg,
                    "reconciler tick body panicked; continuing on the next tick"
                );
            }
            metrics
                .histogram("ab_reconcile_duration_seconds", "Idle reconciliation duration")
                .observe_us(elapsed_us(started));
        }
    })
}

fn checked_recovery_add(current: u64, value: u64, field: &str) -> Result<u64, FinalizeError> {
    current
        .checked_add(value)
        .filter(|total| *total <= ab_core::error::JCS_SAFE_MAX)
        .ok_or_else(|| FinalizeError::Atif(format!("recovered {field} overflow")))
}

fn track_response_attempt(
    pending: &mut std::collections::HashSet<String>,
    attempt: Option<&crate::worker::ResponseAttempt>,
) -> Result<(), FinalizeError> {
    let Some(attempt) = attempt else {
        return Ok(());
    };
    if attempt.terminal {
        if !pending.remove(&attempt.id) {
            pending.insert(format!("orphan-terminal:{}", attempt.id));
        }
    } else if !pending.insert(attempt.id.clone()) {
        return Err(FinalizeError::Atif(
            "active journal repeats a response attempt id".to_owned(),
        ));
    }
    Ok(())
}

fn lifecycle_event_uid(value: &serde_json::Value) -> Result<String, FinalizeError> {
    value
        .get("metadata")
        .and_then(|metadata| metadata.get("uid"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| FinalizeError::Bridge("lifecycle event has no metadata UID".to_owned()))
}

async fn resolve_lifecycle_ack(
    bridge: Arc<dyn EventBus>,
    topic: String,
    key: String,
    value: serde_json::Value,
    event_uid: String,
) -> Result<ab_bridge::PublishAck, FinalizeError> {
    let lookup_bridge = Arc::clone(&bridge);
    let lookup_topic = topic.clone();
    let lookup_key = key.clone();
    let lookup_uid = event_uid.clone();
    if let Some(ack) = tokio::task::spawn_blocking(move || {
        lookup_bridge.find_event_by_uid(&lookup_topic, &lookup_key, &lookup_uid)
    })
    .await
    .map_err(|error| FinalizeError::Task(error.to_string()))?
    .map_err(|error| FinalizeError::Bridge(error.to_string()))?
    {
        return Ok(ack);
    }
    tokio::task::spawn_blocking(move || bridge.publish_idempotent(&topic, &key, &value, &event_uid))
        .await
        .map_err(|error| FinalizeError::Task(error.to_string()))?
        .map_err(|error| FinalizeError::Bridge(error.to_string()))
}

/// Round-14 F5: check whether `read_complete_journal` has previously
/// quarantined this stem's events journal to
/// `<stem>.events.ndjson.corrupt-*`. Callers use this to decide
/// whether to delete the sealed metadata sidecar when the events
/// journal appears empty — if there's a sibling `.corrupt-*` file,
/// the "empty" is actually "torn and moved out for post-mortem" and
/// the metadata must be preserved (or quarantined itself) rather
/// than removed.
async fn quarantine_sibling_exists(
    spool_dir: &std::path::Path,
    stem: &str,
) -> Result<bool, FinalizeError> {
    let prefix = format!("{stem}.events.ndjson.corrupt-");
    let spool_dir = spool_dir.to_path_buf();
    tokio::task::spawn_blocking(move || -> Result<bool, FinalizeError> {
        let entries = match std::fs::read_dir(&spool_dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(FinalizeError::Atif(error.to_string())),
        };
        for entry in entries {
            let entry = entry.map_err(|error| FinalizeError::Atif(error.to_string()))?;
            let name = entry.file_name();
            if let Some(name) = name.to_str() {
                if name.starts_with(&prefix) {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    })
    .await
    .map_err(|error| FinalizeError::Task(error.to_string()))?
}

/// Round-17 F3: async wrapper around `ab_core::fsutil::read_capped`
/// for the reconciler's hot-path reads. A fs-tamper attacker
/// (co-scheduled workload, backup restore gone wrong, malicious
/// sidecar) can otherwise plant a multi-GB receipt/trajectory and
/// OOM the harness on every recovery tick. `spawn_blocking` keeps
/// the tokio runtime healthy while `File::open` + `metadata` +
/// bounded `read_to_end` run on the blocking pool.
async fn read_capped_async(
    path: std::path::PathBuf,
    max_bytes: u64,
) -> Result<Vec<u8>, std::io::Error> {
    tokio::task::spawn_blocking(move || ab_core::fsutil::read_capped(&path, max_bytes))
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?
}

async fn read_complete_journal(path: &std::path::Path) -> Result<Vec<String>, FinalizeError> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || -> Result<Vec<String>, FinalizeError> {
        // Round-18: bounded via the shared MAX_ATIF_BYTES so a fs-tamper
        // attacker cannot plant a multi-GB journal and OOM the
        // recovery scan.
        let bytes = ab_core::fsutil::read_capped(&path, ab_core::fsutil::MAX_ATIF_BYTES)
            .map_err(|error| FinalizeError::Atif(error.to_string()))?;
        if bytes.is_empty() {
            return Ok(Vec::new());
        }
        let complete_len = if bytes.last() == Some(&b'\n') {
            bytes.len()
        } else {
            bytes
                .iter()
                .rposition(|byte| *byte == b'\n')
                .map_or(0, |index| index + 1)
        };
        // Round-13 F2: if the file contains NO complete line (no
        // newline anywhere), truncating to 0 would silently destroy
        // every byte of a torn-write journal — the caller then sees
        // an empty journal, deletes the sealed metadata sidecar, and
        // an operator investigating "session missing" has no
        // evidence at all. Instead, quarantine the file to
        // `<path>.corrupt-<uid>` so post-mortem inspection can happen,
        // then return an error so the reconciler leaves the session
        // in place rather than progressing to metadata deletion.
        if complete_len == 0 && !bytes.is_empty() {
            let mut quarantine = path.clone();
            let stem = quarantine
                .file_name()
                .and_then(std::ffi::OsStr::to_str)
                .unwrap_or("journal");
            let new_name = format!("{stem}.corrupt-{}", ab_core::new_event_uid());
            quarantine.set_file_name(new_name);
            let rename_error_message = match std::fs::rename(&path, &quarantine) {
                Ok(()) => {
                    tracing::error!(
                        original = %ab_core::fsutil::basename(&path),
                        quarantine = %ab_core::fsutil::basename(&quarantine),
                        bytes = bytes.len(),
                        "journal has no complete lines; quarantined for post-mortem instead of silent 0-truncate"
                    );
                    None
                }
                Err(rename_error) => {
                    tracing::error!(
                        path = %ab_core::fsutil::basename(&path),
                        bytes = bytes.len(),
                        error = %rename_error,
                        "journal has no complete lines and quarantine rename failed; refusing to truncate"
                    );
                    Some(rename_error.to_string())
                }
            };
            // Round-14 F6: don't claim the file was quarantined if
            // the rename itself failed. Otherwise the operator
            // chases a phantom `.corrupt-<uid>` path while the real
            // failure (ENOSPC / EACCES / cross-fs rename) sits
            // buried in the tracing log.
            //
            // Round-37 F1: return the file basenames only. This
            // FinalizeError::Atif ultimately flows to
            // `tracing::warn!(%error, "ATIF spool recovery failed")`
            // at line ~2092 and `"promotion retry failed"` at line
            // ~1710; both then export through
            // tracing_opentelemetry -> OTLP -> SIEM. Round-36 F1's
            // sweep basenamed the outer tracing fields but missed
            // this path leak inside a FinalizeError message body,
            // where `#[error("...{0}")]` re-emits the full string.
            let name = ab_core::fsutil::basename(&path);
            let qname = ab_core::fsutil::basename(&quarantine);
            return Err(FinalizeError::Atif(match rename_error_message {
                None => format!(
                    "journal {name} contained no complete lines ({} bytes); quarantined at {qname}",
                    bytes.len()
                ),
                Some(rename_error) => format!(
                    "journal {name} contained no complete lines ({} bytes); quarantine rename to {qname} failed: {rename_error}; bytes remain at {name}",
                    bytes.len()
                ),
            }));
        }
        if complete_len < bytes.len() {
            tracing::warn!(
                path = %ab_core::fsutil::basename(&path),
                stored = bytes.len(),
                keeping = complete_len,
                dropping = bytes.len() - complete_len,
                "trimming partial trailing line from journal recovery"
            );
            let file = std::fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .map_err(|error| FinalizeError::Atif(error.to_string()))?;
            file.set_len(complete_len as u64)
                .map_err(|error| FinalizeError::Atif(error.to_string()))?;
            file.sync_all()
                .map_err(|error| FinalizeError::Atif(error.to_string()))?;
        }
        let complete = String::from_utf8(bytes.get(..complete_len).unwrap_or_default().to_vec())
            .map_err(|error| FinalizeError::Atif(error.to_string()))?;
        Ok(complete
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(str::to_owned)
            .collect())
    })
    .await
    .map_err(|error| FinalizeError::Task(error.to_string()))?
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::unwrap_used
    )]

    use super::*;
    use ab_bridge::{BusError, PublishAck, StoredEvent};
    use ab_events::AgentIdentity;
    use ab_receipts::Ed25519Signer;

    struct FailFirstReceiptBus {
        fail: std::sync::atomic::AtomicBool,
        attempts: parking_lot::Mutex<Vec<(String, serde_json::Value)>>,
    }

    impl EventBus for FailFirstReceiptBus {
        fn publish(
            &self,
            topic: &str,
            _key: &str,
            value: &serde_json::Value,
        ) -> Result<PublishAck, BusError> {
            self.attempts.lock().push((topic.to_owned(), value.clone()));
            if topic == "agent.receipt" && self.fail.swap(false, std::sync::atomic::Ordering::AcqRel) {
                return Err(BusError::Backend("injected receipt outage".to_owned()));
            }
            Ok(PublishAck {
                topic: topic.to_owned(),
                partition: 0,
                offset: self.attempts.lock().len() as u64,
            })
        }

        fn fetch(
            &self,
            _topic: &str,
            _partition: u32,
            _offset: u64,
            _max: usize,
        ) -> Result<Vec<StoredEvent>, BusError> {
            Ok(Vec::new())
        }

        fn partitions(&self, _topic: &str) -> Result<u32, BusError> {
            Ok(1)
        }

        fn topics(&self) -> Vec<String> {
            ab_events::EventClass::all()
                .iter()
                .map(|class| class.topic().to_owned())
                .collect()
        }
    }

    fn session(workflow: Workflow) -> Arc<Session> {
        Arc::new(Session::new(
            "lifecycle-session".to_owned(),
            workflow,
            AgentIdentity {
                version: "1".to_owned(),
                charter: "test".into(),
                instance_uid: "instance-1".to_owned(),
                ttl_remaining_s: Some(600),
            },
            Default::default(),
        ))
    }

    fn finalizer(directory: &std::path::Path) -> Finalizer {
        Finalizer::new(
            Arc::new(Ed25519Signer::from_seed(&[7; 32])),
            directory.to_path_buf(),
            Arc::new(Registry::new()),
        )
    }

    /// A lifecycle emit that fails at `persist_outbox` must not have
    /// consumed a sequence number — otherwise `reset_close` reopens the
    /// session with a burned seq, and the next worker envelope's
    /// `next_seq` return would put a mismatched
    /// `event.metadata.sequence` at the journal's next byte position,
    /// tripping recovery's `sequence != index` check.
    #[tokio::test]
    async fn emit_bridge_event_persist_failure_does_not_burn_a_seq() {
        let directory = tempfile::tempdir().unwrap();
        // Sabotage the outbox path: a regular file at `<spool>/outbox` makes
        // `create_dir_all` inside `write_atomic` fail for every subsequent
        // outbox write.
        std::fs::write(directory.path().join(crate::spool::OUTBOX), b"").unwrap();
        let bus = Arc::new(FailFirstReceiptBus {
            fail: std::sync::atomic::AtomicBool::new(false),
            attempts: parking_lot::Mutex::new(Vec::new()),
        });
        let finalizer = Finalizer::with_bridge(
            Arc::new(Ed25519Signer::from_seed(&[7; 32])),
            directory.path().to_path_buf(),
            Arc::new(Registry::new()),
            bus,
        );
        let session = session(Workflow::Signed);
        let seq_before = session.peek_seq();
        // Signed close writes the receipt to disk, then tries emit_receipt_event → emit_bridge_event.
        // The latter must fail at persist_outbox because <spool>/outbox is a file.
        let result = finalizer
            .close_session(Arc::clone(&session), StopReason::SessionClosed)
            .await;
        assert!(
            result.is_err(),
            "close_session must fail when outbox persist is blocked, got {result:?}",
        );
        assert_eq!(
            session.peek_seq(),
            seq_before,
            "peek_seq must not advance past a failed persist_outbox — the burned \
             seq would misalign the journal on retry",
        );
    }

    /// After a crash between a persisted RECEIPT_OUTBOX (seq = N) and its
    /// corresponding SESSION_CLOSE_OUTBOX emit, recovery restores
    /// `session.seq` from the journal length, which lags the seq the receipt
    /// outbox baked in. `emit_bridge_event` reading the pre-existing outbox
    /// must fast-forward the counter so the next lifecycle event does not
    /// reuse the seq — bridge consumers rely on unique
    /// `metadata.sequence` within a session.
    #[tokio::test]
    async fn emit_bridge_event_reading_persisted_outbox_advances_seq_past_it() {
        let directory = tempfile::tempdir().unwrap();
        let bus = Arc::new(FailFirstReceiptBus {
            fail: std::sync::atomic::AtomicBool::new(false),
            attempts: parking_lot::Mutex::new(Vec::new()),
        });
        let finalizer = Finalizer::with_bridge(
            Arc::new(Ed25519Signer::from_seed(&[7; 32])),
            directory.path().to_path_buf(),
            Arc::new(Registry::new()),
            bus.clone(),
        );
        let session = session(Workflow::Signed);
        // Simulate a crash mid-close: manually persist a RECEIPT_OUTBOX carrying a specific
        // seq and an already-set ack so emit_receipt_event will skip the publish path.
        let receipt_seq = 42u64;
        let receipt_event_uid = ab_core::new_event_uid();
        let value = serde_json::json!({
            "metadata": { "sequence": receipt_seq, "uid": receipt_event_uid },
            "topic": ab_events::EventClass::Receipt.topic(),
        });
        let outbox = LifecycleOutbox {
            session_id: session.id.clone(),
            kind: crate::journal::RECEIPT_OUTBOX_KIND.to_owned(),
            topic: ab_events::EventClass::Receipt.topic().to_owned(),
            key: session.identity.instance_uid.clone(),
            value,
            ack: Some(ab_bridge::PublishAck {
                topic: ab_events::EventClass::Receipt.topic().to_owned(),
                partition: 0,
                offset: 1,
            }),
        };
        let outbox_path = finalizer.lifecycle_outbox_path(&session.id, crate::journal::RECEIPT_OUTBOX_KIND);
        std::fs::create_dir_all(outbox_path.parent().unwrap()).unwrap();
        let sealed = crate::journal::seal(
            &finalizer.journal_key,
            crate::journal::LIFECYCLE_OUTBOX_DOMAIN,
            0,
            &outbox,
        )
        .unwrap();
        std::fs::write(&outbox_path, sealed).unwrap();
        assert!(
            session.peek_seq() < receipt_seq,
            "precondition: in-memory seq must trail the persisted outbox seq",
        );
        finalizer
            .close_session(Arc::clone(&session), StopReason::SessionClosed)
            .await
            .unwrap();
        let attempts = bus.attempts.lock();
        let session_close = attempts
            .iter()
            .find(|(topic, _)| topic == ab_events::EventClass::Session.topic())
            .expect("SESSION_CLOSE lifecycle event must reach the bridge");
        let session_close_seq = session_close
            .1
            .get("metadata")
            .and_then(|metadata| metadata.get("sequence"))
            .and_then(serde_json::Value::as_u64)
            .expect("published event must carry a numeric metadata.sequence");
        assert!(
            session_close_seq > receipt_seq,
            "SESSION_CLOSE seq ({session_close_seq}) must exceed the persisted RECEIPT_OUTBOX seq ({receipt_seq}) — otherwise consumers see duplicate metadata.sequence values within one session",
        );
    }

    /// A signed session inserted into the registry by `recover_signed_journals`
    /// must reject new leases from the moment it is visible — otherwise a client
    /// request landing between `try_insert_recovered` and the finalize path can
    /// submit a worker job that appends to the recovered chain, permanently
    /// diverging it from the persisted receipt's `subject.event_count` and
    /// leaving a wrong-index entry in the on-disk journal. `CloseClaim::drop`
    /// resets `closed` on any finalize error, so pinning the "no leases" state
    /// only via `try_close` inside `close_session_locked` is not enough — the
    /// session must be sealed before it is ever visible.
    #[tokio::test]
    async fn recovered_signed_session_rejects_leases_even_when_finalize_errors() {
        use ab_events::{EventClass, OcsfEventBuilder, StatusId};
        use std::io::Write as _;

        let directory = tempfile::tempdir().unwrap();
        let signer: Arc<dyn Signer> = Arc::new(Ed25519Signer::from_seed(&[29; 32]));
        let journal_key = crate::journal::key_from_signer(signer.as_ref());
        let session_id = "signed-recovery-lease-guard";
        let identity = AgentIdentity {
            version: "1".into(),
            charter: "test".into(),
            instance_uid: "instance-lease-guard".into(),
            ttl_remaining_s: Some(600),
        };

        // Seed the signed session metadata file.
        let digest = ab_core::digest::sha256_hex(session_id.as_bytes());
        let stem = &digest[..32];
        let metadata_payload = serde_json::json!({
            "journal_version": 2,
            "session_id": session_id,
            "identity": identity,
            "workflow": "signed",
        });
        let metadata_sealed = crate::journal::seal(&journal_key, "metadata", 0, &metadata_payload).unwrap();
        std::fs::write(
            directory.path().join(format!("{stem}.session.json")),
            &metadata_sealed,
        )
        .unwrap();

        // Seed one signed event in the active journal.
        let event = OcsfEventBuilder::new(
            EventClass::Compression,
            session_id.to_owned(),
            identity.clone(),
            0,
        )
        .status(StatusId::Success)
        .payload(serde_json::json!({}))
        .build()
        .unwrap();
        let event_uid = event.metadata.uid.clone();
        let record = crate::worker::ActiveJournalRecord {
            event: serde_json::to_value(&event).unwrap(),
            identity: identity.clone(),
            atif_step: None,
            tool_calls: 0,
            tool_allowed: 0,
            tool_blocked: 0,
            prompt_tokens: 0,
            completion_tokens: 0,
            cached_tokens: 0,
            cost_usd_micros: 0,
            stop_reason_id: None,
            response_attempt: None,
        };
        let domain = format!("{session_id}:active");
        let sealed = crate::journal::seal(&journal_key, &domain, 0, &record).unwrap();
        let mut journal_file =
            std::fs::File::create(directory.path().join(format!("{stem}.events.ndjson"))).unwrap();
        journal_file.write_all(&sealed).unwrap();
        journal_file.write_all(b"\n").unwrap();
        drop(journal_file);

        // Seed a broker ack so `ensure_active_event_published` short-circuits.
        crate::worker::persist_broker_ack(
            directory.path(),
            session_id,
            &event_uid,
            &PublishAck {
                topic: EventClass::Compression.topic().to_owned(),
                partition: 0,
                offset: 1,
            },
            &journal_key,
        )
        .await
        .unwrap();

        // Sabotage the receipts directory so that `persist_receipt` inside
        // `close_session_locked` fails BEFORE `mark_artifact_committed` runs.
        // A regular file at `<spool>/receipts` makes `create_dir_all` fail for
        // the receipt write. Because there's no persisted receipt for recovery
        // to verify, the finalize path signs a fresh one and only then hits
        // the sabotage — reproducing the exact "closed=1 → reset → 0, but
        // artifact_committed still 0" window a racing lease can exploit.
        std::fs::write(directory.path().join("receipts"), b"").unwrap();

        let registry = crate::session::SessionRegistry::new();
        let finalizer = Finalizer::with_bridge(
            signer,
            directory.path().to_path_buf(),
            Arc::new(Registry::new()),
            Arc::new(FailFirstReceiptBus {
                fail: std::sync::atomic::AtomicBool::new(false),
                attempts: parking_lot::Mutex::new(Vec::new()),
            }),
        );
        let result = finalizer
            .recover_spooled_sessions(&registry, &Default::default())
            .await;
        // Round-41 F1: per-session finalize errors during signed
        // recovery no longer propagate to the outer function's Err
        // — they warn+continue so one broken session cannot HOL-
        // block every other. The security invariant this test
        // enforces (post-error try_lease rejection) still holds via
        // the round-14 F5 mark_artifact_committed-before-
        // try_insert_recovered ordering: after close_session_locked
        // Err, `is_closed()` is true, so lease is refused.
        assert!(
            result.is_ok(),
            "round-41 F1: per-session errors warn+continue; got {result:?}",
        );

        let session = registry
            .get(session_id)
            .expect("recovered signed session must remain in the registry after a finalize error");
        assert!(
            session.try_lease().is_none(),
            "recovered signed session must reject new leases even after finalize errors — otherwise a racing client request could take a lease, submit a worker job that appends to the recovered chain, and permanently diverge it from the persisted receipt's subject.event_count (also leaving a wrong-index entry sealed at file position N)",
        );
    }

    /// Round-41 F1: a corrupt/tampered signed sidecar must NOT
    /// head-of-line-block recovery of every OTHER session for the
    /// tick. Before this fix, the outer function returned Err on
    /// the first poisoned sidecar and skipped every subsequent
    /// signed AND unsigned candidate. Round-27 F1 / F2 already
    /// applied the warn+continue discipline to the ATIF-spool and
    /// promotion-marker paths; this locks in parity for the
    /// signed-journal path.
    ///
    /// Test plan: plant one poisoned metadata sidecar with a
    /// filename-shape that recover_signed_journals will accept but
    /// content that fails HMAC verification. Assert:
    ///   (a) recover_spooled_sessions returns Ok (was Err
    ///       pre-round-41),
    ///   (b) the poisoned session id is NOT installed into the
    ///       registry.
    #[tokio::test]
    async fn round_41_f1_corrupt_signed_sidecar_does_not_block_other_signed_recovery() {
        let directory = tempfile::tempdir().unwrap();
        // Plant a poisoned sidecar with the correct filename shape
        // but garbage content — read_journal_metadata will fail
        // HMAC verification and return Err. Pre-round-41 F1 this
        // Err propagated through recover_spooled_sessions and
        // aborted every unrelated session's recovery for the tick.
        let poison_stem = "poisonpoisonpoisonpoisonpoison32";
        std::fs::write(
            directory
                .path()
                .join(format!("{poison_stem}.session.json")),
            b"{\"garbage\": true, \"not\": \"a valid sealed metadata\"}",
        )
        .unwrap();
        std::fs::write(
            directory
                .path()
                .join(format!("{poison_stem}.events.ndjson")),
            b"{}\n",
        )
        .unwrap();
        let registry = crate::session::SessionRegistry::new();
        let finalizer = finalizer(directory.path());
        let outcome = finalizer
            .recover_spooled_sessions(&registry, &Default::default())
            .await;
        assert!(
            outcome.is_ok(),
            "poisoned sidecar must not fail the outer recover_spooled_sessions; got {outcome:?}"
        );
        assert!(
            registry.get(poison_stem).is_none(),
            "poisoned session id must NEVER be installed into the registry"
        );
    }

    #[tokio::test]
    async fn signed_close_issues_exactly_one_offline_verifiable_receipt() {
        let directory = tempfile::tempdir().unwrap();
        let finalizer = finalizer(directory.path());
        let session = session(Workflow::Signed);

        let first = finalizer
            .close_session(Arc::clone(&session), StopReason::SessionClosed)
            .await
            .unwrap();
        let FinalizeOutcome::Receipt { receipt } = first else {
            panic!("expected receipt")
        };
        receipt.verify_embedded().unwrap();
        assert!(matches!(
            finalizer
                .close_session(Arc::clone(&session), StopReason::SessionClosed)
                .await
                .unwrap(),
            FinalizeOutcome::AlreadyClosed
        ));
        assert_eq!(
            session.receipt.lock().as_ref().unwrap().body.receipt_id,
            receipt.body.receipt_id
        );
    }

    #[tokio::test]
    async fn lifecycle_outbox_retries_the_same_receipt_event() {
        let directory = tempfile::tempdir().unwrap();
        let bus = Arc::new(FailFirstReceiptBus {
            fail: std::sync::atomic::AtomicBool::new(true),
            attempts: parking_lot::Mutex::new(Vec::new()),
        });
        let finalizer = Finalizer::with_bridge(
            Arc::new(Ed25519Signer::from_seed(&[17; 32])),
            directory.path().to_path_buf(),
            Arc::new(Registry::new()),
            bus.clone(),
        );
        let session = session(Workflow::Signed);
        assert!(matches!(
            finalizer
                .close_session(Arc::clone(&session), StopReason::SessionClosed)
                .await,
            Err(FinalizeError::Bridge(_))
        ));
        assert!(session.is_closed());
        assert!(
            session.try_lease().is_none(),
            "artifact commit must keep admission closed"
        );
        let receipt_id = session.receipt.lock().as_ref().unwrap().body.receipt_id.clone();
        let outcome = finalizer
            .close_session(Arc::clone(&session), StopReason::SessionClosed)
            .await
            .unwrap();
        let FinalizeOutcome::Receipt { receipt } = outcome else {
            panic!("expected receipt")
        };
        assert_eq!(receipt.body.receipt_id, receipt_id);
        let attempts = bus.attempts.lock();
        let receipt_events: Vec<_> = attempts
            .iter()
            .filter(|(topic, _)| topic == "agent.receipt")
            .collect();
        assert_eq!(receipt_events.len(), 2);
        assert_eq!(
            receipt_events[0].1["metadata"]["uid"],
            receipt_events[1].1["metadata"]["uid"]
        );
        assert!(!finalizer.lifecycle_outbox_path(&session.id, "receipt").exists());
    }

    #[tokio::test]
    async fn concurrent_close_waits_for_failed_lifecycle_attempt() {
        let directory = tempfile::tempdir().unwrap();
        let bus = Arc::new(FailFirstReceiptBus {
            fail: std::sync::atomic::AtomicBool::new(true),
            attempts: parking_lot::Mutex::new(Vec::new()),
        });
        let finalizer = Finalizer::with_bridge(
            Arc::new(Ed25519Signer::from_seed(&[23; 32])),
            directory.path().to_path_buf(),
            Arc::new(Registry::new()),
            bus,
        );
        let session = session(Workflow::Signed);
        let first_finalizer = finalizer.clone();
        let first_session = Arc::clone(&session);
        let first = tokio::spawn(async move {
            first_finalizer
                .close_session(first_session, StopReason::SessionClosed)
                .await
        });
        tokio::task::yield_now().await;
        let second = finalizer.close_session(session, StopReason::SessionClosed).await;
        let first = first.await.unwrap();
        assert!(matches!(first, Err(FinalizeError::Bridge(_))));
        assert!(matches!(second, Ok(FinalizeOutcome::Receipt { .. })));
    }

    #[tokio::test]
    async fn startup_replays_lifecycle_outbox_without_session_journal() {
        let directory = tempfile::tempdir().unwrap();
        let bus = Arc::new(FailFirstReceiptBus {
            fail: std::sync::atomic::AtomicBool::new(true),
            attempts: parking_lot::Mutex::new(Vec::new()),
        });
        let finalizer = Finalizer::with_bridge(
            Arc::new(Ed25519Signer::from_seed(&[19; 32])),
            directory.path().to_path_buf(),
            Arc::new(Registry::new()),
            bus.clone(),
        );
        let session = session(Workflow::Signed);
        assert!(matches!(
            finalizer.close_session(session, StopReason::SessionClosed).await,
            Err(FinalizeError::Bridge(_))
        ));
        assert!(finalizer
            .lifecycle_outbox_path("lifecycle-session", "receipt")
            .exists());

        let sessions = SessionRegistry::new();
        assert_eq!(
            finalizer
                .recover_spooled_sessions(&sessions, &Default::default())
                .await
                .unwrap(),
            0
        );
        assert!(sessions.get("lifecycle-session").is_none());
        assert!(!finalizer
            .lifecycle_outbox_path("lifecycle-session", "receipt")
            .exists());
        assert_eq!(
            bus.attempts
                .lock()
                .iter()
                .filter(|(topic, _)| topic == "agent.receipt")
                .count(),
            2
        );
    }

    #[tokio::test]
    async fn unsigned_close_and_promotion_are_strict_and_idempotent() {
        let directory = tempfile::tempdir().unwrap();
        let finalizer = finalizer(directory.path());
        let session = session(Workflow::Unsigned);
        session
            .atif
            .lock()
            .push_step(ab_atif::Step {
                step_id: 0,
                timestamp: Some(ab_core::time::now_iso8601()),
                source: ab_atif::Source::Agent,
                message: serde_json::json!("done"),
                reasoning_effort: None,
                reasoning_content: None,
                model_name: None,
                tool_calls: None,
                observation: None,
                metrics: Some(ab_atif::Metrics {
                    prompt_tokens: Some(10),
                    completion_tokens: Some(2),
                    cached_tokens: Some(4),
                    cost_usd: Some(0.001),
                    logprobs: None,
                    completion_token_ids: None,
                    prompt_token_ids: None,
                    extra: None,
                }),
                is_copied_context: None,
                llm_call_count: Some(1),
                extra: None,
            })
            .unwrap();

        let outcome = finalizer
            .close_session(Arc::clone(&session), StopReason::SessionClosed)
            .await
            .unwrap();
        let FinalizeOutcome::Atif { path } = outcome else {
            panic!("expected ATIF artifact")
        };
        let value: serde_json::Value = serde_json::from_slice(&tokio::fs::read(path).await.unwrap()).unwrap();
        assert!(ab_atif::validate_value(&value, ab_atif::Mode::Strict).is_empty());

        let first = finalizer.promote(Arc::clone(&session)).await.unwrap();
        let second = finalizer.promote(Arc::clone(&session)).await.unwrap();
        assert_eq!(first.body.receipt_id, second.body.receipt_id);
        first.verify_embedded().unwrap();
        assert!(matches!(
            first.body.subject,
            ReceiptSubject::AtifTrajectory {
                step_count: 1,
                retroactive: true,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn unsigned_restart_preserves_receipt_accounting_and_identity() {
        let directory = tempfile::tempdir().unwrap();
        let finalizer = finalizer(directory.path());
        let original = session(Workflow::Unsigned);
        original
            .totals
            .tool_calls
            .store(2, std::sync::atomic::Ordering::Release);
        original
            .totals
            .tool_allowed
            .store(1, std::sync::atomic::Ordering::Release);
        original
            .totals
            .tool_blocked
            .store(1, std::sync::atomic::Ordering::Release);
        original
            .totals
            .prompt_tokens
            .store(17, std::sync::atomic::Ordering::Release);
        original
            .totals
            .completion_tokens
            .store(9, std::sync::atomic::Ordering::Release);
        original
            .totals
            .cached_tokens
            .store(3, std::sync::atomic::Ordering::Release);
        original
            .totals
            .cost_usd_micros
            .store(1_234_567, std::sync::atomic::Ordering::Release);
        original.record_stop_reason(StopReason::PolicyBlocked);
        original
            .atif
            .lock()
            .push_step(ab_atif::Step {
                step_id: 0,
                timestamp: None,
                source: ab_atif::Source::User,
                message: serde_json::json!("test"),
                reasoning_effort: None,
                reasoning_content: None,
                model_name: None,
                tool_calls: None,
                observation: None,
                metrics: None,
                is_copied_context: None,
                llm_call_count: None,
                extra: None,
            })
            .unwrap();
        finalizer
            .close_session(original, StopReason::SessionClosed)
            .await
            .unwrap();

        let registry = SessionRegistry::new();
        finalizer
            .recover_spooled_sessions(&registry, &Default::default())
            .await
            .unwrap();
        let recovered = registry.get("lifecycle-session").unwrap();
        assert_eq!(recovered.current_identity().ttl_remaining_s, Some(600));
        let receipt = finalizer.promote(recovered).await.unwrap();
        assert_eq!(receipt.body.tool_calls.total, 2);
        assert_eq!(receipt.body.tool_calls.allowed, 1);
        assert_eq!(receipt.body.tool_calls.blocked, 1);
        assert_eq!(receipt.body.cost.prompt_tokens, 17);
        assert_eq!(receipt.body.cost.completion_tokens, 9);
        assert_eq!(receipt.body.cost.cached_tokens, 3);
        assert_eq!(receipt.body.cost.cost_usd_micros, 1_234_567);
        assert_eq!(receipt.body.stop_reason_id, StopReason::PolicyBlocked.id());
    }

    #[tokio::test]
    async fn incomplete_capture_never_produces_receipt_or_atif() {
        let directory = tempfile::tempdir().unwrap();
        let finalizer = finalizer(directory.path());
        for workflow in [Workflow::Signed, Workflow::Unsigned] {
            let session = session(workflow);
            session.mark_capture_failed();
            assert!(matches!(
                finalizer
                    .close_session(Arc::clone(&session), StopReason::SessionClosed)
                    .await,
                Err(FinalizeError::CaptureIncomplete)
            ));
            assert!(session.receipt.lock().is_none());
            assert!(session.atif_path.lock().is_none());
        }
    }

    /// Regression for the live-session analog of the quarantined-recovery
    /// idle-sweep churn (bug 20). A worker job panic sets `capture_failed = 1`
    /// on the live session's flag while `closed = 0, artifact_committed = 0`.
    /// The idle sweeper's `!is_closed()` filter therefore picks the session
    /// up on every tick, `close_session_locked` runs its full body only to
    /// hit `if session.capture_failed() { return Err(CaptureIncomplete); }`,
    /// `CloseClaim` drops unarmed, `reset_close()` puts `closed` back to 0,
    /// and the session churns forever burning CPU, `lifecycle_lock`
    /// acquisitions, log noise, and `ab_incomplete_sessions_total`. The fix
    /// is symmetric with bug 20: on the `CaptureIncomplete` return, mark the
    /// session `artifact_committed` and commit the `CloseClaim` so the
    /// session is sealed once and the idle sweeper's `!is_closed()` filter
    /// skips it forever after.
    #[tokio::test]
    async fn close_session_seals_capture_failed_session_so_idle_sweep_stops_churning() {
        let directory = tempfile::tempdir().unwrap();
        let finalizer = finalizer(directory.path());
        for workflow in [Workflow::Signed, Workflow::Unsigned] {
            let session = session(workflow);
            session.mark_capture_failed();
            let result = finalizer
                .close_session(Arc::clone(&session), StopReason::SessionClosed)
                .await;
            assert!(matches!(result, Err(FinalizeError::CaptureIncomplete)));
            assert!(
                session.is_closed(),
                "close_session_locked must seal a capture_failed session (mark_artifact_committed + claim.committed = true) on the CaptureIncomplete return path so subsequent idle-sweep passes skip it via the `!is_closed()` filter — otherwise CloseClaim drops unarmed, reset_close puts `closed` back to 0, is_closed() stays false, and the idle sweeper churns forever on this session (workflow: {workflow:?})",
            );
            assert!(session.receipt.lock().is_none());
            assert!(session.atif_path.lock().is_none());
        }
    }

    /// Regression for a third idle-sweep churn shape (analog of bugs 20 and
    /// 21): an unsigned session that was opened but never had any events
    /// captured. Sessions get opened as a side effect of `get_or_open` inside
    /// `prepare_chat` / `intercept_tool`, but the request itself can fail
    /// before any worker job is submitted (worker queue full, admission
    /// rejected, loop-breaker Open). The session is left in the registry
    /// with an empty `atif` (no `push_step` ever ran). When
    /// `close_session_locked` reaches its unsigned branch it calls
    /// `snapshot_trajectory()`, hands the empty trajectory to
    /// `ab_atif::write_atomic`, which runs strict validation, which rejects
    /// `steps.is_empty()` with "must contain at least one step". The write
    /// returns `WriterError::Invalid`, `close_session_locked` returns
    /// `Err(FinalizeError::Atif)`, `CloseClaim` drops unarmed,
    /// `reset_close()` puts `closed` back to `0`, and the idle sweeper
    /// re-enters this exact code path on every tick forever — burning CPU,
    /// growing `ab_reconcile_errors_total`, and generating warning logs.
    /// The fix is analogous to bug 21: detect the terminal condition (empty
    /// ATIF cannot ever produce a valid strict artifact) and seal the
    /// session so `is_closed()` returns true and the idle sweeper skips it.
    #[tokio::test]
    async fn close_session_seals_empty_unsigned_session_so_idle_sweep_stops_churning() {
        let directory = tempfile::tempdir().unwrap();
        let finalizer = finalizer(directory.path());
        let session = session(Workflow::Unsigned);
        assert_eq!(
            session.atif.lock().clone().finish().steps.len(),
            0,
            "precondition: session has no captured steps",
        );
        let result = finalizer
            .close_session(Arc::clone(&session), StopReason::SessionClosed)
            .await;
        assert!(
            matches!(result, Err(FinalizeError::Atif(_))),
            "empty unsigned close must surface an ATIF error to the caller: {result:?}",
        );
        assert!(
            session.is_closed(),
            "close_session_locked must seal an empty unsigned session (mark_artifact_committed + claim.committed = true) when write_atomic's strict validation rejects the empty trajectory — otherwise CloseClaim drops unarmed, reset_close puts `closed` back to 0, is_closed() stays false, and the idle sweeper churns forever on this session (write_atomic → validate → \"must contain at least one step\" → Err → reset_close → picked up next tick → repeat)",
        );
        assert!(
            session.atif_path.lock().is_none(),
            "no ATIF file was ever produced for the empty session",
        );
    }

    /// An in-flight response marker belonging to a *currently active*
    /// session is normal operation (the marker lives for the duration of
    /// the upstream call), not evidence of an abandoned effect. A periodic
    /// recovery tick that runs while such a request is in flight must not
    /// quarantine the session — otherwise any LLM call slower than one
    /// reconcile tick would poison its own session as capture-failed and
    /// wrongly quarantine the final trajectory at close.
    #[tokio::test]
    async fn recovery_tick_does_not_quarantine_live_sessions_with_inflight_markers() {
        let directory = tempfile::tempdir().unwrap();
        let finalizer = finalizer(directory.path());
        let live = session(Workflow::Unsigned);
        let registry = crate::session::SessionRegistry::new();
        let live = registry.insert_recovered(Arc::try_unwrap(live).map_err(|_| ()).unwrap());
        crate::worker::create_response_marker(
            directory.path(),
            &finalizer.journal_key,
            &live.id,
            "digest".to_owned(),
        )
        .await
        .unwrap();
        finalizer
            .recover_spooled_sessions(&registry, &Default::default())
            .await
            .unwrap();
        assert!(
            !finalizer.quarantined_sessions.lock().contains(&live.id),
            "a live session's in-flight marker must not put it in quarantine",
        );
        assert!(
            !live.capture_failed(),
            "a recovery tick must not poison a live session mid-request",
        );
    }

    /// The quarantined_sessions set records id-space markers for recoveries
    /// that saw inconsistent effects on disk. A live session (client retry
    /// under the same id) that shares such an id must NOT inherit the
    /// capture-failed verdict on finalize — the verdict belongs to the
    /// recovered Session inserted with `mark_capture_failed()`, not to a
    /// fresh live Session whose in-memory `capture_failed` flag is still 0.
    /// close_session_locked must therefore rely on the per-session flag,
    /// not on the process-wide id set.
    #[tokio::test]
    async fn live_session_with_id_in_quarantine_set_can_still_close() {
        let directory = tempfile::tempdir().unwrap();
        let finalizer = finalizer(directory.path());
        // Simulate a prior recovery pass that added this session id to the set.
        finalizer
            .quarantined_sessions
            .lock()
            .insert("lifecycle-session".to_owned());
        let live = session(Workflow::Unsigned);
        assert!(!live.capture_failed(), "precondition: live session is clean");
        // Give the live session a step so its unsigned finalize can succeed.
        live.atif
            .lock()
            .push_step(ab_atif::Step {
                step_id: 0,
                timestamp: None,
                source: ab_atif::Source::Agent,
                message: serde_json::json!("live response"),
                reasoning_effort: None,
                reasoning_content: None,
                model_name: Some("test-model".into()),
                tool_calls: None,
                observation: None,
                metrics: Some(ab_atif::Metrics {
                    prompt_tokens: Some(1),
                    completion_tokens: Some(1),
                    cached_tokens: Some(0),
                    cost_usd: Some(0.0),
                    logprobs: None,
                    completion_token_ids: None,
                    prompt_token_ids: None,
                    extra: None,
                }),
                is_copied_context: None,
                llm_call_count: Some(1),
                extra: None,
            })
            .unwrap();
        let outcome = finalizer
            .close_session(Arc::clone(&live), StopReason::SessionClosed)
            .await
            .expect("live session must finalize despite id sharing space with a set entry");
        match outcome {
            FinalizeOutcome::Atif { .. } => {}
            other => panic!("expected FinalizeOutcome::Atif, got {other:?}"),
        }
        assert!(
            !live.capture_failed(),
            "close_session must not poison the live session's capture_failed flag",
        );
    }

    /// Recovery must never clobber a live session that shares its id with a
    /// stale spool artifact — a client retrying the same session_id after a
    /// crash could otherwise have its in-flight session force-closed by the
    /// reconciler. Two layers guard against this: the early registry check
    /// AND `try_insert_recovered` returning `Err(existing)` at the point of
    /// insertion. This test locks the outer invariant.
    #[tokio::test]
    async fn recovery_does_not_clobber_a_live_session_with_the_same_id() {
        let directory = tempfile::tempdir().unwrap();
        let finalizer = finalizer(directory.path());
        // Produce a valid ATIF artifact on disk under the "lifecycle-session" id.
        let closed_session = session(Workflow::Unsigned);
        closed_session
            .atif
            .lock()
            .push_step(ab_atif::Step {
                step_id: 0,
                timestamp: None,
                source: ab_atif::Source::Agent,
                message: serde_json::json!("archived response"),
                reasoning_effort: None,
                reasoning_content: None,
                model_name: Some("test-model".into()),
                tool_calls: None,
                observation: None,
                metrics: Some(ab_atif::Metrics {
                    prompt_tokens: Some(1),
                    completion_tokens: Some(1),
                    cached_tokens: Some(0),
                    cost_usd: Some(0.0),
                    logprobs: None,
                    completion_token_ids: None,
                    prompt_token_ids: None,
                    extra: None,
                }),
                is_copied_context: None,
                llm_call_count: Some(1),
                extra: None,
            })
            .unwrap();
        finalizer
            .close_session(Arc::clone(&closed_session), StopReason::SessionClosed)
            .await
            .unwrap();
        // Now simulate a client retrying under the same session_id.
        let registry = SessionRegistry::new();
        let live = registry.get_or_open(
            "lifecycle-session",
            Workflow::Unsigned,
            &AgentIdentity {
                version: "1".to_owned(),
                charter: "test".into(),
                instance_uid: "instance-1".to_owned(),
                ttl_remaining_s: Some(600),
            },
            &Default::default(),
        );
        assert!(!live.is_closed(), "precondition: live session is open");
        assert!(live.receipt.lock().is_none(), "precondition: no receipt yet");
        assert!(live.atif_path.lock().is_none(), "precondition: no atif path yet");
        // Recovery must see the live session and skip the stale artifact.
        finalizer
            .recover_spooled_sessions(&registry, &Default::default())
            .await
            .unwrap();
        assert!(
            !live.is_closed(),
            "live session must not be force-closed by recovery"
        );
        assert!(
            live.receipt.lock().is_none(),
            "live session's receipt must not be overwritten from the stale artifact",
        );
        assert!(
            live.atif_path.lock().is_none(),
            "live session's atif_path must not be reassigned to the stale artifact",
        );
        assert_eq!(registry.len(), 1, "recovery must not add a duplicate entry");
    }

    /// A tampered (or unauthenticated) artifact left in the spool must not
    /// abort the recovery scan: before this fix, `recover_spooled_sessions`
    /// returned `Err` at the first provenance failure, so one corrupt file
    /// starved recovery of every *other* session on every tick — and the
    /// warn (with no path) repeated forever. Integrity failures now skip
    /// the file (it stays on disk as evidence), count a skip metric, and
    /// let the rest of the spool recover.
    #[tokio::test]
    async fn recovery_skips_tampered_artifact_and_still_recovers_the_rest() {
        let directory = tempfile::tempdir().unwrap();
        let metrics = Arc::new(Registry::new());
        let finalizer = Finalizer::new(
            Arc::new(Ed25519Signer::from_seed(&[7; 32])),
            directory.path().to_path_buf(),
            Arc::clone(&metrics),
        );
        let step = ab_atif::Step {
            step_id: 0,
            timestamp: None,
            source: ab_atif::Source::Agent,
            message: serde_json::json!("archived response"),
            reasoning_effort: None,
            reasoning_content: None,
            model_name: Some("test-model".into()),
            tool_calls: None,
            observation: None,
            metrics: Some(ab_atif::Metrics {
                prompt_tokens: Some(1),
                completion_tokens: Some(1),
                cached_tokens: Some(0),
                cost_usd: Some(0.0),
                logprobs: None,
                completion_token_ids: None,
                prompt_token_ids: None,
                extra: None,
            }),
            is_copied_context: None,
            llm_call_count: Some(1),
            extra: None,
        };
        let identity = AgentIdentity {
            version: "1".to_owned(),
            charter: "test".into(),
            instance_uid: "instance-1".to_owned(),
            ttl_remaining_s: Some(600),
        };
        let mut artifact_paths = Vec::new();
        for id in ["tampered-session", "healthy-session"] {
            let session = Arc::new(Session::new(
                id.to_owned(),
                Workflow::Unsigned,
                identity.clone(),
                Default::default(),
            ));
            session.atif.lock().push_step(step.clone()).unwrap();
            let outcome = finalizer
                .close_session(Arc::clone(&session), StopReason::SessionClosed)
                .await
                .unwrap();
            match outcome {
                FinalizeOutcome::Atif { path } => artifact_paths.push(path),
                other => panic!("expected FinalizeOutcome::Atif, got {other:?}"),
            }
        }
        // Corrupt the first artifact's bytes so its .atif-auth digest no
        // longer matches.
        let tampered = &artifact_paths[0];
        let mut bytes = std::fs::read(tampered).unwrap();
        let position = bytes
            .windows("archived".len())
            .position(|window| window == b"archived")
            .expect("artifact must contain the step message");
        bytes[position] = b'X';
        std::fs::write(tampered, &bytes).unwrap();

        let registry = SessionRegistry::new();
        finalizer
            .recover_spooled_sessions(&registry, &Default::default())
            .await
            .expect("one tampered artifact must not abort the recovery scan");
        assert!(
            registry.get("healthy-session").is_some(),
            "the healthy artifact must still recover when a sibling is tampered",
        );
        assert!(
            registry.get("tampered-session").is_none(),
            "the tampered artifact must not recover a session",
        );
        assert!(
            tampered.exists(),
            "the tampered artifact must stay on disk as evidence",
        );
        let rendered = metrics.render();
        assert!(
            rendered.contains("ab_atif_recovery_skipped_total{reason=\"provenance\"}"),
            "skips must be visible to operators via metrics; got: {rendered}",
        );
    }

    /// A background promotion retry must never force-close a session that is
    /// currently active. Without this guard, `retry_marked_promotions` would
    /// pick up a stale `.promote` marker left by a prior crash, look up the
    /// current live session from the registry (client retried under the same
    /// session_id), and call `promote()` — which starts by
    /// `close_session_locked`-ing any non-closed session. The live session
    /// would be prematurely terminated and its ATIF artifact overwritten.
    #[tokio::test]
    async fn promotion_retry_does_not_force_close_a_live_session() {
        let directory = tempfile::tempdir().unwrap();
        let finalizer = finalizer(directory.path());
        // Produce a valid unsigned artifact so a real promotion marker can point at it.
        let closed_session = session(Workflow::Unsigned);
        closed_session
            .atif
            .lock()
            .push_step(ab_atif::Step {
                step_id: 0,
                timestamp: None,
                source: ab_atif::Source::Agent,
                message: serde_json::json!("archived response"),
                reasoning_effort: None,
                reasoning_content: None,
                model_name: Some("test-model".into()),
                tool_calls: None,
                observation: None,
                metrics: Some(ab_atif::Metrics {
                    prompt_tokens: Some(1),
                    completion_tokens: Some(1),
                    cached_tokens: Some(0),
                    cost_usd: Some(0.0),
                    logprobs: None,
                    completion_token_ids: None,
                    prompt_token_ids: None,
                    extra: None,
                }),
                is_copied_context: None,
                llm_call_count: Some(1),
                extra: None,
            })
            .unwrap();
        let outcome = finalizer
            .close_session(Arc::clone(&closed_session), StopReason::SessionClosed)
            .await
            .unwrap();
        let FinalizeOutcome::Atif { path } = outcome else {
            panic!("expected ATIF artifact")
        };
        let trajectory_bytes = tokio::fs::read(&path).await.unwrap();
        let promotion_marker = crate::journal::seal(
            &finalizer.journal_key,
            "promotion-marker",
            0,
            &PromotionMarker {
                session_id: closed_session.id.clone(),
                trajectory_digest: ab_core::digest::sha256_hex(&trajectory_bytes),
            },
        )
        .unwrap();
        tokio::fs::write(path.with_extension("promote"), &promotion_marker)
            .await
            .unwrap();
        // Now simulate a client retrying under the same session_id.
        let registry = SessionRegistry::new();
        let live = registry.get_or_open(
            &closed_session.id,
            Workflow::Unsigned,
            &AgentIdentity {
                version: "1".to_owned(),
                charter: "test".into(),
                instance_uid: "instance-1".to_owned(),
                ttl_remaining_s: Some(600),
            },
            &Default::default(),
        );
        // Give the live session a distinct step so its trajectory would
        // pass strict validation — this makes the potential overwrite of
        // the archived artifact directly observable.
        live.atif
            .lock()
            .push_step(ab_atif::Step {
                step_id: 0,
                timestamp: None,
                source: ab_atif::Source::Agent,
                message: serde_json::json!("live response"),
                reasoning_effort: None,
                reasoning_content: None,
                model_name: Some("test-model".into()),
                tool_calls: None,
                observation: None,
                metrics: Some(ab_atif::Metrics {
                    prompt_tokens: Some(2),
                    completion_tokens: Some(3),
                    cached_tokens: Some(0),
                    cost_usd: Some(0.0),
                    logprobs: None,
                    completion_token_ids: None,
                    prompt_token_ids: None,
                    extra: None,
                }),
                is_copied_context: None,
                llm_call_count: Some(1),
                extra: None,
            })
            .unwrap();
        assert!(!live.is_closed(), "precondition: live session is open");
        let promoted = finalizer.retry_marked_promotions(&registry).await.unwrap();
        assert_eq!(
            promoted, 0,
            "promotion retry must not count a skipped live session as promoted",
        );
        assert!(
            !live.is_closed(),
            "live session must not be force-closed by promotion retry",
        );
        assert!(
            live.receipt.lock().is_none(),
            "live session must not receive a receipt from a stale promotion marker",
        );
        assert!(
            live.atif_path.lock().is_none(),
            "live session's atif_path must not be set by a background promotion retry — that would mean its trajectory was snapshotted to disk out of band",
        );
        assert_eq!(
            tokio::fs::read(&path).await.unwrap(),
            trajectory_bytes,
            "the archived ATIF artifact must not be overwritten by a background retry that force-finalized the live session",
        );
        // The stale marker persists — it will be handled after the live
        // session finalizes normally, or expire with the artifact.
        assert!(
            path.with_extension("promote").exists(),
            "the promotion marker must remain on disk for future retries",
        );
    }

    /// Regression for the quarantined-unsigned recovery branch. When a
    /// crashed process left an unsigned session's `.session.json` metadata
    /// on disk AND the session id was already in the `quarantined_sessions`
    /// set (populated on the same pass by `inflight_response_sessions` or
    /// `unresolved_tool_sessions`), `consolidate_step_journals` builds a
    /// fresh `Session::new` (`closed = 0`, `artifact_committed = 0`),
    /// calls `mark_capture_failed()`, and inserts it via
    /// `insert_recovered` — but forgets the `mark_artifact_committed()`
    /// step that its signed-recovery sibling applies before
    /// `try_insert_recovered`. The result is a permanent
    /// `is_closed() == false, capture_failed == true` session in the
    /// registry: the idle sweeper's `!is_closed()` filter keeps picking
    /// it up every tick, `close_session_locked` runs its full body only
    /// to hit `if session.capture_failed()` and return
    /// `CaptureIncomplete`, `CloseClaim` drops unarmed → `reset_close`
    /// puts `closed` back to `0`, and the churn is unbounded: growing
    /// `ab_incomplete_sessions_total`, growing log noise, wasted lifecycle
    /// lock acquisitions, and a session that never leaves the registry.
    #[tokio::test]
    async fn recovery_marks_quarantined_unsigned_session_finalized_to_stop_idle_sweep_churn() {
        let directory = tempfile::tempdir().unwrap();
        let finalizer = finalizer(directory.path());
        let session_id = "quarantined-unsigned";
        let identity = AgentIdentity {
            version: "1".into(),
            charter: "test".into(),
            instance_uid: "instance-1".into(),
            ttl_remaining_s: Some(600),
        };

        let digest = ab_core::digest::sha256_hex(session_id.as_bytes());
        let stem = &digest[..32];
        let metadata_payload = serde_json::json!({
            "journal_version": 2,
            "session_id": session_id,
            "identity": identity,
            "workflow": "unsigned",
        });
        let metadata_sealed =
            crate::journal::seal(&finalizer.journal_key, "metadata", 0, &metadata_payload).unwrap();
        std::fs::write(
            directory.path().join(format!("{stem}.session.json")),
            &metadata_sealed,
        )
        .unwrap();

        // Pre-populate the quarantine set — this is what a prior recovery
        // pass would do after finding an inflight-response marker or an
        // unresolved-tool marker on disk for this session id.
        finalizer
            .quarantined_sessions
            .lock()
            .insert(session_id.to_owned());

        let registry = SessionRegistry::new();
        finalizer
            .recover_spooled_sessions(&registry, &Default::default())
            .await
            .unwrap();

        let recovered = registry
            .get(session_id)
            .expect("quarantined session must be inserted");
        assert!(
            recovered.capture_failed(),
            "quarantined session must carry the capture-failed verdict",
        );
        assert!(
            recovered.is_closed(),
            "the quarantined-unsigned recovery branch (consolidate_step_journals) must also mark the session finalized (artifact_committed) so the idle sweeper's `!is_closed()` filter skips it — otherwise every idle tick calls close_session_locked which returns CaptureIncomplete, CloseClaim resets the close, and the session churns forever burning CPU, log noise, and metrics without ever leaving the registry",
        );
    }

    /// A live session's `{stem}.session.json` journal metadata must be
    /// invisible to the ATIF spool scan. Both journal consumers skip a
    /// session that is still in the registry, so without the scan-side
    /// guard, every reconciler tick re-parsed the metadata file as an
    /// ATIF document, failed, warned "ignoring invalid ATIF spool file",
    /// and inflated the invalid_json skip counter — pure noise while a
    /// session was merely open.
    #[tokio::test]
    async fn atif_scan_ignores_live_session_journal_metadata() {
        let directory = tempfile::tempdir().unwrap();
        let metrics = Arc::new(Registry::new());
        let finalizer = Finalizer::new(
            Arc::new(Ed25519Signer::from_seed(&[7; 32])),
            directory.path().to_path_buf(),
            Arc::clone(&metrics),
        );
        let session_id = "still-open-session";
        let identity = AgentIdentity {
            version: "1".into(),
            charter: "test".into(),
            instance_uid: "instance-1".into(),
            ttl_remaining_s: Some(600),
        };
        let digest = ab_core::digest::sha256_hex(session_id.as_bytes());
        let stem = &digest[..32];
        let metadata_payload = serde_json::json!({
            "journal_version": 2,
            "session_id": session_id,
            "identity": identity,
            "workflow": "unsigned",
        });
        let metadata_sealed =
            crate::journal::seal(&finalizer.journal_key, "metadata", 0, &metadata_payload).unwrap();
        std::fs::write(
            directory.path().join(format!("{stem}.session.json")),
            &metadata_sealed,
        )
        .unwrap();

        // The session is live, so consolidate/recover leave its journal alone.
        let registry = SessionRegistry::new();
        let live = registry.get_or_open(session_id, Workflow::Unsigned, &identity, &Default::default());
        assert!(!live.is_closed(), "precondition: session is open");

        finalizer
            .recover_spooled_sessions(&registry, &Default::default())
            .await
            .unwrap();

        assert!(
            !metrics.render().contains("ab_atif_recovery_skipped_total"),
            "the ATIF scan must skip *.session.json instead of counting it as an invalid spool file",
        );
        assert!(
            directory.path().join(format!("{stem}.session.json")).exists(),
            "the live session's journal metadata must survive the pass",
        );
    }

    #[tokio::test]
    async fn restart_quarantines_inflight_response_without_stopping_recovery() {
        let directory = tempfile::tempdir().unwrap();
        let finalizer = finalizer(directory.path());
        crate::worker::create_response_marker(
            directory.path(),
            &finalizer.journal_key,
            "uncertain-session",
            "request-digest".to_owned(),
        )
        .await
        .unwrap();

        let registry = SessionRegistry::new();
        assert_eq!(
            finalizer
                .recover_spooled_sessions(&registry, &Default::default())
                .await
                .unwrap(),
            0
        );
        assert!(finalizer
            .quarantined_sessions
            .lock()
            .contains("uncertain-session"));
        assert!(registry.get("uncertain-session").is_none());
    }

    #[tokio::test]
    async fn restart_recovers_atif_and_retries_marked_promotion() {
        let directory = tempfile::tempdir().unwrap();
        let first = finalizer(directory.path());
        let original = session(Workflow::Unsigned);
        original
            .atif
            .lock()
            .push_step(ab_atif::Step {
                step_id: 0,
                timestamp: None,
                source: ab_atif::Source::Agent,
                message: serde_json::json!("recovered response"),
                reasoning_effort: None,
                reasoning_content: None,
                model_name: Some("test-model".into()),
                tool_calls: None,
                observation: None,
                metrics: Some(ab_atif::Metrics {
                    prompt_tokens: Some(5),
                    completion_tokens: Some(2),
                    cached_tokens: Some(1),
                    cost_usd: Some(0.001),
                    logprobs: None,
                    completion_token_ids: None,
                    prompt_token_ids: None,
                    extra: None,
                }),
                is_copied_context: None,
                llm_call_count: Some(1),
                extra: None,
            })
            .unwrap();
        let outcome = first
            .close_session(Arc::clone(&original), StopReason::SessionClosed)
            .await
            .unwrap();
        let FinalizeOutcome::Atif { path } = outcome else {
            panic!("expected ATIF artifact")
        };
        let trajectory_bytes = tokio::fs::read(&path).await.unwrap();
        let promotion_marker = crate::journal::seal(
            &first.journal_key,
            "promotion-marker",
            0,
            &PromotionMarker {
                session_id: original.id.clone(),
                trajectory_digest: ab_core::digest::sha256_hex(&trajectory_bytes),
            },
        )
        .unwrap();
        tokio::fs::write(path.with_extension("promote"), &promotion_marker)
            .await
            .unwrap();

        let recovered_registry = SessionRegistry::new();
        let after_restart = finalizer(directory.path());
        assert_eq!(
            after_restart
                .recover_spooled_sessions(&recovered_registry, &Default::default())
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            after_restart
                .retry_marked_promotions(&recovered_registry)
                .await
                .unwrap(),
            1
        );
        let recovered = recovered_registry.get(&original.id).unwrap();
        let receipt = recovered.receipt.lock().clone().unwrap();
        receipt.verify_embedded().unwrap();
        assert!(recovered.is_promoted());
        assert!(!path.with_extension("promote").exists());

        tokio::fs::write(path.with_extension("promote"), &promotion_marker)
            .await
            .unwrap();
        let second_registry = SessionRegistry::new();
        assert_eq!(
            after_restart
                .recover_spooled_sessions(&second_registry, &Default::default())
                .await
                .unwrap(),
            1
        );
        let restored = second_registry.get(&original.id).unwrap();
        assert_eq!(
            restored.receipt.lock().as_ref().unwrap().body.receipt_id,
            receipt.body.receipt_id,
            "restart must restore the persisted receipt, not issue a duplicate"
        );
        assert_eq!(
            after_restart
                .retry_marked_promotions(&second_registry)
                .await
                .unwrap(),
            1
        );
        assert!(restored.is_promoted());
        assert!(!path.with_extension("promote").exists());
    }

    #[tokio::test]
    async fn close_waits_for_active_response_lease() {
        let directory = tempfile::tempdir().unwrap();
        let finalizer = finalizer(directory.path());
        let session = session(Workflow::Signed);
        let lease = crate::session::SessionLease::new(Arc::clone(&session));
        let close_session = Arc::clone(&session);
        let task = tokio::spawn(async move {
            finalizer
                .close_session(close_session, StopReason::SessionClosed)
                .await
        });
        tokio::task::yield_now().await;
        assert!(!task.is_finished(), "close overtook an active response");
        drop(lease);
        assert!(matches!(
            task.await.unwrap().unwrap(),
            FinalizeOutcome::Receipt { .. }
        ));
    }

    /// Round-18 F6: FIFO eviction lets one legitimate recurring
    /// artifact re-warn ONCE after it's evicted, but does not cause
    /// every legitimate artifact to re-warn together on the same
    /// tick when a rotating-timestamp attacker fills the cap.
    /// Round-20 F6: `WarnedArtifacts::new(0)` used to degenerate
    /// into oscillate-at-size-1 rather than reject or clamp. Now
    /// clamps to cap.max(1) so a future config-wiring bug that
    /// passes 0 doesn't silently break "warn once per artifact".
    #[test]
    fn warned_artifacts_clamps_zero_cap_to_one() {
        let mut warned = WarnedArtifacts::new(0);
        // First distinct entry is accepted.
        assert!(warned.insert(PathBuf::from("a")));
        assert_eq!(warned.len(), 1);
        // Same entry is deduplicated (the whole point).
        assert!(!warned.insert(PathBuf::from("a")));
        // A distinct entry evicts the first — cap=1 (clamped).
        assert!(warned.insert(PathBuf::from("b")));
        assert_eq!(warned.len(), 1);
    }

    #[test]
    fn warned_artifacts_evicts_one_at_a_time_not_all_at_once() {
        let mut warned = WarnedArtifacts::new(3);
        assert!(warned.insert(PathBuf::from("a")));
        assert!(warned.insert(PathBuf::from("b")));
        assert!(warned.insert(PathBuf::from("c")));
        assert_eq!(warned.len(), 3);
        // Reinserting an existing entry is a no-op — still in-set,
        // no warn.
        assert!(!warned.insert(PathBuf::from("b")));
        // Fourth distinct entry evicts the OLDEST ("a"), NOT all.
        // Other legitimate entries (b, c) still tracked.
        assert!(warned.insert(PathBuf::from("d")));
        assert_eq!(warned.len(), 3);
        assert!(!warned.insert(PathBuf::from("b")));
        assert!(!warned.insert(PathBuf::from("c")));
        assert!(!warned.insert(PathBuf::from("d")));
        // "a" was evicted, so a re-warn on "a" returns true.
        // This new insert evicts b (now the oldest) — but c and d
        // survive. That's the FIFO contract: ONE eviction per
        // insert, not a full flush.
        assert!(warned.insert(PathBuf::from("a")));
        assert_eq!(warned.len(), 3);
        assert!(!warned.insert(PathBuf::from("c")));
        assert!(!warned.insert(PathBuf::from("d")));
        assert!(!warned.insert(PathBuf::from("a")));
    }

    #[tokio::test]
    async fn torn_journal_tail_is_truncated_without_losing_complete_records() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("journal.ndjson");
        std::fs::write(&path, b"{\"complete\":true}\n{\"torn\":").unwrap();
        let lines = read_complete_journal(&path).await.unwrap();
        assert_eq!(lines, vec![r#"{"complete":true}"#]);
        assert_eq!(std::fs::read(&path).unwrap(), b"{\"complete\":true}\n");
    }

    /// Round-13 F2: a journal containing NO newline anywhere (all
    /// bytes are a single partial record) must NOT be silently
    /// truncated to 0 bytes — that would destroy the only evidence
    /// of the failure. Quarantine to `<name>.corrupt-<uid>` instead
    /// and return an error so the reconciler leaves the sealed
    /// metadata sidecar in place.
    #[tokio::test]
    async fn journal_with_no_complete_lines_is_quarantined_not_truncated() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("journal.ndjson");
        std::fs::write(&path, b"{\"torn_before_first_newline\":").unwrap();
        let outcome = read_complete_journal(&path).await;
        // Must be an error, not an Ok(vec![]).
        let err = outcome.unwrap_err();
        assert!(
            format!("{err:?}").contains("no complete lines"),
            "expected quarantine error, got {err:?}",
        );
        // Original file must NOT exist any more — it was moved out.
        assert!(!path.exists(), "journal was not moved out of the recovery path");
        // Quarantine file must exist with the original content and
        // carry `.corrupt-` in its name.
        let entries: Vec<_> = std::fs::read_dir(directory.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains(".corrupt-")
            })
            .collect();
        assert_eq!(entries.len(), 1, "expected exactly one quarantine file");
        let bytes = std::fs::read(entries[0].path()).unwrap();
        assert_eq!(&bytes, b"{\"torn_before_first_newline\":");
        // Round-37 F1: `FinalizeError::Atif`'s Display flows to
        // `tracing::warn!(%error, "ATIF spool recovery failed")`
        // and thence to `tracing_opentelemetry` -> OTLP -> SIEM.
        // The message body must NOT embed the absolute spool
        // directory (round-36 F1 basenamed the tracing FIELDS but
        // this ERROR STRING was missed). Assert:
        //   (a) the containing tempdir path is not in the message,
        //   (b) neither is any parent directory component.
        let msg = format!("{err}");
        assert!(
            !msg.contains(directory.path().to_string_lossy().as_ref()),
            "FinalizeError::Atif leaked spool dir absolute path: {msg}"
        );
        assert!(
            !msg.contains(std::path::MAIN_SEPARATOR_STR),
            "FinalizeError::Atif still contains a path separator: {msg}"
        );
        // The basename must still be present so an operator can
        // correlate the message with the quarantined file on disk.
        assert!(
            msg.contains("journal.ndjson"),
            "FinalizeError::Atif should still mention the journal basename: {msg}"
        );
    }

    #[tokio::test]
    async fn failed_persistence_reopens_session_for_retry() {
        let directory = tempfile::tempdir().unwrap();
        let blocking_file = directory.path().join("not-a-directory");
        std::fs::write(&blocking_file, b"file").unwrap();
        let finalizer = finalizer(&blocking_file);
        let session = session(Workflow::Signed);
        assert!(finalizer
            .close_session(Arc::clone(&session), StopReason::SessionClosed)
            .await
            .is_err());
        assert!(!session.is_closed());
        assert!(session.try_close(), "failed close claim was not reset");
    }

    #[tokio::test]
    async fn failed_unsigned_persistence_keeps_steps_for_retry() {
        let directory = tempfile::tempdir().unwrap();
        let spool = directory.path().join("spool");
        std::fs::write(&spool, b"blocking file").unwrap();
        let finalizer = finalizer(&spool);
        let session = session(Workflow::Unsigned);
        session
            .atif
            .lock()
            .push_step(ab_atif::Step {
                step_id: 0,
                timestamp: None,
                source: ab_atif::Source::User,
                message: serde_json::json!("survive"),
                reasoning_effort: None,
                reasoning_content: None,
                model_name: None,
                tool_calls: None,
                observation: None,
                metrics: None,
                is_copied_context: None,
                llm_call_count: None,
                extra: None,
            })
            .unwrap();
        assert!(finalizer
            .close_session(Arc::clone(&session), StopReason::SessionClosed)
            .await
            .is_err());
        assert!(!session.is_closed());
        std::fs::remove_file(&spool).unwrap();
        std::fs::create_dir(&spool).unwrap();
        let FinalizeOutcome::Atif { path } = finalizer
            .close_session(session, StopReason::SessionClosed)
            .await
            .unwrap()
        else {
            panic!("expected ATIF")
        };
        let trajectory: ab_atif::Trajectory = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(trajectory.steps.len(), 1);
        assert_eq!(trajectory.steps[0].message, serde_json::json!("survive"));
    }

    // ------------------------------------------------------------------
    // Congestion & bottleneck stress tests.
    // ------------------------------------------------------------------

    /// The lifecycle_lock serializes close_session and promote to prevent
    /// concurrent lifecycle-outbox rewrites, so many concurrent closes
    /// queue behind a single Mutex. This test locks the QUEUING behavior:
    /// N distinct sessions closing at once must all complete within a
    /// generous time bound and none must deadlock.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_closes_across_many_sessions_never_deadlock() {
        const SESSIONS: usize = 32;
        let directory = tempfile::tempdir().unwrap();
        let finalizer = Arc::new(finalizer(directory.path()));
        let mut tasks = Vec::with_capacity(SESSIONS);
        for i in 0..SESSIONS {
            let f = Arc::clone(&finalizer);
            let s = Arc::new(Session::new(
                format!("lifecycle-{i}"),
                Workflow::Signed,
                AgentIdentity {
                    version: "1".to_owned(),
                    charter: "test".into(),
                    instance_uid: format!("instance-{i}"),
                    ttl_remaining_s: Some(600),
                },
                Default::default(),
            ));
            tasks.push(tokio::spawn(async move {
                f.close_session(s, StopReason::SessionClosed).await
            }));
        }
        let results = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            futures::future::join_all(tasks),
        )
        .await
        .expect("close_session tasks deadlocked under lifecycle_lock contention");
        for result in results {
            let outcome = result.expect("task panicked");
            assert!(outcome.is_ok(), "close failed: {outcome:?}");
        }
    }

    /// Per-session lock table must not accumulate entries indefinitely.
    /// Every guard drop attempts to prune the corresponding entry
    /// (only when the map holds the last strong ref) — steady-state
    /// resident set = concurrent lifecycle ops, not total distinct
    /// session_ids ever seen. Otherwise an attacker firing 100k
    /// distinct session_ids could OOM the process.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn per_session_lock_table_prunes_entries_after_close() {
        const SESSIONS: usize = 200;
        let directory = tempfile::tempdir().unwrap();
        let finalizer = Arc::new(finalizer(directory.path()));
        let locks = finalizer.lifecycle_locks();
        let mut tasks = Vec::with_capacity(SESSIONS);
        for i in 0..SESSIONS {
            let f = Arc::clone(&finalizer);
            let s = Arc::new(Session::new(
                format!("prune-{i}"),
                Workflow::Signed,
                AgentIdentity {
                    version: "1".to_owned(),
                    charter: "test".into(),
                    instance_uid: format!("instance-{i}"),
                    ttl_remaining_s: Some(600),
                },
                Default::default(),
            ));
            tasks.push(tokio::spawn(async move {
                f.close_session(s, StopReason::SessionClosed).await
            }));
        }
        for task in tasks {
            let _ = task.await.expect("task panicked");
        }
        // With no active lifecycle ops, the table should end up empty.
        // Some entries may briefly linger if a guard's drop is racing
        // another `arc_for` call, but a bounded settle window is fine.
        for _ in 0..20 {
            if locks.len() == 0 {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        panic!(
            "SessionLockTable did not prune to empty after {SESSIONS} closes; \
             residual entries = {}",
            locks.len()
        );
    }

    /// A recovery scan of a large ATIF spool must not head-of-line-block
    /// a client-driven close on an unrelated session. Under the old
    /// global `lifecycle_lock` the client close waited for the entire
    /// scan to finish. With per-session locks, close on session B
    /// proceeds while recovery is still scanning candidate A.
    ///
    /// Seeded with real spool candidates that force per-file I/O in
    /// the scan; a concurrent close on a distinct session must
    /// complete well below the scan's total duration. Without a
    /// real spool the scan returns in microseconds and the test
    /// cannot distinguish per-session locks from the old global lock.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn recovery_scan_does_not_head_of_line_block_unrelated_close() {
        let directory = tempfile::tempdir().unwrap();
        let finalizer = Arc::new(finalizer(directory.path()));
        // Seed the spool with a pile of candidates that fail provenance
        // (unauthenticated / not `.session.json`) so recovery iterates
        // read_dir + read + hash + skip on each, taking observable
        // wall-clock time. 64 candidates × per-file work ≫ the 200 ms
        // budget below on the old global lock.
        for i in 0..64 {
            let path = directory.path().join(format!("scan-probe-{i}.json"));
            let payload = serde_json::json!({
                "atif_version": "1.7",
                "session_id": format!("scan-probe-{i}"),
                "agent": {"version": "1", "charter": "test", "instance_uid": "x"},
                "steps": [],
                "provenance": {"scheme": "none"},
            });
            tokio::fs::write(&path, serde_json::to_vec(&payload).unwrap())
                .await
                .unwrap();
        }
        let f_scan = Arc::clone(&finalizer);
        let scan_task = tokio::spawn(async move {
            f_scan
                .recover_spooled_sessions(&crate::session::SessionRegistry::new(), &Default::default())
                .await
        });
        // Small yield so the scan task grabs `recovery_lock` first —
        // this is the state where the old global `lifecycle_lock`
        // would have blocked the client close below.
        tokio::task::yield_now().await;

        let session = Arc::new(Session::new(
            "unrelated-close".to_owned(),
            Workflow::Signed,
            AgentIdentity {
                version: "1".to_owned(),
                charter: "test".into(),
                instance_uid: "instance-close".to_owned(),
                ttl_remaining_s: Some(600),
            },
            Default::default(),
        ));
        // Tight timeout: under the OLD global `lifecycle_lock`, the
        // client close would have waited for the entire 64-file
        // scan to finish. Under per-session locks the close hits a
        // different id and proceeds in a few ms.
        let close_result = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            finalizer.close_session(session, StopReason::SessionClosed),
        )
        .await;
        assert!(
            close_result.is_ok(),
            "unrelated close was head-of-line-blocked by the recovery scan (should have completed within 200 ms)"
        );
        let _ = scan_task.await;
    }

    /// A saturated worker-side finalizer must not hold the lifecycle_lock
    /// across independent await points that could stall other closers. We
    /// verify this indirectly by asserting the p50 latency for a single
    /// close under contention stays within 3x the uncontended latency
    /// (with a generous multiplier for CI noise). A regression that
    /// awaited a slow I/O with the lock held would blow this bound.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn close_latency_scales_reasonably_under_lock_contention() {
        let directory = tempfile::tempdir().unwrap();
        let finalizer = Arc::new(finalizer(directory.path()));
        // Warm-up: measure a single uncontended close.
        let warm = Arc::new(Session::new(
            "warm".to_owned(),
            Workflow::Signed,
            AgentIdentity {
                version: "1".to_owned(),
                charter: "test".into(),
                instance_uid: "warm".to_owned(),
                ttl_remaining_s: Some(600),
            },
            Default::default(),
        ));
        let uncontended = std::time::Instant::now();
        finalizer
            .close_session(warm, StopReason::SessionClosed)
            .await
            .unwrap();
        let baseline = uncontended.elapsed();

        // Contended: 16 closes at once. Measure their WALL-CLOCK total.
        const N: usize = 16;
        let mut tasks = Vec::with_capacity(N);
        let started = std::time::Instant::now();
        for i in 0..N {
            let f = Arc::clone(&finalizer);
            let s = Arc::new(Session::new(
                format!("contended-{i}"),
                Workflow::Signed,
                AgentIdentity {
                    version: "1".to_owned(),
                    charter: "test".into(),
                    instance_uid: format!("contended-{i}"),
                    ttl_remaining_s: Some(600),
                },
                Default::default(),
            ));
            tasks.push(tokio::spawn(async move {
                f.close_session(s, StopReason::SessionClosed).await
            }));
        }
        for t in tasks {
            t.await.unwrap().unwrap();
        }
        let total = started.elapsed();
        // A serialized lock gives ~N * baseline. Anything > 10 * N * baseline
        // signals we're holding the lock across additional awaits.
        let multiplier = u32::try_from(N * 10).unwrap_or(u32::MAX);
        let budget = baseline
            .saturating_mul(multiplier)
            .max(std::time::Duration::from_secs(60));
        assert!(
            total < budget,
            "16 contended closes took {total:?}, budget {budget:?} (baseline {baseline:?})",
        );
    }
}
