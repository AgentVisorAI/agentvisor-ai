//! Session finalization and periodic idle reconciliation.

use crate::session::{Session, SessionRegistry, Workflow};
use av_bridge::EventBus;
use av_core::metrics::Registry;
use av_core::time::elapsed_us;
use av_events::StopReason;
use av_receipts::{Receipt, ReceiptSubject, Signer};
use serde::Serialize;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

/// Classification bound for the recovery scan's `too_large` skip metric:
/// files above this are refused up front without any read attempt. The
/// effective buffering cap is the smaller `fsutil::MAX_ATIF_BYTES`
/// (64 MiB) enforced by `read_capped_async` at the read site — a file
/// between the two bounds passes this gate but fails the capped read
/// (`reason="read_error"`); nothing larger than 64 MiB is ever buffered,
/// so an attacker-crafted multi-gigabyte trajectory cannot force
/// recovery to OOM.
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
    /// Round-28 F1: lifecycle bridge failed due to a PERMANENT
    /// misconfiguration (e.g. `BusError::UnknownTopic` — the topic
    /// was not provisioned via the manifest). SDKs should NOT
    /// retry this; the operator must fix the config. Historically
    /// this collapsed into `Bridge(_)` and mapped to HTTP 503 +
    /// `Retry-After`, so clients retried pointlessly. Kept as a
    /// distinct variant so `finalize_error_response` can route it
    /// to 400 (no Retry-After) while genuine transient failures
    /// keep 503 semantics.
    #[error("lifecycle event publication failed (permanent): {0}")]
    BridgeConfig(String),
}

impl From<av_bridge::BusError> for FinalizeError {
    /// Round-28 F1: preserve the permanence classification when
    /// converting a bridge error into a Finalize error. Permanent
    /// causes (unknown topic, serde) route to `BridgeConfig` so
    /// clients see a 4xx status without `Retry-After`; transient
    /// causes (I/O, backend outage) stay `Bridge` and keep 503
    /// with `Retry-After`.
    fn from(error: av_bridge::BusError) -> Self {
        if error.is_permanent() {
            Self::BridgeConfig(error.to_string())
        } else {
            Self::Bridge(error.to_string())
        }
    }
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
    state_store: Option<Arc<dyn av_state::StateStore>>,
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
    /// Round-6 (hunt4 R-F4): best-effort vector-store cleanup at close.
    /// Optional because lifecycle tests construct a Finalizer without one.
    vector_sink: Option<Arc<dyn av_loopdetect::VectorSink>>,
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
    ack: Option<av_bridge::PublishAck>,
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

/// Durable "the close tail finished" record for Unsigned sessions.
///
/// `mark_close_complete` is in-memory only, and finalized Unsigned
/// sessions leave their ATIF + `.atif-auth` in the spool forever (they
/// are never evicted), so on restart the recovery scan cannot tell a
/// finished close from one that crashed mid-tail — the pending-close
/// sweep then re-emitted a SESSION_CLOSE bridge event with a freshly
/// minted `metadata.uid` (the original outbox and its UID are gone by
/// then), duplicating the close on the bus once per restart per
/// finalized Unsigned session. Absence-of-residue inference is NOT a
/// sound substitute: `consolidate_step_journals` also removes step
/// journals for sessions that crashed while still open (whose close
/// was never published), leaving the same "nothing on disk" shape.
///
/// The marker is sealed under its own MAC domain and bound to the
/// artifact digest so a recycled session id's new incarnation (whose
/// conflicting ATIF gets archived) can never inherit a stale marker.
/// Written only after the SESSION_CLOSE emit + outbox removal succeed;
/// a marker write failure degrades to the historical at-most-one
/// duplicate-per-restart, warned loudly.
#[derive(serde::Serialize, serde::Deserialize)]
struct CloseCompleteMarker {
    session_id: String,
    digest: String,
}

const CLOSE_COMPLETE_DOMAIN: &str = "unsigned-close-complete";

fn close_complete_marker_path(atif_path: &std::path::Path) -> std::path::PathBuf {
    atif_path.with_extension("close-complete")
}

impl Drop for CloseClaim<'_> {
    fn drop(&mut self) {
        if !self.committed {
            self.session.reset_close();
        }
    }
}

/// RAII owner of the promotion claim taken by `try_promote`.
///
/// `promote()` awaits several fallible operations between claiming and
/// committing. The explicit error arms used to call `reset_promotion()`
/// by hand — but the /promote request future is dropped wholesale when
/// the client disconnects (axum cancels handler futures), running NONE
/// of those arms. The claim then stayed at 1 forever: every subsequent
/// promotion attempt hit `try_promote() == false` and returned
/// "promotion is already in progress" (409) with no recovery path short
/// of a restart. Mirror `CloseClaim`: reset on drop unless committed.
struct PromotionClaim<'a> {
    session: &'a Session,
    committed: bool,
}

impl Drop for PromotionClaim<'_> {
    fn drop(&mut self) {
        if !self.committed {
            self.session.reset_promotion();
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
            warned_artifacts: Arc::new(parking_lot::Mutex::new(WarnedArtifacts::new(
                WARNED_ARTIFACTS_CAP,
            ))),
            journal_key,
            vector_sink: None,
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
            warned_artifacts: Arc::new(parking_lot::Mutex::new(WarnedArtifacts::new(
                WARNED_ARTIFACTS_CAP,
            ))),
            journal_key,
            vector_sink: None,
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
    pub fn with_state_store(mut self, store: Arc<dyn av_state::StateStore>) -> Self {
        self.state_store = Some(store);
        self
    }

    /// Round-6 (hunt4 R-F4): attach the vector sink so a session close
    /// can delete its Qdrant points (best-effort — errors are logged,
    /// never surfaced into the close outcome).
    pub fn with_vector_sink(mut self, sink: Arc<dyn av_loopdetect::VectorSink>) -> Self {
        self.vector_sink = Some(sink);
        self
    }

    /// Drop a sealed session's budget counters. Two reasons, both load-
    /// bearing: (a) leaving them grows the state store by a few cells per
    /// session forever (attacker-chosen session ids make that unbounded);
    /// (b) `SessionRegistry::get_or_open` recycles a finalized session id
    /// into a fresh open session that spends against the same keys, so a
    /// stale counter would bill the new incarnation for the old one's
    /// spend (see `RedisStore::remove_prefix` for the backend parity
    /// history).
    fn clear_budget_state(&self, session_id: &str) {
        if let Some(store) = self.state_store.as_deref() {
            store.remove_prefix(&av_state::ActionBudget::session_prefix(session_id));
        }
    }

    /// Close exactly once. Receipt signing and ATIF serialization never run on
    /// the request hot path.
    #[tracing::instrument(
        name = "agentvisor.session.close",
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
                    "av_incomplete_sessions_total",
                    "Sessions refused due to incomplete capture",
                )
                .inc();
            // Seal the session finalized so the idle sweeper's `!is_closed()`
            // filter skips it — otherwise CloseClaim resets `closed` to 0 and
            // this branch retries on every idle tick forever.
            session.mark_artifact_committed();
            claim.committed = true;
            self.clear_budget_state(&session.id);
            // Round-6 (hunt4 R-F3): move this session's tool-execution
            // triples out of the scanned namespace — they can never
            // resolve now, and leaving them meant every reconciler tick
            // re-read + re-MAC-verified them forever.
            self.quarantine_tool_executions(&session.id).await;
            return Err(FinalizeError::CaptureIncomplete);
        }
        let started = Instant::now();
        // Round-21 F2 (av-harness metrics): observe finalize latency
        // on EVERY exit path, not only on the success terminal at
        // ~line 597. `close_session_locked` is a long function with
        // multiple `?`-propagations; a failing bridge/fs/receipt
        // step would return without an observation, hiding the
        // fact that repeated finalize attempts were themselves
        // slow. `_finalize_observer`'s Drop records duration under
        // every exit including early Err returns.
        struct FinalizeObserver<'a> {
            metrics: &'a Registry,
            started: Instant,
        }
        impl Drop for FinalizeObserver<'_> {
            fn drop(&mut self) {
                self.metrics
                    .histogram(
                        "av_session_finalize_duration_seconds",
                        "Session finalization latency",
                    )
                    .observe_us(elapsed_us(self.started));
            }
        }
        let _finalize_observer = FinalizeObserver {
            metrics: self.metrics.as_ref(),
            started,
        };
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
                    // Round-6 (hunt4 R-F5): a persisted receipt that no
                    // longer verifies (signer/key rotation) or whose
                    // subject mismatches the chain is a PERMANENT
                    // condition — the in-memory receipt will never
                    // change. Treating it as transient made the idle
                    // sweeper re-enter this close every tick forever
                    // (full re-verify + warn loop, fleet-wide after a
                    // key rotation). Seal terminally like the
                    // capture-failed branch: evidence quarantined, no
                    // per-tick retry.
                    let verified = self.verify_configured_receipt(&receipt).and_then(|()| {
                        if receipt.body.subject == subject {
                            Ok(())
                        } else {
                            Err(FinalizeError::Receipt(
                                "persisted receipt subject does not match reconstructed chain".to_owned(),
                            ))
                        }
                    });
                    if let Err(error) = verified {
                        tracing::warn!(
                            session = %session.id,
                            %error,
                            "persisted receipt does not verify; sealing session terminally \
                             (evidence quarantined, no per-tick retry)"
                        );
                        session.mark_capture_failed();
                        session.mark_artifact_committed();
                        claim.committed = true;
                        self.clear_budget_state(&session.id);
                        self.quarantine_tool_executions(&session.id).await;
                        self.quarantined_sessions.lock().insert(session.id.clone());
                        return Err(error);
                    }
                    receipt
                } else {
                    let body = session.receipt_body(subject, stop_reason);
                    let sign_started = Instant::now();
                    let receipt_result = Receipt::issue(body, self.signer.as_ref());
                    // Round-21 F1 (av-harness metrics): observe the
                    // signing histogram BEFORE `?`-propagating the
                    // error, so a Receipt::issue failure still
                    // produces a latency sample. The prior code
                    // observed only on the success branch, so
                    // sudden signing-latency regressions on error
                    // paths (e.g. key-provider timeouts) were
                    // invisible to alerting.
                    self.metrics
                        .histogram("av_receipt_sign_duration_seconds", "Receipt signing latency")
                        .observe_us(elapsed_us(sign_started));
                    let receipt =
                        receipt_result.map_err(|error| FinalizeError::Receipt(error.to_string()))?;
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
                    // Round-6 (hunt4 R2): snapshot for the write so a
                    // failed atomic write leaves the builder intact for
                    // retry; drain the builder AFTER the write is
                    // durable (below, right before `close_complete`)
                    // to reclaim RAM. The prior code kept the builder
                    // populated forever because evict_finalized only
                    // evicts Signed sessions.
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
                                / av_core::units::USD_MICROS_PER_DOLLAR as f64,
                        );
                        metrics.extra = Some(serde_json::json!({
                            "tool_calls": session.totals.tool_calls.load(std::sync::atomic::Ordering::Acquire),
                            "tool_allowed": session.totals.tool_allowed.load(std::sync::atomic::Ordering::Acquire),
                            "tool_blocked": session.totals.tool_blocked.load(std::sync::atomic::Ordering::Acquire),
                            "cost_usd_micros": session.totals.cost_usd_micros.load(std::sync::atomic::Ordering::Acquire),
                            "stop_reason_id": session.recorded_stop_reason_id(),
                            // The sticky enforcement latch, persisted so the
                            // same-id refusal survives restarts. Inferring it
                            // from stop_reason_id was wrong: Inject-action
                            // breaker trips record LoopDetected without
                            // latching, so a restart upgraded a deliberately
                            // non-terminal trip into a permanent lockout.
                            "enforcement_latched": session.enforcement_latched_id(),
                        }));
                    }
                    let name = format!(
                        "{}.json",
                        &av_core::digest::sha256_hex(session.id.as_bytes())[..32]
                    );
                    let path = self.spool_dir.join(name);
                    let write_path = path.clone();
                    let archive_session = session.id.clone();
                    let new_trajectory_id = trajectory.trajectory_id.clone();
                    tokio::task::spawn_blocking(move || {
                        // A recycled session id must not overwrite the prior
                        // incarnation's trajectory (and stale sidecar) —
                        // archive the old pair first.
                        archive_conflicting_atif(&write_path, new_trajectory_id.as_deref(), &archive_session)
                            .map_err(av_atif::writer::WriterError::Io)?;
                        av_atif::write_atomic(&trajectory, &write_path)
                    })
                    .await
                    .map_err(|error| FinalizeError::Task(error.to_string()))?
                    .map_err(|error| FinalizeError::Atif(error.to_string()))?;
                    path
                };
                self.ensure_atif_provenance(&path, &session.id).await?;
                // Cache the path only AFTER the provenance seal succeeded.
                // Caching it right after `write_atomic` (the old order)
                // meant a transient `ensure_atif_provenance` failure left
                // `atif_path` set while `CloseClaim::drop` reopened the
                // session — the client kept chatting, appending steps
                // n..n+m, and the NEXT close hit the `existing_path`
                // fast path above, sealing provenance over the STALE
                // n-step artifact and then destroying the step journal:
                // silent, permanent loss of every step captured between
                // the two close attempts. With the assignment here, a
                // provenance failure leaves `atif_path` unset, so the
                // retry re-snapshots the (still intact) builder and
                // rewrites the artifact with the full step set. The
                // `existing_path` fast path remains load-bearing for
                // RECOVERED sessions (whose builder is empty and whose
                // on-disk artifact is authoritative) — those set
                // `atif_path` in `recover_unsigned` with the artifact
                // already durable.
                *session.atif_path.lock() = Some(path.clone());
                session.mark_artifact_committed();
                FinalizeOutcome::Atif { path }
            }
        };
        let workflow = session.workflow.as_str();
        self.emit_bridge_event(
            &session,
            av_events::EventClass::Session,
            serde_json::json!({"action": "closed", "workflow": workflow}),
            crate::journal::SESSION_CLOSE_OUTBOX_KIND,
        )
        .await?;
        self.remove_step_journal(&session.id).await?;
        self.remove_tool_executions(&session.id).await?;
        self.remove_lifecycle_outbox(&session.id, crate::journal::RECEIPT_OUTBOX_KIND)
            .await?;
        self.remove_lifecycle_outbox(&session.id, crate::journal::SESSION_CLOSE_OUTBOX_KIND)
            .await?;
        // Round-21 F2 (round-22 self-fix): finalize latency is now
        // observed via `_finalize_observer`'s Drop at the top of
        // this function so it also fires on early Err returns. The
        // prior terminal observation here would DOUBLE-count on
        // every successful close — inflating rate/QPS by ~2× and
        // distorting error-ratio alerting. Kept the counter
        // increment; only the histogram observation is removed.
        self.metrics
            .counter("av_sessions_finalized_total", "Sessions finalized")
            .inc();
        claim.committed = true;
        // Durable close-complete marker for Unsigned sessions: written only
        // after the SESSION_CLOSE emit and outbox removals above succeeded,
        // so the recovery scan can restore `close_complete` without
        // re-emitting the close on every restart (see CloseCompleteMarker).
        if session.workflow == Workflow::Unsigned {
            self.persist_close_complete_marker(&session).await;
        }
        // Only now — with lifecycle events published and the on-disk journal
        // removed — may the registry evict this session.
        session.mark_close_complete();
        // Round-6 (hunt4 R-F4): best-effort vector-store cleanup. The
        // scoped points are dead weight after close (the generation-uid
        // scope makes them unreachable for any future incarnation) and
        // an external Qdrant would otherwise grow without bound. Errors
        // must never affect the close outcome.
        if let Some(sink) = &self.vector_sink {
            if let Err(error) = sink.delete_scope(&session.session_scope).await {
                tracing::warn!(
                    session = %session.id,
                    %error,
                    "vector-store scope cleanup failed at close (points remain as dead weight)"
                );
            }
        }
        // Round-6 (hunt4 R2): reclaim the trajectory builder's RAM.
        // Signed sessions are handled by evict_finalized; unsigned
        // sessions live in the registry forever, so their builders
        // must be released here or RSS grows unbounded under
        // sustained traffic. Safe to drop unconditionally: any
        // subsequent read of the trajectory comes from the durable
        // on-disk artifact via promote()'s read_capped_async, not the
        // builder.
        if session.workflow == Workflow::Unsigned {
            session.drain_trajectory_builder();
        }
        // Release the loop-detector's retained embedding: closed
        // sessions never observe() again, and retained unsigned
        // sessions otherwise pin ~2 KB of dead vector each, forever.
        session.loop_state.release_embedding();
        self.clear_budget_state(&session.id);
        Ok(outcome)
    }

    /// Promote a persisted unsigned trajectory into a retroactive Receipt.
    #[tracing::instrument(
        name = "agentvisor.session.promote",
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
        // Check `is_promoted()` BEFORE taking the receipt lock —
        // preemptive hardening. The per-session lifecycle mutex
        // acquired at line 628 already serializes the only
        // `restore_receipt` writer in this codebase (called from
        // `recover_spooled_sessions` inside the per-candidate
        // `acquire_lifecycle` block at line 1126, and both invocation
        // paths — `main.rs` startup and the reconciler tick — await
        // recovery to completion before calling
        // `retry_marked_promotions`), so the reader-writer race the
        // read-then-check ordering allows in isolation is not
        // observable in the current code. Reordering to check first
        // documents the invariant explicitly and hardens against a
        // future refactor that could shrink the lifecycle-lock scope
        // to expose the observable race (reader reads
        // `receipt = None`, writer commits receipt + `finish_promotion()`,
        // reader observes `promoted = 2` via Acquire but returns the
        // stale `None` → spurious "promoted session has no persisted
        // receipt"). Checking `is_promoted()` first pins the read
        // order: any subsequent mutex lock observes the writer's
        // fully-committed state.
        if session.is_promoted() {
            let persisted_receipt = { session.receipt.lock().clone() };
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
            let atif_path_opt: Option<std::path::PathBuf> = { session.atif_path.lock().clone() };
            if let Some(atif_path) = atif_path_opt {
                let marker = atif_path.with_extension("promote");
                if marker.exists() {
                    if let Err(error) = remove_outbox(&marker).await {
                        tracing::warn!(
                            %error,
                            path = %av_core::fsutil::basename(&marker),
                            "failed to clean up orphan promotion marker (promotion still succeeded)"
                        );
                    }
                }
            }
            return Ok(receipt);
        }
        let persisted_receipt = { session.receipt.lock().clone() };
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
        let bytes = read_capped_async(path.clone(), av_core::fsutil::MAX_ATIF_BYTES)
            .await
            .map_err(|error| FinalizeError::Atif(error.to_string()))?;
        let trajectory: av_atif::Trajectory =
            serde_json::from_slice(&bytes).map_err(|error| FinalizeError::Atif(error.to_string()))?;
        // Round-23 F2: also strict-validate the raw bytes so
        // duplicate JSON keys and unknown-fields (both silently
        // accepted by the typed `serde_json::from_slice::<Trajectory>`
        // path) are refused. `validate_bytes` returns Err for a
        // parse/duplicate-key failure; treat that as a strict
        // failure with a short reason.
        let issues = match av_atif::validate_bytes(&bytes, av_atif::Mode::Strict) {
            Ok(issues) => issues,
            Err(reason) => {
                return Err(FinalizeError::Atif(format!(
                    "strict validation failed (bytes-level): {reason}"
                )))
            }
        };
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
        let trajectory_digest = av_core::digest::sha256_hex(&bytes);
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
            let sealed = read_capped_async(marker.clone(), av_core::fsutil::MAX_CONTROL_BYTES)
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
        // Cancellation-safe claim release: if this future is dropped at any
        // await below (client disconnect), the guard resets the claim so
        // promotion can be retried. Explicit error arms rely on it too.
        let mut claim = PromotionClaim {
            session: &session,
            committed: false,
        };
        let receipt = if let Some(receipt) = persisted_receipt {
            self.verify_configured_receipt(&receipt)?;
            if receipt.body.subject != subject {
                return Err(FinalizeError::Receipt(
                    "persisted promotion receipt does not match ATIF artifact".to_owned(),
                ));
            }
            receipt
        } else {
            let body = session.receipt_body(subject, StopReason::SessionClosed);
            // Round-49 F2: also observe here — the receipt-signing
            // histogram was only observed in `close_session_locked`
            // (the signed-close path), leaving retroactive
            // promotion signing latency invisible. An operator
            // watching `av_receipt_sign_duration_seconds` would
            // see promotion-signing regressions as a flat metric.
            //
            // Round-21 F1 (av-harness metrics): observe the
            // histogram BEFORE `?`-propagating so signing failures
            // still produce samples.
            let sign_started = Instant::now();
            let receipt_result = Receipt::issue(body, self.signer.as_ref());
            self.metrics
                .histogram("av_receipt_sign_duration_seconds", "Receipt signing latency")
                .observe_us(elapsed_us(sign_started));
            let receipt = receipt_result.map_err(|error| FinalizeError::Receipt(error.to_string()))?;
            self.persist_receipt(&session.id, &receipt).await?;
            *session.receipt.lock() = Some(receipt.clone());
            receipt
        };
        self.emit_receipt_event(&session, &receipt).await?;
        claim.committed = true;
        session.finish_promotion();
        remove_outbox(&marker).await?;
        self.remove_lifecycle_outbox(&session.id, crate::journal::RECEIPT_OUTBOX_KIND)
            .await?;
        self.metrics
            .counter("av_sessions_promoted_total", "Unsigned sessions promoted")
            .inc();
        Ok(receipt)
    }

    /// Recover interrupted sessions from the spool: quarantine sessions with
    /// incomplete effects, replay lifecycle outboxes, recover signed journal
    /// sessions, consolidate unsigned step journals, then scan strict ATIF
    /// artifacts for closed unsigned sessions. Returns the total count of
    /// recovered sessions (unsigned + signed).
    #[tracing::instrument(name = "agentvisor.recovery", skip_all)]
    pub async fn recover_spooled_sessions(
        &self,
        sessions: &SessionRegistry,
        breaker: &av_loopdetect::BreakerConfig,
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
        // Round-6 (hunt4 R-F2): precompute the filename stems of every
        // registry-known session. Artifact filenames are
        // `{sha256(session_id)[..32]}.json`, so a stem match means the
        // adoption below would skip anyway ("session already active" at
        // try_insert_recovered) — but only AFTER a full 64 MiB read +
        // parse + double strict-validation. The per-tick scan cost was
        // O(total historical artifacts × 2 × artifact size), every
        // tick, forever; this makes the steady-state cost one stat +
        // one set-lookup per already-adopted artifact.
        let known_stems: std::collections::HashSet<String> = sessions
            .open_sessions_including_closed()
            .iter()
            .map(|session| {
                let digest = av_core::digest::sha256_hex(session.id.as_bytes());
                digest.get(..32).unwrap_or(&digest).to_owned()
            })
            .collect();
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
            // Round-6 (hunt4 R-F2): the session is already in the
            // registry — adoption would skip it after an expensive
            // read+parse+validate; skip on the stem match instead.
            if path
                .file_stem()
                .and_then(std::ffi::OsStr::to_str)
                .is_some_and(|stem| known_stems.contains(stem))
            {
                continue;
            }
            // Round-44 F1: cheap sidecar-existence check FIRST — before
            // the 64 MiB read + serde parse + strict validate. Without
            // this ordering, N sidecar-less files (attacker-planted OR
            // honest crashes between the ATIF `write_atomic` and the
            // subsequent `ensure_atif_provenance` in
            // `close_session_locked`'s Unsigned branch) would burn O(N * 64 MiB)
            // IO per 5 s reconciler tick, missing tick cadence and
            // starving lifecycle-outbox replay, close completion,
            // promotion retry, and idle eviction.
            //
            // Round-44 F4: quarantine sidecar-less files after the warn
            // so per-tick cost is bounded to a single stat+rename per
            // file, regardless of how many the attacker plants or how
            // long a crash-torn orphan persists. Data cannot be
            // authenticated without a `journal_key`-signed sidecar (an
            // attacker-planted trajectory would forge a session's
            // audit trail if we generated a sidecar from bytes on
            // recovery), so orphaned trajectories are unrecoverable by
            // design; renaming to `<name>.corrupt-<uid>` moves them
            // out of the recovery scan glob (the `.json` extension
            // filter at the top of this scan loop rejects the
            // renamed file) while preserving
            // the bytes for operator forensic inspection.
            if !path.with_extension("atif-auth").exists() {
                // Live-race guard (round-16 stress finding): a sidecar-less
                // `{stem}.json` is ALSO the normal transient state of an
                // in-flight close — `close_session_locked` writes the ATIF
                // via `write_atomic` and seals `.atif-auth` moments later.
                // A reconciler tick landing in that window used to rename
                // the fresh artifact to `.corrupt-<uid>`, ripping it out
                // from under the close (its provenance step then fails,
                // racing promotes 500, and the artifact is orphaned as
                // "corrupt" forensics). Only quarantine files old enough
                // that no live close can still be mid-window; young files
                // are skipped this tick at the cost of a single stat, so
                // the round-44 F1/F4 per-tick cost bounds are preserved.
                const MIN_ORPHAN_AGE: std::time::Duration = std::time::Duration::from_secs(60);
                let age = tokio::fs::metadata(&path)
                    .await
                    .ok()
                    .and_then(|meta| meta.modified().ok())
                    .and_then(|mtime| std::time::SystemTime::now().duration_since(mtime).ok());
                // Only quarantine when the age is DETERMINATELY past the
                // threshold. An indeterminate age (stat error, or a future
                // mtime after a backward clock step — NTP correction, VM
                // resume) must count as young: treating it as old would
                // quarantine a fresh in-flight-close artifact and recreate
                // the exact race this guard exists to prevent. The skip
                // costs one stat per tick — the same bound accepted above.
                if !age.is_some_and(|age| age >= MIN_ORPHAN_AGE) {
                    continue;
                }
                self.metrics
                    .counter(
                        "av_atif_recovery_skipped_total{reason=\"unauthenticated\"}",
                        "ATIF spool files skipped during recovery",
                    )
                    .inc();
                let mut quarantine = path.clone();
                let stem = quarantine
                    .file_name()
                    .and_then(std::ffi::OsStr::to_str)
                    .unwrap_or("orphan-atif")
                    .to_owned();
                let new_name = format!("{stem}.corrupt-{}", av_core::new_event_uid());
                quarantine.set_file_name(new_name);
                match tokio::fs::rename(&path, &quarantine).await {
                    Ok(()) => {
                        if self.warn_once(quarantine.clone()) {
                            tracing::warn!(
                                original = %av_core::fsutil::basename(&path),
                                quarantine = %av_core::fsutil::basename(&quarantine),
                                "quarantined ATIF spool file with no authenticated provenance"
                            );
                        }
                    }
                    Err(error) => {
                        if self.warn_once(path.clone()) {
                            tracing::warn!(
                                %error,
                                path = %av_core::fsutil::basename(&path),
                                "failed to quarantine ATIF spool file with no authenticated provenance; will retry next tick"
                            );
                        }
                    }
                }
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
                    tracing::warn!(%error, path = %av_core::fsutil::basename(&path), "skipping ATIF spool file whose metadata is unreadable");
                    continue;
                }
            };
            if metadata.len() > MAX_ATIF_RECOVERY_BYTES {
                self.metrics
                    .counter(
                        "av_atif_recovery_skipped_total{reason=\"too_large\"}",
                        "ATIF spool files skipped during recovery",
                    )
                    .inc();
                tracing::warn!(
                    path = %av_core::fsutil::basename(&path),
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
            // discipline the other per-file steps in this scan use
            // so recovery is per-file.
            let bytes = match read_capped_async(path.clone(), av_core::fsutil::MAX_ATIF_BYTES).await {
                Ok(bytes) => bytes,
                Err(error) => {
                    self.metrics
                        .counter(
                            "av_atif_recovery_skipped_total{reason=\"read_error\"}",
                            "ATIF spool files skipped during recovery",
                        )
                        .inc();
                    tracing::warn!(%error, path = %av_core::fsutil::basename(&path), "skipping unreadable ATIF spool file");
                    continue;
                }
            };
            let trajectory: av_atif::Trajectory = match serde_json::from_slice(&bytes) {
                Ok(trajectory) => trajectory,
                Err(error) => {
                    self.metrics
                        .counter(
                            "av_atif_recovery_skipped_total{reason=\"invalid_json\"}",
                            "ATIF spool files skipped during recovery",
                        )
                        .inc();
                    tracing::warn!(%error, path = %av_core::fsutil::basename(&path), "ignoring invalid ATIF spool file");
                    continue;
                }
            };
            // Round-23 F2: parity with `promote` — the recovery path
            // must also refuse duplicate-key / unknown-field wire
            // bytes that the typed path silently accepts.
            let bytes_issues = match av_atif::validate_bytes(&bytes, av_atif::Mode::Strict) {
                Ok(issues) => issues,
                Err(reason) => {
                    self.metrics
                        .counter(
                            "av_atif_recovery_skipped_total{reason=\"invalid_json\"}",
                            "ATIF spool files skipped during recovery",
                        )
                        .inc();
                    tracing::warn!(
                        reason = %reason,
                        path = %av_core::fsutil::basename(&path),
                        "ignoring ATIF spool file rejected at bytes level"
                    );
                    continue;
                }
            };
            if !bytes_issues.is_empty()
                || !av_atif::validate_trajectory(&trajectory, av_atif::Mode::Strict).is_empty()
            {
                self.metrics
                    .counter(
                        "av_atif_recovery_skipped_total{reason=\"nonconformant\"}",
                        "ATIF spool files skipped during recovery",
                    )
                    .inc();
                tracing::warn!(path = %av_core::fsutil::basename(&path), "ignoring nonconformant ATIF spool file");
                continue;
            }
            let Some(session_id) = trajectory.session_id.clone() else {
                continue;
            };
            // Round-44 F1: sidecar existence is now checked early
            // (before the read+parse+validate) at the top of this
            // loop iteration, so orphan sidecar-less files no longer
            // reach this point.
            if let Err(error) = self
                .ensure_atif_provenance_from_bytes(&path, &session_id, &bytes)
                .await
            {
                self.metrics
                    .counter(
                        "av_atif_recovery_skipped_total{reason=\"provenance\"}",
                        "ATIF spool files skipped during recovery",
                    )
                    .inc();
                if self.warn_once(path.clone()) {
                    tracing::warn!(
                        %error,
                        path = %av_core::fsutil::basename(&path),
                        "ignoring ATIF spool file whose provenance does not verify"
                    );
                }
                // Quarantine files old enough that no live close can
                // still be repairing the sidecar (same MIN_ORPHAN_AGE
                // guard used for sidecar-less files at the top of this
                // scan). Without this, a strict-valid attacker-planted
                // trajectory paired with a bogus-MAC sidecar re-parses
                // and re-strict-validates every tick forever — the read
                // + parse + strict validate walk of the whole trajectory
                // (up to `MAX_ATIF_RECOVERY_BYTES`) runs on the recovery
                // scan task, so N planted files burn O(N × file_size)
                // CPU per tick indefinitely. `warn_once` only bounds the
                // log noise, not the work. Quarantine (rename out of
                // the `.json` glob) so the file drops out of the scan
                // after one pass. Young files (< MIN_ORPHAN_AGE) skip
                // this tick and retry: a legitimate MAC mismatch during
                // a torn-sidecar-write window resolves the moment the
                // close finishes writing.
                const MIN_ORPHAN_AGE: std::time::Duration = std::time::Duration::from_secs(60);
                let age = tokio::fs::metadata(&path)
                    .await
                    .ok()
                    .and_then(|meta| meta.modified().ok())
                    .and_then(|mtime| std::time::SystemTime::now().duration_since(mtime).ok());
                if !age.is_some_and(|age| age >= MIN_ORPHAN_AGE) {
                    continue;
                }
                let mut quarantine = path.clone();
                let stem = quarantine
                    .file_name()
                    .and_then(std::ffi::OsStr::to_str)
                    .unwrap_or("provenance-fail-atif")
                    .to_owned();
                let new_name = format!("{stem}.corrupt-{}", av_core::new_event_uid());
                quarantine.set_file_name(new_name);
                if let Err(rename_error) = tokio::fs::rename(&path, &quarantine).await {
                    if self.warn_once(path.clone()) {
                        tracing::warn!(
                            %rename_error,
                            path = %av_core::fsutil::basename(&path),
                            "failed to quarantine ATIF file with bad provenance; will retry next tick"
                        );
                    }
                }
                continue;
            }
            if sessions.get(&session_id).is_some() {
                continue;
            }
            // Round-42 F1: previously the per-candidate "adopt +
            // restore receipt" body used bare `?` on the receipt
            // read/parse/verify calls, so a single corrupt or
            // tamper-signed receipt on disk would abort recovery of
            // every OTHER ATIF trajectory in the same tick (HOL
            // block). Round-41 F1 fixed the same class of bug in
            // `recover_signed_journals` and `consolidate_step_journals`;
            // this branch was missed. Mirror the async-block +
            // outcome-enum wrap so per-candidate errors warn+skip
            // via the `av_atif_trajectory_recovery_skipped_total`
            // counter instead of stopping the scan.
            enum AtifCandidateOutcome {
                Recovered,
                Skipped,
            }
            let outcome: Result<AtifCandidateOutcome, FinalizeError> = async {
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
                    serde_json::from_value::<av_events::CharterFile>(value.clone())
                        .ok()
                        .or_else(|| value.as_str().map(Into::into))
                })
                .unwrap_or_else(|| "recovered".into());
            let ttl_remaining_s = extra
                .and_then(|value| value.get("ttl_remaining_s"))
                .and_then(serde_json::Value::as_u64);
            let recovered_session = match sessions.try_insert_recovered(
                Session::recover_unsigned(
                    session_id.clone(),
                    av_events::AgentIdentity {
                        version: trajectory.agent.version.clone(),
                        charter,
                        instance_uid,
                        ttl_remaining_s,
                    },
                    breaker.clone(),
                    path.clone(),
                    trajectory.final_metrics.as_ref(),
                    // One bridge event was published per persisted step (the
                    // journal enforces sequence == index during
                    // consolidation), so the step count is the next free
                    // sequence when the close tail has NOT yet run. When a
                    // verified close-complete marker proves it has, the
                    // marker branch below additionally advances past the
                    // published SESSION_CLOSE.
                    trajectory.steps.len() as u64,
                )
                .map_err(FinalizeError::Atif)?,
            ) {
                Ok(inserted) => inserted,
                Err(_active) => {
                    tracing::info!(session = %av_core::fsutil::basename(&path), "unsigned recovery skipped: session already active");
                    return Ok(AtifCandidateOutcome::Skipped);
                }
            };
            // Restore `close_complete` from the durable marker written by the
            // close tail. Absence-of-residue inference is unsound here:
            // `consolidate_step_journals` (which ran just above) also removes
            // step journals for sessions that crashed while still OPEN — whose
            // SESSION_CLOSE was never published — so "no journal + no outbox"
            // does not prove the close finished. Only the sealed marker
            // (written strictly after a successful emit + outbox removal, and
            // bound to this artifact's digest) does. No marker ⇒ the
            // pending-close sweep owns the session and emits the close exactly
            // once, then writes the marker itself.
            let marker_path = close_complete_marker_path(&path);
            match read_capped_async(marker_path.clone(), av_core::fsutil::MAX_CONTROL_BYTES).await {
                Ok(sealed) => {
                    match crate::journal::open::<CloseCompleteMarker>(
                        &self.journal_key,
                        CLOSE_COMPLETE_DOMAIN,
                        0,
                        &sealed,
                    ) {
                        Ok(marker)
                            if marker.session_id == session_id
                                && marker.digest == av_core::digest::sha256_hex(&bytes) =>
                        {
                            recovered_session.mark_close_complete();
                            // The verified marker proves the close tail ran:
                            // SESSION_CLOSE was published at sequence
                            // `steps.len()` (both lifecycle outboxes are
                            // removed before the marker is written, so no
                            // fast-forward source survives). Advance past it
                            // or the first retroactive-receipt event would be
                            // minted at the close's sequence — the exact
                            // collision `restore_next_seq` above exists to
                            // prevent.
                            recovered_session.advance_seq_past(trajectory.steps.len() as u64);
                        }
                        Ok(_) | Err(_) => {
                            // Stale (prior incarnation) or corrupt marker:
                            // remove it and let the sweep re-drive the tail —
                            // at worst one duplicate close, never a lost one.
                            tracing::warn!(
                                session = %av_core::fsutil::basename(&path),
                                "close-complete marker does not verify for this artifact; removing it"
                            );
                            if let Err(error) = tokio::fs::remove_file(&marker_path).await {
                                if error.kind() != std::io::ErrorKind::NotFound {
                                    tracing::warn!(%error, "failed to remove stale close-complete marker");
                                }
                            }
                        }
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    tracing::warn!(
                        %error,
                        session = %av_core::fsutil::basename(&path),
                        "close-complete marker unreadable; the pending-close sweep will re-drive the tail"
                    );
                }
            }
            // Round-6 (hunt3 F5): the ATIF adoption path must consult
            // quarantined_sessions like both sibling recovery paths do
            // (signed at :1766, consolidate at :1963). Skipping this
            // check lets a quarantined recycled-id session be restored
            // as cleanly closed — masking the incident evidence the
            // quarantine exists to preserve.
            if self.quarantined_sessions.lock().contains(&session_id) {
                recovered_session.mark_capture_failed();
            }
            let receipt_path = self.receipt_path(&recovered_session.id);
            // Round-40 F4: distinguish ENOENT from other read
            // failures (see the twin in recover_signed_journals
            // for full rationale). An oversize/EACCES/EIO would
            // previously fold into "no prior receipt" and mint a
            // fresh one — silently erasing evidence of the
            // original.
            //
            // The restore is wrapped so its failure can UNDO the
            // adoption (see below): the session was already installed
            // by `try_insert_recovered`, and leaving it registered
            // with `closed=1`, `artifact_committed=1`, and no receipt
            // would (a) make every later tick return Skipped — the
            // round-40 F4 error surfaces exactly once and then becomes
            // permanent silent state, never retried — and (b) let a
            // `.promote` marker or an operator `/promote` find
            // `persisted_receipt = None` and MINT A FRESH RECEIPT,
            // the precise silent re-mint round-40 F4 exists to
            // prevent. The signed twin removes its half-committed
            // session on transient error (round-42 F3); mirror it.
            let receipt_restore: Result<(), FinalizeError> = async {
            match tokio::fs::metadata(&receipt_path).await {
                Ok(_) => {
                    let bytes_receipt = read_capped_async(
                        receipt_path.clone(),
                        av_core::fsutil::MAX_RECEIPT_BYTES,
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
                    let receipt = Receipt::from_json_slice(&bytes_receipt)
                        .map_err(|error| FinalizeError::Receipt(error.to_string()))?;
                    self.verify_configured_receipt(&receipt)?;
                    // Round-6 (hunt3 F3): also bind the persisted
                    // receipt to THIS artifact by its digest before
                    // restoring it. A recycled session id can leave a
                    // prior incarnation's receipt at the shared hash
                    // path; without this check the ATIF adoption
                    // restored it as if it attested the current
                    // trajectory. The signed twin at :1712 enforces the
                    // same invariant; parity here closes the gap.
                    let atif_digest = av_core::digest::sha256_hex(&bytes);
                    let receipt_matches = matches!(
                        &receipt.body.subject,
                        ReceiptSubject::AtifTrajectory { trajectory_digest, .. }
                            if *trajectory_digest == atif_digest
                    );
                    if !receipt_matches {
                        tracing::warn!(
                            session = %av_core::fsutil::basename(&path),
                            "prior receipt does not attest the recovered ATIF trajectory; ignoring as prior-incarnation evidence"
                        );
                    } else if path.with_extension("promote").exists() {
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
            Ok(())
            }.await;
            if let Err(error) = receipt_restore {
                // Remove the half-adopted session so the next tick
                // re-reads the still-present ATIF artifact and
                // re-attempts the receipt restore cleanly, instead of
                // stranding a receipt-less closed session forever.
                sessions.remove(&recovered_session.id);
                return Err(error);
            }
            Ok(AtifCandidateOutcome::Recovered)
            }.await;
            match outcome {
                Ok(AtifCandidateOutcome::Recovered) => recovered += 1,
                Ok(AtifCandidateOutcome::Skipped) => {}
                Err(error) => {
                    self.metrics
                        .counter(
                            "av_atif_trajectory_recovery_skipped_total",
                            "ATIF trajectories skipped during recovery due to per-session errors (round-42 F1)",
                        )
                        .inc();
                    if self.warn_once(path.clone()) {
                        tracing::warn!(
                            %error,
                            path = %av_core::fsutil::basename(&path),
                            "skipping ATIF trajectory recovery due to per-session error; other sessions continue"
                        );
                    }
                }
            }
        }
        self.remove_acked_lifecycle_outboxes(sessions).await?;
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
        breaker: &av_loopdetect::BreakerConfig,
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
            // up through `recover_spooled_sessions`'s `?` on the
            // `recover_signed_journals` call and killing
            // the whole recovery scan for the tick. Every prior
            // `continue;` becomes `return Ok(Skipped);`; every
            // `recovered += 1; continue;` becomes `return Ok(Recovered);`.
            let outcome: Result<SignedCandidateOutcome, FinalizeError> = async {
            // NotFound: a concurrent close removed the sidecar between the
            // directory listing and this read — the session finished; skip.
            let Some(metadata) = self.read_journal_metadata(&metadata_path).await? else {
                return Ok(SignedCandidateOutcome::Skipped);
            };
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
                        path = %av_core::fsutil::basename(&metadata_path),
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
            let identity: av_events::AgentIdentity = serde_json::from_value(
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
                // a prior tick (see `read_complete_journal` further
                // down this file). Without this, we'd delete the sidecar the
                // very next tick, orphaning the `.corrupt-<uid>`
                // bytes with no linkage back to session identity.
                if quarantine_sibling_exists(&self.spool_dir, stem).await? {
                    let quarantine_metadata = self
                        .spool_dir
                        .join(format!("{stem}.session.json.corrupt-{}", av_core::new_event_uid()));
                    match tokio::fs::rename(&metadata_path, &quarantine_metadata).await {
                        Ok(()) => tracing::warn!(
                            metadata = %av_core::fsutil::basename(&metadata_path),
                            quarantine = %av_core::fsutil::basename(&quarantine_metadata),
                            "sealed metadata sidecar quarantined alongside its torn signed journal (round-14 F5)"
                        ),
                        Err(error) => tracing::error!(
                            metadata = %av_core::fsutil::basename(&metadata_path),
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
                let event: av_events::OcsfEvent = serde_json::from_value(record.event.clone())
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
                    let reason = av_events::StopReason::from_id(id);
                    if reason != av_events::StopReason::Unknown {
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
                        av_core::fsutil::MAX_RECEIPT_BYTES,
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
                // Loud, per-boot telemetry: without this the branch
                // re-adopted the wedged session at EVERY restart with
                // no log line and no metric — the only signal was one
                // WARN at the original failure, long lost to rotation.
                // The spool files are retained deliberately (evidence),
                // but the operator must be able to see the session is
                // permanently quarantined and clean it up.
                self.metrics
                    .counter(
                        "av_signed_recovery_quarantined_total",
                        "Signed sessions re-adopted as capture-failed quarantines during recovery",
                    )
                    .inc();
                tracing::warn!(
                    session = %session.id,
                    "signed recovery re-adopted a capture-failed session (inconsistent response \
                     journal); it will refuse all requests and its spool files are retained as \
                     evidence until removed by an operator"
                );
                return Ok(SignedCandidateOutcome::Recovered);
            }
            if self.quarantined_sessions.lock().contains(&session.id) {
                session.mark_capture_failed();
                return Ok(SignedCandidateOutcome::Recovered);
            }
            // Round-42 F3: `mark_artifact_committed()` above sealed the
            // session against new leases before `try_insert_recovered`
            // to plug the race the seal-before-insert comment above
            // describes. But if
            // `close_session_locked` then fails transiently (broker
            // outage → Bridge; ENOSPC/EIO → Receipt; verify mismatch
            // after key rotation → Receipt), the session sits in the
            // registry with `artifact_committed = 1` forever:
            // `is_closed()` is true so the idle sweeper skips it, and
            // the next reconciler tick's registry-hit check
            // returns Skipped so signed recovery never re-attempts.
            // Remove the half-committed session on transient error so
            // the next tick re-reads the still-present journal sidecar
            // and re-adopts cleanly. `CaptureIncomplete` is a legit
            // sealed-quarantine outcome (close_session_locked already
            // set `claim.committed = true`), so leave those installed.
            match self
                .close_session_locked(Arc::clone(&session), StopReason::SessionClosed)
                .await
            {
                Ok(_) => Ok(SignedCandidateOutcome::Recovered),
                Err(FinalizeError::CaptureIncomplete) => {
                    Err(FinalizeError::CaptureIncomplete)
                }
                Err(error) => {
                    sessions.remove(&session.id);
                    Err(error)
                }
            }
            }.await;
            match outcome {
                Ok(SignedCandidateOutcome::Recovered) => recovered += 1,
                Ok(SignedCandidateOutcome::Skipped) => {}
                Err(error) => {
                    self.metrics
                        .counter(
                            "av_signed_recovery_skipped_total",
                            "Signed sessions skipped during recovery due to per-session errors (round-41 F1)",
                        )
                        .inc();
                    if self.warn_once(metadata_path.clone()) {
                        tracing::warn!(
                            %error,
                            path = %av_core::fsutil::basename(&metadata_path),
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
        event: &av_events::OcsfEvent,
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
        .map_err(FinalizeError::from)?
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
            .map_err(FinalizeError::from)?;
        crate::worker::persist_broker_ack(&self.spool_dir, session_id, event_uid, &ack, &self.journal_key)
            .await
            .map_err(FinalizeError::Bridge)
    }

    async fn consolidate_step_journals(
        &self,
        sessions: &SessionRegistry,
        breaker: &av_loopdetect::BreakerConfig,
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
            let mut claimed_session: Option<String> = None;
            let outcome: Result<(), FinalizeError> = async {
            let final_path = self.spool_dir.join(format!("{stem}.json"));
            let journal_path = self.spool_dir.join(format!("{stem}.events.ndjson"));
            // NotFound: a concurrent close removed the sidecar between the
            // directory listing and this read — the session finished; skip.
            let Some(metadata) = self.read_journal_metadata(&metadata_path).await? else {
                return Ok(());
            };
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
                        path = %av_core::fsutil::basename(&metadata_path),
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
            let identity: av_events::AgentIdentity = serde_json::from_value(
                metadata
                    .get("identity")
                    .cloned()
                    .ok_or_else(|| FinalizeError::Atif("journal metadata has no identity".into()))?,
            )
            .map_err(|error| FinalizeError::Atif(error.to_string()))?;
            // Claim the id in the registry BEFORE any destructive step.
            // The `sessions.get` check above races client admission:
            // `get_or_open` inserts without touching the lifecycle-lock
            // table, so a client could re-open this id after the check
            // and start appending to the very journal files this
            // consolidation is consuming — and `remove_step_journal`
            // below would then destroy the live session's records
            // (position-vs-seq mismatch, unrecoverable audit trail).
            // Every sibling recovery path claims via
            // `try_insert_recovered` before destructive work; this was
            // the only one that didn't. The placeholder is closed (so
            // admission refuses the id while consolidation runs) but
            // NOT artifact-committed/capture-failed/close-complete, so
            // the pending-close sweep, the idle sweeper, and
            // `get_or_open`'s reopen-recycling all skip it; it is
            // removed again right after the candidate body finishes.
            let placeholder = Session::new(
                session_id.to_owned(),
                Workflow::Unsigned,
                identity.clone(),
                breaker.clone(),
            );
            placeholder.closed.store(1, std::sync::atomic::Ordering::Release);
            let claimed = match sessions.try_insert_recovered(placeholder) {
                Ok(claimed) => claimed,
                Err(_active) => {
                    // A client re-opened the id between the check above
                    // and this claim — the session is live; leave its
                    // journal alone and skip, exactly like the pre-lock
                    // check.
                    return Ok(());
                }
            };
            claimed_session = Some(session_id.to_owned());
            let journal = if journal_path.exists() {
                read_complete_journal(&journal_path).await?
            } else {
                Vec::new()
            };
            if self.quarantined_sessions.lock().contains(session_id) {
                // Convert the already-claimed placeholder into the
                // quarantined session IN PLACE. A remove-then-insert swap
                // would vacate the registry entry for a moment, letting
                // `get_or_open` insert a fresh live session whose journal
                // index starts at 0 on top of the N on-disk records —
                // exactly the position-vs-seq corruption the claim exists
                // to prevent (and `insert_recovered`'s or_insert would
                // then silently discard the quarantine seal).
                claimed.restore_journal_index(
                    u64::try_from(journal.len())
                        .map_err(|_| FinalizeError::Atif("active journal length overflow".to_owned()))?,
                );
                claimed.mark_capture_failed();
                // Also seal the session finalized (like the signed-journal
                // capture-failed path) so the idle sweeper's `!is_closed()` filter
                // skips it. Otherwise every idle tick re-enters
                // close_session_locked, hits the capture_failed guard, and
                // CloseClaim resets `closed` — an unbounded churn loop.
                claimed.mark_artifact_committed();
                // The converted session must stay registered — do not
                // release the claim on this path.
                claimed_session = None;
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
                        .join(format!("{stem}.session.json.corrupt-{}", av_core::new_event_uid()));
                    match tokio::fs::rename(&metadata_path, &quarantine_metadata).await {
                        Ok(()) => tracing::warn!(
                            metadata = %av_core::fsutil::basename(&metadata_path),
                            quarantine = %av_core::fsutil::basename(&quarantine_metadata),
                            "sealed metadata sidecar quarantined alongside its torn unsigned journal (round-14 F5)"
                        ),
                        Err(error) => tracing::error!(
                            metadata = %av_core::fsutil::basename(&metadata_path),
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
            let agent = av_atif::Agent {
                name: "agentvisor-ai-harness".into(),
                version: identity.version.clone(),
                model_name: None,
                tool_definitions: None,
                extra: Some(serde_json::json!({
                    "charter": identity.charter,
                    "instance_uid": identity.instance_uid,
                })),
            };
            let mut builder = av_atif::TrajectoryBuilder::new(agent, Some(session_id.to_owned()));
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
                let event: av_events::OcsfEvent = serde_json::from_value(record.event.clone())
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
                    Some(cost_usd_micros as f64 / av_core::units::USD_MICROS_PER_DOLLAR as f64);
                metrics.extra = Some(serde_json::json!({
                    "tool_calls": tool_calls,
                    "tool_allowed": tool_allowed,
                    "tool_blocked": tool_blocked,
                    "cost_usd_micros": cost_usd_micros,
                    // Round-43 F2: match the close-time `metrics.extra`
                    // `stop_reason_id` serialization in
                    // `close_session_locked` which writes `u64` (0 when never
                    // recorded) via `session.recorded_stop_reason_id()`.
                    // Emitting `Option<u8>` here made JSON `null` vs
                    // JSON `0`, so the `trajectory != existing`
                    // comparison below
                    // fired on every session that closed without a
                    // terminal stop-reason event (client hangup mid-
                    // stream, /close before final assistant message,
                    // tool-only session). That mismatch marked the
                    // session `av_unsigned_recovery_skipped_total`,
                    // left the step-journal on disk uncleaned, and
                    // repeated every restart.
                    "stop_reason_id": stop_reason_id.map_or(0u64, u64::from),
                    // The journal cannot reconstruct the enforcement
                    // latch; write 0 and normalize the key away in the
                    // comparison below (same class as ttl_remaining_s).
                    // A crash-mid-close latched session therefore keeps
                    // its close-written latch when the artifacts
                    // otherwise agree, and forgets it when the journal
                    // genuinely wins — a bounded degradation.
                    "enforcement_latched": 0u64,
                }));
            }
            if final_path.exists() {
                let existing: av_atif::Trajectory = serde_json::from_slice(
                    &read_capped_async(final_path.clone(), av_core::fsutil::MAX_ATIF_BYTES)
                        .await
                        .map_err(|error| FinalizeError::Atif(error.to_string()))?,
                )
                .map_err(|error| FinalizeError::Atif(error.to_string()))?;
                trajectory.trajectory_id.clone_from(&existing.trajectory_id);
                // Round-6 (hunt2 crosscrate F1): `ttl_remaining_s` is
                // recomputed at every token validation, so close-time
                // ATIF (last REFRESHED identity) and recovery-rebuilt
                // ATIF (last JOURNALED identity) legitimately disagree
                // whenever the final admitted request was rejected
                // eventlessly (breaker-open 403, queue exhaustion).
                // The identity-consistency check upstream deliberately
                // compares version/charter/instance_uid only — mirror
                // that here by normalizing the ttl on comparison COPIES
                // (never the artifact we might persist), same
                // normalization class as the trajectory_id clone_from
                // above and the round-43 F2 stop_reason fix.
                let differs = {
                    let mut lhs = trajectory.clone();
                    let mut rhs = existing.clone();
                    normalize_extra_ttl(&mut lhs);
                    normalize_extra_ttl(&mut rhs);
                    normalize_extra_enforcement(&mut lhs);
                    normalize_extra_enforcement(&mut rhs);
                    lhs != rhs
                };
                if differs {
                    // Round-6 (hunt3 F4): a recycled session id whose
                    // prior incarnation finalized an unsigned artifact
                    // will land its follow-up incarnation here — the
                    // journal we just consolidated is genuinely
                    // different from the prior artifact. The close-time
                    // path (see round-6 F1 at ~:630) archives the
                    // existing artifact via `archive_conflicting_atif`;
                    // the recovery path did the wrong thing (hard warn,
                    // skip, retry every tick, journal never cleaned,
                    // and if a later incarnation reopens the id the
                    // next journal append lands at position 0 onto
                    // leftover events.ndjson — breaking the
                    // position-vs-seq invariant forever). Apply the
                    // twin: archive prior incarnation's artifact +
                    // sidecar + markers, then write our consolidated
                    // trajectory in its place.
                    let write_path = final_path.clone();
                    let archive_session = session_id.to_owned();
                    let new_trajectory_id = trajectory.trajectory_id.clone();
                    let archive_result = tokio::task::spawn_blocking(move || {
                        archive_conflicting_atif(
                            &write_path,
                            new_trajectory_id.as_deref(),
                            &archive_session,
                        )
                    })
                    .await
                    .map_err(|error| FinalizeError::Task(error.to_string()))?;
                    if let Err(error) = archive_result {
                        return Err(FinalizeError::Atif(format!(
                            "failed to archive prior-incarnation ATIF during recovery: {error}"
                        )));
                    }
                    let write_path = final_path.clone();
                    tokio::task::spawn_blocking(move || av_atif::write_atomic(&trajectory, &write_path))
                        .await
                        .map_err(|error| FinalizeError::Task(error.to_string()))?
                        .map_err(|error| FinalizeError::Atif(error.to_string()))?;
                }
            } else {
                let write_path = final_path.clone();
                tokio::task::spawn_blocking(move || av_atif::write_atomic(&trajectory, &write_path))
                    .await
                    .map_err(|error| FinalizeError::Task(error.to_string()))?
                    .map_err(|error| FinalizeError::Atif(error.to_string()))?;
            }
            self.ensure_atif_provenance(&final_path, session_id).await?;
            self.remove_step_journal(session_id).await?;
            Ok(())
            }.await;
            // Release the consolidation claim regardless of outcome: on
            // success the ATIF adoption scan re-adopts the artifact
            // properly; on error the next tick re-claims and retries.
            if let Some(id) = claimed_session {
                sessions.remove(&id);
            }
            if let Err(error) = outcome {
                self.metrics
                    .counter(
                        "av_unsigned_recovery_skipped_total",
                        // Keep in sync with the pre-registration in pipeline.rs —
                        // render() emits one HELP per family.
                        "Unsigned step-journal consolidations skipped during recovery due to per-session errors (round-41 F1)",
                    )
                    .inc();
                if self.warn_once(metadata_path.clone()) {
                    tracing::warn!(
                        %error,
                        path = %av_core::fsutil::basename(&metadata_path),
                        "skipping unsigned session consolidation due to per-session error; other sessions continue"
                    );
                }
            }
        }
        Ok(())
    }

    async fn remove_step_journal(&self, session_id: &str) -> Result<(), FinalizeError> {
        let digest = av_core::digest::sha256_hex(session_id.as_bytes());
        let stem = digest.get(..32).unwrap_or(&digest).to_owned();
        let spool_dir = self.spool_dir.clone();
        tokio::task::spawn_blocking(move || -> Result<(), FinalizeError> {
            let mut spool_changed = false;
            // Deletion order matters: the `.session.json` sidecar is the
            // ONLY name the recovery scans iterate, so it must go LAST.
            // The old sidecar-first order had a crash window that left an
            // events journal invisible to every recovery path; a later
            // reuse of the session id then recreated fresh metadata and
            // appended a record MAC-sealed at index 0 at file position N
            // — permanently breaking the position==sequence invariant.
            // With journal-first order, a crash leaves sidecar-without-
            // journal, which recovery already self-heals (treats the
            // journal as empty and removes the metadata).
            for suffix in ["events.ndjson", "steps.ndjson", "session.json"] {
                let path = spool_dir.join(format!("{stem}.{suffix}"));
                match std::fs::remove_file(&path) {
                    Ok(()) => spool_changed = true,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(FinalizeError::Atif(error.to_string())),
                }
            }
            if spool_changed {
                av_core::fsutil::sync_directory(&spool_dir)
                    .map_err(|error| FinalizeError::Atif(error.to_string()))?;
            }
            let ack_parent = spool_dir.join("broker-acks");
            let ack_path = ack_parent.join(&stem);
            match std::fs::remove_dir_all(&ack_path) {
                Ok(()) => av_core::fsutil::sync_directory(&ack_parent)
                    .map_err(|error| FinalizeError::Atif(error.to_string()))?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(FinalizeError::Atif(error.to_string())),
            }
            Ok(())
        })
        .await
        .map_err(|error| FinalizeError::Task(error.to_string()))?
    }

    /// Remove all forwarded MCP tool-execution intent/outcome/audited
    /// files for `session_id`. Runs at successful close time so that a
    /// recycled session id (see `SessionRegistry::get_or_open` — a
    /// completed-closed entry is replaced with a fresh `Session`) does
    /// not inherit prior-incarnation execution keys. Without this, a
    /// client reusing `(x-av-session, JSON-RPC id, body, identity)`
    /// against a recycled session hit the `Completed` fast-path in
    /// `mcp_call_inner` and got the prior incarnation's cached
    /// response — with NO new audit event on the recycled session's
    /// event chain. The tool-completed audit event for the original
    /// execution is already durably on the bridge before we reach
    /// this cleanup, so the on-disk files are pure idempotency
    /// markers and safe to drop.
    ///
    /// Bounded scan across the `tool-executions/` directory; each
    /// intent's authenticated `session_id` field is checked before
    /// removal, so unrelated sessions' files are never touched.
    async fn remove_tool_executions(&self, session_id: &str) -> Result<(), FinalizeError> {
        let spool_dir = self.spool_dir.clone();
        let session_id = session_id.to_owned();
        let control_key = self.journal_key;
        tokio::task::spawn_blocking(move || -> Result<(), FinalizeError> {
            let directory = spool_dir.join(crate::spool::TOOL_EXECUTIONS);
            let entries = match std::fs::read_dir(&directory) {
                Ok(entries) => entries,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(error) => return Err(FinalizeError::Atif(error.to_string())),
            };
            let mut removed_any = false;
            for entry in entries {
                let entry = entry.map_err(|error| FinalizeError::Atif(error.to_string()))?;
                let path = entry.path();
                let Some(name) = path.file_name().and_then(std::ffi::OsStr::to_str) else {
                    continue;
                };
                let Some(key) = name.strip_suffix(crate::spool::TOOL_INTENT_SUFFIX) else {
                    continue;
                };
                let intent_bytes = match std::fs::read(&path) {
                    Ok(bytes) => bytes,
                    // Concurrent removal or a torn intent already
                    // quarantined by the recovery scan: skip and
                    // continue rather than aborting the cleanup pass
                    // over unrelated files.
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(error) => return Err(FinalizeError::Atif(error.to_string())),
                };
                let intent_session_id = crate::journal::open::<serde_json::Value>(
                    &control_key,
                    &format!("{}:{key}", crate::journal::TOOL_INTENT_DOMAIN),
                    0,
                    &intent_bytes,
                )
                .ok()
                .and_then(|value| {
                    value
                        .get("session_id")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned)
                });
                if intent_session_id.as_deref() != Some(session_id.as_str()) {
                    continue;
                }
                // Round-21 F3 (av-harness spool): delete AUDITED first,
                // OUTCOME next, INTENT last. Recovery invariant: the
                // outcome file exists only if the intent exists.
                // Historically we deleted intent FIRST, so a crash
                // between the intent removal and the outcome removal
                // left an orphaned outcome that startup recovery
                // treats as fatal (routes.rs::from_request refuses
                // outcome-without-intent), and main.rs bubbles that
                // up as a startup failure. Reversing the order keeps
                // the invariant intact under any crash timing.
                //
                // Round-21 F4 (defense-in-depth): also try to remove
                // any `.intent.torn` twin for the same key. Note
                // that orphan `.intent.torn` files (whose companion
                // `.intent.json` was quarantined by rename) are not
                // reached by this loop and are preserved as
                // forensic evidence; they are the operator's
                // choice to sweep by age.
                for suffix in [
                    crate::spool::TOOL_AUDITED_SUFFIX,
                    crate::spool::TOOL_OUTCOME_SUFFIX,
                    crate::spool::TOOL_INTENT_SUFFIX,
                    ".intent.torn",
                ] {
                    let file = directory.join(format!("{key}{suffix}"));
                    match std::fs::remove_file(&file) {
                        Ok(()) => removed_any = true,
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                        Err(error) => return Err(FinalizeError::Atif(error.to_string())),
                    }
                }
            }
            if removed_any {
                av_core::fsutil::sync_directory(&directory)
                    .map_err(|error| FinalizeError::Atif(error.to_string()))?;
            }
            Ok(())
        })
        .await
        .map_err(|error| FinalizeError::Task(error.to_string()))?
    }

    /// Round-6 (hunt4 R-F3): move a capture-failed session's
    /// tool-execution triples out of the scanned namespace. These
    /// executions can never resolve (the session is sealed), but
    /// leaving them at their primary names meant
    /// `unresolved_tool_sessions` re-read and re-MAC-verified them
    /// every reconciler tick FOREVER, and every close of any other
    /// session paid the read+MAC cost for them too. Rename (not
    /// delete): the outcome hex may be the only copy of what the tool
    /// returned, so the triple is preserved as incident evidence under
    /// a `.capturefailed-<uid>` suffix that no scan globs.
    async fn quarantine_tool_executions(&self, session_id: &str) {
        let spool_dir = self.spool_dir.clone();
        let session_id = session_id.to_owned();
        let control_key = self.journal_key;
        let outcome = tokio::task::spawn_blocking(move || {
            let directory = spool_dir.join(crate::spool::TOOL_EXECUTIONS);
            let entries = match std::fs::read_dir(&directory) {
                Ok(entries) => entries,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(error) => return Err(error.to_string()),
            };
            for entry in entries {
                let Ok(entry) = entry else { continue };
                let path = entry.path();
                let Some(name) = path.file_name().and_then(std::ffi::OsStr::to_str) else {
                    continue;
                };
                let Some(key) = name.strip_suffix(crate::spool::TOOL_INTENT_SUFFIX) else {
                    continue;
                };
                let intent_bytes = match std::fs::read(&path) {
                    Ok(bytes) => bytes,
                    Err(_) => continue,
                };
                let intent_session_id = crate::journal::open::<serde_json::Value>(
                    &control_key,
                    &format!("{}:{key}", crate::journal::TOOL_INTENT_DOMAIN),
                    0,
                    &intent_bytes,
                )
                .ok()
                .and_then(|value| {
                    value
                        .get("session_id")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned)
                });
                if intent_session_id.as_deref() != Some(session_id.as_str()) {
                    continue;
                }
                let uid = av_core::new_event_uid();
                // Audited first, outcome next, intent last — mirrors the
                // remove path's crash-ordering rationale (outcome must
                // never exist without its intent at the primary names).
                for suffix in [
                    crate::spool::TOOL_AUDITED_SUFFIX,
                    crate::spool::TOOL_OUTCOME_SUFFIX,
                    crate::spool::TOOL_INTENT_SUFFIX,
                ] {
                    let file = directory.join(format!("{key}{suffix}"));
                    let quarantine = directory.join(format!("{key}{suffix}.capturefailed-{uid}"));
                    match std::fs::rename(&file, &quarantine) {
                        Ok(()) | Err(_) => {}
                    }
                }
                tracing::warn!(
                    session = %session_id,
                    key = %key,
                    "tool-execution triple quarantined as capture-failed incident evidence"
                );
            }
            let _ = av_core::fsutil::sync_directory(&directory);
            Ok(())
        })
        .await;
        match outcome {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::warn!(%error, "failed to quarantine capture-failed tool executions")
            }
            Err(error) => {
                tracing::warn!(%error, "failed to quarantine capture-failed tool executions")
            }
        }
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
            let sealed = match read_capped_async(path.clone(), av_core::fsutil::MAX_CONTROL_BYTES).await {
                Ok(bytes) => bytes,
                // A concurrent client promote legitimately consumes (removes)
                // the marker between our read_dir listing and this read —
                // NotFound is normal operation, not a warning.
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    tracing::warn!(
                        %error,
                        path = %av_core::fsutil::basename(&path),
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
                            path = %av_core::fsutil::basename(&path),
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
                    tracing::warn!(%error, path = %av_core::fsutil::basename(&path), "promotion retry failed");
                }
            }
        }
        Ok(promoted)
    }

    fn receipt_path(&self, session_id: &str) -> PathBuf {
        self.spool_dir.join("receipts").join(format!(
            "{}.json",
            &av_core::digest::sha256_hex(session_id.as_bytes())[..32]
        ))
    }

    async fn ensure_atif_provenance(
        &self,
        path: &std::path::Path,
        session_id: &str,
    ) -> Result<AtifProvenance, FinalizeError> {
        // Round-18: ATIF trajectory read is bounded via MAX_ATIF_BYTES.
        // Sibling of round-17 F3 that missed this internal caller.
        let bytes = read_capped_async(path.to_path_buf(), av_core::fsutil::MAX_ATIF_BYTES)
            .await
            .map_err(|error| FinalizeError::Atif(error.to_string()))?;
        self.ensure_atif_provenance_from_bytes(path, session_id, &bytes)
            .await
    }

    /// Round-6 (hunt4 R-F2): variant taking already-read artifact bytes
    /// so the recovery scan doesn't read every artifact twice per tick.
    async fn ensure_atif_provenance_from_bytes(
        &self,
        path: &std::path::Path,
        session_id: &str,
        bytes: &[u8],
    ) -> Result<AtifProvenance, FinalizeError> {
        let expected = AtifProvenance {
            session_id: session_id.to_owned(),
            digest: av_core::digest::sha256_hex(bytes),
        };
        let provenance_path = path.with_extension("atif-auth");
        if provenance_path.exists() {
            let sealed = read_capped_async(provenance_path.clone(), av_core::fsutil::MAX_CONTROL_BYTES)
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

    /// Best-effort durable close-complete marker write (see
    /// [`CloseCompleteMarker`]). Never fails the close: a lost marker
    /// degrades to at most one duplicate SESSION_CLOSE on the next
    /// restart (the historical behavior), warned here.
    async fn persist_close_complete_marker(&self, session: &Session) {
        let atif_path: Option<std::path::PathBuf> = { session.atif_path.lock().clone() };
        let Some(atif_path) = atif_path else {
            return;
        };
        let digest = match self.ensure_atif_provenance(&atif_path, &session.id).await {
            Ok(provenance) => provenance.digest,
            Err(error) => {
                tracing::warn!(
                    session = %session.id,
                    %error,
                    "close-complete marker skipped: ATIF provenance unavailable; \
                     the next restart may re-emit one SESSION_CLOSE for this session"
                );
                return;
            }
        };
        let marker = CloseCompleteMarker {
            session_id: session.id.clone(),
            digest,
        };
        let sealed = match crate::journal::seal(&self.journal_key, CLOSE_COMPLETE_DOMAIN, 0, &marker) {
            Ok(sealed) => sealed,
            Err(error) => {
                tracing::warn!(session = %session.id, %error, "close-complete marker seal failed");
                return;
            }
        };
        if let Err(error) = persist_marker(&close_complete_marker_path(&atif_path), &sealed).await {
            tracing::warn!(
                session = %session.id,
                %error,
                "close-complete marker persist failed; \
                 the next restart may re-emit one SESSION_CLOSE for this session"
            );
        }
    }

    /// Read + authenticate a `{stem}.session.json` sidecar. Returns
    /// `Ok(None)` when the file no longer exists — recovery scans list the
    /// spool directory and then read entries one by one, and a concurrent
    /// client close legitimately removes the sidecar in between (its
    /// absence means the session finished; skipping is correct, warning is
    /// noise).
    async fn read_journal_metadata(
        &self,
        path: &std::path::Path,
    ) -> Result<Option<serde_json::Value>, FinalizeError> {
        // Round-18: bounded via MAX_CONTROL_BYTES — journal metadata
        // sidecar is a tiny sealed blob (session_id + identity +
        // workflow), so 1 MiB is a generous upper bound.
        let bytes = match read_capped_async(path.to_path_buf(), av_core::fsutil::MAX_CONTROL_BYTES).await {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(FinalizeError::Atif(error.to_string())),
        };
        crate::journal::open(&self.journal_key, "metadata", 0, &bytes)
            .map(Some)
            .map_err(FinalizeError::Atif)
    }

    fn verify_configured_receipt(&self, receipt: &Receipt) -> Result<(), FinalizeError> {
        if receipt.body.key_id != self.signer.key_id() {
            return Err(FinalizeError::Receipt(format!(
                "receipt key {:?} does not match configured key {:?}",
                receipt.body.key_id,
                self.signer.key_id()
            )));
        }
        let mut keyring = av_receipts::Keyring::new();
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
        let receipt_id = receipt.body.receipt_id.clone();
        let session = session_id.to_owned();
        tokio::task::spawn_blocking(move || {
            archive_conflicting_receipt(&path, &receipt_id, &session)?;
            av_core::fsutil::write_atomic(&path, &bytes)
        })
        .await
        .map_err(|error| FinalizeError::Task(error.to_string()))?
        .map_err(|error| FinalizeError::Receipt(error.to_string()))
    }

    async fn emit_receipt_event(&self, session: &Session, receipt: &Receipt) -> Result<(), FinalizeError> {
        self.emit_bridge_event(
            session,
            av_events::EventClass::Receipt,
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
        class: av_events::EventClass,
        payload: serde_json::Value,
        kind: &str,
    ) -> Result<(), FinalizeError> {
        let Some(bridge) = self.bridge.as_ref().map(Arc::clone) else {
            return Ok(());
        };
        let path = self.lifecycle_outbox_path(&session.id, kind);
        let mut outbox = if path.exists() {
            let sealed = read_capped_async(path.clone(), av_core::fsutil::MAX_CONTROL_BYTES)
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
            let event = av_events::OcsfEventBuilder::new(
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
                        "av_lifecycle_event_errors_total",
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

    /// Replay (publish + ack) one lifecycle outbox if it exists and is
    /// still unacked. Used by the pending-close sweep so it can never
    /// delete an intent whose event was never published. A missing
    /// outbox is not an error — it was either acked and removed by a
    /// prior close attempt, or never persisted (the caller decides how
    /// to recover that case).
    async fn replay_unacked_lifecycle_outbox(
        &self,
        session: &Session,
        kind: &str,
    ) -> Result<(), FinalizeError> {
        let Some(bridge) = self.bridge.as_ref().map(Arc::clone) else {
            return Ok(());
        };
        let path = self.lifecycle_outbox_path(&session.id, kind);
        let sealed = match read_capped_async(path.clone(), av_core::fsutil::MAX_CONTROL_BYTES).await {
            Ok(sealed) => sealed,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(FinalizeError::Bridge(error.to_string())),
        };
        let mut outbox: LifecycleOutbox = crate::journal::open(
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
        if outbox.ack.is_some() {
            return Ok(());
        }
        let event_uid = lifecycle_event_uid(&outbox.value)?;
        let ack = resolve_lifecycle_ack(
            bridge,
            outbox.topic.clone(),
            outbox.key.clone(),
            outbox.value.clone(),
            event_uid,
        )
        .await?;
        outbox.ack = Some(ack);
        persist_outbox(&path, &outbox, &self.journal_key).await
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
            let sealed = match read_capped_async(path.clone(), av_core::fsutil::MAX_CONTROL_BYTES).await {
                Ok(bytes) => bytes,
                // A concurrent close legitimately removes its outbox between
                // the directory listing and this read — normal operation.
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    tracing::warn!(%error, path = %av_core::fsutil::basename(&path), "skipping unreadable outbox file");
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
                    tracing::warn!(%error, path = %av_core::fsutil::basename(&path), "skipping malformed outbox");
                    continue;
                }
            };
            if path != self.lifecycle_outbox_path(&outbox.session_id, &outbox.kind) {
                tracing::warn!(
                    path = %av_core::fsutil::basename(&path),
                    "skipping outbox whose filename does not match its authenticated session_id/kind"
                );
                continue;
            }
            if outbox.ack.is_none() {
                let topic = outbox.topic.clone();
                let key = outbox.key.clone();
                let value = outbox.value.clone();
                // Per-outbox error isolation (round-16 stress finding): a
                // publish/ack-persist failure for ONE outbox — e.g. the
                // broker-ack write racing a concurrent client close whose
                // `remove_step_journal` just deleted the session's
                // broker-acks directory (ENOENT), or a transiently
                // unreachable broker — used to abort the entire recovery
                // pass via `?`, starving every other session's recovery
                // for the tick. Warn and continue; the outbox stays
                // unacked on disk and is retried next tick.
                let outcome: Result<(), FinalizeError> = async {
                    let event_uid = lifecycle_event_uid(&value)?;
                    outbox.ack =
                        Some(resolve_lifecycle_ack(Arc::clone(&bridge), topic, key, value, event_uid).await?);
                    persist_outbox(&path, &outbox, &self.journal_key).await
                }
                .await;
                match outcome {
                    Ok(()) => replayed = replayed.saturating_add(1),
                    Err(error) => {
                        tracing::warn!(
                            %error,
                            path = %av_core::fsutil::basename(&path),
                            "outbox replay failed for this session; will retry next tick"
                        );
                    }
                }
            }
        }
        Ok(replayed)
    }

    /// Round-43 F1: complete the finalization tail for sessions
    /// where `close_session_locked` marked `artifact_committed = 1`
    /// but returned Err before running the tail — typically a
    /// transient `emit_bridge_event(SESSION_CLOSE)` publish failure
    /// while the broker was unreachable, or a `remove_step_journal`
    /// EIO. Round-42 F3 handled the "orphaned in recovery" analogue
    /// inside `recover_signed_journals`, but the client
    /// `/v1/sessions/{id}/close` route and the idle-sweeper caller
    /// (both entering via `Finalizer::close_session`) inherited the
    /// same orphan-after-partial-close shape. Rather than removing
    /// the session from the registry (which would break the client
    /// contract that the id remains queryable), drive the tail to
    /// completion here: every step is idempotent
    /// (`emit_bridge_event` re-uses an existing outbox,
    /// `remove_step_journal` treats ENOENT as success, and
    /// `remove_lifecycle_outbox` is `rm -f`). Once
    /// `mark_close_complete` fires, `evict_finalized` can reclaim
    /// the registry slot.
    ///
    /// Per-session errors warn+continue via
    /// `av_pending_close_completion_failed_total` so one persistently-
    /// bad broker for one session does not HOL-block completion of
    /// every other pending-close session for the tick.
    pub(crate) async fn complete_pending_closes(
        &self,
        sessions: &SessionRegistry,
    ) -> Result<usize, FinalizeError> {
        let pending = sessions.pending_close_sessions();
        let mut completed = 0usize;
        for session in pending {
            // Round-44 F3: acquire the per-session lifecycle lock
            // before running the finalization tail. Without this the
            // sweep could race with a concurrent client `/v1/close`
            // (which also enters through `close_session` and holds
            // `acquire_lifecycle`), producing:
            //   - two parallel `resolve_lifecycle_ack` calls on the
            //     same event UID → duplicate SESSION_CLOSE OCSF
            //     events on the bridge for one session close,
            //   - transient re-creation of a just-deleted outbox
            //     file after the client's `remove_lifecycle_outbox`
            //     ran (visible to disk snapshots / backups),
            //   - split audit trail if a chat request arriving
            //     during the sweep triggers `get_or_open` reopen
            //     while the client's original `/close` is still
            //     `.await`ing on the old Arc.
            // The lifecycle lock is the same one every other
            // finalize path takes (reconciler.rs:302), so this
            // preserves the "close_session_locked is the single
            // serialization point for finalization tail work"
            // invariant.
            let _lifecycle = self.acquire_lifecycle(&session.id).await;
            // Re-check state under the lock — a concurrent client
            // close may have already driven this session to
            // completion between `pending_close_sessions()` and
            // this point.
            if !session.artifact_committed_flag() || session.close_complete_flag() {
                continue;
            }
            let workflow = session.workflow.as_str();
            let outcome: Result<(), FinalizeError> = async {
                // The receipt lifecycle event must reach the bridge before
                // its outbox is deleted below. A prior close can fail
                // between artifact commit and a successful receipt publish,
                // leaving the receipt outbox unacked (publish failed) or
                // never persisted (persist failed with the receipt still in
                // memory). The old sweep deleted the unacked outbox and
                // marked the close complete — silently losing the
                // audit-stream receipt event forever.
                if session.workflow == Workflow::Signed {
                    let receipt_outbox =
                        self.lifecycle_outbox_path(&session.id, crate::journal::RECEIPT_OUTBOX_KIND);
                    if receipt_outbox.exists() {
                        self.replay_unacked_lifecycle_outbox(&session, crate::journal::RECEIPT_OUTBOX_KIND)
                            .await?;
                    } else if !self
                        .lifecycle_outbox_path(&session.id, crate::journal::SESSION_CLOSE_OUTBOX_KIND)
                        .exists()
                    {
                        // No receipt outbox AND no session-close outbox: the
                        // prior close aborted before persisting the receipt
                        // intent (nothing was published — the intent is
                        // always persisted before any publish). Re-emit from
                        // the in-memory receipt when available. When the
                        // session-close outbox exists, the prior close got
                        // past a successful receipt emit, so the event is
                        // already on the bridge and its outbox was removed.
                        let receipt = session.receipt.lock().clone();
                        if let Some(receipt) = receipt {
                            self.emit_receipt_event(&session, &receipt).await?;
                        } else {
                            tracing::warn!(
                                session = %session.id,
                                "pending-close sweep found no receipt outbox and no in-memory receipt; \
                                 the receipt lifecycle event cannot be reconstructed (the signed receipt \
                                 file itself is on disk)"
                            );
                        }
                    }
                }
                self.emit_bridge_event(
                    &session,
                    av_events::EventClass::Session,
                    serde_json::json!({"action": "closed", "workflow": workflow}),
                    crate::journal::SESSION_CLOSE_OUTBOX_KIND,
                )
                .await?;
                self.remove_step_journal(&session.id).await?;
                self.remove_tool_executions(&session.id).await?;
                self.remove_lifecycle_outbox(&session.id, crate::journal::RECEIPT_OUTBOX_KIND)
                    .await?;
                self.remove_lifecycle_outbox(&session.id, crate::journal::SESSION_CLOSE_OUTBOX_KIND)
                    .await?;
                self.metrics
                    .counter("av_sessions_finalized_total", "Sessions finalized")
                    .inc();
                // Same durable marker as the normal close tail: the sweep just
                // published (or verified) the SESSION_CLOSE for this session.
                if session.workflow == Workflow::Unsigned {
                    self.persist_close_complete_marker(&session).await;
                }
                session.mark_close_complete();
                // Mirror the normal close tail (close_session_locked):
                // without this the sweep leaked the session's budget
                // counters in the state store forever, and a recycled id
                // (get_or_open reopens completed-close entries) inherited
                // the stale counters → spurious BudgetExceeded on the
                // fresh incarnation.
                self.clear_budget_state(&session.id);
                // Also mirror the round-6 (hunt4 R2) builder drain:
                // an unsigned session whose close committed the artifact
                // but failed in the tail reaches close-complete through
                // THIS sweep, not close_session_locked — without the
                // drain here its full step builder stayed resident for
                // the life of the process (unsigned sessions are never
                // evicted from the registry).
                session.drain_trajectory_builder();
                // Mirror the close-tail embedding release (see
                // close_session_locked).
                session.loop_state.release_embedding();
                Ok(())
            }
            .await;
            match outcome {
                Ok(()) => completed = completed.saturating_add(1),
                Err(error) => {
                    self.metrics
                        .counter(
                            "av_pending_close_completion_failed_total",
                            "Pending-close completions that failed to finish their tail (round-43 F1)",
                        )
                        .inc();
                    let key = self.spool_dir.join(format!("pending-close::{}", session.id));
                    if self.warn_once(key) {
                        tracing::warn!(
                            session = %session.id,
                            %error,
                            "pending-close completion failed; will retry next tick",
                        );
                    }
                }
            }
        }
        Ok(completed)
    }

    async fn remove_acked_lifecycle_outboxes(&self, sessions: &SessionRegistry) -> Result<(), FinalizeError> {
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
            let sealed = match read_capped_async(path.clone(), av_core::fsutil::MAX_CONTROL_BYTES).await {
                Ok(bytes) => bytes,
                // A concurrent close legitimately removes its outbox between
                // the directory listing and this read — normal operation.
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    tracing::warn!(%error, path = %av_core::fsutil::basename(&path), "skipping unreadable outbox during acked-outbox GC");
                    continue;
                }
            };
            // Per-file error isolation (round-16 stress finding): a single
            // corrupt or misplaced outbox used to abort this GC — and with
            // it the entire recovery pass — via `?` on EVERY tick, forever.
            // Mirror `replay_lifecycle_outboxes`: warn and continue, leaving
            // the bad file on disk as forensic evidence.
            let outbox: LifecycleOutbox = match crate::journal::open(
                &self.journal_key,
                crate::journal::LIFECYCLE_OUTBOX_DOMAIN,
                0,
                &sealed,
            ) {
                Ok(outbox) => outbox,
                Err(error) => {
                    tracing::warn!(%error, path = %av_core::fsutil::basename(&path), "skipping malformed outbox during acked-outbox GC");
                    continue;
                }
            };
            if path != self.lifecycle_outbox_path(&outbox.session_id, &outbox.kind) {
                tracing::warn!(
                    path = %av_core::fsutil::basename(&path),
                    "skipping outbox whose filename does not match its authenticated session_id/kind"
                );
                continue;
            }
            if outbox.ack.is_some() {
                // Keep acked outboxes for sessions whose close has not
                // completed: the pending-close sweep uses outbox presence to
                // decide whether the receipt event already reached the
                // bridge. Deleting an acked receipt outbox while its session
                // is still pending close would make the sweep re-emit the
                // receipt event with a fresh uid — a duplicate on the audit
                // stream. The retention condition mirrors
                // `pending_close_sessions()`: capture-failed and
                // empty-unsigned quarantined sessions are permanently
                // excluded from the sweep (and from eviction), so their
                // acked outboxes can never be consumed and retaining them
                // would leak the files forever — collect those, plus true
                // orphans whose session is gone or close-complete.
                if sessions.get(&outbox.session_id).is_some_and(|session| {
                    !session.close_complete_flag()
                        && !session.capture_failed()
                        && !session.is_empty_unsigned_quarantine()
                }) {
                    continue;
                }
                // Round-17 live-stress finding: an acked RECEIPT outbox is
                // ALSO the dedup anchor for promotion retries. When a
                // promotion fails after emitting the receipt event (its
                // `.promote` marker stays for retry), the retry's
                // `emit_bridge_event` re-reads this outbox to reuse the
                // published event's uid. GC'ing it (the session is
                // close-complete by then) made the retry mint a fresh uid
                // and publish a DUPLICATE receipt event. Retain acked
                // receipt outboxes while their promotion marker exists.
                if outbox.kind == crate::journal::RECEIPT_OUTBOX_KIND {
                    let session_hash = &av_core::digest::sha256_hex(outbox.session_id.as_bytes())[..32];
                    if self.spool_dir.join(format!("{session_hash}.promote")).exists() {
                        continue;
                    }
                }
                remove_outbox(&path).await?;
            }
        }
        Ok(())
    }

    fn lifecycle_outbox_path(&self, session_id: &str, kind: &str) -> PathBuf {
        let session_hash = &av_core::digest::sha256_hex(session_id.as_bytes())[..32];
        self.spool_dir
            .join(crate::spool::OUTBOX)
            .join(format!("{session_hash}.{kind}.json"))
    }

    async fn remove_lifecycle_outbox(&self, session_id: &str, kind: &str) -> Result<(), FinalizeError> {
        remove_outbox(&self.lifecycle_outbox_path(session_id, kind)).await
    }
}

/// ATIF trajectory paths are keyed by `sha256(session_id)` exactly like
/// receipt paths, and `get_or_open` recycles completed-close session
/// ids — a second incarnation of a recycled id would otherwise silently
/// overwrite the first incarnation's on-disk trajectory, and the stale
/// `.atif-auth` provenance sidecar (sealed over the OLD bytes) would
/// then fail `ensure_atif_provenance` on every finalize of the new
/// incarnation. Archive any existing artifact whose `trajectory_id`
/// differs — together with its sidecar so the archived pair stays
/// verifiable — before writing. Same-trajectory-id rewrites stay
/// idempotent overwrites on the primary path; an unreadable or corrupt
/// existing file is archived too rather than destroyed. Archived names
/// drop the `.json` extension (same convention as the recovery scan's
/// `.corrupt-<uid>` quarantine) so the recovery scan never re-adopts a
/// superseded incarnation.
/// Round-6 (hunt2 crosscrate F1): normalize `agent.extra.ttl_remaining_s`
/// to null before an equality comparison between a close-time and a
/// recovery-rebuilt trajectory. The field carries a per-validation
/// wall-clock recomputation, not an identity fact.
fn normalize_extra_ttl(trajectory: &mut av_atif::Trajectory) {
    if let Some(extra) = trajectory.agent.extra.as_mut() {
        if let Some(object) = extra.as_object_mut() {
            if object.contains_key("ttl_remaining_s") {
                object.insert("ttl_remaining_s".to_owned(), serde_json::Value::Null);
            }
        }
    }
}

/// Same comparison-copy normalization class as [`normalize_extra_ttl`]:
/// the enforcement latch is close-time in-memory state the journal
/// cannot reconstruct, so the consolidation rebuild writes 0 and the
/// rebuilt-vs-existing equality must not fire on that key alone.
fn normalize_extra_enforcement(trajectory: &mut av_atif::Trajectory) {
    if let Some(metrics) = trajectory.final_metrics.as_mut() {
        if let Some(extra) = metrics.extra.as_mut() {
            if let Some(object) = extra.as_object_mut() {
                if object.contains_key("enforcement_latched") {
                    object.insert("enforcement_latched".to_owned(), serde_json::Value::Null);
                }
            }
        }
    }
}

fn archive_conflicting_atif(
    path: &std::path::Path,
    new_trajectory_id: Option<&str>,
    session_id: &str,
) -> std::io::Result<()> {
    let existing_id = match av_core::fsutil::read_capped(path, av_core::fsutil::MAX_ATIF_BYTES) {
        Ok(bytes) => serde_json::from_slice::<serde_json::Value>(&bytes)
            .ok()
            .and_then(|existing| {
                existing
                    .get("trajectory_id")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
            }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        // Unreadable existing file: treat conservatively as evidence
        // from a prior incarnation and archive it.
        Err(_) => None,
    };
    if existing_id.is_some() && existing_id.as_deref() == new_trajectory_id {
        return Ok(());
    }
    // Trajectory ids come from `new_event_uid` (UUIDv7), but the bytes
    // on disk are untrusted — keep only filesystem-safe characters so a
    // planted trajectory_id cannot steer the archive path. `'.'` is
    // deliberately excluded: a planted id ending in `.json` would give
    // `with_extension` an archived name whose `extension()` is still
    // `json`, re-entering the recovery scan this rename exists to escape
    // (the scan would then quarantine the archive as sidecar-less,
    // splitting the archived evidence pair).
    let mut suffix: String = existing_id
        .unwrap_or_default()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
        .take(64)
        .collect();
    if suffix.is_empty() {
        suffix = format!("corrupt-{}", av_core::new_event_uid());
    }
    let mut archived = path.with_extension(format!("archived-{suffix}"));
    if archived.exists() {
        archived = path.with_extension(format!("archived-{suffix}-{}", av_core::new_event_uid()));
    }
    tracing::warn!(
        session = %session_id,
        archived = %av_core::fsutil::basename(&archived),
        "ATIF path collision (recycled session id); archiving previous incarnation's trajectory",
    );
    std::fs::rename(path, &archived)?;
    // Move the sidecar alongside so the archived pair stays verifiable and
    // the new incarnation's provenance is sealed fresh. A missing sidecar
    // (crash between artifact write and provenance seal) is fine — the
    // primary path simply has none to clear.
    let sidecar = path.with_extension("atif-auth");
    let mut archived_sidecar = archived.clone();
    archived_sidecar.as_mut_os_string().push(".atif-auth");
    match std::fs::rename(&sidecar, &archived_sidecar) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    // The close-complete marker is bound to the OLD artifact's digest —
    // archive it alongside so the new incarnation cannot inherit it (the
    // recovery scan also digest-verifies markers as defense-in-depth).
    let close_marker = close_complete_marker_path(path);
    let mut archived_marker = archived.clone();
    archived_marker.as_mut_os_string().push(".close-complete");
    match std::fs::rename(&close_marker, &archived_marker) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    // The promotion marker is likewise digest-bound to the OLD artifact. A
    // first incarnation that crashed mid-promotion leaves it on disk;
    // `promote()` hard-errors on a digest mismatch with the marker left in
    // place, so the stale marker would permanently block every future
    // promotion of the recycled id (and warn from retry_marked_promotions
    // every tick) until manual removal.
    //
    // Round-48 F1: the archived name MUST NOT have `Path::extension()`
    // equal to `"promote"` — that extension re-enters the
    // `retry_marked_promotions` scan filter (`reconciler.rs:2227`), which
    // then MAC-verifies the archived bytes (unchanged by rename), looks
    // up `sessions.get(&marker.session_id)` and gets the *recycled*
    // Session (S2) — and calls `promote(S2)` on it. Effect: an
    // unrequested promotion of S2 minted a receipt and emitted a
    // receipt event no operator asked for; the archived marker stayed
    // on disk forever, re-firing every tick. Appending
    // `.promote-archived` keeps the "promote" hint in the name while
    // making the extension `promote-archived` — outside the scan
    // filter — and is stable for forensic inspection.
    let promote_marker = path.with_extension("promote");
    let mut archived_promote = archived.clone();
    archived_promote.as_mut_os_string().push(".promote-archived");
    match std::fs::rename(&promote_marker, &archived_promote) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// Receipt paths are keyed by `sha256(session_id)`, and `get_or_open`
/// recycles completed-close session ids — a second incarnation of a
/// recycled id would otherwise silently overwrite the first
/// incarnation's on-disk receipt (local evidence loss; the receipt
/// event was already published via the bridge, so not total loss).
/// Archive any existing receipt whose id differs before writing.
/// Same-receipt-id rewrites stay idempotent overwrites on the primary
/// path; an unreadable or corrupt existing file is archived too rather
/// than destroyed.
fn archive_conflicting_receipt(
    path: &std::path::Path,
    new_receipt_id: &str,
    session_id: &str,
) -> std::io::Result<()> {
    let existing_id = match av_core::fsutil::read_capped(path, av_core::fsutil::MAX_RECEIPT_BYTES) {
        Ok(bytes) => serde_json::from_slice::<Receipt>(&bytes)
            .ok()
            .map(|existing| existing.body.receipt_id),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        // Unreadable existing file: treat conservatively as evidence
        // from a prior incarnation and archive it.
        Err(_) => None,
    };
    if existing_id.as_deref() == Some(new_receipt_id) {
        return Ok(());
    }
    // Old receipt ids come from `new_event_uid` (UUIDv7), but the bytes
    // on disk are untrusted — keep only filesystem-safe characters so a
    // planted receipt_id cannot steer the archive path.
    let mut suffix: String = existing_id
        .unwrap_or_default()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        .take(64)
        .collect();
    if suffix.is_empty() {
        suffix = format!("corrupt-{}", av_core::new_event_uid());
    }
    let mut archived = path.with_extension(format!("archived-{suffix}.json"));
    if archived.exists() {
        archived = path.with_extension(format!("archived-{suffix}-{}.json", av_core::new_event_uid()));
    }
    tracing::warn!(
        session = %session_id,
        archived = %av_core::fsutil::basename(&archived),
        "receipt path collision (recycled session id); archiving previous incarnation's receipt",
    );
    std::fs::rename(path, &archived)
}

async fn persist_outbox(
    path: &std::path::Path,
    outbox: &LifecycleOutbox,
    journal_key: &[u8; 32],
) -> Result<(), FinalizeError> {
    let path = path.to_path_buf();
    let bytes = crate::journal::seal(journal_key, crate::journal::LIFECYCLE_OUTBOX_DOMAIN, 0, outbox)
        .map_err(FinalizeError::Bridge)?;
    tokio::task::spawn_blocking(move || av_core::fsutil::write_atomic(&path, &bytes))
        .await
        .map_err(|error| FinalizeError::Task(error.to_string()))?
        .map_err(|error| FinalizeError::Bridge(error.to_string()))
}

async fn persist_marker(path: &std::path::Path, bytes: &[u8]) -> Result<(), FinalizeError> {
    let path = path.to_path_buf();
    let bytes = bytes.to_vec();
    tokio::task::spawn_blocking(move || av_core::fsutil::write_atomic(&path, &bytes))
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
            Ok(()) => {
                // Round-19 F2 (av-harness reconciler): the file is
                // gone from the caller's perspective — its inode is
                // released once the last handle closes. A failing
                // `sync_directory` here means the DIRECTORY ENTRY
                // removal is not yet durable across a crash, but the
                // caller-observable state ("no such outbox marker")
                // is stable. Returning `Err` in this arm made
                // callers retry the whole operation, and paths that
                // infer state from outbox presence — see
                // `recover_signed_journals` around
                // reconciler.rs:2778-2793 — would then re-emit
                // duplicate lifecycle events off the retry, because
                // the first pass had ALREADY moved the state
                // forward. Log the durability warning and return Ok:
                // an unsynced dirent survives a normal shutdown and
                // is retried by the reconciler on next tick if a
                // crash truly loses it.
                if let Err(error) = av_core::fsutil::sync_directory(parent) {
                    // Round-6 (hunt4 F20): basename discipline —
                    // absolute paths in log fields defeat the round-36
                    // sweep everywhere else in this file.
                    tracing::warn!(
                        target: "av_harness::reconciler",
                        path = %av_core::fsutil::basename(&path),
                        parent = %av_core::fsutil::basename(parent),
                        detail = %error,
                        "remove_outbox: dirent unsync but file removed; caller state is stable, \
                         relying on reconciler retry to re-sync on next tick"
                    );
                }
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(FinalizeError::Bridge(error.to_string())),
        }
    })
    .await
    .map_err(|error| FinalizeError::Task(error.to_string()))?
}

/// Start the periodic reconciler tick: spool recovery, promotion retry,
/// pending-close completion, idle-session finalization, and
/// finalized-session eviction.
pub fn spawn_reconciler(
    sessions: Arc<SessionRegistry>,
    finalizer: Finalizer,
    idle_s: u64,
    tick_s: u64,
    breaker: av_loopdetect::BreakerConfig,
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
                        .counter("av_reconcile_errors_total", "Reconciliation errors")
                        .inc();
                }
                if let Err(error) = finalizer.retry_marked_promotions(&sessions).await {
                    tracing::warn!(%error, "durable promotion retry failed");
                    metrics
                        .counter("av_reconcile_errors_total", "Reconciliation errors")
                        .inc();
                }
                // Round-43 F1: drive the finalization tail forward for
                // sessions that got past `mark_artifact_committed` but
                // failed the subsequent SESSION_CLOSE emit or journal
                // cleanup on a prior tick / client call. Without this
                // sweep those sessions accumulate in the registry
                // forever and their step journals never get removed.
                if let Err(error) = finalizer.complete_pending_closes(&sessions).await {
                    tracing::warn!(%error, "pending-close completion sweep failed");
                    metrics
                        .counter("av_reconcile_errors_total", "Reconciliation errors")
                        .inc();
                }
                // Bounded batch: idle closes run serially inside the
                // tick (each is a full finalize with journal + broker
                // I/O), and an unbounded batch collapsed tick cadence
                // under churn — soak-measured single ticks of ~150 s
                // while thousands of aborted sessions went idle at
                // once, starving close/promote calls and pending-close
                // completion for minutes. Cap the per-tick batch; the
                // remainder is still idle next tick and closes then.
                const MAX_IDLE_CLOSES_PER_TICK: usize = 64;
                let idle = sessions.idle_sessions(idle_s);
                let deferred = idle.len().saturating_sub(MAX_IDLE_CLOSES_PER_TICK);
                if deferred > 0 {
                    tracing::info!(
                        closing = MAX_IDLE_CLOSES_PER_TICK,
                        deferred,
                        "idle-close batch capped; remaining sessions close on later ticks"
                    );
                }
                for session in idle.into_iter().take(MAX_IDLE_CLOSES_PER_TICK) {
                    let session_id = session.id.clone();
                    if let Err(error) = finalizer.close_session(session, StopReason::SessionClosed).await {
                        tracing::warn!(session = %session_id, %error, "idle session finalization failed");
                        metrics
                            .counter("av_reconcile_errors_total", "Reconciliation errors")
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
                        "av_reconciler_panics_total",
                        "Reconciler tick body panicked; loop supervised via catch_unwind",
                    )
                    .inc();
                tracing::error!(
                    panic = %msg,
                    "reconciler tick body panicked; continuing on the next tick"
                );
            }
            metrics
                .histogram("av_reconcile_duration_seconds", "Idle reconciliation duration")
                .observe_us(elapsed_us(started));
        }
    })
}

fn checked_recovery_add(current: u64, value: u64, field: &str) -> Result<u64, FinalizeError> {
    current
        .checked_add(value)
        .filter(|total| *total <= av_core::error::JCS_SAFE_MAX)
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
) -> Result<av_bridge::PublishAck, FinalizeError> {
    let lookup_bridge = Arc::clone(&bridge);
    let lookup_topic = topic.clone();
    let lookup_key = key.clone();
    let lookup_uid = event_uid.clone();
    if let Some(ack) = tokio::task::spawn_blocking(move || {
        lookup_bridge.find_event_by_uid(&lookup_topic, &lookup_key, &lookup_uid)
    })
    .await
    .map_err(|error| FinalizeError::Task(error.to_string()))?
    .map_err(FinalizeError::from)?
    {
        return Ok(ack);
    }
    tokio::task::spawn_blocking(move || bridge.publish_idempotent(&topic, &key, &value, &event_uid))
        .await
        .map_err(|error| FinalizeError::Task(error.to_string()))?
        .map_err(FinalizeError::from)
}

/// Round-14 F5: check whether `read_complete_journal` has previously
/// quarantined this stem's events journal to
/// `<stem>.events.ndjson.corrupt-*`. Callers use this to decide
/// whether to delete the sealed metadata sidecar when the events
/// journal appears empty — if there's a sibling `.corrupt-*` file,
/// the "empty" is actually "torn and moved out for post-mortem" and
/// the metadata must be preserved (or quarantined itself) rather
/// than removed.
async fn quarantine_sibling_exists(spool_dir: &std::path::Path, stem: &str) -> Result<bool, FinalizeError> {
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

/// Round-17 F3: async wrapper around `av_core::fsutil::read_capped`
/// for the reconciler's hot-path reads. A fs-tamper attacker
/// (co-scheduled workload, backup restore gone wrong, malicious
/// sidecar) can otherwise plant a multi-GB receipt/trajectory and
/// OOM the harness on every recovery tick. `spawn_blocking` keeps
/// the tokio runtime healthy while `File::open` + `metadata` +
/// bounded `read_to_end` run on the blocking pool.
async fn read_capped_async(path: std::path::PathBuf, max_bytes: u64) -> Result<Vec<u8>, std::io::Error> {
    tokio::task::spawn_blocking(move || av_core::fsutil::read_capped(&path, max_bytes))
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?
}

async fn read_complete_journal(path: &std::path::Path) -> Result<Vec<String>, FinalizeError> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || -> Result<Vec<String>, FinalizeError> {
        // Round-18: bounded via the shared MAX_ATIF_BYTES so a fs-tamper
        // attacker cannot plant a multi-GB journal and OOM the
        // recovery scan.
        let bytes = av_core::fsutil::read_capped(&path, av_core::fsutil::MAX_ATIF_BYTES)
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
            let new_name = format!("{stem}.corrupt-{}", av_core::new_event_uid());
            quarantine.set_file_name(new_name);
            let rename_error_message = match std::fs::rename(&path, &quarantine) {
                Ok(()) => {
                    tracing::error!(
                        original = %av_core::fsutil::basename(&path),
                        quarantine = %av_core::fsutil::basename(&quarantine),
                        bytes = bytes.len(),
                        "journal has no complete lines; quarantined for post-mortem instead of silent 0-truncate"
                    );
                    None
                }
                Err(rename_error) => {
                    tracing::error!(
                        path = %av_core::fsutil::basename(&path),
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
            // and `"promotion retry failed"` (grep those literals);
            // both then export through
            // tracing_opentelemetry -> OTLP -> SIEM. Round-36 F1's
            // sweep basenamed the outer tracing fields but missed
            // this path leak inside a FinalizeError message body,
            // where `#[error("...{0}")]` re-emits the full string.
            let name = av_core::fsutil::basename(&path);
            let qname = av_core::fsutil::basename(&quarantine);
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
                path = %av_core::fsutil::basename(&path),
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
    use av_bridge::{BusError, PublishAck, StoredEvent};
    use av_events::AgentIdentity;
    use av_receipts::Ed25519Signer;

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
            av_events::EventClass::all()
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
        let receipt_event_uid = av_core::new_event_uid();
        let value = serde_json::json!({
            "metadata": { "sequence": receipt_seq, "uid": receipt_event_uid },
            "topic": av_events::EventClass::Receipt.topic(),
        });
        let outbox = LifecycleOutbox {
            session_id: session.id.clone(),
            kind: crate::journal::RECEIPT_OUTBOX_KIND.to_owned(),
            topic: av_events::EventClass::Receipt.topic().to_owned(),
            key: session.identity.instance_uid.clone(),
            value,
            ack: Some(av_bridge::PublishAck {
                topic: av_events::EventClass::Receipt.topic().to_owned(),
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
            .find(|(topic, _)| topic == av_events::EventClass::Session.topic())
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
        use av_events::{EventClass, OcsfEventBuilder, StatusId};
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
        let digest = av_core::digest::sha256_hex(session_id.as_bytes());
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
        // block every other.
        //
        // Round-42 F3: transient close errors (Bridge / Receipt /
        // Atif / Task) now REMOVE the half-committed session from
        // the registry instead of leaving it orphaned with
        // `artifact_committed = 1` forever. The security invariant
        // this test enforces (post-error the session cannot be
        // leased and thus cannot have its chain diverged) still
        // holds — even more strongly, because the session is no
        // longer in the registry to be looked up at all. The
        // journal sidecar remains on disk so the next reconciler
        // tick re-adopts cleanly once the transient cause clears.
        assert!(
            result.is_ok(),
            "round-41 F1: per-session errors warn+continue; got {result:?}",
        );

        assert!(
            registry.get(session_id).is_none(),
            "round-42 F3: after a transient close error the session must be removed from the registry so the next reconciler tick can re-adopt via the still-present journal sidecar — leaving it in the registry with `is_closed()` = true would starve recovery forever",
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
        //
        // Note (round-49 audit): this test does NOT plant a healthy
        // signed session alongside — a healthy signed session that
        // actually reaches recovery requires a mid-flight-crashed
        // journal fixture (the live `close_session` path
        // fully removes the journal on success, so the healthy
        // recovery corpus is intentionally empty here). The invariant
        // this test locks in is the OUTER `Ok(())` — any regression
        // that propagates the sidecar Err through
        // `recover_spooled_sessions` would fail
        // `assert!(outcome.is_ok())`.
        let poison_stem = "poisonpoisonpoisonpoisonpoison32";
        std::fs::write(
            directory.path().join(format!("{poison_stem}.session.json")),
            b"{\"garbage\": true, \"not\": \"a valid sealed metadata\"}",
        )
        .unwrap();
        std::fs::write(
            directory.path().join(format!("{poison_stem}.events.ndjson")),
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

    /// Round-43 F1: fire-and-forget close (no client retry, no idle
    /// sweeper hit) that failed at `emit_receipt_event` AFTER
    /// `mark_artifact_committed` used to leave the session
    /// permanently orphaned in the registry — `is_closed()` is true
    /// so the idle sweeper skips it, `close_complete = 0` so
    /// `evict_finalized` refuses it, and recovery scans hit the
    /// "already in registry" short-circuit. `complete_pending_closes`
    /// now drives the finalization tail to completion on the next
    /// reconciler tick without any client involvement.
    #[tokio::test]
    async fn round_43_f1_pending_close_completes_via_reconciler_sweep() {
        let directory = tempfile::tempdir().unwrap();
        let bus = Arc::new(FailFirstReceiptBus {
            fail: std::sync::atomic::AtomicBool::new(true),
            attempts: parking_lot::Mutex::new(Vec::new()),
        });
        let finalizer = Finalizer::with_bridge(
            Arc::new(Ed25519Signer::from_seed(&[43; 32])),
            directory.path().to_path_buf(),
            Arc::new(Registry::new()),
            bus.clone(),
        );
        let sessions = SessionRegistry::new();
        let session = session(Workflow::Signed);
        // Install into registry so `pending_close_sessions` can see it.
        sessions.insert_recovered(Arc::try_unwrap(session.clone()).unwrap_or_else(|arc| {
            Session::new(
                arc.id.clone(),
                arc.workflow,
                arc.current_identity(),
                Default::default(),
            )
        }));
        // Look up the Arc actually stored in the registry (identity
        // mapping after insert_recovered).
        let registered = sessions.get(&session.id).unwrap();

        // First close attempt: signed workflow persists receipt on
        // disk, marks `artifact_committed = 1`, then fails on
        // `emit_receipt_event` via the injected bus outage. This is
        // the fire-and-forget window — no second `close_session` call
        // will follow.
        assert!(matches!(
            finalizer
                .close_session(Arc::clone(&registered), StopReason::SessionClosed)
                .await,
            Err(FinalizeError::Bridge(_))
        ));
        assert!(
            registered.artifact_committed_flag(),
            "signed close must have persisted the receipt and marked artifact_committed before the emit_receipt_event failure",
        );
        assert!(
            !registered.close_complete_flag(),
            "close_complete must NOT be set yet — the finalization tail did not run",
        );
        // Pre-round-43 the session would sit here forever.
        let pending = sessions.pending_close_sessions();
        assert_eq!(pending.len(), 1, "sweep must see the orphaned session");
        assert_eq!(pending[0].id, registered.id);

        // Simulate the next reconciler tick — `replay_lifecycle_outboxes`
        // publishes the pending receipt event (the bus outage was one-
        // shot, so the retry succeeds), then `complete_pending_closes`
        // drives the tail to `mark_close_complete`.
        finalizer.replay_lifecycle_outboxes().await.unwrap();
        let completed = finalizer.complete_pending_closes(&sessions).await.unwrap();
        assert_eq!(completed, 1, "sweep must complete the orphan");
        assert!(
            registered.close_complete_flag(),
            "close_complete must be set after the sweep — round-43 F1 invariant",
        );
        assert!(
            sessions.pending_close_sessions().is_empty(),
            "no sessions remain in the pending-close set once completed",
        );
        // Step journal cleanup ran too — no debris on disk.
        let digest = av_core::digest::sha256_hex(registered.id.as_bytes());
        let stem = digest.get(..32).unwrap();
        assert!(
            !directory.path().join(format!("{stem}.session.json")).exists(),
            "step journal metadata sidecar must be removed by the completion sweep",
        );
    }

    /// The round-43 pending-close sweep runs the same finalization tail
    /// as `close_session_locked` and must therefore also clear the
    /// session's budget counters — otherwise they leak in the state
    /// store unboundedly and a recycled session id (`get_or_open`
    /// reopens completed-close entries) inherits the stale counters,
    /// tripping a spurious BudgetExceeded on the fresh incarnation.
    #[tokio::test]
    async fn pending_close_sweep_clears_budget_state_like_normal_close() {
        let directory = tempfile::tempdir().unwrap();
        let bus = Arc::new(FailFirstReceiptBus {
            fail: std::sync::atomic::AtomicBool::new(true),
            attempts: parking_lot::Mutex::new(Vec::new()),
        });
        let store: Arc<dyn av_state::StateStore> = Arc::new(av_state::InMemoryStore::new());
        let finalizer = Finalizer::with_bridge(
            Arc::new(Ed25519Signer::from_seed(&[43; 32])),
            directory.path().to_path_buf(),
            Arc::new(Registry::new()),
            bus,
        )
        .with_state_store(Arc::clone(&store));
        let sessions = SessionRegistry::new();
        let session = session(Workflow::Signed);
        sessions.insert_recovered(Session::new(
            session.id.clone(),
            session.workflow,
            session.current_identity(),
            Default::default(),
        ));
        let registered = sessions.get(&session.id).unwrap();
        let budget_key = format!(
            "{}tool_calls",
            av_state::ActionBudget::session_prefix(&registered.id)
        );
        store.add(&budget_key, 5).unwrap();

        // First close fails on the injected receipt-bus outage AFTER
        // mark_artifact_committed — the fire-and-forget orphan window.
        assert!(matches!(
            finalizer
                .close_session(Arc::clone(&registered), StopReason::SessionClosed)
                .await,
            Err(FinalizeError::Bridge(_))
        ));
        assert_eq!(
            store.get(&budget_key).unwrap(),
            5,
            "budget counters must survive a failed close (session may still be retried)",
        );

        finalizer.replay_lifecycle_outboxes().await.unwrap();
        let completed = finalizer.complete_pending_closes(&sessions).await.unwrap();
        assert_eq!(completed, 1);
        assert!(registered.close_complete_flag());
        assert_eq!(
            store.get(&budget_key).unwrap(),
            0,
            "sweep must clear budget counters exactly like close_session_locked",
        );
        assert_eq!(
            finalizer
                .metrics
                .counter("av_sessions_finalized_total", "Sessions finalized")
                .get(),
            1,
            "sweep completion must count as a finalized session",
        );
    }

    /// Receipt paths are keyed by sha256(session_id) and `get_or_open`
    /// recycles completed-close session ids, so a second incarnation
    /// writing its receipt must archive — not overwrite — the first
    /// incarnation's on-disk receipt. Same-receipt-id rewrites stay
    /// idempotent, and a corrupt existing file is archived too.
    #[tokio::test]
    async fn persist_receipt_archives_previous_incarnation_on_recycled_id() {
        let directory = tempfile::tempdir().unwrap();
        let finalizer = finalizer(directory.path());
        let session = session(Workflow::Signed);
        let subject = || av_receipts::ReceiptSubject::EventChain {
            chain_head: "aa".repeat(32),
            event_count: 0,
        };
        let receipts_dir = directory.path().join("receipts");
        let json_files = |dir: &std::path::Path| {
            std::fs::read_dir(dir)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|e| e.path().extension().and_then(std::ffi::OsStr::to_str) == Some("json"))
                .count()
        };

        let first = Receipt::issue(
            session.receipt_body(subject(), StopReason::SessionClosed),
            finalizer.signer.as_ref(),
        )
        .unwrap();
        finalizer.persist_receipt(&session.id, &first).await.unwrap();
        // Idempotent same-id rewrite: no archive appears.
        finalizer.persist_receipt(&session.id, &first).await.unwrap();
        assert_eq!(
            json_files(&receipts_dir),
            1,
            "same-id rewrite must stay idempotent"
        );

        // Second incarnation of the recycled id issues a fresh receipt.
        let second = Receipt::issue(
            session.receipt_body(subject(), StopReason::SessionClosed),
            finalizer.signer.as_ref(),
        )
        .unwrap();
        assert_ne!(first.body.receipt_id, second.body.receipt_id);
        finalizer.persist_receipt(&session.id, &second).await.unwrap();
        assert_eq!(
            json_files(&receipts_dir),
            2,
            "first incarnation's receipt must be archived, not overwritten",
        );
        let primary: Receipt =
            serde_json::from_slice(&std::fs::read(finalizer.receipt_path(&session.id)).unwrap()).unwrap();
        assert_eq!(primary.body.receipt_id, second.body.receipt_id);
        let archived = finalizer
            .receipt_path(&session.id)
            .with_extension(format!("archived-{}.json", first.body.receipt_id));
        let archived: Receipt = serde_json::from_slice(&std::fs::read(&archived).unwrap()).unwrap();
        assert_eq!(archived.body.receipt_id, first.body.receipt_id);

        // Corrupt existing file at the primary path is archived conservatively.
        std::fs::write(finalizer.receipt_path(&session.id), b"{not json").unwrap();
        finalizer.persist_receipt(&session.id, &second).await.unwrap();
        assert_eq!(
            json_files(&receipts_dir),
            3,
            "corrupt bytes at the receipt path must be archived, not destroyed",
        );
        let primary: Receipt =
            serde_json::from_slice(&std::fs::read(finalizer.receipt_path(&session.id)).unwrap()).unwrap();
        assert_eq!(primary.body.receipt_id, second.body.receipt_id);
    }

    /// ATIF trajectory paths share the sha256(session_id) keying, so a
    /// recycled session id's second incarnation must archive — not
    /// overwrite — the first incarnation's trajectory, and must move the
    /// `.atif-auth` sidecar alongside so the stale digest cannot fail
    /// every subsequent finalize of the new incarnation. Same-id rewrites
    /// stay idempotent; archived names drop the `.json` extension so the
    /// recovery scan never re-adopts a superseded incarnation.
    #[test]
    fn archive_conflicting_atif_preserves_previous_incarnation() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("abc123.json");
        // No existing file: nothing to archive.
        archive_conflicting_atif(&path, Some("traj-2"), "s").unwrap();
        std::fs::write(&path, br#"{"trajectory_id": "traj-1"}"#).unwrap();
        let sidecar = path.with_extension("atif-auth");
        std::fs::write(&sidecar, b"sealed-old").unwrap();
        // Digest-bound companion markers from the first incarnation: a
        // stale close-complete marker would wrongly suppress the new
        // incarnation's close event; a stale promotion marker would
        // permanently hard-fail every promote of the recycled id (the
        // digest-mismatch branch errors with the marker left in place).
        let close_marker = path.with_extension("close-complete");
        std::fs::write(&close_marker, b"sealed-close").unwrap();
        let promote_marker = path.with_extension("promote");
        std::fs::write(&promote_marker, b"sealed-promote").unwrap();
        // Same-id rewrite: idempotent, nothing moves.
        archive_conflicting_atif(&path, Some("traj-1"), "s").unwrap();
        assert!(path.exists() && sidecar.exists());
        // New incarnation: pair is archived together, primary path clears.
        archive_conflicting_atif(&path, Some("traj-2"), "s").unwrap();
        assert!(!path.exists(), "old trajectory must move off the primary path");
        assert!(
            !sidecar.exists(),
            "stale sidecar must not survive to fail the new incarnation"
        );
        assert!(
            !close_marker.exists(),
            "stale close-complete marker must not survive to suppress the new incarnation's close"
        );
        assert!(
            !promote_marker.exists(),
            "stale promotion marker must not survive to hard-fail the new incarnation's promote"
        );
        let archived = path.with_extension("archived-traj-1");
        assert!(archived.exists(), "previous incarnation must be preserved");
        assert!(
            archived.extension().and_then(std::ffi::OsStr::to_str) != Some("json"),
            "archived artifact must not match the recovery scan's .json glob"
        );
        let mut archived_sidecar = archived.clone().into_os_string();
        archived_sidecar.push(".atif-auth");
        assert_eq!(
            std::fs::read(std::path::PathBuf::from(archived_sidecar)).unwrap(),
            b"sealed-old",
            "sidecar must be archived alongside so the pair stays verifiable"
        );
        // Corrupt existing bytes are archived conservatively, not destroyed.
        std::fs::write(&path, b"{not json").unwrap();
        archive_conflicting_atif(&path, Some("traj-3"), "s").unwrap();
        assert!(!path.exists());
        let preserved = std::fs::read_dir(directory.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .is_some_and(|n| n.starts_with("abc123.archived-corrupt-"))
            })
            .count();
        assert_eq!(preserved, 1, "corrupt bytes must be archived, not destroyed");
    }

    /// Round-17 live-stress finding: an acked RECEIPT outbox is the dedup
    /// anchor for promotion retries — `emit_bridge_event` re-reads it to
    /// reuse the already-published event's uid. The acked-outbox GC used to
    /// remove it once the session was close-complete/gone, so a promotion
    /// retry (its `.promote` marker still on disk) minted a fresh uid and
    /// published a duplicate receipt event. The GC must retain acked
    /// receipt outboxes while their promotion marker exists.
    #[tokio::test]
    async fn acked_receipt_outbox_is_retained_while_promotion_marker_exists() {
        let directory = tempfile::tempdir().unwrap();
        let finalizer = finalizer(directory.path());
        let session_id = "promo-retain";
        let topic = av_events::EventClass::Receipt.topic();
        let outbox = LifecycleOutbox {
            session_id: session_id.to_owned(),
            kind: crate::journal::RECEIPT_OUTBOX_KIND.to_owned(),
            topic: topic.to_owned(),
            key: "instance-1".to_owned(),
            value: serde_json::json!({
                "metadata": { "sequence": 0, "uid": av_core::new_event_uid() },
                "topic": topic,
            }),
            ack: Some(av_bridge::PublishAck {
                topic: topic.to_owned(),
                partition: 0,
                offset: 1,
            }),
        };
        let outbox_path = finalizer.lifecycle_outbox_path(session_id, crate::journal::RECEIPT_OUTBOX_KIND);
        std::fs::create_dir_all(outbox_path.parent().unwrap()).unwrap();
        let sealed = crate::journal::seal(
            &finalizer.journal_key,
            crate::journal::LIFECYCLE_OUTBOX_DOMAIN,
            0,
            &outbox,
        )
        .unwrap();
        std::fs::write(&outbox_path, sealed).unwrap();
        let stem = &av_core::digest::sha256_hex(session_id.as_bytes())[..32];
        let marker = directory.path().join(format!("{stem}.promote"));
        std::fs::write(&marker, b"pending-promotion").unwrap();

        // Session absent from the registry (or close-complete): without the
        // marker rule the GC would remove the acked outbox here.
        let registry = SessionRegistry::new();
        finalizer
            .remove_acked_lifecycle_outboxes(&registry)
            .await
            .unwrap();
        assert!(
            outbox_path.exists(),
            "acked receipt outbox must survive while its promotion marker exists"
        );

        // Marker gone (promotion completed): the outbox is a true orphan now.
        std::fs::remove_file(&marker).unwrap();
        finalizer
            .remove_acked_lifecycle_outboxes(&registry)
            .await
            .unwrap();
        assert!(
            !outbox_path.exists(),
            "with no promotion pending, the orphan acked outbox must be collected"
        );
    }

    /// Round-44 F1: sidecar-less ATIF files (attacker plants OR
    /// honest crash-torn state between `write_atomic` and
    /// `ensure_atif_provenance`) must be checked cheaply and
    /// quarantined on first sighting — NOT read + parsed +
    /// strict-validated on every reconciler tick. Pre-fix, N such
    /// files would each burn a 64 MiB read + serde deserialize +
    /// strict validate every 5 s, starving the tick cadence and
    /// blocking lifecycle-outbox replay, close completion,
    /// promotion retry, and idle eviction.
    #[tokio::test]
    async fn round_44_f1_sidecar_less_atif_is_quarantined_without_reading_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let finalizer = finalizer(directory.path());
        // Plant a `.json` file that would look like an ATIF spool
        // artifact but has no `.atif-auth` sidecar. Use bytes that
        // would definitely fail to parse — if the fix regresses and
        // the parser runs, the test will still pass because the
        // `invalid_json` skip branch also does `continue`, but the
        // quarantine rename assertion below distinguishes the
        // fix from the regression.
        let orphan = directory.path().join("hostileplant0000000000000000.json");
        std::fs::write(&orphan, b"{not valid json at all - this MUST NOT be parsed").unwrap();
        // Round-16 stress fix: FRESH sidecar-less files are the normal
        // transient state of an in-flight close (write_atomic → sidecar
        // seal) and must be left alone. Age the plant past the 60 s
        // orphan threshold so the quarantine path (under test here)
        // engages.
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(120);
        let file = std::fs::OpenOptions::new().append(true).open(&orphan).unwrap();
        file.set_times(std::fs::FileTimes::new().set_modified(old))
            .unwrap();
        drop(file);

        let registry = SessionRegistry::new();
        let outcome = finalizer
            .recover_spooled_sessions(&registry, &Default::default())
            .await;
        assert!(
            outcome.is_ok(),
            "orphan must not fail the outer scan; got {outcome:?}"
        );

        // The orphan must have been renamed out of the `.json`
        // extension so subsequent ticks skip it in O(1). Pre-fix
        // it would still be at `hostileplant....json` costing a
        // full read+parse per tick.
        assert!(
            !orphan.exists(),
            "sidecar-less ATIF must be quarantined-renamed after first sighting so subsequent ticks don't re-read it",
        );
        // Some sibling file must exist with the same stem plus a
        // `.corrupt-<uid>` suffix — the operator-forensic bytes.
        let mut found_quarantine = false;
        for entry in std::fs::read_dir(directory.path()).unwrap() {
            let entry = entry.unwrap();
            if let Some(name) = entry.file_name().to_str() {
                if name.contains(".json.corrupt-") {
                    found_quarantine = true;
                }
            }
        }
        assert!(
            found_quarantine,
            "quarantined file must be preserved on disk under a `.corrupt-<uid>` name for forensic inspection",
        );
    }

    /// Round-16 stress finding: a FRESH sidecar-less `{stem}.json` is the
    /// normal transient state of an in-flight close (`write_atomic` runs
    /// moments before `ensure_atif_provenance` seals `.atif-auth`). A
    /// reconciler tick landing in that window used to quarantine-rename
    /// the artifact out from under the close: the close's provenance step
    /// then failed, racing promotes returned 500, and the fresh evidence
    /// was orphaned as `.corrupt-*` forensics. Young files must survive
    /// the scan untouched; only aged orphans are quarantined (previous
    /// test).
    #[tokio::test]
    async fn fresh_sidecar_less_atif_is_not_quarantined_out_from_under_a_live_close() {
        let directory = tempfile::tempdir().unwrap();
        let finalizer = finalizer(directory.path());
        let fresh = directory.path().join("freshinflightclose0000000000.json");
        std::fs::write(&fresh, b"{}").unwrap();

        let registry = SessionRegistry::new();
        finalizer
            .recover_spooled_sessions(&registry, &Default::default())
            .await
            .unwrap();
        assert!(
            fresh.exists(),
            "a fresh sidecar-less artifact (in-flight close window) must not be quarantined"
        );
        let quarantined = std::fs::read_dir(directory.path())
            .unwrap()
            .filter_map(Result::ok)
            .any(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.contains(".corrupt-"))
            });
        assert!(
            !quarantined,
            "no quarantine sibling may be created for a fresh file"
        );
    }

    /// Round-44 F2: the pending-close sweep must NOT touch the
    /// empty-unsigned quarantine. That reject path
    /// (reconciler.rs:442-449) sets `artifact_committed = 1` but
    /// never wrote an ATIF file and never emitted a receipt.
    /// Driving the finalization tail on it would emit a spurious
    /// SESSION_CLOSE bridge event for a session that has no
    /// observable audit event on the wire, AND mark
    /// `close_complete = 1` which lets `get_or_open` (reopen=true)
    /// silently replace the quarantined Session on the next chat
    /// request — losing the incident evidence the reject was
    /// designed to preserve.
    #[tokio::test]
    async fn round_44_f2_empty_unsigned_quarantine_excluded_from_pending_close_sweep() {
        let directory = tempfile::tempdir().unwrap();
        let finalizer = finalizer(directory.path());
        let sessions = SessionRegistry::new();
        let empty = session(Workflow::Unsigned);
        // Install into the registry so the sweep can see it.
        let empty_id = empty.id.clone();
        sessions.insert_recovered(Arc::try_unwrap(empty).unwrap_or_else(|arc| {
            Session::new(
                arc.id.clone(),
                arc.workflow,
                arc.current_identity(),
                Default::default(),
            )
        }));
        let registered = sessions.get(&empty_id).unwrap();

        // The empty-unsigned close reject is the code path we're
        // simulating. It returns Err after `mark_artifact_committed`
        // + `claim.committed = true`, so post-error the session
        // has `artifact_committed = 1`, `close_complete = 0`,
        // `capture_failed = 0`, and no `atif_path` — the exact
        // shape that used to trip the sweep.
        let result = finalizer
            .close_session(Arc::clone(&registered), StopReason::SessionClosed)
            .await;
        assert!(
            matches!(result, Err(FinalizeError::Atif(_))),
            "empty unsigned close must reject; got {result:?}",
        );
        assert!(
            registered.artifact_committed_flag(),
            "empty-unsigned reject seals with artifact_committed to stop idle-sweep churn",
        );
        assert!(
            registered.is_empty_unsigned_quarantine(),
            "empty-unsigned reject must be recognizable as a quarantine",
        );

        // Pre-round-44 F2 the sweep would have picked this up.
        // Post-fix it must be excluded so no spurious SESSION_CLOSE
        // event is emitted and `close_complete` stays 0 (preserving
        // the incident evidence — a subsequent get_or_open won't
        // replace this session).
        let pending = sessions.pending_close_sessions();
        assert!(
            pending.iter().all(|s| s.id != empty_id),
            "empty-unsigned quarantine must be excluded from pending_close_sessions()",
        );
        let completed = finalizer.complete_pending_closes(&sessions).await.unwrap();
        assert_eq!(
            completed, 0,
            "sweep must NOT complete the empty-unsigned quarantine — evidence would be lost",
        );
        assert!(
            !registered.close_complete_flag(),
            "close_complete must remain 0 for the empty-unsigned quarantine so it can NOT be reopened by get_or_open (reopen=true) — preserving the incident record",
        );
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
            .push_step(av_atif::Step {
                step_id: 0,
                timestamp: Some(av_core::time::now_iso8601()),
                source: av_atif::Source::Agent,
                message: serde_json::json!("done"),
                reasoning_effort: None,
                reasoning_content: None,
                model_name: None,
                tool_calls: None,
                observation: None,
                metrics: Some(av_atif::Metrics {
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
        assert!(av_atif::validate_value(&value, av_atif::Mode::Strict).is_empty());

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
            .push_step(av_atif::Step {
                step_id: 0,
                timestamp: None,
                source: av_atif::Source::User,
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

    /// Regression (round-12/13 recovery-trace): `mark_close_complete` is
    /// in-memory only, and finalized Unsigned sessions leave their ATIF +
    /// sidecar in the spool forever. Every restart re-adopted them with
    /// `close_complete = 0`, and the pending-close sweep re-emitted a
    /// SESSION_CLOSE bridge event with a fresh metadata.uid — one spurious
    /// duplicate per finalized Unsigned session per restart. The close tail
    /// now writes a sealed, digest-bound close-complete marker; recovery
    /// restores `close_complete` only from that marker (absence-of-residue
    /// inference is unsound: journal consolidation also removes step
    /// journals for sessions that crashed while still open, whose close was
    /// never published).
    #[tokio::test]
    async fn restart_does_not_reemit_session_close_for_finalized_unsigned() {
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
        let original = session(Workflow::Unsigned);
        original
            .atif
            .lock()
            .push_step(av_atif::Step {
                step_id: 0,
                timestamp: None,
                source: av_atif::Source::User,
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
        let session_topic = av_events::EventClass::Session.topic();
        let closes_after_close = bus
            .attempts
            .lock()
            .iter()
            .filter(|(topic, _)| topic == session_topic)
            .count();
        assert_eq!(closes_after_close, 1, "exactly one close on the wire");
        let stem = &av_core::digest::sha256_hex("lifecycle-session".as_bytes())[..32];
        let marker_path = directory.path().join(format!("{stem}.close-complete"));
        assert!(
            marker_path.exists(),
            "the close tail must persist the close-complete marker"
        );

        // Simulated restart: fresh registry, same spool.
        let registry = SessionRegistry::new();
        finalizer
            .recover_spooled_sessions(&registry, &Default::default())
            .await
            .unwrap();
        let recovered = registry.get("lifecycle-session").unwrap();
        assert!(
            recovered.close_complete_flag(),
            "recovery must restore close_complete from the sealed marker"
        );
        assert!(
            registry.pending_close_sessions().is_empty(),
            "a finalized Unsigned session must not re-enter the pending-close sweep"
        );
        finalizer.complete_pending_closes(&registry).await.unwrap();
        let closes_after_restart = bus
            .attempts
            .lock()
            .iter()
            .filter(|(topic, _)| topic == session_topic)
            .count();
        assert_eq!(
            closes_after_restart, 1,
            "restart must not publish a duplicate SESSION_CLOSE for a finalized session"
        );

        // Consolidation window (the unsound-inference case): no marker, no
        // step journal, no outbox — exactly what a session that crashed
        // while still OPEN looks like after journal consolidation. Recovery
        // must NOT mark it complete; the sweep must emit its close exactly
        // once and then write the marker itself.
        std::fs::remove_file(&marker_path).unwrap();
        let registry = SessionRegistry::new();
        finalizer
            .recover_spooled_sessions(&registry, &Default::default())
            .await
            .unwrap();
        let recovered = registry.get("lifecycle-session").unwrap();
        assert!(
            !recovered.close_complete_flag(),
            "without the marker, recovery must leave the session to the sweep \
             (its close may never have been published)"
        );
        finalizer.complete_pending_closes(&registry).await.unwrap();
        let closes_after_sweep = bus
            .attempts
            .lock()
            .iter()
            .filter(|(topic, _)| topic == session_topic)
            .count();
        assert_eq!(
            closes_after_sweep, 2,
            "the sweep must emit the close exactly once"
        );
        assert!(
            marker_path.exists(),
            "the sweep must persist the marker after emitting the close"
        );

        // A tampered / wrong-incarnation marker must be refused and removed,
        // leaving the sweep in charge (duplicate close beats lost close).
        std::fs::write(&marker_path, b"garbage").unwrap();
        let registry = SessionRegistry::new();
        finalizer
            .recover_spooled_sessions(&registry, &Default::default())
            .await
            .unwrap();
        let recovered = registry.get("lifecycle-session").unwrap();
        assert!(
            !recovered.close_complete_flag(),
            "a marker that fails MAC/digest verification must not restore close_complete"
        );
        assert!(
            !marker_path.exists(),
            "an invalid marker must be removed so the sweep can rewrite it"
        );
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
    /// acquisitions, log noise, and `av_incomplete_sessions_total`. The fix
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
    /// `av_atif::write_atomic`, which runs strict validation, which rejects
    /// `steps.is_empty()` with "must contain at least one step". The write
    /// returns `WriterError::Invalid`, `close_session_locked` returns
    /// `Err(FinalizeError::Atif)`, `CloseClaim` drops unarmed,
    /// `reset_close()` puts `closed` back to `0`, and the idle sweeper
    /// re-enters this exact code path on every tick forever — burning CPU,
    /// growing `av_reconcile_errors_total`, and generating warning logs.
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
            .push_step(av_atif::Step {
                step_id: 0,
                timestamp: None,
                source: av_atif::Source::Agent,
                message: serde_json::json!("live response"),
                reasoning_effort: None,
                reasoning_content: None,
                model_name: Some("test-model".into()),
                tool_calls: None,
                observation: None,
                metrics: Some(av_atif::Metrics {
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
            .push_step(av_atif::Step {
                step_id: 0,
                timestamp: None,
                source: av_atif::Source::Agent,
                message: serde_json::json!("archived response"),
                reasoning_effort: None,
                reasoning_content: None,
                model_name: Some("test-model".into()),
                tool_calls: None,
                observation: None,
                metrics: Some(av_atif::Metrics {
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
        let step = av_atif::Step {
            step_id: 0,
            timestamp: None,
            source: av_atif::Source::Agent,
            message: serde_json::json!("archived response"),
            reasoning_effort: None,
            reasoning_content: None,
            model_name: Some("test-model".into()),
            tool_calls: None,
            observation: None,
            metrics: Some(av_atif::Metrics {
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
            rendered.contains("av_atif_recovery_skipped_total{reason=\"provenance\"}"),
            "skips must be visible to operators via metrics; got: {rendered}",
        );
    }

    /// Round-42 F1: a corrupt on-disk receipt for one ATIF-recovered
    /// session must NOT head-of-line-block recovery of every OTHER
    /// unsigned session for the tick. Pre-fix, the receipt-restore
    /// branch inside `recover_spooled_sessions`' ATIF loop used bare
    /// `?` for `read_capped_async`, `Receipt::from_json_slice`, and
    /// `verify_configured_receipt`, so a single garbage receipt file
    /// aborted the entire scan at the outer function's Err.
    ///
    /// Round-41 F1 applied the same async-block-with-outcome-enum
    /// pattern to `recover_signed_journals` +
    /// `consolidate_step_journals`; this test locks in parity for
    /// the third recovery loop.
    #[tokio::test]
    async fn round_42_f1_corrupt_receipt_does_not_block_other_atif_recovery() {
        let directory = tempfile::tempdir().unwrap();
        let metrics = Arc::new(Registry::new());
        let finalizer = Finalizer::new(
            Arc::new(Ed25519Signer::from_seed(&[42; 32])),
            directory.path().to_path_buf(),
            Arc::clone(&metrics),
        );
        let step = av_atif::Step {
            step_id: 0,
            timestamp: None,
            source: av_atif::Source::Agent,
            message: serde_json::json!("archived response"),
            reasoning_effort: None,
            reasoning_content: None,
            model_name: Some("test-model".into()),
            tool_calls: None,
            observation: None,
            metrics: Some(av_atif::Metrics {
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
        // Close two unsigned sessions to produce two valid ATIF
        // trajectories (with matching .atif-auth sidecars). One will
        // receive a poisoned receipt on disk; the other stays clean
        // and must still recover.
        for id in ["poisoned-receipt-session", "healthy-atif-session"] {
            let session = Arc::new(Session::new(
                id.to_owned(),
                Workflow::Unsigned,
                identity.clone(),
                Default::default(),
            ));
            session.atif.lock().push_step(step.clone()).unwrap();
            finalizer
                .close_session(Arc::clone(&session), StopReason::SessionClosed)
                .await
                .unwrap();
        }

        // Plant a garbage receipt file at the exact path
        // `recover_spooled_sessions` looks up for the first session.
        // `Receipt::from_json_slice` will reject the bytes, which
        // pre-round-42 propagated Err out of the outer function and
        // aborted the whole scan before the second session was even
        // examined.
        let poisoned_receipt = directory.path().join("receipts").join(format!(
            "{}.json",
            &av_core::digest::sha256_hex(b"poisoned-receipt-session")[..32]
        ));
        std::fs::create_dir_all(poisoned_receipt.parent().unwrap()).unwrap();
        std::fs::write(&poisoned_receipt, b"{not valid receipt json").unwrap();

        let registry = SessionRegistry::new();
        let outcome = finalizer
            .recover_spooled_sessions(&registry, &Default::default())
            .await;
        assert!(
            outcome.is_ok(),
            "round-42 F1: corrupt receipt must not abort the ATIF recovery scan; got {outcome:?}",
        );
        assert!(
            registry.get("healthy-atif-session").is_some(),
            "the healthy ATIF session MUST recover even when a sibling has a poisoned receipt — this is the HOL-block invariant",
        );
        let rendered = metrics.render();
        assert!(
            rendered.contains("av_atif_trajectory_recovery_skipped_total"),
            "per-session ATIF recovery skips must be visible to operators via a dedicated counter; got: {rendered}",
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
            .push_step(av_atif::Step {
                step_id: 0,
                timestamp: None,
                source: av_atif::Source::Agent,
                message: serde_json::json!("archived response"),
                reasoning_effort: None,
                reasoning_content: None,
                model_name: Some("test-model".into()),
                tool_calls: None,
                observation: None,
                metrics: Some(av_atif::Metrics {
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
                trajectory_digest: av_core::digest::sha256_hex(&trajectory_bytes),
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
            .push_step(av_atif::Step {
                step_id: 0,
                timestamp: None,
                source: av_atif::Source::Agent,
                message: serde_json::json!("live response"),
                reasoning_effort: None,
                reasoning_content: None,
                model_name: Some("test-model".into()),
                tool_calls: None,
                observation: None,
                metrics: Some(av_atif::Metrics {
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
    /// `av_incomplete_sessions_total`, growing log noise, wasted lifecycle
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

        let digest = av_core::digest::sha256_hex(session_id.as_bytes());
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
        let digest = av_core::digest::sha256_hex(session_id.as_bytes());
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
            !metrics.render().contains("av_atif_recovery_skipped_total"),
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
            .push_step(av_atif::Step {
                step_id: 0,
                timestamp: None,
                source: av_atif::Source::Agent,
                message: serde_json::json!("recovered response"),
                reasoning_effort: None,
                reasoning_content: None,
                model_name: Some("test-model".into()),
                tool_calls: None,
                observation: None,
                metrics: Some(av_atif::Metrics {
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
                trajectory_digest: av_core::digest::sha256_hex(&trajectory_bytes),
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
            .filter(|entry| entry.file_name().to_string_lossy().contains(".corrupt-"))
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
            .push_step(av_atif::Step {
                step_id: 0,
                timestamp: None,
                source: av_atif::Source::User,
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
        let trajectory: av_atif::Trajectory = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(trajectory.steps.len(), 1);
        assert_eq!(trajectory.steps[0].message, serde_json::json!("survive"));
    }

    // ------------------------------------------------------------------
    // Congestion & bottleneck stress tests.
    // ------------------------------------------------------------------

    /// Per-session lifecycle locks serialize close_session and promote
    /// per session id to prevent concurrent lifecycle-outbox rewrites;
    /// N distinct sessions do NOT queue behind a shared mutex. This
    /// test locks that behavior:
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
    /// proceeds while recovery is still working on candidate A.
    ///
    /// Deterministic construction (the previous end-ordering comparison
    /// `close_end < scan_end` still raced: on a fast runner the scan
    /// can legitimately finish milliseconds before an fsync-heavy close
    /// with nothing blocked). Here the test plants a sealed signed-journal
    /// sidecar for a "blocker" session and pre-holds that session's
    /// lifecycle lock, so `recover_signed_journals` provably parks at its
    /// `acquire_lifecycle` mid-scan. While the scan is parked:
    ///
    /// * under per-session locks the unrelated close acquires its own
    ///   lock and completes;
    /// * under a regressed global lock the close would queue behind the
    ///   very lock the test holds, and the outer timeout fires.
    ///
    /// No wall-clock ordering is asserted anywhere.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn recovery_scan_does_not_head_of_line_block_unrelated_close() {
        let directory = tempfile::tempdir().unwrap();
        let finalizer = Arc::new(finalizer(directory.path()));
        // Same seed as the `finalizer` helper so the sealed sidecar
        // authenticates against the finalizer's journal key.
        let signer: Arc<dyn Signer> = Arc::new(Ed25519Signer::from_seed(&[7; 32]));
        let journal_key = crate::journal::key_from_signer(signer.as_ref());

        // Plant a signed-journal sidecar the scan must adopt: it passes
        // the metadata checks in `recover_signed_journals` and reaches
        // that path's per-candidate `acquire_lifecycle`.
        let blocker_id = "scan-blocker";
        let digest = av_core::digest::sha256_hex(blocker_id.as_bytes());
        let stem = &digest[..32];
        let metadata_payload = serde_json::json!({
            "journal_version": 2,
            "session_id": blocker_id,
            "identity": AgentIdentity {
                version: "1".to_owned(),
                charter: "test".into(),
                instance_uid: "instance-blocker".to_owned(),
                ttl_remaining_s: Some(600),
            },
            "workflow": "signed",
        });
        let sealed = crate::journal::seal(&journal_key, "metadata", 0, &metadata_payload).unwrap();
        std::fs::write(directory.path().join(format!("{stem}.session.json")), &sealed).unwrap();

        // Pre-hold the blocker's lifecycle lock. The scan cannot finish
        // while this guard lives: it must park at `acquire_lifecycle`
        // for the planted candidate.
        let locks = finalizer.lifecycle_locks();
        let held = locks.arc_for(blocker_id).lock_owned().await;

        let f_scan = Arc::clone(&finalizer);
        let scan_task = tokio::spawn(async move {
            f_scan
                .recover_spooled_sessions(&crate::session::SessionRegistry::new(), &Default::default())
                .await
        });

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
        // The generous timeout only fires on a genuine global-lock
        // regression (the close queuing behind the lock held above) or
        // a deadlock; it is not a performance gate.
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(60),
            finalizer.close_session(session, StopReason::SessionClosed),
        )
        .await
        .expect("unrelated close blocked behind the in-flight recovery scan — the head-of-line blocking signature of a global lifecycle lock");

        // The close finished while the scan was provably still in
        // flight: the scan cannot complete until the blocker guard is
        // released.
        assert!(
            !scan_task.is_finished(),
            "recovery scan finished while its candidate's lifecycle lock was externally held — \
             the scan never acquired the per-session lock, so this test lost its teeth"
        );

        drop(held);
        scan_task
            .await
            .unwrap()
            .expect("recovery scan must complete after the blocker lock is released");
    }

    /// A saturated worker-side finalizer must not hold a session's
    /// lifecycle lock
    /// across independent await points that could stall other closers. We
    /// verify this indirectly: the aggregate wall-clock for 16 concurrent
    /// closes must stay within `10 × N ×` the uncontended single-close
    /// baseline (floored at 60 s for CI noise). A regression that
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
        // A shared serialized lock would give ~N * baseline. Anything
        // > 10 * N * baseline
        // signals we're holding a lock across additional awaits.
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
