//! Bounded asynchronous worker for loop analysis, event emission, and capture.

use crate::session::{Session, Workflow};
use av_bridge::{EventBus, PublishAck};
use av_core::metrics::Registry;
use av_events::{EventClass, EventMetrics, OcsfEventBuilder, StatusId, StopReason};
use av_loopdetect::{BreakerVerdict, Embedder, NoopVectorSink, VectorSink};
use serde_json::Value;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};
use tracing::Instrument as _;

/// Structured ATIF representation attached to an asynchronous event job.
pub struct AtifCapture {
    /// Step originator.
    pub source: av_atif::Source,
    /// Required dialog message.
    pub message: Value,
    /// Optional explicit reasoning.
    pub reasoning_content: Option<String>,
    /// Model used for this step.
    pub model_name: Option<String>,
    /// Structured tool calls.
    pub tool_calls: Option<Vec<av_atif::ToolCall>>,
    /// Structured environment feedback.
    pub observation: Option<av_atif::Observation>,
    /// Number of represented LLM calls.
    pub llm_call_count: Option<u64>,
}

/// Work copied from the hot path for asynchronous processing.
pub struct WorkerJob {
    /// Session receiving the resulting event and trajectory step.
    pub session: Arc<Session>,
    /// Identity validated for the request that created this job.
    pub identity: av_events::AgentIdentity,
    /// Event class to emit when loop detection does not override it.
    pub class: EventClass,
    /// Class-specific event payload.
    pub payload: Value,
    /// Reasoning or response text used for loop detection and ATIF capture.
    pub text: String,
    /// Whether this job represents a reasoning step that should update the
    /// semantic loop breaker.
    pub analyze_loop: bool,
    /// Event outcome.
    pub status: StatusId,
    /// Normalized stop reason for stop events.
    pub stop_reason: Option<StopReason>,
    /// Provider or source-native stop reason value.
    pub native_stop_reason: Option<String>,
    /// Token and compression metrics.
    pub metrics: EventMetrics,
    /// provider-vs-heuristic prompt-token correction
    /// (see `ActiveJournalRecord::prompt_token_correction`). Zero for
    /// every job class except terminal response captures whose
    /// provider reported `usage.prompt_tokens`.
    pub prompt_token_correction: i64,
    /// Cost attributed to this step, in micro-USD.
    pub cost_usd_micros: u64,
    /// ATIF step representation for unsigned workflows.
    pub atif: Option<AtifCapture>,
    /// Durable response-attempt marker cleared only after journal and broker commit.
    pub response_marker: Option<String>,
    /// Chat response attempt correlated across request and terminal capture records.
    pub response_attempt: Option<ResponseAttempt>,
}

/// Durable request/terminal marker embedded in the active event journal.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ResponseAttempt {
    /// Stable ID shared by request admission and its terminal response event.
    pub id: String,
    /// False on request admission, true on response completion or dispatch failure.
    pub terminal: bool,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct InFlightResponse {
    session_id: String,
    attempt_id: String,
    request_digest: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct ActiveJournalRecord {
    pub(crate) event: Value,
    pub(crate) identity: av_events::AgentIdentity,
    pub(crate) atif_step: Option<av_atif::Step>,
    pub(crate) tool_calls: u64,
    pub(crate) tool_allowed: u64,
    pub(crate) tool_blocked: u64,
    pub(crate) prompt_tokens: u64,
    pub(crate) completion_tokens: u64,
    pub(crate) cached_tokens: u64,
    pub(crate) cost_usd_micros: u64,
    /// Signed reconciliation of the admission-time
    /// prompt-token HEURISTIC against the provider's reported
    /// `usage.prompt_tokens` (provider − heuristic; negative for the
    /// common CJK 3-4× over-estimate). Carried on terminal response
    /// records; `#[serde(default)]` keeps old journals readable and
    /// lets a rolled-back binary ignore it (totals then fall back to
    /// the heuristic — bounded degradation, never corruption).
    #[serde(default)]
    pub(crate) prompt_token_correction: i64,
    pub(crate) stop_reason_id: Option<u8>,
    pub(crate) response_attempt: Option<ResponseAttempt>,
}

/// Accounting totals folded from journal records during recovery.
///
/// The same
/// accounting fold used to be implemented THREE times — the live path
/// in `process_job`, signed recovery in `recover_signed_journals`, and
/// unsigned consolidation in `consolidate_step_journals`. Any change to
/// a counted dimension had to be made in three places or a
/// crash-recovered receipt attested different numbers than a
/// clean-close receipt for identical traffic — and no test caught it,
/// because the paths were asserted separately. `ActiveJournalRecord`'s
/// fields are now the single source: the live path applies them via
/// [`ActiveJournalRecord::apply_to_totals`], recovery folds them via
/// [`ActiveJournalRecord::fold_into`], and the proof-harness test
/// (`unified_fold_matches_live_path`) pins the two applications to
/// identical results over representative record shapes.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct RecoveredTotals {
    pub(crate) tool_calls: u64,
    pub(crate) tool_allowed: u64,
    pub(crate) tool_blocked: u64,
    pub(crate) prompt_tokens: u64,
    pub(crate) completion_tokens: u64,
    pub(crate) cached_tokens: u64,
    pub(crate) cost_usd_micros: u64,
}

impl RecoveredTotals {
    /// The tool-accounting invariant every fold must check: classified
    /// outcomes can never exceed observed calls.
    pub(crate) fn validate_tool_accounting(&self) -> Result<(), String> {
        if self
            .tool_allowed
            .checked_add(self.tool_blocked)
            .is_none_or(|classified| classified > self.tool_calls)
        {
            return Err("journal has inconsistent tool accounting".to_owned());
        }
        Ok(())
    }

    /// Publish the folded totals onto a session (Release ordering, the
    /// same discipline both recovery paths used inline).
    pub(crate) fn store_on(&self, totals: &crate::session::Totals) {
        use std::sync::atomic::Ordering;
        totals.tool_calls.store(self.tool_calls, Ordering::Release);
        totals.tool_allowed.store(self.tool_allowed, Ordering::Release);
        totals.tool_blocked.store(self.tool_blocked, Ordering::Release);
        totals.prompt_tokens.store(self.prompt_tokens, Ordering::Release);
        totals
            .completion_tokens
            .store(self.completion_tokens, Ordering::Release);
        totals.cached_tokens.store(self.cached_tokens, Ordering::Release);
        totals
            .cost_usd_micros
            .store(self.cost_usd_micros, Ordering::Release);
    }
}

impl ActiveJournalRecord {
    /// Fold this record's counted dimensions into recovery totals with
    /// overflow + JCS-bound checks. THE accounting rule — do not
    /// re-implement per call site.
    pub(crate) fn fold_into(&self, totals: &mut RecoveredTotals) -> Result<(), String> {
        fn checked(current: u64, value: u64, field: &str) -> Result<u64, String> {
            current
                .checked_add(value)
                .filter(|total| *total <= av_core::error::JCS_SAFE_MAX)
                .ok_or_else(|| format!("recovered {field} overflow"))
        }
        totals.tool_calls = checked(totals.tool_calls, self.tool_calls, "tool calls")?;
        totals.tool_allowed = checked(totals.tool_allowed, self.tool_allowed, "allowed tools")?;
        totals.tool_blocked = checked(totals.tool_blocked, self.tool_blocked, "blocked tools")?;
        totals.prompt_tokens = checked(totals.prompt_tokens, self.prompt_tokens, "prompt tokens")?;
        if self.prompt_token_correction != 0 {
            totals.prompt_tokens = totals
                .prompt_tokens
                .checked_add_signed(self.prompt_token_correction)
                .filter(|total| *total <= av_core::error::JCS_SAFE_MAX)
                .ok_or_else(|| "recovered prompt token correction underflow/overflow".to_owned())?;
        }
        totals.completion_tokens = checked(
            totals.completion_tokens,
            self.completion_tokens,
            "completion tokens",
        )?;
        totals.cached_tokens = checked(totals.cached_tokens, self.cached_tokens, "cached tokens")?;
        totals.cost_usd_micros = checked(totals.cost_usd_micros, self.cost_usd_micros, "cost")?;
        Ok(())
    }

    /// Apply this record's counted dimensions to a live session's
    /// atomic totals — the live-path twin of [`Self::fold_into`], with
    /// the same JCS-bound discipline via `checked_atomic_add`. The
    /// record's fields were conditionalized ONCE at construction
    /// (compression carries prompt tokens; terminal responses carry
    /// completion/cached/cost; tool records carry call outcomes), so
    /// applying them unconditionally here is exactly the old
    /// per-class branching, without the second copy of the rules.
    pub(crate) fn apply_to_totals(&self, totals: &crate::session::Totals) -> Result<(), String> {
        for (counter, value, field) in [
            (&totals.tool_calls, self.tool_calls, "tool calls"),
            (&totals.tool_allowed, self.tool_allowed, "allowed tools"),
            (&totals.tool_blocked, self.tool_blocked, "blocked tools"),
            (&totals.prompt_tokens, self.prompt_tokens, "prompt tokens"),
            (
                &totals.completion_tokens,
                self.completion_tokens,
                "completion tokens",
            ),
            (&totals.cached_tokens, self.cached_tokens, "cached tokens"),
            (&totals.cost_usd_micros, self.cost_usd_micros, "cost"),
        ] {
            if value > 0 {
                checked_atomic_add(counter, value, field)?;
            }
        }
        if self.prompt_token_correction != 0 {
            totals
                .prompt_tokens
                .fetch_update(
                    std::sync::atomic::Ordering::AcqRel,
                    std::sync::atomic::Ordering::Acquire,
                    |current| {
                        current
                            .checked_add_signed(self.prompt_token_correction)
                            .filter(|next| *next <= av_core::error::JCS_SAFE_MAX)
                    },
                )
                .map(|_| ())
                .map_err(|_| "prompt token correction underflow/overflow".to_owned())?;
        }
        Ok(())
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct BrokerAckRecord {
    session_id: String,
    event_uid: String,
    ack: PublishAck,
}

struct Envelope {
    job: WorkerJob,
    completion: Option<oneshot::Sender<Result<(), String>>>,
    span: tracing::Span,
    _capacity_permit: tokio::sync::OwnedSemaphorePermit,
}

/// Non-blocking submission error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SubmitError {
    /// The bounded worker queue has no remaining capacity.
    #[error("worker queue is full")]
    Full,
    /// The worker supervisor has stopped.
    #[error("worker queue is closed")]
    Closed,
}

/// Which admission stage a drop should be counted against. Each variant
/// maps to a distinct `av_events_dropped_total{stage="..."}` counter,
/// so operators can PromQL-alert on the actual bottleneck class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DropStage {
    /// Initial worker-side admission. `try_reserve` / `try_reserve_pair`'s
    /// worker half. Bumps `av_events_dropped_total{stage="worker_queue"}`.
    WorkerQueue,
    /// Downstream response-capture submission (`ResponsePermit::submit`).
    /// The permit itself only holds the response-capacity semaphore; the
    /// mpsc slot is contested at submit time, so exhaustion at THIS
    /// stage — which is a real observable class of failure — bumps
    /// `av_events_dropped_total{stage="response_slot"}`.
    ResponseSlot,
}

impl DropStage {
    fn full_counter_key(self) -> &'static str {
        match self {
            Self::WorkerQueue => "av_events_dropped_total{stage=\"worker_queue\"}",
            Self::ResponseSlot => "av_events_dropped_total{stage=\"response_slot\"}",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::WorkerQueue => "worker_queue",
            Self::ResponseSlot => "response_slot",
        }
    }
}

/// Cloneable handle used by request handlers to submit worker jobs.
#[derive(Clone)]
pub struct WorkerHandle {
    senders: Arc<Vec<mpsc::Sender<Envelope>>>,
    metrics: Arc<Registry>,
    pending: Arc<std::sync::atomic::AtomicU64>,
    drained: Arc<tokio::sync::Notify>,
    capacity: Arc<tokio::sync::Semaphore>,
    /// Separate admission budget for downstream response jobs. Every
    /// chat request reserves a worker slot AND a response slot; giving
    /// them distinct semaphores + distinct
    /// `av_events_dropped_total{stage=...}` counters lets operators see
    /// which class of capacity ran out. Prior to this split both
    /// reservations pulled from the same semaphore so admission was
    /// silently halved and both failures aliased to `stage="worker_queue"`.
    response_capacity: Arc<tokio::sync::Semaphore>,
}

/// Guaranteed slot in the bounded worker queue.
pub struct WorkerPermit {
    permit: mpsc::OwnedPermit<Envelope>,
    pending: Arc<std::sync::atomic::AtomicU64>,
    capacity_permit: tokio::sync::OwnedSemaphorePermit,
}

/// Reservation for the downstream response-capture worker job. Draws
/// from a distinct capacity semaphore so operators can tell via
/// `av_events_dropped_total{stage="response_slot"}` vs
/// `stage="worker_queue"` which class of admission is the bottleneck.
///
/// Unlike [`WorkerPermit`], the response permit only holds the
/// capacity semaphore — the mpsc queue slot is re-acquired at submit
/// time via [`Self::submit`]. This keeps the initial admission cheap
/// (one semaphore acquire instead of two mpsc reservations that would
/// otherwise compete for the same shard's slot with the worker
/// permit) and lets the response job land whenever worker capacity
/// and the shard have room, which is the common case since response
/// capture happens
/// tens-of-seconds after the initial worker job has drained.
///
/// Held by the streaming-response wrapper in `routes.rs`
/// (`AbortFinalizingStream`) for the lifetime of the forwarded response;
/// drops on stream completion or client abort.
pub struct ResponsePermit {
    _capacity_permit: tokio::sync::OwnedSemaphorePermit,
}

impl ResponsePermit {
    /// Commit a response-capture job. The capacity slot reserved at
    /// admission travels INTO the envelope: the submission never
    /// contends on the main worker semaphore, so a backlog of new
    /// admissions cannot starve the capture job of an
    /// already-admitted stream — the guarantee `try_reserve_pair`'s
    /// acquire-both-or-fail exists to provide. (A previous revision
    /// dropped this permit and drew a fresh slot from the WORKER
    /// semaphore, which both forfeited the reservation under load and
    /// charged the resulting drop to `stage="response_slot"` when the
    /// exhausted budget was actually worker capacity.) The only
    /// remaining failure mode is the shard's bounded mpsc queue being
    /// momentarily full, which returns `SubmitError::Full` and bumps
    /// `av_events_dropped_total{stage="response_slot"}`.
    pub fn submit(self, worker: &WorkerHandle, job: WorkerJob) -> Result<(), SubmitError> {
        worker.submit_with_permit(job, self._capacity_permit, DropStage::ResponseSlot)
    }
}

/// Fused reservation covering a worker job AND its downstream response
/// slot. Acquired atomically at request admission: on any failure the
/// worker slot (if already held) is released via RAII before the error
/// surfaces, so callers cannot end up with an orphaned half-permit.
pub struct WorkerAndResponsePermit {
    /// Permit for the initial worker job (dispatch / quota / receipt-sign).
    pub worker: WorkerPermit,
    /// Permit for the downstream response-capture job.
    pub response: ResponsePermit,
}

impl WorkerPermit {
    /// Commit a job into the previously reserved queue slot.
    pub fn submit(self, job: WorkerJob) {
        job.session.worker_job_started();
        self.pending.fetch_add(1, Ordering::AcqRel);
        let span = worker_span(&job);
        self.permit.send(Envelope {
            job,
            completion: None,
            span,
            _capacity_permit: self.capacity_permit,
        });
    }
}

impl WorkerHandle {
    /// Reserve queue capacity before committing quota or other state.
    pub fn try_reserve(&self, session_id: &str) -> Result<WorkerPermit, SubmitError> {
        let capacity_permit = self.try_capacity()?;
        let Some(sender) = self.sender_for(session_id).cloned() else {
            return Err(SubmitError::Closed);
        };
        match sender.try_reserve_owned() {
            Ok(permit) => Ok(WorkerPermit {
                permit,
                pending: Arc::clone(&self.pending),
                capacity_permit,
            }),
            Err(mpsc::error::TrySendError::Full(_sender)) => {
                self.metrics
                    .counter(
                        "av_events_dropped_total{stage=\"worker_queue\"}",
                        "Worker jobs or response-slot reservations dropped, labeled by admission stage",
                    )
                    .inc();
                Err(SubmitError::Full)
            }
            Err(mpsc::error::TrySendError::Closed(_sender)) => {
                self.metrics
                    .counter(
                        "av_events_dropped_total{stage=\"worker_closed\"}",
                        "Worker jobs or response-slot reservations dropped, labeled by admission stage",
                    )
                    .inc();
                Err(SubmitError::Closed)
            }
        }
    }

    /// Reserve the downstream response-capture slot. Distinct from
    /// [`Self::try_reserve`] because response capture is a separate
    /// stage with its own admission budget; keeping the counters
    /// separate lets operators see which one ran out. The mpsc queue
    /// slot is re-acquired at submit time via [`ResponsePermit::submit`].
    fn try_reserve_response(&self) -> Result<ResponsePermit, SubmitError> {
        Arc::clone(&self.response_capacity)
            .try_acquire_owned()
            .map(|p| ResponsePermit { _capacity_permit: p })
            .map_err(|_| {
                self.metrics
                    .counter(
                        "av_events_dropped_total{stage=\"response_slot\"}",
                        "Worker jobs or response-slot reservations dropped, labeled by admission stage",
                    )
                    .inc();
                SubmitError::Full
            })
    }

    /// Atomic acquire-both-or-fail for admission: obtains a worker
    /// permit AND a response permit for the same request, distinct
    /// counters on failure. On any error path (worker slot or response
    /// slot exhaustion, closed channel), a partially-taken worker
    /// permit drops via RAII before the error surfaces so callers
    /// never observe an orphaned half-reservation.
    pub fn try_reserve_pair(&self, session_id: &str) -> Result<WorkerAndResponsePermit, SubmitError> {
        // Stage 1: worker slot. Bumps stage="worker_queue" on failure.
        let worker = self.try_reserve(session_id)?;
        // Stage 2: response slot. Bumps stage="response_slot" on
        // failure. If this fails, `worker` drops via NLL — its
        // OwnedSemaphorePermit + mpsc::OwnedPermit release cleanly
        // and the counters agree with the caller's view (only the
        // response-slot counter incremented).
        let response = self.try_reserve_response()?;
        Ok(WorkerAndResponsePermit { worker, response })
    }

    /// Submit without waiting. Used by rejection/failure paths; the hot path
    /// reserves capacity up front via [`WorkerHandle::try_reserve`] and
    /// submits through [`WorkerPermit::submit`].
    pub fn try_submit(&self, job: WorkerJob) -> Result<(), SubmitError> {
        self.try_submit_labeled(job, DropStage::WorkerQueue)
    }

    /// Same as [`Self::try_submit`], but the failure counters carry a
    /// caller-supplied stage label so response-slot exhaustion mid-stream
    /// can be distinguished from admission-side worker-queue exhaustion.
    /// See [`ResponsePermit::submit`].
    fn try_submit_labeled(&self, job: WorkerJob, stage: DropStage) -> Result<(), SubmitError> {
        let capacity_permit = self.try_capacity_labeled(stage)?;
        self.submit_with_permit(job, capacity_permit, stage)
    }

    /// Queue-admission tail shared by [`Self::try_submit_labeled`]
    /// (which draws a fresh worker-capacity slot) and
    /// [`ResponsePermit::submit`] (which carries the response-capacity
    /// slot reserved at admission). The permit — whichever semaphore
    /// it came from — rides inside the envelope and releases to its
    /// origin when the worker finishes the job.
    fn submit_with_permit(
        &self,
        job: WorkerJob,
        capacity_permit: tokio::sync::OwnedSemaphorePermit,
        stage: DropStage,
    ) -> Result<(), SubmitError> {
        let Some(sender) = self.sender_for(&job.session.id).cloned() else {
            return Err(SubmitError::Closed);
        };
        job.session.worker_job_started();
        self.pending.fetch_add(1, Ordering::AcqRel);
        let span = worker_span(&job);
        match sender.try_send(Envelope {
            job,
            completion: None,
            span,
            _capacity_permit: capacity_permit,
        }) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(envelope)) => {
                let session_id = envelope.job.session.id.clone();
                envelope.job.session.worker_job_finished();
                self.worker_job_finished();
                self.metrics
                    .counter(
                        stage.full_counter_key(),
                        "Worker jobs or response-slot reservations dropped, labeled by admission stage",
                    )
                    .inc();
                tracing::warn!(
                    session = %session_id,
                    stage = %stage.label(),
                    "worker queue full; request must fail closed"
                );
                Err(SubmitError::Full)
            }
            Err(mpsc::error::TrySendError::Closed(envelope)) => {
                let session_id = envelope.job.session.id.clone();
                envelope.job.session.worker_job_finished();
                self.worker_job_finished();
                self.metrics
                    .counter(
                        "av_events_dropped_total{stage=\"worker_closed\"}",
                        "Worker jobs or response-slot reservations dropped, labeled by admission stage",
                    )
                    .inc();
                tracing::warn!(
                    session = %session_id,
                    stage = %stage.label(),
                    "worker queue closed; request must fail closed"
                );
                Err(SubmitError::Closed)
            }
        }
    }

    /// Submit and wait for completion. Intended for lifecycle operations and
    /// deterministic integration tests, never streaming hot paths.
    pub async fn submit_and_wait(&self, job: WorkerJob) -> Result<(), String> {
        let sender_for_session = self
            .sender_for(&job.session.id)
            .cloned()
            .ok_or_else(|| "worker queue is closed".to_owned())?;
        let (sender, receiver) = oneshot::channel();
        let capacity_permit = Arc::clone(&self.capacity)
            .acquire_owned()
            .await
            .map_err(|_| "worker capacity semaphore is closed".to_owned())?;
        job.session.worker_job_started();
        self.pending.fetch_add(1, Ordering::AcqRel);
        let span = worker_span(&job);
        sender_for_session
            .send(Envelope {
                job,
                completion: Some(sender),
                span,
                _capacity_permit: capacity_permit,
            })
            .await
            .map_err(|error| {
                error.0.job.session.worker_job_finished();
                self.worker_job_finished();
                "worker queue is closed".to_owned()
            })?;
        receiver
            .await
            .map_err(|_| "worker completion channel closed".to_owned())?
    }

    /// Wait until every accepted job has completed processing.
    pub async fn wait_idle(&self) {
        loop {
            // Same pinned Notified must span enable() and .await; a fresh
            // notified() after enable is dropped would miss a notify_waiters()
            // firing in the interval.
            let notified = self.drained.notified();
            let mut notified = std::pin::pin!(notified);
            notified.as_mut().enable();
            if self.pending.load(Ordering::Acquire) == 0 {
                return;
            }
            notified.await;
        }
    }

    /// Number of accepted-but-not-yet-completed jobs. Sampled by the
    /// `/metrics` scrape into the `av_worker_queue_depth` gauge.
    pub fn queue_depth(&self) -> u64 {
        self.pending.load(Ordering::Acquire)
    }

    fn worker_job_finished(&self) {
        if self.pending.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.drained.notify_waiters();
        }
    }

    fn try_capacity(&self) -> Result<tokio::sync::OwnedSemaphorePermit, SubmitError> {
        self.try_capacity_labeled(DropStage::WorkerQueue)
    }

    /// Same as [`Self::try_capacity`] but the failure counter carries a
    /// caller-supplied stage label. `WorkerQueue` accounts to the main
    /// worker admission semaphore; `ResponseSlot` accounts to the mid-
    /// stream response-capture submission path — so operators can tell
    /// which class of exhaustion is producing drops.
    fn try_capacity_labeled(
        &self,
        stage: DropStage,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, SubmitError> {
        Arc::clone(&self.capacity).try_acquire_owned().map_err(|_| {
            self.metrics
                .counter(
                    stage.full_counter_key(),
                    "Worker jobs or response-slot reservations dropped, labeled by admission stage",
                )
                .inc();
            SubmitError::Full
        })
    }

    fn sender_for(&self, session_id: &str) -> Option<&mpsc::Sender<Envelope>> {
        let partitions = u32::try_from(self.senders.len()).ok()?;
        let shard = av_bridge::bus::partition_for(session_id, partitions) as usize;
        self.senders.get(shard)
    }
}

/// Start the session-sharded worker pool (16 shards, each behind a
/// bounded channel). Ordering is per session via hash sharding.
pub fn spawn_worker(
    capacity: usize,
    bridge: Arc<dyn EventBus>,
    embedder: Arc<dyn Embedder>,
    metrics: Arc<Registry>,
) -> WorkerHandle {
    spawn_worker_with_sink(capacity, bridge, embedder, Arc::new(NoopVectorSink), metrics)
}

/// Start the worker pool with an explicit off-path vector sink.
pub fn spawn_worker_with_sink(
    capacity: usize,
    bridge: Arc<dyn EventBus>,
    embedder: Arc<dyn Embedder>,
    vector_sink: Arc<dyn VectorSink>,
    metrics: Arc<Registry>,
) -> WorkerHandle {
    spawn_worker_with_spool(capacity, bridge, embedder, vector_sink, None, metrics)
}

/// Start the worker pool with vector persistence and optional ATIF journal.
pub fn spawn_worker_with_spool(
    capacity: usize,
    bridge: Arc<dyn EventBus>,
    embedder: Arc<dyn Embedder>,
    vector_sink: Arc<dyn VectorSink>,
    spool_dir: Option<std::path::PathBuf>,
    metrics: Arc<Registry>,
) -> WorkerHandle {
    spawn_worker_with_spool_authenticated(
        capacity,
        bridge,
        embedder,
        vector_sink,
        spool_dir,
        [0; 32],
        metrics,
    )
}

/// Start the worker pool with authenticated active-workflow journals.
pub fn spawn_worker_with_spool_authenticated(
    capacity: usize,
    bridge: Arc<dyn EventBus>,
    embedder: Arc<dyn Embedder>,
    vector_sink: Arc<dyn VectorSink>,
    spool_dir: Option<std::path::PathBuf>,
    journal_key: [u8; 32],
    metrics: Arc<Registry>,
) -> WorkerHandle {
    // Sharding is decoupled from `capacity`: routing is by
    // `partition_for(session_id, senders.len())`, so every spawned
    // shard is routable by construction. Under `capacity = 1` all
    // shards still spawn; the global semaphore continues to enforce
    // the caller's admission cap so total in-flight work is still
    // bounded by `capacity`.
    //
    // The count was hardcoded at 16 regardless of core
    // count, so the throughput ceiling (~24k events/s measured, and
    // 1/16th of the id space frozen behind any one stalled session)
    // did not improve with more cores. Scale with available
    // parallelism, floored at the historical 16 so small machines
    // keep the old fan-out. Per-session ordering is unaffected: a
    // session's shard is stable for the process lifetime because
    // routing derives from the spawned count.
    const MIN_SHARDS: usize = 16;
    let capacity = capacity.max(1);
    let shard_count = std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(MIN_SHARDS)
        .max(MIN_SHARDS);
    // Per-shard channel size: enough that a single shard can absorb
    // the full admission burst if every request happens to hash to it,
    // capped at `capacity` so we never over-allocate the caller's
    // memory budget across shards.
    let per_shard_capacity = capacity.min(capacity.div_ceil(shard_count).max(1) * shard_count);
    let per_shard_capacity = per_shard_capacity.max(1);
    let global_capacity = Arc::new(tokio::sync::Semaphore::new(capacity));
    // Response-slot capacity mirrors worker capacity by default. Keeping
    // them equal preserves the historical behaviour (both counters were
    // silently drawn from the same pool) while distinct semaphores let
    // operators observe which class exhausts first via
    // `av_events_dropped_total{stage="response_slot"}` vs
    // `stage="worker_queue"`. A follow-up can expose an independent
    // `response_capacity` config field once operators have telemetry.
    let response_capacity = Arc::new(tokio::sync::Semaphore::new(capacity));
    let pending = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let drained = Arc::new(tokio::sync::Notify::new());
    let mut senders = Vec::with_capacity(shard_count);
    for _ in 0..shard_count {
        let (sender, receiver) = mpsc::channel::<Envelope>(per_shard_capacity);
        senders.push(sender);
        spawn_worker_shard(
            receiver,
            Arc::clone(&bridge),
            Arc::clone(&embedder),
            Arc::clone(&vector_sink),
            spool_dir.clone(),
            journal_key,
            Arc::clone(&metrics),
            Arc::clone(&pending),
            Arc::clone(&drained),
        );
    }
    WorkerHandle {
        senders: Arc::new(senders),
        metrics,
        pending,
        drained,
        capacity: global_capacity,
        response_capacity,
    }
}

/// Sessions a shard may process concurrently. One
/// stalled session (slow journal fsync, hung broker publish) used to
/// freeze its entire shard — 31× measured head-of-line blocking for
/// every other session hashed there. Eight slots bound the
/// wasted-capacity blast radius of pathological neighbors to 1/8 of
/// a shard while keeping per-shard task fan-out small.
const MAX_ACTIVE_SESSIONS_PER_SHARD: usize = 8;

/// Group commit: how many backlogged envelopes of ONE
/// session a single dispatch drains into a batch (one journal
/// fdatasync per batch instead of one per event). Sized to cap both
/// the added completion latency of the batch's first job and the
/// replay window a crash-before-sync leaves (nothing acknowledged is
/// ever lost — Phase B runs only after the batch sync).
const MAX_BATCH_PER_SESSION: usize = 16;

#[allow(clippy::too_many_arguments)]
fn spawn_worker_shard(
    mut receiver: mpsc::Receiver<Envelope>,
    bridge: Arc<dyn EventBus>,
    embedder: Arc<dyn Embedder>,
    vector_sink: Arc<dyn VectorSink>,
    spool_dir: Option<std::path::PathBuf>,
    journal_key: [u8; 32],
    worker_metrics: Arc<Registry>,
    worker_pending: Arc<std::sync::atomic::AtomicU64>,
    worker_drained: Arc<tokio::sync::Notify>,
) {
    // To avoid intra-shard head-of-line blocking, the shard is
    // a DISPATCHER over per-session FIFO queues, not a serial loop.
    // Invariants:
    //   * Per-session ordering: at most ONE envelope per session is in
    //     flight; the next spawns only after its predecessor's task
    //     joins. Arrival order per session is preserved (mpsc order →
    //     VecDeque order).
    //   * Cross-session progress: up to MAX_ACTIVE_SESSIONS_PER_SHARD
    //     sessions run concurrently, so one stalled session occupies
    //     one slot instead of the whole shard.
    //   * Memory stays bounded by the GLOBAL capacity semaphore: every
    //     queued envelope still holds its `_capacity_permit`, so
    //     draining the channel into local queues does not raise the
    //     in-flight ceiling.
    //   * Shutdown: the loop exits only when the channel is closed AND
    //     every local queue and in-flight task has drained, preserving
    //     the drain contract (`worker_pending` accounting is inside
    //     `process_envelope`, unchanged).
    tokio::spawn(async move {
        let mut queues: std::collections::HashMap<String, std::collections::VecDeque<Envelope>> =
            std::collections::HashMap::new();
        // Sessions with an envelope IN FLIGHT. Tracked separately from
        // `queues`: a session can be active AND have a backlog queued
        // behind its in-flight envelope, and the slot-release scan
        // must never dispatch from an active session's backlog — that
        // would run two envelopes of one session concurrently and
        // corrupt the per-session journal index sequence.
        let mut active: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut tasks: tokio::task::JoinSet<String> = tokio::task::JoinSet::new();
        let mut receiver_open = true;

        let spawn_batch = |tasks: &mut tokio::task::JoinSet<String>, batch: Vec<Envelope>| {
            let session_id = batch
                .first()
                .map(|envelope| envelope.job.session.id.clone())
                .unwrap_or_default();
            let bridge = Arc::clone(&bridge);
            let embedder = Arc::clone(&embedder);
            let vector_sink = Arc::clone(&vector_sink);
            let spool_dir = spool_dir.clone();
            let worker_metrics = Arc::clone(&worker_metrics);
            let worker_pending = Arc::clone(&worker_pending);
            let worker_drained = Arc::clone(&worker_drained);
            tasks.spawn(async move {
                use futures::future::FutureExt as _;
                // Supervise the whole envelope (routing + process_job)
                // exactly like the pre-dispatcher shard loop did: the
                // INNER tokio::spawn(process_job) already catches job
                // panics; this catch_unwind covers the outer routing so
                // a panic cannot lose the session's dispatch slot. The
                // task cannot panic between here and returning the id.
                let outcome = std::panic::AssertUnwindSafe(async {
                    let metrics = Arc::clone(&worker_metrics);
                    let outcome = std::panic::AssertUnwindSafe(process_envelope_batch(
                        batch,
                        bridge,
                        embedder,
                        vector_sink,
                        spool_dir,
                        journal_key,
                        worker_metrics,
                        worker_pending,
                        worker_drained,
                    ))
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
                                "av_worker_shard_panics_total",
                                "Worker shard driver panicked outside a job; supervised via catch_unwind",
                            )
                            .inc();
                        tracing::error!(
                            panic = %msg,
                            "worker envelope routing panicked; continuing"
                        );
                    }
                })
                .catch_unwind()
                .await;
                drop(outcome);
                session_id
            });
        };

        loop {
            if !receiver_open && tasks.is_empty() && queues.is_empty() {
                break;
            }
            tokio::select! {
                maybe_envelope = receiver.recv(), if receiver_open => {
                    match maybe_envelope {
                        Some(envelope) => {
                            let session_id = envelope.job.session.id.clone();
                            if !active.contains(&session_id)
                                // Defense in depth: a WAITING backlog
                                // (queued while at cap) must drain
                                // first or this envelope would jump
                                // its predecessors. Unreachable today
                                // (every join refills slots from the
                                // waiting set before the next recv),
                                // but cheap to make impossible.
                                && !queues.contains_key(&session_id)
                                && active.len() < MAX_ACTIVE_SESSIONS_PER_SHARD
                            {
                                // Idle session, free slot: dispatch now.
                                active.insert(session_id);
                                spawn_batch(&mut tasks, vec![envelope]);
                            } else {
                                // Active (order! behind the in-flight
                                // envelope) or no free slot: queue.
                                queues.entry(session_id).or_default().push_back(envelope);
                            }
                        }
                        None => receiver_open = false,
                    }
                }
                Some(joined) = tasks.join_next(), if !tasks.is_empty() => {
                    match joined {
                        Ok(session_id) => {
                            let backlog = queues.get_mut(&session_id).map_or(Vec::new(), |queue| {
                                let take = queue.len().min(MAX_BATCH_PER_SESSION);
                                queue.drain(..take).collect::<Vec<_>>()
                            });
                            if !backlog.is_empty() {
                                // Same session next-in-line keeps its
                                // slot: per-session order is preserved
                                // because dispatch for an ACTIVE session
                                // happens only here, after its
                                // predecessor joined. The backlog runs
                                // as ONE group-committed batch (§7.3).
                                if queues.get(&session_id).is_some_and(std::collections::VecDeque::is_empty) {
                                    queues.remove(&session_id);
                                }
                                spawn_batch(&mut tasks, backlog);
                            } else {
                                queues.remove(&session_id);
                                active.remove(&session_id);
                                // Slot freed: activate WAITING sessions
                                // (queued work, not active — enqueued
                                // while the shard was at cap).
                                let waiting = queues
                                    .keys()
                                    .filter(|id| !active.contains(*id))
                                    .take(
                                        MAX_ACTIVE_SESSIONS_PER_SHARD.saturating_sub(active.len()),
                                    )
                                    .cloned()
                                    .collect::<Vec<_>>();
                                for id in waiting {
                                    let batch = queues.get_mut(&id).map_or(Vec::new(), |queue| {
                                        let take = queue.len().min(MAX_BATCH_PER_SESSION);
                                        queue.drain(..take).collect::<Vec<_>>()
                                    });
                                    if batch.is_empty() {
                                        continue;
                                    }
                                    if queues.get(&id).is_some_and(std::collections::VecDeque::is_empty) {
                                        queues.remove(&id);
                                    }
                                    active.insert(id);
                                    spawn_batch(&mut tasks, batch);
                                }
                            }
                        }
                        Err(error) => {
                            // Only runtime teardown/abort can land here
                            // (the task body is panic-supervised and
                            // infallible). The session's queue entry
                            // stays; it re-activates on the next slot
                            // release via the waiting scan above.
                            tracing::error!(%error, "worker envelope task failed to join");
                        }
                    }
                }
                else => {
                    // Receiver closed and no tasks in flight. Queues can
                    // only be non-empty here after a JoinError leak
                    // (runtime teardown); surface it rather than hang.
                    if !queues.is_empty() {
                        tracing::error!(
                            sessions = queues.len(),
                            "worker shard exiting with undispatched envelopes after task join failure"
                        );
                    }
                    break;
                }
            }
        }
    });
}

/// Group commit: fdatasync a session's events journal
/// once, covering every deferred append a batch wrote before it.
async fn sync_session_journal(directory: &std::path::Path, session: &Session) -> Result<(), String> {
    let digest = av_core::digest::sha256_hex(session.id.as_bytes());
    let stem = digest.get(..32).unwrap_or(&digest);
    let path = directory.join(format!("{stem}.events.ndjson"));
    tokio::task::spawn_blocking(move || match std::fs::File::open(&path) {
        Ok(journal) => journal.sync_data().map_err(|error| error.to_string()),
        // No journal file: every job in the batch was skipped by the
        // capture-failed guard before appending anything.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.to_string()),
    })
    .await
    .map_err(|error| error.to_string())?
}

/// Group commit: process a SAME-SESSION batch of
/// envelopes with one journal fdatasync.
///
/// Phase A appends every job's record with the per-append sync
/// deferred; one `sync_session_journal` then makes the whole batch
/// durable; Phase B (publish, ack, totals, marker clear — everything
/// externally visible) runs per job strictly afterwards, so no job's
/// effects can precede its record's durability. A crash before the
/// batch sync is indistinguishable from crashing before processing:
/// nothing was published or acked, the response markers are still on
/// disk, and recovery quarantines exactly as it would have.
///
/// Fail-stop semantics match the serial path: a Phase A error marks
/// the session capture-failed and the remaining jobs resolve as
/// skipped/failed (their guards would have skipped them serially); a
/// Phase B error fails the batch's remaining jobs (their durable
/// records replay through crash recovery's re-publish path).
#[allow(clippy::too_many_arguments)]
async fn process_envelope_batch(
    envelopes: Vec<Envelope>,
    bridge: Arc<dyn EventBus>,
    embedder: Arc<dyn Embedder>,
    vector_sink: Arc<dyn VectorSink>,
    spool_dir: Option<std::path::PathBuf>,
    journal_key: [u8; 32],
    worker_metrics: Arc<Registry>,
    worker_pending: Arc<std::sync::atomic::AtomicU64>,
    worker_drained: Arc<tokio::sync::Notify>,
) {
    let mut iterator = envelopes.into_iter();
    let Some(first) = iterator.next() else { return };
    let rest: Vec<Envelope> = iterator.collect();
    if rest.is_empty() {
        return process_envelope(
            first,
            bridge,
            embedder,
            vector_sink,
            spool_dir,
            journal_key,
            worker_metrics,
            worker_pending,
            worker_drained,
        )
        .await;
    }
    let session = Arc::clone(&first.job.session);
    // Per-envelope bookkeeping: guards + permits live for the whole
    // batch; completions resolve individually below.
    let mut guards = Vec::new();
    let mut completions = Vec::new();
    let mut jobs = Vec::new();
    for envelope in std::iter::once(first).chain(rest) {
        let Envelope {
            job,
            completion,
            span,
            _capacity_permit: capacity_permit,
        } = envelope;
        guards.push((
            PendingGuard::new(Arc::clone(&worker_pending), Arc::clone(&worker_drained)),
            SessionPendingGuard {
                session: Arc::clone(&job.session),
            },
            capacity_permit,
        ));
        completions.push(completion);
        jobs.push((job, span));
    }
    let batch_metrics = Arc::clone(&worker_metrics);
    let batch_session = Arc::clone(&session);
    let spool = spool_dir.clone();
    let result = tokio::spawn(async move {
        let mut outcomes: Vec<Result<(), String>> = Vec::new();
        let mut persisted: Vec<Option<PersistedJob>> = Vec::new();
        let mut failed = false;
        // Phase A: append every record, sync deferred.
        for (job, span) in jobs {
            if failed {
                // Serial semantics: after a sibling failure the
                // capture-failed guard would have skipped this job.
                outcomes.push(Ok(()));
                persisted.push(None);
                continue;
            }
            let outcome = persist_job(
                job,
                Arc::clone(&embedder),
                Arc::clone(&vector_sink),
                spool.as_deref(),
                journal_key,
                &batch_metrics,
                /* sync_journal */ false,
            )
            .instrument(span)
            .await;
            match outcome {
                Ok(slot) => {
                    persisted.push(slot);
                    outcomes.push(Ok(()));
                }
                Err(error) => {
                    // Latch NOW so recovery semantics match serial
                    // processing (later jobs must not consume seqs).
                    batch_session.mark_capture_failed();
                    persisted.push(None);
                    outcomes.push(Err(error));
                    failed = true;
                }
            }
        }
        // The batch fsync: everything Phase A appended becomes
        // durable in one fdatasync.
        if let Some(directory) = spool.as_deref() {
            if persisted.iter().any(Option::is_some) {
                if let Err(error) = sync_session_journal(directory, &batch_session).await {
                    // None of the batch is provably durable: fail every
                    // job that had persisted (fail-closed, like a
                    // failed per-append sync on the serial path).
                    for (index, slot) in persisted.iter_mut().enumerate() {
                        if slot.take().is_some() {
                            if let Some(outcome) = outcomes.get_mut(index) {
                                *outcome = Err(format!("batch journal sync failed: {error}"));
                            }
                        }
                    }
                }
            }
        }
        // Phase B, in order, fail-stop.
        let mut tail_failed = false;
        for (index, slot) in persisted.into_iter().enumerate() {
            let Some(slot) = slot else { continue };
            if tail_failed {
                if let Some(outcome) = outcomes.get_mut(index) {
                    *outcome = Err("skipped after a batch sibling's post-persist failure".to_owned());
                }
                continue;
            }
            if let Err(error) = finish_job(slot, Arc::clone(&bridge), spool.as_deref(), journal_key).await {
                if let Some(outcome) = outcomes.get_mut(index) {
                    *outcome = Err(error);
                }
                tail_failed = true;
            }
        }
        outcomes
    })
    .await;
    let outcomes = match result {
        Ok(outcomes) => outcomes,
        Err(error) => {
            worker_metrics
                .counter(
                    "av_worker_panics_total",
                    "Worker job panics isolated by supervisor",
                )
                .inc();
            let failure = format!("worker batch panicked: {error}");
            vec![Err(failure); completions.len()]
        }
    };
    let mut any_failed = false;
    for (completion, outcome) in completions.into_iter().zip(outcomes) {
        if let Err(error) = &outcome {
            any_failed = true;
            tracing::warn!(session = %session.id, %error, "capture job failed; session is fail-closed");
            worker_metrics
                .counter("av_worker_errors_total", "Worker jobs that failed")
                .inc();
        }
        if let Some(completion) = completion {
            let _ = completion.send(outcome);
        }
    }
    if any_failed {
        session.mark_capture_failed();
    }
    drop(guards);
}

/// One envelope's worth of shard-driver work, factored out so
/// [`spawn_worker_shard`] can wrap the whole body in `catch_unwind`.
#[allow(clippy::too_many_arguments)]
async fn process_envelope(
    envelope: Envelope,
    bridge: Arc<dyn EventBus>,
    embedder: Arc<dyn Embedder>,
    vector_sink: Arc<dyn VectorSink>,
    spool_dir: Option<std::path::PathBuf>,
    journal_key: [u8; 32],
    worker_metrics: Arc<Registry>,
    worker_pending: Arc<std::sync::atomic::AtomicU64>,
    worker_drained: Arc<tokio::sync::Notify>,
) {
    // `worker_pending` was previously decremented at the
    // bottom of this function. Any panic between here and that line
    // (tokio::spawn(...).await JoinError construction under runtime
    // shutdown races, or a panic inside tracing::warn's Display
    // formatter when the error string exceeds the allocator's
    // fragmentation threshold) would leak the pending count — and
    // `WorkerHandle::wait_idle()` at shutdown would spin on
    // `notify.notified().await` forever, tripping the 30 s drain
    // budget and terminating without capturing evidence. Encode the
    // decrement in an RAII guard so unwinding is a valid release
    // point.
    let _pending_guard = PendingGuard::new(Arc::clone(&worker_pending), Arc::clone(&worker_drained));
    let Envelope {
        job,
        completion,
        span,
        _capacity_permit: capacity_permit,
    } = envelope;
    let session = Arc::clone(&job.session);
    // Guard the session-level pending-jobs decrement in
    // the same RAII shape as `PendingGuard`. The bare
    // `session.worker_job_finished()` after `tokio::spawn(...).await`
    // used to leak the session-level counter on any panic or drop
    // between here and line ~712. A stuck `session.pending_jobs` means
    // `close_session_locked -> wait_for_worker_jobs().await` blocks
    // forever on `jobs_drained.notified()`, holding the session's
    // lifecycle lock and starving every subsequent close / promote /
    // recovery-adopt on that id. Same leak class as the worker-level
    // counter, closed one call
    // frame up.
    let _session_pending_guard = SessionPendingGuard {
        session: Arc::clone(&session),
    };
    let result = tokio::spawn(
        {
            let job_metrics = Arc::clone(&worker_metrics);
            async move {
                process_job(
                    job,
                    bridge,
                    embedder,
                    vector_sink,
                    spool_dir,
                    journal_key,
                    job_metrics,
                )
                .await
            }
        }
        .instrument(span),
    )
    .await;
    let outcome = match result {
        Ok(result) => result,
        Err(error) => {
            worker_metrics
                .counter(
                    "av_worker_panics_total",
                    "Worker job panics isolated by supervisor",
                )
                .inc();
            Err(format!("worker job panicked: {error}"))
        }
    };
    if let Err(error) = &outcome {
        // The session flips fail-closed silently otherwise: name the
        // session and the root cause (e.g. EACCES on the journal
        // file) so operators can trace "capture is incomplete"
        // refusals back to this event.
        tracing::warn!(session = %session.id, %error, "capture job failed; session is fail-closed");
        session.mark_capture_failed();
        worker_metrics
            .counter("av_worker_errors_total", "Worker jobs that failed")
            .inc();
    }
    // `_session_pending_guard`'s Drop calls
    // `worker_job_finished()` — replaces the bare call previously
    // here so a panic between `spawn.await` and this point cannot
    // leak the session pending counter.
    drop(capacity_permit);
    // The pending guards (named bindings above) drop at end of scope —
    // AFTER the completion send below, not here. That order is fine:
    // the receiver needs only the outcome, and `wait_idle` /
    // `wait_for_worker_jobs` re-check the pending counters in a loop,
    // so a momentary completed-but-still-pending window is benign.
    if let Some(completion) = completion {
        let _ = completion.send(outcome);
    }
}

/// RAII decrement for `worker_pending`. Runs on every path — normal
/// return, error return, or panic — so `wait_idle` never sees a
/// permanently non-zero pending count after a panic in
/// [`process_envelope`].
struct PendingGuard {
    pending: Arc<std::sync::atomic::AtomicU64>,
    drained: Arc<tokio::sync::Notify>,
}

impl PendingGuard {
    fn new(pending: Arc<std::sync::atomic::AtomicU64>, drained: Arc<tokio::sync::Notify>) -> Self {
        Self { pending, drained }
    }
}

impl Drop for PendingGuard {
    fn drop(&mut self) {
        if self.pending.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.drained.notify_waiters();
        }
    }
}

/// RAII pair to [`PendingGuard`] for the session-level
/// pending-jobs counter. `Session::worker_job_finished()` was
/// previously called as a bare method after `tokio::spawn(...).await`,
/// but a panic in the routing-side epilogue (Display-side allocator
/// failure, catch_unwind of the wrapper future, runtime shutdown
/// mid-envelope) between `.await` and that call left
/// `session.pending_jobs` stuck. `close_session_locked` then blocked
/// forever on `wait_for_worker_jobs().await`, holding the session's
/// lifecycle lock — the exact leak class already closed on the
/// worker-level counter.
struct SessionPendingGuard {
    session: Arc<crate::session::Session>,
}

impl Drop for SessionPendingGuard {
    fn drop(&mut self) {
        self.session.worker_job_finished();
    }
}

fn worker_span(job: &WorkerJob) -> tracing::Span {
    tracing::info_span!(
        parent: &tracing::Span::current(),
        "agentvisor.worker",
        session.id = %job.session.id,
        event.class = ?job.class,
    )
}

#[allow(clippy::too_many_arguments)]
/// A job whose journal record is appended (Phase A of the
/// group commit) and which still owes its post-persist tail:
/// chain/step accounting, bridge publish, broker ack, totals, marker
/// clear. Carried between `persist_job` and `finish_job` so a
/// same-session batch can append N records under ONE fdatasync
/// before any job's effects become externally visible.
struct PersistedJob {
    session: Arc<Session>,
    identity: av_events::AgentIdentity,
    class: EventClass,
    value: Value,
    event_uid: String,
    record: ActiveJournalRecord,
    response_marker: Option<String>,
}

async fn process_job(
    job: WorkerJob,
    bridge: Arc<dyn EventBus>,
    embedder: Arc<dyn Embedder>,
    vector_sink: Arc<dyn VectorSink>,
    spool_dir: Option<std::path::PathBuf>,
    journal_key: [u8; 32],
    metrics: Arc<Registry>,
) -> Result<(), String> {
    match persist_job(
        job,
        embedder,
        vector_sink,
        spool_dir.as_deref(),
        journal_key,
        &metrics,
        /* sync_journal */ true,
    )
    .await?
    {
        None => Ok(()),
        Some(persisted) => finish_job(persisted, bridge, spool_dir.as_deref(), journal_key).await,
    }
}

/// Phase A: analyze, build the event + journal record, and append it
/// to the session journal (fsynced only when `sync_journal` — a batch
/// syncs once after its last append). Returns `None` when the session
/// is poisoned (capture-failed guard) and the job must be skipped
/// without consuming a sequence number.
async fn persist_job(
    mut job: WorkerJob,
    embedder: Arc<dyn Embedder>,
    vector_sink: Arc<dyn VectorSink>,
    spool_dir: Option<&std::path::Path>,
    journal_key: [u8; 32],
    metrics: &Arc<Registry>,
    sync_journal: bool,
) -> Result<Option<PersistedJob>, String> {
    // A queued envelope for a session that has already been poisoned must not
    // consume a sequence number or write to the journal — otherwise the seq
    // its OcsfEvent carries (from `next_seq`, advanced by the failed prior
    // envelope) would not match the entry's position on disk, breaking
    // recovery's `event.metadata.sequence != index` check.
    if job.session.capture_failed() {
        return Ok(None);
    }
    let response_marker = job.response_marker.clone();
    let is_llm_agent_response = job
        .atif
        .as_ref()
        .is_some_and(|capture| capture.source == av_atif::Source::Agent && capture.llm_call_count != Some(0));
    let step_tokens = job
        .metrics
        .prompt_tokens
        .unwrap_or(0)
        .saturating_add(job.metrics.completion_tokens.unwrap_or(0));
    let breaker = if job.analyze_loop {
        let text = job.text.clone();
        // vector-sink and embedder errors must not
        // brick the session — the sink's trait doc-comment describes it
        // as "off-path observability, not participating in the hot
        // path". A single 2 s Qdrant timeout or one transient
        // ONNX/HashEmbedder error used to `?`-propagate all the way to
        // `mark_capture_failed` (sticky) → 503 forever. Downgrade all
        // three failure modes (embed, query, record) to warn+counter +
        // continue-without-breaker: the audit chain still gets the
        // step; only the semantic-loop breaker is skipped for that
        // step. Journal and receipt integrity still fail-close as
        // before via other paths.
        let embedding_result = tokio::task::spawn_blocking(move || embedder.try_embed(&text))
            .await
            .map_err(|error| error.to_string())?;
        match embedding_result {
            Ok(embedding) => {
                let similarity = match vector_sink
                    .nearest_similarity(&job.session.session_scope, &embedding)
                    .await
                {
                    Ok(similarity) => similarity,
                    Err(error) => {
                        tracing::warn!(
                            session = %job.session.id,
                            %error,
                            "vector-sink nearest_similarity failed; skipping breaker for this step"
                        );
                        metrics
                            .counter(
                                "av_vector_sink_errors_total",
                                "Vector-sink errors demoted to warn",
                            )
                            .inc();
                        None
                    }
                };
                let verdict = job.session.loop_state.observe_embedding_with_similarity(
                    embedding.clone(),
                    step_tokens,
                    similarity,
                );
                if let Err(error) = vector_sink.record(&job.session.session_scope, &embedding).await {
                    tracing::warn!(
                        session = %job.session.id,
                        %error,
                        "vector-sink record failed; the local breaker still observed this step"
                    );
                    metrics
                        .counter(
                            "av_vector_sink_errors_total",
                            "Vector-sink errors demoted to warn",
                        )
                        .inc();
                }
                Some(verdict)
            }
            Err(error) => {
                tracing::warn!(
                    session = %job.session.id,
                    %error,
                    "embedder try_embed failed; skipping breaker for this step"
                );
                metrics
                    .counter("av_embedder_errors_total", "Embedder errors demoted to warn")
                    .inc();
                None
            }
        }
    } else {
        None
    };
    // Accounting must key on the class the job was *submitted* with: a
    // breaker trip replaces `class` with StopReason below, and deciding the
    // prompt/completion buckets from the replaced class silently dropped a
    // tripped chat admission's prompt tokens from the journal record and the
    // receipt totals — undercounting exactly the runaway sessions the
    // breaker exists to attest.
    let submitted_class = job.class;
    let (class, status, stop_reason, payload) = match breaker {
        Some(BreakerVerdict::Tripped {
            delta,
            streak,
            tokens_consumed,
            action,
        }) => {
            // The trip is recorded in the trajectory, but operators watching
            // logs/metrics must also see why this session's next request
            // will be rejected/aborted/injected.
            tracing::warn!(
                session = %job.session.id,
                delta,
                streak,
                tokens_consumed,
                action = ?action,
                "semantic loop circuit breaker tripped"
            );
            metrics
                .counter("av_breaker_trips_total", "Semantic loop breaker trips")
                .inc();
            // Latch at the trip itself — not only at the NEXT
            // admission's breaker-open refusal: a session whose breaker
            // trips and is then closed without another admission
            // attempt (explicit /close, idle sweep) would otherwise
            // recycle its id with a fresh breaker. Terminal actions
            // only, matching the admission arms: an Inject-configured
            // breaker resolves the trip by rewriting the next request,
            // so its trip must not make the id terminal.
            if matches!(
                action,
                av_loopdetect::BreakerAction::Abort | av_loopdetect::BreakerAction::Reject
            ) {
                job.session.latch_enforcement(StopReason::LoopDetected);
            }
            (
                EventClass::StopReason,
                StatusId::Failure,
                Some(StopReason::LoopDetected),
                serde_json::json!({
                    "delta": delta,
                    "streak": streak,
                    "tokens_consumed": tokens_consumed,
                    "action": action,
                }),
            )
        }
        _ => (job.class, job.status, job.stop_reason, job.payload),
    };

    let mut builder = OcsfEventBuilder::new(
        class,
        job.session.id.clone(),
        job.identity.clone(),
        job.session.next_seq(),
    )
    .status(status)
    .payload(payload)
    .metrics(job.metrics);
    if let Some(reason) = stop_reason {
        job.session.record_stop_reason(reason);
        builder = match job.native_stop_reason {
            Some(native) => builder.stop_reason_native(reason, native),
            None => builder.stop_reason(reason),
        };
    }
    let event = builder.build().map_err(|error| error.to_string())?;
    let event_uid = event.metadata.uid.clone();
    let value = serde_json::to_value(&event).map_err(|error| error.to_string())?;

    let atif_step = if job.session.workflow == Workflow::Unsigned {
        let capture = job
            .atif
            .take()
            .ok_or_else(|| "unsigned worker job has no ATIF capture".to_owned())?;
        let is_llm_step = capture.source == av_atif::Source::Agent && capture.llm_call_count != Some(0);
        Some(av_atif::Step {
            step_id: 0,
            timestamp: Some(av_core::time::now_iso8601()),
            source: capture.source,
            message: capture.message,
            reasoning_effort: None,
            reasoning_content: capture.reasoning_content,
            model_name: capture.model_name,
            tool_calls: capture.tool_calls,
            observation: capture.observation,
            metrics: is_llm_step.then(|| av_atif::Metrics {
                prompt_tokens: Some(job.metrics.prompt_tokens.unwrap_or(0)),
                completion_tokens: Some(job.metrics.completion_tokens.unwrap_or(0)),
                cached_tokens: Some(job.metrics.cached_tokens.unwrap_or(0)),
                cost_usd: Some(job.cost_usd_micros as f64 / av_core::units::USD_MICROS_PER_DOLLAR as f64),
                logprobs: None,
                completion_token_ids: None,
                prompt_token_ids: None,
                extra: None,
            }),
            is_copied_context: None,
            llm_call_count: capture.llm_call_count,
            extra: None,
        })
    } else {
        None
    };
    let is_tool_call = submitted_class == EventClass::ToolCall;
    let is_response_accounting = is_llm_agent_response && submitted_class != EventClass::Compression;
    let record = ActiveJournalRecord {
        event: value.clone(),
        identity: job.identity.clone(),
        atif_step: atif_step.clone(),
        tool_calls: u64::from(is_tool_call),
        tool_allowed: u64::from(is_tool_call && status == StatusId::Success),
        tool_blocked: u64::from(is_tool_call && status == StatusId::Failure),
        prompt_tokens: if submitted_class == EventClass::Compression {
            job.metrics.prompt_tokens.unwrap_or(0)
        } else {
            0
        },
        completion_tokens: if is_response_accounting {
            job.metrics.completion_tokens.unwrap_or(0)
        } else {
            0
        },
        cached_tokens: if is_response_accounting {
            job.metrics.cached_tokens.unwrap_or(0)
        } else {
            0
        },
        cost_usd_micros: if is_response_accounting {
            job.cost_usd_micros
        } else {
            0
        },
        prompt_token_correction: if is_response_accounting {
            job.prompt_token_correction
        } else {
            0
        },
        stop_reason_id: event.stop_reason_id,
        response_attempt: job.response_attempt.clone(),
    };
    if let Some(directory) = spool_dir {
        append_active_event_journal(
            directory,
            &job.session,
            &job.identity,
            &record,
            &journal_key,
            sync_journal,
        )
        .await?;
    }
    Ok(Some(PersistedJob {
        session: job.session,
        identity: job.identity,
        class,
        value,
        event_uid,
        record,
        response_marker,
    }))
}

/// Phase B: everything that makes the job externally visible. MUST
/// run only after the job's journal record is durable (its own
/// synced append, or the batch fsync covering it) — publishing an
/// unsynced event would let a crash leave the bus ahead of the
/// journal.
async fn finish_job(
    persisted: PersistedJob,
    bridge: Arc<dyn EventBus>,
    spool_dir: Option<&std::path::Path>,
    journal_key: [u8; 32],
) -> Result<(), String> {
    let PersistedJob {
        session,
        identity,
        class,
        value,
        event_uid,
        record,
        response_marker,
    } = persisted;
    match session.workflow {
        Workflow::Signed => session
            .chain
            .lock()
            .append(&value)
            .map_err(|error| error.to_string())?,
        Workflow::Unsigned => {
            // RAM-cliff guard: the step was already
            // journaled durably in `record.atif_step` — do NOT
            // retain a second copy in the in-RAM builder (50 turns ×
            // 2 KB × 10k sessions was 1.35 GB held for the idle
            // window). Close rebuilds the trajectory from the
            // journal; RAM keeps only the count.
            if record.atif_step.is_none() {
                return Err("unsigned ATIF step disappeared".to_owned());
            }
            session.note_atif_step();
        }
    }

    let key = identity.instance_uid.clone();
    let publish_topic = class.topic().to_owned();
    let publish_uid = event_uid.clone();
    let ack = tokio::task::spawn_blocking(move || {
        bridge.publish_idempotent(&publish_topic, &key, &value, &publish_uid)
    })
    .await
    .map_err(|error| error.to_string())?
    .map_err(|error| error.to_string())?;
    if let Some(directory) = spool_dir {
        persist_broker_ack(directory, &session.id, &event_uid, &ack, &journal_key).await?;
    }
    // The record IS the accounting rule. Its fields
    // were conditionalized once at construction above; apply them
    // through the same impl the recovery folds replay, so the live
    // path and a crash-recovered session can never attest different
    // numbers for identical traffic.
    record
        .apply_to_totals(&session.totals)
        .map_err(|error| error.to_string())?;
    if let (Some(directory), Some(attempt_id)) = (spool_dir, response_marker.as_deref()) {
        clear_response_marker(directory, &journal_key, &session.id, attempt_id).await?;
    }
    Ok(())
}

fn checked_atomic_add(counter: &std::sync::atomic::AtomicU64, value: u64, field: &str) -> Result<(), String> {
    counter
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            current
                .checked_add(value)
                .filter(|next| *next <= av_core::error::JCS_SAFE_MAX)
        })
        .map(|_| ())
        .map_err(|_| format!("{field} accounting exceeds JCS-safe bounds"))
}

/// Reserve a fresh attempt id without touching the disk. The guard
/// **must** be armed with this id before the `write_response_marker`
/// await below, so a client cancellation between the two doesn't leave
/// a durable marker no in-memory guard owns.
pub(crate) fn reserve_response_attempt_id() -> String {
    av_core::new_event_uid()
}

pub(crate) async fn write_response_marker(
    spool_dir: &std::path::Path,
    journal_key: &[u8; 32],
    session_id: &str,
    attempt_id: &str,
    request_digest: String,
) -> Result<(), String> {
    let marker = InFlightResponse {
        session_id: session_id.to_owned(),
        attempt_id: attempt_id.to_owned(),
        request_digest,
    };
    let sealed = crate::journal::seal(journal_key, "in-flight-response", 0, &marker)?;
    let path = response_marker_path(spool_dir, session_id, attempt_id);
    tokio::task::spawn_blocking(move || write_atomic_control(&path, &sealed))
        .await
        .map_err(|error| error.to_string())??;
    Ok(())
}

// Retained for tests + backwards compat — reserves id, writes marker,
// returns the id. Do not use on cancellable paths (see
// `reserve_response_attempt_id`).
#[allow(dead_code)]
pub(crate) async fn create_response_marker(
    spool_dir: &std::path::Path,
    journal_key: &[u8; 32],
    session_id: &str,
    request_digest: String,
) -> Result<String, String> {
    let attempt_id = reserve_response_attempt_id();
    write_response_marker(spool_dir, journal_key, session_id, &attempt_id, request_digest).await?;
    Ok(attempt_id)
}

#[cfg(test)]
pub(crate) async fn ensure_no_inflight_responses(
    spool_dir: &std::path::Path,
    journal_key: &[u8; 32],
) -> Result<(), String> {
    let sessions = inflight_response_sessions(spool_dir, journal_key).await?;
    if let Some(session_id) = sessions.into_iter().next() {
        Err(format!(
            "provider response for session {session_id} was not durably captured"
        ))
    } else {
        Ok(())
    }
}

pub(crate) async fn inflight_response_sessions(
    spool_dir: &std::path::Path,
    journal_key: &[u8; 32],
) -> Result<std::collections::HashSet<String>, String> {
    let spool_dir = spool_dir.to_path_buf();
    let directory = spool_dir.join(crate::spool::INFLIGHT_RESPONSES);
    let journal_key = *journal_key;
    tokio::task::spawn_blocking(move || {
        let entries = match std::fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(std::collections::HashSet::new());
            }
            Err(error) => return Err(error.to_string()),
        };
        let mut sessions = std::collections::HashSet::new();
        for entry in entries {
            let path = entry.map_err(|error| error.to_string())?.path();
            if path.extension().and_then(std::ffi::OsStr::to_str) != Some("json") {
                continue;
            }
            let marker_bytes = match av_core::fsutil::read_capped(&path, av_core::fsutil::MAX_CONTROL_BYTES) {
                Ok(bytes) => bytes,
                // A live request legitimately clears its marker between
                // the directory listing and this read — the response
                // completed; it is not in flight.
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.to_string()),
            };
            // A single unverifiable marker (seed rotation, future field
            // added to `InFlightResponse`, torn payload) must not brick
            // recovery — which is fatal at boot in main.rs. Mirror the
            // tool-intent quarantine discipline: warn, rename to
            // `.corrupt-<uid>`, skip. The signed chain never referenced
            // this file; nothing else claims it.
            let marker: InFlightResponse =
                match crate::journal::open(&journal_key, "in-flight-response", 0, &marker_bytes) {
                    Ok(marker) => marker,
                    Err(error) => {
                        quarantine_inflight_marker(&path, &error);
                        continue;
                    }
                };
            if path != response_marker_path(&spool_dir, &marker.session_id, &marker.attempt_id) {
                // Same defense: a marker whose payload's ids don't
                // reconstruct its filename must not stall recovery.
                quarantine_inflight_marker(
                    &path,
                    "in-flight response marker path does not match its payload",
                );
                continue;
            }
            sessions.insert(marker.session_id);
        }
        Ok(sessions)
    })
    .await
    .map_err(|error| error.to_string())?
}

async fn clear_response_marker(
    spool_dir: &std::path::Path,
    journal_key: &[u8; 32],
    session_id: &str,
    attempt_id: &str,
) -> Result<(), String> {
    let path = response_marker_path(spool_dir, session_id, attempt_id);
    let journal_key = *journal_key;
    let session_id = session_id.to_owned();
    let attempt_id = attempt_id.to_owned();
    tokio::task::spawn_blocking(move || {
        // Cancellation tolerance: the caller may race a write that
        // never landed (cancellation between spawn_blocking and
        // set_marker), or a marker that recovery already quarantined.
        // Absent marker means "already cleared" — do not surface as an
        // error, which would poison the terminal job and leak the
        // marker into unbounded scan/growth.
        let marker_bytes = match av_core::fsutil::read_capped(&path, av_core::fsutil::MAX_CONTROL_BYTES) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.to_string()),
        };
        let marker: InFlightResponse =
            crate::journal::open(&journal_key, "in-flight-response", 0, &marker_bytes)?;
        if marker.session_id != session_id || marker.attempt_id != attempt_id {
            return Err("in-flight response marker does not match completed job".to_owned());
        }
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.to_string()),
        }
        let parent = path
            .parent()
            .ok_or_else(|| "in-flight response marker has no parent".to_owned())?;
        av_core::fsutil::sync_directory(parent).map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| error.to_string())?
}

/// Rename an unverifiable in-flight-response marker out of the way and
/// log a single warn. Keeps the file as evidence at a stable
/// `.corrupt-<uid>` name so operators can retrieve it. The quarantine
/// name must NOT end in `.json`: the recovery scan filters on that
/// extension, so a `.json`-suffixed quarantine would be re-read,
/// MAC-fail, and re-quarantine on every reconciler tick — compounding
/// the name until ENAMETOOLONG and warning twice per tick forever
/// (same rule as the reconciler's quarantine rename).
fn quarantine_inflight_marker(path: &std::path::Path, error: impl std::fmt::Display) {
    let uid = av_core::new_event_uid();
    let name = path
        .file_stem()
        .and_then(std::ffi::OsStr::to_str)
        .map(|stem| format!("{stem}.corrupt-{uid}"))
        .unwrap_or_else(|| format!("corrupt-{uid}"));
    let quarantine = path.with_file_name(name);
    tracing::warn!(
        %error,
        original = %av_core::fsutil::basename(path),
        quarantine = %av_core::fsutil::basename(&quarantine),
        "unverifiable in-flight-response marker quarantined so recovery can proceed"
    );
    if let Err(rename_err) = std::fs::rename(path, &quarantine) {
        tracing::warn!(
            %rename_err,
            "failed to quarantine in-flight-response marker — leaving in place"
        );
    }
}

fn response_marker_path(
    spool_dir: &std::path::Path,
    session_id: &str,
    attempt_id: &str,
) -> std::path::PathBuf {
    let digest = av_core::digest::sha256_hex(format!("{session_id}:{attempt_id}").as_bytes());
    spool_dir
        .join(crate::spool::INFLIGHT_RESPONSES)
        .join(format!("{}.json", &digest[..32]))
}

fn write_atomic_control(path: &std::path::Path, bytes: &[u8]) -> Result<(), String> {
    av_core::fsutil::write_atomic(path, bytes).map_err(|error| error.to_string())
}

async fn append_active_event_journal(
    directory: &std::path::Path,
    session: &Session,
    _identity: &av_events::AgentIdentity,
    record: &ActiveJournalRecord,
    journal_key: &[u8; 32],
    sync: bool,
) -> Result<(), String> {
    let index = session.journal_index();
    let domain = format!("{}:active", session.id);
    let line = crate::journal::seal(journal_key, &domain, index, record)?;
    append_journal(directory, session, line, *journal_key, sync).await?;
    session.commit_journal_index(index)
}

async fn append_journal(
    directory: &std::path::Path,
    session: &Session,
    line: Vec<u8>,
    journal_key: [u8; 32],
    sync: bool,
) -> Result<(), String> {
    let directory = directory.to_path_buf();
    let session_id = session.id.clone();
    let identity = session.identity.clone();
    let workflow = session.workflow.as_str();
    tokio::task::spawn_blocking(move || -> Result<(), String> {
        use std::io::Write as _;
        // Skip the mkdir when the spool dir already
        // exists (every request after the first).
        if !directory.is_dir() {
            std::fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
        }
        let digest = av_core::digest::sha256_hex(session_id.as_bytes());
        let stem = digest.get(..32).unwrap_or(&digest);
        let metadata_path = directory.join(format!("{stem}.session.json"));
        let metadata_payload = serde_json::json!({
            "journal_version": 2,
            "session_id": session_id,
            "identity": identity,
            "workflow": workflow,
        });
        if !metadata_path.exists() {
            let metadata = crate::journal::seal(&journal_key, "metadata", 0, &metadata_payload)?;
            // Use the centralized atomic writer: it uses an RAII guard
            // so any intermediate failure (write_all / sync_all /
            // rename) cannot leak a zero-byte `.tmp` orphan. A
            // repeatedly-failing journal writer used to be able to
            // exhaust the ext4 inode table long before disk-full.
            //
            // Basename the paths in error strings. These
            // errors bubble to `tracing::warn!(session = %session.id,
            // %error, "capture job failed; session is fail-closed")`
            // at process_envelope; that warn exports through
            // tracing_opentelemetry -> OTLP -> SIEM, so a single
            // disk-full incident used to emit one span per pending
            // event with the full absolute journal tree. Basename
            // preserves enough context for triage (the stem encodes
            // the session id) without leaking the deployment topology.
            av_core::fsutil::write_atomic(&metadata_path, &metadata).map_err(|error| {
                format!(
                    "write journal metadata {}: {error}",
                    av_core::fsutil::basename(&metadata_path)
                )
            })?;
        } else {
            let stored: serde_json::Value = crate::journal::open(
                &journal_key,
                "metadata",
                0,
                // Cap sealed journal-metadata read at
                // MAX_CONTROL_BYTES.
                &av_core::fsutil::read_capped(&metadata_path, av_core::fsutil::MAX_CONTROL_BYTES)
                    .map_err(|error| error.to_string())?,
            )?;
            if stored != metadata_payload {
                return Err("journal metadata does not match session workflow and identity".to_owned());
            }
        }
        let journal_path = directory.join(format!("{stem}.events.ndjson"));
        // Track whether the journal is being created by *this* append so
        // we can fsync the containing directory once the file exists —
        // the metadata fsync above only durably named the metadata
        // file, not this new journal file. Without the dirent fsync,
        // a power loss on POSIX-conformant filesystems (xfs, btrfs)
        // can lose the entry entirely — the file appears not to exist
        // on restart, `recover_signed_journals` treats the journal as
        // empty, deletes the metadata, and every already-acked event
        // becomes orphaned on the broker.
        let journal_created = !journal_path.exists();
        let mut journal = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&journal_path)
            .map_err(|error| {
                format!(
                    "open event journal {}: {error}",
                    av_core::fsutil::basename(&journal_path)
                )
            })?;
        journal.write_all(&line).map_err(|error| error.to_string())?;
        journal.write_all(b"\n").map_err(|error| error.to_string())?;
        // Group commit: a same-session batch defers
        // this to ONE fdatasync issued by its LAST append —
        // `sync_data` flushes all of the file's dirty pages
        // regardless of which fd wrote them, so the final synced
        // append makes every prior deferred line in the batch
        // durable. No job's Phase B runs before the batch sync.
        if sync {
            journal.sync_data().map_err(|error| error.to_string())?;
        }
        if journal_created {
            std::fs::File::open(&directory)
                .and_then(|dir| dir.sync_all())
                .map_err(|error| {
                    // Drop the full path entirely; the
                    // sibling `session = %session.id` field on the
                    // downstream warn already scopes this to a
                    // specific session, and the containing directory
                    // is `atif_spool_dir` — same across the whole
                    // deployment.
                    format!("fsync journal directory: {error}")
                })?;
        }
        Ok(())
    })
    .await
    .map_err(|error| error.to_string())?
}

/// Broker acks append to ONE per-session NDJSON
/// journal (`{stem}.acks.ndjson` in the spool root) instead of one
/// `write_atomic` file per event under `broker-acks/<hash>/`. Per
/// ack this replaces two durable syncs (tmp `sync_all` + parent-dir
/// sync) and the tmp-create/rename metadata ops with a single
/// appended line + `sync_data`, and stops leaving one file per
/// request on disk. Each line is the SAME sealed record bytes the
/// per-event file carried (domain "broker-ack", index 0): lines are
/// self-describing and order-independent, so reordering/duplication
/// grants nothing, and a truncated tail line simply reads as "no
/// ack" — the event is re-published, which the bridge tolerates
/// (same recovery semantics as a lost ack file).
pub(crate) async fn persist_broker_ack(
    directory: &std::path::Path,
    session_id: &str,
    event_uid: &str,
    ack: &PublishAck,
    journal_key: &[u8; 32],
) -> Result<(), String> {
    let path = ack_journal_path(directory, session_id);
    let record = BrokerAckRecord {
        session_id: session_id.to_owned(),
        event_uid: event_uid.to_owned(),
        ack: ack.clone(),
    };
    let sealed = crate::journal::seal(journal_key, "broker-ack", 0, &record)?;
    tokio::task::spawn_blocking(move || -> Result<(), String> {
        use std::io::Write as _;
        let created = !path.exists();
        let mut journal = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|error| format!("open ack journal {}: {error}", av_core::fsutil::basename(&path)))?;
        journal.write_all(&sealed).map_err(|error| error.to_string())?;
        journal.write_all(b"\n").map_err(|error| error.to_string())?;
        journal.sync_data().map_err(|error| error.to_string())?;
        if created {
            // First ack for this session: make the dirent durable so a
            // crash cannot lose the whole journal (same discipline as
            // the events journal).
            let parent = path
                .parent()
                .ok_or_else(|| "ack journal has no parent".to_owned())?;
            av_core::fsutil::sync_directory(parent).map_err(|error| error.to_string())?;
        }
        Ok(())
    })
    .await
    .map_err(|error| error.to_string())?
}

pub(crate) async fn read_broker_ack(
    directory: &std::path::Path,
    session_id: &str,
    event_uid: &str,
    journal_key: &[u8; 32],
) -> Result<Option<PublishAck>, String> {
    // New layout first: scan the per-session ack journal. Recovery-only
    // path, so the linear scan per lookup is acceptable (the journal is
    // capped at MAX_CONTROL_BYTES ≈ 5k acks).
    {
        let path = ack_journal_path(directory, session_id);
        let bytes = match tokio::task::spawn_blocking({
            let path = path.clone();
            move || av_core::fsutil::read_capped(&path, av_core::fsutil::MAX_CONTROL_BYTES)
        })
        .await
        .map_err(|error| error.to_string())?
        {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.to_string()),
        };
        if let Some(bytes) = bytes {
            for line in bytes.split(|byte| *byte == b'\n') {
                if line.is_empty() {
                    continue;
                }
                // A torn tail line (crash mid-append) or a tampered line
                // must not poison the earlier, intact acks: skip lines
                // that fail to open and keep scanning. "No ack found"
                // degrades to a re-publish, exactly like a lost file.
                let Ok(record) = crate::journal::open::<BrokerAckRecord>(journal_key, "broker-ack", 0, line)
                else {
                    continue;
                };
                if record.session_id == session_id && record.event_uid == event_uid {
                    return Ok(Some(record.ack));
                }
            }
        }
    }
    // Legacy layout fallback (older per-event files), so a
    // deployment upgraded mid-session still sees its earlier acks.
    let path = broker_ack_path(directory, session_id, event_uid);
    // Bounded read — same policy as every other sealed marker in the
    // spool (close-complete marker, promotion marker, response marker,
    // ATIF sidecar). A local fs-tamper attacker plant at
    // `spool/broker-acks/<hash>/<hash>.json` would otherwise blow up
    // memory during finalize before MAC rejection: `journal::open` calls
    // `serde_json::from_slice` on the raw bytes, and a multi-GB file
    // reaches serde_json's own limit only after the initial `read` has
    // already allocated the whole buffer. `MAX_CONTROL_BYTES` (1 MiB)
    // is far above any legitimate ack record.
    let bytes = match tokio::task::spawn_blocking({
        let path = path.clone();
        move || av_core::fsutil::read_capped(&path, av_core::fsutil::MAX_CONTROL_BYTES)
    })
    .await
    .map_err(|error| error.to_string())?
    {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };
    let record: BrokerAckRecord = crate::journal::open(journal_key, "broker-ack", 0, &bytes)?;
    if record.session_id != session_id || record.event_uid != event_uid {
        return Err("broker acknowledgment does not match event".to_owned());
    }
    Ok(Some(record.ack))
}

/// Group-commit layout: one append-only ack journal per session.
fn ack_journal_path(directory: &std::path::Path, session_id: &str) -> std::path::PathBuf {
    let digest = av_core::digest::sha256_hex(session_id.as_bytes());
    directory.join(format!("{}.acks.ndjson", digest.get(..32).unwrap_or(&digest)))
}

/// Legacy per-event layout, read-only fallback.
fn broker_ack_path(directory: &std::path::Path, session_id: &str, event_uid: &str) -> std::path::PathBuf {
    let session_digest = av_core::digest::sha256_hex(session_id.as_bytes());
    let event_digest = av_core::digest::sha256_hex(event_uid.as_bytes());
    directory
        .join("broker-acks")
        .join(&session_digest[..32])
        .join(format!("{}.json", &event_digest[..32]))
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
    use av_loopdetect::{BreakerConfig, HashEmbedder};
    use parking_lot::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};

    /// Mutation-run hardening (round 11): the queue-drain notify in
    /// `worker_job_finished` fires exactly on the LAST decrement — a
    /// surviving `==`→`!=` mutant notified on every decrement EXCEPT
    /// the final one, so a `wait_idle` caller that subscribed while the
    /// last job was in flight waited forever (the lost-final-wakeup
    /// class; shutdown and tests both sit in wait_idle).
    #[tokio::test]
    async fn wait_idle_wakes_on_the_final_job() {
        let bus = Arc::new(GatedBus::new("drain-session"));
        let worker = Arc::new(spawn_worker(
            64,
            Arc::clone(&bus) as Arc<dyn EventBus>,
            Arc::new(HashEmbedder::default()),
            Arc::new(Registry::new()),
        ));
        let session = session_with_id("drain-session");
        worker.try_submit(job(Arc::clone(&session))).unwrap();
        // Subscribe while the single job is still gated in publish.
        let waiter = tokio::spawn({
            let worker = Arc::clone(&worker);
            async move { worker.wait_idle().await }
        });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(
            !waiter.is_finished(),
            "wait_idle must block while the job is gated"
        );
        bus.release.store(true, std::sync::atomic::Ordering::Release);
        tokio::time::timeout(std::time::Duration::from_secs(5), waiter)
            .await
            .expect("wait_idle must wake on the FINAL job's completion")
            .unwrap();
    }

    /// Mutation-run hardening (round 11): a batch whose every job was
    /// skipped by the capture-failed guard writes NO journal file —
    /// the group-commit fsync must treat the missing file as success,
    /// not an error (a guard mutant converting NotFound to failure
    /// survived because no test synced a journal-less session).
    #[tokio::test]
    async fn sync_session_journal_tolerates_a_missing_journal() {
        let directory = tempfile::tempdir().unwrap();
        let session = session_with_id("never-journaled");
        sync_session_journal(directory.path(), &session)
            .await
            .expect("a missing journal is the every-job-skipped shape, not a fault");
    }

    /// Mutation-run hardening (round 11): the attempt-id reservation
    /// must mint unique non-empty ids (a constant would collide the
    /// durable marker paths of concurrent attempts), the marker write
    /// must create its spool subdirectory on FIRST use, and the
    /// broker-ack lookup must refuse an ack whose session OR event uid
    /// differs (an ||→&& mutant accepted half-matching acks — cross-
    /// event ack reuse during recovery).
    #[tokio::test]
    async fn markers_and_acks_pin_identity_and_first_use() {
        let a = reserve_response_attempt_id();
        let b = reserve_response_attempt_id();
        assert!(!a.is_empty());
        assert_ne!(a, b, "attempt ids must be unique");

        let directory = tempfile::tempdir().unwrap();
        let key = [21u8; 32];
        write_response_marker(directory.path(), &key, "marker-session", &a, "digest".to_owned())
            .await
            .expect("the first marker write must create the spool subdirectory");

        let ack = PublishAck {
            topic: "agent.session".to_owned(),
            partition: 0,
            offset: 7,
        };
        persist_broker_ack(directory.path(), "ack-session", "uid-1", &ack, &key)
            .await
            .unwrap();
        assert_eq!(
            read_broker_ack(directory.path(), "ack-session", "uid-1", &key)
                .await
                .unwrap(),
            Some(ack),
            "the matching (session, uid) pair must resolve"
        );
        assert!(
            read_broker_ack(directory.path(), "ack-session", "uid-2", &key)
                .await
                .unwrap()
                .is_none()
                || read_broker_ack(directory.path(), "ack-session", "uid-2", &key)
                    .await
                    .is_err(),
            "a half-matching ack (same session, different uid) must never resolve"
        );
        assert!(
            read_broker_ack(directory.path(), "other-session", "uid-1", &key)
                .await
                .unwrap()
                .is_none()
                || read_broker_ack(directory.path(), "other-session", "uid-1", &key)
                    .await
                    .is_err(),
            "a half-matching ack (different session, same uid) must never resolve"
        );
    }

    /// Mutation-run hardening (round 11): the fold invariant every
    /// journal replay checks — classified tool outcomes can never
    /// exceed observed calls — had a surviving Ok(()) mutant. A fold
    /// that accepts inconsistent accounting attests corrupted tool
    /// totals into the signed receipt.
    #[test]
    fn tool_accounting_invariant_is_enforced() {
        let consistent = RecoveredTotals {
            tool_calls: 5,
            tool_allowed: 3,
            tool_blocked: 2,
            ..RecoveredTotals::default()
        };
        assert!(consistent.validate_tool_accounting().is_ok());
        let inconsistent = RecoveredTotals {
            tool_calls: 4,
            tool_allowed: 3,
            tool_blocked: 2,
            ..RecoveredTotals::default()
        };
        assert!(
            inconsistent.validate_tool_accounting().is_err(),
            "classified > calls must be refused"
        );
        let overflowing = RecoveredTotals {
            tool_calls: u64::MAX,
            tool_allowed: u64::MAX,
            tool_blocked: 1,
            ..RecoveredTotals::default()
        };
        assert!(
            overflowing.validate_tool_accounting().is_err(),
            "the classified sum overflowing u64 must be refused"
        );
    }

    #[derive(Default)]
    struct RecordingBus {
        events: Mutex<Vec<(String, String, Value)>>,
    }

    struct PanicOnceSink {
        panicked: AtomicBool,
    }

    struct SlowEmbedder;

    impl Embedder for SlowEmbedder {
        fn dim(&self) -> usize {
            1
        }

        fn embed(&self, _text: &str) -> Vec<f32> {
            std::thread::sleep(std::time::Duration::from_millis(100));
            vec![1.0]
        }
    }

    /// A bus that BLOCKS publishes whose value names
    /// the gated session until released — deterministic stand-in for
    /// a hung broker/journal on one session.
    struct GatedBus {
        gated_session: String,
        release: AtomicBool,
        published: Mutex<Vec<String>>,
    }

    impl GatedBus {
        fn new(gated_session: &str) -> Self {
            Self {
                gated_session: gated_session.to_owned(),
                release: AtomicBool::new(false),
                published: Mutex::new(Vec::new()),
            }
        }
    }

    impl EventBus for GatedBus {
        fn publish(&self, topic: &str, _key: &str, value: &Value) -> Result<PublishAck, BusError> {
            let text = value.to_string();
            if text.contains(&self.gated_session) {
                while !self.release.load(Ordering::Acquire) {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
            }
            self.published.lock().push(text);
            Ok(PublishAck {
                topic: topic.to_owned(),
                partition: 0,
                offset: 0,
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
            EventClass::all()
                .iter()
                .map(|class| class.topic().to_owned())
                .collect()
        }
    }

    struct SlowBus;

    impl EventBus for SlowBus {
        fn publish(&self, topic: &str, _key: &str, _value: &Value) -> Result<PublishAck, BusError> {
            std::thread::sleep(std::time::Duration::from_millis(100));
            Ok(PublishAck {
                topic: topic.to_owned(),
                partition: 0,
                offset: 0,
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
            EventClass::all()
                .iter()
                .map(|class| class.topic().to_owned())
                .collect()
        }
    }

    impl VectorSink for PanicOnceSink {
        fn record<'a>(
            &'a self,
            _session_id: &'a str,
            _vector: &'a [f32],
        ) -> av_loopdetect::VectorSinkFuture<'a> {
            Box::pin(async move {
                if !self.panicked.swap(true, AtomicOrdering::AcqRel) {
                    panic!("injected vector sink panic");
                }
                Ok(())
            })
        }
    }

    impl EventBus for RecordingBus {
        fn publish(&self, topic: &str, key: &str, value: &Value) -> Result<PublishAck, BusError> {
            let mut events = self.events.lock();
            let offset = events.len() as u64;
            events.push((topic.to_owned(), key.to_owned(), value.clone()));
            Ok(PublishAck {
                topic: topic.to_owned(),
                partition: 0,
                offset,
            })
        }

        fn publish_idempotent(
            &self,
            topic: &str,
            key: &str,
            value: &Value,
            event_uid: &str,
        ) -> Result<PublishAck, BusError> {
            if let Some((offset, _)) = self
                .events
                .lock()
                .iter()
                .enumerate()
                .find(|(_, (_, _, event))| event["metadata"]["uid"] == event_uid)
            {
                return Ok(PublishAck {
                    topic: topic.to_owned(),
                    partition: 0,
                    offset: offset as u64,
                });
            }
            self.publish(topic, key, value)
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
            EventClass::all()
                .iter()
                .map(|class| class.topic().to_owned())
                .collect()
        }
    }

    fn session(workflow: Workflow) -> Arc<Session> {
        Arc::new(Session::new(
            "session-1".to_owned(),
            workflow,
            AgentIdentity {
                version: "1".to_owned(),
                charter: "test".into(),
                instance_uid: "instance-1".to_owned(),
                ttl_remaining_s: Some(600),
            },
            BreakerConfig {
                min_tokens: u64::MAX,
                ..BreakerConfig::default()
            },
        ))
    }

    fn job(session: Arc<Session>) -> WorkerJob {
        WorkerJob {
            identity: session.current_identity(),
            session,
            class: EventClass::Compression,
            payload: serde_json::json!({"kind": "response"}),
            text: "a useful response".to_owned(),
            analyze_loop: true,
            status: StatusId::Success,
            stop_reason: None,
            native_stop_reason: None,
            metrics: EventMetrics {
                prompt_tokens: Some(100),
                completion_tokens: Some(20),
                cached_tokens: Some(40),
                pruned_tokens: Some(10),
                pruning_ratio_millis: Some(100),
            },
            cost_usd_micros: 250,
            prompt_token_correction: 0,
            atif: Some(AtifCapture {
                source: av_atif::Source::Agent,
                message: Value::String("a useful response".to_owned()),
                reasoning_content: None,
                model_name: None,
                tool_calls: None,
                observation: None,
                llm_call_count: Some(1),
            }),
            response_marker: None,
            response_attempt: None,
        }
    }

    #[test]
    fn receipt_accounting_never_wraps_or_exceeds_jcs_bounds() {
        let counter = std::sync::atomic::AtomicU64::new(av_core::error::JCS_SAFE_MAX);
        assert!(checked_atomic_add(&counter, 1, "test").is_err());
        assert_eq!(counter.load(Ordering::Acquire), av_core::error::JCS_SAFE_MAX);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn synchronous_backends_do_not_block_tokio_worker_thread() {
        let worker = spawn_worker(
            4,
            Arc::new(SlowBus),
            Arc::new(SlowEmbedder),
            Arc::new(Registry::new()),
        );
        worker.try_submit(job(session(Workflow::Signed))).unwrap();

        let started = std::time::Instant::now();
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        assert!(
            started.elapsed() < std::time::Duration::from_millis(75),
            "synchronous worker dependency blocked the Tokio reactor"
        );
        worker.wait_idle().await;
    }

    #[tokio::test]
    async fn response_marker_is_authenticated_and_cleared_after_publish() {
        let directory = tempfile::tempdir().unwrap();
        let journal_key = [13; 32];
        let marker = create_response_marker(
            directory.path(),
            &journal_key,
            "session-1",
            "request-digest".to_owned(),
        )
        .await
        .unwrap();
        assert!(ensure_no_inflight_responses(directory.path(), &journal_key)
            .await
            .unwrap_err()
            .contains("was not durably captured"));

        let worker = spawn_worker_with_spool_authenticated(
            4,
            Arc::new(RecordingBus::default()),
            Arc::new(HashEmbedder::default()),
            Arc::new(NoopVectorSink),
            Some(directory.path().to_path_buf()),
            journal_key,
            Arc::new(Registry::new()),
        );
        let session = session(Workflow::Signed);
        let mut response = job(session);
        response.response_marker = Some(marker);
        worker.submit_and_wait(response).await.unwrap();
        ensure_no_inflight_responses(directory.path(), &journal_key)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn response_marker_rejects_payload_mutation() {
        // Behavior contract: an unverifiable marker is
        // now quarantined (renamed to `.corrupt-<uid>`) instead of
        // bricking the recovery scan. Verify (a) the tampered file is
        // moved out of the way, so it no longer counts as "in-flight",
        // and (b) recovery reports "no in-flight sessions" cleanly. A
        // hard error would fail-close the entire boot, the exact
        // regression the fix eliminates.
        let directory = tempfile::tempdir().unwrap();
        let journal_key = [17; 32];
        create_response_marker(
            directory.path(),
            &journal_key,
            "session-1",
            "request-digest".to_owned(),
        )
        .await
        .unwrap();
        let marker_path = std::fs::read_dir(directory.path().join(crate::spool::INFLIGHT_RESPONSES))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let mut envelope: Value = serde_json::from_slice(&std::fs::read(&marker_path).unwrap()).unwrap();
        envelope["payload"]["request_digest"] = Value::String("forged".to_owned());
        std::fs::write(&marker_path, serde_json::to_vec(&envelope).unwrap()).unwrap();
        ensure_no_inflight_responses(directory.path(), &journal_key)
            .await
            .expect("tampered marker quarantines cleanly instead of poisoning recovery");
        // Original path is renamed; a `.corrupt-*.json` sibling remains
        // for operator evidence retrieval.
        assert!(
            !marker_path.exists(),
            "tampered marker should be quarantined out of the primary name"
        );
        let inflight_dir = directory.path().join(crate::spool::INFLIGHT_RESPONSES);
        let mut has_corrupt = false;
        for entry in std::fs::read_dir(&inflight_dir).unwrap() {
            let name = entry.unwrap().file_name();
            if name.to_string_lossy().contains(".corrupt-") {
                has_corrupt = true;
                break;
            }
        }
        assert!(
            has_corrupt,
            "expected a `.corrupt-<uid>.json` sibling as evidence"
        );
    }

    #[tokio::test]
    async fn signed_job_publishes_and_extends_chain() {
        let bridge = Arc::new(RecordingBus::default());
        let metrics = Arc::new(Registry::new());
        let worker = spawn_worker(4, bridge.clone(), Arc::new(HashEmbedder::default()), metrics);
        let session = session(Workflow::Signed);
        worker.submit_and_wait(job(Arc::clone(&session))).await.unwrap();

        assert_eq!(session.chain.lock().count(), 1);
        assert_eq!(session.totals.prompt_tokens.load(Ordering::Acquire), 100);
        let events = bridge.events.lock();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].0, "agent.compression");
        assert_eq!(events[0].1, "instance-1");
    }

    #[tokio::test]
    async fn signed_job_journals_event_and_accounting() {
        let directory = tempfile::tempdir().unwrap();
        let journal_key = [9; 32];
        let worker = spawn_worker_with_spool_authenticated(
            4,
            Arc::new(RecordingBus::default()),
            Arc::new(HashEmbedder::default()),
            Arc::new(NoopVectorSink),
            Some(directory.path().to_path_buf()),
            journal_key,
            Arc::new(Registry::new()),
        );
        let session = session(Workflow::Signed);
        worker.submit_and_wait(job(Arc::clone(&session))).await.unwrap();

        let digest = av_core::digest::sha256_hex(session.id.as_bytes());
        let stem = digest.get(..32).unwrap();
        let metadata: Value = crate::journal::open(
            &journal_key,
            "metadata",
            0,
            &std::fs::read(directory.path().join(format!("{stem}.session.json"))).unwrap(),
        )
        .unwrap();
        assert_eq!(metadata["workflow"], "signed");
        let journal =
            std::fs::read_to_string(directory.path().join(format!("{stem}.events.ndjson"))).unwrap();
        let record: ActiveJournalRecord =
            crate::journal::open(&journal_key, "session-1:active", 0, journal.trim().as_bytes()).unwrap();
        assert_eq!(record.prompt_tokens, 100);
        assert_eq!(record.completion_tokens, 0);
        assert_eq!(record.event["class_name"], "agent.compression");
    }

    /// A session marked `capture_failed` (typically because a prior envelope's
    /// journal append failed) must not have subsequent queued envelopes advance
    /// `next_seq` and land in the journal — their `event.metadata.sequence`
    /// would exceed the entry's byte position, which recovery rejects with
    /// "signed event sequence does not match active journal index". Regression
    /// against the process_job pattern that treated capture_failed as a
    /// post-processing check only.
    #[tokio::test]
    async fn capture_failed_session_does_not_write_further_journal_entries() {
        let directory = tempfile::tempdir().unwrap();
        let journal_key = [23; 32];
        let worker = spawn_worker_with_spool_authenticated(
            4,
            Arc::new(RecordingBus::default()),
            Arc::new(HashEmbedder::default()),
            Arc::new(NoopVectorSink),
            Some(directory.path().to_path_buf()),
            journal_key,
            Arc::new(Registry::new()),
        );
        let session = session(Workflow::Signed);
        worker.submit_and_wait(job(Arc::clone(&session))).await.unwrap();
        let digest = av_core::digest::sha256_hex(session.id.as_bytes());
        let stem = digest.get(..32).unwrap();
        let journal_path = directory.path().join(format!("{stem}.events.ndjson"));
        let bytes_after_first = std::fs::read(&journal_path).unwrap();
        assert!(
            !bytes_after_first.is_empty(),
            "first envelope must journal one line"
        );
        assert_eq!(
            bytes_after_first.iter().filter(|byte| **byte == b'\n').count(),
            1,
            "first envelope must produce exactly one journal line",
        );
        session.mark_capture_failed();
        // The second envelope must silently short-circuit: no journal line, no
        // chain append, no next_seq increment for the poisoned session.
        let seq_before = session.next_seq();
        worker.submit_and_wait(job(Arc::clone(&session))).await.unwrap();
        let seq_after = session.next_seq();
        assert_eq!(
            seq_after,
            seq_before + 1,
            "process_job for a capture_failed session must not advance next_seq",
        );
        assert_eq!(
            std::fs::read(&journal_path).unwrap(),
            bytes_after_first,
            "process_job for a capture_failed session must not append to the journal",
        );
        assert_eq!(
            session.chain.lock().count(),
            1,
            "process_job for a capture_failed session must not extend the chain",
        );
    }

    #[tokio::test]
    async fn signed_job_journal_recovers_replays_and_issues_one_receipt() {
        let directory = tempfile::tempdir().unwrap();
        let bridge = Arc::new(RecordingBus::default());
        let metrics = Arc::new(Registry::new());
        let signer = Arc::new(av_receipts::Ed25519Signer::from_seed(&[14; 32]));
        let journal_key = crate::journal::key_from_signer(signer.as_ref());
        let worker = spawn_worker_with_spool_authenticated(
            4,
            bridge.clone(),
            Arc::new(HashEmbedder::default()),
            Arc::new(NoopVectorSink),
            Some(directory.path().to_path_buf()),
            journal_key,
            Arc::clone(&metrics),
        );
        let active = session(Workflow::Signed);
        worker.submit_and_wait(job(Arc::clone(&active))).await.unwrap();
        let digest = av_core::digest::sha256_hex(active.id.as_bytes());
        let stem = digest.get(..32).unwrap();
        let ack_path = directory.path().join(format!("{stem}.acks.ndjson"));
        std::fs::remove_file(&ack_path).unwrap();

        let registry = crate::session::SessionRegistry::new();
        let finalizer = crate::reconciler::Finalizer::with_bridge(
            signer,
            directory.path().to_path_buf(),
            metrics,
            bridge.clone(),
        );
        assert_eq!(
            finalizer
                .recover_spooled_sessions(&registry, &Default::default())
                .await
                .unwrap(),
            1
        );
        let recovered = registry.get(&active.id).unwrap();
        let receipt = recovered.receipt.lock().clone().unwrap();
        receipt.verify_embedded().unwrap();
        assert!(matches!(
            receipt.body.subject,
            av_receipts::ReceiptSubject::EventChain { event_count: 1, .. }
        ));
        assert_eq!(receipt.body.cost.prompt_tokens, 100);
        let events = bridge.events.lock();
        assert_eq!(events.len(), 3, "acknowledged active event must not be replayed");
        assert_eq!(events[0].2["metadata"]["sequence"], 0);
        assert_eq!(events[1].2["metadata"]["sequence"], 1);
        assert_eq!(events[2].2["metadata"]["sequence"], 2);
        assert!(!directory.path().join(format!("{stem}.events.ndjson")).exists());
    }

    #[tokio::test]
    async fn recovery_quarantines_only_the_incomplete_signed_session() {
        let directory = tempfile::tempdir().unwrap();
        let bridge = Arc::new(RecordingBus::default());
        let metrics = Arc::new(Registry::new());
        let signer = Arc::new(av_receipts::Ed25519Signer::from_seed(&[27; 32]));
        let journal_key = crate::journal::key_from_signer(signer.as_ref());
        let worker = spawn_worker_with_spool_authenticated(
            8,
            bridge.clone(),
            Arc::new(HashEmbedder::default()),
            Arc::new(NoopVectorSink),
            Some(directory.path().to_path_buf()),
            journal_key,
            Arc::clone(&metrics),
        );
        let incomplete = Arc::new(Session::new(
            "incomplete-signed".to_owned(),
            Workflow::Signed,
            session(Workflow::Signed).current_identity(),
            BreakerConfig::default(),
        ));
        let complete = Arc::new(Session::new(
            "complete-signed".to_owned(),
            Workflow::Signed,
            session(Workflow::Signed).current_identity(),
            BreakerConfig::default(),
        ));
        let mut incomplete_request = job(Arc::clone(&incomplete));
        incomplete_request.response_attempt = Some(ResponseAttempt {
            id: "incomplete-attempt".to_owned(),
            terminal: false,
        });
        worker.submit_and_wait(incomplete_request).await.unwrap();
        worker.submit_and_wait(job(Arc::clone(&complete))).await.unwrap();

        let registry = crate::session::SessionRegistry::new();
        let finalizer = crate::reconciler::Finalizer::with_bridge(
            signer,
            directory.path().to_path_buf(),
            metrics,
            bridge,
        );
        assert_eq!(
            finalizer
                .recover_spooled_sessions(&registry, &Default::default())
                .await
                .unwrap(),
            2
        );
        let quarantined = registry.get("incomplete-signed").unwrap();
        assert!(quarantined.capture_failed());
        assert!(quarantined.receipt.lock().is_none());
        assert!(registry.get("complete-signed").unwrap().receipt.lock().is_some());
    }

    /// Unsigned twin of the test above. The pending-response quarantine
    /// branch in `consolidate_step_journals` used to build a fresh
    /// `Session` and `try_insert_recovered` it — which always collided
    /// with the recovery placeholder claimed at the top of the candidate
    /// body, so the insert failed, the guard release evicted the
    /// placeholder, and the session never converged: no registry entry,
    /// no quarantine, journal left on disk, one silent skip per
    /// reconciler tick forever. The branch now converts the claimed
    /// placeholder in place.
    #[tokio::test]
    async fn recovery_quarantines_the_incomplete_unsigned_session_in_place() {
        let directory = tempfile::tempdir().unwrap();
        let bridge = Arc::new(RecordingBus::default());
        let metrics = Arc::new(Registry::new());
        let signer = Arc::new(av_receipts::Ed25519Signer::from_seed(&[29; 32]));
        let journal_key = crate::journal::key_from_signer(signer.as_ref());
        let worker = spawn_worker_with_spool_authenticated(
            4,
            bridge.clone(),
            Arc::new(HashEmbedder::default()),
            Arc::new(NoopVectorSink),
            Some(directory.path().to_path_buf()),
            journal_key,
            Arc::clone(&metrics),
        );
        let active = session(Workflow::Unsigned);
        let mut incomplete_request = job(Arc::clone(&active));
        incomplete_request.response_attempt = Some(ResponseAttempt {
            id: "incomplete-attempt".to_owned(),
            terminal: false,
        });
        worker.submit_and_wait(incomplete_request).await.unwrap();

        let registry = crate::session::SessionRegistry::new();
        let finalizer = crate::reconciler::Finalizer::with_bridge(
            signer,
            directory.path().to_path_buf(),
            metrics,
            bridge,
        );
        finalizer
            .recover_spooled_sessions(&registry, &Default::default())
            .await
            .unwrap();
        let quarantined = registry
            .get(&active.id)
            .expect("quarantined unsigned session must stay registered");
        assert!(quarantined.capture_failed());
        assert!(
            quarantined.is_closed() && quarantined.artifact_committed_flag(),
            "quarantine must be sealed so the idle sweeper skips it"
        );
        assert_eq!(
            quarantined.totals.prompt_tokens.load(Ordering::Acquire),
            100,
            "folded journal totals must land on the quarantined session"
        );
        // A second recovery pass is a no-op: the registered quarantine
        // short-circuits the candidate, with no placeholder churn.
        finalizer
            .recover_spooled_sessions(&registry, &Default::default())
            .await
            .unwrap();
        let still = registry
            .get(&active.id)
            .expect("second pass must not evict the quarantined session");
        assert!(still.capture_failed());
    }

    #[tokio::test]
    async fn tampered_signed_journal_is_never_turned_into_a_receipt() {
        let directory = tempfile::tempdir().unwrap();
        let signer = Arc::new(av_receipts::Ed25519Signer::from_seed(&[18; 32]));
        let journal_key = crate::journal::key_from_signer(signer.as_ref());
        let worker = spawn_worker_with_spool_authenticated(
            4,
            Arc::new(RecordingBus::default()),
            Arc::new(HashEmbedder::default()),
            Arc::new(NoopVectorSink),
            Some(directory.path().to_path_buf()),
            journal_key,
            Arc::new(Registry::new()),
        );
        let active = session(Workflow::Signed);
        worker.submit_and_wait(job(Arc::clone(&active))).await.unwrap();
        let digest = av_core::digest::sha256_hex(active.id.as_bytes());
        let stem = digest.get(..32).unwrap();
        let journal_path = directory.path().join(format!("{stem}.events.ndjson"));
        let mut envelope: Value =
            serde_json::from_str(std::fs::read_to_string(&journal_path).unwrap().trim()).unwrap();
        envelope["payload"]["prompt_tokens"] = serde_json::json!(999_999);
        std::fs::write(
            &journal_path,
            format!("{}\n", serde_json::to_string(&envelope).unwrap()),
        )
        .unwrap();
        let registry = crate::session::SessionRegistry::new();
        let finalizer = crate::reconciler::Finalizer::new(
            signer,
            directory.path().to_path_buf(),
            Arc::new(Registry::new()),
        );
        // per-session errors during signed recovery no
        // longer propagate to the outer `recover_spooled_sessions`
        // Err (which used to head-of-line-block every other session
        // for the reconciler tick). They now warn+continue. The
        // security invariant this test locks in is unchanged: the
        // tampered journal MUST NOT be turned into a receipt AND
        // the corrupted session MUST NOT be installed into the
        // registry (both were previously ensured by the outer Err
        // short-circuit). Now they're ensured by the async block
        // returning Err BEFORE `try_insert_recovered` runs.
        let outcome = finalizer
            .recover_spooled_sessions(&registry, &Default::default())
            .await;
        assert!(
            outcome.is_ok(),
            "per-session HMAC failures warn+continue instead of propagating, got {outcome:?}"
        );
        // The corrupted session must NOT be installed into the
        // registry — the security property this test was written to
        // enforce.
        assert!(registry.get(&active.id).is_none());
    }

    #[tokio::test]
    async fn signed_restart_reuses_receipt_persisted_before_journal_cleanup() {
        let directory = tempfile::tempdir().unwrap();
        let signer = Arc::new(av_receipts::Ed25519Signer::from_seed(&[15; 32]));
        let journal_key = crate::journal::key_from_signer(signer.as_ref());
        let worker = spawn_worker_with_spool_authenticated(
            4,
            Arc::new(RecordingBus::default()),
            Arc::new(HashEmbedder::default()),
            Arc::new(NoopVectorSink),
            Some(directory.path().to_path_buf()),
            journal_key,
            Arc::new(Registry::new()),
        );
        let active = session(Workflow::Signed);
        worker.submit_and_wait(job(Arc::clone(&active))).await.unwrap();
        let digest = av_core::digest::sha256_hex(active.id.as_bytes());
        let stem = digest.get(..32).unwrap();
        let metadata_path = directory.path().join(format!("{stem}.session.json"));
        let journal_path = directory.path().join(format!("{stem}.events.ndjson"));
        let metadata = std::fs::read(&metadata_path).unwrap();
        let journal = std::fs::read(&journal_path).unwrap();
        let ack_path = directory.path().join(format!("{stem}.acks.ndjson"));
        let ack = std::fs::read(&ack_path).unwrap();
        let first_finalizer = crate::reconciler::Finalizer::new(
            signer.clone(),
            directory.path().to_path_buf(),
            Arc::new(Registry::new()),
        );
        let crate::reconciler::FinalizeOutcome::Receipt { receipt: first } = first_finalizer
            .close_session(active, av_events::StopReason::SessionClosed)
            .await
            .unwrap()
        else {
            panic!("expected signed receipt")
        };

        std::fs::write(&metadata_path, metadata).unwrap();
        std::fs::write(&journal_path, journal).unwrap();
        std::fs::write(&ack_path, ack).unwrap();
        let registry = crate::session::SessionRegistry::new();
        let after_restart = crate::reconciler::Finalizer::new(
            signer,
            directory.path().to_path_buf(),
            Arc::new(Registry::new()),
        );
        assert_eq!(
            after_restart
                .recover_spooled_sessions(&registry, &Default::default())
                .await
                .unwrap(),
            1
        );
        let recovered = registry.get("session-1").unwrap();
        assert_eq!(
            recovered.receipt.lock().as_ref().unwrap().body.receipt_id,
            first.body.receipt_id
        );
    }

    #[tokio::test]
    async fn unsigned_job_preserves_required_atif_metrics() {
        // RAM-cliff guard: the step now lives ONLY in the
        // events journal; RAM keeps a counter. Use a spooled worker
        // and assert the journaled step carries the metrics.
        let bridge = Arc::new(RecordingBus::default());
        let directory = tempfile::tempdir().unwrap();
        let journal_key = [4u8; 32];
        let worker = spawn_worker_with_spool_authenticated(
            4,
            bridge,
            Arc::new(HashEmbedder::default()),
            Arc::new(NoopVectorSink),
            Some(directory.path().to_path_buf()),
            journal_key,
            Arc::new(Registry::new()),
        );
        let session = session(Workflow::Unsigned);
        worker.submit_and_wait(job(Arc::clone(&session))).await.unwrap();

        assert_eq!(session.atif_steps_count(), 1);
        assert!(
            session.atif.lock().is_empty(),
            "steps must not be retained in RAM (RAM-cliff guard)"
        );
        let digest = av_core::digest::sha256_hex(session.id.as_bytes());
        let stem = digest.get(..32).unwrap();
        let journal =
            std::fs::read_to_string(directory.path().join(format!("{stem}.events.ndjson"))).unwrap();
        let line = journal.lines().next().unwrap();
        let record: ActiveJournalRecord = crate::journal::open(
            &journal_key,
            &format!("{}:active", session.id),
            0,
            line.as_bytes(),
        )
        .unwrap();
        let step = record.atif_step.unwrap();
        assert_eq!(step.metrics.as_ref().unwrap().cached_tokens, Some(40));
        assert_eq!(session.totals.cached_tokens.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn unsigned_job_journal_survives_restart_and_promotes() {
        let directory = tempfile::tempdir().unwrap();
        let bridge = Arc::new(RecordingBus::default());
        let metrics = Arc::new(Registry::new());
        let signer = Arc::new(av_receipts::Ed25519Signer::from_seed(&[13; 32]));
        let journal_key = crate::journal::key_from_signer(signer.as_ref());
        let worker = spawn_worker_with_spool_authenticated(
            4,
            bridge.clone(),
            Arc::new(HashEmbedder::default()),
            Arc::new(NoopVectorSink),
            Some(directory.path().to_path_buf()),
            journal_key,
            Arc::clone(&metrics),
        );
        let active = session(Workflow::Unsigned);
        worker.submit_and_wait(job(Arc::clone(&active))).await.unwrap();
        let mut tool = job(Arc::clone(&active));
        tool.class = EventClass::ToolCall;
        tool.status = StatusId::Failure;
        tool.stop_reason = Some(StopReason::PolicyBlocked);
        tool.metrics = EventMetrics::default();
        tool.cost_usd_micros = 0;
        tool.atif.as_mut().unwrap().llm_call_count = Some(0);
        worker.submit_and_wait(tool).await.unwrap();
        assert_eq!(bridge.events.lock().len(), 2);

        let registry = crate::session::SessionRegistry::new();
        let finalizer = crate::reconciler::Finalizer::with_bridge(
            signer,
            directory.path().to_path_buf(),
            metrics,
            bridge.clone(),
        );
        assert_eq!(
            finalizer
                .recover_spooled_sessions(&registry, &Default::default())
                .await
                .unwrap(),
            1
        );
        let recovered = registry.get(&active.id).unwrap();
        assert!(recovered.atif_path.lock().as_ref().unwrap().exists());
        assert_eq!(
            bridge.events.lock().len(),
            2,
            "acknowledged unsigned events must not replay"
        );
        assert_eq!(recovered.current_identity().ttl_remaining_s, Some(600));
        let receipt = finalizer.promote(recovered).await.unwrap();
        receipt.verify_embedded().unwrap();
        assert_eq!(receipt.body.cost.prompt_tokens, 100);
        assert_eq!(receipt.body.tool_calls.total, 1);
        assert_eq!(receipt.body.tool_calls.blocked, 1);
        assert_eq!(receipt.body.stop_reason_id, StopReason::PolicyBlocked.id());
        assert!(matches!(
            receipt.body.subject,
            av_receipts::ReceiptSubject::AtifTrajectory {
                step_count: 2,
                retroactive: true,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn full_queue_is_counted_without_blocking() {
        let metrics = Arc::new(Registry::new());
        let (sender, _receiver) = mpsc::channel(1);
        let worker = WorkerHandle {
            senders: Arc::new(vec![sender]),
            metrics: Arc::clone(&metrics),
            pending: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            drained: Arc::new(tokio::sync::Notify::new()),
            capacity: Arc::new(tokio::sync::Semaphore::new(1)),
            response_capacity: Arc::new(tokio::sync::Semaphore::new(1)),
        };
        worker.try_submit(job(session(Workflow::Signed))).unwrap();
        assert_eq!(
            worker.try_submit(job(session(Workflow::Signed))),
            Err(SubmitError::Full)
        );
        assert!(metrics
            .render()
            .contains("av_events_dropped_total{stage=\"worker_queue\"} 1"));
    }

    /// The fused permit split (worker_queue vs response_slot) exists
    /// so operators can distinguish which class of admission ran out.
    /// Assert the counters are actually distinct at the metrics
    /// registry level under two adversarial saturations.
    #[tokio::test]
    async fn worker_queue_and_response_slot_counters_are_distinct() {
        let metrics = Arc::new(Registry::new());
        let (sender, _receiver) = mpsc::channel(1);
        let worker = WorkerHandle {
            senders: Arc::new(vec![sender]),
            metrics: Arc::clone(&metrics),
            pending: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            drained: Arc::new(tokio::sync::Notify::new()),
            capacity: Arc::new(tokio::sync::Semaphore::new(1)),
            response_capacity: Arc::new(tokio::sync::Semaphore::new(1)),
        };
        // First pair succeeds — worker and response semaphores each go
        // to 0.
        let first = worker.try_reserve_pair("s").expect("first pair");
        // Second pair fails at the worker stage (first failure). Only
        // the worker_queue counter should be bumped.
        assert_eq!(worker.try_reserve_pair("s").err(), Some(SubmitError::Full));
        let rendered = metrics.render();
        assert!(
            rendered.contains("av_events_dropped_total{stage=\"worker_queue\"} 1"),
            "expected worker_queue counter increment, got:\n{rendered}"
        );
        assert!(
            !rendered.contains("av_events_dropped_total{stage=\"response_slot\"}"),
            "response_slot must not have been touched when worker_queue exhausts first, got:\n{rendered}"
        );
        // Free the worker slot but keep the response permit held. A
        // fresh pair acquire should succeed on the worker side then
        // fail at the response stage, bumping response_slot.
        drop(first.worker);
        let _still_holding_response = first.response;
        assert_eq!(worker.try_reserve_pair("s").err(), Some(SubmitError::Full));
        let rendered = metrics.render();
        assert!(
            rendered.contains("av_events_dropped_total{stage=\"response_slot\"} 1"),
            "expected response_slot counter increment, got:\n{rendered}"
        );
        assert!(
            rendered.contains("av_events_dropped_total{stage=\"worker_queue\"} 1"),
            "worker_queue must remain at 1 (only response stage exhausted this time), got:\n{rendered}"
        );
    }

    /// The pair reservation exists so an ADMITTED stream's response-
    /// capture job can never be starved by later admissions. A prior
    /// revision of `ResponsePermit::submit` dropped the reserved
    /// response slot and drew a fresh permit from the WORKER
    /// semaphore — so a worker backlog at stream-completion time
    /// failed the capture (latching the session capture-failed and
    /// destroying an intact response) and charged the drop to
    /// `stage="response_slot"` even though worker capacity was the
    /// exhausted budget. Lock the guarantee: with worker capacity
    /// fully exhausted, the response submit still succeeds on its
    /// admission-time reservation, and no drop counter fires.
    #[tokio::test]
    async fn response_permit_submit_succeeds_on_worker_capacity_exhaustion() {
        let bridge = Arc::new(RecordingBus::default());
        let metrics = Arc::new(Registry::new());
        let worker = spawn_worker(
            2,
            bridge.clone(),
            Arc::new(HashEmbedder::default()),
            Arc::clone(&metrics),
        );
        // Issue a pair permit (worker=1 held; response=1 held for the
        // rest of the test).
        let permits = worker
            .try_reserve_pair("mid-stream-response")
            .expect("initial pair");
        // Drop the worker permit so that half is free; the response
        // half stays held until we submit below.
        drop(permits.worker);
        // Now consume both remaining worker slots directly so any
        // fresh worker-side acquire would fail. The response semaphore
        // is untouched — permits.response still holds its slot.
        let hog_a = worker.try_reserve("hog-a").expect("hog-a");
        let hog_b = worker.try_reserve("hog-b").expect("hog-b");
        // Submit the response-capture job. It must ride the response
        // reservation taken at admission — worker-capacity exhaustion
        // is irrelevant to an already-admitted stream's capture.
        let job = job(session(Workflow::Signed));
        permits
            .response
            .submit(&worker, job)
            .expect("an admitted stream's capture must not be starved by worker admissions");
        let rendered = metrics.render();
        assert!(
            !rendered.contains("av_events_dropped_total{stage=\"response_slot\"} 1"),
            "no response_slot drop: the reserved slot was used, not re-acquired; got:\n{rendered}"
        );
        assert!(
            !rendered.contains("av_events_dropped_total{stage=\"worker_queue\"} 1"),
            "no worker_queue drop either; got:\n{rendered}"
        );
        drop(hog_a);
        drop(hog_b);
        worker.wait_idle().await;
    }

    #[tokio::test]
    async fn one_shard_can_borrow_all_global_capacity() {
        const CAPACITY: usize = 16;
        let worker = spawn_worker(
            CAPACITY,
            Arc::new(RecordingBus::default()),
            Arc::new(HashEmbedder::default()),
            Arc::new(Registry::new()),
        );
        let partitions = u32::try_from(CAPACITY).unwrap();
        let target = av_bridge::bus::partition_for("target", partitions);
        let session_ids: Vec<String> = (0..10_000)
            .map(|index| format!("same-shard-{index}"))
            .filter(|id| av_bridge::bus::partition_for(id, partitions) == target)
            .take(CAPACITY)
            .collect();
        assert_eq!(session_ids.len(), CAPACITY);
        let permits: Vec<_> = session_ids
            .iter()
            .map(|id| worker.try_reserve(id).unwrap())
            .collect();
        assert!(matches!(
            worker.try_reserve("globally-full"),
            Err(SubmitError::Full)
        ));
        drop(permits);
        assert!(worker.try_reserve("capacity-released").is_ok());
    }

    #[tokio::test]
    async fn panic_is_counted_and_supervisor_processes_next_job() {
        let bridge = Arc::new(RecordingBus::default());
        let metrics = Arc::new(Registry::new());
        let worker = spawn_worker_with_sink(
            4,
            bridge.clone(),
            Arc::new(HashEmbedder::default()),
            Arc::new(PanicOnceSink {
                panicked: AtomicBool::new(false),
            }),
            Arc::clone(&metrics),
        );
        let failed_session = session(Workflow::Signed);
        assert!(worker
            .submit_and_wait(job(Arc::clone(&failed_session)))
            .await
            .is_err());
        assert!(failed_session.capture_failed());
        worker
            .submit_and_wait(job(session(Workflow::Signed)))
            .await
            .unwrap();
        assert_eq!(bridge.events.lock().len(), 1);
        assert!(metrics.render().contains("av_worker_panics_total 1"));
    }

    // Regression: subscribe (enable) and await must operate on the SAME pinned
    // Notified, or notify_waiters() firing between the two loses the wakeup.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn wait_idle_survives_notify_races_under_contention() {
        let bridge = Arc::new(RecordingBus::default());
        let worker = spawn_worker(
            64,
            bridge.clone(),
            Arc::new(HashEmbedder::default()),
            Arc::new(Registry::new()),
        );
        for _ in 0..64 {
            for _ in 0..4 {
                worker.try_submit(job(session(Workflow::Signed))).unwrap();
            }
            tokio::time::timeout(std::time::Duration::from_secs(5), worker.wait_idle())
                .await
                .expect("wait_idle deadlocked: notify_waiters was lost during subscribe/check race");
        }
    }

    // Deterministic proof of the enable/await invariant: producer's
    // notify_waiters() fires between the consumer's check and its await.
    // If the consumer re-subscribes with a fresh notified() after check, the
    // notify_waiters() is lost and the consumer deadlocks. The correct pattern
    // keeps the same pinned Notified alive across the check.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn notified_enable_check_await_pattern_is_race_free() {
        use std::sync::atomic::AtomicUsize;
        use tokio::sync::Notify;

        for _ in 0..64 {
            let notify = Arc::new(Notify::new());
            let pending = Arc::new(AtomicUsize::new(1));
            let (check_done_tx, check_done_rx) = tokio::sync::oneshot::channel::<()>();
            let (notify_done_tx, notify_done_rx) = tokio::sync::oneshot::channel::<()>();

            let n_c = Arc::clone(&notify);
            let p_c = Arc::clone(&pending);
            let consumer = tokio::spawn(async move {
                let notified = n_c.notified();
                let mut notified = std::pin::pin!(notified);
                notified.as_mut().enable();
                assert_ne!(p_c.load(AtomicOrdering::Acquire), 0, "producer ran early");
                check_done_tx.send(()).unwrap();
                notify_done_rx.await.unwrap();
                notified.await;
            });

            let n_p = Arc::clone(&notify);
            let p_p = Arc::clone(&pending);
            let producer = tokio::spawn(async move {
                check_done_rx.await.unwrap();
                p_p.store(0, AtomicOrdering::Release);
                n_p.notify_waiters();
                notify_done_tx.send(()).unwrap();
            });

            tokio::time::timeout(std::time::Duration::from_secs(2), async {
                producer.await.unwrap();
                consumer.await.unwrap();
            })
            .await
            .expect("consumer deadlocked: enable/await pattern violated");
        }
    }

    // ------------------------------------------------------------------
    // Congestion & bottleneck stress tests.
    // ------------------------------------------------------------------

    /// `try_submit` must never block the caller when the worker is saturated —
    /// it must return `SubmitError::Full` immediately. A regression that made
    /// the hot path await capacity would silently convert backpressure into
    /// head-of-line blocking on the request pipeline.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn try_submit_returns_full_within_the_first_millisecond_when_saturated() {
        const CAPACITY: usize = 4;
        let worker = spawn_worker(
            CAPACITY,
            Arc::new(RecordingBus::default()),
            Arc::new(HashEmbedder::default()),
            Arc::new(Registry::new()),
        );
        // Hold every permit so try_submit sees a saturated semaphore.
        let session = session(Workflow::Signed);
        let _held: Vec<_> = (0..CAPACITY)
            .map(|i| worker.try_reserve(&format!("hold-{i}")).unwrap())
            .collect();
        let started = std::time::Instant::now();
        let result = worker.try_submit(job(Arc::clone(&session)));
        let elapsed = started.elapsed();
        assert!(matches!(result, Err(SubmitError::Full)));
        assert!(
            elapsed < std::time::Duration::from_millis(1),
            "try_submit blocked for {elapsed:?} when saturated \
             (backpressure should be synchronous)",
        );
    }

    /// Metrics must record every drop; operators cannot see congestion
    /// otherwise. This locks the counter name and its increment on both
    /// the semaphore-exhaustion path (returning Full from `try_capacity`)
    /// and the closed-channel path.
    #[tokio::test]
    async fn every_dropped_job_increments_the_drop_metric() {
        const CAPACITY: usize = 2;
        let bridge = Arc::new(RecordingBus::default());
        let metrics = Arc::new(Registry::new());
        let worker = spawn_worker(
            CAPACITY,
            bridge,
            Arc::new(HashEmbedder::default()),
            Arc::clone(&metrics),
        );
        let _hold: Vec<_> = (0..CAPACITY)
            .map(|i| worker.try_reserve(&format!("s-{i}")).unwrap())
            .collect();
        for _ in 0..17 {
            assert!(matches!(worker.try_reserve("x"), Err(SubmitError::Full)));
        }
        let rendered = metrics.render();
        assert!(
            rendered.contains("av_events_dropped_total{stage=\"worker_queue\"} 17"),
            "expected 17 drops in metrics, got:\n{rendered}",
        );
    }

    /// Capacity released by dropping a permit is immediately reusable.
    /// If the semaphore forgot to release on drop, a bursty workload would
    /// hit a false Full condition and reject every subsequent request
    /// until the worker was recycled.
    #[tokio::test]
    async fn capacity_is_reusable_after_permit_drop() {
        const CAPACITY: usize = 8;
        let worker = spawn_worker(
            CAPACITY,
            Arc::new(RecordingBus::default()),
            Arc::new(HashEmbedder::default()),
            Arc::new(Registry::new()),
        );
        for cycle in 0..1_000 {
            let permits: Vec<_> = (0..CAPACITY)
                .map(|i| worker.try_reserve(&format!("cycle-{cycle}-{i}")).unwrap())
                .collect();
            assert!(matches!(worker.try_reserve("overflow"), Err(SubmitError::Full)));
            drop(permits);
            // Full capacity must be immediately re-acquirable.
            let recycled: Vec<_> = (0..CAPACITY)
                .map(|i| worker.try_reserve(&format!("recycle-{cycle}-{i}")).unwrap())
                .collect();
            drop(recycled);
        }
    }

    /// Shard partitioning is deterministic and roughly balanced. If one
    /// session hashed to the same shard as many others, that shard's queue
    /// would fill up first and every other shard would run under-utilized
    /// (see `one_shard_can_borrow_all_global_capacity` for the extreme).
    /// This test asserts the *balance* invariant across a wide id space.
    #[test]
    fn partition_for_distributes_uniformly_across_shards() {
        const SHARDS: u32 = 16;
        const SAMPLES: u32 = 100_000;
        let mut hits = [0u32; SHARDS as usize];
        for i in 0..SAMPLES {
            let id = format!("session-{i}");
            let s = av_bridge::bus::partition_for(&id, SHARDS) as usize;
            hits[s] += 1;
        }
        let expected = SAMPLES / SHARDS;
        for (shard, count) in hits.iter().enumerate() {
            let lower = expected * 9 / 10;
            let upper = expected * 11 / 10;
            assert!(
                (lower..=upper).contains(count),
                "shard {shard} got {count} hits, expected {expected} (10% band)",
            );
        }
    }

    /// All 16 partitions must have a live shard channel, even when the
    /// caller passes a small `capacity`. An earlier version sized
    /// `shard_count = capacity.min(16)`, so with `capacity < 16` any
    /// session id hashing to a partition without a shard silently
    /// returned `SubmitError::Closed` — 15/16 of the id space was
    /// unroutable at capacity = 1.
    #[tokio::test]
    async fn every_shard_is_routable_at_capacity_one() {
        let worker = spawn_worker(
            1,
            Arc::new(RecordingBus::default()),
            Arc::new(HashEmbedder::default()),
            Arc::new(Registry::new()),
        );
        // Probe every one of the 16 possible partition indices with a
        // synthetic id crafted to hash there.
        for target in 0..16u32 {
            let mut candidate = None;
            for i in 0..10_000u64 {
                let id = format!("probe-{target}-{i}");
                if av_bridge::bus::partition_for(&id, 16) == target {
                    candidate = Some(id);
                    break;
                }
            }
            let id = candidate.unwrap_or_else(|| panic!("no id found for shard {target}"));
            let permit = worker
                .try_reserve(&id)
                .unwrap_or_else(|error| panic!("shard {target} not routable: {error:?}"));
            drop(permit);
        }
    }

    /// Design invariant: `submit_and_wait` canceled at any point must not
    /// leave the `pending` counter incremented, because a leaked pending
    /// count would deadlock `wait_idle` on shutdown. The coupled
    /// semaphore + shard-channel capacity guarantees `send().await` never
    /// blocks while a permit is held, so cancellation before the envelope
    /// enters the channel can only happen while the counter has not yet
    /// been incremented. This test locks that invariant across many
    /// cancellation timings.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelling_submit_and_wait_never_leaks_pending() {
        const CAPACITY: usize = 4;
        let bridge = Arc::new(RecordingBus::default());
        let worker = Arc::new(spawn_worker(
            CAPACITY,
            bridge.clone(),
            Arc::new(HashEmbedder::default()),
            Arc::new(Registry::new()),
        ));
        // Saturate the semaphore so submit_and_wait always blocks on
        // acquire_owned; abort at randomized delays to hit every polling
        // window of the acquire future.
        let held: Vec<_> = (0..CAPACITY)
            .map(|i| worker.try_reserve(&format!("hold-{i}")).unwrap())
            .collect();
        for delay_us in [0u64, 50, 200, 800, 3_200] {
            let hostile_session = session(Workflow::Signed);
            let worker_for_task = Arc::clone(&worker);
            let task = tokio::spawn(async move {
                let _ = worker_for_task
                    .submit_and_wait(job(Arc::clone(&hostile_session)))
                    .await;
            });
            if delay_us > 0 {
                tokio::time::sleep(std::time::Duration::from_micros(delay_us)).await;
            }
            task.abort();
            let _ = task.await;
        }
        drop(held);
        tokio::time::timeout(std::time::Duration::from_secs(2), worker.wait_idle())
            .await
            .expect("wait_idle deadlocked — a canceled submit_and_wait leaked pending");
    }

    /// Group commit: a backlog that accumulates behind
    /// a gated first job drains as one same-session batch (Phase A
    /// appends + ONE fdatasync + per-job tails). Every job must
    /// complete successfully, the journal must carry every record in
    /// submission order at its sealed index, and publishes must
    /// follow submission order.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn session_backlog_group_commits_in_order() {
        let directory = tempfile::tempdir().unwrap();
        let journal_key = [6u8; 32];
        let bus = Arc::new(GatedBus::new("batched-session"));
        let worker = spawn_worker_with_spool_authenticated(
            64,
            Arc::clone(&bus) as Arc<dyn EventBus>,
            Arc::new(HashEmbedder::default()),
            Arc::new(NoopVectorSink),
            Some(directory.path().to_path_buf()),
            journal_key,
            Arc::new(Registry::new()),
        );
        let session = session_with_id("batched-session");
        // First job blocks in publish (Phase B), so the next ten
        // envelopes pile up behind it and dispatch as one batch.
        // Sequential try_submit pins arrival order (spawned submitters
        // would race the channel); the gate holds job 0 in Phase B so
        // jobs 1..10 accumulate and dispatch as one batch.
        for n in 0..11 {
            let mut submitted = job(Arc::clone(&session));
            submitted.payload = serde_json::json!({"kind": "response", "burst": n});
            worker.try_submit(submitted).unwrap();
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        bus.release.store(true, std::sync::atomic::Ordering::Release);
        session.wait_for_worker_jobs().await;
        assert!(!session.capture_failed(), "a batched burst must not fail capture");

        // Journal: 11 records, each MAC-sealed at its position.
        let digest = av_core::digest::sha256_hex(session.id.as_bytes());
        let stem = digest.get(..32).unwrap();
        let journal =
            std::fs::read_to_string(directory.path().join(format!("{stem}.events.ndjson"))).unwrap();
        let lines: Vec<&str> = journal.lines().collect();
        assert_eq!(lines.len(), 11, "every batched record must be journaled");
        for (index, line) in lines.iter().enumerate() {
            let record: ActiveJournalRecord = crate::journal::open(
                &journal_key,
                &format!("{}:active", session.id),
                index as u64,
                line.as_bytes(),
            )
            .unwrap();
            assert_eq!(
                record.event.pointer("/payload/burst").and_then(Value::as_u64),
                Some(index as u64),
                "journal record {index} must carry the {index}th submitted payload"
            );
        }
        // Publishes followed submission order.
        let published = bus.published.lock();
        let bursts: Vec<u64> = published
            .iter()
            .filter_map(|text| {
                serde_json::from_str::<Value>(text)
                    .ok()?
                    .pointer("/payload/burst")
                    .and_then(Value::as_u64)
            })
            .collect();
        assert_eq!(
            bursts,
            (0..11).collect::<Vec<_>>(),
            "publish order must match submission order"
        );
    }

    fn session_with_id(id: &str) -> Arc<Session> {
        Arc::new(Session::new(
            id.to_owned(),
            Workflow::Signed,
            AgentIdentity {
                version: "1".to_owned(),
                charter: "test".into(),
                instance_uid: "instance-1".to_owned(),
                ttl_remaining_s: Some(600),
            },
            BreakerConfig {
                min_tokens: u64::MAX,
                ..BreakerConfig::default()
            },
        ))
    }

    /// Find a session id that shares `reference`'s shard, so the test
    /// provably exercises INTRA-shard scheduling.
    fn colliding_session_id(reference: &str, shard_count: usize) -> String {
        let target = av_bridge::bus::partition_for(reference, u32::try_from(shard_count).unwrap());
        (0..)
            .map(|n| format!("victim-{n}"))
            .find(|candidate| {
                candidate != reference
                    && av_bridge::bus::partition_for(candidate, u32::try_from(shard_count).unwrap()) == target
            })
            .unwrap()
    }

    /// One stalled session must not freeze its shard.
    /// Pre-dispatcher, the victim (same shard) sat behind the stalled
    /// session's envelope forever (31× measured HOL blocking); now it
    /// completes while the stalled session occupies one slot.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn stalled_session_does_not_block_shard_neighbors() {
        let shard_count = std::thread::available_parallelism()
            .map(std::num::NonZero::get)
            .unwrap_or(16)
            .max(16);
        let stalled_id = "stalled-session".to_owned();
        let victim_id = colliding_session_id(&stalled_id, shard_count);
        let bus = Arc::new(GatedBus::new(&stalled_id));
        let worker = spawn_worker(
            64,
            Arc::clone(&bus) as Arc<dyn EventBus>,
            Arc::new(HashEmbedder::default()),
            Arc::new(Registry::new()),
        );
        let stalled = session_with_id(&stalled_id);
        let victim = session_with_id(&victim_id);

        let stalled_wait = {
            let worker = worker.clone();
            let job = job(Arc::clone(&stalled));
            tokio::spawn(async move { worker.submit_and_wait(job).await })
        };
        // The victim must complete while the stalled session is gated.
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            worker.submit_and_wait(job(Arc::clone(&victim))),
        )
        .await
        .expect("victim session must not be head-of-line blocked by a stalled shard neighbor")
        .unwrap();
        assert!(
            !stalled_wait.is_finished(),
            "the stalled session must still be gated (the victim did not just win a race)"
        );
        bus.release.store(true, Ordering::Release);
        stalled_wait.await.unwrap().unwrap();
    }

    /// Per-session ordering survives the dispatcher: two jobs for one
    /// session publish in submission order even though the shard runs
    /// sessions concurrently.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn per_session_ordering_is_preserved() {
        let bus = Arc::new(RecordingBus::default());
        let worker = spawn_worker(
            64,
            Arc::clone(&bus) as Arc<dyn EventBus>,
            Arc::new(HashEmbedder::default()),
            Arc::new(Registry::new()),
        );
        let session = session_with_id("ordered-session");
        for n in 0..8u64 {
            let mut ordered = job(Arc::clone(&session));
            ordered.payload = serde_json::json!({"kind": "response", "step": n});
            worker.submit_and_wait(ordered).await.unwrap();
        }
        let events = bus.events.lock();
        let steps: Vec<u64> = events
            .iter()
            .filter_map(|(_, _, value)| value.pointer("/payload/step").and_then(Value::as_u64))
            .collect();
        assert_eq!(
            steps,
            (0..8).collect::<Vec<_>>(),
            "per-session publish order must match submission order"
        );
    }
}

#[cfg(test)]
mod unified_fold_tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use super::*;

    fn record(
        tool: (u64, u64, u64),
        prompt: u64,
        completion: u64,
        cached: u64,
        cost: u64,
    ) -> ActiveJournalRecord {
        ActiveJournalRecord {
            event: serde_json::json!({"k": "v"}),
            identity: av_events::AgentIdentity {
                version: "1".to_owned(),
                charter: "test".into(),
                instance_uid: "i".to_owned(),
                ttl_remaining_s: None,
            },
            atif_step: None,
            tool_calls: tool.0,
            tool_allowed: tool.1,
            tool_blocked: tool.2,
            prompt_tokens: prompt,
            completion_tokens: completion,
            cached_tokens: cached,
            cost_usd_micros: cost,
            prompt_token_correction: 0,
            stop_reason_id: None,
            response_attempt: None,
        }
    }

    /// Shared-fold proof harness: the live-path atomic
    /// application and the recovery fold MUST produce identical
    /// totals over the same record stream — this is the property the
    /// three hand-rolled folds could silently violate ('a
    /// crash-recovered receipt attests different numbers than a
    /// clean-close receipt for identical traffic — and no test
    /// catches it, because both paths are asserted separately').
    #[test]
    fn unified_fold_matches_live_path() {
        // Representative shapes: a compression record (prompt only),
        // a terminal response (completion/cached/cost), an allowed
        // tool call, a blocked tool call, an unclassified tool call,
        // and a stop record (all zeros).
        let records = [
            record((0, 0, 0), 4_822, 0, 0, 0),
            record((0, 0, 0), 0, 319, 12, 84_340),
            record((1, 1, 0), 0, 0, 0, 0),
            record((1, 0, 1), 0, 0, 0, 0),
            record((1, 0, 0), 0, 0, 0, 0),
            record((0, 0, 0), 0, 0, 0, 0),
        ];

        // Recovery fold.
        let mut folded = RecoveredTotals::default();
        for r in &records {
            r.fold_into(&mut folded).unwrap();
        }
        folded.validate_tool_accounting().unwrap();

        // Live-path fold onto atomics.
        let live = crate::session::Totals::default();
        for r in &records {
            r.apply_to_totals(&live).unwrap();
        }

        use std::sync::atomic::Ordering;
        assert_eq!(folded.tool_calls, live.tool_calls.load(Ordering::Acquire));
        assert_eq!(folded.tool_allowed, live.tool_allowed.load(Ordering::Acquire));
        assert_eq!(folded.tool_blocked, live.tool_blocked.load(Ordering::Acquire));
        assert_eq!(folded.prompt_tokens, live.prompt_tokens.load(Ordering::Acquire));
        assert_eq!(
            folded.completion_tokens,
            live.completion_tokens.load(Ordering::Acquire)
        );
        assert_eq!(folded.cached_tokens, live.cached_tokens.load(Ordering::Acquire));
        assert_eq!(
            folded.cost_usd_micros,
            live.cost_usd_micros.load(Ordering::Acquire)
        );
        assert_eq!(folded.prompt_tokens, 4_822);
        assert_eq!(folded.tool_calls, 3);
    }

    /// Both fold directions must refuse a JCS-bound overflow rather
    /// than wrap or saturate — a receipt attesting a wrapped total is
    /// worse than a refused close.
    #[test]
    fn both_folds_refuse_jcs_overflow() {
        let poisoned = record((0, 0, 0), av_core::error::JCS_SAFE_MAX, 0, 0, 0);
        let mut folded = RecoveredTotals::default();
        poisoned.fold_into(&mut folded).unwrap();
        assert!(
            record((0, 0, 0), 1, 0, 0, 0).fold_into(&mut folded).is_err(),
            "recovery fold must refuse crossing JCS_SAFE_MAX"
        );

        let live = crate::session::Totals::default();
        poisoned.apply_to_totals(&live).unwrap();
        assert!(
            record((0, 0, 0), 1, 0, 0, 0).apply_to_totals(&live).is_err(),
            "live fold must refuse crossing JCS_SAFE_MAX"
        );
    }

    /// A terminal record carrying a provider
    /// reconciliation (`prompt_token_correction`) must adjust the
    /// prompt total identically on the live path and in recovery — a
    /// crash between charge and close must not resurrect the
    /// heuristic over-estimate into the signed receipt.
    #[test]
    fn correction_applies_identically_and_refuses_underflow() {
        // Heuristic charged 30 prompt tokens, provider reported 10.
        let mut charged = record((0, 0, 0), 30, 0, 0, 0);
        let mut terminal = record((0, 0, 0), 0, 5, 0, 100);
        terminal.prompt_token_correction = -20;

        let mut folded = RecoveredTotals::default();
        charged.fold_into(&mut folded).unwrap();
        terminal.fold_into(&mut folded).unwrap();
        assert_eq!(folded.prompt_tokens, 10);

        let live = crate::session::Totals::default();
        charged.apply_to_totals(&live).unwrap();
        terminal.apply_to_totals(&live).unwrap();
        use std::sync::atomic::Ordering;
        assert_eq!(live.prompt_tokens.load(Ordering::Acquire), 10);

        // A correction larger than the accumulated total is a
        // tampered/corrupt journal: both folds must refuse, not wrap.
        charged = record((0, 0, 0), 5, 0, 0, 0);
        terminal.prompt_token_correction = -20;
        let mut folded = RecoveredTotals::default();
        charged.fold_into(&mut folded).unwrap();
        assert!(
            terminal.fold_into(&mut folded).is_err(),
            "recovery fold must refuse correction underflow"
        );
        let live = crate::session::Totals::default();
        charged.apply_to_totals(&live).unwrap();
        assert!(
            terminal.apply_to_totals(&live).is_err(),
            "live fold must refuse correction underflow"
        );
    }
}

#[cfg(test)]
mod ack_journal_tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    /// Acks round-trip through the per-session journal,
    /// tolerate a torn tail line, and the legacy per-event file layout
    /// is still readable (a deployment upgraded mid-session must see
    /// its earlier acks).
    #[tokio::test]
    async fn ack_journal_roundtrips_tolerates_torn_tail_and_reads_legacy() {
        let directory = tempfile::tempdir().unwrap();
        let key = [9u8; 32];
        let ack = PublishAck {
            topic: "t".to_owned(),
            partition: 0,
            offset: 7,
        };
        persist_broker_ack(directory.path(), "s1", "evt-1", &ack, &key)
            .await
            .unwrap();
        persist_broker_ack(directory.path(), "s1", "evt-2", &ack, &key)
            .await
            .unwrap();
        // Torn tail: simulate a crash mid-append.
        let journal = ack_journal_path(directory.path(), "s1");
        let mut bytes = std::fs::read(&journal).unwrap();
        bytes.extend_from_slice(b"{\"torn");
        std::fs::write(&journal, bytes).unwrap();

        let found = read_broker_ack(directory.path(), "s1", "evt-1", &key)
            .await
            .unwrap();
        assert_eq!(found.map(|ack| ack.offset), Some(7));
        assert!(
            read_broker_ack(directory.path(), "s1", "missing", &key)
                .await
                .unwrap()
                .is_none(),
            "an unknown event has no ack (torn tail must not error the scan)"
        );

        // Legacy layout: an older per-event file is still found.
        let legacy = broker_ack_path(directory.path(), "s2", "evt-9");
        std::fs::create_dir_all(legacy.parent().unwrap()).unwrap();
        let record = BrokerAckRecord {
            session_id: "s2".to_owned(),
            event_uid: "evt-9".to_owned(),
            ack: ack.clone(),
        };
        let sealed = crate::journal::seal(&key, "broker-ack", 0, &record).unwrap();
        std::fs::write(&legacy, sealed).unwrap();
        let found = read_broker_ack(directory.path(), "s2", "evt-9", &key)
            .await
            .unwrap();
        assert_eq!(found.map(|ack| ack.offset), Some(7));
    }
}
