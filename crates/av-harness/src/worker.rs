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
    pub(crate) stop_reason_id: Option<u8>,
    pub(crate) response_attempt: Option<ResponseAttempt>,
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
    /// Commit a response-capture job. Consumes the response permit's
    /// capacity slot and races for a shard's mpsc slot; if the shard is
    /// momentarily full, returns a `SubmitError::Full` and bumps
    /// `av_events_dropped_total{stage="response_slot"}` — NOT the
    /// worker_queue counter. That distinction is the whole point of
    /// the split: operators need to see which class of exhaustion is
    /// producing drops.
    pub fn submit(self, worker: &WorkerHandle, job: WorkerJob) -> Result<(), SubmitError> {
        // Release the response-capacity permit before contending for
        // the mpsc slot so a failed submit does not artificially pin
        // the response budget. An explicit drop — a named `_`-prefixed
        // binding would live to end of scope (NLL shortens borrows,
        // not Drop timing). The permit is not
        // used by `try_submit_labeled`, which draws a fresh
        // worker-capacity slot for the actual queue admission.
        drop(self._capacity_permit);
        worker.try_submit_labeled(job, DropStage::ResponseSlot)
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
    // `partition_for(session_id, MAX_SHARDS)`, so if we sized
    // `senders.len() < MAX_SHARDS`, requests whose id hashes to a
    // partition >= senders.len() would silently see
    // `SubmitError::Closed` (via `sender_for` returning `None`).
    // Under `capacity = 1`, 15/16 partitions were unroutable. Always
    // spawn all MAX_SHARDS shards; the global semaphore continues to
    // enforce the caller's admission cap so total in-flight work is
    // still bounded by `capacity`.
    const MAX_SHARDS: usize = 16;
    let capacity = capacity.max(1);
    let shard_count = MAX_SHARDS;
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
    use futures::future::FutureExt as _;
    tokio::spawn(async move {
        loop {
            let Some(envelope) = receiver.recv().await else {
                break;
            };
            // Supervise the per-envelope routing code (Arc::clones,
            // span instrumentation, capacity_permit drop, drained
            // notify, worker_pending accounting). The INNER
            // `tokio::spawn(process_job).await` already catches
            // process_job panics via JoinError → av_worker_panics_total,
            // but a panic in the OUTER routing (allocator failure
            // inside a tracing::warn Display, `worker_pending
            // .fetch_sub` accounting bug) would kill the whole shard
            // driver task, and every future envelope routed to this
            // shard would pile up forever — jamming 1/MAX_SHARDS of
            // the session id space until process restart.
            let bridge_ref = Arc::clone(&bridge);
            let embedder_ref = Arc::clone(&embedder);
            let vector_sink_ref = Arc::clone(&vector_sink);
            let spool_dir_ref = spool_dir.clone();
            let worker_metrics_ref = Arc::clone(&worker_metrics);
            let worker_pending_ref = Arc::clone(&worker_pending);
            let worker_drained_ref = Arc::clone(&worker_drained);
            let outcome = std::panic::AssertUnwindSafe(process_envelope(
                envelope,
                bridge_ref,
                embedder_ref,
                vector_sink_ref,
                spool_dir_ref,
                journal_key,
                worker_metrics_ref,
                worker_pending_ref,
                worker_drained_ref,
            ))
            .catch_unwind()
            .await;
            if let Err(panic) = outcome {
                let msg = panic
                    .downcast_ref::<&'static str>()
                    .copied()
                    .or_else(|| panic.downcast_ref::<String>().map(String::as_str))
                    .unwrap_or("panic payload was not a string");
                worker_metrics
                    .counter(
                        "av_worker_shard_panics_total",
                        "Worker shard driver panicked outside a job; supervised via catch_unwind",
                    )
                    .inc();
                tracing::error!(
                    panic = %msg,
                    "worker shard driver panicked during envelope routing; continuing"
                );
            }
        }
    });
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
    // Round-12 F3: `worker_pending` was previously decremented at the
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
    // Round-33 F2: guard the session-level pending-jobs decrement in
    // the same RAII shape as `PendingGuard` (round-12 F3). The bare
    // `session.worker_job_finished()` after `tokio::spawn(...).await`
    // used to leak the session-level counter on any panic or drop
    // between here and line ~712. A stuck `session.pending_jobs` means
    // `close_session_locked -> wait_for_worker_jobs().await` blocks
    // forever on `jobs_drained.notified()`, holding the session's
    // lifecycle lock and starving every subsequent close / promote /
    // recovery-adopt on that id. Class round-12 F3 closed, one call
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
    // Round-33 F2: `_session_pending_guard`'s Drop calls
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

/// Round-33 F2: RAII pair to [`PendingGuard`] for the session-level
/// pending-jobs counter. `Session::worker_job_finished()` was
/// previously called as a bare method after `tokio::spawn(...).await`,
/// but a panic in the routing-side epilogue (Display-side allocator
/// failure, catch_unwind of the wrapper future, runtime shutdown
/// mid-envelope) between `.await` and that call left
/// `session.pending_jobs` stuck. `close_session_locked` then blocked
/// forever on `wait_for_worker_jobs().await`, holding the session's
/// lifecycle lock — the exact class round-12 F3 closed on the
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
async fn process_job(
    mut job: WorkerJob,
    bridge: Arc<dyn EventBus>,
    embedder: Arc<dyn Embedder>,
    vector_sink: Arc<dyn VectorSink>,
    spool_dir: Option<std::path::PathBuf>,
    journal_key: [u8; 32],
    metrics: Arc<Registry>,
) -> Result<(), String> {
    // A queued envelope for a session that has already been poisoned must not
    // consume a sequence number or write to the journal — otherwise the seq
    // its OcsfEvent carries (from `next_seq`, advanced by the failed prior
    // envelope) would not match the entry's position on disk, breaking
    // recovery's `event.metadata.sequence != index` check.
    if job.session.capture_failed() {
        return Ok(());
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
        let embedding = tokio::task::spawn_blocking(move || embedder.try_embed(&text))
            .await
            .map_err(|error| error.to_string())??;
        let nearest_similarity = vector_sink
            .nearest_similarity(&job.session.id, &embedding)
            .await?;
        let verdict = job.session.loop_state.observe_embedding_with_similarity(
            embedding.clone(),
            step_tokens,
            nearest_similarity,
        );
        vector_sink.record(&job.session.id, &embedding).await?;
        Some(verdict)
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
        stop_reason_id: event.stop_reason_id,
        response_attempt: job.response_attempt.clone(),
    };
    if let Some(directory) = spool_dir.as_deref() {
        append_active_event_journal(directory, &job.session, &job.identity, &record, &journal_key).await?;
    }

    match job.session.workflow {
        Workflow::Signed => job
            .session
            .chain
            .lock()
            .append(&value)
            .map_err(|error| error.to_string())?,
        Workflow::Unsigned => {
            job.session
                .atif
                .lock()
                .push_step(atif_step.ok_or_else(|| "unsigned ATIF step disappeared".to_owned())?)
                .map_err(|error| error.to_string())?;
        }
    }

    let topic = class.topic().to_owned();
    let key = job.identity.instance_uid.clone();
    let publish_topic = topic.clone();
    let publish_key = key.clone();
    let publish_uid = event_uid.clone();
    let ack = tokio::task::spawn_blocking(move || {
        bridge.publish_idempotent(&publish_topic, &publish_key, &value, &publish_uid)
    })
    .await
    .map_err(|error| error.to_string())?
    .map_err(|error| error.to_string())?;
    if let Some(directory) = spool_dir.as_deref() {
        persist_broker_ack(directory, &job.session.id, &event_uid, &ack, &journal_key).await?;
    }
    if is_tool_call {
        checked_atomic_add(&job.session.totals.tool_calls, 1, "tool calls")?;
        match status {
            StatusId::Success => {
                checked_atomic_add(&job.session.totals.tool_allowed, 1, "allowed tools")?;
            }
            StatusId::Failure => {
                checked_atomic_add(&job.session.totals.tool_blocked, 1, "blocked tools")?;
            }
            StatusId::Unknown => {}
            _ => {}
        }
    }
    if submitted_class == EventClass::Compression {
        checked_atomic_add(
            &job.session.totals.prompt_tokens,
            job.metrics.prompt_tokens.unwrap_or(0),
            "prompt tokens",
        )?;
    } else if is_llm_agent_response {
        checked_atomic_add(
            &job.session.totals.completion_tokens,
            job.metrics.completion_tokens.unwrap_or(0),
            "completion tokens",
        )?;
        checked_atomic_add(
            &job.session.totals.cached_tokens,
            job.metrics.cached_tokens.unwrap_or(0),
            "cached tokens",
        )?;
        checked_atomic_add(&job.session.totals.cost_usd_micros, job.cost_usd_micros, "cost")?;
    }
    if let (Some(directory), Some(attempt_id)) = (spool_dir.as_deref(), response_marker.as_deref()) {
        clear_response_marker(directory, &journal_key, &job.session.id, attempt_id).await?;
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

pub(crate) async fn create_response_marker(
    spool_dir: &std::path::Path,
    journal_key: &[u8; 32],
    session_id: &str,
    request_digest: String,
) -> Result<String, String> {
    let attempt_id = av_core::new_event_uid();
    let marker = InFlightResponse {
        session_id: session_id.to_owned(),
        attempt_id: attempt_id.clone(),
        request_digest,
    };
    let sealed = crate::journal::seal(journal_key, "in-flight-response", 0, &marker)?;
    let path = response_marker_path(spool_dir, session_id, &attempt_id);
    tokio::task::spawn_blocking(move || write_atomic_control(&path, &sealed))
        .await
        .map_err(|error| error.to_string())??;
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
            let marker: InFlightResponse = crate::journal::open(
                &journal_key,
                "in-flight-response",
                0,
                // Round-18: cap sealed marker read at MAX_CONTROL_BYTES.
                &marker_bytes,
            )?;
            if path != response_marker_path(&spool_dir, &marker.session_id, &marker.attempt_id) {
                return Err("in-flight response marker path does not match its payload".to_owned());
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
        let marker: InFlightResponse = crate::journal::open(
            &journal_key,
            "in-flight-response",
            0,
            // Round-18: cap sealed marker read at MAX_CONTROL_BYTES.
            &av_core::fsutil::read_capped(&path, av_core::fsutil::MAX_CONTROL_BYTES)
                .map_err(|error| error.to_string())?,
        )?;
        if marker.session_id != session_id || marker.attempt_id != attempt_id {
            return Err("in-flight response marker does not match completed job".to_owned());
        }
        std::fs::remove_file(&path).map_err(|error| error.to_string())?;
        let parent = path
            .parent()
            .ok_or_else(|| "in-flight response marker has no parent".to_owned())?;
        av_core::fsutil::sync_directory(parent).map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| error.to_string())?
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
) -> Result<(), String> {
    let index = session.journal_index();
    let domain = format!("{}:active", session.id);
    let line = crate::journal::seal(journal_key, &domain, index, record)?;
    append_journal(directory, session, line, *journal_key).await?;
    session.commit_journal_index(index)
}

async fn append_journal(
    directory: &std::path::Path,
    session: &Session,
    line: Vec<u8>,
    journal_key: [u8; 32],
) -> Result<(), String> {
    let directory = directory.to_path_buf();
    let session_id = session.id.clone();
    let identity = session.identity.clone();
    let workflow = session.workflow.as_str();
    tokio::task::spawn_blocking(move || -> Result<(), String> {
        use std::io::Write as _;
        std::fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
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
            // Round-37 F2: basename the paths in error strings. These
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
                // Round-18: cap sealed journal-metadata read at
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
        journal.sync_data().map_err(|error| error.to_string())?;
        if journal_created {
            std::fs::File::open(&directory)
                .and_then(|dir| dir.sync_all())
                .map_err(|error| {
                    // Round-37 F2: drop the full path entirely; the
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

pub(crate) async fn persist_broker_ack(
    directory: &std::path::Path,
    session_id: &str,
    event_uid: &str,
    ack: &PublishAck,
    journal_key: &[u8; 32],
) -> Result<(), String> {
    let path = broker_ack_path(directory, session_id, event_uid);
    let record = BrokerAckRecord {
        session_id: session_id.to_owned(),
        event_uid: event_uid.to_owned(),
        ack: ack.clone(),
    };
    let sealed = crate::journal::seal(journal_key, "broker-ack", 0, &record)?;
    tokio::task::spawn_blocking(move || write_atomic_control(&path, &sealed))
        .await
        .map_err(|error| error.to_string())?
}

pub(crate) async fn read_broker_ack(
    directory: &std::path::Path,
    session_id: &str,
    event_uid: &str,
    journal_key: &[u8; 32],
) -> Result<Option<PublishAck>, String> {
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
        std::fs::write(marker_path, serde_json::to_vec(&envelope).unwrap()).unwrap();
        assert!(ensure_no_inflight_responses(directory.path(), &journal_key)
            .await
            .unwrap_err()
            .contains("authentication failed"));
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
        let ack_path = std::fs::read_dir(directory.path().join("broker-acks").join(stem))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        std::fs::remove_file(ack_path).unwrap();

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
        // Round-41 F1: per-session errors during signed recovery no
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
            "round-41 F1: per-session HMAC failures warn+continue instead of propagating, got {outcome:?}"
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
        let ack_path = std::fs::read_dir(directory.path().join("broker-acks").join(stem))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
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
        std::fs::create_dir_all(ack_path.parent().unwrap()).unwrap();
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
        let bridge = Arc::new(RecordingBus::default());
        let worker = spawn_worker(
            4,
            bridge,
            Arc::new(HashEmbedder::default()),
            Arc::new(Registry::new()),
        );
        let session = session(Workflow::Unsigned);
        worker.submit_and_wait(job(Arc::clone(&session))).await.unwrap();

        let trajectory = session.take_trajectory();
        assert_eq!(trajectory.steps.len(), 1);
        assert_eq!(
            trajectory.steps[0].metrics.as_ref().unwrap().cached_tokens,
            Some(40)
        );
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

    /// The prior review caught that `ResponsePermit::submit` was going
    /// through the generic `try_submit` path, which bumps
    /// `stage="worker_queue"` on any capacity/mpsc-full failure — so a
    /// mid-stream response-capture job that raced with re-admitted
    /// worker jobs would be silently misattributed to the wrong
    /// counter, defeating the observability goal of the fused-permit
    /// split. Locking the correct routing: saturate worker capacity
    /// AFTER a response permit is issued, then commit the response job
    /// and assert it lands on `stage="response_slot"`.
    #[tokio::test]
    async fn response_permit_submit_bumps_response_slot_on_worker_capacity_exhaustion() {
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
        // further worker-side acquire fails. The response semaphore
        // is untouched — permits.response still holds its slot.
        let hog_a = worker.try_reserve("hog-a").expect("hog-a");
        let hog_b = worker.try_reserve("hog-b").expect("hog-b");
        // Submit the response-capture job. It draws from worker
        // capacity + mpsc — worker capacity is exhausted → `Full`.
        // The counter increment MUST be `stage="response_slot"`,
        // NOT `stage="worker_queue"`.
        let job = job(session(Workflow::Signed));
        let err = permits.response.submit(&worker, job).unwrap_err();
        assert_eq!(err, SubmitError::Full);
        let rendered = metrics.render();
        assert!(
            rendered.contains("av_events_dropped_total{stage=\"response_slot\"} 1"),
            "response_slot MUST have been bumped by ResponsePermit::submit; got:\n{rendered}"
        );
        assert!(
            !rendered.contains("av_events_dropped_total{stage=\"worker_queue\"} 1"),
            "worker_queue must NOT be bumped by ResponsePermit::submit failure — that would \
             mask which class of exhaustion produced the drop; got:\n{rendered}"
        );
        drop(hog_a);
        drop(hog_b);
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
}
