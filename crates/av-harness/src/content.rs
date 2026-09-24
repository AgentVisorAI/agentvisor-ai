//! Content export for external telemetry (the tenant OpenTelemetry
//! collector).
//!
//! The audit worker hands every step it has journaled and published to an
//! optional [`ContentSink`] as a [`ContentRecord`]: the OCSF event plus the
//! step's content (the new input message, the model output, tool calls and
//! results, token usage, finish reason). `agentvisord` installs a sink that
//! turns records into OpenTelemetry GenAI spans for the tenant collector
//! only; the operational collector never receives content. The library has
//! no telemetry dependency: without an installed sink nothing is exported.

use av_events::{AgentIdentity, EventClass};
use serde_json::Value;
use std::sync::Arc;

/// One journaled step in content form.
#[derive(Debug, Clone)]
pub struct ContentRecord {
    /// AgentVisor session id (the conversation id).
    pub session_id: String,
    /// OCSF event uid of the step.
    pub event_uid: String,
    /// Event class of the step.
    pub class: EventClass,
    /// True when the step's status is success.
    pub success: bool,
    /// Agent identity bound to the step.
    pub identity: AgentIdentity,
    /// When the step was journaled, epoch milliseconds.
    pub time_ms: u64,
    /// The OCSF event as journaled (already redacted when redaction is on).
    pub event: Value,
    /// Who produced the message: `user`, `agent`, or `system`.
    pub source: Option<String>,
    /// The step's message (input message for a request, output for a response).
    pub message: Option<Value>,
    /// Explicit reasoning text, when the provider returned it.
    pub reasoning: Option<String>,
    /// Model that produced a response.
    pub model: Option<String>,
    /// Tool calls requested by the model, as JSON.
    pub tool_calls: Option<Value>,
    /// Tool results or other environment feedback, as JSON.
    pub observation: Option<Value>,
    /// Prompt tokens attributed to the step.
    pub prompt_tokens: Option<u64>,
    /// Completion tokens attributed to the step.
    pub completion_tokens: Option<u64>,
    /// Provider-native finish reason.
    pub finish_reason: Option<String>,
    /// Chat response attempt shared by a request and its response.
    pub attempt_id: Option<String>,
    /// True for the terminal (response) record of a chat attempt.
    pub terminal: bool,
}

/// Receives journaled steps. Called on a dedicated thread, one record at a
/// time, in journal order per session.
pub trait ContentSink: Send + Sync {
    /// Accept one record.
    fn record(&self, record: ContentRecord);
}

/// Records waiting for the sink thread. A full queue drops new records
/// (counted in `av_content_records_dropped_total`) instead of slowing the
/// audit worker.
pub const CONTENT_QUEUE_CAPACITY: usize = 8192;

/// Hands records from the audit worker to a [`ContentSink`] on a dedicated
/// thread. The worker only does a non-blocking `try_send`; redaction,
/// serialization, and export all run on the sink thread, and a panicking
/// sink cannot reach the worker.
pub struct ContentDispatcher {
    sender: std::sync::mpsc::SyncSender<ContentRecord>,
    dropped: Arc<av_core::metrics::Counter>,
}

impl ContentDispatcher {
    /// Start the sink thread.
    pub fn spawn(sink: Arc<dyn ContentSink>, metrics: &av_core::metrics::Registry) -> std::io::Result<Self> {
        let (sender, receiver) = std::sync::mpsc::sync_channel::<ContentRecord>(CONTENT_QUEUE_CAPACITY);
        let dropped = metrics.counter(
            "av_content_records_dropped_total",
            "Content records dropped because the tenant telemetry queue was full or the sink failed",
        );
        let failures = Arc::clone(&dropped);
        std::thread::Builder::new()
            .name("agentvisor-content".to_owned())
            .spawn(move || {
                for record in receiver {
                    let sink = Arc::clone(&sink);
                    let outcome =
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || sink.record(record)));
                    if outcome.is_err() {
                        failures.inc();
                        tracing::error!("content sink panicked; record dropped");
                    }
                }
            })?;
        Ok(Self { sender, dropped })
    }

    /// Queue one record without blocking; drop it when the queue is full.
    pub fn submit(&self, record: ContentRecord) {
        if self.sender.try_send(record).is_err() {
            self.dropped.inc();
        }
    }
}

/// A dispatcher slot shared by the application state and the audit worker,
/// so a sink can be installed after both exist.
pub type SharedContentSink = Arc<parking_lot::RwLock<Option<Arc<ContentDispatcher>>>>;

/// Everything the audit worker applies to a step on its way out: the
/// redaction engine (before journal and broker writes) and the content
/// dispatcher (after the step is durable and published).
#[derive(Clone, Default)]
pub struct AuditOutputs {
    /// Redaction applied to the journaled event and trajectory step.
    pub redaction: Option<Arc<av_redact::RedactionEngine>>,
    /// Optional content dispatcher.
    pub content: SharedContentSink,
}

impl AuditOutputs {
    /// Outputs with redaction only.
    pub fn with_redaction(redaction: Option<Arc<av_redact::RedactionEngine>>) -> Self {
        Self {
            redaction,
            content: SharedContentSink::default(),
        }
    }

    /// The installed dispatcher, if any.
    pub fn dispatcher(&self) -> Option<Arc<ContentDispatcher>> {
        self.content.read().clone()
    }
}
