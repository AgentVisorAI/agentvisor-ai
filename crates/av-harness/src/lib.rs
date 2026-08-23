//! The Agent Harness: the drop-in inline proxy wrapping agent → LLM traffic
//! (brief §9 data flow).
//!
//! Hot path (per request): validate identity → check token quota → sanitize →
//! compress → dispatch a copy to the async workers (non-blocking `try_send`,
//! bounded channels) → forward upstream → stream chunks back. Workers do the
//! heavy work: embeddings, loop delta, OCSF emission, bridge publish, ATIF
//! appends. Receipts are signed once, at session close, asynchronously
//! (brief §2 signing rule).
//!
//! Silent-error posture: every dropped worker message increments
//! `av_events_dropped_total`; audited chat/tool work reserves worker capacity
//! before quotas mutate, so ATIF-bearing jobs are admission-gated (fail
//! closed), never dropped mid-flight; client aborts still finalize sessions;
//! worker panics are supervised and counted.

pub mod config;
pub mod dashboard;
pub(crate) mod journal;
pub mod pipeline;
pub(crate) mod provider;
pub mod reconciler;
pub(crate) mod recovery;
pub mod routes;
pub mod session;
pub(crate) mod spool;
pub mod worker;

pub use config::HarnessConfig;
pub use journal::key_from_signer as control_key_from_signer;
pub use pipeline::AppState;
pub use routes::build_router;

/// Internal-only re-exports for coverage-guided fuzzing. Not part of
/// the stable API; do not depend on these outside `fuzz/`. The
/// `#[doc(hidden)]` attribute keeps rustdoc from listing them.
#[doc(hidden)]
pub mod fuzz {
    pub use crate::routes::__fuzz_parse_provider_chunk as parse_provider_chunk;
    pub use crate::routes::__fuzz_sse_frame_end as sse_frame_end;
}
