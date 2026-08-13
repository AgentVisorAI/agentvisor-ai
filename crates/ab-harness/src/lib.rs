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
//! `ab_events_dropped_total`; ATIF appends spill to disk rather than drop;
//! client aborts still finalize sessions; worker panics are supervised and
//! counted.

pub mod config;
pub(crate) mod journal;
pub mod pipeline;
pub mod reconciler;
pub mod routes;
pub mod session;
pub(crate) mod spool;
pub mod worker;

pub use config::HarnessConfig;
pub use journal::key_from_signer as control_key_from_signer;
pub use pipeline::AppState;
pub use routes::build_router;
