//! AgentBridge core primitives shared by every crate in the workspace.
//!
//! Provides: identifiers (UUIDv7), wall/monotonic time helpers, the approximate
//! tokenizer used for budgets and compression ratios, SHA-256 digest helpers,
//! a dependency-free Prometheus-text metrics registry, and common error types.

pub mod digest;
pub mod error;
pub mod fsutil;
pub mod hash;
pub mod ids;
pub mod metrics;
pub mod text;
pub mod time;
pub mod tokens;
pub mod units;

pub use error::CoreError;
pub use ids::{new_event_uid, new_session_id, InstanceUid, SessionId};
