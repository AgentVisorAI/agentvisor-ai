//! Session/agent state: atomic counters, token-velocity windows, rate limits,
//! and action budgets (brief Modules B/D and the §8 "In-Memory State" layer).
//!
//! The core abstraction is [`StateStore`]: check-and-spend operations that are
//! atomic even under concurrent tool calls from parallel sub-agents
//! (silent-error class D13.9 — a budget must never over-spend by racing).
//! `InMemoryStore` is the single-node reference; a Redis Cluster backend
//! compiles behind the `redis` feature for multi-node deployments and is
//! contract-tested against a live server when `AB_REDIS_URL` is set.
//!
//! All arithmetic here is checked — budget/monetary code must fail loudly,
//! never wrap.

pub mod budget;
pub mod store;
pub mod velocity;

pub use budget::{ActionBudget, BudgetDecision, BudgetSpec};
pub use store::{InMemoryStore, Spend, StateError, StateStore};
pub use velocity::TokenVelocity;

#[cfg(feature = "redis")]
pub mod redis_store;
