//! In-flight context compression (brief Module C).
//!
//! Parses OpenAI-shape chat payloads (`messages[]` with system prompts,
//! conversation history, and tool outputs) and applies auditable pruning
//! passes targeting the brief's 30–50 % reduction on ≥ 50 k-token histories.
//!
//! Hard invariants, property-tested (never semantically destructive, D9/D13.10):
//! 1. the first system message is byte-identical;
//! 2. the last `keep_tail` messages are byte-identical;
//! 3. output parses as the same shape (roles preserved, no orphaned
//!    `tool_call_id` references);
//! 4. idempotent: `compress(compress(x)) == compress(x)`;
//! 5. output token count ≤ input token count.
//!
//! Every pruned block leaves an audit stub `[pruned: N tokens, sha256:…]` so a
//! reviewer can prove what was removed. Metrics mirror ATIF field names.

pub mod passes;

pub use passes::{compress, CompressionConfig, CompressionOutcome};
