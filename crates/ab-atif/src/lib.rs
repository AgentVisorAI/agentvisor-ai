//! ATIF — Agent Trajectory Interchange Format (Harbor), version 1.7.
//!
//! Verified against the published specification at
//! harborframework.com/docs/agents/trajectory-format (2026-08-10):
//!
//! - root `Trajectory` with `schema_version`, optional run-scoped `session_id`
//!   (relaxed in v1.7), `trajectory_id` + `subagent_trajectories` (v1.7),
//!   `agent`, ordered `steps`, `final_metrics`, `extra` (v1.1);
//! - `Step.step_id` sequential from 1; `source` ∈ {system, user, agent};
//!   agent-only fields (`reasoning_content`, `model_name`, `tool_calls`,
//!   `metrics`, `llm_call_count`) rejected on non-agent steps; `observation`
//!   allowed on agent steps and, since v1.2, system steps;
//! - `Metrics` carries `prompt_tokens` / `completion_tokens` / `cached_tokens`
//!   / `cost_usd` (+ `logprobs`, `completion_token_ids` v1.3,
//!   `prompt_token_ids` v1.4) — the cached-token preservation that makes an
//!   exported trajectory a replayable KV-cache checkpoint (brief Module H);
//! - validator collects **all** errors (Harbor philosophy), not just the first.
//!
//! Reader accepts every published version v1.0–v1.7 with per-version field
//! gating; the writer always emits v1.7 (inbound tolerant, outbound strict).

pub mod model;
pub mod validate;
pub mod writer;

pub use model::{
    Agent, FinalMetrics, Metrics, Observation, ObservationResult, ReasoningEffort, Source, Step,
    SubagentTrajectoryRef, ToolCall, Trajectory, ATIF_VERSION, SUPPORTED_VERSIONS,
};
pub use validate::{validate_trajectory, validate_value, Mode, ValidationIssue};
pub use writer::{write_atomic, TrajectoryBuilder};
