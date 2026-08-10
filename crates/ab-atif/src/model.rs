//! ATIF data model (serde), matching Harbor's published Pydantic models.

use serde::{Deserialize, Serialize};

/// The version this crate always writes.
pub const ATIF_VERSION: &str = "ATIF-v1.7";

/// Every published schema version the reader/validator accepts.
pub const SUPPORTED_VERSIONS: &[&str] = &[
    "ATIF-v1.0",
    "ATIF-v1.1",
    "ATIF-v1.2",
    "ATIF-v1.3",
    "ATIF-v1.4",
    "ATIF-v1.5",
    "ATIF-v1.6",
    "ATIF-v1.7",
];

/// Step source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    /// System / environment step.
    System,
    /// User message.
    User,
    /// Agent action or response.
    Agent,
}

/// Root trajectory object.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Trajectory {
    /// `"ATIF-vX.Y"`.
    pub schema_version: String,
    /// Run-scoped session id (optional since v1.7).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Unique trajectory id (v1.7, for single-file subagent embedding).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trajectory_id: Option<String>,
    /// Agent configuration.
    pub agent: Agent,
    /// Ordered interaction steps (`step_id` sequential from 1).
    pub steps: Vec<Step>,
    /// Aggregate metrics.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub final_metrics: Option<FinalMetrics>,
    /// Embedded subagent trajectories (v1.7).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subagent_trajectories: Option<Vec<Trajectory>>,
    /// Custom metadata (v1.1).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<serde_json::Value>,
}

/// Agent configuration block.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Agent {
    /// Agent name.
    pub name: String,
    /// Agent version.
    pub version: String,
    /// Backing model name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_name: Option<String>,
    /// Tool/function definitions in scope (v1.5, for SFT pipelines).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_definitions: Option<serde_json::Value>,
    /// Custom metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<serde_json::Value>,
}

/// One interaction step.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Step {
    /// Sequential id starting at 1.
    pub step_id: u64,
    /// ISO-8601 timestamp.
    pub timestamp: String,
    /// Who produced the step.
    pub source: Source,
    /// Message content (string or content-part array since v1.6).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<serde_json::Value>,
    /// Agent-only: chain-of-thought / reasoning content.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reasoning_content: Option<String>,
    /// Agent-only: model that produced this step.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_name: Option<String>,
    /// Agent-only: tool calls issued in this step.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<ToolCall>>,
    /// Environment feedback (agent steps; system steps since v1.2).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observation: Option<Observation>,
    /// Agent-only: per-step LLM metrics.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics: Option<Metrics>,
    /// Agent-only: number of LLM calls in this step (v1.7).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub llm_call_count: Option<u64>,
    /// Custom metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<serde_json::Value>,
}

/// A tool/function invocation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolCall {
    /// Correlation id referenced by observation results.
    pub tool_call_id: String,
    /// Invoked function name.
    pub function_name: String,
    /// Arguments object.
    pub arguments: serde_json::Value,
    /// Custom metadata (v1.7).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<serde_json::Value>,
}

/// Environment feedback for a step.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Observation {
    /// Results, each referencing a `tool_call_id` from the same step.
    pub results: Vec<ObservationResult>,
}

/// One observation result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObservationResult {
    /// The `tool_call_id` this result answers (optional for free-form
    /// system observations).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_call_id: Option<String>,
    /// Result content (string or content-part array since v1.6).
    pub content: serde_json::Value,
    /// Custom metadata (v1.7).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<serde_json::Value>,
}

/// Per-step LLM metrics. `cached_tokens` preservation is the Module H
/// replayable-KV-checkpoint requirement (success criterion R17/R28).
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct Metrics {
    /// Prompt tokens.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt_tokens: Option<u64>,
    /// Completion tokens.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completion_tokens: Option<u64>,
    /// Provider-cached prompt tokens.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cached_tokens: Option<u64>,
    /// Cost in USD.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost_usd: Option<f64>,
    /// Per-token logprobs (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logprobs: Option<Vec<f64>>,
    /// Completion token ids (v1.3, RL training).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completion_token_ids: Option<Vec<u64>>,
    /// Prompt token ids (v1.4).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt_token_ids: Option<Vec<u64>>,
}

/// Trajectory-level aggregates.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct FinalMetrics {
    /// Sum of prompt tokens.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_prompt_tokens: Option<u64>,
    /// Sum of completion tokens.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_completion_tokens: Option<u64>,
    /// Sum of cached tokens.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_cached_tokens: Option<u64>,
    /// Total cost in USD.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_cost_usd: Option<f64>,
    /// Number of steps.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_steps: Option<u64>,
}
