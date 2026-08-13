//! Emit one ATIF trajectory through the production writer for interoperability checks.

use ab_atif::{
    write_atomic, Agent, Metrics, Observation, ObservationResult, Source, Step, ToolCall, TrajectoryBuilder,
};

fn step(source: Source, message: serde_json::Value) -> Step {
    Step {
        step_id: 0,
        timestamp: Some(ab_core::time::now_iso8601()),
        source,
        message,
        reasoning_effort: None,
        reasoning_content: None,
        model_name: None,
        tool_calls: None,
        observation: None,
        metrics: None,
        is_copied_context: None,
        llm_call_count: None,
        extra: None,
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args_os()
        .nth(1)
        .map(std::path::PathBuf::from)
        .ok_or("usage: emit_valid <output.json>")?;
    let agent = Agent {
        name: "agent-bridge-harness".to_owned(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        model_name: Some("interop-model".to_owned()),
        tool_definitions: None,
        extra: None,
    };
    let mut builder = TrajectoryBuilder::new(agent, Some("harbor-interop".to_owned()));
    builder.push_step(step(Source::User, serde_json::json!("Read the record")))?;
    let mut agent_step = step(Source::Agent, serde_json::json!("Reading the record"));
    agent_step.tool_calls = Some(vec![ToolCall {
        tool_call_id: "call-1".to_owned(),
        function_name: "record_read".to_owned(),
        arguments: serde_json::json!({"id": 7}),
        extra: None,
    }]);
    agent_step.observation = Some(Observation {
        results: vec![ObservationResult {
            source_call_id: Some("call-1".to_owned()),
            content: Some(serde_json::json!("record 7")),
            subagent_trajectory_ref: None,
            extra: None,
        }],
    });
    agent_step.metrics = Some(Metrics {
        prompt_tokens: Some(12),
        completion_tokens: Some(4),
        cached_tokens: Some(3),
        cost_usd: Some(0.000_01),
        logprobs: None,
        completion_token_ids: None,
        prompt_token_ids: None,
        extra: None,
    });
    agent_step.llm_call_count = Some(1);
    builder.push_step(agent_step)?;
    write_atomic(&builder.finish(), &path)?;
    Ok(())
}
