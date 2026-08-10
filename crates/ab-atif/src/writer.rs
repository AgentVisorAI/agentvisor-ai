//! Trajectory construction and crash-safe persistence.

use crate::model::{Agent, FinalMetrics, Metrics, Step, Trajectory, ATIF_VERSION};
use std::io::Write;
use std::path::Path;

/// Errors from trajectory building / writing.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WriterError {
    /// Filesystem failure.
    #[error("io error writing trajectory: {0}")]
    Io(#[from] std::io::Error),
    /// Serialization failure.
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    /// The built trajectory failed self-validation — never write invalid files.
    #[error("built trajectory failed validation: {0:?}")]
    Invalid(Vec<crate::validate::ValidationIssue>),
}

/// Incremental builder used by the harness's unsigned-workflow path.
///
/// Steps receive sequential ids automatically; aggregate metrics accumulate as
/// steps are appended (checked arithmetic — a corrupt aggregate must fail
/// loudly, not wrap).
#[derive(Debug)]
pub struct TrajectoryBuilder {
    session_id: Option<String>,
    trajectory_id: Option<String>,
    agent: Agent,
    steps: Vec<Step>,
    total_prompt: u64,
    total_completion: u64,
    total_cached: u64,
    total_cost: f64,
}

impl TrajectoryBuilder {
    /// Start a trajectory for `agent`.
    pub fn new(agent: Agent, session_id: Option<String>) -> Self {
        Self {
            session_id,
            trajectory_id: Some(ab_core::new_event_uid()),
            agent,
            steps: Vec::new(),
            total_prompt: 0,
            total_completion: 0,
            total_cached: 0,
            total_cost: 0.0,
        }
    }

    /// Number of steps so far.
    pub fn len(&self) -> usize {
        self.steps.len()
    }

    /// True when no steps have been appended.
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// Append a step. The builder overwrites `step_id` with the next
    /// sequential id (callers cannot corrupt ordering) and accumulates
    /// aggregate metrics.
    pub fn push_step(&mut self, mut step: Step) -> Result<(), ab_core::CoreError> {
        step.step_id = self.steps.len() as u64 + 1;
        if let Some(m) = &step.metrics {
            self.total_prompt = self
                .total_prompt
                .checked_add(m.prompt_tokens.unwrap_or(0))
                .ok_or(ab_core::CoreError::Overflow { context: "total_prompt_tokens" })?;
            self.total_completion = self
                .total_completion
                .checked_add(m.completion_tokens.unwrap_or(0))
                .ok_or(ab_core::CoreError::Overflow { context: "total_completion_tokens" })?;
            self.total_cached = self
                .total_cached
                .checked_add(m.cached_tokens.unwrap_or(0))
                .ok_or(ab_core::CoreError::Overflow { context: "total_cached_tokens" })?;
            self.total_cost += m.cost_usd.unwrap_or(0.0);
        }
        self.steps.push(step);
        Ok(())
    }

    /// Finalize into a v1.7 trajectory with aggregate metrics.
    pub fn finish(self) -> Trajectory {
        let total_steps = self.steps.len() as u64;
        Trajectory {
            schema_version: ATIF_VERSION.to_owned(),
            session_id: self.session_id,
            trajectory_id: self.trajectory_id,
            agent: self.agent,
            steps: self.steps,
            final_metrics: Some(FinalMetrics {
                total_prompt_tokens: Some(self.total_prompt),
                total_completion_tokens: Some(self.total_completion),
                total_cached_tokens: Some(self.total_cached),
                total_cost_usd: Some(self.total_cost),
                total_steps: Some(total_steps),
            }),
            subagent_trajectories: None,
            extra: None,
        }
    }
}

/// Convenience: build a metrics block with the three token counts the fidelity
/// criterion (R17) requires on every exported step.
pub fn metrics(prompt: u64, completion: u64, cached: u64, cost_usd: f64) -> Metrics {
    Metrics {
        prompt_tokens: Some(prompt),
        completion_tokens: Some(completion),
        cached_tokens: Some(cached),
        cost_usd: Some(cost_usd),
        logprobs: None,
        completion_token_ids: None,
        prompt_token_ids: None,
    }
}

/// Write a trajectory to `path` atomically: serialize → temp file in the same
/// directory → fsync → rename. A crash can leave a stale `.tmp` file but never
/// a torn trajectory (silent-error class D13.16). The trajectory is validated
/// (strict) before any byte is written — this crate never produces an invalid
/// file (success criterion R28).
pub fn write_atomic(trajectory: &Trajectory, path: &Path) -> Result<(), WriterError> {
    let issues = crate::validate::validate_trajectory(trajectory, crate::validate::Mode::Strict);
    if !issues.is_empty() {
        return Err(WriterError::Invalid(issues));
    }
    let json = serde_json::to_vec_pretty(trajectory)?;
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir)?;
    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
    tmp.write_all(&json)?;
    tmp.flush()?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| WriterError::Io(e.error))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::model::Source;

    fn agent() -> Agent {
        Agent {
            name: "harness".into(),
            version: "0.1.0".into(),
            model_name: Some("claude-sonnet-4".into()),
            tool_definitions: None,
            extra: None,
        }
    }

    fn step(source: Source) -> Step {
        Step {
            step_id: 999, // deliberately wrong; builder must overwrite
            timestamp: ab_core::time::now_iso8601(),
            source,
            message: Some(serde_json::json!("hello")),
            reasoning_content: None,
            model_name: None,
            tool_calls: None,
            observation: None,
            metrics: matches!(source, Source::Agent).then(|| metrics(100, 20, 60, 0.001)),
            llm_call_count: None,
            extra: None,
        }
    }

    #[test]
    fn builder_assigns_sequential_ids_and_aggregates() {
        let mut b = TrajectoryBuilder::new(agent(), Some("sess-1".into()));
        b.push_step(step(Source::User)).unwrap();
        b.push_step(step(Source::Agent)).unwrap();
        b.push_step(step(Source::Agent)).unwrap();
        let t = b.finish();
        assert_eq!(t.steps.iter().map(|s| s.step_id).collect::<Vec<_>>(), vec![1, 2, 3]);
        let fm = t.final_metrics.unwrap();
        assert_eq!(fm.total_prompt_tokens, Some(200));
        assert_eq!(fm.total_completion_tokens, Some(40));
        assert_eq!(fm.total_cached_tokens, Some(120));
        assert_eq!(fm.total_steps, Some(3));
        assert!((fm.total_cost_usd.unwrap() - 0.002).abs() < 1e-12);
    }

    #[test]
    fn aggregate_overflow_is_loud() {
        let mut b = TrajectoryBuilder::new(agent(), None);
        let mut s = step(Source::Agent);
        s.metrics = Some(metrics(u64::MAX, 0, 0, 0.0));
        b.push_step(s).unwrap();
        let mut s2 = step(Source::Agent);
        s2.metrics = Some(metrics(1, 0, 0, 0.0));
        assert!(b.push_step(s2).is_err(), "overflow must not wrap silently");
    }

    #[test]
    fn atomic_write_produces_valid_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("trajectory.json");
        let mut b = TrajectoryBuilder::new(agent(), Some("sess-2".into()));
        b.push_step(step(Source::User)).unwrap();
        b.push_step(step(Source::Agent)).unwrap();
        write_atomic(&b.finish(), &path).unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let issues = crate::validate::validate_value(&value, crate::validate::Mode::Strict);
        assert!(issues.is_empty(), "{issues:?}");
        // No temp litter after success.
        let litter: Vec<_> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.path() != path)
            .collect();
        assert!(litter.is_empty(), "temp files left behind: {litter:?}");
    }

    #[test]
    fn invalid_trajectory_never_written() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.json");
        let mut t = TrajectoryBuilder::new(agent(), None);
        t.push_step(step(Source::Agent)).unwrap();
        let mut t = t.finish();
        // Corrupt: agent-only field on a user step.
        if let Some(s) = t.steps.first_mut() {
            s.source = Source::User;
            s.reasoning_content = Some("should not be here".into());
        }
        let err = write_atomic(&t, &path);
        assert!(matches!(err, Err(WriterError::Invalid(_))));
        assert!(!path.exists(), "invalid file must not be created");
    }
}
