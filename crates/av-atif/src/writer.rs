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
#[derive(Debug, Clone)]
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
            trajectory_id: Some(av_core::new_event_uid()),
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
    pub fn push_step(&mut self, mut step: Step) -> Result<(), av_core::CoreError> {
        step.step_id = self.steps.len() as u64 + 1;
        // Strict-validator parity (same rationale as the round-6 hunt2
        // F2 cost cap below: the builder must never accept a step that
        // makes the trajectory permanently un-writable at
        // `write_atomic`, which strict-validates before persisting):
        // agent steps couple `llm_call_count` and `metrics` —
        // `llm_call_count == 0` forbids metrics/reasoning_content, any
        // other agent step requires metrics with all three token
        // fields present.
        if step.source == crate::model::Source::Agent {
            if step.llm_call_count == Some(0) {
                if step.metrics.is_some() || step.reasoning_content.is_some() {
                    return Err(av_core::CoreError::InvalidId(
                        "agent step with llm_call_count 0 must not carry metrics or reasoning_content"
                            .to_owned(),
                    ));
                }
            } else {
                let complete = step.metrics.as_ref().is_some_and(|m| {
                    m.prompt_tokens.is_some() && m.completion_tokens.is_some() && m.cached_tokens.is_some()
                });
                if !complete {
                    return Err(av_core::CoreError::InvalidId(
                        "agent step requires metrics with prompt/completion/cached token counts \
                         (strict ATIF-v1.7 agent-step fidelity)"
                            .to_owned(),
                    ));
                }
            }
        }
        // Compute the proposed totals into locals so an overflow on the
        // second/third field cannot leave the builder with partially-updated
        // totals ahead of a step that never got pushed.
        let (next_prompt, next_completion, next_cached, next_cost) = if let Some(m) = &step.metrics {
            let next_prompt = self
                .total_prompt
                .checked_add(m.prompt_tokens.unwrap_or(0))
                .ok_or(av_core::CoreError::Overflow {
                    context: "total_prompt_tokens",
                })?;
            let next_completion = self
                .total_completion
                .checked_add(m.completion_tokens.unwrap_or(0))
                .ok_or(av_core::CoreError::Overflow {
                    context: "total_completion_tokens",
                })?;
            let next_cached = self
                .total_cached
                .checked_add(m.cached_tokens.unwrap_or(0))
                .ok_or(av_core::CoreError::Overflow {
                    context: "total_cached_tokens",
                })?;
            // Reject a non-finite or negative cost the same way tokens are
            // rejected on overflow: without this the aggregate silently
            // saturates to +∞ (or drifts negative), and a downstream Strict
            // validator that trusts final_metrics.total_cost_usd signs
            // corrupt evidence. serde_json does NOT refuse non-finite
            // floats — it silently serializes them as `null` (empirically
            // verified against the workspace serde_json), which would
            // corrupt `total_cost_usd` in the persisted file. Reject them
            // here, before they can reach serialization.
            let step_cost = m.cost_usd.unwrap_or(0.0);
            if !step_cost.is_finite() || step_cost < 0.0 {
                return Err(av_core::CoreError::Overflow {
                    context: "step_cost_usd",
                });
            }
            // Round-6 (hunt2 F2): the validator caps step and total
            // cost at MAX_COST_USD (1e12) and refuses to persist
            // anything beyond. The prior writer accepted any finite
            // non-negative step cost, so the reconciler's u64-micros ↔
            // f64 USD round-trip could construct a step whose cost
            // exceeded the cap — the trajectory then became
            // permanently un-writable at `write_atomic` (evidence loss
            // at export time). Refuse here so the builder never
            // produces validator-invalid output.
            if step_cost > crate::validate::MAX_COST_USD {
                return Err(av_core::CoreError::Overflow {
                    context: "step_cost_usd",
                });
            }
            let next_cost = self.total_cost + step_cost;
            if !next_cost.is_finite() {
                return Err(av_core::CoreError::Overflow {
                    context: "total_cost_usd",
                });
            }
            if next_cost > crate::validate::MAX_COST_USD {
                return Err(av_core::CoreError::Overflow {
                    context: "total_cost_usd",
                });
            }
            (next_prompt, next_completion, next_cached, next_cost)
        } else {
            (
                self.total_prompt,
                self.total_completion,
                self.total_cached,
                self.total_cost,
            )
        };
        self.steps.push(step);
        self.total_prompt = next_prompt;
        self.total_completion = next_completion;
        self.total_cached = next_cached;
        self.total_cost = next_cost;
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
            notes: None,
            final_metrics: Some(FinalMetrics {
                total_prompt_tokens: Some(self.total_prompt),
                total_completion_tokens: Some(self.total_completion),
                total_cached_tokens: Some(self.total_cached),
                total_cost_usd: Some(self.total_cost),
                total_steps: Some(total_steps),
                extra: None,
            }),
            continued_trajectory_ref: None,
            subagent_trajectories: None,
            extra: None,
        }
    }
}

/// Convenience: build a metrics block with the three token counts the fidelity
/// criterion (R17) requires on strict v1.7 agent steps with nonzero
/// `llm_call_count` — in practice, every LLM-backed exported step.
pub fn metrics(prompt: u64, completion: u64, cached: u64, cost_usd: f64) -> Metrics {
    Metrics {
        prompt_tokens: Some(prompt),
        completion_tokens: Some(completion),
        cached_tokens: Some(cached),
        cost_usd: Some(cost_usd),
        logprobs: None,
        completion_token_ids: None,
        prompt_token_ids: None,
        extra: None,
    }
}

/// Write a trajectory to `path` atomically: serialize → temp file in the same
/// directory → fsync → rename. A crash can leave a stale `.tmp` file but never
/// a torn trajectory (silent-error class D13.16). The trajectory is validated
/// (strict) before any byte is written — this crate never produces an invalid
/// file (success criterion R28).
///
/// **Post-rename durability semantics**: once `tmp.persist(path)` returns
/// `Ok`, the file is atomically visible at `path`. A subsequent
/// `sync_directory` failure means the dirent may not survive an
/// immediate power loss on POSIX-conformant filesystems, but every
/// observer running now sees the file. Round-13 F1 change: log a
/// `tracing::warn!` and return `Ok(())` instead of returning `Err`,
/// matching `av_core::fsutil::write_atomic`'s round-12 F5 semantic.
/// Returning `Err` after a successful rename historically confused
/// caller retry logic: the reconciler would treat this as
/// "trajectory not persisted" and redo the whole
/// validate + serialize + rename cycle on the next tick — wasted IO,
/// and worse: a caller that gates session-state advancement on `Ok`
/// would keep the session as "capture failed" while the trajectory
/// was in fact on disk.
pub fn write_atomic(trajectory: &Trajectory, path: &Path) -> Result<(), WriterError> {
    let issues = crate::validate::validate_trajectory(trajectory, crate::validate::Mode::Strict);
    if !issues.is_empty() {
        return Err(WriterError::Invalid(issues));
    }
    let json = serde_json::to_vec_pretty(trajectory)?;
    // `parent()` of a relative leaf like "t.json" is `Some("")`, which is
    // not a usable directory path; normalize to `.` (same fix as
    // `av_core::fsutil::write_atomic`).
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    // Round-24 F3 (av-atif writer): parity with `av_core::fsutil::write_atomic`
    // (round-23) — use `create_dir_all_synced` so a first ATIF write
    // into a new subtree also fsyncs the newly-created ancestor
    // dirents. `create_dir_all` alone left them volatile until the
    // next ambient sync; a power loss between mkdir and sync could
    // drop the trajectory even though its bytes were fsynced.
    av_core::fsutil::create_dir_all_synced(dir).map_err(WriterError::Io)?;
    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
    tmp.write_all(&json)?;
    tmp.flush()?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| WriterError::Io(e.error))?;
    if let Err(error) = av_core::fsutil::sync_directory(dir) {
        tracing::warn!(
            path = %av_core::fsutil::basename(path),
            error = %error,
            "post-rename ATIF trajectory directory fsync failed; file is visible but its dirent may not survive an immediate power loss"
        );
    }
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
            timestamp: Some(av_core::time::now_iso8601()),
            source,
            message: serde_json::json!("hello"),
            reasoning_effort: None,
            reasoning_content: None,
            model_name: None,
            tool_calls: None,
            observation: None,
            metrics: matches!(source, Source::Agent).then(|| metrics(100, 20, 60, 0.001)),
            is_copied_context: None,
            llm_call_count: None,
            extra: None,
        }
    }

    /// Pin the agent-step coupling guards individually (mutants
    /// flipping the conjunctions previously survived): partially
    /// populated metrics are refused, and `llm_call_count == 0` with
    /// exactly one of metrics/reasoning_content present is refused.
    #[test]
    fn partial_metrics_and_zero_call_couplings_are_refused() {
        // Each missing token field alone must refuse the step.
        for missing in ["prompt", "completion", "cached"] {
            let mut s = step(Source::Agent);
            let mut m = metrics(100, 20, 60, 0.001);
            match missing {
                "prompt" => m.prompt_tokens = None,
                "completion" => m.completion_tokens = None,
                _ => m.cached_tokens = None,
            }
            s.metrics = Some(m);
            let mut b = TrajectoryBuilder::new(agent(), None);
            assert!(
                b.push_step(s).is_err(),
                "agent step missing {missing}_tokens must be refused"
            );
        }
        // llm_call_count == 0 with metrics only.
        let mut s = step(Source::Agent);
        s.llm_call_count = Some(0);
        let mut b = TrajectoryBuilder::new(agent(), None);
        assert!(b.push_step(s).is_err(), "metrics with zero calls must be refused");
        // llm_call_count == 0 with reasoning_content only.
        let mut s = step(Source::Agent);
        s.llm_call_count = Some(0);
        s.metrics = None;
        s.reasoning_content = Some("thinking".into());
        let mut b = TrajectoryBuilder::new(agent(), None);
        assert!(
            b.push_step(s).is_err(),
            "reasoning_content with zero calls must be refused"
        );
        // llm_call_count == 0 bare is accepted.
        let mut s = step(Source::Agent);
        s.llm_call_count = Some(0);
        s.metrics = None;
        let mut b = TrajectoryBuilder::new(agent(), None);
        assert!(b.push_step(s).is_ok());
    }

    #[test]
    fn builder_assigns_sequential_ids_and_aggregates() {
        let mut b = TrajectoryBuilder::new(agent(), Some("sess-1".into()));
        b.push_step(step(Source::User)).unwrap();
        b.push_step(step(Source::Agent)).unwrap();
        b.push_step(step(Source::Agent)).unwrap();
        let t = b.finish();
        assert_eq!(
            t.steps.iter().map(|s| s.step_id).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
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

    /// Mutation-run hardening: the cost guard is
    /// `!is_finite() || cost < 0.0` — flipping `||` to `&&` (which
    /// disables the guard entirely, since no value is both non-finite
    /// AND negative) survived the suite. Pin each arm independently:
    /// NaN, +∞, and negative costs must all be refused, and a valid
    /// cost on the same builder must still be accepted afterwards.
    #[test]
    fn non_finite_and_negative_costs_are_each_refused() {
        for bad_cost in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -0.001] {
            let mut b = TrajectoryBuilder::new(agent(), None);
            let mut s = step(Source::Agent);
            s.metrics = Some(metrics(1, 1, 0, bad_cost));
            assert!(
                b.push_step(s).is_err(),
                "cost {bad_cost} must be refused before it can reach serialization",
            );
            // The refusal must not have partially updated the aggregates.
            let mut ok = step(Source::Agent);
            ok.metrics = Some(metrics(1, 1, 0, 0.5));
            b.push_step(ok).unwrap();
            let fm = b.finish().final_metrics.unwrap();
            assert_eq!(fm.total_prompt_tokens, Some(1));
            assert!((fm.total_cost_usd.unwrap() - 0.5).abs() < 1e-12);
        }
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

    /// Vicious bug caught in review round 17: `push_step` used to mutate
    /// `total_prompt` before checking `total_completion` for overflow, so an
    /// overflow on a later field would leave the builder with totals ahead
    /// of a step that was never pushed. Locks the atomic-commit invariant:
    /// on any overflow, every accumulator + `steps` stays exactly as it was
    /// before the call.
    #[test]
    fn push_step_overflow_leaves_builder_state_unchanged() {
        let mut b = TrajectoryBuilder::new(agent(), None);
        // First a legitimate step to establish nonzero totals.
        b.push_step(step(Source::Agent)).unwrap();
        let before_prompt = b.total_prompt;
        let before_completion = b.total_completion;
        let before_cached = b.total_cached;
        let before_len = b.steps.len();

        // Craft a step whose `completion_tokens` overflows the running total
        // while `prompt_tokens` does not. Without the atomic-commit fix,
        // total_prompt would be updated but the step would not be pushed,
        // leaving total_prompt out of sync with sum(steps.prompt).
        let mut hostile = step(Source::Agent);
        hostile.metrics = Some(metrics(1, u64::MAX, 0, 0.0));
        let err = b.push_step(hostile).expect_err("must refuse overflowing totals");
        assert!(
            matches!(err, av_core::CoreError::Overflow { .. }),
            "wrong error variant: {err:?}",
        );

        assert_eq!(b.total_prompt, before_prompt, "total_prompt leaked");
        assert_eq!(b.total_completion, before_completion, "total_completion leaked");
        assert_eq!(b.total_cached, before_cached, "total_cached leaked");
        assert_eq!(b.steps.len(), before_len, "steps len leaked");
    }
}
