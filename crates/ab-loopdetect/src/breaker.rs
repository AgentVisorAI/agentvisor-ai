//! The circuit breaker: per-session Δ window + token gate + verdicts.

use crate::embed::{cosine, Embedder};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// Breaker tuning (config-file surface). Defaults implement the brief's rule:
/// Δ≈0 across 3 consecutive steps while consuming N+ tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakerConfig {
    /// Δ threshold: a step with `1 - cosine < delta_epsilon` counts as
    /// near-zero semantic progress.
    pub delta_epsilon: f32,
    /// Consecutive near-zero steps required to trip.
    pub window: usize,
    /// Minimum session token consumption before the breaker may trip
    /// (prevents tripping on short legitimate confirmations).
    pub min_tokens: u64,
    /// Action on trip: `reject` (HTTP 429), `inject` (corrective system
    /// payload), or `abort` (connection abort) — the enforceable equivalents
    /// of the brief's TCP RST / 429 / corrective-payload triple.
    pub action: BreakerAction,
}

/// What the harness does when the breaker trips.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum BreakerAction {
    /// Respond HTTP 429 to the offending request.
    Reject,
    /// Inject a corrective system payload into the conversation.
    Inject,
    /// Abort the connection.
    Abort,
}

impl Default for BreakerConfig {
    fn default() -> Self {
        // ε calibrated against measured HashEmbedder delta distributions
        // (tests/calibrate.rs): paraphrase-loop steps score Δ ≈ 0.13–0.18,
        // genuinely progressing steps Δ ≈ 0.88–0.98. 0.30 sits between with
        // wide margins on both sides (semantic ONNX embedders push loop
        // deltas even lower, so the margin only grows with better models).
        Self { delta_epsilon: 0.30, window: 3, min_tokens: 1_000, action: BreakerAction::Reject }
    }
}

/// Verdict for one observed step.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum BreakerVerdict {
    /// Session is making progress.
    Progressing {
        /// Semantic delta vs the previous step (1 − cosine).
        delta: f32,
    },
    /// Near-zero progress but the window/token gate hasn't tripped yet.
    Suspicious {
        /// Semantic delta vs the previous step.
        delta: f32,
        /// Consecutive near-zero steps so far.
        streak: usize,
    },
    /// Loop detected — enforce now.
    Tripped {
        /// Semantic delta vs the previous step.
        delta: f32,
        /// Consecutive near-zero steps that tripped the breaker.
        streak: usize,
        /// Session tokens consumed at trip time.
        tokens_consumed: u64,
        /// Configured action.
        action: BreakerAction,
    },
}

/// Current breaker state (exposed to metrics / events).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BreakerState {
    /// Not tripped.
    Closed,
    /// Tripped: session enforcement active.
    Open,
}

/// Per-session loop-detection state. All mutation happens on worker threads;
/// the hot path only reads [`SessionLoopState::state`].
pub struct SessionLoopState {
    cfg: BreakerConfig,
    inner: Mutex<Inner>,
}

struct Inner {
    prev_embedding: Option<Vec<f32>>,
    deltas: VecDeque<f32>,
    streak: usize,
    tokens_consumed: u64,
    state: BreakerState,
}

impl SessionLoopState {
    /// Create with `cfg`.
    pub fn new(cfg: BreakerConfig) -> Self {
        Self {
            cfg,
            inner: Mutex::new(Inner {
                prev_embedding: None,
                deltas: VecDeque::with_capacity(16),
                streak: 0,
                tokens_consumed: 0,
                state: BreakerState::Closed,
            }),
        }
    }

    /// Current breaker state (hot-path read).
    pub fn state(&self) -> BreakerState {
        self.inner.lock().state
    }

    /// Observe one reasoning step (worker thread): embed, compute Δ against
    /// the previous step, update the streak, return the verdict.
    pub fn observe(&self, embedder: &dyn Embedder, text: &str, step_tokens: u64) -> BreakerVerdict {
        let embedding = embedder.embed(text);
        let mut inner = self.inner.lock();
        inner.tokens_consumed = inner.tokens_consumed.saturating_add(step_tokens);

        let delta = match &inner.prev_embedding {
            Some(prev) => 1.0 - cosine(prev, &embedding),
            None => 1.0, // first step: maximum novelty by definition
        };
        inner.prev_embedding = Some(embedding);
        inner.deltas.push_back(delta);
        if inner.deltas.len() > 32 {
            inner.deltas.pop_front();
        }

        if delta < self.cfg.delta_epsilon {
            inner.streak += 1;
        } else {
            inner.streak = 0;
        }

        if inner.streak >= self.cfg.window && inner.tokens_consumed >= self.cfg.min_tokens {
            inner.state = BreakerState::Open;
            BreakerVerdict::Tripped {
                delta,
                streak: inner.streak,
                tokens_consumed: inner.tokens_consumed,
                action: self.cfg.action,
            }
        } else if inner.streak > 0 {
            BreakerVerdict::Suspicious { delta, streak: inner.streak }
        } else {
            BreakerVerdict::Progressing { delta }
        }
    }

    /// Manually reset (e.g. after a corrective injection gave the agent a new
    /// direction). Clears the streak and closes the breaker but keeps token
    /// accounting.
    pub fn reset(&self) {
        let mut inner = self.inner.lock();
        inner.streak = 0;
        inner.state = BreakerState::Closed;
        inner.prev_embedding = None;
        inner.deltas.clear();
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::embed::HashEmbedder;

    fn cfg() -> BreakerConfig {
        BreakerConfig { min_tokens: 1000, ..BreakerConfig::default() }
    }

    #[test]
    fn verbatim_loop_trips_within_window() {
        let s = SessionLoopState::new(cfg());
        let e = HashEmbedder::default();
        let text = "I should check the database again for the pending orders";
        // Step 1 establishes the baseline (delta = 1.0).
        assert!(matches!(s.observe(&e, text, 400), BreakerVerdict::Progressing { .. }));
        // Steps 2-3: identical → streak builds but token gate also applies.
        assert!(matches!(s.observe(&e, text, 400), BreakerVerdict::Suspicious { streak: 1, .. }));
        assert!(matches!(s.observe(&e, text, 400), BreakerVerdict::Suspicious { streak: 2, .. }));
        // Step 4: streak 3 + 1600 tokens ≥ 1000 → tripped (≤ 3 cycles after baseline).
        let v = s.observe(&e, text, 400);
        assert!(matches!(v, BreakerVerdict::Tripped { streak: 3, .. }), "{v:?}");
        assert_eq!(s.state(), BreakerState::Open);
    }

    #[test]
    fn token_gate_defers_tripping() {
        let s = SessionLoopState::new(cfg());
        let e = HashEmbedder::default();
        let text = "same thing";
        for _ in 0..6 {
            let v = s.observe(&e, text, 10); // tiny token flow
            assert!(
                !matches!(v, BreakerVerdict::Tripped { .. }),
                "tripped below the token floor: {v:?}"
            );
        }
        // Once tokens cross the floor, the standing streak trips immediately.
        let v = s.observe(&e, text, 2_000);
        assert!(matches!(v, BreakerVerdict::Tripped { .. }), "{v:?}");
    }

    #[test]
    fn progressing_content_never_trips() {
        let s = SessionLoopState::new(cfg());
        let e = HashEmbedder::default();
        let steps = [
            "Parse the user's CSV upload and validate the header row",
            "Header valid; now inferring column types from the first 100 rows",
            "Types inferred: 3 numeric, 2 categorical; building the schema migration",
            "Migration built; applying to staging and running the smoke tests",
            "Smoke tests green; generating the summary report for review",
            "Report ready; posting the artifact link and closing the task",
        ];
        for step in steps {
            let v = s.observe(&e, step, 5_000);
            assert!(
                matches!(v, BreakerVerdict::Progressing { .. }),
                "false positive on progressing step {step:?}: {v:?}"
            );
        }
        assert_eq!(s.state(), BreakerState::Closed);
    }

    #[test]
    fn streak_resets_on_progress() {
        let s = SessionLoopState::new(cfg());
        let e = HashEmbedder::default();
        let looped = "retry the same call once more";
        s.observe(&e, looped, 800);
        s.observe(&e, looped, 800); // streak 1
        s.observe(&e, looped, 800); // streak 2
        // Progress breaks the streak before it reaches 3.
        let v = s.observe(&e, "completely new direction: escalate to the human operator with log excerpts", 800);
        assert!(matches!(v, BreakerVerdict::Progressing { .. }), "{v:?}");
        // Next looped step compares against the *progress* text → still novel
        // (streak 0); only the one after that restarts the streak at 1.
        let v = s.observe(&e, looped, 800);
        assert!(matches!(v, BreakerVerdict::Progressing { .. }), "{v:?}");
        let v = s.observe(&e, looped, 800);
        assert!(matches!(v, BreakerVerdict::Suspicious { streak: 1, .. }), "{v:?}");
    }

    #[test]
    fn reset_closes_the_breaker() {
        let s = SessionLoopState::new(cfg());
        let e = HashEmbedder::default();
        let t = "loop loop loop";
        for _ in 0..4 {
            s.observe(&e, t, 500);
        }
        assert_eq!(s.state(), BreakerState::Open);
        s.reset();
        assert_eq!(s.state(), BreakerState::Closed);
        assert!(matches!(s.observe(&e, t, 500), BreakerVerdict::Progressing { .. }));
    }
}
