//! The circuit breaker: per-session Δ window + token gate + verdicts.

use crate::embed::{cosine, Embedder};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// Breaker tuning (config-file surface). Defaults implement the brief's rule:
/// Δ≈0 across 3 consecutive steps while consuming N+ tokens.
///
/// Unknown keys are rejected so `[breaker]` typos fail loudly at startup.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BreakerConfig {
    /// Δ threshold: a step with `1 - cosine < delta_epsilon` counts as
    /// near-zero semantic progress.
    pub delta_epsilon: f32,
    /// Consecutive near-zero steps required to trip.
    pub window: usize,
    /// Minimum session token consumption before the breaker may trip
    /// (prevents tripping on short legitimate confirmations).
    pub min_tokens: u64,
    /// Action on trip: `reject` (HTTP 403 — deliberately not the brief's
    /// 429, which SDKs auto-retry; see `PipelineError::status`), `inject`
    /// (corrective system
    /// payload), or `abort` (connection abort) — the enforceable equivalents
    /// of the brief's TCP RST / 429 / corrective-payload triple.
    pub action: BreakerAction,
}

/// What the harness does when the breaker trips.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum BreakerAction {
    /// Respond with a permanent policy refusal (HTTP 403 in the harness;
    /// deliberately not 429, which mainstream SDKs auto-retry — see
    /// `PipelineError::status`).
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
        Self {
            delta_epsilon: 0.30,
            window: 3,
            min_tokens: 1_000,
            action: BreakerAction::Reject,
        }
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

/// Per-session loop-detection state. Embedding/delta mutation happens on
/// worker threads; the hot path reads [`SessionLoopState::state`] and
/// [`SessionLoopState::action`], and calls [`SessionLoopState::reset`] when
/// an Inject verdict fires.
pub struct SessionLoopState {
    cfg: BreakerConfig,
    inner: Mutex<Inner>,
}

struct Inner {
    /// Ring of the most recent usable embeddings. Round-51 §3.5: the
    /// breaker previously compared only against the IMMEDIATELY
    /// preceding embedding, so simple alternation (A, B, A, B, …) —
    /// the canonical agent-loop shape — never tripped in the default
    /// build (cross-history tightening needed a Qdrant sink). The
    /// delta is now the minimum against any embedding in this window,
    /// so a step that duplicates ANY recent step grows the streak.
    recent_embeddings: VecDeque<Vec<f32>>,
    streak: usize,
    tokens_consumed: u64,
    state: BreakerState,
}

/// How many recent embeddings the alternation window retains. Eight
/// covers alternation periods up to 8 (A,B,…,H,A,…) while keeping
/// per-session memory bounded (8 × dim × 4 bytes ≈ 12 KiB at
/// MiniLM's 384 dims).
const RECENT_EMBEDDING_WINDOW: usize = 8;

impl SessionLoopState {
    /// Create with `cfg`.
    pub fn new(cfg: BreakerConfig) -> Self {
        Self {
            cfg,
            inner: Mutex::new(Inner {
                recent_embeddings: VecDeque::with_capacity(RECENT_EMBEDDING_WINDOW),
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
    /// Configured enforcement action when the breaker is open.
    pub fn action(&self) -> BreakerAction {
        self.cfg.action
    }

    /// Observe one reasoning step (worker thread): embed, compute Δ against
    /// the previous step, update the streak, return the verdict.
    pub fn observe(&self, embedder: &dyn Embedder, text: &str, step_tokens: u64) -> BreakerVerdict {
        let embedding = embedder.embed(text);
        self.observe_embedding(embedding, step_tokens)
    }

    /// Observe a precomputed embedding. Workers use this path when the same
    /// vector is also persisted to an off-path vector sink.
    pub fn observe_embedding(&self, embedding: Vec<f32>, step_tokens: u64) -> BreakerVerdict {
        self.observe_embedding_with_similarity(embedding, step_tokens, None)
    }

    /// Observe an embedding plus an optional nearest prior-step similarity
    /// (scoped to the same session) supplied by a distributed vector engine.
    pub fn observe_embedding_with_similarity(
        &self,
        embedding: Vec<f32>,
        step_tokens: u64,
        nearest_similarity: Option<f32>,
    ) -> BreakerVerdict {
        let mut inner = self.inner.lock();
        inner.tokens_consumed = inner.tokens_consumed.saturating_add(step_tokens);

        // Fail-closed on non-finite or all-zero embeddings: a hostile
        // or misconfigured embedder can produce NaN/Inf vectors (any
        // arithmetic through `cosine`'s clamp path would return NaN,
        // and NaN < delta_epsilon is false, so the streak resets on
        // every step and the breaker never trips). An all-zero vector
        // is the ONNX embedder's error fallback — treating it as
        // maximum novelty lets a client with malformed prompts drive
        // the breaker into "novel-forever" mode. In both cases, treat
        // the step as a duplicate of the previous one (delta = 0),
        // which conservatively grows the streak.
        let embedding_is_finite = embedding.iter().all(|x| x.is_finite());
        let embedding_is_all_zero = embedding.iter().all(|x| *x == 0.0);
        let embedding_is_hostile = !embedding_is_finite || embedding_is_all_zero;

        let adjacent_delta = if embedding_is_hostile {
            0.0
        } else if inner.recent_embeddings.is_empty() {
            1.0 // first step: maximum novelty by definition
        } else {
            // Minimum delta against ANY recent embedding — catches
            // A,B,A,B alternation, not only exact-adjacent repeats.
            inner
                .recent_embeddings
                .iter()
                .map(|prev| 1.0 - cosine(prev, &embedding))
                .fold(f32::INFINITY, f32::min)
        };
        let delta = nearest_similarity
            .filter(|similarity| similarity.is_finite())
            .map_or(adjacent_delta, |similarity| {
                adjacent_delta.min(1.0 - similarity.clamp(-1.0, 1.0))
            });
        // Only record the embedding for future comparisons when it's
        // usable — a stored NaN vector would poison every subsequent
        // step's cosine.
        if !embedding_is_hostile {
            inner.recent_embeddings.push_back(embedding);
            if inner.recent_embeddings.len() > RECENT_EMBEDDING_WINDOW {
                inner.recent_embeddings.pop_front();
            }
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
            BreakerVerdict::Suspicious {
                delta,
                streak: inner.streak,
            }
        } else {
            BreakerVerdict::Progressing { delta }
        }
    }

    /// Manually reset (e.g. after a corrective injection gave the agent a new
    /// direction). Clears the streak and the embedding window and closes the
    /// breaker.
    ///
    /// Round-51 §3.5: `tokens_consumed` deliberately SURVIVES the reset.
    /// It implements the documented "minimum session token consumption"
    /// floor — zeroing it on every Inject turned the session-lifetime
    /// floor into a per-cycle floor, letting an agent that ignores the
    /// corrective message loop forever at ~min_tokens per correction.
    /// Release the retained embedding buffers.
    ///
    /// Unsigned sessions stay registered for the process lifetime by
    /// design, and each one otherwise pins its recent response
    /// embeddings (window × dim × f32) forever — dead weight after
    /// close, since a closed session never calls `observe` again.
    /// Unlike [`Self::reset`], the breaker verdict state is preserved.
    pub fn release_embedding(&self) {
        self.inner.lock().recent_embeddings.clear();
    }

    /// Manually reset (e.g. after a corrective injection gave the agent a new
    /// direction). Clears the streak and the embedding window and closes the
    /// breaker.
    ///
    /// Round-51 §3.5: `tokens_consumed` deliberately SURVIVES the reset.
    /// It implements the documented "minimum session token consumption"
    /// floor — zeroing it on every Inject turned the session-lifetime
    /// floor into a per-cycle floor, letting an agent that ignores the
    /// corrective message loop forever at ~min_tokens per correction.
    pub fn reset(&self) {
        let mut inner = self.inner.lock();
        inner.streak = 0;
        inner.state = BreakerState::Closed;
        inner.recent_embeddings.clear();
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::embed::HashEmbedder;

    fn cfg() -> BreakerConfig {
        BreakerConfig {
            min_tokens: 1000,
            ..BreakerConfig::default()
        }
    }

    #[test]
    fn verbatim_loop_trips_within_window() {
        let s = SessionLoopState::new(cfg());
        let e = HashEmbedder::default();
        let text = "I should check the database again for the pending orders";
        // Step 1 establishes the baseline (delta = 1.0).
        assert!(matches!(
            s.observe(&e, text, 400),
            BreakerVerdict::Progressing { .. }
        ));
        // Steps 2-3: identical → streak builds but token gate also applies.
        assert!(matches!(
            s.observe(&e, text, 400),
            BreakerVerdict::Suspicious { streak: 1, .. }
        ));
        assert!(matches!(
            s.observe(&e, text, 400),
            BreakerVerdict::Suspicious { streak: 2, .. }
        ));
        // Step 4: streak 3 + 1600 tokens ≥ 1000 → tripped (≤ 3 cycles after baseline).
        let v = s.observe(&e, text, 400);
        assert!(matches!(v, BreakerVerdict::Tripped { streak: 3, .. }), "{v:?}");
        assert_eq!(s.state(), BreakerState::Open);
    }

    /// Mutation-run hardening: `release_embedding` must actually clear the
    /// retained window (a no-op mutant survived). Observable behavior: an
    /// identical step right after a release compares against an EMPTY
    /// history — maximum novelty, streak reset — where the un-released
    /// window would have scored it a near-zero delta and kept the streak.
    #[test]
    fn release_embedding_clears_the_comparison_window() {
        let s = SessionLoopState::new(cfg());
        let e = HashEmbedder::default();
        let text = "repeat the same reasoning step about pending orders";
        s.observe(&e, text, 100);
        assert!(matches!(
            s.observe(&e, text, 100),
            BreakerVerdict::Suspicious { streak: 1, .. }
        ));
        s.release_embedding();
        let v = s.observe(&e, text, 100);
        assert!(
            matches!(v, BreakerVerdict::Progressing { .. }),
            "released window must not remember prior steps: {v:?}"
        );
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
        let v = s.observe(
            &e,
            "completely new direction: escalate to the human operator with log excerpts",
            800,
        );
        assert!(matches!(v, BreakerVerdict::Progressing { .. }), "{v:?}");
        // Round-51 §3.5: a looped step after ONE progress interjection
        // still matches the earlier repeats in the embedding window —
        // the streak resumes immediately instead of being laundered by
        // an A,A,B,A alternation (the old adjacent-only comparison
        // treated the return to A as novel).
        let v = s.observe(&e, looped, 800);
        assert!(matches!(v, BreakerVerdict::Suspicious { streak: 1, .. }), "{v:?}");
    }

    /// Round-51 §3.5: simple alternation — A, B, A, B, … — is the
    /// canonical agent-loop shape and previously NEVER tripped the
    /// breaker in the default build (only the immediately-preceding
    /// embedding was compared; the cross-history path needed a Qdrant
    /// sink). The recent-embedding window must catch it.
    #[test]
    fn simple_alternation_trips_the_breaker() {
        let s = SessionLoopState::new(cfg());
        let e = HashEmbedder::default();
        let a = "check the deployment status of service alpha again";
        let b = "list the open incidents for service alpha again";
        let mut tripped = false;
        for _ in 0..8 {
            if matches!(s.observe(&e, a, 800), BreakerVerdict::Tripped { .. }) {
                tripped = true;
                break;
            }
            if matches!(s.observe(&e, b, 800), BreakerVerdict::Tripped { .. }) {
                tripped = true;
                break;
            }
        }
        assert!(
            tripped,
            "A,B,A,B alternation ran 16 steps without tripping the breaker"
        );
    }

    /// Round-51 §3.5: `tokens_consumed` is a SESSION floor, not a
    /// per-cycle floor. After an Inject-triggered reset, an agent that
    /// ignores the corrective message must re-trip without having to
    /// burn `min_tokens` again from zero.
    #[test]
    fn token_floor_survives_reset() {
        let s = SessionLoopState::new(cfg());
        let e = HashEmbedder::default();
        let t = "loop loop loop";
        for _ in 0..4 {
            s.observe(&e, t, 500);
        }
        assert_eq!(s.state(), BreakerState::Open);
        s.reset();
        // Post-reset: the window is cleared so the first step is novel,
        // but the token floor is already satisfied — the next streak of
        // `window` duplicates trips WITHOUT further token accumulation.
        s.observe(&e, t, 0);
        s.observe(&e, t, 0);
        s.observe(&e, t, 0);
        let v = s.observe(&e, t, 0);
        assert!(
            matches!(v, BreakerVerdict::Tripped { .. }),
            "an agent ignoring the corrective injection must re-trip without re-earning the token floor: {v:?}"
        );
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
        assert!(matches!(
            s.observe(&e, t, 500),
            BreakerVerdict::Progressing { .. }
        ));
    }

    #[test]
    fn distributed_similarity_detects_periodic_dag_loop() {
        let s = SessionLoopState::new(BreakerConfig {
            window: 2,
            min_tokens: 0,
            ..BreakerConfig::default()
        });
        assert!(matches!(
            s.observe_embedding_with_similarity(vec![1.0, 0.0], 10, None),
            BreakerVerdict::Progressing { .. }
        ));
        assert!(matches!(
            s.observe_embedding_with_similarity(vec![0.0, 1.0], 10, Some(0.99)),
            BreakerVerdict::Suspicious { streak: 1, .. }
        ));
        assert!(matches!(
            s.observe_embedding_with_similarity(vec![-1.0, 0.0], 10, Some(0.99)),
            BreakerVerdict::Tripped { streak: 2, .. }
        ));
    }

    /// A hostile / misconfigured embedder that returns all-zero vectors
    /// (the ONNX embedder's error fallback) or NaN/Inf vectors must not
    /// let a caller drive the breaker into "novel-forever" mode.
    /// Zero-vector adjacent delta is `1.0 - cosine(0, 0)`; `cosine`
    /// short-circuits `0.0` on either magnitude, so the raw delta is
    /// `1.0` — full novelty on every step, streak never grows, breaker
    /// never trips. NaN vectors take the clamp path and produce NaN
    /// deltas which compare false against `delta_epsilon`, same effect.
    /// Fail-closed: treat both as maximum suspicion (delta = 0).
    #[test]
    fn all_zero_embedding_does_not_defeat_the_breaker() {
        let s = SessionLoopState::new(BreakerConfig {
            window: 3,
            min_tokens: 0,
            ..BreakerConfig::default()
        });
        // Three consecutive all-zero steps must trip, not walk indefinitely.
        for _ in 0..2 {
            let verdict = s.observe_embedding_with_similarity(vec![0.0; 4], 10, None);
            assert!(
                matches!(
                    verdict,
                    BreakerVerdict::Suspicious { .. } | BreakerVerdict::Progressing { .. }
                ),
                "unexpected verdict during buildup: {verdict:?}"
            );
        }
        let final_verdict = s.observe_embedding_with_similarity(vec![0.0; 4], 10, None);
        assert!(
            matches!(final_verdict, BreakerVerdict::Tripped { .. }),
            "3rd all-zero step must trip the breaker, got {final_verdict:?}"
        );
    }

    #[test]
    fn nan_embedding_does_not_defeat_the_breaker() {
        let s = SessionLoopState::new(BreakerConfig {
            window: 2,
            min_tokens: 0,
            ..BreakerConfig::default()
        });
        // First step establishes prev_embedding.
        let _ = s.observe_embedding_with_similarity(vec![1.0, 0.0], 10, None);
        // Two NaN steps: treated as duplicate (delta = 0), streak grows.
        let _ = s.observe_embedding_with_similarity(vec![f32::NAN, 0.0], 10, None);
        let tripped = s.observe_embedding_with_similarity(vec![0.0, f32::NAN], 10, None);
        assert!(
            matches!(tripped, BreakerVerdict::Tripped { .. }),
            "NaN vectors must not slip past the breaker; got {tripped:?}"
        );
    }
}

#[cfg(test)]
mod similarity_path_tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]

    use super::*;

    /// Mutation-run hardening (round 12): the Qdrant-similarity arm
    /// (`1.0 - similarity`) had no direct test — a mutant deleting the
    /// subtraction turns "nearly identical to history" (similarity ~1,
    /// delta ~0) into "maximum novelty" (delta ~1) and the breaker
    /// never trips through the vector-store path. Feed orthogonal
    /// adjacent embeddings (adjacent delta = 1.0: never trips) with
    /// near-1 nearest_similarity and require the trip; then prove
    /// near-0 similarity does NOT trip.
    #[test]
    fn near_duplicate_history_similarity_trips_the_breaker() {
        let cfg = BreakerConfig {
            min_tokens: 100,
            ..BreakerConfig::default()
        };
        let looping = SessionLoopState::new(cfg.clone());
        let mut tripped = false;
        for step in 0..8u32 {
            // Orthogonal one-hot embeddings: adjacent cosine = 0, so
            // only the similarity path can produce a small delta.
            let mut e = vec![0.0f32; 16];
            e[(step as usize) % 16] = 1.0;
            let verdict = looping.observe_embedding_with_similarity(e, 50, Some(0.999));
            if matches!(verdict, BreakerVerdict::Tripped { .. }) {
                tripped = true;
                break;
            }
        }
        assert!(
            tripped,
            "similarity ~1 against history must trip within the window"
        );

        let progressing = SessionLoopState::new(cfg);
        for step in 0..8u32 {
            let mut e = vec![0.0f32; 16];
            e[(step as usize) % 16] = 1.0;
            let verdict = progressing.observe_embedding_with_similarity(e, 50, Some(0.01));
            assert!(
                !matches!(verdict, BreakerVerdict::Tripped { .. }),
                "low similarity must not trip"
            );
        }
    }
}
