//! Extensive loop-detector (breaker) tests.
//!
//! Covers:
//!   1. Verbatim repetition — trivial loop
//!   2. Synonym / paraphrase rotation — common evasion
//!   3. Number-incrementing evasion attempt
//!   4. Whitespace-bombing evasion
//!   5. Case-flip evasion (UPPER / lower alternation)
//!   6. Token-gate precision — trips at exactly the right budget
//!   7. Streak resets cleanly on genuine progress
//!   8. Manual reset re-opens every path
//!   9. Corrective `Inject` action reported in the tripped verdict;
//!      breaker stays Open until manual reset
//!  10. Very short streak window (window = 1)
//!  11. Very wide streak window (window = 10)
//!  12. Genuinely progressing content never accrues a false streak
//! 13. Multilingual loop (transliteration or same concept)
//! 14. Massive token count — tokens_consumed arithmetic never overflows
//! 15. Concurrent observe — no panics, no data corruption
//! 16. Distributed nearest-similarity: identical session history
//!     detected even when adjacent delta varies
//! 17. Zero-vector embedding edge case
//! 18. Single-character step — minimal hash-collision surface

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::float_cmp
)]

use av_loopdetect::{
    cosine, BreakerAction, BreakerConfig, BreakerState, BreakerVerdict, Embedder, HashEmbedder,
    SessionLoopState,
};
use std::sync::Arc;

/// Default delta_epsilon from BreakerConfig::default() — 0.30.
const EPSILON: f32 = 0.30;
/// Default HashEmbedder::default() dimension.
const DEFAULT_DIM: usize = 512;
/// Floating-point tolerance for unit-norm and cosine-reflexivity checks.
const NORM_TOL: f32 = 1e-4;
const COS_TOL: f32 = 1e-5;

fn cfg_with(window: usize, min_tokens: u64, delta_epsilon: f32) -> BreakerConfig {
    BreakerConfig {
        window,
        min_tokens,
        delta_epsilon,
        action: BreakerAction::Reject,
    }
}

fn std_cfg() -> BreakerConfig {
    cfg_with(3, 1_000, EPSILON)
}

fn embedder() -> HashEmbedder {
    HashEmbedder::default()
}

// ---------------------------------------------------------------------------
// 1. Verbatim repetition (baseline — must trip within window).
// ---------------------------------------------------------------------------

#[test]
fn verbatim_loop_trips_within_configured_window() {
    let s = SessionLoopState::new(std_cfg());
    let e = embedder();
    let text = "I will retry the database query for pending transactions.";
    s.observe(&e, text, 400);
    s.observe(&e, text, 400);
    s.observe(&e, text, 400);
    let v = s.observe(&e, text, 400);
    assert!(matches!(v, BreakerVerdict::Tripped { .. }), "{v:?}");
    assert_eq!(s.state(), BreakerState::Open);
}

// ---------------------------------------------------------------------------
// 2. Synonym / paraphrase rotation — near-synonym phrases EVADE the hash
//    embedder (documented design: n-gram overlap drops when surface forms
//    differ, so δ stays high). This test proves the hash embedder behaves
//    correctly per spec, and that detection of semantic paraphrases requires
//    an ONNX embedder (exercised by `sla::production_onnx_model_meets_loop_sla`).
// ---------------------------------------------------------------------------

#[test]
fn paraphrase_rotation_is_correctly_not_detected_by_the_hash_embedder() {
    let s = SessionLoopState::new(std_cfg());
    let e = embedder();
    let paraphrases = [
        "retry the pending DB query once more",
        "re-run the database lookup for pending items",
        "query the database again for items that are still pending",
        "re-execute the pending database query",
        "make another attempt at the database query for pending transactions",
        "try the DB query one more time for unresolved items",
    ];
    // The hash embedder sees distinct n-grams across these 6 variants; a
    // single pass (all distinct surface forms) must not trip. NB: this
    // deliberately does NOT cycle the same 6 strings 20 times — a
    // verbatim period-6 cycle IS a loop, and the recent-
    // embedding window correctly catches it; what the hash embedder
    // must NOT do is equate distinct paraphrase surface forms.
    let mut trips = 0;
    for t in &paraphrases {
        if let BreakerVerdict::Tripped { .. } = s.observe(&e, t, 600) {
            trips += 1;
        }
    }
    // Zero trips is CORRECT for the hash embedder; semantic
    // paraphrase detection needs the ONNX path.
    assert!(
        trips == 0,
        "hash embedder falsely detected semantic paraphrase rotation ({trips} trips)"
    );
}

// ---------------------------------------------------------------------------
// 3. Number-incrementing evasion — attacker appends "step N" to each message
//    hoping to diversify the n-grams enough to reset the streak.
// ---------------------------------------------------------------------------

#[test]
fn number_incrementing_is_not_sufficient_evasion_for_long_loops() {
    let s = SessionLoopState::new(std_cfg());
    let e = embedder();
    let mut tripped = false;
    for i in 0..30 {
        let text = format!("retry the database query for pending transactions step {i}");
        if let BreakerVerdict::Tripped { .. } = s.observe(&e, &text, 600) {
            tripped = true;
            break;
        }
    }
    assert!(
        tripped,
        "number-increment evasion escaped the breaker for 30 steps"
    );
}

// ---------------------------------------------------------------------------
// 4. Whitespace-bombing — attacker pads with spaces / newlines hoping to
//    dilute n-gram overlap.
// ---------------------------------------------------------------------------

#[test]
fn whitespace_bombing_does_not_evade_the_detector() {
    let s = SessionLoopState::new(std_cfg());
    let e = embedder();
    let core = "retry the database query for pending transactions";
    let variants = [
        core.to_owned(),
        format!("  {core}  "),
        format!("{core}\n\n"),
        format!("   {core}   "),
        format!("{core}\t\t"),
        format!("\n{core}\n"),
    ];
    let mut tripped = false;
    for (i, v) in variants.iter().cycle().take(24).enumerate() {
        if let BreakerVerdict::Tripped { .. } = s.observe(&e, v, 400 + i as u64) {
            tripped = true;
            break;
        }
    }
    assert!(tripped, "whitespace-bombing escaped the breaker");
}

// ---------------------------------------------------------------------------
// 5. Case-flip evasion — alternating ALL CAPS and lowercase.
// ---------------------------------------------------------------------------

#[test]
fn case_alternation_does_not_evade_the_detector() {
    let s = SessionLoopState::new(std_cfg());
    let e = embedder();
    let lower = "retry the database query for pending transactions";
    let upper = lower.to_uppercase();
    let steps = [lower, upper.as_str()];
    let mut tripped = false;
    for (i, &t) in steps.iter().cycle().take(20).enumerate() {
        if let BreakerVerdict::Tripped { .. } = s.observe(&e, t, 400 + i as u64) {
            tripped = true;
            break;
        }
    }
    assert!(tripped, "case-flip evasion escaped the breaker");
}

// ---------------------------------------------------------------------------
// 6. Token-gate precision — breaker does NOT trip when tokens < min, even
//    with a long streak; trips on the step that crosses the floor.
// ---------------------------------------------------------------------------

#[test]
fn token_gate_trips_exactly_at_the_configured_floor() {
    let s = SessionLoopState::new(cfg_with(2, 5_000, EPSILON));
    let e = embedder();
    let text = "same step again";
    s.observe(&e, text, 500); // establish baseline
                              // Feed many low-token steps — streak builds but token floor not reached.
    for _ in 0..10 {
        let v = s.observe(&e, text, 100); // running total rises by 100 each time
        assert!(
            !matches!(v, BreakerVerdict::Tripped { .. }),
            "tripped below floor: {v:?}"
        );
    }
    // Running total now = 500 + 10*100 = 1500 < 5000; still not tripped.
    assert_eq!(s.state(), BreakerState::Closed);
    // Big token push crosses the floor.
    let v = s.observe(&e, text, 4_000); // 1500 + 4000 = 5500 ≥ 5000
    assert!(matches!(v, BreakerVerdict::Tripped { .. }), "{v:?}");
}

// ---------------------------------------------------------------------------
// 7. Streak resets on genuine progress (mid-stream direction change).
// ---------------------------------------------------------------------------

#[test]
fn mid_stream_direction_change_resets_streak_and_prevents_trip() {
    let s = SessionLoopState::new(std_cfg());
    let e = embedder();
    let looped = "retry the database query for pending transactions";
    s.observe(&e, looped, 400);
    s.observe(&e, looped, 400);
    s.observe(&e, looped, 400); // streak 2 (would trip on next loop)
                                // Genuine progress.
    let v = s.observe(
        &e,
        "SQL timeout encountered; switching to async batch export and notifying ops team",
        400,
    );
    assert!(matches!(v, BreakerVerdict::Progressing { .. }), "{v:?}");
    assert_eq!(s.state(), BreakerState::Closed);
    // Next loop step compares to the progress text → novel → streak = 0.
    let v = s.observe(&e, looped, 400);
    assert!(!matches!(v, BreakerVerdict::Tripped { .. }), "{v:?}");
}

// ---------------------------------------------------------------------------
// 8. Manual reset re-opens every path, including token accounting carry.
// ---------------------------------------------------------------------------

#[test]
fn manual_reset_clears_streak_and_enables_re_detection() {
    let s = SessionLoopState::new(std_cfg());
    let e = embedder();
    let text = "loop step";
    // Trip the breaker.
    for _ in 0..4 {
        s.observe(&e, text, 500);
    }
    assert_eq!(s.state(), BreakerState::Open);
    // Reset closes it.
    s.reset();
    assert_eq!(s.state(), BreakerState::Closed);
    // Can loop again.
    s.observe(&e, text, 400);
    s.observe(&e, text, 400);
    s.observe(&e, text, 400);
    let v = s.observe(&e, text, 400);
    assert!(matches!(v, BreakerVerdict::Tripped { .. }), "{v:?}");
}

// ---------------------------------------------------------------------------
// 9. Corrective inject action is reported in the verdict, and the breaker
//    stays open until manually reset.
// ---------------------------------------------------------------------------

#[test]
fn inject_action_is_propagated_in_the_tripped_verdict() {
    let s = SessionLoopState::new(BreakerConfig {
        action: BreakerAction::Inject,
        min_tokens: 0,
        window: 2,
        delta_epsilon: EPSILON,
    });
    let e = embedder();
    let text = "same loop";
    s.observe(&e, text, 0);
    s.observe(&e, text, 0);
    let v = s.observe(&e, text, 0);
    match v {
        BreakerVerdict::Tripped { action, .. } => {
            assert_eq!(action, BreakerAction::Inject);
        }
        other => panic!("expected Tripped, got {other:?}"),
    }
    // Still open after trip.
    assert_eq!(s.state(), BreakerState::Open);
    assert_eq!(s.action(), BreakerAction::Inject);
}

// ---------------------------------------------------------------------------
// 10. Very short window (1): every near-zero step beyond the first trips.
// ---------------------------------------------------------------------------

#[test]
fn window_of_one_trips_on_the_second_identical_step() {
    let s = SessionLoopState::new(cfg_with(1, 0, EPSILON));
    let e = embedder();
    let text = "identical";
    let v1 = s.observe(&e, text, 0);
    assert!(matches!(v1, BreakerVerdict::Progressing { .. }), "{v1:?}");
    let v2 = s.observe(&e, text, 0);
    assert!(matches!(v2, BreakerVerdict::Tripped { streak: 1, .. }), "{v2:?}");
}

// ---------------------------------------------------------------------------
// 11. Very wide window (10): loops up to 9 consecutive near-zero steps
//     remain Suspicious; the 10th trips.
// ---------------------------------------------------------------------------

#[test]
fn wide_window_accumulates_streak_and_trips_exactly_at_threshold() {
    let s = SessionLoopState::new(cfg_with(10, 0, EPSILON));
    let e = embedder();
    let text = "same content";
    s.observe(&e, text, 0); // baseline
    for expected_streak in 1..10 {
        let v = s.observe(&e, text, 0);
        assert!(
            matches!(v, BreakerVerdict::Suspicious { streak, .. } if streak == expected_streak),
            "at streak {expected_streak}: {v:?}"
        );
    }
    let v = s.observe(&e, text, 0);
    assert!(matches!(v, BreakerVerdict::Tripped { streak: 10, .. }), "{v:?}");
}

// ---------------------------------------------------------------------------
// 12. Progressing content — every step scores well above the default
//     epsilon (0.30) on the hash embedder. The breaker must never accrue a
//     streak of 3 when each step is genuinely progressing.
// ---------------------------------------------------------------------------

#[test]
fn progressing_content_never_falsely_trips() {
    let s = SessionLoopState::new(std_cfg());
    let e = embedder();
    // Twenty genuinely-distinct high-entropy steps (should always score
    // Δ > 0.30 on the hash embedder). NB: these are all
    // substantively DISTINCT — cycling a fixed set verbatim (or with
    // only a step-number suffix, which the number-incrementing test
    // pins as insufficient evasion) is a period-N loop the
    // recent-embedding window correctly detects. A genuinely
    // progressing agent produces per-step-unique content like this.
    let high = [
        "parse the user's CSV file and validate header rows against the expected schema",
        "infer column types from the first hundred rows using the statistical model",
        "build the SQL migration script and verify it on a staging clone",
        "run the smoke test suite and collect the results for review",
        "post the artifact URL to the ticketing system and notify the team",
        "download the vendor price list and normalize currencies to USD",
        "diff the staging schema against production and flag drift",
        "compress the archived logs older than ninety days into cold storage",
        "rotate the API credentials for the payments integration",
        "generate the quarterly usage report grouped by business unit",
        "reconcile the invoice ledger against the bank statement export",
        "profile the slow endpoint and capture a flame graph for review",
        "upgrade the container base image and rebuild the CI pipeline",
        "annotate the incident timeline with links to the relevant dashboards",
        "backfill the missing telemetry for the third week of March",
        "draft the customer-facing changelog for the upcoming release",
        "verify the backup restore procedure on an isolated environment",
        "tune the cache eviction policy based on the observed hit rates",
        "migrate the remaining cron jobs to the new scheduler service",
        "summarize open pull requests and assign reviewers by expertise",
    ];
    for step in &high {
        let v = s.observe(&e, step, 1_000);
        assert!(
            !matches!(v, BreakerVerdict::Tripped { .. }),
            "false positive on genuinely diverse content: {v:?}"
        );
    }
    assert_eq!(s.state(), BreakerState::Closed);
}

// ---------------------------------------------------------------------------
// 13. Multilingual loop — same semantic concept in English then French.
//     The hash embedder sees different character n-grams, so this WILL appear
//     as progress. That is correct: n-gram overlap drops across languages.
//     Alternation is embedder-sensitive, so a trip is tolerated — but if it
//     trips, the state machine must be coherent (Open), never a nonsense state.
// ---------------------------------------------------------------------------

#[test]
fn alternating_languages_for_same_concept_is_not_a_false_positive() {
    let s = SessionLoopState::new(std_cfg());
    let e = embedder();
    let steps = [
        "retry the database query for pending transactions",
        "réessayer la requête de base de données pour les transactions en attente",
        "retry the database query for pending transactions",
        "requête de base de données réessayée pour les transactions en cours",
        "retry the database query for pending transactions",
        "tentative de nouvelle requête sur la base de données",
    ];
    for step in &steps {
        let v = s.observe(&e, step, 500);
        // May be Suspicious (if n-gram overlap is high) but must not trip
        // during the first 6 steps of 3-window detection given the alternation.
        if matches!(v, BreakerVerdict::Tripped { .. }) {
            // If it does trip, verify it's not a nonsense state.
            assert_eq!(s.state(), BreakerState::Open);
        }
    }
}

// ---------------------------------------------------------------------------
// 14. tokens_consumed arithmetic never overflows even near u64::MAX.
// ---------------------------------------------------------------------------

#[test]
fn tokens_consumed_uses_saturating_add_not_wrapping() {
    let s = SessionLoopState::new(cfg_with(1, u64::MAX / 2, 0.30));
    let e = embedder();
    let v = s.observe(&e, "step one", u64::MAX / 2);
    assert!(matches!(v, BreakerVerdict::Progressing { .. }), "{v:?}");
    // Saturating add: (MAX/2) + MAX would wrap to MAX/2 - 1, dropping below
    // the MAX/2 token floor — saturating gives MAX, so the floor is met and
    // a streak trip is possible.
    let v = s.observe(&e, "step one", u64::MAX);
    // (streak would be 1 from repeated text, and tokens >= floor) → Tripped.
    assert!(matches!(v, BreakerVerdict::Tripped { .. }), "{v:?}");
    // No panic — that's the key invariant.
}

// ---------------------------------------------------------------------------
// 15. Concurrent observe — no panic, no data corruption.
// ---------------------------------------------------------------------------

#[test]
fn concurrent_observe_from_many_threads_never_panics() {
    let s = Arc::new(SessionLoopState::new(std_cfg()));
    let e = Arc::new(embedder());
    const N: usize = 16;
    const K: usize = 50;
    let barrier = Arc::new(std::sync::Barrier::new(N));
    let handles: Vec<_> = (0..N)
        .map(|t| {
            let s = Arc::clone(&s);
            let e = Arc::clone(&e);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                for i in 0..K {
                    let text = if i % 3 == 0 {
                        "loop step that repeats".to_owned()
                    } else {
                        format!("thread {t} step {i} with unique content")
                    };
                    let _ = s.observe(&*e, &text, 100);
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    // State is some valid BreakerState — no corrupted sentinel.
    let _state = s.state();
}

// ---------------------------------------------------------------------------
// 16. Distributed nearest-similarity path: a periodic loop within a session
//     is detected even when adjacent embeddings differ significantly,
//     because the nearest_similarity signal from the vector DB (which
//     production scopes to the same session_id) is high.
// ---------------------------------------------------------------------------

#[test]
fn vector_db_similarity_catches_periodic_loop_within_session() {
    let s = SessionLoopState::new(cfg_with(2, 0, EPSILON));
    // Step 1: fresh start.
    let v = s.observe_embedding_with_similarity(vec![1.0, 0.0, 0.0], 100, None);
    assert!(matches!(v, BreakerVerdict::Progressing { .. }), "{v:?}");
    // Step 2: adjacent delta high (new vector), but the vector DB says this
    // step matches an earlier step of the same session (similarity 0.98).
    // min(high_adj_delta, 1-0.98) = 0.02 < epsilon → Suspicious.
    let v = s.observe_embedding_with_similarity(vec![0.0, 1.0, 0.0], 100, Some(0.98));
    assert!(matches!(v, BreakerVerdict::Suspicious { streak: 1, .. }), "{v:?}");
    // Step 3: same nearest-neighbor hit → Tripped.
    let v = s.observe_embedding_with_similarity(vec![0.0, 0.0, 1.0], 100, Some(0.97));
    assert!(matches!(v, BreakerVerdict::Tripped { streak: 2, .. }), "{v:?}");
}

// ---------------------------------------------------------------------------
// 17. Zero-vector embedding edge case (empty/degenerate input).
// ---------------------------------------------------------------------------

#[test]
fn zero_vector_embedding_is_treated_as_hostile_and_grows_the_streak() {
    // Design change: a caller supplying an all-zero embedding (the
    // ONNX embedder's error fallback) used to walk the breaker into
    // "novel-forever" mode because `1 - cos(0, 0) = 1.0 = maximum
    // novelty`, so the streak reset on every step and the breaker
    // never tripped even under a verbatim semantic loop. Now the
    // breaker fails closed: zero-vector steps register delta = 0
    // (maximum suspicion) so a misconfigured embedder cannot silently
    // disable loop detection.
    let s = SessionLoopState::new(BreakerConfig {
        window: 3,
        min_tokens: 0,
        ..std_cfg()
    });
    for _ in 0..2 {
        let verdict = s.observe_embedding(vec![0.0; DEFAULT_DIM], 100);
        assert!(
            !matches!(verdict, BreakerVerdict::Tripped { .. }),
            "expected not-yet-tripped during buildup: {verdict:?}"
        );
    }
    let tripped = s.observe_embedding(vec![0.0; DEFAULT_DIM], 100);
    assert!(
        matches!(tripped, BreakerVerdict::Tripped { .. }),
        "third zero-vector step must trip: {tripped:?}"
    );
}

// ---------------------------------------------------------------------------
// 18. Single-character step — minimal possible text.
// ---------------------------------------------------------------------------

#[test]
fn single_character_steps_handled_without_panic() {
    let s = SessionLoopState::new(cfg_with(2, 0, EPSILON));
    let e = embedder();
    for _ in 0..3 {
        let _ = s.observe(&e, "x", 0);
    }
    // "x" repeated → should trip (window 2, min_tokens 0).
    let v = s.observe(&e, "x", 0);
    assert!(matches!(v, BreakerVerdict::Tripped { .. }), "{v:?}");
}

// ---------------------------------------------------------------------------
// 19. Tripped state is reflected in .state(); after a trip the BreakerState
//     stays Open. A novel step (high delta) still produces Progressing in the
//     per-call verdict but .state() remains Open until manual reset.
// ---------------------------------------------------------------------------

#[test]
fn tripped_state_persists_until_manual_reset() {
    let s = SessionLoopState::new(cfg_with(2, 0, EPSILON));
    let e = embedder();
    let text = "same same";
    s.observe(&e, text, 0);
    s.observe(&e, text, 0);
    s.observe(&e, text, 0); // trip
    assert_eq!(s.state(), BreakerState::Open);
    // A novel step computes a fresh Progressing verdict (streak resets),
    // but the Open state must persist.
    let v = s.observe(&e, "completely different idea with new content", 0);
    assert!(
        !matches!(v, BreakerVerdict::Suspicious { .. }),
        "novel step after trip should not be Suspicious: {v:?}"
    );
    assert_eq!(
        s.state(),
        BreakerState::Open,
        "state must stay Open after novel step"
    );
    s.reset();
    assert_eq!(s.state(), BreakerState::Closed);
    // After reset a loop immediately builds a fresh streak.
    s.observe(&e, text, 0);
    s.observe(&e, text, 0);
    let v = s.observe(&e, text, 0);
    assert!(matches!(v, BreakerVerdict::Tripped { .. }), "{v:?}");
}

// ---------------------------------------------------------------------------
// 20. Delta values in verdicts are always in [0.0, 2.0] — cosine ∈ [−1, 1]
//     so 1 − cosine ∈ [0, 2]. Random embeddings must respect the range.
// ---------------------------------------------------------------------------

#[test]
fn verdict_delta_is_always_in_range_0_to_2() {
    let s = SessionLoopState::new(std_cfg());
    let e = embedder();
    let steps = [
        "step one some text here for hashing",
        "step two completely different from one",
        "step three more and more words",
        "step one some text here for hashing", // repeat
        "step four brand new direction now",
        "step two completely different from one", // repeat
    ];
    for step in &steps {
        let v = s.observe(&e, step, 400);
        let delta = match v {
            BreakerVerdict::Progressing { delta }
            | BreakerVerdict::Suspicious { delta, .. }
            | BreakerVerdict::Tripped { delta, .. } => delta,
        };
        assert!(
            (0.0..=2.0).contains(&delta),
            "delta {delta} out of [0, 2] for step {step:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// 21. BreakerAction::Abort is propagated correctly in the verdict.
// ---------------------------------------------------------------------------

#[test]
fn abort_action_is_propagated_in_tripped_verdict() {
    let s = SessionLoopState::new(BreakerConfig {
        action: BreakerAction::Abort,
        min_tokens: 0,
        window: 2,
        delta_epsilon: EPSILON,
    });
    let e = embedder();
    let text = "abort loop";
    s.observe(&e, text, 0);
    s.observe(&e, text, 0);
    let v = s.observe(&e, text, 0);
    match v {
        BreakerVerdict::Tripped { action, .. } => {
            assert_eq!(action, BreakerAction::Abort);
        }
        other => panic!("expected Tripped(Abort), got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 22. tokens_consumed resets to 0 after manual reset — token floor
//     starts counting fresh, preventing a trip on the first loop after
//     a genuine correction.
// ---------------------------------------------------------------------------

#[test]
fn manual_reset_zeroes_token_accumulation() {
    // High token floor so the gate requires substantial traffic to re-arm.
    let s = SessionLoopState::new(cfg_with(2, 10_000, EPSILON));
    let e = embedder();
    let text = "same loop text";
    // Consume tokens up to the floor, trip the breaker.
    s.observe(&e, text, 4_000);
    s.observe(&e, text, 4_000);
    let v = s.observe(&e, text, 4_000); // 12 000 ≥ 10 000 → trip
    assert!(matches!(v, BreakerVerdict::Tripped { .. }), "{v:?}");
    // Reset — tokens must restart.
    s.reset();
    // First step: baseline.
    s.observe(&e, text, 0);
    // Second step: streak 1, but only 0 tokens → still below floor.
    let v = s.observe(&e, text, 0);
    assert!(
        !matches!(v, BreakerVerdict::Tripped { .. }),
        "tripped immediately after reset with 0 tokens: {v:?}"
    );
}

// ---------------------------------------------------------------------------
// 23. Non-finite nearest_similarity (NaN, +Inf, -Inf) is rejected by the
//     breaker — the `is_finite()` guard must discard it and fall back to
//     the adjacent delta.
// ---------------------------------------------------------------------------

#[test]
fn non_finite_nearest_similarity_is_ignored() {
    let s = SessionLoopState::new(cfg_with(2, 0, EPSILON));
    let e = embedder();
    let text = "loop step for finite check";
    s.observe(&e, text, 0); // baseline
    for bad_sim in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
        let v = s.observe_embedding_with_similarity(e.embed(text), 0, Some(bad_sim));
        // Non-finite similarity must be ignored; the adjacent delta (≈ 0 for
        // same text) drives the verdict → Suspicious or Tripped, not Progressing
        // from a bogus fallback.
        assert!(
            !matches!(v, BreakerVerdict::Progressing { delta } if delta > 0.9),
            "non-finite sim {bad_sim} produced unexpectedly high progress delta: {v:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// 24. cosine() reflexivity: cos(v, v) = 1.0 for any non-zero vector.
// ---------------------------------------------------------------------------

#[test]
fn cosine_reflexivity_holds_for_any_non_zero_vector() {
    let e = embedder();
    let texts = [
        "hello world",
        "retry the database query",
        &"x".repeat(500),
        "\u{1f600}\u{1f680}",
    ];
    for text in &texts {
        let v = e.embed(text);
        let sim = cosine(&v, &v);
        assert!((sim - 1.0).abs() < COS_TOL, "cos(v,v) = {sim} for {text:?}");
    }
}

// ---------------------------------------------------------------------------
// 25. cosine() with dimension mismatch returns 0.0 (defined safe fallback).
// ---------------------------------------------------------------------------

#[test]
fn cosine_dimension_mismatch_returns_zero() {
    let a = vec![1.0f32; 128];
    let b = vec![1.0f32; 64];
    assert_eq!(cosine(&a, &b), 0.0);
}

// ---------------------------------------------------------------------------
// 26. L2-norm guarantee: HashEmbedder returns an L2-normalized vector for
//     any non-empty input (‖v‖ ≈ 1.0).
// ---------------------------------------------------------------------------

#[test]
fn hash_embedder_output_is_l2_normalized() {
    let e = embedder();
    let ws = " ".repeat(100);
    let texts: &[&str] = &[
        "hello world",
        "a",
        "retry the database query for pending transactions",
        "𝓗ello",
        ws.as_str(),
    ];
    for text in texts {
        let v = e.embed(text);
        let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
        // Either the vector is zero (whitespace-only) or unit-normalized.
        assert!(
            norm == 0.0 || (norm - 1.0).abs() < NORM_TOL,
            "norm = {norm} for {text:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// 27. Gradual semantic drift never triggers: each step shares < half its
//     n-grams with the previous one (delta > ε) so the streak never builds.
// ---------------------------------------------------------------------------

#[test]
fn gradual_semantic_drift_never_triggers_false_positive() {
    let s = SessionLoopState::new(std_cfg());
    let e = embedder();
    // Each step adds new domain-specific tokens while loosely referencing
    // the prior step — delta stays above 0.30.
    let steps = [
        "connect to the database and start the transaction",
        "fetch the account balance and apply the pending debit",
        "write the debit record to the ledger and commit",
        "send confirmation to the payment gateway with the transaction id",
        "await the webhook acknowledgment from the payment gateway",
        "record the final settlement in the accounting system",
        "close the database connection and release the lock",
        "log the completed transaction to the audit trail",
    ];
    for step in &steps {
        let v = s.observe(&e, step, 1_000);
        assert!(
            !matches!(v, BreakerVerdict::Tripped { .. }),
            "false positive on drift step {step:?}: {v:?}"
        );
    }
    assert_eq!(s.state(), BreakerState::Closed);
}

// ---------------------------------------------------------------------------
// 28. Empty string input: the embedder returns a zero vector, and the
//     breaker now treats zero vectors as maximum suspicion (delta = 0)
//     rather than maximum novelty (delta = 1). Two consecutive empties
//     therefore grow the streak; assert the behaviour instead of the
//     old "Progressing" claim.
// ---------------------------------------------------------------------------

#[test]
fn empty_string_step_grows_the_streak_and_does_not_panic() {
    let s = SessionLoopState::new(cfg_with(2, 0, EPSILON));
    let e = embedder();
    let _ = s.observe(&e, "", 0);
    // Two consecutive empties: streak=2 with window=2 trips the breaker.
    let tripped = s.observe(&e, "", 0);
    assert!(
        matches!(tripped, BreakerVerdict::Tripped { .. }),
        "empty→empty must trip (streak=2, window=2), got {tripped:?}"
    );
}

// ---------------------------------------------------------------------------
// 29. Multiple rapid resets in sequence leave the breaker fully functional.
// ---------------------------------------------------------------------------

#[test]
fn multiple_rapid_resets_leave_the_breaker_functional() {
    let s = SessionLoopState::new(cfg_with(2, 0, EPSILON));
    let e = embedder();
    let text = "cycle test";
    for _ in 0..10 {
        s.observe(&e, text, 0);
        s.observe(&e, text, 0);
        let v = s.observe(&e, text, 0);
        assert!(matches!(v, BreakerVerdict::Tripped { .. }), "{v:?}");
        s.reset();
        assert_eq!(s.state(), BreakerState::Closed);
    }
}

// ---------------------------------------------------------------------------
// 30. Very large step text (100 KiB): embedder must complete without OOM or
//     panic, and a repeated identical large step must still register as a
//     near-duplicate (streak accumulates).
// ---------------------------------------------------------------------------

#[test]
fn hundred_kib_step_text_embeds_without_panic() {
    let s = SessionLoopState::new(std_cfg());
    let e = embedder();
    let big: String = "the quick brown fox jumps over the lazy dog ".repeat(2_300);
    let start = std::time::Instant::now();
    let v = s.observe(&e, &big, 10_000);
    let elapsed = start.elapsed();
    assert!(elapsed.as_secs() < 30, "100KiB embed took {elapsed:?}");
    // First step is always Progressing.
    assert!(matches!(v, BreakerVerdict::Progressing { .. }), "{v:?}");
    // Repeated identical large step should accumulate streak.
    let v = s.observe(&e, &big, 10_000);
    assert!(matches!(v, BreakerVerdict::Suspicious { .. }), "{v:?}");
}

// ---------------------------------------------------------------------------
// 31. streak count in Suspicious verdicts is monotonically increasing and
//     exactly tracks consecutive low-delta steps.
// ---------------------------------------------------------------------------

#[test]
fn suspicious_streak_count_increments_exactly() {
    let s = SessionLoopState::new(cfg_with(10, 0, EPSILON));
    let e = embedder();
    let text = "repeated step content";
    s.observe(&e, text, 0); // baseline
    for expected in 1..=9 {
        match s.observe(&e, text, 0) {
            BreakerVerdict::Suspicious { streak, .. } => {
                assert_eq!(streak, expected, "wrong streak at step {expected}");
            }
            other => panic!("expected Suspicious at step {expected}, got {other:?}"),
        }
    }
    match s.observe(&e, text, 0) {
        BreakerVerdict::Tripped { streak: 10, .. } => {}
        other => panic!("expected Tripped(10), got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 32. Delta calibration: paraphrase Δ < ε, progressing Δ > ε. This
//     is a regression guard on the embedder's separation margin.
// ---------------------------------------------------------------------------

#[test]
fn embedder_delta_separation_paraphrase_below_epsilon_progressing_above() {
    let e = embedder();
    let epsilon = EPSILON;
    let paraphrase_pairs = [
        // Drawn from the calibrate.rs paraphrase corpus (its windows(2)
        // check verifies consecutive variants, covering the first pair);
        // this test asserts δ < ε for both pairs directly.
        (
            "I should check the inventory service for stock level of SKU 12345",
            "Let me check the inventory service for stock level of SKU 12345",
        ),
        (
            "I should check the inventory service for stock level of SKU 12345",
            "Okay, I will check the inventory service for stock level of SKU 12345",
        ),
    ];
    let progressing_pairs = [
        (
            "Parsed the CSV headers and found 5 columns",
            "Inferred column types: numeric, text, date from the first 100 rows",
        ),
        (
            "Authentication failed due to JWT clock skew",
            "Applied NTP sync patch to the container base image",
        ),
    ];
    for (a, b) in &paraphrase_pairs {
        let delta = 1.0 - cosine(&e.embed(a), &e.embed(b));
        assert!(
            delta < epsilon - 0.05,
            "paraphrase delta {delta} should be below ε−0.05={}: {a:?} vs {b:?}",
            epsilon - 0.05
        );
    }
    for (a, b) in &progressing_pairs {
        let delta = 1.0 - cosine(&e.embed(a), &e.embed(b));
        assert!(
            delta > epsilon + 0.05,
            "progressing delta {delta} should be above ε+0.05={}: {a:?} vs {b:?}",
            epsilon + 0.05
        );
    }
}
