//! Rambling / loop-breaker stress test: dissimilar surface forms with the
//! same underlying meaning.
//!
//! The hash-based reference embedder computes similarity from character
//! 3-5-gram overlap. When an adversarial agent (or a well-drilled LLM)
//! paraphrases an intent using entirely different vocabulary, the surface
//! n-grams no longer overlap, cosine similarity collapses, and the breaker
//! sees each step as "progress". This suite characterizes that
//! false-negative surface so any future embedding change is measured
//! against a real evasion corpus.
//!
//! The tests here are permissive assertions on hash-embedder behavior
//! (they LOCK the documented limitation) and would be tightened once the
//! ONNX embedder is available — see the ONNX path in `sla.rs`.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use av_loopdetect::{cosine, BreakerConfig, BreakerVerdict, Embedder, HashEmbedder, SessionLoopState};

/// 15 semantic-paraphrase pairs. Each pair says the same thing using
/// deliberately non-overlapping vocabulary and structure. Trivial function
/// words (`the`, `a`, `to`, `for`) are the only bytes intentionally shared.
fn dissimilar_but_same_meaning_pairs() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "The billing database has stale records that need cleanup.",
            "Old rows in our invoice storage should be purged.",
        ),
        (
            "I should retry fetching the customer profile from the identity service.",
            "Let me attempt another lookup against the auth backend for that user.",
        ),
        (
            "The payment processor keeps returning error 502 for these charges.",
            "Bad gateway responses persist when we try to authorise those transactions.",
        ),
        (
            "Please summarise the quarterly financial report for the executive briefing.",
            "Condense Q3 fiscal figures into a leadership overview.",
        ),
        (
            "The warehouse inventory count does not match the ledger totals.",
            "Physical stock levels diverge from what accounting shows on the books.",
        ),
        (
            "Investigate why the deployment pipeline is stuck on the canary phase.",
            "Look into the release rollout hanging during limited-audience validation.",
        ),
        (
            "Send an escalation notice to the on-call engineer about the outage.",
            "Page whoever is holding the beeper and inform them of the service degradation.",
        ),
        (
            "The recommendation engine keeps suggesting the same three products.",
            "Our personalisation system is stuck offering an identical trio of items.",
        ),
        (
            "Cancel the pending shipment before it leaves the fulfilment centre.",
            "Halt the in-progress delivery while it is still inside the distribution hub.",
        ),
        (
            "Translate the user-facing error message into French for the Paris launch.",
            "Localise the on-screen alert copy into français ahead of the Parisian release.",
        ),
        (
            "The clustering algorithm is not converging within the iteration budget.",
            "Our unsupervised grouping model fails to stabilise inside the compute cap.",
        ),
        (
            "Verify the customer's email address before granting account access.",
            "Confirm the correspondence identifier held by the client prior to permitting entry.",
        ),
        (
            "The image pipeline is dropping frames intermittently under load.",
            "Photo processing loses occasional captures when the system is busy.",
        ),
        (
            "Roll back the schema migration; production is throwing constraint errors.",
            "Reverse the table structure change because live traffic keeps failing integrity checks.",
        ),
        (
            "Warm the cache with yesterday's most-requested articles before the morning peak.",
            "Preload popular pieces from the previous day into memory ahead of AM traffic.",
        ),
    ]
}

/// The hash embedder must render dissimilar surface forms as dissimilar
/// vectors — otherwise it would flag genuine progress as a loop. The
/// average cosine across these 15 semantic paraphrases stays well below
/// the "near-duplicate" cutoff of 0.70; the max stays below 0.85.
#[test]
fn dissimilar_paraphrases_produce_low_lexical_similarity() {
    let e = HashEmbedder::default();
    let mut sims: Vec<f32> = Vec::new();
    for (a, b) in dissimilar_but_same_meaning_pairs() {
        let va = e.embed(a);
        let vb = e.embed(b);
        let s = cosine(&va, &vb);
        assert!(
            (-1.0..=1.0).contains(&s),
            "cosine out of range for {a:?} vs {b:?}: {s}",
        );
        sims.push(s);
    }
    #[allow(clippy::cast_precision_loss)]
    let avg = sims.iter().sum::<f32>() / sims.len() as f32;
    let max = sims.iter().copied().fold(f32::NEG_INFINITY, f32::max);
    println!("dissimilar-paraphrase hash similarity: avg={avg:.3}, max={max:.3}");
    assert!(
        avg < 0.30,
        "hash embedder unexpectedly matched dissimilar paraphrases (avg cosine {avg:.3})",
    );
    assert!(
        max < 0.85,
        "hash embedder produced a near-duplicate score {max:.3} for a dissimilar-word pair — \
         either the corpus is not adversarial enough or the embedder changed",
    );
}

/// End-to-end evasion: an agent cycling through semantically equivalent
/// but lexically dissimilar restatements is essentially not caught by the
/// hash breaker (at most one coincidental trip is tolerated). This
/// documents the residual false-negative surface: any
/// deployment relying on real semantic loop detection must enable the
/// ONNX embedder (see `sla::production_onnx_model_meets_loop_sla`).
#[test]
fn hash_breaker_does_not_catch_dissimilar_paraphrase_rotation() {
    let cfg = BreakerConfig {
        min_tokens: 500,
        ..BreakerConfig::default()
    };
    let e = HashEmbedder::default();
    let mut trips = 0;
    let pairs = dissimilar_but_same_meaning_pairs();
    // 30 steps: walk the pairs, emitting each pair's two same-meaning
    // restatements back to back (a0, b0, a1, b1, …) so semantically
    // equivalent texts really do appear on consecutive steps.
    let session = SessionLoopState::new(cfg);
    for i in 0..30 {
        let (a, b) = pairs[(i / 2) % pairs.len()];
        let step = if i % 2 == 0 { a } else { b };
        if let BreakerVerdict::Tripped { .. } = session.observe(&e, step, 400) {
            trips += 1;
        }
    }
    // We expect zero trips (n-gram overlap is too low). Allow up to one for
    // fold-in-connective-word coincidence; anything above documents drift.
    assert!(
        trips <= 1,
        "hash embedder unexpectedly caught semantic paraphrase rotation ({trips} trips); \
         if it does now, tighten the evasion corpus or celebrate progress",
    );
}

/// Sensitivity floor: lexically similar but semantically OPPOSITE
/// statements should NOT collapse to identical vectors — that would be
/// the mirror-image failure (false positive risk). Locks the "hash
/// embedder distinguishes negation" property so a refactor that
/// dropped stop words or reduced n-gram range would fail this test.
#[test]
fn semantically_opposite_but_lexically_similar_statements_still_show_meaningful_delta() {
    let e = HashEmbedder::default();
    let pairs = [
        (
            "The migration succeeded and every row was written.",
            "The migration failed and no rows were written.",
        ),
        (
            "The API returned 200 with the full user list.",
            "The API returned 500 and no data was returned.",
        ),
        (
            "The customer confirmed the purchase.",
            "The customer canceled the purchase.",
        ),
        (
            "Deploy the change to production now.",
            "Do not deploy the change to production now.",
        ),
    ];
    for (a, b) in pairs {
        let sim = cosine(&e.embed(a), &e.embed(b));
        let delta = 1.0 - sim;
        // These share MANY n-grams so sim is naturally high; but a healthy
        // embedder still leaves a non-trivial delta rather than collapsing
        // to 1.0.
        assert!(
            (0.001..0.999).contains(&delta),
            "delta {delta} between opposites {a:?} vs {b:?} is degenerate",
        );
    }
}

/// Adversarial cycle: an attacker who KNOWS the hash embedder is
/// character-n-gram-based can still be caught if they leave enough
/// character skeleton in place. Rewording that preserves >70% of the
/// character 3-grams — a plausible LLM behavior when brainstorming
/// mid-sentence variations — must still trip the breaker. Locks the
/// per-step Δ ceiling so any regression that de-tunes the hash embedder
/// away from n-gram overlap will be flagged.
#[test]
fn shallow_character_reshuffle_still_trips_the_breaker() {
    let cfg = BreakerConfig {
        min_tokens: 200,
        ..BreakerConfig::default()
    };
    let e = HashEmbedder::default();
    let session = SessionLoopState::new(cfg);

    // Six ways to nudge the same sentence at the character level — each
    // preserves most 3-grams so cosine stays high.
    let shallow = [
        "I will retry the database query for the pending orders now",
        "I will  retry the database query for the pending orders now",
        "I  will retry the database query for the pending orders now",
        "i will retry the database query for the pending orders now",
        "I will retry the database  query for the pending orders now",
        "I will retry the database query for the pending orders now.",
    ];
    let mut tripped = false;
    for _ in 0..2 {
        for text in shallow {
            if let BreakerVerdict::Tripped { .. } = session.observe(&e, text, 200) {
                tripped = true;
                break;
            }
        }
        if tripped {
            break;
        }
    }
    assert!(
        tripped,
        "shallow reshuffle failed to trip: the hash embedder must catch character-level jitter \
         (this is its primary competency)",
    );
}
