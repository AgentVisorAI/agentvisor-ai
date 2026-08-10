//! Calibration regression test: the Δ separation between paraphrase loops and
//! progressing work must stay wide enough for the default ε = 0.30 to be safe
//! on both sides. Measured on 2026-08-10: paraphrase 0.13–0.18, progressing
//! 0.88–0.98. If an embedder change erodes this margin, this test fails before
//! any SLA does.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use ab_loopdetect::{cosine, Embedder, HashEmbedder};

#[test]
fn delta_separation_margin_holds() {
    let e = HashEmbedder::default();
    let paraphrase = [
        "I should check the inventory service for stock level of SKU 12345",
        "Let me check the inventory service for stock level of SKU 12345",
        "Okay, I will check the inventory service for stock level of SKU 12345",
        "Next step: check the inventory service for stock level of SKU 12345",
        "I need to check the inventory service for stock level of SKU 12345 now",
        "Proceeding to check the inventory service for stock level of SKU 12345",
    ];
    let progressing = [
        "Read the ticket: user reports login failures since the 14:00 deploy",
        "Pulled auth-service logs; 401 spike correlates with JWT clock skew errors",
        "Found the cause: the new pod image has no NTP sync; drift is 42 seconds",
        "Patched the base image with chrony and redeployed to staging",
        "Staging verifies clean; promoting to production and watching error rates",
    ];
    let deltas = |steps: &[&str]| -> Vec<f32> {
        steps.windows(2).map(|w| 1.0 - cosine(&e.embed(w[0]), &e.embed(w[1]))).collect()
    };
    let para = deltas(&paraphrase);
    let prog = deltas(&progressing);
    println!("paraphrase deltas: {para:?}");
    println!("progressing deltas: {prog:?}");
    // Both sides must clear ε = 0.30 with ≥ 0.05 margin.
    for d in &para {
        assert!(*d < 0.25, "paraphrase delta {d} too close to ε=0.30");
    }
    for d in &prog {
        assert!(*d > 0.35, "progressing delta {d} too close to ε=0.30");
    }
}
