#![no_main]
//! `av_compress::compress` documents five hard invariants (lib.rs):
//! byte-identical first system message, byte-identical tail,
//! idempotence, and a never-increasing token count. This target feeds
//! arbitrary JSON payloads (including hostile `messages` shapes:
//! non-object entries, multimodal content arrays, absurd nesting) and
//! asserts every invariant that is checkable without re-implementing
//! the passes. A panic OR an invariant violation is a finding.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(payload) = serde_json::from_slice::<serde_json::Value>(data) else {
        return;
    };
    // Engage the passes on small inputs too — the default 512-token
    // floor would make most fuzz inputs a no-op.
    let cfg = av_compress::CompressionConfig {
        min_tokens_to_engage: 0,
        keep_tail: 2,
        tool_output_stub_threshold: 4,
        ..av_compress::CompressionConfig::default()
    };
    let outcome = av_compress::compress(&payload, &cfg);

    // Invariant 5: output token count never exceeds the input's.
    assert!(
        outcome.tokens_after <= outcome.tokens_before,
        "token count grew: {} -> {}",
        outcome.tokens_before,
        outcome.tokens_after
    );

    // Invariant 2: the last keep_tail messages are byte-identical.
    if let (Some(before), Some(after)) = (
        payload.get("messages").and_then(|m| m.as_array()),
        outcome.payload.get("messages").and_then(|m| m.as_array()),
    ) {
        assert_eq!(before.len(), after.len(), "message count changed");
        let tail = before.len().saturating_sub(cfg.keep_tail);
        assert_eq!(&before[tail..], &after[tail..], "protected tail mutated");
    }

    // Invariant 4: idempotence.
    let second = av_compress::compress(&outcome.payload, &cfg);
    assert_eq!(
        second.payload, outcome.payload,
        "compress is not idempotent on this input"
    );
});
