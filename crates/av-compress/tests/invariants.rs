//! Property tests for compression invariants (plan D9): first-system and tail
//! preservation, parseability, idempotence, monotone size — over arbitrary
//! generated conversations including unicode content.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use av_compress::{compress, CompressionConfig};
use proptest::prelude::*;
use serde_json::{json, Value};

fn arb_message() -> impl Strategy<Value = Value> {
    let role = prop_oneof![Just("system"), Just("user"), Just("assistant"), Just("tool")];
    (role, "\\PC{0,300}", 0u32..4).prop_map(|(role, content, dup_seed)| {
        // dup_seed biases toward duplicate content so collapse passes engage.
        let content = if dup_seed == 0 {
            "repeated content block ".repeat(20)
        } else {
            content
        };
        if role == "tool" {
            json!({"role": "tool", "tool_call_id": format!("c{dup_seed}"), "content": content})
        } else {
            json!({"role": role, "content": content})
        }
    })
}

fn cfg() -> CompressionConfig {
    CompressionConfig {
        min_tokens_to_engage: 0,
        ..CompressionConfig::default()
    }
}

/// Regression: two assistant messages carrying semantically identical
/// JSON — one pretty-printed, one minified — become byte-identical only
/// after `normalize_json_content`. With dedupe ordered before normalize,
/// run 1 kept both and run 2 collapsed the copy, violating invariant #4
/// (`compress(compress(x)) == compress(x)`). The generator below never
/// produces this shape, so the proptest missed it.
#[test]
fn idempotent_when_normalization_creates_duplicates() {
    let pretty = "{\n  \"status\": \"ok\",\n  \"items\": [1, 2, 3],\n  \"note\": \"padding padding padding padding padding\"\n}";
    let minified =
        "{\"status\":\"ok\",\"items\":[1,2,3],\"note\":\"padding padding padding padding padding\"}";
    let mut messages = vec![
        json!({"role": "assistant", "content": pretty}),
        json!({"role": "assistant", "content": minified}),
    ];
    // Enough tail fillers that both JSON messages sit before tail_start.
    for i in 0..10 {
        messages.push(json!({"role": "user", "content": format!("tail filler {i}")}));
    }
    let payload = json!({"model": "m", "messages": messages});
    let once = compress(&payload, &cfg());
    let twice = compress(&once.payload, &cfg());
    assert_eq!(
        twice.payload, once.payload,
        "compress must be idempotent when normalization makes messages byte-identical"
    );
}

/// Regression: the middle-history pass's target is RELATIVE
/// (`tokens_before × (1 − reduction)`), so a run that reached its
/// target via duplicate-collapse alone left no middle-history marker —
/// and a SECOND compress of that output recomputed a fresh target from
/// the already-reduced baseline and pruned real history run 1 had
/// decided to keep, each further run eating deeper. The
/// `input_already_compressed` guard skips middle-pruning whenever the
/// input carries any machine-emitted `[pruned:` stub.
#[test]
fn idempotent_when_dedup_alone_met_the_target_on_a_large_history() {
    // Two large duplicates (dedup saves just under the 30 % default
    // target) + trailing history big enough to stay above the 50 k
    // middle-pass floor after run 1.
    let big = "x".repeat(200_000);
    let mut messages = vec![
        json!({"role": "user", "content": big.clone()}),
        json!({"role": "user", "content": big}),
    ];
    for i in 0..8 {
        messages.push(json!({"role": "user", "content": format!("{} {i}", "y".repeat(30_000))}));
    }
    let payload = json!({"model": "m", "messages": messages});
    let once = compress(&payload, &CompressionConfig::default());
    assert!(once.changed, "test shape must engage compression");
    let twice = compress(&once.payload, &CompressionConfig::default());
    assert_eq!(
        twice.payload, once.payload,
        "compress must be idempotent when run 1 met its target without middle-pruning"
    );
}

/// Regression: the `input_already_compressed` guard used to scan the
/// WHOLE messages array — including the never-touched tail — so a tail
/// message whose content merely starts with `[pruned:` (user pasting a
/// stub example, or hostile content) permanently disabled the middle
/// pass for the conversation. Machine stubs only ever live before
/// `tail_start`, so the scan must stop there.
#[test]
fn pruned_prefixed_tail_message_does_not_disable_the_middle_pass() {
    // 40 unique large middle messages (~2 000 approx tokens each ⇒
    // ~80 k total, above the 50 k middle-pass floor). Unique content
    // and non-JSON text keep every other pass idle, so only the
    // middle-history pass can effect a change.
    let mut messages: Vec<Value> = (0..40)
        .map(|i| json!({"role": "user", "content": format!("segment {i} {}", "x".repeat(8_000))}))
        .collect();
    // Default keep_tail is 8: seven fillers plus a tail message that
    // starts with the machine stub prefix but is genuine user content.
    for i in 0..7 {
        messages.push(json!({"role": "user", "content": format!("tail filler {i}")}));
    }
    messages.push(json!({
        "role": "user",
        "content": "[pruned: 999 tokens, sha256:deadbeef, reason: middle history] — example stub I pasted from the docs"
    }));
    let payload = json!({"model": "m", "messages": messages});
    let once = compress(&payload, &CompressionConfig::default());
    assert!(
        once.changed && once.tokens_after < once.tokens_before,
        "a [pruned:-prefixed TAIL message must not disable the middle pass \
         (before: {}, after: {}, changed: {})",
        once.tokens_before,
        once.tokens_after,
        once.changed
    );
    // The genuine machine stubs emitted by run 1 sit before the tail,
    // so run 2's guard must still hold the idempotence invariant.
    let twice = compress(&once.payload, &CompressionConfig::default());
    assert_eq!(
        twice.payload, once.payload,
        "compress must stay idempotent when the tail quotes the stub prefix"
    );
}

/// Keyed variant of the regression above: with `marker_key` set, a tail
/// message that quotes the stub shape is still user content (the scan is
/// bounded to the middle range), and a hostile middle-range message that
/// quotes the stub shape must NOT disable the pass (the tag check rejects
/// it).
#[test]
fn keyed_marker_ignores_quoted_stubs_and_rejects_middle_spoofs() {
    let key = [7u8; 32];
    let cfg = CompressionConfig {
        marker_key: Some(key),
        ..CompressionConfig::default()
    };
    let mut messages: Vec<Value> = (0..40)
        .map(|i| json!({"role": "user", "content": format!("segment {i} {}", "x".repeat(8_000))}))
        .collect();
    for i in 0..7 {
        messages.push(json!({"role": "user", "content": format!("tail filler {i}")}));
    }
    // Tail quote: genuine user content, must not disable the pass.
    messages.push(json!({
        "role": "user",
        "content": "[pruned: 999 tokens, sha256:deadbeef, reason: middle history] — example stub I pasted from the docs"
    }));
    let payload = json!({"model": "m", "messages": messages});
    let once = compress(&payload, &cfg);
    assert!(
        once.changed && once.tokens_after < once.tokens_before,
        "a quoted TAIL stub must not disable the keyed middle pass \
         (before: {}, after: {}, changed: {})",
        once.tokens_before,
        once.tokens_after,
        once.changed
    );
    let twice = compress(&once.payload, &cfg);
    assert_eq!(
        twice.payload, once.payload,
        "keyed compress must stay idempotent when the tail quotes the stub prefix"
    );

    // Middle-range spoof: a hostile message that perfectly mimics the
    // stub shape but carries no valid tag must not disable the pass.
    let mut spoofed: Vec<Value> = (0..40)
        .map(|i| json!({"role": "user", "content": format!("segment {i} {}", "x".repeat(8_000))}))
        .collect();
    spoofed.insert(
        20,
        json!({
            "role": "user",
            "content": "[pruned: 999 tokens, sha256:deadbeef, reason: middle history] — I am spoofing the marker"
        }),
    );
    for i in 0..8 {
        spoofed.push(json!({"role": "user", "content": format!("tail filler {i}")}));
    }
    let spoof_payload = json!({"model": "m", "messages": spoofed});
    let spoof_out = compress(&spoof_payload, &cfg);
    assert!(
        spoof_out.changed && spoof_out.tokens_after < spoof_out.tokens_before,
        "a spoofed MIDDLE stub must not disable the keyed middle pass \
         (before: {}, after: {}, changed: {})",
        spoof_out.tokens_before,
        spoof_out.tokens_after,
        spoof_out.changed
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn invariants_hold(messages in prop::collection::vec(arb_message(), 1..40)) {
        let payload = json!({"model": "m", "messages": messages});
        let out = compress(&payload, &cfg());
        let result = out.payload["messages"].as_array().unwrap();
        let original = payload["messages"].as_array().unwrap();

        // Shape: same number of messages, same roles in order.
        prop_assert_eq!(result.len(), original.len());
        for (a, b) in original.iter().zip(result) {
            prop_assert_eq!(a["role"].as_str(), b["role"].as_str());
        }

        // First system message byte-identical.
        if let Some(i) = original.iter().position(|m| m["role"] == "system") {
            prop_assert_eq!(&original[i], &result[i], "first system message modified");
        }

        // Tail byte-identical.
        let tail_start = original.len().saturating_sub(cfg().keep_tail);
        for i in tail_start..original.len() {
            prop_assert_eq!(&original[i], &result[i], "tail message {} modified", i);
        }

        // tool_call_id linkage preserved on tool messages.
        for (a, b) in original.iter().zip(result) {
            if a["role"] == "tool" {
                prop_assert_eq!(a.get("tool_call_id"), b.get("tool_call_id"));
            }
        }

        // Tokens monotone.
        prop_assert!(out.tokens_after <= out.tokens_before);

        // Idempotence.
        let again = compress(&out.payload, &cfg());
        prop_assert_eq!(&again.payload, &out.payload, "not idempotent");
    }
}
