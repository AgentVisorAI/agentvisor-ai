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
