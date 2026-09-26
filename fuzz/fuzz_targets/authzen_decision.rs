#![no_main]
//! AuthZEN decision parsing must be total over arbitrary JSON.
//! A hostile or buggy PDP can return any shape; `decision_of` must
//! return `Err` rather than panic. The reason string must never carry
//! control characters or bidirectional overrides (log-line forgery and
//! display spoofing).

use libfuzzer_sys::fuzz_target;
use serde_json::Value;

fuzz_target!(|data: &[u8]| {
    let Ok(value) = serde_json::from_slice::<Value>(data) else {
        return;
    };
    match av_harness::authzen::decision_of(&value) {
        Ok(av_harness::authzen::AuthzenDecision::Permit) => {}
        Ok(av_harness::authzen::AuthzenDecision::Deny(reason)) => {
            assert!(
                !reason.chars().any(|c| c.is_control()),
                "control char in reason: {reason:?}"
            );
            assert!(
                !av_core::text::contains_bidi_or_zero_width(&reason),
                "bidi override in reason: {reason:?}"
            );
            assert!(
                reason.chars().count() <= 512,
                "reason exceeds 512 chars: {}",
                reason.chars().count()
            );
        }
        Err(_) => {}
    }
});