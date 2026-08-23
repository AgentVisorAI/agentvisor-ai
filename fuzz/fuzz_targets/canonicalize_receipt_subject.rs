#![no_main]
//! JCS (RFC 8785) canonicalization must be total over arbitrary JSON
//! documents up to the strict-nesting refusal boundary — any panic
//! here breaks the signing chain (a signer that panics mid-signature
//! leaks a partial signature and the receipt would be unverifiable).
//!
//! Round-51 §10.4: beyond totality, assert the offline-forgery-
//! equivalent property the review named —
//! `canonicalize(v) == canonicalize(parse(canonicalize(v)))`. Drift
//! here means two spec-compliant verifiers can disagree on the signed
//! bytes for the same document.

use libfuzzer_sys::fuzz_target;
use serde_json::Value;

fuzz_target!(|data: &[u8]| {
    let Ok(value) = serde_json::from_slice::<Value>(data) else {
        return;
    };
    let Ok(first) = av_receipts::canonicalize(&value) else {
        return;
    };
    let reparsed: Value =
        serde_json::from_str(&first).expect("canonical output must be valid JSON");
    let second =
        av_receipts::canonicalize(&reparsed).expect("canonical output must re-canonicalize");
    assert_eq!(first, second, "canonicalization must be idempotent");
});
