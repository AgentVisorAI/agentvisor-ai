#![no_main]
//! JCS (RFC 8785) canonicalization must be total over arbitrary JSON
//! documents up to the strict-nesting refusal boundary — any panic
//! here breaks the signing chain (a signer that panics mid-signature
//! leaks a partial signature and the receipt would be unverifiable).

use libfuzzer_sys::fuzz_target;
use serde_json::Value;

fuzz_target!(|data: &[u8]| {
    let Ok(value) = serde_json::from_slice::<Value>(data) else {
        return;
    };
    let _ = av_receipts::canonicalize(&value);
});
