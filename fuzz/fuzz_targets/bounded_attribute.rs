#![no_main]
//! Attribute bounding must never exceed the limit and must never
//! panic on multi-byte UTF-8. An oversized OTLP attribute is a
//! denial-of-service against the tenant collector.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let bounded = av_harness::otel_content::bounded(text);
    // The result must never exceed the limit by more than the marker.
    const MAX_ATTRIBUTE_BYTES: usize = 256 * 1024;
    const MARKER_OVERHEAD: usize = 64;
    assert!(
        bounded.len() <= MAX_ATTRIBUTE_BYTES + MARKER_OVERHEAD,
        "bounded output too large: {} bytes (input {} bytes)",
        bounded.len(),
        text.len()
    );
    // Short inputs pass through verbatim.
    if text.len() <= MAX_ATTRIBUTE_BYTES {
        assert_eq!(bounded, text, "short input must pass through verbatim");
    }
});