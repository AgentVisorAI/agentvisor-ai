#![no_main]
//! The provider SSE chunk parser must be total: any adversarial
//! byte sequence (mid-UTF-8 truncation, embedded NULs, mixed CR/LF,
//! Unicode edge cases) must return Ok/Err without panic. A panic in
//! the streaming path would sever the client connection AND poison
//! the audit chain for the affected session.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    av_harness::fuzz::parse_provider_chunk(data);
});
