#![no_main]
//! The provider SSE chunk parser must be total: any adversarial
//! byte sequence must return Ok/Err without panic. A panic in
//! the streaming path would sever the client connection AND poison
//! the audit chain for the affected session.
//!
//! NB on coverage: production (`routes.rs` drain loop) rejects
//! non-UTF-8 frames with a typed error BEFORE the parser runs, and
//! the shim mirrors that contract — so inputs with truncated
//! multibyte sequences exercise only the (production-equivalent)
//! decode refusal, not the parser body. Embedded NULs, mixed CR/LF
//! and Unicode edge cases are all valid UTF-8 and reach the parser.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    av_harness::fuzz::parse_provider_chunk(data);
});
