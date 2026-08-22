#![no_main]
//! `sse_frame_end` returns the byte-index of the frame terminator in a
//! streaming buffer or None if the frame is incomplete. It must never
//! panic, never return an out-of-bounds index, and never overflow
//! usize on adversarial input (mismatched CR/LF, embedded NULs,
//! extremely long lines).

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    av_harness::fuzz::sse_frame_end(data);
});
