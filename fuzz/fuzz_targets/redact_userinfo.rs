#![no_main]
//! `av_core::url_redact::redact_userinfo` runs on every log line that
//! renders an operator URL. Two properties:
//!
//! 1. Never panics and is a no-op on inputs without `://` (checked on
//!    the raw fuzz bytes).
//! 2. Never leaks the password: for a synthesized credential-carrying
//!    URL whose password stays OUTSIDE the documented residual gaps
//!    (no `[`/`]`, no digits or `:` — which can collide with the
//!    host:port discrimination heuristic — and no `@`), a fixed canary
//!    embedded in the password must never survive into the output,
//!    whatever punctuation, separators, or nested URLs the fuzzer
//!    weaves around it.

use libfuzzer_sys::fuzz_target;

const CANARY: &str = "S3CR3TZQCANARY";

fuzz_target!(|data: &[u8]| {
    // Property 1: total function on arbitrary UTF-8.
    if let Ok(raw) = std::str::from_utf8(data) {
        let out = av_core::url_redact::redact_userinfo(raw);
        if !raw.contains("://") {
            assert_eq!(out, raw, "non-URL input must round-trip verbatim");
        }
    }

    // Property 2: synthesized secret never survives redaction.
    let mut password = String::from(CANARY);
    let mut tail = String::new();
    for (i, b) in data.iter().enumerate() {
        let c = *b as char;
        if !c.is_ascii_graphic() {
            continue;
        }
        if i % 2 == 0 {
            // Exclusions per the documented residual gaps and the
            // userinfo grammar itself ('@' ends the userinfo).
            if !matches!(c, '@' | '[' | ']' | ':') && !c.is_ascii_digit() {
                password.push(c);
            }
        } else if !matches!(c, '@') && !password.contains(c) {
            // Path/query noise that provably cannot recreate the canary.
            tail.push(c);
        }
    }
    let url = format!("https://user:{password}@example.com/{tail}");
    let redacted = av_core::url_redact::redact_userinfo(&url);
    assert!(
        !redacted.contains(CANARY),
        "password canary survived redaction: {redacted:?}"
    );
});
