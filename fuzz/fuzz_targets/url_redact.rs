#![no_main]
//! URL userinfo redaction runs on every log line that renders an upstream
//! URL. It must never panic, must leave non-URL text untouched, must be
//! idempotent, and must replace the userinfo of a single URL's authority.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let redacted = av_core::url_redact::redact_userinfo(text);

    // Redaction is a pure rewrite. Running it again must change nothing,
    // so a log pipeline that redacts twice cannot behave differently from
    // one that redacts once.
    let again = av_core::url_redact::redact_userinfo(&redacted);
    assert_eq!(again, redacted, "redaction is not idempotent on {text:?}");

    // Inputs with no URL scheme are returned verbatim.
    if !text.contains("://") {
        assert_eq!(redacted, text, "non-URL input must pass through");
        return;
    }

    // For a single URL whose RFC authority carries `user:pass@host`, the
    // userinfo must be gone from the output. The marker `***` is the only
    // legal userinfo remainder. Slicing is done with `get` so a mistake in
    // this harness cannot be mistaken for a bug in the code under test.
    if text.matches("://").count() == 1 {
        if let Some(scheme_end) = text.find("://") {
            let rest = &text[scheme_end + 3..];
            let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
            let authority = &rest[..authority_end];
            if let Some((userinfo, _host)) = authority.rsplit_once('@') {
                if !userinfo.is_empty() && userinfo != "***" {
                    // Assert only on the userinfo SLOT, never on a raw
                    // substring search of the whole output: a one-character
                    // credential ("T") also appears in the host
                    // ("%TTT"), so `!redacted.contains(userinfo)` fires
                    // even when redaction succeeded.
                    let out_rest = redacted.get(scheme_end + 3..).unwrap_or_default();
                    let out_end = out_rest.find(['/', '?', '#']).unwrap_or(out_rest.len());
                    let out_authority = out_rest.get(..out_end).unwrap_or_default();
                    assert_eq!(
                        out_authority.rsplit_once('@').map(|(u, _)| u).unwrap_or(""),
                        "***",
                        "userinfo was not replaced: {redacted}"
                    );
                }
            }
        }
    }
});