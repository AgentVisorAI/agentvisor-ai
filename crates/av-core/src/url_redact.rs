//! Shared URL-userinfo redaction for logs and diagnostics.
//!
//! The `upstream_url` field is
//! validated to only require an `http(s)://` scheme, so an operator
//! whose provider requires HTTP Basic auth (a common pattern with
//! self-hosted litellm/proxy shims) can legitimately put credentials
//! in the URL as `https://user:pass@host/…`. Every tracing/log
//! statement that renders that field then ships the credentials to
//! OTLP/SIEM. `avctl doctor` already redacts it; this helper is the
//! shared implementation so every log site can do the same.
//!
//! Semantics: keep the scheme + host(:port)(+ path/query/fragment)
//! intact so log correlation still works; replace any `user[:pass]`
//! segment with `***`. Handle comma-separated cluster lists (Redis
//! Cluster style: `redis://user:pass@host1,host2,host3`) without
//! splitting on commas that belong to a password.

/// Redact URL userinfo. Non-URL inputs are returned verbatim.
///
/// Handles two shapes used across the codebase:
///
/// 1. Multiple full URLs joined with commas — the historical shape
///    `avctl doctor` prints (`redis://u:p@h1,redis://u:p@h2`). Each
///    segment is processed independently.
/// 2. A single URL whose authority contains a cluster host list —
///    Redis Cluster URI grammar `redis://user:pass@h1:port,h2:port`.
///    The whole authority is treated as one segment and userinfo is
///    stripped before the LAST `@` — which stays inside the userinfo
///    even when the password itself contains `,`.
///
/// # Examples
///
/// ```
/// use av_core::url_redact::redact_userinfo;
///
/// assert_eq!(
///     redact_userinfo("https://alice:secret@api.example.com/v1"),
///     "https://***@api.example.com/v1",
/// );
/// // Password containing `,` (a legal RFC 3986 sub-delim):
/// assert_eq!(
///     redact_userinfo("redis://u:p,w@host1:6379,host2:6379"),
///     "redis://***@host1:6379,host2:6379",
/// );
/// // Comma-joined list of complete URLs:
/// assert_eq!(
///     redact_userinfo("redis://u:p@h1:7000,redis://u:p@h2:7001"),
///     "redis://***@h1:7000,redis://***@h2:7001",
/// );
/// assert_eq!(redact_userinfo("https://api.example.com/v1"), "https://api.example.com/v1");
/// assert_eq!(redact_userinfo("plain text"), "plain text");
/// ```
pub fn redact_userinfo(input: &str) -> String {
    if !input.contains("://") {
        return input.to_owned();
    }
    // Heuristic split: if the input contains multiple `://` occurrences
    // AND commas that START a new URL (i.e. are immediately followed by
    // `scheme://`), it's a list of full URLs — process each
    // independently. A comma inside a password or query never precedes
    // a scheme, so it stays inside its segment. The prior naive
    // `split(',')` cut a comma-carrying password in half whenever the
    // SAME URL's query held a second URL (`https://u:pa,ss@h/cb?u=http://x`):
    // both halves then failed the userinfo heuristics and the whole
    // secret was returned verbatim.
    let scheme_count = input.matches("://").count();
    if scheme_count > 1 {
        return split_url_list(input)
            .into_iter()
            .map(redact_single)
            .collect::<Vec<_>>()
            .join(",");
    }
    redact_single(input)
}

/// Split at commas immediately followed by a `scheme://` prefix (RFC
/// 3986 scheme grammar: ALPHA then ALPHA/DIGIT/`+`/`-`/`.`). Commas
/// inside passwords, cluster host lists, or queries never match.
fn split_url_list(input: &str) -> Vec<&str> {
    let mut segments = Vec::new();
    let mut start = 0;
    for (index, _) in input.match_indices(',') {
        if index >= start && starts_with_scheme(&input[index + 1..]) {
            segments.push(&input[start..index]);
            start = index + 1;
        }
    }
    segments.push(&input[start..]);
    segments
}

fn starts_with_scheme(s: &str) -> bool {
    let Some(scheme) = s.find("://").map(|end| &s[..end]) else {
        return false;
    };
    let mut bytes = scheme.bytes();
    bytes.next().is_some_and(|first| first.is_ascii_alphabetic())
        && bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
}

fn redact_single(input: &str) -> String {
    let Some(scheme_end) = input.find("://") else {
        return input.to_owned();
    };
    let auth_start = scheme_end + 3;
    let scheme_prefix = &input[..auth_start];
    let rest = &input[auth_start..];
    // RFC-correct case first: the authority ends at the first `/`,
    // `?`, or `#`, and the last `@` within it splits userinfo from
    // host (a password may legally contain `,` — sub-delims). This
    // also keeps `@` characters later in the path/query (mailto-style
    // tokens) out of the decision.
    let auth_end_off = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = rest.get(..auth_end_off).unwrap_or_default();
    let trailing = rest.get(auth_end_off..).unwrap_or_default();
    if let Some((_, host_segment)) = authority.rsplit_once('@') {
        return format!("{scheme_prefix}***@{host_segment}{trailing}");
    }
    // No `@` inside the RFC authority, but one later in the string:
    // either a password containing a raw `/`, `?`, or `#` (routine in
    // base64-style secrets — a shape that used to be returned
    // VERBATIM, defeating redaction) or a credential-less URL with an
    // `@` in its path (`http://h/p@th`), which must stay untouched.
    // Discriminate by the naive authority's shape: a truncated
    // `user:password` leaves a `:` followed by non-digit characters,
    // while a legitimate credential-less authority is `host`,
    // `host:port` (digits only after the colon), or a bracketed IPv6
    // literal (whose colons are address syntax, never a userinfo
    // separator — RFC 3986 requires the brackets precisely so `:` in
    // the address cannot be confused with the port delimiter). Known
    // residual gaps: a password whose pre-`/` prefix is all digits or
    // contains `[`/`]` still leaks — the mixed-character secrets this
    // defends against are covered.
    let truncated_userinfo = !authority.contains('[')
        && authority
            .rsplit_once(':')
            .is_some_and(|(_, suffix)| !suffix.is_empty() && !suffix.bytes().all(|b| b.is_ascii_digit()));
    if !truncated_userinfo {
        return input.to_owned();
    }
    match rest.rfind('@') {
        Some(at) => {
            let after_at = rest.get(at + 1..).unwrap_or_default();
            let host_end = after_at.find(['/', '?', '#']).unwrap_or(after_at.len());
            let host_segment = after_at.get(..host_end).unwrap_or_default();
            let tail = after_at.get(host_end..).unwrap_or_default();
            format!("{scheme_prefix}***@{host_segment}{tail}")
        }
        None => input.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_with_password() {
        assert_eq!(
            redact_userinfo("https://alice:secret@api.example.com/v1/chat"),
            "https://***@api.example.com/v1/chat",
        );
    }

    #[test]
    fn https_without_userinfo_unchanged() {
        assert_eq!(
            redact_userinfo("https://api.example.com/v1/chat"),
            "https://api.example.com/v1/chat",
        );
    }

    #[test]
    fn redis_cluster_list_with_comma_password() {
        // `,` inside the password used to break the per-segment splitter.
        assert_eq!(
            redact_userinfo("redis://user:p,w@host1:6379,host2:6379"),
            "redis://***@host1:6379,host2:6379",
        );
    }

    #[test]
    fn redis_cluster_no_userinfo() {
        assert_eq!(
            redact_userinfo("redis://host1:6379,host2:6379"),
            "redis://host1:6379,host2:6379",
        );
    }

    /// A comma-carrying password in a URL whose QUERY holds a second
    /// URL used to leak in full: two `://` occurrences tripped the
    /// naive `split(',')`, the cut segments failed every userinfo
    /// heuristic, and both halves of the secret were returned
    /// verbatim. The list splitter must only split at commas that
    /// start a new `scheme://`.
    #[test]
    fn comma_password_with_nested_url_in_query_still_redacts() {
        assert_eq!(
            redact_userinfo("https://alice:se,cret@host/cb?u=http://inner"),
            "https://***@host/cb?u=http://inner",
        );
        // The doctor's comma-joined URL list still splits correctly,
        // including when a listed URL carries a comma password (the
        // inner comma is not followed by a scheme, so it stays put).
        assert_eq!(
            redact_userinfo("redis://u:p,w@h1:7000,redis://u:pw@h2:7001"),
            "redis://***@h1:7000,redis://***@h2:7001",
        );
        // Comma in a query, multiple schemes, no userinfo: untouched.
        assert_eq!(
            redact_userinfo("https://host/a?list=x,http://y"),
            "https://host/a?list=x,http://y",
        );
    }

    #[test]
    fn plain_string_untouched() {
        assert_eq!(redact_userinfo("hello world"), "hello world");
        assert_eq!(redact_userinfo(""), "");
    }

    #[test]
    fn query_fragment_after_authority() {
        assert_eq!(
            redact_userinfo("https://u:p@host/x?token=@abc#frag"),
            "https://***@host/x?token=@abc#frag",
        );
    }

    #[test]
    fn password_with_path_query_fragment_chars_still_redacts() {
        // Base64-style secrets routinely contain `/`; `?` and `#` are
        // also possible in operator-pasted passwords. These shapes used
        // to be returned verbatim (the first path/query/fragment byte
        // truncated the authority before the `@` was found).
        for (input, expected) in [
            ("redis://user:AB/CDEF@host:6379", "redis://***@host:6379"),
            ("redis://user:AB?CD@host:6379", "redis://***@host:6379"),
            ("redis://user:AB#CD@host:6379", "redis://***@host:6379"),
            (
                "https://user:AB/CD@api.example.com/v1",
                "https://***@api.example.com/v1",
            ),
            // Credential-less shapes with a raw `@` in the path stay
            // untouched (the naive authority is host / host:port).
            ("http://h/p@th", "http://h/p@th"),
            ("http://host:8080/p@th", "http://host:8080/p@th"),
            // Bracketed IPv6 literals: address colons are never a
            // userinfo separator.
            ("http://[::1]/p@th", "http://[::1]/p@th"),
            (
                "https://[2001:db8::1]:8443/p@th",
                "https://[2001:db8::1]:8443/p@th",
            ),
        ] {
            assert_eq!(redact_userinfo(input), expected, "input: {input}");
        }
    }
}
