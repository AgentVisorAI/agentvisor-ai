//! Shared URL-userinfo redaction for logs and diagnostics.
//!
//! Round-6 (hunt4 F4 + hunt1 F3): the `upstream_url` field is
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
    // AND commas that separate them (i.e. it's a list of full URLs),
    // process each URL independently. Otherwise treat the input as a
    // single URI whose authority may contain a comma-separated cluster
    // host list AFTER an `@` (so any comma before the last `@` is
    // inside a password).
    let scheme_count = input.matches("://").count();
    if scheme_count > 1 {
        return input
            .split(',')
            .map(redact_single)
            .collect::<Vec<_>>()
            .join(",");
    }
    redact_single(input)
}

fn redact_single(input: &str) -> String {
    let Some(scheme_end) = input.find("://") else {
        return input.to_owned();
    };
    let auth_start = scheme_end + 3;
    let scheme_prefix = &input[..auth_start];
    let rest = &input[auth_start..];
    let auth_end_off = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..auth_end_off];
    let trailing = &rest[auth_end_off..];
    match authority.rsplit_once('@') {
        Some((_, host_segment)) => format!("{scheme_prefix}***@{host_segment}{trailing}"),
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
}
