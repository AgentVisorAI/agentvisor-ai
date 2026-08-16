//! Identifier newtypes. UUIDv7 gives time-ordered ids (useful for log locality)
//! while remaining globally unique.

use serde::{Deserialize, Serialize};
use std::fmt;

/// A session identifier (UUIDv7 canonical text form).
///
/// Serialization is transparent (the wire form is a plain string), but
/// deserialization runs [`Self::parse`] so wire-supplied ids can never
/// bypass the visible-ASCII / length invariants that downstream code
/// (loggers, header emitters, filesystem-path composers) relies on.
/// A `#[serde(transparent)]` derive would forward to `String`'s impl
/// and silently accept `""`, `"\n\r"`, Trojan-Source unicode, or
/// megabyte-long ids embedded in any struct field that carries a
/// SessionId.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct SessionId(String);

impl SessionId {
    /// Wrap an externally supplied session id (validated non-empty, ≤ 128 chars,
    /// visible ASCII only — header-safe).
    pub fn parse(s: &str) -> Result<Self, crate::CoreError> {
        if s.is_empty() || s.len() > 128 || !s.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
            return Err(crate::CoreError::InvalidId(format!("session id {s:?}")));
        }
        Ok(Self(s.to_owned()))
    }

    /// Access the string form.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for SessionId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(|error| D::Error::custom(error.to_string()))
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// An agent instance identifier (`ai_agent.instance_uid`).
///
/// Same invariants as [`SessionId`]; the custom `Deserialize` runs
/// [`Self::parse`] so wire-supplied ids embedded in any struct field
/// cannot bypass the visible-ASCII / length checks.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct InstanceUid(String);

impl InstanceUid {
    /// Wrap an externally supplied instance uid with the same constraints as
    /// [`SessionId::parse`].
    pub fn parse(s: &str) -> Result<Self, crate::CoreError> {
        if s.is_empty() || s.len() > 128 || !s.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
            return Err(crate::CoreError::InvalidId(format!("instance uid {s:?}")));
        }
        Ok(Self(s.to_owned()))
    }

    /// Access the string form.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for InstanceUid {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(|error| D::Error::custom(error.to_string()))
    }
}

impl fmt::Display for InstanceUid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Generate a fresh session id (UUIDv7).
pub fn new_session_id() -> SessionId {
    SessionId(uuid::Uuid::now_v7().to_string())
}

/// Generate a fresh event uid (UUIDv7).
pub fn new_event_uid() -> String {
    uuid::Uuid::now_v7().to_string()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn v7_ids_are_time_ordered() {
        let a = new_event_uid();
        let b = new_event_uid();
        assert!(a <= b, "UUIDv7 must sort by creation time: {a} vs {b}");
    }

    #[test]
    fn session_id_rejects_bad_input() {
        assert!(SessionId::parse("").is_err());
        assert!(SessionId::parse("has space").is_err());
        assert!(SessionId::parse("ctrl\x07char").is_err());
        assert!(SessionId::parse(&"x".repeat(129)).is_err());
        assert!(SessionId::parse("ok-id_123").is_ok());
    }

    /// Every byte that could be used to escape a log line, terminal control
    /// sequence, or cross-line boundary must be rejected. This locks the
    /// defense: any `SessionId` that survives `parse` is safe to interpolate
    /// into log lines and event chains, so hostile `X-AV-Session` values can
    /// never ride a *parsed* id into a forged log record. (Middleware that
    /// logs the raw header string separately relies on the tracing layer's
    /// own field escaping.)
    #[test]
    fn session_id_rejects_every_log_injection_byte() {
        // Cover: NUL, tab, LF, CR, ESC, DEL, and every high-ASCII byte.
        let mut hostile_bytes: Vec<u8> = (0..=0x20).collect();
        hostile_bytes.push(0x7f);
        hostile_bytes.extend(0x80u8..=0xff);
        for b in hostile_bytes {
            let s = format!("legit{}injected", b as char);
            assert!(
                SessionId::parse(&s).is_err(),
                "byte 0x{b:02x} must not be allowed in a session id",
            );
            // Also test with the byte as the leading character.
            let leading = format!("{}suffix", b as char);
            assert!(
                SessionId::parse(&leading).is_err(),
                "leading byte 0x{b:02x} must not be allowed",
            );
        }
    }

    #[test]
    fn instance_uid_rejects_bad_input() {
        assert!(InstanceUid::parse("").is_err());
        assert!(InstanceUid::parse("é").is_err());
        assert!(InstanceUid::parse("agent-7").is_ok());
    }

    #[test]
    fn length_boundary_128_is_accepted_129_is_rejected() {
        // Catches `> 128` vs `== 128` / `>= 128` mutations on both types.
        for parser in [
            SessionId::parse("x".repeat(128).as_str()).is_ok(),
            InstanceUid::parse("x".repeat(128).as_str()).is_ok(),
        ] {
            assert!(parser, "128-char id must be accepted");
        }
        assert!(SessionId::parse(&"x".repeat(129)).is_err());
        assert!(InstanceUid::parse(&"x".repeat(129)).is_err());
    }

    #[test]
    fn as_str_and_display_return_the_wrapped_string() {
        // Catches `as_str -> "xyzzy"` / `-> ""` and Display default-return.
        let sid = SessionId::parse("sess-abc-123").unwrap();
        assert_eq!(sid.as_str(), "sess-abc-123");
        assert_eq!(format!("{sid}"), "sess-abc-123");
        let iid = InstanceUid::parse("inst-42").unwrap();
        assert_eq!(iid.as_str(), "inst-42");
        assert_eq!(format!("{iid}"), "inst-42");
    }

    #[test]
    fn new_event_uid_returns_a_uuid_shaped_string() {
        // Catches `new_event_uid -> String::new()` and `-> "xyzzy".into()`.
        let uid = new_event_uid();
        assert_eq!(uid.len(), 36, "UUID text is 36 chars: {uid:?}");
        assert_eq!(uid.matches('-').count(), 4, "UUID has 4 hyphens: {uid:?}");
    }

    /// Deserializing a `SessionId` MUST run the same visible-ASCII /
    /// length invariants as `parse` — otherwise any struct with a
    /// `SessionId` field silently accepts an empty id, a Trojan-Source
    /// unicode payload, or a megabyte-long string, defeating every
    /// downstream invariant (log injection, header emission,
    /// filesystem-path composition) that trusts `parse` succeeded.
    #[test]
    fn session_id_deserialize_rejects_hostile_wire_input() {
        // Empty string — bypasses the `is_empty()` guard if we forwarded
        // to `String::deserialize`.
        let empty = serde_json::from_str::<SessionId>(r#""""#);
        assert!(empty.is_err(), "empty id must be rejected on deserialize");
        // CRLF injection — every log line embedding a raw id would be
        // trivially spoofable.
        let crlf = serde_json::from_str::<SessionId>(r#""a\r\nfake-log""#);
        assert!(crlf.is_err(), "CRLF must be rejected on deserialize");
        // Unicode Trojan Source (right-to-left override).
        let rtl = serde_json::from_str::<SessionId>(r#""\u202Elegit""#);
        assert!(rtl.is_err(), "non-ASCII must be rejected on deserialize");
        // 129 chars — one over the boundary.
        let too_long = format!(r#""{}""#, "x".repeat(129));
        assert!(
            serde_json::from_str::<SessionId>(&too_long).is_err(),
            "> 128 chars must be rejected on deserialize"
        );
    }

    #[test]
    fn instance_uid_deserialize_rejects_hostile_wire_input() {
        let empty = serde_json::from_str::<InstanceUid>(r#""""#);
        assert!(empty.is_err(), "empty instance_uid must be rejected");
        let non_ascii = serde_json::from_str::<InstanceUid>(r#""agent-é""#);
        assert!(non_ascii.is_err(), "non-ASCII instance_uid must be rejected");
    }

    /// Serialize is transparent: a `SessionId` round-trips as a plain
    /// string, and a *valid* id survives the round-trip unchanged.
    #[test]
    fn session_id_valid_deserialize_round_trip() {
        let id = SessionId::parse("sess-abc-123").unwrap();
        let wire = serde_json::to_string(&id).unwrap();
        assert_eq!(wire, r#""sess-abc-123""#);
        let restored: SessionId = serde_json::from_str(&wire).unwrap();
        assert_eq!(restored, id);
    }
}
