//! Identifier newtypes. UUIDv7 gives time-ordered ids (useful for log locality)
//! while remaining globally unique.

use serde::{Deserialize, Serialize};
use std::fmt;

/// A session identifier (UUIDv7 canonical text form).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
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

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// An agent instance identifier (`ai_agent.instance_uid`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
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

/// Generate a fresh instance uid (UUIDv7).
pub fn new_instance_uid() -> InstanceUid {
    InstanceUid(uuid::Uuid::now_v7().to_string())
}

#[cfg(test)]
mod tests {
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

    #[test]
    fn instance_uid_rejects_bad_input() {
        assert!(InstanceUid::parse("").is_err());
        assert!(InstanceUid::parse("é").is_err());
        assert!(InstanceUid::parse("agent-7").is_ok());
    }
}
