//! Stop-reason identifiers.
//!
//! Values 0–4 and 99 track conventional completion semantics; 90–97 are the
//! AgentBridge extension range for enforcement verdicts. The numeric mapping is
//! part of our authored profile (the brief's upstream PR does not publish enum
//! values); EVOLUTION.md documents the re-mapping policy should upstream
//! ocsf#1704 land different numbers.

use serde::{Deserialize, Serialize};

/// Why an agent execution step (or session) stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum StopReason {
    /// Unknown / not reported.
    Unknown,
    /// Natural completion (provider `stop`).
    Stop,
    /// Provider truncated at max tokens.
    MaxTokens,
    /// Stopped to invoke a tool.
    ToolUse,
    /// Provider content filter.
    ContentFilter,
    /// AgentBridge loop breaker tripped (Module A).
    LoopDetected,
    /// Action/token budget exhausted (Module B).
    BudgetExceeded,
    /// Policy engine blocked the action (Module B).
    PolicyBlocked,
    /// NHI identity validation rejected the caller (Module D).
    IdentityRejected,
    /// Session explicitly closed.
    SessionClosed,
    /// Other (see `stop_reason` free text).
    Other,
}

impl StopReason {
    /// Numeric `stop_reason_id` for the wire format.
    pub fn id(self) -> u8 {
        match self {
            Self::Unknown => 0,
            Self::Stop => 1,
            Self::MaxTokens => 2,
            Self::ToolUse => 3,
            Self::ContentFilter => 4,
            Self::LoopDetected => 90,
            Self::BudgetExceeded => 91,
            Self::PolicyBlocked => 92,
            Self::IdentityRejected => 93,
            Self::SessionClosed => 94,
            Self::Other => 99,
        }
    }

    /// Canonical caption for the wire format.
    pub fn caption(self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::Stop => "Stop",
            Self::MaxTokens => "Max Tokens",
            Self::ToolUse => "Tool Use",
            Self::ContentFilter => "Content Filter",
            Self::LoopDetected => "Loop Detected",
            Self::BudgetExceeded => "Budget Exceeded",
            Self::PolicyBlocked => "Policy Blocked",
            Self::IdentityRejected => "Identity Rejected",
            Self::SessionClosed => "Session Closed",
            Self::Other => "Other",
        }
    }

    /// Parse a numeric id back into a reason (inbound tolerance: unknown ids
    /// map to `Unknown`, never an error — forward compatibility).
    pub fn from_id(id: u8) -> Self {
        match id {
            1 => Self::Stop,
            2 => Self::MaxTokens,
            3 => Self::ToolUse,
            4 => Self::ContentFilter,
            90 => Self::LoopDetected,
            91 => Self::BudgetExceeded,
            92 => Self::PolicyBlocked,
            93 => Self::IdentityRejected,
            94 => Self::SessionClosed,
            99 => Self::Other,
            _ => Self::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: &[StopReason] = &[
        StopReason::Unknown,
        StopReason::Stop,
        StopReason::MaxTokens,
        StopReason::ToolUse,
        StopReason::ContentFilter,
        StopReason::LoopDetected,
        StopReason::BudgetExceeded,
        StopReason::PolicyBlocked,
        StopReason::IdentityRejected,
        StopReason::SessionClosed,
        StopReason::Other,
    ];

    #[test]
    fn id_roundtrip_all_variants() {
        for &r in ALL {
            assert_eq!(StopReason::from_id(r.id()), r, "roundtrip failed for {r:?}");
        }
    }

    #[test]
    fn ids_are_unique() {
        let mut ids: Vec<u8> = ALL.iter().map(|r| r.id()).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), ALL.len(), "duplicate stop_reason_id values");
    }

    #[test]
    fn unknown_id_tolerated() {
        assert_eq!(StopReason::from_id(42), StopReason::Unknown);
        assert_eq!(StopReason::from_id(255), StopReason::Unknown);
    }
}
