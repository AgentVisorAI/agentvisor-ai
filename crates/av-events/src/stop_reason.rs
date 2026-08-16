//! Stop-reason identifiers.
//!
//! Values 0–4 follow upstream OCSF PR #1704. 90 = provider content filter
//! (provider-native, not enforcement). 91–94 are AgentVisor AI enforcement
//! extensions. 99 = Other (catch-all; forward-compatible).

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
    /// AgentVisor AI loop breaker tripped (Module A).
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
    ///
    /// Round-29 F7: `#[serde(other)]` makes this the deserialize
    /// fallback for any unrecognised variant. Heterogeneous
    /// cluster upgrades (harness-N publishing a new stop reason
    /// variant, harness-N-1 reading it back from the bridge
    /// during recovery) would otherwise fail the whole event
    /// parse — dropping evidence and breaking chain
    /// reconstruction on stragglers. Forward-compat: a peer
    /// emitter that adds `"FutureVariant"` deserializes to
    /// `Other`; re-serialization emits `"Other"` (lossy on the
    /// specific variant name, but the free-text `stop_reason`
    /// field is the intended carrier for that detail anyway).
    #[serde(other)]
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
            Self::SessionClosed => 4,
            Self::ContentFilter => 90,
            Self::LoopDetected => 91,
            Self::BudgetExceeded => 92,
            Self::PolicyBlocked => 93,
            Self::IdentityRejected => 94,
            Self::Other => 99,
        }
    }

    /// Canonical caption for the wire format.
    pub fn caption(self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::Stop => "Stop",
            Self::MaxTokens => "Length",
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
            0 => Self::Unknown,
            1 => Self::Stop,
            2 => Self::MaxTokens,
            3 => Self::ToolUse,
            4 => Self::SessionClosed,
            90 => Self::ContentFilter,
            91 => Self::LoopDetected,
            92 => Self::BudgetExceeded,
            93 => Self::PolicyBlocked,
            94 => Self::IdentityRejected,
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

    /// Round-29 F7: `#[serde(other)]` makes `Other` the deserialize
    /// fallback for any unrecognised discriminant. Heterogeneous
    /// cluster upgrades (harness-N publishing a new variant,
    /// harness-N-1 reading it back from the bridge during recovery)
    /// would otherwise fail the whole event parse — dropping
    /// evidence and breaking chain reconstruction on stragglers.
    #[test]
    #[allow(clippy::unwrap_used)]
    fn unknown_serde_variant_falls_back_to_other() {
        let unknown: StopReason = serde_json::from_str("\"FutureVariant\"").unwrap();
        assert_eq!(unknown, StopReason::Other);
        // Known variants still parse to themselves — the fallback
        // does not shadow them.
        let known: StopReason = serde_json::from_str("\"MaxTokens\"").unwrap();
        assert_eq!(known, StopReason::MaxTokens);
        // Emitted representation of Other stays "Other" (no invisible
        // renaming of the fallback).
        assert_eq!(serde_json::to_string(&StopReason::Other).unwrap(), "\"Other\"");
    }
}
