//! Structured denial codes for tool-call authorization failures.
//!
//! Each code is a stable, machine-readable string that appears in JSON-RPC
//! `error.data.code`, in the OCSF event's `denial_code` field, and in
//! operator metrics. Consumers can match on these codes without parsing
//! human-readable reason strings.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Machine-readable denial code attached to every `ToolVerdict::Blocked`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum DenialCode {
    /// JSON-RPC envelope did not parse (malformed JSON, wrong version, etc.).
    #[serde(rename = "PARSE_ERROR")]
    ParseError,
    /// Method is not `tools/call` — the call was passed through or refused
    /// at the protocol level.
    #[serde(rename = "PASSTHROUGH_REFUSED")]
    PassthroughRefused,
    /// Tool arguments failed JSON Schema validation.
    #[serde(rename = "SCHEMA_VIOLATION")]
    SchemaViolation,
    /// No argument schema configured for this tool and `require_schema` is on.
    #[serde(rename = "SCHEMA_MISSING")]
    SchemaMissing,
    /// A named policy engine denied the call.
    #[serde(rename = "POLICY_DENIED")]
    PolicyDenied,
    /// Session or principal action budget exhausted.
    #[serde(rename = "BUDGET_EXCEEDED")]
    BudgetExceeded,
    /// Budget subsystem failed and the sandbox failed closed.
    #[serde(rename = "BUDGET_ERROR")]
    BudgetError,
    /// Tool has no configured intent mapping (pillar 2: AuthZEN).
    #[serde(rename = "UNMAPPED_TOOL")]
    UnmappedTool,
    /// The active mission has expired.
    #[serde(rename = "MISSION_EXPIRED")]
    MissionExpired,
    /// The active mission does not authorize this intent.
    #[serde(rename = "MISSION_DENIED")]
    MissionDenied,
    /// The caller's identity scopes do not cover the required tool scope.
    #[serde(rename = "SCOPE_INSUFFICIENT")]
    ScopeInsufficient,
    /// Identity token was revoked (JTI revocation list).
    #[serde(rename = "TOKEN_REVOKED")]
    TokenRevoked,
    /// No backend is configured for this tool.
    #[serde(rename = "NO_BACKEND")]
    NoBackend,
    /// The intent token could not be issued (signing failure, clock skew, etc.).
    #[serde(rename = "INTENT_TOKEN_ERROR")]
    IntentTokenError,
    /// Payout amount field could not be parsed or is negative.
    #[serde(rename = "PAYOUT_INVALID")]
    PayoutInvalid,
}

impl DenialCode {
    /// Stable wire string (matches the serde rename).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ParseError => "PARSE_ERROR",
            Self::PassthroughRefused => "PASSTHROUGH_REFUSED",
            Self::SchemaViolation => "SCHEMA_VIOLATION",
            Self::SchemaMissing => "SCHEMA_MISSING",
            Self::PolicyDenied => "POLICY_DENIED",
            Self::BudgetExceeded => "BUDGET_EXCEEDED",
            Self::BudgetError => "BUDGET_ERROR",
            Self::UnmappedTool => "UNMAPPED_TOOL",
            Self::MissionExpired => "MISSION_EXPIRED",
            Self::MissionDenied => "MISSION_DENIED",
            Self::ScopeInsufficient => "SCOPE_INSUFFICIENT",
            Self::TokenRevoked => "TOKEN_REVOKED",
            Self::NoBackend => "NO_BACKEND",
            Self::IntentTokenError => "INTENT_TOKEN_ERROR",
            Self::PayoutInvalid => "PAYOUT_INVALID",
        }
    }
}

impl fmt::Display for DenialCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn as_str_round_trips_through_serde() {
        let codes = [
            DenialCode::ParseError,
            DenialCode::PassthroughRefused,
            DenialCode::SchemaViolation,
            DenialCode::SchemaMissing,
            DenialCode::PolicyDenied,
            DenialCode::BudgetExceeded,
            DenialCode::BudgetError,
            DenialCode::UnmappedTool,
            DenialCode::MissionExpired,
            DenialCode::MissionDenied,
            DenialCode::ScopeInsufficient,
            DenialCode::TokenRevoked,
            DenialCode::NoBackend,
            DenialCode::IntentTokenError,
            DenialCode::PayoutInvalid,
        ];
        for code in codes {
            let json = serde_json::to_string(&code).unwrap();
            let back: DenialCode = serde_json::from_str(&json).unwrap();
            assert_eq!(back, code);
            assert_eq!(format!("\"{code}\""), json);
        }
    }

    #[test]
    fn display_matches_as_str() {
        for code in [DenialCode::UnmappedTool, DenialCode::MissionExpired] {
            assert_eq!(format!("{code}"), code.as_str());
        }
    }
}
