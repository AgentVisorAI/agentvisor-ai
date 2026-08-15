//! NHI JWT claims.

use serde::{Deserialize, Serialize};

/// Hard TTL ceiling for NHI tokens: 15 minutes (brief Module D).
pub const MAX_TTL_SECS: u64 = 15 * 60;

/// The `aud` claim per RFC 7519 §4.1.3: "a StringOrURI value or an
/// array of StringOrURI". Mainstream IdPs (Okta, Auth0, Azure AD,
/// Cognito) emit the array form for multi-audience apps
/// (`"aud": ["agentbridge", "some-other-svc"]`). Accepting only the
/// string form silently locks the operator out at go-live with an
/// `invalid type: sequence, expected string` error deep inside
/// `jsonwebtoken::decode`, before our validator's aud check runs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum Audience {
    /// Single-string form (`"aud": "agentbridge"`).
    Single(String),
    /// Array form (`"aud": ["agentbridge", "other"]`).
    Multi(Vec<String>),
}

impl Audience {
    /// True when `expected` appears in this audience claim (either the
    /// single string equals it, or the array contains it).
    pub fn contains(&self, expected: &str) -> bool {
        match self {
            Self::Single(value) => value == expected,
            Self::Multi(values) => values.iter().any(|v| v == expected),
        }
    }

    /// A borrowed view suitable for logging/display. Returns the first
    /// entry of a multi-audience — the "primary" audience by
    /// convention.
    pub fn primary(&self) -> &str {
        match self {
            Self::Single(value) => value.as_str(),
            Self::Multi(values) => values.first().map(String::as_str).unwrap_or(""),
        }
    }
}

impl From<&str> for Audience {
    fn from(s: &str) -> Self {
        Self::Single(s.to_owned())
    }
}

impl From<String> for Audience {
    fn from(s: String) -> Self {
        Self::Single(s)
    }
}

/// Claims carried by an AgentBridge NHI token.
///
/// Standard claims (`sub`, `iss`, `aud`, `iat`, `nbf`, `exp`, `jti`) plus the
/// agent identity block and scopes. `parent_token` embeds the parent's full
/// JWT for delegation-chain verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NhiClaims {
    /// Subject: the agent principal (e.g. `agent:billing-support`).
    pub sub: String,
    /// Issuer (corporate IdP or the harness's own token service).
    pub iss: String,
    /// Audience (the harness deployment id). RFC 7519 §4.1.3 allows
    /// either a single string or an array of strings; both are
    /// accepted here so mainstream IdPs (Okta, Auth0, Azure AD,
    /// Cognito) that emit multi-audience tokens are compatible.
    pub aud: Audience,
    /// Issued-at, epoch seconds.
    pub iat: u64,
    /// Not-before, epoch seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nbf: Option<u64>,
    /// Expiry, epoch seconds. `exp - iat` must be ≤ [`MAX_TTL_SECS`].
    pub exp: u64,
    /// Unique token id (revocation hook).
    pub jti: String,
    /// Agent instance uid bound into every emitted event.
    pub instance_uid: String,
    /// Agent charter.
    pub charter: String,
    /// Agent version.
    pub version: String,
    /// Granted scopes, e.g. `tool:db_write`, `payout`.
    pub scopes: Vec<String>,
    /// Parent agent's full JWT (delegation). `None` for root tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_token: Option<String>,
}

impl NhiClaims {
    /// True when `candidate`'s scopes are a subset of `self`'s.
    pub fn scopes_cover(&self, candidate: &NhiClaims) -> bool {
        candidate
            .scopes
            .iter()
            .all(|s| self.scopes.iter().any(|p| p == s))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn claims(scopes: &[&str]) -> NhiClaims {
        NhiClaims {
            sub: "agent:a".into(),
            iss: "idp".into(),
            aud: "harness".into(),
            iat: 0,
            nbf: None,
            exp: 60,
            jti: "j1".into(),
            instance_uid: "i1".into(),
            charter: "c".into(),
            version: "1".into(),
            scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
            parent_token: None,
        }
    }

    #[test]
    fn subset_logic() {
        let parent = claims(&["tool:read", "tool:write", "payout"]);
        assert!(parent.scopes_cover(&claims(&["tool:read"])));
        assert!(parent.scopes_cover(&claims(&["tool:read", "payout"])));
        assert!(parent.scopes_cover(&claims(&[])));
        assert!(!parent.scopes_cover(&claims(&["tool:admin"])));
        assert!(!parent.scopes_cover(&claims(&["tool:read", "tool:admin"])));
    }

    /// Single-string aud (`"aud": "agentbridge"`) round-trips.
    #[test]
    fn audience_single_string_round_trips() {
        let json = r#"{"aud":"agentbridge"}"#;
        #[derive(Deserialize)]
        struct Just {
            aud: Audience,
        }
        let value: Just = serde_json::from_str(json).unwrap();
        assert!(value.aud.contains("agentbridge"));
        assert!(!value.aud.contains("other"));
        assert_eq!(value.aud.primary(), "agentbridge");
    }

    /// Array aud (`"aud": ["agentbridge", "other"]`) is accepted per
    /// RFC 7519 §4.1.3. This is exactly the case that used to lock out
    /// Okta / Auth0 / Azure AD multi-audience apps.
    #[test]
    fn audience_array_form_is_accepted_and_probed() {
        let json = r#"{"aud":["other","agentbridge","yet-another"]}"#;
        #[derive(Deserialize)]
        struct Just {
            aud: Audience,
        }
        let value: Just = serde_json::from_str(json).unwrap();
        assert!(value.aud.contains("agentbridge"));
        assert!(value.aud.contains("other"));
        assert!(!value.aud.contains("nope"));
    }
}
