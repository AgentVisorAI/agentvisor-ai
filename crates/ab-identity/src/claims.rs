//! NHI JWT claims.

use serde::{Deserialize, Serialize};

/// Hard TTL ceiling for NHI tokens: 15 minutes (brief Module D).
pub const MAX_TTL_SECS: u64 = 15 * 60;

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
    /// Audience (the harness deployment id).
    pub aud: String,
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
        candidate.scopes.iter().all(|s| self.scopes.iter().any(|p| p == s))
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
}
