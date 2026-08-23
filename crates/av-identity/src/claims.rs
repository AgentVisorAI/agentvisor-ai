//! NHI JWT claims.

use serde::{Deserialize, Serialize};

/// Hard TTL ceiling for NHI tokens: 15 minutes (brief Module D).
pub const MAX_TTL_SECS: u64 = 15 * 60;

/// The `aud` claim per RFC 7519 §4.1.3: "a StringOrURI value or an
/// array of StringOrURI". Mainstream IdPs (Okta, Auth0, Azure AD,
/// Cognito) emit the array form for multi-audience apps
/// (`"aud": ["agentvisor", "some-other-svc"]`). Accepting only the
/// string form silently locks the operator out at go-live with an
/// `invalid type: sequence, expected string` error deep inside
/// `jsonwebtoken::decode`, before our validator's aud check runs.
///
/// Defense-in-depth: reject `"aud": []` at deserialize
/// time. Without this guard `Multi(vec![])` would still be caught by
/// `jsonwebtoken`'s `set_audience` intersection check, but a future
/// refactor that removed the library gate would leave the empty-list
/// shape silently accepting *any* token. Refusing at the concrete
/// deserialize step means the audience gate remains sound at both
/// layers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Audience {
    /// Single-string form (`"aud": "agentvisor"`).
    Single(String),
    /// Array form (`"aud": ["agentvisor", "other"]`).
    Multi(Vec<String>),
}

impl serde::Serialize for Audience {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Single(value) => serializer.serialize_str(value),
            Self::Multi(values) => {
                use serde::ser::SerializeSeq as _;
                let mut seq = serializer.serialize_seq(Some(values.len()))?;
                for value in values {
                    seq.serialize_element(value)?;
                }
                seq.end()
            }
        }
    }
}

impl<'de> serde::Deserialize<'de> for Audience {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::{SeqAccess, Visitor};
        struct AudienceVisitor;
        impl<'de> Visitor<'de> for AudienceVisitor {
            type Value = Audience;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a JWT audience: a non-empty string or a non-empty array of strings")
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Audience, E> {
                if value.is_empty() {
                    return Err(E::custom(
                        "aud claim must not be an empty string; provide the audience or omit the claim",
                    ));
                }
                Ok(Audience::Single(value.to_owned()))
            }
            fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Audience, E> {
                if value.is_empty() {
                    return Err(E::custom(
                        "aud claim must not be an empty string; provide the audience or omit the claim",
                    ));
                }
                Ok(Audience::Single(value))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Audience, A::Error> {
                let mut values = Vec::with_capacity(seq.size_hint().unwrap_or(0));
                while let Some(value) = seq.next_element::<String>()? {
                    values.push(value);
                }
                if values.is_empty() {
                    return Err(serde::de::Error::custom(
                        "aud claim must not be an empty array; provide the audience or omit the claim",
                    ));
                }
                // Symmetry with the empty-string reject in
                // visit_str. Without this, an
                // `aud: [""]` would deserialize as
                // `Multi(vec!["".to_owned()])` and pass the "not
                // empty array" gate while still carrying zero
                // meaningful audience entries. Any code path that
                // treats `contains("expected")` returning false as
                // "audience is present but doesn't match" (vs
                // "audience is unspecified") is misled.
                if values.iter().any(|v| v.is_empty()) {
                    return Err(serde::de::Error::custom(
                        "aud claim array must not contain empty strings",
                    ));
                }
                Ok(Audience::Multi(values))
            }
        }
        deserializer.deserialize_any(AudienceVisitor)
    }
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

/// Claims carried by an AgentVisor AI NHI token.
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

    /// Single-string aud (`"aud": "agentvisor"`) round-trips.
    #[test]
    fn audience_single_string_round_trips() {
        let json = r#"{"aud":"agentvisor"}"#;
        #[derive(Deserialize)]
        struct Just {
            aud: Audience,
        }
        let value: Just = serde_json::from_str(json).unwrap();
        assert!(value.aud.contains("agentvisor"));
        assert!(!value.aud.contains("other"));
        assert_eq!(value.aud.primary(), "agentvisor");
    }

    /// Array aud (`"aud": ["agentvisor", "other"]`) is accepted per
    /// RFC 7519 §4.1.3. This is exactly the case that used to lock out
    /// Okta / Auth0 / Azure AD multi-audience apps.
    #[test]
    fn audience_array_form_is_accepted_and_probed() {
        let json = r#"{"aud":["other","agentvisor","yet-another"]}"#;
        #[derive(Deserialize)]
        struct Just {
            aud: Audience,
        }
        let value: Just = serde_json::from_str(json).unwrap();
        assert!(value.aud.contains("agentvisor"));
        assert!(value.aud.contains("other"));
        assert!(!value.aud.contains("nope"));
    }

    /// Symmetry with the empty-string reject in
    /// visit_str. An `aud: [""]` would
    /// otherwise deserialize as `Multi(vec!["".to_owned()])` and
    /// pass the "not empty array" gate while still carrying zero
    /// meaningful audience entries.
    #[test]
    fn audience_array_with_empty_string_element_is_rejected() {
        let json = r#"{"aud":["real","",""]}"#;
        #[derive(Debug, Deserialize)]
        #[allow(dead_code)]
        struct Just {
            aud: Audience,
        }
        let err = serde_json::from_str::<Just>(json).unwrap_err().to_string();
        assert!(
            err.contains("empty strings"),
            "expected empty-string-in-array rejection, got: {err}",
        );
    }

    /// Mirror of the empty-array rejection for the string half. The docstring
    /// promises "non-empty string or non-empty array". Refuse the
    /// empty string at deserialize time as defense-in-depth against a
    /// misconfigured validator whose expected audience is also `""`.
    #[test]
    fn audience_empty_string_is_rejected_by_the_concrete_deserialize() {
        let json = r#"{"aud":""}"#;
        #[derive(Debug, Deserialize)]
        #[allow(dead_code)]
        struct Just {
            aud: Audience,
        }
        let err = serde_json::from_str::<Just>(json).unwrap_err().to_string();
        assert!(
            err.contains("empty string"),
            "expected empty-string rejection, got: {err}",
        );
    }

    /// An empty audience array must be rejected at the
    /// concrete deserialize step, so the audience gate remains sound
    /// even if a future refactor drops `jsonwebtoken`'s
    /// `set_audience` intersection check.
    #[test]
    fn audience_empty_array_is_rejected_by_the_concrete_deserialize() {
        let json = r#"{"aud":[]}"#;
        #[derive(Debug, Deserialize)]
        #[allow(dead_code)]
        struct Just {
            aud: Audience,
        }
        let err = serde_json::from_str::<Just>(json).unwrap_err().to_string();
        assert!(
            err.contains("empty array"),
            "expected empty-array rejection, got: {err}",
        );
    }

    /// `aud` present but of an unsupported JSON type (number,
    /// bool, null) must be rejected with a clear "expected a JWT
    /// audience" message — the untagged enum variant used to fall
    /// through with a much more confusing message.
    #[test]
    fn audience_unsupported_json_type_is_rejected() {
        #[derive(Debug, Deserialize)]
        #[allow(dead_code)]
        struct Just {
            aud: Audience,
        }
        for wrong in [r#"{"aud":42}"#, r#"{"aud":true}"#, r#"{"aud":null}"#] {
            let err = serde_json::from_str::<Just>(wrong).unwrap_err().to_string();
            assert!(
                err.contains("JWT audience"),
                "expected JWT-audience rejection for {wrong}, got: {err}",
            );
        }
    }
}
