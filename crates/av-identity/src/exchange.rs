//! RFC 8693 token exchange: exchange an inbound NHI token for a
//! backend-scoped token with narrowed scopes.
//!
//! The exchange endpoint accepts a form-encoded request containing:
//! - `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`
//! - `subject_token` — the inbound NHI JWT
//! - `subject_token_type=urn:ietf:params:oauth:token-type:jwt`
//! - `audience` — the target backend name
//! - `scope` — requested scopes (space-separated, optional)
//!
//! The issued token preserves the original `sub` (human principal),
//! places the agent identity in `act`, carries `azp` from the exchange
//! client, and scopes = requested ∩ subject ∩ actor (intersection, never
//! union).

use crate::claims::{ActorClaim, Audience, NhiClaims};
use crate::revocation::{RevocationIdentity, RevocationStore, RevokedBy};
use crate::validator::{
    validate_claim_fields, IdentityError, DEFAULT_LEEWAY_SECS, MAX_IDENTITY_STRING_CHARS, MAX_SCOPES,
};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Signed ancestry travels with exchanged tokens without trusting such claims
/// in upstream NHI tokens. Each entry came from a verified delegation link.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExchangedClaims {
    /// Standard identity and authorization claims.
    #[serde(flatten)]
    pub claims: NhiClaims,
    /// Original identities, leaf first, for JTI and instance revocation.
    pub av_subject_tokens: Vec<RevocationIdentity>,
    /// Total delegation depth, including parent links removed during exchange.
    pub av_delegation_depth: usize,
}

impl std::ops::Deref for ExchangedClaims {
    type Target = NhiClaims;
    fn deref(&self) -> &Self::Target {
        &self.claims
    }
}

/// RFC 8693 grant type.
pub const TOKEN_EXCHANGE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

/// RFC 8693 JWT token type.
pub const JWT_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:jwt";

/// Token exchange request (form-encoded body).
#[derive(Debug, Deserialize)]
pub struct TokenExchangeRequest {
    /// RFC 8693 grant type URI.
    pub grant_type: String,
    /// The inbound NHI JWT to exchange.
    pub subject_token: String,
    /// Token type of the subject (must be `urn:ietf:params:oauth:token-type:jwt`).
    pub subject_token_type: String,
    /// Target backend audience for the exchanged token.
    pub audience: String,
    /// Requested scopes (space-separated, optional).
    #[serde(default)]
    pub scope: Option<String>,
}

/// Token exchange response.
#[derive(Debug, Serialize)]
pub struct TokenExchangeResponse {
    /// The exchanged token (JWT or JSON-encoded claims).
    pub access_token: String,
    /// Token type URI of the issued token.
    pub issued_token_type: String,
    /// Always `"Bearer"`.
    pub token_type: String,
    /// Seconds until the exchanged token expires.
    pub expires_in: u64,
    /// Effective scopes of the exchanged token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

/// Errors from the exchange process.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ExchangeError {
    /// The `grant_type` is not the RFC 8693 token exchange URI.
    #[error("unsupported grant_type: {0}")]
    UnsupportedGrant(String),
    /// The `subject_token_type` is not `urn:ietf:params:oauth:token-type:jwt`.
    #[error("unsupported subject_token_type: {0}")]
    UnsupportedTokenType(String),
    /// The inbound subject token failed identity validation.
    #[error("subject token validation failed: {0}")]
    SubjectInvalid(#[from] crate::validator::IdentityError),
    /// The requested scope is not a subset of the subject's scopes.
    #[error("requested scope {0:?} exceeds subject scopes")]
    ScopeExceedsSubject(String),
    /// Scope intersection produced an empty set.
    #[error("no scopes remain after intersection")]
    EmptyIntersection,
    /// The subject has no remaining lifetime to delegate.
    #[error("subject token has expired")]
    SubjectExpired,
    /// The caller failed to supply a verified source chain.
    #[error("subject delegation chain is missing or inconsistent")]
    MissingSubjectChain,
    /// A scope request exceeds the supported count or field limits.
    #[error("requested scopes exceed supported limits or contain invalid characters")]
    InvalidScopes,
    /// Token signing failed.
    #[error("token signing failed: {0}")]
    SigningFailed(String),
    /// The resulting delegation chain exceeds the maximum allowed depth.
    #[error("delegation depth {depth} exceeds maximum {max}")]
    DelegationExceeded {
        /// The computed depth of the resulting chain.
        depth: usize,
        /// The configured maximum.
        max: usize,
    },
    /// The requested audience is not a configured backend name.
    #[error("target audience {0:?} is not an allowed backend")]
    TargetNotAllowed(String),
}

/// Compute the intersection of two scope sets, respecting wildcard rules.
/// Returns only scopes that are covered by BOTH inputs.
pub fn scope_intersection(a: &[String], b: &[String]) -> Vec<String> {
    let mut result = Vec::new();
    let mut seen = HashSet::new();
    for scope in a {
        if b.iter().any(|bs| scope_covers(bs, scope)) && seen.insert(scope.as_str()) {
            result.push(scope.clone());
        }
    }
    for scope in b {
        if a.iter().any(|as_| scope_covers(as_, scope)) && seen.insert(scope.as_str()) {
            result.push(scope.clone());
        }
    }
    result
}

/// Returns true if `parent` covers `child` (same wildcard rules as the
/// delegation chain validator).
fn scope_covers(parent: &str, child: &str) -> bool {
    parent == "*"
        || parent == child
        || parent.strip_suffix(":*").is_some_and(|prefix| {
            child
                .strip_prefix(prefix)
                .is_some_and(|rest| rest.starts_with(':'))
        })
}

/// Parameters for building exchanged claims.
pub struct ExchangeParams<'a> {
    /// Claims from the validated inbound subject token.
    pub subject: &'a NhiClaims,
    /// Verified identities returned by `IdentityValidator`, leaf first.
    pub subject_chain: &'a [RevocationIdentity],
    /// Combined parent-token and actor depth returned by the validator.
    pub subject_delegation_depth: usize,
    /// Target backend audience for the exchanged token.
    pub target_audience: &'a str,
    /// Space-separated requested scopes (None inherits the subject's scopes).
    pub requested_scopes: Option<&'a str>,
    /// Authorized party identifier (the client requesting the exchange).
    pub azp: &'a str,
    /// Current time in seconds since epoch.
    pub now_s: u64,
    /// TTL in seconds for the exchanged token.
    pub ttl_s: u64,
    /// Issuer URI for the gateway itself (not the upstream IdP).
    pub issuer: &'a str,
    /// Maximum allowed delegation depth. The resulting `act` chain must
    /// not exceed this depth.
    pub max_depth: usize,
    /// Backend names that are valid exchange targets. When non-empty, the
    /// target audience must appear in this list.
    pub allowed_audiences: &'a [String],
}

/// Build exchanged claims from a validated subject token. The resulting
/// token preserves `sub` (the human), adds a new link to the `act`
/// chain, scopes to the intersection of requested and subject scopes,
/// and narrows audience to the target backend.
pub fn build_exchanged_claims(params: &ExchangeParams<'_>) -> Result<ExchangedClaims, ExchangeError> {
    let subject = params.subject;
    if params.subject_chain.first() != Some(&RevocationIdentity::from(subject))
        || params.subject_chain.len().saturating_sub(1) > params.subject_delegation_depth
        || subject.act.as_ref().map_or(0, |a| 1 + a.depth()) > params.subject_delegation_depth
    {
        return Err(ExchangeError::MissingSubjectChain);
    }

    if !params.allowed_audiences.is_empty()
        && !params
            .allowed_audiences
            .iter()
            .any(|a| a == params.target_audience)
    {
        return Err(ExchangeError::TargetNotAllowed(params.target_audience.to_owned()));
    }

    // Bound input before allocating or intersecting. UTF-8 uses at most four
    // bytes per code point; the extra byte permits a separating space.
    if params
        .requested_scopes
        .is_some_and(|s| s.len() > MAX_SCOPES * (4 * MAX_IDENTITY_STRING_CHARS + 1))
    {
        return Err(ExchangeError::InvalidScopes);
    }
    let requested: Vec<String> = match params.requested_scopes {
        Some(scopes) => scopes
            .split(' ')
            .take(MAX_SCOPES + 1)
            .map(str::to_owned)
            .collect(),
        None => subject.scopes.clone(),
    };
    if requested.len() > MAX_SCOPES
        || requested.iter().any(|s| {
            s.is_empty()
                || s.chars().count() > MAX_IDENTITY_STRING_CHARS
                || !s.bytes().all(|b| matches!(b, 0x21 | 0x23..=0x5b | 0x5d..=0x7e))
                || av_core::text::contains_bidi_or_zero_width(s)
        })
    {
        return Err(ExchangeError::InvalidScopes);
    }

    // RFC 6749 scope-token grammar also applies to subject entries. The
    // inbound NHI profile permits non-ASCII scope names for compatibility,
    // but an OAuth exchange must never serialize those as an invalid scope.
    if subject
        .scopes
        .iter()
        .any(|s| s.is_empty() || !s.bytes().all(|b| matches!(b, 0x21 | 0x23..=0x5b | 0x5d..=0x7e)))
    {
        return Err(ExchangeError::InvalidScopes);
    }
    let effective = scope_intersection(&requested, &subject.scopes);
    if effective.is_empty() {
        return Err(ExchangeError::EmptyIntersection);
    }

    let actor = ActorClaim {
        sub: params.azp.to_owned(),
        act: subject.act.as_ref().map(|a| Box::new(a.clone())),
    };
    let depth = params.subject_delegation_depth.saturating_add(1);
    if depth > params.max_depth {
        return Err(ExchangeError::DelegationExceeded {
            depth,
            max: params.max_depth,
        });
    }

    let exp = params
        .now_s
        .saturating_add(params.ttl_s.min(crate::MAX_TTL_SECS))
        .min(subject.exp);
    if exp <= params.now_s {
        return Err(ExchangeError::SubjectExpired);
    }

    let claims = NhiClaims {
        sub: subject.sub.clone(),
        iss: params.issuer.to_owned(),
        aud: Audience::Single(params.target_audience.to_owned()),
        iat: params.now_s,
        nbf: Some(params.now_s.max(subject.nbf.unwrap_or(subject.iat))),
        exp,
        jti: av_core::ids::new_event_uid(),
        azp: Some(params.azp.to_owned()),
        act: Some(actor),
        instance_uid: subject.instance_uid.clone(),
        charter: subject.charter.clone(),
        version: subject.version.clone(),
        scopes: effective,
        parent_token: None,
    };
    validate_claim_fields(&claims, params.now_s, DEFAULT_LEEWAY_SECS, false)?;
    let exchanged = ExchangedClaims {
        claims,
        av_subject_tokens: params.subject_chain.to_vec(),
        av_delegation_depth: depth,
    };
    // Leave room for base64url expansion, the JOSE header and Ed25519
    // signature inside the verifier's 16 KiB pre-authentication limit.
    if serde_json::to_vec(&exchanged)
        .map_err(|error| ExchangeError::SigningFailed(error.to_string()))?
        .len()
        > 11 * 1024
    {
        return Err(ExchangeError::InvalidScopes);
    }
    Ok(exchanged)
}

/// Trust and time settings for a token issued by this harness.
pub struct ExchangedValidation<'a> {
    /// Harness Ed25519 public key.
    pub key: &'a DecodingKey,
    /// Exact expected signing-key identifier.
    pub kid: &'a str,
    /// Exact expected harness issuer.
    pub issuer: &'a str,
    /// Configured backend names accepted as single-string audiences.
    pub allowed_audiences: &'a [String],
    /// Configured maximum combined delegation depth.
    pub max_depth: usize,
    /// Validation clock, in epoch seconds.
    pub now_s: u64,
    /// Exact expected type: `JWT` or `av-tool+jwt`.
    pub token_type: &'a str,
    /// Permit bounded future activation for holder revocation only.
    pub for_revocation: bool,
}

/// Verify a harness-issued token without reading revocation storage.
pub fn verify_exchanged_token(
    token: &str,
    params: &ExchangedValidation<'_>,
) -> Result<ExchangedClaims, IdentityError> {
    if token.len() > 16 * 1024 {
        return Err(IdentityError::Malformed("exchanged token exceeds 16 KiB".into()));
    }
    let header = jsonwebtoken::decode_header(token).map_err(|e| IdentityError::Malformed(e.to_string()))?;
    crate::validator::validate_jose_header(&header)?;
    if !matches!(params.token_type, "JWT" | "av-tool+jwt")
        || header.typ.as_deref() != Some(params.token_type)
        || header.alg != Algorithm::EdDSA
        || header.kid.as_deref() != Some(params.kid)
    {
        return Err(IdentityError::Verification(
            "unexpected exchanged-token header".into(),
        ));
    }
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_audience(params.allowed_audiences);
    validation.set_issuer(&[params.issuer]);
    validation.set_required_spec_claims(&["exp", "aud", "sub", "iss", "iat", "jti", "nbf"]);
    // Apply the supplied clock after signature verification, rather than
    // mixing it with jsonwebtoken's process clock.
    validation.validate_exp = false;
    validation.validate_nbf = false;
    let token = jsonwebtoken::decode::<ExchangedClaims>(token, params.key, &validation)
        .map_err(|e| IdentityError::Verification(e.to_string()))?
        .claims;
    let Audience::Single(audience) = &token.aud else {
        return Err(IdentityError::Verification(
            "exchanged audience must be a single backend".into(),
        ));
    };
    if !params.allowed_audiences.contains(audience) || token.parent_token.is_some() {
        return Err(IdentityError::Verification(
            "invalid exchanged-token audience or parent".into(),
        ));
    }
    validate_claim_fields(
        &token.claims,
        params.now_s,
        DEFAULT_LEEWAY_SECS,
        params.for_revocation,
    )?;
    if token.scopes.iter().any(|scope| {
        scope.is_empty()
            || !scope
                .bytes()
                .all(|b| matches!(b, 0x21 | 0x23..=0x5b | 0x5d..=0x7e))
    }) {
        return Err(IdentityError::Verification("invalid OAuth scope token".into()));
    }
    if (!params.for_revocation && token.exp <= params.now_s)
        || token.exp < params.now_s.saturating_sub(DEFAULT_LEEWAY_SECS)
    {
        return Err(IdentityError::Expired {
            exp: token.exp,
            now: params.now_s,
        });
    }
    if !params.for_revocation
        && token
            .nbf
            .is_some_and(|nbf| nbf > params.now_s.saturating_add(DEFAULT_LEEWAY_SECS))
    {
        return Err(IdentityError::Verification("token is not yet active".into()));
    }
    if token.av_subject_tokens.is_empty()
        || token.av_subject_tokens.len() > params.max_depth
        || token.av_delegation_depth == 0
        || token.av_delegation_depth > params.max_depth
        || token.av_subject_tokens.len() > token.av_delegation_depth
        || token.act.as_ref().map_or(0, |a| 1 + a.depth()) > token.av_delegation_depth
        || token.act.is_none()
    {
        return Err(IdentityError::Verification(
            "invalid exchanged-token ancestry or depth".into(),
        ));
    }
    for ancestor in &token.av_subject_tokens {
        if ancestor.iss.is_empty()
            || ancestor.iss.chars().count() > MAX_IDENTITY_STRING_CHARS
            || av_core::text::contains_bidi_or_zero_width(&ancestor.iss)
            || ancestor.jti.trim().is_empty()
            || ancestor.instance_uid.trim().is_empty()
            || ancestor.jti.chars().any(char::is_control)
            || ancestor.instance_uid.chars().any(char::is_control)
            || ancestor.jti.chars().count() > MAX_IDENTITY_STRING_CHARS
            || ancestor.instance_uid.chars().count() > 128
            || av_core::text::contains_bidi_or_zero_width(&ancestor.jti)
            || av_core::text::contains_bidi_or_zero_width(&ancestor.instance_uid)
            || ancestor.iat > token.iat.saturating_add(DEFAULT_LEEWAY_SECS)
        {
            return Err(IdentityError::Verification(
                "invalid exchanged-token ancestor".into(),
            ));
        }
    }
    if token
        .av_subject_tokens
        .first()
        .is_none_or(|source| source.instance_uid != token.instance_uid)
    {
        return Err(IdentityError::Verification(
            "subject instance does not match ancestry".into(),
        ));
    }
    Ok(token)
}

/// Check a verified exchanged token in its separate namespace, then check
/// every original identity against JTI and instance revocation rules.
pub fn check_exchanged_revocation(
    token: &ExchangedClaims,
    exchanged: &dyn RevocationStore,
    upstream: &dyn RevocationStore,
) -> Result<(), IdentityError> {
    if exchanged
        .check_token(&token.iss, &token.jti, &token.instance_uid, token.iat)
        .map_err(IdentityError::RevocationUnavailable)?
        .is_some()
    {
        return Err(IdentityError::Revoked(token.jti.clone()));
    }
    for ancestor in &token.av_subject_tokens {
        match upstream
            .check_token(&ancestor.iss, &ancestor.jti, &ancestor.instance_uid, ancestor.iat)
            .map_err(IdentityError::RevocationUnavailable)?
        {
            None => {}
            Some(RevokedBy::Jti) => return Err(IdentityError::Revoked(ancestor.jti.clone())),
            Some(RevokedBy::Instance { cutoff }) => {
                return Err(IdentityError::InstanceRevoked {
                    instance_uid: ancestor.instance_uid.clone(),
                    cutoff,
                })
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

    use super::*;

    fn base_claims(scopes: &[&str]) -> NhiClaims {
        NhiClaims {
            sub: "user:alice@corp.com".into(),
            iss: "idp.corp.com".into(),
            aud: "agentvisor-ai".into(),
            iat: 1000,
            nbf: None,
            exp: 1900,
            jti: "jti-1".into(),
            azp: None,
            act: None,
            instance_uid: "inst-1".into(),
            charter: "support".into(),
            version: "1.0".into(),
            scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
            parent_token: None,
        }
    }

    #[test]
    fn intersection_exact_match() {
        let a = vec!["tool:read".to_owned(), "tool:write".to_owned()];
        let b = vec!["tool:read".to_owned(), "payout".to_owned()];
        let result = scope_intersection(&a, &b);
        assert_eq!(result, vec!["tool:read".to_owned()]);
    }

    #[test]
    fn intersection_wildcard() {
        let a = vec!["tool:*".to_owned()];
        let b = vec!["tool:read".to_owned(), "tool:write".to_owned()];
        let result = scope_intersection(&a, &b);
        assert!(result.contains(&"tool:read".to_owned()));
        assert!(result.contains(&"tool:write".to_owned()));
    }

    #[test]
    fn intersection_star() {
        let a = vec!["*".to_owned()];
        let b = vec!["tool:read".to_owned(), "payout".to_owned()];
        let result = scope_intersection(&a, &b);
        assert!(result.contains(&"tool:read".to_owned()));
        assert!(result.contains(&"payout".to_owned()));
    }

    #[test]
    fn intersection_empty() {
        let a = vec!["tool:read".to_owned()];
        let b = vec!["payout".to_owned()];
        let result = scope_intersection(&a, &b);
        assert!(result.is_empty());
    }

    fn default_params<'a>(
        subject: &'a NhiClaims,
        target: &'a str,
        scopes: Option<&'a str>,
        chain: &'a [RevocationIdentity],
    ) -> ExchangeParams<'a> {
        ExchangeParams {
            subject,
            subject_chain: chain,
            subject_delegation_depth: subject.act.as_ref().map_or(0, |a| 1 + a.depth()),
            target_audience: target,
            requested_scopes: scopes,
            azp: "client-1",
            now_s: 1100,
            ttl_s: 60,
            issuer: "agentvisor-ai",
            max_depth: 4,
            allowed_audiences: &[],
        }
    }

    #[test]
    fn exchanged_claims_preserve_sub_and_narrow_scopes() {
        let subject = base_claims(&["tool:read", "tool:write", "payout"]);
        let chain = [RevocationIdentity::from(&subject)];
        let params = default_params(&subject, "backend-a", Some("tool:read payout"), &chain);
        let result = build_exchanged_claims(&params).unwrap();
        assert_eq!(result.sub, "user:alice@corp.com");
        assert_eq!(result.azp, Some("client-1".to_owned()));
        assert!(result.act.is_some());
        assert_eq!(result.act.as_ref().unwrap().sub, "client-1");
        assert_eq!(result.aud, Audience::Single("backend-a".to_owned()));
        assert_eq!(result.scopes, vec!["tool:read", "payout"]);
        assert_eq!(result.exp - result.iat, 60);
        assert_eq!(result.iss, "agentvisor-ai");
    }

    #[test]
    fn exchanged_claims_add_act_link() {
        let mut subject = base_claims(&["tool:read"]);
        subject.act = Some(ActorClaim {
            sub: "agent:billing".into(),
            act: None,
        });
        let chain = [RevocationIdentity::from(&subject)];
        let mut params = default_params(&subject, "backend-b", None, &chain);
        params.azp = "client-2";
        let result = build_exchanged_claims(&params).unwrap();
        let act = result.act.as_ref().unwrap();
        assert_eq!(act.sub, "client-2");
        let inner = act.act.as_ref().unwrap();
        assert_eq!(inner.sub, "agent:billing");
        assert!(inner.act.is_none());
    }

    #[test]
    fn exchange_refuses_scope_escalation() {
        let subject = base_claims(&["tool:read"]);
        let chain = [RevocationIdentity::from(&subject)];
        let params = default_params(&subject, "backend-a", Some("tool:write"), &chain);
        let result = build_exchanged_claims(&params);
        assert!(result.is_err());
    }

    #[test]
    fn exchange_refuses_excessive_depth() {
        let mut subject = base_claims(&["tool:read"]);
        subject.act = Some(ActorClaim {
            sub: "a1".into(),
            act: Some(Box::new(ActorClaim {
                sub: "a2".into(),
                act: None,
            })),
        });
        let chain = [RevocationIdentity::from(&subject)];
        let mut params = default_params(&subject, "backend-a", None, &chain);
        params.max_depth = 1;
        let result = build_exchanged_claims(&params);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ExchangeError::DelegationExceeded { depth: 3, max: 1 }
        ));
    }

    #[test]
    fn exchange_refuses_unknown_audience() {
        let subject = base_claims(&["tool:read"]);
        let allowed = vec!["backend-a".to_owned(), "backend-b".to_owned()];
        let chain = [RevocationIdentity::from(&subject)];
        let mut params = default_params(&subject, "backend-c", None, &chain);
        params.allowed_audiences = &allowed;
        let result = build_exchanged_claims(&params);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ExchangeError::TargetNotAllowed(_)));
    }

    #[test]
    fn exchange_allows_known_audience() {
        let subject = base_claims(&["tool:read"]);
        let allowed = vec!["backend-a".to_owned()];
        let chain = [RevocationIdentity::from(&subject)];
        let mut params = default_params(&subject, "backend-a", None, &chain);
        params.allowed_audiences = &allowed;
        let result = build_exchanged_claims(&params);
        assert!(result.is_ok());
    }

    #[test]
    fn scope_requests_are_bounded_and_empty_authority_is_refused() {
        let subject = base_claims(&[]);
        let chain = [RevocationIdentity::from(&subject)];
        for requested in [None, Some("tool:admin")] {
            assert!(matches!(
                build_exchanged_claims(&default_params(&subject, "backend-a", requested, &chain)),
                Err(ExchangeError::EmptyIntersection)
            ));
        }
        let subject = base_claims(&["tool:*"]);
        let chain = [RevocationIdentity::from(&subject)];
        let excessive = (0..65).map(|i| format!("tool:{i}")).collect::<Vec<_>>().join(" ");
        let huge = "x".repeat(70_000);
        let long_field = format!("tool:{}", "x".repeat(256));
        for requested in [&excessive, &huge, &long_field] {
            assert!(matches!(
                build_exchanged_claims(&default_params(&subject, "backend-a", Some(requested), &chain)),
                Err(ExchangeError::InvalidScopes)
            ));
        }
        let result = build_exchanged_claims(&default_params(
            &subject,
            "backend-a",
            Some("tool:a tool:a tool:b"),
            &chain,
        ))
        .unwrap();
        assert_eq!(result.scopes, vec!["tool:a", "tool:b"]);
    }

    #[test]
    fn exchanged_output_stays_inside_verifier_size_limit_and_preserves_activation() {
        let mut subject = base_claims(&["tool:*"]);
        subject.nbf = Some(1105);
        let chain = [RevocationIdentity::from(&subject)];
        let params = default_params(&subject, "backend-a", Some("tool:read"), &chain);
        assert_eq!(build_exchanged_claims(&params).unwrap().nbf, Some(1105));
        let oversized = (0..64)
            .map(|i| format!("tool:{i}:{}", "x".repeat(192)))
            .collect::<Vec<_>>()
            .join(" ");
        let params = default_params(&subject, "backend-a", Some(&oversized), &chain);
        assert!(matches!(
            build_exchanged_claims(&params),
            Err(ExchangeError::InvalidScopes)
        ));
    }

    #[test]
    fn exchange_never_outlives_its_subject_or_extends_depth_budget() {
        let mut subject = base_claims(&["tool:read"]);
        subject.exp = 1105;
        let chain = [RevocationIdentity::from(&subject)];
        let mut params = default_params(&subject, "backend-a", None, &chain);
        params.ttl_s = u64::MAX;
        let result = build_exchanged_claims(&params).unwrap();
        assert_eq!(result.exp, 1105);
        params.now_s = 1105;
        assert!(matches!(
            build_exchanged_claims(&params),
            Err(ExchangeError::SubjectExpired)
        ));
        params.now_s = 1100;
        params.subject_delegation_depth = params.max_depth;
        assert!(matches!(
            build_exchanged_claims(&params),
            Err(ExchangeError::DelegationExceeded { depth: 5, max: 4 })
        ));
        params.subject_delegation_depth = 0;
        params.subject_chain = &[];
        assert!(matches!(
            build_exchanged_claims(&params),
            Err(ExchangeError::MissingSubjectChain)
        ));
    }

    fn exchange_keys() -> (jsonwebtoken::EncodingKey, DecodingKey) {
        use ed25519_dalek::pkcs8::{spki::der::pem::LineEnding, EncodePrivateKey, EncodePublicKey};
        let signing = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
        let private = signing.to_pkcs8_pem(LineEnding::LF).unwrap();
        let public = signing.verifying_key().to_public_key_pem(LineEnding::LF).unwrap();
        (
            jsonwebtoken::EncodingKey::from_ed_pem(private.as_bytes()).unwrap(),
            DecodingKey::from_ed_pem(public.as_bytes()).unwrap(),
        )
    }

    fn signed_exchange(token: &ExchangedClaims, typ: &str, key: &jsonwebtoken::EncodingKey) -> String {
        let mut header = jsonwebtoken::Header::new(Algorithm::EdDSA);
        header.kid = Some("exchange-key".into());
        header.typ = Some(typ.into());
        jsonwebtoken::encode(&header, token, key).unwrap()
    }

    #[test]
    fn exchanged_verification_enforces_type_issuer_audience_signature_time_and_ancestry() {
        let subject = base_claims(&["tool:read"]);
        let chain = [RevocationIdentity::from(&subject)];
        let token = build_exchanged_claims(&default_params(&subject, "backend-a", None, &chain)).unwrap();
        let (encoding, decoding) = exchange_keys();
        let audiences = ["backend-a".to_owned()];
        let mut params = ExchangedValidation {
            key: &decoding,
            kid: "exchange-key",
            issuer: "agentvisor-ai",
            allowed_audiences: &audiences,
            max_depth: 4,
            now_s: 1100,
            token_type: "JWT",
            for_revocation: false,
        };
        let signed = signed_exchange(&token, "JWT", &encoding);
        assert_eq!(
            verify_exchanged_token(&signed, &params)
                .unwrap()
                .av_subject_tokens,
            chain
        );
        for typ in ["av-intent+jwt", "av-tool+jwt", "jwt"] {
            assert!(verify_exchanged_token(&signed_exchange(&token, typ, &encoding), &params).is_err());
        }
        params.token_type = "av-tool+jwt";
        assert!(verify_exchanged_token(&signed_exchange(&token, "av-tool+jwt", &encoding), &params).is_ok());
        params.token_type = "JWT";
        for mutation in 0..10 {
            let mut invalid = token.clone();
            match mutation {
                0 => invalid.claims.iss = "other-issuer".into(),
                1 => invalid.claims.aud = "other-backend".into(),
                2 => invalid.claims.aud = Audience::Multi(audiences.to_vec()),
                3 => invalid.av_subject_tokens.clear(),
                4 => invalid.av_subject_tokens[0].jti.clear(),
                5 => invalid.claims.jti.clear(),
                6 => invalid.av_delegation_depth = 5,
                7 => invalid.av_subject_tokens[0].instance_uid = "different".into(),
                8 => invalid.av_subject_tokens[0].iss.clear(),
                _ => invalid.claims.parent_token = Some("nested-jwt".into()),
            }
            assert!(
                verify_exchanged_token(&signed_exchange(&invalid, "JWT", &encoding), &params).is_err(),
                "accepted malformed exchanged token variant {mutation}"
            );
        }
        // Tokens issued before issuer-bound ancestry was introduced must be
        // reissued. Guessing the missing issuer would permit cross-issuer rules.
        let mut legacy = serde_json::to_value(&token).unwrap();
        legacy["av_subject_tokens"][0]
            .as_object_mut()
            .unwrap()
            .remove("iss");
        let mut header = jsonwebtoken::Header::new(Algorithm::EdDSA);
        header.kid = Some("exchange-key".into());
        let legacy = jsonwebtoken::encode(&header, &legacy, &encoding).unwrap();
        assert!(verify_exchanged_token(&legacy, &params).is_err());

        for mutation in 0..3 {
            let mut header = jsonwebtoken::Header::new(Algorithm::EdDSA);
            header.kid = Some("exchange-key".into());
            match mutation {
                0 => header.crit = Some(vec!["issuer-restriction".into()]),
                1 => header.crit = Some(vec![]),
                _ => header.extras.insert("b64", false),
            }
            let invalid = jsonwebtoken::encode(&header, &token, &encoding).unwrap();
            assert!(verify_exchanged_token(&invalid, &params).is_err());
        }

        let mut forged = signed.into_bytes();
        let end = forged.len() - 10;
        forged[end] = if forged[end] == b'A' { b'B' } else { b'A' };
        assert!(verify_exchanged_token(&String::from_utf8(forged).unwrap(), &params).is_err());
        params.now_s = token.exp;
        assert!(matches!(
            verify_exchanged_token(&signed_exchange(&token, "JWT", &encoding), &params),
            Err(IdentityError::Expired { .. })
        ));
        params.for_revocation = true;
        assert!(verify_exchanged_token(&signed_exchange(&token, "JWT", &encoding), &params).is_ok());
        params.for_revocation = false;
        params.now_s = 1000;
        assert!(verify_exchanged_token(&signed_exchange(&token, "JWT", &encoding), &params).is_err());
        params.for_revocation = true;
        assert!(verify_exchanged_token(&signed_exchange(&token, "JWT", &encoding), &params).is_ok());
    }

    #[test]
    fn exchanged_revocation_uses_original_issuance_and_separate_namespaces() {
        use crate::InMemoryRevocationStore;
        let subject = base_claims(&["tool:read"]);
        let chain = [
            RevocationIdentity::from(&subject),
            RevocationIdentity {
                iss: subject.iss.clone(),
                jti: "parent".into(),
                instance_uid: "parent-instance".into(),
                iat: 900,
            },
        ];
        let mut params = default_params(&subject, "backend-a", None, &chain);
        params.subject_delegation_depth = 1;
        let token = build_exchanged_claims(&params).unwrap();
        let upstream = InMemoryRevocationStore::new();
        let exchanged = InMemoryRevocationStore::new();
        upstream.revoke(&token.jti, 2000).unwrap();
        assert!(check_exchanged_revocation(&token, &exchanged, &upstream).is_ok());
        upstream.revoke_instance("parent-instance", 900, 2000).unwrap();
        assert_eq!(
            check_exchanged_revocation(&token, &exchanged, &upstream).unwrap_err(),
            IdentityError::InstanceRevoked {
                instance_uid: "parent-instance".into(),
                cutoff: 900
            }
        );
        let upstream = InMemoryRevocationStore::new();
        upstream
            .revoke_instance(&subject.instance_uid, 1000, 2000)
            .unwrap();
        assert!(matches!(
            check_exchanged_revocation(&token, &exchanged, &upstream),
            Err(IdentityError::InstanceRevoked { .. })
        ));
        let upstream = InMemoryRevocationStore::new();
        upstream.revoke("parent", 2000).unwrap();
        assert_eq!(
            check_exchanged_revocation(&token, &exchanged, &upstream).unwrap_err(),
            IdentityError::Revoked("parent".into())
        );
        let upstream = InMemoryRevocationStore::new();
        exchanged.revoke(&token.jti, 2000).unwrap();
        assert_eq!(
            check_exchanged_revocation(&token, &exchanged, &upstream).unwrap_err(),
            IdentityError::Revoked(token.jti.clone())
        );
        assert!(!upstream.is_revoked(&subject.jti).unwrap());
    }

    #[test]
    fn exchanged_revocation_store_errors_never_report_active() {
        struct Offline;
        impl RevocationStore for Offline {
            fn revoke(&self, _: &str, _: u64) -> Result<(), String> {
                Err("offline".into())
            }
            fn is_revoked(&self, _: &str) -> Result<bool, String> {
                Err("offline".into())
            }
        }
        let subject = base_claims(&["tool:read"]);
        let chain = [RevocationIdentity::from(&subject)];
        let token = build_exchanged_claims(&default_params(&subject, "backend-a", None, &chain)).unwrap();
        let live = crate::InMemoryRevocationStore::new();
        assert!(matches!(
            check_exchanged_revocation(&token, &Offline, &live),
            Err(IdentityError::RevocationUnavailable(_))
        ));
        assert!(matches!(
            check_exchanged_revocation(&token, &live, &Offline),
            Err(IdentityError::RevocationUnavailable(_))
        ));
    }

    #[test]
    fn oauth_scope_grammar_rejects_ambiguous_or_non_ascii_scope_tokens() {
        let subject = base_claims(&["tool:*"]);
        let chain = [RevocationIdentity::from(&subject)];
        for invalid in [
            "",
            "tool:read\ttool:write",
            "tool:read\n",
            "tool:read  tool:write",
            " tool:read",
            "tool:read ",
            "tool:\"read",
            "tool:read\\write",
            "tool:café",
        ] {
            assert!(
                matches!(
                    build_exchanged_claims(&default_params(&subject, "backend-a", Some(invalid), &chain)),
                    Err(ExchangeError::InvalidScopes)
                ),
                "accepted {invalid:?}"
            );
        }
        for invalid in ["tool:read tool:write", "tool:café", "tool:read\\write"] {
            let subject = base_claims(&[invalid]);
            let chain = [RevocationIdentity::from(&subject)];
            assert!(matches!(
                build_exchanged_claims(&default_params(&subject, "backend-a", None, &chain)),
                Err(ExchangeError::InvalidScopes)
            ));
        }
        let params = default_params(&subject, "backend-a", Some("tool:read tool:write"), &chain);
        assert_eq!(
            build_exchanged_claims(&params).unwrap().scopes,
            ["tool:read", "tool:write"]
        );
    }
}
