//! Token validation and delegation-chain verification.

use crate::claims::{NhiClaims, MAX_TTL_SECS};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use std::collections::HashMap;

/// Verification key material, bound to a `kid`.
pub enum KeyMaterial {
    /// Ed25519 public key, SPKI PEM (`-----BEGIN PUBLIC KEY-----`). EdDSA.
    Ed25519Pem(String),
    /// HMAC shared secret. HS256 (dev / shared-secret IdP integrations).
    HmacSecret(Vec<u8>),
}

impl std::fmt::Debug for KeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ed25519Pem(_) => f.write_str("KeyMaterial::Ed25519Pem(..)"),
            Self::HmacSecret(_) => f.write_str("KeyMaterial::HmacSecret(..)"), // never print secrets
        }
    }
}

/// Identity validation failures.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum IdentityError {
    /// Token structurally malformed.
    #[error("malformed token: {0}")]
    Malformed(String),
    /// Header lacks a `kid`.
    #[error("token header has no kid")]
    MissingKid,
    /// No key registered for this `kid`.
    #[error("unknown kid {0:?}")]
    UnknownKid(String),
    /// Token `alg` is not accepted, or does not match the key type for its
    /// `kid` (algorithm-confusion defense).
    #[error("algorithm {alg:?} not permitted for kid {kid:?}")]
    AlgorithmRejected {
        /// Stated algorithm.
        alg: String,
        /// Key id.
        kid: String,
    },
    /// Signature invalid / expired / nbf future / wrong audience — collapsed
    /// by jsonwebtoken; the detail string preserves the cause.
    #[error("verification failed: {0}")]
    Verification(String),
    /// `exp - iat` exceeds the 15-minute NHI cap.
    #[error("ttl {0}s exceeds the {MAX_TTL_SECS}s NHI cap")]
    TtlTooLong(u64),
    /// `exp ≤ iat` or other timestamp nonsense.
    #[error("inconsistent timestamps (iat {iat}, exp {exp})")]
    BadTimestamps {
        /// Issued-at.
        iat: u64,
        /// Expiry.
        exp: u64,
    },
    /// Required identity field empty.
    #[error("empty identity field {0}")]
    EmptyField(&'static str),
    /// Issuer not in the allowlist.
    #[error("issuer {0:?} not allowed")]
    BadIssuer(String),
    /// Child scopes exceed parent scopes.
    #[error("scope escalation: {scope:?} not granted by parent")]
    ScopeEscalation {
        /// The offending scope.
        scope: String,
    },
    /// Child outlives parent.
    #[error("child exp {child} outlives parent exp {parent}")]
    ExpEscalation {
        /// Child expiry.
        child: u64,
        /// Parent expiry.
        parent: u64,
    },
    /// Delegation chain deeper than permitted.
    #[error("delegation chain deeper than {0}")]
    ChainTooDeep(usize),
}

/// A successfully validated identity.
#[derive(Debug, Clone)]
pub struct ValidatedIdentity {
    /// The leaf token's claims.
    pub claims: NhiClaims,
    /// Number of delegation links above the leaf (0 = root token).
    pub chain_depth: usize,
    /// Seconds of TTL remaining at validation time.
    pub ttl_remaining_s: u64,
}

impl ValidatedIdentity {
    /// The agent identity block to bind into emitted events (Module D → E).
    pub fn agent_identity(&self) -> ab_events::AgentIdentity {
        ab_events::AgentIdentity {
            version: self.claims.version.clone(),
            charter: self.claims.charter.clone(),
            instance_uid: self.claims.instance_uid.clone(),
            ttl_remaining_s: Some(self.ttl_remaining_s),
        }
    }
}

/// The validator: keyed by `kid`, audience-bound, issuer-allowlisted.
pub struct IdentityValidator {
    keys: HashMap<String, KeyMaterial>,
    audience: String,
    allowed_issuers: Option<Vec<String>>,
    max_chain_depth: usize,
    leeway_secs: u64,
}

impl IdentityValidator {
    /// Create a validator for `audience`.
    pub fn new(audience: impl Into<String>) -> Self {
        Self {
            keys: HashMap::new(),
            audience: audience.into(),
            allowed_issuers: None,
            max_chain_depth: 4,
            leeway_secs: 30,
        }
    }

    /// Register key material under a `kid`.
    pub fn add_key(&mut self, kid: impl Into<String>, key: KeyMaterial) {
        self.keys.insert(kid.into(), key);
    }

    /// Restrict accepted issuers.
    pub fn allow_issuers(&mut self, issuers: Vec<String>) {
        self.allowed_issuers = Some(issuers);
    }

    /// Override the delegation-depth cap (default 4).
    pub fn set_max_chain_depth(&mut self, depth: usize) {
        self.max_chain_depth = depth;
    }

    /// Validate a token and its full delegation chain.
    pub fn validate(&self, token: &str) -> Result<ValidatedIdentity, IdentityError> {
        let leaf = self.validate_single(token)?;
        let mut depth = 0usize;
        let mut child = leaf.clone();
        let mut parent_token = leaf.parent_token.clone();
        while let Some(pt) = parent_token {
            depth += 1;
            if depth > self.max_chain_depth {
                return Err(IdentityError::ChainTooDeep(self.max_chain_depth));
            }
            let parent = self.validate_single(&pt)?;
            // Scope inheritance: child ⊆ parent.
            if let Some(escalated) =
                child.scopes.iter().find(|s| !parent.scopes.iter().any(|p| p == *s))
            {
                return Err(IdentityError::ScopeEscalation { scope: escalated.clone() });
            }
            // Child must not outlive parent.
            if child.exp > parent.exp {
                return Err(IdentityError::ExpEscalation { child: child.exp, parent: parent.exp });
            }
            parent_token = parent.parent_token.clone();
            child = parent;
        }
        let now_s = ab_core::time::now_ms() / 1000;
        Ok(ValidatedIdentity {
            ttl_remaining_s: leaf.exp.saturating_sub(now_s),
            chain_depth: depth,
            claims: leaf,
        })
    }

    /// Validate one JWT: header sanity, kid lookup, alg/key-type match,
    /// signature, exp/nbf/aud, TTL cap, issuer allowlist, field presence.
    fn validate_single(&self, token: &str) -> Result<NhiClaims, IdentityError> {
        let header =
            jsonwebtoken::decode_header(token).map_err(|e| IdentityError::Malformed(e.to_string()))?;
        let kid = header.kid.ok_or(IdentityError::MissingKid)?;
        let key = self.keys.get(&kid).ok_or_else(|| IdentityError::UnknownKid(kid.clone()))?;

        // Algorithm-confusion defense: the key's type dictates the only
        // acceptable alg; the token's stated alg must equal it exactly.
        let (expected_alg, decoding_key) = match key {
            KeyMaterial::Ed25519Pem(pem) => (
                Algorithm::EdDSA,
                DecodingKey::from_ed_pem(pem.as_bytes())
                    .map_err(|e| IdentityError::Malformed(format!("bad key for kid {kid}: {e}")))?,
            ),
            KeyMaterial::HmacSecret(secret) => (Algorithm::HS256, DecodingKey::from_secret(secret)),
        };
        if header.alg != expected_alg {
            return Err(IdentityError::AlgorithmRejected { alg: format!("{:?}", header.alg), kid });
        }

        let mut validation = Validation::new(expected_alg);
        validation.set_audience(std::slice::from_ref(&self.audience));
        validation.set_required_spec_claims(&["exp", "aud", "sub", "iss"]);
        validation.leeway = self.leeway_secs;
        validation.validate_nbf = true;

        let data = jsonwebtoken::decode::<NhiClaims>(token, &decoding_key, &validation)
            .map_err(|e| IdentityError::Verification(e.to_string()))?;
        let claims = data.claims;

        if claims.exp <= claims.iat {
            return Err(IdentityError::BadTimestamps { iat: claims.iat, exp: claims.exp });
        }
        let ttl = claims.exp - claims.iat;
        if ttl > MAX_TTL_SECS {
            return Err(IdentityError::TtlTooLong(ttl));
        }
        if claims.instance_uid.is_empty() {
            return Err(IdentityError::EmptyField("instance_uid"));
        }
        if claims.charter.is_empty() {
            return Err(IdentityError::EmptyField("charter"));
        }
        if claims.version.is_empty() {
            return Err(IdentityError::EmptyField("version"));
        }
        if let Some(allowed) = &self.allowed_issuers {
            if !allowed.contains(&claims.iss) {
                return Err(IdentityError::BadIssuer(claims.iss));
            }
        }
        Ok(claims)
    }
}
