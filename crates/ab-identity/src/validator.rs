//! Token validation and delegation-chain verification.

use crate::claims::{NhiClaims, MAX_TTL_SECS};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};

/// Verification key material, bound to a `kid`.
#[derive(Clone)]
pub enum KeyMaterial {
    /// Ed25519 public key, SPKI PEM (`-----BEGIN PUBLIC KEY-----`). EdDSA.
    Ed25519Pem(String),
    /// Ed25519 JWK `x` coordinate, base64url without padding.
    Ed25519Jwk(String),
    /// HMAC shared secret. HS256 (dev / shared-secret IdP integrations).
    HmacSecret(Vec<u8>),
}

impl std::fmt::Debug for KeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ed25519Pem(_) => f.write_str("KeyMaterial::Ed25519Pem(..)"),
            Self::Ed25519Jwk(_) => f.write_str("KeyMaterial::Ed25519Jwk(..)"),
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
    /// `iat` is unreasonably far in the future.
    #[error("issued-at timestamp {iat} is in the future (now {now})")]
    FutureIat {
        /// Issued-at claim.
        iat: u64,
        /// Validator wall clock.
        now: u64,
    },
    /// Required identity field empty.
    #[error("empty identity field {0}")]
    EmptyField(&'static str),
    /// Field carries a bidi override or zero-width character that would
    /// spoof how the identity renders in a log or audit view.
    #[error("identity field {0} carries a bidi/zero-width spoofing character")]
    SpoofingCharacter(&'static str),
    /// Issuer not in the allowlist.
    #[error("issuer {0:?} not allowed")]
    BadIssuer(String),
    /// JWKS document was malformed or contained no supported signing keys.
    #[error("invalid JWKS: {0}")]
    Jwks(String),
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
            charter: self.claims.charter.clone().into(),
            instance_uid: self.claims.instance_uid.clone(),
            ttl_remaining_s: Some(self.ttl_remaining_s),
        }
    }
}

/// The validator: keyed by `kid`, audience-bound, issuer-allowlisted.
pub struct IdentityValidator {
    keys: RwLock<HashMap<String, KeyMaterial>>,
    jwks_kids: RwLock<HashSet<String>>,
    audience: String,
    allowed_issuers: Option<Vec<String>>,
    max_chain_depth: usize,
    leeway_secs: u64,
}

impl IdentityValidator {
    /// Create a validator for `audience`.
    pub fn new(audience: impl Into<String>) -> Self {
        Self {
            keys: RwLock::new(HashMap::new()),
            jwks_kids: RwLock::new(HashSet::new()),
            audience: audience.into(),
            allowed_issuers: None,
            max_chain_depth: 4,
            leeway_secs: 30,
        }
    }

    /// Register key material under a `kid`.
    pub fn add_key(&self, kid: impl Into<String>, key: KeyMaterial) {
        self.keys.write().insert(kid.into(), key);
    }

    /// Add all supported Ed25519 keys from a standard JWKS document. Keys
    /// loaded by a *previous* `add_jwks` call are retired (replace
    /// semantics, so IdP rotation drops superseded JWKS keys); keys
    /// registered manually via `add_key` are left untouched, and a JWKS
    /// entry whose `kid` collides with a manually-registered key is
    /// refused so the manual key stays authoritative.
    pub fn add_jwks(&self, document: &serde_json::Value) -> Result<usize, IdentityError> {
        // Round-12 F11 + round-15 F5: cap the total number of
        // entries iterated (parsed OR skipped), so a hostile JWKS
        // full of RSA/EC decoys with a handful of legitimate OKP
        // keys cannot stall the parse loop just by inflating the
        // `keys` array to tens of thousands of entries. The
        // round-12 fix only capped parsed OKP entries, so a JWKS
        // with 40k `kty=RSA` decoys still walked the whole array.
        // Cap the outer array up front at the same threshold, and
        // keep the inner cap as defense-in-depth against a future
        // parser that stops short-circuiting on non-Ed25519 entries.
        const MAX_JWKS_KEYS: usize = 256;
        let keys = document
            .get("keys")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| IdentityError::Jwks("missing keys array".to_owned()))?;
        if keys.len() > MAX_JWKS_KEYS {
            return Err(IdentityError::Jwks(format!(
                "JWKS keys array carries {} entries; refusing to walk more than {MAX_JWKS_KEYS} (round-15 F5: fires before the inner parser regardless of `kty`)",
                keys.len()
            )));
        }
        let mut parsed = Vec::new();
        // Round-12 F6: refuse duplicate `kid` within a single JWKS.
        // HashMap's insert-with-overwrite semantics would otherwise
        // silently accept a poisoned refresh where an attacker mixes
        // an alien public key with the same kid as a legitimate one —
        // the array's LAST entry silently wins verification with no
        // log line, no counter, no error.
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        for key in keys {
            if key.get("kty").and_then(serde_json::Value::as_str) != Some("OKP")
                || key.get("crv").and_then(serde_json::Value::as_str) != Some("Ed25519")
            {
                continue;
            }
            let kid = key
                .get("kid")
                .and_then(serde_json::Value::as_str)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| IdentityError::Jwks("Ed25519 key missing kid".to_owned()))?;
            if !seen.insert(kid.to_owned()) {
                return Err(IdentityError::Jwks(format!(
                    "duplicate kid {kid:?} in JWKS document; refusing to accept a poisoned key set"
                )));
            }
            let x = key
                .get("x")
                .and_then(serde_json::Value::as_str)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| IdentityError::Jwks(format!("key {kid:?} missing x")))?;
            parsed.push((kid.to_owned(), KeyMaterial::Ed25519Jwk(x.to_owned())));
            if parsed.len() > MAX_JWKS_KEYS {
                return Err(IdentityError::Jwks(format!(
                    "JWKS declares more than {MAX_JWKS_KEYS} Ed25519 OKP keys; refusing to install"
                )));
            }
        }
        if parsed.is_empty() {
            return Err(IdentityError::Jwks("no Ed25519 OKP keys found".to_owned()));
        }
        let mut loaded = self.keys.write();
        let mut prior = self.jwks_kids.write();
        // A manually-added key must not be silently converted to a
        // JWKS-tracked entry: without this refusal, the next JWKS refresh
        // that no longer carries the colliding kid would retire (delete)
        // an operator-configured key. Report the conflict — the operator
        // can rename either side.
        for (kid, _) in &parsed {
            if loaded.contains_key(kid) && !prior.contains(kid) {
                return Err(IdentityError::Jwks(format!(
                    "JWKS kid {kid:?} conflicts with a manually-registered key; rename one"
                )));
            }
        }
        for kid in prior.drain() {
            loaded.remove(&kid);
        }
        for (kid, material) in &parsed {
            loaded.insert(kid.clone(), material.clone());
            prior.insert(kid.clone());
        }
        Ok(parsed.len())
    }

    /// Number of verification keys currently loaded.
    pub fn key_count(&self) -> usize {
        self.keys.read().len()
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
            if let Some(escalated) = child
                .scopes
                .iter()
                .find(|s| !parent.scopes.iter().any(|p| p == *s))
            {
                return Err(IdentityError::ScopeEscalation {
                    scope: escalated.clone(),
                });
            }
            // Child must not outlive parent.
            if child.exp > parent.exp {
                return Err(IdentityError::ExpEscalation {
                    child: child.exp,
                    parent: parent.exp,
                });
            }
            parent_token = parent.parent_token.clone();
            child = parent;
        }
        let now_s = ab_core::time::now_ms() / ab_core::units::MS_PER_SEC;
        Ok(ValidatedIdentity {
            ttl_remaining_s: leaf.exp.saturating_sub(now_s),
            chain_depth: depth,
            claims: leaf,
        })
    }

    /// Validate one JWT: header sanity, kid lookup, alg/key-type match,
    /// signature, exp/nbf/aud, future-iat, TTL cap, field presence,
    /// bidi/zero-width spoofing guard, issuer allowlist.
    fn validate_single(&self, token: &str) -> Result<NhiClaims, IdentityError> {
        // Reject oversized tokens up front so an unauthenticated caller
        // cannot amplify their pre-auth memory footprint through
        // `jsonwebtoken::decode_header`, which base64-decodes the
        // header segment before signature verification. RFC-realistic
        // NHI JWTs are at most a few KiB; 8 KiB is a comfortable
        // ceiling that blocks the amplification while accepting real
        // tokens with generous claim sets.
        const MAX_JWT_BYTES: usize = 8 * 1024;
        if token.len() > MAX_JWT_BYTES {
            return Err(IdentityError::Malformed(format!(
                "token is {} bytes, exceeds pre-auth cap of {MAX_JWT_BYTES}",
                token.len()
            )));
        }
        let header =
            jsonwebtoken::decode_header(token).map_err(|e| IdentityError::Malformed(e.to_string()))?;
        let kid = header.kid.ok_or(IdentityError::MissingKid)?;
        let keys = self.keys.read();
        let key = keys
            .get(&kid)
            .ok_or_else(|| IdentityError::UnknownKid(kid.clone()))?;

        // Algorithm-confusion defense: the key's type dictates the only
        // acceptable alg; the token's stated alg must equal it exactly.
        let (expected_alg, decoding_key) = match key {
            KeyMaterial::Ed25519Pem(pem) => (
                Algorithm::EdDSA,
                DecodingKey::from_ed_pem(pem.as_bytes())
                    .map_err(|e| IdentityError::Malformed(format!("bad key for kid {kid}: {e}")))?,
            ),
            KeyMaterial::Ed25519Jwk(x) => (
                Algorithm::EdDSA,
                DecodingKey::from_ed_components(x)
                    .map_err(|e| IdentityError::Malformed(format!("bad JWK for kid {kid}: {e}")))?,
            ),
            KeyMaterial::HmacSecret(secret) => (Algorithm::HS256, DecodingKey::from_secret(secret)),
        };
        if header.alg != expected_alg {
            return Err(IdentityError::AlgorithmRejected {
                alg: format!("{:?}", header.alg),
                kid,
            });
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
            return Err(IdentityError::BadTimestamps {
                iat: claims.iat,
                exp: claims.exp,
            });
        }
        let now_s = ab_core::time::now_ms() / ab_core::units::MS_PER_SEC;
        if claims.iat > now_s.saturating_add(self.leeway_secs) {
            return Err(IdentityError::FutureIat {
                iat: claims.iat,
                now: now_s,
            });
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
        // Trojan-Source guard: any bidi override or zero-width character in
        // a rendered identity field would spoof how it looks in operator
        // logs, receipts, and event chains while remaining part of the raw
        // bytes on the wire.
        for (name, value) in [
            ("instance_uid", claims.instance_uid.as_str()),
            ("charter", claims.charter.as_str()),
            ("version", claims.version.as_str()),
            ("sub", claims.sub.as_str()),
            ("iss", claims.iss.as_str()),
            ("jti", claims.jti.as_str()),
        ] {
            if ab_core::text::contains_bidi_or_zero_width(value) {
                return Err(IdentityError::SpoofingCharacter(name));
            }
        }
        if let Some(allowed) = &self.allowed_issuers {
            if !allowed.contains(&claims.iss) {
                return Err(IdentityError::BadIssuer(claims.iss));
            }
        }
        Ok(claims)
    }
}
