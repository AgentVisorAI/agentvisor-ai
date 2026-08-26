//! Token validation and delegation-chain verification.

use crate::claims::{NhiClaims, MAX_TTL_SECS};
use base64::Engine as _;
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
    /// Identity field longer than its documented cap.
    #[error("identity field {field} exceeds {max} characters")]
    FieldTooLong {
        /// Field name.
        field: &'static str,
        /// Documented cap in Unicode code points.
        max: usize,
    },
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
    /// Child claims to be issued before its parent (the delegator).
    /// A backdated child forges audit-trail causality: consumers that
    /// treat `claims.iat` as "when this identity became authorized"
    /// see the child asserting authority before the parent that
    /// granted it existed.
    #[error("child iat {child} predates parent iat {parent}")]
    IatEscalation {
        /// Child issued-at.
        child: u64,
        /// Parent issued-at.
        parent: u64,
    },
    /// Child's effective start (`nbf` when set, else `iat`) is
    /// earlier than the parent's effective start (`nbf` when set,
    /// else `iat`) — same forgery class as `IatEscalation`. The
    /// carried `child` and `parent` values are the compared
    /// EFFECTIVE starts, not the raw `nbf` fields (which may be
    /// absent). See `IdentityValidator::validate` for the full
    /// case matrix.
    #[error("child effective-start {child} predates parent effective-start {parent}")]
    NbfEscalation {
        /// Child effective start: `child.nbf` when set, else
        /// `child.iat`. The fallback closes an input case where the
        /// child omits `nbf` but its `iat` predates the parent's
        /// explicit `nbf` — a temporal-inversion forgery an earlier
        /// version of this guard silently accepted.
        child: u64,
        /// Parent effective start: `parent.nbf` when set, else
        /// `parent.iat`.
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
    pub fn agent_identity(&self) -> av_events::AgentIdentity {
        av_events::AgentIdentity {
            version: self.claims.version.clone(),
            charter: self.claims.charter.clone().into(),
            instance_uid: self.claims.instance_uid.clone(),
            ttl_remaining_s: Some(self.ttl_remaining_s),
        }
    }
}

/// The validator: keyed by `kid`, audience-bound, and optionally
/// issuer-allowlisted (opt in via [`IdentityValidator::allow_issuers`];
/// with no allowlist configured, any issuer is accepted).
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
    ///
    /// Refuse to shadow a JWKS-tracked kid. Without
    /// this guard, an ordering hazard silently discarded operator
    /// intent: if `add_key("X", …)` was called for a kid `X` that
    /// a prior `add_jwks` had installed, the manual entry would
    /// overwrite the JWKS one — but `jwks_kids` still contained
    /// `X`, so the *next* `add_jwks` drain would remove `X` and
    /// reinstall the JWKS version, silently discarding the
    /// operator's manual key. `add_key` is normally a startup
    /// call, but nothing in the API constrained late/admin use.
    pub fn add_key(&self, kid: impl Into<String>, key: KeyMaterial) -> Result<(), IdentityError> {
        let kid = kid.into();
        // Lock order matches `add_jwks` (keys before jwks_kids) and the
        // keys lock is held across the check AND the insert: releasing
        // between them let a concurrent `add_jwks` install kid X in the
        // gap, after which this insert silently shadowed the JWKS entry —
        // exactly the ordering hazard this guard exists to refuse.
        let mut loaded = self.keys.write();
        let prior = self.jwks_kids.read();
        if prior.contains(&kid) {
            return Err(IdentityError::Jwks(format!(
                "manual kid {kid:?} conflicts with a JWKS-tracked kid; rotate JWKS first"
            )));
        }
        drop(prior);
        loaded.insert(kid, key);
        Ok(())
    }

    /// Add all supported Ed25519 keys from a standard JWKS document. Keys
    /// loaded by a *previous* `add_jwks` call are retired (replace
    /// semantics, so IdP rotation drops superseded JWKS keys); keys
    /// registered manually via `add_key` are left untouched, and a JWKS
    /// entry whose `kid` collides with a manually-registered key is
    /// refused so the manual key stays authoritative.
    pub fn add_jwks(&self, document: &serde_json::Value) -> Result<usize, IdentityError> {
        // Cap the total number of
        // entries iterated (parsed OR skipped), so a hostile JWKS
        // full of RSA/EC decoys with a handful of legitimate OKP
        // keys cannot stall the parse loop just by inflating the
        // `keys` array to tens of thousands of entries. An
        // earlier fix only capped parsed OKP entries, so a JWKS
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
                "JWKS keys array carries {} entries; refusing to walk more than {MAX_JWKS_KEYS} (this cap fires before the inner parser regardless of `kty`)",
                keys.len()
            )));
        }
        let mut parsed = Vec::new();
        // Refuse duplicate `kid` within a single JWKS.
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
            // Respect RFC 7517 §4.2/§4.4. A JWK's
            // `use` (public key use) member — when present — MUST
            // be "sig" for verification material; "enc" keys are
            // encryption-only and MUST NOT be installed for
            // signature verification. Similarly `alg` — when
            // present — MUST identify the algorithm intended for
            // this key. For OKP/Ed25519 that's exclusively
            // "EdDSA" (RFC 8037 §3.1). An IdP that ships an
            // encryption-only key with a signing-domain kid
            // (misconfig or partial compromise) would otherwise
            // be silently installed as a verifier. Signature
            // correctness is still protected by the alg/kty
            // check at verify time, so this is defence-in-depth
            // rather than a direct forgery close, but it aligns
            // with the IdP's stated policy so audits can rely on
            // it.
            let kid_for_diag = key
                .get("kid")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("<missing>");
            if let Some(use_) = key.get("use").and_then(serde_json::Value::as_str) {
                if use_ != "sig" {
                    return Err(IdentityError::Jwks(format!(
                        "kid {kid_for_diag:?} declares use={use_:?}; only \"sig\" is accepted"
                    )));
                }
            }
            if let Some(alg) = key.get("alg").and_then(serde_json::Value::as_str) {
                if alg != "EdDSA" {
                    return Err(IdentityError::Jwks(format!(
                        "kid {kid_for_diag:?} declares alg={alg:?}; only \"EdDSA\" is accepted for OKP/Ed25519"
                    )));
                }
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
            // Shape-check the key at load time. Without
            // this, a malformed base64url `x` (e.g., "!!!") or a
            // wrong-length pubkey installs successfully, then every
            // JWT with that kid fails at verify time with a confusing
            // "bad JWK for kid" error. Rejecting during `add_jwks`
            // surfaces operator config errors at boot/JWKS refresh
            // instead of silently poisoning every downstream request.
            let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(x)
                .map_err(|error| {
                    IdentityError::Jwks(format!("key {kid:?} has malformed base64url `x`: {error}"))
                })?;
            if decoded.len() != 32 {
                return Err(IdentityError::Jwks(format!(
                    "key {kid:?} `x` decodes to {} bytes; Ed25519 public keys must be exactly 32",
                    decoded.len()
                )));
            }
            parsed.push((kid.to_owned(), KeyMaterial::Ed25519Jwk(x.to_owned())));
            // The outer `keys.len() > MAX_JWKS_KEYS`
            // guard at the top of the function already bounds
            // `parsed.len()` (parsed is a subset of the outer
            // array). This inner check is therefore unreachable in
            // practice — kept as defense-in-depth so a future
            // refactor that drops the outer guard cannot silently
            // reopen the write-lock stall vector.
            debug_assert!(
                parsed.len() <= MAX_JWKS_KEYS,
                "outer keys.len() cap should have already refused this document"
            );
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
            // Scope inheritance: child ⊆ parent, with the SAME wildcard
            // semantics the harness's runtime authorization uses
            // (`av-harness::pipeline::scope_allows`). Do not use
            // exact-string equality here: it rejected legitimately-delegated
            // narrower scopes when the parent held a wildcard — e.g.,
            // parent `["tool:*"]`, child `["tool:db_write"]` was refused
            // as `ScopeEscalation("tool:db_write")` even though the
            // runtime gate would authorize it, so the delegation
            // machinery was strictly stricter than the authorization
            // machinery. That asymmetry made wildcard-parent tokens
            // effectively unusable for narrowing delegation, the
            // canonical use case for scope subsetting.
            if let Some(escalated) = child
                .scopes
                .iter()
                .find(|scope| !scope_covered_by(scope, &parent.scopes))
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
            // Child must not be backdated before its parent. A
            // hostile HMAC-shared-secret holder could otherwise mint
            // a child with `iat` up to MAX_TTL_SECS BEFORE the parent
            // that "delegated" it — asserting authorization causality
            // that never happened. Consumers that treat `claims.iat`
            // as "when this identity became authorized" (audit
            // pipelines, revocation-cache pruning that keys eviction
            // horizons on `iat + MAX_TTL_SECS`) are then lied to.
            if child.iat < parent.iat {
                return Err(IdentityError::IatEscalation {
                    child: child.iat,
                    parent: parent.iat,
                });
            }
            // Same posture for `nbf`: a child cannot become usable
            // before the parent that granted it did. Compare
            // EFFECTIVE start times uniformly — fall back to `iat`
            // on either side that omits `nbf`. An earlier version
            // of this block was guarded by
            // `if let Some(child_nbf) = child.nbf`, so a child that
            // OMITTED `nbf` sailed past the check even when its raw
            // `iat` predated the parent's explicit `nbf`: e.g.
            // `parent{iat=t0, nbf=t0+15}` +
            // `child{iat=t0+10, nbf=None}` was accepted, though the
            // child asserts authority 5 seconds before the parent
            // grant became active. The `IatEscalation` check above
            // fires only for `child.iat < parent.iat` and does not
            // cover this gap. Consumers treating `claims.iat` (or
            // `nbf`) as "when this identity became authorized" saw
            // an inverted causal ordering.
            let parent_start = parent.nbf.unwrap_or(parent.iat);
            let child_start = child.nbf.unwrap_or(child.iat);
            if child_start < parent_start {
                return Err(IdentityError::NbfEscalation {
                    child: child_start,
                    parent: parent_start,
                });
            }
            parent_token = parent.parent_token.clone();
            child = parent;
        }
        let now_s = av_core::time::now_ms() / av_core::units::MS_PER_SEC;
        Ok(ValidatedIdentity {
            ttl_remaining_s: leaf.exp.saturating_sub(now_s),
            chain_depth: depth,
            claims: leaf,
        })
    }

    /// Validate one JWT, in order: pre-auth 8 KiB size cap, header sanity,
    /// kid lookup, alg/key-type match, signature,
    /// exp/aud/sub/iss required (+ `nbf` when present), `exp > iat`
    /// consistency, future-iat, TTL cap, field presence,
    /// bidi/zero-width spoofing guard, issuer allowlist (when configured).
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
        let now_s = av_core::time::now_ms() / av_core::units::MS_PER_SEC;
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
        // docs/reference/LIMITS.md documents a 256-code-point charter cap
        // ("longer are refused with 400"); the same reasoning applies to
        // EVERY identity string that flows into logs, receipts, and
        // event chains — an unbounded (up to the ~7 KiB per-claim JWT
        // budget) attacker-chosen field is log-spam surface and — since
        // instance_uid/version bind into every SIGNED receipt — bloats
        // the JCS-canonicalized signing input on every request. Cap all
        // identity strings at the same limit for one consistent rule.
        // Threat model: an HMAC-shared-secret deployment where multiple
        // principals hold the identity signing key. Any of them can
        // construct a valid JWT with hostile-length claims.
        const MAX_IDENTITY_STRING_CHARS: usize = 256;
        for (name, value) in [
            ("instance_uid", claims.instance_uid.as_str()),
            ("charter", claims.charter.as_str()),
            ("version", claims.version.as_str()),
            ("sub", claims.sub.as_str()),
            ("iss", claims.iss.as_str()),
            ("jti", claims.jti.as_str()),
        ] {
            if value.chars().count() > MAX_IDENTITY_STRING_CHARS {
                return Err(IdentityError::FieldTooLong {
                    field: name,
                    max: MAX_IDENTITY_STRING_CHARS,
                });
            }
        }
        // Bound the scopes array too: an unbounded list (or an
        // individually oversized scope) is the same log-spam / receipt-
        // bloat vector as the strings above, and the delegation-chain
        // subset check runs a per-element comparison so a 10000-entry
        // scopes[] amplifies delegation-verification cost per request.
        const MAX_SCOPES: usize = 64;
        if claims.scopes.len() > MAX_SCOPES {
            return Err(IdentityError::FieldTooLong {
                field: "scopes",
                max: MAX_SCOPES,
            });
        }
        for scope in &claims.scopes {
            if scope.chars().count() > MAX_IDENTITY_STRING_CHARS {
                return Err(IdentityError::FieldTooLong {
                    field: "scopes[]",
                    max: MAX_IDENTITY_STRING_CHARS,
                });
            }
        }
        // Trojan-Source guard: any bidi override or zero-width character in
        // a rendered identity field would spoof how it looks in operator
        // logs, receipts, and event chains while remaining part of the raw
        // bytes on the wire. Scopes must be guarded too — they are the
        // most audit-prominent identity strings and were the only one
        // omitted from the original list, an inconsistency that let a
        // scope like `payout\u{202E}elbast` render as visually-corrupt
        // junk in operator logs while still surviving the length cap and
        // the scope-subset check on raw bytes.
        for (name, value) in [
            ("instance_uid", claims.instance_uid.as_str()),
            ("charter", claims.charter.as_str()),
            ("version", claims.version.as_str()),
            ("sub", claims.sub.as_str()),
            ("iss", claims.iss.as_str()),
            ("jti", claims.jti.as_str()),
        ] {
            if av_core::text::contains_bidi_or_zero_width(value) {
                return Err(IdentityError::SpoofingCharacter(name));
            }
        }
        for scope in &claims.scopes {
            if av_core::text::contains_bidi_or_zero_width(scope) {
                return Err(IdentityError::SpoofingCharacter("scopes[]"));
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

/// Return true if `scope` is authorized by any of the `parent_scopes`,
/// using the SAME wildcard semantics
/// (`av-harness::pipeline::scope_allows`) applied at runtime
/// authorization. Duplicating (rather than re-exporting) the check
/// keeps `av-identity` free of an `av-harness` dependency; if these
/// two ever diverge, the delegation gate becomes strictly stricter or
/// looser than the runtime gate — exact-string matching here once
/// rejected legitimately-delegated narrower scopes under a wildcard
/// parent, which is the class of bug such divergence produces.
fn scope_covered_by(scope: &str, parent_scopes: &[String]) -> bool {
    parent_scopes.iter().any(|parent| {
        parent == "*"
            || parent == scope
            || parent
                .strip_suffix(":*")
                .is_some_and(|prefix| scope.starts_with(&format!("{prefix}:")))
    })
}
