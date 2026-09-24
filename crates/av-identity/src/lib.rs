//! Ephemeral Non-Human Identity (NHI) validation — brief Module D.
//!
//! Short-lived JWTs (EdDSA primary, HS256 for dev/IdP-shared-secret setups)
//! with a hard 15-minute TTL cap, plus cryptographically enforced scope
//! inheritance for parent→child agent delegation: a child token carries its
//! parent's token; the chain is signature-verified link by link and every
//! link's scopes must be a subset of its parent's, with `child.exp ≤
//! parent.exp` and bounded chain depth.
//!
//! Adversarial coverage (tests): `alg=none`, algorithm confusion (HS256
//! header against an Ed25519 key), expired / not-yet-valid, oversized TTL,
//! scope escalation at any link, truncated & tampered tokens, unknown `kid`.

pub mod claims;
pub mod exchange;
pub mod revocation;
pub mod validator;
pub mod workload;

pub use claims::{ActorClaim, Audience, NhiClaims, MAX_TTL_SECS};
pub use exchange::{
    build_exchanged_claims, build_exchanged_claims_with_actor, check_exchanged_revocation,
    scope_intersection, verify_exchanged_token, ExchangeActor, ExchangeError, ExchangeParams,
    ExchangedClaims, ExchangedValidation, TokenExchangeRequest, TokenExchangeResponse,
    TOKEN_EXCHANGE_GRANT_TYPE,
};
pub use revocation::{
    InMemoryRevocationStore, RevocationHealth, RevocationIdentity, RevocationStore, RevokeOutcome, RevokedBy,
};
pub use validator::{IdentityError, IdentityValidator, KeyMaterial, ValidatedIdentity};
pub use workload::{
    CfInstanceIdentity, VerifiedAssertion, WorkloadError, WorkloadTrust, JWT_BEARER_GRANT_TYPE,
    MAX_ASSERTION_LIFETIME_S,
};
