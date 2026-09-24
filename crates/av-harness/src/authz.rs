//! Intent mapping, mission narrowing, and AuthZEN PDP (pillar 2).
//!
//! Maps tool names to business intents, enforces mission constraints,
//! and issues short-lived signed intent tokens per call.

use crate::config::{HarnessConfig, MissionConfig};
use av_sandbox::DenialCode;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;

/// Ed25519 JWT signer for exchange tokens and intent tokens.
pub struct TokenSigner {
    key: jsonwebtoken::EncodingKey,
    kid: String,
    public_key: [u8; 32],
}

impl TokenSigner {
    /// Build from a 32-byte Ed25519 seed. Derives the kid from the
    /// public key using the same scheme as the receipt signer.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        use av_receipts::Signer as _;
        let receipt_signer = av_receipts::Ed25519Signer::from_seed(seed);
        let kid = receipt_signer.key_id().to_owned();
        let public_key = receipt_signer.public_key_bytes();
        let pkcs8 = ed25519_seed_to_pkcs8(seed);
        let key = jsonwebtoken::EncodingKey::from_ed_der(&pkcs8);
        Self { key, kid, public_key }
    }

    /// Sign claims as an EdDSA JWT with the configured kid.
    pub fn sign<T: Serialize>(&self, claims: &T) -> Result<String, String> {
        self.sign_with_typ(claims, "JWT")
    }

    /// Sign with an explicit JWT `typ` header (RFC 8725 §3.11).
    pub fn sign_with_typ<T: Serialize>(&self, claims: &T, typ: &str) -> Result<String, String> {
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA);
        header.kid = Some(self.kid.clone());
        header.typ = Some(typ.to_owned());
        jsonwebtoken::encode(&header, claims, &self.key).map_err(|e| e.to_string())
    }

    /// The key id (first 32 hex chars of SHA-256 of the public key).
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// Public verification key for JWTs minted by this signer.
    pub fn decoding_key(&self) -> jsonwebtoken::DecodingKey {
        jsonwebtoken::DecodingKey::from_ed_der(&self.public_key)
    }

    /// Return a JWKS document containing this signer's public key,
    /// suitable for serving at `/.well-known/jwks.json` so backends
    /// can verify signed tokens.
    pub fn jwks_json(&self) -> serde_json::Value {
        use base64::Engine as _;
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.public_key);
        serde_json::json!({
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "x": x,
                "kid": self.kid,
                "alg": "EdDSA",
                "use": "sig",
            }]
        })
    }
}

/// Encode a raw 32-byte Ed25519 seed as a PKCS8v1 DER private key
/// (the format `jsonwebtoken::EncodingKey::from_ed_der` expects).
fn ed25519_seed_to_pkcs8(seed: &[u8; 32]) -> Vec<u8> {
    let mut der = Vec::with_capacity(48);
    der.extend_from_slice(&[0x30, 0x2e]);
    der.extend_from_slice(&[0x02, 0x01, 0x00]);
    der.extend_from_slice(&[0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70]);
    der.extend_from_slice(&[0x04, 0x22, 0x04, 0x20]);
    der.extend_from_slice(seed);
    der
}

/// Result of an authorization decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthzDecision {
    /// The call is permitted under the resolved business intent.
    Permit {
        /// The resolved business intent for this tool call.
        intent: String,
    },
    /// The call is denied with a structured code and reason.
    Deny {
        /// Machine-readable denial code.
        code: DenialCode,
        /// Human-readable explanation.
        reason: String,
    },
}

/// AuthZEN-style evaluation request (per IETF AuthZEN WG draft).
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthzEvalRequest {
    /// The agent or principal being evaluated.
    pub subject: AuthzSubject,
    /// The action being requested.
    pub action: AuthzAction,
    /// The resource being acted upon.
    pub resource: AuthzResource,
}

/// Subject of an authorization evaluation.
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthzSubject {
    /// Subject identifier (e.g. `agent:billing`).
    pub id: String,
    /// Subject type (e.g. `agent`, `user`).
    #[serde(rename = "type")]
    pub subject_type: String,
    /// Additional subject properties.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<serde_json::Value>,
}

/// Action being evaluated.
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthzAction {
    /// Action name (the resolved business intent).
    pub name: String,
    /// Additional action properties.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<serde_json::Value>,
}

/// Resource being acted upon.
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthzResource {
    /// Resource identifier (typically the tool name).
    pub id: String,
    /// Resource type (e.g. `tool`).
    #[serde(rename = "type")]
    pub resource_type: String,
}

/// AuthZEN evaluation response.
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthzEvalResponse {
    /// `true` if the action is permitted.
    pub decision: bool,
    /// Additional context for the decision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<AuthzContext>,
}

/// Additional context in an AuthZEN response.
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthzContext {
    /// Human-readable reason for the decision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// JWT `typ` of intent tokens. A distinct explicit type (RFC 8725 §3.11)
/// keeps a backend from accepting an intent token as an access token: both
/// are signed by the same exchange key and carry the backend as `aud`.
pub const INTENT_TOKEN_TYP: &str = "av-intent+jwt";

/// Claims inside a signed intent token.
#[derive(Debug, Serialize, Deserialize)]
#[allow(missing_docs)]
pub struct IntentClaims {
    pub iss: String,
    pub aud: String,
    pub sub: String,
    pub tool: String,
    pub intent: String,
    pub iat: u64,
    pub exp: u64,
    pub jti: String,
}

/// The local policy decision point. Evaluates tool calls against the
/// intent map and the active mission.
pub struct PolicyDecisionPoint {
    intent_map: BTreeMap<String, String>,
    require_mapping: bool,
    mission: Option<MissionConfig>,
    intent_token_ttl_s: u64,
    issuer: String,
    signer: Option<Arc<TokenSigner>>,
}

impl PolicyDecisionPoint {
    /// Build from harness config with an optional token signer.
    pub fn from_config(config: &HarnessConfig, signer: Option<Arc<TokenSigner>>) -> Self {
        Self {
            intent_map: config.intent_map.clone(),
            require_mapping: config.require_intent_mapping,
            mission: config.mission.clone(),
            intent_token_ttl_s: config.intent_token_ttl_s,
            issuer: config.audience.clone(),
            signer,
        }
    }

    /// Decide whether `tool` may run at `now_s`. Signs nothing, so the
    /// pipeline can run it before the budget is charged.
    pub fn decide(&self, tool: &str, now_s: u64) -> AuthzDecision {
        // Step 1: resolve intent from tool name.
        let intent = match self.intent_map.get(tool) {
            Some(intent) => intent.clone(),
            None => {
                if self.require_mapping {
                    return AuthzDecision::Deny {
                        code: DenialCode::UnmappedTool,
                        reason: format!("tool {tool:?} has no configured intent mapping"),
                    };
                }
                tool.to_owned()
            }
        };

        // Step 2: check mission constraints.
        if let Some(mission) = &self.mission {
            if now_s >= mission.expires_at {
                return AuthzDecision::Deny {
                    code: DenialCode::MissionExpired,
                    reason: format!(
                        "mission {:?} expired at {} (now {})",
                        mission.id, mission.expires_at, now_s
                    ),
                };
            }
            if !mission.allowed_intents.iter().any(|ai| ai == &intent) {
                return AuthzDecision::Deny {
                    code: DenialCode::MissionDenied,
                    reason: format!("intent {intent:?} not permitted by mission {:?}", mission.id),
                };
            }
        }

        AuthzDecision::Permit { intent }
    }

    /// The business intent `tool` maps to: its `intent_map` entry, or the
    /// tool name itself. A plain lookup that never denies.
    pub fn intent_for(&self, tool: &str) -> String {
        self.intent_map
            .get(tool)
            .cloned()
            .unwrap_or_else(|| tool.to_owned())
    }

    /// Sign a short-lived intent token for a permitted call, bound to the
    /// backend that receives it. `None` when no signer is configured.
    pub fn mint_intent_token(
        &self,
        tool: &str,
        intent: &str,
        subject: &str,
        audience: &str,
        now_s: u64,
    ) -> Option<String> {
        let signer = self.signer.as_ref()?;
        let claims = IntentClaims {
            iss: self.issuer.clone(),
            aud: audience.to_owned(),
            sub: subject.to_owned(),
            tool: tool.to_owned(),
            intent: intent.to_owned(),
            iat: now_s,
            exp: self
                .mission
                .as_ref()
                .map_or(now_s.saturating_add(self.intent_token_ttl_s), |mission| {
                    now_s
                        .saturating_add(self.intent_token_ttl_s)
                        .min(mission.expires_at)
                }),
            jti: av_core::ids::new_event_uid(),
        };
        match signer.sign_with_typ(&claims, INTENT_TOKEN_TYP) {
            Ok(jwt) => Some(jwt),
            Err(e) => {
                tracing::error!(error = %e, "intent token signing failed");
                None
            }
        }
    }

    /// The configured intent token TTL.
    pub fn intent_token_ttl_s(&self) -> u64 {
        self.intent_token_ttl_s
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]

    use super::*;
    use crate::config::MissionConfig;

    fn pdp(intents: &[(&str, &str)], require: bool, mission: Option<MissionConfig>) -> PolicyDecisionPoint {
        PolicyDecisionPoint {
            intent_map: intents
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
            require_mapping: require,
            mission,
            intent_token_ttl_s: 60,
            issuer: "agentvisor-ai".into(),
            signer: None,
        }
    }

    fn verify_intent_token(signer: &TokenSigner, jwt: &str) -> jsonwebtoken::TokenData<IntentClaims> {
        let dk = signer.decoding_key();
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
        validation.validate_exp = false;
        validation.validate_aud = false;
        validation.required_spec_claims.clear();
        jsonwebtoken::decode::<IntentClaims>(jwt, &dk, &validation).unwrap()
    }

    #[test]
    fn mapped_tool_resolves_intent() {
        let p = pdp(&[("db_write", "data.mutate")], false, None);
        match p.decide("db_write", 1000) {
            AuthzDecision::Permit { intent, .. } => assert_eq!(intent, "data.mutate"),
            AuthzDecision::Deny { .. } => panic!("expected permit"),
        }
    }

    #[test]
    fn unmapped_tool_denied_when_required() {
        let p = pdp(&[("db_write", "data.mutate")], true, None);
        match p.decide("unknown_tool", 1000) {
            AuthzDecision::Deny { code, .. } => assert_eq!(code, DenialCode::UnmappedTool),
            AuthzDecision::Permit { .. } => panic!("expected deny"),
        }
    }

    #[test]
    fn unmapped_tool_passes_when_not_required() {
        let p = pdp(&[], false, None);
        match p.decide("any_tool", 1000) {
            AuthzDecision::Permit { intent, .. } => assert_eq!(intent, "any_tool"),
            AuthzDecision::Deny { .. } => panic!("expected permit"),
        }
    }

    #[test]
    fn expired_mission_denied() {
        let mission = MissionConfig {
            id: "m-1".into(),
            allowed_intents: vec!["data.mutate".into()],
            expires_at: 500,
        };
        let p = pdp(&[("db_write", "data.mutate")], false, Some(mission));
        match p.decide("db_write", 1000) {
            AuthzDecision::Deny { code, .. } => assert_eq!(code, DenialCode::MissionExpired),
            AuthzDecision::Permit { .. } => panic!("expected deny"),
        }
        assert!(matches!(p.decide("db_write", 499), AuthzDecision::Permit { .. }));
        assert!(matches!(
            p.decide("db_write", 500),
            AuthzDecision::Deny {
                code: DenialCode::MissionExpired,
                ..
            }
        ));
    }

    #[test]
    fn mission_denies_unlisted_intent() {
        let mission = MissionConfig {
            id: "m-2".into(),
            allowed_intents: vec!["data.read".into()],
            expires_at: 2000,
        };
        let p = pdp(&[("db_write", "data.mutate")], false, Some(mission));
        match p.decide("db_write", 1000) {
            AuthzDecision::Deny { code, .. } => assert_eq!(code, DenialCode::MissionDenied),
            AuthzDecision::Permit { .. } => panic!("expected deny"),
        }
    }

    #[test]
    fn mission_permits_listed_intent() {
        let mission = MissionConfig {
            id: "m-3".into(),
            allowed_intents: vec!["data.mutate".into()],
            expires_at: 2000,
        };
        let p = pdp(&[("db_write", "data.mutate")], false, Some(mission));
        match p.decide("db_write", 1000) {
            AuthzDecision::Permit { intent, .. } => assert_eq!(intent, "data.mutate"),
            AuthzDecision::Deny { .. } => panic!("expected permit"),
        }
    }

    #[test]
    fn intent_token_cannot_outlive_its_mission() {
        let mission = MissionConfig {
            id: "m-ttl".into(),
            allowed_intents: vec!["data.mutate".into()],
            expires_at: 1001,
        };
        let mut policy = pdp(&[("db_write", "data.mutate")], false, Some(mission));
        let signer = Arc::new(TokenSigner::from_seed(&[94; 32]));
        policy.signer = Some(Arc::clone(&signer));
        let token = policy
            .mint_intent_token("db_write", "data.mutate", "caller", "db", 1000)
            .unwrap();
        let claims = verify_intent_token(&signer, &token).claims;
        assert_eq!(claims.iat, 1000);
        assert_eq!(claims.exp, 1001);
    }

    #[test]
    fn intent_token_none_without_signer() {
        let p = pdp(&[("search", "data.read")], false, None);
        assert!(
            p.mint_intent_token("search", "data.read", "inst-1", "backend-a", 1000)
                .is_none(),
            "no signer → no intent token"
        );
    }

    #[test]
    fn intent_token_is_typed_and_bound_to_issuer_audience_and_subject() {
        let signer = Arc::new(TokenSigner::from_seed(&[99u8; 32]));
        let mut p = pdp(&[("search", "data.read")], false, None);
        p.signer = Some(Arc::clone(&signer));
        let jwt = p
            .mint_intent_token("search", "data.read", "inst-1", "backend-a", 1000)
            .expect("signer present → must produce JWT");
        let header = jsonwebtoken::decode_header(&jwt).unwrap();
        assert_eq!(header.alg, jsonwebtoken::Algorithm::EdDSA);
        assert_eq!(header.typ.as_deref(), Some(INTENT_TOKEN_TYP));
        assert_eq!(header.kid.as_deref(), Some(signer.kid()));
        let decoded = verify_intent_token(&signer, &jwt);
        assert_eq!(decoded.claims.iss, "agentvisor-ai");
        assert_eq!(decoded.claims.aud, "backend-a");
        assert_eq!(decoded.claims.sub, "inst-1");
        assert_eq!(decoded.claims.tool, "search");
        assert_eq!(decoded.claims.intent, "data.read");
        assert_eq!(decoded.claims.iat, 1000);
        assert_eq!(decoded.claims.exp - decoded.claims.iat, 60);
        assert!(!decoded.claims.jti.is_empty());
    }

    #[test]
    fn intent_tokens_carry_unique_jtis() {
        let mut p = pdp(&[("search", "data.read")], false, None);
        p.signer = Some(Arc::new(TokenSigner::from_seed(&[98u8; 32])));
        let signer = p.signer.clone().unwrap();
        let a = p
            .mint_intent_token("search", "data.read", "inst-1", "backend-a", 1000)
            .unwrap();
        let b = p
            .mint_intent_token("search", "data.read", "inst-1", "backend-a", 1000)
            .unwrap();
        assert_ne!(
            verify_intent_token(&signer, &a).claims.jti,
            verify_intent_token(&signer, &b).claims.jti,
            "each intent token needs a distinct jti so backends can reject replays"
        );
    }

    #[test]
    fn intent_for_is_the_mapping_or_the_tool_name_and_never_denies() {
        let p = pdp(&[("db_write", "data.mutate")], true, None);
        assert_eq!(p.intent_for("db_write"), "data.mutate");
        assert_eq!(p.intent_for("unmapped"), "unmapped");
    }

    #[test]
    fn plain_sign_keeps_the_default_jwt_type() {
        let signer = TokenSigner::from_seed(&[97u8; 32]);
        let jwt = signer.sign(&serde_json::json!({"sub": "x"})).unwrap();
        let header = jsonwebtoken::decode_header(&jwt).unwrap();
        assert_eq!(header.typ.as_deref(), Some("JWT"));
    }

    #[test]
    fn authz_eval_request_serializes() {
        let req = AuthzEvalRequest {
            subject: AuthzSubject {
                id: "agent:billing".into(),
                subject_type: "agent".into(),
                properties: None,
            },
            action: AuthzAction {
                name: "data.mutate".into(),
                properties: None,
            },
            resource: AuthzResource {
                id: "db_write".into(),
                resource_type: "tool".into(),
            },
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["subject"]["id"], "agent:billing");
        assert_eq!(json["action"]["name"], "data.mutate");
    }
}
