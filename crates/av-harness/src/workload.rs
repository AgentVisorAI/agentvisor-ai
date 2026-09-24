//! Agent identities for platform workloads: the RFC 7523 JWT-bearer grant
//! on `/v1/token`.
//!
//! An app instance (usually the AgentVisor sidecar beside it) proves its
//! Cloud Foundry instance identity with an assertion signed by the instance
//! key (see `av_identity::workload`). The gateway maps the proven app,
//! space, and organization to one configured `[[workload_identities]]`
//! entry, which names the human principal the agent acts for, its charter,
//! and its scopes, and returns a short-lived agent token signed with the
//! gateway's exchange key. The gateway's own identity validator trusts that
//! key and issuer, so the token works on every route like an identity
//! provider's token: it expires, it can be revoked (by `jti`, or by the
//! instance GUID in `instance_uid`), and its `sub` is the human.

use crate::config::{HarnessConfig, WorkloadMapping};
use crate::pipeline::AppState;
use axum::body::Bytes;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use std::sync::Arc;

/// Issuer of gateway-issued agent tokens.
pub fn issuer(config: &HarnessConfig) -> String {
    format!("{}#workload", config.audience)
}

/// Make `validator` accept agent tokens this gateway issues: trust the
/// exchange signing key under its key id and, when an issuer allowlist is
/// configured, add the workload issuer to it. No-op without
/// `[workload_identity]`.
pub fn trust_gateway_tokens(
    validator: &mut av_identity::IdentityValidator,
    config: &HarnessConfig,
) -> Result<(), String> {
    if config.workload_identity.is_none() {
        return Ok(());
    }
    let seed_path = config
        .token_exchange_seed_file
        .as_deref()
        .ok_or_else(|| "[workload_identity] requires token_exchange_seed_file".to_owned())?;
    let seed = crate::pipeline::load_exchange_seed(seed_path)?;
    let signer = crate::authz::TokenSigner::from_seed(&seed);
    validator
        .add_key(
            signer.kid(),
            av_identity::KeyMaterial::Ed25519Jwk(signer.public_key_b64url()),
        )
        .map_err(|error| format!("trust the workload token key: {error}"))?;
    if !config.identity_allowed_issuers.is_empty() {
        let mut issuers = config.identity_allowed_issuers.clone();
        issuers.push(issuer(config));
        validator.allow_issuers(issuers);
    }
    Ok(())
}

/// Verifies workload assertions and maps them to configured workloads.
pub struct WorkloadIssuer {
    trust: av_identity::WorkloadTrust,
    mappings: Vec<WorkloadMapping>,
    token_ttl_s: u64,
}

impl WorkloadIssuer {
    /// Load the trust bundle named by `[workload_identity].ca_file`.
    pub fn from_config(config: &HarnessConfig) -> Result<Option<Self>, String> {
        let Some(settings) = &config.workload_identity else {
            return Ok(None);
        };
        let pem = std::fs::read(&settings.ca_file)
            .map_err(|error| format!("read workload_identity.ca_file {:?}: {error}", settings.ca_file))?;
        let trust = av_identity::WorkloadTrust::from_pem(&pem).map_err(|error| error.to_string())?;
        Ok(Some(Self {
            trust,
            mappings: config.workload_identities.clone(),
            token_ttl_s: settings.token_ttl_s,
        }))
    }

    /// The single mapping that selects `identity`, if exactly one does.
    fn mapping_for(
        &self,
        identity: &av_identity::CfInstanceIdentity,
    ) -> Result<&WorkloadMapping, &'static str> {
        let mut matches = self.mappings.iter().filter(|mapping| mapping.selects(identity));
        match (matches.next(), matches.next()) {
            (Some(mapping), None) => Ok(mapping),
            (None, _) => Err("unregistered"),
            (Some(_), Some(_)) => Err("ambiguous"),
        }
    }
}

fn oauth_error(status: StatusCode, error: &str, description: &str) -> Response {
    let mut response = (
        status,
        Json(json!({"error": error, "error_description": description})),
    )
        .into_response();
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}

fn rejected(state: &AppState, reason: &str) {
    state
        .metrics
        .counter(
            &format!("av_workload_assertions_rejected_total{{reason=\"{reason}\"}}"),
            "Workload identity assertions refused at /v1/token, by reason",
        )
        .inc();
}

#[derive(serde::Deserialize)]
struct GrantForm {
    #[allow(dead_code)]
    grant_type: String,
    assertion: String,
    #[serde(default)]
    scope: Option<String>,
}

/// Handle `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`.
pub(crate) fn grant(state: &AppState, body: &Bytes) -> Response {
    let Some(issuer_state) = state.workload.as_ref() else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "this gateway does not accept workload assertions",
        );
    };
    let Ok(form) = serde_urlencoded::from_bytes::<GrantForm>(body) else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "the jwt-bearer grant needs an assertion",
        );
    };
    let now_s = av_core::time::now_ms() / 1000;
    let verified = match issuer_state
        .trust
        .verify(&form.assertion, &state.config.audience, now_s)
    {
        Ok(verified) => verified,
        Err(error) => {
            let reason = match &error {
                av_identity::WorkloadError::Chain(_) => "chain",
                av_identity::WorkloadError::Signature => "signature",
                av_identity::WorkloadError::Replay => "replay",
                av_identity::WorkloadError::Claims(_) => "claims",
                av_identity::WorkloadError::Subject(_) => "subject",
                _ => "malformed",
            };
            rejected(state, reason);
            tracing::warn!(target: "agentvisor.workload", %error, "workload assertion refused");
            // One opaque description: details name trust anchors and claims.
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "the workload assertion was not accepted",
            );
        }
    };
    let mapping = match issuer_state.mapping_for(&verified.identity) {
        Ok(mapping) => mapping,
        Err(reason) => {
            rejected(state, reason);
            tracing::warn!(
                target: "agentvisor.workload",
                app = %verified.identity.app_guid,
                space = %verified.identity.space_guid,
                org = %verified.identity.org_guid,
                reason,
                "workload has no single [[workload_identities]] entry"
            );
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "this workload is not registered with the gateway",
            );
        }
    };
    let scopes = match form.scope.as_deref() {
        None => mapping.scopes.clone(),
        Some(requested) => {
            let requested: Vec<String> = requested
                .split(' ')
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect();
            let granted = av_identity::scope_intersection(&requested, &mapping.scopes);
            if granted.is_empty() {
                rejected(state, "scope");
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_scope",
                    "no requested scope is granted to this workload",
                );
            }
            granted
        }
    };
    let Some(signer) = state.token_signer.as_ref() else {
        return oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "workload identity is enabled but no signing key is configured",
        );
    };
    let ttl = issuer_state.token_ttl_s.min(av_identity::MAX_TTL_SECS);
    let claims = av_identity::NhiClaims {
        sub: mapping.sub.clone(),
        iss: issuer(&state.config),
        aud: av_identity::Audience::Single(state.config.audience.clone()),
        iat: now_s,
        nbf: Some(now_s),
        exp: now_s.saturating_add(ttl),
        jti: av_core::ids::new_event_uid(),
        azp: Some(format!("cf-app:{}", verified.identity.app_guid)),
        act: None,
        instance_uid: verified.identity.instance_guid.clone(),
        charter: mapping.charter.clone(),
        version: mapping.version.clone(),
        scopes: scopes.clone(),
        parent_token: None,
    };
    let access_token = match signer.sign(&claims) {
        Ok(token) => token,
        Err(error) => {
            tracing::error!(%error, "workload token signing failed");
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "token signing failed",
            );
        }
    };
    state
        .metrics
        .counter(
            &format!("av_workload_tokens_issued_total{{workload=\"{}\"}}", mapping.name),
            "Agent tokens issued to platform workloads, by workload",
        )
        .inc();
    tracing::info!(
        target: "agentvisor.workload",
        workload = %mapping.name,
        sub = %mapping.sub,
        instance = %verified.identity.instance_guid,
        app = %verified.identity.app_guid,
        jti = %claims.jti,
        "issued an agent token to a platform workload"
    );
    let mut response = Json(json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "issued_token_type": av_identity::exchange::JWT_TOKEN_TYPE,
        "expires_in": ttl,
        "scope": scopes.join(" "),
    }))
    .into_response();
    for (name, value) in [("cache-control", "no-store"), ("pragma", "no-cache")] {
        response.headers_mut().insert(
            axum::http::HeaderName::from_static(name),
            axum::http::HeaderValue::from_static(value),
        );
    }
    response
}

/// Shared pointer type stored in the application state.
pub type SharedWorkloadIssuer = Option<Arc<WorkloadIssuer>>;
