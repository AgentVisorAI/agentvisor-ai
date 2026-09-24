//! Authenticated revocation administration and RFC 7662 introspection.

use crate::pipeline::AppState;
use av_events::{AgentIdentity, EventClass, EventMetrics, StatusId, StopReason};
use av_identity::{IdentityError, RevokeOutcome};
use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

/// Keep bounded control requests alive after disconnect, so a committed
/// revocation still reaches its audit job and shutdown waits for it.
pub(crate) async fn control_request<F, Fut>(state: AppState, operation: F) -> Response
where
    F: FnOnce(AppState) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Response> + Send + 'static,
{
    let Ok(permit) = Arc::clone(&state.mcp_admission).try_acquire_owned() else {
        return unavailable();
    };
    let guard = state.mcp_inflight.enter();
    match tokio::spawn(async move {
        let _permit = permit;
        let _guard = guard;
        operation(state).await
    })
    .await
    {
        Ok(response) => response,
        Err(_) => unavailable(),
    }
}

fn response(status: StatusCode, body: Value) -> Response {
    let mut response = (status, Json(body)).into_response();
    response
        .headers_mut()
        .insert("cache-control", HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert("pragma", HeaderValue::from_static("no-cache"));
    if status == StatusCode::SERVICE_UNAVAILABLE {
        response
            .headers_mut()
            .insert("retry-after", HeaderValue::from_static("5"));
    }
    response
}

fn unavailable() -> Response {
    response(
        StatusCode::SERVICE_UNAVAILABLE,
        json!({"error":"temporarily_unavailable"}),
    )
}

fn bearer_digest(headers: &HeaderMap) -> Option<String> {
    let value = crate::pipeline::single_header(headers, "authorization").ok()??;
    let token = crate::pipeline::strip_bearer_scheme(value.to_str().ok()?)?;
    if token.len() < 32 || token.len() > 4096 {
        return None;
    }
    Some(av_core::digest::sha256_hex(token.as_bytes()))
}

// Both sides are fixed-size, public SHA-256 encodings; compare every byte.
fn digest_matches(a: &str, b: &str) -> bool {
    a.len() == 64
        && b.len() == 64
        && a.bytes().zip(b.bytes()).fold(0_u8, |difference, (a, b)| {
            difference | (a ^ b.to_ascii_lowercase())
        }) == 0
}

fn unauthorized() -> Response {
    let mut response = response(StatusCode::UNAUTHORIZED, json!({"error":"invalid_client"}));
    response
        .headers_mut()
        .insert("www-authenticate", HeaderValue::from_static("Bearer"));
    response
}

#[derive(Deserialize)]
pub(crate) struct TokenForm {
    token: String,
}

pub(crate) fn verify_exchange(
    state: &AppState,
    token: &str,
    audiences: &[String],
    for_revocation: bool,
) -> Result<av_identity::ExchangedClaims, IdentityError> {
    if token.len() > 16 * 1024 {
        return Err(IdentityError::Malformed("token exceeds 16 KiB".into()));
    }
    let signer = state
        .token_signer
        .as_ref()
        .ok_or_else(|| IdentityError::Verification("exchange signer unavailable".into()))?;
    // Reading the untrusted type only selects an explicit validation profile;
    // the verifier checks the same type again under signature verification.
    let header = jsonwebtoken::decode_header(token)
        .map_err(|_| IdentityError::Verification("invalid token".into()))?;
    let typ = header.typ.as_deref().unwrap_or("");
    av_identity::verify_exchanged_token(
        token,
        &av_identity::ExchangedValidation {
            key: &signer.decoding_key(),
            kid: signer.kid(),
            issuer: &state.config.audience,
            allowed_audiences: audiences,
            max_depth: state.config.max_delegation_depth,
            now_s: av_core::time::now_ms() / 1000,
            token_type: typ,
            for_revocation,
        },
    )
}

pub(crate) async fn introspect(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    control_request(state, move |state| introspect_inner(state, headers, body)).await
}

async fn introspect_inner(state: AppState, headers: HeaderMap, body: Bytes) -> Response {
    let Some(digest) = bearer_digest(&headers) else {
        return unauthorized();
    };
    let Some(client) = state
        .config
        .introspection_tokens
        .iter()
        .find(|client| digest_matches(&digest, &client.sha256))
    else {
        return unauthorized();
    };
    let audiences = vec![client.backend.clone()];
    let Ok(form) = serde_urlencoded::from_bytes::<TokenForm>(&body) else {
        return response(StatusCode::BAD_REQUEST, json!({"error":"invalid_request"}));
    };
    let result = tokio::task::spawn_blocking(move || {
        let token = verify_exchange(&state, &form.token, &audiences, false)?;
        let store = state
            .identity
            .as_ref()
            .and_then(|validator| validator.revocation_store())
            .ok_or_else(|| {
                IdentityError::RevocationUnavailable("identity revocation is not configured".into())
            })?;
        av_identity::check_exchanged_revocation(
            &token,
            state.exchanged_revocations.as_ref(),
            store.as_ref(),
        )?;
        Ok::<_, IdentityError>(token)
    })
    .await;
    match result {
        // Revocation reads may block long enough for a previously valid token
        // to expire. Decide activity at response time, after that work returns.
        Ok(Ok(token)) if token.exp > av_core::time::now_ms() / 1000 => response(
            StatusCode::OK,
            json!({
                "active":true, "scope":token.scopes.join(" "), "client_id":token.azp,
                "sub":token.sub, "aud":token.aud, "iss":token.iss, "iat":token.iat,
                "exp":token.exp, "jti":token.jti, "token_type":"Bearer",
            }),
        ),
        Ok(Err(IdentityError::RevocationUnavailable(_))) | Err(_) => unavailable(),
        Ok(Ok(_)) | Ok(Err(_)) => response(StatusCode::OK, json!({"active":false})),
    }
}

pub(crate) async fn revoke(State(state): State<AppState>, body: Bytes) -> Response {
    control_request(state, move |state| revoke_inner(state, body)).await
}

async fn revoke_inner(state: AppState, body: Bytes) -> Response {
    if state.identity.is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Ok(form) = serde_urlencoded::from_bytes::<TokenForm>(&body) else {
        return response(StatusCode::BAD_REQUEST, json!({"error":"invalid_request"}));
    };
    let task_state = state.clone();
    let result = tokio::task::spawn_blocking(move || revoke_verified(&task_state, &form.token)).await;
    match result {
        Ok(Ok(Some((identity, payload)))) => {
            record_revocation(&state, identity, payload).await;
        }
        Ok(Ok(None)) => {}
        Ok(Err(_)) | Err(_) => return unavailable(),
    }
    let mut response = StatusCode::OK.into_response();
    response
        .headers_mut()
        .insert("cache-control", HeaderValue::from_static("no-store"));
    response
}

fn revoke_verified(state: &AppState, token: &str) -> Result<Option<(AgentIdentity, Value)>, String> {
    let Some(validator) = state.identity.as_ref() else {
        return Ok(None);
    };
    let Some(store) = validator.revocation_store() else {
        return Ok(None);
    };
    let now = av_core::time::now_ms() / 1000;
    let audiences: Vec<_> = state
        .config
        .backends
        .iter()
        .map(|backend| backend.name.clone())
        .collect();
    // Exchanged and inbound tokens have separate trust roots and revocation namespaces.
    let (claims, store, kind) = match verify_exchange(state, token, &audiences, true) {
        Ok(exchanged) => (
            exchanged.claims,
            Arc::clone(&state.exchanged_revocations),
            "exchanged",
        ),
        Err(_) if has_gateway_signature(state, token) => return Ok(None),
        Err(_) => match validator.validate_for_revocation(token) {
            Ok(identity) => (identity.claims, Arc::clone(store), "nhi"),
            // Preserve the RFC 7009 no-op response for forged gateway tokens.
            // This classifies a failed validation, never establishes trust.
            // Use the actual unknown key: it may belong to a delegation parent.
            Err(IdentityError::UnknownKid(unknown_kid))
                if state
                    .token_signer
                    .as_ref()
                    .is_some_and(|signer| signer.kid() == unknown_kid.as_str()) =>
            {
                return Ok(None);
            }
            Err(IdentityError::UnknownKid(_)) => return Err("identity key may be rotating".into()),
            Err(IdentityError::RevocationUnavailable(reason)) => return Err(reason),
            Err(_) => return Ok(None),
        },
    };
    store.sweep_expired(now);
    if store.try_revoke_token(
        &claims.iss,
        &claims.jti,
        claims.exp.saturating_add(validator.leeway_secs()),
    )? == RevokeOutcome::AlreadyRevoked
    {
        return Ok(None);
    }
    let identity = AgentIdentity {
        version: claims.version,
        charter: claims.charter.into(),
        instance_uid: claims.instance_uid,
        ttl_remaining_s: Some(claims.exp.saturating_sub(now)),
    };
    let payload = json!({"action":"token_revoked", "method":"rfc7009", "token_kind":kind,
        "jti":claims.jti, "iss":claims.iss, "sub":claims.sub, "token_iat":claims.iat, "token_exp":claims.exp});
    Ok(Some((identity, payload)))
}

/// A key ID is not proof of a token's origin: trusted external issuers may
/// reuse it with different key material. Only an actual gateway signature
/// prevents an invalid exchange profile from falling back to inbound NHI
/// validation. This check grants no authority and does not parse claims.
fn has_gateway_signature(state: &AppState, token: &str) -> bool {
    if token.len() > 16 * 1024 {
        return false;
    }
    let Some(signer) = state.token_signer.as_ref() else {
        return false;
    };
    let Some((message, signature)) = token.rsplit_once('.') else {
        return false;
    };
    let Some((header, claims)) = message.split_once('.') else {
        return false;
    };
    if header.is_empty() || claims.is_empty() || signature.is_empty() || claims.contains('.') {
        return false;
    }
    jsonwebtoken::crypto::verify(
        signature,
        message.as_bytes(),
        &signer.decoding_key(),
        jsonwebtoken::Algorithm::EdDSA,
    )
    .unwrap_or(false)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminRevocation {
    #[serde(default)]
    jti: Option<String>,
    #[serde(default)]
    instance_uid: Option<String>,
    #[serde(default)]
    token_kind: Option<String>,
}

pub(crate) async fn admin_revoke(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    control_request(state, move |state| admin_revoke_inner(state, headers, body)).await
}

async fn admin_revoke_inner(state: AppState, headers: HeaderMap, body: Bytes) -> Response {
    let Some(digest) = bearer_digest(&headers) else {
        return unauthorized();
    };
    let Some(operator) = state
        .config
        .operator_tokens
        .iter()
        .find(|operator| digest_matches(&digest, &operator.sha256))
    else {
        return unauthorized();
    };
    let operator = operator.name.clone();
    let Ok(request) = serde_json::from_slice::<AdminRevocation>(&body) else {
        return response(StatusCode::BAD_REQUEST, json!({"error":"invalid_request"}));
    };
    let valid_id = |value: &str, limit: usize| {
        !value.trim().is_empty()
            && value.chars().count() <= limit
            && !value.chars().any(char::is_control)
            && !av_core::text::contains_bidi_or_zero_width(value)
    };
    if request.jti.is_some() == request.instance_uid.is_some()
        || request.jti.as_deref().is_some_and(|id| !valid_id(id, 256))
        || request
            .instance_uid
            .as_deref()
            .is_some_and(|id| !valid_id(id, 128))
        || request
            .token_kind
            .as_deref()
            .is_some_and(|kind| !matches!(kind, "nhi" | "exchanged"))
        || (request.instance_uid.is_some() && request.token_kind.as_deref() == Some("exchanged"))
    {
        return response(
            StatusCode::BAD_REQUEST,
            json!({"error":"invalid_request", "error_description":"supply exactly one jti or instance_uid; token_kind may be nhi or exchanged for a jti"}),
        );
    }
    let Some(validator) = state.identity.as_ref() else {
        return unavailable();
    };
    let Some(nhi_store) = validator.revocation_store() else {
        return unavailable();
    };
    let store = if request.token_kind.as_deref() == Some("exchanged") {
        Arc::clone(&state.exchanged_revocations)
    } else {
        Arc::clone(nhi_store)
    };
    let now = av_core::time::now_ms() / 1000;
    let cutoff = now.saturating_add(validator.leeway_secs());
    // Covers every token already valid at the cutoff and bounded future-dated tokens.
    let expires_at = cutoff
        .saturating_add(av_identity::claims::MAX_TTL_SECS)
        .saturating_add(validator.leeway_secs());
    let jti = request.jti.clone();
    let instance = request.instance_uid.clone();
    let result = tokio::task::spawn_blocking(move || {
        store.sweep_expired(now);
        if let Some(jti) = jti {
            store.try_revoke(&jti, now.saturating_add(86_400)).map(|_| ())
        } else if let Some(instance) = instance {
            store.revoke_instance(&instance, cutoff, expires_at)
        } else {
            Err("missing revocation target".into())
        }
    })
    .await;
    if !matches!(result, Ok(Ok(()))) {
        return unavailable();
    }
    let payload = json!({"action":"token_revoked", "method":"operator", "operator":operator,
        "jti":request.jti, "instance_uid":request.instance_uid, "token_kind":request.token_kind.as_deref().unwrap_or("nhi"),
        "issued_at_or_before":request.instance_uid.as_ref().map(|_|cutoff)});
    let response_cutoff = request.instance_uid.as_ref().map(|_| cutoff);
    let identity = AgentIdentity {
        version: "operator".into(),
        charter: "revocation".into(),
        instance_uid: request
            .instance_uid
            .unwrap_or_else(|| "operator-revocation".into()),
        ttl_remaining_s: None,
    };
    let audited = record_revocation(&state, identity, payload).await;
    response(
        StatusCode::OK,
        json!({"revoked":true, "audited":audited, "issued_at_or_before":response_cutoff}),
    )
}

async fn record_revocation(state: &AppState, identity: AgentIdentity, payload: Value) -> bool {
    state
        .metrics
        .counter(
            crate::routes::TOKENS_REVOKED_METRIC,
            crate::routes::TOKENS_REVOKED_HELP,
        )
        .inc();
    tracing::info!(target: "agentvisor.revocation", action = %payload, "token authority revoked");
    let refused = |reason: &str| {
        state
            .metrics
            .counter(
                &format!("av_tokens_revoked_unaudited_total{{reason=\"{reason}\"}}"),
                "Revocations without signed audit capture",
            )
            .inc();
        false
    };
    {
        let mut window = state.revocation_audit_window.lock();
        if window.0.elapsed().as_secs() >= 60 {
            *window = (std::time::Instant::now(), 0);
        }
        if window.1 >= state.config.revocation_audit_per_minute {
            return refused("budget");
        }
        window.1 += 1;
    }
    let id = format!("token-revoked-{}", av_core::new_event_uid());
    let Ok(permit) = state.worker.try_reserve(&id) else {
        return refused("worker_queue");
    };
    let session = crate::session::Session::new(
        id,
        crate::session::Workflow::Signed,
        identity.clone(),
        state.config.breaker.clone(),
    );
    let Ok(session) = state.sessions.try_insert_recovered(session) else {
        return refused("internal");
    };
    permit.submit(crate::worker::WorkerJob {
        session: Arc::clone(&session),
        identity,
        class: EventClass::Identity,
        payload,
        text: String::new(),
        analyze_loop: false,
        status: StatusId::Success,
        stop_reason: None,
        native_stop_reason: None,
        metrics: EventMetrics::default(),
        cost_usd_micros: 0,
        prompt_token_correction: 0,
        atif: None,
        response_marker: None,
        response_attempt: None,
    });
    // Wait for the journal before reporting audit success. A registered session
    // is recoverable if finalization or the process fails after the journal write.
    session.wait_for_worker_jobs().await;
    if session.capture_failed() {
        return refused("capture");
    }
    match state
        .finalizer
        .close_session(session, StopReason::SessionClosed)
        .await
    {
        Ok(_) => true,
        Err(error) => {
            tracing::warn!(%error, "revocation receipt close failed; recovery will retry");
            state
                .metrics
                .counter(
                    "av_revocation_audit_close_failures_total",
                    "Revocation receipt finalization failures",
                )
                .inc();
            false
        }
    }
}
