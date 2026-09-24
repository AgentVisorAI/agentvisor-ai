//! Client for an external AuthZEN policy decision point
//! ([Authorization API 1.0](https://openid.net/specs/authorization-api-1_0.html)).
//!
//! When `[authzen]` is configured, every tool call that the local policy
//! decision point permits is also sent to the external PDP's Access
//! Evaluation endpoint (`POST .../access/v1/evaluation`). Both must permit.
//! The request names the human principal as the subject, the acting agent
//! and its scopes as subject properties, the resolved business intent as
//! the action, and the tool (with its backend) as the resource.
//!
//! A `{"decision": false}` answer is an audited policy denial
//! (`PDP_DENIED`). Anything else that is not a well-formed decision — a
//! timeout, a connection failure, a non-200 status, an unreadable body —
//! fails closed with 503, because an unreachable policy service is an
//! availability fault, not a verdict about the caller.

use crate::authz::{AuthzAction, AuthzEvalRequest, AuthzEvalResponse, AuthzResource, AuthzSubject};
use crate::config::AuthzenConfig;
use crate::pipeline::AuthenticatedCaller;
use axum::http::HeaderValue;
use futures::StreamExt as _;
use serde_json::{json, Value};

/// Largest PDP response body read.
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// Most evaluations sent in one batch request.
const MAX_BATCH: usize = 256;

/// The external PDP's verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthzenDecision {
    /// The PDP permitted the call.
    Permit,
    /// The PDP denied the call, with the reason it gave (if any).
    Deny(String),
}

/// HTTP client for the configured AuthZEN endpoints.
pub struct AuthzenClient {
    client: reqwest::Client,
    evaluation_endpoint: String,
    evaluations_endpoint: Option<String>,
    authorization: Option<HeaderValue>,
    timeout: std::time::Duration,
}

impl AuthzenClient {
    /// Build from configuration, reading the optional bearer token file
    /// with the same owner-only checks as other secrets.
    pub fn from_config(config: &AuthzenConfig, client: reqwest::Client) -> Result<Self, String> {
        let authorization =
            crate::pipeline::read_secret(None, config.auth_file.as_deref(), "AuthZEN bearer token")
                .map_err(|error| error.to_string())?
                .map(|token| {
                    let mut value = HeaderValue::from_str(&format!("Bearer {token}")).map_err(|_| {
                        "AuthZEN bearer token cannot be represented as an HTTP header".to_owned()
                    })?;
                    value.set_sensitive(true);
                    Ok::<_, String>(value)
                })
                .transpose()?;
        Ok(Self {
            client,
            evaluation_endpoint: config.evaluation_endpoint.clone(),
            evaluations_endpoint: config.evaluations_endpoint.clone(),
            authorization,
            timeout: std::time::Duration::from_millis(config.timeout_ms),
        })
    }

    async fn post(&self, endpoint: &str, body: &Value) -> Result<Value, String> {
        let bytes = serde_json::to_vec(body).map_err(|error| error.to_string())?;
        let request_id = av_core::ids::new_event_uid();
        let mut request = self
            .client
            .post(endpoint)
            .timeout(self.timeout)
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .header(axum::http::header::ACCEPT, "application/json")
            .header("x-request-id", request_id.as_str())
            .body(bytes);
        if let Some(authorization) = &self.authorization {
            request = request.header(axum::http::header::AUTHORIZATION, authorization.clone());
        }
        let response = request
            .send()
            .await
            .map_err(|error| crate::pipeline::classify_upstream_error(&error).to_owned())?;
        let status = response.status();
        if status != reqwest::StatusCode::OK {
            return Err(format!("policy decision point answered HTTP {}", status.as_u16()));
        }
        let mut stream = response.bytes_stream();
        let mut body = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|error| crate::pipeline::classify_upstream_error(&error).to_owned())?;
            if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
                return Err("policy decision point response is too large".to_owned());
            }
            body.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&body).map_err(|_| "policy decision point response is not JSON".to_owned())
    }

    /// Evaluate one access request.
    pub async fn evaluate(&self, request: &AuthzEvalRequest) -> Result<AuthzenDecision, String> {
        let body = serde_json::to_value(request).map_err(|error| error.to_string())?;
        let answer = self.post(&self.evaluation_endpoint, &body).await?;
        decision_of(&answer)
    }

    /// Evaluate several requests that share a subject and context. Uses the
    /// batch endpoint when configured (in chunks of at most 256), and one
    /// evaluation per request otherwise. The result has one entry per
    /// request, in order.
    pub async fn evaluate_many(&self, requests: &[AuthzEvalRequest]) -> Result<Vec<bool>, String> {
        let Some(endpoint) = &self.evaluations_endpoint else {
            let answers =
                futures::future::join_all(requests.iter().map(|request| self.evaluate(request))).await;
            return answers
                .into_iter()
                .map(|answer| answer.map(|decision| decision == AuthzenDecision::Permit))
                .collect();
        };
        let mut decisions = Vec::with_capacity(requests.len());
        for chunk in requests.chunks(MAX_BATCH) {
            let Some(first) = chunk.first() else {
                continue;
            };
            let evaluations: Vec<Value> = chunk
                .iter()
                .map(|request| json!({"action": request.action, "resource": request.resource}))
                .collect();
            let mut body = json!({
                "subject": first.subject,
                "evaluations": evaluations,
                "options": {"evaluations_semantic": "execute_all"},
            });
            if let (Some(context), Some(object)) = (&first.context, body.as_object_mut()) {
                object.insert("context".to_owned(), context.clone());
            }
            let answer = self.post(endpoint, &body).await?;
            let results = answer
                .get("evaluations")
                .and_then(Value::as_array)
                .filter(|results| results.len() == chunk.len())
                .ok_or_else(|| "policy decision point returned a mismatched evaluations array".to_owned())?;
            for result in results {
                decisions.push(decision_of(result)? == AuthzenDecision::Permit);
            }
        }
        Ok(decisions)
    }
}

/// Read `{"decision": bool, "context": ...}`; anything else is an error.
fn decision_of(answer: &Value) -> Result<AuthzenDecision, String> {
    let parsed: AuthzEvalResponse = serde_json::from_value(answer.clone())
        .map_err(|_| "policy decision point returned no boolean decision".to_owned())?;
    if parsed.decision {
        return Ok(AuthzenDecision::Permit);
    }
    Ok(AuthzenDecision::Deny(reason_of(parsed.context.as_ref())))
}

/// The most useful human-readable reason in a PDP context. The spec's
/// examples use `reason_admin` / `reason_user`, either as a string or as
/// a language map such as `{"en": "..."}`.
fn reason_of(context: Option<&Value>) -> String {
    let text = |value: &Value| -> Option<String> {
        match value {
            Value::String(text) => Some(text.clone()),
            Value::Object(map) => map
                .get("en")
                .or_else(|| map.values().next())
                .and_then(Value::as_str)
                .map(str::to_owned),
            _ => None,
        }
    };
    context
        .and_then(|context| {
            ["reason_admin", "reason_user", "reason"]
                .iter()
                .find_map(|key| context.get(*key).and_then(text))
        })
        .map(|reason| reason.chars().take(512).collect())
        .unwrap_or_else(|| "denied by the external policy decision point".to_owned())
}

/// Build the Access Evaluation request for `tool` on behalf of `caller`.
pub(crate) fn evaluation_request(
    caller: &AuthenticatedCaller,
    tool: &str,
    intent: &str,
    backend: Option<&str>,
    session: Option<&str>,
    missions: &[String],
) -> AuthzEvalRequest {
    let (subject_type, subject_id, properties) = match &caller.validated {
        Some(validated) => (
            "user",
            validated.claims.sub.clone(),
            json!({
                "issuer": validated.claims.iss,
                "agent": {
                    "instance_uid": validated.claims.instance_uid,
                    "charter": validated.claims.charter,
                    "version": validated.claims.version,
                },
                "azp": validated.claims.azp,
                "act": validated.claims.act,
                "scopes": validated.claims.scopes,
            }),
        ),
        None => (
            "agent",
            caller.identity.instance_uid.clone(),
            json!({"agent": {"instance_uid": caller.identity.instance_uid}}),
        ),
    };
    AuthzEvalRequest {
        subject: AuthzSubject {
            id: subject_id,
            subject_type: subject_type.to_owned(),
            properties: Some(properties),
        },
        action: AuthzAction {
            name: intent.to_owned(),
            properties: Some(json!({"tool": tool})),
        },
        resource: AuthzResource {
            id: tool.to_owned(),
            resource_type: "tool".to_owned(),
            properties: Some(json!({"backend": backend})),
        },
        context: Some(json!({
            "session_id": session,
            "missions": missions,
            "time": av_core::time::now_ms() / 1000,
        })),
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

    #[test]
    fn decisions_and_reasons_are_parsed_strictly() {
        assert_eq!(
            decision_of(&json!({"decision": true})).unwrap(),
            AuthzenDecision::Permit
        );
        assert_eq!(
            decision_of(&json!({"decision": false, "context": {"reason_admin": {"en": "outside hours"}}}))
                .unwrap(),
            AuthzenDecision::Deny("outside hours".into())
        );
        assert_eq!(
            decision_of(&json!({"decision": false, "context": {"reason_user": "ask your manager"}})).unwrap(),
            AuthzenDecision::Deny("ask your manager".into())
        );
        assert_eq!(
            decision_of(&json!({"decision": false})).unwrap(),
            AuthzenDecision::Deny("denied by the external policy decision point".into())
        );
        assert!(decision_of(&json!({"decision": "yes"})).is_err());
        assert!(decision_of(&json!({})).is_err());
    }
}
