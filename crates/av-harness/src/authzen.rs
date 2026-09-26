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
pub fn decision_of(answer: &Value) -> Result<AuthzenDecision, String> {
    let parsed: AuthzEvalResponse = serde_json::from_value(answer.clone())
        .map_err(|_| "policy decision point returned no boolean decision".to_owned())?;
    if parsed.decision {
        return Ok(AuthzenDecision::Permit);
    }
    Ok(AuthzenDecision::Deny(reason_of(parsed.context.as_ref())))
}

/// The most useful human-readable reason in a PDP context. The spec's
/// examples use `reason_admin` / `reason_user`, either as a string or as
/// a language map such as `{"en": "..."}`. Control characters and
/// bidirectional overrides are stripped so a hostile PDP cannot forge
/// log lines or spoof display text.
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
        .map(|reason| sanitize_reason(&reason))
        .filter(|reason| !reason.is_empty())
        .unwrap_or_else(|| "denied by the external policy decision point".to_owned())
}

/// Strip control characters and bidirectional overrides from a
/// PDP-supplied reason string. The result is at most 512 characters.
fn sanitize_reason(reason: &str) -> String {
    reason
        .chars()
        .filter(|c| !c.is_control() && !av_core::text::is_bidi_or_zero_width(*c))
        .take(512)
        .collect()
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
    use std::sync::{Arc, Mutex};

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

    #[test]
    fn hostile_reasons_stripped_of_control_and_bidi() {
        // Newlines and carriage returns are removed so a PDP cannot
        // inject extra log lines through a denial reason.
        let reason = decision_of(&json!({
            "decision": false,
            "context": {"reason_user": "ok\nmalicious line"}
        }))
        .unwrap();
        assert_eq!(reason, AuthzenDecision::Deny("okmalicious line".into()));

        // Tab is a control character and is stripped.
        let reason = decision_of(&json!({
            "decision": false,
            "context": {"reason_admin": "a\tb"}
        }))
        .unwrap();
        assert_eq!(reason, AuthzenDecision::Deny("ab".into()));

        // Bidirectional overrides are stripped so a PDP cannot reorder
        // displayed text.
        let reason = decision_of(&json!({
            "decision": false,
            "context": {"reason_user": "before\u{202E}evil\u{202D}after"}
        }))
        .unwrap();
        assert_eq!(reason, AuthzenDecision::Deny("beforeevilafter".into()));

        // A reason consisting entirely of hostile bytes collapses to
        // the fallback string.
        let reason = decision_of(&json!({
            "decision": false,
            "context": {"reason_user": "\r\n\t\u{202E}"}
        }))
        .unwrap();
        assert_eq!(
            reason,
            AuthzenDecision::Deny("denied by the external policy decision point".into())
        );
    }

    #[test]
    fn reason_language_map_variants_are_read() {
        // Language map with "en" key is preferred.
        assert_eq!(
            reason_of(Some(&json!({"reason_admin": {"en": "outside hours", "fr": "hors heures"}}))),
            "outside hours"
        );
        // Missing "en" falls back to the first value.
        assert_eq!(
            reason_of(Some(&json!({"reason_user": {"fr": "hors heures"}}))),
            "hors heures"
        );
        // Non-string values are ignored.
        assert_eq!(
            reason_of(Some(&json!({"reason_user": 42}))),
            "denied by the external policy decision point"
        );
        // reason_user is preferred over reason when both exist.
        assert_eq!(
            reason_of(Some(&json!({"reason_user": "user reason", "reason": "generic"}))),
            "user reason"
        );
        // reason_admin is preferred over reason_user.
        assert_eq!(
            reason_of(Some(&json!({"reason_admin": "admin reason", "reason_user": "user reason"}))),
            "admin reason"
        );
        // Unknown keys are ignored.
        assert_eq!(
            reason_of(Some(&json!({"unknown": "value"}))),
            "denied by the external policy decision point"
        );
    }

    #[test]
    fn reason_is_capped_at_512_characters() {
        let long = "x".repeat(2000);
        assert_eq!(sanitize_reason(&long).chars().count(), 512);
    }

    /// How the mock's batch endpoint answers a request.
    #[derive(Clone)]
    enum Batch {
        /// One result per evaluation in the request, all with this verdict.
        Echo(bool),
        /// Exactly these verdicts, whatever the request length.
        Fixed(Vec<bool>),
        /// Omit the `evaluations` array entirely.
        Missing,
    }

    /// A stand-in for an external policy decision point. It records every
    /// request body it receives. `single` is the verdict it gives on the
    /// Access Evaluation endpoint; `batch` is how it answers the Access
    /// Evaluations endpoint.
    async fn mock_pdp(single: bool, batch: Batch) -> (String, Arc<Mutex<Vec<Value>>>) {
        let seen: Arc<Mutex<Vec<Value>>> = Arc::default();
        let seen_in_handler = Arc::clone(&seen);
        let app = axum::Router::new().fallback(
            move |uri: axum::http::Uri, body: axum::body::Bytes| {
                let seen = Arc::clone(&seen_in_handler);
                let batch = batch.clone();
                async move {
                    let request: Value = serde_json::from_slice(&body).unwrap();
                    seen.lock().unwrap().push(request.clone());
                    if !uri.path().ends_with("/evaluations") {
                        let answer = if single {
                            json!({"decision": true})
                        } else {
                            json!({"decision": false, "context": {"reason_admin": "blocked by policy"}})
                        };
                        return (axum::http::StatusCode::OK, axum::Json(answer));
                    }
                    let answer = match batch {
                        Batch::Echo(verdict) => {
                            let count = request["evaluations"].as_array().map(Vec::len).unwrap_or(0);
                            let evaluations: Vec<Value> =
                                (0..count).map(|_| json!({"decision": verdict})).collect();
                            json!({"evaluations": evaluations})
                        }
                        Batch::Fixed(verdicts) => json!({
                            "evaluations": verdicts
                                .iter()
                                .map(|verdict| json!({"decision": verdict}))
                                .collect::<Vec<Value>>()
                        }),
                        Batch::Missing => json!({}),
                    };
                    (axum::http::StatusCode::OK, axum::Json(answer))
                }
            },
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (base, seen)
    }

    fn eval_request(id: &str) -> AuthzEvalRequest {
        AuthzEvalRequest {
            subject: AuthzSubject {
                id: "user:alice".into(),
                subject_type: "user".into(),
                properties: None,
            },
            action: AuthzAction {
                name: "data.read".into(),
                properties: None,
            },
            resource: AuthzResource {
                id: id.into(),
                resource_type: "tool".into(),
                properties: None,
            },
            context: None,
        }
    }

    fn pdp_client(base: &str, batch: bool) -> AuthzenClient {
        AuthzenClient::from_config(
            &AuthzenConfig {
                evaluation_endpoint: format!("{base}/access/v1/evaluation"),
                evaluations_endpoint: batch.then(|| format!("{base}/access/v1/evaluations")),
                auth_file: None,
                timeout_ms: 2_000,
            },
            reqwest::Client::new(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn batch_eval_returns_one_decision_per_request() {
        let (base, seen) = mock_pdp(false, Batch::Fixed(vec![true, false, true])).await;
        let client = pdp_client(&base, true);
        let decisions = client
            .evaluate_many(&[eval_request("a"), eval_request("b"), eval_request("c")])
            .await
            .unwrap();
        assert_eq!(decisions, vec![true, false, true]);
        let requests = seen.lock().unwrap();
        assert_eq!(requests.len(), 1, "the batch path sends exactly one request");
        assert_eq!(requests[0]["evaluations"].as_array().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn batch_eval_mismatched_array_length_is_an_error() {
        // Fewer results than requests must be refused.
        let (base, _seen) = mock_pdp(false, Batch::Fixed(vec![true])).await;
        let client = pdp_client(&base, true);
        let error = client
            .evaluate_many(&[eval_request("a"), eval_request("b")])
            .await
            .unwrap_err();
        assert!(error.contains("mismatched"), "{error}");

        // More results than requests must also be refused.
        let (base, _seen) = mock_pdp(false, Batch::Fixed(vec![true, true, true])).await;
        let client = pdp_client(&base, true);
        let error = client
            .evaluate_many(&[eval_request("a"), eval_request("b")])
            .await
            .unwrap_err();
        assert!(error.contains("mismatched"), "{error}");

        // A missing `evaluations` array must also be refused.
        let (base, _seen) = mock_pdp(false, Batch::Missing).await;
        let client = pdp_client(&base, true);
        let error = client.evaluate_many(&[eval_request("a")]).await.unwrap_err();
        assert!(error.contains("mismatched"), "{error}");
    }

    #[tokio::test]
    async fn batch_eval_chunks_requests_above_the_batch_limit() {
        // MAX_BATCH is 256, so 300 requests become two HTTP calls.
        let (base, seen) = mock_pdp(false, Batch::Echo(true)).await;
        let client = pdp_client(&base, true);
        let requests: Vec<AuthzEvalRequest> = (0..300)
            .map(|index| eval_request(&format!("tool-{index}")))
            .collect();
        let decisions = client.evaluate_many(&requests).await.unwrap();
        assert_eq!(decisions.len(), 300);
        assert!(decisions.iter().all(|decision| *decision));
        let requests = seen.lock().unwrap();
        assert_eq!(requests.len(), 2, "300 requests are sent in two chunks");
        assert_eq!(requests[0]["evaluations"].as_array().unwrap().len(), 256);
        assert_eq!(requests[1]["evaluations"].as_array().unwrap().len(), 44);
    }

    #[tokio::test]
    async fn single_eval_falls_back_when_no_batch_endpoint() {
        let (base, seen) = mock_pdp(true, Batch::Missing).await;
        let client = pdp_client(&base, false);
        let decisions = client
            .evaluate_many(&[eval_request("a"), eval_request("b")])
            .await
            .unwrap();
        assert_eq!(decisions, vec![true, true], "each request gets its own verdict");
        let requests = seen.lock().unwrap();
        assert_eq!(requests.len(), 2, "one HTTP call per request without a batch endpoint");
    }

    #[test]
    fn decision_of_rejects_non_object_answers() {
        for answer in [json!("deny"), json!(null), json!([])] {
            assert!(decision_of(&answer).is_err(), "accepted: {answer}");
        }
    }

    #[test]
    fn sanitize_reason_strips_all_hostile_code_points() {
        // Every control character and bidi override is stripped.
        let hostile = "\u{0000}\u{0001}\u{0007}\u{0008}\u{000B}\u{000C}\u{000E}\u{001F}\u{007F}\u{202A}\u{202B}\u{202C}\u{202D}\u{202E}\u{2066}\u{2067}\u{2068}\u{2069}\u{206A}\u{206B}\u{206C}\u{206D}\u{206E}\u{206F}\u{FEFF}";
        assert_eq!(sanitize_reason(hostile), "");
        // Normal text is preserved.
        assert_eq!(sanitize_reason("hello world 42"), "hello world 42");
        // Unicode text is preserved.
        assert_eq!(sanitize_reason("réseau café"), "réseau café");
    }

    #[test]
    fn decision_of_rejects_non_boolean_decisions() {
        for answer in [
            json!({"decision": 1}),
            json!({"decision": "true"}),
            json!({"decision": null}),
            json!({"decision": []}),
            json!({"decision": {}}),
            json!({"result": true}),
            json!({"allow": true}),
        ] {
            assert!(
                decision_of(&answer).is_err(),
                "accepted non-boolean decision: {answer}"
            );
        }
    }

    #[test]
    fn decision_of_accepts_both_decision_spellings() {
        assert_eq!(
            decision_of(&json!({"decision": true})).unwrap(),
            AuthzenDecision::Permit
        );
        assert_eq!(
            decision_of(&json!({"decision": false})).unwrap(),
            AuthzenDecision::Deny("denied by the external policy decision point".into())
        );
        // Context is optional.
        assert_eq!(
            decision_of(&json!({"decision": true, "context": {"extra": 1}})).unwrap(),
            AuthzenDecision::Permit
        );
    }
}
