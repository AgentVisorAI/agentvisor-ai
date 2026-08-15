//! Read-only operator dashboard.
//!
//! Serves a single-page HTML/CSS/JS application at `/dashboard` and a small
//! JSON API under `/api/v1/dashboard/*` that lets the page render live
//! sessions, per-session details, and aggregate stats. The assets are
//! bundled into the binary via [`include_str!`] so there is no filesystem
//! dependency at runtime.
//!
//! Trust posture: the dashboard exposes the same session metadata that
//! already lands on disk and in `/metrics`. It is not authenticated by
//! itself — front it with the same ingress-level control operators use
//! for `/metrics`. There is no mutating endpoint here; every route is
//! `GET`.

use crate::pipeline::AppState;
use crate::session::Workflow;
use axum::extract::{Path, State};
use axum::http::{header, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use serde_json::{json, Value};
use std::sync::atomic::Ordering;

const INDEX_HTML: &str = include_str!("../dashboard/index.html");
const STYLE_CSS: &str = include_str!("../dashboard/style.css");
const APP_JS: &str = include_str!("../dashboard/app.js");

/// Sorted, capped list of session summaries. `?limit=N` clamped to
/// `MAX_LIST_LIMIT`; the default is [`DEFAULT_LIST_LIMIT`].
pub const DEFAULT_LIST_LIMIT: usize = 50;
/// Upper bound on the `?limit=N` query parameter for the sessions list.
pub const MAX_LIST_LIMIT: usize = 500;

#[derive(Serialize)]
pub(crate) struct SessionSummary {
    pub id: String,
    pub workflow: &'static str,
    pub last_activity_ms: u64,
    pub open: bool,
    pub closed: bool,
    pub artifact_committed: bool,
    pub close_complete: bool,
    pub capture_failed: bool,
    pub active_streams: u64,
    pub pending_jobs: u64,
    pub stop_reason_id: u8,
    pub stop_reason: &'static str,
    pub tool_calls: u64,
    pub tool_allowed: u64,
    pub tool_blocked: u64,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub cached_tokens: u64,
    pub cost_usd_micros: u64,
    pub identity: Identity,
    pub has_receipt: bool,
}

#[derive(Serialize)]
pub(crate) struct Identity {
    pub instance_uid: String,
    pub charter: String,
    pub version: String,
    pub ttl_remaining_s: Option<u64>,
}

impl SessionSummary {
    pub(crate) fn from_session(session: &crate::session::Session) -> Self {
        let latest = session.current_identity();
        let stop_id = u8::try_from(session.recorded_stop_reason_id()).unwrap_or(0);
        let stop = ab_events::StopReason::from_id(stop_id);
        Self {
            id: session.id.clone(),
            workflow: session.workflow.as_str(),
            last_activity_ms: session.last_activity_ms.load(Ordering::Acquire),
            open: !session.is_closed(),
            closed: session.closed.load(Ordering::Acquire) != 0,
            artifact_committed: session.artifact_committed_flag(),
            close_complete: session.close_complete_flag(),
            capture_failed: session.capture_failed(),
            active_streams: session.active_streams_count(),
            pending_jobs: session.pending_jobs_count(),
            stop_reason_id: stop_id,
            stop_reason: stop.caption(),
            tool_calls: session.totals.tool_calls.load(Ordering::Acquire),
            tool_allowed: session.totals.tool_allowed.load(Ordering::Acquire),
            tool_blocked: session.totals.tool_blocked.load(Ordering::Acquire),
            prompt_tokens: session.totals.prompt_tokens.load(Ordering::Acquire),
            completion_tokens: session.totals.completion_tokens.load(Ordering::Acquire),
            cached_tokens: session.totals.cached_tokens.load(Ordering::Acquire),
            cost_usd_micros: session.totals.cost_usd_micros.load(Ordering::Acquire),
            identity: Identity {
                instance_uid: latest.instance_uid,
                charter: latest.charter.name.clone(),
                version: latest.version,
                ttl_remaining_s: latest.ttl_remaining_s,
            },
            has_receipt: session.receipt.lock().is_some(),
        }
    }
}

#[derive(Serialize)]
struct Stats {
    generated_at_ms: u64,
    session_count: usize,
    open_count: usize,
    closed_count: usize,
    capture_failed_count: usize,
    total_prompt_tokens: u64,
    total_completion_tokens: u64,
    total_cached_tokens: u64,
    total_cost_usd_micros: u64,
    total_tool_calls: u64,
    total_tool_allowed: u64,
    total_tool_blocked: u64,
    workflow_signed: usize,
    workflow_unsigned: usize,
}

/// GET /dashboard — HTML shell.
pub async fn index() -> Response {
    static_asset(INDEX_HTML, "text/html; charset=utf-8")
}

/// GET /dashboard/style.css — dashboard CSS.
pub async fn style_css() -> Response {
    static_asset(STYLE_CSS, "text/css; charset=utf-8")
}

/// GET /dashboard/app.js — dashboard app JS.
pub async fn app_js() -> Response {
    static_asset(APP_JS, "text/javascript; charset=utf-8")
}

fn static_asset(body: &'static str, content_type: &'static str) -> Response {
    let mut response = Response::new(axum::body::Body::from(body));
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, max-age=0"),
    );
    response.headers_mut().insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    response
}

/// GET /api/v1/dashboard/sessions?limit=&status=
pub async fn list_sessions(
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<ListQuery>,
) -> Response {
    let limit = query.limit.unwrap_or(DEFAULT_LIST_LIMIT).min(MAX_LIST_LIMIT);
    let mut summaries: Vec<SessionSummary> = state
        .sessions
        .open_sessions_including_closed()
        .iter()
        .filter(|session| match query.status.as_deref() {
            Some("open") => !session.is_closed(),
            Some("closed") => session.is_closed(),
            Some("failed") => session.capture_failed(),
            _ => true,
        })
        .filter(|session| match query.workflow.as_deref() {
            Some("signed") => session.workflow == Workflow::Signed,
            Some("unsigned") => session.workflow == Workflow::Unsigned,
            _ => true,
        })
        .map(|session| SessionSummary::from_session(session))
        .collect();
    summaries.sort_by_key(|s| std::cmp::Reverse(s.last_activity_ms));
    summaries.truncate(limit);
    let total = state.sessions.len();
    Json(json!({
        "sessions": summaries,
        "generated_at_ms": ab_core::time::now_ms(),
        "total_before_truncate": total,
    }))
    .into_response()
}

/// GET /api/v1/dashboard/sessions/{id}
pub async fn session_detail(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let Some(session) = state.sessions.get(&id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "session not found in registry"})),
        )
            .into_response();
    };
    let summary = SessionSummary::from_session(&session);
    let receipt: Option<Value> = session
        .receipt
        .lock()
        .as_ref()
        .and_then(|r| serde_json::to_value(r).ok());
    let atif_path: Option<String> = session
        .atif_path
        .lock()
        .as_ref()
        .map(|path| path.display().to_string());
    // Chain head/count are exposed as a small provenance stub so the UI can
    // show "47 events, head=b2b7…". The full chain lives in the journal on
    // disk; we don't stream it through the dashboard.
    let chain = {
        let chain = session.chain.lock();
        json!({
            "head_hex": chain.head_hex(),
            "count": chain.count(),
        })
    };
    Json(json!({
        "summary": summary,
        "chain": chain,
        "receipt": receipt,
        "atif_path": atif_path,
    }))
    .into_response()
}

/// GET /api/v1/dashboard/stats
pub async fn stats(State(state): State<AppState>) -> Response {
    let sessions = state.sessions.open_sessions_including_closed();
    let mut totals = Stats {
        generated_at_ms: ab_core::time::now_ms(),
        session_count: sessions.len(),
        open_count: 0,
        closed_count: 0,
        capture_failed_count: 0,
        total_prompt_tokens: 0,
        total_completion_tokens: 0,
        total_cached_tokens: 0,
        total_cost_usd_micros: 0,
        total_tool_calls: 0,
        total_tool_allowed: 0,
        total_tool_blocked: 0,
        workflow_signed: 0,
        workflow_unsigned: 0,
    };
    for session in &sessions {
        if session.is_closed() {
            totals.closed_count += 1;
        } else {
            totals.open_count += 1;
        }
        if session.capture_failed() {
            totals.capture_failed_count += 1;
        }
        match session.workflow {
            Workflow::Signed => totals.workflow_signed += 1,
            Workflow::Unsigned => totals.workflow_unsigned += 1,
        }
        totals.total_prompt_tokens = totals
            .total_prompt_tokens
            .saturating_add(session.totals.prompt_tokens.load(Ordering::Acquire));
        totals.total_completion_tokens = totals
            .total_completion_tokens
            .saturating_add(session.totals.completion_tokens.load(Ordering::Acquire));
        totals.total_cached_tokens = totals
            .total_cached_tokens
            .saturating_add(session.totals.cached_tokens.load(Ordering::Acquire));
        totals.total_cost_usd_micros = totals
            .total_cost_usd_micros
            .saturating_add(session.totals.cost_usd_micros.load(Ordering::Acquire));
        totals.total_tool_calls = totals
            .total_tool_calls
            .saturating_add(session.totals.tool_calls.load(Ordering::Acquire));
        totals.total_tool_allowed = totals
            .total_tool_allowed
            .saturating_add(session.totals.tool_allowed.load(Ordering::Acquire));
        totals.total_tool_blocked = totals
            .total_tool_blocked
            .saturating_add(session.totals.tool_blocked.load(Ordering::Acquire));
    }
    Json(totals).into_response()
}

/// Query parameters for `GET /api/v1/dashboard/sessions`.
#[derive(Debug, Default, Clone, serde::Deserialize)]
pub struct ListQuery {
    limit: Option<usize>,
    status: Option<String>,
    workflow: Option<String>,
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]

    use crate::config::HarnessConfig;
    use crate::pipeline::{AppState, SESSION_HEADER};
    use crate::routes::build_router;
    use ab_bridge::{BusError, EventBus, PublishAck, StoredEvent};
    use ab_events::EventClass;
    use ab_receipts::Ed25519Signer;
    use ab_sandbox::{Sandbox, SandboxConfig};
    use ab_state::InMemoryStore;
    use axum::body::{to_bytes, Body};
    use axum::http::{header, HeaderValue, Method, Request, StatusCode};
    use serde_json::Value;
    use std::sync::Arc;
    use tower::ServiceExt;

    struct NullBus;

    impl EventBus for NullBus {
        fn publish(&self, topic: &str, _key: &str, _value: &Value) -> Result<PublishAck, BusError> {
            Ok(PublishAck {
                topic: topic.to_owned(),
                partition: 0,
                offset: 0,
            })
        }

        fn fetch(
            &self,
            _topic: &str,
            _partition: u32,
            _offset: u64,
            _max: usize,
        ) -> Result<Vec<StoredEvent>, BusError> {
            Ok(Vec::new())
        }

        fn partitions(&self, _topic: &str) -> Result<u32, BusError> {
            Ok(1)
        }

        fn topics(&self) -> Vec<String> {
            EventClass::all()
                .iter()
                .map(|class| class.topic().to_owned())
                .collect()
        }
    }

    fn build_state(mut config: HarnessConfig) -> AppState {
        config.atif_spool_dir = tempfile::tempdir().unwrap().keep().to_string_lossy().into_owned();
        AppState::new(
            config,
            Arc::new(InMemoryStore::new()),
            Arc::new(Sandbox::new(SandboxConfig::default(), Vec::new()).unwrap()),
            Arc::new(NullBus),
            None,
            Arc::new(Ed25519Signer::from_seed([9; 32])),
        )
        .unwrap()
    }

    async fn get_json(router: &axum::Router, path: &str) -> (StatusCode, Value) {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 256 * 1024).await.unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, value)
    }

    fn open_a_session(state: &AppState, id: &str) {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(SESSION_HEADER, HeaderValue::from_str(id).unwrap());
        let payload = serde_json::json!({
            "model": "test",
            "messages": [{"role": "user", "content": "hello"}],
        });
        state.prepare_chat(&headers, payload).unwrap();
    }

    #[tokio::test]
    async fn stats_endpoint_reports_empty_registry() {
        let config = HarnessConfig::for_tests("http://127.0.0.1:9", "/tmp", "/tmp");
        let state = build_state(config);
        let router = build_router(state);
        let (status, body) = get_json(&router, "/api/v1/dashboard/stats").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["session_count"], 0);
        assert_eq!(body["open_count"], 0);
        assert_eq!(body["closed_count"], 0);
        assert_eq!(body["total_cost_usd_micros"], 0);
    }

    #[tokio::test]
    async fn list_endpoint_returns_open_session() {
        let config = HarnessConfig::for_tests("http://127.0.0.1:9", "/tmp", "/tmp");
        let state = build_state(config);
        open_a_session(&state, "sess-abc");
        let router = build_router(state);

        let (status, body) = get_json(&router, "/api/v1/dashboard/sessions").await;
        assert_eq!(status, StatusCode::OK);
        let sessions = body["sessions"].as_array().unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0]["id"], "sess-abc");
        assert_eq!(sessions[0]["open"], true);
        assert_eq!(sessions[0]["closed"], false);
        assert_eq!(body["total_before_truncate"], 1);
    }

    #[tokio::test]
    async fn list_endpoint_filters_by_status() {
        let config = HarnessConfig::for_tests("http://127.0.0.1:9", "/tmp", "/tmp");
        let state = build_state(config);
        open_a_session(&state, "sess-open");
        let router = build_router(state);

        let (_, all) = get_json(&router, "/api/v1/dashboard/sessions?status=all").await;
        assert_eq!(all["sessions"].as_array().unwrap().len(), 1);

        let (_, only_closed) = get_json(&router, "/api/v1/dashboard/sessions?status=closed").await;
        assert_eq!(only_closed["sessions"].as_array().unwrap().len(), 0);

        let (_, only_open) = get_json(&router, "/api/v1/dashboard/sessions?status=open").await;
        assert_eq!(only_open["sessions"].as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn detail_endpoint_returns_summary_shape() {
        let config = HarnessConfig::for_tests("http://127.0.0.1:9", "/tmp", "/tmp");
        let state = build_state(config);
        open_a_session(&state, "sess-detail");
        let router = build_router(state);

        let (status, body) = get_json(&router, "/api/v1/dashboard/sessions/sess-detail").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["summary"]["id"], "sess-detail");
        assert!(body["chain"].is_object());
        assert!(body["receipt"].is_null(), "no receipt until session close");
    }

    #[tokio::test]
    async fn detail_endpoint_404_for_unknown_id() {
        let config = HarnessConfig::for_tests("http://127.0.0.1:9", "/tmp", "/tmp");
        let router = build_router(build_state(config));
        let (status, _body) = get_json(&router, "/api/v1/dashboard/sessions/does-not-exist").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn dashboard_index_served_as_html() {
        let config = HarnessConfig::for_tests("http://127.0.0.1:9", "/tmp", "/tmp");
        let router = build_router(build_state(config));
        let response = router
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/dashboard")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let ct = response
            .headers()
            .get(header::CONTENT_TYPE)
            .cloned()
            .unwrap_or_else(|| HeaderValue::from_static(""));
        assert!(
            ct.to_str().unwrap().starts_with("text/html"),
            "unexpected content-type: {ct:?}"
        );
        let body = to_bytes(response.into_body(), 256 * 1024).await.unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(text.contains("AgentBridge"), "index should mention product");
    }

    #[tokio::test]
    async fn dashboard_disabled_returns_404() {
        let mut config = HarnessConfig::for_tests("http://127.0.0.1:9", "/tmp", "/tmp");
        config.dashboard_enabled = false;
        let router = build_router(build_state(config));
        let response = router
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/dashboard")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
