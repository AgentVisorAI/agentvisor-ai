//! MCP Streamable HTTP client for backends configured with
//! `transport = "mcp"` (the default for `[[backends]]`).
//!
//! The gateway speaks to each backend the way a conforming MCP client does
//! ([Streamable HTTP transport, 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)):
//!
//! - every POST carries `Accept: application/json, text/event-stream`;
//! - the first request of a backend session is `initialize`, followed by
//!   `notifications/initialized`; a returned `MCP-Session-Id` is sent on
//!   every later request together with `MCP-Protocol-Version`;
//! - a `404` on a request that carried a session id means the backend
//!   ended the session: the client starts a new one and retries once
//!   (the backend did not process the request, so the retry cannot run
//!   a tool twice);
//! - a request may be answered with one JSON object or with an SSE
//!   stream. The stream is decoded incrementally and reading stops at the
//!   JSON-RPC response whose `id` matches the request. Server-to-client
//!   requests that arrive first are answered (`ping` with an empty result,
//!   anything else with "method not found"), because the gateway declares
//!   no client capabilities and a waiting backend would otherwise hang
//!   until the deadline. A stream that ends early after carrying an event
//!   id is resumed with `GET` and `Last-Event-ID`.
//!
//! Backend sessions are kept per (agent session, backend) pair so state a
//! backend keeps per session never leaks between agents. The table is
//! bounded; an evicted entry only costs a fresh `initialize`.

use axum::http::{HeaderName, HeaderValue};
use futures::StreamExt as _;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

/// Protocol versions this gateway implements, newest first.
pub const SUPPORTED_PROTOCOL_VERSIONS: [&str; 4] = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

/// The version offered in `initialize` and preferred in negotiation.
pub const LATEST_PROTOCOL_VERSION: &str = "2025-11-25";

/// `Accept` value every Streamable HTTP POST must carry.
const ACCEPT_BOTH: &str = "application/json, text/event-stream";

/// Header carrying the backend-assigned (or gateway-assigned) session id.
pub const SESSION_ID_HEADER: &str = "mcp-session-id";

/// Header carrying the negotiated protocol version on later requests.
pub const PROTOCOL_VERSION_HEADER: &str = "mcp-protocol-version";

/// Upper bound on cached backend sessions.
const MAX_BACKEND_SESSIONS: usize = 4096;

/// Upper bound on bytes read from one backend exchange, matching the
/// tool-response ceiling used by the plain JSON-RPC transport.
pub(crate) const MAX_MCP_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// Upper bound on `tools/list` pages and tools collected per backend.
const MAX_DISCOVERY_PAGES: usize = 32;
const MAX_DISCOVERED_TOOLS: usize = 2048;

/// Stream resumptions attempted after an early end of an SSE stream.
const MAX_RESUMPTIONS: usize = 3;

/// Longest wait honored from a backend's SSE `retry` field.
const MAX_RETRY_WAIT_MS: u64 = 5_000;

/// True for a protocol version string this gateway implements.
pub fn is_supported_version(version: &str) -> bool {
    SUPPORTED_PROTOCOL_VERSIONS.contains(&version)
}

/// A negotiated backend session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendSession {
    /// `MCP-Session-Id` returned by the backend, when it assigned one.
    pub id: Option<String>,
    /// Protocol version the backend answered `initialize` with.
    pub protocol_version: String,
}

/// Why a backend exchange failed. The distinction matters to the caller:
/// only [`McpError::NotDelivered`] proves the backend never processed the
/// request, so only that failure may release a claimed tool execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpError {
    /// The request never reached the backend (connect failure, or the
    /// handshake that precedes it failed).
    NotDelivered(String),
    /// The backend received the request, but its answer is unusable.
    AfterDelivery(String),
}

impl std::fmt::Display for McpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotDelivered(detail) | Self::AfterDelivery(detail) => f.write_str(detail),
        }
    }
}

/// Everything needed to talk to one backend endpoint.
#[derive(Clone)]
pub struct BackendEndpoint {
    /// Backend MCP endpoint URL (from configuration only).
    pub url: String,
    /// Credential header for this call, already marked sensitive.
    pub auth: Option<(HeaderName, HeaderValue)>,
    /// Extra headers (for example the per-call intent token).
    pub extra: Vec<(HeaderName, HeaderValue)>,
    /// Absolute deadline for the whole exchange, resumptions included.
    pub deadline: tokio::time::Instant,
}

impl BackendEndpoint {
    fn remaining(&self) -> std::time::Duration {
        self.deadline
            .saturating_duration_since(tokio::time::Instant::now())
            .max(std::time::Duration::from_millis(1))
    }

    fn post(&self, client: &reqwest::Client, session: Option<&BackendSession>) -> reqwest::RequestBuilder {
        let request = client
            .post(&self.url)
            .timeout(self.remaining())
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .header(axum::http::header::ACCEPT, ACCEPT_BOTH);
        self.decorate(request, session)
    }

    fn decorate(
        &self,
        mut request: reqwest::RequestBuilder,
        session: Option<&BackendSession>,
    ) -> reqwest::RequestBuilder {
        if let Some(session) = session {
            request = request.header(PROTOCOL_VERSION_HEADER, session.protocol_version.as_str());
            if let Some(id) = &session.id {
                request = request.header(SESSION_ID_HEADER, id.as_str());
            }
        }
        if let Some((name, value)) = &self.auth {
            request = request.header(name.clone(), value.clone());
        }
        for (name, value) in &self.extra {
            request = request.header(name.clone(), value.clone());
        }
        request
    }
}

fn classify(error: &reqwest::Error) -> McpError {
    let category = crate::pipeline::classify_upstream_error(error).to_owned();
    tracing::warn!(
        category = %category,
        error.status = ?error.status(),
        error.is_timeout = error.is_timeout(),
        error.is_connect = error.is_connect(),
        "MCP backend request failed"
    );
    if error.is_connect() {
        McpError::NotDelivered(category)
    } else {
        McpError::AfterDelivery(category)
    }
}

/// Read and validate the `MCP-Session-Id` a backend returned.
fn session_id_of(response: &reqwest::Response) -> Result<Option<String>, String> {
    let mut values = response.headers().get_all(SESSION_ID_HEADER).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err("backend returned more than one MCP-Session-Id".to_owned());
    }
    let text = value
        .to_str()
        .map_err(|_| "backend MCP-Session-Id is not visible ASCII".to_owned())?;
    if text.is_empty() || text.len() > 1024 || !text.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return Err("backend MCP-Session-Id must be 1-1024 visible ASCII characters".to_owned());
    }
    Ok(Some(text.to_owned()))
}

fn is_event_stream(response: &reqwest::Response) -> bool {
    response
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|media| media.trim().eq_ignore_ascii_case("text/event-stream"))
}

/// Incremental decoder for `text/event-stream` bodies, following the
/// WHATWG event-stream interpretation rules that MCP relies on.
#[derive(Debug, Default)]
pub struct SseDecoder {
    buffer: Vec<u8>,
    data: String,
    has_data: bool,
    /// Last `id` field seen, used for `Last-Event-ID` on resumption.
    pub last_event_id: Option<String>,
    /// Last `retry` field seen, in milliseconds.
    pub retry_ms: Option<u64>,
}

impl SseDecoder {
    /// Feed a chunk and return the `data` payload of every completed event.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<String>, String> {
        self.buffer.extend_from_slice(chunk);
        if self.buffer.len() > MAX_MCP_RESPONSE_BYTES {
            return Err(format!(
                "event stream line exceeds {MAX_MCP_RESPONSE_BYTES} bytes"
            ));
        }
        let mut events = Vec::new();
        while let Some(end) = self.buffer.iter().position(|b| *b == b'\n' || *b == b'\r') {
            let terminator = self.buffer.get(end).copied();
            let mut consumed = end.saturating_add(1);
            if terminator == Some(b'\r') {
                match self.buffer.get(end.saturating_add(1)) {
                    Some(b'\n') => consumed = end.saturating_add(2),
                    Some(_) => {}
                    // A trailing CR may be the first half of CRLF.
                    None => break,
                }
            }
            let line: Vec<u8> = self.buffer.drain(..consumed).take(end).collect();
            let line = String::from_utf8(line).map_err(|_| "event stream is not valid UTF-8".to_owned())?;
            if let Some(event) = self.line(&line) {
                events.push(event);
            }
        }
        Ok(events)
    }

    fn line(&mut self, line: &str) -> Option<String> {
        if line.is_empty() {
            if !self.has_data {
                return None;
            }
            self.has_data = false;
            let mut data = std::mem::take(&mut self.data);
            if data.ends_with('\n') {
                data.pop();
            }
            return Some(data);
        }
        if line.starts_with(':') {
            return None;
        }
        let (field, value) = match line.split_once(':') {
            Some((field, value)) => (field, value.strip_prefix(' ').unwrap_or(value)),
            None => (line, ""),
        };
        match field {
            "data" => {
                self.data.push_str(value);
                self.data.push('\n');
                self.has_data = true;
            }
            "id" if !value.contains('\0') => self.last_event_id = Some(value.to_owned()),
            "retry" if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) => {
                self.retry_ms = value.parse().ok();
            }
            _ => {}
        }
        None
    }
}

/// What one decoded message means for a pending request.
enum Message {
    /// The response to the pending request, re-serialized.
    Response(Vec<u8>),
    /// A request from the backend that needs an answer.
    ServerRequest { id: Value, method: String },
    /// Anything else (notifications, unrelated responses, priming events).
    Other,
}

fn interpret(payload: &str, request_id: &Value) -> Result<Vec<Message>, String> {
    if payload.trim().is_empty() {
        return Ok(vec![Message::Other]);
    }
    let value: Value =
        serde_json::from_str(payload).map_err(|_| "event stream carried a non-JSON message".to_owned())?;
    let items = match value {
        Value::Array(items) => items,
        other => vec![other],
    };
    let mut messages = Vec::with_capacity(items.len());
    for item in items {
        let Some(object) = item.as_object() else {
            messages.push(Message::Other);
            continue;
        };
        let method = object.get("method").and_then(Value::as_str);
        let id = object.get("id");
        match (method, id) {
            (Some(method), Some(id)) => messages.push(Message::ServerRequest {
                id: id.clone(),
                method: method.to_owned(),
            }),
            (None, Some(id))
                if id == request_id && (object.contains_key("result") || object.contains_key("error")) =>
            {
                messages.push(Message::Response(
                    serde_json::to_vec(&item).map_err(|error| error.to_string())?,
                ));
            }
            _ => messages.push(Message::Other),
        }
    }
    Ok(messages)
}

/// Client for MCP backends, holding the bounded backend-session table.
pub struct McpBackendClient {
    client: reqwest::Client,
    sessions: parking_lot::Mutex<HashMap<(String, String), SessionSlot>>,
}

struct SessionSlot {
    session: Arc<tokio::sync::Mutex<Option<BackendSession>>>,
    last_used: Instant,
}

impl McpBackendClient {
    /// Build a client on top of the gateway's shared HTTP client.
    pub fn new(client: reqwest::Client) -> Self {
        Self {
            client,
            sessions: parking_lot::Mutex::new(HashMap::new()),
        }
    }

    /// Number of cached backend sessions (for tests and metrics).
    pub fn cached_sessions(&self) -> usize {
        self.sessions.lock().len()
    }

    fn slot(&self, agent_session: &str, backend: &str) -> Arc<tokio::sync::Mutex<Option<BackendSession>>> {
        let mut sessions = self.sessions.lock();
        let key = (agent_session.to_owned(), backend.to_owned());
        if let Some(slot) = sessions.get_mut(&key) {
            slot.last_used = Instant::now();
            return Arc::clone(&slot.session);
        }
        if sessions.len() >= MAX_BACKEND_SESSIONS {
            // Evict idle slots, oldest first, until there is room. A slot
            // still referenced by an in-flight call is never evicted.
            let mut idle: Vec<((String, String), Instant)> = sessions
                .iter()
                .filter(|(_, slot)| Arc::strong_count(&slot.session) == 1)
                .map(|(key, slot)| (key.clone(), slot.last_used))
                .collect();
            idle.sort_by_key(|(_, used)| *used);
            let excess = sessions
                .len()
                .saturating_add(1)
                .saturating_sub(MAX_BACKEND_SESSIONS);
            for (key, _) in idle.into_iter().take(excess.max(1)) {
                sessions.remove(&key);
            }
        }
        let session = Arc::new(tokio::sync::Mutex::new(None));
        sessions.insert(
            key,
            SessionSlot {
                session: Arc::clone(&session),
                last_used: Instant::now(),
            },
        );
        session
    }

    /// Forget every backend session opened for `agent_session`.
    pub fn forget_agent_session(&self, agent_session: &str) {
        self.sessions
            .lock()
            .retain(|(agent, _), _| agent != agent_session);
    }

    /// Run the `initialize` handshake against `endpoint`.
    pub async fn initialize(&self, endpoint: &BackendEndpoint) -> Result<BackendSession, McpError> {
        let request_id = Value::String(format!("agentvisor-initialize-{}", av_core::ids::new_event_uid()));
        let body = json!({
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "initialize",
            "params": {
                "protocolVersion": LATEST_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "agentvisor-gateway", "version": "undisclosed"},
            },
        });
        let bytes = serde_json::to_vec(&body).map_err(|error| McpError::NotDelivered(error.to_string()))?;
        let response = endpoint
            .post(&self.client, None)
            .body(bytes)
            .send()
            .await
            // Only the handshake can have reached the backend, so the tool
            // call it precedes was not delivered in either case.
            .map_err(|error| McpError::NotDelivered(format!("initialize: {}", classify(&error))))?;
        let status = response.status();
        if !status.is_success() {
            return Err(McpError::NotDelivered(format!(
                "backend refused initialize with HTTP {}",
                status.as_u16()
            )));
        }
        let assigned = session_id_of(&response).map_err(McpError::NotDelivered)?;
        let provisional = BackendSession {
            id: assigned.clone(),
            protocol_version: LATEST_PROTOCOL_VERSION.to_owned(),
        };
        let reply = self
            .read_reply(response, &request_id, endpoint, Some(&provisional))
            .await
            .map_err(|error| McpError::NotDelivered(format!("initialize: {error}")))?;
        let reply: Value = serde_json::from_slice(&reply)
            .map_err(|_| McpError::NotDelivered("initialize reply is not JSON".to_owned()))?;
        if let Some(error) = reply.get("error") {
            let message = error.get("message").and_then(Value::as_str).unwrap_or("error");
            return Err(McpError::NotDelivered(format!(
                "backend rejected initialize: {message}"
            )));
        }
        let version = reply
            .pointer("/result/protocolVersion")
            .and_then(Value::as_str)
            .ok_or_else(|| McpError::NotDelivered("initialize result has no protocolVersion".to_owned()))?;
        if !is_supported_version(version) {
            return Err(McpError::NotDelivered(format!(
                "backend negotiated unsupported MCP protocol version {version:?}"
            )));
        }
        let session = BackendSession {
            id: assigned,
            protocol_version: version.to_owned(),
        };
        let notification =
            serde_json::to_vec(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
                .map_err(|error| McpError::NotDelivered(error.to_string()))?;
        let acknowledged = endpoint
            .post(&self.client, Some(&session))
            .body(notification)
            .send()
            .await
            .map_err(|error| {
                McpError::NotDelivered(format!("initialized notification: {}", classify(&error)))
            })?;
        if !acknowledged.status().is_success() {
            return Err(McpError::NotDelivered(format!(
                "backend refused the initialized notification with HTTP {}",
                acknowledged.status().as_u16()
            )));
        }
        Ok(session)
    }

    /// The cached session for (`agent_session`, `backend`), opening one on
    /// first use. Concurrent callers share a single handshake.
    pub async fn session(
        &self,
        agent_session: &str,
        backend: &str,
        endpoint: &BackendEndpoint,
    ) -> Result<BackendSession, McpError> {
        let slot = self.slot(agent_session, backend);
        let mut guard = slot.lock().await;
        if let Some(session) = guard.as_ref() {
            return Ok(session.clone());
        }
        let session = self.initialize(endpoint).await?;
        *guard = Some(session.clone());
        Ok(session)
    }

    /// Drop a session the backend reported as ended, unless a concurrent
    /// caller already replaced it.
    async fn invalidate(&self, agent_session: &str, backend: &str, stale: &BackendSession) {
        let slot = self.slot(agent_session, backend);
        let mut guard = slot.lock().await;
        if guard.as_ref() == Some(stale) {
            *guard = None;
        }
    }

    /// Send one JSON-RPC request and return the matching JSON-RPC response
    /// bytes. `body` is forwarded verbatim; `request_id` is its `id`.
    ///
    /// Returns `(http_status, response_bytes)`. A non-success HTTP status
    /// other than a session-expiry `404` is returned as-is with the body
    /// the backend sent, so the caller can record it.
    pub async fn request(
        &self,
        agent_session: &str,
        backend: &str,
        endpoint: &BackendEndpoint,
        body: &[u8],
        request_id: &Value,
    ) -> Result<(u16, Vec<u8>, Option<String>), McpError> {
        let mut session = self.session(agent_session, backend, endpoint).await?;
        let mut retried = false;
        loop {
            let response = endpoint
                .post(&self.client, Some(&session))
                .body(body.to_vec())
                .send()
                .await
                .map_err(|error| classify(&error))?;
            let status = response.status();
            if status == reqwest::StatusCode::NOT_FOUND && session.id.is_some() && !retried {
                // Spec: 404 on a request carrying a session id means the
                // session is gone and the request was not processed.
                retried = true;
                self.invalidate(agent_session, backend, &session).await;
                session = self.session(agent_session, backend, endpoint).await?;
                continue;
            }
            if let Some(refused) = refused_encoding(&response) {
                return Err(McpError::AfterDelivery(refused));
            }
            if !status.is_success() {
                let content_type = response
                    .headers()
                    .get(axum::http::header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned);
                let bytes = read_bounded(response).await.map_err(McpError::AfterDelivery)?;
                return Ok((status.as_u16(), bytes, content_type));
            }
            let bytes = self
                .read_reply(response, request_id, endpoint, Some(&session))
                .await
                .map_err(McpError::AfterDelivery)?;
            return Ok((status.as_u16(), bytes, Some("application/json".to_owned())));
        }
    }

    /// Collect every tool a backend advertises through `tools/list`,
    /// following `nextCursor` pagination within fixed bounds.
    pub async fn list_tools(
        &self,
        agent_session: &str,
        backend: &str,
        endpoint: &BackendEndpoint,
    ) -> Result<Vec<Value>, McpError> {
        let mut tools = Vec::new();
        let mut cursor: Option<String> = None;
        for page in 0..MAX_DISCOVERY_PAGES {
            let request_id = Value::String(format!(
                "agentvisor-tools-list-{page}-{}",
                av_core::ids::new_event_uid()
            ));
            let mut request =
                json!({"jsonrpc": "2.0", "id": request_id, "method": "tools/list", "params": {}});
            if let (Some(cursor), Some(params)) = (&cursor, request.get_mut("params")) {
                params["cursor"] = Value::String(cursor.clone());
            }
            let body =
                serde_json::to_vec(&request).map_err(|error| McpError::NotDelivered(error.to_string()))?;
            let (status, bytes, _) = self
                .request(agent_session, backend, endpoint, &body, &request_id)
                .await?;
            if !(200..300).contains(&status) {
                return Err(McpError::AfterDelivery(format!(
                    "tools/list answered HTTP {status}"
                )));
            }
            let reply: Value = serde_json::from_slice(&bytes)
                .map_err(|_| McpError::AfterDelivery("tools/list reply is not JSON".to_owned()))?;
            if reply.get("error").is_some() {
                return Err(McpError::AfterDelivery("backend rejected tools/list".to_owned()));
            }
            let page_tools = reply
                .pointer("/result/tools")
                .and_then(Value::as_array)
                .ok_or_else(|| McpError::AfterDelivery("tools/list result has no tools array".to_owned()))?;
            for tool in page_tools {
                if tools.len() >= MAX_DISCOVERED_TOOLS {
                    return Ok(tools);
                }
                tools.push(tool.clone());
            }
            cursor = reply
                .pointer("/result/nextCursor")
                .and_then(Value::as_str)
                .filter(|next| !next.is_empty())
                .map(str::to_owned);
            if cursor.is_none() {
                return Ok(tools);
            }
        }
        Ok(tools)
    }

    /// Read the JSON-RPC response for `request_id` from a successful reply,
    /// which is either one JSON object or an SSE stream.
    async fn read_reply(
        &self,
        response: reqwest::Response,
        request_id: &Value,
        endpoint: &BackendEndpoint,
        session: Option<&BackendSession>,
    ) -> Result<Vec<u8>, String> {
        if !is_event_stream(&response) {
            return read_bounded(response).await;
        }
        let mut decoder = SseDecoder::default();
        let mut response = response;
        let mut total = 0_usize;
        let mut resumptions = 0_usize;
        loop {
            let mut stream = response.bytes_stream();
            while let Some(chunk) = stream.next().await {
                let chunk =
                    chunk.map_err(|error| crate::pipeline::classify_upstream_error(&error).to_owned())?;
                total = total.saturating_add(chunk.len());
                if total > MAX_MCP_RESPONSE_BYTES {
                    return Err(format!("backend response exceeds {MAX_MCP_RESPONSE_BYTES} bytes"));
                }
                for payload in decoder.push(&chunk)? {
                    for message in interpret(&payload, request_id)? {
                        match message {
                            Message::Response(bytes) => return Ok(bytes),
                            Message::ServerRequest { id, method } => {
                                self.answer_server_request(endpoint, session, id, &method).await;
                            }
                            Message::Other => {}
                        }
                    }
                }
            }
            let Some(last_event_id) = decoder.last_event_id.clone() else {
                return Err("backend event stream ended without a response".to_owned());
            };
            if resumptions >= MAX_RESUMPTIONS {
                return Err("backend event stream ended without a response after resumption".to_owned());
            }
            resumptions = resumptions.saturating_add(1);
            let wait = decoder.retry_ms.unwrap_or(0).min(MAX_RETRY_WAIT_MS);
            if wait > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(wait)).await;
            }
            let resume = endpoint
                .decorate(
                    self.client
                        .get(&endpoint.url)
                        .timeout(endpoint.remaining())
                        .header(axum::http::header::ACCEPT, "text/event-stream")
                        .header("last-event-id", last_event_id.as_str()),
                    session,
                )
                .send()
                .await
                .map_err(|error| crate::pipeline::classify_upstream_error(&error).to_owned())?;
            if !resume.status().is_success() || !is_event_stream(&resume) {
                return Err(format!(
                    "backend refused to resume its event stream (HTTP {})",
                    resume.status().as_u16()
                ));
            }
            response = resume;
        }
    }

    /// Answer a server-to-client request so the backend does not wait for
    /// a reply that would never come. Best effort: failures are logged.
    async fn answer_server_request(
        &self,
        endpoint: &BackendEndpoint,
        session: Option<&BackendSession>,
        id: Value,
        method: &str,
    ) {
        let reply = if method == "ping" {
            json!({"jsonrpc": "2.0", "id": id, "result": {}})
        } else {
            tracing::warn!(method, "MCP backend sent a request the gateway does not support");
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {"code": -32601, "message": "method not supported by the AgentVisor gateway"},
            })
        };
        let Ok(bytes) = serde_json::to_vec(&reply) else {
            return;
        };
        if let Err(error) = endpoint.post(&self.client, session).body(bytes).send().await {
            let _ = classify(&error);
        }
    }
}

fn refused_encoding(response: &reqwest::Response) -> Option<String> {
    for value in response.headers().get_all(axum::http::header::CONTENT_ENCODING) {
        let raw = value.to_str().unwrap_or_default();
        for token in raw.split(',') {
            let token = token.trim();
            if !token.is_empty() && !token.eq_ignore_ascii_case("identity") {
                return Some(format!(
                    "tool upstream responded with unsupported Content-Encoding token {token:?} (full header: {raw:?})"
                ));
            }
        }
    }
    None
}

async fn read_bounded(response: reqwest::Response) -> Result<Vec<u8>, String> {
    let mut stream = response.bytes_stream();
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| crate::pipeline::classify_upstream_error(&error).to_owned())?;
        if body.len().saturating_add(chunk.len()) > MAX_MCP_RESPONSE_BYTES {
            return Err(format!("backend response exceeds {MAX_MCP_RESPONSE_BYTES} bytes"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
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
    fn decoder_joins_multiline_data_and_tracks_ids() {
        let mut decoder = SseDecoder::default();
        let events = decoder
            .push(b": comment\r\nid: 7\r\nretry: 250\r\ndata: {\"a\":\r\ndata: 1}\r\n\r\n")
            .unwrap();
        assert_eq!(events, vec!["{\"a\":\n1}".to_owned()]);
        assert_eq!(decoder.last_event_id.as_deref(), Some("7"));
        assert_eq!(decoder.retry_ms, Some(250));
    }

    #[test]
    fn decoder_handles_split_crlf_and_lone_cr() {
        let mut decoder = SseDecoder::default();
        assert!(decoder.push(b"data: one\r").unwrap().is_empty());
        let events = decoder.push(b"\n\rdata: two\r\r").unwrap();
        assert_eq!(events, vec!["one".to_owned()]);
        let events = decoder.push(b"x").unwrap();
        assert_eq!(events, vec!["two".to_owned()]);
    }

    #[test]
    fn empty_priming_event_is_ignored() {
        let mut decoder = SseDecoder::default();
        let events = decoder.push(b"id: 1\ndata:\n\n").unwrap();
        assert_eq!(events, vec![String::new()]);
        assert!(matches!(
            interpret(&events[0], &json!(1)).unwrap()[0],
            Message::Other
        ));
    }

    #[test]
    fn interpret_finds_matching_response_and_server_requests() {
        let id = json!(5);
        let messages = interpret(
            r#"[{"jsonrpc":"2.0","method":"notifications/progress","params":{}},
                {"jsonrpc":"2.0","id":"s1","method":"ping"},
                {"jsonrpc":"2.0","id":4,"result":{}},
                {"jsonrpc":"2.0","id":5,"result":{"ok":true}}]"#,
            &id,
        )
        .unwrap();
        assert!(matches!(messages[0], Message::Other));
        assert!(matches!(&messages[1], Message::ServerRequest { method, .. } if method == "ping"));
        assert!(
            matches!(messages[2], Message::Other),
            "a response with another id is not ours"
        );
        match &messages[3] {
            Message::Response(bytes) => {
                let value: Value = serde_json::from_slice(bytes).unwrap();
                assert_eq!(value["result"]["ok"], true);
            }
            _ => panic!("expected the matching response"),
        }
    }

    #[test]
    fn non_json_event_is_an_error() {
        assert!(interpret("not json", &json!(1)).is_err());
    }

    #[test]
    fn supported_versions_include_latest() {
        assert!(is_supported_version(LATEST_PROTOCOL_VERSION));
        assert!(is_supported_version("2025-03-26"));
        assert!(!is_supported_version("1.0.0"));
    }
}
