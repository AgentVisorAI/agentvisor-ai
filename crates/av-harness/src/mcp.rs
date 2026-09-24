//! Gateway-side MCP lifecycle: the server role of the Streamable HTTP
//! transport ([2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle)).
//!
//! A stock MCP client talks to `/mcp` (or `/mcp/{backend}`) exactly as it
//! would talk to any MCP server:
//!
//! - `initialize` negotiates a protocol version and returns an
//!   `MCP-Session-Id`. The id is an HMAC-signed value bound to the
//!   authenticated principal and to the negotiated version, so the gateway
//!   keeps no per-session table and a stolen id is useless to anyone else.
//!   The id also names the AgentVisor session the client's calls belong
//!   to, so every call of one MCP session lands in one audited session.
//! - `ping` answers an empty result; notifications and client responses
//!   answer `202 Accepted`.
//! - `tools/list` aggregates the tools of every backend the endpoint
//!   exposes, and lists only tools the caller could actually call: names
//!   the tool gate accepts, routed to that backend, covered by the caller's
//!   scopes, and permitted by the policy decision point.
//! - `tools/call` continues through the existing audited tool path.
//!
//! Requests with an `Origin` header that is not allowed are refused with
//! 403, an unsupported `MCP-Protocol-Version` with 400, and an unknown or
//! foreign `MCP-Session-Id` with 404 (which tells the client to start a
//! new session).

use crate::backend::{BackendAuthMode, ResolvedBackend};
use crate::config::BackendTransport;
use crate::mcp_client::{self, BackendEndpoint, PROTOCOL_VERSION_HEADER, SESSION_ID_HEADER};
use crate::pipeline::{AppState, AuthenticatedCaller, PipelineError};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use hmac::{Hmac, KeyInit as _, Mac as _};
use serde_json::{json, Value};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Lifetime of a gateway-issued `MCP-Session-Id`. After it, the client
/// receives 404 and re-initializes, as the specification requires.
pub(crate) const SESSION_MAX_AGE_S: u64 = 24 * 60 * 60;

/// Tolerated clock difference for an id issued "in the future".
const CLOCK_SKEW_S: u64 = 60;

/// Truncated HMAC tag length (128 bits).
const TAG_BYTES: usize = 16;

/// Largest schema file read from `tool_schema_dir` for `tools/list`.
const MAX_SCHEMA_FILE_BYTES: u64 = 1024 * 1024;

/// Most schema files considered for `tools/list`.
const MAX_SCHEMA_FILES: usize = 2048;

/// The JSON-RPC messages this module answers itself.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Incoming {
    /// `initialize` request.
    Initialize {
        /// Request id to echo.
        id: Value,
        /// `params.protocolVersion`, when present.
        requested_version: Option<String>,
    },
    /// `ping` request.
    Ping {
        /// Request id to echo.
        id: Value,
    },
    /// `tools/list` request.
    ToolsList {
        /// Request id to echo.
        id: Value,
        /// `params.cursor`, when present.
        cursor: Option<Value>,
    },
    /// A `notifications/*` message (no id).
    Notification,
    /// A JSON-RPC response sent by the client.
    ClientResponse,
    /// `tools/call` and everything else: handled by the tool path.
    Forward,
}

/// Classify a request body. Anything this module does not answer itself,
/// including malformed bodies, is [`Incoming::Forward`], so the existing
/// strict parser keeps producing its errors for it.
pub(crate) fn classify(body: &[u8]) -> Incoming {
    let Ok(Value::Object(object)) = serde_json::from_slice::<Value>(body) else {
        return Incoming::Forward;
    };
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Incoming::Forward;
    }
    let method = object.get("method").and_then(Value::as_str);
    let id = object
        .get("id")
        .filter(|id| matches!(id, Value::String(_) | Value::Number(_)))
        .cloned();
    let params = object.get("params");
    match (method, id) {
        (Some("initialize"), Some(id)) => Incoming::Initialize {
            id,
            requested_version: params
                .and_then(|params| params.get("protocolVersion"))
                .and_then(Value::as_str)
                .map(str::to_owned),
        },
        (Some("ping"), Some(id)) => Incoming::Ping { id },
        (Some("tools/list"), Some(id)) => Incoming::ToolsList {
            id,
            cursor: params
                .and_then(|params| params.get("cursor"))
                .filter(|cursor| !cursor.is_null())
                .cloned(),
        },
        (Some(method), None) if method.starts_with("notifications/") && !object.contains_key("id") => {
            Incoming::Notification
        }
        (None, Some(_)) if object.contains_key("result") || object.contains_key("error") => {
            Incoming::ClientResponse
        }
        _ => Incoming::Forward,
    }
}

/// A verified gateway MCP session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GatewaySession {
    /// AgentVisor session id every call of this MCP session belongs to.
    pub(crate) agent_session: String,
    /// Protocol version negotiated at `initialize`.
    pub(crate) protocol_version: String,
}

/// Issues and verifies `MCP-Session-Id` values.
pub(crate) struct SessionSigner {
    key: [u8; 32],
}

impl SessionSigner {
    /// Derive a dedicated key from the journal key (itself derived from
    /// the persistent receipt signer), so ids survive restarts and share
    /// no key material with any other use.
    pub(crate) fn derive(journal_key: &[u8; 32]) -> Self {
        let mut key = [0u8; 32];
        if let Ok(mut mac) = HmacSha256::new_from_slice(journal_key) {
            mac.update(b"agentvisor-mcp-session-key-v1");
            key.copy_from_slice(&mac.finalize().into_bytes());
        }
        Self { key }
    }

    fn mac(&self, principal: &str, version: &str, issued_s: u64, agent_session: &str) -> Option<HmacSha256> {
        let mut mac = HmacSha256::new_from_slice(&self.key).ok()?;
        mac.update(b"agentvisor-mcp-session-v1");
        for field in [principal.as_bytes(), version.as_bytes(), agent_session.as_bytes()] {
            mac.update(&u64::try_from(field.len()).ok()?.to_be_bytes());
            mac.update(field);
        }
        mac.update(&issued_s.to_be_bytes());
        Some(mac)
    }

    /// Issue a session id for `principal` at protocol `version`. Returns
    /// `(MCP-Session-Id value, AgentVisor session id)`.
    pub(crate) fn issue(&self, principal: &str, version: &str, now_s: u64) -> Option<(String, String)> {
        let agent_session = av_core::new_session_id().to_string();
        let tag = self
            .mac(principal, version, now_s, &agent_session)?
            .finalize()
            .into_bytes();
        let tag = hex::encode(tag.get(..TAG_BYTES)?);
        Some((
            format!("v1.{version}.{now_s}.{agent_session}.{tag}"),
            agent_session,
        ))
    }

    /// Verify an id presented by `principal`. `None` means "unknown
    /// session": forged, foreign, malformed, or expired.
    pub(crate) fn verify(&self, principal: &str, token: &str, now_s: u64) -> Option<GatewaySession> {
        if token.len() > 256 {
            return None;
        }
        let mut parts = token.split('.');
        let (Some("v1"), Some(version), Some(issued), Some(agent_session), Some(tag), None) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ) else {
            return None;
        };
        if !mcp_client::is_supported_version(version) {
            return None;
        }
        let issued_s: u64 = issued.parse().ok()?;
        if issued_s > now_s.saturating_add(CLOCK_SKEW_S) || now_s.saturating_sub(issued_s) > SESSION_MAX_AGE_S
        {
            return None;
        }
        av_core::SessionId::parse(agent_session).ok()?;
        let tag = hex::decode(tag).ok()?;
        if tag.len() != TAG_BYTES {
            return None;
        }
        self.mac(principal, version, issued_s, agent_session)?
            .verify_truncated_left(&tag)
            .ok()?;
        Some(GatewaySession {
            agent_session: agent_session.to_owned(),
            protocol_version: version.to_owned(),
        })
    }
}

/// Which backends an MCP endpoint exposes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Scope {
    /// `/mcp` and `/v1/mcp`: every backend.
    All,
    /// `/mcp/{backend}` and `/v1/mcp/{backend}`: one backend.
    Backend(String),
}

impl Scope {
    fn admits(&self, backend: &str) -> bool {
        match self {
            Self::All => true,
            Self::Backend(name) => name == backend,
        }
    }
}

/// JSON-RPC error body with a `null` id, for transport-level refusals.
/// Boxed: `Response` is large and these travel in `Result::Err`.
fn transport_error(status: StatusCode, code: i64, message: &str) -> Box<Response> {
    Box::new(
        (
            status,
            Json(json!({"jsonrpc": "2.0", "id": null, "error": {"code": code, "message": message}})),
        )
            .into_response(),
    )
}

/// Refuse a request whose `Origin` is present and not allowed.
pub(crate) fn check_origin(state: &AppState, headers: &HeaderMap) -> Result<(), Box<Response>> {
    let mut origins = headers.get_all(axum::http::header::ORIGIN).iter();
    let Some(origin) = origins.next() else {
        return Ok(());
    };
    let allowed = origins.next().is_none()
        && origin.to_str().is_ok_and(|origin| {
            state
                .config
                .mcp_allowed_origins
                .iter()
                .any(|allowed| allowed.trim_end_matches('/').eq_ignore_ascii_case(origin))
        });
    if allowed {
        Ok(())
    } else {
        Err(transport_error(
            StatusCode::FORBIDDEN,
            -32600,
            "Origin is not allowed for this MCP endpoint",
        ))
    }
}

/// Refuse an unsupported `MCP-Protocol-Version` header with 400.
pub(crate) fn check_protocol_version(headers: &HeaderMap) -> Result<(), Box<Response>> {
    let mut values = headers.get_all(PROTOCOL_VERSION_HEADER).iter();
    let Some(value) = values.next() else {
        return Ok(());
    };
    if values.next().is_none() && value.to_str().is_ok_and(mcp_client::is_supported_version) {
        return Ok(());
    }
    Err(transport_error(
        StatusCode::BAD_REQUEST,
        -32600,
        "unsupported MCP-Protocol-Version",
    ))
}

/// The principal string a session id is bound to.
pub(crate) fn principal_of(caller: &AuthenticatedCaller) -> String {
    caller
        .principal_digest()
        .unwrap_or_else(|| "anonymous".to_owned())
}

/// Verify an `MCP-Session-Id` and bind its AgentVisor session into
/// `headers` as `X-AV-Session`, so the audited tool path uses it.
pub(crate) fn bind_session(
    state: &AppState,
    headers: &mut HeaderMap,
    caller: &AuthenticatedCaller,
) -> Result<Option<GatewaySession>, Box<Response>> {
    let mut values = headers.get_all(SESSION_ID_HEADER).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(transport_error(
            StatusCode::BAD_REQUEST,
            -32600,
            "more than one MCP-Session-Id header",
        ));
    }
    let now_s = av_core::time::now_ms() / 1000;
    let session = value
        .to_str()
        .ok()
        .and_then(|token| state.mcp_sessions.verify(&principal_of(caller), token, now_s))
        .ok_or_else(|| transport_error(StatusCode::NOT_FOUND, -32001, "MCP session not found"))?;
    match crate::pipeline::single_header(headers, crate::pipeline::SESSION_HEADER) {
        Ok(None) => {}
        Ok(Some(existing)) if existing.as_bytes() == session.agent_session.as_bytes() => {}
        _ => {
            return Err(transport_error(
                StatusCode::BAD_REQUEST,
                -32600,
                "X-AV-Session does not match the MCP session",
            ))
        }
    }
    let bound = HeaderValue::from_str(&session.agent_session).map_err(|_| {
        transport_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            -32603,
            "session id is not a header value",
        )
    })?;
    headers.insert(HeaderName::from_static(crate::pipeline::SESSION_HEADER), bound);
    Ok(Some(session))
}

fn result(id: &Value, result: Value) -> Response {
    Json(json!({"jsonrpc": "2.0", "id": id, "result": result})).into_response()
}

fn rpc_error(id: &Value, code: i64, message: &str) -> Response {
    Json(json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})).into_response()
}

/// Answer the lifecycle and discovery messages. `Ok(None)` means the
/// message belongs to the tool path.
pub(crate) async fn answer(
    state: &AppState,
    headers: &HeaderMap,
    caller: &AuthenticatedCaller,
    incoming: Incoming,
    scope: &Scope,
    session: Option<&GatewaySession>,
) -> Result<Option<Response>, PipelineError> {
    match incoming {
        Incoming::Forward => Ok(None),
        Incoming::Notification | Incoming::ClientResponse => Ok(Some(StatusCode::ACCEPTED.into_response())),
        Incoming::Ping { id } => {
            caller.authorize(state, None)?;
            Ok(Some(result(&id, json!({}))))
        }
        Incoming::Initialize {
            id,
            requested_version,
        } => {
            caller.authorize(state, None)?;
            let version = requested_version
                .filter(|version| mcp_client::is_supported_version(version))
                .unwrap_or_else(|| mcp_client::LATEST_PROTOCOL_VERSION.to_owned());
            let now_s = av_core::time::now_ms() / 1000;
            let Some((token, _)) = state.mcp_sessions.issue(&principal_of(caller), &version, now_s) else {
                return Err(PipelineError::unavailable(
                    "could not issue an MCP session".to_owned(),
                ));
            };
            let server_name = match scope {
                Scope::All => "agentvisor-gateway".to_owned(),
                Scope::Backend(name) => format!("agentvisor-gateway/{name}"),
            };
            let mut response = result(
                &id,
                json!({
                    "protocolVersion": version,
                    "capabilities": {"tools": {"listChanged": false}},
                    "serverInfo": {"name": server_name, "version": "undisclosed"},
                }),
            );
            let value = HeaderValue::from_str(&token)
                .map_err(|_| PipelineError::unavailable("MCP session id is not a header value".to_owned()))?;
            response
                .headers_mut()
                .insert(HeaderName::from_static(SESSION_ID_HEADER), value);
            Ok(Some(response))
        }
        Incoming::ToolsList { id, cursor } => {
            caller.authorize(state, None)?;
            if cursor.is_some() {
                // This gateway returns every tool in one page and never
                // issues a cursor, so any cursor is invalid.
                return Ok(Some(rpc_error(&id, -32602, "invalid cursor")));
            }
            let tools = list_tools(state, headers, caller, scope, session).await;
            Ok(Some(result(&id, json!({"tools": tools}))))
        }
    }
}

/// Why a discovered tool is withheld from `tools/list`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Withheld {
    /// The tool gate would refuse the name (case, encoding, whitespace).
    InvalidName,
    /// Routing sends the name to a different backend, or nowhere.
    Unrouted,
    /// The caller's scopes do not cover `tool:<name>`.
    Scope,
    /// The policy decision point denies the tool.
    Policy,
    /// Another backend already listed the name.
    Duplicate,
}

impl Withheld {
    fn label(self) -> &'static str {
        match self {
            Self::InvalidName => "invalid_name",
            Self::Unrouted => "unrouted",
            Self::Scope => "scope",
            Self::Policy => "policy",
            Self::Duplicate => "duplicate",
        }
    }
}

/// Decide whether `name`, discovered on `backend`, may be listed to `caller`.
pub(crate) fn admissible(
    state: &AppState,
    caller: &AuthenticatedCaller,
    backend: Option<&str>,
    name: &str,
) -> Result<(), Withheld> {
    // Reuse the tool gate's own parser so listing and calling can never
    // disagree about which names are acceptable.
    let probe = serde_json::to_vec(&json!({
        "jsonrpc": "2.0", "id": 0, "method": "tools/call",
        "params": {"name": name, "arguments": {}},
    }))
    .map_err(|_| Withheld::InvalidName)?;
    match av_sandbox::parse_tool_call(&probe) {
        Ok(parsed) if parsed.tool == name => {}
        _ => return Err(Withheld::InvalidName),
    }
    let routed = state
        .backend_router
        .resolve(name)
        .map(|resolved| resolved.name.as_str());
    if routed != backend {
        return Err(Withheld::Unrouted);
    }
    if state.config.enforce_identity_scopes {
        if let Some(validated) = &caller.validated {
            if !crate::pipeline::scope_allows(&validated.claims.scopes, &crate::pipeline::tool_scope(name)) {
                return Err(Withheld::Scope);
            }
        }
    }
    match state
        .pdp
        .decide_for(name, av_core::time::now_ms() / 1000, &caller.facts())
    {
        crate::authz::AuthzDecision::Permit { .. } => Ok(()),
        _ => Err(Withheld::Policy),
    }
}

/// Scopes to request when exchanging the caller's token for discovery:
/// every tool scope the caller holds.
fn discovery_scopes(caller: &AuthenticatedCaller) -> Option<String> {
    let validated = caller.validated.as_ref()?;
    let scopes: Vec<&str> = validated
        .claims
        .scopes
        .iter()
        .map(|scope| if scope == "*" { "tool:*" } else { scope.as_str() })
        .filter(|scope| scope.starts_with("tool:"))
        .collect();
    (!scopes.is_empty()).then(|| scopes.join(" "))
}

/// The credential header for a discovery request to `backend`. `Err`
/// means the caller cannot use this backend at all, so it is skipped.
fn discovery_credential(
    state: &AppState,
    headers: &HeaderMap,
    caller: &AuthenticatedCaller,
    backend: &ResolvedBackend,
) -> Result<Option<(HeaderName, HeaderValue)>, ()> {
    match backend.auth_mode {
        BackendAuthMode::None | BackendAuthMode::Static => Ok(backend.auth_header.clone()),
        BackendAuthMode::Exchange => {
            let scopes = discovery_scopes(caller).ok_or(())?;
            let token =
                crate::routes::exchange_token_for(state, caller, &backend.name, &scopes).map_err(|_| ())?;
            bearer_header(&token).map(Some).ok_or(())
        }
        BackendAuthMode::ForwardToken => caller_bearer(headers).map(Some).ok_or(()),
    }
}

/// `Authorization: Bearer <token>`, marked sensitive.
pub(crate) fn bearer_header(token: &str) -> Option<(HeaderName, HeaderValue)> {
    let mut value = HeaderValue::from_str(&format!("Bearer {token}")).ok()?;
    value.set_sensitive(true);
    Some((axum::http::header::AUTHORIZATION, value))
}

/// The caller's own bearer token, re-serialized as a sensitive header.
pub(crate) fn caller_bearer(headers: &HeaderMap) -> Option<(HeaderName, HeaderValue)> {
    let value = crate::pipeline::single_header(headers, "authorization").ok()??;
    let token = crate::pipeline::strip_bearer_scheme(value.to_str().ok()?)?;
    bearer_header(token)
}

async fn discover(
    state: &AppState,
    headers: &HeaderMap,
    caller: &AuthenticatedCaller,
    backend: &ResolvedBackend,
    session: Option<&GatewaySession>,
) -> Result<Vec<Value>, String> {
    if backend.transport == BackendTransport::JsonRpc {
        return Ok(configured_tools(state, Some(backend)).await);
    }
    let auth = discovery_credential(state, headers, caller, backend)
        .map_err(|()| "caller holds no usable credential for this backend".to_owned())?;
    let timeout = state
        .config
        .mcp_request_timeout_s
        .unwrap_or(crate::config::DEFAULT_MCP_REQUEST_TIMEOUT_S);
    let endpoint = BackendEndpoint {
        url: backend.url.clone(),
        auth,
        extra: Vec::new(),
        deadline: tokio::time::Instant::now() + std::time::Duration::from_secs(timeout),
    };
    // Reuse the MCP session's backend session; a request without an MCP
    // session gets a throwaway backend session.
    let (agent_session, ephemeral) = match session {
        Some(session) => (session.agent_session.clone(), false),
        None => (format!("discovery-{}", av_core::ids::new_event_uid()), true),
    };
    let listed = state
        .mcp_backends
        .list_tools(&agent_session, &backend.name, &endpoint)
        .await
        .map_err(|error| error.to_string());
    if ephemeral {
        state.mcp_backends.forget_agent_session(&agent_session);
    }
    listed
}

/// Tools known from configuration alone: the backend's explicit `tools`
/// list, or (for a default backend, or verdict-only mode) every schema in
/// `tool_schema_dir`. Schemas supply `inputSchema` and `description`.
async fn configured_tools(state: &AppState, backend: Option<&ResolvedBackend>) -> Vec<Value> {
    let names: Option<Vec<String>> = backend
        .filter(|backend| !backend.tools.is_empty())
        .map(|backend| backend.tools.clone());
    let schema_dir = state.config.tool_schema_dir.clone();
    tokio::task::spawn_blocking(move || {
        let read_schema = |name: &str| -> Option<Value> {
            let dir = schema_dir.as_deref()?;
            let path = std::path::Path::new(dir).join(format!("{name}.json"));
            let metadata = std::fs::metadata(&path).ok()?;
            if !metadata.is_file() || metadata.len() > MAX_SCHEMA_FILE_BYTES {
                return None;
            }
            serde_json::from_slice(&std::fs::read(&path).ok()?).ok()
        };
        let names = match names {
            Some(names) => names,
            None => {
                let Some(dir) = schema_dir.as_deref() else {
                    return Vec::new();
                };
                let Ok(entries) = std::fs::read_dir(dir) else {
                    return Vec::new();
                };
                let mut names: Vec<String> = entries
                    .filter_map(Result::ok)
                    .filter_map(|entry| {
                        let name = entry.file_name().into_string().ok()?;
                        name.strip_suffix(".json").map(str::to_owned)
                    })
                    .take(MAX_SCHEMA_FILES)
                    .collect();
                names.sort();
                names
            }
        };
        names
            .into_iter()
            .map(|name| {
                let schema = read_schema(&name);
                let mut tool = json!({
                    "name": name,
                    "inputSchema": schema.clone().filter(Value::is_object).unwrap_or_else(|| json!({"type": "object"})),
                });
                if let Some(description) = schema
                    .as_ref()
                    .and_then(|schema| schema.get("description"))
                    .and_then(Value::as_str)
                {
                    if let Some(object) = tool.as_object_mut() {
                        object.insert("description".to_owned(), Value::String(description.to_owned()));
                    }
                }
                tool
            })
            .collect()
    })
    .await
    .unwrap_or_default()
}

/// Build the `tools/list` result for `scope`.
async fn list_tools(
    state: &AppState,
    headers: &HeaderMap,
    caller: &AuthenticatedCaller,
    scope: &Scope,
    session: Option<&GatewaySession>,
) -> Vec<Value> {
    let mut sources: Vec<(Option<String>, Vec<Value>)> = Vec::new();
    if state.backend_router.is_empty() {
        // Verdict-only mode: calls are decided but not forwarded, so the
        // configured schemas are the whole catalog.
        if *scope == Scope::All {
            sources.push((None, configured_tools(state, None).await));
        }
    } else {
        for backend in state
            .backend_router
            .iter()
            .filter(|backend| scope.admits(&backend.name))
        {
            match discover(state, headers, caller, backend, session).await {
                Ok(tools) => sources.push((Some(backend.name.clone()), tools)),
                Err(error) => {
                    tracing::warn!(backend = %backend.name, %error, "MCP tool discovery failed");
                    state
                        .metrics
                        .counter(
                            &format!("av_mcp_discovery_failures_total{{backend=\"{}\"}}", backend.name),
                            "MCP tools/list discovery failures by backend",
                        )
                        .inc();
                }
            }
        }
    }
    let withhold = |reason: Withheld| {
        state
            .metrics
            .counter(
                &format!("av_mcp_tools_withheld_total{{reason=\"{}\"}}", reason.label()),
                "Discovered MCP tools withheld from tools/list, by reason",
            )
            .inc();
    };
    let mut seen = std::collections::HashSet::new();
    let mut candidates: Vec<(Option<String>, String, Value)> = Vec::new();
    for (backend, discovered) in sources {
        for tool in discovered {
            let Some(name) = tool.get("name").and_then(Value::as_str).map(str::to_owned) else {
                continue;
            };
            let verdict = if seen.contains(&name) {
                Err(Withheld::Duplicate)
            } else {
                admissible(state, caller, backend.as_deref(), &name)
            };
            match verdict {
                Ok(()) => {
                    seen.insert(name.clone());
                    candidates.push((backend.clone(), name, tool));
                }
                Err(reason) => withhold(reason),
            }
        }
    }
    let Some(authzen) = &state.authzen else {
        return candidates.into_iter().map(|(_, _, tool)| tool).collect();
    };
    // The external PDP must also permit each listed tool. One batch
    // request when the PDP offers the evaluations endpoint.
    let facts = caller.facts();
    let missions: Vec<String> = state
        .pdp
        .applicable_missions(&facts)
        .into_iter()
        .map(|mission| mission.id.clone())
        .collect();
    let agent_session = session.map(|session| session.agent_session.as_str());
    let requests: Vec<crate::authz::AuthzEvalRequest> = candidates
        .iter()
        .map(|(backend, name, _)| {
            crate::authzen::evaluation_request(
                caller,
                name,
                &state.pdp.intent_for(name),
                backend.as_deref(),
                agent_session,
                &missions,
            )
        })
        .collect();
    match authzen.evaluate_many(&requests).await {
        Ok(decisions) => candidates
            .into_iter()
            .zip(decisions)
            .filter_map(|((_, _, tool), permitted)| {
                if !permitted {
                    withhold(Withheld::Policy);
                }
                permitted.then_some(tool)
            })
            .collect(),
        Err(error) => {
            // Fail closed: without a decision nothing is listed as callable.
            tracing::warn!(%error, "external policy decision point unavailable during tools/list");
            for _ in &candidates {
                withhold(Withheld::Policy);
            }
            Vec::new()
        }
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
    fn classify_recognizes_lifecycle_messages() {
        let init =
            br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}"#;
        assert_eq!(
            classify(init),
            Incoming::Initialize {
                id: json!(1),
                requested_version: Some("2025-06-18".into())
            }
        );
        assert_eq!(
            classify(br#"{"jsonrpc":"2.0","id":"p","method":"ping"}"#),
            Incoming::Ping { id: json!("p") }
        );
        assert_eq!(
            classify(br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#),
            Incoming::Notification
        );
        assert_eq!(
            classify(br#"{"jsonrpc":"2.0","id":9,"result":{}}"#),
            Incoming::ClientResponse
        );
        assert_eq!(
            classify(br#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"cursor":"c"}}"#),
            Incoming::ToolsList {
                id: json!(2),
                cursor: Some(json!("c"))
            }
        );
    }

    #[test]
    fn classify_forwards_tool_calls_and_malformed_bodies() {
        assert_eq!(
            classify(br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}"#),
            Incoming::Forward
        );
        assert_eq!(classify(b"not json"), Incoming::Forward);
        assert_eq!(classify(br#"{"id":1,"method":"initialize"}"#), Incoming::Forward);
        // A notification-shaped tools/call keeps its existing handling.
        assert_eq!(
            classify(br#"{"jsonrpc":"2.0","method":"tools/call","params":{}}"#),
            Incoming::Forward
        );
        // A null id is not a request id MCP allows.
        assert_eq!(
            classify(br#"{"jsonrpc":"2.0","id":null,"method":"ping"}"#),
            Incoming::Forward
        );
    }

    #[test]
    fn session_ids_round_trip_and_bind_to_principal_and_time() {
        let signer = SessionSigner::derive(&[7u8; 32]);
        let (token, agent_session) = signer.issue("alice", "2025-11-25", 1_000).unwrap();
        let session = signer.verify("alice", &token, 1_010).unwrap();
        assert_eq!(session.agent_session, agent_session);
        assert_eq!(session.protocol_version, "2025-11-25");
        assert!(token.len() <= 128, "token must fit a session header comfortably");
        assert!(
            signer.verify("mallory", &token, 1_010).is_none(),
            "foreign principal"
        );
        assert!(
            signer
                .verify("alice", &token, 1_000 + SESSION_MAX_AGE_S + 1)
                .is_none(),
            "expired"
        );
        assert!(
            signer.verify("alice", &token, 1_000 - CLOCK_SKEW_S - 1).is_none(),
            "future"
        );
        let other = SessionSigner::derive(&[8u8; 32]);
        assert!(
            other.verify("alice", &token, 1_010).is_none(),
            "other deployment key"
        );
    }

    #[test]
    fn tampered_session_ids_are_refused() {
        let signer = SessionSigner::derive(&[7u8; 32]);
        let (token, _) = signer.issue("alice", "2025-11-25", 1_000).unwrap();
        let swapped_version = token.replacen("2025-11-25", "2025-06-18", 1);
        assert!(signer.verify("alice", &swapped_version, 1_010).is_none());
        let mut bytes = token.clone().into_bytes();
        let last = bytes.len() - 1;
        bytes[last] = if bytes[last] == b'0' { b'1' } else { b'0' };
        assert!(signer
            .verify("alice", &String::from_utf8(bytes).unwrap(), 1_010)
            .is_none());
        assert!(signer
            .verify("alice", "v1.2025-11-25.1000.x.y.z", 1_010)
            .is_none());
        assert!(signer.verify("alice", "", 1_010).is_none());
    }
}
