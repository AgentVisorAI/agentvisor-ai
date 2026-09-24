//! Shared scaffolding for the av-harness integration suites.
//!
//! Each file under `tests/` compiles to its own binary and pulls in only
//! the pieces it uses; the remainder is dead code from that binary's
//! point of view, hence the file-level allow.
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use av_bridge::{BusError, EventBus, PublishAck, StoredEvent};
use av_events::EventClass;
use av_harness::{AppState, HarnessConfig};
use av_receipts::{Ed25519Signer, Keyring, Signer};
use av_sandbox::Sandbox;
use av_state::InMemoryStore;
use axum::http::{HeaderMap, HeaderValue};
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

fn all_topics() -> Vec<String> {
    EventClass::all().iter().map(|c| c.topic().to_owned()).collect()
}

/// In-memory bus double that acks every publish with a monotonically
/// increasing offset and counts the publishes.
#[derive(Default)]
pub struct CountingBus {
    /// Number of successful publishes so far.
    pub published: AtomicU64,
}

impl EventBus for CountingBus {
    fn publish(&self, topic: &str, _key: &str, _value: &Value) -> Result<PublishAck, BusError> {
        Ok(PublishAck {
            topic: topic.to_owned(),
            partition: 0,
            offset: self.published.fetch_add(1, Ordering::AcqRel),
        })
    }
    fn fetch(&self, _t: &str, _p: u32, _o: u64, _m: usize) -> Result<Vec<StoredEvent>, BusError> {
        Ok(Vec::new())
    }
    fn partitions(&self, _t: &str) -> Result<u32, BusError> {
        Ok(1)
    }
    fn topics(&self) -> Vec<String> {
        all_topics()
    }
}

/// Counting bus that additionally records every published payload,
/// per-topic publish counts, and any `metadata.uid` values it sees, so
/// tests can assert on exactly what reached the bus.
#[derive(Default)]
pub struct RecordingBus {
    /// Number of successful publishes so far.
    pub published: AtomicU64,
    /// Every published payload, in publish order.
    pub payloads: Mutex<Vec<Value>>,
    /// Publish count per topic.
    pub per_topic: Mutex<HashMap<String, u64>>,
    /// `metadata.uid` of every payload that carried one, in publish order.
    pub seen_uids: Mutex<Vec<String>>,
}

impl EventBus for RecordingBus {
    fn publish(&self, topic: &str, _key: &str, value: &Value) -> Result<PublishAck, BusError> {
        let offset = self.published.fetch_add(1, Ordering::AcqRel);
        self.payloads.lock().push(value.clone());
        *self.per_topic.lock().entry(topic.to_owned()).or_default() += 1;
        if let Some(uid) = value
            .get("metadata")
            .and_then(|m| m.get("uid"))
            .and_then(Value::as_str)
        {
            self.seen_uids.lock().push(uid.to_owned());
        }
        Ok(PublishAck {
            topic: topic.to_owned(),
            partition: 0,
            offset,
        })
    }
    fn fetch(&self, _t: &str, _p: u32, _o: u64, _m: usize) -> Result<Vec<StoredEvent>, BusError> {
        Ok(Vec::new())
    }
    fn partitions(&self, _t: &str) -> Result<u32, BusError> {
        Ok(1)
    }
    fn topics(&self) -> Vec<String> {
        all_topics()
    }
}

/// Publish-and-forget bus for latency-sensitive runs: no counters, no
/// recording, constant ack.
pub struct NullBus;

impl EventBus for NullBus {
    fn publish(&self, topic: &str, _key: &str, _value: &Value) -> Result<PublishAck, BusError> {
        Ok(PublishAck {
            topic: topic.to_owned(),
            partition: 0,
            offset: 0,
        })
    }
    fn fetch(&self, _t: &str, _p: u32, _o: u64, _m: usize) -> Result<Vec<StoredEvent>, BusError> {
        Ok(Vec::new())
    }
    fn partitions(&self, _t: &str) -> Result<u32, BusError> {
        Ok(1)
    }
    fn topics(&self) -> Vec<String> {
        all_topics()
    }
}

/// Deterministic test signer from a repeated one-byte seed.
pub fn signer(seed: u8) -> Ed25519Signer {
    Ed25519Signer::from_seed(&[seed; 32])
}

/// Keyring holding the public keys of the given signers.
pub fn ring(signers: &[&Ed25519Signer]) -> Keyring {
    let mut r = Keyring::new();
    for s in signers {
        r.add_key_bytes(&Signer::public_key_bytes(*s)).unwrap();
    }
    r
}

/// Sandbox built from the harness config the way `agentvisord` builds it
/// (`load_sandbox`), so budget and schema settings in `config` are the ones
/// actually enforced. `SandboxConfig::default()` ignores them.
pub fn sandbox_for(config: &HarnessConfig) -> Sandbox {
    Sandbox::new(
        av_sandbox::SandboxConfig {
            schemas: HashMap::new(),
            budget: config.budget.clone(),
            payout_field: config.payout_field.clone(),
            require_schema: config.require_tool_schema,
        },
        Vec::new(),
    )
    .unwrap()
}

/// Tempdir-backed test config pointing at an unreachable upstream. The
/// tempdir is leaked so its paths stay valid for the life of the process
/// (the AppState built from the config holds paths into it).
pub fn leaked_test_config() -> HarnessConfig {
    let dir = tempfile::tempdir().unwrap();
    let config = HarnessConfig::for_tests(
        "http://127.0.0.1:9",
        &dir.path().to_string_lossy(),
        &dir.path().to_string_lossy(),
    );
    std::mem::forget(dir);
    config
}

/// Assemble an `AppState` from the standard test parts: in-memory store,
/// the given sandbox and bus, no identity validator, and a signer seeded
/// with `signer_seed`.
pub fn app_state(
    config: HarnessConfig,
    sandbox: Sandbox,
    bus: Arc<dyn EventBus>,
    signer_seed: u8,
) -> Arc<AppState> {
    Arc::new(
        AppState::new(
            config,
            Arc::new(InMemoryStore::new()),
            Arc::new(sandbox),
            bus,
            None,
            Arc::new(signer(signer_seed)),
        )
        .unwrap(),
    )
}

/// Assemble an `AppState` with a real identity validator (HMAC shared
/// secret) and an in-memory revocation list, as `agentvisord` wires it
/// for `state_backend = "memory"`.
pub fn app_state_with_identity(
    config: HarnessConfig,
    sandbox: Sandbox,
    bus: Arc<dyn EventBus>,
    signer_seed: u8,
    hmac_secret: &[u8],
    hmac_kid: &str,
) -> Arc<AppState> {
    app_state_with_revocation(
        config,
        sandbox,
        bus,
        signer_seed,
        hmac_secret,
        hmac_kid,
        Arc::new(av_identity::InMemoryRevocationStore::new()),
    )
}

/// [`app_state_with_identity`] with a caller-chosen revocation list.
pub fn app_state_with_revocation(
    config: HarnessConfig,
    sandbox: Sandbox,
    bus: Arc<dyn EventBus>,
    signer_seed: u8,
    hmac_secret: &[u8],
    hmac_kid: &str,
    revocation: Arc<dyn av_identity::RevocationStore>,
) -> Arc<AppState> {
    let mut validator = av_identity::IdentityValidator::new(&config.audience);
    validator.set_max_chain_depth(config.max_delegation_depth);
    if !config.identity_allowed_issuers.is_empty() {
        validator.allow_issuers(config.identity_allowed_issuers.clone());
    }
    validator
        .add_key(
            hmac_kid,
            av_identity::KeyMaterial::HmacSecret(hmac_secret.to_vec()),
        )
        .unwrap();
    validator.set_revocation_store(revocation);
    Arc::new(
        AppState::new(
            config,
            Arc::new(InMemoryStore::new()),
            Arc::new(sandbox),
            bus,
            Some(Arc::new(validator)),
            Arc::new(signer(signer_seed)),
        )
        .unwrap(),
    )
}

/// Session headers for the given workflow.
pub fn headers(session: &str, workflow: &'static str) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert("x-av-session", HeaderValue::from_str(session).unwrap());
    h.insert("x-av-workflow", HeaderValue::from_static(workflow));
    h
}

/// Session headers for the signed workflow.
pub fn signed_headers(session: &str) -> HeaderMap {
    headers(session, "signed")
}

/// Serialized JSON-RPC `tools/call` request for the given tool.
pub fn tools_call(tool: &str, args: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool, "arguments": args}
    }))
    .unwrap()
}

/// Minimal single-message chat payload with the given user content.
pub fn chat(content: &str) -> Value {
    json!({"model": "m", "messages": [{"role": "user", "content": content}]})
}

/// Minimal single-message chat payload.
pub fn chat_payload() -> Value {
    chat("hi")
}

/// One HTTP request captured by [`MockBackend`].
#[derive(Debug, Clone)]
pub struct CapturedRequest {
    /// Request path.
    pub path: String,
    /// `(lower-cased name, value)` pairs in arrival order.
    pub headers: Vec<(String, String)>,
    /// Raw request body.
    pub body: Vec<u8>,
}

impl CapturedRequest {
    /// First value of header `name` (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        let name = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| value.as_str())
    }

    /// Every header and the body as text, for "this secret never left
    /// the gateway" assertions.
    pub fn everything(&self) -> String {
        let mut text = String::new();
        for (key, value) in &self.headers {
            text.push_str(key);
            text.push_str(": ");
            text.push_str(value);
            text.push('\n');
        }
        text.push_str(&String::from_utf8_lossy(&self.body));
        text
    }
}

/// Tool backend on 127.0.0.1 that records every request and answers each
/// with a JSON-RPC success echoing the request id.
pub struct MockBackend {
    /// URL to put in `[[backends]].url` or `tool_upstream_url`.
    pub url: String,
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
    task: tokio::task::JoinHandle<()>,
}

impl MockBackend {
    /// Bind an ephemeral port and start serving.
    pub async fn start() -> Self {
        let requests: Arc<Mutex<Vec<CapturedRequest>>> = Arc::default();
        let recorded = Arc::clone(&requests);
        let app = axum::Router::new().fallback(
            move |uri: axum::http::Uri, headers: HeaderMap, body: axum::body::Bytes| {
                let recorded = Arc::clone(&recorded);
                async move {
                    recorded.lock().push(CapturedRequest {
                        path: uri.path().to_owned(),
                        headers: headers
                            .iter()
                            .map(|(key, value)| {
                                (
                                    key.as_str().to_owned(),
                                    value.to_str().unwrap_or("<non-text>").to_owned(),
                                )
                            })
                            .collect(),
                        body: body.to_vec(),
                    });
                    let id = serde_json::from_slice::<Value>(&body)
                        .ok()
                        .and_then(|request| request.get("id").cloned())
                        .unwrap_or(Value::Null);
                    axum::Json(json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {"content": [{"type": "text", "text": "ok"}]}
                    }))
                }
            },
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/mcp", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self { url, requests, task }
    }

    /// Requests received so far, in arrival order.
    pub fn requests(&self) -> Vec<CapturedRequest> {
        self.requests.lock().clone()
    }
}

impl Drop for MockBackend {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Claims that vary between the NHI tokens a test mints.
pub struct NhiSpec<'a> {
    /// Human principal (`sub`).
    pub sub: &'a str,
    /// Calling agent (`instance_uid`).
    pub instance_uid: &'a str,
    /// Granted scopes.
    pub scopes: &'a [&'a str],
    /// Token id.
    pub jti: &'a str,
}

/// Mint an HS256 NHI token that a harness built with
/// [`app_state_with_identity`] (same secret and kid) accepts.
pub fn mint_nhi_token(secret: &[u8], kid: &str, audience: &str, spec: &NhiSpec<'_>) -> String {
    let now_s = av_core::time::now_ms() / 1000;
    let claims = av_identity::NhiClaims {
        sub: spec.sub.to_owned(),
        iss: "test-issuer".to_owned(),
        aud: av_identity::Audience::Single(audience.to_owned()),
        iat: now_s,
        nbf: None,
        exp: now_s + 300,
        jti: spec.jti.to_owned(),
        azp: Some("caller-app".to_owned()),
        act: None,
        instance_uid: spec.instance_uid.to_owned(),
        charter: "support-agent".to_owned(),
        version: "1.0".to_owned(),
        scopes: spec.scopes.iter().map(|scope| (*scope).to_owned()).collect(),
        parent_token: None,
    };
    let header = jsonwebtoken::Header {
        alg: jsonwebtoken::Algorithm::HS256,
        kid: Some(kid.to_owned()),
        ..Default::default()
    };
    jsonwebtoken::encode(&header, &claims, &jsonwebtoken::EncodingKey::from_secret(secret)).unwrap()
}

/// Write `contents` to `dir/name` with owner-only permissions and return
/// the path as a config string.
pub fn owner_only_file(dir: &std::path::Path, name: &str, contents: &str) -> String {
    let path = dir.join(name);
    std::fs::write(&path, contents).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    path.to_string_lossy().into_owned()
}

/// Verify an EdDSA token against the first key of a JWKS document, the
/// way a backend would after fetching `/.well-known/jwks.json`.
pub fn verify_with_jwks<T: serde::de::DeserializeOwned>(
    jwks: &Value,
    token: &str,
) -> jsonwebtoken::TokenData<T> {
    let x = jwks["keys"][0]["x"].as_str().unwrap();
    let key = jsonwebtoken::DecodingKey::from_ed_components(x).unwrap();
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
    validation.validate_aud = false;
    validation.required_spec_claims.clear();
    jsonwebtoken::decode::<T>(token, &key, &validation).unwrap()
}
