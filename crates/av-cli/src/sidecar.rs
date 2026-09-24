//! `avctl sidecar`: a loopback proxy that gives an unmodified application an
//! AgentVisor identity.
//!
//! The application's OpenAI SDK and MCP client point at this sidecar
//! (`OPENAI_BASE_URL=http://127.0.0.1:8485/v1`, MCP URL
//! `http://127.0.0.1:8485/mcp`; the buildpack sets both). For every request
//! the sidecar:
//!
//! - drops the application's own `Authorization` header (SDKs send a
//!   placeholder key) and attaches a short-lived AgentVisor identity token;
//! - forwards method, path, query, body, and end-to-end headers (including
//!   `MCP-Session-Id` and `MCP-Protocol-Version`) to the gateway;
//! - streams the response back unchanged, so SSE chat streams and MCP
//!   event streams pass through as they arrive.
//!
//! Identity comes from one of two sources:
//!
//! - `cf-instance` (Cloud Foundry): the instance identity certificate and
//!   key named by `CF_INSTANCE_CERT` / `CF_INSTANCE_KEY`. The sidecar signs
//!   a short RFC 7523 assertion (`RS256`, certificate chain in `x5c`) and
//!   exchanges it at the gateway's `/v1/token` for an agent token. The
//!   files are re-read on every refresh because the platform rotates them.
//! - `token-file:<path>`: a file an external identity agent keeps filled
//!   with a current AgentVisor token; it is re-read every 30 seconds.
//!
//! The sidecar listens on a loopback address only: any other address is
//! refused, so no other host can borrow the application's identity.

use anyhow::{bail, Context as _, Result};
use axum::body::Body;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode};
use base64::Engine as _;
use futures::StreamExt as _;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// RFC 7523 grant type accepted by the gateway's `/v1/token`.
const JWT_BEARER_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

/// Lifetime of each assertion the sidecar signs (the gateway accepts ≤ 300 s).
const ASSERTION_LIFETIME_S: u64 = 120;

/// How often a token file is re-read.
const TOKEN_FILE_REFRESH: Duration = Duration::from_secs(30);

/// Largest request body forwarded (the gateway's own limit is lower by
/// default).
const MAX_REQUEST_BYTES: usize = 32 * 1024 * 1024;

/// Where the sidecar gets the identity it attaches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Credential {
    /// Cloud Foundry instance identity certificate and key.
    CfInstance {
        /// PEM file with the instance certificate followed by its chain.
        cert: PathBuf,
        /// PEM file with the instance RSA private key.
        key: PathBuf,
        /// Instance GUID (the certificate CN; `CF_INSTANCE_GUID`).
        instance_guid: String,
    },
    /// A file holding a current AgentVisor token.
    TokenFile(PathBuf),
}

impl Credential {
    /// Parse `cf-instance` or `token-file:<path>`. `cf-instance` reads
    /// `CF_INSTANCE_CERT`, `CF_INSTANCE_KEY`, and `CF_INSTANCE_GUID`.
    pub fn parse(value: &str) -> Result<Self> {
        if let Some(path) = value.strip_prefix("token-file:") {
            if path.is_empty() {
                bail!("token-file: needs a path");
            }
            return Ok(Self::TokenFile(PathBuf::from(path)));
        }
        if value == "cf-instance" {
            let var = |name: &str| {
                std::env::var(name)
                    .ok()
                    .filter(|value| !value.trim().is_empty())
                    .with_context(|| format!("{name} is not set; is this a Cloud Foundry app instance?"))
            };
            return Ok(Self::CfInstance {
                cert: PathBuf::from(var("CF_INSTANCE_CERT")?),
                key: PathBuf::from(var("CF_INSTANCE_KEY")?),
                instance_guid: var("CF_INSTANCE_GUID")?,
            });
        }
        bail!("unknown credential {value:?}: use cf-instance or token-file:<path>")
    }
}

/// Settings file written by the buildpack (`avctl sidecar --config`), so no
/// binding value ever appears on a command line.
#[derive(Debug, Clone, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SidecarFile {
    /// Gateway base URL.
    pub gateway: String,
    /// Gateway audience.
    pub audience: String,
    /// Loopback listen address, e.g. `127.0.0.1:8485`.
    pub listen: String,
    /// `cf-instance` or `token-file:<path>`.
    pub credential: String,
}

impl SidecarFile {
    /// Read and parse a settings file.
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))
    }
}

/// Sidecar settings.
#[derive(Debug, Clone)]
pub struct SidecarOptions {
    /// Gateway base URL, e.g. `http://agentvisor-ai.apps.internal:8484`.
    pub gateway: String,
    /// Gateway audience (`aud` of the assertion).
    pub audience: String,
    /// Identity source.
    pub credential: Credential,
}

struct CachedToken {
    token: String,
    refresh_at: Instant,
}

struct Context {
    options: SidecarOptions,
    client: reqwest::Client,
    token: tokio::sync::Mutex<Option<CachedToken>>,
}

/// Refuse any listen address that is not loopback.
pub fn check_listen(address: &SocketAddr) -> Result<()> {
    if !address.ip().is_loopback() {
        bail!(
            "the sidecar must listen on a loopback address (127.0.0.1 or ::1), not {address}: \
             any other address would lend this application's identity to other hosts"
        );
    }
    Ok(())
}

/// Serve on an already-bound loopback listener until `shutdown` resolves.
pub async fn serve(
    listener: tokio::net::TcpListener,
    options: SidecarOptions,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<()> {
    check_listen(&listener.local_addr()?)?;
    let gateway = reqwest::Url::parse(&options.gateway).context("gateway URL")?;
    if !matches!(gateway.scheme(), "http" | "https") || gateway.host_str().is_none() {
        bail!("gateway URL must be http:// or https:// with a host");
    }
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .build()?;
    let context = Arc::new(Context {
        options,
        client,
        token: tokio::sync::Mutex::new(None),
    });
    let app = axum::Router::new()
        .fallback(proxy)
        .with_state(context)
        .layer(axum::extract::DefaultBodyLimit::max(MAX_REQUEST_BYTES));
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
        .context("sidecar server")
}

/// Bind `listen` (loopback only) and serve until Ctrl-C or SIGTERM.
pub async fn run(listen: SocketAddr, options: SidecarOptions) -> Result<()> {
    check_listen(&listen)?;
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .with_context(|| format!("bind {listen}"))?;
    eprintln!(
        "agentvisor sidecar listening on http://{} -> {}",
        listener.local_addr()?,
        options.gateway
    );
    serve(listener, options, async {
        #[cfg(unix)]
        {
            let mut terminate = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(signal) => signal,
                Err(_) => {
                    let _ = tokio::signal::ctrl_c().await;
                    return;
                }
            };
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = terminate.recv() => {}
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
    })
    .await
}

/// Hop-by-hop headers (RFC 9110 §7.6.1) plus the ones the sidecar owns.
fn forwardable(name: &HeaderName) -> bool {
    !matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "host"
            | "content-length"
            | "authorization"
    )
}

fn error(status: StatusCode, message: &str) -> Response<Body> {
    let body = serde_json::json!({"error": {"message": message, "type": "agentvisor_sidecar_error"}});
    let mut response = Response::new(Body::from(body.to_string()));
    *response.status_mut() = status;
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
}

async fn proxy(
    axum::extract::State(context): axum::extract::State<Arc<Context>>,
    request: Request<Body>,
) -> Response<Body> {
    let token = match context.token().await {
        Ok(token) => token,
        Err(problem) => {
            eprintln!("agentvisor sidecar: could not obtain an identity token: {problem:#}");
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "the AgentVisor sidecar has no identity token",
            );
        }
    };
    let (parts, body) = request.into_parts();
    let path = parts.uri.path_and_query().map_or("/", |value| value.as_str());
    let url = format!("{}{path}", context.options.gateway.trim_end_matches('/'));
    let Ok(body) = axum::body::to_bytes(body, MAX_REQUEST_BYTES).await else {
        return error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "request body is too large for the sidecar",
        );
    };
    let mut headers = HeaderMap::new();
    for (name, value) in &parts.headers {
        if forwardable(name) {
            headers.append(name.clone(), value.clone());
        }
    }
    let Ok(mut authorization) = HeaderValue::from_str(&format!("Bearer {token}")) else {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "identity token is not a header value",
        );
    };
    authorization.set_sensitive(true);
    headers.insert(axum::http::header::AUTHORIZATION, authorization);
    let upstream = match context
        .client
        .request(parts.method, url)
        .headers(headers)
        .body(body)
        .send()
        .await
    {
        Ok(upstream) => upstream,
        Err(problem) => {
            eprintln!(
                "agentvisor sidecar: gateway unreachable (connect={}, timeout={})",
                problem.is_connect(),
                problem.is_timeout()
            );
            return error(StatusCode::BAD_GATEWAY, "the AgentVisor gateway is unreachable");
        }
    };
    let mut response = Response::builder().status(upstream.status());
    if let Some(target) = response.headers_mut() {
        for (name, value) in upstream.headers() {
            if forwardable(name) {
                target.append(name.clone(), value.clone());
            }
        }
    }
    let stream = upstream
        .bytes_stream()
        .map(|chunk| chunk.map_err(std::io::Error::other));
    response
        .body(Body::from_stream(stream))
        .unwrap_or_else(|_| error(StatusCode::BAD_GATEWAY, "invalid gateway response"))
}

impl Context {
    /// The current token, refreshed when due. Concurrent requests share
    /// one refresh.
    async fn token(&self) -> Result<String> {
        let mut cached = self.token.lock().await;
        if let Some(current) = cached
            .as_ref()
            .filter(|current| current.refresh_at > Instant::now())
        {
            return Ok(current.token.clone());
        }
        let fresh = match &self.options.credential {
            Credential::TokenFile(path) => {
                let token = tokio::fs::read_to_string(path)
                    .await
                    .with_context(|| format!("read token file {}", path.display()))?
                    .trim()
                    .to_owned();
                if token.is_empty() {
                    bail!("token file {} is empty", path.display());
                }
                CachedToken {
                    token,
                    refresh_at: Instant::now() + TOKEN_FILE_REFRESH,
                }
            }
            Credential::CfInstance {
                cert,
                key,
                instance_guid,
            } => {
                let cert = tokio::fs::read(cert)
                    .await
                    .with_context(|| format!("read {}", cert.display()))?;
                let key = tokio::fs::read(key)
                    .await
                    .with_context(|| format!("read {}", key.display()))?;
                let assertion = assertion(&cert, &key, instance_guid, &self.options.audience)?;
                self.exchange(&assertion).await?
            }
        };
        let token = fresh.token.clone();
        *cached = Some(fresh);
        Ok(token)
    }

    async fn exchange(&self, assertion: &str) -> Result<CachedToken> {
        let url = format!("{}/v1/token", self.options.gateway.trim_end_matches('/'));
        let form = format!(
            "grant_type={}&assertion={}",
            percent_encode(JWT_BEARER_GRANT_TYPE),
            percent_encode(assertion)
        );
        let response = self
            .client
            .post(url)
            .timeout(Duration::from_secs(15))
            .header(
                axum::http::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(form)
            .send()
            .await
            .context("reach the gateway token endpoint")?;
        let status = response.status();
        let body: serde_json::Value = response.json().await.context("token response is not JSON")?;
        if !status.is_success() {
            bail!(
                "gateway refused the workload assertion ({status}): {}",
                body.get("error_description")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("no description")
            );
        }
        let token = body
            .get("access_token")
            .and_then(serde_json::Value::as_str)
            .filter(|token| !token.is_empty())
            .context("token response has no access_token")?
            .to_owned();
        let expires_in = body
            .get("expires_in")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(60);
        // Refresh at 80% of the lifetime, never sooner than 5 seconds.
        let refresh_in = Duration::from_secs((expires_in.saturating_mul(4) / 5).max(5));
        Ok(CachedToken {
            token,
            refresh_at: Instant::now() + refresh_in,
        })
    }
}

/// Every `CERTIFICATE` block of a PEM file, as DER.
fn certificates(pem: &[u8]) -> Result<Vec<Vec<u8>>> {
    let text = std::str::from_utf8(pem).context("certificate file is not UTF-8")?;
    let mut chain = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("-----BEGIN CERTIFICATE-----") {
        let after = rest
            .get(start.saturating_add("-----BEGIN CERTIFICATE-----".len())..)
            .unwrap_or_default();
        let end = after
            .find("-----END CERTIFICATE-----")
            .context("unterminated CERTIFICATE block")?;
        let body: String = after
            .get(..end)
            .unwrap_or_default()
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        chain.push(
            base64::engine::general_purpose::STANDARD
                .decode(body)
                .context("CERTIFICATE block is not base64")?,
        );
        rest = after
            .get(end.saturating_add("-----END CERTIFICATE-----".len())..)
            .unwrap_or_default();
    }
    if chain.is_empty() {
        bail!("certificate file contains no certificate");
    }
    Ok(chain)
}

/// Sign an RFC 7523 assertion with the instance key, carrying the
/// certificate chain in `x5c`.
pub fn assertion(cert_pem: &[u8], key_pem: &[u8], instance_guid: &str, audience: &str) -> Result<String> {
    let chain = certificates(cert_pem)?;
    let key =
        jsonwebtoken::EncodingKey::from_rsa_pem(key_pem).context("instance key is not an RSA PEM key")?;
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.x5c = Some(
        chain
            .iter()
            .map(|der| base64::engine::general_purpose::STANDARD.encode(der))
            .collect(),
    );
    let now = av_core::time::now_ms() / 1000;
    let claims = serde_json::json!({
        "iss": instance_guid,
        "sub": instance_guid,
        "aud": audience,
        "iat": now,
        "exp": now.saturating_add(ASSERTION_LIFETIME_S),
        "jti": av_core::new_event_uid(),
    });
    jsonwebtoken::encode(&header, &claims, &key).context("sign the workload assertion")
}

/// `application/x-www-form-urlencoded` value encoding.
fn percent_encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
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
    fn only_loopback_listen_addresses_are_accepted() {
        assert!(check_listen(&"127.0.0.1:8485".parse().unwrap()).is_ok());
        assert!(check_listen(&"[::1]:8485".parse().unwrap()).is_ok());
        assert!(check_listen(&"0.0.0.0:8485".parse().unwrap()).is_err());
        assert!(check_listen(&"10.0.0.5:8485".parse().unwrap()).is_err());
    }

    #[test]
    fn settings_file_is_strict() {
        let dir = std::env::temp_dir().join(format!("av-sidecar-{}", av_core::new_event_uid()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sidecar.json");
        std::fs::write(
            &path,
            r#"{"gateway":"http://gw:8484","audience":"a'b","listen":"127.0.0.1:8485","credential":"cf-instance"}"#,
        )
        .unwrap();
        let file = SidecarFile::load(&path).unwrap();
        assert_eq!(file.audience, "a'b");
        std::fs::write(
            &path,
            r#"{"gateway":"g","audience":"a","listen":"l","credential":"c","extra":1}"#,
        )
        .unwrap();
        assert!(SidecarFile::load(&path).is_err(), "unknown keys are refused");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn credential_parsing() {
        assert_eq!(
            Credential::parse("token-file:/run/token").unwrap(),
            Credential::TokenFile("/run/token".into())
        );
        assert!(Credential::parse("token-file:").is_err());
        assert!(Credential::parse("password").is_err());
    }

    #[test]
    fn form_values_are_percent_encoded() {
        assert_eq!(
            percent_encode("urn:ietf:params:oauth:grant-type:jwt-bearer"),
            "urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer"
        );
        assert_eq!(percent_encode("a.b-c_d~"), "a.b-c_d~");
    }

    #[test]
    fn hop_by_hop_and_authorization_headers_are_not_forwarded() {
        assert!(!forwardable(&HeaderName::from_static("authorization")));
        assert!(!forwardable(&HeaderName::from_static("connection")));
        assert!(forwardable(&HeaderName::from_static("mcp-session-id")));
        assert!(forwardable(&HeaderName::from_static("mcp-protocol-version")));
        assert!(forwardable(&HeaderName::from_static("accept")));
    }

    const FIXTURES: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../av-identity/tests/fixtures/cf-instance-identity"
    );

    #[derive(Default)]
    struct Seen {
        token_requests: usize,
        authorizations: Vec<String>,
        sessions: Vec<Option<String>>,
    }

    /// A fake gateway that verifies workload assertions with the real
    /// verifier, then records what the sidecar forwards.
    async fn fake_gateway(seen: Arc<parking_lot::Mutex<Seen>>) -> String {
        let trust = Arc::new(
            av_identity::WorkloadTrust::from_pem(&std::fs::read(format!("{FIXTURES}/root.pem")).unwrap())
                .unwrap(),
        );
        let app = axum::Router::new().fallback(move |request: Request<Body>| {
            let seen = Arc::clone(&seen);
            let trust = Arc::clone(&trust);
            async move {
                let path = request.uri().path().to_owned();
                let headers = request.headers().clone();
                let body = axum::body::to_bytes(request.into_body(), 1 << 20).await.unwrap();
                if path == "/v1/token" {
                    let form: Vec<(String, String)> = serde_urlencoded::from_bytes(&body).unwrap();
                    let get = |key: &str| {
                        form.iter()
                            .find(|(k, _)| k == key)
                            .map(|(_, v)| v.clone())
                            .unwrap()
                    };
                    assert_eq!(get("grant_type"), JWT_BEARER_GRANT_TYPE);
                    let verified = trust
                        .verify(&get("assertion"), "agentvisor-ai", av_core::time::now_ms() / 1000)
                        .expect("the sidecar's assertion must satisfy the gateway verifier");
                    assert_eq!(
                        verified.identity.instance_guid,
                        "0b6c1d2e-3f40-4a5b-8c6d-7e8f90a1b2c3"
                    );
                    seen.lock().token_requests += 1;
                    return axum::Json(
                        serde_json::json!({"access_token": "agent-token-1", "expires_in": 300}),
                    )
                    .into_response();
                }
                let mut seen = seen.lock();
                seen.authorizations.push(
                    headers
                        .get("authorization")
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or_default()
                        .to_owned(),
                );
                seen.sessions.push(
                    headers
                        .get("mcp-session-id")
                        .and_then(|value| value.to_str().ok())
                        .map(str::to_owned),
                );
                if path == "/v1/chat/completions" {
                    let chunks = ["data: {\"a\":1}\n\n", "data: {\"a\":2}\n\n", "data: [DONE]\n\n"];
                    let stream =
                        futures::stream::iter(chunks.map(|chunk| Ok::<_, std::io::Error>(chunk.to_owned())));
                    let mut response = Response::new(Body::from_stream(stream));
                    response
                        .headers_mut()
                        .insert("content-type", HeaderValue::from_static("text/event-stream"));
                    return response;
                }
                let mut response =
                    axum::Json(serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": {}})).into_response();
                response
                    .headers_mut()
                    .insert("mcp-session-id", HeaderValue::from_static("gateway-session"));
                response
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        url
    }

    use axum::response::IntoResponse as _;

    #[tokio::test]
    async fn sidecar_attaches_the_instance_identity_and_streams_through() {
        let seen = Arc::new(parking_lot::Mutex::new(Seen::default()));
        let gateway = fake_gateway(Arc::clone(&seen)).await;
        let dir = std::env::temp_dir().join(format!("av-sidecar-{}", av_core::new_event_uid()));
        std::fs::create_dir_all(&dir).unwrap();
        // CF_INSTANCE_CERT holds the instance certificate followed by its chain.
        let cert = dir.join("instance.crt");
        std::fs::write(
            &cert,
            std::fs::read_to_string(format!("{FIXTURES}/instance.pem")).unwrap()
                + &std::fs::read_to_string(format!("{FIXTURES}/intermediate.pem")).unwrap(),
        )
        .unwrap();
        let options = SidecarOptions {
            gateway,
            audience: "agentvisor-ai".into(),
            credential: Credential::CfInstance {
                cert,
                key: PathBuf::from(format!("{FIXTURES}/instance.key")),
                instance_guid: "0b6c1d2e-3f40-4a5b-8c6d-7e8f90a1b2c3".into(),
            },
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let sidecar = format!("http://{}", listener.local_addr().unwrap());
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(serve(listener, options, async {
            let _ = stopped.await;
        }));

        let client = reqwest::Client::new();
        let chat = client
            .post(format!("{sidecar}/v1/chat/completions"))
            .bearer_auth("sk-placeholder-from-the-sdk")
            .json(&serde_json::json!({"model": "m", "stream": true, "messages": []}))
            .send()
            .await
            .unwrap();
        assert_eq!(chat.status(), 200);
        assert_eq!(chat.headers()["content-type"], "text/event-stream");
        assert_eq!(
            chat.text().await.unwrap(),
            "data: {\"a\":1}\n\ndata: {\"a\":2}\n\ndata: [DONE]\n\n"
        );

        let mcp = client
            .post(format!("{sidecar}/mcp"))
            .header("mcp-session-id", "client-session")
            .json(&serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "ping"}))
            .send()
            .await
            .unwrap();
        assert_eq!(mcp.headers()["mcp-session-id"], "gateway-session");

        {
            let seen = seen.lock();
            assert_eq!(seen.token_requests, 1, "the token is cached between requests");
            assert_eq!(seen.authorizations, vec!["Bearer agent-token-1"; 2]);
            assert_eq!(seen.sessions, vec![None, Some("client-session".to_owned())]);
        }
        let _ = stop.send(());
        server.await.unwrap().unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }
}
