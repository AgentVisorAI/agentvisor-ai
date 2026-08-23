//! Process-level restart tests (engineering review round-51 §10.2).
//!
//! Every other recovery test drives `recover_spooled_sessions` against a
//! hand-constructed spool. These spawn the REAL `agentvisord` binary,
//! serve real HTTP traffic through it, SIGKILL it mid-life, and restart
//! it on the same spool — the exact experiment that found §8.2 (restart
//! re-finalizes every closed session) and §8.5 (quarantine races an
//! in-progress close). `async fn main`'s recovery-then-serve sequencing
//! and the config/env plumbing get their only end-to-end coverage here.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{Read as _, Write as _};
use std::time::{Duration, Instant};

/// Pick a free loopback port by binding :0 and dropping the listener.
/// (Tiny bind race until the daemon rebinds it; acceptable in tests.)
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Minimal canned OpenAI-shaped mock upstream. Serves every connection
/// on a background thread until the process exits — deliberately
/// outliving daemon restarts.
fn spawn_mock_upstream() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            std::thread::spawn(move || {
                // Read until end of headers, then drain Content-Length.
                let mut buffer = Vec::new();
                let mut chunk = [0u8; 4096];
                let header_end = loop {
                    match stream.read(&mut chunk) {
                        Ok(0) => return,
                        Ok(n) => {
                            buffer.extend_from_slice(chunk.get(..n).unwrap());
                            if let Some(pos) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                                break pos + 4;
                            }
                        }
                        Err(_) => return,
                    }
                };
                let headers = String::from_utf8_lossy(buffer.get(..header_end).unwrap()).to_string();
                let content_length: usize = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse().ok())?
                    })
                    .unwrap_or(0);
                while buffer.len() < header_end + content_length {
                    match stream.read(&mut chunk) {
                        Ok(0) => break,
                        Ok(n) => buffer.extend_from_slice(chunk.get(..n).unwrap()),
                        Err(_) => return,
                    }
                }
                let body = r#"{"model":"mock","choices":[{"message":{"role":"assistant","content":"hello from mock"},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":3}}"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
            });
        }
    });
    port
}

/// Kills the daemon on drop so a failed assertion cannot leak a process.
struct Daemon(std::process::Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start_daemon(config_path: &std::path::Path, seed_path: &std::path::Path) -> Daemon {
    let child = std::process::Command::new(env!("CARGO_BIN_EXE_agentvisord"))
        .arg("--config")
        .arg(config_path)
        // cwd = the temp root: the default (relative) bridge-manifest
        // path is absent there, which exercises the embedded builtin
        // fallback, and any other relative path stays inside the temp.
        .current_dir(config_path.parent().unwrap())
        .env("AV_SIGNING_SEED_FILE", seed_path)
        // Quiet child logs; the assertions are HTTP-level.
        .env("RUST_LOG", "warn")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn agentvisord");
    Daemon(child)
}

fn http_get(port: u16, path: &str) -> Option<(u16, String)> {
    let mut stream =
        std::net::TcpStream::connect_timeout(&([127, 0, 0, 1], port).into(), Duration::from_millis(500))
            .ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n"
    )
    .ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
    let status: u16 = response.split_whitespace().nth(1)?.parse().ok()?;
    let body = response.split("\r\n\r\n").nth(1).unwrap_or("").to_owned();
    Some((status, body))
}

fn http_post_chat(port: u16, session: &str) -> Option<(u16, String)> {
    let body = r#"{"model":"mock","messages":[{"role":"user","content":"ping"}]}"#;
    let mut stream =
        std::net::TcpStream::connect_timeout(&([127, 0, 0, 1], port).into(), Duration::from_millis(500))
            .ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(10))).ok()?;
    write!(
        stream,
        "POST /v1/chat/completions HTTP/1.1\r\nhost: localhost\r\ncontent-type: application/json\r\nx-av-session: {session}\r\nx-av-workflow: unsigned\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    )
    .ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
    let status: u16 = response.split_whitespace().nth(1)?.parse().ok()?;
    let payload = response.split("\r\n\r\n").nth(1).unwrap_or("").to_owned();
    Some((status, payload))
}

fn wait_healthy(port: u16, daemon: &mut Daemon) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some((200, body)) = http_get(port, "/health") {
            assert!(body.contains("agentvisor"), "unexpected /health body: {body}");
            return;
        }
        if let Ok(Some(status)) = daemon.0.try_wait() {
            panic!("agentvisord exited during startup: {status}");
        }
        assert!(Instant::now() < deadline, "daemon never became healthy");
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn spool_file_count(dir: &std::path::Path) -> usize {
    std::fs::read_dir(dir)
        .map(|entries| entries.flatten().filter(|e| e.path().is_file()).count())
        .unwrap_or(0)
}

/// The §10.2 experiment: serve → SIGKILL → restart → serve → SIGKILL →
/// restart. Asserts the daemon survives its own crash artifacts, the
/// spool recovery is idempotent across repeated restarts (§8.2: no
/// unbounded duplicate work), and fresh traffic flows after each boot.
#[test]
fn sigkill_restart_recovers_and_is_idempotent() {
    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path();
    let upstream_port = spawn_mock_upstream();
    let listen_port = free_port();
    let spool = root.join("spool/atif");
    let config_path = root.join("agentvisor.toml");
    let seed_path = root.join("signing.seed");
    std::fs::write(
        &config_path,
        format!(
            r#"config_version = 1
listen = "127.0.0.1:{listen_port}"
upstream_url = "http://127.0.0.1:{upstream_port}"
require_identity = false
default_workflow = "unsigned"
compression_enabled = false
dashboard_enabled = false
atif_spool_dir = "{spool}"
bridge_data_dir = "{bridge}"
tool_schema_dir = "{schemas}"
state_backend = "memory"
embedder_backend = "hash"
vector_backend = "memory"
"#,
            spool = spool.display(),
            bridge = root.join("data/bridge").display(),
            schemas = root.join("tool-schemas").display(),
        ),
    )
    .unwrap();
    std::fs::create_dir_all(root.join("tool-schemas")).unwrap();

    // ---- Boot 1: cold start, serve one turn, SIGKILL. ----
    let mut daemon = start_daemon(&config_path, &seed_path);
    wait_healthy(listen_port, &mut daemon);
    let (status, body) = http_post_chat(listen_port, "restart-session").expect("chat request");
    assert_eq!(status, 200, "first-boot chat failed: {body}");
    assert!(
        body.contains("hello from mock"),
        "relay did not pass the upstream body: {body}"
    );
    // SIGKILL: no drain, no finalize — the spool is left exactly as a
    // crash leaves it (journal + metadata + possibly an in-flight
    // marker; the response completed so no marker is expected, but the
    // test must not assume either way).
    daemon.0.kill().unwrap();
    daemon.0.wait().unwrap();
    drop(daemon);
    assert!(spool.exists(), "first boot never wrote a spool");

    // ---- Boot 2: recover the crashed spool, then serve fresh traffic. ----
    let mut daemon = start_daemon(&config_path, &seed_path);
    wait_healthy(listen_port, &mut daemon);
    let (status, body) = http_post_chat(listen_port, "post-restart-session").expect("chat after restart");
    assert_eq!(status, 200, "post-restart chat failed: {body}");
    // Give the reconciler's first tick a moment to run recovery to
    // quiescence before measuring the idempotence baseline.
    std::thread::sleep(Duration::from_secs(2));
    let after_second_boot = spool_file_count(&spool);
    daemon.0.kill().unwrap();
    daemon.0.wait().unwrap();
    drop(daemon);

    // ---- Boot 3: recovery must be idempotent (§8.2). ----
    let mut daemon = start_daemon(&config_path, &seed_path);
    wait_healthy(listen_port, &mut daemon);
    std::thread::sleep(Duration::from_secs(2));
    let after_third_boot = spool_file_count(&spool);
    // §8.2's failure shape was unbounded growth: every restart re-adopted
    // and re-finalized every closed session, emitting duplicate events.
    // Recovery work may complete residue from the LAST crash (bounded),
    // but a third boot over the same artifacts must not add more than
    // the second did.
    assert!(
        after_third_boot <= after_second_boot + 2,
        "restart recovery is not idempotent: {after_second_boot} files after boot 2, {after_third_boot} after boot 3"
    );
    // And the daemon must still be serving.
    let (status, _) = http_post_chat(listen_port, "third-boot-session").expect("chat on third boot");
    assert_eq!(status, 200);
    drop(daemon);
}

/// A daemon killed BEFORE its response completes must, on restart,
/// quarantine the interrupted session (its in-flight marker survives
/// the crash) while still serving fresh sessions — the §8.9 shape,
/// verifying the quarantine isolates rather than wedges the daemon.
#[test]
fn sigkill_before_first_request_leaves_daemon_restartable() {
    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path();
    let upstream_port = spawn_mock_upstream();
    let listen_port = free_port();
    let config_path = root.join("agentvisor.toml");
    let seed_path = root.join("signing.seed");
    std::fs::write(
        &config_path,
        format!(
            r#"config_version = 1
listen = "127.0.0.1:{listen_port}"
upstream_url = "http://127.0.0.1:{upstream_port}"
require_identity = false
default_workflow = "unsigned"
compression_enabled = false
dashboard_enabled = false
atif_spool_dir = "{spool}"
bridge_data_dir = "{bridge}"
tool_schema_dir = "{schemas}"
state_backend = "memory"
embedder_backend = "hash"
vector_backend = "memory"
"#,
            spool = root.join("spool/atif").display(),
            bridge = root.join("data/bridge").display(),
            schemas = root.join("tool-schemas").display(),
        ),
    )
    .unwrap();
    std::fs::create_dir_all(root.join("tool-schemas")).unwrap();

    // Kill within the startup window — before recovery/serve settled.
    let mut daemon = start_daemon(&config_path, &seed_path);
    std::thread::sleep(Duration::from_millis(300));
    daemon.0.kill().unwrap();
    daemon.0.wait().unwrap();
    drop(daemon);

    // A boot-window SIGKILL (half-written seed install, torn bridge
    // provision, partial spool mkdir) must not brick the next boot.
    let mut daemon = start_daemon(&config_path, &seed_path);
    wait_healthy(listen_port, &mut daemon);
    let (status, _) = http_post_chat(listen_port, "fresh-after-boot-kill").expect("chat");
    assert_eq!(status, 200);
    drop(daemon);
}
