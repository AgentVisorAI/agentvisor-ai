//! Process-level restart tests.
//!
//! Every other recovery test drives `recover_spooled_sessions` against a
//! hand-constructed spool. These spawn the REAL `agentvisord` binary,
//! serve real HTTP traffic through it, SIGKILL it mid-life, and restart
//! it on the same spool — the exact experiment that found two real bugs
//! (restart re-finalized every closed session; quarantine raced an
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

/// Poll `spool_file_count` until it stabilises (same value across
/// `stable_polls` consecutive reads spaced by `poll_interval`), then
/// return that value. Times out after `budget`.
///
/// Replaces a hardcoded `thread::sleep(Duration::from_secs(2))` used
/// as a "let reconciler tick to quiescence" wait — on a slow CI the
/// first tick can still be in-flight at 2 s, giving a
/// mid-tick file count and a spurious idempotence-regression failure.
/// Polling for a stable value tolerates loaded runners while still
/// detecting a real unbounded-growth regression (the count would
/// never stabilise).
fn wait_for_spool_quiescence(
    dir: &std::path::Path,
    poll_interval: Duration,
    stable_polls: usize,
    budget: Duration,
) -> usize {
    let deadline = Instant::now() + budget;
    let mut last = spool_file_count(dir);
    let mut stable = 0usize;
    while Instant::now() < deadline {
        std::thread::sleep(poll_interval);
        let now = spool_file_count(dir);
        if now == last {
            stable = stable.saturating_add(1);
            if stable >= stable_polls {
                return now;
            }
        } else {
            stable = 0;
            last = now;
        }
    }
    // Budget exhausted; return the most recent count. A real failure
    // shape here (recovery still churning after the whole budget) is
    // caught by the caller's idempotence assertion on the resulting
    // value against the previous boot's stable value.
    last
}

/// The kill-and-restart experiment: serve → SIGKILL → restart → serve →
/// SIGKILL → restart. Asserts the daemon survives its own crash artifacts,
/// the spool recovery is idempotent across repeated restarts (no
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
    // Wait for the reconciler's recovery to reach a stable file
    // count before measuring the idempotence baseline. Replaces a
    // fixed 2 s sleep that races the first tick on loaded CI.
    let after_second_boot =
        wait_for_spool_quiescence(&spool, Duration::from_millis(200), 3, Duration::from_secs(10));
    daemon.0.kill().unwrap();
    daemon.0.wait().unwrap();
    drop(daemon);

    // ---- Boot 3: recovery must be idempotent. ----
    let mut daemon = start_daemon(&config_path, &seed_path);
    wait_healthy(listen_port, &mut daemon);
    let after_third_boot =
        wait_for_spool_quiescence(&spool, Duration::from_millis(200), 3, Duration::from_secs(10));
    // The failure shape to guard against is unbounded growth: a buggy
    // recovery re-adopted and re-finalized every closed session on each
    // restart, emitting duplicate events.
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
/// the crash) while still serving fresh sessions — verifying the
/// quarantine isolates rather than wedges the daemon.
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

/// Every ENOSPC/EIO durability path was once reasoned about
/// in comments and tested nowhere. This is the reproducible variant of
/// the failure-mode table's "disk full" row, driven end-to-end through
/// the real daemon: with the spool filesystem unwritable, chat requests
/// must FAIL CLOSED (5xx, no unaudited traffic reaches the upstream)
/// while the process itself stays alive and recovers the moment the
/// spool is writable again.
#[cfg(unix)]
#[test]
fn unwritable_spool_fails_closed_and_recovers() {
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

    let mut daemon = start_daemon(&config_path, &seed_path);
    wait_healthy(listen_port, &mut daemon);
    // Healthy baseline turn (also forces the spool tree to exist).
    let (status, _) = http_post_chat(listen_port, "pre-outage").expect("baseline chat");
    assert_eq!(status, 200);

    // Simulate the outage: the WHOLE spool tree becomes unwritable —
    // the observable shape of a full or read-only filesystem for every
    // create/rename the audit path performs (a top-level-only chmod
    // would miss the inflight-responses/ subdirectory the sync marker
    // write targets).
    fn chmod_tree(dir: &std::path::Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt as _;
        for entry in std::fs::read_dir(dir).unwrap().flatten() {
            if entry.path().is_dir() {
                chmod_tree(&entry.path(), mode);
            }
        }
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(mode)).unwrap();
    }
    chmod_tree(&spool, 0o555);

    let (status, body) = http_post_chat(listen_port, "during-outage").expect("chat during outage");
    // Restore permissions FIRST so a failed assertion cannot leave the
    // tempdir undeletable.
    chmod_tree(&spool, 0o755);
    assert!(
        (500..600).contains(&status),
        "an unwritable spool must fail closed with a 5xx, got {status}: {body}"
    );
    assert!(
        !body.contains("hello from mock"),
        "no unaudited traffic may reach the upstream during a spool outage: {body}"
    );

    // Liveness must NOT flap on a spool outage (/livez is
    // constant; a restart cannot fix a full disk).
    let (live, _) = http_get(listen_port, "/livez").expect("livez");
    assert_eq!(live, 200);

    // Recovery: the moment the spool is writable, traffic flows again
    // with no restart required.
    let (status, body) = http_post_chat(listen_port, "post-outage").expect("chat after recovery");
    assert_eq!(
        status, 200,
        "traffic must recover once the spool is writable: {body}"
    );
    drop(daemon);
}

/// Two daemons sharing one spool would silently split the
/// audit trail (interleaved journals, racing reconcilers, torn
/// artifacts). The daemon holds an exclusive advisory lock on
/// `.agentvisord.lock` for its whole lifetime; a second instance
/// must refuse to boot while the first lives, and must boot cleanly
/// once the first is gone (the OS releases the lock on ANY exit,
/// including SIGKILL — no stale-lock recovery to get wrong).
#[test]
fn second_daemon_on_same_spool_refuses_to_boot() {
    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path();
    let upstream_port = spawn_mock_upstream();
    let spool = root.join("spool/atif");
    let seed_path = root.join("signing.seed");

    let write_config = |listen_port: u16| {
        let config_path = root.join(format!("agentvisor-{listen_port}.toml"));
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
                bridge = root.join(format!("data/bridge-{listen_port}")).display(),
                schemas = root.join("tool-schemas").display(),
            ),
        )
        .unwrap();
        config_path
    };
    std::fs::create_dir_all(root.join("tool-schemas")).unwrap();

    let first_port = free_port();
    let mut first = start_daemon(&write_config(first_port), &seed_path);
    wait_healthy(first_port, &mut first);

    // A second instance pointed at the SAME spool must exit non-zero
    // without ever serving.
    let second_port = free_port();
    let second_config = write_config(second_port);
    let mut second = start_daemon(&second_config, &seed_path);
    let deadline = Instant::now() + Duration::from_secs(20);
    let second_status = loop {
        if let Ok(Some(status)) = second.0.try_wait() {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "second daemon on the same spool must refuse to boot, but it kept running"
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    assert!(
        !second_status.success(),
        "second daemon must exit non-zero on a held spool lock, got {second_status}"
    );
    // The winner must be unaffected.
    let (status, _) = http_get(first_port, "/health").expect("first daemon still serving");
    assert_eq!(status, 200, "the lock-holding daemon must keep serving");

    // SIGKILL the holder: the OS releases the advisory lock with no
    // cleanup, so a replacement instance must boot successfully.
    first.0.kill().unwrap();
    let _ = first.0.wait();
    let mut replacement = start_daemon(&second_config, &seed_path);
    wait_healthy(second_port, &mut replacement);
    drop(replacement);
}

/// The register's "minute one" path, end-to-end against the REAL
/// binary: a config carrying the exact posture `avctl init` now
/// generates (signed default workflow, `ignore_client_authorization`,
/// a binding `[budget]`) must accept a stock-OpenAI-SDK-shaped request
/// — which unconditionally sends a placeholder `Authorization: Bearer`
/// header and names no X-AV-Workflow — and mint a SIGNED receipt at
/// session close. No prior test combined these: the restart suite
/// forces unsigned and never sends Authorization, so the flagship
/// onboarding promise ("past minute one", "every session ends with a
/// signed receipt") had zero end-to-end coverage.
#[test]
fn init_shaped_config_serves_a_stock_sdk_request_and_signs_the_receipt() {
    let upstream_port = spawn_mock_upstream();
    let listen_port = free_port();
    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path();
    let spool = root.join("spool/atif");
    std::fs::create_dir_all(&spool).unwrap();
    std::fs::create_dir_all(root.join("tool-schemas")).unwrap();
    let config_path = root.join("agentvisor.toml");
    let seed_path = root.join("signing.seed");
    // Mirrors `render_config` in av-cli (whose template is pinned by
    // `every_preset_generates_a_valid_config`); this test pins the
    // POSTURE end-to-end rather than the literal template bytes.
    std::fs::write(
        &config_path,
        format!(
            r#"config_version = 1
listen = "127.0.0.1:{listen_port}"
upstream_url = "http://127.0.0.1:{upstream_port}"
require_identity = false
ignore_client_authorization = true
default_workflow = "signed"
compression_enabled = false
dashboard_enabled = false
atif_spool_dir = "{spool}"
bridge_data_dir = "{bridge}"
tool_schema_dir = "{schemas}"
state_backend = "memory"
embedder_backend = "hash"
vector_backend = "memory"

[budget]
max_tokens = 200000
max_payout_usd_micros = 50000000
max_total_tool_calls = 100
"#,
            spool = spool.display(),
            bridge = root.join("data/bridge").display(),
            schemas = root.join("tool-schemas").display(),
        ),
    )
    .unwrap();

    let mut daemon = start_daemon(&config_path, &seed_path);
    wait_healthy(listen_port, &mut daemon);

    // Stock SDK shape: placeholder bearer, no X-AV-Workflow header.
    let body = r#"{"model":"mock","messages":[{"role":"user","content":"ping"}]}"#;
    let mut stream = std::net::TcpStream::connect_timeout(
        &([127, 0, 0, 1], listen_port).into(),
        Duration::from_millis(500),
    )
    .expect("connect");
    stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    write!(
        stream,
        "POST /v1/chat/completions HTTP/1.1\r\nhost: localhost\r\ncontent-type: application/json\r\nauthorization: Bearer sk-placeholder-from-stock-sdk\r\nx-av-session: minute-one\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    let status: u16 = response
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    assert_eq!(
        status, 200,
        "a stock SDK request (placeholder bearer) must succeed on request one: {response}"
    );
    assert!(
        response.contains("hello from mock"),
        "relay must pass the upstream body: {response}"
    );

    // Close the session: the signed workflow must mint a receipt.
    let mut stream = std::net::TcpStream::connect_timeout(
        &([127, 0, 0, 1], listen_port).into(),
        Duration::from_millis(500),
    )
    .expect("connect for close");
    stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    write!(
        stream,
        "POST /v1/sessions/minute-one/close HTTP/1.1\r\nhost: localhost\r\nauthorization: Bearer sk-placeholder-from-stock-sdk\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
    )
    .unwrap();
    let mut close_response = String::new();
    stream.read_to_string(&mut close_response).unwrap();
    let close_status: u16 = close_response
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    assert_eq!(close_status, 200, "close must succeed: {close_response}");
    assert!(
        close_response.contains("signature_b64") && close_response.contains("receipt_id"),
        "the shipped posture must mint a SIGNED receipt at close (the product's headline claim): {close_response}"
    );
    drop(daemon);
}

/// The receipt-signing trust anchor must reach the logs UNCONDITIONALLY
/// (Action Register item 5: "log signing_key_id at startup
/// unconditionally"). The startup banner is info-level, so a
/// `RUST_LOG=error` deployment — and even our own test/compose guidance
/// of `RUST_LOG=warn` — filtered the only steady-state record of which
/// key the process signs under, and at `error` even the
/// freshly-generated-seed WARN vanished: a silent new signing anchor,
/// the exact failure the register item exists to prevent. The
/// `trust_anchor` tracing target is pinned to info inside init_tracing
/// regardless of RUST_LOG; this test boots the real binary twice at
/// `RUST_LOG=error` (fresh anchor, then steady-state reuse) and asserts
/// the anchor line appears both times.
#[test]
fn trust_anchor_is_logged_even_when_rust_log_silences_info() {
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

    let boot = |log_path: &std::path::Path| -> String {
        let stdout = std::fs::File::create(log_path).unwrap();
        let child = std::process::Command::new(env!("CARGO_BIN_EXE_agentvisord"))
            .arg("--config")
            .arg(&config_path)
            .current_dir(root)
            .env("AV_SIGNING_SEED_FILE", &seed_path)
            // The regression under test: error-level filtering used to
            // drop the trust anchor entirely.
            .env("RUST_LOG", "error")
            .stdout(std::process::Stdio::from(stdout))
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn agentvisord");
        let mut daemon = Daemon(child);
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let contents = std::fs::read_to_string(log_path).unwrap_or_default();
            if contents.contains("\"target\":\"trust_anchor\"") {
                drop(daemon);
                return contents;
            }
            if let Ok(Some(status)) = daemon.0.try_wait() {
                panic!("daemon exited ({status}) before logging the trust anchor: {contents}");
            }
            assert!(
                Instant::now() < deadline,
                "no trust_anchor line within 30s at RUST_LOG=error: {contents}"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    };

    // Boot 1: fresh anchor (seed file does not exist yet).
    let first = boot(&root.join("boot1.log"));
    let anchor_line = first
        .lines()
        .find(|line| line.contains("\"target\":\"trust_anchor\""))
        .unwrap();
    assert!(
        anchor_line.contains("signer_key_id") && anchor_line.contains("signer_public_key_hex"),
        "anchor line must carry the key identity: {anchor_line}"
    );
    assert!(
        anchor_line.contains("\"freshly_generated\":true"),
        "first boot generates the seed: {anchor_line}"
    );

    // Boot 2: steady-state reuse — the case the info-level banner
    // silently dropped before the fix.
    let second = boot(&root.join("boot2.log"));
    let anchor_line = second
        .lines()
        .find(|line| line.contains("\"target\":\"trust_anchor\""))
        .unwrap();
    assert!(
        anchor_line.contains("signer_key_id") && anchor_line.contains("\"freshly_generated\":false"),
        "steady-state boot must still log the anchor at RUST_LOG=error: {anchor_line}"
    );
}

/// Every metric the OPERATIONS.md alert table tells operators to wire
/// alerts onto must exist on `/metrics` from boot (Action Register
/// item 20: pre-register data-plane series). `Registry::counter` is
/// lazy — a series created on first increment leaves its alert blind
/// until the bad thing has already happened once, and `absent()`
/// alerts false-fire on healthy nodes. This boots the REAL binary and
/// scrapes a fresh `/metrics`: it caught av_incomplete_sessions_total
/// (documented "Escalate" alert, created only in the capture-failure
/// branch) and av_events_dropped_total{stage="response_slot"} (the
/// alert names response_slot; only worker_queue was pre-registered).
#[test]
fn every_documented_alert_series_exists_on_a_fresh_boot() {
    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path();
    let listen_port = free_port();
    let config_path = root.join("agentvisor.toml");
    let seed_path = root.join("signing.seed");
    std::fs::write(
        &config_path,
        format!(
            r#"config_version = 1
listen = "127.0.0.1:{listen_port}"
upstream_url = "http://127.0.0.1:9"
require_identity = false
default_workflow = "signed"
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

    let mut daemon = start_daemon(&config_path, &seed_path);
    wait_healthy(listen_port, &mut daemon);
    let (status, body) = http_get(listen_port, "/metrics").expect("scrape /metrics");
    assert_eq!(status, 200, "metrics endpoint must serve on a fresh boot");

    // The exact series named by docs/reference/OPERATIONS.md (alert
    // table + probe/drain sections). Adding a row there without
    // pre-registering the series breaks this test — by design.
    for series in [
        "av_atif_recovery_skipped_total{reason=\"unauthenticated\"}",
        "av_atif_recovery_skipped_total{reason=\"too_large\"}",
        "av_incomplete_sessions_total",
        "av_events_dropped_total{stage=\"response_slot\"}",
        "av_events_dropped_total{stage=\"worker_queue\"}",
        "av_http_shutdown_drain_timeouts_total",
        "av_reconciler_last_tick_completed_seconds",
        // Stream-drop failure counters (pass 19 + pass 20). Each one
        // is written only inside an error arm on the AbortFinalizingStream
        // drop path; without pre-registration they never appear on
        // `/metrics` until the first failure, so `rate() > 0` alerts
        // silently miss the first incident. Documented in OPERATIONS.md.
        "av_ephemeral_close_failures_total",
        "av_stream_abort_close_failures_total",
        "av_stream_abort_no_runtime_total",
        // Panic-supervision counters. Each is written only from the
        // panic arm of a background task or Drop-spawned task; without
        // pre-registration `rate() > 0` alerts silently miss the FIRST
        // panic — exactly the incident the alert exists to catch.
        // Documented in OPERATIONS.md.
        "av_reconciler_panics_total",
        "av_worker_shard_panics_total",
        "av_bridge_maintenance_panics_total",
        "av_bridge_maintenance_errors_total",
        "av_bridge_maintenance_join_errors_total",
        "av_atif_retention_panics_total",
        "av_atif_retention_errors_total",
        "av_stream_abort_panics_total",
        "av_ephemeral_close_panics_total",
        "av_admission_refund_panics_total",
        "av_idle_close_timeouts_total",
        "av_shutdown_session_close_timeouts_total",
        // Per-tick recovery-scan cap: one labelled series per pass.
        // Absent series → `rate() > 0` alerts miss the FIRST fire.
        "av_recovery_scan_capped_total{pass=\"adopt_strict_atif\"}",
        "av_recovery_scan_capped_total{pass=\"recover_signed_journals\"}",
        "av_recovery_scan_capped_total{pass=\"consolidate_step_journals\"}",
        "av_recovery_scan_capped_total{pass=\"retry_marked_promotions\"}",
        "av_recovery_scan_capped_total{pass=\"remove_acked_outboxes\"}",
        "av_recovery_scan_capped_total{pass=\"replay_lifecycle_outboxes\"}",
        "av_recovery_scan_capped_total{pass=\"quarantine_orphan_json\"}",
        // Lifecycle-outbox backlog gauge. On a fresh boot no bridge
        // activity has happened, so the gauge is 0 — but it must
        // be pre-registered so `absent()` alerts distinguish
        // "healthy, no backlog" from "reconciler tick hasn't run yet".
        "av_lifecycle_outbox_pending",
    ] {
        assert!(
            body.contains(series),
            "documented alert series {series} is missing from a fresh boot's /metrics"
        );
    }
    drop(daemon);
}

/// The readiness-controlled pre-drain window (register item 11): on
/// SIGTERM with `shutdown_ready_drain_s` set, `/readyz` must serve a
/// real HTTP 503 (draining) while the listener KEEPS ACCEPTING and
/// `/livez` stays 200, and the process must exit cleanly after the
/// window. Without the window, axum stops accepting the instant the
/// signal lands and a fresh probe sees connection-refused, never the
/// 503. This applies to every deployment: the shipped k8s manifest
/// runs on a distroless base with no shell so a `preStop` sleep
/// hook cannot execute, and docker-compose / systemd / bare-LB
/// deployments have no preStop equivalent at all. Reproduced live
/// before the fix: 0.5 s after SIGTERM both probes got
/// connection-refused.
#[cfg(unix)]
#[test]
fn sigterm_serves_readyz_503_during_the_pre_drain_window() {
    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path();
    let listen_port = free_port();
    let config_path = root.join("agentvisor.toml");
    let seed_path = root.join("signing.seed");
    std::fs::write(
        &config_path,
        format!(
            r#"config_version = 1
listen = "127.0.0.1:{listen_port}"
upstream_url = "http://127.0.0.1:9"
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
shutdown_ready_drain_s = 2
"#,
            spool = root.join("spool/atif").display(),
            bridge = root.join("data/bridge").display(),
            schemas = root.join("tool-schemas").display(),
        ),
    )
    .unwrap();
    std::fs::create_dir_all(root.join("tool-schemas")).unwrap();

    let mut daemon = start_daemon(&config_path, &seed_path);
    wait_healthy(listen_port, &mut daemon);

    // SIGTERM (graceful), NOT SIGKILL — /bin/kill avoids a libc dep.
    let killed = std::process::Command::new("kill")
        .args(["-TERM", &daemon.0.id().to_string()])
        .status()
        .expect("send SIGTERM");
    assert!(killed.success(), "kill -TERM must succeed");

    // Inside the 2 s window: readyz = REAL 503 (connection accepted),
    // livez still 200 (no restart cascade).
    let deadline = Instant::now() + Duration::from_millis(1500);
    let mut saw_503 = false;
    while Instant::now() < deadline {
        if let Some((status, body)) = http_get(listen_port, "/readyz") {
            if status == 503 {
                assert!(
                    body.contains("\"draining\":true"),
                    "the 503 must name draining as the cause: {body}"
                );
                saw_503 = true;
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        saw_503,
        "readyz must serve HTTP 503 during the pre-drain window (connection-refused means \
         the listener closed before the LB could observe the drain)"
    );
    let (livez_status, _) = http_get(listen_port, "/livez").expect("livez during drain");
    assert_eq!(livez_status, 200, "livez must stay 200 while draining");

    // After the window the process must exit cleanly on its own.
    let exit_deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Ok(Some(status)) = daemon.0.try_wait() {
            break status;
        }
        assert!(
            Instant::now() < exit_deadline,
            "daemon must exit after the pre-drain window + graceful drain"
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    assert!(
        status.success(),
        "graceful SIGTERM shutdown must exit 0, got {status}"
    );
}
