//! The actual avctl process sends authenticated operator requests without
//! following redirects or exposing credentials in diagnostics.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::process::{Command, Output};
use std::sync::mpsc::{self, Receiver};

const BIN: &str = env!("CARGO_BIN_EXE_avctl");
const TOKEN: &str = "separate-operator-token-with-at-least-32-characters";

fn mock(status: &str, headers: &str, body: &str) -> (String, Receiver<String>, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let response = format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n{headers}\r\n{body}", body.len());
    let (tx, rx) = mpsc::channel();
    let join = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut bytes = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let n = socket.read(&mut chunk).unwrap();
            if n == 0 {
                break;
            }
            bytes.extend_from_slice(chunk.get(..n).unwrap());
            assert!(bytes.len() <= 32768);
            let request = String::from_utf8_lossy(&bytes);
            if let Some((header, payload)) = request.split_once("\r\n\r\n") {
                let length = header
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                if payload.len() >= length {
                    break;
                }
            }
        }
        tx.send(String::from_utf8(bytes).unwrap()).unwrap();
        socket.write_all(response.as_bytes()).unwrap();
    });
    (url, rx, join)
}

fn run(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .env("AV_OPERATOR_TOKEN", TOKEN)
        .env_remove("AV_OPERATOR_TOKEN_FILE")
        .output()
        .unwrap()
}

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn token_command_sends_distinct_operator_auth_and_namespace() {
    let (url, request, server) = mock("200 OK", "", r#"{"revoked":true,"audited":true}"#);
    let output = run(&[
        "token-revoke",
        "--jti",
        "token-123",
        "--token-kind",
        "exchanged",
        "--url",
        &url,
    ]);
    assert!(output.status.success(), "{}", text(&output));
    let request = request.recv().unwrap();
    assert!(request.starts_with("POST /admin/v1/revocations HTTP/1.1\r\n"));
    assert!(request
        .to_ascii_lowercase()
        .contains(&format!("authorization: bearer {TOKEN}")));
    let body: serde_json::Value = serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1).unwrap();
    assert_eq!(
        body,
        serde_json::json!({"jti":"token-123","token_kind":"exchanged"})
    );
    assert!(!text(&output).contains(TOKEN));
    server.join().unwrap();
}

#[test]
fn instance_command_reports_the_cutoff_and_audit_failure() {
    let (url, request, server) = mock(
        "200 OK",
        "",
        r#"{"revoked":true,"audited":false,"issued_at_or_before":1790000030}"#,
    );
    let output = run(&["instance-revoke", "--instance-uid", "agent-7", "--url", &url]);
    assert!(output.status.success(), "{}", text(&output));
    let body: serde_json::Value =
        serde_json::from_str(request.recv().unwrap().split_once("\r\n\r\n").unwrap().1).unwrap();
    assert_eq!(body, serde_json::json!({"instance_uid":"agent-7"}));
    assert!(text(&output).contains("1790000030"));
    assert!(String::from_utf8_lossy(&output.stderr).contains("signed audit receipt could not be confirmed"));
    assert!(!text(&output).contains(TOKEN));
    server.join().unwrap();
}

#[test]
fn redirects_are_refused_and_error_bodies_cannot_leak_credentials() {
    let destination = TcpListener::bind("127.0.0.1:0").unwrap();
    destination.set_nonblocking(true).unwrap();
    let location = format!("Location: http://{}/steal\r\n", destination.local_addr().unwrap());
    let (url, request, server) = mock("307 Temporary Redirect", &location, TOKEN);
    let output = run(&["token-revoke", "--jti", "token-123", "--url", &url]);
    assert!(!output.status.success());
    assert!(text(&output).contains("HTTP 307"));
    assert!(!text(&output).contains(TOKEN));
    request.recv().unwrap();
    server.join().unwrap();
    assert!(matches!(destination.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock));
}

#[test]
fn every_replica_is_attempted_and_any_failure_sets_the_exit_code() {
    let (first, first_request, first_server) = mock("503 Service Unavailable", "", TOKEN);
    let (second, second_request, second_server) = mock("200 OK", "", r#"{"revoked":true,"audited":true}"#);
    let output = run(&[
        "token-revoke",
        "--jti",
        "token-123",
        "--url",
        &first,
        "--url",
        &second,
    ]);
    assert!(!output.status.success());
    assert!(text(&output).contains("HTTP 503"));
    assert!(text(&output).contains("Revocation was recorded"));
    assert!(!text(&output).contains(TOKEN));
    first_request.recv().unwrap();
    second_request.recv().unwrap();
    first_server.join().unwrap();
    second_server.join().unwrap();
}

#[test]
fn owner_only_file_takes_precedence_over_environment_token() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operator-token");
    av_core::fsutil::write_atomic(&path, TOKEN.as_bytes()).unwrap();
    let (url, request, server) = mock("200 OK", "", r#"{"revoked":true,"audited":true}"#);
    let output = Command::new(BIN)
        .args([
            "token-revoke",
            "--jti",
            "one",
            "--url",
            &url,
            "--operator-token-file",
            path.to_str().unwrap(),
        ])
        .env(
            "AV_OPERATOR_TOKEN",
            "bad-environment-secret-that-should-not-be-used",
        )
        .env_remove("AV_OPERATOR_TOKEN_FILE")
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", text(&output));
    assert!(request.recv().unwrap().contains(TOKEN));
    assert!(!text(&output).contains(TOKEN));
    server.join().unwrap();
}
