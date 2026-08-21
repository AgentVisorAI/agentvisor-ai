//! Dynamic end-to-end verification of the `avctl` operator UI.
//!
//! "Extensive & dynamic" means beyond single-command exit codes:
//!   1. Property-based:      100 keygens produce 100 distinct valid keys.
//!   2. Concurrent race:     N processes racing on the same output path
//!                           produce exactly one winner.
//!   3. Multi-step workflow: keygen → sign a receipt with the on-disk seed →
//!                           receipt-verify → tamper 1 byte → verify fails.
//!   4. Live event flow:     bridge-provision, inject real events, then
//!                           `event-tail` returns them in offset order.
//!   5. Fuzz robustness:     random garbage TOMLs never crash `config-validate`.
//!   6. Live HTTP:           `session-promote` reflects a mock server's
//!                           200/401/500 status codes correctly.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::too_many_lines,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::doc_overindented_list_items
)]

use av_bridge::{BridgeManifest, EmbeddedBroker, EventBus};
use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

const BIN: &str = env!("CARGO_BIN_EXE_avctl");

fn run(args: &[&str]) -> Output {
    Command::new(BIN).args(args).output().expect("spawn avctl")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}
fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

// ------------------------------------------------------------------
// 1. Property-based: 100 keygens produce 100 distinct valid pubkeys.
// ------------------------------------------------------------------

#[test]
fn keygen_produces_many_unique_valid_keys() {
    const N: usize = 100;
    let dir = tempfile::tempdir().unwrap();
    let mut pubkeys = std::collections::HashSet::with_capacity(N);
    let mut key_ids = std::collections::HashSet::with_capacity(N);
    for i in 0..N {
        let seed = dir.path().join(format!("key-{i:03}.seed"));
        let out = run(&["keygen", "--output", seed.to_str().unwrap()]);
        assert!(out.status.success(), "keygen #{i} failed: {}", stderr(&out));
        let v: serde_json::Value = serde_json::from_str(stdout(&out).trim())
            .unwrap_or_else(|error| panic!("keygen #{i} stdout not JSON: {error}"));
        let pk = v["public_key_hex"].as_str().unwrap().to_owned();
        let kid = v["key_id"].as_str().unwrap().to_owned();
        assert_eq!(pk.len(), 64, "iter #{i}: pubkey wrong length");
        assert!(
            pk.chars().all(|c| c.is_ascii_hexdigit()),
            "iter #{i}: pubkey not hex"
        );
        assert!(pubkeys.insert(pk.clone()), "iter #{i}: duplicate pubkey {pk}");
        assert!(key_ids.insert(kid.clone()), "iter #{i}: duplicate key_id {kid}");
        let seed_bytes = std::fs::read_to_string(&seed).unwrap();
        let raw: Vec<u8> = hex::decode(seed_bytes.trim()).unwrap();
        assert_eq!(raw.len(), 32, "iter #{i}: seed must be 32 bytes");
    }
    assert_eq!(pubkeys.len(), N);
    assert_eq!(key_ids.len(), N);
}

// ------------------------------------------------------------------
// 2. Concurrent race: N processes racing on the same output path.
// ------------------------------------------------------------------

#[test]
fn concurrent_keygen_race_produces_exactly_one_winner() {
    const N: usize = 12;
    let dir = tempfile::tempdir().unwrap();
    let seed = dir.path().join("shared-key.seed");
    let seed_path = seed.to_str().unwrap().to_owned();

    // Barrier so all children hit `create_new` in a tight window.
    let barrier = Arc::new(std::sync::Barrier::new(N));
    let mut handles = Vec::with_capacity(N);
    for _ in 0..N {
        let barrier = Arc::clone(&barrier);
        let seed_path = seed_path.clone();
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            run(&["keygen", "--output", &seed_path])
        }));
    }
    let outputs: Vec<Output> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    let winners: Vec<_> = outputs.iter().filter(|o| o.status.success()).collect();
    let losers: Vec<_> = outputs.iter().filter(|o| !o.status.success()).collect();
    assert_eq!(
        winners.len(),
        1,
        "expected exactly one keygen winner, got {} winners and {} losers",
        winners.len(),
        losers.len()
    );
    for l in &losers {
        let err = stderr(l).to_lowercase();
        assert!(
            err.contains("refus") || err.contains("exist"),
            "loser did not explain refusal cleanly, stderr={}",
            stderr(l)
        );
    }
    // The persisted seed's pubkey must match the sole winner.
    let winner_json: serde_json::Value = serde_json::from_str(stdout(winners[0]).trim()).unwrap();
    let winner_pk = winner_json["public_key_hex"].as_str().unwrap().to_owned();
    let seed_bytes: [u8; 32] = hex::decode(std::fs::read_to_string(&seed).unwrap().trim())
        .unwrap()
        .try_into()
        .unwrap();
    let signer = av_receipts::Ed25519Signer::from_seed(&seed_bytes);
    assert_eq!(
        hex::encode(av_receipts::Signer::public_key_bytes(&signer)),
        winner_pk,
        "on-disk seed does not match the winner keygen printed"
    );
}

#[test]
fn concurrent_bridge_provision_race_produces_exactly_one_winner() {
    const N: usize = 8;
    let dir = tempfile::tempdir().unwrap();
    let manifest = dir.path().join("bridge.yaml");
    std::fs::write(
        &manifest,
        "manifest_version: 1\n\
         name: race\n\
         replication_factor: 1\n\
         topics:\n  \
           - {name: agent.tool_call, partitions: 1, retention: {hot_hours: 24}}\n",
    )
    .unwrap();
    let data_dir = dir.path().join("data");
    let manifest_str = manifest.to_str().unwrap().to_owned();
    let data_dir_str = data_dir.to_str().unwrap().to_owned();

    let barrier = Arc::new(std::sync::Barrier::new(N));
    let mut handles = Vec::with_capacity(N);
    for _ in 0..N {
        let barrier = Arc::clone(&barrier);
        let m = manifest_str.clone();
        let d = data_dir_str.clone();
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            run(&["bridge-provision", "--manifest", &m, "--data-dir", &d])
        }));
    }
    let outputs: Vec<Output> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let winners = outputs.iter().filter(|o| o.status.success()).count();
    assert_eq!(winners, 1, "expected exactly one provision winner, got {winners}");
    assert!(
        data_dir.join("manifest.yaml").exists(),
        "sole winner must have persisted the manifest"
    );
}

// ------------------------------------------------------------------
// 3. Multi-step signed-receipt workflow (keygen → sign → verify → tamper).
// ------------------------------------------------------------------

fn build_receipt_for(dir: &std::path::Path, seed_bytes: [u8; 32]) -> PathBuf {
    use av_events::{AgentIdentity, CharterFile};
    use av_receipts::{CostSummary, Ed25519Signer, Receipt, ReceiptBody, ReceiptSubject, ToolCallSummary};
    let signer = Ed25519Signer::from_seed(&seed_bytes);
    let body = ReceiptBody {
        receipt_version: 1,
        receipt_id: "dyn-workflow".to_owned(),
        session_id: "dyn".to_owned(),
        issued_at: 0,
        issued_at_iso: "1970-01-01T00:00:00.000Z".to_owned(),
        ai_agent: AgentIdentity {
            version: "1".to_owned(),
            charter: CharterFile::from("c"),
            instance_uid: "i".to_owned(),
            ttl_remaining_s: None,
        },
        subject: ReceiptSubject::EventChain {
            chain_head: "00".repeat(32),
            event_count: 1,
        },
        tool_calls: ToolCallSummary::default(),
        cost: CostSummary::default(),
        stop_reason_id: 1,
        stop_reason: "SessionClosed".to_owned(),
        key_id: String::new(),
        public_key_b64: String::new(),
    };
    let receipt = Receipt::issue(body, &signer).unwrap();
    let path = dir.join("receipt.json");
    std::fs::write(&path, serde_json::to_vec_pretty(&receipt).unwrap()).unwrap();
    path
}

#[test]
fn dynamic_workflow_keygen_sign_verify_tamper() {
    let dir = tempfile::tempdir().unwrap();
    let seed = dir.path().join("k.seed");
    let out = run(&["keygen", "--output", seed.to_str().unwrap()]);
    assert!(out.status.success());
    let key_info: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
    let pk_hex = key_info["public_key_hex"].as_str().unwrap().to_owned();
    let seed_bytes: [u8; 32] = hex::decode(std::fs::read_to_string(&seed).unwrap().trim())
        .unwrap()
        .try_into()
        .unwrap();
    let receipt_path = build_receipt_for(dir.path(), seed_bytes);
    // Step 1: honest verify.
    let out = run(&[
        "receipt-verify",
        receipt_path.to_str().unwrap(),
        "--public-key-hex",
        &pk_hex,
    ]);
    assert!(out.status.success(), "honest verify failed: {}", stderr(&out));

    // Step 2: flip one bit in the signature; verify must fail.
    let mut val: serde_json::Value = serde_json::from_slice(&std::fs::read(&receipt_path).unwrap()).unwrap();
    let sig = val["signature_b64"].as_str().unwrap().to_owned();
    // Change the last non-`=` character.
    let last = sig
        .chars()
        .rev()
        .position(|c| c != '=')
        .expect("sig should have non-padding chars");
    let idx = sig.len() - 1 - last;
    let mut sig_bytes: Vec<char> = sig.chars().collect();
    sig_bytes[idx] = if sig_bytes[idx] == 'A' { 'B' } else { 'A' };
    let tampered_sig: String = sig_bytes.into_iter().collect();
    val["signature_b64"] = serde_json::json!(tampered_sig);
    std::fs::write(&receipt_path, serde_json::to_vec_pretty(&val).unwrap()).unwrap();
    let out = run(&[
        "receipt-verify",
        receipt_path.to_str().unwrap(),
        "--public-key-hex",
        &pk_hex,
    ]);
    assert!(
        !out.status.success(),
        "verifier accepted a receipt with a tampered signature"
    );

    // Step 3: restore signature, tamper the body (session_id). Verify must fail.
    let receipt_path = build_receipt_for(dir.path(), seed_bytes);
    let mut val: serde_json::Value = serde_json::from_slice(&std::fs::read(&receipt_path).unwrap()).unwrap();
    val["session_id"] = serde_json::json!("attacker-session");
    std::fs::write(&receipt_path, serde_json::to_vec_pretty(&val).unwrap()).unwrap();
    let out = run(&[
        "receipt-verify",
        receipt_path.to_str().unwrap(),
        "--public-key-hex",
        &pk_hex,
    ]);
    assert!(
        !out.status.success(),
        "verifier accepted a receipt whose body was mutated"
    );
}

// ------------------------------------------------------------------
// 4. Live event flow: provision + inject + event-tail sees them.
// ------------------------------------------------------------------

#[test]
fn event_tail_after_injection_returns_events_in_offset_order() {
    let dir = tempfile::tempdir().unwrap();
    let manifest_path = dir.path().join("bridge.yaml");
    std::fs::write(
        &manifest_path,
        "manifest_version: 1\n\
         name: dyn\n\
         replication_factor: 1\n\
         topics:\n  \
           - {name: agent.tool_call, partitions: 1, retention: {hot_hours: 24}}\n",
    )
    .unwrap();
    let data_dir = dir.path().join("data");
    let provisioned = run(&[
        "bridge-provision",
        "--manifest",
        manifest_path.to_str().unwrap(),
        "--data-dir",
        data_dir.to_str().unwrap(),
    ]);
    assert!(provisioned.status.success());

    // Open the bridge with the av-bridge library and inject real events.
    let broker = EmbeddedBroker::open(&data_dir).unwrap();
    let inputs: Vec<serde_json::Value> = (0..7)
        .map(|n| {
            serde_json::json!({
                "metadata": {"uid": format!("uid-{n}")},
                "payload": {"n": n},
            })
        })
        .collect();
    for value in &inputs {
        broker.publish("agent.tool_call", "inst-1", value).unwrap();
    }
    drop(broker);

    let out = run(&[
        "event-tail",
        "--data-dir",
        data_dir.to_str().unwrap(),
        "--topic",
        "agent.tool_call",
        "--max",
        "10",
    ]);
    assert!(out.status.success(), "event-tail failed: {}", stderr(&out));
    let events: Vec<serde_json::Value> = stdout(&out)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect();
    assert_eq!(events.len(), inputs.len(), "expected {} events", inputs.len());
    // Offsets must be strictly increasing.
    let offsets: Vec<u64> = events.iter().map(|e| e["offset"].as_u64().unwrap()).collect();
    for w in offsets.windows(2) {
        assert!(w[0] < w[1], "offsets not strictly increasing: {offsets:?}");
    }
    // Payloads must match, in order.
    for (i, e) in events.iter().enumerate() {
        assert_eq!(e["value"]["payload"]["n"].as_u64(), Some(i as u64));
    }
}

// ------------------------------------------------------------------
// 5. Fuzz robustness: random garbage TOML never crashes config-validate.
// ------------------------------------------------------------------

#[test]
fn config_validate_never_crashes_on_random_garbage() {
    const CASES: usize = 60;
    // Deterministic-seed xorshift keeps the test reproducible.
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let dir = tempfile::tempdir().unwrap();
    let charset: Vec<char> = "abcdefghijklmnopqrstuvwxyz_= \"\n[]0123456789.,{}#\t"
        .chars()
        .collect();
    for i in 0..CASES {
        let n = (next() % 200) as usize + 1;
        let mut buf = String::with_capacity(n);
        for _ in 0..n {
            buf.push(charset[(next() as usize) % charset.len()]);
        }
        let path = dir.path().join(format!("garbage-{i}.toml"));
        std::fs::write(&path, buf.as_bytes()).unwrap();
        let out = run(&["config-validate", path.to_str().unwrap()]);
        assert!(
            out.status.code().is_some(),
            "case #{i} exit was a signal (crash): status={:?}",
            out.status
        );
        // No crash-leak in stderr.
        let se = stderr(&out).to_lowercase();
        assert!(
            !se.contains("panicked at") && !se.contains("backtrace"),
            "case #{i} leaked panic/backtrace: {se}"
        );
    }
}

// ------------------------------------------------------------------
// 6. Live HTTP: session-promote reflects a mock server's status codes.
// ------------------------------------------------------------------

/// Spawn a one-shot HTTP mock on 127.0.0.1:0 that answers with `status`,
/// `body`. Returns `(port, join_handle, hits)`. The listener stays alive
/// until it has served `expected_hits` connections, then exits.
fn spawn_http_mock(
    status_line: &'static str,
    body: &'static str,
    expected_hits: usize,
) -> (u16, std::thread::JoinHandle<()>, Arc<AtomicU64>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let hits = Arc::new(AtomicU64::new(0));
    let hits_thread = Arc::clone(&hits);
    let handle = std::thread::spawn(move || {
        let mut served = 0;
        for stream in listener.incoming() {
            let mut stream = match stream {
                Ok(s) => s,
                Err(_) => break,
            };
            // Drain the request (best-effort). Read up to a small chunk.
            let mut buf = [0u8; 4096];
            let _ = stream.set_read_timeout(Some(std::time::Duration::from_millis(500)));
            let _ = stream.read(&mut buf);
            let response = format!(
                "HTTP/1.1 {status_line}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
            drop(stream);
            hits_thread.fetch_add(1, Ordering::AcqRel);
            served += 1;
            if served >= expected_hits {
                break;
            }
        }
    });
    (port, handle, hits)
}

#[test]
fn session_promote_reflects_server_ok_status() {
    let (port, handle, hits) = spawn_http_mock("200 OK", "promoted!", 1);
    let url = format!("http://127.0.0.1:{port}");
    let out = run(&["session-promote", "--url", &url, "sess-1"]);
    handle.join().unwrap();
    assert!(out.status.success(), "expected 0 exit on 200: {}", stderr(&out));
    assert!(
        stdout(&out).contains("promoted"),
        "stdout must echo response body, got: {}",
        stdout(&out)
    );
    assert_eq!(hits.load(Ordering::Acquire), 1);
}

#[test]
fn session_promote_reflects_server_unauthorized() {
    let (port, handle, _hits) = spawn_http_mock("401 Unauthorized", "no token", 1);
    let url = format!("http://127.0.0.1:{port}");
    let out = run(&["session-promote", "--url", &url, "sess-1"]);
    handle.join().unwrap();
    assert!(!out.status.success(), "401 must fail exit");
    let se = stderr(&out);
    assert!(
        se.contains("401") || se.to_lowercase().contains("unauthorized"),
        "stderr must reflect the server error, got: {se}"
    );
}

#[test]
fn session_promote_reflects_server_internal_error() {
    let (port, handle, _hits) = spawn_http_mock("500 Internal Server Error", "oops", 1);
    let url = format!("http://127.0.0.1:{port}");
    let out = run(&["session-promote", "--url", &url, "sess-1"]);
    handle.join().unwrap();
    assert!(!out.status.success(), "500 must fail exit");
    let se = stderr(&out);
    assert!(
        se.contains("500") || se.to_lowercase().contains("internal"),
        "stderr must reflect the server error, got: {se}"
    );
}

#[test]
fn session_promote_against_dead_port_fails_cleanly() {
    // A port that is almost certainly not listening.
    let out = run(&["session-promote", "--url", "http://127.0.0.1:1", "sess-1"]);
    assert!(!out.status.success(), "dead port must not succeed");
    assert!(
        out.status.code().is_some(),
        "dead port must fail cleanly (not a signal), got {:?}",
        out.status
    );
    assert!(
        !stderr(&out).is_empty(),
        "dead port must produce diagnostic stderr"
    );
}

// ------------------------------------------------------------------
// 7. Cross-command bridge lifecycle: valid manifest → provision →
//    manifest-validate on the persisted YAML still passes.
// ------------------------------------------------------------------

#[test]
fn bridge_lifecycle_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = dir.path().join("bridge.yaml");
    std::fs::write(
        &manifest,
        "manifest_version: 1\n\
         name: lifecycle\n\
         replication_factor: 1\n\
         topics:\n  \
           - {name: agent.tool_call, partitions: 2, retention: {hot_hours: 24}}\n  \
           - {name: agent.session, partitions: 1, retention: {hot_hours: 24}}\n",
    )
    .unwrap();
    let data_dir = dir.path().join("data");
    // manifest-validate before provision.
    let out = run(&["manifest-validate", manifest.to_str().unwrap()]);
    assert!(out.status.success());
    // provision.
    let out = run(&[
        "bridge-provision",
        "--manifest",
        manifest.to_str().unwrap(),
        "--data-dir",
        data_dir.to_str().unwrap(),
    ]);
    assert!(out.status.success());
    // manifest-validate on the persisted copy inside data-dir.
    let persisted = data_dir.join("manifest.yaml");
    assert!(persisted.exists());
    let out = run(&["manifest-validate", persisted.to_str().unwrap()]);
    assert!(
        out.status.success(),
        "persisted manifest failed to re-validate: {}",
        stderr(&out)
    );
    // The persisted manifest must parse to the same shape.
    let persisted_manifest =
        BridgeManifest::from_yaml(&std::fs::read_to_string(&persisted).unwrap()).unwrap();
    assert_eq!(persisted_manifest.name, "lifecycle");
    assert_eq!(persisted_manifest.topics.len(), 2);
}
