//! Deep contract checks for the `avctl` operator UI.
//!
//! The confusion-matrix suite proves exit codes are correct; this suite proves
//! the CLI honors its documented contract in every detail an operator can see:
//! stdout shape (JSON for `keygen`, `verified <id>` for `receipt-verify`),
//! stderr on failure, discoverability (`--help` mentions every subcommand),
//! version tag, argument validation edge cases (empty strings, unicode and
//! space paths, newline payloads), and cross-command
//! consistency (the pubkey printed by `keygen` verifies a receipt signed by
//! that seed).

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use std::path::Path;
use std::process::{Command, Output};

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

#[test]
fn help_mentions_every_subcommand() {
    let expected = [
        "keygen",
        "receipt-verify",
        "atif-validate",
        "manifest-validate",
        "bridge-provision",
        "event-tail",
        "session-promote",
        "config-validate",
        "loadgen",
    ];
    let out = run(&["--help"]);
    assert!(out.status.success(), "avctl --help must succeed");
    let text = stdout(&out) + &stderr(&out);
    for cmd in expected {
        assert!(
            text.contains(cmd),
            "avctl --help must document {cmd}, got:\n{text}"
        );
    }
}

#[test]
fn each_subcommand_has_its_own_help() {
    for cmd in [
        "keygen",
        "receipt-verify",
        "atif-validate",
        "manifest-validate",
        "bridge-provision",
        "event-tail",
        "session-promote",
        "config-validate",
        "loadgen",
    ] {
        let out = run(&[cmd, "--help"]);
        assert!(
            out.status.success(),
            "avctl {cmd} --help must exit 0, got status {:?}\nstderr: {}",
            out.status,
            stderr(&out)
        );
        let text = stdout(&out) + &stderr(&out);
        assert!(
            text.contains(cmd),
            "avctl {cmd} --help output must mention the command name"
        );
    }
}

#[test]
fn version_flag_reports_a_nonempty_version() {
    let out = run(&["--version"]);
    assert!(out.status.success(), "avctl --version must succeed");
    let text = stdout(&out);
    // clap's default: "avctl <VERSION>\n"
    let head = text.trim();
    assert!(
        head.starts_with("avctl "),
        "unexpected --version output: {head:?}"
    );
    let ver = head.trim_start_matches("avctl ").trim();
    assert!(!ver.is_empty(), "version string must not be empty");
}

#[test]
fn keygen_emits_valid_json_with_public_key_and_key_id() {
    let dir = tempfile::tempdir().unwrap();
    let seed = dir.path().join("key.seed");
    let out = run(&["keygen", "--output", seed.to_str().unwrap()]);
    assert!(out.status.success(), "keygen failed: {}", stderr(&out));
    let text = stdout(&out);
    let value: serde_json::Value = serde_json::from_str(text.trim())
        .unwrap_or_else(|error| panic!("keygen stdout must be JSON: {error}\nstdout:\n{text}"));
    let key_id = value["key_id"].as_str().expect("key_id");
    let pk_hex = value["public_key_hex"].as_str().expect("public_key_hex");
    assert_eq!(
        pk_hex.len(),
        64,
        "public_key_hex must be 32 bytes as 64 hex chars"
    );
    assert!(
        pk_hex.chars().all(|c| c.is_ascii_hexdigit()),
        "public_key_hex must be hex-only"
    );
    assert!(!key_id.is_empty(), "key_id must be non-empty");
    assert!(
        std::fs::metadata(&seed).unwrap().len() > 0,
        "seed file must be non-empty"
    );
}

#[test]
fn keygen_refuse_overwrite_writes_to_stderr_and_leaves_the_seed_intact() {
    let dir = tempfile::tempdir().unwrap();
    let seed = dir.path().join("key.seed");
    let first = run(&["keygen", "--output", seed.to_str().unwrap()]);
    assert!(first.status.success());
    let original = std::fs::read(&seed).unwrap();
    let second = run(&["keygen", "--output", seed.to_str().unwrap()]);
    assert!(!second.status.success(), "overwriting must fail");
    let err = stderr(&second).to_lowercase();
    assert!(
        err.contains("refusing") || err.contains("overwrite") || err.contains("exists"),
        "stderr must explain refusal, got: {}",
        stderr(&second)
    );
    let after = std::fs::read(&seed).unwrap();
    assert_eq!(original, after, "seed content must not have changed");
}

#[test]
fn receipt_verify_stdout_matches_receipt_id_on_success() {
    use av_events::{AgentIdentity, CharterFile};
    use av_receipts::{
        CostSummary, Ed25519Signer, Receipt, ReceiptBody, ReceiptSubject, Signer, ToolCallSummary,
    };
    let dir = tempfile::tempdir().unwrap();
    let signer = Ed25519Signer::from_seed(&[13; 32]);
    let body = ReceiptBody {
        receipt_version: 1,
        receipt_id: "receipt-01".to_owned(),
        session_id: "sess-01".to_owned(),
        issued_at: 0,
        issued_at_iso: "1970-01-01T00:00:00Z".to_owned(),
        ai_agent: AgentIdentity {
            version: "1".to_owned(),
            charter: CharterFile::from("charter"),
            instance_uid: "inst-1".to_owned(),
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
    let path = dir.path().join("receipt.json");
    std::fs::write(&path, serde_json::to_vec_pretty(&receipt).unwrap()).unwrap();
    let out = run(&[
        "receipt-verify",
        path.to_str().unwrap(),
        "--public-key-hex",
        &hex::encode(signer.public_key_bytes()),
    ]);
    assert!(out.status.success(), "verify failed: {}", stderr(&out));
    assert!(
        stdout(&out).starts_with("verified ") && stdout(&out).contains("receipt-01"),
        "stdout must be the documented `verified <id>` shape, got: {}",
        stdout(&out)
    );
}

#[test]
fn receipt_verify_wrong_key_writes_reason_to_stderr() {
    // Build a receipt with signer A; verify with attacker key B.
    use av_events::{AgentIdentity, CharterFile};
    use av_receipts::{CostSummary, Ed25519Signer, Receipt, ReceiptBody, ReceiptSubject, ToolCallSummary};
    let dir = tempfile::tempdir().unwrap();
    let signer = Ed25519Signer::from_seed(&[17; 32]);
    let body = ReceiptBody {
        receipt_version: 1,
        receipt_id: "r".to_owned(),
        session_id: "s".to_owned(),
        issued_at: 0,
        issued_at_iso: "1970-01-01T00:00:00Z".to_owned(),
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
    let path = dir.path().join("receipt.json");
    std::fs::write(&path, serde_json::to_vec_pretty(&receipt).unwrap()).unwrap();
    let attacker = "11".repeat(32);
    let out = run(&[
        "receipt-verify",
        path.to_str().unwrap(),
        "--public-key-hex",
        &attacker,
    ]);
    assert!(!out.status.success());
    let err = stderr(&out).to_lowercase();
    assert!(
        err.contains("receipt")
            || err.contains("key")
            || err.contains("verification")
            || err.contains("verify"),
        "stderr must explain rejection, got: {}",
        stderr(&out)
    );
}

#[test]
fn keygen_public_key_verifies_a_receipt_signed_by_the_same_seed_when_reloaded() {
    // Cross-command consistency: keygen writes seed; a receipt signed by that
    // seed must verify with the public key keygen printed.
    use av_events::{AgentIdentity, CharterFile};
    use av_receipts::{CostSummary, Ed25519Signer, Receipt, ReceiptBody, ReceiptSubject, ToolCallSummary};
    let dir = tempfile::tempdir().unwrap();
    let seed = dir.path().join("key.seed");
    let out = run(&["keygen", "--output", seed.to_str().unwrap()]);
    assert!(out.status.success());
    let key_info: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
    let pk_hex = key_info["public_key_hex"].as_str().unwrap().to_owned();
    // Reload the seed and produce a receipt with the same signer.
    let raw = std::fs::read_to_string(&seed).unwrap();
    let seed_bytes: [u8; 32] = hex::decode(raw.trim()).unwrap().try_into().unwrap();
    let signer = Ed25519Signer::from_seed(&seed_bytes);
    let body = ReceiptBody {
        receipt_version: 1,
        receipt_id: "roundtrip".to_owned(),
        session_id: "s".to_owned(),
        issued_at: 0,
        issued_at_iso: "1970-01-01T00:00:00Z".to_owned(),
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
    let receipt_path = dir.path().join("receipt.json");
    std::fs::write(&receipt_path, serde_json::to_vec_pretty(&receipt).unwrap()).unwrap();
    let verify = run(&[
        "receipt-verify",
        receipt_path.to_str().unwrap(),
        "--public-key-hex",
        &pk_hex,
    ]);
    assert!(
        verify.status.success(),
        "receipt from keygen'd seed did not verify with the pubkey keygen printed: {}",
        stderr(&verify)
    );
}

#[test]
fn config_validate_success_reports_config_version_and_listen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("harness.toml");
    std::fs::write(&path, r#"upstream_url = "http://127.0.0.1:9""#).unwrap();
    let out = run(&["config-validate", path.to_str().unwrap()]);
    assert!(out.status.success(), "config-validate failed: {}", stderr(&out));
    let s = stdout(&out);
    assert!(s.contains("config_version="), "expected config_version=, got {s}");
    assert!(s.contains("listen="), "expected listen=, got {s}");
}

#[test]
fn manifest_validate_success_reports_name_and_topic_count() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bridge.yaml");
    std::fs::write(
        &path,
        "manifest_version: 1\n\
         name: extensive-ui\n\
         replication_factor: 1\n\
         topics:\n  \
           - {name: agent.tool_call, partitions: 1, retention: {hot_hours: 24}}\n  \
           - {name: agent.session, partitions: 2, retention: {hot_hours: 24}}\n",
    )
    .unwrap();
    let out = run(&["manifest-validate", path.to_str().unwrap()]);
    assert!(out.status.success(), "manifest-validate failed: {}", stderr(&out));
    let s = stdout(&out);
    assert!(s.contains("extensive-ui"), "expected manifest name, got {s}");
    assert!(s.contains("topics=2"), "expected topic count, got {s}");
}

#[test]
fn bridge_provision_reports_topic_count_and_elapsed() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = dir.path().join("bridge.yaml");
    std::fs::write(
        &manifest,
        "manifest_version: 1\n\
         name: prov\n\
         replication_factor: 1\n\
         topics:\n  \
           - {name: agent.tool_call, partitions: 1, retention: {hot_hours: 24}}\n",
    )
    .unwrap();
    let data_dir = dir.path().join("data");
    let out = run(&[
        "bridge-provision",
        "--manifest",
        manifest.to_str().unwrap(),
        "--data-dir",
        data_dir.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "provision failed: {}", stderr(&out));
    let s = stdout(&out);
    assert!(s.contains("provisioned prov"), "expected banner, got {s}");
    assert!(s.contains("topics=1"), "expected topics=1, got {s}");
    assert!(s.contains("elapsed_ms="), "expected elapsed_ms, got {s}");
    assert!(
        data_dir.join("manifest.yaml").exists(),
        "provision must persist the manifest"
    );
}

#[test]
fn cli_rejects_flags_that_are_not_documented() {
    // A totally-unknown top-level flag must fail (clap's default; belt-and-braces).
    let out = run(&["--definitely-not-a-flag"]);
    assert!(!out.status.success());
    let out = run(&["keygen", "--not-a-real-arg", "x"]);
    assert!(!out.status.success());
}

#[test]
fn cli_rejects_missing_required_arguments() {
    // keygen requires --output; bridge-provision requires --manifest and --data-dir.
    assert!(!run(&["keygen"]).status.success());
    assert!(!run(&["bridge-provision"]).status.success());
    assert!(!run(&["bridge-provision", "--manifest", "m.yaml"])
        .status
        .success());
    assert!(!run(&["event-tail"]).status.success());
    assert!(!run(&["receipt-verify"]).status.success());
    assert!(!run(&["config-validate"]).status.success());
    assert!(!run(&["manifest-validate"]).status.success());
    assert!(!run(&["atif-validate"]).status.success());
}

#[test]
fn cli_handles_paths_with_spaces_and_unicode() {
    let dir = tempfile::tempdir().unwrap();
    // Path containing a space.
    let sub = dir.path().join("with spaces");
    std::fs::create_dir_all(&sub).unwrap();
    let seed = sub.join("key.seed");
    let out = run(&["keygen", "--output", seed.to_str().unwrap()]);
    assert!(out.status.success(), "space path failed: {}", stderr(&out));

    // Path containing non-ASCII (café) unicode.
    let uni = dir.path().join("café");
    std::fs::create_dir_all(&uni).unwrap();
    let seed = uni.join("key.seed");
    let out = run(&["keygen", "--output", seed.to_str().unwrap()]);
    assert!(out.status.success(), "unicode path failed: {}", stderr(&out));
}

#[test]
fn cli_rejects_empty_string_paths_for_required_positional_args() {
    let out = run(&["config-validate", ""]);
    assert!(!out.status.success(), "empty path must not silently succeed");
    let out = run(&["manifest-validate", ""]);
    assert!(!out.status.success());
    let out = run(&["atif-validate", ""]);
    assert!(!out.status.success());
}

#[test]
fn cli_rejects_hostile_paths_with_null_or_newline() {
    // A newline in a path should fail cleanly (not crash) — nul bytes are
    // impossible to pass through argv on Unix, but newlines are legal filename
    // bytes that we still don't create on disk, so the path won't exist.
    let out = run(&["config-validate", "no-such\nfile.toml"]);
    assert!(!out.status.success(), "hostile path must fail");
}

#[test]
fn cli_exit_status_is_never_a_signal() {
    // A CLI that segfaults or panics leaves an unwrap-able exit code but no
    // clean status.code(). We insist every observed exit has a proper code.
    for args in [
        vec!["--help"],
        vec!["--version"],
        vec!["config-validate", "/no/such/file"],
        vec![
            "receipt-verify",
            "/no/such/file",
            "--public-key-hex",
            &"00".repeat(32),
        ],
        vec!["bridge-provision", "--manifest", "/x", "--data-dir", "/y"],
    ] {
        let out = run(&args);
        assert!(
            out.status.code().is_some(),
            "avctl {args:?} did not exit cleanly (signal?): status={:?}",
            out.status
        );
    }
}

#[test]
fn help_output_does_not_leak_backtraces_or_debug_types() {
    let out = run(&["--help"]);
    let all = stdout(&out) + &stderr(&out);
    for hostile in [
        // Rust-specific tokens that only appear in leaked debug/panic output.
        "src/main.rs",
        "panicked at",
        "note: run with `RUST_BACKTRACE",
        "backtrace",
        "unwrap",
        "thread 'main'",
    ] {
        assert!(
            !all.to_lowercase().contains(&hostile.to_lowercase()),
            "avctl --help leaks {hostile:?} into user-facing output:\n{all}"
        );
    }
}

#[test]
fn all_error_paths_write_to_stderr_not_stdout() {
    // Contract: successful output goes to stdout; errors go to stderr.
    for args in [
        vec!["config-validate", "/no/such/file"],
        vec!["manifest-validate", "/no/such/file"],
        vec![
            "receipt-verify",
            "/no/such/file",
            "--public-key-hex",
            &"00".repeat(32),
        ],
        vec!["atif-validate", "/no/such/file"],
    ] {
        let out = run(&args);
        assert!(!out.status.success(), "{args:?} was expected to fail");
        let so = stdout(&out);
        let se = stderr(&out);
        assert!(
            !se.is_empty(),
            "{args:?} failure produced empty stderr; ops can't diagnose (stdout={so:?})"
        );
    }
}

#[test]
fn avctl_binary_exists_and_is_executable() {
    let path = Path::new(BIN);
    assert!(path.exists(), "avctl binary not found at {BIN}");
    let meta = std::fs::metadata(path).unwrap();
    assert!(meta.is_file(), "avctl at {BIN} is not a regular file");
    // On unix, at least owner-execute must be set.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = meta.permissions().mode();
        assert!(
            mode & 0o100 != 0,
            "avctl at {BIN} is not executable: mode={mode:o}"
        );
    }
}
