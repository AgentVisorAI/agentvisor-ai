//! End-to-end confusion-matrix scenarios for the `avctl` CLI (the operator UI).
//!
//! For each scenario we declare:
//!   - `Expected`: whether a well-behaved CLI must **succeed** or **fail**
//!   - a driver closure that runs the compiled binary as a subprocess
//!
//! Classification:
//!   TP: expected=Fail,    observed=Failed     (CLI correctly rejected bad input)
//!   TN: expected=Succeed, observed=Succeeded  (CLI correctly processed good input)
//!   FP: expected=Succeed, observed=Failed     (CLI incorrectly rejected valid input)
//!   FN: expected=Fail,    observed=Succeeded  (CLI incorrectly accepted bad input — security-critical)
//!
//! At the end the runner asserts **zero FPs and zero FNs**.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::too_many_lines
)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_avctl");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expected {
    Succeed,
    Fail,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Observed {
    Succeeded,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    TP,
    TN,
    FP,
    FN,
}

fn classify(expected: Expected, observed: Observed) -> Class {
    match (expected, observed) {
        (Expected::Fail, Observed::Failed) => Class::TP,
        (Expected::Succeed, Observed::Succeeded) => Class::TN,
        (Expected::Succeed, Observed::Failed) => Class::FP,
        (Expected::Fail, Observed::Succeeded) => Class::FN,
    }
}

fn run(args: &[&str]) -> Output {
    Command::new(BIN).args(args).output().expect("spawn avctl")
}

fn observed(out: &Output) -> Observed {
    if out.status.success() {
        Observed::Succeeded
    } else {
        Observed::Failed
    }
}

/// Write a file under a tempdir and return its path.
fn write_temp(dir: &Path, name: &str, contents: &[u8]) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, contents).unwrap();
    path
}

fn minimal_valid_manifest_yaml() -> &'static str {
    "manifest_version: 1\n\
     name: cli-e2e\n\
     replication_factor: 1\n\
     topics:\n  \
       - name: agent.tool_call\n    \
         partitions: 1\n    \
         retention: { hot_hours: 24 }\n"
}

fn minimal_valid_harness_toml() -> &'static str {
    r#"upstream_url = "http://127.0.0.1:9""#
}

/// Build a signed receipt on disk and return (receipt_path, public_key_hex).
fn sign_receipt(dir: &Path) -> (PathBuf, String) {
    use av_events::{AgentIdentity, CharterFile};
    use av_receipts::{
        CostSummary, Ed25519Signer, Receipt, ReceiptBody, ReceiptSubject, Signer, ToolCallSummary,
    };
    let signer = Ed25519Signer::from_seed(&[9; 32]);
    let body = ReceiptBody {
        receipt_version: 1,
        receipt_id: av_core::new_event_uid(),
        session_id: "cli-e2e-tn".to_owned(),
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
        // Overwritten by Receipt::issue.
        key_id: String::new(),
        public_key_b64: String::new(),
    };
    let receipt = Receipt::issue(body, &signer).unwrap();
    let path = dir.join("receipt.json");
    std::fs::write(&path, serde_json::to_vec_pretty(&receipt).unwrap()).unwrap();
    (path, hex::encode(signer.public_key_bytes()))
}

struct Scenario {
    name: &'static str,
    expected: Expected,
    run: Box<dyn Fn() -> Observed>,
}

fn scenarios() -> Vec<Scenario> {
    let mut suite: Vec<Scenario> = Vec::new();

    // -------------------- HELP / VERSION / TOP-LEVEL --------------------

    suite.push(Scenario {
        name: "--help exits 0",
        expected: Expected::Succeed,
        run: Box::new(|| observed(&run(&["--help"]))),
    });
    suite.push(Scenario {
        name: "--version exits 0",
        expected: Expected::Succeed,
        run: Box::new(|| observed(&run(&["--version"]))),
    });
    suite.push(Scenario {
        name: "no subcommand fails with usage",
        expected: Expected::Fail,
        run: Box::new(|| observed(&run(&[]))),
    });
    suite.push(Scenario {
        name: "unknown subcommand fails",
        expected: Expected::Fail,
        run: Box::new(|| observed(&run(&["definitely-not-a-command"]))),
    });

    // -------------------- KEYGEN --------------------

    suite.push(Scenario {
        name: "keygen writes a fresh seed",
        expected: Expected::Succeed,
        run: Box::new(|| {
            let dir = tempfile::tempdir().unwrap();
            let seed = dir.path().join("key.seed");
            observed(&run(&["keygen", "--output", seed.to_str().unwrap()]))
        }),
    });
    suite.push(Scenario {
        name: "keygen refuses to overwrite an existing seed",
        expected: Expected::Fail,
        run: Box::new(|| {
            let dir = tempfile::tempdir().unwrap();
            let seed = dir.path().join("key.seed");
            let first = run(&["keygen", "--output", seed.to_str().unwrap()]);
            assert!(first.status.success(), "seed setup failed");
            observed(&run(&["keygen", "--output", seed.to_str().unwrap()]))
        }),
    });

    // -------------------- CONFIG VALIDATE --------------------

    suite.push(Scenario {
        name: "config-validate accepts a minimal valid TOML",
        expected: Expected::Succeed,
        run: Box::new(|| {
            let dir = tempfile::tempdir().unwrap();
            let path = write_temp(
                dir.path(),
                "harness.toml",
                minimal_valid_harness_toml().as_bytes(),
            );
            observed(&run(&["config-validate", path.to_str().unwrap()]))
        }),
    });
    suite.push(Scenario {
        name: "config-validate rejects TOML missing upstream_url",
        expected: Expected::Fail,
        run: Box::new(|| {
            let dir = tempfile::tempdir().unwrap();
            let path = write_temp(dir.path(), "harness.toml", b"listen = \"0.0.0.0:8484\"\n");
            observed(&run(&["config-validate", path.to_str().unwrap()]))
        }),
    });
    suite.push(Scenario {
        name: "config-validate rejects malformed TOML",
        expected: Expected::Fail,
        run: Box::new(|| {
            let dir = tempfile::tempdir().unwrap();
            let path = write_temp(dir.path(), "harness.toml", b"this = is not [ valid\n");
            observed(&run(&["config-validate", path.to_str().unwrap()]))
        }),
    });
    suite.push(Scenario {
        name: "config-validate rejects a missing file",
        expected: Expected::Fail,
        run: Box::new(|| observed(&run(&["config-validate", "/nope/does/not/exist.toml"]))),
    });

    // -------------------- MANIFEST VALIDATE --------------------

    suite.push(Scenario {
        name: "manifest-validate accepts a minimal valid manifest",
        expected: Expected::Succeed,
        run: Box::new(|| {
            let dir = tempfile::tempdir().unwrap();
            let path = write_temp(
                dir.path(),
                "bridge.yaml",
                minimal_valid_manifest_yaml().as_bytes(),
            );
            observed(&run(&["manifest-validate", path.to_str().unwrap()]))
        }),
    });
    suite.push(Scenario {
        name: "manifest-validate rejects a manifest with zero topics",
        expected: Expected::Fail,
        run: Box::new(|| {
            let dir = tempfile::tempdir().unwrap();
            let path = write_temp(
                dir.path(),
                "bridge.yaml",
                b"manifest_version: 1\nname: bad\nreplication_factor: 1\ntopics: []\n",
            );
            observed(&run(&["manifest-validate", path.to_str().unwrap()]))
        }),
    });
    suite.push(Scenario {
        name: "manifest-validate rejects garbage YAML",
        expected: Expected::Fail,
        run: Box::new(|| {
            let dir = tempfile::tempdir().unwrap();
            let path = write_temp(dir.path(), "bridge.yaml", b": : : not yaml [\n");
            observed(&run(&["manifest-validate", path.to_str().unwrap()]))
        }),
    });
    suite.push(Scenario {
        name: "manifest-validate rejects a missing file",
        expected: Expected::Fail,
        run: Box::new(|| observed(&run(&["manifest-validate", "/nope/missing.yaml"]))),
    });

    // -------------------- RECEIPT VERIFY --------------------

    suite.push(Scenario {
        name: "receipt-verify accepts a well-formed signed receipt",
        expected: Expected::Succeed,
        run: Box::new(|| {
            let dir = tempfile::tempdir().unwrap();
            let (path, pk_hex) = sign_receipt(dir.path());
            observed(&run(&[
                "receipt-verify",
                path.to_str().unwrap(),
                "--public-key-hex",
                &pk_hex,
            ]))
        }),
    });
    suite.push(Scenario {
        name: "receipt-verify rejects a receipt when the trusted key is different",
        expected: Expected::Fail,
        run: Box::new(|| {
            let dir = tempfile::tempdir().unwrap();
            let (path, _) = sign_receipt(dir.path());
            // 32-byte hex representing a *different* Ed25519 public key.
            let attacker = "11".repeat(32);
            observed(&run(&[
                "receipt-verify",
                path.to_str().unwrap(),
                "--public-key-hex",
                &attacker,
            ]))
        }),
    });
    suite.push(Scenario {
        name: "receipt-verify rejects a non-hex public key",
        expected: Expected::Fail,
        run: Box::new(|| {
            let dir = tempfile::tempdir().unwrap();
            let (path, _) = sign_receipt(dir.path());
            observed(&run(&[
                "receipt-verify",
                path.to_str().unwrap(),
                "--public-key-hex",
                "not-hexadecimal-at-all",
            ]))
        }),
    });
    suite.push(Scenario {
        name: "receipt-verify rejects a wrong-length public key",
        expected: Expected::Fail,
        run: Box::new(|| {
            let dir = tempfile::tempdir().unwrap();
            let (path, _) = sign_receipt(dir.path());
            observed(&run(&[
                "receipt-verify",
                path.to_str().unwrap(),
                "--public-key-hex",
                // 30 bytes instead of 32.
                &"ab".repeat(30),
            ]))
        }),
    });
    suite.push(Scenario {
        name: "receipt-verify rejects a missing receipt file",
        expected: Expected::Fail,
        run: Box::new(|| {
            observed(&run(&[
                "receipt-verify",
                "/nope/missing-receipt.json",
                "--public-key-hex",
                &"00".repeat(32),
            ]))
        }),
    });

    // -------------------- BRIDGE PROVISION + EVENT TAIL --------------------

    suite.push(Scenario {
        name: "bridge-provision + event-tail succeed on a fresh data dir",
        expected: Expected::Succeed,
        run: Box::new(|| {
            let dir = tempfile::tempdir().unwrap();
            let manifest = write_temp(
                dir.path(),
                "bridge.yaml",
                minimal_valid_manifest_yaml().as_bytes(),
            );
            let data_dir = dir.path().join("data");
            let provisioned = run(&[
                "bridge-provision",
                "--manifest",
                manifest.to_str().unwrap(),
                "--data-dir",
                data_dir.to_str().unwrap(),
            ]);
            if !provisioned.status.success() {
                return Observed::Failed;
            }
            observed(&run(&[
                "event-tail",
                "--data-dir",
                data_dir.to_str().unwrap(),
                "--topic",
                "agent.tool_call",
                "--max",
                "1",
            ]))
        }),
    });
    suite.push(Scenario {
        name: "bridge-provision refuses to re-provision a populated data dir",
        expected: Expected::Fail,
        run: Box::new(|| {
            let dir = tempfile::tempdir().unwrap();
            let manifest = write_temp(
                dir.path(),
                "bridge.yaml",
                minimal_valid_manifest_yaml().as_bytes(),
            );
            let data_dir = dir.path().join("data");
            let first = run(&[
                "bridge-provision",
                "--manifest",
                manifest.to_str().unwrap(),
                "--data-dir",
                data_dir.to_str().unwrap(),
            ]);
            assert!(first.status.success(), "first provision failed");
            observed(&run(&[
                "bridge-provision",
                "--manifest",
                manifest.to_str().unwrap(),
                "--data-dir",
                data_dir.to_str().unwrap(),
            ]))
        }),
    });
    suite.push(Scenario {
        name: "event-tail rejects a non-provisioned data dir",
        expected: Expected::Fail,
        run: Box::new(|| {
            let dir = tempfile::tempdir().unwrap();
            observed(&run(&[
                "event-tail",
                "--data-dir",
                dir.path().to_str().unwrap(),
                "--topic",
                "agent.tool_call",
            ]))
        }),
    });
    suite.push(Scenario {
        name: "event-tail on unknown topic fails cleanly",
        expected: Expected::Fail,
        run: Box::new(|| {
            let dir = tempfile::tempdir().unwrap();
            let manifest = write_temp(
                dir.path(),
                "bridge.yaml",
                minimal_valid_manifest_yaml().as_bytes(),
            );
            let data_dir = dir.path().join("data");
            let first = run(&[
                "bridge-provision",
                "--manifest",
                manifest.to_str().unwrap(),
                "--data-dir",
                data_dir.to_str().unwrap(),
            ]);
            assert!(first.status.success());
            observed(&run(&[
                "event-tail",
                "--data-dir",
                data_dir.to_str().unwrap(),
                "--topic",
                "agent.does_not_exist",
            ]))
        }),
    });

    // -------------------- ATIF VALIDATE (failure modes only) --------------------

    suite.push(Scenario {
        name: "atif-validate rejects a missing file",
        expected: Expected::Fail,
        run: Box::new(|| observed(&run(&["atif-validate", "/nope/missing-trajectory.json"]))),
    });
    suite.push(Scenario {
        name: "atif-validate rejects malformed JSON",
        expected: Expected::Fail,
        run: Box::new(|| {
            let dir = tempfile::tempdir().unwrap();
            let path = write_temp(dir.path(), "traj.json", b"{not json");
            observed(&run(&["atif-validate", path.to_str().unwrap()]))
        }),
    });
    suite.push(Scenario {
        name: "atif-validate rejects an empty JSON object",
        expected: Expected::Fail,
        run: Box::new(|| {
            let dir = tempfile::tempdir().unwrap();
            let path = write_temp(dir.path(), "traj.json", b"{}");
            observed(&run(&["atif-validate", path.to_str().unwrap()]))
        }),
    });

    suite
}

#[test]
fn cli_end_to_end_confusion_matrix_has_no_false_negatives_or_false_positives() {
    let mut tp = 0u32;
    let mut tn = 0u32;
    let mut fp: Vec<&'static str> = Vec::new();
    let mut fn_: Vec<&'static str> = Vec::new();
    println!(
        "\n{:<3} {:<70} {:<9} {:<10} class",
        "#", "scenario", "expected", "observed"
    );
    println!("{}", "-".repeat(110));
    for (idx, scn) in scenarios().into_iter().enumerate() {
        let observed = (scn.run)();
        let class = classify(scn.expected, observed);
        println!(
            "{:<3} {:<70} {:<9} {:<10} {:?}",
            idx + 1,
            scn.name,
            format!("{:?}", scn.expected),
            format!("{:?}", observed),
            class
        );
        match class {
            Class::TP => tp += 1,
            Class::TN => tn += 1,
            Class::FP => fp.push(scn.name),
            Class::FN => fn_.push(scn.name),
        }
    }
    println!("{}", "-".repeat(110));
    println!("Totals: TP={tp}  TN={tn}  FP={}  FN={}\n", fp.len(), fn_.len());

    assert!(
        fn_.is_empty(),
        "SECURITY: {} false negative(s) — CLI accepted bad input: {:?}",
        fn_.len(),
        fn_
    );
    assert!(
        fp.is_empty(),
        "REGRESSION: {} false positive(s) — CLI rejected valid input: {:?}",
        fp.len(),
        fp
    );
    assert!(tp >= 5, "expected several TP scenarios, got {tp}");
    assert!(tn >= 5, "expected several TN scenarios, got {tn}");
}
