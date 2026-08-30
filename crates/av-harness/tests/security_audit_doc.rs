//! SECURITY-AUDIT.md truth pins (R282). The audit doc's "NOT reachable"
//! arguments rest on named code facts: the wasmtime feature set, the
//! containment regression tests, the constant-time MAC path, the pinned
//! dependency states. Each was verified by hand once; these asserts keep
//! the doc and the code from drifting apart silently (a rename here or a
//! doc edit there fails with a message naming the other side). The doc's
//! one rotting line-number reference (onnx_embed.rs:30 -> 32) is exactly
//! the failure mode this file exists to prevent.
#![allow(clippy::expect_used, clippy::panic)]

const AUDIT: &str = include_str!("../../../SECURITY-AUDIT.md");
const ROOT_MANIFEST: &str = include_str!("../../../Cargo.toml");
const LOCKFILE: &str = include_str!("../../../Cargo.lock");
const WASM_POLICY: &str = include_str!("../../av-sandbox/src/wasm_policy.rs");
const COLD_STORE: &str = include_str!("../../av-bridge/src/cold_store.rs");
const COMPRESS_PASSES: &str = include_str!("../../av-compress/src/passes.rs");
const ONNX_EMBED: &str = include_str!("../../av-loopdetect/src/onnx_embed.rs");

/// The whole wasmtime advisory triage rests on this exact feature set.
#[test]
fn wasmtime_feature_containment_matches_the_audit() {
    let line = r#"wasmtime = { version = "47", default-features = false, features = ["runtime", "cranelift", "wat"] }"#;
    assert!(
        ROOT_MANIFEST.contains(line),
        "root Cargo.toml wasmtime declaration changed — re-run the advisory \
         triage in SECURITY-AUDIT.md (the Winch/component-model/WASI \
         not-reachable arguments assume this exact feature set)"
    );
    assert!(
        AUDIT.contains(r#"default-features = false, features = ["runtime", "cranelift", "wat"]"#),
        "SECURITY-AUDIT.md no longer states the wasmtime feature set"
    );
}

/// The named containment regressions the audit cites must keep existing.
#[test]
fn audit_cited_regression_tests_exist() {
    for name in [
        "fn invalid_wasm_rejected_at_load",
        "fn missing_exports_fail_closed",
        "fn hostile_infinite_loop_fails_closed_via_fuel_and_epoch",
        "fn memory_bomb_policy_fails_closed_via_store_limits",
        "fn hostile_return_codes_all_deny",
    ] {
        assert!(
            WASM_POLICY.contains(name),
            "SECURITY-AUDIT.md cites `{name}` in av-sandbox wasm_policy.rs; \
             renaming it silently voids the audit's containment evidence — \
             update the doc in the same commit"
        );
    }
    for name in [
        "fn verify_pending_mac",
        "fn tampered_cold_intent_fails_authentication",
        "fn corrupt_hex_mac_field_fails_authentication",
        "fn wrong_control_key_fails_authentication",
    ] {
        assert!(
            COLD_STORE.contains(name),
            "SECURITY-AUDIT.md cites `{name}` in av-bridge cold_store.rs — \
             update the doc in the same commit as any rename"
        );
    }
}

/// The constant-time comparison the audit's one real fix introduced.
#[test]
fn cold_store_mac_still_verified_constant_time() {
    assert!(
        COLD_STORE.contains("verify_slice"),
        "cold_store.rs no longer uses hmac::Mac::verify_slice — the CWE-208 \
         fix in SECURITY-AUDIT.md claims constant-time MAC comparison"
    );
}

/// The compression-marker design limitation is tracked at a named TODO.
#[test]
fn compression_marker_todo_still_tracked() {
    assert!(
        COMPRESS_PASSES.contains("TODO(compression-marker)"),
        "SECURITY-AUDIT.md tracks the marker-spoofing limitation at \
         TODO(compression-marker) in av-compress/src/passes.rs; if the fix \
         landed, update the audit doc's entry instead of deleting the TODO"
    );
    assert!(AUDIT.contains("TODO(compression-marker)"));
}

/// The tract-nnef not-reachable argument names the real call site.
#[test]
fn onnx_load_path_matches_the_audit() {
    assert!(
        ONNX_EMBED.contains(".model_for_path(") && ONNX_EMBED.contains("pub fn load("),
        "av-loopdetect onnx_embed.rs load path changed — SECURITY-AUDIT.md \
         cites OnnxEmbedder::load calling tract_onnx model_for_path"
    );
    assert!(
        AUDIT.contains("OnnxEmbedder::load"),
        "SECURITY-AUDIT.md should reference the enclosing symbol (not a \
         line number — those rot)"
    );
}

/// Dependency states the audit records as "Resolved after this audit".
#[test]
fn resolved_dependency_states_hold_in_the_lockfile() {
    let wasmtime_pinned = LOCKFILE
        .split("name = \"wasmtime\"\n")
        .nth(1)
        .expect("wasmtime in lockfile")
        .starts_with("version = \"47.");
    assert!(
        wasmtime_pinned,
        "Cargo.lock wasmtime left 47.x — SECURITY-AUDIT.md's post-audit \
         resolution note pins 47.x as post-dating every analyzed advisory; \
         re-triage and update the doc"
    );
    assert!(
        !LOCKFILE.contains("name = \"rustls-pemfile\""),
        "rustls-pemfile re-entered the dependency tree — SECURITY-AUDIT.md \
         records it as gone (2026-08-16); update the informational section"
    );
    let nats = LOCKFILE
        .split("name = \"async-nats\"\n")
        .nth(1)
        .expect("async-nats in lockfile");
    assert!(
        nats.starts_with("version = \"0.5"),
        "async-nats left the 0.50+ line SECURITY-AUDIT.md records for the \
         rustls-webpki chain resolution — re-check the webpki advisories"
    );
}
