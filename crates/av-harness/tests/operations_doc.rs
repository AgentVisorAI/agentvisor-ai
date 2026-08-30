//! OPERATIONS.md truth pins (R283). The operator guide was executed
//! verbatim against a real daemon: probe semantics (readyz 503 on a
//! non-writable spool while livez stays 200), SIGTERM pre-drain 503
//! window, the full key-rotation runbook (keygen -> pubkey -> atomic
//! mv -> SIGHUP is NOT wired -> restart -> multi-key rotation-window
//! verify), orphan quarantine (exact `<name>.json.corrupt-<uid>`
//! rename + `unauthenticated` metric), and `avctl spool-prune`. All
//! true at audit time; these pins keep the doc's greppable claims from
//! drifting: alert-table metric names, recovery pass labels, probe
//! routes, config search order, and the commands the runbook tells an
//! operator to type.
#![allow(clippy::expect_used, clippy::panic)]

const DOC: &str = include_str!("../../../docs/reference/OPERATIONS.md");
const MAIN_RS: &str = include_str!("../src/main.rs");
const PIPELINE: &str = include_str!("../src/pipeline.rs");
const RECONCILER: &str = include_str!("../src/reconciler.rs");
const ROUTES: &str = include_str!("../src/routes.rs");
const WORKER: &str = include_str!("../src/worker.rs");
const RECOVERY: &str = include_str!("../src/recovery.rs");
const CLI_MAIN: &str = include_str!("../../av-cli/src/main.rs");
const K8S_MANIFEST: &str = include_str!("../../../deploy/kubernetes/agentvisor-ai.yaml");

/// Every metric the alert table names must still be a registered
/// literal somewhere in the harness sources. A rename strands the
/// operator's alert rules on a series that stops existing.
#[test]
fn alert_table_metrics_are_registered_in_the_sources() {
    let sources = [MAIN_RS, PIPELINE, RECONCILER, ROUTES, WORKER, RECOVERY];
    let mut checked = 0;
    for chunk in DOC.split('`').skip(1).step_by(2) {
        let name = chunk.split('{').next().unwrap_or(chunk);
        if !name.starts_with("av_") {
            continue;
        }
        if !(name.ends_with("_total") || name.ends_with("_seconds") || name.ends_with("_pending")) {
            continue; // crate paths like `av_receipts::keys::Keyring`
        }
        checked += 1;
        assert!(
            sources.iter().any(|s| s.contains(name)),
            "OPERATIONS.md alerts on `{name}` but no harness source \
             registers that literal — a metric rename must update the \
             operator guide in the same commit"
        );
    }
    assert!(
        checked >= 25,
        "expected the alert table to name at least 25 metrics, parsed {checked} — \
         the doc structure changed; update this test's extraction"
    );
}

/// The recovery-scan cap's `pass` label vocabulary is enumerated in the
/// doc; each label must exist in the reconciler/pipeline sources.
#[test]
fn recovery_pass_labels_match_the_doc() {
    for label in [
        "adopt_strict_atif",
        "recover_signed_journals",
        "consolidate_step_journals",
        "retry_marked_promotions",
        "remove_acked_outboxes",
        "replay_lifecycle_outboxes",
        "quarantine_orphan_json",
    ] {
        assert!(
            DOC.contains(label),
            "pass label {label} left the OPERATIONS.md enumeration"
        );
        assert!(
            PIPELINE.contains(label) || RECONCILER.contains(label),
            "OPERATIONS.md documents recovery pass label {label} but the \
             sources no longer contain it"
        );
    }
}

/// Probe routes and their semantics: all three documented routes exist,
/// and the k8s manifest wires the two the doc says it wires.
#[test]
fn probe_routes_and_manifest_wiring_match() {
    for route in ["/health", "/livez", "/readyz"] {
        assert!(DOC.contains(route));
        assert!(
            ROUTES.contains(&format!("\"{route}\"")),
            "documented probe route {route} not found in routes.rs"
        );
    }
    for needle in [
        "startupProbe",
        "readinessProbe",
        "livenessProbe",
        "path: /livez",
        "path: /readyz",
        "shutdown_ready_drain_s = 5",
    ] {
        assert!(
            K8S_MANIFEST.contains(needle),
            "OPERATIONS.md describes the k8s manifest wiring `{needle}` — \
             the manifest no longer contains it"
        );
    }
    assert!(
        !K8S_MANIFEST.contains("preStop:"),
        "OPERATIONS.md documents the manifest as having NO preStop hook \
         (distroless base has no /bin/sh); an active `preStop:` key was \
         added — update the doc (comments ABOUT preStop are fine)"
    );
}

/// Boot search order: the doc's list must match CONFIG_SEARCH_PATHS and
/// the AV_CONFIG env override.
#[test]
fn config_search_order_matches_the_doc() {
    assert_eq!(
        av_harness::config::CONFIG_SEARCH_PATHS,
        ["agentvisor.toml", "config/harness.toml"],
        "config search paths changed — update OPERATIONS.md §Boot"
    );
    for needle in [
        "$AV_CONFIG",
        "`./agentvisor.toml`",
        "`./config/harness.toml`",
        "$HOME/.agentvisor/agentvisor.toml",
        "NOT searched",
    ] {
        assert!(DOC.contains(needle), "OPERATIONS.md §Boot lost `{needle}`");
    }
}

/// The rotation runbook's commands must stay real avctl subcommands,
/// and the quarantine/inflight filename formats the doc teaches
/// operators to recognize must match the code.
#[test]
fn runbook_commands_and_filename_formats_match() {
    for (doc_phrase, cli_needle) in [
        ("avctl keygen --output", "Keygen"),
        ("avctl pubkey --seed", "Pubkey"),
        ("avctl spool-prune --spool", "SpoolPrune"),
    ] {
        assert!(DOC.contains(doc_phrase), "runbook lost `{doc_phrase}`");
        assert!(
            CLI_MAIN.contains(cli_needle),
            "OPERATIONS.md tells operators to run `{doc_phrase}` but av-cli \
             no longer has `{cli_needle}`"
        );
    }
    // SIGHUP is documented as NOT wired for reload; main.rs installs an
    // explicit ignore (default SIGHUP action would TERMINATE the daemon
    // on terminal hangup / systemd ExecReload). If reload wiring ever
    // lands, this intent comment goes away and the runbook's step 4
    // (restart required) must change with it.
    assert!(DOC.contains("`SIGHUP` is **not** wired"));
    assert!(
        MAIN_RS.contains("support config-reload on SIGHUP"),
        "main.rs lost the SIGHUP no-reload intent comment — if SIGHUP \
         reload was wired, update OPERATIONS.md §Key rotation step 4"
    );
    // Quarantine rename: `<name>.json.corrupt-<uid>`.
    assert!(DOC.contains(".json.corrupt-<uid>"));
    assert!(
        RECOVERY.contains(".corrupt-"),
        "recovery.rs quarantine rename format changed — update the doc"
    );
    // Inflight marker naming: sha256(session_id:attempt_id)[..32].json
    assert!(DOC.contains("sha256(session_id:attempt_id)[..32].json"));
    assert!(
        WORKER.contains("{session_id}:{attempt_id}") && WORKER.contains("&digest[..32]"),
        "inflight-responses filename derivation changed — the manual \
         release procedure in OPERATIONS.md describes the old format"
    );
}
