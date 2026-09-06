//! Build-time asset dependency tracking for the harness dashboard and
//! its embedded WAT policy.
//!
//! `include_str!` in `src/dashboard.rs` and `src/main.rs` embeds files
//! from this crate's `dashboard/` and `policies/` directories,
//! but Cargo's automatic dep-info fingerprinting proved
//! unreliable for these embedded assets in this workspace — the empirical statement is that editing
//! `dashboard/` files alone did not rebuild the binary until this
//! script was added. Once one `rerun-if-changed` line exists, Cargo
//! narrows the fingerprint to exactly the listed paths, so every
//! embedded asset MUST be listed here or edits will silently produce
//! a stale binary.
fn main() {
    for asset in ["index.html", "style.css", "app.js"] {
        println!("cargo:rerun-if-changed=dashboard/{asset}");
    }
    // Baked into the release binary by `src/main.rs::BUILTIN_POLICY_WAT`
    // and re-parsed at every start under a fresh Wasmtime engine —
    // stale bundling here means the wrong sandbox policy is enforced
    // for every request after the operator edits the .wat.
    //
    // The file lives inside the crate
    // (`crates/av-harness/policies/payload_limit.wat`) so `cargo
    // publish` packages it. The out-of-crate copy at
    // `<repo>/config/policies/payload_limit.wat` is still shipped with
    // release tarballs / Docker / systemd / k8s as the operator-editable
    // runtime path — keep both in sync during development.
    println!("cargo:rerun-if-changed=policies/payload_limit.wat");
    // Out-of-crate assets embedded via `include_str!` (mostly by the
    // config/deploy PIN TESTS). Per the fingerprint-narrowing note
    // above, once any rerun-if-changed line exists these must be
    // listed too — otherwise editing e.g. the shipped k8s manifest or
    // harness.docker.toml did not invalidate the test binary, and the
    // shutdown-grace / ConfigMap pin tests kept re-asserting against
    // the PREVIOUSLY embedded copy: exactly the drift they exist to
    // catch went green. Existence-gated: these workspace files are
    // absent in `cargo publish` builds (the embedding sites are
    // test-only), and a rerun-if-changed on a missing path would
    // force a rebuild on every invocation.
    for asset in [
        "../../config/harness.container.toml",
        "../../config/harness.docker.toml",
        "../../config/harness.example.toml",
        "../../config/tool-schemas",
        "../../deploy/kubernetes/agentvisor-ai.yaml",
        "../../docker/docker-compose.minimal.yml",
        "../../docker/docker-compose.yml",
        "../../docs/app/pitch/console.js",
        "../../docs/app/pitch/index.html",
        "../../docs/reference/CONFIGURATION.md",
        "../../docs/reference/LIMITS.md",
        "../../docs/reference/OPENAI-COMPATIBILITY.md",
        "../../docs/reference/OPERATIONS.md",
        "../../docs/reference/SPOOL-AND-RECOVERY.md",
    ] {
        if std::path::Path::new(asset).exists() {
            println!("cargo:rerun-if-changed={asset}");
        }
    }
}
