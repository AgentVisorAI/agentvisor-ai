//! Build-time asset dependency tracking for the harness dashboard and
//! its embedded WAT policy.
//!
//! `include_str!` in `src/dashboard.rs` and `src/main.rs` embeds files
//! from `dashboard/` and `policies/` (both inside this crate since
//! round-45), but Cargo's automatic dep-info fingerprinting proved
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
    // Round-45: the file lives INSIDE the crate now
    // (`crates/av-harness/policies/payload_limit.wat`) so `cargo
    // publish` packages it. The out-of-crate copy at
    // `<repo>/config/policies/payload_limit.wat` is still shipped with
    // release tarballs / Docker / systemd / k8s as the operator-editable
    // runtime path — keep both in sync during development.
    println!("cargo:rerun-if-changed=policies/payload_limit.wat");
}
