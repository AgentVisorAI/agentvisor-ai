//! Build-time asset dependency tracking for the harness dashboard and
//! its embedded WAT policy.
//!
//! `include_str!` in `src/dashboard.rs` and `src/main.rs` reads files
//! outside the crate root at compile time, but Cargo's automatic
//! dep-info fingerprinting is unreliable for parent-relative embedded
//! assets in this workspace — the empirical statement is that editing
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
    println!("cargo:rerun-if-changed=../../config/policies/payload_limit.wat");
}
