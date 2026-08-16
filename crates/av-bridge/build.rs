//! Build-time asset dependency tracking for schemas embedded via
//! `include_str!`.
//!
//! `crates/av-bridge/src/manifest.rs::schema_document` bakes the shipped
//! OCSF event schema into the binary and validates every published event
//! against it. Cargo's automatic dep-info fingerprinting is unreliable
//! for parent-relative embedded assets in this workspace (see the
//! matching build.rs in av-harness), so an operator editing the schema
//! JSON would silently produce a stale binary that validates against
//! yesterday's schema. Once any `rerun-if-changed` line exists, Cargo
//! narrows the fingerprint to exactly the listed paths.
fn main() {
    println!("cargo:rerun-if-changed=../../schemas/ocsf-agent-event.schema.json");
}
