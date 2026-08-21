//! Build-time asset dependency tracking for schemas embedded via
//! `include_str!`.
//!
//! `crates/av-bridge/src/manifest.rs::schema_document` bakes the shipped
//! OCSF event schema into the binary and validates every published event
//! against it. Round-6 (hunt5 portability F1): the embedded copy lives
//! inside the crate at `schemas/` so `cargo package`/publish works — an
//! `include_str!` reaching outside the package root cannot be packaged.
//! The workspace-level copy in `<repo>/schemas/` remains the canonical
//! artifact consumers validate against; a unit test asserts the two are
//! byte-identical. Track both so editing either re-triggers the build.
fn main() {
    println!("cargo:rerun-if-changed=schemas/ocsf-agent-event.schema.json");
    println!("cargo:rerun-if-changed=../../schemas/ocsf-agent-event.schema.json");
}
