//! Build-time asset dependency tracking for the harness dashboard.
//!
//! `include_str!` in `src/dashboard.rs` reads these files at compile time,
//! but Cargo does not always track the dependency across the `../dashboard/`
//! path walk — telling it explicitly here avoids a stale binary after
//! asset edits.
fn main() {
    for asset in ["index.html", "style.css", "app.js"] {
        println!("cargo:rerun-if-changed=dashboard/{asset}");
    }
}
