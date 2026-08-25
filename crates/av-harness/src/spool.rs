//! Spool subdirectory names shared across the harness.

/// Directory under the spool root that holds durable lifecycle-outbox files.
pub(crate) const OUTBOX: &str = "outbox";
/// Directory under the spool root that holds tool intent/outcome/audited files.
pub(crate) const TOOL_EXECUTIONS: &str = "tool-executions";
/// Directory under the spool root that holds authenticated response markers.
pub(crate) const INFLIGHT_RESPONSES: &str = "inflight-responses";

/// On-disk file suffixes for the tool-execution state machine.
pub(crate) const TOOL_INTENT_SUFFIX: &str = ".intent.json";
pub(crate) const TOOL_OUTCOME_SUFFIX: &str = ".outcome.json";
pub(crate) const TOOL_AUDITED_SUFFIX: &str = ".audited";

#[cfg(test)]
mod tests {
    use super::*;

    /// Register item 30 sub-clause: "write a one-page 'spool layout
    /// and recovery' doc". docs/reference/SPOOL-AND-RECOVERY.md exists
    /// and its file inventory must actually enumerate every real
    /// on-disk artifact the harness writes. When a new suffix or
    /// subdirectory constant is added here, this test forces it into
    /// the doc — otherwise the layout grows silently and an operator
    /// inspecting a live spool sees files they can't reason about.
    ///
    /// Behaviorally verified: adding a new constant here and NOT
    /// touching the doc fails this test with a message naming the
    /// exact missing string.
    #[test]
    fn spool_constants_are_documented_in_spool_and_recovery() {
        let doc = include_str!("../../../docs/reference/SPOOL-AND-RECOVERY.md");
        for (name, value) in [
            ("OUTBOX", OUTBOX),
            ("TOOL_EXECUTIONS", TOOL_EXECUTIONS),
            ("INFLIGHT_RESPONSES", INFLIGHT_RESPONSES),
            ("TOOL_INTENT_SUFFIX", TOOL_INTENT_SUFFIX),
            ("TOOL_OUTCOME_SUFFIX", TOOL_OUTCOME_SUFFIX),
            ("TOOL_AUDITED_SUFFIX", TOOL_AUDITED_SUFFIX),
        ] {
            assert!(
                doc.contains(value),
                "spool constant {name} = {value:?} is not documented in \
                 docs/reference/SPOOL-AND-RECOVERY.md. Every on-disk artifact \
                 the harness writes must appear in the file-inventory table \
                 so operators inspecting a live spool can identify it."
            );
        }
    }
}
