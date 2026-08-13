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
