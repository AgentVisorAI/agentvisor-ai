//! Structural validation for events, independent of (and cross-checked
//! against) the shipped JSON Schema.

use crate::model::OcsfEvent;

/// A structural validation failure.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ValidationError {
    /// A required string field was empty.
    #[error("required field `{0}` is empty")]
    EmptyField(&'static str),
    /// `type_uid` doesn't match `class_uid * 100 + activity_id`.
    #[error("type_uid {type_uid} != class_uid {class_uid} * 100 + activity_id {activity_id}")]
    TypeUidMismatch {
        /// Stated type uid.
        type_uid: u64,
        /// Stated class uid.
        class_uid: u32,
        /// Stated activity id.
        activity_id: u8,
    },
    /// `class_uid` doesn't match the class enum.
    #[error("class_uid {0} does not match class_name")]
    ClassUidMismatch(u32),
    /// Event is not in the OCSF Application Activity category.
    #[error("category_uid {0} is not Application Activity (6)")]
    BadCategory(u8),
    /// Charter is not represented as an OCSF Regular File.
    #[error("ai_agent.charter.type_id {0} is not Regular File (1)")]
    BadCharterType(u8),
    /// Severity outside 1–6.
    #[error("severity_id {0} outside 1..=6")]
    BadSeverity(u8),
    /// Status outside 0–2.
    #[error("status_id {0} outside 0..=2")]
    BadStatus(u8),
    /// stop_reason caption present without id (or vice versa).
    #[error("stop_reason and stop_reason_id must be present together")]
    StopReasonPairMismatch,
    /// Timestamp is zero.
    #[error("time is zero")]
    ZeroTime,
}

/// Validate structural invariants of an event. Returns *all* violations
/// (collect-all-errors, matching the Harbor validator philosophy).
pub fn validate_event(ev: &OcsfEvent) -> Result<(), Vec<ValidationError>> {
    let mut errors = Vec::new();
    if ev.metadata.uid.is_empty() {
        errors.push(ValidationError::EmptyField("metadata.uid"));
    }
    if ev.metadata.version.is_empty() {
        errors.push(ValidationError::EmptyField("metadata.version"));
    }
    if ev.metadata.product.name.is_empty() {
        errors.push(ValidationError::EmptyField("metadata.product.name"));
    }
    if ev.metadata.product.vendor_name.is_empty() {
        errors.push(ValidationError::EmptyField("metadata.product.vendor_name"));
    }
    if ev.metadata.product.version.is_empty() {
        errors.push(ValidationError::EmptyField("metadata.product.version"));
    }
    if ev.session_uid.is_empty() {
        errors.push(ValidationError::EmptyField("session_uid"));
    }
    if ev.ai_agent.version.is_empty() {
        errors.push(ValidationError::EmptyField("ai_agent.version"));
    }
    if ev.ai_agent.charter.name.is_empty() {
        errors.push(ValidationError::EmptyField("ai_agent.charter.name"));
    }
    if ev.ai_agent.charter.type_id != 1 {
        errors.push(ValidationError::BadCharterType(ev.ai_agent.charter.type_id));
    }
    if ev.ai_agent.instance_uid.is_empty() {
        errors.push(ValidationError::EmptyField("ai_agent.instance_uid"));
    }
    if ev.class_uid != ev.class_name.class_uid() {
        errors.push(ValidationError::ClassUidMismatch(ev.class_uid));
    }
    if ev.category_uid != crate::model::CATEGORY_UID {
        errors.push(ValidationError::BadCategory(ev.category_uid));
    }
    let expected_type = u64::from(ev.class_name.class_uid()) * 100 + u64::from(ev.activity_id);
    if ev.type_uid != expected_type {
        errors.push(ValidationError::TypeUidMismatch {
            type_uid: ev.type_uid,
            class_uid: ev.class_uid,
            activity_id: ev.activity_id,
        });
    }
    if !(1..=6).contains(&ev.severity_id) {
        errors.push(ValidationError::BadSeverity(ev.severity_id));
    }
    if ev.status_id > 2 {
        errors.push(ValidationError::BadStatus(ev.status_id));
    }
    if ev.stop_reason_id.is_some() != ev.stop_reason.is_some() {
        errors.push(ValidationError::StopReasonPairMismatch);
    }
    if ev.time == 0 {
        errors.push(ValidationError::ZeroTime);
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]

    use super::*;
    use crate::model::{AgentIdentity, EventClass, OcsfEventBuilder};
    use crate::StopReason;

    fn valid_event() -> OcsfEvent {
        OcsfEventBuilder::new(
            EventClass::ToolCall,
            "sess",
            AgentIdentity {
                version: "1".into(),
                charter: "c".into(),
                instance_uid: "i".into(),
                ttl_remaining_s: None,
            },
            1,
        )
        .stop_reason(StopReason::PolicyBlocked)
        .build()
        .unwrap()
    }

    #[test]
    fn valid_event_passes() {
        assert!(validate_event(&valid_event()).is_ok());
    }

    #[test]
    fn empty_identity_fields_all_reported() {
        let mut ev = valid_event();
        ev.ai_agent.version.clear();
        ev.ai_agent.charter.name.clear();
        ev.ai_agent.instance_uid.clear();
        let errs = validate_event(&ev).unwrap_err();
        assert_eq!(errs.len(), 3, "collect-all: {errs:?}");
    }

    #[test]
    fn tampered_type_uid_detected() {
        let mut ev = valid_event();
        ev.type_uid += 1;
        assert!(matches!(
            validate_event(&ev).unwrap_err().first(),
            Some(ValidationError::TypeUidMismatch { .. })
        ));
    }

    #[test]
    fn orphan_stop_reason_caption_detected() {
        let mut ev = valid_event();
        ev.stop_reason_id = None; // caption still set
        assert!(validate_event(&ev)
            .unwrap_err()
            .contains(&ValidationError::StopReasonPairMismatch));
    }

    #[test]
    fn bad_severity_detected() {
        let mut ev = valid_event();
        ev.severity_id = 0;
        assert!(validate_event(&ev)
            .unwrap_err()
            .contains(&ValidationError::BadSeverity(0)));
        ev.severity_id = 7;
        assert!(validate_event(&ev)
            .unwrap_err()
            .contains(&ValidationError::BadSeverity(7)));
    }

    #[test]
    fn status_id_boundary_accepts_up_to_2_rejects_3() {
        // Catches `> 2` vs `== 2` / `>= 2` mutations: status_id=2 (Failure)
        // is VALID and must not be flagged; 3 is invalid and must be flagged.
        let mut ev = valid_event();
        for valid in [0u8, 1, 2] {
            ev.status_id = valid;
            let errs = validate_event(&ev).map(|_| Vec::new()).unwrap_or_else(|e| e);
            assert!(
                !errs.iter().any(|e| matches!(e, ValidationError::BadStatus(_))),
                "status_id={valid} incorrectly flagged: {errs:?}"
            );
        }
        ev.status_id = 3;
        assert!(validate_event(&ev)
            .unwrap_err()
            .contains(&ValidationError::BadStatus(3)));
    }
}
