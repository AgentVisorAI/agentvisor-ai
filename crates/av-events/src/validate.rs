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
    /// Round-6 (hunt2 F11): `unmapped` carries inbound-tolerance fields
    /// that re-serialize to the top level, but the shipped schema
    /// declares `additionalProperties: false` — such an event passes the
    /// Rust validator yet fails the broker's schema gate at publish
    /// (which fail-closes the session). The tolerance is INBOUND-ONLY;
    /// republishing an event that carries unmapped fields is refused
    /// here so both validators agree.
    #[error("event carries {0} unmapped field(s); inbound tolerance is not publishable")]
    UnmappedNotPublishable(usize),
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
    /// Round-38 F3: activity_id must be < 100 or the
    /// `class_uid × 100 + activity_id` bijection collapses:
    /// `class_uid=9901, activity_id=100` produces the same
    /// `type_uid = 990200` as `class_uid=9902, activity_id=0`,
    /// so downstream SIEM pipelines routing/aggregating by
    /// type_uid mis-classify. Not currently reachable via the
    /// builder (defaults 1), but `OcsfEvent`'s fields are all pub
    /// and the struct is not `#[non_exhaustive]`, so callers can
    /// construct or mutate events directly, bypassing the builder;
    /// enforce the bijection
    /// invariant at validate time.
    #[error("activity_id {0} outside 0..=99 (would collide type_uid namespaces)")]
    BadActivityId(u8),
    /// stop_reason caption present without id (or vice versa).
    #[error("stop_reason and stop_reason_id must be present together")]
    StopReasonPairMismatch,
    /// Round-17 F1: stop_reason_id maps to a KNOWN `StopReason` variant,
    /// but the accompanying caption does not match that variant's
    /// canonical caption. The two fields split downstream analytics
    /// (SIEM pipelines that group by id disagree with dashboards that
    /// group by caption) — reject the disagreement so both fields
    /// mean the same thing.
    #[error("stop_reason_id {id} maps to {expected_caption:?} but stop_reason is {actual_caption:?}")]
    StopReasonCaptionMismatch {
        /// Stated stop reason id.
        id: u8,
        /// Canonical caption for that id.
        expected_caption: &'static str,
        /// Actual caption that was emitted with the id.
        actual_caption: String,
    },
    /// Round-17 F2: a numeric field exceeds `av_core::error::JCS_SAFE_MAX`
    /// (2^53) on the deserialize path. `OcsfEventBuilder::build`
    /// already refuses values above the JCS-safe integer range, but
    /// wire deserialization (`serde_json::from_slice::<OcsfEvent>`)
    /// bypassed the guard — an issuer sending `prompt_tokens = 2^53+1`
    /// would round-trip through JS-based auditors (JSON.parse) as a
    /// silently-truncated value, losing 1 or more low bits and
    /// breaking any receipt hash computed by JS consumers.
    #[error("field {field} = {value} exceeds JCS-safe integer range 2^53")]
    JcsUnsafeInteger {
        /// Field name.
        field: &'static str,
        /// Offending value.
        value: u64,
    },
    /// Round-26 F1 (self-fix): a numeric field is out of its
    /// schema-declared range. Currently only `pruning_ratio_millis`
    /// (permille ratio, capped at 1000) enforces this, but the
    /// variant is variant-generic so future range-bound fields can
    /// reuse it. Parallel to `JcsUnsafeInteger` — build() and
    /// `validate_event` (the deserialize backstop) both enforce the
    /// bound, closing the emitter/validator drift the wire-side path
    /// used to have.
    #[error("field {field} = {value} exceeds schema max {max}")]
    OutOfSchemaRange {
        /// Field name.
        field: &'static str,
        /// Offending value.
        value: u64,
        /// Declared inclusive max.
        max: u64,
    },
    /// Timestamp is zero.
    #[error("time is zero")]
    ZeroTime,
    /// Schema parity: `stop_reason_id` outside the schema enum
    /// {0..=4, 90..=94, 99}.
    #[error("stop_reason_id {0} is not a known reason id")]
    UnknownStopReasonId(u8),
    /// Schema parity: `metadata.version` must be the const "1.10.0".
    #[error("metadata.version {0:?} is not the pinned OCSF version")]
    BadOcsfVersion(String),
    /// Schema parity: fingerprint constants (SHA-256/JCS/64-hex value).
    #[error("{0} fingerprint violates the SHA-256/JCS/hex-64 shape")]
    BadFingerprint(&'static str),
    /// Schema parity: `payload` maxProperties 512.
    #[error("payload carries {0} properties, above the schema max of 512")]
    PayloadTooManyProperties(usize),
    /// Schema parity: `time_iso`'s pattern requires a 4-digit year, so
    /// epoch-ms beyond 9999-12-31 renders a caption the schema rejects.
    #[error("time {0} is beyond 9999-12-31 (time_iso year would exceed 4 digits)")]
    TimeBeyondSchemaRange(u64),
    /// `time_iso` does not match the canonical ISO-8601 rendering of
    /// `time`. The two fields are dual representations of one instant;
    /// a mismatch means a signed/chained event names different times to
    /// human auditors (caption) and machine tooling (epoch-ms). Same
    /// class as the receipt's `issued_at`/`issued_at_iso` cross-check.
    #[error("time_iso {time_iso:?} does not match time ({time}); expected {expected_iso:?}")]
    TimeIsoMismatch {
        /// Epoch-milliseconds timestamp.
        time: u64,
        /// Caption that was actually emitted.
        time_iso: String,
        /// Canonical rendering of `time`.
        expected_iso: String,
    },
}

/// Validate structural invariants of an event. Returns *all* violations
/// (collect-all-errors, matching the Harbor validator philosophy).
pub fn validate_event(ev: &OcsfEvent) -> Result<(), Vec<ValidationError>> {
    let mut errors = Vec::new();
    // Round-6 (hunt2 F11): see UnmappedNotPublishable.
    if !ev.unmapped.is_empty() {
        errors.push(ValidationError::UnmappedNotPublishable(ev.unmapped.len()));
    }
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
    // Round-38 F3: the `class_uid × 100 + activity_id` invariant
    // above is only a bijection when activity_id < 100. Enforce
    // that at validate time so an adversarial event asserting
    // `class_uid=9901, activity_id=100, type_uid=990200` (which
    // is self-consistent per the mismatch check but collides
    // with `class_uid=9902, activity_id=0`) cannot slip through
    // and mis-route downstream SIEM aggregation by type_uid.
    if ev.activity_id >= 100 {
        errors.push(ValidationError::BadActivityId(ev.activity_id));
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
    // Schema parity (validator/schema agreement is this module's stated
    // purpose — see the module doc): the shipped schema pins
    // `stop_reason_id` to the enum {0..=4, 90..=94, 99}; an id like 50
    // previously passed here yet failed the broker's schema gate.
    if let Some(id) = ev.stop_reason_id {
        if !matches!(id, 0..=4 | 90..=94 | 99) {
            errors.push(ValidationError::UnknownStopReasonId(id));
        }
    }
    // Schema parity: `metadata.version` is `const "1.10.0"`.
    if ev.metadata.version != crate::model::OCSF_VERSION {
        errors.push(ValidationError::BadOcsfVersion(ev.metadata.version.clone()));
    }
    // Schema parity: fingerprint constants (algorithm 3/"SHA-256",
    // serialization 2/"JCS", 64-hex value) — previously entirely
    // unvalidated on the wire path.
    for (field, fingerprint) in [
        ("inventory", ev.inventory.as_ref()),
        ("prev_inventory", ev.prev_inventory.as_ref()),
    ] {
        let Some(fp) = fingerprint else { continue };
        let hex64 = fp.value.len() == 64
            && fp
                .value
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase());
        if fp.algorithm_id != 3
            || fp.algorithm != "SHA-256"
            || fp.serialization_id != 2
            || fp.serialization != "JCS"
            || !hex64
        {
            errors.push(ValidationError::BadFingerprint(field));
        }
    }
    // Schema parity: `payload` maxProperties 512.
    if let Some(map) = ev.payload.as_object() {
        if map.len() > 512 {
            errors.push(ValidationError::PayloadTooManyProperties(map.len()));
        }
    }
    // Round-6 (hunt2 F4): match the shipped JSON schema's
    // `"stop_reason": {"type": "string", "minLength": 1}`. Some
    // OpenAI-compatible shims emit `finish_reason: ""` mid-stream; the
    // parse-site filter in routes.rs::parse_provider_chunk drops that,
    // but this defense-in-depth check ensures any other emitter path
    // (`stop_reason_native`, direct builder use) also cannot produce
    // an event that would pass the Rust validator here yet fail the
    // schema validator at publish — which permanently fail-closes the
    // session AFTER the bytes are relayed.
    if ev.stop_reason.as_deref() == Some("") {
        errors.push(ValidationError::EmptyField("stop_reason"));
    }
    // Round-17 F1 (revised in round-18 after self-audit): the initial
    // fix required `StopReason::from_id(id).caption() == stop_reason`
    // whenever id was known. That's WRONG — the field docstring at
    // `model.rs::OcsfEvent::stop_reason` and the builder API
    // `OcsfEventBuilder::stop_reason_native` both document
    // `stop_reason` as "the provider's native value when captured".
    // So `id=1, caption="stop"` (OpenAI native), `id=1,
    // caption="end_turn"` (Anthropic native), `id=99, caption="Custom
    // Free Text"` (Other) are ALL legitimate emissions from the
    // official builder. The over-strict check would have rejected the
    // vast majority of production events.
    //
    // Narrow to the specific cross-wiring case that started this
    // finding: the caption is ITSELF a canonical caption for a
    // DIFFERENT known variant. `id=93 (PolicyBlocked)` +
    // `caption="Loop Detected"` (canonical caption of variant 91) is
    // an unambiguous mistake — the two fields disagree on which
    // enforcement fired. Provider-native captions like `"stop"` or
    // `"tool_calls"` are not canonical captions of any variant, so
    // they pass. Round-33's `map_finish_reason` in routes.rs uses the
    // lowercase provider tokens; none of those coincide with a
    // canonical caption (which are Title-cased: `"Stop"`, `"Tool
    // Use"`, `"Length"`, `"Content Filter"`, …).
    if let (Some(id), Some(caption)) = (ev.stop_reason_id, ev.stop_reason.as_deref()) {
        let expected = crate::StopReason::from_id(id).caption();
        let is_known_id = matches!(id, 0..=4 | 90..=94 | 99);
        let caption_is_canonical_of_other_variant = is_known_id
            && expected != caption
            && [
                crate::StopReason::Unknown,
                crate::StopReason::Stop,
                crate::StopReason::MaxTokens,
                crate::StopReason::ToolUse,
                crate::StopReason::SessionClosed,
                crate::StopReason::ContentFilter,
                crate::StopReason::LoopDetected,
                crate::StopReason::BudgetExceeded,
                crate::StopReason::PolicyBlocked,
                crate::StopReason::IdentityRejected,
                crate::StopReason::Other,
            ]
            .iter()
            .any(|other| other.caption() == caption);
        if caption_is_canonical_of_other_variant {
            errors.push(ValidationError::StopReasonCaptionMismatch {
                id,
                expected_caption: expected,
                actual_caption: caption.to_owned(),
            });
        }
    }
    if ev.time == 0 {
        errors.push(ValidationError::ZeroTime);
    }
    // Schema parity: the `time_iso` pattern pins a 4-digit year. A
    // `time` near 2^53 is JCS-safe and consistent with its own caption
    // (the cross-check below), but renders a 6-digit year the schema
    // pattern rejects. 253402300799999 = 9999-12-31T23:59:59.999Z.
    if ev.time > 253_402_300_799_999 {
        errors.push(ValidationError::TimeBeyondSchemaRange(ev.time));
    }
    // `time_iso` is the second representation of the event's timestamp;
    // the schema pins its exact format and `OcsfEventBuilder::build`
    // derives it from `time`. But the wire/deserialize path never
    // checked the two agree, so a signed/chained event could carry a
    // `time` and a `time_iso` naming different instants (or a garbage
    // caption) and still validate — auditors reading the caption and
    // tooling reading the epoch field would extract contradictory facts
    // from the same event. Same dual-representation class as the
    // receipt's issued_at/issued_at_iso cross-check; strict equality
    // against the canonical rendering enforces format and consistency
    // in one step.
    {
        let expected_iso = av_core::time::iso8601_ms(ev.time);
        if ev.time_iso != expected_iso {
            errors.push(ValidationError::TimeIsoMismatch {
                time: ev.time,
                time_iso: ev.time_iso.clone(),
                expected_iso,
            });
        }
    }
    // Round-17 F2: JCS-safe integer guard on deserialize path.
    // `OcsfEventBuilder::build` already enforces this for its own
    // outputs, but a wire event bypasses build(). Values above
    // `av_core::error::JCS_SAFE_MAX` (2^53) round-trip through
    // JS-based JSON parsers as silently-truncated values,
    // breaking any receipt hash a JS auditor computes over the
    // event. Cover the fields build() covers: `time`, `seq`, and
    // every `EventMetrics` counter.
    for (field, value) in [("time", ev.time), ("metadata.sequence", ev.metadata.sequence)] {
        if av_core::error::check_jcs_safe(value).is_err() {
            errors.push(ValidationError::JcsUnsafeInteger { field, value });
        }
    }
    // Round-6 (hunt2 F1): `ai_agent.ttl_remaining_s` is a schema-typed
    // u64 with no maximum in the shipped JSON schema. Any value above
    // 2^53 silently truncates in JS-based auditors and hard-fails
    // `av_receipts::canonicalize`. `OcsfEventBuilder::build`'s
    // check_jcs_safe loop already covers the fields listed above; add
    // ttl_remaining_s here so the wire/deserialize path also refuses.
    // (`OcsfEvent.ai_agent.ttl_remaining_s` was omitted from the
    // original round-17 F2 sweep.)
    if let Some(ttl) = ev.ai_agent.ttl_remaining_s {
        if av_core::error::check_jcs_safe(ttl).is_err() {
            errors.push(ValidationError::JcsUnsafeInteger {
                field: "ai_agent.ttl_remaining_s",
                value: ttl,
            });
        }
    }
    if let Some(m) = &ev.metrics {
        for (field, value) in [
            ("metrics.prompt_tokens", m.prompt_tokens),
            ("metrics.completion_tokens", m.completion_tokens),
            ("metrics.cached_tokens", m.cached_tokens),
            ("metrics.pruned_tokens", m.pruned_tokens),
            ("metrics.pruning_ratio_millis", m.pruning_ratio_millis),
        ] {
            if let Some(v) = value {
                if av_core::error::check_jcs_safe(v).is_err() {
                    errors.push(ValidationError::JcsUnsafeInteger { field, value: v });
                }
            }
        }
        // Round-26 F1 (self-fix): mirror the `> 1000` guard from
        // `OcsfEventBuilder::build`. The schema declares
        // `pruning_ratio_millis` in `[0, 1000]`; round-17 F2 already
        // introduced this validator as the wire-side backstop for
        // build's checks, and round-26 F1 added the range check to
        // build. Adding it here closes the emitter/validator drift
        // — an event with `pruning_ratio_millis = 5000` now fails
        // both paths, not just build.
        if let Some(v) = m.pruning_ratio_millis {
            if v > 1000 {
                errors.push(ValidationError::OutOfSchemaRange {
                    field: "metrics.pruning_ratio_millis",
                    value: v,
                    max: 1000,
                });
            }
        }
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

    /// Round-18 F1 self-fix: `stop_reason` carries the provider's
    /// NATIVE finish_reason token (documented at
    /// `model.rs::OcsfEvent::stop_reason` and the builder API
    /// `OcsfEventBuilder::stop_reason_native`). Provider-native
    /// captions (OpenAI `"stop"`, Anthropic `"end_turn"`, `"length"`,
    /// `"tool_calls"`, `"content_filter"`, `"function_call"`) plus
    /// `Other`-family free text MUST NOT be flagged as a caption
    /// mismatch even though they differ from the canonical caption.
    #[test]
    fn stop_reason_provider_native_captions_are_accepted() {
        for (id, native) in [
            (1u8, "stop"),
            (1, "end_turn"),
            (1, "stop_sequence"),
            (2, "length"),
            (2, "max_tokens"),
            (3, "tool_calls"),
            (3, "function_call"),
            (3, "tool_use"),
            (90, "content_filter"),
            (99, "provider_specific_free_text"),
        ] {
            let mut ev = valid_event();
            ev.stop_reason_id = Some(id);
            ev.stop_reason = Some(native.to_owned());
            let errs = validate_event(&ev).map(|_| Vec::new()).unwrap_or_else(|e| e);
            assert!(
                !errs
                    .iter()
                    .any(|e| matches!(e, ValidationError::StopReasonCaptionMismatch { .. })),
                "provider-native caption ({id}, {native:?}) must not be flagged, got {errs:?}"
            );
        }
    }

    /// The one shape the check DOES flag: the caption is itself a
    /// canonical caption for a DIFFERENT known variant. `id=93` +
    /// `caption="Loop Detected"` (canonical for id=91) is the
    /// unambiguous cross-wiring case.
    #[test]
    fn stop_reason_cross_wired_captions_are_flagged() {
        let mut ev = valid_event();
        ev.stop_reason_id = Some(93);
        ev.stop_reason = Some("Loop Detected".into());
        let errs = validate_event(&ev).unwrap_err();
        assert!(
            errs.iter()
                .any(|e| matches!(e, ValidationError::StopReasonCaptionMismatch { id: 93, .. })),
            "cross-wired caption must be flagged: {errs:?}"
        );
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

    /// Round-17 F2 regression: the deserialize path bypasses
    /// `OcsfEventBuilder::build`'s JCS-safe integer check, so a
    /// wire event with a token counter above 2^53 would round-trip
    /// through JS-based JSON parsers as silently-truncated,
    /// breaking any receipt hash JS consumers compute over the
    /// event. `validate_event` must flag it on every JCS-safe
    /// carrier field: `time`, `metadata.sequence`, and every
    /// `EventMetrics.*_tokens`.
    #[test]
    fn jcs_unsafe_integer_flagged_on_every_deserialize_carrier() {
        let unsafe_value = av_core::error::JCS_SAFE_MAX + 1;

        // time
        let mut ev = valid_event();
        ev.time = unsafe_value;
        let errs = validate_event(&ev).unwrap_err();
        assert!(
            errs.iter()
                .any(|e| matches!(e, ValidationError::JcsUnsafeInteger { field: "time", .. })),
            "time above JCS_SAFE_MAX must be flagged, got {errs:?}"
        );

        // metadata.sequence
        let mut ev = valid_event();
        ev.metadata.sequence = unsafe_value;
        let errs = validate_event(&ev).unwrap_err();
        assert!(
            errs.iter().any(|e| matches!(
                e,
                ValidationError::JcsUnsafeInteger {
                    field: "metadata.sequence",
                    ..
                }
            )),
            "sequence above JCS_SAFE_MAX must be flagged, got {errs:?}"
        );

        // EventMetrics counters
        for field in [
            "metrics.prompt_tokens",
            "metrics.completion_tokens",
            "metrics.cached_tokens",
            "metrics.pruned_tokens",
            "metrics.pruning_ratio_millis",
        ] {
            let mut ev = valid_event();
            let mut metrics = crate::model::EventMetrics::default();
            match field {
                "metrics.prompt_tokens" => metrics.prompt_tokens = Some(unsafe_value),
                "metrics.completion_tokens" => metrics.completion_tokens = Some(unsafe_value),
                "metrics.cached_tokens" => metrics.cached_tokens = Some(unsafe_value),
                "metrics.pruned_tokens" => metrics.pruned_tokens = Some(unsafe_value),
                "metrics.pruning_ratio_millis" => metrics.pruning_ratio_millis = Some(unsafe_value),
                _ => unreachable!(),
            }
            ev.metrics = Some(metrics);
            let errs = validate_event(&ev).unwrap_err();
            assert!(
                errs.iter().any(|e| matches!(
                    e,
                    ValidationError::JcsUnsafeInteger { field: f, .. } if *f == field
                )),
                "{field} above JCS_SAFE_MAX must be flagged, got {errs:?}"
            );
        }
    }

    /// Round-26 F1 (self-fix from round-27): `validate_event` must
    /// mirror `OcsfEventBuilder::build`'s `pruning_ratio_millis <=
    /// 1000` guard. Round-17 F2 introduced this validator
    /// specifically as the wire-side backstop for build's guards;
    /// leaving the range check only on build left an
    /// emitter/validator drift where an event with a 500%
    /// compression ratio would parse-and-validate but fail the
    /// external JSON schema check downstream.
    #[test]
    fn out_of_schema_pruning_ratio_is_flagged_on_validate() {
        let mut ev = valid_event();
        ev.metrics = Some(crate::model::EventMetrics {
            pruning_ratio_millis: Some(5000),
            ..crate::model::EventMetrics::default()
        });
        let errs = validate_event(&ev).unwrap_err();
        assert!(
            errs.iter().any(|e| matches!(
                e,
                ValidationError::OutOfSchemaRange {
                    field: "metrics.pruning_ratio_millis",
                    value: 5000,
                    max: 1000,
                }
            )),
            "pruning_ratio_millis=5000 must be flagged, got {errs:?}"
        );
        // Boundary: 1000 is accepted.
        ev.metrics = Some(crate::model::EventMetrics {
            pruning_ratio_millis: Some(1000),
            ..crate::model::EventMetrics::default()
        });
        let errs = validate_event(&ev).map(|_| Vec::new()).unwrap_or_else(|e| e);
        assert!(
            !errs
                .iter()
                .any(|e| matches!(e, ValidationError::OutOfSchemaRange { .. })),
            "boundary 1000 must not be flagged, got {errs:?}"
        );
    }

    /// Round-38 F3: activity_id must be < 100 so
    /// `class_uid × 100 + activity_id` is a bijection. Without this
    /// check, `class_uid=9901, activity_id=100` produces the same
    /// type_uid (990200) as `class_uid=9902, activity_id=0`, so
    /// downstream SIEM pipelines routing by type_uid mis-classify.
    /// Not currently reachable via the builder (defaults 1), but the
    /// all-pub, non-`#[non_exhaustive]` struct is mutable directly
    /// (as this test does below), bypassing the builder.
    #[test]
    fn activity_id_100_is_rejected_even_when_type_uid_matches() {
        let mut ev = valid_event();
        ev.activity_id = 100;
        // Keep type_uid self-consistent so the mismatch check
        // doesn't fire — this test isolates the bijection guard.
        ev.type_uid = u64::from(ev.class_name.class_uid()) * 100 + 100;
        let errs = validate_event(&ev).unwrap_err();
        assert!(
            errs.contains(&ValidationError::BadActivityId(100)),
            "activity_id=100 must be flagged even when type_uid matches; got {errs:?}"
        );
        // Boundary: 99 must NOT be flagged.
        ev.activity_id = 99;
        ev.type_uid = u64::from(ev.class_name.class_uid()) * 100 + 99;
        let errs = validate_event(&ev).map(|_| Vec::new()).unwrap_or_else(|e| e);
        assert!(
            !errs
                .iter()
                .any(|e| matches!(e, ValidationError::BadActivityId(_))),
            "activity_id=99 must be valid; got {errs:?}"
        );
    }
}
