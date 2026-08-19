//! Signature-coverage property: every byte-level mutation of a signed
//! receipt's JSON that still parses as a `Receipt` and differs from the
//! original must fail verification. A passing mutant would mean some field
//! is outside the signature's coverage (malleability).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use av_receipts::{CostSummary, Ed25519Signer, Receipt, ReceiptBody, ReceiptSubject, ToolCallSummary};
use proptest::prelude::*;

fn signed_receipt() -> (Receipt, String) {
    let signer = Ed25519Signer::from_seed(&[7u8; 32]);
    let body = ReceiptBody {
        receipt_version: 1,
        receipt_id: "rcpt-0001".to_owned(),
        session_id: "sess-0001".to_owned(),
        issued_at: 1_700_000_000_000,
        issued_at_iso: "2023-11-14T22:13:20Z".to_owned(),
        ai_agent: av_events::AgentIdentity {
            version: "1.0".to_owned(),
            charter: "billing".to_owned().into(),
            instance_uid: "instance-1".to_owned(),
            ttl_remaining_s: Some(600),
        },
        subject: ReceiptSubject::EventChain {
            chain_head: "ab".repeat(32),
            event_count: 7,
        },
        tool_calls: ToolCallSummary {
            total: 3,
            allowed: 2,
            blocked: 1,
        },
        cost: CostSummary {
            prompt_tokens: 100,
            completion_tokens: 50,
            cached_tokens: 10,
            cost_usd_micros: 1234,
        },
        stop_reason_id: 1,
        stop_reason: "stop".to_owned(),
        key_id: String::new(),
        public_key_b64: String::new(),
    };
    let receipt = Receipt::issue(body, &signer).unwrap();
    let json = serde_json::to_string(&receipt).unwrap();
    (receipt, json)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(8192))]

    /// Mutate one byte of the serialized receipt. If the mutant still
    /// parses as a Receipt and is not byte-identical in re-serialized
    /// form, verification must fail — no field may escape signature
    /// coverage.
    #[test]
    fn any_effective_single_byte_mutation_fails_verification(
        index in any::<prop::sample::Index>(),
        replacement in 0u8..=255,
    ) {
        let (original, json) = signed_receipt();
        let bytes = json.as_bytes();
        let index = index.index(bytes.len());
        let mut mutated = bytes.to_vec();
        if mutated[index] == replacement {
            return Ok(()); // no-op mutation
        }
        mutated[index] = replacement;
        let Ok(mutant) = Receipt::from_json_slice(&mutated) else {
            return Ok(()); // parse-rejected mutants are fine
        };
        if mutant == original {
            return Ok(()); // semantically identical (e.g. whitespace-level)
        }
        prop_assert!(
            mutant.verify_embedded().is_err(),
            "mutated receipt verified: byte {index} -> {replacement:#04x}"
        );
    }
}
