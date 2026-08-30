//! VERIFYING-A-RECEIPT.md truth pins (R281). The doc's §5 Rust snippet
//! shipped for months with an INVERTED receiver (`ring.verify(&receipt)`)
//! and a `Vec<u8>` passed where `add_key_bytes` takes `&[u8; 32]` — it
//! never compiled. These tests couple the doc to the real API in both
//! directions: the documented call shape is EXECUTED against a real
//! signed receipt, and the doc text is parsed to assert it still shows
//! that exact shape (an API rename or a doc edit each fail loudly).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use av_receipts::{
    signing_message, CostSummary, Ed25519Signer, Keyring, Receipt, ReceiptBody, ReceiptSubject,
    Signer, ToolCallSummary, RECEIPT_DOMAIN_TAG_V2,
};

const DOC: &str = include_str!("../../../docs/reference/VERIFYING-A-RECEIPT.md");

fn signed_v2_receipt_json() -> (String, String) {
    let signer = Ed25519Signer::from_seed(&[42u8; 32]);
    let body = ReceiptBody {
        receipt_version: 2,
        receipt_id: "rcpt-doc-0001".to_owned(),
        session_id: "audit-doc-session".to_owned(),
        issued_at: 1_700_000_000_000,
        issued_at_iso: "2023-11-14T22:13:20.000Z".to_owned(),
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
    let pubkey_hex = hex::encode(signer.public_key_bytes());
    (json, pubkey_hex)
}

/// §5 EXECUTED: the exact sequence the doc shows, line for line —
/// parse with serde_json, decode the hex key into `[u8; 32]`, pin it
/// with `Keyring::add_key_bytes`, verify with `receipt.verify(&ring)`.
/// If any of these signatures change shape, update the doc's snippet
/// in the same commit this test forces you to touch.
#[test]
fn section_5_snippet_sequence_executes_against_the_real_api() {
    let (json, trusted_public_key_hex) = signed_v2_receipt_json();

    let bytes = json.into_bytes();
    let receipt: Receipt = serde_json::from_slice(&bytes).unwrap();

    let mut ring = Keyring::new();
    let key: [u8; 32] = hex::decode(trusted_public_key_hex)
        .unwrap()
        .try_into()
        .expect("trusted key must be 32 bytes");
    ring.add_key_bytes(&key).unwrap();

    receipt.verify(&ring).expect("documented sequence verifies");
}

/// §5 TEXT: the doc's rust block must show the shape the test above
/// executes — and must never regress to the inverted receiver that
/// shipped broken (`ring.verify(&receipt)` / raw Vec into
/// `add_key_bytes`).
#[test]
fn section_5_snippet_text_matches_the_executed_shape() {
    let snippet = DOC
        .split("```rust")
        .nth(1)
        .expect("§5 rust block present")
        .split("```")
        .next()
        .unwrap();
    for needle in [
        "use av_receipts::{Keyring, Receipt};",
        "let receipt: Receipt = serde_json::from_slice(&bytes)?;",
        "let key: [u8; 32] = hex::decode(trusted_public_key_hex)?",
        "ring.add_key_bytes(&key)?;",
        "receipt.verify(&ring)?;",
    ] {
        assert!(
            snippet.contains(needle),
            "VERIFYING-A-RECEIPT.md §5 snippet lost the load-bearing line \
             {needle:?} — it must show exactly what \
             section_5_snippet_sequence_executes_against_the_real_api runs"
        );
    }
    assert!(
        !snippet.contains("ring.verify(&receipt)"),
        "§5 snippet regressed to the inverted receiver that never compiled"
    );
}

/// §5a: the reimplementation prose pins exact protocol bytes. The
/// domain-tag hex the doc prints, the tag length it states, and the
/// "13 remaining top-level fields" count must all match the code.
#[test]
fn section_5a_protocol_facts_match_the_code() {
    // The doc spells the tag twice: as ASCII-with-NUL prose and as hex.
    assert!(
        DOC.contains(&hex::encode(RECEIPT_DOMAIN_TAG_V2)),
        "§5a domain-tag hex must equal hex(RECEIPT_DOMAIN_TAG_V2)"
    );
    assert!(
        DOC.contains(&format!("the {}-byte domain tag", RECEIPT_DOMAIN_TAG_V2.len())),
        "§5a states the domain-tag byte length; keep it equal to the constant's"
    );

    // Signed-field count: serialize a receipt, drop signature_b64.
    let (json, _) = signed_v2_receipt_json();
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    let object = value.as_object().unwrap();
    assert!(object.contains_key("signature_b64"));
    let signed_fields = object.len() - 1;
    assert_eq!(
        signed_fields, 13,
        "receipt gained/lost a top-level field — update §5a's \"all 13 \
         remaining top-level fields\" sentence AND the reimplementation notes"
    );
    assert!(DOC.contains("all 13 remaining top-level"));

    // Framing: tag || u64 BE length || canon, exactly as documented.
    let canon = r#"{"probe":true}"#;
    let message = signing_message(2, canon).unwrap();
    let mut expected = RECEIPT_DOMAIN_TAG_V2.to_vec();
    expected.extend_from_slice(&(canon.len() as u64).to_be_bytes());
    expected.extend_from_slice(canon.as_bytes());
    assert_eq!(message, expected, "§5a v2 framing description drifted");
    assert_eq!(signing_message(1, canon).unwrap(), canon.as_bytes(), "§5a v1 framing");
    assert!(signing_message(3, canon).is_err(), "§5a: unknown versions refused");
}

/// §4: "the receipt's `key_id` … the first 32 hex characters of the
/// SHA-256 digest of the raw 32-byte public key".
#[test]
fn section_4_key_id_derivation_matches_the_doc() {
    use sha2::{Digest, Sha256};
    let signer = Ed25519Signer::from_seed(&[42u8; 32]);
    let derived = hex::encode(Sha256::digest(signer.public_key_bytes()));
    assert_eq!(signer.key_id(), &derived[..32]);
    assert!(DOC.contains("first 32 hex characters of the SHA-256 digest"));
}
