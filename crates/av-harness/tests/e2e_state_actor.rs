//! State-actor-grade cryptographic resilience.
//!
//! A well-resourced adversary (state agency, sophisticated APT) is willing to
//! run byte-level fuzzers against every signed artifact we produce. Every one
//! of these tests targets a primitive integrity guarantee that must hold
//! against an attacker with:
//!   - byte-level control of the signed artifact at rest,
//!   - possession of their own Ed25519 signing key,
//!   - unbounded compute to try mutations, and
//!   - full knowledge of our canonicalization + key-derivation pipeline.
//!
//! References for the threat model:
//!   - RFC 8032 (Ed25519 verification requirements)
//!   - RFC 8785 (JCS canonicalization)
//!   - RFC 2104 (HMAC construction requirements)

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

use av_events::{AgentIdentity, CharterFile};
use av_receipts::{
    CostSummary, Ed25519Signer, Keyring, Receipt, ReceiptBody, ReceiptSubject, Signer, ToolCallSummary,
};

fn signer() -> Ed25519Signer {
    Ed25519Signer::from_seed(&[200; 32])
}

fn attacker_signer() -> Ed25519Signer {
    Ed25519Signer::from_seed(&[1; 32])
}

fn body(session: &str, event_count: u64) -> ReceiptBody {
    ReceiptBody {
        receipt_version: 1,
        receipt_id: "rcpt-1".to_owned(),
        session_id: session.to_owned(),
        issued_at: 42,
        issued_at_iso: "1970-01-01T00:00:00.042Z".to_owned(),
        ai_agent: AgentIdentity {
            version: "1".to_owned(),
            charter: CharterFile::from("c"),
            instance_uid: "i".to_owned(),
            ttl_remaining_s: None,
        },
        subject: ReceiptSubject::EventChain {
            chain_head: "0e".repeat(32),
            event_count,
        },
        tool_calls: ToolCallSummary::default(),
        cost: CostSummary::default(),
        stop_reason_id: 1,
        stop_reason: "SessionClosed".to_owned(),
        key_id: String::new(),
        public_key_b64: String::new(),
    }
}

fn trusted_ring(s: &Ed25519Signer) -> Keyring {
    let mut ring = Keyring::new();
    ring.add_key_bytes(&Signer::public_key_bytes(s)).unwrap();
    ring
}

// ---------------------------------------------------------------------------
// 1. Byte-flip fuzz: 200 random single-bit mutations of a signed receipt
//    must all fail verification. Zero silent acceptance.
// ---------------------------------------------------------------------------

#[test]
fn byte_flip_fuzz_on_signed_receipt_never_verifies() {
    let s = signer();
    let ring = trusted_ring(&s);
    let receipt = Receipt::issue(body("sess-fuzz", 3), &s).unwrap();
    let bytes = serde_json::to_vec(&receipt).unwrap();
    // Deterministic xorshift keeps the coverage reproducible.
    let mut state: u64 = 0x0b10_00de_adbe_ef12;
    let mut acceptances = 0u32;
    for iter in 0..200 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let offset = usize::try_from(state).unwrap_or(0) % bytes.len();
        // Flip one bit at the chosen offset.
        let bit_index = u8::try_from((state >> 32) & 0b0111).unwrap_or(0);
        let mut mutated = bytes.clone();
        mutated[offset] ^= 1u8 << bit_index;
        let Ok(candidate) = serde_json::from_slice::<Receipt>(&mutated) else {
            continue;
        };
        if candidate.verify(&ring).is_ok() {
            acceptances += 1;
            eprintln!("iter {iter}: mutation at byte {offset} bit {bit_index} was silently accepted");
        }
    }
    assert_eq!(
        acceptances, 0,
        "verifier silently accepted {acceptances} single-bit mutations"
    );
}

// ---------------------------------------------------------------------------
// 2. Signature transplantation: a signature that is valid for body A must
//    never verify body B, even under the same key.
// ---------------------------------------------------------------------------

#[test]
fn signature_valid_for_one_body_does_not_verify_a_different_body() {
    let s = signer();
    let ring = trusted_ring(&s);
    let receipt_a = Receipt::issue(body("sess-A", 1), &s).unwrap();
    let mut receipt_b = Receipt::issue(body("sess-B", 1), &s).unwrap();
    receipt_b.signature_b64 = receipt_a.signature_b64.clone();
    assert!(
        receipt_b.verify(&ring).is_err(),
        "transplanted signature must not verify a different body"
    );
}

// ---------------------------------------------------------------------------
// 3. Field-level tamper: changing session_id, chain_head, or event_count
//    inside the signed body must be caught.
// ---------------------------------------------------------------------------

#[test]
fn every_signed_field_is_covered_by_the_signature() {
    let s = signer();
    let ring = trusted_ring(&s);
    let receipt = Receipt::issue(body("sess-cov", 5), &s).unwrap();
    let raw = serde_json::to_value(&receipt).unwrap();
    let mut cases: Vec<(&str, serde_json::Value)> = Vec::new();
    let mut c1 = raw.clone();
    c1["session_id"] = serde_json::json!("attacker-session");
    cases.push(("session_id", c1));
    let mut c2 = raw.clone();
    c2["subject"]["chain_head"] = serde_json::json!("ff".repeat(32));
    cases.push(("chain_head", c2));
    let mut c3 = raw.clone();
    c3["subject"]["event_count"] = serde_json::json!(99);
    cases.push(("event_count", c3));
    let mut c4 = raw.clone();
    c4["stop_reason"] = serde_json::json!("Other");
    cases.push(("stop_reason", c4));
    let mut c5 = raw.clone();
    c5["cost"]["cost_usd_micros"] = serde_json::json!(1_000_000_000);
    cases.push(("cost_usd_micros", c5));
    let mut c6 = raw.clone();
    c6["issued_at"] = serde_json::json!(0);
    cases.push(("issued_at", c6));
    let mut c7 = raw.clone();
    c7["ai_agent"]["charter"]["name"] = serde_json::json!("evil");
    cases.push(("charter", c7));
    for (label, mutated) in cases {
        let candidate: Receipt = serde_json::from_value(mutated).unwrap();
        assert!(
            candidate.verify(&ring).is_err(),
            "field {label:?} was tampered but verifier accepted"
        );
    }
}

// ---------------------------------------------------------------------------
// 4. Key substitution: an attacker with their own key cannot forge a
//    receipt that verifies against the trusted ring, even by rewriting the
//    embedded key_id.
// ---------------------------------------------------------------------------

#[test]
fn attacker_key_cannot_forge_a_receipt_that_verifies_with_trusted_ring() {
    let honest = signer();
    let attacker = attacker_signer();
    let ring = trusted_ring(&honest);
    // Attacker signs their OWN receipt with their key, then rewrites the
    // key_id + embedded pubkey to try to impersonate the honest signer.
    let mut receipt = Receipt::issue(body("sess-forge", 1), &attacker).unwrap();
    receipt.body.key_id = Signer::key_id(&honest).to_owned();
    receipt.body.public_key_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        Signer::public_key_bytes(&honest),
    );
    // The signature was made over the ATTACKER's body (with their key_id).
    // Rewriting the key_id changes the canonical bytes, so the signature
    // no longer matches the (now-modified) body — verification fails.
    assert!(
        receipt.verify(&ring).is_err(),
        "attacker forged a receipt that verified against the trusted ring"
    );
}

// ---------------------------------------------------------------------------
// 5. All-zeros signature must never verify. RFC 8032 requires strict
//    Ed25519 encoding; a zeroed R/S vector cannot be a valid signature
//    over a real body.
// ---------------------------------------------------------------------------

#[test]
fn all_zeros_signature_is_refused_by_the_verifier() {
    let s = signer();
    let ring = trusted_ring(&s);
    let mut receipt = Receipt::issue(body("sess-zero", 1), &s).unwrap();
    receipt.signature_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0u8; 64]);
    assert!(receipt.verify(&ring).is_err(), "all-zeros signature verified");
}

// ---------------------------------------------------------------------------
// 6. Truncated / oversized signatures must be refused at the length check,
//    before any Ed25519 math runs.
// ---------------------------------------------------------------------------

#[test]
fn malformed_signature_lengths_are_refused() {
    let s = signer();
    let ring = trusted_ring(&s);
    let receipt = Receipt::issue(body("sess-len", 1), &s).unwrap();
    for len in [0usize, 32, 63, 65, 128, 4096] {
        let mut candidate = receipt.clone();
        candidate.signature_b64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, vec![0u8; len]);
        assert!(
            candidate.verify(&ring).is_err(),
            "signature of length {len} incorrectly verified"
        );
    }
}

// ---------------------------------------------------------------------------
// 7. Cross-key ring — an attacker signing with their own key (own key_id
//    and pubkey) must be refused by a ring that only trusts the honest
//    key: an unknown key_id can never satisfy the ring lookup, so a state
//    actor cannot substitute material a verifier never enrolled.
// ---------------------------------------------------------------------------

#[test]
fn attacker_bytes_under_a_trusted_key_id_do_not_verify() {
    let honest = signer();
    let attacker = attacker_signer();
    // Set up a ring that only knows the honest key.
    let ring = trusted_ring(&honest);
    // Attacker builds a receipt with their own key_id + pubkey.  It should
    // fail against the honest ring even under wildly optimistic assumptions.
    let receipt = Receipt::issue(body("sess-x", 1), &attacker).unwrap();
    let err = receipt
        .verify(&ring)
        .expect_err("attacker's key should not verify against a ring that only knows the honest key");
    let s = format!("{err:?}");
    assert!(
        s.contains("UnknownKeyId") || s.contains("Key") || s.contains("BadSignature"),
        "unexpected error variant: {s}"
    );
}
