//! Cryptographic-attack resilience — primitives, not just artifacts.
//!
//! The state-actor suite fuzzes signed artifacts. This suite attacks the
//! *primitives* our receipt/MAC stack rests on: RFC 8785 JCS determinism,
//! RFC 8032 Ed25519 verification strictness (small-order, non-canonical S,
//! all-zero signatures), base64 alphabet strictness, and the key-id binding
//! between `Receipt.body.key_id` and `Receipt.body.public_key_b64`.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use ab_events::{AgentIdentity, CharterFile};
use ab_receipts::{
    canonicalize, CostSummary, Ed25519Signer, JcsError, Keyring, Receipt, ReceiptBody, ReceiptSubject,
    Signer, ToolCallSummary,
};
use base64::Engine as _;
use serde_json::json;

fn signer() -> Ed25519Signer {
    Ed25519Signer::from_seed([73; 32])
}

fn ring(s: &Ed25519Signer) -> Keyring {
    let mut r = Keyring::new();
    r.add_key_bytes(&Signer::public_key_bytes(s)).unwrap();
    r
}

fn body(session: &str) -> ReceiptBody {
    ReceiptBody {
        receipt_version: 1,
        receipt_id: "rcpt-c".to_owned(),
        session_id: session.to_owned(),
        issued_at: 100,
        issued_at_iso: "1970-01-01T00:00:00.100Z".to_owned(),
        ai_agent: AgentIdentity {
            version: "1".to_owned(),
            charter: CharterFile::from("c"),
            instance_uid: "i".to_owned(),
            ttl_remaining_s: None,
        },
        subject: ReceiptSubject::EventChain {
            chain_head: "aa".repeat(32),
            event_count: 1,
        },
        tool_calls: ToolCallSummary::default(),
        cost: CostSummary::default(),
        stop_reason_id: 1,
        stop_reason: "SessionClosed".to_owned(),
        key_id: String::new(),
        public_key_b64: String::new(),
    }
}

// ---------------------------------------------------------------------------
// 1. JCS determinism: reordered / whitespace-padded input MUST canonicalize
//    to identical bytes. Otherwise an attacker who re-serializes could
//    invalidate a signature on identical logical content or, worse, forge
//    equivalence.
// ---------------------------------------------------------------------------

#[test]
fn jcs_is_deterministic_under_key_reordering_and_whitespace() {
    let v1: serde_json::Value =
        serde_json::from_str(r#"{"b":2,"a":1,"nested":{"z":"z","a":[3,1,2]}}"#).unwrap();
    let v2: serde_json::Value =
        serde_json::from_str(r#" {  "nested" : { "a" : [3, 1, 2] , "z":"z" } , "a":1 , "b":2 }  "#).unwrap();
    let c1 = canonicalize(&v1).unwrap();
    let c2 = canonicalize(&v2).unwrap();
    assert_eq!(c1, c2, "JCS canonicalization drifted under reorder/whitespace");
    assert_eq!(c1, r#"{"a":1,"b":2,"nested":{"a":[3,1,2],"z":"z"}}"#);
}

// ---------------------------------------------------------------------------
// 2. JCS integer safety: integers beyond ±2^53 lose double precision and
//    would corrupt canonical hashes silently. RFC 8785 mandates rejection.
// ---------------------------------------------------------------------------

#[test]
fn jcs_rejects_integers_beyond_ieee754_safe_range() {
    // 2^53 + 1 is not exactly representable as f64.
    let unsafe_int = json!({"n": 9_007_199_254_740_993_u64});
    assert!(matches!(
        canonicalize(&unsafe_int),
        Err(JcsError::UnsafeInteger(_))
    ));
    // 2^53 exactly is at the boundary and MUST be accepted.
    let safe_int = json!({"n": 9_007_199_254_740_992_u64});
    assert!(canonicalize(&safe_int).is_ok());
}

// ---------------------------------------------------------------------------
// 3. Ed25519 all-zero public key: point of order 1 (identity) must be
//    refused by strict verification. The verifier must not accept a
//    signature under the identity element.
// ---------------------------------------------------------------------------

#[test]
fn embedded_all_zero_public_key_is_refused_by_ring() {
    let mut r = Keyring::new();
    // ed25519_dalek accepts the identity point as a valid encoding but any
    // signature verification against it is refused; here we prove that
    // *adding* the all-zero public key either fails (invalid encoding) or
    // yields a ring that cannot verify a real signature.
    let added = r.add_key_bytes(&[0u8; 32]);
    match added {
        Err(_) => {} // preferred outcome: rejected at add time
        Ok(id) => {
            // Otherwise: any signature must fail. Sign something with a real
            // key and try to verify against the id of the identity key.
            let s = signer();
            let sig = s.sign(b"msg");
            assert!(r.verify(&id, b"msg", &sig).is_err());
        }
    }
}

// ---------------------------------------------------------------------------
// 4. Base64 alphabet strictness: STANDARD base64 must NOT accept URL-safe
//    characters ('-','_') or embedded whitespace/newlines when decoding a
//    receipt's signature. RFC 4648 §5 (URL-safe) is a DIFFERENT alphabet.
// ---------------------------------------------------------------------------

#[test]
fn signature_field_rejects_url_safe_base64_and_embedded_whitespace() {
    let s = signer();
    let ring = ring(&s);
    let receipt = Receipt::issue(body("sess-b64"), &s).unwrap();
    // Replace any '+' with '-' and '/' with '_' — URL-safe alphabet.
    let urlsafe: String = receipt
        .signature_b64
        .chars()
        .map(|c| match c {
            '+' => '-',
            '/' => '_',
            other => other,
        })
        .collect();
    if urlsafe != receipt.signature_b64 {
        let mut mutated = receipt.clone();
        mutated.signature_b64 = urlsafe;
        assert!(
            mutated.verify(&ring).is_err(),
            "URL-safe base64 in signature_b64 was accepted"
        );
    }
    // Whitespace injection anywhere in the payload must fail STANDARD decode.
    let mut wsp = receipt.clone();
    let mid = wsp.signature_b64.len() / 2;
    wsp.signature_b64.insert(mid, '\n');
    assert!(
        wsp.verify(&ring).is_err(),
        "embedded newline in signature_b64 was accepted"
    );
}

// ---------------------------------------------------------------------------
// 5. Key-id binding: an attacker who swaps the embedded `public_key_b64`
//    for their own key (while keeping the honest `key_id`) must be caught
//    by the `derived_id != key_id` check inside `Receipt::verify`.
// ---------------------------------------------------------------------------

#[test]
fn embedded_pubkey_swap_is_caught_by_key_id_binding() {
    let honest = signer();
    let attacker = Ed25519Signer::from_seed([9; 32]);
    let ring = ring(&honest);
    let mut receipt = Receipt::issue(body("sess-bind"), &honest).unwrap();
    // Attacker replaces embedded key bytes with their own, but the outer
    // `key_id` still names the honest signer.
    receipt.body.public_key_b64 =
        base64::engine::general_purpose::STANDARD.encode(Signer::public_key_bytes(&attacker));
    assert!(
        receipt.verify(&ring).is_err(),
        "swapped embedded pubkey went undetected"
    );
}

// ---------------------------------------------------------------------------
// 6. Ed25519 signature non-canonical S: RFC 8032 §5.1.7 requires S < L
//    (the group order). Adding L to S produces a bit-different signature
//    that some libraries (pre-strict) would accept — dalek must refuse.
//    We simulate by flipping the high bit of the S half of the signature,
//    which almost certainly makes S ≥ L or off the curve.
// ---------------------------------------------------------------------------

#[test]
fn signature_high_bit_mutation_of_s_half_is_refused() {
    let s = signer();
    let ring = ring(&s);
    let receipt = Receipt::issue(body("sess-s"), &s).unwrap();
    let mut sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(&receipt.signature_b64)
        .unwrap();
    assert_eq!(sig_bytes.len(), 64);
    // Flip the high bit of the last S byte (byte 63).
    sig_bytes[63] ^= 0x80;
    let mut mutated = receipt.clone();
    mutated.signature_b64 = base64::engine::general_purpose::STANDARD.encode(&sig_bytes);
    assert!(
        mutated.verify(&ring).is_err(),
        "non-canonical S signature was accepted"
    );
}

// ---------------------------------------------------------------------------
// 7. Signature over one canonicalized message cannot verify a body that
//    differs only in a semantically-equivalent JCS re-encoding — because
//    JCS is deterministic (test 1) there IS no re-encoding, and any bit
//    change in the canonical bytes changes the signature target. We assert
//    that even reordering keys inside a serialized receipt does NOT
//    invalidate verification (proving the signature binds to canonical
//    content, not lexical form).
// ---------------------------------------------------------------------------

#[test]
fn verifier_accepts_any_lexical_reordering_of_the_same_receipt() {
    let s = signer();
    let ring = ring(&s);
    let receipt = Receipt::issue(body("sess-lex"), &s).unwrap();
    // Reverse the top-level key order (this workspace enables serde_json's
    // preserve_order, so insertion order IS wire order — reversing it
    // genuinely reorders the serialized bytes). The verifier
    // re-canonicalizes, so this MUST still verify.
    let as_value: serde_json::Value = serde_json::to_value(&receipt).unwrap();
    let object = as_value.as_object().unwrap();
    let mut reversed = serde_json::Map::new();
    for (key, value) in object.iter().rev() {
        reversed.insert(key.clone(), value.clone());
    }
    let reserialized = serde_json::to_string(&serde_json::Value::Object(reversed)).unwrap();
    let restored: Receipt = serde_json::from_str(&reserialized).unwrap();
    restored.verify(&ring).expect("lexical reordering broke verify");
}

// ---------------------------------------------------------------------------
// 8. Chain splice: hᵢ = SHA-256(hᵢ₋₁ ‖ JCS(eventᵢ)) has no length prefix,
//    so probe the boundary-shift class: one event whose canonical bytes
//    equal the concatenation of two honest events. JCS syntax makes that
//    concatenation a non-value, and the signed event_count is a second
//    independent binding.
// ---------------------------------------------------------------------------

#[test]
fn chain_boundary_splice_cannot_preserve_head_and_count() {
    use ab_receipts::EventChain;
    let e1 = json!({"seq": 0, "p": "alpha"});
    let e2 = json!({"seq": 1, "p": "beta"});
    let honest = EventChain::compute("s", &[e1.clone(), e2.clone()]).unwrap();
    // The concatenation of two canonical forms must not parse as one value.
    let concat = format!("{}{}", canonicalize(&e1).unwrap(), canonicalize(&e2).unwrap());
    assert!(
        serde_json::from_str::<serde_json::Value>(&concat).is_err(),
        "canonical concatenation parsed as a single JSON value — splice possible"
    );
    // A string event CONTAINING those bytes canonicalizes with quotes and
    // escapes, so its hash input differs.
    let smuggled = json!(concat);
    let spliced = EventChain::compute("s", &[smuggled]).unwrap();
    assert_ne!(spliced.head_hex(), honest.head_hex());
    assert_ne!(spliced.count(), honest.count());
}

// ---------------------------------------------------------------------------
// 9. Genesis concatenation: SHA-256("ab-genesis" ‖ session_id) has no
//    separator — distinct ids must yield distinct heads, and the empty id
//    must still be domain-tagged (not plain SHA-256("")).
// ---------------------------------------------------------------------------

#[test]
fn genesis_concatenation_shift_does_not_collide() {
    use ab_receipts::EventChain;
    let a = EventChain::new("XY");
    let b = EventChain::new("X");
    let c = EventChain::new("Y");
    assert_ne!(a.head_hex(), b.head_hex());
    assert_ne!(a.head_hex(), c.head_hex());
    let empty = EventChain::new("");
    let sha_empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    assert_ne!(empty.head_hex(), sha_empty);
}

// ---------------------------------------------------------------------------
// 10. Unicode normalization confusion: NFC "é" (U+00E9) vs NFD "é"
//     (U+0065 U+0301) are visually identical, different code points. JCS
//     must NOT normalize — a signature over one can never verify the other.
// ---------------------------------------------------------------------------

#[test]
fn unicode_normalization_forms_are_distinct_not_confusable() {
    let s = signer();
    let ring = ring(&s);
    let nfc = "caf\u{e9}";
    let nfd = "cafe\u{301}";
    assert_ne!(nfc, nfd);
    let canon_nfc = canonicalize(&json!({ "s": nfc })).unwrap();
    let canon_nfd = canonicalize(&json!({ "s": nfd })).unwrap();
    assert_ne!(canon_nfc, canon_nfd, "JCS silently normalized Unicode");
    let receipt = Receipt::issue(body(nfc), &s).unwrap();
    let mut raw = serde_json::to_value(&receipt).unwrap();
    raw["session_id"] = json!(nfd);
    let forged: Receipt = serde_json::from_value(raw).unwrap();
    assert!(
        forged.verify(&ring).is_err(),
        "NFD look-alike session id verified against NFC signature"
    );
}

// ---------------------------------------------------------------------------
// 11. Duplicate-key smuggling (parser-differential class, cf. JWS/JOSE
//     duplicate-header attacks): JSON carrying both
//     "session_id":"attacker" and "session_id":"honest" must not let our
//     verifier see one value while a first-wins downstream parser sees the
//     other.
// ---------------------------------------------------------------------------

#[test]
fn duplicate_json_keys_cannot_smuggle_a_second_session_id() {
    let s = signer();
    let ring = ring(&s);
    let receipt = Receipt::issue(body("honest"), &s).unwrap();
    let serialized = serde_json::to_string(&receipt).unwrap();
    // Duplicate BEFORE the honest value: first-wins parsers see "attacker".
    let injected = serialized.replacen(
        "\"session_id\":\"honest\"",
        "\"session_id\":\"attacker\",\"session_id\":\"honest\"",
        1,
    );
    assert_ne!(injected, serialized, "injection point not found");
    match serde_json::from_str::<Receipt>(&injected) {
        // Preferred: duplicate field refused outright.
        Err(_) => {}
        Ok(parsed) => {
            // If parsed, verification must bind to the parsed value — the
            // only verifying parse is the honest one.
            if parsed.verify(&ring).is_ok() {
                assert_eq!(
                    parsed.body.session_id, "honest",
                    "verifier accepted a parse whose session_id differs from the signed one"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 12. Base64 string malleability: several base64 strings can decode to the
//     same bytes (non-zero trailing bits in the final data char). What must
//     NEVER happen is a variant decoding to DIFFERENT bytes and verifying.
// ---------------------------------------------------------------------------

#[test]
fn base64_trailing_bit_variants_never_verify_with_different_bytes() {
    let s = signer();
    let ring = ring(&s);
    let receipt = Receipt::issue(body("sess-mall"), &s).unwrap();
    let honest_bytes = base64::engine::general_purpose::STANDARD
        .decode(&receipt.signature_b64)
        .unwrap();
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    // 64-byte signature → "…xx==": the char before "==" carries 4 spare bits.
    let chars: Vec<char> = receipt.signature_b64.chars().collect();
    let variable_idx = chars.len() - 3;
    for &candidate in ALPHABET {
        let candidate = candidate as char;
        if candidate == chars[variable_idx] {
            continue;
        }
        let mut variant = chars.clone();
        variant[variable_idx] = candidate;
        let variant: String = variant.into_iter().collect();
        let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(&variant) else {
            continue; // strict decode refused — fine
        };
        if decoded == honest_bytes {
            continue; // identical bytes — benign
        }
        let mut mutated = receipt.clone();
        mutated.signature_b64 = variant;
        assert!(
            mutated.verify(&ring).is_err(),
            "base64 variant decoding to different bytes verified"
        );
    }
}

// ---------------------------------------------------------------------------
// 13. Small-order public key through the FULL verify path: embed a
//     small-order point (torsion subgroup) as the receipt's public key.
//     Signatures under such keys are trivially forgeable for ANY message —
//     the ring must refuse the key or the key-id binding must break the
//     forgery.
// ---------------------------------------------------------------------------

#[test]
fn small_order_embedded_public_key_cannot_authenticate_a_receipt() {
    let honest = signer();
    let ring = ring(&honest);
    // Canonical encodings of small-order points (identity and the
    // order-2/order-4 torsion points).
    let small_order_points: [[u8; 32]; 3] = [
        // identity
        {
            let mut p = [0u8; 32];
            p[0] = 1;
            p
        },
        // order-4 point (y = 0): the all-zero encoding
        [0u8; 32],
        // order-2 point (0, -1): y = p - 1 = 2^255 - 20, sign bit clear
        {
            let mut p = [0u8; 32];
            p[0] = 0xec;
            for byte in p.iter_mut().skip(1).take(30) {
                *byte = 0xff;
            }
            p[31] = 0x7f;
            p
        },
    ];
    for (i, point) in small_order_points.iter().enumerate() {
        let mut receipt = Receipt::issue(body("sess-torsion"), &honest).unwrap();
        receipt.body.public_key_b64 = base64::engine::general_purpose::STANDARD.encode(point);
        // Forged all-zero signature under the small-order key.
        receipt.signature_b64 = base64::engine::general_purpose::STANDARD.encode([0u8; 64]);
        assert!(
            receipt.verify(&ring).is_err(),
            "small-order point {i} authenticated a receipt"
        );
        assert!(
            receipt.verify_embedded().is_err(),
            "small-order point {i} authenticated via verify_embedded"
        );
    }
}

// ---------------------------------------------------------------------------
// 14. SHA-256 length-extension on the event chain: SHA-256 is
//     length-extensible for `H(secret ‖ m)`, but our chain reveals no secret
//     — `head_i` IS the extension target and `head_i` is public. An attacker
//     who knows `head_i` and its input length can compute
//     `H(head_i_input ‖ pad ‖ extra)` for any `extra`; to weaponize it into
//     a valid `head_{i+1}` they would need the SHA-256 padding bytes
//     (0x80, zeros, big-endian length) to appear as a valid canonical event
//     bytestring. JCS starts with '"', '{', '[', 't', 'f', 'n', '-' or a
//     digit; 0x80 is not a valid JSON start byte, so no valid event can
//     begin with the extension pad.
// ---------------------------------------------------------------------------

#[test]
fn sha256_length_extension_padding_is_not_a_valid_event_prefix() {
    // SHA-256 MD-strengthening padding begins with 0x80.
    let pad_byte: u8 = 0x80;
    // Every legal JCS event start byte.
    let starts: &[u8] = b"\"{[tfn-0123456789";
    for &start in starts {
        assert_ne!(
            pad_byte, start,
            "SHA-256 pad byte collides with legal JCS event start {start:#x}"
        );
    }
    // And an event whose canonical form starts with 0x80 cannot exist —
    // canonicalize gives quoted-string form, whose first byte is '"'.
    let evil = json!("\u{80}payload");
    let canon = canonicalize(&evil).unwrap();
    assert_eq!(canon.as_bytes()[0], b'"');
}

// ---------------------------------------------------------------------------
// 15. RFC 8785 §3.2.3 mandates UTF-16 code-unit ordering for object keys,
//     which differs from Unicode codepoint ordering for supplementary-plane
//     characters (they sit above U+FFFF in codepoints but below U+E000 in
//     UTF-16 surrogate encoding). A verifier that sorted by codepoint
//     instead of UTF-16 would produce different canonical bytes on the same
//     receipt — an offline forgery-equivalent bug.
// ---------------------------------------------------------------------------

#[test]
fn jcs_key_ordering_uses_utf16_code_units_not_codepoints() {
    // Key "𝄞" (U+1D11E, MUSICAL SYMBOL G CLEF) — codepoint > 0xE000, but
    // its UTF-16 encoding starts with the high surrogate 0xD834 < 0xE000.
    let obj = json!({ "\u{1d11e}": 1, "\u{e000}": 2 });
    let canon = canonicalize(&obj).unwrap();
    let idx_music = canon.find("\"\u{1d11e}\"").expect("music symbol key present");
    let idx_pua = canon.find("\"\u{e000}\"").expect("PUA key present");
    // UTF-16 order: 0xD834 < 0xE000, so the music symbol key must sort FIRST.
    assert!(
        idx_music < idx_pua,
        "JCS key order is codepoint-based, not UTF-16 (RFC 8785 §3.2.3)"
    );
}

// ---------------------------------------------------------------------------
// 16. Trailing garbage after a receipt JSON must be refused. serde_json's
//     `from_slice` rejects trailing non-whitespace after a complete value
//     ("trailing characters") — lock that in so an attacker cannot smuggle
//     a second document behind a valid receipt.
// ---------------------------------------------------------------------------

#[test]
fn trailing_garbage_after_receipt_json_is_refused() {
    let s = signer();
    let receipt = Receipt::issue(body("sess-tg"), &s).unwrap();
    let mut serialized = serde_json::to_vec(&receipt).unwrap();
    serialized.extend_from_slice(b"{\"attacker\":true}");
    assert!(
        serde_json::from_slice::<Receipt>(&serialized).is_err(),
        "serde_json accepted trailing garbage after a receipt"
    );
}

// ---------------------------------------------------------------------------
// 17. Unknown extra fields on the wire: forward-compat requires them to
//     round-trip through parsing, but they MUST NOT influence verification.
//     An attacker adding "admin":true to a signed receipt must not cause
//     verify to see the field (serde drops unknowns for our struct), and
//     the receipt must still verify identically.
// ---------------------------------------------------------------------------

#[test]
fn unknown_wire_fields_do_not_participate_in_verification() {
    let s = signer();
    let ring = ring(&s);
    let receipt = Receipt::issue(body("sess-fwd"), &s).unwrap();
    let mut raw: serde_json::Value = serde_json::to_value(&receipt).unwrap();
    raw.as_object_mut()
        .unwrap()
        .insert("admin".to_owned(), json!(true));
    let restored: Receipt = serde_json::from_value(raw).unwrap();
    restored.verify(&ring).expect("unknown field broke verify");
    // After round-trip through the struct, the field is gone: it never had
    // a chance to influence any signed logic.
    let round_tripped: serde_json::Value = serde_json::to_value(&restored).unwrap();
    assert!(
        !round_tripped.as_object().unwrap().contains_key("admin"),
        "unknown field survived into the verified receipt"
    );
}

// ---------------------------------------------------------------------------
// 18. Journal control-key derivation: `control_key_from_signer` must be
//     deterministic per signer, distinct across signers, and must NOT
//     equal the signer's public key bytes (i.e., the MAC key is not the
//     signer's identity).
// ---------------------------------------------------------------------------

#[test]
fn control_key_derivation_is_deterministic_and_signer_separated() {
    let a1 = Ed25519Signer::from_seed([5; 32]);
    let a2 = Ed25519Signer::from_seed([5; 32]);
    let b = Ed25519Signer::from_seed([6; 32]);
    let k_a1 = ab_harness::control_key_from_signer(&a1);
    let k_a2 = ab_harness::control_key_from_signer(&a2);
    let k_b = ab_harness::control_key_from_signer(&b);
    assert_eq!(k_a1, k_a2, "same seed yielded different control keys");
    assert_ne!(k_a1, k_b, "different seeds produced identical control keys");
    // The derived key must not equal the signer's public key bytes: the
    // public key is broadcast, but the control key is the deployment-local
    // HMAC secret. Reusing it as the MAC key would leak the MAC secret.
    assert_ne!(
        k_a1,
        Signer::public_key_bytes(&a1),
        "control key equals public key — MAC key is not secret"
    );
}

// ---------------------------------------------------------------------------
// 19. RFC 8032 Ed25519 is DETERMINISTIC: signing the same message under
//     the same key produces the same signature bytes. This eliminates the
//     nonce-reuse class of ECDSA attacks (broken by static-k Sony PS3, etc.)
//     and lets us assert byte-for-byte reproducibility.
// ---------------------------------------------------------------------------

#[test]
fn ed25519_signatures_are_deterministic_no_nonce_reuse_surface() {
    let s = signer();
    let msg = b"agentbridge-crypto-canary";
    let sig_a = s.sign(msg);
    let sig_b = s.sign(msg);
    assert_eq!(sig_a, sig_b, "Ed25519 signing was non-deterministic");
    // Two receipts over identical bodies also match byte-for-byte.
    let r1 = Receipt::issue(body("sess-det"), &s).unwrap();
    let r2 = Receipt::issue(body("sess-det"), &s).unwrap();
    assert_eq!(
        r1.signature_b64, r2.signature_b64,
        "receipt signatures diverged for identical inputs"
    );
}

// ---------------------------------------------------------------------------
// 20. Receipt-vs-embedded-object domain confusion: a signature over the
//     JCS bytes of a bare `ReceiptSubject` value must NOT verify a full
//     receipt that happens to embed that subject, because the receipt's
//     JCS bytes are a superset (contain surrounding object braces + other
//     signed fields). No sub-message forgery is possible.
// ---------------------------------------------------------------------------

#[test]
fn signature_over_inner_value_does_not_verify_outer_receipt() {
    let s = signer();
    let ring = ring(&s);
    // Sign just the subject JSON (the bytes an attacker might extract from a
    // decoded receipt) and try to pass the resulting sig as a receipt sig.
    let subject_only = json!({
        "chain_head": "aa".repeat(32),
        "event_count": 1,
    });
    let canon_subject = canonicalize(&subject_only).unwrap();
    let inner_sig = s.sign(canon_subject.as_bytes());
    let mut receipt = Receipt::issue(body("sess-inner"), &s).unwrap();
    receipt.signature_b64 = base64::engine::general_purpose::STANDARD.encode(inner_sig);
    assert!(
        receipt.verify(&ring).is_err(),
        "sub-message signature verified against the full receipt"
    );
}

// ---------------------------------------------------------------------------
// 21. Ed25519 point validation: 32-byte encodings that decode to a
//     y-coordinate ≥ p (2^255 - 19) are invalid per RFC 8032 §5.1.3.
//     dalek's `VerifyingKey::from_bytes` must refuse them, so
//     `Keyring::add_key_bytes` bubbles up `KeyError::InvalidKey`.
// ---------------------------------------------------------------------------

#[test]
fn ed25519_point_encoding_with_y_geq_p_is_refused_by_ring() {
    let mut r = Keyring::new();
    // y = 2^255 - 18 > p = 2^255 - 19: high bit set, low byte carries the
    // "+1" that pushes y past p. This is an invalid Edwards encoding.
    let mut invalid = [0xffu8; 32];
    invalid[0] = 0xee;
    invalid[31] = 0x7f;
    let outcome = r.add_key_bytes(&invalid);
    // Either the ring rejects at add time, or a subsequent verify against
    // it must fail — both are acceptable outcomes for a malformed point.
    match outcome {
        Err(_) => {}
        Ok(id) => {
            let s = signer();
            let sig = s.sign(b"msg");
            assert!(
                r.verify(&id, b"msg", &sig).is_err(),
                "verify succeeded under an invalid (y ≥ p) public key"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 22. Chain replay: appending the same event twice must yield a head
//     distinct from appending it once. If the chain were idempotent under
//     duplicates, an attacker could replay events without moving the head,
//     letting them break the `event_count` binding silently.
// ---------------------------------------------------------------------------

#[test]
fn chain_is_not_idempotent_under_duplicate_events() {
    use ab_receipts::EventChain;
    let e = json!({"seq": 0, "p": "same"});
    let once = EventChain::compute("s", std::slice::from_ref(&e)).unwrap();
    let twice = EventChain::compute("s", &[e.clone(), e]).unwrap();
    assert_ne!(once.head_hex(), twice.head_hex());
    assert_eq!(twice.count(), once.count() + 1);
}
