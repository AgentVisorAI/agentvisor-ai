# Verifying an AgentVisor AI Receipt Offline

An AgentVisor AI receipt is a JSON document containing an audit chain
subject and an Ed25519 signature over the canonical (RFC 8785 JCS) form
of that subject. Anyone with the harness's public key can verify a
receipt without contacting the harness — this is the cryptographic
audit posture the deployment is built around.

This guide walks through the offline verification path end to end.

## 1. Obtain the trusted public key

Two supported channels, ordered by trust:

1. **From the operator directly.** The operator ran
   `avctl pubkey --seed /path/to/seed` on the host where the signer
   lives and copied the JSON output to you out of band (Slack DM,
   signed email, a manual filesystem copy over SSH). Only the
   `public_key_hex` field matters:

   ```
   $ avctl pubkey --seed /var/lib/agentvisor/signer.seed
   {"key_id":"a74…","public_key_hex":"7d2b60…","seed_file":"…"}
   ```

2. **From the harness startup banner.** Every process logs
   `signer_key_id` and `signer_public_key_hex` at INFO on start. Pull
   these from your log store; check both the `key_id` you're pinning
   *and* the full `public_key_hex` — a `key_id` alone is only a
   32-hex-char fingerprint of the encoded key and would collide under
   a first-preimage attack against SHA-256, whereas the raw public
   key is the actual verification input.

Never derive the trusted public key from the receipt itself. A
tampered receipt could carry a public key it forged a signature
against; the whole point of an out-of-band key exchange is to break
that loop.

## 2. Locate the receipt for a session

Spool filenames are `sha256(session_id)[..32]` — not the session id
itself (ids never touch the filesystem). Use the lookup command:

```
$ avctl receipt-locate my-session-id --spool /var/lib/agentvisor/spool/atif
{"session_id":"my-session-id","stem":"34655f…","artifacts":{"receipt":{"path":"…/receipts/34655f….json","exists":true},…},"archived_prior_incarnations":[]}
```

It reports every artifact class for the stem: the receipt
(`receipts/{stem}.json`), the ATIF trajectory (`{stem}.json`), its
provenance sidecar (`{stem}.atif-auth`), and any live journals.

**One session id can have many receipts.** A client reusing a
completed session's id starts a NEW incarnation; the prior
incarnation's artifact is renamed to `{stem}.archived-<uid>…` rather
than overwritten, and `receipt-locate` lists these under
`archived_prior_incarnations`. When auditing a specific conversation,
match on the receipt's `issued_at`/`subject.event_count`, not on the
session id alone.

## 3. Run `avctl receipt-verify`

```
$ avctl receipt-verify path/to/receipt.json \
    --public-key-hex 7d2b60851d57106aed8bd9bae69efd35f0c41c56bfd3096d327bbe31c9baa19f

`--public-key-hex` is repeatable — pin both the retiring and the
incoming key during a rotation window; the receipt's `key_id` selects
which one verifies it. Keys are accepted in hex (what `avctl pubkey`
and the startup banner print) or standard base64 (what the receipt's
`public_key_b64` field carries).
```

The command:

* parses the receipt JSON
* extracts the `signature` and `subject` fields
* canonicalises `subject` with RFC 8785 JCS
* runs `ed25519_dalek::VerifyingKey::verify_strict` against the
  canonical bytes with the trusted key you passed
* prints `verified <receipt_id>` on success (inspect the receipt JSON
  itself for key_id, stop_reason, and event_count — see step 4)
* exits non-zero with a diagnostic on any failure

`verify_strict` (as opposed to `verify`) refuses low-order and mixed-
order public keys and refuses signatures whose `s` scalar is not
canonically encoded — both are prerequisites for a strong unforgeability
argument.

## 4. Sanity-check the subject

`avctl receipt-verify` succeeding only proves the signature is
authentic. It does not prove the receipt is *the one you expect*.
Check at least:

* `subject.session_id` matches the session you were audited for
* `subject.workflow` is one of `Signed`, `Unsigned`
* `subject.event_count` matches the number of ATIF steps you got
* `subject.stop_reason` is one of the enumerated values
  (see `av_events::StopReason`)
* `subject.identity.charter` is the charter you intended
* the receipt's `key_id` (top level) matches the trusted key's
  `key_id` (Blake3-based fingerprint of the raw 32-byte public key)

Any mismatch is a hard failure — the signature verified the
attackers' subject, not yours.

## 5. Alternative: verify programmatically

The exact JCS + Ed25519 sequence `avctl` runs is:

```rust
use av_receipts::Receipt;
use av_receipts::keys::Keyring;

let bytes = std::fs::read("receipt.json")?;
let receipt: Receipt = serde_json::from_slice(&bytes)?;

let mut ring = Keyring::new();
ring.add_key_bytes(&hex::decode(trusted_public_key_hex)?)?;

// verify returns Ok(()) only if the canonical subject bytes signed
// by any pinned key match the receipt's signature.
ring.verify(&receipt)?;
```

The `Keyring::verify` path calls `verify_strict` under the hood and
refuses known-weak keys (`is_weak()` — a defence in depth added after
`av_receipts::keys::KeyError::WeakKey` review round 51).

## 6. Common failure modes

* **Signature verification failed** — the receipt was signed by a
  different key (rotation, an impostor, or the wrong environment).
* **Malformed receipt** — the JSON does not deserialize; the file
  is truncated, corrupted, or wasn't a receipt in the first place.
* **JCS canonicalization changed** — the subject bytes differ from
  what was signed. This is what a byte-level tamper looks like; the
  content will decode successfully but the signature no longer
  matches the canonical form.
* **WeakKey** — the trusted-key material you passed in is one of the
  small-order Curve25519 points ed25519-dalek refuses; check that
  you didn't paste `0x00…00` or `0xff…ff` by accident.
* **Unsupported receipt_version** — the verifier refuses any
  `receipt_version` other than the one it implements (currently 1),
  so a future-format receipt is never silently interpreted under
  old semantics. Upgrade `avctl` to verify newer receipts.

## 7. Continuous verification

The recommended pattern for auditors and downstream consumers:

* subscribe to the `agent.receipt` broker topic (or replay it from
  the embedded Bridge with `avctl event-tail --topic agent.receipt`)
* verify each receipt as it arrives
* if a batch's `event_count` sum diverges from your own count of
  the corresponding `agent.step` events on the same session ids,
  escalate — the harness dropped or refused to sign a step

`avctl receipt-verify` is deliberately stateless: it takes one
receipt and one trusted key. Building a streaming verifier on top
of `av_receipts::keys::Keyring` is one page of Rust and matches the
in-tree production behaviour byte for byte.
