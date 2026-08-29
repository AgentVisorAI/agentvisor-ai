#!/usr/bin/env node
/*
 * Standalone AgentVisor receipt verifier.
 *
 * Reads a receipt bundle exported from the console (Download receipt
 * button on the session detail page) and verifies the Ed25519
 * signature against the embedded public key.
 *
 * Requires only Node 16+. No AgentVisor dependency, no network
 * call — everything the verifier needs is inside the JSON file
 * (plus the trust-anchor list this script ships with).
 *
 * Usage:
 *   node server/scripts/verify-receipt.mjs path/to/agentvisor-receipt-<sessId>.json
 *   node server/scripts/verify-receipt.mjs --allow-untrusted-key <bundle.json>
 *
 * Exit codes:
 *   0 — signature verifies AND the pubkey is on the trust anchor list
 *       (or --allow-untrusted-key was passed, in which case only the
 *       signature-vs-pubkey check must pass)
 *   1 — signature does NOT verify (tampered or wrong pubkey)
 *   2 — malformed bundle, OR signature verifies but the pubkey is
 *       NOT on the trust anchor list and --allow-untrusted-key was
 *       not passed. This case is a UI/CI distinction from "tamper" —
 *       it's the "self-signed by an untrusted party" attack:
 *       the attacker generated their own Ed25519 keypair, signed
 *       arbitrary contents, and embedded their pubkey. The signature
 *       math checks out; the AUTHORSHIP claim does not.
 *
 * You can safely email this file + a receipt JSON to an auditor,
 * insurer, or opposing counsel — no proprietary code required.
 */
import { readFileSync } from "node:fs";
import { createPublicKey, verify, createHash } from "node:crypto";

// R78 HIGH #1: trust anchor pinning. Without this, an attacker who
// generates their own Ed25519 keypair, signs any `rawBody`, and
// embeds their pubkey in a fresh bundle passes the internal
// signature check with an "authentic" verdict — the entire premise
// of "any auditor can verify offline" collapses. Populate with
// lowercased 64-hex Ed25519 pubkeys of the AgentVisor deployment(s).
// Empty list defaults to REQUIRING `--allow-untrusted-key`.
const TRUSTED_RECEIPT_KEYS = new Set([
  // Keep in sync with docs/verify/verify.js TRUSTED_RECEIPT_KEYS.
  // Sample/shared receipts signing key (legacy demo exports).
  "9992e71fe6a6e5edc18129becef2ec640f9611a4e12a4b9a311bab943ab19467",
  // Demo console signing key (docs/app/datasource.js fixed keypair).
  "573c8f249012fbb08b3d79973411bb93141f32719c86ada25306fde5e59e8d57",
]);

const argv = process.argv.slice(2);
let allowUntrusted = false;
const files = [];
for (const a of argv) {
  if (a === "--allow-untrusted-key") {
    allowUntrusted = true;
  } else if (a.startsWith("-")) {
    console.error("unknown flag:", a);
    console.error("usage: verify-receipt.mjs [--allow-untrusted-key] <bundle.json>");
    process.exit(2);
  } else {
    files.push(a);
  }
}
if (files.length !== 1) {
  console.error("usage: verify-receipt.mjs [--allow-untrusted-key] <bundle.json>");
  process.exit(2);
}

let bundle;
try {
  bundle = JSON.parse(readFileSync(files[0], "utf8"));
} catch (e) {
  console.error("Could not read/parse:", files[0], "-", e.message);
  process.exit(2);
}

if (bundle.format !== "agentvisor.receipt.v1") {
  console.error("Unrecognized format:", bundle.format);
  process.exit(2);
}
const r = bundle.receipt;
const pub = bundle.publicKey;
if (!r || !pub) {
  console.error("Bundle missing receipt or publicKey");
  process.exit(2);
}

const missing = ["rawBody", "rawSignatureB64"].filter((k) => !r[k]);
if (missing.length) {
  console.error("Receipt missing:", missing.join(", "));
  process.exit(2);
}

const pubKeyHex = pub.hex;
if (!/^[0-9a-fA-F]{64}$/.test(pubKeyHex)) {
  console.error("Public key hex must be 64 chars (32 bytes)");
  process.exit(2);
}
const pubBytes = Buffer.from(pubKeyHex, "hex");
// Ed25519 raw pubkey -> DER SPKI so createPublicKey can consume it.
// SPKI prefix for Ed25519: 302a300506032b6570032100 (12 bytes) + 32
// bytes of raw key = 44-byte DER.
const spki = Buffer.concat([
  Buffer.from("302a300506032b6570032100", "hex"),
  pubBytes,
]);
const key = createPublicKey({ key: spki, format: "der", type: "spki" });

// R190 F1: match the Rust `av-receipts` signing framing.
// crates/av-receipts/src/receipt.rs:50-64 `signing_message()`
// dispatches on `receipt_version`:
//   v1 → bare canonical bytes (legacy)
//   v2 → RECEIPT_DOMAIN_TAG_V2 (b"agentvisor-receipt-v2\0") ||
//        u64_be(canonical.len()) || canonical
// Rust defaults RECEIPT_VERSION=2 (receipt.rs:30), so modern
// daemons emit v2 receipts. Prior CLI used bare-body semantics
// only and would fail every v2 receipt as "SIGNATURE DOES NOT
// VERIFY" (exit 1) even though the sig was cryptographically
// valid. Now: parse body, dispatch to correct framing.
const RECEIPT_DOMAIN_TAG_V2 = Buffer.from("agentvisor-receipt-v2\0", "utf8");
function receiptSigningMessage(rawBody) {
  const canonical = Buffer.from(rawBody, "utf8");
  let receiptVersion = 1;
  try {
    const parsed = JSON.parse(rawBody);
    if (typeof parsed.receipt_version === "number") receiptVersion = parsed.receipt_version;
  } catch { /* body not JSON — leave as v1 */ }
  if (receiptVersion === 1) return canonical;
  if (receiptVersion === 2) {
    const lenBuf = Buffer.alloc(8);
    lenBuf.writeBigUInt64BE(BigInt(canonical.length), 0);
    return Buffer.concat([RECEIPT_DOMAIN_TAG_V2, lenBuf, canonical]);
  }
  // Unknown version — return empty to fail-closed.
  return Buffer.alloc(0);
}
const msg = receiptSigningMessage(r.rawBody);
const sig = Buffer.from(r.rawSignatureB64, "base64");

const sigOk = verify(null, msg, key, sig);
// R193 F1: enforce identity binding — body.key_id must derive
// from the pubkey. Mirrors Rust `Receipt::verify_embedded()` at
// crates/av-receipts/src/receipt.rs:371-374. Legacy v1 receipts
// (sample-receipt.json) have no body.key_id — skip.
function deriveKeyIdFromPubHex(hex) {
  return createHash("sha256").update(Buffer.from(hex, "hex")).digest("hex").slice(0, 32);
}
let keyIdOk = true;
let bodyKeyId = null;
if (sigOk) {
  try {
    const parsed = JSON.parse(r.rawBody);
    if (typeof parsed.key_id === "string" && parsed.key_id.length > 0) {
      bodyKeyId = parsed.key_id.toLowerCase();
      const derived = deriveKeyIdFromPubHex(pubKeyHex.toLowerCase());
      if (derived !== bodyKeyId) keyIdOk = false;
    }
  } catch { /* body not JSON — leave keyIdOk true */ }
}
const ok = sigOk && keyIdOk;
const trustedKey = ok && TRUSTED_RECEIPT_KEYS.has(pubKeyHex.toLowerCase());

console.log("Session:       ", bundle.session?.externalId || bundle.session?.id);
console.log("Agent:         ", bundle.session?.agent);
console.log("Events sealed: ", r.eventCount);
console.log("Receipt ID:    ", r.receiptId);
console.log("Public key:    ", pubKeyHex);
console.log("Trusted key:   ", trustedKey ? "yes" : "NO (not on the trust anchor list)");
console.log("Message bytes: ", msg.length);
console.log("Signature:     ", sig.length + " bytes (Ed25519)");
console.log("");

if (!ok) {
  console.log("❌ SIGNATURE DOES NOT VERIFY — bundle has been tampered with or the public key is wrong.");
  process.exit(1);
}

if (trustedKey) {
  console.log("✅ SIGNATURE VERIFIES against a TRUSTED key — this session record is authentic.");
  process.exit(0);
}

if (allowUntrusted) {
  console.log(
    "⚠️  SIGNATURE IS INTERNALLY CONSISTENT — but the public key is NOT on the trust anchor list.",
  );
  console.log(
    "   `--allow-untrusted-key` was passed, so exiting 0. The bundle attests only that WHOEVER",
  );
  console.log(
    "   holds the corresponding private key signed this payload — NOT that it was AgentVisor.",
  );
  process.exit(0);
}

console.log(
  "⚠️  SIGNATURE IS INTERNALLY CONSISTENT — but the public key is NOT on the trust anchor list.",
);
console.log(
  "   The signature math checks out AGAINST THE PUBLIC KEY IN THE BUNDLE, but that key is not",
);
console.log(
  "   one this verifier is willing to trust. An attacker who generates their own Ed25519 keypair",
);
console.log(
  "   can produce identical output, so this is NOT proof of AgentVisor authorship. Rerun with",
);
console.log(
  "   `--allow-untrusted-key` to acknowledge and exit 0, or populate TRUSTED_RECEIPT_KEYS with",
);
console.log(
  "   the deployment's canonical Ed25519 pubkey and rerun.",
);
process.exit(2);
