#!/usr/bin/env node
/*
 * Standalone AgentVisor receipt verifier.
 *
 * Reads a receipt bundle exported from the console (Download receipt
 * button on the session detail page) and verifies the Ed25519
 * signature against the embedded public key.
 *
 * Requires only Node 16+. No AgentVisor dependency, no network
 * call — everything the verifier needs is inside the JSON file.
 *
 * Usage:
 *   node scripts/verify-receipt.mjs path/to/agentvisor-receipt-<sessId>.json
 *
 * Exit codes:
 *   0 — signature verifies
 *   1 — signature does NOT verify (tampered or wrong pubkey)
 *   2 — malformed bundle
 *
 * You can safely email this file + a receipt JSON to an auditor,
 * insurer, or opposing counsel — no proprietary code required.
 */
import { readFileSync } from "node:fs";
import { createPublicKey, verify } from "node:crypto";

const argv = process.argv.slice(2);
if (argv.length !== 1) {
  console.error("usage: verify-receipt.mjs <bundle.json>");
  process.exit(2);
}

let bundle;
try {
  bundle = JSON.parse(readFileSync(argv[0], "utf8"));
} catch (e) {
  console.error("Could not read/parse:", argv[0], "-", e.message);
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

const msg = Buffer.from(r.rawBody, "utf8");
const sig = Buffer.from(r.rawSignatureB64, "base64");

const ok = verify(null, msg, key, sig);

console.log("Session:       ", bundle.session?.externalId || bundle.session?.id);
console.log("Agent:         ", bundle.session?.agent);
console.log("Events sealed: ", r.eventCount);
console.log("Receipt ID:    ", r.receiptId);
console.log("Public key:    ", pubKeyHex);
console.log("Message bytes: ", msg.length);
console.log("Signature:     ", sig.length + " bytes (Ed25519)");
console.log("");
if (ok) {
  console.log("✅ SIGNATURE VERIFIES — this session record is authentic.");
  process.exit(0);
} else {
  console.log("❌ SIGNATURE DOES NOT VERIFY — bundle has been tampered with or the public key is wrong.");
  process.exit(1);
}
