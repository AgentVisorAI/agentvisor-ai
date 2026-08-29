/*
 * Receipt round-trip drill:
 *
 *   1. Log in, navigate to a session with a receipt.
 *   2. Click "Download receipt" → intercept the browser download.
 *   3. Run verify-receipt.mjs on the downloaded JSON → expect exit 0.
 *   4. Tamper a byte in the receipt's rawBody → re-run verifier →
 *      expect exit 1 (SIGNATURE DOES NOT VERIFY).
 *   5. Tamper the publicKey.hex → re-run → expect exit 1.
 *
 * Proves the whole "any auditor can verify offline with no
 * AgentVisor dependency" pitch is real, end-to-end.
 */
import { chromium } from "playwright";
import { execSync } from "node:child_process";
import { readFileSync, writeFileSync, unlinkSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve, join } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const VERIFIER = resolve(__dirname, "verify-receipt.mjs");
const SITE = process.env.SITE ?? process.argv[2] ?? "https://agentvisorai.me/app/";

function fail(m) { console.log("❌", m); process.exit(1); }
async function wait(ms) { return new Promise((r) => setTimeout(r, ms)); }

const browser = await chromium.launch({ headless: true });
const context = await browser.newContext({
  viewport: { width: 1440, height: 900 },
  acceptDownloads: true,
});
const page = await context.newPage();

// Login (mock)
await page.addInitScript(() => { try { localStorage.setItem("av_mock_signed_out", "1"); } catch {} });
await page.goto(SITE + "#/login", { waitUntil: "networkidle" });
await page.waitForSelector('input#email', { timeout: 15000 });
await page.locator('input#email').fill("olivia.tan@northwind.com");
await page.locator('input#password').fill("d3mo");
await page.locator('button[type="submit"]').first().click();
await wait(1500);

// Grab the first session's id from the API (mock returns mock data)
const list = await page.evaluate(async () => {
  const r = await window.dataSource.listSessions({ range: "24h" });
  // API mode returns { sessions: [...] }; mock returns [...] directly.
  const arr = Array.isArray(r) ? r : (r?.sessions || []);
  return { sessions: arr };
});
if (!list.sessions.length) fail("no sessions in mock");
const targetSess = list.sessions.find((s) => s.receiptOk !== false) || list.sessions[0];
console.log("Navigating to session", targetSess.id);

await page.goto(SITE + "#/sessions/" + targetSess.id);
await wait(2000);

// Click Download receipt
const dlBtn = page.locator('#dlRcpt');
if (await dlBtn.count() === 0) fail("no Download receipt button");

const [download] = await Promise.all([
  page.waitForEvent("download"),
  dlBtn.click(),
]);
const bundlePath = "/tmp/av-receipt-" + Math.random().toString(36).slice(2, 8) + ".json";
await download.saveAs(bundlePath);
if (!existsSync(bundlePath)) fail("download not saved");
console.log("✅ Receipt downloaded:", bundlePath);

// Inspect the bundle
const bundle = JSON.parse(readFileSync(bundlePath, "utf8"));
if (bundle.format !== "agentvisor.receipt.v1") fail("bad format: " + bundle.format);
if (!bundle.receipt?.rawBody) fail("no rawBody");
if (!bundle.receipt?.rawSignatureB64) fail("no signature");
if (!bundle.publicKey?.hex) fail("no publicKey.hex");
console.log("✅ Bundle shape correct: format=" + bundle.format + " pubKey=" + bundle.publicKey.hex.slice(0, 12) + "…");

// Verify — expect exit 0. Since TRUSTED_RECEIPT_KEYS is empty
// (no canonical anchor published yet, R78 HIGH #1), pass
// `--allow-untrusted-key` to acknowledge that the drill is
// exercising signature-vs-embedded-pubkey consistency, not
// trust-anchor authorship. When the anchor list is populated
// in a future release-hardening round, this flag can be
// dropped.
let out;
try {
  out = execSync(`node ${VERIFIER} --allow-untrusted-key ${bundlePath}`, { stdio: "pipe" }).toString();
} catch (e) {
  fail("verifier exited non-zero on legit bundle: " + (e.stdout?.toString() || "") + " " + (e.stderr?.toString() || ""));
}
if (!/SIGNATURE (VERIFIES|IS INTERNALLY CONSISTENT)/i.test(out)) fail("verifier didn't confirm legit bundle: " + out.slice(0, 400));
console.log("✅ verifier: legit bundle passes internal consistency (trust anchor empty in R78)");

// Tamper the rawBody
const tampered = JSON.parse(JSON.stringify(bundle));
tampered.receipt.rawBody = tampered.receipt.rawBody.replace(/./, "X");
const tamperedPath = bundlePath.replace(".json", "-tampered.json");
writeFileSync(tamperedPath, JSON.stringify(tampered, null, 2));
try {
  execSync(`node ${VERIFIER} --allow-untrusted-key ${tamperedPath}`, { stdio: "pipe" });
  fail("tampered bundle verified — that's a security failure!");
} catch (e) {
  const output = (e.stdout?.toString() || "") + (e.stderr?.toString() || "");
  if (!/DOES NOT VERIFY/i.test(output)) fail("tampered bundle didn't fail cleanly: " + output.slice(0, 400));
  if (e.status !== 1) fail("tampered exit code: " + e.status + " expected 1");
}
console.log("✅ tampered rawBody -> SIGNATURE DOES NOT VERIFY (exit 1)");

// Tamper the publicKey.hex (flip one hex char)
const tamperedKey = JSON.parse(JSON.stringify(bundle));
tamperedKey.publicKey.hex = tamperedKey.publicKey.hex.slice(0, 5)
  + (tamperedKey.publicKey.hex[5] === "0" ? "1" : "0")
  + tamperedKey.publicKey.hex.slice(6);
const tamperedKeyPath = bundlePath.replace(".json", "-keytamper.json");
writeFileSync(tamperedKeyPath, JSON.stringify(tamperedKey, null, 2));
try {
  execSync(`node ${VERIFIER} --allow-untrusted-key ${tamperedKeyPath}`, { stdio: "pipe" });
  fail("tampered public key verified!");
} catch (e) {
  const output = (e.stdout?.toString() || "") + (e.stderr?.toString() || "");
  if (!/DOES NOT VERIFY/i.test(output)) fail("tampered key didn't fail cleanly: " + output.slice(0, 400));
}
console.log("✅ tampered publicKey -> SIGNATURE DOES NOT VERIFY (exit 1)");

// R78 F2: fresh-keypair forgery. The naive tamper cases above
// only test that a `sed`-edited receipt fails Ed25519 verify.
// The interesting attack — the one that undermines the "any
// auditor can verify offline" pitch — is an attacker who
// generates their own keypair, signs an arbitrary rawBody,
// and embeds their pubkey. Prior to the R78 HIGH #1 fix, the
// verifier printed "✅ SIGNATURE VERIFIES — authentic" on this
// input. This drill must now assert (a) without
// `--allow-untrusted-key`, exit is 2 with "internally
// consistent"; (b) WITH `--allow-untrusted-key`, exit is 0
// but the output NEVER says "authentic" without qualification.
const { generateKeyPairSync, sign } = await import("node:crypto");
const forgedKeys = generateKeyPairSync("ed25519");
const forgedRaw = JSON.stringify({
  version: 1,
  sessionExternalId: "attacker-controlled",
  eventCount: 0,
  toolsBlocked: 0,
  blockedPayoutUsdMicros: 0,
});
const forgedSig = sign(null, Buffer.from(forgedRaw, "utf8"), forgedKeys.privateKey);
// Extract the raw 32 bytes of the public key from the SPKI DER.
const forgedSpki = forgedKeys.publicKey.export({ format: "der", type: "spki" });
const forgedPubHex = forgedSpki.slice(-32).toString("hex");
const forged = JSON.parse(JSON.stringify(bundle));
forged.receipt.rawBody = forgedRaw;
forged.receipt.rawSignatureB64 = forgedSig.toString("base64");
forged.publicKey.hex = forgedPubHex;
const forgedPath = bundlePath.replace(".json", "-forged.json");
writeFileSync(forgedPath, JSON.stringify(forged, null, 2));

// (a) Without --allow-untrusted-key: MUST exit 2 with the
// "internally consistent but untrusted" message.
try {
  execSync(`node ${VERIFIER} ${forgedPath}`, { stdio: "pipe" });
  fail("forged bundle passed WITHOUT --allow-untrusted-key — trust anchor gate is broken!");
} catch (e) {
  const output = (e.stdout?.toString() || "") + (e.stderr?.toString() || "");
  if (e.status !== 2) fail("forged-untrusted exit code: " + e.status + " expected 2");
  if (!/INTERNALLY CONSISTENT/i.test(output)) fail("forged-untrusted didn't say INTERNALLY CONSISTENT: " + output.slice(0, 400));
  if (/^✅ SIGNATURE VERIFIES against a TRUSTED key/im.test(output)) fail("forged-untrusted incorrectly claimed trusted: " + output.slice(0, 400));
}
console.log("✅ fresh-keypair forgery WITHOUT --allow-untrusted-key -> INTERNALLY CONSISTENT (exit 2)");

// (b) With --allow-untrusted-key: exit 0 but output NEVER
// contains "authentic" without the "internally consistent"
// disclaimer. Grep the output text.
let forgedAcked;
try {
  forgedAcked = execSync(`node ${VERIFIER} --allow-untrusted-key ${forgedPath}`, { stdio: "pipe" }).toString();
} catch (e) {
  fail("forged bundle failed WITH --allow-untrusted-key: " + (e.stdout?.toString() || "") + " " + (e.stderr?.toString() || ""));
}
if (/^✅ SIGNATURE VERIFIES against a TRUSTED key/im.test(forgedAcked)) fail("forged-ack claimed trusted: " + forgedAcked.slice(0, 400));
if (!/INTERNALLY CONSISTENT/i.test(forgedAcked)) fail("forged-ack didn't say INTERNALLY CONSISTENT: " + forgedAcked.slice(0, 400));
console.log("✅ fresh-keypair forgery WITH --allow-untrusted-key -> INTERNALLY CONSISTENT (exit 0, not TRUSTED)");

// Cleanup
for (const p of [bundlePath, tamperedPath, tamperedKeyPath, forgedPath]) {
  try { unlinkSync(p); } catch {}
}

await browser.close();
console.log("\nReceipt download + offline verification round-trip: 6/6 checks passed.");
