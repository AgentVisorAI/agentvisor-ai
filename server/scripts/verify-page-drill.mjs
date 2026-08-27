/*
 * /verify page drill.
 *
 * Verifies:
 *   1. Page renders + has drop zone + "Try it with a sample" button.
 *   2. Click "Try sample" -> loads sample-receipt.json -> Web Crypto
 *      Ed25519 verifies -> DOM shows "Signature verifies".
 *   3. Upload the same file via the hidden file input -> same result.
 *   4. Upload a tampered version (rawBody modified) -> DOM shows
 *      "Signature does not verify".
 *   5. Upload a malformed JSON -> "Not valid JSON" error card, no
 *      uncaught exception.
 *   6. Upload a bundle with wrong format tag -> "Unrecognized bundle
 *      format" error.
 *
 * Runs against the deployed URL by default; the local variant serves
 * docs/ on 127.0.0.1 first.
 */
import { chromium } from "playwright";

const SITE = process.env.SITE ?? "https://agentvisorai.me/";
const VERIFY_URL = new URL("verify/", SITE).href;

function fail(m) { console.log("❌", m); process.exit(1); }
async function wait(ms) { return new Promise((r) => setTimeout(r, ms)); }

const browser = await chromium.launch({ headless: true });
const context = await browser.newContext({ viewport: { width: 1200, height: 900 } });
const page = await context.newPage();
const jsErrors = [];
page.on("pageerror", (e) => jsErrors.push(e.message));

// 1. Page loads with drop zone
await page.goto(VERIFY_URL, { waitUntil: "networkidle" });
await page.waitForSelector("#drop", { timeout: 10000 });
await page.waitForSelector("#loadExample", { timeout: 5000 });
console.log("✅ /verify page renders with drop zone + sample button");

// 2. Try sample -> should render as internally consistent (empty trust anchor)
await page.locator("#loadExample").click();
await wait(1500);
{
  const title = await page.locator(".result-title").innerText();
  // R78 HIGH #1 + R80 F1: with empty TRUSTED_RECEIPT_KEYS, any
  // receipt (including the shipped sample) must render as
  // INTERNALLY CONSISTENT, not TRUSTED. Assertion regression:
  // commit 30e8085 reverted this from R78's `/internally
  // consistent/` back to `/verifies/`, causing the drill to
  // fail at step 2 in CI — which also made R79's positive
  // trust-anchor guard at step 5 unreachable (dead-code
  // regression test). This restores the correct assertion.
  if (/does not verify/i.test(title)) fail("sample rendered as does-not-verify. title=" + title);
  if (/verifies against a trusted key/i.test(title)) fail("sample falsely claimed TRUSTED (empty anchor list should show INTERNALLY CONSISTENT until anchors are populated): " + title);
  if (!/internally consistent/i.test(title)) fail("sample missing INTERNALLY CONSISTENT string: " + title);
  const kvText = await page.locator(".result-card dl.kv").innerText();
  if (!/Session/.test(kvText)) fail("no session field in kv");
  if (!/supply-planner|northwind|demo/i.test(kvText)) fail("session content missing");
  console.log("✅ sample receipt renders as INTERNALLY CONSISTENT via Web Crypto in the browser");
}

// 3. Fetch the same sample and upload via file input
const sampleText = await page.evaluate(async (verifyUrl) => {
  const r = await fetch(new URL("sample-receipt.json", verifyUrl).href);
  return await r.text();
}, VERIFY_URL);
if (!sampleText.startsWith("{")) fail("sample fetch got HTML");

async function uploadJson(text) {
  await page.evaluate((t) => {
    const dt = new DataTransfer();
    dt.items.add(new File([t], "receipt.json", { type: "application/json" }));
    const input = document.getElementById("fileInput");
    input.files = dt.files;
    input.dispatchEvent(new Event("change", { bubbles: true }));
  }, text);
  await wait(1200);
}

await uploadJson(sampleText);
{
  const title = await page.locator(".result-title").innerText();
  // R78 HIGH #1 + R80 F1: same assertion as step 2 above.
  if (/does not verify/i.test(title)) fail("uploaded legit rendered as does-not-verify");
  if (/verifies against a trusted key/i.test(title)) fail("uploaded legit falsely claimed TRUSTED (empty anchor list should always give INTERNALLY CONSISTENT until anchors are populated)");
  if (!/internally consistent/i.test(title)) fail("uploaded legit missing INTERNALLY CONSISTENT string: " + title);
  console.log("✅ upload path renders legit receipt as INTERNALLY CONSISTENT (empty trust anchor)");
}

// 4. Upload tampered
const tampered = JSON.parse(sampleText);
// Flip a key that every receipt schema carries in the signed body, so
// the mutation is never a silent no-op if the sample's schema evolves.
if (!/"receiptId"/.test(tampered.receipt.rawBody)) fail("sample rawBody has no receiptId to tamper");
tampered.receipt.rawBody = tampered.receipt.rawBody.replace(/"receiptId"/, '"receiptID"');
await uploadJson(JSON.stringify(tampered));
{
  const title = await page.locator(".result-title").innerText();
  if (!/does not verify/i.test(title)) fail("tampered still says verifies: " + title);
  console.log("✅ tampered rawBody -> DOM shows 'Signature does not verify'");
}

// R78 F2: fresh-keypair forgery test on the DOM path.
// Generate a fresh Ed25519 keypair in a Node subshell (the
// browser can generate too but we already have the utilities
// server-side), sign attacker-chosen contents, embed the
// pubkey, upload, and assert the DOM does NOT render the
// "authentic" / "verifies against a trusted key" wording.
{
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
  const forgedSpki = forgedKeys.publicKey.export({ format: "der", type: "spki" });
  const forgedPubHex = forgedSpki.slice(-32).toString("hex");
  const forged = JSON.parse(sampleText);
  forged.receipt.rawBody = forgedRaw;
  forged.receipt.rawSignatureB64 = forgedSig.toString("base64");
  forged.publicKey.hex = forgedPubHex;
  await uploadJson(JSON.stringify(forged));
  const title = await page.locator(".result-title").innerText();
  if (/verifies against a trusted key/i.test(title)) fail("forged bundle rendered as TRUSTED — trust anchor gate bypassed: " + title);
  if (!/internally consistent/i.test(title)) fail("forged bundle didn't render as INTERNALLY CONSISTENT: " + title);
  console.log("✅ fresh-keypair forgery -> DOM shows INTERNALLY CONSISTENT (not TRUSTED)");

  // R79 review guard: inject the forged pubkey into
  // `window.TRUSTED_RECEIPT_KEYS` at runtime and re-upload the
  // same forged bundle. The DOM MUST now render "verifies
  // against a trusted key". This asserts (a) `verifyBundle`
  // returns `trustedKey: true` when the pubkey is on the anchor
  // list, (b) the outer render pipeline correctly THREADS
  // `trustedKey` through the destructure. R78 shipped a bug
  // where the destructure dropped `trustedKey` — the pre-R79
  // drill's negative assertion (`!/trusted key/`) was vacuously
  // true because the code path was unreachable. Regression
  // guard: this positive assertion MUST fail if the outer
  // render loses `trustedKey` again.
  await page.evaluate((hex) => {
    window.TRUSTED_RECEIPT_KEYS.add(hex);
  }, forgedPubHex);
  await uploadJson(JSON.stringify(forged));
  const trustedTitle = await page.locator(".result-title").innerText();
  if (!/verifies against a trusted key/i.test(trustedTitle)) fail("after injecting pubkey into TRUSTED_RECEIPT_KEYS, DOM still didn't render as TRUSTED — R78 destructure bug regressed?: " + trustedTitle);
  console.log("✅ forged bundle with pubkey in TRUSTED_RECEIPT_KEYS -> DOM shows TRUSTED (trustedKey threaded correctly)");
}

// 5. Upload malformed JSON
await uploadJson("this is not JSON at all {");
{
  const title = await page.locator(".result-title").innerText();
  if (!/couldn't verify/i.test(title)) fail("malformed didn't show err: " + title);
  console.log("✅ malformed JSON -> error card, no crash");
}

// 6. Upload wrong format tag
const wrongFormat = JSON.parse(sampleText);
wrongFormat.format = "agentvisor.receipt.v99";
await uploadJson(JSON.stringify(wrongFormat));
{
  const sub = await page.locator(".result-card .result-sub").innerText();
  if (!/format/i.test(sub) && !/agentvisor\.receipt\.v99/.test(sub)) {
    fail("wrong-format error not shown: " + sub);
  }
  console.log("✅ wrong format tag -> clean error message");
}

if (jsErrors.length) fail("JS errors during drill: " + JSON.stringify(jsErrors));
console.log("✅ zero uncaught JS errors");

await browser.close();
console.log("\nAll 9 /verify page drill checks passed.");
