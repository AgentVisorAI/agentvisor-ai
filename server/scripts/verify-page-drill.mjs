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
// R91 F4: the /verify page's TRUSTED_RECEIPT_KEYS Set is only
// exposed on `window` when the ?ci-drill=1 URL flag is set (see
// docs/verify/verify.js R91 F4 comment). This drill mutates the
// Set at runtime to inject a per-test trusted pubkey, so append
// the flag to every /verify navigation.
const VERIFY_URL = new URL("verify/?ci-drill=1", SITE).href;

function fail(m) { console.log("❌", m); process.exit(1); }
async function wait(ms) { return new Promise((r) => setTimeout(r, ms)); }

// R81 F1 + R82 F1: helper — every `.result-title` read races the
// async `crypto.subtle.verify` inside `verify.js`, and the transient
// "Verifying signature…" loading card shares its `.pending` class
// with the terminal "internally consistent" state. R81 F1 landed
// this guard on ONE of eight title reads in this drill; without it
// on every read, a busy CI runner reads the loading string and
// falls into a silent fail. Call `waitVerifyStable(page)` after any
// action that triggers a verify (loadExample click, uploadJson,
// tamper/restore) and BEFORE reading .result-title.
async function waitVerifyStable(pg, timeout = 8000) {
  await pg.waitForFunction(
    () => {
      const t = document.querySelector(".result-title")?.textContent || "";
      return t.length > 0 && !/verifying signature/i.test(t);
    },
    { timeout },
  );
}

const browser = await chromium.launch({ headless: true });
const context = await browser.newContext({ viewport: { width: 1200, height: 900 }, acceptDownloads: true });
const page = await context.newPage();
const jsErrors = [];
page.on("pageerror", (e) => jsErrors.push(e.message));

// 1. Page loads with drop zone
await page.goto(VERIFY_URL, { waitUntil: "networkidle" });
await page.waitForSelector("#drop", { timeout: 10000 });
await page.waitForSelector("#loadExample", { timeout: 5000 });
console.log("✅ /verify page renders with drop zone + sample button");

// 2. Try sample -> the sample's pubkey ships on the page's trust
// anchor list (a deliberate product decision from #44: investors
// clicking "Try it with a sample" must see the full green TRUSTED
// experience), so it must render as TRUSTED — and, critically,
// a forged fresh-keypair bundle must NOT (step 4 guards that).
await page.locator("#loadExample").click();
await wait(1500);
await waitVerifyStable(page);
{
  const title = await page.locator(".result-title").innerText();
  if (/does not verify/i.test(title)) fail("sample rendered as does-not-verify. title=" + title);
  if (!/verifies against a trusted key/i.test(title)) fail("sample did not render as TRUSTED (its pubkey ships on the page's anchor list; did TRUSTED_RECEIPT_KEYS lose the sample key?): " + title);
  const kvText = await page.locator(".result-card dl.kv").innerText();
  if (!/Session/.test(kvText)) fail("no session field in kv");
  if (!/supply-planner|northwind|demo/i.test(kvText)) fail("session content missing");
  console.log("✅ sample receipt renders as TRUSTED via Web Crypto in the browser");
}

// 2b. One-click tamper demo: green -> tamper one byte -> red ->
// restore -> green. Guards the #tamperBtn/#restoreBtn feature.
{
  await page.locator("#tamperBtn").click();
  await wait(1200);
  await waitVerifyStable(page);
  const title = await page.locator(".result-title").innerText();
  if (!/does not verify/i.test(title)) fail("tamper demo didn't flip to does-not-verify: " + title);
  const note = await page.locator(".tamper-note").innerText();
  if (!/one byte/i.test(note)) fail("tamper demo missing explainer note: " + note);
  await page.locator("#restoreBtn").click();
  await wait(1200);
  await waitVerifyStable(page);
  const restored = await page.locator(".result-title").innerText();
  if (!/verifies against a trusted key/i.test(restored)) fail("restore didn't return to TRUSTED: " + restored);
  console.log("✅ tamper demo: one byte -> red, restore -> green");
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
  await waitVerifyStable(page);
  const title = await page.locator(".result-title").innerText();
  // Same rationale as step 2: the sample's key is a shipped anchor.
  if (/does not verify/i.test(title)) fail("uploaded legit rendered as does-not-verify");
  if (!/verifies against a trusted key/i.test(title)) fail("uploaded legit did not render as TRUSTED: " + title);
  console.log("✅ upload path renders legit receipt as TRUSTED");
}

// 4. Upload tampered
const tampered = JSON.parse(sampleText);
// Flip a key that every receipt schema carries in the signed body, so
// the mutation is never a silent no-op if the sample's schema evolves.
if (!/"receiptId"/.test(tampered.receipt.rawBody)) fail("sample rawBody has no receiptId to tamper");
tampered.receipt.rawBody = tampered.receipt.rawBody.replace(/"receiptId"/, '"receiptID"');
await uploadJson(JSON.stringify(tampered));
{
  await waitVerifyStable(page);
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
  await waitVerifyStable(page);
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
  await waitVerifyStable(page);
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

// 7. File paths: picker + drag-drop verify green; tampered file red.
// Auditors receive receipt.json as a FILE — these gestures matter as
// much as paste, and were never exercised before this check.
{
  const os = await import("node:os");
  const fsp = await import("node:fs/promises");
  const pathm = await import("node:path");
  const dir = await fsp.mkdtemp(pathm.join(os.tmpdir(), "av-verify-"));
  const good = pathm.join(dir, "receipt.json");
  await fsp.writeFile(good, sampleText);
  await page.reload({ waitUntil: "domcontentloaded" });
  await page.waitForSelector("#fileInput", { state: "attached", timeout: 10000 });
  await page.setInputFiles("#fileInput", good);
  await page.waitForSelector(".result-card", { timeout: 10000 });
  let head = await page.locator(".result-card").innerText();
  if (!/verifies|TRUSTED/i.test(head)) fail("file-picker verify failed: " + head.slice(0, 60));

  await page.reload({ waitUntil: "domcontentloaded" });
  await page.waitForSelector("#drop", { timeout: 10000 });
  await page.evaluate((content) => {
    const dt = new DataTransfer();
    dt.items.add(new File([content], "receipt.json", { type: "application/json" }));
    document.getElementById("drop").dispatchEvent(new DragEvent("drop", { bubbles: true, cancelable: true, dataTransfer: dt }));
  }, sampleText);
  await page.waitForSelector(".result-card", { timeout: 10000 });
  head = await page.locator(".result-card").innerText();
  if (!/verifies|TRUSTED/i.test(head)) fail("drag-drop verify failed: " + head.slice(0, 60));

  const tampered = JSON.parse(sampleText);
  tampered.receipt.rawBody = tampered.receipt.rawBody.replace(/7/, "8");
  const bad = pathm.join(dir, "tampered.json");
  await fsp.writeFile(bad, JSON.stringify(tampered));
  await page.reload({ waitUntil: "domcontentloaded" });
  await page.waitForSelector("#fileInput", { state: "attached", timeout: 10000 });
  await page.setInputFiles("#fileInput", bad);
  await page.waitForSelector(".result-card", { timeout: 10000 });
  head = await page.locator(".result-card").innerText();
  if (!/does not verify|invalid/i.test(head)) fail("tampered file not rejected: " + head.slice(0, 60));
  await fsp.rm(dir, { recursive: true, force: true });
  console.log("✅ file picker + drag-drop verify green; tampered file -> red");
}

// 12. The REAL downloaded bundle round-trips through the web verifier.
// The receipt drill proves download → CLI verifier; this closes the
// seam the print footer actually instructs auditors to use: download
// the receipt in the console, drop that exact file on /verify/ →
// green; tamper one byte of rawBody → red.
{
  const os = await import("node:os");
  const fsp = await import("node:fs/promises");
  const pathm = await import("node:path");
  const dir = await fsp.mkdtemp(pathm.join(os.tmpdir(), "av-dlverify-"));
  const appPage = await context.newPage();
  await appPage.goto(new URL("app/#/sessions/sess_01H9K", SITE).href, { waitUntil: "domcontentloaded" });
  await appPage.waitForSelector("#dlRcpt", { timeout: 15000 });
  const [dl] = await Promise.all([appPage.waitForEvent("download"), appPage.click("#dlRcpt")]);
  const bundlePath = pathm.join(dir, "bundle.json");
  await dl.saveAs(bundlePath);
  await appPage.close();
  await page.goto(VERIFY_URL, { waitUntil: "domcontentloaded" });
  await page.waitForSelector("#fileInput", { state: "attached", timeout: 10000 });
  await page.setInputFiles("#fileInput", bundlePath);
  await waitVerifyStable(page);
  let title = await page.locator(".result-title").innerText();
  if (!/verifies/i.test(title)) fail("downloaded bundle did not verify green on /verify/: " + title.slice(0, 60));
  const obj = JSON.parse(await fsp.readFile(bundlePath, "utf8"));
  obj.receipt.rawBody = obj.receipt.rawBody.replace(/[0-9]/, (d) => String((+d + 1) % 10));
  const tamperedPath = pathm.join(dir, "tampered.json");
  await fsp.writeFile(tamperedPath, JSON.stringify(obj));
  await page.reload({ waitUntil: "domcontentloaded" });
  await page.waitForSelector("#fileInput", { state: "attached", timeout: 10000 });
  await page.setInputFiles("#fileInput", tamperedPath);
  await waitVerifyStable(page);
  title = await page.locator(".result-title").innerText();
  if (!/does not verify|invalid/i.test(title)) fail("tampered downloaded bundle not rejected: " + title.slice(0, 60));
  await fsp.rm(dir, { recursive: true, force: true });
  console.log("✅ console download → /verify/ drop → green; tampered rawBody → red (the auditor path, end-to-end)");
}

if (jsErrors.length) fail("JS errors during drill: " + JSON.stringify(jsErrors));
console.log("✅ zero uncaught JS errors");

await browser.close();
console.log("\nAll 12 /verify page drill checks passed.");
