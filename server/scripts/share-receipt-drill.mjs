/*
 * Shareable-receipt-URL drill.
 *
 * The scenario:
 *   * Investor Alice is looking at a session receipt on the console.
 *   * She clicks "Share verify link" -> the console copies a URL of
 *     the form `agentvisorai.me/verify/#data=<b64>` to her clipboard.
 *   * She DMs the URL to her partner Bob.
 *   * Bob opens the URL in his browser.
 *   * Bob's browser decodes the base64 fragment, imports the
 *     Ed25519 public key from the receipt, and verifies the
 *     signature. He sees the green "Signature verifies" card in
 *     under a second.
 *
 * Also verifies:
 *   * A hand-crafted URL with a tampered rawBody -> "Signature does
 *     not verify" card. Proves the URL scheme doesn't accidentally
 *     bypass the crypto.
 *   * A URL with a totally malformed base64 body -> clean error card.
 */
import { chromium } from "playwright";

const SITE = process.env.SITE ?? "http://127.0.0.1:44125/app/";
const VERIFY_URL = new URL("../verify/", SITE).href;

function fail(m) { console.log("❌", m); process.exit(1); }
async function wait(ms) { return new Promise((r) => setTimeout(r, ms)); }

const browser = await chromium.launch({ headless: true });

// ── Alice — the console user who wants to share a receipt ──────────────
const aliceCtx = await browser.newContext({
  viewport: { width: 1280, height: 900 },
  permissions: ["clipboard-read", "clipboard-write"],
});
const alice = await aliceCtx.newPage();

// Log in mock-mode
await alice.addInitScript(() => { try { localStorage.setItem("av_mock_signed_out", "1"); } catch {} });
await alice.goto(SITE + "#/login", { waitUntil: "networkidle" });
await alice.waitForSelector("input#email", { timeout: 15000 });
await alice.locator("input#email").fill("olivia.tan@northwind.com");
await alice.locator("input#password").fill("d3mo");
await alice.locator("button[type='submit']").first().click();
await wait(1500);

// Find a session with a receipt (mock always seeds them)
const firstSess = await alice.evaluate(async () => {
  const list = await window.dataSource.listSessions({ range: "24h" });
  const arr = Array.isArray(list) ? list : (list?.sessions || []);
  return arr[0];
});
if (!firstSess) fail("no mock sessions available");
console.log("Alice viewing session", firstSess.id);

// Point the console at our local /verify page for the drill (so it
// doesn't try to open the live URL from a captured URL).
await alice.evaluate((base) => {
  window.VERIFY_BASE = base;
}, new URL(VERIFY_URL).origin);

await alice.goto(SITE + "#/sessions/" + firstSess.id);
await wait(1800);

// Click Share verify link — should copy a URL to clipboard.
const shareBtn = alice.locator("#shareRcpt");
if (await shareBtn.count() === 0) fail("no Share button on session detail");
await shareBtn.click();
await wait(600);
const clipboardUrl = await alice.evaluate(() => navigator.clipboard.readText());
if (!clipboardUrl || !clipboardUrl.includes("/verify/#data=")) {
  fail("clipboard does not contain a verify URL: " + clipboardUrl?.slice(0, 100));
}
console.log("✅ Share button copied a URL: length=" + clipboardUrl.length);
if (clipboardUrl.length > 30000) fail("URL too long, warn threshold hit");

// ── Bob — a fresh browser context, no cookies, no prior state ──────────
const bobCtx = await browser.newContext({ viewport: { width: 1280, height: 900 } });
const bob = await bobCtx.newPage();
const bobJsErrors = [];
bob.on("pageerror", (e) => bobJsErrors.push(e.message));

// Bob opens the URL Alice DM'd him. Rewrite the origin to our local
// server since Alice's URL points at agentvisorai.me but our drill
// runs locally.
const localizedUrl = clipboardUrl.replace(
  /^https?:\/\/[^/]+\/verify\//,
  VERIFY_URL,
);
await bob.goto(localizedUrl, { waitUntil: "networkidle" });
await wait(2500); // allow async crypto verify to complete
// Accept either .result-card.ok (crypto AND trusted anchor) or
// .result-card.pending (crypto verified, mock key isn't in
// production trust anchor list — that's the correct outcome).
await bob.waitForSelector(".result-card.ok, .result-card.pending", { timeout: 8000 });
{
  const title = await bob.locator(".result-title").innerText();
  // "verifies" (trusted anchor) or "internally consistent" both prove
  // the crypto path works. "does not verify" is the failure state.
  if (/does not verify/i.test(title)) fail("Bob's browser rejected legit URL: " + title);
  if (!/verifies|internally consistent/i.test(title)) fail("unexpected title: " + title);
  const kvText = await bob.locator(".result-card dl.kv").innerText();
  if (!/Session/.test(kvText)) fail("kv missing session field");
  if (!/agent/i.test(kvText)) fail("kv missing agent");
  console.log("✅ Bob's browser auto-verified from URL: " + title.trim());
}
if (bobJsErrors.length) fail("Bob had JS errors: " + bobJsErrors.join(" | "));

// ── Attacker — hand-craft a URL with tampered rawBody ──────────────────
// Extract the base64 payload from the legit URL, decode, tamper, re-encode.
const b64u = localizedUrl.split("#data=")[1];
const b64 = b64u.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((b64u.length + 3) % 4);
const decoded = Buffer.from(b64, "base64").toString("utf8");
const parsed = JSON.parse(decoded);
parsed.receipt.rawBody = parsed.receipt.rawBody.replace(/"sessionId":"/, '"sessionId":"X-');
const tamperedJson = JSON.stringify(parsed);
const tamperedB64u = Buffer.from(tamperedJson, "utf8").toString("base64")
  .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const tamperedUrl = localizedUrl.split("#data=")[0] + "#data=" + tamperedB64u;

await bob.goto(tamperedUrl, { waitUntil: "networkidle" });
await bob.waitForSelector(".result-card", { timeout: 8000 });
{
  const title = await bob.locator(".result-title").innerText();
  if (!/does not verify/i.test(title)) fail("tampered URL still says verifies: " + title);
  console.log("✅ tampered URL -> 'Signature does not verify'");
}

// ── Malformed base64 ───────────────────────────────────────────────────
const badUrl = localizedUrl.split("#data=")[0] + "#data=!!!!not-valid-base64-at-all!!!!";
await bob.goto(badUrl, { waitUntil: "networkidle" });
await bob.waitForSelector(".result-card.bad, .result-card.pending", { timeout: 8000 });
await wait(400);
{
  const title = await bob.locator(".result-title").innerText();
  if (!/couldn't|not valid|decode/i.test(title)) fail("malformed base64 didn't show err: " + title);
  console.log("✅ malformed base64 URL -> clean error card");
}
if (bobJsErrors.length) fail("Bob had JS errors: " + bobJsErrors.join(" | "));

await browser.close();
console.log("\nAll 4 share-receipt-URL drill checks passed.");
