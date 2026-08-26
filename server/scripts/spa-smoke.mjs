/*
 * Playwright smoke test of the SPA against the live backend.
 *
 * Boots headless Chromium, navigates to the login page, signs up a
 * new owner, and verifies the console's core surfaces render without
 * a JavaScript error and the network requests they make return 2xx.
 *
 * This complements the JSON-only drills — they prove the API is
 * correct; this proves the UI actually invokes the API correctly
 * from a real browser and renders sensible output.
 */
import { chromium } from "playwright";

const API_BASE = process.env.API_BASE ?? "http://127.0.0.1:8749";
const SPA_BASE = process.env.SPA_BASE ?? "http://127.0.0.1:8749"; // API also serves /app in dev

const nonce = Math.random().toString(36).slice(2, 6);
const email = `spa+${nonce}@example.com`;
const password = "s3cret-drill-pw-1234!";

// First: sign up via API so we can log in via SPA (avoids playing with
// captcha / rate limit ceremony on signup form).
{
  const r = await fetch(API_BASE + "/api/v1/auth/signup", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password, orgName: `SPA-${nonce}`, displayName: "SPA drill" }),
  });
  if (r.status !== 200 && r.status !== 201) {
    console.error("signup failed:", r.status, await r.text());
    process.exit(1);
  }
  console.log("Pre-created user:", email);
}

let browser;
try {
  browser = await chromium.launch({ headless: true });
} catch (e) {
  console.error("Playwright browser launch failed:", e.message);
  console.error("Try: npx playwright install chromium");
  process.exit(2);
}

const jsErrors = [];
const networkFailures = [];
const context = await browser.newContext();
const page = await context.newPage();
page.on("pageerror", (err) => jsErrors.push(err.message));
page.on("requestfailed", (req) => networkFailures.push(req.url() + " -> " + (req.failure()?.errorText || "?")));
page.on("response", (res) => {
  if (res.url().includes("/api/v1/") && res.status() >= 500) {
    networkFailures.push(res.url() + " -> " + res.status());
  }
});

function fail(msg) {
  console.log("❌", msg);
  console.log("Console/network errors so far:", jsErrors, networkFailures);
  process.exit(1);
}

// Serve the SPA — the API server doesn't; we need to boot a static
// server. Simplest is to just use file:// but XHR credentials get weird
// there. Instead, point at the API server's /app if available, or
// fall back to serving the docs folder via a tiny HTTP server here.
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, resolve, extname } from "node:path";
const __dirname = dirname(fileURLToPath(import.meta.url));
const DOCS_ROOT = resolve(__dirname, "../../docs");
const staticPort = 44119;
const mime = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".json": "application/json", ".svg": "image/svg+xml", ".png": "image/png" };
const staticSrv = createServer(async (req, res) => {
  let p = decodeURIComponent(new URL(req.url, "http://x").pathname);
  if (p === "/" || p === "/app" || p === "/app/") p = "/app/index.html";
  try {
    const data = await readFile(DOCS_ROOT + p);
    res.setHeader("content-type", mime[extname(p)] || "application/octet-stream");
    // Rewrite API base for the SPA to point at our backend.
    if (p.endsWith(".html") || p.endsWith(".js")) {
      let s = data.toString();
      if (p.endsWith("/app/index.html")) {
        // Rewrite the built-in mock-mode block to point at our backend.
        s = s.replace(
          /window\.MOCK_MODE\s*=\s*true;\s*window\.API_BASE\s*=\s*"";/,
          `window.MOCK_MODE = false; window.API_BASE = ${JSON.stringify(API_BASE)};`,
        );
      }
      res.end(s);
    } else {
      res.end(data);
    }
  } catch (e) {
    res.statusCode = 404;
    res.end("not found: " + p);
  }
});
await new Promise((r) => staticSrv.listen(staticPort, "127.0.0.1", r));
const spaUrl = `http://127.0.0.1:${staticPort}/app/`;
console.log("SPA serving at", spaUrl);

// Navigate to login
await page.goto(spaUrl + "#/login", { waitUntil: "domcontentloaded" });
try {
  await page.waitForSelector('input#email', { timeout: 8000 });
} catch (e) {
  const html = await page.content();
  console.log("DOM at timeout:", html.slice(0, 2000));
  throw e;
}

// Fill and submit
await page.locator('input[type="email"], input#email').first().fill(email);
await page.locator('input[type="password"], input#password').first().fill(password);
await Promise.all([
  page.waitForURL((url) => !url.hash.includes("/login"), { timeout: 10000 }).catch(() => {}),
  page.locator('button[type="submit"], form button').first().click(),
]);
await page.waitForTimeout(1000);

// We should now be on #/overview (or similar). Check the URL.
const urlNow = page.url();
if (urlNow.includes("/login")) {
  const bodyText = await page.locator("body").innerText();
  fail("still on login after submit. url=" + urlNow + " body[0..200]=" + bodyText.slice(0, 200));
}
console.log("✅ login -> URL:", urlNow);

// Verify /me was called and returned OK
const meRes = await page.evaluate(async (base) => {
  const r = await fetch(base + "/api/v1/auth/me", { credentials: "include" });
  return { status: r.status, body: await r.text() };
}, API_BASE);
if (meRes.status !== 200) fail("me not OK: " + meRes.status + " " + meRes.body);
console.log("✅ /me returned 200 with cookie");

// Navigate through key surfaces
const routes = ["#/overview", "#/deployments", "#/sessions", "#/policies", "#/settings/general", "#/settings/keys", "#/settings/sso", "#/settings/webhooks", "#/settings/audit"];
for (const route of routes) {
  await page.goto(spaUrl + route);
  await page.waitForTimeout(600);
  const bodyLen = await page.locator("body").innerText().then((t) => t.length);
  if (bodyLen < 20) fail("route " + route + " rendered nearly empty (len=" + bodyLen + ")");
}
console.log("✅ all " + routes.length + " routes render without crash");

// Verify no JS errors on any route
if (jsErrors.length) fail("JS errors during flow: " + JSON.stringify(jsErrors));
console.log("✅ no JS errors thrown");

// Verify no 5xx API responses
if (networkFailures.length) fail("network 5xx during flow: " + JSON.stringify(networkFailures));
console.log("✅ no 5xx API responses");

// Verify retention card actually renders with real data
await page.goto(spaUrl + "#/settings/general");
await page.waitForTimeout(1500);
const retSess = await page.locator("#retSess").inputValue().catch(() => null);
const retAudit = await page.locator("#retAudit").inputValue().catch(() => null);
if (retSess !== "90") fail("retention session input value: " + retSess);
if (retAudit !== "365") fail("retention audit input value: " + retAudit);
console.log("✅ retention card shows API values: sess=" + retSess + " audit=" + retAudit);

// Update retention via UI + verify persistence via API
await page.locator("#retSess").fill("60");
await page.locator("#retSave").click();
await page.waitForTimeout(800);
const check = await page.evaluate(async (base) => {
  const r = await fetch(base + "/api/v1/org/retention", { credentials: "include" });
  return await r.json();
}, API_BASE);
if (check.retention.sessionRetentionDays !== 60) fail("UI update didn't persist: " + JSON.stringify(check));
console.log("✅ UI retention update -> API confirms 60");

// Create a deployment via the SPA + verify it appears in the list
await page.goto(spaUrl + "#/deployments");
await page.waitForTimeout(800);
// Find the "New deployment" button (label varies; look for + or New)
const newBtn = page.locator("button", { hasText: /New deployment|\+ Deployment|Create deployment|Add deployment|Register/i }).first();
if (await newBtn.count() === 0) {
  // Fallback: find any "New" button in the header
  const anyNew = page.locator("button:has-text('New')").first();
  if (await anyNew.count() === 0) fail("no 'New deployment' button found on /deployments");
  await anyNew.click();
} else {
  await newBtn.click();
}
await page.waitForTimeout(500);
// Fill deployment form
const depName = "spa-drill-" + Math.random().toString(36).slice(2, 6);
const depNameInput = page.locator('input[placeholder*="northwind" i], input[placeholder*="name" i], input[id*="name" i]').first();
await depNameInput.fill(depName);
await page.locator("button", { hasText: /Create|Save|Register/i }).last().click();
await page.waitForTimeout(1500);
// A token modal should appear; capture its text
const modalText = await page.locator(".modal-backdrop").innerText().catch(() => "");
if (!/av_dep_|token|copy/i.test(modalText)) {
  console.log("modal text:", modalText.slice(0, 300));
  fail("no token modal after create deployment");
}
console.log("✅ create deployment via SPA -> token modal shown");
// Capture the ingest token from the modal so we can simulate a daemon
// against it later.
const ingestToken = await page.locator(".modal-backdrop .token-display").innerText();
if (!ingestToken || ingestToken.length < 20) {
  fail("ingest token doesn't look right: " + ingestToken.slice(0, 40));
}
console.log("✅ captured ingest token from modal: " + ingestToken.slice(0, 12) + "…");
// Close modal
await page.keyboard.press("Escape");
await page.waitForTimeout(400);

// Verify it appears in the deployments list via API
const dList = await page.evaluate(async (base) => {
  const r = await fetch(base + "/api/v1/deployments", { credentials: "include" });
  return await r.json();
}, API_BASE);
if (!dList.deployments?.some((d) => d.name === depName)) {
  fail("newly created deployment not in list: " + JSON.stringify(dList.deployments?.map((d) => d.name)));
}
console.log("✅ deployment '" + depName + "' appears in API list");

// ============================================================
// DAEMON SIMULATION — prove the "customer's daemon ships events"
// leg of the full investor flow works end-to-end from the actual
// hosted ingest surface.
// ============================================================
const sessionExternalId = "sess_" + Math.random().toString(36).slice(2, 8);
const now = new Date();
// Ingest requires x-av-deployment + Bearer. Get deployment id via API.
const deploymentId = dList.deployments.find((d) => d.name === depName).id;
{
  const r = await fetch(API_BASE + "/api/v1/ingest/sessions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: "Bearer " + ingestToken,
      "x-av-deployment": deploymentId,
    },
    body: JSON.stringify({
      externalId: sessionExternalId,
      agent: "demo-support-bot",
      openedAt: now.toISOString(),
      status: "live",
    }),
  });
  if (r.status !== 200) fail("ingest session -> " + r.status + " " + await r.text());
}
console.log("✅ daemon simulation: session upserted");
{
  const evs = [
    { seq: 0, kind: "sys",  tag: "start",     body: "Session started" },
    { seq: 1, kind: "user", tag: "prompt",    body: "Refund the customer's order" },
    { seq: 2, kind: "llm",  tag: "response",  body: "I will refund the order.", addPromptTokens: 40, addCompletionTokens: 12 },
    { seq: 3, kind: "tool", tag: "search",    body: "results ok", addToolsAllowed: 1 },
    { seq: 4, kind: "block",tag: "refund",    body: "policy_denied high_value_refund", addToolsBlocked: 1 },
  ].map((e) => ({
    ...e,
    sessionExternalId,
    occurredAt: new Date(now.getTime() + e.seq * 1000).toISOString(),
    journalCount: 1,
  }));
  const r = await fetch(API_BASE + "/api/v1/ingest/events", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: "Bearer " + ingestToken,
      "x-av-deployment": deploymentId,
    },
    body: JSON.stringify(evs),
  });
  if (r.status !== 200) fail("ingest events -> " + r.status + " " + await r.text());
  const j = await r.json();
  if (j.inserted !== 5) fail("expected 5 inserted, got " + j.inserted);
}
console.log("✅ daemon simulation: 5 events ingested (1 tool_block)");

// Navigate to sessions list — the newly-ingested session should be there
await page.goto(spaUrl + "#/sessions");
await page.waitForTimeout(1500);
const sessListText = await page.locator("body").innerText();
if (!sessListText.includes("demo-support-bot") && !sessListText.includes(sessionExternalId.slice(0, 8))) {
  console.log("sessions body snippet:", sessListText.slice(0, 400));
  fail("session not visible in sessions list");
}
console.log("✅ session appears in /sessions list");

// Verify the session's rollup counters via API
const sessDetail = await page.evaluate(async (base) => {
  const r = await fetch(base + "/api/v1/sessions", { credentials: "include" });
  return await r.json();
}, API_BASE);
const sess = sessDetail.sessions.find((s) => s.externalId === sessionExternalId);
if (!sess) fail("session not in API list: " + JSON.stringify(sessDetail.sessions.map((s) => s.externalId)));
if (sess.toolsAllowed !== 1) fail("toolsAllowed rollup: " + sess.toolsAllowed);
if (sess.toolsBlocked !== 1) fail("toolsBlocked rollup: " + sess.toolsBlocked);
if (sess.promptTokens !== 40) fail("promptTokens rollup: " + sess.promptTokens);
if (sess.completionTokens !== 12) fail("completionTokens rollup: " + sess.completionTokens);
console.log("✅ session rollups correct: prompt=" + sess.promptTokens + " completion=" + sess.completionTokens + " allowed=" + sess.toolsAllowed + " blocked=" + sess.toolsBlocked);

// Session detail page — verify events render
await page.goto(spaUrl + "#/sessions/" + sess.id);
await page.waitForTimeout(1500);
const detailText = await page.locator("body").innerText();
if (!detailText.includes("refund")) {
  console.log("session detail body:", detailText.slice(0, 500));
  fail("session detail missing event text");
}
console.log("✅ session detail page renders events");

// Verify audit log picked up ALL our activity
const audit = await page.evaluate(async (base) => {
  const r = await fetch(base + "/api/v1/audit?limit=50", { credentials: "include" });
  return await r.json();
}, API_BASE);
const events = audit.entries.map((e) => e.event);
if (!events.includes("deployment.create")) fail("audit missing deployment.create: " + events.slice(0,10));
if (!events.includes("org.retention_updated")) fail("audit missing org.retention_updated: " + events.slice(0,10));
console.log("✅ audit log picked up deployment.create + org.retention_updated");

// Sanity: no JS errors during the whole extended flow
if (jsErrors.length) fail("JS errors during extended flow: " + JSON.stringify(jsErrors));
if (networkFailures.length) fail("network 5xx during extended flow: " + JSON.stringify(networkFailures));
console.log("✅ still zero JS errors + zero 5xx after extended flow");

await browser.close();
staticSrv.close();
console.log("\nSPA e2e smoke passed (23 checks).");
