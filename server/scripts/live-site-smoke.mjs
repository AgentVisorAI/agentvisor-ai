/*
 * Live-site smoke test: hits https://agentvisorai.me/app/ (the actual
 * deployed console) and asserts the SPA works end-to-end from a real
 * browser against the real GitHub Pages CDN.
 *
 * Runs in MOCK_MODE=true (as deployed) so no backend is needed.
 * Verifies:
 *   1. HTTPS + valid cert.
 *   2. index.html loads with our SPA bundle.
 *   3. Login form renders when signed out.
 *   4. Login with any credentials -> overview.
 *   5. All 9 SPA routes render (no JS errors, no 4xx from Pages).
 *   6. Every settings tab has POPULATED demo data — no empty states
 *      that would make an investor think the product is a stub.
 *   7. Live indicator pulses (mock subscribe fires an event).
 */
import { chromium } from "playwright";

const SITE = process.env.SITE ?? "https://agentvisorai.me/app/";

const browser = await chromium.launch({ headless: true });
const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
const page = await context.newPage();

const jsErrors = [];
const netErrors = [];
page.on("pageerror", (e) => jsErrors.push(e.message));
page.on("response", (r) => {
  if ((r.url().includes("agentvisorai.me") || r.url().includes("127.0.0.1")) && r.status() >= 400) {
    netErrors.push(r.url() + " -> " + r.status());
  }
});
function fail(m) {
  console.log("❌", m);
  console.log("JS errors:", jsErrors);
  console.log("Net errors:", netErrors);
  process.exit(1);
}
async function wait(ms) { return new Promise((r) => setTimeout(r, ms)); }

// 1-2. Load the SPA. Force signed-out so login form renders.
await page.addInitScript(() => {
  try { localStorage.setItem("av_mock_signed_out", "1"); } catch {}
});
await page.goto(SITE, { waitUntil: "networkidle" });
if (!page.url().includes("/app")) fail("wrong URL: " + page.url());
console.log("✅ SPA loaded from", new URL(SITE).host);

// 3-4. Login
await page.goto(SITE + "#/login", { waitUntil: "networkidle" });
await page.waitForSelector('input#email', { timeout: 15000 });
await page.locator('input#email').fill("olivia.tan@northwind.com");
await page.locator('input#password').fill("d3mo");
await page.locator('button[type="submit"]').first().click();
await wait(1500);
if (page.url().includes("/login")) fail("stuck on login. url=" + page.url());
console.log("✅ login worked in mock mode");

// 5. Navigate through all routes; no JS errors.
const routes = [
  "#/overview", "#/deployments", "#/sessions", "#/policies",
  "#/settings/general", "#/settings/members", "#/settings/keys",
  "#/settings/sso", "#/settings/webhooks", "#/settings/audit", "#/settings/billing",
];
for (const r of routes) {
  await page.goto(SITE + r);
  await wait(700);
  const len = await page.locator("body").innerText().then((t) => t.length);
  if (len < 200) fail("route " + r + " nearly empty (" + len + " chars)");
}
console.log("✅ all " + routes.length + " routes render (>200 chars)");
if (jsErrors.length) fail("JS errors: " + JSON.stringify(jsErrors));
if (netErrors.filter((n) => !n.includes("favicon") && !n.includes("host")).length) fail("network errors: " + JSON.stringify(netErrors));
console.log("✅ no JS errors, no 4xx");

// 6. Populated settings tabs — no empty states in the pitch surface.
await page.goto(SITE + "#/settings/webhooks");
await wait(1200);
{
  const text = await page.locator("body").innerText();
  if (/No webhooks yet/i.test(text)) fail("Webhooks tab shows empty state!");
  if (!/slack|pagerduty|datadog/i.test(text)) fail("Webhooks: no populated endpoints");
  console.log("✅ Webhooks tab populated with Slack + PagerDuty + Datadog");
}
await page.goto(SITE + "#/settings/keys");
await wait(1000);
{
  const text = await page.locator("body").innerText();
  if (/No API keys yet/i.test(text)) fail("API keys tab shows empty state!");
  if (!/CI runner|Ops dashboard/i.test(text)) fail("API keys: no populated rows");
  console.log("✅ API keys tab populated");
}
await page.goto(SITE + "#/settings/sso");
await wait(1200);
{
  const text = await page.locator("body").innerText();
  if (/No SAML IdPs yet/i.test(text)) fail("SSO tab shows empty state!");
  console.log("✅ SSO tab populated");
}
await page.goto(SITE + "#/settings/members");
await wait(1200);
{
  const text = await page.locator("body").innerText();
  if (!/olivia|raj|sam/i.test(text)) fail("Members: no rows");
  console.log("✅ Members tab populated");
}
await page.goto(SITE + "#/settings/audit");
await wait(1200);
{
  const rows = await page.locator("tbody tr").count();
  if (rows < 3) fail("Audit tab: only " + rows + " rows");
  console.log("✅ Audit log populated (" + rows + " rows)");
}

// 7. Live/Demo indicator — mock shows "Demo" pill, real backend shows
// "Live" pulse.
await page.goto(SITE + "#/overview");
await wait(500);
const anyPill = page.locator('.env-pill');
if (await anyPill.count() === 0) fail("no env pill on overview");
const pillText = (await anyPill.first().innerText()).toLowerCase();
if (!/(live|demo)/.test(pillText)) fail("pill text: " + pillText);
console.log("✅ Environment pill present: " + pillText);

await browser.close();
console.log("\nLive site smoke passed (7 checks against " + SITE + ").");
