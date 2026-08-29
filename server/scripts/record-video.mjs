/*
 * Record a ~60s walkthrough of the AgentVisor console for investors.
 *
 * Distilled flow — one narrative arc: problem (fleet of agents) →
 * proof (live sessions, policy blocks, receipts) → integration
 * story (SSO + webhooks + audit).
 *
 * Runs against the live site at https://agentvisorai.me/app/ in
 * MOCK_MODE=true (built-in Northwind Traders fixtures, already
 * populated, no backend needed). Playwright records to WebM which
 * we then re-encode to MP4.
 */
import { chromium } from "playwright";
import { rmSync, existsSync, readdirSync, renameSync } from "node:fs";
import { join } from "node:path";

const OUT_DIR = "/tmp/av-video";
if (existsSync(OUT_DIR)) rmSync(OUT_DIR, { recursive: true, force: true });

const SITE = process.env.SITE ?? process.argv[2] ?? "https://agentvisorai.me/app/";

async function wait(ms) { return new Promise((r) => setTimeout(r, ms)); }

async function slowType(page, selector, text, perChar = 55) {
  const el = page.locator(selector).first();
  await el.click();
  for (const ch of text) {
    await el.type(ch);
    await wait(perChar);
  }
}

const browser = await chromium.launch({ headless: true });
const context = await browser.newContext({
  viewport: { width: 1440, height: 900 },
  recordVideo: { dir: OUT_DIR, size: { width: 1440, height: 900 } },
  deviceScaleFactor: 2,
});
const page = await context.newPage();

// SCENE 1 — Login (0-8s)
// The SPA auto-authenticates in mock mode; set the "signed out" flag
// via localStorage BEFORE the SPA JS runs so the login form actually
// renders for the cinematic "watch someone log in" moment.
await page.addInitScript(() => {
  try { localStorage.setItem("av_mock_signed_out", "1"); } catch {}
});
await page.goto(SITE + "#/login", { waitUntil: "networkidle" });
await page.waitForSelector('input#email', { timeout: 15000 });
await wait(800);
await slowType(page, 'input#email', "olivia.tan@northwind.com");
await wait(200);
await slowType(page, 'input#password', "d3mo-pw", 35);
await wait(400);
await page.locator('button[type="submit"]').first().click();
await wait(2500);

// SCENE 2 — Overview / dashboard (8-18s)
// The mock backend routes to /overview with populated KPIs + sparkline.
await wait(3500);

// SCENE 3 — Deployments (18-25s)
await page.goto(SITE + "#/deployments");
await wait(2200);
// Hover the first row to show interactivity
const firstDep = page.locator("tbody tr").first();
if (await firstDep.count() > 0) {
  try { await firstDep.click(); await wait(2800); } catch {}
}

// SCENE 4 — Sessions list (25-35s)
await page.goto(SITE + "#/sessions");
await wait(3000);
const firstSess = page.locator("tbody tr").first();
if (await firstSess.count() > 0) {
  try { await firstSess.click(); await wait(3500); } catch {}
}

// SCENE 5 — Policies (35-42s)
await page.goto(SITE + "#/policies");
await wait(2800);

// SCENE 6 — Settings tour: SSO + Webhooks + Audit (42-58s)
await page.goto(SITE + "#/settings/sso");
await wait(2500);
await page.goto(SITE + "#/settings/webhooks");
await wait(2200);
await page.goto(SITE + "#/settings/audit");
await wait(2800);

// SCENE 7 — Verify page as closing beat (58-70s)
// This is the moment: no login, no signup — anyone can drop a
// receipt in their browser and see the cryptographic guarantee
// hold up.
const verifyUrl = new URL(SITE).origin + "/verify/";
await page.goto(verifyUrl, { waitUntil: "networkidle" });
await wait(2000);
await page.locator("#loadExample").click();
await wait(4000);

await context.close();
await browser.close();

// Playwright writes .webm files under OUT_DIR with random names.
// Rename to something predictable.
const files = readdirSync(OUT_DIR).filter((f) => f.endsWith(".webm"));
if (files.length === 0) {
  console.error("No video file produced.");
  process.exit(1);
}
const src = join(OUT_DIR, files[0]);
const dst = join(OUT_DIR, "agentvisor-console-walkthrough.webm");
renameSync(src, dst);
console.log(dst);
