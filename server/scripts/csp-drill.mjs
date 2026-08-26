/*
 * CSP + security headers drill.
 *
 * Verifies:
 *   1. Landing, /app/, /verify/ all render zero CSP violations.
 *   2. Security-relevant meta tags are present (CSP header).
 *   3. No inline <script> without a src attribute (would be caught
 *      by strict CSP anyway but this gives a clearer failure).
 *   4. All 3 pages still function normally with CSP in place —
 *      the /verify sample still verifies, the console still logs
 *      in, the landing still renders.
 */
import { chromium } from "playwright";

const SITE = process.env.SITE ?? "https://agentvisorai.me/";
const APP = new URL("app/", SITE).href;
const VERIFY = new URL("verify/", SITE).href;

function fail(m) { console.log("❌", m); process.exit(1); }
async function wait(ms) { return new Promise((r) => setTimeout(r, ms)); }

const browser = await chromium.launch({ headless: true });

async function auditPage(name, url) {
  console.log("\n=== " + name + " (" + url + ") ===");
  const context = await browser.newContext({ viewport: { width: 1280, height: 900 } });
  const page = await context.newPage();
  const cspViolations = [];
  const jsErrors = [];

  // CSP violation reports arrive via securitypolicyviolation events.
  await page.exposeFunction("__cspRecord", (v) => cspViolations.push(v));
  page.on("pageerror", (e) => jsErrors.push(e.message));

  await page.addInitScript(() => {
    document.addEventListener("securitypolicyviolation", (e) => {
      window.__cspRecord({
        directive: e.violatedDirective,
        blockedURI: e.blockedURI,
        sourceFile: e.sourceFile,
        lineNumber: e.lineNumber,
        sample: (e.sample || "").slice(0, 100),
      });
    });
  });

  await page.goto(url, { waitUntil: "networkidle" });
  await wait(1500);

  // Check CSP meta is present
  const cspMeta = await page.evaluate(() => {
    const m = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
    return m ? m.getAttribute("content") : null;
  });
  if (!cspMeta) fail(name + ": no CSP <meta> tag found");
  if (!/script-src[^;]*'self'/.test(cspMeta) && !/script-src[^;]*'none'/.test(cspMeta)) {
    fail(name + ": CSP script-src not strict: " + cspMeta.slice(0, 200));
  }
  if (/'unsafe-inline'.*script-src/.test(cspMeta) || /script-src[^;]*'unsafe-inline'/.test(cspMeta)) {
    fail(name + ": CSP allows 'unsafe-inline' for scripts");
  }
  if (/'unsafe-eval'/.test(cspMeta)) {
    fail(name + ": CSP allows 'unsafe-eval'");
  }
  console.log("✅ CSP meta present + strict (no unsafe-inline, no unsafe-eval)");

  // Check no inline scripts without src (would be blocked anyway)
  const inlineCount = await page.evaluate(() => {
    return Array.from(document.querySelectorAll("script")).filter((s) => !s.src).length;
  });
  if (inlineCount > 0) fail(name + ": has " + inlineCount + " inline <script> tags");
  console.log("✅ zero inline <script> tags");

  // Check for common security response headers via a fresh fetch
  const headResp = await page.evaluate(async (u) => {
    const r = await fetch(u, { method: "HEAD" });
    return {
      status: r.status,
      csp: r.headers.get("content-security-policy"),
      xfo: r.headers.get("x-frame-options"),
      xcto: r.headers.get("x-content-type-options"),
      hsts: r.headers.get("strict-transport-security"),
      referrer: r.headers.get("referrer-policy"),
    };
  }, url);
  // GitHub Pages doesn't set these — document that fact for the operator
  // rather than fail. Real CDN deploys (Cloudflare/Netlify) would set
  // them via _headers.
  console.log("  Response headers (GitHub Pages baseline):");
  console.log("    x-frame-options:         " + (headResp.xfo || "(not set)"));
  console.log("    x-content-type-options:  " + (headResp.xcto || "(not set)"));
  console.log("    strict-transport-security: " + (headResp.hsts || "(not set)"));
  console.log("    referrer-policy:         " + (headResp.referrer || "(not set)"));

  await wait(500);
  if (cspViolations.length > 0) {
    console.log("CSP violations captured:");
    cspViolations.forEach((v) => {
      console.log("  - " + v.directive + " blocked " + v.blockedURI + " at " + v.sourceFile + ":" + v.lineNumber);
    });
    fail(name + ": " + cspViolations.length + " CSP violations");
  }
  console.log("✅ zero CSP violations at page load");

  if (jsErrors.length) {
    console.log("JS errors:", jsErrors);
    fail(name + ": " + jsErrors.length + " JS errors");
  }
  console.log("✅ zero JS errors");

  await context.close();
}

await auditPage("Landing", SITE);
await auditPage("Verify", VERIFY);
await auditPage("Console", APP);

// Functional smoke: /verify sample still verifies with CSP in place
console.log("\n=== Functional: /verify sample still verifies under strict CSP ===");
{
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  const cspViolations = [];
  await page.exposeFunction("__cspRecord", (v) => cspViolations.push(v));
  await page.addInitScript(() => {
    document.addEventListener("securitypolicyviolation", (e) => {
      window.__cspRecord({ directive: e.violatedDirective, blockedURI: e.blockedURI });
    });
  });
  await page.goto(VERIFY, { waitUntil: "networkidle" });
  await page.waitForSelector("#loadExample");
  await page.locator("#loadExample").click();
  await page.waitForSelector(".result-card.ok", { timeout: 8000 });
  const title = await page.locator(".result-title").innerText();
  if (!/verifies/i.test(title)) fail("sample didn't verify under CSP: " + title);
  if (cspViolations.length) fail("CSP violations during verify: " + JSON.stringify(cspViolations));
  console.log("✅ sample still verifies under strict CSP (no violations)");
  await ctx.close();
}

// Console still logs in (mock mode)
console.log("\n=== Functional: console login still works under strict CSP ===");
{
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  const cspViolations = [];
  await page.exposeFunction("__cspRecord", (v) => cspViolations.push(v));
  await page.addInitScript(() => {
    try { localStorage.setItem("av_mock_signed_out", "1"); } catch {}
    document.addEventListener("securitypolicyviolation", (e) => {
      window.__cspRecord({ directive: e.violatedDirective, blockedURI: e.blockedURI });
    });
  });
  await page.goto(APP + "#/login", { waitUntil: "networkidle" });
  await page.waitForSelector("input#email", { timeout: 10000 });
  await page.locator("input#email").fill("demo@example.com");
  await page.locator("input#password").fill("d3mo");
  await page.locator('button[type="submit"]').first().click();
  await wait(1500);
  if (page.url().includes("/login")) fail("console login failed under CSP");
  if (cspViolations.length) fail("CSP violations during login: " + JSON.stringify(cspViolations));
  console.log("✅ console login still works under strict CSP (no violations)");
  await ctx.close();
}

await browser.close();
console.log("\nAll CSP + security header checks passed.");
