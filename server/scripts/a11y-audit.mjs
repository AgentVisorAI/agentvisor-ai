/*
 * Axe-core accessibility audit against the live console.
 *
 * Runs axe on each of the SPA's main routes, filters to serious+critical
 * WCAG 2.1 A/AA violations, and fails if any surface has any.
 *
 * We intentionally exclude:
 *   * `color-contrast` on some brand-color pill combos that pass real-
 *     world screen-reader review but trip axe's absolute threshold
 *     (documented decisions).
 *   * Rules that only apply to <video> / <audio> / <object> content —
 *     the console is text + tables.
 */
import { chromium } from "playwright";
import { AxeBuilder } from "@axe-core/playwright";

const SITE = process.env.SITE ?? "https://agentvisorai.me/app/";
const IGNORE_RULES = [
  // Known intentional decisions:
  //   * Nothing right now — every rule fires or is documented.
];

const routes = [
  "#/login",
  "#/overview",
  "#/deployments",
  "#/sessions",
  "#/sessions/sess_01H9K",
  "#/policies",
  "#/settings/general",
  "#/settings/keys",
  "#/settings/webhooks",
  "#/settings/sso",
  "#/settings/audit",
];

const browser = await chromium.launch({ headless: true });
const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
const page = await context.newPage();

// Force signed-out first so login form renders too.
await page.addInitScript(() => { try { localStorage.setItem("av_mock_signed_out", "1"); } catch {} });
await page.goto(SITE + "#/login", { waitUntil: "networkidle" });
await page.waitForSelector("input#email", { timeout: 15000 });
await page.locator("input#email").fill("olivia.tan@northwind.com");
await page.locator("input#password").fill("d3mo");
await page.locator("button[type='submit']").first().click();
await new Promise((r) => setTimeout(r, 1000));

let anyFail = false;

// Both themes: the tokens differ (dark's accent/success solids are
// light tints needing dark ink), so contrast must be audited per
// theme — the launcher's white-on-light-blue dark-theme failure
// shipped invisibly while this audit only covered one theme.
for (const theme of ["light", "dark"]) {
  await page.evaluate((t) => {
    try { localStorage.setItem("av_theme", t); } catch {}
    document.documentElement.setAttribute("data-theme", t);
  }, theme);

for (const route of routes) {
  await page.goto(SITE + route, { waitUntil: "networkidle" });
  await page.evaluate((t) => document.documentElement.setAttribute("data-theme", t), theme);
  await new Promise((r) => setTimeout(r, 800));

  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .disableRules(IGNORE_RULES)
    .analyze();

  const serious = results.violations.filter(
    (v) => v.impact === "serious" || v.impact === "critical",
  );

  if (serious.length === 0) {
    console.log("✅ [" + theme + "] " + route + ": 0 serious/critical violations");
  } else {
    anyFail = true;
    console.log("❌ [" + theme + "] " + route + ": " + serious.length + " serious/critical violations");
    for (const v of serious) {
      console.log("   - " + v.id + " (" + v.impact + "): " + v.help);
      console.log("     Nodes: " + v.nodes.length);
      // Print the first node's HTML for quick debugging
      if (v.nodes[0]) {
        console.log("     Example: " + v.nodes[0].html.slice(0, 140));
      }
    }
  }
}
}

// The static pages (landing, verifier, pitch) live outside the SPA and
// follow prefers-color-scheme instead of the data-theme toggle — audit
// them in both schemes too, or they'd stay a blind spot.
const ROOT = SITE.replace(/app\/?$/, "");
for (const scheme of ["light", "dark"]) {
  const sctx = await browser.newContext({ colorScheme: scheme });
  const spage = await sctx.newPage();
  for (const path of ["", "verify/", "pitch/"]) {
    await spage.goto(ROOT + path, { waitUntil: "networkidle" });
    await new Promise((r) => setTimeout(r, 500));
    const results = await new AxeBuilder({ page: spage })
      .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
      .disableRules(IGNORE_RULES)
      .analyze();
    const serious = results.violations.filter(
      (v) => v.impact === "serious" || v.impact === "critical",
    );
    if (serious.length === 0) {
      console.log("✅ [" + scheme + "] /" + path + ": 0 serious/critical violations");
    } else {
      anyFail = true;
      console.log("❌ [" + scheme + "] /" + path + ": " + serious.length + " serious/critical violations");
      for (const v of serious) {
        console.log("   - " + v.id + " (" + v.impact + "): " + v.help);
        if (v.nodes[0]) console.log("     Example: " + v.nodes[0].html.slice(0, 140));
      }
    }
  }
  await sctx.close();
}

await browser.close();

if (anyFail) {
  console.log("\nA11y audit FAILED. Fix the serious+critical violations above.");
  process.exit(1);
}
console.log("\nA11y audit passed — all " + routes.length + " console routes (both themes) + 3 static pages (both schemes) clear.");
