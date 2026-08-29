/*
 * Full investor-flow rehearsal: ONE continuous browser session walking
 * the exact Saturday narrative, in story order. Every other suite
 * exercises features piecewise; this proves the transitions between
 * them — the actual demo — hold together end to end:
 *
 *   1. Landing page → "See the full flow" CTA (app/?tour=1)
 *   2. Guided tour auto-starts, all 6 steps advance on their targets
 *   3. Finale CTA → public verifier (new tab) → sample verifies green
 *   4. Back in the console: ⚡ Simulate an attack → blocked toast →
 *      story banner on the injected session
 *   5. Download that session's receipt → bundle shape sane
 *   6. Sign out → sign up a FRESH workspace → onboarding checklist at
 *      1 of 4 with the judge's own org name
 *   7. Reset demo data via the palette → pristine Northwind restored
 *
 * Mock-mode only (as deployed). SITE env overrides the target root.
 */
import { chromium, devices } from "playwright";

const SITE = process.env.SITE ?? process.argv[2] ?? "https://agentvisorai.me/";
const ROOT = SITE.replace(/app\/?$/, "");
// PROFILE=phone rehearses the QR-code path: the printed handout's QR
// lands investors on the site on their phones — same narrative, tap
// interactions, 390px layout.
const PHONE = process.env.PROFILE === "phone";
// SLOW=1 simulates venue WiFi: every datasource call gains 300–700 ms
// of jittered latency, injected right after the console boots. The
// narrative must still hold — skeletons, in-flight guards, fetch-first
// refreshes, and race tokens all under realistic timing.
const SLOW = process.env.SLOW === "1";

function fail(m) { console.log("❌", m); process.exit(1); }

const browser = await chromium.launch({ headless: true });
const context = await browser.newContext(
  PHONE
    ? { ...devices["iPhone 13"], acceptDownloads: true }
    : { viewport: { width: 1440, height: 900 }, acceptDownloads: true },
);
const page = await context.newPage();
const jsErrors = [];
page.on("pageerror", (e) => jsErrors.push(e.message.slice(0, 120)));
const t0 = Date.now();
const beat = (m) => console.log("✅ [" + ((Date.now() - t0) / 1000).toFixed(1) + "s] " + m);

// ── 1. Landing → CTA
await page.goto(ROOT, { waitUntil: "domcontentloaded" });
await page.click('a.cta.primary[href="app/?tour=1"]');
await page.waitForSelector(".av-tour-card", { timeout: 20000 });
if (SLOW) {
  await page.evaluate(() => {
    const ds = window.dataSource;
    for (const k of Object.keys(Object.getOwnPropertyDescriptors(ds))) {
      if (typeof ds[k] !== "function" || k === "subscribe") continue;
      const orig = ds[k].bind(ds);
      ds[k] = (...a) => new Promise((r) => setTimeout(r, 300 + Math.random() * 400)).then(() => orig(...a));
    }
  });
  console.log("   (venue-wifi mode: 300–700ms jitter on every datasource call)");
}
beat("landing CTA → console, tour auto-started");

// ── 2. Tour: advance through all steps on their real targets
// Sync with the tour's own pacing: the card's step counter only
// updates after the tour's waitFor() anchors the target — under
// venue-wifi latency that can take a second per step. Fixed sleeps
// here produced false "target missing" failures.
const tourTargets = [".stat.savings", ".stat.blocks", 'tr[data-id="sess_01H9K"]', ".evt.err", ".receipt-card"];
for (let step = 0; step < tourTargets.length; step++) {
  await page.waitForFunction((n) => document.querySelector(".av-tour-step")?.textContent.includes("Step " + n + " of"), step + 1, { timeout: 20000 });
  const onTarget = await page.evaluate((sel) => {
    const t = document.querySelector(sel);
    if (!t) return false;
    const r = t.getBoundingClientRect();
    return r.width > 0 && r.height > 0;
  }, tourTargets[step]);
  if (!onTarget) {
    console.log("DEBUG", await page.evaluate(() => ({
      hash: location.hash,
      stepTxt: document.querySelector(".av-tour-step")?.textContent,
      rows: document.querySelectorAll("tr[data-clickable]").length,
      ids: [...document.querySelectorAll("tr[data-clickable]")].slice(0, 3).map((r) => r.getAttribute("data-id")),
      skl: !!document.querySelector("#view .skl"),
    })));
    fail("tour step " + step + " target missing: " + tourTargets[step]);
  }
  await page.evaluate(() => {
    const btns = [...document.querySelectorAll(".av-tour-card button")];
    (btns.find((x) => /next|→/i.test(x.textContent)) || btns[btns.length - 1]).click();
  });
}
await page.waitForFunction(() => document.querySelector(".av-tour-step")?.textContent.includes("Step 6 of"), { timeout: 20000 });
beat("tour: all 6 steps landed on live targets");

// ── 3. Finale CTA → verifier in a new tab → sample verifies green
const [verifyPage] = await Promise.all([
  context.waitForEvent("page", { timeout: 10000 }),
  page.evaluate(() => { [...document.querySelectorAll(".av-tour-card a, .av-tour-card button")].find((x) => /verifier/i.test(x.textContent)).click(); }),
]).catch(() => fail("tour finale verifier CTA did not open a tab"));
await verifyPage.waitForSelector("#loadExample", { timeout: 15000 });
await verifyPage.click("#loadExample");
await verifyPage.waitForFunction(() => {
  const t = document.querySelector(".result-title")?.textContent || "";
  return t.length > 0 && !/verifying/i.test(t);
}, { timeout: 15000 });
if (!/verifies/i.test(await verifyPage.locator(".result-title").innerText())) fail("sample receipt did not verify green in the finale tab");
await verifyPage.close();
beat("finale CTA → verifier tab → sample verifies green");

// ── 4. Back in the console: attack demo → story banner
await page.evaluate(() => { window.AVTour && window.AVTour.stop(); location.hash = "#/overview"; });
await page.waitForSelector("#simAttack", { timeout: 15000 });
await page.click("#simAttack");
await page.waitForFunction(() => [...document.querySelectorAll(".toast")].some((t) => /BLOCKED/i.test(t.textContent)), { timeout: 15000 });
const link = await page.waitForSelector('.toast a[href*="#/sessions/"]', { timeout: 15000 });
const attackHref = await link.getAttribute("href");
await page.evaluate((h) => { location.hash = h.slice(h.indexOf("#")); }, attackHref);
await page.waitForSelector("#eventList .evt", { timeout: 15000 });
if (!(await page.evaluate(() => /blocked/i.test(document.getElementById("view").textContent)))) fail("attack session page missing the blocked story");
beat("attack demo → blocked toast → injected session page");

// ── 5. Download the receipt from the attack session
await page.waitForSelector("#dlRcpt", { timeout: 10000 });
const [dl] = await Promise.all([page.waitForEvent("download", { timeout: 10000 }), page.click("#dlRcpt")]);
const path = await dl.path();
const bundle = JSON.parse((await import("node:fs")).readFileSync(path, "utf8"));
if (!bundle.receipt || !bundle.publicKey) fail("downloaded bundle malformed: " + Object.keys(bundle).join(","));
beat("receipt downloaded from the attack session (bundle sane)");

// ── 6. Sign out → fresh signup → onboarding at 1 of 4
await page.evaluate(() => { location.hash = "#/settings/general"; });
await page.waitForSelector("#signOut", { timeout: 10000 });
await page.click("#signOut");
await page.waitForSelector(".modal-backdrop [data-confirm]", { timeout: 5000 });
await page.click(".modal-backdrop [data-confirm]");
await page.waitForSelector("input#email", { timeout: 10000 });
await page.evaluate(() => { location.hash = "#/signup"; });
await page.waitForSelector("#orgName", { timeout: 10000 });
await page.fill("#orgName", "Rehearsal Robotics");
await page.fill("input#email", "founder@rehearsal.dev");
await page.fill("input#password", "rehearsal-password-1");
await page.click("button[type=submit]");
await page.waitForSelector(".onboard-card", { timeout: 15000 });
const ob = await page.evaluate(() => ({
  count: document.querySelector(".ob-count").textContent,
  org: document.querySelector(".org-switcher").textContent,
}));
if (!ob.count.startsWith("1 of") || !ob.org.includes("Rehearsal Robotics")) fail("fresh workspace wrong: " + JSON.stringify(ob));
beat("fresh signup → 'Rehearsal Robotics' onboarding at " + ob.count);

// ── 7. Reset demo data via the palette → Northwind restored
await page.click(".cmdk-trigger");
await page.waitForSelector(".cmdk-backdrop input", { timeout: 5000 });
await page.fill(".cmdk-backdrop input", "reset");
await page.waitForTimeout(300);
await page.keyboard.press("Enter");
await page.waitForFunction(() => document.querySelector(".org-switcher")?.textContent.includes("Northwind"), { timeout: 20000 });
beat("palette reset → pristine Northwind restored");

if (jsErrors.length) fail("JS errors during rehearsal: " + JSON.stringify([...new Set(jsErrors)]));
console.log("\nFull investor-flow rehearsal (" + (PHONE ? "phone/QR path" : "desktop") + (SLOW ? ", venue-wifi latency" : "") + ") passed in " + ((Date.now() - t0) / 1000).toFixed(1) + "s — the Saturday narrative holds end to end.");
await browser.close();
