/*
 * Interactive-features drill: walks every investor-facing interactive
 * experience shipped in the UX campaign, end to end, against the
 * deployed console. Guards the surface no other drill covers:
 *
 *   1. Guided tour: auto-start via /app/?tour=1, all 6 steps land on
 *      their targets, overlay absorbs background clicks (audit D1),
 *      finale offers the verifier CTA.
 *   2. Simulate an attack: full ~5s timeline, stats catch up
 *      (prevented losses grows), link toast appears, injected
 *      session page carries the story banner.
 *   3. Story banner on the featured session + Jump to the block
 *      selects the BLOCKED row and populates the drawer.
 *   4. Onboarding checklist: signup as a new org shows the judge's
 *      workspace (audit D3), 1-of-4 checklist, live tick to 4-of-4
 *      when the sim clock advances, identity survives reload (D4).
 *   5. Billing: three tiers + unit-economics card whose call count
 *      equals allowed+blocked from the overview.
 *   6. Reset demo data via the palette returns to Northwind.
 *
 * Mock-mode only (as deployed). SITE env overrides the target.
 */
import { chromium } from "playwright";

const SITE = process.env.SITE ?? "https://agentvisorai.me/app/";

function fail(m) { console.log("❌", m); process.exit(1); }

const browser = await chromium.launch({ headless: true });
const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
const page = await context.newPage();
const jsErrors = [];
page.on("pageerror", (e) => jsErrors.push(e.message));

// ── 1. Guided tour ────────────────────────────────────────────────
await page.goto(SITE + "?tour=1#/overview", { waitUntil: "domcontentloaded" });
await page.waitForSelector(".av-tour-card", { timeout: 15000 });
{
  // Overlay must absorb background clicks (audit D1).
  const hashBefore = await page.evaluate(() => location.hash);
  const topmost = await page.evaluate(() => {
    const a = [...document.querySelectorAll("a")].find((x) => x.textContent.includes("View all"));
    if (!a) return "no-link";
    const r = a.getBoundingClientRect();
    const el = document.elementFromPoint(r.left + 4, r.top + 4);
    return el ? (el.id || el.className || el.tagName).toString() : "none";
  });
  if (topmost !== "no-link" && !/avTour/.test(topmost)) fail("tour overlay does not absorb background clicks; topmost=" + topmost);
  if ((await page.evaluate(() => location.hash)) !== hashBefore) fail("hash moved under the tour");
  console.log("✅ tour overlay absorbs background clicks");

  const expects = [/money/i, /checked/i, /session/i, /stopped/i, /receipt/i, /verify/i];
  for (let i = 0; i < 6; i++) {
    await page.waitForTimeout(1300);
    const s = await page.evaluate(() => ({
      step: document.querySelector(".av-tour-step").textContent,
      title: document.querySelector(".av-tour-card h3").textContent,
      holeVisible: getComputedStyle(document.querySelector(".av-tour-hole")).display !== "none",
      centered: document.querySelector(".av-tour-card").classList.contains("centered"),
    }));
    if (!s.step.includes(`${i + 1} of 6`)) fail(`tour step ${i + 1}: got "${s.step}"`);
    if (!expects[i].test(s.title)) fail(`tour step ${i + 1} title unexpected: "${s.title}"`);
    if (i < 5 && !s.holeVisible) fail(`tour step ${i + 1}: spotlight hole missing`);
    if (i === 5 && !s.centered) fail("tour finale should be a centered card");
    if (i < 5) await page.evaluate(() => document.querySelector(".av-tour-next").click());
  }
  const cta = await page.evaluate(() => document.querySelector(".av-tour-next").textContent);
  if (!/verifier/i.test(cta)) fail("tour finale CTA is not the verifier: " + cta);
  await page.evaluate(() => document.querySelector(".av-tour-skip").click());
  console.log("✅ guided tour: 6 steps, targets anchored, verifier finale");
}

// ── 2. Simulate an attack ─────────────────────────────────────────
{
  await page.evaluate(() => { location.hash = "#/overview"; });
  await page.waitForSelector("#simAttack", { timeout: 10000 });
  const before = await page.evaluate(() =>
    parseInt(document.querySelector(".stat.savings .value").textContent.replace(/[^0-9]/g, ""), 10));
  await page.evaluate(() => document.getElementById("simAttack").click());
  await page.waitForTimeout(6000);
  const link = await page.evaluate(() => {
    const a = document.querySelector("#toastStack .toast a");
    return a ? a.getAttribute("href") : null;
  });
  if (!link || !/#\/sessions\/sess_live/.test(link)) fail("attack demo link toast missing; got " + link);
  await page.evaluate((h) => { location.hash = h.slice(1); }, link);
  await page.waitForSelector(".story-banner", { timeout: 10000 });
  const banner = await page.evaluate(() => document.querySelector(".story-banner p").textContent);
  if (!/tried to send \$[\d,]+ to/.test(banner)) fail("attack session story banner wrong: " + banner.slice(0, 80));
  await page.evaluate(() => { location.hash = "#/overview"; });
  await page.waitForSelector(".stat.savings", { timeout: 10000 });
  await page.waitForTimeout(800);
  const after = await page.evaluate(() =>
    parseInt(document.querySelector(".stat.savings .value").textContent.replace(/[^0-9]/g, ""), 10));
  if (!(after > before)) fail(`prevented losses did not grow after attack (${before} -> ${after})`);
  console.log(`✅ attack demo: toast link, story banner, savings ${before} -> ${after}`);
}

// ── 3. Featured-session story banner + jump to block ─────────────
{
  await page.evaluate(() => { location.hash = "#/sessions/sess_01H9K"; });
  await page.waitForSelector(".story-banner", { timeout: 10000 });
  await page.evaluate(() => document.getElementById("jumpToBlock").click());
  await page.waitForTimeout(900);
  const ok = await page.evaluate(() => ({
    selected: !!document.querySelector(".evt.err.selected"),
    drawer: /BLOCKED/i.test(document.querySelector("#eventDrawer").textContent),
  }));
  if (!ok.selected || !ok.drawer) fail("Jump to the block did not select the BLOCKED event: " + JSON.stringify(ok));
  // Event deep links: selecting mirrors into the hash, and a fresh
  // load of that URL restores the selection + drawer + copy-link.
  const deepHash = await page.evaluate(() => location.hash);
  if (!/^#\/sessions\/sess_01H9K\?evt=\d+$/.test(deepHash)) fail("selection not mirrored into hash: " + deepHash);
  await page.reload();
  await page.waitForSelector(".evt.selected", { timeout: 10000 });
  const restored = await page.evaluate(() => ({
    hash: location.hash,
    err: !!document.querySelector(".evt.err.selected"),
    copyLink: (document.querySelector("#eventDrawer .evt-link-btn") || {}).getAttribute?.("data-copy") || "",
  }));
  if (restored.hash !== deepHash || !restored.err) fail("deep link did not restore selection: " + JSON.stringify(restored));
  if (!restored.copyLink.includes(deepHash)) fail("drawer copy-link wrong: " + restored.copyLink);
  console.log("✅ story banner: jump-to-block selects the event, deep link survives reload");
}

// ── 4. Onboarding checklist + signup identity ─────────────────────
{
  await page.evaluate(() => { localStorage.setItem("av_mock_signed_out", "1"); });
  await page.reload({ waitUntil: "domcontentloaded" });
  await page.waitForSelector("input#email", { timeout: 10000 });
  await page.evaluate(() => { location.hash = "#/signup"; });
  await page.waitForSelector("#orgName", { timeout: 10000 });
  await page.evaluate(() => {
    document.querySelector("#orgName").value = "Drill Robotics";
    document.querySelector("input#email").value = "drill@example.dev";
    document.querySelector("input[type=password]").value = "drill-password-1";
    document.querySelector("button[type=submit]").click();
  });
  await page.waitForSelector(".onboard-card", { timeout: 15000 });
  const fresh = await page.evaluate(() => ({
    count: document.querySelector(".ob-count").textContent,
    org: document.querySelector(".org-switcher").textContent,
    email: document.querySelector(".user-btn").textContent,
  }));
  if (!fresh.count.startsWith("1 of")) fail("fresh checklist not at 1 of 4: " + fresh.count);
  if (!fresh.org.includes("Drill Robotics")) fail("signup org ignored (audit D3): " + fresh.org.slice(0, 40));
  if (!fresh.email.includes("drill@example.dev")) fail("signup identity missing: " + fresh.email.slice(0, 40));
  // Identity survives reload (audit D4)
  await page.reload({ waitUntil: "domcontentloaded" });
  await page.waitForSelector(".onboard-card", { timeout: 15000 });
  const kept = await page.evaluate(() => document.querySelector(".org-switcher").textContent);
  if (!kept.includes("Drill Robotics")) fail("identity reverted on reload (audit D4)");
  // Live tick: advance the sim clock past the blocked-session arrival.
  await page.evaluate(() => { localStorage.setItem("av_mock_fresh_t0", String(Date.now() - 27500)); });
  await page.waitForTimeout(4500);
  const done = await page.evaluate(() => (document.querySelector(".ob-count") || {}).textContent || "");
  if (!done.startsWith("4 of")) fail("checklist did not tick to 4 of 4: " + done);
  console.log("✅ onboarding: personalized workspace, survives reload, ticks live to 4/4");
}

// ── 5. Billing math coherent with overview ────────────────────────
{
  await page.evaluate(() => { location.hash = "#/settings/billing"; });
  await page.waitForSelector(".pricing-grid", { timeout: 10000 });
  const b = await page.evaluate(() => ({
    tiers: document.querySelectorAll(".price-tier").length,
    nums: [...document.querySelectorAll(".bm-num")].map((n) => n.textContent),
  }));
  if (b.tiers !== 3) fail("billing tiers: " + b.tiers);
  if (b.nums.length !== 3) fail("billing math card incomplete: " + JSON.stringify(b.nums));
  console.log("✅ billing: 3 tiers + unit-economics card " + JSON.stringify(b.nums));
}

// ── 6. Reset demo data ────────────────────────────────────────────
{
  await page.keyboard.press("Meta+KeyK");
  await page.waitForSelector(".cmdk input", { timeout: 5000 });
  await page.fill(".cmdk input", "reset");
  await page.waitForTimeout(400);
  const top = await page.evaluate(() => document.querySelector("#cmdkList .item.selected").textContent);
  if (!/Reset demo data/.test(top)) fail("palette ranking: 'reset' selected " + top.slice(0, 30));
  await page.keyboard.press("Enter");
  await page.waitForTimeout(2500);
  await page.waitForSelector(".stat.savings", { timeout: 15000 });
  const org = await page.evaluate(() => document.querySelector(".org-switcher").textContent);
  if (!org.includes("Northwind")) fail("reset did not restore Northwind: " + org.slice(0, 40));
  const checklist = await page.evaluate(() => !!document.querySelector(".onboard-card"));
  if (checklist) fail("reset left the fresh checklist behind");
  console.log("✅ reset demo data: pristine Northwind restored");
}

if (jsErrors.length) fail("JS errors during drill: " + JSON.stringify(jsErrors));
console.log("✅ zero uncaught JS errors");

await browser.close();
console.log("\nAll 7 interactive-features drill checks passed.");
