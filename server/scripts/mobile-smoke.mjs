/*
 * Mobile viewport smoke: iPhone 13 (390x844 CSS pixels) and iPad
 * (768x1024). Investors will check the pitch on their phone during
 * the walk back to the elevator; if the console is broken there the
 * pitch is dead.
 *
 * Verifies:
 *   1. Landing page renders without horizontal scroll.
 *   2. Console login renders without horizontal scroll.
 *   3. Overview page renders on mobile.
 *   4. Sessions list on mobile — table stays inside viewport.
 *   5. Settings tabs reachable on mobile.
 */
import { chromium, devices } from "playwright";

const SITE = process.env.SITE ?? "https://agentvisorai.me/app/";
const LANDING = new URL(SITE).origin + "/";

const profiles = [
  { name: "iPhone 13", device: devices["iPhone 13"] },
  { name: "iPad (gen 7)", device: devices["iPad (gen 7)"] || devices["iPad Mini"] || devices["iPhone 13 Pro Max"] },
];

function fail(m) { console.log("❌", m); process.exit(1); }
async function wait(ms) { return new Promise((r) => setTimeout(r, ms)); }

const browser = await chromium.launch({ headless: true });
for (const { name, device } of profiles) {
  console.log("\n=== " + name + " (" + device.viewport.width + "x" + device.viewport.height + ") ===");
  const context = await browser.newContext(device);
  const page = await context.newPage();
  const jsErrors = [];
  page.on("pageerror", (e) => jsErrors.push(e.message));

  // 1. Landing page
  await page.goto(LANDING, { waitUntil: "networkidle" });
  await wait(400);
  const landingScrollX = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  if (landingScrollX > 8) fail(`${name} landing has horizontal scroll: ${landingScrollX}px overflow`);
  console.log("✅ landing: no horizontal scroll");

  // 2. Console login
  await page.addInitScript(() => { try { localStorage.setItem("av_mock_signed_out", "1"); } catch {} });
  await page.goto(SITE + "#/login", { waitUntil: "networkidle" });
  await page.waitForSelector("input#email", { timeout: 15000 });
  const loginScrollX = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  if (loginScrollX > 8) fail(`${name} login has horizontal scroll: ${loginScrollX}px overflow`);
  console.log("✅ login: no horizontal scroll");

  // 3. Overview
  await page.locator("input#email").fill("olivia.tan@northwind.com");
  await page.locator("input#password").fill("d3mo");
  await page.locator("button[type='submit']").first().click();
  await wait(1500);
  const bodyText = await page.locator("body").innerText();
  if (bodyText.length < 300) fail(`${name} overview nearly empty`);
  const ovScrollX = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  if (ovScrollX > 8) fail(`${name} overview has horizontal scroll: ${ovScrollX}px`);
  console.log("✅ overview: renders + no horizontal scroll");

  // 4. Sessions list — the table is the most likely offender for horizontal scroll
  await page.goto(SITE + "#/sessions");
  await wait(1200);
  const sessScrollX = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  // Tables inside .table-wrap are allowed to scroll, but the page body shouldn't.
  if (sessScrollX > 8) fail(`${name} sessions page-wide scroll: ${sessScrollX}px`);
  console.log("✅ sessions: no page-level horizontal scroll");

  // 5. Settings navigation
  await page.goto(SITE + "#/settings/general");
  await wait(800);
  await page.goto(SITE + "#/settings/webhooks");
  await wait(800);
  const setScrollX = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  if (setScrollX > 8) fail(`${name} settings has horizontal scroll: ${setScrollX}px`);
  console.log("✅ settings: no horizontal scroll");

  // Phone-width navigation: the sidebar is hidden ≤760px, so the
  // bottom tab bar is the ONLY way to switch sections. It shipped
  // missing once — phones could render pages but never leave them.
  // (Tablets keep the sidebar, so this only applies under 760px.)
  if (device.viewport.width <= 760) {
    await page.goto(SITE + "#/overview", { waitUntil: "domcontentloaded" });
    await page.waitForSelector(".tabbar", { timeout: 10000 });
    const tb = await page.evaluate(() => ({
      visible: getComputedStyle(document.querySelector(".tabbar")).display !== "none",
      tabs: document.querySelectorAll(".tabbar a").length,
    }));
    if (!tb.visible || tb.tabs !== 5) fail(`${name}: tab bar missing/incomplete: ${JSON.stringify(tb)}`);
    await page.click('.tabbar a[href="#/sessions"]');
    await new Promise((r) => setTimeout(r, 700));
    const nav = await page.evaluate(() => ({
      hash: location.hash,
      active: document.querySelector(".tabbar a.active")?.getAttribute("href"),
    }));
    if (nav.hash !== "#/sessions" || nav.active !== "#/sessions") fail(`${name}: tab navigation broken: ${JSON.stringify(nav)}`);
    console.log("✅ bottom tab bar: 5 tabs, tap navigates, active state follows");

    // Tap interactions that keyboard-first desktop testing never
    // exercises: the palette via the topbar search button, and the
    // event drawer via a row tap.
    await page.click("#cmdkOpen");
    await page.waitForSelector(".cmdk input", { timeout: 5000 });
    const palFits = await page.evaluate(() => {
      const r = document.querySelector(".cmdk").getBoundingClientRect();
      return r.left >= 0 && r.right <= innerWidth + 1;
    });
    if (!palFits) fail(`${name}: palette overflows the viewport`);
    await page.fill(".cmdk input", "policies");
    await new Promise((r) => setTimeout(r, 400));
    await page.click("#cmdkList .item.selected");
    await new Promise((r) => setTimeout(r, 700));
    if ((await page.evaluate(() => location.hash)) !== "#/policies") fail(`${name}: palette tap-run broken`);
    console.log("✅ palette: opens by tap, fits viewport, tap-run navigates");

    await page.goto(SITE + "#/sessions/sess_01H9K", { waitUntil: "domcontentloaded" });
    await page.waitForSelector(".evt", { timeout: 10000 });
    await page.click('.evt[data-i="2"]');
    await new Promise((r) => setTimeout(r, 500));
    const drawerFilled = await page.evaluate(() => document.querySelectorAll("#eventDrawer .meta dt").length >= 4);
    if (!drawerFilled) fail(`${name}: event tap does not fill the drawer`);
    console.log("✅ event stream: row tap fills the inspector drawer");

    // Chart tooltip on touch: hover-only meant the console's primary
    // visualization said nothing on phones.
    await page.goto(SITE + "#/overview", { waitUntil: "domcontentloaded" });
    await page.waitForSelector(".hover-strip", { timeout: 10000 });
    await page.click(".hover-strip >> nth=5");
    await new Promise((r) => setTimeout(r, 300));
    const tipShown = await page.evaluate(() => document.querySelector(".chart-tip")?.style.display === "block");
    if (!tipShown) fail(`${name}: chart tap tooltip missing`);
    console.log("✅ chart: tap pins the bucket tooltip");
  }

  if (jsErrors.length) fail(`${name} JS errors: ${jsErrors.join(" | ")}`);
  console.log("✅ zero JS errors on " + name);

  await context.close();
}
await browser.close();
console.log("\nAll mobile viewport smoke checks passed.");
