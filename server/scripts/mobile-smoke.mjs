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

const SITE = process.env.SITE ?? process.argv[2] ?? "https://agentvisorai.me/app/";
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

  // Modal usability on a phone: the deliveries table, the long SAML
  // form, and the token modal must fit the viewport with their action
  // buttons hittable (the sticky-actions bar keeps Save/Cancel on
  // screen even when a 9-field form scrolls internally). This probe
  // also guards the skeleton-phase dead-button class: #addDep paints
  // before its data resolves and must respond via the delegated
  // handler immediately.
  if (device.viewport.width <= 760) {
    const modals = [
      ["deliveries", "#/settings/webhooks", async () => { await page.waitForSelector("#whAdd", { timeout: 10000 }); await page.tap("tbody tr[data-id] td:nth-child(2)"); } ],
      ["saml-add", "#/settings/sso", async () => { await page.waitForSelector("#addSamlBtn", { timeout: 10000 }); await page.tap("#addSamlBtn"); } ],
      ["deployment-create", "#/deployments", async () => { await page.waitForSelector("#addDep", { timeout: 10000 }); await page.tap("#addDep"); } ],
    ];
    for (const [mname, route, open] of modals) {
      await page.evaluate((r) => { location.hash = r; }, route);
      await page.waitForTimeout(700);
      await open();
      await page.waitForSelector(".modal-backdrop .modal", { timeout: 6000 });
      await page.waitForTimeout(400);
      const m = await page.evaluate(() => {
        const modal = document.querySelector(".modal-backdrop .modal");
        const r = modal.getBoundingClientRect();
        const bad = [];
        for (const bn of modal.querySelectorAll(".actions button")) {
          const br = bn.getBoundingClientRect();
          if (br.width === 0) continue;
          const el = document.elementFromPoint(br.left + Math.min(br.width / 2, 20), br.top + br.height / 2);
          if (!(el && (bn === el || bn.contains(el) || bn === el.closest("button")))) bad.push(bn.textContent.trim() + " hit=" + (el ? el.tagName + "." + String(el.className).slice(0, 24) : "none") );
          if (br.bottom > innerHeight || br.top < 0) bad.push(bn.textContent.trim() + " offscreen");
        }
        return { fits: r.right <= innerWidth + 1 && r.left >= -1, hOverflow: document.documentElement.scrollWidth - document.documentElement.clientWidth, bad };
      });
      if (!m.fits || m.hOverflow > 0 || m.bad.length) fail(mname + " modal unusable at " + device.viewport.width + "px: " + JSON.stringify(m));
      // Stacking: the tab bar must sit BELOW the open modal's backdrop
      // (it used to float above it — a mid-form tab tap navigated and
      // destroyed the modal without confirmation).
      const tabUnder = await page.evaluate(() => {
        const tb = document.querySelector(".tabbar");
        if (!tb || getComputedStyle(tb).display === "none") return true;
        const tr = tb.getBoundingClientRect();
        const el = document.elementFromPoint(tr.left + 40, tr.top + tr.height / 2);
        return !!el && !!el.closest(".modal-backdrop");
      });
      if (!tabUnder) fail(mname + ": tab bar floats above the open modal");
      await page.keyboard.press("Escape");
      await page.waitForTimeout(300);
    }
    console.log("✅ modals fit + action buttons hittable on phone (deliveries, saml-add, deployment-create)");
    // Static pages on a phone: investors open these links from chat
    // apps — no horizontal overflow, and the pitch video fits.
    const ROOT = SITE.replace(/app\/?$/, "");
    for (const sp of ["", "pitch/", "verify/"]) {
      await page.goto(ROOT + sp, { waitUntil: "domcontentloaded" });
      await page.waitForTimeout(600);
      const ov = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
      if (ov > 0) fail("/" + sp + " overflows by " + ov + "px on phone");
      if (sp === "pitch/") {
        const vFits = await page.evaluate(() => {
          const v = document.querySelector("video");
          if (!v) return false;
          const r = v.getBoundingClientRect();
          return r.right <= innerWidth + 1 && r.left >= -1;
        });
        if (!vFits) fail("pitch video missing or overflows the phone viewport");
      }
    }
    await page.goto(SITE + "#/overview", { waitUntil: "domcontentloaded" });
    await page.waitForTimeout(800);
    console.log("✅ static pages (landing/pitch/verify) fit the phone viewport; video contained");
  }

  if (jsErrors.length) fail(`${name} JS errors: ${jsErrors.join(" | ")}`);
  console.log("✅ zero JS errors on " + name);

  await context.close();
}
await browser.close();

// ── Mid-width sweep: tablet / split-screen (640–900px) sits between the
// phone breakpoints and the desktop suites and used to be tested by
// nobody — the session-detail receipt buttons were clipped unreachable
// at 768–900px (no scrollbar; .main clips). Interactive elements must
// stay inside the viewport unless a scrollable ancestor makes them
// reachable.
{
  const b2 = await chromium.launch();
  for (const w of [640, 768, 900]) {
    const page = await (await b2.newContext({ viewport: { width: w, height: 900 } })).newPage();
    await page.goto(SITE + "#/overview", { waitUntil: "domcontentloaded" });
    await page.waitForSelector(".app-shell", { timeout: 15000 });
    for (const r of ["#/overview", "#/sessions", "#/sessions/sess_01H9K", "#/policies", "#/deployments", "#/settings/general", "#/settings/webhooks", "#/settings/billing"]) {
      await page.evaluate((h) => { location.hash = h; }, r);
      await page.waitForTimeout(800);
      const st = await page.evaluate(() => {
        const scrollable = (el) => {
          for (let p = el.parentElement; p; p = p.parentElement) {
            const cs = getComputedStyle(p);
            if (/(auto|scroll)/.test(cs.overflowX) && p.scrollWidth > p.clientWidth + 1) return true;
          }
          return false;
        };
        const bad = [];
        for (const el of document.querySelectorAll("button, a.btn, input, select")) {
          const r2 = el.getBoundingClientRect();
          if (r2.width === 0) continue;
          if ((r2.right > innerWidth + 1 || r2.left < -1) && !scrollable(el)) bad.push((el.id || el.textContent.trim().slice(0, 18)) + "@" + Math.round(r2.left) + "-" + Math.round(r2.right));
        }
        return { hOv: document.documentElement.scrollWidth - document.documentElement.clientWidth, bad: bad.slice(0, 5) };
      });
      if (st.hOv > 0 || st.bad.length) fail(`mid-width ${w}px ${r}: hOv=${st.hOv} unreachable=${JSON.stringify(st.bad)}`);
    }
    await page.close();
  }
  await b2.close();
  console.log("✅ mid-width sweep (640/768/900px): every control inside the viewport or a scrollable wrap");
}

console.log("\nAll mobile viewport smoke checks passed.");
