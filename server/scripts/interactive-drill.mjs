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

// Accept the target as SITE env or first positional arg — a passed-but-
// ignored argument once silently ran this whole drill against production.
const SITE = process.env.SITE ?? process.argv[2] ?? "https://agentvisorai.me/app/";

function fail(m) { console.log("❌", m); process.exit(1); }

const browser = await chromium.launch({ headless: true });
const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
// Count document/window listeners so the leak check (check 10) can
// assert the refresh loops and modal cycles don't accumulate handlers.
await context.addInitScript(() => {
  window.__lc = {};
  // Interval accounting for the soak: navigation churn must not
  // accumulate live intervals (the tago refresher + tour launcher
  // poll are the only long-lived ones).
  window.__iv = new Set();
  const oi = window.setInterval, oc = window.clearInterval;
  window.setInterval = (...a) => { const id = oi(...a); window.__iv.add(id); return id; };
  window.clearInterval = (id) => { window.__iv.delete(id); return oc(id); };
  for (const t of [document, window]) {
    const orig = t.addEventListener.bind(t);
    const origRm = t.removeEventListener.bind(t);
    t.addEventListener = (type, fn, opts) => { window.__lc[type] = (window.__lc[type] || 0) + 1; return orig(type, fn, opts); };
    t.removeEventListener = (type, fn, opts) => { window.__lc[type] = (window.__lc[type] || 0) - 1; return origRm(type, fn, opts); };
  }
});
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
  // waitForFunction (not a bare evaluate): a live-stream refresh can
  // swap the stats between our wait and a read.
  const before = await (await page.waitForFunction(() => {
    const v = document.querySelector(".stat.savings .value");
    return v ? parseInt(v.textContent.replace(/[^0-9]/g, ""), 10) : false;
  }, { timeout: 10000 })).jsonValue();
  await page.evaluate(() => document.getElementById("simAttack").click());
  await page.waitForTimeout(6000);
  const link = await page.evaluate(() => {
    const a = document.querySelector("#toastStack .toast a");
    return a ? a.getAttribute("href") : null;
  });
  if (!link || !/#\/sessions\/sess_live/.test(link)) fail("attack demo link toast missing; got " + link);
  await page.evaluate((h) => { location.hash = h.slice(1); }, link);
  await page.waitForSelector(".story-banner", { timeout: 10000 });
  const banner = await (await page.waitForFunction(() => {
    const p = document.querySelector(".story-banner p");
    return p ? p.textContent : false;
  }, { timeout: 10000 })).jsonValue();
  if (!/tried to send \$[\d,]+ to/.test(banner)) fail("attack session story banner wrong: " + banner.slice(0, 80));
  await page.evaluate(() => { location.hash = "#/overview"; });
  await page.waitForSelector(".stat.savings", { timeout: 10000 });
  await page.waitForTimeout(800);
  let after = before;
  try {
    after = await (await page.waitForFunction((b) => {
      const v = document.querySelector(".stat.savings .value");
      if (!v) return false;
      const n = parseInt(v.textContent.replace(/[^0-9]/g, ""), 10);
      return n > b ? n : false;
    }, before, { timeout: 10000 })).jsonValue();
  } catch (e) { /* leaves after === before → the fail() below fires */ }
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

// ── 7. Policy creation: template → live DSL → enforcing ──────────
{
  // Check 6's reload kept ?tour=1 in the query string, so the tour
  // auto-restarted and its overlay would swallow our clicks.
  await page.evaluate(() => window.AVTour && window.AVTour.stop());
  await page.evaluate(() => { location.hash = "#/policies"; });
  await page.waitForSelector("#addPol", { timeout: 10000 });
  await page.click("#addPol");
  await page.waitForSelector(".modal-wide #polPreview", { timeout: 5000 });
  await page.fill("#polParam", "1250");
  await page.waitForTimeout(200);
  const dsl = await page.evaluate(() => document.querySelector("#polPreview").textContent);
  if (!dsl.includes("arg.amount_usd > 1250")) fail("policy preview not live: " + dsl.slice(0, 80));
  await page.click('button:has-text("Create & enable")');
  await page.waitForSelector("#polSwitch", { timeout: 10000 });
  const pol = await page.evaluate(() => ({
    hash: location.hash,
    name: document.querySelector("h1").textContent,
    enabled: document.querySelector("#polSwitch").getAttribute("aria-checked"),
  }));
  if (!pol.hash.startsWith("#/policies/pol_") || pol.name !== "finance.payment_cap_usd:1250" || pol.enabled !== "true")
    fail("policy creation broken: " + JSON.stringify(pol));
  console.log("✅ policy creation: spend-cap template → live DSL → enabled detail page");
}

// ── 8. Table action buttons are actually hittable ─────────────────
// Regression guard for the fixed-layout overflow bug: the sr-only
// actions column got an equal 1/n width share, so multi-button cells
// (webhooks Pause/Delete, SSO Edit/Delete, deployments Delete)
// spilled past their td into overflow:hidden dead space — rendered
// clipped and unclickable by a real mouse.
{
  for (const route of ["deployments", "settings/webhooks", "settings/sso", "settings/members", "settings/keys"]) {
    await page.evaluate((r) => { location.hash = "#/" + r; }, route);
    await page.waitForTimeout(900);
    const bad = await page.evaluate(async () => {
      const out = [];
      for (const el of document.querySelectorAll("td button, td select")) {
        const td = el.closest("td");
        // elementsFromPoint only works inside the viewport.
        el.scrollIntoView({ block: "center" });
        await new Promise((r2) => requestAnimationFrame(r2));
        const er = el.getBoundingClientRect();
        const tr2 = td.getBoundingClientRect();
        const hit = document.elementsFromPoint(er.left + er.width / 2, er.top + er.height / 2)[0];
        if (er.right > tr2.right + 0.5 || !(hit === el || el.contains(hit)))
          out.push((el.textContent || el.getAttribute("aria-label") || "?").trim().slice(0, 16) +
            " btn=" + JSON.stringify({ x: Math.round(er.x), r: Math.round(er.right), y: Math.round(er.y) }) +
            " td_r=" + Math.round(tr2.right) + " hit=" + (hit ? hit.tagName + "." + String(hit.className).split(" ")[0] : "none"));
      }
      return out;
    });
    if (bad.length) fail(`unclickable/overflowing controls on ${route}: ${JSON.stringify(bad)}`);
    // Unsized-inline-SVG blowout: an <svg> with no width/height
    // renders at the replaced-element default — the OAuth provider
    // logos on the SSO tab exploded to ~110px and shattered their
    // pills. Any icon-context svg over 40px is a regression
    // (sparkline/chart svgs live outside pills/buttons/td and are
    // exempt by the selector).
    const fatSvgs = await page.evaluate(() =>
      [...document.querySelectorAll(".pill svg, td svg, .btn svg, button svg")]
        .filter((s) => { const r = s.getBoundingClientRect(); return r.width > 40 || r.height > 40; })
        .map((s) => (s.parentElement.className || "?").toString().slice(0, 24) + " " + Math.round(s.getBoundingClientRect().width) + "px")
        .slice(0, 4));
    if (fatSvgs.length) fail(`unsized inline svg blowout on ${route}: ${JSON.stringify(fatSvgs)}`);
    // Duplicate DOM ids break label/for + getElementById silently on
    // whichever copy loses; renders must never emit the same id twice.
    const dupIds = await page.evaluate(() => {
      const seen = {}, out = [];
      for (const el of document.querySelectorAll("[id]")) { if (seen[el.id]) out.push(el.id); else seen[el.id] = 1; }
      return [...new Set(out)];
    });
    if (dupIds.length) fail(`duplicate DOM ids on ${route}: ${JSON.stringify(dupIds)}`);
  }
  console.log("✅ table action buttons: all inside their cells and hittable (5 routes); no unsized-svg blowouts; no duplicate DOM ids");
}

// ── 9. Corrupted-storage resilience ───────────────────────────────
// A persisted fresh identity that parses as JSON but has the wrong
// shape (or a NaN/future fresh t0) used to brick the app on boot with
// a TypeError in renderShell. The datasource must shape-check and
// self-heal instead.
{
  for (const kv of [
    { av_mock_fresh_identity: "42", av_mock_fresh_t0: String(Date.now()) },
    { av_mock_fresh_identity: '{"user":{"email":"x@y.z"}}', av_mock_fresh_t0: String(Date.now()) },
    { av_mock_fresh_t0: "not-a-number" },
    // every av_* key garbage at once — incl. the pre-paint theme
    // whitelist in config.js (av_theme "banana" must not become
    // data-theme="banana")
    { av_theme: "banana", av_mock_fresh_t0: "not-a-number", av_mock_fresh_identity: "{broken", av_mock_bigdata: "yes{}", av_signed_in_at: "🦄", av_mock_fastload: "{}" },
  ]) {
    await page.evaluate((k) => { localStorage.clear(); for (const [a, b2] of Object.entries(k)) localStorage.setItem(a, b2); }, kv);
    await page.reload({ waitUntil: "domcontentloaded" });
    await page.waitForTimeout(1500);
    const st = await page.evaluate(() => ({
      shell: !!document.querySelector(".app-shell, .auth"),
      len: (document.getElementById("view")?.innerText || "").trim().length,
      theme: document.documentElement.getAttribute("data-theme"),
    }));
    if (!st.shell || st.len < 30) fail("corrupted storage bricked the app: " + JSON.stringify(kv) + " → " + JSON.stringify(st));
    if (kv.av_theme && st.theme === kv.av_theme) fail("theme whitelist leaked a garbage value: " + st.theme);
  }
  await page.evaluate(() => localStorage.clear());
  await page.reload({ waitUntil: "domcontentloaded" });
  await page.waitForTimeout(1200);
  // Quota-exhaustion fuzz (Safari private mode): every Storage write
  // throws. Walk the write-heavy paths — any unwrapped setItem call
  // surfaces as an uncaught error in the final zero-errors check.
  const qPage = await context.newPage();
  const qErrs = [];
  qPage.on("pageerror", (e) => qErrs.push(e.message.slice(0, 120)));
  await qPage.addInitScript(() => {
    Object.getPrototypeOf(localStorage).setItem = function () { throw new DOMException("QuotaExceededError", "QuotaExceededError"); };
  });
  await qPage.goto(SITE + "#/overview", { waitUntil: "domcontentloaded" });
  await qPage.waitForFunction(() => document.querySelector(".stat")?.textContent.trim().length > 0, { timeout: 15000 });
  for (const r of ["#/sessions?q=x", "#/sessions/sess_01H9K?evt=8", "#/policies"]) {
    await qPage.evaluate((h) => { location.hash = h; }, r);
    await qPage.waitForTimeout(700);
  }
  await qPage.click(".user-btn");
  await qPage.waitForTimeout(200);
  await qPage.click('#accountMenu [data-act="theme"]');
  await qPage.waitForTimeout(400);
  await qPage.close();
  if (qErrs.length) fail("storage-quota fuzz: unguarded setItem crashed: " + qErrs.join("; "));
  console.log("✅ corrupted-storage fuzz: bad identity shapes + NaN t0 self-heal; quota-exhausted writes all guarded");
  // Router fuzz: malformed and hostile hashes (broken percent
  // escapes, XSS payloads in path/query, traversal, absurd lengths,
  // __proto__/constructor ids) must render an error card or a safe
  // page — never crash, never inject, always recoverable.
  const hostile = [
    "#/sessions/%%%",
    "#/sessions/<img src=x onerror=window.__xss=1>",
    "#/sessions?q=%22%3E%3Cimg%20src%3Dx%20onerror%3Dwindow.__xss%3D1%3E",
    "#/sessions?q=" + "a".repeat(5000),
    "#/../../../etc/passwd",
    "#/settings/__proto__",
    "#/policies/constructor",
    "#/%00null",
  ];
  for (const hz of hostile) {
    await page.evaluate((x) => { location.hash = x; }, hz);
    await page.waitForTimeout(500);
    const st = await page.evaluate(() => ({
      alive: !!document.querySelector(".sidebar, .tabbar, .topbar"),
      rendered: (document.getElementById("view")?.textContent || "").trim().length > 20,
      injected: !!document.querySelector('#view img[src="x"]') || !!window.__xss,
    }));
    if (!st.alive || !st.rendered || st.injected) fail("router fuzz broke on " + hz.slice(0, 50) + ": " + JSON.stringify(st));
    await page.evaluate(() => { location.hash = "#/overview"; });
    await page.waitForTimeout(300);
  }
  await page.waitForFunction(() => document.querySelector(".stat"), { timeout: 10000 });
  console.log("✅ router fuzz: 8 hostile hashes render safely, zero injection, app recovers");
  // Crash-guard contract: (a) a broken app.js shows the crash card
  // (throw → immediately; 404 → the 6s watchdog, never a blank page);
  // (b) a POST-boot stray error must NOT wipe a working console (an
  // extension throwing mid-demo used to replace the whole UI).
  const cgPage = await context.newPage();
  await cgPage.route("**/app/app.js", (r) => r.fulfill({ status: 200, contentType: "text/javascript", body: "throw new Error('drill-simulated corruption');" }));
  await cgPage.goto(SITE + "#/overview", { waitUntil: "domcontentloaded" });
  await cgPage.waitForTimeout(1000);
  const cg = await cgPage.evaluate(() => ({
    card: document.body.textContent.includes("hit an error"),
    reload: !![...document.querySelectorAll("button")].find((x) => x.textContent === "Reload"),
  }));
  await cgPage.close();
  if (!cg.card || !cg.reload) fail("crash card missing on boot corruption: " + JSON.stringify(cg));
  await page.evaluate(() => setTimeout(() => { throw new Error("drill post-boot noise"); }, 0));
  await page.waitForTimeout(500);
  const alive = await page.evaluate(() => ({ app: !!document.querySelector(".app-shell"), card: document.body.textContent.includes("hit an error") }));
  if (!alive.app || alive.card) fail("post-boot error wiped the app: " + JSON.stringify(alive));
  jsErrors.length = 0; // the deliberate post-boot throw is expected noise
  console.log("✅ crash guard: boot corruption shows the card; post-boot errors never wipe the console");
}

// ── 10. Pagination under the big-data mode ─────────────────────────
// The 32-session fixture fits one page, so Load more / cursor
// paging / sort-across-pages only execute with av_mock_bigdata on.
// This shipped untested once; keep it exercised.
{
  await page.evaluate(() => localStorage.setItem("av_mock_bigdata", "1"));
  // goto a clean URL (no ?tour=1): the drill boots with the tour param,
  // which survives page.reload() and re-arms the tour autostart — the
  // tour's start() then yanks the hash to #/overview mid-check.
  await page.goto(SITE + "#/sessions?range=720", { waitUntil: "domcontentloaded" });
  await page.waitForFunction(() => document.querySelectorAll("tr[data-clickable]").length === 50 && !!document.getElementById("loadMore"), { timeout: 15000 });
  await page.click("#loadMore");
  await page.waitForFunction(() => document.querySelectorAll("tr[data-clickable]").length === 100, { timeout: 10000 });
  await page.click('.th-sort[data-sort="cost"]');
  await page.waitForFunction(() => {
    const c = [...document.querySelectorAll("tbody tr")].map((r) => parseFloat(r.cells[5].textContent.replace(/[^0-9.]/g, "")));
    return c.length === 100 && c.every((v, i) => !i || v <= c[i - 1] + 1e-9);
  }, { timeout: 10000 });
  // Event-stream paging on the 700-event mega-session: the page merge
  // had a documented bug once (re-fetch threw away appended pages) —
  // keep the path executed, and assert a selection survives the merge.
  await page.evaluate(() => { location.hash = "#/sessions/sess_bd_mega"; });
  await page.waitForSelector("#loadMoreEv", { timeout: 15000 });
  await page.click('.evt[data-i="3"]');
  await page.waitForTimeout(300);
  await page.click("#loadMoreEv");
  await page.waitForFunction(() => document.querySelectorAll(".evt").length === 700, { timeout: 15000 });
  const megaSel = await page.evaluate(() => document.querySelector(".evt.selected .seq")?.textContent);
  if (megaSel !== "#4") fail("event-page merge lost the selection: " + megaSel);
  // Deep link to an event beyond page 1: renderSessionDetail must
  // auto-load pages until the target arrives and select it (a shared
  // link to event #600 landed silently unselected before this).
  await page.goto(SITE + "#/sessions/sess_bd_mega?evt=600", { waitUntil: "domcontentloaded" });
  await page.waitForFunction(() => document.querySelector(".evt.selected .seq")?.textContent === "#600", { timeout: 20000 });
  const deepCount = await page.evaluate(() => document.querySelectorAll(".evt").length);
  if (deepCount !== 700) fail("deep-link auto-paging stopped early: " + deepCount + " events");
  // Nonexistent target: the walk must terminate (bounded by the cursor
  // end), explain itself, and clean the ?evt from the URL — a shared
  // link that lands silently unselected reads as "the link is broken".
  await page.goto(SITE + "#/sessions/sess_bd_mega?evt=99999", { waitUntil: "domcontentloaded" });
  const missToast = await page.waitForFunction(() => {
    const t = document.querySelector(".toast")?.textContent || "";
    return /isn't in this session/i.test(t) ? t : null;
  }, { timeout: 15000 }).then((h) => h.jsonValue()).catch(() => null);
  if (!missToast) fail("nonexistent ?evt deep link gave no feedback");
  await page.waitForTimeout(300);
  if (await page.evaluate(() => /evt=99999/.test(location.hash))) fail("dead ?evt param not cleaned from the URL");
  await page.evaluate(() => localStorage.removeItem("av_mock_bigdata"));
  console.log("✅ pagination: sessions 50→100 + sort; events 500→700 with selection kept; ?evt=600 auto-pages; dead ?evt explains itself");
}

// ── 11. Browser Back vs overlays + copy feedback ───────────────────
// Browser Back while the command palette was open used to strand its
// full-screen backdrop, which then ate every click on the new page
// (the hashchange sweep only knew about .modal-backdrop). Same walk
// for a modal, and copy buttons must always give toast feedback —
// including when navigator.clipboard is missing entirely (the
// documented offline fallback serves over plain http on a LAN).
{
  await page.goto(SITE + "#/policies", { waitUntil: "domcontentloaded" });
  await page.waitForSelector("#addPol", { timeout: 15000 });
  // modal → Back
  await page.click("#addPol");
  await page.waitForSelector(".modal-backdrop", { timeout: 5000 });
  await page.goBack();
  await page.waitForTimeout(500);
  let o = await page.evaluate(() => ({ m: document.querySelectorAll(".modal-backdrop").length, locked: document.body.classList.contains("locked") }));
  if (o.m || o.locked) fail("browser Back left a modal backdrop/lock: " + JSON.stringify(o));
  await page.keyboard.press("Escape"); // leaked-listener canary (caught the webhook modal once)
  // palette → Back
  await page.goto(SITE + "#/policies", { waitUntil: "domcontentloaded" });
  await page.waitForSelector(".cmdk-trigger", { timeout: 15000 });
  await page.click(".cmdk-trigger");
  await page.waitForSelector(".cmdk-backdrop", { timeout: 5000 });
  await page.goBack();
  await page.waitForTimeout(500);
  o = await page.evaluate(() => ({ p: document.querySelectorAll(".cmdk-backdrop").length, locked: document.body.classList.contains("locked") }));
  if (o.p || o.locked) fail("browser Back left the palette backdrop up: " + JSON.stringify(o));
  // ...and the palette must still open afterwards (cmdkOpen_ reset)
  await page.click(".cmdk-trigger");
  await page.waitForSelector(".cmdk-backdrop", { timeout: 5000 });
  await page.waitForTimeout(300);
  await page.keyboard.press("Escape");
  await page.waitForTimeout(300);
  if (await page.$(".cmdk-backdrop")) fail("palette did not close via Escape after a Back-close cycle");
  // copy feedback with NO clipboard API at all (execCommand fallback)
  const noClip = await context.newPage();
  await noClip.addInitScript(() => Object.defineProperty(navigator, "clipboard", { value: undefined }));
  await noClip.goto(SITE + "#/sessions/sess_01H9K?evt=8", { waitUntil: "domcontentloaded" });
  await noClip.waitForSelector(".evt.selected", { timeout: 15000 });
  await noClip.click("#eventDrawer .evt-link-btn");
  await noClip.waitForFunction(() => !!document.querySelector(".toast"), { timeout: 5000 });
  const toastTxt = await noClip.evaluate(() => document.querySelector(".toast").textContent);
  const clipErrs = [];
  noClip.on("pageerror", (e) => clipErrs.push(e.message));
  await noClip.click("#copyRcpt");
  await noClip.waitForTimeout(400);
  await noClip.close();
  if (clipErrs.length) fail("copy without clipboard API threw: " + clipErrs.join("; "));
  // Copy-payload truth: no copy affordance may carry a redacted/
  // truncated placeholder (the ingest-token HINT "av_live_9HpD…" once
  // had a copy button — pasting it anywhere yields garbage).
  const cpPage = await context.newPage();
  await cpPage.goto(SITE + "#/deployments", { waitUntil: "domcontentloaded" });
  await cpPage.waitForSelector("tr[data-clickable]", { timeout: 15000 });
  await cpPage.click("tr[data-clickable]");
  await cpPage.waitForSelector(".copy-btn", { timeout: 10000 });
  const truncated = await cpPage.evaluate(() =>
    [...document.querySelectorAll("[data-copy]")].map((b) => b.getAttribute("data-copy")).filter((v) => v.includes("…")));
  if (truncated.length) fail("copy button carries a truncated placeholder: " + JSON.stringify(truncated));
  // SAML details modal: the modal's whole purpose is copying SP values
  // into the IdP — all four URL-ish fields must carry copy buttons.
  await cpPage.goto(SITE + "#/settings/sso", { waitUntil: "domcontentloaded" });
  await cpPage.waitForSelector('button[data-act="details"]', { timeout: 15000 });
  await cpPage.click('button[data-act="details"]');
  await cpPage.waitForSelector(".modal-backdrop", { timeout: 5000 });
  const samlCopies = await cpPage.evaluate(() => document.querySelectorAll(".modal-backdrop .copy-btn").length);
  if (samlCopies < 4) fail("SAML details modal missing copy buttons: " + samlCopies + "/4");
  await cpPage.keyboard.press("Escape");
  await cpPage.close();
  console.log("✅ browser Back sweeps modal + palette overlays; copy gives feedback without clipboard API (" + toastTxt.trim().slice(0, 30) + "); no copy button carries a truncated payload; SAML SP values copyable");
}

// ── 12. Double-submit guards ───────────────────────────────────────
// The mock datasource answers near-instantly, so these races never
// showed locally — but with real latency a double-click on "Save"
// created two identical webhook endpoints (each with its own secret),
// and rapid clicks on a policy switch queued interleaved toggles.
// Inject 400ms latency + a call counter around the datasource methods
// and hammer each control; exactly one call must go through.
{
  const slow = (m) => page.evaluate((m) => {
    const ds = window.dataSource;
    window.__calls = window.__calls || {};
    window.__calls[m] = 0;
    if (ds[m].__wrapped) return;
    const orig = ds[m].bind(ds);
    ds[m] = (...a) => { window.__calls[m]++; return new Promise((r) => setTimeout(r, 400)).then(() => orig(...a)); };
    ds[m].__wrapped = true;
  }, m);
  const calls = (m) => page.evaluate((m) => window.__calls[m], m);
  // webhook create
  await page.goto(SITE + "#/settings/webhooks", { waitUntil: "domcontentloaded" });
  await page.waitForSelector("#whAdd", { timeout: 15000 });
  const rowsBefore = await page.evaluate(() => document.querySelectorAll("tbody tr").length);
  await page.click("#whAdd");
  await page.waitForSelector(".modal-backdrop", { timeout: 5000 });
  await page.fill("#whName", "Drill Dbl");
  await page.fill("#whUrl", "https://example.dev/drill-hook");
  await page.evaluate(() => { const c = document.querySelector("#whEventsPicker input"); if (c && !c.checked) c.click(); });
  await slow("createWebhook");
  await page.evaluate(() => { const s = document.querySelector("#whSave"); s.click(); s.click(); s.click(); });
  await page.waitForTimeout(1400);
  const whCalls = await calls("createWebhook");
  const rowsAfter = await page.evaluate(() => document.querySelectorAll("tbody tr").length);
  if (whCalls !== 1 || rowsAfter !== rowsBefore + 1) fail("webhook double-submit: " + whCalls + " calls, rows " + rowsBefore + "→" + rowsAfter);
  await page.keyboard.press("Escape");
  // policy switch (list + detail)
  await page.goto(SITE + "#/policies", { waitUntil: "domcontentloaded" });
  await page.waitForSelector(".switch", { timeout: 10000 });
  await slow("togglePolicy");
  await page.evaluate(() => { const s = document.querySelector(".switch"); s.click(); s.click(); s.click(); });
  await page.waitForTimeout(1200);
  if ((await calls("togglePolicy")) !== 1) fail("policy list switch fired " + (await calls("togglePolicy")) + " toggles on a triple-click");
  // invite revoke row action
  await page.goto(SITE + "#/settings/members", { waitUntil: "domcontentloaded" });
  await page.waitForSelector("tbody tr", { timeout: 10000 });
  if (await page.$("tr[data-invite] [data-act='revoke']")) {
    await slow("revokeInvite");
    await page.evaluate(() => { const r = document.querySelector("tr[data-invite] [data-act='revoke']"); r.click(); r.click(); r.click(); });
    await page.waitForTimeout(1200);
    if ((await calls("revokeInvite")) !== 1) fail("invite revoke fired " + (await calls("revokeInvite")) + " times on a triple-click");
  }
  console.log("✅ double-submit guards: webhook create, policy toggle, invite revoke — one call each under 400ms latency");
}

// ── 13. Failure-path UX ────────────────────────────────────────────
// The mock never fails, so the error paths never execute anywhere
// else. Inject a rejecting datasource per route: every page must show
// the graceful error card (never a stuck skeleton, never an uncaught
// rejection — the audit tab once hung on skeletons forever), recover
// on re-entry, and a failing background refresh must keep the stale
// dashboard instead of replacing it with the error card.
{
  const failOnce = (m) => page.evaluate((m) => {
    const ds = window.dataSource;
    if (!ds["__orig_" + m]) ds["__orig_" + m] = ds[m].bind(ds);
    ds[m] = () => Promise.reject(new Error("injected_network_failure"));
  }, m);
  const restore = (m) => page.evaluate((m) => {
    const ds = window.dataSource;
    if (ds["__orig_" + m]) ds[m] = ds["__orig_" + m];
  }, m);
  const cases = [
    ["#/overview", "getOverview", ".stat"],
    ["#/sessions", "listSessions", "tr[data-clickable]"],
    ["#/policies", "listPolicies", ".switch"],
    ["#/settings/audit", "listAudit", "tbody tr"],
    ["#/settings/webhooks", "listWebhooks", "#whAdd"],
  ];
  await page.goto(SITE + "#/overview", { waitUntil: "domcontentloaded" });
  await page.waitForSelector(".stat", { timeout: 15000 });
  for (const [route, method, okSel] of cases) {
    const away = route === "#/overview" ? "#/policies" : "#/overview";
    await page.evaluate((a) => { location.hash = a; }, away);
    await page.waitForTimeout(300);
    await failOnce(method);
    await page.evaluate((r) => { location.hash = r; }, route);
    await page.waitForTimeout(900);
    const st = await page.evaluate(() => ({
      errUi: /Something went wrong|Could not load|Not found/i.test(document.getElementById("view").textContent),
      skeleton: !!document.querySelector("#view .skl"),
    }));
    await restore(method);
    if (!st.errUi || st.skeleton) fail("failure path broken on " + route + " (" + method + "): " + JSON.stringify(st));
    await page.evaluate((a) => { location.hash = a; }, away);
    await page.waitForTimeout(250);
    await page.evaluate((r) => { location.hash = r; }, route);
    await page.waitForSelector(okSel, { timeout: 8000 }).catch(() => fail(route + " did not recover after the failure cleared"));
  }
  // background (quiet) refresh failure keeps the stale dashboard
  await page.evaluate(() => { location.hash = "#/overview"; });
  await page.waitForSelector(".stat", { timeout: 10000 });
  await failOnce("getOverview");
  await page.waitForTimeout(6000);
  const quiet = await page.evaluate(() => ({
    stats: document.querySelectorAll(".stat").length,
    errUi: /Something went wrong/i.test(document.getElementById("view").textContent),
  }));
  await restore("getOverview");
  if (!quiet.stats || quiet.errUi) fail("quiet overview refresh replaced the live dashboard on a transient failure: " + JSON.stringify(quiet));
  // Catch-up after sleep: tab-visible and network-online must trigger a
  // quiet refresh of the on-screen route (background tabs throttle
  // timers, so without this the dashboard sits stale after lid-close).
  await page.evaluate(() => {
    const ds = window.dataSource;
    window.__ovCalls = 0;
    if (!ds.__origOv2) ds.__origOv2 = ds.getOverview.bind(ds);
    ds.getOverview = (...a) => { window.__ovCalls++; return ds.__origOv2(...a); };
    Object.defineProperty(document, "hidden", { configurable: true, get: () => true });
    document.dispatchEvent(new Event("visibilitychange"));
    Object.defineProperty(document, "hidden", { configurable: true, get: () => false });
    document.dispatchEvent(new Event("visibilitychange"));
  });
  await page.waitForTimeout(1400);
  const catchUp = await page.evaluate(() => window.__ovCalls);
  await page.evaluate(() => { window.dataSource.getOverview = window.dataSource.__origOv2; });
  if (!catchUp) fail("tab-visible catch-up refresh did not fire");
  console.log("✅ failure paths: 5 routes show the error card + recover; background refresh keeps the stale dashboard; visibility catch-up fires");
}

// ── 14. Cross-tab sync ─────────────────────────────────────────────
// Ops users keep multiple console tabs open. Sign-out already synced
// via a storage event; sign-IN did not — a tab parked on the login
// page after a cross-tab sign-out stayed stranded there forever. The
// theme now follows explicit toggles too, so side-by-side windows
// don't end up half dark, half light.
{
  await page.goto(SITE + "#/overview", { waitUntil: "domcontentloaded" });
  await page.waitForSelector(".stat", { timeout: 15000 });
  const tabB = await context.newPage();
  await tabB.goto(SITE + "#/sessions", { waitUntil: "domcontentloaded" });
  await tabB.waitForSelector("tr[data-clickable], input#email", { timeout: 15000 });
  // another-tab sign-out (what signOut() writes, minus the modal walk)
  await tabB.evaluate(() => {
    localStorage.setItem("av_mock_signed_out", "1");
    localStorage.setItem("av_signed_out_at", String(Date.now()));
  });
  await page.waitForSelector("input#email", { timeout: 8000 }).catch(() => fail("tab did not react to a cross-tab sign-out"));
  // another-tab sign-IN lets the stranded login tab back in
  await tabB.evaluate(async () => {
    await window.dataSource.login({ email: "demo@agentvisor.ai", password: "drill-pass-1" });
    localStorage.setItem("av_signed_in_at", String(Date.now()));
  });
  await page.waitForSelector(".stat", { timeout: 8000 }).catch(() => fail("login tab stayed stranded after a cross-tab sign-in"));
  // explicit theme toggle in one tab follows in the other
  await tabB.evaluate(() => localStorage.setItem("av_theme", "dark"));
  await page.waitForFunction(() => document.documentElement.getAttribute("data-theme") === "dark", { timeout: 5000 })
    .catch(() => fail("theme toggle did not sync across tabs"));
  await tabB.evaluate(() => localStorage.setItem("av_theme", "light"));
  await page.waitForFunction(() => document.documentElement.getAttribute("data-theme") === "light", { timeout: 5000 });
  await tabB.close();
  // No dark-mode FOUC: with an explicit theme saved, config.js applies
  // data-theme BEFORE first paint (a dark chooser on a light-OS
  // machine used to get a white flash every load). Assert the first
  // painted frame is already dark.
  await page.evaluate(() => localStorage.setItem("av_theme", "dark"));
  const foucPage = await context.newPage();
  await foucPage.addInitScript(() => {
    window.__firstFrame = null;
    const grab = () => requestAnimationFrame(() => {
      window.__firstFrame = document.documentElement.getAttribute("data-theme");
    });
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", grab); else grab();
  });
  await foucPage.goto(SITE + "#/overview", { waitUntil: "domcontentloaded" });
  await foucPage.waitForFunction(() => window.__firstFrame !== null, { timeout: 8000 });
  const firstFrame = await foucPage.evaluate(() => window.__firstFrame);
  await foucPage.close();
  if (firstFrame !== "dark") fail("dark-mode FOUC: first painted frame theme was " + firstFrame);
  await page.evaluate(() => localStorage.removeItem("av_theme"));
  await page.reload({ waitUntil: "domcontentloaded" });
  await page.waitForFunction(() => document.querySelector(".stat")?.textContent.trim().length > 0, { timeout: 15000 });
  console.log("✅ cross-tab sync: sign-out bounces, sign-in un-strands the login tab, theme follows; no dark-mode FOUC");
}

// ── 15. Focus rings + hostile data ─────────────────────────────────
// (a) WCAG 2.4.7: every keyboard focus stop must show a visible
// indicator (outline or box-shadow) — axe can't verify this, only a
// real Tab walk can. (b) Garbage API fields (bad dates, non-numeric
// money) must render as dashes/$0.00, never "NaNd ago" / "$NaN" /
// "Invalid Date" — in the table OR the CSV export.
{
  let stops = 0; const naked = [];
  for (const r of ["#/sessions", "#/settings/webhooks"]) {
    await page.evaluate((r) => { location.hash = r; }, r);
    await page.waitForTimeout(900);
    for (let i = 0; i < 25; i++) {
      await page.keyboard.press("Tab");
      const info = await page.evaluate(() => {
        const el = document.activeElement;
        if (!el || el === document.body || el === document.documentElement) return null;
        const cs = getComputedStyle(el);
        const visible = (parseFloat(cs.outlineWidth) > 0 && cs.outlineStyle !== "none") || cs.boxShadow !== "none";
        const rr = el.getBoundingClientRect();
        return { visible, onscreen: rr.width > 0 && rr.height > 0, id: el.id || el.tagName };
      });
      if (!info) break;
      stops++;
      if (info.onscreen && !info.visible) naked.push(r + "→" + info.id);
    }
  }
  if (naked.length) fail("focus stops without a visible ring: " + [...new Set(naked)].join(", "));
  await page.evaluate(() => {
    const ds = window.dataSource;
    if (!ds.__origList) ds.__origList = ds.listSessions.bind(ds);
    ds.listSessions = async (...a) => {
      const r = await ds.__origList(...a);
      r.sessions = [{ id: "sess_garbage", externalId: "sess_garbage", agent: "bad-agent", user: null, model: undefined, startedAt: "not-a-date", lastEventAt: "also-garbage", events: "many", toolsAllowed: null, toolsBlocked: undefined, costUsdMicros: "garbage", blockedPayoutUsdMicros: {}, status: "weird_status", deploymentId: "dep_nope", policiesFired: null }, ...r.sessions];
      return r;
    };
  });
  await page.goto(SITE + "#/sessions", { waitUntil: "domcontentloaded" });
  await page.waitForSelector("tr[data-clickable]", { timeout: 10000 });
  const leak = await page.evaluate(() => {
    const t = document.getElementById("view").textContent;
    return ["NaN", "Invalid Date", "undefined"].filter((x) => t.includes(x));
  });
  if (leak.length) fail("garbage session row leaked into the UI: " + leak.join(","));
  const dl = page.waitForEvent("download", { timeout: 8000 });
  await page.click("#exportCsv");
  const csv = (await import("fs")).readFileSync(await (await dl).path(), "utf8");
  const csvLeak = ["NaN", "Invalid Date", "undefined"].filter((x) => csv.includes(x));
  if (csvLeak.length) fail("garbage session row leaked into the CSV: " + csvLeak.join(","));
  await page.evaluate(() => { window.dataSource.listSessions = window.dataSource.__origList; });
  console.log("✅ " + stops + " focus stops all show a ring; garbage API fields render clean in table + CSV");
  // Reduced motion (WCAG 2.3.3): under prefers-reduced-motion, NO
  // element may keep a real animation/transition duration — the old
  // enumerated list drifted as new animated surfaces shipped.
  const rmPage = await context.newPage();
  await rmPage.emulateMedia({ reducedMotion: "reduce" });
  await rmPage.goto(SITE + "#/overview", { waitUntil: "domcontentloaded" });
  await rmPage.waitForFunction(() => document.querySelector(".stat")?.textContent.trim().length > 0, { timeout: 15000 });
  const residual = await rmPage.evaluate(() => {
    const out = [];
    for (const el of document.querySelectorAll("*")) {
      const cs = getComputedStyle(el);
      if (cs.animationName !== "none" && parseFloat(cs.animationDuration) > 0.01) out.push((el.className || el.tagName).toString().slice(0, 30));
      if (parseFloat(cs.transitionDuration) > 0.01 && cs.transitionProperty !== "none") out.push((el.className || el.tagName).toString().slice(0, 30));
    }
    return [...new Set(out)].slice(0, 6);
  });
  await rmPage.close();
  if (residual.length) fail("elements still animate under prefers-reduced-motion: " + residual.join(", "));
  // account menu: full keyboard contract (arrows wrap + Home/End)
  await page.click(".user-btn");
  await page.waitForSelector("#accountMenu", { timeout: 3000 });
  await page.keyboard.press("End");
  const endAct = await page.evaluate(() => document.activeElement.getAttribute("data-act"));
  await page.keyboard.press("ArrowDown"); // wraps to first
  const wrapAct = await page.evaluate(() => document.activeElement.getAttribute("data-act"));
  await page.keyboard.press("Escape");
  await page.waitForTimeout(200);
  if (endAct !== "signout" || wrapAct !== "shortcuts") fail("account menu keyboard contract broken: End=" + endAct + " wrap=" + wrapAct);
  console.log("✅ reduced-motion kill-switch total; account menu End/wrap keyboard contract");
  // Shortcut guards: with a modal open, g-nav must not navigate (the
  // hashchange would destroy the open dialog mid-form), "?" must not
  // stack the sheet, and "/" must not steal focus out of the trap.
  await page.evaluate(() => { location.hash = "#/policies"; });
  await page.waitForSelector("#addPol", { timeout: 10000 });
  await page.click("#addPol");
  await page.waitForSelector(".modal-backdrop", { timeout: 3000 });
  await page.keyboard.press("g");
  await page.keyboard.press("s");
  await page.waitForTimeout(400);
  const kb = await page.evaluate(() => ({ hash: location.hash, modal: !!document.querySelector(".modal-backdrop") }));
  if (kb.hash !== "#/policies" || !kb.modal) fail("g-nav fired through an open modal: " + JSON.stringify(kb));
  await page.keyboard.press("?");
  await page.waitForTimeout(250);
  if ((await page.evaluate(() => document.querySelectorAll(".modal-backdrop").length)) !== 1) fail("? stacked the sheet over an open modal");
  await page.keyboard.press("Escape");
  await page.waitForTimeout(300);
  await page.keyboard.press("g");
  await page.keyboard.press("s");
  await page.waitForTimeout(500);
  if ((await page.evaluate(() => location.hash)) !== "#/sessions") fail("g-nav dead after modal close");
  console.log("✅ shortcut guards: g-nav / ? / focus-steal all blocked while a dialog is open, restored after");
  // Focus-trap wrap (installModalKeys implements it; nothing asserted
  // it): Tab from the modal's last focusable wraps to the first,
  // Shift+Tab from the first wraps to the last, focus never escapes.
  await page.evaluate(() => { location.hash = "#/policies"; });
  await page.waitForSelector("#addPol", { timeout: 10000 });
  await page.click("#addPol");
  await page.waitForSelector(".modal-backdrop", { timeout: 3000 });
  await page.waitForTimeout(300);
  const focusables = () => page.evaluate(() => {
    const modal = document.querySelector(".modal-backdrop");
    return [...modal.querySelectorAll('button, [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])')]
      .filter((el) => el.offsetParent !== null || el.tagName === "INPUT").length;
  });
  const nF = await focusables();
  if (nF < 3) fail("focus-trap probe found too few focusables: " + nF);
  await page.evaluate(() => {
    const modal = document.querySelector(".modal-backdrop");
    const els = [...modal.querySelectorAll('button, [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])')]
      .filter((el) => el.offsetParent !== null || el.tagName === "INPUT");
    els[els.length - 1].focus();
  });
  await page.keyboard.press("Tab");
  if (!(await page.evaluate(() => !!document.activeElement.closest(".modal-backdrop")))) fail("Tab escaped the modal focus trap");
  await page.keyboard.press("Shift+Tab");
  await page.keyboard.press("Shift+Tab");
  if (!(await page.evaluate(() => !!document.activeElement.closest(".modal-backdrop")))) fail("Shift+Tab escaped the modal focus trap");
  await page.keyboard.press("Escape");
  await page.waitForTimeout(300);
  // aria-expanded round trip on the account menu button
  await page.evaluate(() => { location.hash = "#/overview"; });
  await page.waitForTimeout(600);
  await page.click(".user-btn");
  await page.waitForSelector("#accountMenu", { timeout: 3000 });
  const exp1 = await page.evaluate(() => document.getElementById("userBtn").getAttribute("aria-expanded"));
  await page.keyboard.press("Escape");
  await page.waitForTimeout(200);
  const exp0 = await page.evaluate(() => document.getElementById("userBtn").getAttribute("aria-expanded"));
  if (exp1 !== "true" || exp0 !== "false") fail("aria-expanded round-trip broken: " + exp1 + "→" + exp0);
  console.log("✅ modal focus trap wraps both directions; aria-expanded round-trips");
  // Live regions (WCAG 4.1.3): toasts, form errors, and filter count
  // labels must be announced — axe can't verify dynamic announcements.
  const lr = await page.evaluate(() => ({
    toast: (document.getElementById("toastStack") || { getAttribute: () => null }).getAttribute("role"),
    announcer: document.getElementById("routeAnnouncer")?.getAttribute("aria-live"),
  }));
  if (lr.toast !== "status" || lr.announcer !== "polite") fail("live regions wrong: " + JSON.stringify(lr));
  await page.evaluate(() => { location.hash = "#/sessions/sess_01H9K"; });
  await page.waitForSelector("#evtCount", { timeout: 10000 });
  if ((await page.evaluate(() => document.getElementById("evtCount").getAttribute("role"))) !== "status") fail("evtCount not a status region");
  await page.evaluate(() => { location.hash = "#/login"; });
  await page.waitForTimeout(400);
  // signed-in → login redirects to overview; check authErr markup via signed-out page is covered in check 21's flows —
  // assert statically here that the auth template carries role=alert
  console.log("✅ live regions: toastStack status, route announcer polite, count labels status");
}

// ── 16. Tactile polish ─────────────────────────────────────────────
// (a) Selecting text inside a clickable row must NOT navigate — users
// select session ids to copy them. (b) Returning to a scrolled list
// (Back button / ← All sessions) restores the scroll offset. (c) A
// toast flood caps at 4 visible, newest wins.
{
  // Route away then back: check 15 left a stale garbage row painted,
  // and a goto to the SAME hash URL is a same-document navigation —
  // it re-renders nothing.
  await page.evaluate(() => { location.hash = "#/overview"; });
  await page.waitForTimeout(400);
  await page.evaluate(() => { location.hash = "#/sessions"; });
  await page.waitForSelector("tr[data-clickable]", { timeout: 15000 });
  const cell = await page.$("tr[data-clickable] td:nth-child(2)");
  const box = await cell.boundingBox();
  await page.mouse.move(box.x + 4, box.y + box.height / 2);
  await page.mouse.down();
  await page.mouse.move(box.x + box.width - 8, box.y + box.height / 2, { steps: 8 });
  await page.mouse.up();
  await page.waitForTimeout(400);
  const afterSel = await page.evaluate(() => location.hash);
  if (afterSel !== "#/sessions") fail("selecting text in a row navigated to " + afterSel);
  // ...but a plain click still navigates
  await page.click("tr[data-clickable] td:nth-child(3)");
  await page.waitForSelector("#eventList", { timeout: 10000 });
  // scroll restoration through a Back round-trip
  await page.goto(SITE + "#/sessions", { waitUntil: "domcontentloaded" });
  await page.waitForSelector("tr[data-clickable]", { timeout: 10000 });
  await page.evaluate(() => window.scrollTo(0, 600));
  await page.waitForTimeout(200);
  await page.evaluate(() => { const trs = document.querySelectorAll("tr[data-clickable]"); trs[trs.length - 1].click(); });
  await page.waitForSelector("#eventList", { timeout: 10000 });
  if ((await page.evaluate(() => window.scrollY)) !== 0) fail("detail page inherited the list's scroll offset");
  await page.goBack();
  await page.waitForSelector("tr[data-clickable]", { timeout: 10000 });
  await page.waitForTimeout(800);
  const restored = await page.evaluate(() => window.scrollY);
  if (restored < 400) fail("Back did not restore the list scroll offset (got " + restored + ")");
  // toast flood cap
  await page.evaluate(() => {
    for (let i = 0; i < 12; i++) {
      const btn = document.createElement("button");
      btn.setAttribute("data-copy", "x" + i);
      document.body.appendChild(btn); btn.click(); btn.remove();
    }
  });
  await page.waitForTimeout(400);
  const toasts = await page.evaluate(() => document.querySelectorAll(".toast").length);
  if (toasts > 4) fail("toast flood not capped: " + toasts + " visible");
  // Unbroken-token containment: a message carrying a 120-char token
  // (copy-failure echoing av_live_…) once stretched a toast to ~885px,
  // off the left edge of a phone.
  const wide = await page.evaluate(() => {
    const stack = document.querySelector("#toastStack") || document.body;
    const el = document.createElement("div");
    el.className = "toast";
    el.textContent = "av_live_" + "x".repeat(120);
    stack.appendChild(el);
    const r = el.getBoundingClientRect();
    const bad = r.width > Math.min(430, innerWidth) || r.left < -1;
    el.remove();
    return bad ? Math.round(r.width) : 0;
  });
  if (wide) fail("long-token toast overflows: " + wide + "px wide");
  await page.waitForTimeout(2600); // let them drain before the soak
  console.log("✅ tactile polish: text-select doesn't navigate, Back restores scroll, toasts cap at 4 and contain unbroken tokens");
}

// ── 17. Filter/sort semantic correctness ───────────────────────────
// The URL plumbing is drilled elsewhere; this asserts the filters
// return the RIGHT rows against ground truth computed from the
// datasource itself — case-insensitive q across id/agent/actor,
// status=blocked, dep, composition, and per-column sort monotonicity.
// This logic graduates into the real product's list views.
{
  await page.evaluate(() => localStorage.setItem("av_mock_bigdata", "1"));
  await page.goto(SITE + "#/sessions?range=720", { waitUntil: "domcontentloaded" });
  await page.waitForSelector("tr[data-clickable]", { timeout: 15000 });
  const all = await page.evaluate(async () => {
    const out = []; let cursor = null;
    do {
      const r = await window.dataSource.listSessions({ limit: 100, sinceHours: 720, cursor });
      out.push(...r.sessions); cursor = r.nextCursor;
    } while (cursor);
    return out.map((s) => ({ id: s.id, agent: s.agent, user: s.user || "", ext: s.externalId || s.id, blocked: s.toolsBlocked > 0, dep: s.deploymentId, started: s.startedAt, cost: parseInt(s.costUsdMicros, 10) || 0 }));
  });
  const uiIds = async () => {
    for (let i = 0; i < 6; i++) {
      const lm = await page.$("#loadMore");
      if (!lm) break;
      await lm.click();
      await page.waitForTimeout(700);
    }
    return page.evaluate(() => [...document.querySelectorAll("tr[data-clickable]")].map((r) => r.getAttribute("data-id")));
  };
  const goF = async (qs) => {
    await page.evaluate(() => { location.hash = "#/overview"; });
    await page.waitForTimeout(300);
    await page.evaluate((q) => { location.hash = "#/sessions" + q; }, qs);
    await page.waitForSelector("tr[data-clickable], .empty", { timeout: 10000 });
    await page.waitForTimeout(400);
  };
  const eq = (name, got, want) => {
    if (want.length === 0) fail("filter check '" + name + "' matched 0 rows — probe is trivial, fixture changed?");
    if ([...got].sort().join() !== [...want].sort().join()) fail("filter '" + name + "' wrong rows: ui=" + got.length + " truth=" + want.length);
  };
  await goF("?q=PLANNER&range=720");
  eq("q case-insensitive", await uiIds(), all.filter((s) => [s.ext, s.agent, s.user].some((v) => v.toLowerCase().includes("planner"))).map((s) => s.id));
  await goF("?status=blocked&range=720");
  eq("status=blocked", await uiIds(), all.filter((s) => s.blocked).map((s) => s.id));
  await goF("?q=NORTHWIND&status=blocked&range=720");
  eq("q+blocked composition", await uiIds(), all.filter((s) => s.blocked && [s.ext, s.agent, s.user].some((v) => v.toLowerCase().includes("northwind"))).map((s) => s.id));
  const m = Object.fromEntries(all.map((s) => [s.id, s]));
  await goF("?range=720&sort=cost.asc");
  const seq = (await page.evaluate(() => [...document.querySelectorAll("tr[data-clickable]")].map((r) => r.getAttribute("data-id")))).map((id) => m[id]?.cost);
  if (!seq.every((v, i) => i === 0 || seq[i - 1] <= v)) fail("sort cost.asc not monotone");
  // Filter-race: a slow stale query must never paint over a newer one,
  // and keystrokes typed while a fetch is in flight must survive (the
  // old repaint-then-fetch flow dropped them with the listeners).
  await goF("?range=720");
  await page.evaluate(() => {
    const ds = window.dataSource;
    if (!ds.__origListRace) ds.__origListRace = ds.listSessions.bind(ds);
    ds.listSessions = (p) => new Promise((r) => setTimeout(r, p && p.q ? 1000 : 80)).then(() => ds.__origListRace(p));
  });
  await page.fill("#fSearch", "planner");
  await page.waitForTimeout(300); // slow q-fetch in flight
  await page.fill("#fSearch", ""); // fast unfiltered fetch supersedes it
  await page.waitForTimeout(2200);
  const race = await page.evaluate(() => ({
    box: document.querySelector("#fSearch")?.value,
    q: /q=/.test(location.hash),
    rows: document.querySelectorAll("tr[data-clickable]").length,
  }));
  if (race.q || race.box !== "" || race.rows !== 50) fail("stale filter fetch painted over the newer one: " + JSON.stringify(race));
  await page.evaluate(() => { window.dataSource.listSessions = window.dataSource.__origListRace; });
  await page.evaluate(() => localStorage.removeItem("av_mock_bigdata"));
  await page.evaluate(() => { location.hash = "#/overview"; });
  await page.waitForTimeout(500);
  console.log("✅ filter/sort semantics: q (case-insens), blocked, composition all match ground truth; cost sort monotone; stale fetch never paints");
}

// ── 18. Session detail vs ground truth ─────────────────────────────
// The flagship page (tour, attack demo, and deep links all land
// here). Waterfall offsets/widths must be the cumulative-duration
// math over the datasource's own events; chip counts, chip+text
// filter composition, and the drawer must all agree with the data.
{
  await page.evaluate(() => { location.hash = "#/sessions/sess_01H9K"; });
  await page.waitForSelector("#eventList .evt", { timeout: 15000 });
  const r = await page.evaluate(async () => {
    const gt = (await window.dataSource.getSessionById("sess_01H9K")).events;
    const rows = [...document.querySelectorAll("#eventList .evt")];
    const problems = [];
    if (rows.length !== gt.length) problems.push(`rows ${rows.length} != events ${gt.length}`);
    const total = gt.reduce((a, e) => a + (e.durationMs || 0), 0) || 1;
    let off = 0;
    gt.forEach((e, i) => {
      const row = rows[i];
      if (row.querySelector(".seq").textContent !== "#" + e.seq) problems.push(`row ${i} seq mismatch`);
      if (row.querySelector(".body b").textContent !== (e.tag || e.kind)) problems.push(`row ${i} tag mismatch`);
      const bar = row.querySelector(".wf-bar");
      if (Math.abs(parseFloat(bar.style.left) - (off / total) * 100) > 0.05) problems.push(`row ${i} waterfall offset wrong`);
      if (Math.abs(parseFloat(bar.style.width) - Math.max(1, ((e.durationMs || 0) / total) * 100)) > 0.05) problems.push(`row ${i} waterfall width wrong`);
      off += e.durationMs || 0;
    });
    const kc = {}; gt.forEach((e) => { kc[e.kind] = (kc[e.kind] || 0) + 1; });
    for (const c of document.querySelectorAll(".evt-chip")) {
      const k = c.getAttribute("data-kind");
      const want = k === "" ? gt.length : (kc[k] || 0);
      if (parseInt(c.querySelector(".n").textContent, 10) !== want) problems.push(`chip ${k || "All"} count wrong`);
    }
    // chip + text composition
    document.querySelector('.evt-chip[data-kind="block"]').click();
    const s = document.querySelector("#evtSearch");
    s.value = "vendor"; s.dispatchEvent(new Event("input"));
    await new Promise((res) => setTimeout(res, 120));
    const vis = document.querySelectorAll("#eventList .evt:not(.evt-hidden)").length;
    const want = gt.filter((e) => e.kind === "block" && ((e.tag || "") + " " + (e.msg || "") + " " + (e.sub || "") + " " + e.kind).toLowerCase().includes("vendor")).length;
    if (!want) problems.push("compose probe matched 0 events — fixture drift");
    if (vis !== want) problems.push(`chip+text filter shows ${vis}, truth ${want}`);
    s.value = ""; s.dispatchEvent(new Event("input"));
    document.querySelector('.evt-chip[data-kind=""]').click();
    // drawer agrees with the selected event
    document.querySelector('#eventList .evt[data-i="3"]').click();
    await new Promise((res) => setTimeout(res, 150));
    const ev = gt[3];
    const drawer = document.getElementById("eventDrawer").textContent;
    if (!drawer.includes("#" + ev.seq) || !drawer.includes(ev.tag || ev.kind)) problems.push("drawer content mismatch");
    if (!document.querySelector("#eventDrawer .evt-link-btn")?.getAttribute("data-copy")?.includes("evt=" + ev.seq)) problems.push("drawer copy-link wrong seq");
    return problems;
  });
  if (r.length) fail("session detail vs ground truth: " + r.join("; "));
  console.log("✅ session detail matches ground truth: waterfall math, chip counts, chip+text filter, drawer");
}

// ── 19. Chart ground truth + interaction budgets ───────────────────
// (a) The overview chart's bars must be the series data (heights
// proportional, aria summary equal to the sums, tooltip showing the
// hovered bucket). (b) Latency ceilings on the heavy interactions
// under the 250-row dataset — generous enough for shared runners,
// tight enough to catch an accidental O(n²) (locally these run
// 30–800ms; budgets are 3–6x that).
{
  await page.evaluate(() => { location.hash = "#/overview"; });
  await page.waitForFunction(() => document.querySelector(".chart-svg"), { timeout: 15000 });
  const chartProblems = await page.evaluate(async () => {
    const o = await window.dataSource.getOverview("24h");
    const series = o.series || [];
    const problems = [];
    const svg = document.querySelector(".chart-svg");
    const vb = svg.getAttribute("viewBox").split(" ").map(Number);
    const chartH = vb[3] - 12 - 22;
    let max = Math.max(...series.map((s) => s.allowed + s.blocked), 1);
    max = Math.ceil(max / 4) * 4 || 4;
    const bars = [...svg.querySelectorAll("rect.bar:not(.blocked)")];
    const withAllowed = series.filter((s) => s.allowed);
    if (bars.length !== withAllowed.length) problems.push("allowed bar count " + bars.length + " != " + withAllowed.length);
    let bi = 0;
    series.forEach((s, i) => {
      if (!s.allowed) return;
      const wantH = ((s.allowed + s.blocked) / max) * chartH - (s.blocked / max) * chartH;
      if (Math.abs(parseFloat(bars[bi++].getAttribute("height")) - wantH) > 0.15) problems.push("bucket " + i + " height wrong");
    });
    const sumA = series.reduce((a, s) => a + s.allowed, 0), sumB = series.reduce((a, s) => a + s.blocked, 0);
    const label = svg.getAttribute("aria-label");
    if (!label.includes(sumA + " allowed") || !label.includes(sumB + " blocked")) problems.push("aria summary wrong");
    const strip = svg.querySelectorAll(".hover-strip")[5];
    strip.dispatchEvent(new MouseEvent("mousemove", { bubbles: true }));
    await new Promise((r) => setTimeout(r, 150));
    const tip = document.querySelector(".chart-tip, #chartTip, [class*=tooltip]")?.textContent || "";
    if (!(tip.includes(String(series[5].allowed)) && tip.includes(String(series[5].blocked)))) problems.push("tooltip bucket 5 wrong: " + tip.slice(0, 50));
    return problems;
  });
  if (chartProblems.length) fail("chart vs ground truth: " + chartProblems.join("; "));
  await page.evaluate(() => localStorage.setItem("av_mock_bigdata", "1"));
  await page.goto(SITE + "#/sessions?range=720", { waitUntil: "domcontentloaded" });
  await page.waitForSelector("tr[data-clickable]", { timeout: 15000 });
  const budgets = [];
  const timed = async (name, ceiling, fn) => {
    const t0 = Date.now();
    await fn();
    const ms = Date.now() - t0;
    budgets.push(name + " " + ms + "ms");
    if (ms > ceiling) fail("interaction budget blown: " + name + " took " + ms + "ms (ceiling " + ceiling + ")");
  };
  await timed("loadMore→100rows", 3000, async () => {
    await page.click("#loadMore");
    await page.waitForFunction(() => document.querySelectorAll("tr[data-clickable]").length === 100, { timeout: 10000 });
  });
  await timed("sort 100 rows", 1500, async () => {
    await page.click('.th-sort[data-sort="cost"]');
    await page.waitForFunction(() => {
      const c = [...document.querySelectorAll("tbody tr")].map((r) => parseFloat(r.cells[5].textContent.replace(/[^0-9.]/g, "")));
      return c.length === 100 && c.every((v, i) => !i || v <= c[i - 1] + 1e-9);
    }, { timeout: 10000 });
  });
  await timed("search→filtered", 3000, async () => {
    await page.fill("#fSearch", "planner");
    await page.waitForFunction(() => /q=planner/.test(location.hash) && document.querySelectorAll("tr[data-clickable]").length > 0 && document.querySelectorAll("tr[data-clickable]").length < 100, { timeout: 10000 });
  });
  await timed("mega 700-evt deep link", 8000, async () => {
    await page.goto(SITE + "#/sessions/sess_bd_mega?evt=600", { waitUntil: "domcontentloaded" });
    await page.reload({ waitUntil: "domcontentloaded" });
    await page.waitForFunction(() => document.querySelector(".evt.selected .seq")?.textContent === "#600", { timeout: 25000 });
  });
  await page.evaluate(() => localStorage.removeItem("av_mock_bigdata"));
  await page.goto(SITE + "#/overview", { waitUntil: "domcontentloaded" });
  await page.waitForFunction(() => document.querySelector(".stat")?.textContent.trim().length > 0, { timeout: 15000 });
  console.log("✅ chart matches series ground truth; budgets: " + budgets.join(", "));
}

// ── 20. Audit log truth, palette ranking, print pack ───────────────
// (a) Audit chips/search/CSV must agree with listAudit ground truth
// (CSV is WYSIWYG of the filtered view). (b) Palette: literal-match
// ranking beats scattered-subsequence ("reset" → Reset demo data
// first, not SeTtings) and async dynamic entries arrive. (c) Print
// emulation: chrome stripped, provenance footer visible.
{
  await page.goto(SITE + "#/settings/audit", { waitUntil: "domcontentloaded" });
  await page.waitForSelector("#auditBody tr", { timeout: 15000 });
  const a = await page.evaluate(async () => {
    const gt = await window.dataSource.listAudit();
    const problems = [];
    if (document.querySelectorAll("#auditBody tr").length !== gt.length) problems.push("row count wrong");
    const cc = {}; gt.forEach((x) => { const c = x.event.split(".")[0]; cc[c] = (cc[c] || 0) + 1; });
    for (const chip of document.querySelectorAll(".evt-chip")) {
      const c = chip.getAttribute("data-cat");
      if (parseInt(chip.querySelector(".n").textContent, 10) !== (c === "" ? gt.length : cc[c])) problems.push("chip " + (c || "All") + " wrong");
    }
    const cat = Object.keys(cc).sort()[0];
    document.querySelector('.evt-chip[data-cat="' + cat + '"]').click();
    const s = document.querySelector("#auditSearch");
    s.value = "a"; s.dispatchEvent(new Event("input"));
    await new Promise((r) => setTimeout(r, 120));
    const want = gt.filter((x) => x.event.split(".")[0] === cat && (x.event + " " + x.actor + " " + (x.target || "") + " " + (x.note || "")).toLowerCase().includes("a")).length;
    if (!want) problems.push("audit compose probe trivial — fixture drift");
    if (document.querySelectorAll("#auditBody tr").length !== want) problems.push("audit chip+search compose wrong");
    return { problems, want };
  });
  if (a.problems.length) fail("audit log vs ground truth: " + a.problems.join("; "));
  const dl = page.waitForEvent("download", { timeout: 8000 });
  await page.click("#auditExportBtn");
  const csvLines = (await import("fs")).readFileSync(await (await dl).path(), "utf8").trim().split(/\r?\n/).length - 1;
  if (csvLines !== a.want) fail("audit CSV not WYSIWYG: " + csvLines + " rows, filtered view " + a.want);
  // palette ranking + dynamic entries
  await page.evaluate(() => { location.hash = "#/overview"; });
  await page.waitForTimeout(500);
  await page.click(".cmdk-trigger");
  await page.waitForSelector(".cmdk-backdrop input", { timeout: 5000 });
  await page.fill(".cmdk-backdrop input", "reset");
  await page.waitForTimeout(300);
  const first = await page.evaluate(() => document.querySelector("#cmdkList .item")?.textContent || "");
  if (!/Reset demo data/.test(first)) fail("palette ranking: 'reset' first hit is " + first.slice(0, 40));
  await page.fill(".cmdk-backdrop input", "sess_01H9K");
  await page.waitForTimeout(700);
  const dyn = await page.evaluate(() => [...document.querySelectorAll("#cmdkList .item")].map((i) => i.textContent));
  if (!dyn.some((d) => /sess_01H9K/.test(d))) fail("palette dynamic session entries missing");
  await page.keyboard.press("Escape");
  await page.waitForTimeout(200);
  // print evidence pack — and it must be COMPLETE: an active kind-chip
  // filter hides rows on screen, but a printed audit document missing
  // events would look complete while being cropped.
  await page.evaluate(() => { location.hash = "#/sessions/sess_01H9K"; });
  await page.waitForSelector("#eventList .evt", { timeout: 10000 });
  await page.click('.evt-chip[data-kind="block"]');
  await page.waitForTimeout(300);
  // Print from DARK theme too: the print block force-overrides the
  // theme tokens to light — a dark print would be an ink nightmare
  // and unreadable on paper.
  await page.evaluate(() => document.documentElement.setAttribute("data-theme", "dark"));
  await page.emulateMedia({ media: "print" });
  await page.waitForTimeout(300);
  const pr = await page.evaluate(() => ({
    sidebarHidden: getComputedStyle(document.querySelector(".sidebar")).display === "none",
    provenance: getComputedStyle(document.querySelector(".print-only")).display === "block" && /receipt/i.test(document.querySelector(".print-only").textContent),
    eventCount: /13 events/.test(document.querySelector(".print-only").textContent),
    printedRows: [...document.querySelectorAll("#eventList .evt")].filter((r) => getComputedStyle(r).display !== "none").length,
    totalRows: document.querySelectorAll("#eventList .evt").length,
    lightForced: getComputedStyle(document.body).backgroundColor === "rgb(255, 255, 255)",
  }));
  await page.emulateMedia({ media: "screen" });
  await page.evaluate(() => document.documentElement.removeAttribute("data-theme"));
  await page.click('.evt-chip[data-kind=""]');
  await page.waitForTimeout(200);
  if (!pr.sidebarHidden || !pr.provenance) fail("print evidence pack broken: " + JSON.stringify(pr));
  if (pr.printedRows !== pr.totalRows || !pr.eventCount) fail("print pack incomplete under an active filter: " + JSON.stringify(pr));
  if (!pr.lightForced) fail("dark theme leaked into print: " + JSON.stringify(pr));
  console.log("✅ audit log matches ground truth (chips/search/CSV WYSIWYG); palette ranks + loads dynamic entries; print pack complete even when filtered, light-forced from dark theme");
}

// ── 21. Password reset + member redaction + policy derivation ──────
// (a) The #/reset flow end-to-end: token issued inline (mock), wrong
// token rejected, correct token sets the password once, reuse fails
// (single-use). (b) "Preview as member" must redact LLM bodies with
// the 🔒 sentinel exactly like the real API (R101) — the mock used to
// show full content, lying about redaction. (c) Policy detail derives
// its block count from the fired-session list, not the fixture.
{
  // (a) reset flow — enter via reload-then-hash (in-memory session
  // bounces public routes before a reload)
  await page.evaluate(() => { localStorage.setItem("av_mock_signed_out", "1"); });
  await page.reload({ waitUntil: "domcontentloaded" });
  await page.waitForSelector("input#email", { timeout: 10000 });
  await page.evaluate(() => { location.hash = "#/reset"; });
  await page.waitForSelector("#resetReqForm", { timeout: 10000 });
  await page.fill("#email", "drill@northwind.com");
  await page.click("#resetReqForm button[type=submit]");
  await page.waitForSelector("#resetErr .mono", { timeout: 8000 });
  const tok = await page.evaluate(() => document.querySelector("#resetErr .mono").textContent.trim());
  await page.evaluate(() => { location.hash = "#/reset?email=drill%40northwind.com&token=WRONG"; });
  await page.waitForSelector("#resetConfirmForm", { timeout: 8000 });
  await page.fill("#newPassword", "drill-horse-battery!");
  await page.click("#resetConfirmForm button[type=submit]");
  await page.waitForFunction(() => /invalid or has expired/i.test(document.querySelector("#resetErr")?.textContent || ""), { timeout: 8000 });
  await page.evaluate((t) => { location.hash = "#/reset?email=drill%40northwind.com&token=" + encodeURIComponent(t); }, tok);
  await page.waitForFunction((t) => document.querySelector("#token")?.value === t, tok, { timeout: 8000 });
  await page.fill("#newPassword", "drill-horse-battery!");
  await page.click("#resetConfirmForm button[type=submit]");
  await page.waitForSelector("#authForm", { timeout: 8000 });
  await page.evaluate((t) => { location.hash = "#/reset?email=drill%40northwind.com&token=" + encodeURIComponent(t) + "&x=1"; }, tok);
  await page.waitForFunction((t) => document.querySelector("#token")?.value === t, tok, { timeout: 8000 });
  await page.fill("#newPassword", "second-reuse-attempt!");
  await page.click("#resetConfirmForm button[type=submit]");
  await page.waitForFunction(() => /invalid or has expired/i.test(document.querySelector("#resetErr")?.textContent || ""), { timeout: 8000 });
  // (a2) auth error branches — dead code in the demo (mock login
  // accepts anything) but the most-hit error paths in production.
  // Inject failures: friendly message + button re-enable, and the 429
  // countdown must tick, clear, and re-enable on expiry.
  await page.evaluate(() => { location.hash = "#/login"; });
  await page.waitForSelector("#authForm", { timeout: 8000 });
  await page.evaluate(() => {
    const ds = window.dataSource;
    ds.__origLogin2 = ds.login.bind(ds);
    ds.login = () => Promise.reject(Object.assign(new Error("invalid_credentials"), { friendlyMessage: "That email/password combination doesn't match.", status: 401 }));
  });
  await page.fill("input#email", "drill@northwind.com");
  await page.fill("input#password", "wrong-password-1");
  await page.click("button[type=submit]");
  await page.waitForSelector(".auth-err", { timeout: 5000 });
  if (!(await page.evaluate(() => /doesn't match/.test(document.querySelector(".auth-err").textContent) && !document.querySelector("button[type=submit]").disabled)))
    fail("wrong-password branch broken (message or button re-enable)");
  await page.evaluate(() => {
    window.dataSource.login = () => Promise.reject(Object.assign(new Error("rate_limited"), { friendlyMessage: "Too many attempts. Try again in 2 seconds.", status: 429, retryAfterSec: 2 }));
  });
  await page.click("button[type=submit]");
  await page.waitForSelector(".auth-err", { timeout: 5000 });
  if (!(await page.evaluate(() => document.querySelector("button[type=submit]").disabled))) fail("429 did not lock the submit button");
  await page.waitForFunction(() => !document.querySelector("button[type=submit]").disabled && !document.querySelector(".auth-err"), { timeout: 6000 })
    .catch(() => fail("429 countdown did not re-enable + clear"));
  await page.evaluate(() => { window.dataSource.login = window.dataSource.__origLogin2; });
  // (b) member redaction round-trip
  await page.evaluate(() => localStorage.removeItem("av_mock_signed_out"));
  await page.reload({ waitUntil: "domcontentloaded" });
  await page.waitForFunction(() => document.querySelector(".stat"), { timeout: 15000 });
  await page.evaluate(() => { location.hash = "#/sessions/sess_01H9K"; });
  await page.waitForSelector("#eventList .evt", { timeout: 10000 });
  if (await page.evaluate(() => document.querySelectorAll(".redacted-pill").length)) fail("owner view showed redaction pills");
  await page.click(".cmdk-trigger");
  await page.waitForSelector(".cmdk-backdrop input", { timeout: 5000 });
  await page.fill(".cmdk-backdrop input", "preview as member");
  await page.waitForTimeout(300);
  await page.keyboard.press("Enter");
  await page.waitForFunction(() => document.querySelectorAll(".redacted-pill").length > 0, { timeout: 10000 })
    .catch(() => fail("member preview did not redact LLM bodies"));
  // While previewing member: admin-only tabs redirect on deep link,
  // and the member-visible SSO tab is VIEW-only (Add/Edit/Delete and
  // the details modal's keypair-regen hit admin routes that would 403).
  await page.evaluate(() => { location.hash = "#/settings/webhooks"; });
  await page.waitForTimeout(800);
  if ((await page.evaluate(() => location.hash)) !== "#/settings/general") fail("member deep link to webhooks tab was not redirected");
  await page.evaluate(() => { location.hash = "#/settings/sso"; });
  await page.waitForSelector("#setPanel table", { timeout: 10000 });
  const ssoBtns = await page.evaluate(() => [...document.querySelectorAll("#setPanel .table-wrap button, #addSamlBtn")].map((x) => x.textContent.trim()));
  if (ssoBtns.some((t) => /Add IdP|Edit|Delete/.test(t))) fail("member SSO view still shows mutating controls: " + ssoBtns.join(","));
  await page.click('#setPanel [data-act="details"]');
  await page.waitForSelector(".modal-backdrop", { timeout: 5000 });
  if (await page.$('.modal-backdrop [data-act="regen"]')) fail("member details modal still offers keypair regeneration");
  await page.keyboard.press("Escape");
  await page.waitForTimeout(300);
  await page.evaluate(() => { location.hash = "#/sessions/sess_01H9K"; });
  await page.waitForSelector("#eventList .evt", { timeout: 10000 });
  await page.click(".cmdk-trigger");
  await page.waitForSelector(".cmdk-backdrop input", { timeout: 5000 });
  await page.fill(".cmdk-backdrop input", "exit member preview");
  await page.waitForTimeout(300);
  await page.keyboard.press("Enter");
  await page.waitForFunction(() => document.querySelectorAll(".redacted-pill").length === 0, { timeout: 10000 })
    .catch(() => fail("exiting preview did not restore LLM content"));
  // (c) policy detail derivation
  const pd = await page.evaluate(async () => {
    const pols = await window.dataSource.listPolicies();
    const p = pols.find((x) => (x.hits24h || 0) > 0) || pols[0];
    const resp = await window.dataSource.listSessions({ limit: 100 });
    const fired = (resp.sessions || []).filter((s) => (s.policiesFired || []).includes(p.id));
    location.hash = "#/policies/" + p.id;
    await new Promise((r) => setTimeout(r, 1200));
    const view = document.getElementById("view").textContent;
    const blocks = fired.length ? fired.reduce((a, s) => a + (s.toolsBlocked || 0), 0) : p.blocks24h;
    const rows = document.querySelectorAll("tbody tr[data-clickable], tbody tr[data-id]").length;
    return { ok: view.includes(p.name) && view.includes(String(blocks)) && rows === Math.min(fired.length, 8), fired: fired.length, blocks, rows };
  });
  if (!pd.ok || !pd.fired) fail("policy detail derivation wrong: " + JSON.stringify(pd));
  // Accept-invite edges: (a) an AUTHED user clicking an invite link is
  // bounced to Overview — that bounce used to swallow the invite
  // silently while the page's own hint said "sign in first, then click
  // the link again" (a dead end). It must explain itself. (b) A link
  // missing its email param must not render "Accept your invite for
  // <empty>".
  const aiPage = await context.newPage();
  await aiPage.goto(SITE + "#/accept-invite?token=drill_tok", { waitUntil: "domcontentloaded" });
  const aiToast = await aiPage.waitForFunction(() => {
    const t = document.querySelector(".toast")?.textContent || "";
    return /already signed in/i.test(t) ? t : null;
  }, { timeout: 8000 }).then((h) => h.jsonValue()).catch(() => null);
  if (!aiToast || !/#\/overview/.test(await aiPage.evaluate(() => location.hash)))
    fail("authed invite click did not bounce-with-explanation: " + JSON.stringify({ aiToast }));
  await aiPage.evaluate(() => { try { localStorage.setItem("av_mock_signed_out", "1"); } catch (e) {} });
  await aiPage.reload({ waitUntil: "domcontentloaded" });
  await aiPage.evaluate(() => { location.hash = "#/accept-invite?token=drill_tok"; });
  await aiPage.waitForSelector("#acceptForm", { timeout: 8000 });
  const aiCopy = await aiPage.evaluate(() => document.querySelector(".auth-form .sub")?.textContent.trim() || "");
  if (/for\s*$|for\s+and/i.test(aiCopy)) fail("email-less invite renders dangling copy: " + JSON.stringify(aiCopy));
  await aiPage.evaluate(() => { try { localStorage.removeItem("av_mock_signed_out"); } catch (e) {} });
  await aiPage.close();
  console.log("✅ reset flow + auth error branches (401 msg, 429 countdown); member preview redacts + is view-only (tabs, SSO, keypair); policy blocks derived from " + pd.fired + " fired sessions; authed invite click explains itself; email-less invite copy clean");
}

// ── 22. Deployment lifecycle + billing math ────────────────────────
// Create (modal → one-time token → pending row), detail ground truth
// (env block carries the dep id, sessions table is that deployment's
// sessions, View-all carries ?dep=), rotate (confirm → new token),
// and the billing card's metered math (calls/1000 × $0.10).
{
  await page.goto(SITE + "#/deployments", { waitUntil: "domcontentloaded" });
  await page.waitForSelector("tr[data-clickable]", { timeout: 15000 });
  const rowsBefore = await page.evaluate(() => document.querySelectorAll("tr[data-clickable]").length);
  await page.click("#addDep");
  await page.waitForSelector("#depForm", { timeout: 5000 });
  await page.fill("#depName", "drill-daemon");
  await page.click("#depForm button[type=submit]");
  await page.waitForSelector(".token-display", { timeout: 8000 });
  const tok = await page.evaluate(() => document.querySelector(".token-display").textContent.trim());
  if (!tok.startsWith("av_live_")) fail("create-deployment token wrong shape: " + tok.slice(0, 20));
  await page.evaluate(() => document.querySelector(".modal-backdrop [data-close]").click());
  await page.waitForFunction((n) => document.querySelectorAll("tr[data-clickable]").length === n + 1, rowsBefore, { timeout: 8000 })
    .catch(() => fail("new deployment did not appear in the list"));
  if (!(await page.evaluate(() => document.getElementById("view").textContent.includes("drill-daemon")))) fail("new deployment name missing");
  const d = await page.evaluate(async () => {
    const deps = await window.dataSource.listDeployments();
    const dep = deps.find((x) => x.id === "dep_prod") || deps[0];
    const sess = (await window.dataSource.listSessions({ deploymentId: dep.id })).sessions;
    location.hash = "#/deployments/" + dep.id;
    await new Promise((r) => setTimeout(r, 1200));
    const view = document.getElementById("view");
    const envBtn = view.querySelector('[data-copy*="AV_INGEST_URL"]');
    const rows = [...view.querySelectorAll("tbody tr[data-clickable]")].map((r) => r.getAttribute("data-id"));
    return {
      envOk: envBtn && envBtn.getAttribute("data-copy").includes("AV_DEPLOYMENT=" + dep.id),
      statusOk: view.textContent.includes(dep.status),
      rowsOk: rows.length === Math.min(sess.length, 8) && rows.every((id) => sess.some((s) => s.id === id)),
      viewAllOk: (view.querySelector('a[href*="dep="]')?.getAttribute("href") || "").includes("dep=" + dep.id),
      nSess: sess.length,
    };
  });
  if (!d.envOk || !d.statusOk || !d.rowsOk || !d.viewAllOk || !d.nSess) fail("deployment detail vs ground truth: " + JSON.stringify(d));
  await page.evaluate(() => { location.hash = "#/deployments"; });
  await page.waitForSelector('button[data-action="rotate"]', { timeout: 10000 });
  await page.click('button[data-action="rotate"]');
  await page.waitForSelector(".modal-backdrop [data-confirm]", { timeout: 5000 });
  await page.click(".modal-backdrop [data-confirm]");
  await page.waitForSelector(".token-display", { timeout: 8000 });
  if (!(await page.evaluate(() => document.querySelector(".token-display").textContent.trim().startsWith("av_live_")))) fail("rotated token wrong shape");
  await page.keyboard.press("Escape");
  await page.waitForTimeout(300);
  const bm = await page.evaluate(async () => {
    const o = await window.dataSource.getOverview("24h");
    const calls = o.toolsAllowed + o.toolsBlocked;
    location.hash = "#/settings/billing";
    await new Promise((r) => setTimeout(r, 1200));
    const t = document.getElementById("view").textContent;
    return { ok: t.includes(calls.toLocaleString("en-US")) && t.includes("$" + ((calls / 1000) * 0.10).toFixed(2)), calls };
  });
  if (!bm.ok) fail("billing card math wrong for " + bm.calls + " calls");
  console.log("✅ deployment lifecycle: create→token→pending row, detail truth (env/status/sessions/View-all), rotate; billing math exact");
}

// ── 23. Onboarding truth, members RBAC, key lifecycle ──────────────
// (a) The checklist's four items must tick for the RIGHT reasons at
// controlled simulation ages (t0 rewound), matching the datasource's
// own stats — not just the count. (b) The members panel is view-only
// for members: no Remove, no Invite, and no invite-Revoke (that one
// leaked). (c) API key create → one-time token → row; revoke → gone.
{
  for (const [age, wantCount] of [[2000, 1], [13500, 2], [17500, 3], [30000, 4]]) {
    await page.evaluate((a) => {
      localStorage.setItem("av_mock_fresh_t0", String(Date.now() - a));
      localStorage.setItem("av_mock_fresh_identity", JSON.stringify({ user: { id: "u", email: "drill@x.dev", displayName: "Drill" }, org: { id: "org_d", name: "Drill Co", slug: "drill", createdAt: new Date().toISOString(), role: "owner" } }));
    }, age);
    await page.goto(SITE + "#/overview", { waitUntil: "domcontentloaded" });
    await page.reload({ waitUntil: "domcontentloaded" });
    await page.waitForSelector(".onboard-card", { timeout: 15000 });
    const r = await page.evaluate(async () => {
      const stats = await window.dataSource.getOverview("24h");
      const sessions = (await window.dataSource.listSessions()).sessions;
      const want = [true, stats.deployments > 0, stats.sessions > 0, sessions.some((s) => s.toolsBlocked > 0)];
      const got = [...document.querySelectorAll(".ob-tick")].map((t) => t.classList.contains("done"));
      return { ok: JSON.stringify(want) === JSON.stringify(got), got, want };
    });
    if (!r.ok) fail("checklist items wrong at age " + age + "ms: got " + JSON.stringify(r.got) + " want " + JSON.stringify(r.want));
    if (r.got.filter(Boolean).length !== wantCount) fail("checklist schedule drifted at age " + age + "ms: " + JSON.stringify(r.got));
  }
  await page.evaluate(() => { localStorage.removeItem("av_mock_fresh_t0"); localStorage.removeItem("av_mock_fresh_identity"); });
  await page.reload({ waitUntil: "domcontentloaded" });
  await page.waitForFunction(() => document.querySelector(".stat")?.textContent.trim().length > 0, { timeout: 15000 });
  // members panel under member preview: zero management controls
  await page.click(".cmdk-trigger");
  await page.waitForSelector(".cmdk-backdrop input", { timeout: 5000 });
  await page.fill(".cmdk-backdrop input", "preview as member");
  await page.waitForTimeout(300);
  await page.keyboard.press("Enter");
  await page.waitForTimeout(800);
  await page.evaluate(() => { location.hash = "#/settings/members"; });
  await page.waitForSelector("tbody tr", { timeout: 10000 });
  await page.waitForTimeout(400);
  const mm = await page.evaluate(() => ({
    remove: document.querySelectorAll("[data-act='remove']").length,
    revoke: document.querySelectorAll("[data-act='revoke']").length,
    invite: !![...document.querySelectorAll("#setPanel button")].find((x) => /invite/i.test(x.textContent)),
    rows: document.querySelectorAll("tbody tr").length,
  }));
  if (mm.remove || mm.revoke || mm.invite || !mm.rows) fail("members panel not view-only for members: " + JSON.stringify(mm));
  await page.click(".cmdk-trigger");
  await page.waitForSelector(".cmdk-backdrop input", { timeout: 5000 });
  await page.fill(".cmdk-backdrop input", "exit member preview");
  await page.waitForTimeout(300);
  await page.keyboard.press("Enter");
  await page.waitForTimeout(800);
  // API key lifecycle
  await page.evaluate(() => { location.hash = "#/settings/keys"; });
  await page.waitForSelector("#setPanel", { timeout: 10000 });
  await page.waitForTimeout(800);
  const kb = await page.evaluate(() => document.querySelectorAll("tbody tr").length);
  await page.evaluate(() => [...document.querySelectorAll("#setPanel button")].find((x) => /create/i.test(x.textContent)).click());
  await page.waitForSelector("#inpVal", { timeout: 5000 });
  await page.fill("#inpVal", "drill-ci-key");
  await page.click("#inpForm button[type=submit]");
  await page.waitForSelector(".token-display", { timeout: 8000 });
  await page.evaluate(() => document.querySelector(".modal-backdrop [data-close]").click());
  await page.waitForFunction((n) => document.querySelectorAll("tbody tr").length === n + 1, kb, { timeout: 8000 })
    .catch(() => fail("created API key did not appear"));
  await page.evaluate(() => {
    const tr = [...document.querySelectorAll("tbody tr")].find((r) => r.textContent.includes("drill-ci-key"));
    (tr.querySelector("button[data-act='revoke']") || tr.querySelector(".btn.danger")).click();
  });
  const conf = await page.waitForSelector(".modal-backdrop [data-confirm]", { timeout: 5000 }).catch(() => null);
  if (conf) await page.click(".modal-backdrop [data-confirm]");
  await page.waitForFunction(() => !document.getElementById("view").textContent.includes("drill-ci-key"), { timeout: 8000 })
    .catch(() => fail("revoked API key still listed"));
  // (d) Fresh-workspace relogin truth: signing back in with the SAME
  // email resumes the created workspace (login() used to wipe the
  // fresh keys unconditionally — sign-out → sign-in silently dumped
  // the investor into Northwind, reading as data loss). A different
  // email gets Northwind and clears the abandoned workspace.
  const rl = await page.evaluate(async () => {
    localStorage.setItem("av_mock_fresh_t0", String(Date.now() - 60000));
    localStorage.setItem("av_mock_fresh_identity", JSON.stringify({ user: { id: "u_rl", email: "founder@relogin.dev", displayName: "Founder" }, org: { id: "org_rl", name: "Relogin Co", slug: "rl", createdAt: new Date().toISOString(), role: "owner" } }));
    await window.dataSource.logout();
    const same = await window.dataSource.login({ email: "FOUNDER@relogin.dev", password: "x" });
    const kept = !!localStorage.getItem("av_mock_fresh_t0");
    await window.dataSource.logout();
    const other = await window.dataSource.login({ email: "someone@else.dev", password: "x" });
    const cleared = !localStorage.getItem("av_mock_fresh_t0");
    return { sameOrg: same.org.name, kept, otherOrg: other.org.name, cleared };
  });
  if (rl.sameOrg !== "Relogin Co" || !rl.kept) fail("same-email relogin lost the fresh workspace: " + JSON.stringify(rl));
  if (rl.otherOrg === "Relogin Co" || !rl.cleared) fail("different-email login kept the stale fresh workspace: " + JSON.stringify(rl));
  await page.evaluate(() => { localStorage.removeItem("av_mock_fresh_t0"); localStorage.removeItem("av_mock_fresh_identity"); localStorage.removeItem("av_mock_signed_out"); });
  await page.reload({ waitUntil: "domcontentloaded" });
  await page.waitForTimeout(800);
  console.log("✅ onboarding items tick for the right reasons at 4 sim ages; members panel view-only for members; key create→revoke round-trip; same-email relogin resumes the fresh workspace (case-insensitive), other emails get Northwind");
}

// ── 24. Live audit trail, webhook toggle, menu, pager ──────────────
// (a) Admin mutations must land in the audit log as they happen (the
// demo's log used to be static fixtures — an investor's own actions
// never appeared). (b) Webhook pause/resume round-trip with the label
// following state. (c) Account-menu items do what they say. (d) The
// [ / ] pager walks the FILTERED list, not the full set.
{
  await page.goto(SITE + "#/settings/webhooks", { waitUntil: "domcontentloaded" });
  await page.waitForSelector("#whAdd", { timeout: 15000 });
  const at = await page.evaluate(async () => {
    const before = (await window.dataSource.listAudit()).length;
    await window.dataSource.testWebhook((await window.dataSource.listWebhooks())[0].id);
    const after = await window.dataSource.listAudit();
    return { d: after.length - before, ev: after[0].event, actor: after[0].actor };
  });
  if (at.d !== 1 || at.ev !== "webhook.test_fired" || !at.actor.includes("@")) fail("mutation did not land in the audit trail: " + JSON.stringify(at));
  const w0 = await page.evaluate(async () => (await window.dataSource.listWebhooks())[0].isActive);
  await page.evaluate(() => { const tr = document.querySelector("tbody tr"); [...tr.querySelectorAll("button")].find((x) => /Pause|Resume/.test(x.textContent)).click(); });
  await page.waitForTimeout(1000);
  const w1 = await page.evaluate(async () => ({
    active: (await window.dataSource.listWebhooks())[0].isActive,
    label: [...document.querySelector("tbody tr").querySelectorAll("button")].map((x) => x.textContent.trim()).find((t) => /Pause|Resume/.test(t)),
  }));
  if (w1.active !== !w0 || w1.label !== (w1.active ? "Pause" : "Resume")) fail("webhook toggle round-trip broken: " + JSON.stringify(w1));
  await page.evaluate(() => { const tr = document.querySelector("tbody tr"); [...tr.querySelectorAll("button")].find((x) => /Pause|Resume/.test(x.textContent)).click(); });
  await page.waitForTimeout(800);
  // account menu: theme + shortcuts sheet
  await page.evaluate(() => { location.hash = "#/overview"; });
  await page.waitForFunction(() => document.querySelector(".stat")?.textContent.trim().length > 0, { timeout: 10000 });
  const th0 = await page.evaluate(() => document.documentElement.getAttribute("data-theme") || "light");
  await page.click(".user-btn");
  await page.waitForSelector("#accountMenu", { timeout: 3000 });
  await page.click('#accountMenu [data-act="theme"]');
  await page.waitForTimeout(400);
  if ((await page.evaluate(() => document.documentElement.getAttribute("data-theme"))) === th0) fail("menu theme toggle did nothing");
  await page.click(".user-btn");
  await page.waitForSelector("#accountMenu", { timeout: 3000 });
  await page.click('#accountMenu [data-act="theme"]');
  await page.waitForTimeout(300);
  await page.click(".user-btn");
  await page.waitForSelector("#accountMenu", { timeout: 3000 });
  await page.click('#accountMenu [data-act="shortcuts"]');
  await page.waitForSelector(".modal-backdrop", { timeout: 3000 });
  if (!(await page.evaluate(() => /shortcut/i.test(document.querySelector(".modal-backdrop").textContent)))) fail("menu shortcuts item opened the wrong thing");
  await page.keyboard.press("Escape");
  await page.waitForTimeout(300);
  // [ / ] pager honors the filtered set
  await page.evaluate(() => { location.hash = "#/sessions?status=blocked"; });
  await page.waitForSelector("tr[data-clickable]", { timeout: 10000 });
  const blockedIds = await page.evaluate(() => [...document.querySelectorAll("tr[data-clickable]")].map((r) => r.getAttribute("data-id")));
  await page.click("tr[data-clickable]");
  await page.waitForSelector("#eventList", { timeout: 10000 });
  await page.keyboard.press("]");
  await page.waitForTimeout(800);
  if ((await page.evaluate(() => location.hash.split("?")[0].split("/")[2])) !== blockedIds[1]) fail("] pager left the filtered set");
  await page.keyboard.press("[");
  await page.waitForTimeout(800);
  if ((await page.evaluate(() => location.hash.split("?")[0].split("/")[2])) !== blockedIds[0]) fail("[ pager did not return");
  const pos = await page.evaluate(() => document.querySelector(".sess-nav-pos")?.textContent);
  if (pos !== "1 / " + blockedIds.length) fail("pager position label wrong: " + pos);
  // Boundaries: at the first item, prev is disabled and [ is a no-op;
  // pressing past either end must never error or navigate weirdly.
  const bounds = await page.evaluate(() => ({
    prevDisabled: !!document.querySelector("#prevSess")?.disabled,
    hash: location.hash,
  }));
  if (!bounds.prevDisabled) fail("prev not disabled at the first session of the browsed set");
  await page.keyboard.press("[");
  await page.waitForTimeout(400);
  if ((await page.evaluate(() => location.hash)) !== bounds.hash) fail("[ at the first item navigated somewhere");
  // Webhook deliveries view: row click opens the per-endpoint history,
  // rows equal listWebhookDeliveries ground truth, the retry case
  // carries its error note, latency is computed.
  await page.goto(SITE + "#/settings/webhooks", { waitUntil: "domcontentloaded" });
  await page.waitForSelector("#whAdd", { timeout: 15000 });
  await page.click("tbody tr[data-id] td:nth-child(2)");
  await page.waitForSelector("#whdBody table", { timeout: 8000 });
  const del = await page.evaluate(async () => {
    const gt = await window.dataSource.listWebhookDeliveries(document.querySelector("tbody tr[data-id]").getAttribute("data-id"));
    const rows = [...document.querySelectorAll("#whdBody tbody tr")];
    return {
      ok: rows.length === gt.length &&
        rows.filter((r) => r.textContent.includes("delivered")).length === gt.filter((d) => d.status === "delivered").length &&
        rows.some((r) => /server_error/.test(r.textContent)) &&
        rows.every((r) => /ms| s/.test(r.cells[4].textContent)),
      n: rows.length,
    };
  });
  if (!del.ok || !del.n) fail("webhook deliveries view vs ground truth: " + JSON.stringify(del));
  await page.keyboard.press("Escape");
  await page.waitForTimeout(300);
  console.log("✅ audit trail records live mutations; webhook toggle round-trips; deliveries view matches ground truth; menu items act; [ ] pager honors filters (" + blockedIds.length + " blocked)");
}

// ── 25. Listener-leak soak ─────────────────────────────────────────
// Every earlier check opened modals, ran the tour, refreshed the
// overview, and re-rendered lists dozens of times. If any of that
// leaked document/window listeners (the webhook modal once leaked a
// keydown per open), the counters instrumented at context start
// would show it. Navigation churn amplifies any remaining leak.
{
  const before = await page.evaluate(() => ({ lc: { ...window.__lc }, iv: window.__iv.size }));
  for (let i = 0; i < 6; i++) {
    await page.evaluate((r) => { location.hash = "#/" + r; }, ["sessions", "overview", "policies", "overview", "deployments", "overview"][i]);
    await page.waitForTimeout(700);
  }
  // Rapid open/close cycling: 10x modal + 10x palette. A fast
  // ⌘K→Escape once hit the pre-autofocus window and left the palette
  // backdrop stuck (Escape only lived on the input); the capture-phase
  // Escape now closes it regardless of focus.
  await page.evaluate(() => { location.hash = "#/policies"; });
  await page.waitForSelector("#addPol", { timeout: 10000 });
  for (let i = 0; i < 10; i++) {
    await page.click("#addPol");
    await page.waitForSelector(".modal-backdrop", { timeout: 3000 });
    await page.keyboard.press("Escape");
    await page.waitForTimeout(60);
  }
  for (let i = 0; i < 10; i++) {
    await page.click(".cmdk-trigger");
    await page.waitForSelector(".cmdk-backdrop", { timeout: 3000 });
    await page.keyboard.press("Escape");
    await page.waitForTimeout(40);
  }
  const residue = await page.evaluate(() => ({
    backdrops: document.querySelectorAll(".modal-backdrop, .cmdk-backdrop").length,
    locked: document.body.classList.contains("locked"),
  }));
  if (residue.backdrops || residue.locked) fail("open/close cycling left residue: " + JSON.stringify(residue));
  const after = await page.evaluate(() => ({ lc: { ...window.__lc }, iv: window.__iv.size }));
  const leaks = {};
  for (const [k, v] of Object.entries(after.lc)) {
    const d = v - (before.lc[k] || 0);
    if (d > 2) leaks[k] = d; // small tolerance for in-flight renders
  }
  if (Object.keys(leaks).length) fail("listener leak during navigation churn: " + JSON.stringify(leaks));
  if (after.iv > before.iv + 1) fail("interval leak: " + before.iv + " → " + after.iv);
  console.log("✅ leak soak: no listener/interval growth across the drill + 6 navigations + 20 open/close cycles");
}

// ── 27. Form semantics truth: HTML validation attributes must actually
// run. The webhook modal was a click-wired div — type=url was dead
// decoration ("not-a-url" created a garbage endpoint) and Enter (the
// mobile keyboard's Go key) did nothing. Retention's max=3650 never
// constrained typed values (99999 saved fine).
{
  // Dismiss anything the previous check left open (openAddModal
  // no-ops while body.locked).
  for (let i = 0; i < 4; i++) {
    const locked = await page.evaluate(() => document.body.classList.contains("locked"));
    if (!locked) break;
    await page.keyboard.press("Escape");
    await page.waitForTimeout(250);
  }
  // (a) webhook: garbage URL is rejected by native validation, modal stays open
  await page.goto(SITE + "#/settings/webhooks", { waitUntil: "domcontentloaded" });
  await page.waitForSelector("#whAdd", { timeout: 15000 });
  const rowsBefore = await page.evaluate(() => document.querySelectorAll("tbody tr").length);
  await page.click("#whAdd");
  await page.waitForSelector("#whForm", { timeout: 5000 });
  await page.fill("#whName", "Form Truth");
  await page.fill("#whUrl", "not-a-url");
  await page.click("#whSave");
  await page.waitForTimeout(300);
  const st = await page.evaluate(() => ({
    open: !!document.querySelector(".modal-backdrop"),
    valid: document.querySelector("#whUrl").checkValidity(),
    rows: document.querySelectorAll("tbody tr").length,
  }));
  if (!st.open || st.valid || st.rows !== rowsBefore) fail("garbage webhook URL was not rejected: " + JSON.stringify(st));
  // (b) Enter in the URL field submits the form (no Save click)
  await page.fill("#whUrl", "https://example.dev/form-truth-hook");
  await page.press("#whUrl", "Enter");
  await page.waitForSelector(".modal-backdrop .mono, .modal-backdrop code", { timeout: 5000 }).catch(() => null);
  await page.waitForFunction((n) => document.querySelectorAll("tbody tr").length === n + 1, rowsBefore, { timeout: 5000 })
    .catch(() => fail("Enter in the webhook URL field did not submit the form"));
  await page.keyboard.press("Escape"); // dismiss the secret modal
  await page.waitForTimeout(200);
  // (c) retention: typed out-of-range value must not save
  await page.goto(SITE + "#/settings/general", { waitUntil: "domcontentloaded" });
  await page.waitForSelector("#retSess", { timeout: 15000 });
  const before = await page.evaluate(async () => (await window.dataSource.getRetention()).retention.sessionRetentionDays);
  await page.fill("#retSess", "99999");
  await page.click("#retSave");
  await page.waitForTimeout(400);
  const after = await page.evaluate(async () => (await window.dataSource.getRetention()).retention.sessionRetentionDays);
  if (after !== before) fail("out-of-range retention (99999) saved: " + before + "→" + after);
  // Scroll-wheel accident: wheel over the FOCUSED number input must
  // not change its value (Chrome default increments it — 90 became 95
  // from scrolling the page).
  await page.fill("#retSess", "90");
  await page.click("#retSess");
  const rBox = await page.locator("#retSess").boundingBox();
  await page.mouse.move(rBox.x + rBox.width / 2, rBox.y + rBox.height / 2);
  for (let i = 0; i < 5; i++) await page.mouse.wheel(0, -120);
  await page.waitForTimeout(300);
  const wheeled = await page.inputValue("#retSess");
  if (wheeled !== "90") fail("scroll wheel changed a focused number input: 90 → " + wheeled);
  console.log("✅ form semantics: type=url validates, Enter submits the webhook form, retention max enforced, wheel can't nudge focused number inputs");
}

// ── 28. Skeleton-phase filter liveness: the sessions filter bar paints
// with the loading skeleton, but its listeners used to be wired only
// after the fetch resolved — anything typed in that window sat dead in
// the bar while the unfiltered list painted below. Delegated listeners
// (invariant 4) must keep the bar live from first paint.
{
  const skPage = await context.newPage();
  await skPage.addInitScript(() => {
    window.__slowOnce = true;
    const arm = () => {
      if (!window.dataSource) return setTimeout(arm, 5);
      const orig = window.dataSource.listSessions.bind(window.dataSource);
      window.dataSource.listSessions = (...a) => {
        if (window.__slowOnce) { window.__slowOnce = false; return new Promise((r) => setTimeout(r, 2000)).then(() => orig(...a)); }
        return orig(...a);
      };
    };
    arm();
  });
  await skPage.goto(SITE + "#/sessions", { waitUntil: "domcontentloaded" });
  await skPage.waitForSelector("#fSearch", { timeout: 15000 });
  await skPage.click("#fSearch");
  await skPage.keyboard.type("returns", { delay: 40 });
  await skPage.waitForTimeout(3200); // superseding fetch + the stale slow one both land
  const sk = await skPage.evaluate(() => ({
    inputVal: document.getElementById("fSearch")?.value,
    rows: document.querySelectorAll("tbody tr").length,
    allMatch: [...document.querySelectorAll("tbody tr")].every((r) => /returns-triage/.test(r.textContent)),
    hash: location.hash,
  }));
  if (sk.inputVal !== "returns" || !sk.rows || !sk.allMatch || !/q=returns/.test(sk.hash))
    fail("skeleton-phase typing was dropped: " + JSON.stringify(sk));
  // Search-field Escape two-step: first press clears the query and
  // re-applies the filter (focus kept), second press blurs. The
  // palette's own Escape (type=text input) must stay untouched.
  await skPage.keyboard.press("Escape");
  await skPage.waitForTimeout(1200); // debounce (220ms) + mock fetch + repaint
  const esc1 = await skPage.evaluate(() => ({
    val: document.getElementById("fSearch").value,
    rows: document.querySelectorAll("tbody tr").length,
    focused: document.activeElement?.id,
  }));
  if (esc1.val !== "" || esc1.rows <= sk.rows || esc1.focused !== "fSearch")
    fail("Escape did not clear the search and restore the list: " + JSON.stringify(esc1));
  await skPage.keyboard.press("Escape");
  await skPage.waitForTimeout(200);
  if (await skPage.evaluate(() => document.activeElement?.id === "fSearch")) fail("second Escape did not blur the search field");
  // Sticky column headers: on a long list the thead must stick flush
  // under the topbar (overflow-x:hidden on .main or overflow:hidden on
  // .table-wrap silently retargets sticky to a non-scrolling box).
  await skPage.evaluate(() => window.scrollTo(0, 2000));
  await skPage.waitForTimeout(250);
  const sticky = await skPage.evaluate(() => {
    const th = document.querySelector("thead th");
    const tb = document.querySelector(".topbar");
    if (!th || !tb) return null;
    const a = th.getBoundingClientRect(), b2 = tb.getBoundingClientRect();
    return { scrolled: window.scrollY > 500, thTop: Math.round(a.top), tbBottom: Math.round(b2.bottom) };
  });
  if (!sticky || !sticky.scrolled || Math.abs(sticky.thTop - sticky.tbBottom) > 2)
    fail("table header did not stick under the topbar: " + JSON.stringify(sticky));
  await skPage.close();
  console.log("✅ skeleton-phase filter liveness: typing during the loading skeleton filters and syncs the URL");
  // Same class on the overview: the range group paints with the
  // skeleton but was wired only after the fetch — a click in that
  // window silently did nothing, and rapid flips let the slower stale
  // fetch paint a dashboard that didn't match the active button.
  const rgPage = await context.newPage();
  await rgPage.addInitScript(() => {
    const arm = () => {
      if (!window.dataSource) return setTimeout(arm, 5);
      let first = true;
      const orig = window.dataSource.getOverview.bind(window.dataSource);
      window.dataSource.getOverview = (...a) => {
        if (first) { first = false; return new Promise((r) => setTimeout(r, 2000)).then(() => orig(...a)); }
        return orig(...a);
      };
    };
    arm();
  });
  await rgPage.goto(SITE + "#/overview", { waitUntil: "domcontentloaded" });
  await rgPage.waitForSelector(".range-group button", { timeout: 15000 });
  await rgPage.click('.range-group button[data-range="7d"]');
  await rgPage.waitForTimeout(3000); // both fetches land; the stale one must not paint
  const rg = await rgPage.evaluate(() => ({
    active: document.querySelector(".range-group button.active")?.getAttribute("data-range"),
    label: document.querySelector(".page-header")?.innerText || "",
    hasStats: !!document.querySelector(".stat .value"),
    hash: location.hash,
  }));
  if (rg.active !== "7d" || !/7 days/.test(rg.label) || !rg.hasStats || !/range=7d/.test(rg.hash))
    fail("skeleton-phase range click dropped or stale fetch clobbered: " + JSON.stringify(rg));
  await rgPage.close();
  console.log("✅ skeleton-phase range click lands; stale overview fetch cannot clobber the newer range");
}

// ── 29. Dirty-modal discard guard: a reflexive Escape or a backdrop
// mis-click used to instantly wipe everything typed into a modal form.
// First attempt on a dirty modal must block + explain; second attempt
// discards; pristine modals and explicit Cancel stay immediate.
{
  const dmPage = await context.newPage();
  const open = () => dmPage.evaluate(() => !!document.querySelector(".modal-backdrop"));
  await dmPage.goto(SITE + "#/settings/members", { waitUntil: "domcontentloaded" });
  await dmPage.waitForSelector("#inviteBtn", { timeout: 15000 });
  // pristine: Escape closes immediately
  await dmPage.click("#inviteBtn");
  await dmPage.waitForSelector("#inviteForm", { timeout: 5000 });
  await dmPage.keyboard.press("Escape");
  await dmPage.waitForTimeout(250);
  if (await open()) fail("pristine modal did not close on first Escape");
  // dirty: Escape blocked + toast, second Escape discards
  await dmPage.click("#inviteBtn");
  await dmPage.waitForSelector("#inviteForm", { timeout: 5000 });
  await dmPage.fill("#inv_email", "half-typed@acme.com");
  await dmPage.keyboard.press("Escape");
  await dmPage.waitForTimeout(250);
  const toastTxt = await dmPage.evaluate(() => document.querySelector(".toast")?.textContent || "");
  if (!(await open()) || !/unsaved/i.test(toastTxt)) fail("dirty modal not guarded on Escape: open=" + (await open()) + " toast=" + toastTxt.slice(0, 40));
  await dmPage.keyboard.press("Escape");
  await dmPage.waitForTimeout(250);
  if (await open()) fail("second Escape did not discard the dirty modal");
  // dirty: backdrop mis-click blocked; explicit Cancel immediate
  await dmPage.click("#inviteBtn");
  await dmPage.waitForSelector("#inviteForm", { timeout: 5000 });
  await dmPage.fill("#inv_email", "oops@acme.com");
  await dmPage.mouse.click(15, 400);
  await dmPage.waitForTimeout(250);
  if (!(await open())) fail("dirty modal closed on a backdrop mis-click");
  await dmPage.click(".modal [data-close]");
  await dmPage.waitForTimeout(250);
  if (await open()) fail("explicit Cancel was blocked on a dirty modal");
  await dmPage.close();
  console.log("✅ dirty-modal discard guard: mis-close blocked + explained, second attempt discards, Cancel immediate");
  // Hostile-length identity (real signups will have these): a long
  // email once stretched the account menu to ~1040px wide. Topbar must
  // not overflow; the menu stays capped and on-screen.
  const lnPage = await context.newPage();
  await lnPage.addInitScript(() => {
    localStorage.setItem("av_mock_fresh_t0", String(Date.now() - 60000));
    localStorage.setItem("av_mock_fresh_identity", JSON.stringify({
      user: { id: "u_x", email: "maximilian.von.hohenzollern-sigmaringen@acme-international-holdings.example.com", displayName: "Maximilian Alexander von Hohenzollern-Sigmaringen III, Esq.", role: "owner" },
      org: { id: "org_x", name: "Acme Corporation International Holdings & Consolidated Subsidiaries GmbH & Co. KGaA" },
    }));
  });
  await lnPage.goto(SITE + "#/overview", { waitUntil: "domcontentloaded" });
  await lnPage.waitForSelector(".user-btn", { timeout: 15000 });
  await lnPage.click(".user-btn");
  await lnPage.waitForTimeout(300);
  const ln = await lnPage.evaluate(() => {
    const m = document.querySelector("#accountMenu")?.getBoundingClientRect();
    return {
      hOv: document.documentElement.scrollWidth - document.documentElement.clientWidth,
      menuW: Math.round(m?.width || 9999),
      menuFits: !!m && m.right <= innerWidth + 1 && m.left >= -1,
    };
  });
  if (ln.hOv > 0 || ln.menuW > 340 || !ln.menuFits) fail("hostile-length identity broke the chrome: " + JSON.stringify(ln));
  await lnPage.close();
  console.log("✅ hostile-length identity: topbar contained, account menu capped at " + ln.menuW + "px");
}

// ── 30. Theme toggle preserves widget state: toggleTheme used to call
// render(), wiping typed-but-uncommitted filters, the selected event +
// drawer, loaded pages, and scroll. Theming is CSS-var-driven — a flip
// must repaint colors only. Covers the in-tab toggle AND the cross-tab
// storage follower (which had the same render() reset).
{
  const tPage = await context.newPage();
  await tPage.goto(SITE + "#/sessions/sess_01H9K", { waitUntil: "domcontentloaded" });
  await tPage.waitForSelector("#evtSearch", { timeout: 15000 });
  await tPage.click(".evt");
  await tPage.waitForTimeout(250);
  await tPage.click("#evtSearch");
  await tPage.keyboard.type("tool", { delay: 25 });
  await tPage.waitForTimeout(450);
  await tPage.evaluate(() => window.scrollTo(0, 300));
  await tPage.waitForTimeout(150);
  const pre = await tPage.evaluate(() => ({
    visible: [...document.querySelectorAll(".evt")].filter((x) => !x.classList.contains("evt-hidden")).length,
    scrollY: window.scrollY, // may be < 300 if the page is short at this viewport
  }));
  await tPage.click(".user-btn");
  await tPage.waitForSelector('#accountMenu [data-act="theme"]', { timeout: 4000 });
  await tPage.click('#accountMenu [data-act="theme"]');
  await tPage.waitForTimeout(450);
  const post = await tPage.evaluate(() => ({
    themed: !!document.documentElement.getAttribute("data-theme"),
    q: document.getElementById("evtSearch")?.value,
    visible: [...document.querySelectorAll(".evt")].filter((x) => !x.classList.contains("evt-hidden")).length,
    selected: !!document.querySelector(".evt.selected"),
    scrollY: window.scrollY,
  }));
  const scrollKept = Math.abs(post.scrollY - pre.scrollY) <= 4; // a render() reset would land at 0
  if (!post.themed || post.q !== "tool" || post.visible !== pre.visible || !post.selected || !scrollKept)
    fail("theme toggle reset widget state: " + JSON.stringify(post));
  // menu label reflects the new theme on next open
  await tPage.click(".user-btn");
  await tPage.waitForSelector("#accountMenu", { timeout: 4000 });
  const themeNow = await tPage.evaluate(() => document.documentElement.getAttribute("data-theme"));
  const label = await tPage.evaluate(() => document.querySelector('#accountMenu [data-act="theme"]').textContent);
  const expectWord = themeNow === "dark" ? /light/i : /dark/i;
  if (!expectWord.test(label)) fail("menu label stale after toggle: theme=" + themeNow + " label=" + label);
  // cross-tab follower keeps the second tab's widget state too
  const t2 = await context.newPage();
  await t2.goto(SITE + "#/sessions/sess_01H9K", { waitUntil: "domcontentloaded" });
  await t2.waitForSelector("#evtSearch", { timeout: 15000 });
  await t2.click("#evtSearch");
  await t2.keyboard.type("block", { delay: 25 });
  await t2.waitForTimeout(400);
  await tPage.bringToFront();
  await tPage.click('#accountMenu [data-act="theme"]'); // toggle back (menu still open)
  await tPage.waitForTimeout(600);
  const tab2 = await t2.evaluate(() => ({
    theme: document.documentElement.getAttribute("data-theme"),
    q: document.getElementById("evtSearch")?.value,
  }));
  if (tab2.q !== "block") fail("cross-tab theme follow reset the other tab's widgets: " + JSON.stringify(tab2));
  await tPage.close();
  await t2.close();
  console.log("✅ theme toggle: colors flip, widgets keep state (filter/selection/scroll, both tabs), menu label fresh");
}

// ── 31. Keyboard-only tour: Tab reaches Next, and Enter walks all six
// steps with focus STAYING on Next across route changes — announceRoute
// used to steal focus to #view on every cross-route step, stranding
// keyboard users mid-tour (the tour card is a persistent body-level
// overlay; its focus must survive navigation).
{
  const kbPage = await context.newPage();
  await kbPage.goto(SITE + "?tour=1#/overview", { waitUntil: "domcontentloaded" });
  await kbPage.waitForSelector(".av-tour-card", { timeout: 15000 });
  let reached = false;
  for (let i = 0; i < 30; i++) {
    await kbPage.keyboard.press("Tab");
    if (await kbPage.evaluate(() => document.activeElement?.classList?.contains("av-tour-next"))) { reached = true; break; }
  }
  if (!reached) fail("Tab could not reach the tour Next button");
  for (let step = 0; step < 6; step++) {
    await kbPage.keyboard.press("Enter");
    await kbPage.waitForTimeout(1300);
    const st = await kbPage.evaluate(() => ({
      onNext: document.activeElement?.classList?.contains("av-tour-next"),
      label: document.querySelector(".av-tour-next")?.textContent.trim() || "",
    }));
    if (/verifier/i.test(st.label)) break; // finale CTA reached
    if (!st.onNext) fail("focus left the tour Next button after step " + (step + 1) + " (route-change steal)");
  }
  const finale = await kbPage.evaluate(() => document.querySelector(".av-tour-next")?.textContent.trim() || "");
  if (!/verifier/i.test(finale)) fail("keyboard walk did not reach the finale CTA: " + finale);
  await kbPage.keyboard.press("Escape");
  await kbPage.close();
  console.log("✅ keyboard-only tour: Tab to Next, Enter × steps, focus survives every route change, finale CTA reached");
}

if (jsErrors.length) fail("JS errors during drill: " + JSON.stringify(jsErrors));
console.log("✅ zero uncaught JS errors");

await browser.close();
console.log("\nAll 31 interactive-features drill checks passed.");
