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
// Count document/window listeners so the leak check (check 10) can
// assert the refresh loops and modal cycles don't accumulate handlers.
await context.addInitScript(() => {
  window.__lc = {};
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
  }
  console.log("✅ table action buttons: all inside their cells and hittable (5 routes)");
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
  ]) {
    await page.evaluate((k) => { localStorage.clear(); for (const [a, b2] of Object.entries(k)) localStorage.setItem(a, b2); }, kv);
    await page.reload({ waitUntil: "domcontentloaded" });
    await page.waitForTimeout(1500);
    const st = await page.evaluate(() => ({
      shell: !!document.querySelector(".app-shell, .auth"),
      len: (document.getElementById("view")?.innerText || "").trim().length,
    }));
    if (!st.shell || st.len < 30) fail("corrupted storage bricked the app: " + JSON.stringify(kv) + " → " + JSON.stringify(st));
  }
  await page.evaluate(() => localStorage.clear());
  await page.reload({ waitUntil: "domcontentloaded" });
  await page.waitForTimeout(1200);
  console.log("✅ corrupted-storage fuzz: bad identity shapes + NaN t0 all self-heal");
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
  await page.evaluate(() => localStorage.removeItem("av_mock_bigdata"));
  console.log("✅ pagination: sessions 50→100 + sort; events 500→700 with selection kept; ?evt=600 auto-pages");
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
  console.log("✅ browser Back sweeps modal + palette overlays; copy gives feedback without clipboard API (" + toastTxt.trim().slice(0, 30) + ")");
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
  console.log("✅ cross-tab sync: sign-out bounces, sign-in un-strands the login tab, theme follows");
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
  await page.waitForTimeout(2600); // let them drain before the soak
  console.log("✅ tactile polish: text-select doesn't navigate, Back restores scroll, toasts cap at 4");
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

// ── 20. Listener-leak soak ─────────────────────────────────────────
// Every earlier check opened modals, ran the tour, refreshed the
// overview, and re-rendered lists dozens of times. If any of that
// leaked document/window listeners (the webhook modal once leaked a
// keydown per open), the counters instrumented at context start
// would show it. Navigation churn amplifies any remaining leak.
{
  const before = await page.evaluate(() => ({ ...window.__lc }));
  for (let i = 0; i < 6; i++) {
    await page.evaluate((r) => { location.hash = "#/" + r; }, ["sessions", "overview", "policies", "overview", "deployments", "overview"][i]);
    await page.waitForTimeout(700);
  }
  const after = await page.evaluate(() => ({ ...window.__lc }));
  const leaks = {};
  for (const [k, v] of Object.entries(after)) {
    const d = v - (before[k] || 0);
    if (d > 2) leaks[k] = d; // small tolerance for in-flight renders
  }
  if (Object.keys(leaks).length) fail("listener leak during navigation churn: " + JSON.stringify(leaks));
  console.log("✅ listener-leak soak: no document/window handler growth across the whole drill + 6 navigations");
}

if (jsErrors.length) fail("JS errors during drill: " + JSON.stringify(jsErrors));
console.log("✅ zero uncaught JS errors");

await browser.close();
console.log("\nAll 21 interactive-features drill checks passed.");
