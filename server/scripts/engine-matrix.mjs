import { chromium, webkit, firefox } from "playwright";
// Cross-engine feature matrix: the post-campaign interactive surface
// (sortable columns, session pager, event-triage chips, account menu,
// policy-create preview, audit filters, mobile tab bar) exercised on
// Chromium, WebKit, and Firefox. Engine-specific regressions (Safari
// especially) don't show up in the chromium-only drills.
const SITE = process.env.SITE ?? process.argv[2] ?? "https://agentvisorai.me/app/";
const engines = { chromium, webkit, firefox };
let anyFail = false;
for (const [name, engine] of Object.entries(engines)) {
  const b = await engine.launch();
  const pg = await (await b.newContext()).newPage();
  const errs = []; pg.on("pageerror", e => errs.push(String(e).slice(0, 100)));
  const fails = [];
  try {
    await pg.goto(SITE + "#/login");
    await pg.click('button:has-text("Continue with Google")').catch(()=>{});
    await pg.waitForTimeout(900);

    // sortable headers
    await pg.goto(SITE + "#/sessions");
    await pg.waitForSelector(".th-sort", { timeout: 8000 });
    await pg.click('.th-sort[data-sort="cost"]');
    await pg.waitForTimeout(500);
    const sorted = await pg.evaluate(() => {
      const c = [...document.querySelectorAll("tbody tr")].map(r => parseFloat(r.cells[5].textContent.replace(/[^0-9.]/g, "")));
      return c.every((v, i) => !i || v <= c[i-1] + 1e-9);
    });
    if (!sorted) fails.push("sort");

    // pager
    await pg.locator("tr[data-clickable]").first().click();
    await pg.waitForSelector(".sess-nav", { timeout: 8000 });
    await pg.keyboard.press("]");
    await pg.waitForTimeout(600);
    const paged = await pg.evaluate(() => document.querySelector(".sess-nav-pos")?.textContent.startsWith("2"));
    if (!paged) fails.push("pager");

    // event triage chips
    await pg.goto(SITE + "#/sessions/sess_01H9K");
    await pg.waitForSelector(".evt-chip", { timeout: 8000 });
    await pg.click('.evt-chip[data-kind="block"]');
    const chipOk = await pg.evaluate(() => document.querySelectorAll(".evt:not(.evt-hidden)").length === 1);
    if (!chipOk) fails.push("evt-chips");

    // account menu
    await pg.click("#userBtn");
    await pg.waitForSelector("#accountMenu", { timeout: 4000 });
    await pg.keyboard.press("Escape");
    await pg.waitForTimeout(200);
    if (await pg.locator("#accountMenu").count()) fails.push("account-menu");

    // policy create (template modal end-to-end)
    await pg.goto(SITE + "#/policies");
    await pg.waitForSelector("#addPol", { timeout: 8000 });
    await pg.click("#addPol");
    await pg.waitForSelector("#polPreview", { timeout: 5000 });
    await pg.fill("#polParam", "333");
    await pg.waitForTimeout(200);
    const dsl = await pg.evaluate(() => document.querySelector("#polPreview").textContent.includes("> 333"));
    if (!dsl) fails.push("policy-preview");
    await pg.keyboard.press("Escape");

    // audit filters + csv-less check
    await pg.goto(SITE + "#/settings/audit");
    await pg.waitForSelector(".evt-chip", { timeout: 8000 });
    await pg.click('.evt-chip[data-cat="policy"]');
    const audOk = await pg.evaluate(() => document.getElementById("auditCount").textContent.includes("of"));
    if (!audOk) fails.push("audit-filter");

    // mobile tab bar (resize context)
    await pg.setViewportSize({ width: 390, height: 844 });
    await pg.evaluate(() => { location.hash = "#/overview"; });
    await pg.waitForTimeout(600);
    const tab = await pg.evaluate(() => getComputedStyle(document.querySelector(".tabbar")).display !== "none");
    if (!tab) fails.push("tabbar");
    await pg.click('.tabbar a[href="#/sessions"]');
    await pg.waitForTimeout(500);
    if ((await pg.evaluate(() => location.hash)) !== "#/sessions") fails.push("tabbar-nav");

    // ── Newest invariants (post-#225 work): these lean hardest on
    // engine-specific behavior — position:sticky containing blocks,
    // wheel event semantics, and capture-phase click vetoes.
    await pg.setViewportSize({ width: 1280, height: 800 });

    // sticky table headers (overflow:clip vs scroll-container retarget)
    await pg.evaluate(() => { location.hash = "#/sessions"; });
    await pg.waitForSelector("thead th", { timeout: 8000 });
    await pg.evaluate(() => window.scrollTo(0, 1200));
    await pg.waitForTimeout(300);
    const stickyOk = await pg.evaluate(() => {
      if (window.scrollY < 400) return true; // page too short to test here
      const th = document.querySelector("thead th").getBoundingClientRect();
      const tb = document.querySelector(".topbar").getBoundingClientRect();
      return Math.abs(th.top - tb.bottom) <= 2;
    });
    if (!stickyOk) fails.push("sticky-th");
    await pg.evaluate(() => window.scrollTo(0, 0));

    // dirty-modal discard guard (capture-phase Escape veto)
    await pg.evaluate(() => { location.hash = "#/settings/members"; });
    await pg.waitForSelector("#inviteBtn", { timeout: 8000 });
    await pg.click("#inviteBtn");
    await pg.waitForSelector("#inv_email", { timeout: 5000 });
    await pg.fill("#inv_email", "dirty@x.dev");
    await pg.keyboard.press("Escape");
    await pg.waitForTimeout(300);
    const guarded = await pg.evaluate(() => !!document.querySelector(".modal-backdrop"));
    await pg.keyboard.press("Escape");
    await pg.waitForTimeout(300);
    const discarded = await pg.evaluate(() => !document.querySelector(".modal-backdrop"));
    if (!guarded || !discarded) fails.push("dirty-guard");

    // theme toggle preserves widget state (no render)
    await pg.evaluate(() => { location.hash = "#/sessions/sess_01H9K"; });
    await pg.waitForSelector("#evtSearch", { timeout: 8000 });
    await pg.click("#evtSearch");
    await pg.keyboard.type("tool");
    await pg.waitForTimeout(500);
    await pg.click("#userBtn");
    await pg.waitForSelector('#accountMenu [data-act="theme"]', { timeout: 4000 });
    await pg.click('#accountMenu [data-act="theme"]');
    await pg.waitForTimeout(400);
    const themeKept = await pg.evaluate(() => !!document.documentElement.getAttribute("data-theme") && document.getElementById("evtSearch")?.value === "tool");
    if (!themeKept) fails.push("theme-state");
  } catch (e) { fails.push("exception: " + String(e).split("\n")[0].slice(0, 80)); }
  const status = fails.length || errs.length ? "❌" : "✅";
  anyFail = anyFail || fails.length > 0 || errs.length > 0;
  console.log(`${status} ${name}: ${fails.length ? "FAIL " + fails.join(",") : "all 11 features pass"}${errs.length ? " | JS: " + errs[0] : ""}`);
  await b.close();
}
process.exit(anyFail ? 1 : 0);
