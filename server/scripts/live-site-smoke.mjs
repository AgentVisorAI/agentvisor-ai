/*
 * Live-site smoke test: hits https://agentvisorai.me/app/ (the actual
 * deployed console) and asserts the SPA works end-to-end from a real
 * browser against the real GitHub Pages CDN.
 *
 * Runs in MOCK_MODE=true (as deployed) so no backend is needed.
 * Verifies:
 *   1. HTTPS + valid cert.
 *   2. index.html loads with our SPA bundle.
 *   3. Login form renders when signed out.
 *   4. Login with any credentials -> overview.
 *   5. All 9 SPA routes render (no JS errors, no 4xx from Pages).
 *   6. Every settings tab has POPULATED demo data — no empty states
 *      that would make an investor think the product is a stub.
 *   7. Live indicator pulses (mock subscribe fires an event).
 */
import { chromium } from "playwright";

const SITE = process.env.SITE ?? process.argv[2] ?? "https://agentvisorai.me/app/";

const browser = await chromium.launch({ headless: true });
const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
const page = await context.newPage();

const jsErrors = [];
const netErrors = [];
page.on("pageerror", (e) => jsErrors.push(e.message));
page.on("response", (r) => {
  if ((r.url().includes("agentvisorai.me") || r.url().includes("127.0.0.1")) && r.status() >= 400) {
    netErrors.push(r.url() + " -> " + r.status());
  }
});
function fail(m) {
  console.log("❌", m);
  console.log("JS errors:", jsErrors);
  console.log("Net errors:", netErrors);
  process.exit(1);
}
async function wait(ms) { return new Promise((r) => setTimeout(r, ms)); }

// 1-2. Load the SPA. Force signed-out so login form renders.
await page.addInitScript(() => {
  try { localStorage.setItem("av_mock_signed_out", "1"); } catch {}
});
await page.goto(SITE, { waitUntil: "networkidle" });
if (!page.url().includes("/app")) fail("wrong URL: " + page.url());
console.log("✅ SPA loaded from", new URL(SITE).host);

// 3-4. Login
await page.goto(SITE + "#/login", { waitUntil: "networkidle" });
await page.waitForSelector('input#email', { timeout: 15000 });
await page.locator('input#email').fill("olivia.tan@northwind.com");
await page.locator('input#password').fill("d3mo");
await page.locator('button[type="submit"]').first().click();
await wait(1500);
if (page.url().includes("/login")) fail("stuck on login. url=" + page.url());
console.log("✅ login worked in mock mode");

// 5. Navigate through all routes; no JS errors.
const routes = [
  "#/overview", "#/deployments", "#/sessions", "#/policies",
  "#/settings/general", "#/settings/members", "#/settings/keys",
  "#/settings/sso", "#/settings/webhooks", "#/settings/audit", "#/settings/billing",
];
for (const r of routes) {
  await page.goto(SITE + r);
  await wait(700);
  const len = await page.locator("body").innerText().then((t) => t.length);
  if (len < 200) fail("route " + r + " nearly empty (" + len + " chars)");
}
console.log("✅ all " + routes.length + " routes render (>200 chars)");
if (jsErrors.length) fail("JS errors: " + JSON.stringify(jsErrors));
if (netErrors.filter((n) => !n.includes("favicon") && !n.includes("host")).length) fail("network errors: " + JSON.stringify(netErrors));
console.log("✅ no JS errors, no 4xx");

// 6. Populated settings tabs — no empty states in the pitch surface.
await page.goto(SITE + "#/settings/webhooks");
await wait(1200);
{
  const text = await page.locator("body").innerText();
  if (/No webhooks yet/i.test(text)) fail("Webhooks tab shows empty state!");
  if (!/slack|pagerduty|datadog/i.test(text)) fail("Webhooks: no populated endpoints");
  console.log("✅ Webhooks tab populated with Slack + PagerDuty + Datadog");
}
await page.goto(SITE + "#/settings/keys");
await wait(1000);
{
  const text = await page.locator("body").innerText();
  if (/No API keys yet/i.test(text)) fail("API keys tab shows empty state!");
  if (!/CI runner|Ops dashboard/i.test(text)) fail("API keys: no populated rows");
  console.log("✅ API keys tab populated");
}
await page.goto(SITE + "#/settings/sso");
await wait(1200);
{
  const text = await page.locator("body").innerText();
  if (/No SAML IdPs yet/i.test(text)) fail("SSO tab shows empty state!");
  console.log("✅ SSO tab populated");
}
await page.goto(SITE + "#/settings/members");
await wait(1200);
{
  const text = await page.locator("body").innerText();
  if (!/olivia|raj|sam/i.test(text)) fail("Members: no rows");
  console.log("✅ Members tab populated");
}
await page.goto(SITE + "#/settings/audit");
await wait(1200);
{
  const rows = await page.locator("tbody tr").count();
  if (rows < 3) fail("Audit tab: only " + rows + " rows");
  console.log("✅ Audit log populated (" + rows + " rows)");
}

// 7. Live/Demo indicator — mock shows "Demo" pill, real backend shows
// "Live" pulse.
await page.goto(SITE + "#/overview");
await wait(500);
const anyPill = page.locator('.env-pill');
if (await anyPill.count() === 0) fail("no env pill on overview");
const pillText = (await anyPill.first().innerText()).toLowerCase();
if (!/(live|demo)/.test(pillText)) fail("pill text: " + pillText);
console.log("✅ Environment pill present: " + pillText);

// 8. Link + media integrity across the static pages: every internal
// link resolves, every same-page anchor target exists, external
// _blank links carry noopener, and both pitch videos load with a
// parsed captions track. (/api/ is assembled by the Pages workflow,
// so it only exists on the deployed site — skipped on localhost.)
{
  const origin = new URL(SITE).origin + "/";
  const isLocal = /localhost|127\.0\.0\.1/.test(origin);
  const problems = [];
  for (const p of ["", "pitch/", "verify/"]) {
    await page.goto(origin + p, { waitUntil: "domcontentloaded" });
    await wait(500);
    const links = await page.evaluate(() => [...document.querySelectorAll("a[href]")].map((a) => ({
      href: a.getAttribute("href"), target: a.getAttribute("target"), rel: a.getAttribute("rel") || "", text: a.textContent.trim().slice(0, 30),
    })));
    const ids = await page.evaluate(() => [...document.querySelectorAll("[id]")].map((e) => e.id));
    for (const l of links) {
      if (!l.href || l.href.startsWith("mailto:")) continue;
      if (l.href.startsWith("#")) {
        if (l.href.length > 1 && !ids.includes(l.href.slice(1))) problems.push(`/${p}: dead anchor ${l.href}`);
        continue;
      }
      if (/^https?:\/\//.test(l.href)) {
        if (l.target === "_blank" && !/noopener/.test(l.rel)) problems.push(`/${p}: _blank without noopener: ${l.href}`);
        continue;
      }
      if (isLocal && /^\.?\/?api\//.test(l.href)) continue;
      const clean = new URL(l.href, origin + p).href.split("#")[0];
      const st = await page.evaluate(async (u) => { try { return (await fetch(u)).status; } catch { return 0; } }, clean);
      if (st !== 200) problems.push(`/${p}: ${l.href} -> HTTP ${st} ('${l.text}')`);
    }
  }
  await page.goto(origin + "pitch/", { waitUntil: "domcontentloaded" });
  await wait(800);
  const media = await page.evaluate(async () => {
    const out = [];
    for (const v of document.querySelectorAll("video")) {
      const t = v.textTracks[0];
      if (t) t.mode = "hidden"; // force cue load
      await new Promise((r) => setTimeout(r, 400));
      out.push({ tracks: v.textTracks.length, cues: t && t.cues ? t.cues.length : 0 });
    }
    return out;
  });
  for (const m of media) if (!m.tracks || !m.cues) problems.push("pitch video captions missing/unparsed: " + JSON.stringify(m));
  if (problems.length) fail("link/media integrity:\n  " + problems.join("\n  "));
  console.log("✅ Link + media integrity: all internal links resolve, anchors exist, videos have parsed captions");
  // Alias stubs + branded 404: /mockup and /demo are meta-refresh
  // shortcuts (printed on the QR handout), and the 404 page must keep
  // its brand line + escape links — dead ends lose investors.
  for (const [alias, want] of [["mockup/", "/pitch/"], ["demo/", "/app/"]]) {
    const html = await page.evaluate(async (u) => (await fetch(u)).text(), origin + alias);
    if (!html.includes('http-equiv="refresh"') || !html.includes(want)) fail("/" + alias + " alias stub broken (wants " + want + ")");
  }
  const h404 = await page.evaluate(async (u) => (await fetch(u)).text(), origin + "404.html");
  if (!/AgentVisor/i.test(h404) || !h404.includes('href="/pitch/"') || !h404.includes('href="/app/"') || !h404.includes('href="/verify/"'))
    fail("404 page missing brand line or escape links");
  console.log("✅ Alias stubs (/mockup→/pitch, /demo→/app) + branded 404 with escape links");
}

// 9. Link previews: these URLs get pasted into Slack/WhatsApp/email —
// every page needs complete OG/Twitter metadata with an absolute
// og:image that actually resolves, and a working favicon.
{
  const origin = new URL(SITE).origin + "/";
  for (const p of ["", "pitch/", "verify/", "app/"]) {
    await page.goto(origin + p, { waitUntil: "domcontentloaded" });
    const m = await page.evaluate(async (orig) => {
      const g = (sel) => document.querySelector(sel)?.getAttribute("content") || null;
      const ogImage = g('meta[property="og:image"]');
      let imgStatus = 0;
      if (ogImage && /^https?:\/\//.test(ogImage)) {
        try { imgStatus = (await fetch(ogImage.replace("https://agentvisorai.me/", orig))).status; } catch {}
      }
      const iconHref = document.querySelector('link[rel~="icon"]')?.getAttribute("href");
      let iconStatus = 0;
      if (iconHref) { try { iconStatus = (await fetch(iconHref)).status; } catch {} }
      return { title: !!g('meta[property="og:title"]'), desc: !!g('meta[property="og:description"]'), imgAbs: !!ogImage && /^https?:\/\//.test(ogImage), imgStatus, twitter: !!g('meta[name="twitter:card"]'), iconStatus };
    }, origin);
    if (!m.title || !m.desc || !m.imgAbs || m.imgStatus !== 200 || !m.twitter || m.iconStatus !== 200) {
      fail("/" + p + " link-preview metadata broken: " + JSON.stringify(m));
    }
  }
  console.log("✅ Link previews: OG/Twitter tags complete on all 4 pages, og:image + favicon resolve");
}

// ── 10. Video playback truth: a corrupt/truncated MP4 still passes a
// 200-status crawl. Headless Chromium reads container metadata —
// assert both pitch videos expose their expected durations with no
// MediaError (pitch ~30s, tour ~130s).
{
  const origin = new URL(SITE).origin;
  const page = await context.newPage();
  await page.goto(origin + "/pitch/", { waitUntil: "domcontentloaded" });
  await page.waitForSelector("video", { timeout: 10000 });
  const vids = await page.evaluate(async () => {
    const out = [];
    for (const v of document.querySelectorAll("video")) {
      v.muted = true;
      try { v.load(); } catch {}
      await new Promise((r) => { const done = () => r(); v.addEventListener("loadedmetadata", done, { once: true }); v.addEventListener("error", done, { once: true }); setTimeout(done, 8000); });
      out.push({ src: (v.currentSrc || "").split("/").pop(), dur: Math.round(v.duration || 0), err: v.error ? v.error.code : null, ready: v.readyState });
    }
    return out;
  });
  const pitch = vids.find((v) => /pitch/.test(v.src));
  const tour = vids.find((v) => /tour/.test(v.src));
  if (!pitch || pitch.err !== null || pitch.ready < 1 || pitch.dur < 25 || pitch.dur > 40)
    fail("pitch video metadata broken: " + JSON.stringify(pitch));
  if (!tour || tour.err !== null || tour.ready < 1 || tour.dur < 120 || tour.dur > 140)
    fail("tour video metadata broken: " + JSON.stringify(tour));
  await page.close();
  console.log("✅ video truth: both MP4s decode metadata (pitch " + pitch.dur + "s, tour " + tour.dur + "s), zero MediaErrors");
}

await browser.close();
console.log("\nLive site smoke passed (10 checks against " + SITE + ").");
