/*
 * Perfect investor mockup video — record every scene individually so
 * we can polish, retry, and iterate cheaply on any single clip.
 *
 * Output: /tmp/video-v4/scenes/<n>-<name>.webm
 *
 * ffmpeg then stitches with crossfades + captions.
 */
import { chromium } from "playwright";
import { writeFileSync, mkdirSync, rmSync, readdirSync, renameSync, existsSync } from "node:fs";
import { join } from "node:path";

const OUT = "/tmp/video-v4/scenes";
if (existsSync(OUT)) rmSync(OUT, { recursive: true, force: true });
mkdirSync(OUT, { recursive: true });

const SITE = process.env.SITE ?? "https://agentvisorai.me/app/";
const LANDING = new URL(SITE).origin;

function cardHtml(opts) {
  const bg = opts.bg || "#0a5c8b";
  const kicker = opts.kicker || "";
  const headline = opts.headline;
  const sub = opts.sub || "";
  return `<!doctype html><html><head><meta charset="utf-8"><style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    html, body { width: 100%; height: 100%; overflow: hidden; background: ${bg}; color: #fff; font-family: -apple-system, BlinkMacSystemFont, "SF Pro Display", "Segoe UI", system-ui, sans-serif; -webkit-font-smoothing: antialiased; }
    .stage { width: 100vw; height: 100vh; display: flex; flex-direction: column; align-items: center; justify-content: center; text-align: center; padding: 4rem; opacity: 0; transform: translateY(12px); animation: fadeIn 0.7s 0.15s cubic-bezier(0.16,1,0.3,1) forwards; }
    @keyframes fadeIn { to { opacity: 1; transform: translateY(0); } }
    .kicker { font-size: 15px; font-weight: 600; letter-spacing: 0.35em; text-transform: uppercase; opacity: 0.6; margin-bottom: 2.5rem; }
    .headline { font-size: 92px; font-weight: 800; letter-spacing: -0.035em; line-height: 1.02; max-width: 1250px; }
    .accent-red { color: #ff6a58; }
    .accent-yellow { color: #ffd54f; }
    .accent-green { color: #6ecf8e; }
    .subline { font-size: 26px; font-weight: 400; margin-top: 2rem; opacity: 0.85; max-width: 900px; line-height: 1.4; }
    .brand { position: absolute; bottom: 40px; display: flex; align-items: center; gap: 12px; font-size: 15px; opacity: 0.6; letter-spacing: 0.02em; }
    .brand-mark { width: 26px; height: 26px; background: #fff; color: #0a5c8b; border-radius: 6px; display: flex; align-items: center; justify-content: center; font-weight: 800; font-size: 15px; }
  </style></head><body>
    <div class="stage">
      ${kicker ? `<div class="kicker">${kicker}</div>` : ""}
      <div class="headline">${headline}</div>
      ${sub ? `<div class="subline">${sub}</div>` : ""}
    </div>
    <div class="brand"><div class="brand-mark">A</div>AgentVisor AI · agentvisorai.me</div>
  </body></html>`;
}

async function recordScene(browser, sceneName, durationMs, fn) {
  console.log(`\n▶ Recording scene "${sceneName}" (${durationMs}ms)…`);
  const sceneDir = join(OUT, sceneName);
  mkdirSync(sceneDir, { recursive: true });
  const ctx = await browser.newContext({
    viewport: { width: 1920, height: 1080 },
    recordVideo: { dir: sceneDir, size: { width: 1920, height: 1080 } },
    deviceScaleFactor: 1,
  });
  const page = await ctx.newPage();
  await fn(page, durationMs);
  await ctx.close();
  const files = readdirSync(sceneDir).filter((f) => f.endsWith(".webm"));
  if (files.length === 0) throw new Error(`no video for ${sceneName}`);
  const src = join(sceneDir, files[0]);
  const dst = join(OUT, `${sceneName}.webm`);
  renameSync(src, dst);
  rmSync(sceneDir, { recursive: true, force: true });
  console.log(`  ✓ Wrote ${dst}`);
}

async function showCard(page, html, holdMs) {
  const dataUrl = "data:text/html;base64," + Buffer.from(html).toString("base64");
  await page.goto(dataUrl, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(holdMs);
}

// Inject a subtle vignette + focus mask onto the SPA. This is what
// makes the console scenes feel cinematic instead of "here's a
// dashboard, good luck reading it".
async function applyFocusEffect(page, focusSelector, zoom = 1.05) {
  await page.addStyleTag({ content: `
    body { transition: transform 0.6s cubic-bezier(0.16,1,0.3,1); }
    body::after {
      content: "";
      position: fixed;
      inset: 0;
      pointer-events: none;
      background: radial-gradient(ellipse at center, transparent 0%, transparent 40%, rgba(6, 10, 16, 0.28) 90%);
      z-index: 999;
    }
  ` });
  if (focusSelector) {
    await page.evaluate(({ sel, zoom }) => {
      const el = document.querySelector(sel);
      if (!el) return;
      const rect = el.getBoundingClientRect();
      const cx = rect.left + rect.width / 2;
      const cy = rect.top + rect.height / 2;
      const vw = window.innerWidth;
      const vh = window.innerHeight;
      const dx = vw / 2 - cx;
      const dy = vh / 2 - cy;
      document.body.style.transformOrigin = `${cx}px ${cy}px`;
      document.body.style.transform = `translate(${dx * 0.35}px, ${dy * 0.35}px) scale(${zoom})`;
    }, { sel: focusSelector, zoom });
  }
}

const browser = await chromium.launch({ headless: true });

// ═════════════════════════════════════════════════════════════════
// SCENE 1 — Title card: "AI agents are making real decisions."
// ═════════════════════════════════════════════════════════════════
await recordScene(browser, "01-intro", 5500, async (page, ms) => {
  await showCard(page, cardHtml({
    bg: "#0a5c8b",
    kicker: "The problem",
    headline: `AI agents are making<br>real decisions&mdash;<br>with real money.`,
  }), ms);
});

// ═════════════════════════════════════════════════════════════════
// SCENE 2 — Problem card: "$8,400 problem"
// ═════════════════════════════════════════════════════════════════
await recordScene(browser, "02-problem", 5500, async (page, ms) => {
  await showCard(page, cardHtml({
    bg: "#08111a",
    kicker: "Today",
    headline: `An agent buys the wrong vendor.<br><span class="accent-red">$8,400</span> gone.<br>Nobody signed off.`,
    sub: "No audit trail. No accountability. No way to prove what happened.",
  }), ms);
});

// ═════════════════════════════════════════════════════════════════
// SCENE 3 — Solution promise card
// ═════════════════════════════════════════════════════════════════
await recordScene(browser, "03-solution", 4000, async (page, ms) => {
  await showCard(page, cardHtml({
    bg: "#0a5c8b",
    kicker: "AgentVisor AI",
    headline: `Every agent decision,<br>captured. Enforced.<br><span class="accent-yellow">Signed.</span>`,
  }), ms);
});

// ═════════════════════════════════════════════════════════════════
// SCENE 4 — Console overview with camera on the KPIs + activity chart
// ═════════════════════════════════════════════════════════════════
await recordScene(browser, "04-console", 7500, async (page, ms) => {
  await page.addInitScript(() => { try { localStorage.setItem("av_mock_signed_out", "1"); } catch {} });
  await page.goto(SITE + "#/login", { waitUntil: "networkidle" });
  await page.waitForSelector("input#email", { timeout: 15000 });
  await page.locator("input#email").fill("olivia.tan@northwind.com");
  await page.locator("input#password").fill("demo");
  await page.locator("button[type='submit']").first().click();
  await page.waitForTimeout(1500);
  await page.goto(SITE + "#/overview", { waitUntil: "networkidle" });
  await page.waitForTimeout(600);
  // Cinematic vignette focusing attention on the KPI row + chart
  await applyFocusEffect(page, null);
  await page.waitForTimeout(ms - 2100);
});

// ═════════════════════════════════════════════════════════════════
// SCENE 5 — Session detail: highlight the BLOCKED $8,400 + green
// signature-verified pill by zooming in slightly.
// ═════════════════════════════════════════════════════════════════
await recordScene(browser, "05-session", 8500, async (page, ms) => {
  await page.addInitScript(() => { try { localStorage.setItem("av_mock_signed_out", "1"); } catch {} });
  await page.goto(SITE + "#/login", { waitUntil: "networkidle" });
  await page.waitForSelector("input#email", { timeout: 15000 });
  await page.locator("input#email").fill("olivia.tan@northwind.com");
  await page.locator("input#password").fill("demo");
  await page.locator("button[type='submit']").first().click();
  await page.waitForTimeout(1200);
  await page.goto(SITE + "#/sessions/sess_01H9K", { waitUntil: "networkidle" });
  await page.waitForTimeout(600);
  await applyFocusEffect(page, null);
  await page.waitForTimeout(ms - 1800);
});

// ═════════════════════════════════════════════════════════════════
// SCENE 6 — Anyone can verify
// ═════════════════════════════════════════════════════════════════
await recordScene(browser, "06-verify", 7500, async (page, ms) => {
  await page.goto(LANDING + "/verify/", { waitUntil: "networkidle" });
  await page.waitForSelector("#loadExample", { timeout: 10000 });
  await page.waitForTimeout(1000);
  await page.locator("#loadExample").click();
  await page.waitForSelector(".result-card", { timeout: 8000 });
  await page.waitForTimeout(800);
  // Scroll so the green verify card is centered
  await page.evaluate(() => {
    const card = document.querySelector(".result-card");
    if (card) card.scrollIntoView({ behavior: "smooth", block: "center" });
  });
  await page.waitForTimeout(ms - 2800);
});

// ═════════════════════════════════════════════════════════════════
// SCENE 7 — Closing card
// ═════════════════════════════════════════════════════════════════
await recordScene(browser, "07-close", 4500, async (page, ms) => {
  await showCard(page, cardHtml({
    bg: "#0a5c8b",
    kicker: "AgentVisor AI",
    headline: `AI agents you can<br>hand to an <span class="accent-yellow">auditor</span>.`,
    sub: "agentvisorai.me",
  }), ms);
});

await browser.close();
console.log("\n✅ All scenes recorded.");
