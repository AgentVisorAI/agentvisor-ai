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
  // Split headline into <span class="line"> per <br>-separated line so
  // each one animates in on a stagger. Investors read the top line
  // first, then each subsequent line reveals with a small delay — the
  // eye's rhythm matches the text's rhythm.
  const lines = headline.split("<br>");
  const animatedHeadline = lines.map((line, i) =>
    `<span class="line" style="animation-delay: ${0.15 + i * 0.18}s">${line}</span>`
  ).join("");
  return `<!doctype html><html><head><meta charset="utf-8"><style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    html, body { width: 100%; height: 100%; overflow: hidden; background: ${bg}; color: #fff; font-family: -apple-system, BlinkMacSystemFont, "SF Pro Display", "Segoe UI", system-ui, sans-serif; -webkit-font-smoothing: antialiased; }
    .stage { width: 100vw; height: 100vh; display: flex; flex-direction: column; align-items: center; justify-content: center; text-align: center; padding: 4rem; }
    .kicker {
      font-size: 15px; font-weight: 600; letter-spacing: 0.35em;
      text-transform: uppercase; opacity: 0; color: #fff;
      margin-bottom: 2.5rem;
      transform: translateY(8px);
      animation: revealText 0.6s 0s cubic-bezier(0.16,1,0.3,1) forwards;
    }
    .kicker.dim { opacity: 0.6; }
    .headline {
      font-size: 92px; font-weight: 800; letter-spacing: -0.035em;
      line-height: 1.02; max-width: 1250px;
    }
    .headline .line {
      display: block; opacity: 0; transform: translateY(20px);
      animation: revealText 0.7s cubic-bezier(0.16, 1, 0.3, 1) forwards;
    }
    @keyframes revealText { to { opacity: 1; transform: translateY(0); } }
    .accent-red { color: #ff6a58; }
    .accent-yellow { color: #ffd54f; }
    .accent-green { color: #6ecf8e; }
    .subline {
      font-size: 26px; font-weight: 400; margin-top: 2rem;
      opacity: 0; max-width: 900px; line-height: 1.4;
      color: rgba(255, 255, 255, 0.85);
      transform: translateY(8px);
      animation: revealText 0.6s ${0.15 + lines.length * 0.18 + 0.15}s cubic-bezier(0.16,1,0.3,1) forwards;
    }
    .brand {
      position: absolute; bottom: 40px;
      display: flex; align-items: center; gap: 12px;
      font-size: 15px; opacity: 0.5; letter-spacing: 0.02em;
    }
    .brand-mark {
      width: 26px; height: 26px; background: #fff; color: #0a5c8b;
      border-radius: 6px; display: flex; align-items: center;
      justify-content: center; font-weight: 800; font-size: 15px;
    }
  </style></head><body>
    <div class="stage">
      ${kicker ? `<div class="kicker ${opts.dimKicker ? 'dim' : ''}">${kicker}</div>` : ""}
      <div class="headline">${animatedHeadline}</div>
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

/*
 * Two-phase console-scene helper.
 *
 * The Playwright recording starts the moment newContext(recordVideo)
 * fires. So any login+navigation+waitForSelector-for-data time gets
 * baked into the front of the clip as "loading spinner" footage.
 *
 * Fix: log in + navigate + wait for data in a SEPARATE preload
 * context whose recording is discarded. Then reopen a fresh context
 * with the same localStorage state, whose recording IS kept — that
 * one starts already on the target page with data ready.
 */
async function recordConsoleScene(browser, sceneName, durationMs, hash, waitFor, cinematicOpts) {
  console.log(`\n▶ Recording console scene "${sceneName}" (${durationMs}ms)…`);
  // ── Phase 1: warm up in an unrecorded context, capture its state ──
  const warmCtx = await browser.newContext({ viewport: { width: 1920, height: 1080 } });
  const warm = await warmCtx.newPage();
  await warm.addInitScript(() => { try { localStorage.setItem("av_mock_signed_out", "1"); } catch {} });
  await warm.goto(SITE + "#/login", { waitUntil: "networkidle" });
  await warm.waitForSelector("input#email", { timeout: 15000 });
  await warm.locator("input#email").fill("olivia.tan@northwind.com");
  await warm.locator("input#password").fill("demo");
  await warm.locator("button[type='submit']").first().click();
  await warm.waitForTimeout(1500);
  const storage = await warmCtx.storageState();
  await warmCtx.close();

  // ── Phase 2: fresh RECORDED context with the storage restored ─────
  const sceneDir = join(OUT, sceneName);
  mkdirSync(sceneDir, { recursive: true });
  const ctx = await browser.newContext({
    viewport: { width: 1920, height: 1080 },
    recordVideo: { dir: sceneDir, size: { width: 1920, height: 1080 } },
    deviceScaleFactor: 1,
    storageState: storage,
  });
  const page = await ctx.newPage();
  // Go directly to the target hash. Since the auth state is warmed,
  // no login round-trip is recorded.
  await page.goto(SITE + hash, { waitUntil: "networkidle" });
  // Belt-and-suspenders: wait for the specific selector(s) that prove
  // the data is rendered.
  for (const sel of waitFor) {
    await page.waitForSelector(sel, { timeout: 10000 });
  }
  // Tiny settle for CSS animations
  await page.waitForTimeout(200);
  // Apply cinematic layer (vignette + Ken Burns + optional pulse)
  await applyCinematic(page, {
    zoomMs: durationMs - 500,
    ...cinematicOpts,
  });
  // Hold for the remainder of the requested duration
  await page.waitForTimeout(durationMs - 500);
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

/*
 * Cinematic layer — added to every UI scene:
 *
 *   1. Radial vignette (dark corners, spotlight middle) drawing the
 *      eye to the center.
 *   2. Ken Burns slow zoom — the SPA <body> scales from 1.0 to 1.05
 *      over the scene duration. Camera moves = not a slideshow.
 *   3. Optional highlight-pulse on a target element (the $8,400, the
 *      Signature-verified pill, the green trusted-key card). A slow
 *      breathing glow that draws attention to what the caption
 *      references, without hijacking it.
 */
async function applyCinematic(page, opts = {}) {
  const zoomDuration = opts.zoomMs ?? 7000;
  const pulseSel = opts.pulseSelector ?? null;
  await page.addStyleTag({ content: `
    body { transition: none; will-change: transform; }
    body::after {
      content: "";
      position: fixed;
      inset: 0;
      pointer-events: none;
      background: radial-gradient(ellipse at center, transparent 0%, transparent 45%, rgba(6, 10, 16, 0.32) 92%);
      z-index: 999;
    }
    @keyframes kenburns {
      from { transform: scale(1); }
      to { transform: scale(1.055); }
    }
    body { animation: kenburns ${zoomDuration}ms cubic-bezier(0.16, 1, 0.3, 1) forwards; transform-origin: center center; }
    @keyframes pulse-glow {
      0%, 100% { box-shadow: 0 0 0 0 rgba(255, 213, 79, 0), 0 0 0 0 rgba(255, 213, 79, 0); }
      50% { box-shadow: 0 0 0 6px rgba(255, 213, 79, 0.55), 0 0 40px 8px rgba(255, 213, 79, 0.35); }
    }
    .av-pulse-target { animation: pulse-glow 1.6s ease-in-out 3 !important; border-radius: 8px; }
  ` });
  if (pulseSel) {
    // Give the zoom half a beat to breathe, then trigger the pulse
    setTimeout(async () => {
      try {
        await page.evaluate((sel) => {
          const el = document.querySelector(sel);
          if (el) el.classList.add("av-pulse-target");
        }, pulseSel);
      } catch {}
    }, 1000);
  }
}

const browser = await chromium.launch({ headless: true });

// ═════════════════════════════════════════════════════════════════
// SCENE 1 — Title card. No kicker; "The problem" is meta-commentary.
// Let the headline land alone. Two lines instead of three.
// ═════════════════════════════════════════════════════════════════
await recordScene(browser, "01-intro", 5500, async (page, ms) => {
  await showCard(page, cardHtml({
    bg: "#0a5c8b",
    headline: `AI agents make<br>real decisions<br>with real money.`,
  }), ms);
});

// ═════════════════════════════════════════════════════════════════
// SCENE 2 — Problem card. Tighter: two-line headline + subline.
// "One wrong decision" links back to scene 1's "AI agents make real
// decisions" — the payoff for that framing lands directly.
// ═════════════════════════════════════════════════════════════════
await recordScene(browser, "02-problem", 5500, async (page, ms) => {
  await showCard(page, cardHtml({
    bg: "#08111a",
    headline: `One wrong decision.<br><span class="accent-red">$8,400</span> gone.`,
    sub: "No audit trail. No accountability. No way to prove what happened.",
  }), ms);
});

// ═════════════════════════════════════════════════════════════════
// SCENE 3 — Solution promise. No kicker (persistent brand at bottom
// already says AgentVisor AI).
// ═════════════════════════════════════════════════════════════════
await recordScene(browser, "03-solution", 4000, async (page, ms) => {
  await showCard(page, cardHtml({
    bg: "#0a5c8b",
    headline: `Every decision:<br>captured. enforced.<br><span class="accent-yellow">signed.</span>`,
  }), ms);
});

// ═════════════════════════════════════════════════════════════════
// SCENE 4 — Console: pre-warm auth + wait for data, then record.
// ═════════════════════════════════════════════════════════════════
await recordConsoleScene(
  browser,
  "04-console",
  7500,
  "#/overview",
  ['text=PREVENTED LOSSES', 'text=$31,840', 'text=Recent sessions'],
  { /* no pulse — hero is the whole dashboard */ },
);

// ═════════════════════════════════════════════════════════════════
// SCENE 5 — Session detail: pre-warm + wait for data, pulse the
// $8,400 to close the callback from scene 2.
// ═════════════════════════════════════════════════════════════════
await recordConsoleScene(
  browser,
  "05-session",
  9000,
  "#/sessions/sess_01H9K",
  ['.session-summary', 'text=Signature verified'],
  { pulseSelector: ".session-summary > *:nth-child(5)" },
);

// ═════════════════════════════════════════════════════════════════
// SCENE 6 — Verify page: watch the "click sample → verify" happen
// LIVE. This is the "magic moment" — investors should see the click
// happen, not arrive at a pre-verified state.
//
// Tighter than v6: cursor pre-positioned near the sample link so the
// user's eye is already there when the click fires. Pre-click dwell
// down from 1.4s to 0.8s. Verified state now holds for ~5s (was ~3.5s).
// ═════════════════════════════════════════════════════════════════
await recordScene(browser, "06-verify", 8500, async (page, ms) => {
  await page.goto(LANDING + "/verify/", { waitUntil: "networkidle" });
  await page.waitForSelector("#loadExample", { timeout: 10000 });
  // Pre-position cursor near the target so the eye tracks to it during
  // the initial 0.8s dwell. Investor sees the cursor already hovering
  // over "Try it with a sample receipt" and knows what's about to
  // happen.
  const btn = page.locator("#loadExample");
  const box = await btn.boundingBox();
  if (box) {
    await page.mouse.move(box.x + box.width / 2 - 30, box.y - 8, { steps: 1 });
  }
  await page.waitForTimeout(700);
  // Small final micro-move for humanity, then click
  if (box) {
    await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2, { steps: 6 });
  }
  await page.waitForTimeout(120);
  await btn.click();
  await page.waitForSelector(".result-card", { timeout: 8000 });
  await page.waitForTimeout(350);
  // Smooth-scroll to center the verified card
  await page.evaluate(() => {
    const card = document.querySelector(".result-card");
    if (card) card.scrollIntoView({ behavior: "smooth", block: "center" });
  });
  await page.waitForTimeout(700);
  // Longer hold on the verified state — 4.5s of Ken Burns + pulse
  await applyCinematic(page, { zoomMs: 4500, pulseSelector: ".result-card" });
  await page.waitForTimeout(4500);
});

// ═════════════════════════════════════════════════════════════════
// SCENE 7 — Closing card. No kicker (redundant with brand bar).
// ═════════════════════════════════════════════════════════════════
await recordScene(browser, "07-close", 4500, async (page, ms) => {
  await showCard(page, cardHtml({
    bg: "#0a5c8b",
    headline: `AI agents you can<br>hand to an <span class="accent-yellow">auditor</span>.`,
    sub: "agentvisorai.me",
  }), ms);
});

await browser.close();
console.log("\n✅ All scenes recorded.");
