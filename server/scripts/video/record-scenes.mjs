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
  //
  // When `staticHeadline: true`, the reveal is baked in — text is at
  // its final position from frame 1. Used on scene 1 (the intro card)
  // because its first frame is the thumbnail everyone sees when the
  // URL is shared. A blank fade-in makes for a terrible thumbnail.
  const lines = headline.split("<br>");
  const staticHead = opts.staticHeadline === true;
  const animatedHeadline = lines.map((line, i) =>
    staticHead
      ? `<span class="line static">${line}</span>`
      : `<span class="line" style="animation-delay: ${0.15 + i * 0.18}s">${line}</span>`
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
    /* Static variant used on scene 1 so the first frame is
     * already the fully-composed poster (used as the thumbnail
     * everywhere the URL is shared). */
    .headline .line.static {
      opacity: 1; transform: none; animation: none;
    }
    @keyframes revealText { to { opacity: 1; transform: translateY(0); } }
    /* Palette aligned to the site's design tokens (dark-mode variants,
     * since the cards sit on the site's --accent navy background).
     *
     *   --accent  #0a5c8b  navy card background
     *   --danger  #e07b60  coral for the problem $8,400
     *   --success #6ecf8e  green for the "auditor" callback + CTA
     */
    .accent-red    { color: #e07b60; }
    .accent-green  { color: #6ecf8e; }
    .accent-yellow { color: #6ecf8e; }
    .subline {
      font-size: 26px; font-weight: 400; margin-top: 2rem;
      opacity: 0; max-width: 900px; line-height: 1.4;
      color: rgba(255, 255, 255, 0.85);
      transform: translateY(8px);
      animation: revealText 0.6s ${0.15 + lines.length * 0.18 + 0.15}s cubic-bezier(0.16,1,0.3,1) forwards;
    }
    /* Big CTA URL for the closing card. Business-card treatment.
     * Uses site --success green so the eye reads "proof / verified".
     */
    .cta {
      display: inline-flex; align-items: center; gap: 18px;
      margin-top: 3rem; padding: 18px 34px;
      font-size: 44px; font-weight: 700; letter-spacing: -0.01em;
      color: #6ecf8e;
      border: 2px solid rgba(110, 207, 142, 0.40);
      border-radius: 999px;
      background: rgba(110, 207, 142, 0.06);
      opacity: 0; transform: translateY(10px);
      animation: revealText 0.7s ${0.15 + lines.length * 0.18 + 0.3}s cubic-bezier(0.16,1,0.3,1) forwards;
    }
    .cta .arrow {
      display: inline-block; transition: transform 200ms ease-out;
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
      ${opts.cta ? `<div class="cta"><span class="arrow">→</span> ${opts.cta}</div>` : ""}
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
  const zoomToSel = opts.zoomToSelector ?? null;

  // If a zoom target is provided, resolve its viewport-relative center
  // and use a stronger zoom that ENDS focused on that target (money
  // shot). Otherwise fall back to the subtle center Ken Burns.
  let originX = "center";
  let originY = "center";
  let endScale = 1.055;
  if (zoomToSel) {
    try {
      const rect = await page.evaluate((sel) => {
        const el = document.querySelector(sel);
        if (!el) return null;
        const r = el.getBoundingClientRect();
        return {
          cx: r.left + r.width / 2,
          cy: r.top + r.height / 2,
          vw: window.innerWidth,
          vh: window.innerHeight,
        };
      }, zoomToSel);
      if (rect) {
        originX = ((rect.cx / rect.vw) * 100).toFixed(2) + "%";
        originY = ((rect.cy / rect.vh) * 100).toFixed(2) + "%";
        endScale = 1.35;
      }
    } catch {}
  }

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
      to { transform: scale(${endScale}); }
    }
    body { animation: kenburns ${zoomDuration}ms cubic-bezier(0.16, 1, 0.3, 1) forwards; transform-origin: ${originX} ${originY}; }
    @keyframes pulse-glow {
      0%, 100% { box-shadow: 0 0 0 0 rgba(110, 207, 142, 0), 0 0 0 0 rgba(110, 207, 142, 0); }
      50%      { box-shadow: 0 0 0 6px rgba(110, 207, 142, 0.55), 0 0 40px 8px rgba(110, 207, 142, 0.35); }
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
// SCENE 1 — PROBLEM HOOK. Prove we understand what's at stake.
// First frame of the whole video is this card (= thumbnail).
// ═════════════════════════════════════════════════════════════════
await recordScene(browser, "01-problem", 4000, async (page, ms) => {
  await showCard(page, cardHtml({
    bg: "#0a5c8b",
    headline: `One wrong decision.<br><span class="accent-red">$8,400</span> gone.`,
    sub: "No audit trail. No accountability. No way to prove what happened.",
    staticHeadline: true,
  }), ms);
});

// ═════════════════════════════════════════════════════════════════
// SCENE 2 — SIGN IN (fast). Show the login page + cursor moving to
// the Sign in button + click. No typing. Non-technical investors
// don't need to see 6s of typing to understand "user logs in".
// ═════════════════════════════════════════════════════════════════
await recordScene(browser, "02-signin", 3000, async (page, ms) => {
  await page.addInitScript(() => {
    try { localStorage.setItem("av_mock_signed_out", "1"); } catch {}
  });
  await page.goto(SITE + "#/login", { waitUntil: "networkidle" });
  await page.waitForSelector("input#email", { timeout: 10000 });
  // Pre-fill fields quickly (no on-screen typing) so the Sign in
  // click has visible credentials next to it.
  await page.locator("input#email").fill("alex@acme.co");
  await page.locator("input#password").fill("demo");
  await page.waitForTimeout(600);
  // Move cursor to Sign in button, hold, click.
  const btn = page.locator("button[type='submit']").first();
  const btnBox = await btn.boundingBox();
  if (btnBox) {
    await page.mouse.move(btnBox.x + btnBox.width / 2, btnBox.y + btnBox.height / 2, { steps: 20 });
  }
  await page.waitForTimeout(500);
  await btn.click();
  await page.waitForTimeout(Math.max(0, ms - 1500));
});

// ═════════════════════════════════════════════════════════════════
// SCENE 3 — OVERVIEW. Dashboard first-load. Wide-establishing shot
// → zoom lands on "$31,840 Prevented losses" tile. This is the
// "money shot" and it MUST land in the 30-second window.
// ═════════════════════════════════════════════════════════════════
await recordConsoleScene(
  browser,
  "03-overview",
  6000,
  "#/overview",
  ['text=PREVENTED LOSSES', 'text=$31,840', 'text=Recent sessions'],
  { zoomToSelector: ".stat.savings" },
);

// ═════════════════════════════════════════════════════════════════
// SCENE 4 — SESSION DETAIL. Drill straight into the blocked $8,400
// session (skip the sessions-list detour — the overview already
// shows recent sessions with blocked pills). Pulse on $8,400 tile.
// ═════════════════════════════════════════════════════════════════
await recordConsoleScene(
  browser,
  "04-session",
  7000,
  "#/sessions/sess_01H9K",
  ['.session-summary', 'text=Signature verified'],
  { pulseSelector: ".session-summary > *:nth-child(5)" },
);

// ═════════════════════════════════════════════════════════════════
// SCENE 5 — DOWNLOAD RECEIPT. Pulse-glow on Download receipt
// button + implicit click. Short scene — 2.5s is enough.
// ═════════════════════════════════════════════════════════════════
await recordConsoleScene(
  browser,
  "05-download",
  2500,
  "#/sessions/sess_01H9K",
  ['#dlRcpt'],
  { pulseSelector: "#dlRcpt" },
);

// ═════════════════════════════════════════════════════════════════
// SCENE 6 — VERIFY (tighter than v16). Drop → green tick within
// the 30-second understanding window.
// ═════════════════════════════════════════════════════════════════
await recordScene(browser, "06-verify", 6500, async (page, ms) => {
  await page.goto(LANDING + "/verify/", { waitUntil: "networkidle" });
  await page.waitForSelector("#loadExample", { timeout: 10000 });
  const btn = page.locator("#loadExample");
  const box = await btn.boundingBox();
  if (box) {
    await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2, { steps: 10 });
  }
  await page.waitForTimeout(400);
  await btn.click();
  await page.waitForSelector(".result-card", { timeout: 8000 });
  await page.waitForTimeout(250);
  await page.evaluate(() => {
    const card = document.querySelector(".result-card");
    if (card) card.scrollIntoView({ behavior: "smooth", block: "center" });
  });
  await page.waitForTimeout(500);
  await applyCinematic(page, { zoomMs: 3800, pulseSelector: ".result-card" });
  await page.waitForTimeout(3800);
});

// ═════════════════════════════════════════════════════════════════
// SCENE 7 — CLOSE. CTA card + agentvisorai.me pill.
// ═════════════════════════════════════════════════════════════════
await recordScene(browser, "07-close", 5500, async (page, ms) => {
  await showCard(page, cardHtml({
    bg: "#0a5c8b",
    headline: `AI agents you can<br>hand to an <span class="accent-yellow">auditor</span>.`,
    cta: "agentvisorai.me",
  }), ms);
});

await browser.close();
console.log("\n✅ All scenes recorded.");
