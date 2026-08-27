/*
 * Perfect investor mockup video — record every scene individually so
 * we can polish, retry, and iterate cheaply on any single clip.
 *
 * Output: /tmp/video-tour/scenes/<n>-<name>.webm
 *
 * ffmpeg then stitches with crossfades + captions.
 */
import { chromium } from "playwright";
import { writeFileSync, mkdirSync, rmSync, readdirSync, renameSync, existsSync } from "node:fs";
import { join } from "node:path";

const OUT = "/tmp/video-tour/scenes";
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
    permissions: ["clipboard-read", "clipboard-write"],
    deviceScaleFactor: 1,
    // Force dark mode so the app's dark-mode tokens (mint --success,
    // coral --danger) match the video's card palette. Without this,
    // the app renders in light mode with Tailwind red/green while the
    // cards use dark-mode mint/coral, and the two clash visually.
    colorScheme: "dark",
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
async function recordConsoleScene(browser, sceneName, durationMs, hash, waitFor, cinematicOpts, actions) {
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
    permissions: ["clipboard-read", "clipboard-write"],
    deviceScaleFactor: 1,
    storageState: storage,
    // Force dark mode so the app's dark-mode tokens (mint --success,
    // coral --danger) match the video's card palette. Prevents the
    // Tailwind-red/green vs mint/coral clash between UI and cards.
    colorScheme: "dark",
  });
  // First-user simulation clock: seed how far along the fresh
  // workspace is when this scene opens (see datasource FRESH_*).
  if (cinematicOpts && cinematicOpts.freshOffset != null) {
    await ctx.addInitScript((off) => {
      try { localStorage.setItem("av_mock_fresh_t0", String(Date.now() - off)); } catch {}
    }, cinematicOpts.freshOffset);
  }
  const page = await ctx.newPage();
  // Go directly to the target hash. Since the auth state is warmed,
  // no login round-trip is recorded.
  // domcontentloaded, not networkidle: the fresh-workspace mode keeps
  // a polling loop alive, so networkidle never fires and the recording
  // captures ~30s of idle wait. The waitFor selectors below guarantee
  // readiness.
  await page.goto(SITE + hash, { waitUntil: "domcontentloaded" });
  // Belt-and-suspenders: wait for the specific selector(s) that prove
  // the data is rendered.
  for (const sel of waitFor) {
    await page.waitForSelector(sel, { timeout: 10000 });
  }
  // Tiny settle for CSS animations
  await page.waitForTimeout(200);
  await injectCursor(page);
  // Apply cinematic layer (vignette + Ken Burns + optional pulse)
  await applyCinematic(page, {
    zoomMs: durationMs - 500,
    ...cinematicOpts,
  });
  const started = Date.now();
  // Optional scripted interactions (search typing, filter clicks,
  // event-drawer opens...). The actions own their internal waits;
  // whatever budget they don't use becomes the tail hold.
  if (actions) await actions(page);
  const remaining = durationMs - 500 - (Date.now() - started);
  if (remaining > 0) await page.waitForTimeout(remaining);
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

/**
 * Inject a visible cursor that follows Playwright's mouse. The OS
 * cursor is never captured by recordVideo, so we draw our own: an
 * arrow that tracks mousemove and pulses on mousedown / synthetic
 * clicks (av-click event).
 */
async function injectCursor(page) {
  await page.evaluate(() => {
    if (document.getElementById("av-cursor")) return;
    const c = document.createElement("div");
    c.id = "av-cursor";
    c.innerHTML = '<svg width="26" height="26" viewBox="0 0 24 24"><path d="M4 1.5 L4 19.5 L8.9 15 L12.2 21.6 L15.2 20.1 L11.9 13.6 L18.5 13.2 Z" fill="#ffffff" stroke="#10161d" stroke-width="1.5" stroke-linejoin="round"/></svg>';
    Object.assign(c.style, {
      position: "fixed", left: "0px", top: "0px", zIndex: "2147483647",
      pointerEvents: "none", opacity: "0",
      transition: "opacity 0.25s ease",
      filter: "drop-shadow(0 1px 3px rgba(0,0,0,0.55))",
    });
    document.documentElement.appendChild(c);
    const svg = c.firstChild;
    svg.style.transition = "transform 0.12s ease";
    svg.style.transformOrigin = "5px 3px";
    document.addEventListener("mousemove", (e) => {
      c.style.opacity = "1";
      c.style.left = e.clientX + "px";
      c.style.top = e.clientY + "px";
    }, true);
    const pulse = () => {
      svg.style.transform = "scale(0.75)";
      setTimeout(() => { svg.style.transform = "scale(1)"; }, 140);
    };
    document.addEventListener("mousedown", pulse, true);
    document.addEventListener("av-click", pulse, true);
  });
}

/** Synthetic click with a cursor pulse so the click reads on camera. */
async function cursorClick(page, selector) {
  await page.evaluate((sel) => {
    document.dispatchEvent(new CustomEvent("av-click"));
    const el = typeof sel === "string" ? document.querySelector(sel) : sel;
    if (el) el.click();
  }, selector);
}

async function applyCinematic(page, opts = {}) {
  const zoomDuration = opts.zoomMs ?? 7000;
  const pulseSel = opts.pulseSelector ?? null;
  const zoomToSel = opts.zoomToSelector ?? null;

  // If a zoom target is provided, resolve its viewport-relative center
  // and use a stronger zoom that ENDS focused on that target (money
  // shot). Otherwise fall back to the subtle center Ken Burns.
  let originX = opts.origin ? opts.origin.split(" ")[0] : "center";
  let originY = opts.origin ? opts.origin.split(" ")[1] : "center";
  let endScale = opts.static ? 1.0 : 1.055;
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
        // Percentage origins resolve against the FULL BODY height, not
        // the viewport, so on scrollable pages (the landing page) they
        // anchor thousands of px down and fake a scroll. Use px origins
        // in viewport coords (scrollY is 0 when we record), clamped so
        // edge labels never crop mid-word.
        const cx = Math.min(0.65 * rect.vw, Math.max(0.35 * rect.vw, rect.cx));
        const cy = Math.min(0.70 * rect.vh, Math.max(0.30 * rect.vh, rect.cy));
        originX = cx.toFixed(0) + "px";
        originY = cy.toFixed(0) + "px";
        endScale = 1.2;
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
// THE NOVICE TOUR (v20). A completely new user walks through every
// functionality: landing, signup, dashboard, sessions (search +
// filters), session detail (event inspection + receipt), download,
// public verify, policies, deployments, and settings. ~75s.
// ═════════════════════════════════════════════════════════════════

// ── SCENE 1: LANDING. First frame = thumbnail, must be legible. ───
await recordScene(browser, "01-landing", 5000, async (page, ms) => {
  await page.goto(LANDING + "/", { waitUntil: "networkidle" });
  await page.waitForSelector("h1", { timeout: 8000 });
  await page.waitForTimeout(200);
  await injectCursor(page);
  await applyCinematic(page, { zoomMs: ms - 500, zoomToSelector: ".cta.primary" });
  const cta = await page.locator(".cta.primary").boundingBox();
  if (cta) await page.mouse.move(cta.x + cta.width / 2, cta.y + cta.height / 2, { steps: 24 });
  await page.waitForTimeout(ms - 900);
});

// ── SCENE 2: SIGN UP. The novice creates a workspace, live. ──────
await recordScene(browser, "02-signup", 9000, async (page, ms) => {
  await page.addInitScript(() => {
    try { localStorage.setItem("av_mock_signed_out", "1"); } catch {}
  });
  await page.goto(SITE + "#/signup", { waitUntil: "networkidle" });
  await page.waitForSelector("input#orgName", { timeout: 10000 });
  await page.waitForTimeout(300);
  await injectCursor(page);
  const move = async (sel) => {
    const b = await page.locator(sel).boundingBox();
    if (b) await page.mouse.move(b.x + b.width / 2, b.y + b.height / 2, { steps: 12 });
  };
  await move("input#orgName");
  await page.locator("input#orgName").click();
  await page.locator("input#orgName").pressSequentially("Northwind Traders", { delay: 45 });
  await move("input#email");
  await page.locator("input#email").click();
  await page.locator("input#email").pressSequentially("olivia.tan@northwind.com", { delay: 40 });
  await move("input#password");
  await page.locator("input#password").click();
  await page.locator("input#password").pressSequentially("agents-you-trust", { delay: 30 });
  await page.waitForTimeout(300);
  await move("#authForm button[type='submit']");
  await page.waitForTimeout(250);
  await page.locator("#authForm button[type='submit']").click();
  // Land on the overview: EMPTY, because the workspace is brand new.
  await page.waitForTimeout(2600);
});

// ── SCENE 3: EMPTY WORKSPACE. Zero everything. Nothing to audit. ──
await recordConsoleScene(
  browser,
  "03-empty",
  6500,
  "#/overview",
  ['text=SESSIONS'],
  { freshOffset: 3000, static: true },
  async (page) => {
    await page.waitForTimeout(1200);
    // Sweep the zeroed stat tiles so the emptiness registers.
    const tiles = page.locator(".stat");
    const n = await tiles.count();
    for (const i of [0, 2, 4]) {
      if (i < n) {
        const b = await tiles.nth(i).boundingBox();
        if (b) await page.mouse.move(b.x + b.width / 2, b.y + b.height / 2, { steps: 14 });
        await page.waitForTimeout(500);
      }
    }
    // Head for Deployments — the onboarding path.
    const nav = page.locator('a[href="#/deployments"]');
    const nb = await nav.boundingBox();
    if (nb) await page.mouse.move(nb.x + nb.width / 2, nb.y + nb.height / 2, { steps: 14 });
    await page.waitForTimeout(300);
  },
);

// ── SCENE 4: CONNECT. Install command → the daemon connects. ─────
await recordConsoleScene(
  browser,
  "04-connect",
  10000,
  "#/deployments",
  ['text=Connect your first agent'],
  { freshOffset: 8000, static: true },
  async (page) => {
    await page.waitForTimeout(800);
    // Hover the install command like a user reading it.
    const cmd = page.locator("text=install.sh").first();
    const cb = await cmd.boundingBox().catch(() => null);
    if (cb) await page.mouse.move(cb.x + cb.width / 2, cb.y + cb.height / 2, { steps: 16 });
    await page.waitForTimeout(2600);
    // The daemon handshakes (elapsed passes FRESH_CONNECT_MS) —
    // re-render the route so the connected deployment appears.
    await page.evaluate(() => window.dispatchEvent(new HashChangeEvent("hashchange")));
    await page.waitForSelector("text=northwind-prod", { timeout: 4000 }).catch(() => {});
    const row = page.locator("text=northwind-prod").first();
    const rb = await row.boundingBox().catch(() => null);
    if (rb) await page.mouse.move(rb.x + rb.width / 2, rb.y + rb.height / 2, { steps: 14 });
    await page.waitForTimeout(600);
  },
);

// ── SCENE 5: FIRST DATA. Sessions stream in; the first $8,400 save.─
await recordConsoleScene(
  browser,
  "05-firstdata",
  10500,
  "#/overview",
  ['text=SESSIONS'],
  { freshOffset: 15200, pulseSelector: ".stat.savings", zoomMs: 10000 },
  async (page) => {
    await page.waitForTimeout(2300);
    // First session has arrived — refresh the view.
    await page.evaluate(() => window.dispatchEvent(new HashChangeEvent("hashchange")));
    await page.waitForTimeout(3400);
    // Second refresh: the featured blocked session lands, $8,400 appears.
    await page.evaluate(() => window.dispatchEvent(new HashChangeEvent("hashchange")));
    await page.waitForTimeout(1600);
    const tile = page.locator(".stat.savings");
    const tb = await tile.boundingBox().catch(() => null);
    if (tb) await page.mouse.move(tb.x + tb.width / 2, tb.y + tb.height / 2, { steps: 16 });
  },
);

// ── SCENE 6: SESSIONS. Isolate the blocked one. ──────────────────
await recordConsoleScene(
  browser,
  "06-sessions",
  7000,
  "#/sessions",
  ['tr[data-clickable]'],
  { freshOffset: 300000, origin: "0px 540px" },
  async (page) => {
    await page.waitForTimeout(1400);
    const toggle = page.locator('input[type="checkbox"]').first();
    const tb = await toggle.boundingBox();
    if (tb) await page.mouse.move(tb.x + 4, tb.y + 4, { steps: 14 });
    await page.waitForTimeout(300);
    await page.evaluate(() => {
      document.dispatchEvent(new CustomEvent("av-click"));
      const cb = document.querySelector('input[type="checkbox"]');
      if (cb && !cb.checked) cb.click();
    });
    await page.waitForTimeout(1400);
    const row = page.locator("tr[data-clickable]").first();
    const rb = await row.boundingBox();
    if (rb) await page.mouse.move(rb.x + rb.width / 3, rb.y + rb.height / 2, { steps: 14 });
  },
);

// ── SCENE 7: SESSION DETAIL. Pulse $8,400, open the BLOCKED event.─
await recordConsoleScene(
  browser,
  "07-session",
  10000,
  "#/sessions/sess_01H9K",
  ['.session-summary', 'text=Signature verified', '.evt'],
  { pulseSelector: ".session-summary > *:nth-child(5)", zoomMs: 9500, origin: "0px 540px", freshOffset: 300000 },
  async (page) => {
    await page.waitForTimeout(2600);
    const blocked = page.locator(".evt", { hasText: "BLOCKED" }).first();
    const bb = await blocked.boundingBox();
    if (bb) await page.mouse.move(bb.x + bb.width / 2, bb.y + bb.height / 2, { steps: 14 });
    await page.waitForTimeout(250);
    await page.evaluate(() => {
      document.dispatchEvent(new CustomEvent("av-click"));
      const ev = Array.from(document.querySelectorAll(".evt")).find(e => /BLOCKED/.test(e.textContent));
      if (ev) ev.click();
    });
    await page.waitForTimeout(600);
  },
);

// ── SCENE 8: SHARE + COPY. The receipt is portable in one click. ──
await recordConsoleScene(
  browser,
  "08-share",
  6500,
  "#/sessions/sess_01H9K",
  ['#shareRcpt', '#copyRcpt'],
  { static: true, freshOffset: 300000 },
  async (page) => {
    await page.waitForTimeout(1000);
    const share = page.locator("#shareRcpt");
    const sb = await share.boundingBox();
    if (sb) await page.mouse.move(sb.x + sb.width / 2, sb.y + sb.height / 2, { steps: 12 });
    await page.waitForTimeout(300);
    await cursorClick(page, "#shareRcpt");
    await page.waitForTimeout(1900);
    const copy = page.locator("#copyRcpt");
    const cb = await copy.boundingBox();
    if (cb) await page.mouse.move(cb.x + cb.width / 2, cb.y + cb.height / 2, { steps: 10 });
    await page.waitForTimeout(250);
    await cursorClick(page, "#copyRcpt");
    await page.waitForTimeout(1600);
  },
);

// ── SCENE 9: DOWNLOAD RECEIPT. Pulse + click. ────────────────────
await recordConsoleScene(
  browser,
  "09-download",
  3200,
  "#/sessions/sess_01H9K",
  ['#dlRcpt'],
  { pulseSelector: "#dlRcpt", zoomMs: 2500, static: true, freshOffset: 300000 },
  async (page) => {
    const btn = page.locator("#dlRcpt");
    const bb = await btn.boundingBox();
    if (bb) await page.mouse.move(bb.x + bb.width / 2, bb.y + bb.height / 2, { steps: 12 });
    await page.waitForTimeout(900);
    await cursorClick(page, "#dlRcpt");
  },
);

// ── SCENE 10: VERIFY. Drop the receipt, green tick, no account. ───
await recordScene(browser, "10-verify", 7000, async (page, ms) => {
  await page.goto(LANDING + "/verify/", { waitUntil: "networkidle" });
  await page.waitForSelector("#loadExample", { timeout: 10000 });
  await injectCursor(page);
  const btn = page.locator("#loadExample");
  const box = await btn.boundingBox();
  if (box) {
    await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2, { steps: 12 });
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
  await applyCinematic(page, { zoomMs: 4300, pulseSelector: ".result-card" });
  await page.waitForTimeout(4300);
});

// ── SCENE 11: POLICIES. Starter rules, readable, enforced. ───────
await recordConsoleScene(
  browser,
  "11-policies",
  8000,
  "#/policies",
  ['tr[data-clickable]'],
  { origin: "0px 540px", freshOffset: 300000 },
  async (page) => {
    await page.waitForTimeout(1400);
    const row = page.locator("tr[data-clickable]").first();
    const rb = await row.boundingBox();
    if (rb) await page.mouse.move(rb.x + rb.width / 3, rb.y + rb.height / 2, { steps: 14 });
    await page.waitForTimeout(300);
    await cursorClick(page, "tr[data-clickable]");
    await page.waitForSelector(".policy-body", { timeout: 8000 }).catch(() => {});
    await page.waitForTimeout(400);
  },
);

// ── SCENE 12: COMMAND PALETTE + THEME. Keyboard-first console. ────
await recordConsoleScene(
  browser,
  "12-palette",
  7000,
  "#/overview",
  ['#cmdkOpen'],
  { freshOffset: 300000 },
  async (page) => {
    await page.waitForTimeout(800);
    const trigger = page.locator("#cmdkOpen");
    const tb = await trigger.boundingBox();
    if (tb) await page.mouse.move(tb.x + tb.width / 2, tb.y + tb.height / 2, { steps: 12 });
    await page.waitForTimeout(250);
    await cursorClick(page, "#cmdkOpen");
    await page.waitForTimeout(600);
    await page.keyboard.type("sess", { delay: 110 });
    await page.waitForTimeout(1400);
    await page.keyboard.press("Escape");
    await page.waitForTimeout(400);
    await cursorClick(page, "#themeBtn");
    await page.waitForTimeout(1700);
    await cursorClick(page, "#themeBtn");
    await page.waitForTimeout(600);
  },
);

// ── SCENE 13: DEPLOYMENT DETAIL. Keys and tokens, rotatable. ─────
await recordConsoleScene(
  browser,
  "13-deployments",
  6500,
  "#/deployments",
  ['tr[data-clickable]'],
  { origin: "0px 540px", freshOffset: 300000 },
  async (page) => {
    await page.waitForTimeout(1300);
    const row = page.locator("tr[data-clickable]").first();
    const rb = await row.boundingBox();
    if (rb) await page.mouse.move(rb.x + rb.width / 3, rb.y + rb.height / 2, { steps: 14 });
    await page.waitForTimeout(250);
    await cursorClick(page, "tr[data-clickable]");
    await page.waitForTimeout(500);
  },
);

// ── SCENE 14: SETTINGS. Self-serve workspace, tab by tab. ────────
await recordConsoleScene(
  browser,
  "14-settings",
  16000,
  "#/settings/members",
  ['.settings-nav'],
  { origin: "0px 540px", freshOffset: 300000 },
  async (page) => {
    await page.waitForTimeout(2300);
    for (const tab of ["API keys", "SSO", "Webhooks", "Audit log", "Billing"]) {
      const b = page.locator(`.settings-nav button:has-text("${tab}")`);
      const bb = await b.boundingBox();
      if (bb) await page.mouse.move(bb.x + bb.width / 2, bb.y + bb.height / 2, { steps: 10 });
      await page.waitForTimeout(250);
      await page.evaluate((label) => {
        document.dispatchEvent(new CustomEvent("av-click"));
        const btn = Array.from(document.querySelectorAll(".settings-nav button")).find(x => x.textContent.trim() === label);
        if (btn) btn.click();
      }, tab);
      await page.waitForTimeout(2300);
    }
  },
);

// ── SCENE 15: CLOSE. CTA card. ───────────────────────────────────
await recordScene(browser, "15-close", 5500, async (page, ms) => {
  await showCard(page, cardHtml({
    bg: "#0a5c8b",
    headline: `AI agents you can<br>hand to an <span class="accent-yellow">auditor</span>.`,
    cta: "agentvisorai.me",
  }), ms);
});

await browser.close();
console.log("\n✅ All scenes recorded.");
