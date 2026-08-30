// Browser-truth E2E (R284): drives the REAL SPA in a REAL browser
// against the REAL API. ci/e2e.mjs exercises the ApiDataSource adapter
// via Node fetch, which can never catch what only a browser enforces:
// the meta CSP (connect-src blocked the API host in local api-mode
// until R284), cookie credential flow, CORS + X-Requested-With, and
// what error copy actually lands in a toast a human reads.
//
// Env: SPA_ORIGIN (patched console copy), API_BASE (running server).
// The runner (console-api.yml) prepares the copy: MOCK_MODE=false,
// API_BASE set, and the CSP connect-src widened to the local API —
// exactly the edits a self-hoster makes per server/README.md.
import { chromium } from "playwright";

const SPA = process.env.SPA_ORIGIN || "http://127.0.0.1:8787";
const API = process.env.API_BASE || "http://127.0.0.1:8985";

let fails = 0;
const ok = (label, cond, extra = "") => {
  console.log((cond ? "PASS " : "FAIL ") + label + (extra ? ": " + extra : ""));
  if (!cond) fails += 1;
};

const browser = await chromium.launch();
const ctx = await browser.newContext();
const page = await ctx.newPage();
const consoleErrors = [];
page.on("console", (m) => {
  if (m.type() !== "error") return;
  const t = m.text();
  // Expected noise: the boot-time /auth/me 401 probe (not signed in
  // yet) and the DELIBERATE duplicate-name 409 this test triggers.
  // Chromium logs a resource-level error line for any 4xx fetch; the
  // app handles both. Anything else (404 assets, 5xx, JS exceptions)
  // fails the run.
  if (t.includes("status of 401") || t.includes("status of 409")) return;
  consoleErrors.push(t.slice(0, 160));
});

// 1. Signup through the real form.
const email = `browser-${Date.now()}@apexrobotics.test`;
await page.goto(SPA + "/#/signup", { waitUntil: "networkidle" });
await page.waitForSelector("#orgName", { timeout: 15000 });
await page.fill("#orgName", "Browser Truth Org");
await page.fill("#email", email);
await page.fill("#password", "correct-horse-battery-staple-9");
await page.click('button[type="submit"]');
await page.waitForSelector(".app-shell", { timeout: 15000 });
ok("signup lands in the app shell", true);

// 2. Create a deployment; the ingest token must be revealed once.
await page.goto(SPA + "/#/deployments", { waitUntil: "networkidle" });
await page.click('button:has-text("New deployment")');
await page.waitForSelector("#depName");
await page.fill("#depName", "browser-prod");
await page.click('.modal button[type="submit"], .modal .btn-primary');
await page.waitForTimeout(1500);
const tokenModal = await page
  .$eval(".modal", (el) => el.innerText)
  .catch(() => "");
ok(
  "ingest token revealed once",
  /av_ingest_|ingest token/i.test(tokenModal),
  tokenModal.slice(0, 60).replace(/\n/g, " ")
);
await page.keyboard.press("Escape");
await page.waitForTimeout(400);

// 3. Duplicate name -> the toast must read like a sentence, not a slug.
await page.click('button:has-text("New deployment")');
await page.waitForSelector("#depName");
await page.fill("#depName", "browser-prod");
await page.click('.modal button[type="submit"], .modal .btn-primary');
await page.waitForTimeout(1200);
const toast = await page
  .$eval(".toast, [role=status], [role=alert]", (el) => el.innerText)
  .catch(() => "");
ok(
  "duplicate-name toast is human copy",
  toast.length > 0 && !toast.includes("_"),
  JSON.stringify(toast)
);
await page.keyboard.press("Escape");

// 4. API key create: reveal-once with the real prefix.
await page.goto(SPA + "/#/settings/keys", { waitUntil: "networkidle" });
await page.click(
  'button:has-text("New key"), button:has-text("Create key"), button:has-text("New API key")'
);
await page.waitForSelector("#inpVal");
await page.fill("#inpVal", "browser-ci");
await page.click('.modal button:has-text("Create")');
await page.waitForTimeout(1500);
const keyModal = await page.$eval(".modal", (el) => el.innerText).catch(() => "");
ok("api key revealed once", keyModal.includes("av_srv_"), keyModal.slice(0, 40));
await page.keyboard.press("Escape");

// 5. Audit log recorded the browser's actions.
await page.goto(SPA + "/#/settings/audit", { waitUntil: "networkidle" });
await page.waitForTimeout(1000);
const audit = ((await page.textContent("body")) || "").replace(/\s+/g, " ");
for (const slug of ["org.created", "deployment.create", "apikey.create"])
  ok("audit shows " + slug, audit.includes(slug));

// 6. Sign out (confirm modal) and back in.
await page.click('.app-shell button:has-text("' + email + '")');
await page.click("text=Sign out");
await page.waitForTimeout(500);
await page.click('.modal button:has-text("Sign out")');
await page.waitForSelector("#email", { timeout: 10000 });
ok("signout returns to login", page.url().includes("login"));
await page.fill("#email", email);
await page.fill("#password", "correct-horse-battery-staple-9");
await page.click('button[type="submit"]');
await page.waitForSelector(".app-shell", { timeout: 15000 });
ok("re-login restores the shell", true);

ok("no unexpected console errors", consoleErrors.length === 0, consoleErrors.join(" | "));

await browser.close();
if (fails) {
  console.error(`browser-e2e: ${fails} failure(s)`);
  process.exit(1);
}
console.log("browser-e2e: all checks passed");
