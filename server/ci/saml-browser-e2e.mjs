// Exercise the shipped SPA and ApiDataSource in a real browser. Only the
// identity-provider discovery boundary is simulated; signed SAML callbacks
// and shared PostgreSQL state are covered by scripts/saml-shared-drill.mjs.
import assert from "node:assert/strict";
import http from "node:http";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as playwright from "playwright";

const docs = path.resolve(process.env.CONSOLE_DOCS_ROOT || fileURLToPath(new URL("../../docs/", import.meta.url)));
const browserName = process.env.BROWSER || "chromium";
assert.ok(["chromium", "firefox", "webkit"].includes(browserName));
let mode = "outage", origin, browser;
let checks = 0;
const requests = [];
const errors = [];
function check(label, condition) {
  if (!condition) errors.push(label);
  else checks++;
  console.log((condition ? "PASS " : "FAIL ") + label);
}
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, origin);
  function json(status, body) {
    res.writeHead(status, { "content-type": "application/json" });
    res.end(JSON.stringify(body));
  }
  if (url.pathname === "/api/v1/auth/me") return json(401, { error: "unauthorized" });
  if (url.pathname === "/api/v1/auth/oauth/providers") return json(200, { providers: [] });
  if (url.pathname === "/api/v1/auth/saml/discover") {
    requests.push(url.searchParams.get("email"));
    if (mode === "outage") return json(503, { error: "SSO discovery is temporarily unavailable. Try again." });
    return json(200, { ssoConfig: mode === "missing" ? null : {
      id: "fixture", displayName: "Fixture SSO", loginUrl: origin + "/api/v1/auth/saml/fixture/login",
    } });
  }
  if (url.pathname === "/api/v1/auth/saml/fixture/login") {
    res.writeHead(200, { "content-type": "text/html" });
    return res.end("<!doctype html><title>Fixture identity provider</title><p>Login request received</p>");
  }
  if (url.pathname === "/app/config.js") {
    res.writeHead(200, { "content-type": "application/javascript" });
    return res.end("window.MOCK_MODE = false; window.API_BASE = " + JSON.stringify(origin) + ";");
  }
  const relative = decodeURIComponent(url.pathname).replace(/^\/+/, "");
  const filename = path.resolve(docs, relative.endsWith("/") ? relative + "index.html" : relative);
  if (!filename.startsWith(docs + path.sep) && filename !== docs) { res.writeHead(403); return res.end(); }
  try {
    const body = await readFile(filename);
    const types = { ".html": "text/html", ".js": "application/javascript", ".css": "text/css", ".png": "image/png", ".svg": "image/svg+xml", ".ico": "image/x-icon" };
    res.writeHead(200, { "content-type": types[path.extname(filename)] || "application/octet-stream" });
    res.end(body);
  } catch { res.writeHead(404); res.end(); }
});
try {
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  origin = "http://127.0.0.1:" + server.address().port;
  browser = await playwright[browserName].launch();
  const page = await browser.newPage();
  page.setDefaultTimeout(10000);
  page.on("pageerror", error => errors.push(error.message));
  await page.goto(origin + "/app/#/login");
  await page.locator('[data-sso="saml"]').waitFor();
  check("SAML button offers sign-in without a sales placeholder", (await page.locator('[data-sso="saml"]').innerText()) === "Continue with SAML SSO");
  async function submit() {
    await page.locator('[data-sso="saml"]').click();
    await page.locator(".modal").getByLabel("Work email", { exact: true }).fill("person+browser@example.test");
    await page.locator("#inpForm button[type=submit]").click();
  }
  await submit();
  await page.locator(".toast").waitFor();
  const outage = await page.locator(".toast").last().innerText();
  check("Discovery outage is visible without claiming the workspace lacks SSO", /temporarily unavailable/i.test(outage) && !/No SSO configured/i.test(outage));
  mode = "missing";
  await submit();
  await page.getByText("No SSO configured for that domain. Ask your admin to add your IdP in Settings → SSO.", { exact: true }).waitFor();
  check("A successful empty discovery explains the missing workspace configuration", true);
  mode = "available";
  await page.evaluate(() => sessionStorage.setItem("av_return_to", "#/sessions?status=live"));
  await submit();
  await page.waitForURL(origin + "/api/v1/auth/saml/fixture/login?**");
  check("Retry after recovery navigates to the discovered login endpoint with its return path", new URL(page.url()).searchParams.get("RelayState") === "#/sessions?status=live");
  check("Discovery preserves the entered work email", requests.length === 3 && requests.every(email => email === "person+browser@example.test"));
  for (const slug of ["saml_request_unavailable", "saml_assertion_request_state_unavailable"]) {
    await page.goto(origin + "/app/#/login?err=" + slug);
    await page.locator(".auth-note").waitFor();
    check(slug + " tells the user to retry", (await page.locator(".auth-note").innerText()) === "SAML sign-in is temporarily unavailable. Please start sign-in again.");
  }
} finally {
  await browser?.close();
  server.closeAllConnections();
  await new Promise(resolve => server.close(resolve));
}
assert.deepEqual(errors, [], "SAML browser regressions");
console.log(`saml-browser-e2e: ${checks} checks passed (${browserName})`);
