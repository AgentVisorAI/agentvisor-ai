// Test the shipped adapter, including visible audit pagination in the real SPA.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";
import test from "node:test";
import * as playwright from "playwright";

const docs = path.resolve(process.env.CONSOLE_DOCS_ROOT || fileURLToPath(new URL("../../docs/", import.meta.url)));
const source = await readFile(path.join(docs, "app/datasource.js"), "utf8");
const browserName = process.env.BROWSER || "chromium";
assert.ok(["chromium", "firefox", "webkit"].includes(browserName), "supported browser engine");

function fixture(status = 503, body = '{"detail":"Audit temporarily unavailable"}') {
  let clock = 1000, nextId = 1;
  const timeouts = new Map(), intervals = new Map(), instances = [], events = [];
  class TestDate extends Date { static now() { return clock; } }
  class EventSource {
    constructor(url, options) {
      this.url = url; this.options = options; this.readyState = 0;
      this.listeners = {}; this.closed = false; instances.push(this);
    }
    addEventListener(type, callback) { (this.listeners[type] ??= []).push(callback); }
    emit(type, data) { for (const callback of this.listeners[type] || []) callback(data || {}); }
    close() { this.closed = true; this.readyState = 2; }
  }
  const context = vm.createContext({
    window: { MOCK_MODE: false, API_BASE: "http://fixture.invalid", dispatchEvent: event => events.push(event.type) },
    fetch: async () => ({ ok: status < 400, status, headers: { get: name => name === "retry-after" ? "7" : null }, text: async () => body }),
    CustomEvent: class { constructor(type) { this.type = type; } },
    EventSource, Date: TestDate, console, URL, URLSearchParams, TextEncoder, TextDecoder, btoa, atob,
    setTimeout: (fn, delay) => { const id = nextId++; timeouts.set(id, { fn, delay }); return id; },
    clearTimeout: id => timeouts.delete(id),
    setInterval: (fn, delay) => { const id = nextId++; intervals.set(id, { fn, delay }); return id; },
    clearInterval: id => intervals.delete(id),
  });
  vm.runInContext(source, context, { filename: "datasource.js" });
  return {
    ds: context.window.dataSource, events, instances, timeouts, intervals,
    setTime: value => { clock = value; },
    flushTimeouts() { for (const [id, { fn }] of [...timeouts]) { timeouts.delete(id); fn(); } },
  };
}

test("audit errors preserve HTTP status instead of returning end of history", async () => {
  const { ds } = fixture();
  await assert.rejects(ds.listAudit({ cursor: "older-page" }), error => error.status === 503 && /temporarily unavailable/.test(error.message));
});

test("non-object JSON error bodies preserve authentication and rate-limit handling", async () => {
  for (const body of ["null", "false", "17", '"proxy error"', "[]", "<html>proxy error</html>"]) {
    const unauthenticated = fixture(401, body);
    await assert.rejects(unauthenticated.ds.listPolicies(), error => error.status === 401 && error.message === "http_401");
    assert.deepEqual(unauthenticated.events, ["av-session-expired"]);
    const limited = fixture(429, body);
    await assert.rejects(limited.ds.listPolicies(), error => error.status === 429 && error.retryAfterSec === 7);
  }
  const invalidPassword = fixture(401, '{"error":"invalid_password"}');
  await assert.rejects(invalidPassword.ds.listPolicies(), error => error.status === 401);
  assert.deepEqual(invalidPassword.events, [], "body-credential refusal must preserve the browser session");
});

test("terminal error and stale watchdog schedule one stream and unsubscribe closes it", () => {
  const f = fixture(), received = [];
  const unsubscribe = f.ds.subscribe(event => received.push(event));
  const first = f.instances[0];
  first.readyState = 1; first.emit("open");
  f.setTime(32001); first.readyState = 2; first.emit("error");
  for (const { fn } of f.intervals.values()) fn();
  first.emit("error");
  assert.equal(f.timeouts.size, 1);
  f.flushTimeouts();
  assert.equal(f.instances.length, 2);
  assert.equal(f.instances.filter(instance => !instance.closed).length, 1);
  const before = received.length;
  first.emit("open"); first.emit("session.upsert", { data: '{"sessionId":"retired"}' }); first.emit("error");
  assert.equal(received.length, before, "retired sources cannot change the current stream state");
  assert.equal(f.timeouts.size, 0);
  unsubscribe();
  assert.equal(f.instances.filter(instance => !instance.closed).length, 0);
  assert.equal(f.intervals.size, 0);
});

test("unsubscribe cancels a pending reconnect and native reconnect retains a single source", () => {
  const f = fixture();
  const unsubscribe = f.ds.subscribe(() => {});
  const first = f.instances[0];
  first.readyState = 1; first.emit("open");
  first.readyState = 0; first.emit("error");
  assert.equal(f.timeouts.size, 0, "an opened EventSource may reconnect itself");
  first.readyState = 2; first.emit("error");
  assert.equal(f.timeouts.size, 1);
  unsubscribe();
  assert.equal(f.timeouts.size, 0);
  f.flushTimeouts();
  assert.equal(f.instances.length, 1);
  assert.equal(first.closed, true);
});

test(`real audit page retains its rows and retry button during an outage (${browserName})`, { timeout: 30000 }, async () => {
  let origin, browser, initialOutage = true, olderAttempts = 0;
  const cursors = [], pageErrors = [];
  const entry = (event, actor) => ({ at: "2026-09-24T12:00:00Z", actor, event, target: "Fixture", note: "" });
  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, origin);
    const json = (status, body) => { res.writeHead(status, { "content-type": "application/json" }); res.end(JSON.stringify(body)); };
    if (url.pathname === "/api/v1/auth/me") return json(200, {
      user: { id: "fixture-user", email: "owner@example.test", displayName: "Owner" },
      org: { id: "fixture-org", name: "Fixture", slug: "fixture", role: "owner" }, memberships: [],
    });
    if (url.pathname === "/api/v1/stream") { res.writeHead(204); return res.end(); }
    if (url.pathname === "/api/v1/audit") {
      if (initialOutage) return json(503, { detail: "Audit temporarily unavailable" });
      const cursor = url.searchParams.get("cursor");
      if (!cursor) return json(200, { entries: [entry("auth.login", "newest@example.test")], nextCursor: "older-page" });
      cursors.push(cursor);
      if (++olderAttempts === 1) return json(503, { detail: "Older audit entries temporarily unavailable" });
      return json(200, { entries: [entry("auth.logout", "older@example.test")], nextCursor: null });
    }
    if (url.pathname.startsWith("/api/")) return json(200, { deployments: [], providers: [] });
    if (url.pathname === "/app/config.js") {
      res.writeHead(200, { "content-type": "application/javascript" });
      return res.end("window.MOCK_MODE=false;window.API_BASE=" + JSON.stringify(origin) + ";");
    }
    const relative = decodeURIComponent(url.pathname).replace(/^\/+/, "");
    const filename = path.resolve(docs, relative.endsWith("/") ? relative + "index.html" : relative);
    if (!filename.startsWith(docs + path.sep)) { res.writeHead(403); return res.end(); }
    try {
      const body = await readFile(filename);
      const types = { ".html": "text/html", ".js": "application/javascript", ".css": "text/css", ".svg": "image/svg+xml" };
      res.writeHead(200, { "content-type": types[path.extname(filename)] || "application/octet-stream" }); res.end(body);
    } catch { res.writeHead(404); res.end(); }
  });
  try {
    await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
    origin = "http://127.0.0.1:" + server.address().port;
    browser = await playwright[browserName].launch();
    const page = await browser.newPage();
    page.setDefaultTimeout(5000);
    page.on("pageerror", error => pageErrors.push(error.message));
    await page.goto(origin + "/app/#/settings/audit");
    await page.getByText("Could not load the audit log", { exact: true }).waitFor();
    assert.equal(await page.getByText("No audit entries yet", { exact: true }).count(), 0);
    initialOutage = false;
    await page.reload();
    await page.locator("#auditBody").getByText("newest@example.test", { exact: true }).waitFor();
    await page.locator("#auditMoreBtn").click();
    await page.getByText("Older audit entries temporarily unavailable", { exact: true }).waitFor();
    assert.equal(await page.locator("#auditMoreBtn").isVisible(), true);
    assert.equal(await page.locator("#auditMoreBtn").isEnabled(), true);
    assert.equal(await page.locator("#auditBody tr").count(), 1);
    assert.equal(await page.getByText("You've reached the start of the audit history", { exact: true }).count(), 0);
    await page.locator("#auditMoreBtn").click();
    await page.locator("#auditBody").getByText("older@example.test", { exact: true }).waitFor();
    assert.equal(await page.locator("#auditBody tr").count(), 2);
    assert.equal(await page.locator("#auditFooter").isVisible(), false);
    assert.deepEqual(cursors, ["older-page", "older-page"]);
    assert.deepEqual(pageErrors, []);
  } finally {
    await browser?.close();
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
});
