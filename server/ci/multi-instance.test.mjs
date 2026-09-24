import assert from "node:assert/strict";
import { Client } from "pg";
import { get } from "node:http";
import { createServer } from "node:net";
import { once } from "node:events";
import test from "node:test";
import Fastify from "fastify";
import cookie from "@fastify/cookie";

// The test database methods and PostgreSQL sockets are controlled below.
// No database, mailer, container, or external identity provider is contacted.
process.env.NODE_ENV = "test";
process.env.DATABASE_URL = "postgresql://fixture:fixture@127.0.0.1:1/fixture";
process.env.JWT_SECRET = "multi-instance-fixture-secret-is-not-a-real-credential";
const { db } = await import("../src/db.ts");
const { env } = await import("../src/env.ts");
const { bus, Bus } = await import("../src/lib/bus.ts");
const { mintSession } = await import("../src/lib/auth.ts");
const { authenticate, requireSession } = await import("../src/lib/session-middleware.ts");
const { authRoutes } = await import("../src/routes/auth.ts");
const { streamRoutes } = await import("../src/routes/stream.ts");

const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
function replaceMethod(t, target, name, replacement) {
  const original = target[name];
  target[name] = replacement;
  t.after(() => { target[name] = original; });
}
async function eventually(predicate, message, timeout = 1500) {
  const deadline = Date.now() + timeout;
  while (!predicate()) {
    assert.ok(Date.now() < deadline, message);
    await pause(5);
  }
}

async function streamFixture(t, orgId = "tenant-a") {
  const app = Fastify();
  app.addHook("preHandler", async (req) => {
    req.session = { sub: "user-a", orgId, membershipRole: "owner", iat: 1, iatMs: 1 };
  });
  await app.register(streamRoutes);
  const base = await app.listen({ host: "127.0.0.1", port: 0 });
  let response;
  let data = "";
  let ended = false;
  let disconnected = false;
  const request = get(`${base}/stream`);
  request.on("response", (res) => {
    response = res;
    res.setEncoding("utf8");
    res.on("data", (chunk) => { data += chunk; });
    res.on("end", () => { ended = true; });
    res.on("close", () => { disconnected = true; });
  });
  request.on("error", () => {});
  t.after(async () => {
    response?.destroy();
    request.destroy();
    await app.close();
  });
  await eventually(() => data.includes("event: hello"), "stream must open");
  return { app, data: () => data, ended: () => ended, disconnected: () => disconnected };
}

function fakePg(t) {
  const listening = new Set();
  const clients = [];
  const ended = new Set();
  const failPublish = new Set();
  const control = {};
  t.mock.method(Client.prototype, "connect", async function () {
    clients.push(this);
    await control.connect?.(this, clients.length);
  });
  t.mock.method(Client.prototype, "query", async function (query, parameters) {
    const sql = typeof query === "string" ? query : query.text;
    const values = typeof query === "string" ? parameters : query.values;
    if (sql.startsWith("LISTEN ")) listening.add(this);
    if (sql.startsWith("SELECT pg_notify")) {
      if (failPublish.delete(this)) throw new Error("injected publication failure without Client error");
      for (const receiver of listening) {
        receiver.emit("notification", { channel: values[0], payload: values[1] });
      }
    }
    return { rows: [] };
  });
  t.mock.method(Client.prototype, "end", async function () {
    listening.delete(this);
    ended.add(this);
    if (control.errorOnEnd) this.emit("error", new Error("injected error racing socket close"));
    this.emit("end");
  });
  return { clients, listening, ended, failPublish, control };
}

test("logout reports a failed revocation and only succeeds after a durable fence", async (t) => {
  let fence = null;
  let failWrite = true;
  const audits = [];
  replaceMethod(t, db.user, "findUnique", async () => ({
    sessionRevokedAt: fence,
    memberships: [{ role: "owner", org: { ipAllowlist: [] } }],
  }));
  replaceMethod(t, db.user, "update", async ({ data }) => {
    if (failWrite) throw new Error("injected database write outage");
    fence = data.sessionRevokedAt;
    return {};
  });
  replaceMethod(t, db.auditEntry, "create", async ({ data }) => { audits.push(data); return {}; });
  const app = Fastify();
  await app.register(cookie);
  app.addHook("preHandler", authenticate);
  await app.register(authRoutes);
  app.get("/protected", async (req, reply) => requireSession(req, reply) ? { ok: true } : undefined);
  t.after(() => app.close());
  const peer = Fastify();
  await peer.register(cookie);
  peer.addHook("preHandler", authenticate);
  peer.get("/protected", async (req, reply) => requireSession(req, reply) ? { ok: true } : undefined);
  t.after(() => peer.close());
  const token = await mintSession({ sub: "user-a", orgId: "tenant-a", membershipRole: "owner" });
  const headers = { cookie: `av_session=${token}` };
  await pause(2); // The real millisecond fence must be newer than this cookie.
  const failed = await app.inject({ method: "POST", url: "/logout", headers });
  assert.equal(failed.statusCode, 503, failed.body);
  assert.equal(failed.json().error, "session_revocation_unavailable");
  assert.equal(failed.headers["set-cookie"], undefined, "retain the cookie so logout can be retried");
  assert.equal(audits.length, 0, "failed revocation must not emit a successful logout audit");
  assert.equal((await peer.inject({ url: "/protected", headers })).statusCode, 200);
  failWrite = false;
  const succeeded = await app.inject({ method: "POST", url: "/logout", headers });
  assert.equal(succeeded.statusCode, 200);
  assert.match(succeeded.headers["set-cookie"], /Max-Age=0/);
  assert.equal(audits.filter((entry) => entry.event === "auth.logout").length, 1);
  assert.equal((await peer.inject({ url: "/protected", headers })).statusCode, 401,
    "another instance must reject a captured cookie after successful logout");
});

test("graceful shutdown closes an active SSE response and releases its subscription", async (t) => {
  const f = await streamFixture(t);
  assert.equal(bus.listenerCount("org:tenant-a"), 1);
  let closed = false;
  const closing = f.app.close().then(() => { closed = true; });
  await eventually(() => closed, "app.close() must finish while the browser keeps SSE open", 300);
  await closing;
  await eventually(f.disconnected, "the browser must see the stream disconnect");
  assert.equal(bus.listenerCount("org:tenant-a"), 0);
});

test("publisher outages reset peer instances without crossing tenant boundaries or duplicating events", async (t) => {
  const pg = fakePg(t);
  const origin = new Bus();
  const peer = new Bus();
  t.after(() => Promise.all([origin.close(), peer.close()]));
  await origin.connectPgBridge();
  await peer.connectPgBridge();
  const local = [];
  const remote = [];
  const otherTenant = [];
  let resets = 0;
  origin.subscribeOrg("tenant-a", (ev) => local.push(ev));
  peer.subscribeOrg("tenant-a", (ev) => remote.push(ev));
  peer.subscribeOrg("tenant-b", (ev) => otherTenant.push(ev));
  peer.subscribeReset(() => { resets++; });
  const event = { type: "events.appended", orgId: "tenant-a", deploymentId: "deployment-a", sessionId: "session-a", count: 1, blocked: 0, allowed: 1 };
  origin.publish(event);
  assert.equal(local.length, 1);
  assert.equal(remote.length, 1);
  pg.clients[1].emit("error", new Error("injected publisher outage"));
  origin.publish(event); // Commits during the bridge outage remain visible locally.
  assert.equal(local.length, 2);
  assert.equal(remote.length, 1);
  await eventually(() => origin.isReady() && resets === 1, "the healthy peer must refetch after a publisher outage");
  origin.publish(event);
  assert.equal(local.length, 3);
  assert.equal(remote.length, 2);
  pg.failPublish.add(origin.pgPublisher);
  origin.publish(event);
  await eventually(() => resets === 2, "a rejected NOTIFY query must also recover and reset peers");
  assert.equal(local.length, 4);
  assert.equal(remote.length, 2);
  assert.equal(otherTenant.length, 0, "reset signals must never contain another tenant's event data");
});

test("bridge shutdown drains late client errors and cancels its reconnect timer", async (t) => {
  const pg = fakePg(t);
  const bridge = new Bus();
  t.after(() => bridge.close());
  await bridge.connectPgBridge();
  pg.control.errorOnEnd = true;
  await bridge.close();
  assert.equal(bridge.isReady(), false);
  assert.equal(pg.ended.size, 2);
  assert.equal(bridge.reconnectTimer, undefined);
});

test("failed publisher connection closes both partial clients", async (t) => {
  const pg = fakePg(t);
  const bridge = new Bus();
  t.after(() => bridge.close());
  pg.control.connect = async (_client, index) => {
    if (index === 2) throw new Error("injected publisher connection failure");
  };
  assert.equal(await bridge.connectPgBridge(), false);
  assert.equal(bridge.isReady(), false);
  assert.equal(pg.ended.size, 2);
  await bridge.close();
  assert.equal(bridge.reconnectTimer, undefined);
});

test("an error during partial connection cannot resurrect a failed bridge", async (t) => {
  const pg = fakePg(t);
  const bridge = new Bus();
  let release;
  const held = new Promise((resolve) => { release = resolve; });
  t.after(async () => { release(); await bridge.close(); });
  pg.control.connect = async (_client, index) => { if (index === 2) await held; };
  const connecting = bridge.connectPgBridge();
  await eventually(() => pg.clients.length === 2, "the publisher connection must be pending");
  pg.clients[0].emit("error", new Error("listener failed before publisher connected"));
  release();
  assert.equal(await connecting, false);
  assert.equal(bridge.isReady(), false);
  assert.equal(pg.ended.size, 2);
});

test("a late failed connection cannot tear down its healthy replacement", async (t) => {
  const pg = fakePg(t);
  const bridge = new Bus();
  let release;
  const held = new Promise((resolve) => { release = resolve; });
  t.after(async () => { release(); await bridge.close(); });
  pg.control.connect = async (_client, index) => { if (index === 2) await held; };
  const connecting = bridge.connectPgBridge();
  await eventually(() => pg.clients.length === 2, "the first publisher must be pending");
  pg.clients[0].emit("error", new Error("injected error while connect is pending"));
  await eventually(() => pg.clients.length === 4 && bridge.isReady(), "a fresh pair must recover while the old attempt is pending");
  const replacement = bridge.pgPublisher;
  release();
  assert.equal(await connecting, false);
  assert.equal(bridge.isReady(), true);
  assert.equal(bridge.pgPublisher, replacement);
  assert.ok(pg.ended.has(pg.clients[0]) && pg.ended.has(pg.clients[1]));
  assert.ok(!pg.ended.has(pg.clients[2]) && !pg.ended.has(pg.clients[3]));
  assert.equal(bridge.reconnectTimer, undefined);
});

test("a recovered PostgreSQL bridge resets open SSE so missed events are refetched", async (t) => {
  const pg = fakePg(t);
  t.after(() => bus.close());
  assert.equal(await bus.connectPgBridge(), true);
  const f = await streamFixture(t);
  pg.clients[0].emit("error", new Error("injected listener outage"));
  assert.equal(bus.isReady(), false);
  await eventually(() => bus.isReady(), "the bridge must reconnect");
  await eventually(f.ended, "a healthy SSE socket must reset after its notification bridge lost events", 300);
  assert.match(f.data(), /event: stream_reset/);
  assert.equal(bus.listenerCount("org:tenant-a"), 0);
});

test("closing a bridge cancels a real PostgreSQL handshake that never completes", async (t) => {
  const sockets = new Set();
  const blackhole = createServer((socket) => {
    sockets.add(socket);
    socket.on("data", () => {}); // Accept startup bytes, never answer them.
    socket.on("close", () => sockets.delete(socket));
  });
  blackhole.listen(0, "127.0.0.1");
  await once(blackhole, "listening");
  const originalUrl = env.DATABASE_URL;
  env.DATABASE_URL = `postgresql://fixture:fixture@127.0.0.1:${blackhole.address().port}/fixture`;
  const bridge = new Bus();
  const connecting = bridge.connectPgBridge();
  t.after(async () => {
    env.DATABASE_URL = originalUrl;
    for (const socket of sockets) socket.destroy();
    await bridge.close();
    await connecting;
    await new Promise((resolve) => blackhole.close(resolve));
  });
  await eventually(() => sockets.size === 1, "the real TCP peer must accept the client");
  await bridge.close();
  await eventually(() => sockets.size === 0, "close must release the socket without waiting for a PostgreSQL reply", 300);
  assert.equal(await connecting, false);
  assert.equal(bridge.isReady(), false);
});
