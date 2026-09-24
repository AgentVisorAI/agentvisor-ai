import assert from "node:assert/strict";
import { createServer } from "node:net";
import test from "node:test";

// These tests run the installed pg driver against an owned loopback peer that
// speaks the PostgreSQL wire protocol. No PgClient method is mocked. The peer
// can acknowledge authentication, then stop answering a particular query.
// This proves driver/socket failure handling, not actual database durability.
process.env.NODE_ENV = "test";
process.env.DATABASE_URL = "postgresql://fixture:fixture@127.0.0.1:1/fixture";
process.env.JWT_SECRET = "bus-query-fixture-is-not-a-real-credential";
// For the exact production image, copy this file to /app/ci and run:
// BUS_TEST_DIST=1 /nodejs/bin/node --test /app/ci/bus-query-recovery.test.mjs
const modules = process.env.BUS_TEST_DIST === "1" ? "../dist" : "../src";
const extension = process.env.BUS_TEST_DIST === "1" ? "js" : "ts";
const { Bus } = await import(`${modules}/lib/bus.${extension}`);
const { env } = await import(`${modules}/env.${extension}`);
const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function eventually(predicate, message, timeout = 2000) {
  const deadline = Date.now() + timeout;
  while (!predicate()) {
    assert.ok(Date.now() < deadline, message);
    await pause(5);
  }
}

function frame(type, payload = Buffer.alloc(0)) {
  const length = Buffer.alloc(4);
  length.writeInt32BE(payload.length + 4);
  return Buffer.concat([Buffer.from(type), length, payload]);
}
const ready = () => frame("Z", Buffer.from("I"));
const command = (name) => frame("C", Buffer.from(`${name}\0`));

function bindValues(payload) {
  let offset = payload.indexOf(0) + 1; // unnamed portal
  offset = payload.indexOf(0, offset) + 1; // unnamed statement
  const formats = payload.readInt16BE(offset);
  offset += 2 + formats * 2;
  const count = payload.readInt16BE(offset);
  offset += 2;
  const values = [];
  for (let index = 0; index < count; index++) {
    const length = payload.readInt32BE(offset);
    offset += 4;
    assert.ok(length >= 0, "fixture parameters must be non-null text");
    values.push(payload.subarray(offset, offset + length).toString());
    offset += length;
  }
  return values;
}

async function fixture(t) {
  const originalUrl = env.DATABASE_URL;
  const buses = [];
  const sockets = new Set();
  const connections = [];
  const queries = [];
  const stalled = [];
  let stall = () => false;
  const server = createServer((socket) => {
    const state = { socket, listening: false, blackhole: false, closed: false };
    sockets.add(socket);
    connections.push(state);
    let bytes = Buffer.alloc(0);
    let startup = true;
    let sql = "";
    let values = [];
    socket.on("error", () => {});
    socket.on("close", () => { state.closed = true; sockets.delete(socket); });
    const complete = (extended) => {
      const wire = values[1] ? JSON.parse(values[1]) : null;
      const kind = sql.startsWith("LISTEN ") ? "listen"
        : wire?.type === "bridge.reset" ? "reset"
        : wire ? "publication" : "heartbeat";
      const query = { kind, state, sql, values, wire };
      queries.push(query);
      if (state.blackhole || stall(query)) { stalled.push(query); return; }
      if (kind === "listen") state.listening = true;
      if (wire) {
        const payload = Buffer.concat([Buffer.alloc(4), Buffer.from(`${values[0]}\0${values[1]}\0`)]);
        for (const receiver of connections) {
          if (receiver.listening && !receiver.closed && !receiver.blackhole) {
            receiver.socket.write(frame("A", payload));
          }
        }
      }
      socket.write(Buffer.concat([
        ...(extended ? [frame("1"), frame("2"), frame("n")] : []),
        command(kind === "listen" ? "LISTEN" : "SELECT 1"), ready(),
      ]));
    };
    socket.on("data", (chunk) => {
      bytes = Buffer.concat([bytes, chunk]);
      if (startup) {
        if (bytes.length < 4 || bytes.length < bytes.readInt32BE()) return;
        bytes = bytes.subarray(bytes.readInt32BE());
        startup = false;
        socket.write(Buffer.concat([frame("R", Buffer.alloc(4)), ready()]));
      }
      while (bytes.length >= 5) {
        const size = bytes.readInt32BE(1) + 1;
        if (bytes.length < size) return;
        const type = String.fromCharCode(bytes[0]);
        const payload = bytes.subarray(5, size);
        bytes = bytes.subarray(size);
        if (type === "X") { socket.end(); return; }
        if (type === "Q") {
          sql = payload.subarray(0, -1).toString(); values = []; complete(false);
        } else if (type === "P") {
          const start = payload.indexOf(0) + 1;
          sql = payload.subarray(start, payload.indexOf(0, start)).toString();
        } else if (type === "B") values = bindValues(payload);
        else if (type === "S") complete(true);
      }
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  // pg lets URL parameters override constructor defaults. The bridge's own
  // deadline must still apply to every operation, including its heartbeat.
  env.DATABASE_URL = `postgresql://fixture:fixture@127.0.0.1:${server.address().port}/fixture?sslmode=disable&query_timeout=60000`;
  const close = async () => {
    const closing = Promise.all(buses.map((bus) => bus.close()));
    let timer;
    try {
      await Promise.race([closing, new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error("owned bridge sockets did not close")), 2000);
      })]);
    } finally {
      clearTimeout(timer);
      const closed = [...sockets].map((socket) => new Promise((resolve) => {
        socket.once("close", resolve);
        socket.destroy();
      }));
      await Promise.all([...closed, new Promise((resolve) => server.close(resolve))]);
      env.DATABASE_URL = originalUrl;
    }
    assert.equal(sockets.size, 0, "all owned sockets must be gone");
  };
  t.after(close);
  return {
    connections, queries, stalled, sockets,
    stallNext(kind) {
      let armed = true;
      stall = (query) => armed && query.kind === kind && (armed = false, true);
    },
    bus() { const bus = new Bus(); buses.push(bus); return bus; },
  };
}

const event = (sessionId, orgId = "tenant-a") => ({
  type: "events.appended", orgId, deploymentId: `deployment-${orgId}`,
  sessionId, count: 1, blocked: 0, allowed: 1,
});

for (const kind of ["listen", "reset"]) {
  test(`an authenticated peer that stalls ${kind} cannot leave bridge opening pending`, { timeout: 30_000 }, async (t) => {
    const f = await fixture(t);
    const bus = f.bus();
    f.stallNext(kind);
    let result;
    const opening = bus.connectPgBridge().then((value) => { result = value; });
    await eventually(() => f.stalled.length === 1, "the peer must receive the stalled query");
    assert.equal(bus.isReady(), false, "an unconfirmed initial reset is not a ready bridge");
    await eventually(() => result !== undefined, "the existing 5-second query deadline must settle opening", 7000);
    await opening;
    assert.equal(result, false);
    await eventually(() => bus.isReady(), "the bridge must reconnect after the timed-out opening");
    assert.equal(f.stalled[0].state.closed, true, "the stalled socket must be closed");
    assert.equal(f.sockets.size, 2, "only the replacement listener and publisher may remain");
    const count = f.connections.length;
    await pause(600);
    assert.equal(f.connections.length, count, "late close/query failures must not schedule another reconnect");
  });
}

test("stalled publication closes queued work and resets peers before tenant-scoped delivery resumes", { timeout: 30_000 }, async (t) => {
  const f = await fixture(t);
  const origin = f.bus();
  const peer = f.bus();
  assert.equal(await origin.connectPgBridge(), true);
  assert.equal(await peer.connectPgBridge(), true);
  await pause(20); // Drain the two initial reset notifications before observing recovery.
  const local = [], remote = [], otherTenant = [];
  let resets = 0;
  origin.subscribeOrg("tenant-a", (ev) => local.push(ev.sessionId));
  peer.subscribeOrg("tenant-a", (ev) => remote.push(ev.sessionId));
  peer.subscribeOrg("tenant-b", (ev) => otherTenant.push(ev.sessionId));
  peer.subscribeReset(() => { resets++; });
  origin.publish(event("before"));
  await eventually(() => remote.length === 1, "healthy cross-instance delivery must work");
  const oldPublisher = origin.pgPublisher;
  f.stallNext("publication");
  for (const id of ["lost-active", "lost-queued-1", "lost-queued-2"]) origin.publish(event(id));
  await eventually(() => f.stalled.length === 1, "one publication must be active at the stalled peer");
  assert.equal(oldPublisher._queryQueue.length, 2, "real pg must have queued the remaining publications");
  await eventually(() => !origin.isReady(), "a timed-out publication must clear readiness", 7000);
  await eventually(() => origin.isReady() && resets === 1, "a replacement bridge must reset the healthy peer");
  assert.equal(oldPublisher.connection.stream.destroyed, true);
  assert.equal(oldPublisher._queryQueue.length, 0, "closing the failed pg client must drain every queued query");
  origin.publish(event("after"));
  origin.publish(event("other-tenant", "tenant-b"));
  await eventually(() => remote.length === 2 && otherTenant.length === 1, "both tenants must recover independently");
  assert.deepEqual(local, ["before", "lost-active", "lost-queued-1", "lost-queued-2", "after"]);
  assert.deepEqual(remote, ["before", "after"], "lost updates require refetch; they must not be fabricated or duplicated");
  assert.deepEqual(otherTenant, ["other-tenant"], "tenant A metadata must never reach tenant B");
  assert.equal(f.sockets.size, 4);
  const count = f.connections.length;
  await pause(600);
  assert.equal(resets, 1);
  assert.equal(f.connections.length, count);
});

test("a stalled publisher has a bounded queue and recovery preserves local delivery", { timeout: 30_000 }, async (t) => {
  const f = await fixture(t);
  const bus = f.bus();
  assert.equal(await bus.connectPgBridge(), true);
  const oldPublisher = bus.pgPublisher;
  let local = 0, resets = 0;
  bus.subscribeOrg("tenant-a", () => { local++; });
  bus.subscribeReset(() => { resets++; });
  f.stallNext("publication");
  bus.publish(event("first"));
  await eventually(() => f.stalled.length === 1, "the publication must really be stalled on the wire");
  for (let index = 1; index < 1024; index++) bus.publish(event(`burst-${index}`));
  assert.ok(oldPublisher._queryQueue.length <= 255, "at most 256 active plus queued publications may be retained");
  assert.equal(local, 1024, "overflow must retain every local delivery");
  assert.equal(bus.isReady(), false, "overflow must disconnect rather than silently lose remote updates forever");
  await eventually(() => bus.isReady() && resets === 1, "overflow must recover with a reset");
  assert.equal(oldPublisher.connection.stream.destroyed, true);
  assert.equal(oldPublisher._queryQueue.length, 0);
  assert.equal(f.sockets.size, 2);
});

test("an idle listener blackhole is detected even while its publisher remains healthy", { timeout: 35_000 }, async (t) => {
  const f = await fixture(t);
  const origin = f.bus();
  const peer = f.bus();
  assert.equal(await origin.connectPgBridge(), true);
  assert.equal(await peer.connectPgBridge(), true);
  await pause(20);
  const blockedListener = f.connections[2];
  assert.equal(blockedListener.listening, true);
  blockedListener.blackhole = true;
  const received = [], reverse = [], otherTenant = [];
  let resets = 0;
  peer.subscribeOrg("tenant-a", (ev) => received.push(ev.sessionId));
  peer.subscribeOrg("tenant-b", (ev) => otherTenant.push(ev.sessionId));
  origin.subscribeOrg("tenant-a", (ev) => reverse.push(ev.sessionId));
  origin.subscribeReset(() => { resets++; });
  origin.publish(event("missed-during-listener-blackhole"));
  peer.publish(event("publisher-still-works"));
  await eventually(() => reverse.includes("publisher-still-works"), "the affected instance's independent publisher must still work");
  await eventually(() => blockedListener.closed, "a listener heartbeat plus query deadline must detect the blackhole", 23000);
  await eventually(() => peer.isReady() && resets === 1, "listener recovery must tell healthy peers to refetch");
  assert.ok(f.stalled.some((query) => query.kind === "heartbeat" && query.state === blockedListener),
    "the real listener socket must have received an unanswered liveness query");
  origin.publish(event("after-listener-recovery"));
  await eventually(() => received.includes("after-listener-recovery"), "cross-instance delivery must resume");
  assert.deepEqual(received, ["publisher-still-works", "after-listener-recovery"]);
  assert.deepEqual(otherTenant, []);
  assert.equal(f.sockets.size, 4);
  const count = f.connections.length;
  await Promise.all([origin.close(), peer.close()]);
  assert.equal(origin.listenerHeartbeatTimer, undefined);
  assert.equal(peer.listenerHeartbeatTimer, undefined);
  await eventually(() => f.sockets.size === 0, "shutdown must close all connections");
  await pause(600);
  assert.equal(f.connections.length, count, "shutdown must cancel reconnect and liveness timers");
});
