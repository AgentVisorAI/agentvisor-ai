import assert from "node:assert/strict";
import { once } from "node:events";
import { createServer as createHttpServer } from "node:http";
import { createServer as createTcpServer } from "node:net";
import test, { after } from "node:test";
import Fastify from "fastify";
import cookie from "@fastify/cookie";

// This suite never contacts an external provider or mailbox. Database calls
// are controlled, while discovery and SMTP use real owned loopback sockets.
const smtpSockets = new Set();
const messages = [];
let rejectMail = false;
const smtp = createTcpServer((socket) => {
  smtpSockets.add(socket);
  socket.on("close", () => smtpSockets.delete(socket));
  socket.on("error", () => {});
  socket.write("220 fixture.example.test ESMTP\r\n");
  let pending = "", data = null;
  socket.on("data", (chunk) => {
    pending += chunk.toString();
    let end;
    while ((end = pending.indexOf("\r\n")) >= 0) {
      const line = pending.slice(0, end); pending = pending.slice(end + 2);
      if (data !== null) {
        if (line === ".") {
          messages.push(data); data = null;
          socket.write(rejectMail ? "451 4.3.0 injected delivery failure\r\n" : "250 2.0.0 fixture-accepted\r\n");
        } else data += line + "\r\n";
      } else if (/^(EHLO|HELO) /i.test(line)) socket.write("250 fixture.example.test\r\n");
      else if (/^(MAIL FROM|RCPT TO):/i.test(line)) socket.write("250 2.1.0 OK\r\n");
      else if (line === "DATA") { data = ""; socket.write("354 End with dot\r\n"); }
      else if (line === "QUIT") socket.end("221 goodbye\r\n");
      else socket.write("250 OK\r\n");
    }
  });
});
smtp.listen(0, "127.0.0.1");
await once(smtp, "listening");
after(async () => {
  for (const socket of smtpSockets) socket.destroy();
  await new Promise((resolve) => smtp.close(resolve));
});

Object.assign(process.env, {
  NODE_ENV: "test", DATABASE_URL: "postgresql://fixture:fixture@127.0.0.1:1/fixture",
  JWT_SECRET: "local-auth-contract-fixture-with-no-real-authority",
  SMTP_URL: `smtp://127.0.0.1:${smtp.address().port}`, RESEND_API_KEY: "",
  EMAIL_FROM: "fixture@example.test", APP_BASE_URL: "https://console.example.test",
  API_PUBLIC_URL: "https://api.example.test", OIDC_CLIENT_ID: "fixture",
  OIDC_CLIENT_SECRET: "fixture-secret", GOOGLE_CLIENT_ID: "", MICROSOFT_CLIENT_ID: "",
});
const { db } = await import("../src/db.ts");
const { env } = await import("../src/env.ts");
const { mintSession, verifyPassword } = await import("../src/lib/auth.ts");
const { authenticate, requireSession } = await import("../src/lib/session-middleware.ts");
const { samlRoutes } = await import("../src/routes/saml.ts");
const { authRoutes } = await import("../src/routes/auth.ts");
const { getMailer, passwordResetMail } = await import("../src/lib/mail.ts");
function replaceMethod(t, target, name, replacement) {
  const original = target[name];
  target[name] = replacement;
  t.after(() => { target[name] = original; });
}
const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
async function eventually(predicate) {
  const deadline = Date.now() + 5000;
  while (!predicate()) {
    assert.ok(Date.now() < deadline, "local fixture did not finish");
    await pause(5);
  }
}

test("SAML logout preserves retry state and refuses false success when persistence fails", async (t) => {
  let fence = null, fail = true;
  const audits = [];
  replaceMethod(t, db.user, "findUnique", async () => ({ email: "alice@example.test", sessionRevokedAt: fence,
    memberships: [{ role: "owner", org: { ipAllowlist: [] } }] }));
  replaceMethod(t, db.user, "update", async ({ data }) => {
    if (fail) throw new Error("injected revocation write failure");
    fence = data.sessionRevokedAt; return {};
  });
  replaceMethod(t, db.samlConfig, "findFirst", async ({ where }) =>
    where.orgId === "tenant-a" && where.id === "config-a" ? { id: "config-a", orgId: "tenant-a", isActive: true } : null);
  replaceMethod(t, db.auditEntry, "create", async ({ data }) => { audits.push(data); return {}; });
  const app = Fastify(), peer = Fastify();
  for (const instance of [app, peer]) {
    await instance.register(cookie);
    instance.addHook("preHandler", authenticate);
    instance.get("/protected", async (req, reply) => requireSession(req, reply) ? { ok: true } : undefined);
    t.after(() => instance.close());
  }
  await app.register(samlRoutes);
  const token = await mintSession({ sub: "user-a", orgId: "tenant-a", membershipRole: "owner" });
  const headers = { cookie: `av_session=${token}` };
  await pause(2);
  const failed = await app.inject({ method: "POST", url: "/config-a/slo", headers });
  assert.equal(failed.statusCode, 503, failed.body);
  assert.equal(failed.json().error, "session_revocation_unavailable");
  assert.equal(failed.headers["set-cookie"], undefined);
  assert.equal(audits.length, 0);
  assert.equal((await peer.inject({ url: "/protected", headers })).statusCode, 200);
  fail = false;
  const foreign = await app.inject({ method: "POST", url: "/foreign-config/slo", headers });
  assert.equal(foreign.statusCode, 404);
  const succeeded = await app.inject({ method: "POST", url: "/config-a/slo", headers });
  assert.equal(succeeded.statusCode, 200);
  assert.match(succeeded.headers["set-cookie"], /Max-Age=0/);
  assert.equal(audits.filter((entry) => entry.event === "auth.saml.slo").length, 1);
  assert.equal((await peer.inject({ url: "/protected", headers })).statusCode, 401);
});

for (const endpoint of ["start", "callback"]) {
  test(`OIDC ${endpoint} reports discovery outages through the browser redirect and can retry`, async (t) => {
    let available = false;
    const provider = createHttpServer((req, res) => {
      if (!available) { res.writeHead(503); res.end("injected provider failure"); return; }
      res.setHeader("Content-Type", "application/json");
      const issuer = `http://127.0.0.1:${provider.address().port}`;
      res.end(JSON.stringify({ issuer, authorization_endpoint: issuer + "/authorize",
        token_endpoint: issuer + "/token", jwks_uri: issuer + "/jwks",
        response_types_supported: ["code"], subject_types_supported: ["public"],
        id_token_signing_alg_values_supported: ["RS256"] }));
    });
    provider.listen(0, "127.0.0.1"); await once(provider, "listening");
    t.after(() => new Promise((resolve) => { provider.closeAllConnections(); provider.close(resolve); }));
    const oldIssuer = env.OIDC_ISSUER_URL;
    env.OIDC_ISSUER_URL = `http://127.0.0.1:${provider.address().port}`;
    t.after(() => { env.OIDC_ISSUER_URL = oldIssuer; });
    // Independent module caches model the callback arriving on a fresh replica.
    const { oauthRoutes } = await import(`../src/routes/oauth.ts?discovery=${endpoint}`);
    const app = Fastify();
    await app.register(cookie, { secret: env.JWT_SECRET });
    await app.register(oauthRoutes, { prefix: "/api/v1/auth/oauth" });
    await app.ready(); t.after(() => app.close());
    const bag = app.signCookie(JSON.stringify({ state: "fixture-state", nonce: "fixture-nonce",
      codeVerifier: "fixture-verifier", provider: "oidc" }));
    const response = await app.inject({ url: `/api/v1/auth/oauth/oidc/${endpoint}?code=fixture&state=fixture-state`,
      headers: { cookie: `av_oauth_state=${encodeURIComponent(bag)}` } });
    assert.equal(response.statusCode, 302, response.body);
    assert.equal(response.headers.location, "https://console.example.test/app/#/login?err=oauth_provider_unavailable");
    assert.ok(!String(response.headers["set-cookie"] || "").includes("av_session="));
    available = true;
    const retry = await app.inject({ url: "/api/v1/auth/oauth/oidc/start" });
    assert.equal(retry.statusCode, 302, retry.body);
    assert.equal(new URL(retry.headers.location).origin, env.OIDC_ISSUER_URL);
    assert.ok(new URL(retry.headers.location).searchParams.get("code_challenge"));
    assert.match(retry.headers["set-cookie"], /av_oauth_state=/);
  });
}

test("SMTP accepts reset mail through the local protocol and surfaces provider rejection", async () => {
  const mailer = getMailer({ info() {} });
  const link = "https://console.example.test/app/#/reset?token=fixture-token&email=alice%40example.test";
  const message = { to: "alice@example.test", ...passwordResetMail(link) };
  rejectMail = false;
  const accepted = await mailer.send(message);
  assert.equal(accepted.driver, "smtp");
  assert.ok(accepted.id);
  assert.match(messages.at(-1), /alice@example\.test/);
  assert.match(messages.at(-1), /fixture-token/);
  rejectMail = true;
  try { await assert.rejects(mailer.send(message), /451|injected delivery failure/); }
  finally { rejectMail = false; }
});

test("reset confirmation consumes a mailed token once and atomically requests API-key revocation", async (t) => {
  let user = { id: "reset-user", email: "reset@example.test", resetTokenHash: null, resetTokenAt: null };
  let revoked = 0, inTransaction = false;
  const logs = [];
  const app = Fastify({ logger: { level: "info", stream: { write(value) { logs.push(JSON.parse(value)); } } } });
  await app.register(cookie); await app.register(authRoutes);
  t.after(() => app.close());
  replaceMethod(t, db.user, "findUnique", async ({ where }) => where.email === user.email ? { ...user } : null);
  replaceMethod(t, db.user, "update", async ({ data }) => { Object.assign(user, data); return { ...user }; });
  replaceMethod(t, db.user, "updateMany", async ({ where, data }) => {
    if (where.resetTokenHash !== undefined) assert.equal(inTransaction, true);
    if (where.resetTokenHash !== undefined && (where.resetTokenHash !== user.resetTokenHash || where.resetTokenAt !== user.resetTokenAt)) return { count: 0 };
    Object.assign(user, data); return { count: 1 };
  });
  replaceMethod(t, db.membership, "findFirst", async () => null);
  replaceMethod(t, db.apiKey, "updateMany", async ({ where }) => {
    assert.equal(inTransaction, true); assert.equal(where.createdById, user.id); revoked++; return { count: 2 };
  });
  replaceMethod(t, db, "$transaction", async (callback) => {
    inTransaction = true;
    try { return await callback(db); } finally { inTransaction = false; }
  });
  const before = messages.length;
  const unknown = await app.inject({ method: "POST", url: "/reset-request", payload: { email: "absent@example.test" } });
  const requested = await app.inject({ method: "POST", url: "/reset-request", payload: { email: user.email } });
  assert.equal(unknown.statusCode, 202); assert.equal(requested.statusCode, 202);
  assert.equal(unknown.body, requested.body);
  await eventually(() => logs.some((entry) => entry.msg === "password_reset_email_sent"));
  assert.equal(messages.length, before + 1);
  // Decode quoted-printable wrapping from the real captured MIME message.
  const text = messages.at(-1).replace(/=\r\n/g, "").replace(/=([0-9A-F]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
  const token = text.match(/token=([A-Za-z0-9_-]+)&email=/)?.[1];
  assert.ok(token, "SMTP must receive a usable reset token");
  assert.ok(await verifyPassword(user.resetTokenHash, token));
  assert.ok(!JSON.stringify(logs).includes(token), "application logs must not contain the reset token");
  const payload = { email: user.email, token, newPassword: "replacement-password-1234" };
  const invalid = await app.inject({ method: "POST", url: "/reset-confirm", payload: { ...payload, token: "incorrect-token-with-valid-length" } });
  assert.equal(invalid.statusCode, 401);
  const issuedAt = user.resetTokenAt;
  user.resetTokenAt = new Date(Date.now() - 25 * 60 * 60_000);
  const expired = await app.inject({ method: "POST", url: "/reset-confirm", payload });
  assert.equal(expired.statusCode, 401);
  assert.equal(expired.body, invalid.body);
  assert.equal(revoked, 0);
  user.resetTokenAt = issuedAt;
  const outcomes = await Promise.all([app.inject({ method: "POST", url: "/reset-confirm", payload }), app.inject({ method: "POST", url: "/reset-confirm", payload })]);
  assert.deepEqual(outcomes.map((r) => r.statusCode).sort(), [200, 401]);
  assert.equal(revoked, 1);
  assert.equal(user.resetTokenHash, null);
  assert.ok(await verifyPassword(user.passwordHash, payload.newPassword));
});

test("a rejected reset email keeps the public response uniform and records no delivery success", async (t) => {
  const logs = [], writes = [];
  const app = Fastify({ logger: { level: "info", stream: { write(value) { logs.push(JSON.parse(value)); } } } });
  await app.register(authRoutes); t.after(() => app.close());
  replaceMethod(t, db.user, "findUnique", async () => ({ id: "mail-failure-user", email: "rejected@example.test" }));
  replaceMethod(t, db.user, "updateMany", async ({ data }) => { writes.push(data); return { count: 1 }; });
  replaceMethod(t, db.membership, "findFirst", async () => null);
  rejectMail = true;
  t.after(() => { rejectMail = false; });
  const response = await app.inject({ method: "POST", url: "/reset-request", payload: { email: "rejected@example.test" } });
  assert.equal(response.statusCode, 202);
  assert.deepEqual(response.json(), { ok: true });
  await eventually(() => logs.some((entry) => entry.msg === "password_reset_deferred_failed"));
  assert.equal(writes.length, 1);
  assert.ok(!logs.some((entry) => entry.msg === "password_reset_email_sent"));
  assert.match(messages.at(-1), /rejected@example\.test/);
});

test("a reset request cannot install a token for an address changed after its lookup", async (t) => {
  const oldEmail = "previous-owner@example.test";
  const user = { id: "changed-address-user", email: oldEmail, resetTokenHash: null, resetTokenAt: null };
  let writes = 0;
  const before = messages.length;
  replaceMethod(t, db.user, "findUnique", async () => {
    const snapshot = { ...user };
    // A completed email change clears reset credentials. The deferred reset
    // must not resurrect one and mail it to the now-former account address.
    user.email = "new-owner@example.test";
    return snapshot;
  });
  replaceMethod(t, db.user, "update", async ({ data }) => { writes++; Object.assign(user, data); return { ...user }; });
  replaceMethod(t, db.user, "updateMany", async ({ where, data }) => {
    writes++;
    if (where.email !== user.email) return { count: 0 };
    Object.assign(user, data); return { count: 1 };
  });
  replaceMethod(t, db.membership, "findFirst", async () => null);
  const app = Fastify();
  await app.register(authRoutes); t.after(() => app.close());
  const response = await app.inject({ method: "POST", url: "/reset-request", payload: { email: oldEmail } });
  assert.equal(response.statusCode, 202);
  await eventually(() => writes === 1);
  assert.equal(user.resetTokenHash, null, "the stale mailbox must receive no reset authority");
  assert.equal(messages.length, before);
});
