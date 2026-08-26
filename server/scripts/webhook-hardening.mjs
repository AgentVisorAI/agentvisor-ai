/*
 * Webhook hardening drill: attack matrix.
 *
 * Scenarios:
 *
 *   1. SSRF: block 169.254.169.254 (AWS metadata) — always, even in dev.
 *   2. SSRF: block metadata.google.internal — always.
 *   3. Cross-org IDOR: bob can't PATCH/DELETE/see-deliveries/test
 *      alice's endpoint — 404 (opaque, doesn't leak existence).
 *   4. Member 403: carol (invited as member into alice's org) can't
 *      POST, PATCH, or DELETE webhooks — 403.
 *   5. Signature tampering: modify body -> HMAC no longer matches.
 *   6. Give-up: after MAX_ATTEMPT 5xx responses, delivery is 'failed'
 *      permanently, no more retries scheduled.
 *   7. Delete cascade: DELETE endpoint -> deliveries table row for it
 *      is also gone (FK ON DELETE CASCADE).
 */
import { createServer } from "node:http";
import { createHmac } from "node:crypto";
import { execSync } from "node:child_process";

const BASE = process.env.BASE ?? "http://127.0.0.1:8748";
const RECV_PORT = 44118;
const nonce = Math.random().toString(36).slice(2, 6);

let capture = [];
let receiverBehavior = { status: 200 };

const receiver = createServer((req, res) => {
  let body = "";
  req.on("data", (c) => (body += c));
  req.on("end", () => {
    capture.push({ headers: { ...req.headers }, body });
    res.statusCode = receiverBehavior.status;
    res.end(receiverBehavior.status < 400 ? "ok" : "boom");
  });
});
await new Promise((resolve) => receiver.listen(RECV_PORT, "127.0.0.1", resolve));
const recvUrl = `http://127.0.0.1:${RECV_PORT}/hook`;

async function jsonReq(state, method, path, body) {
  const headers = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (state.cookie) headers["Cookie"] = "av_session=" + state.cookie + (state.csrf ? "; av_csrf=" + state.csrf : "");
  if (state.csrf) headers["x-av-csrf"] = state.csrf;
  const r = await fetch(BASE + path, { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined });
  const sc = r.headers.get("set-cookie") ?? "";
  const nc = /av_session=([^;]+)/.exec(sc);
  if (nc) state.cookie = nc[1];
  const nc2 = /av_csrf=([^;]+)/.exec(sc);
  if (nc2) state.csrf = nc2[1];
  return r;
}
function fail(msg) { console.log("❌", msg); receiver.close(); process.exit(1); }
async function wait(ms) { await new Promise((r) => setTimeout(r, ms)); }

// Setup: alice + bob (separate orgs), carol invited into alice's org as member.
const alice = {};
const bob = {};
{
  let r = await jsonReq(alice, "POST", "/api/v1/auth/signup", {
    email: `alice+${nonce}@example.com`, password: "s3cret-drill-pw-1234!",
    orgName: `Alice-${nonce}`, displayName: "Alice",
  });
  if (r.status !== 200 && r.status !== 201) fail(`alice signup -> ${r.status}: ${await r.text()}`);
  r = await jsonReq(bob, "POST", "/api/v1/auth/signup", {
    email: `bob+${nonce}@example.com`, password: "s3cret-drill-pw-1234!",
    orgName: `Bob-${nonce}`, displayName: "Bob",
  });
  if (r.status !== 200 && r.status !== 201) fail(`bob signup -> ${r.status}: ${await r.text()}`);
}
console.log("Setup: alice + bob signed up in separate orgs.");

// Alice creates an endpoint. Uses 127.0.0.1 which is allowed in dev.
let alicEp;
{
  const r = await jsonReq(alice, "POST", "/api/v1/webhooks", {
    name: "Alice hook",
    url: recvUrl,
    events: ["policy.block", "test"],
  });
  if (r.status !== 201) fail(`alice create -> ${r.status}: ${await r.text()}`);
  alicEp = (await r.json()).endpoint;
  console.log("Setup: alice endpoint =", alicEp.id);
}

// 1. SSRF metadata IP
{
  const r = await jsonReq(alice, "POST", "/api/v1/webhooks", {
    name: "AWS metadata attack",
    url: "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    events: ["policy.block"],
  });
  if (r.status !== 400) fail(`metadata IP -> ${r.status}, expected 400`);
  const j = await r.json();
  if (!/metadata|ssrf/i.test(String(j.detail || j.errorCode || j.title || ""))) fail(`error field: ${JSON.stringify(j)}`);
  console.log("✅ SSRF: 169.254.169.254 blocked (" + (j.detail || j.errorCode) + ")");
}

// 2. SSRF metadata host
{
  const r = await jsonReq(alice, "POST", "/api/v1/webhooks", {
    name: "GCP metadata attack",
    url: "http://metadata.google.internal/computeMetadata/v1/",
    events: ["policy.block"],
  });
  if (r.status !== 400) fail(`GCP metadata -> ${r.status}, expected 400`);
  const j = await r.json();
  console.log("✅ SSRF: metadata.google.internal blocked (" + (j.detail || j.errorCode) + ")");
}

// 3. Cross-org IDOR — bob tries everything against alice's endpoint.
{
  const r1 = await jsonReq(bob, "PATCH", "/api/v1/webhooks/" + alicEp.id, { name: "hijacked" });
  if (r1.status !== 404) fail(`bob PATCH -> ${r1.status}, expected 404`);
  const r2 = await jsonReq(bob, "DELETE", "/api/v1/webhooks/" + alicEp.id);
  if (r2.status !== 404) fail(`bob DELETE -> ${r2.status}, expected 404`);
  const r3 = await jsonReq(bob, "GET", "/api/v1/webhooks/" + alicEp.id + "/deliveries");
  if (r3.status !== 404) fail(`bob deliveries -> ${r3.status}, expected 404`);
  const r4 = await jsonReq(bob, "POST", "/api/v1/webhooks/" + alicEp.id + "/test");
  if (r4.status !== 404) fail(`bob test -> ${r4.status}, expected 404`);
  console.log("✅ cross-org IDOR: bob gets 404 on PATCH/DELETE/deliveries/test");
}

// 4. Member 403 — invite carol, accept, try CRUD.
const carol = {};
{
  const inv = await jsonReq(alice, "POST", "/api/v1/members/invites", {
    email: `carol+${nonce}@example.com`, role: "member",
  });
  if (inv.status !== 201) fail(`invite -> ${inv.status}: ${await inv.text()}`);
  const invBody = await inv.json();
  const qs = invBody.invite.acceptUrlDev.split("?")[1] || "";
  const params = new URLSearchParams(qs);
  const acc = await jsonReq(carol, "POST", "/api/v1/members/invites/accept", {
    token: params.get("token"), email: params.get("email"),
    password: "s3cret-drill-pw-1234!", displayName: "Carol",
  });
  if (acc.status !== 200) fail(`carol accept -> ${acc.status}`);
  const r1 = await jsonReq(carol, "POST", "/api/v1/webhooks", {
    name: "carol", url: recvUrl, events: ["test"],
  });
  if (r1.status !== 403) fail(`carol POST -> ${r1.status}, expected 403`);
  const r2 = await jsonReq(carol, "PATCH", "/api/v1/webhooks/" + alicEp.id, { isActive: false });
  if (r2.status !== 403) fail(`carol PATCH -> ${r2.status}, expected 403`);
  const r3 = await jsonReq(carol, "DELETE", "/api/v1/webhooks/" + alicEp.id);
  if (r3.status !== 403) fail(`carol DELETE -> ${r3.status}, expected 403`);
  console.log("✅ member: 403 on POST/PATCH/DELETE");
}

// 5. Signature tampering — fire test, capture receiver headers, verify
// that if we tweak the body by even 1 char the HMAC no longer matches.
{
  // fetch endpoint's secret from DB directly (not exposed via API).
  const secret = execSync(
    `docker exec av-pg-r48 psql -U av -d avdb -t -A -c "SELECT secret FROM webhook_endpoints WHERE id='${alicEp.id}'"`,
  ).toString().trim();
  capture = [];
  await jsonReq(alice, "POST", "/api/v1/webhooks/" + alicEp.id + "/test");
  for (let i = 0; i < 30 && capture.length === 0; i++) await wait(150);
  if (capture.length !== 1) fail("no delivery captured");
  const c = capture[0];
  const ts = c.headers["x-agentvisor-timestamp"];
  const sig = c.headers["x-agentvisor-signature"];
  const legit = "sha256=" + createHmac("sha256", secret).update(ts).update(".").update(c.body).digest("hex");
  if (legit !== sig) fail(`legit signature mismatch! ${legit} vs ${sig}`);
  const tamperedBody = c.body.replace(/"test"/, '"attack"');
  const tampered = "sha256=" + createHmac("sha256", secret).update(ts).update(".").update(tamperedBody).digest("hex");
  if (tampered === sig) fail("tampered body still matches — signature useless");
  console.log("✅ signature: legit verifies, single-char tamper breaks it");
}

// 6. Give-up after MAX_ATTEMPT — set receiver to 500 permanently, force
// nextRetryAt to past in a loop until the row goes 'failed'.
{
  receiverBehavior = { status: 500 };
  await jsonReq(alice, "POST", "/api/v1/webhooks/" + alicEp.id + "/test");
  await wait(700);
  let finalStatus = null;
  let finalAttempt = 0;
  for (let i = 0; i < 15; i++) {
    execSync(
      `docker exec av-pg-r48 psql -U av -d avdb -c "UPDATE webhook_deliveries SET \\"nextRetryAt\\" = NOW() - INTERVAL '1 minute' WHERE status='retrying'"`,
      { stdio: "ignore" },
    );
    await wait(900); // sweeper=500ms + 400ms slop for retry
    const list = await (await jsonReq(alice, "GET", "/api/v1/webhooks/" + alicEp.id + "/deliveries")).json();
    const latest = list.deliveries[0];
    finalStatus = latest.status;
    finalAttempt = latest.attempt;
    if (latest.status === "failed") break;
  }
  if (finalStatus !== "failed") fail(`give-up: status=${finalStatus}, attempt=${finalAttempt}, expected failed`);
  if (finalAttempt < 6) fail(`give-up: attempt=${finalAttempt}, expected >=6`);
  console.log(`✅ give-up: status=failed after ${finalAttempt} attempts`);
}

// 7. Delete cascade — remove endpoint, deliveries gone.
receiverBehavior = { status: 200 };
{
  const before = execSync(
    `docker exec av-pg-r48 psql -U av -d avdb -t -A -c "SELECT COUNT(*) FROM webhook_deliveries WHERE \\"endpointId\\"='${alicEp.id}'"`,
  ).toString().trim();
  if (before === "0") fail("no deliveries recorded prior to delete");
  await jsonReq(alice, "DELETE", "/api/v1/webhooks/" + alicEp.id);
  const after = execSync(
    `docker exec av-pg-r48 psql -U av -d avdb -t -A -c "SELECT COUNT(*) FROM webhook_deliveries WHERE \\"endpointId\\"='${alicEp.id}'"`,
  ).toString().trim();
  if (after !== "0") fail(`delete cascade: expected 0 rows, got ${after}`);
  console.log(`✅ delete cascade: ${before} deliveries -> 0`);
}

receiver.close();
console.log("\nAll 7 webhook hardening scenarios passed.");
