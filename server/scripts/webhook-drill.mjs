/*
 * Webhook end-to-end drill.
 *
 * Spins up a local HTTP receiver that captures every POST and verifies
 * the HMAC-SHA256 signature. Then:
 *
 *   1. signup owner
 *   2. POST /webhooks with the receiver URL + events=['test','policy.block']
 *   3. GET /webhooks -> list shows 1 endpoint
 *   4. POST /webhooks/:id/test -> receiver gets one signed 'test' event
 *   5. Verify X-AgentVisor-Signature against payload
 *   6. GET /webhooks/:id/deliveries -> shows the 'delivered' row with
 *      responseCode=200 and attempt=1
 *   7. Deactivate the endpoint (PATCH { isActive: false }), fire another
 *      test -> receiver must NOT get it
 *   8. Reactivate, point to a 500-returning URL, fire test -> receiver
 *      gets 500, delivery moves to 'retrying' with nextRetryAt in future
 *   9. Point back to 200-returning URL; wait ~20s for the sweeper to
 *      retry once. Verify delivery flipped to 'delivered'.
 */

import { createServer } from "node:http";
import { createHmac, timingSafeEqual } from "node:crypto";

const BASE = process.env.BASE ?? "http://127.0.0.1:8747";
const PG_CONTAINER = process.env.PG_CONTAINER ?? "av-pg-r47";
const RECV_PORT = 44117;
const nonce = Math.random().toString(36).slice(2, 6);

let capture = [];
let receiverBehavior = { status: 200 };

function verify(secret, timestamp, body, sig) {
  const h = createHmac("sha256", secret);
  h.update(timestamp);
  h.update(".");
  h.update(body);
  const exp = "sha256=" + h.digest("hex");
  if (exp.length !== sig.length) return false;
  return timingSafeEqual(Buffer.from(exp), Buffer.from(sig));
}

const receiver = createServer((req, res) => {
  let body = "";
  req.on("data", (c) => (body += c));
  req.on("end", () => {
    capture.push({
      method: req.method,
      url: req.url,
      headers: { ...req.headers },
      body,
      at: Date.now(),
    });
    res.statusCode = receiverBehavior.status;
    res.setHeader("content-type", "text/plain");
    res.end(receiverBehavior.status < 400 ? "ok" : "boom");
  });
});
await new Promise((resolve) => receiver.listen(RECV_PORT, "127.0.0.1", resolve));
const recvUrl = `http://127.0.0.1:${RECV_PORT}/hook`;
console.log("Receiver up at", recvUrl);

let cookie = null;
let csrf = null;
async function jsonReq(method, path, body) {
  const headers = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (cookie) headers["Cookie"] = "av_session=" + cookie + (csrf ? "; av_csrf=" + csrf : "");
  if (csrf) headers["x-av-csrf"] = csrf;
  const r = await fetch(BASE + path, { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined });
  const sc = r.headers.get("set-cookie") ?? "";
  const nc = /av_session=([^;]+)/.exec(sc);
  if (nc) cookie = nc[1];
  const nc2 = /av_csrf=([^;]+)/.exec(sc);
  if (nc2) csrf = nc2[1];
  return r;
}
function fail(msg) { console.log("❌", msg); receiver.close(); process.exit(1); }
async function wait(ms) { await new Promise((r) => setTimeout(r, ms)); }

// 1. signup
{
  const r = await jsonReq("POST", "/api/v1/auth/signup", {
    email: `wh+${nonce}@example.com`, password: "s3cret-drill-pw-1234!",
    orgName: `WH-${nonce}`, displayName: "WH owner",
  });
  if (r.status !== 200 && r.status !== 201) fail(`signup -> ${r.status}: ${await r.text()}`);
  console.log("✅ signup ok");
}

// 2. create webhook
let epId, secret;
{
  const r = await jsonReq("POST", "/api/v1/webhooks", {
    name: "Slack #ops",
    url: recvUrl,
    events: ["test", "policy.block", "member.invited"],
  });
  if (r.status !== 201) fail(`create wh -> ${r.status}: ${await r.text()}`);
  const j = await r.json();
  epId = j.endpoint.id;
  secret = j.secret;
  if (!secret || secret.length !== 64) fail(`secret malformed: ${secret}`);
  console.log(`✅ webhook created id=${epId} secret=${secret.slice(0, 8)}…`);
}

// 3. list
{
  const r = await jsonReq("GET", "/api/v1/webhooks");
  if (r.status !== 200) fail(`list -> ${r.status}`);
  const j = await r.json();
  if (j.endpoints.length !== 1) fail(`expected 1, got ${j.endpoints.length}`);
  if (j.endpoints[0].secret !== undefined) fail(`list must not return secret! got ${j.endpoints[0].secret}`);
  console.log("✅ list shows 1 endpoint, secret omitted");
}

// 4. fire test
capture = [];
{
  const r = await jsonReq("POST", `/api/v1/webhooks/${epId}/test`);
  if (r.status !== 200) fail(`test fire -> ${r.status}`);
  // wait for the async delivery
  for (let i = 0; i < 30; i++) {
    if (capture.length > 0) break;
    await wait(150);
  }
  if (capture.length !== 1) fail(`receiver got ${capture.length} hits, expected 1`);
  const c = capture[0];
  if (c.headers["x-agentvisor-event"] !== "test") fail(`event header: ${c.headers["x-agentvisor-event"]}`);
  if (!c.headers["x-agentvisor-delivery"]) fail("delivery header missing");
  if (!c.headers["x-agentvisor-timestamp"]) fail("timestamp header missing");
  if (!c.headers["x-agentvisor-signature"]) fail("signature header missing");
  console.log(`✅ receiver got 1 signed request`);
}

// 5. verify signature
{
  const c = capture[0];
  const ok = verify(
    secret,
    c.headers["x-agentvisor-timestamp"],
    c.body,
    c.headers["x-agentvisor-signature"],
  );
  if (!ok) fail("signature verify failed");
  const parsed = JSON.parse(c.body);
  if (parsed.event !== "test") fail(`payload event: ${parsed.event}`);
  console.log("✅ HMAC-SHA256 signature verifies");
}

// 6. delivery log
{
  const r = await jsonReq("GET", `/api/v1/webhooks/${epId}/deliveries`);
  if (r.status !== 200) fail(`deliveries -> ${r.status}`);
  const j = await r.json();
  if (j.deliveries.length < 1) fail(`no deliveries returned`);
  const d = j.deliveries[0];
  if (d.status !== "delivered") fail(`delivery status: ${d.status}`);
  if (d.responseCode !== 200) fail(`response code: ${d.responseCode}`);
  if (d.attempt !== 1) fail(`attempt: ${d.attempt}`);
  console.log(`✅ delivery logged: status=${d.status} code=${d.responseCode} attempt=${d.attempt}`);
}

// 7. Deactivate + fire test -> no receiver hit
{
  const r1 = await jsonReq("PATCH", `/api/v1/webhooks/${epId}`, { isActive: false });
  if (r1.status !== 200) fail(`deactivate -> ${r1.status}`);
  capture = [];
  const r2 = await jsonReq("POST", `/api/v1/webhooks/${epId}/test`);
  // Deactivated endpoint returns 404 from the /test route (findFirst { isActive: true }).
  if (r2.status !== 404) fail(`test on inactive -> ${r2.status}, expected 404`);
  await wait(500);
  if (capture.length !== 0) fail(`inactive endpoint got fired: ${capture.length}`);
  console.log("✅ inactive endpoint doesn't fire");
}

// 8. Reactivate, point at 500-returning URL, fire test -> retrying
capture = [];
{
  await jsonReq("PATCH", `/api/v1/webhooks/${epId}`, { isActive: true });
  receiverBehavior = { status: 500 };
  const r = await jsonReq("POST", `/api/v1/webhooks/${epId}/test`);
  if (r.status !== 200) fail(`fire test 500 -> ${r.status}`);
  for (let i = 0; i < 30; i++) {
    if (capture.length > 0) break;
    await wait(150);
  }
  if (capture.length !== 1) fail(`500 test not received: ${capture.length}`);
  await wait(400);
  const list = await (await jsonReq("GET", `/api/v1/webhooks/${epId}/deliveries`)).json();
  const latest = list.deliveries[0];
  if (latest.status !== "retrying") fail(`expected retrying, got ${latest.status}`);
  if (!latest.nextRetryAt) fail("nextRetryAt not set on retrying delivery");
  console.log(`✅ 500 response -> status=retrying, nextRetryAt=${latest.nextRetryAt}`);
}

// 9. Force sweeper: bump nextRetryAt to past, flip receiver back to 200,
// and wait for sweeper cycle (fires immediately after boot then every 15s).
{
  receiverBehavior = { status: 200 };
  const { execSync } = await import("node:child_process");
  execSync(
    `docker exec ${PG_CONTAINER} psql -U av -d avdb -c "UPDATE webhook_deliveries SET \\"nextRetryAt\\" = NOW() - INTERVAL '1 minute' WHERE status='retrying'"`,
    { stdio: "ignore" },
  );
  capture = [];
  console.log("Waiting up to 20s for sweeper to retry...");
  for (let i = 0; i < 40; i++) {
    if (capture.length > 0) break;
    await wait(500);
  }
  if (capture.length !== 1) fail(`sweeper didn't retry: capture=${capture.length}`);
  await wait(500);
  const list = await (await jsonReq("GET", `/api/v1/webhooks/${epId}/deliveries`)).json();
  const latest = list.deliveries[0];
  if (latest.status !== "delivered") fail(`after retry expected delivered, got ${latest.status}`);
  if (latest.attempt < 2) fail(`attempt count didn't bump: ${latest.attempt}`);
  console.log(`✅ sweeper retried: status=${latest.status} attempt=${latest.attempt}`);
}

receiver.close();
console.log("\nAll webhook drill scenarios passed.");
