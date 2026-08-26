/*
 * IP allowlist drill.
 *
 * Scenarios:
 *   1. Default: empty allowlist -> everyone allowed.
 *   2. PATCH { cidrs: ["127.0.0.1/32"] } -> saved, our IP still works.
 *   3. Self-lockout guard: PATCH { cidrs: ["203.0.113.0/24"] } from
 *      127.0.0.1 -> 400 would_lock_yourself_out.
 *   4. Malformed CIDR -> 400 invalid_cidr.
 *   5. Bare-IP sugar: PATCH { cidrs: ["127.0.0.1"] } coerces to /32.
 *   6. IPv6 support: PATCH { cidrs: ["::1/128"] } from 127.0.0.1 (v4)
 *      -> 400 because v4 doesn't match v6 CIDR.
 *   7. Non-owner enforcement: patch as owner to a CIDR that only
 *      matches evil-IP (via X-Forwarded-For). Then send request with
 *      real X-Forwarded-For=10.0.0.1 -> 403 forbidden_ip. Send with
 *      the matching XFF -> 200.
 *   8. Member 403 on PATCH.
 *   9. Audit trail contains org.ip_allowlist_updated.
 */

const BASE = process.env.BASE ?? "http://127.0.0.1:8750";
const nonce = Math.random().toString(36).slice(2, 6);

async function jr(state, method, path, body, extraHeaders) {
  const headers = { ...(extraHeaders || {}) };
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
function fail(m) { console.log("❌", m); process.exit(1); }

const alice = {};
{
  const r = await jr(alice, "POST", "/api/v1/auth/signup", {
    email: `ip+${nonce}@example.com`, password: "s3cret-drill-pw-1234!",
    orgName: `IP-${nonce}`, displayName: "IP owner",
  });
  if (r.status !== 200 && r.status !== 201) fail(`signup ${r.status}`);
}

// 1. default empty
{
  const r = await jr(alice, "GET", "/api/v1/org/ip-allowlist");
  if (r.status !== 200) fail(`GET default ${r.status}`);
  const j = await r.json();
  if (!Array.isArray(j.cidrs) || j.cidrs.length !== 0) fail(`default cidrs: ${JSON.stringify(j)}`);
  if (!j.yourIp) fail("yourIp missing");
  console.log(`✅ default: cidrs=[] yourIp=${j.yourIp}`);
}

// 2. save 127.0.0.1/32
{
  const r = await jr(alice, "PATCH", "/api/v1/org/ip-allowlist", { cidrs: ["127.0.0.1/32"] });
  if (r.status !== 200) fail(`patch loopback ${r.status}: ${await r.text()}`);
  const j = await r.json();
  if (!j.cidrs.includes("127.0.0.1/32")) fail(`patch persist: ${JSON.stringify(j)}`);
  // Verify a follow-up authenticated GET still works.
  const check = await jr(alice, "GET", "/api/v1/org/retention");
  if (check.status !== 200) fail(`after patch, retention -> ${check.status}`);
  console.log("✅ patch 127.0.0.1/32 -> saved, next request still works");
}

// 3. Self-lockout guard
{
  const r = await jr(alice, "PATCH", "/api/v1/org/ip-allowlist", { cidrs: ["203.0.113.0/24"] });
  if (r.status !== 400) fail(`self-lockout ${r.status}, expected 400`);
  const j = await r.json();
  if (!/lock/i.test(String(j.detail || j.errorCode))) fail(`error: ${JSON.stringify(j)}`);
  console.log(`✅ self-lockout refused: ${j.detail || j.errorCode}`);
}

// 4. Malformed CIDR
{
  const r = await jr(alice, "PATCH", "/api/v1/org/ip-allowlist", { cidrs: ["not.a.cidr/blah"] });
  if (r.status !== 400) fail(`bad cidr ${r.status}, expected 400`);
  const j = await r.json();
  if (!/invalid_cidr/i.test(String(j.detail || j.errorCode))) fail(`error: ${JSON.stringify(j)}`);
  console.log("✅ malformed CIDR rejected");
}

// 5. Bare IP sugar
{
  const r = await jr(alice, "PATCH", "/api/v1/org/ip-allowlist", { cidrs: ["127.0.0.1"] });
  if (r.status !== 200) fail(`bare-IP ${r.status}: ${await r.text()}`);
  const j = await r.json();
  if (!j.cidrs.includes("127.0.0.1/32")) fail(`bare-IP coercion: ${JSON.stringify(j)}`);
  console.log("✅ bare IP coerced to /32");
}

// 6. IPv6-only allowlist locks us out (we're v4)
{
  const r = await jr(alice, "PATCH", "/api/v1/org/ip-allowlist", { cidrs: ["::1/128"] });
  if (r.status !== 400) fail(`v6-only ${r.status}, expected 400`);
  console.log("✅ v6-only allowlist would lock v4 caller out");
}

// 7. Enforce via X-Forwarded-For — save an allowlist for 10.0.0.0/8,
// then send requests with XFF=10.0.0.1 (allowed) vs XFF=1.2.3.4 (denied).
// Because trustProxy=true, Fastify treats XFF as ground truth for req.ip.
{
  // First reset to allow-all so we can then re-lock via XFF cleanly.
  const reset0 = await jr(alice, "PATCH", "/api/v1/org/ip-allowlist", { cidrs: [] });
  if (reset0.status !== 200) fail(`reset before XFF ${reset0.status}: ${await reset0.text()}`);

  // Save the allowlist while presenting XFF=10.0.0.1 so the self-
  // lockout guard sees our IP as inside the CIDR.
  const r1 = await jr(alice, "PATCH", "/api/v1/org/ip-allowlist",
    { cidrs: ["10.0.0.0/8"] },
    { "X-Forwarded-For": "10.0.0.1" });
  if (r1.status !== 200) fail(`patch via XFF ${r1.status}: ${await r1.text()}`);

  // Now a request with XFF=10.0.0.7 should be allowed.
  const allowed = await jr(alice, "GET", "/api/v1/org/retention", undefined, { "X-Forwarded-For": "10.0.0.7" });
  if (allowed.status !== 200) fail(`allowed 10.0.0.7 -> ${allowed.status}`);

  // A request with XFF=1.2.3.4 should be 403.
  const denied = await jr(alice, "GET", "/api/v1/org/retention", undefined, { "X-Forwarded-For": "1.2.3.4" });
  if (denied.status !== 403) fail(`denied 1.2.3.4 -> ${denied.status}, expected 403`);
  console.log("✅ enforcement: 10.0.0.7 ok, 1.2.3.4 -> 403 forbidden_ip");

  // Reset to allow-all so we can hit the API without XFF for later scenarios.
  const reset = await jr(alice, "PATCH", "/api/v1/org/ip-allowlist", { cidrs: [] }, { "X-Forwarded-For": "10.0.0.1" });
  if (reset.status !== 200) fail(`reset ${reset.status}`);
}

// 8. Member 403
{
  const carol = {};
  const inv = await jr(alice, "POST", "/api/v1/members/invites", {
    email: `carol+${nonce}@example.com`, role: "member",
  });
  const invBody = await inv.json();
  const params = new URLSearchParams(invBody.invite.acceptUrlDev.split("?")[1] || "");
  await jr(carol, "POST", "/api/v1/members/invites/accept", {
    token: params.get("token"), email: params.get("email"),
    password: "s3cret-drill-pw-1234!", displayName: "Carol",
  });
  const r = await jr(carol, "PATCH", "/api/v1/org/ip-allowlist", { cidrs: ["127.0.0.1/32"] });
  if (r.status !== 403) fail(`member PATCH ${r.status}, expected 403`);
  console.log("✅ member PATCH -> 403");
}

// 9. Audit trail
{
  const r = await jr(alice, "GET", "/api/v1/audit?limit=50");
  const j = await r.json();
  const events = j.entries.map((e) => e.event);
  if (!events.includes("org.ip_allowlist_updated")) fail(`audit missing: ${events.slice(0,10)}`);
  console.log("✅ audit trail contains org.ip_allowlist_updated");
}

console.log("\nAll 9 IP-allowlist drill scenarios passed.");
