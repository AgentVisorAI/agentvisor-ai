/*
 * API-key hardening drill: attack matrix.
 *
 * Runs against a fresh org pair (alice + bob), each with their own
 * API key, and asserts the boundary is airtight.
 *
 * Scenarios:
 *   1. Cross-org IDOR: bob's bearer key -> GET /sessions returns
 *      only sessions in bob's org (alice's session must not leak).
 *   2. Cross-org DELETE: bob's session tries to DELETE /keys/<alice-key-id>
 *      -> 404 (not 500, not 403 — must look like the key doesn't
 *      exist from bob's perspective).
 *   3. Member role: carol (member of alice's org) cannot POST /keys
 *      -> 403.
 *   4. Member role: carol cannot DELETE an existing key -> 403.
 *   5. Wrong-prefix bearer: "Authorization: Bearer aaa.bbb.ccc" (JWT
 *      shape) shouldn't crash — must fall through to no-session
 *      then 401 on protected route.
 *   6. Revoked key never appears in list endpoint output.
 *   7. Hint collision: two keys with same 8-char hint both authenticate
 *      correctly. Force by inserting a fake key with matching hint but
 *      wrong hash and verify the real one still works.
 */

import { execSync } from "node:child_process";

const BASE = process.env.BASE ?? "http://127.0.0.1:8745";

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

function fail(msg) { console.log("❌", msg); process.exit(1); }

async function signup(state, email, orgName) {
  const r = await jsonReq(state, "POST", "/api/v1/auth/signup", {
    email, password: "s3cret-drill-pw-1234!", orgName, displayName: email.split("@")[0],
  });
  if (r.status !== 200 && r.status !== 201) fail(`signup ${email} -> ${r.status}: ${await r.text()}`);
}

async function createKey(state, name) {
  const r = await jsonReq(state, "POST", "/api/v1/keys", { name });
  if (r.status !== 201) fail(`create key ${name} -> ${r.status}: ${await r.text()}`);
  return await r.json();
}

const nonce = Math.random().toString(36).slice(2, 6);

// Alice
const alice = {};
await signup(alice, `alice+${nonce}@example.com`, `Alice-${nonce}`);
const aliceKey = await createKey(alice, "alice-runner");

// Bob (separate org)
const bob = {};
await signup(bob, `bob+${nonce}@example.com`, `Bob-${nonce}`);
const bobKey = await createKey(bob, "bob-runner");

console.log("Setup: alice + bob each have an API key.");

// 1. Cross-org IDOR — bob's bearer can't see alice's sessions.
{
  const r = await fetch(BASE + "/api/v1/sessions", {
    headers: { Authorization: `Bearer ${bobKey.plaintextToken}` },
  });
  if (r.status !== 200) fail(`bob bearer /sessions -> ${r.status}`);
  const j = await r.json();
  // Bob has no sessions in his org, so this should be empty.
  if (j.sessions.length !== 0) fail(`bob sees ${j.sessions.length} sessions — cross-org leak!`);
  console.log("✅ cross-org isolation: bob's key sees only bob's org");
}

// 2. Cross-org DELETE — bob (via session cookie) tries to delete
// alice's key by ID.
{
  const r = await jsonReq(bob, "DELETE", "/api/v1/keys/" + aliceKey.key.id);
  if (r.status !== 404) fail(`cross-org DELETE -> ${r.status}, expected 404`);
  console.log("✅ cross-org DELETE -> 404 (opaque)");
}

// 3. Carol as member. Invite + accept flow.
let carolState = {};
{
  const inv = await jsonReq(alice, "POST", "/api/v1/members/invites", {
    email: `carol+${nonce}@example.com`, role: "member",
  });
  if (inv.status !== 201) fail(`invite carol -> ${inv.status}: ${await inv.text()}`);
  const invBody = await inv.json();
  const acceptUrl = invBody.invite.acceptUrlDev;
  const qs = acceptUrl.split("?")[1] || "";
  const params = new URLSearchParams(qs);
  const token = params.get("token");
  const email = params.get("email");
  const acc = await jsonReq(carolState, "POST", "/api/v1/members/invites/accept", {
    token, email, password: "s3cret-drill-pw-1234!", displayName: "Carol",
  });
  if (acc.status !== 200) fail(`carol accept -> ${acc.status}: ${await acc.text()}`);
  const r = await jsonReq(carolState, "POST", "/api/v1/keys", { name: "carol-attempt" });
  if (r.status !== 403) fail(`member POST /keys -> ${r.status}, expected 403`);
  console.log("✅ member cannot create keys");
}

// 4. Member cannot delete a key that DOES exist in her org.
{
  const r = await jsonReq(carolState, "DELETE", "/api/v1/keys/" + aliceKey.key.id);
  if (r.status !== 403) fail(`member DELETE -> ${r.status}, expected 403`);
  console.log("✅ member cannot revoke keys");
}

// 5. Wrong-prefix Bearer (JWT shape) — must fall through.
{
  const r = await fetch(BASE + "/api/v1/sessions", {
    headers: { Authorization: "Bearer eyJhbGciOiJIUzI1NiJ9.aGVsbG8.foo" },
  });
  if (r.status !== 401) fail(`wrong-prefix bearer -> ${r.status}, expected 401`);
  console.log("✅ non-av_srv_ bearer falls through to 401");
}

// 6. Revoke alice's key; ensure GET /keys no longer lists it.
{
  const del = await jsonReq(alice, "DELETE", "/api/v1/keys/" + aliceKey.key.id);
  if (del.status !== 204) fail(`revoke -> ${del.status}`);
  const list = await jsonReq(alice, "GET", "/api/v1/keys");
  if (list.status !== 200) fail(`list after revoke -> ${list.status}`);
  const j = await list.json();
  if (j.keys.some((k) => k.id === aliceKey.key.id)) {
    fail(`revoked key still in list: ${JSON.stringify(j.keys)}`);
  }
  console.log("✅ revoked key hidden from list");
}

// 7. Hint collision — insert a fake row into api_keys with the same
// 8-char hint as bob's live key but a bogus argon2 hash. Bob's
// bearer must still authenticate (proves we don't stop at first
// candidate).
{
  const bobHint = bobKey.key.hint.slice("av_srv_".length, "av_srv_".length + 8);
  const sql = [
    "INSERT INTO api_keys (id, \"orgId\", name, \"tokenHash\", \"tokenHint\", role)",
    `SELECT 'colliderkey000000000000000000', "orgId", 'collider', '$argon2id$v=19$m=65536,t=3,p=4$YWFhYWFhYWE$YWFhYWFhYWFhYWFhYWFh', '${bobHint}', 'admin'`,
    "FROM api_keys LIMIT 1;",
  ].join(" ");
  execSync(
    `docker exec -e PGPASSWORD=av av-pg-r45 psql -U av -d avdb -c "${sql.replace(/"/g, '\\"')}"`,
    { stdio: "ignore" },
  );
  const r = await fetch(BASE + "/api/v1/sessions", {
    headers: { Authorization: `Bearer ${bobKey.plaintextToken}` },
  });
  if (r.status !== 200) fail(`hint collision broke real bearer -> ${r.status}`);
  console.log("✅ hint collision: real key still authenticates past the impostor");
}

console.log("\nAll 7 API-key hardening scenarios passed.");
