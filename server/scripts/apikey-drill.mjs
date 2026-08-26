/*
 * API-key drill: create, use, revoke, verify old key rejected.
 *
 * Full round-trip:
 *   1. signup owner -> keeps session cookie
 *   2. POST /keys with { name } -> receives plaintext once + hint
 *   3. Bearer that token, GET /sessions -> 200 (list, may be empty)
 *   4. GET /keys -> returns 1 row, lastUsedAt bumped, hint matches
 *   5. DELETE /keys/:id -> 204
 *   6. Bearer revoked token, GET /sessions -> 401
 *   7. Bearer wholly-invalid token -> 401
 *   8. GET /audit -> apikey.created + apikey.revoked events present
 */

const BASE = process.env.BASE ?? "http://127.0.0.1:8745";

const nonce = Math.random().toString(36).slice(2, 8);
const email = `keyowner+${nonce}@example.com`;
const password = "s3cret-drill-pw-987!";

async function req(path, opts = {}) {
  const url = BASE + path;
  const r = await fetch(url, opts);
  return r;
}

function parseCookie(setCookie) {
  const m = /av_session=([^;]+)/.exec(setCookie ?? "");
  return m ? m[1] : null;
}

let cookie = null;
let csrfCookie = null;

async function jsonReq(method, path, body) {
  const headers = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (cookie) headers["Cookie"] = `av_session=${cookie}` + (csrfCookie ? `; av_csrf=${csrfCookie}` : "");
  if (csrfCookie) headers["x-av-csrf"] = csrfCookie;
  const r = await fetch(BASE + path, { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined });
  const setC = r.headers.get("set-cookie") ?? "";
  const nc = parseCookie(setC);
  if (nc) cookie = nc;
  const cs = /av_csrf=([^;]+)/.exec(setC);
  if (cs) csrfCookie = cs[1];
  return r;
}

// 1. signup
{
  const r = await jsonReq("POST", "/api/v1/auth/signup", {
    email, password, orgName: `KeyDrill-${nonce}`, displayName: "Owner",
  });
  if (r.status !== 200 && r.status !== 201) {
    console.log("signup failed:", r.status, await r.text());
    process.exit(1);
  }
  console.log("✅ signup ok");
}

// 2. create key
let plaintext, keyId, hint;
{
  const r = await jsonReq("POST", "/api/v1/keys", { name: "CI runner" });
  if (r.status !== 201) {
    console.log("create key failed:", r.status, await r.text());
    process.exit(1);
  }
  const j = await r.json();
  plaintext = j.plaintextToken;
  keyId = j.key.id;
  hint = j.key.hint;
  if (!plaintext?.startsWith("av_srv_")) {
    console.log("❌ plaintext missing prefix:", plaintext);
    process.exit(1);
  }
  if (!hint.startsWith("av_srv_") || hint.length < 12) {
    console.log("❌ hint malformed:", hint);
    process.exit(1);
  }
  console.log(`✅ key created id=${keyId} hint=${hint}`);
}

// 3. Bearer that token, GET /sessions
{
  const r = await fetch(BASE + "/api/v1/sessions", {
    headers: { Authorization: `Bearer ${plaintext}` },
  });
  if (r.status !== 200) {
    console.log("❌ bearer GET /sessions failed:", r.status, await r.text());
    process.exit(1);
  }
  const j = await r.json();
  if (!Array.isArray(j.sessions)) {
    console.log("❌ sessions response malformed:", j);
    process.exit(1);
  }
  console.log(`✅ bearer /sessions ok (n=${j.sessions.length})`);
}

// 4. GET /keys via cookie
{
  const r = await jsonReq("GET", "/api/v1/keys");
  if (r.status !== 200) {
    console.log("❌ list keys failed:", r.status, await r.text());
    process.exit(1);
  }
  const j = await r.json();
  if (j.keys.length !== 1) {
    console.log("❌ expected 1 key, got:", j.keys.length);
    process.exit(1);
  }
  if (!j.keys[0].lastUsedAt) {
    console.log("❌ lastUsedAt not bumped:", j.keys[0]);
    process.exit(1);
  }
  console.log(`✅ list shows lastUsedAt=${j.keys[0].lastUsedAt}`);
}

// 5. DELETE key
{
  const r = await jsonReq("DELETE", `/api/v1/keys/${keyId}`);
  if (r.status !== 204) {
    console.log("❌ delete failed:", r.status, await r.text());
    process.exit(1);
  }
  console.log("✅ delete 204");
}

// 6. Bearer revoked token -> 401
{
  const r = await fetch(BASE + "/api/v1/sessions", {
    headers: { Authorization: `Bearer ${plaintext}` },
  });
  if (r.status !== 401) {
    console.log("❌ revoked token still works:", r.status);
    process.exit(1);
  }
  console.log("✅ revoked bearer -> 401");
}

// 7. Wholly invalid token
{
  const r = await fetch(BASE + "/api/v1/sessions", {
    headers: { Authorization: "Bearer av_srv_notarealtokenatall000000000" },
  });
  if (r.status !== 401) {
    console.log("❌ invalid token accepted:", r.status);
    process.exit(1);
  }
  console.log("✅ invalid bearer -> 401");
}

// 8. Audit trail
{
  const r = await jsonReq("GET", "/api/v1/audit?limit=20");
  if (r.status !== 200) {
    console.log("❌ audit failed:", r.status, await r.text());
    process.exit(1);
  }
  const j = await r.json();
  const events = j.entries.map((e) => e.event);
  if (!events.includes("apikey.created")) {
    console.log("❌ apikey.created missing:", events);
    process.exit(1);
  }
  if (!events.includes("apikey.revoked")) {
    console.log("❌ apikey.revoked missing:", events);
    process.exit(1);
  }
  console.log("✅ audit trail:", events.slice(0, 6).join(", "));
}

console.log("\nAll API-key drill scenarios passed.");
