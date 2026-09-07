#!/usr/bin/env node
/*
 * Generic-OIDC full-flow drill.
 *
 * Boots an in-process mock OIDC IdP (discovery + authorize + token +
 * JWKS, RS256-signed id_tokens) and drives the ENTIRE
 * routes/oauth.ts pipeline against it — the shared code path that
 * Google/Microsoft logins also ride, which is otherwise untestable
 * without live IdP credentials.
 *
 * Run the API under test with:
 *   PORT=4477 \
 *   APP_BASE_URL=http://127.0.0.1:8988 \
 *   ALLOWED_ORIGINS=http://127.0.0.1:8988 \
 *   API_PUBLIC_URL=http://127.0.0.1:4477 \
 *   OIDC_ISSUER_URL=http://127.0.0.1:4478 \
 *   OIDC_CLIENT_ID=av-console \
 *   OIDC_CLIENT_SECRET=drill-secret-123 \
 *   OIDC_DISPLAY_NAME=Keycloak \
 *   npx tsx src/index.ts
 *
 * Then: PG_CONTAINER=server-db-1 node scripts/oidc-drill.mjs
 * (PG_CONTAINER is used once, to seed a WebAuthn credential row for
 * the MFA-gate refusal leg. Skipped with a warning if unset.)
 *
 * Coverage:
 *   1. /providers lists the generic provider with its display name
 *   2. /oidc/start → 302 with PKCE S256 + state + nonce + signed cookie
 *   3. authorize → callback: JIT user + org, session minted, state
 *      cookie cleared, audit rows (org.created, auth.oauth_signin)
 *   4. repeat login: same user, same org, no duplicate JIT
 *   5. email_verified=false → err=oauth_email_not_verified, no session
 *   6. email claim missing → err=oauth_no_email_in_id_token
 *   7. 1000-char name claim → displayName capped at 200
 *   8. callback without state cookie → err=oauth_missing_state_cookie
 *   9. forged state param → err=oauth_exchange_failed
 *  10. wrong nonce in id_token → err=oauth_exchange_failed
 *  11. /google/start (unconfigured) → err=oauth_provider_not_configured
 *  12. cross-provider cookie (/oidc cookie on /google/callback) →
 *      err=oauth_provider_mismatch
 *  13. /nosuch/start → err=oauth_provider_not_found
 *  14. user with a passkey → err=mfa_required_use_password_login,
 *      no session (OAuth must not bypass the WebAuthn gate)
 */

import http from "node:http";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";

const API = process.env.API_BASE || "http://127.0.0.1:4477";
const IDP_PORT = 4478;
const ISSUER = `http://127.0.0.1:${IDP_PORT}`;
const CLIENT_ID = "av-console";
const CLIENT_SECRET = "drill-secret-123";
const APP_BASE = "http://127.0.0.1:8988";
const PG_CONTAINER = process.env.PG_CONTAINER || "";
const PG_USER = process.env.PG_USER || "agentvisor";
const PG_DB = process.env.PG_DB || "agentvisor";

let passed = 0;
let failed = 0;
function check(name, ok, detail) {
  if (ok) {
    passed++;
    console.log(`  PASS ${name}`);
  } else {
    failed++;
    console.log(`  FAIL ${name} ${detail ? JSON.stringify(detail).slice(0, 300) : ""}`);
  }
}

/* ---------------- mock IdP ---------------- */

const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const KID = "drill-key-1";
const jwk = { ...publicKey.export({ format: "jwk" }), kid: KID, alg: "RS256", use: "sig" };

// Mutable scenario the drill flips between legs.
const scenario = {
  email: "jit.user@oidc-drill.example",
  emailVerified: true,
  includeEmail: true,
  name: "Drill User",
  wrongNonce: false,
};

// code → { challenge, nonce, redirectUri }
const codes = new Map();

function b64url(buf) {
  return Buffer.from(buf).toString("base64url");
}

function signIdToken(claims) {
  const header = b64url(JSON.stringify({ alg: "RS256", kid: KID, typ: "JWT" }));
  const payload = b64url(JSON.stringify(claims));
  const sig = crypto.sign("RSA-SHA256", Buffer.from(`${header}.${payload}`), privateKey);
  return `${header}.${payload}.${b64url(sig)}`;
}

const idp = http.createServer((req, res) => {
  const url = new URL(req.url, ISSUER);
  if (url.pathname === "/.well-known/openid-configuration") {
    res.setHeader("content-type", "application/json");
    res.end(
      JSON.stringify({
        issuer: ISSUER,
        authorization_endpoint: `${ISSUER}/authorize`,
        token_endpoint: `${ISSUER}/token`,
        jwks_uri: `${ISSUER}/jwks`,
        response_types_supported: ["code"],
        subject_types_supported: ["public"],
        id_token_signing_alg_values_supported: ["RS256"],
        token_endpoint_auth_methods_supported: ["client_secret_post"],
        code_challenge_methods_supported: ["S256"],
        scopes_supported: ["openid", "email", "profile"],
      }),
    );
    return;
  }
  if (url.pathname === "/jwks") {
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify({ keys: [jwk] }));
    return;
  }
  if (url.pathname === "/authorize") {
    const q = url.searchParams;
    if (q.get("client_id") !== CLIENT_ID || q.get("code_challenge_method") !== "S256") {
      res.statusCode = 400;
      res.end("bad authorize request");
      return;
    }
    const code = crypto.randomBytes(24).toString("base64url");
    codes.set(code, {
      challenge: q.get("code_challenge"),
      nonce: q.get("nonce"),
      redirectUri: q.get("redirect_uri"),
    });
    const back = new URL(q.get("redirect_uri"));
    back.searchParams.set("code", code);
    back.searchParams.set("state", q.get("state"));
    res.statusCode = 302;
    res.setHeader("location", back.toString());
    res.end();
    return;
  }
  if (url.pathname === "/token" && req.method === "POST") {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const p = new URLSearchParams(body);
      const grant = codes.get(p.get("code"));
      const verifier = p.get("code_verifier") || "";
      const expected = grant
        ? crypto.createHash("sha256").update(verifier).digest("base64url")
        : null;
      if (
        !grant ||
        p.get("grant_type") !== "authorization_code" ||
        p.get("client_id") !== CLIENT_ID ||
        p.get("client_secret") !== CLIENT_SECRET ||
        expected !== grant.challenge ||
        p.get("redirect_uri") !== grant.redirectUri
      ) {
        res.statusCode = 400;
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ error: "invalid_grant" }));
        return;
      }
      codes.delete(p.get("code"));
      const now = Math.floor(Date.now() / 1000);
      const claims = {
        iss: ISSUER,
        sub: `sub-${crypto.createHash("sha256").update(scenario.email).digest("hex").slice(0, 16)}`,
        aud: CLIENT_ID,
        iat: now,
        exp: now + 300,
        nonce: scenario.wrongNonce ? "forged-nonce-value" : grant.nonce,
        email_verified: scenario.emailVerified,
        name: scenario.name,
      };
      if (scenario.includeEmail) claims.email = scenario.email;
      res.setHeader("content-type", "application/json");
      res.end(
        JSON.stringify({
          access_token: crypto.randomBytes(16).toString("base64url"),
          token_type: "Bearer",
          expires_in: 300,
          scope: "openid email profile",
          id_token: signIdToken(claims),
        }),
      );
    });
    return;
  }
  res.statusCode = 404;
  res.end("not found");
});

/* ---------------- drill helpers ---------------- */

function cookieFrom(res, name) {
  const all = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
  const hit = all.find((c) => c.startsWith(`${name}=`));
  return hit ? hit.split(";")[0] : null;
}

function errSlugFrom(location) {
  // APP_BASE/app/#/login?err=<slug>
  const m = /err=([^&]+)/.exec(location || "");
  return m ? decodeURIComponent(m[1]) : null;
}

/** Run /start → authorize → /callback. Returns { finalLocation, sessionCookie, stateCookieCleared, status }. */
async function runFlow({ provider = "oidc", omitCookie = false, forgeState = false, crossCallback = null } = {}) {
  const start = await fetch(`${API}/api/v1/auth/oauth/${provider}/start`, { redirect: "manual" });
  if (start.status !== 302) return { startStatus: start.status, startLocation: start.headers.get("location") };
  const authUrl = start.headers.get("location");
  if (!authUrl.startsWith(ISSUER)) {
    return { startStatus: 302, startLocation: authUrl };
  }
  const stateCookie = cookieFrom(start, "av_oauth_state");
  const authz = await fetch(authUrl, { redirect: "manual" });
  let cbUrl = new URL(authz.headers.get("location"));
  if (forgeState) cbUrl.searchParams.set("state", "forged-state-value");
  if (crossCallback) {
    const orig = cbUrl;
    cbUrl = new URL(orig.toString().replace(`/oauth/${provider}/callback`, `/oauth/${crossCallback}/callback`));
  }
  const cb = await fetch(cbUrl, {
    redirect: "manual",
    headers: omitCookie ? {} : { cookie: stateCookie },
  });
  const clearedState = (cb.headers.getSetCookie?.() || []).some(
    (c) => c.startsWith("av_oauth_state=") && /max-age=0|expires=thu, 01 jan 1970/i.test(c),
  );
  return {
    startStatus: 302,
    authUrl,
    stateCookie,
    status: cb.status,
    finalLocation: cb.headers.get("location"),
    sessionCookie: cookieFrom(cb, "av_session"),
    stateCookieCleared: clearedState,
  };
}

async function me(sessionCookie) {
  const r = await fetch(`${API}/api/v1/auth/me`, { headers: { cookie: sessionCookie } });
  return { status: r.status, body: r.status === 200 ? await r.json() : null };
}

/* ---------------- main ---------------- */

async function main() {
  await new Promise((resolve) => idp.listen(IDP_PORT, "127.0.0.1", resolve));
  console.log(`mock IdP listening on ${ISSUER}`);

  // --idp-only: keep the mock IdP up for interactive/browser drills
  // (the SPA click-through needs a live issuer). Ctrl-C to stop.
  if (process.argv.includes("--idp-only")) {
    console.log("idp-only mode: serving discovery/authorize/token/jwks until killed");
    return;
  }

  const health = await fetch(`${API}/healthz`).then((r) => r.ok, () => false);
  if (!health) {
    console.error(`API under test not reachable at ${API} — boot it first (see header comment).`);
    process.exit(2);
  }

  console.log("[1] provider discovery");
  const provs = await fetch(`${API}/api/v1/auth/oauth/providers`).then((r) => r.json());
  const oidcProv = (provs.providers || []).find((p) => p.id === "oidc");
  check("providers lists generic oidc", !!oidcProv, provs);
  check("display name from env", oidcProv?.displayName === "Keycloak", oidcProv);

  console.log("[2] /start contract");
  const start = await fetch(`${API}/api/v1/auth/oauth/oidc/start`, { redirect: "manual" });
  const authUrl = new URL(start.headers.get("location"));
  check("302 to issuer authorize", start.status === 302 && authUrl.origin === ISSUER && authUrl.pathname === "/authorize");
  check("PKCE S256", authUrl.searchParams.get("code_challenge_method") === "S256" && (authUrl.searchParams.get("code_challenge") || "").length >= 40);
  check("state + nonce present", !!authUrl.searchParams.get("state") && !!authUrl.searchParams.get("nonce"));
  check("redirect_uri is API callback", authUrl.searchParams.get("redirect_uri") === `${API}/api/v1/auth/oauth/oidc/callback`);
  const sc = cookieFrom(start, "av_oauth_state");
  check("signed state cookie set", !!sc && sc.includes("."));

  console.log("[3] happy path: JIT signup");
  const flow1 = await runFlow();
  check("callback 302 to overview", flow1.status === 302 && flow1.finalLocation === `${APP_BASE}/app/#/overview`, flow1);
  check("session cookie minted", !!flow1.sessionCookie);
  check("state cookie cleared", flow1.stateCookieCleared === true, flow1);
  const me1 = await me(flow1.sessionCookie);
  check("/me works", me1.status === 200 && me1.body?.user?.email === scenario.email, me1);
  check("JIT org named after domain", me1.body?.org?.name === "oidc-drill", me1.body?.org);
  check("JIT user is owner", me1.body?.org?.role === "owner", me1.body?.org);

  console.log("[4] audit trail");
  const audit = await fetch(`${API}/api/v1/audit?limit=50`, { headers: { cookie: flow1.sessionCookie } }).then((r) => r.json());
  const events = (audit.entries || audit.items || []).map((e) => e.event);
  check("org.created audited", events.includes("org.created"), events);
  check("auth.oauth_signin audited", events.includes("auth.oauth_signin"), events);
  const signinRow = (audit.entries || audit.items || []).find((e) => e.event === "auth.oauth_signin");
  check("audit provider metadata = oidc", signinRow?.metadata?.provider === "oidc", signinRow);

  console.log("[5] repeat login: no duplicate JIT");
  const flow2 = await runFlow();
  const me2 = await me(flow2.sessionCookie);
  check("second login works", me2.status === 200, flow2);
  check("same user id", me2.body?.user?.id === me1.body?.user?.id);
  check("same org id", me2.body?.org?.id === me1.body?.org?.id);

  console.log("[6] unverified email refused");
  scenario.emailVerified = false;
  const flowUnv = await runFlow();
  check("redirected with err slug", errSlugFrom(flowUnv.finalLocation) === "oauth_email_not_verified", flowUnv);
  check("no session minted", !flowUnv.sessionCookie);
  scenario.emailVerified = true;

  console.log("[7] missing email claim refused");
  scenario.includeEmail = false;
  const flowNoMail = await runFlow();
  check("err=oauth_no_email_in_id_token", errSlugFrom(flowNoMail.finalLocation) === "oauth_no_email_in_id_token", flowNoMail);
  check("no session minted", !flowNoMail.sessionCookie);
  scenario.includeEmail = true;

  console.log("[8] hostile 1000-char name capped");
  scenario.email = "capped.name@oidc-drill.example";
  scenario.name = "N".repeat(1000);
  const flowCap = await runFlow();
  const meCap = await me(flowCap.sessionCookie);
  const dn = meCap.body?.user?.displayName || "";
  check("displayName capped at 200", meCap.status === 200 && dn.length === 200, { len: dn.length });
  scenario.name = "Drill User";
  scenario.email = "jit.user@oidc-drill.example";

  console.log("[9] state-cookie attacks");
  const flowNoCookie = await runFlow({ omitCookie: true });
  check("no cookie → oauth_missing_state_cookie", errSlugFrom(flowNoCookie.finalLocation) === "oauth_missing_state_cookie", flowNoCookie);
  const flowForged = await runFlow({ forgeState: true });
  check("forged state → oauth_exchange_failed", errSlugFrom(flowForged.finalLocation) === "oauth_exchange_failed", flowForged);

  console.log("[10] wrong nonce in id_token");
  scenario.wrongNonce = true;
  const flowNonce = await runFlow();
  check("nonce mismatch → oauth_exchange_failed", errSlugFrom(flowNonce.finalLocation) === "oauth_exchange_failed", flowNonce);
  check("no session minted", !flowNonce.sessionCookie);
  scenario.wrongNonce = false;

  console.log("[11] provider routing edges");
  const gStart = await fetch(`${API}/api/v1/auth/oauth/google/start`, { redirect: "manual" });
  check("google unconfigured → not_configured", errSlugFrom(gStart.headers.get("location")) === "oauth_provider_not_configured");
  const badStart = await fetch(`${API}/api/v1/auth/oauth/nosuch/start`, { redirect: "manual" });
  check("unknown provider → not_found", errSlugFrom(badStart.headers.get("location")) === "oauth_provider_not_found");
  const flowCross = await runFlow({ crossCallback: "google" });
  check("oidc cookie on google callback → provider_mismatch", errSlugFrom(flowCross.finalLocation) === "oauth_provider_mismatch", flowCross);

  console.log("[12] MFA gate: passkey holder refused OAuth bypass");
  if (!PG_CONTAINER) {
    console.log("  SKIP (set PG_CONTAINER to run — needs a seeded WebAuthn credential row)");
  } else {
    const uid = me1.body.user.id;
    const seedSql = `INSERT INTO "webauthn_credentials" ("id","userId","credentialId","publicKey","counter","transports","label") VALUES ('drill-mfa-cred','${uid}',decode('ZHJpbGwtY3JlZA==','base64'),decode('ZHJpbGwtcGs=','base64'),0,'usb','drill seed')`;
    execFileSync("docker", ["exec", PG_CONTAINER, "psql", "-U", PG_USER, "-d", PG_DB, "-c", seedSql], { stdio: "pipe" });
    try {
      const flowMfa = await runFlow();
      check("passkey user → mfa_required_use_password_login", errSlugFrom(flowMfa.finalLocation) === "mfa_required_use_password_login", flowMfa);
      check("no session minted", !flowMfa.sessionCookie);
      const auditMfa = await fetch(`${API}/api/v1/audit?limit=20`, { headers: { cookie: flow1.sessionCookie } }).then((r) => r.json());
      const evs = (auditMfa.entries || auditMfa.items || []).map((e) => e.event);
      check("refusal audited", evs.includes("auth.oauth_refused_mfa_required"), evs);
    } finally {
      execFileSync("docker", ["exec", PG_CONTAINER, "psql", "-U", PG_USER, "-d", PG_DB, "-c", `DELETE FROM "webauthn_credentials" WHERE "id"='drill-mfa-cred'`], { stdio: "pipe" });
    }
  }

  console.log("[13] pre-hijack gate: unverified password account refuses OIDC link");
  {
    // An attacker pre-registers the victim's address by password
    // (signup never verifies the mailbox). The victim's later SSO
    // sign-in must NOT be linked into that account.
    const victim = "prehijack.victim@oidc-drill.example";
    const su = await fetch(`${API}/api/v1/auth/signup`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Origin: APP_BASE, "Sec-Fetch-Site": "same-origin" },
      body: JSON.stringify({ email: victim, password: "attacker-chosen-pw-1", orgName: "Attacker Org" }),
    });
    check("pre-hijack: attacker signup 201", su.status === 201, su.status);
    scenario.email = victim;
    const flowHijack = await runFlow();
    check("unverified account → oauth_email_unverified_use_password_login", errSlugFrom(flowHijack.finalLocation) === "oauth_email_unverified_use_password_login", flowHijack);
    check("no session minted for the hijack", !flowHijack.sessionCookie);
    if (PG_CONTAINER) {
      // Positive path: once the mailbox is proven (reset-confirm /
      // change-email confirm set emailVerifiedAt), the link works.
      execFileSync("docker", ["exec", PG_CONTAINER, "psql", "-U", PG_USER, "-d", PG_DB, "-c",
        `UPDATE "users" SET "emailVerifiedAt"=NOW() WHERE "email"='${victim}'`], { stdio: "pipe" });
      const flowVerified = await runFlow();
      check("verified account links via OIDC", !!flowVerified.sessionCookie, flowVerified.finalLocation);
    } else {
      console.log("  SKIP positive path (set PG_CONTAINER to flip emailVerifiedAt)");
    }
    scenario.email = "jit.user@oidc-drill.example";
  }

  console.log("[cleanup] delete drill users");
  if (PG_CONTAINER) {
    // OAuth-JIT users have random passwords — the danger-zone flow
    // needs password step-up, so sweep the drill rows directly.
    for (const email of ["jit.user@oidc-drill.example", "capped.name@oidc-drill.example", "prehijack.victim@oidc-drill.example"]) {
      execFileSync("docker", [
        "exec", PG_CONTAINER, "psql", "-U", PG_USER, "-d", PG_DB, "-c",
        `DELETE FROM "orgs" WHERE "id" IN (SELECT m."orgId" FROM "memberships" m JOIN "users" u ON u."id"=m."userId" WHERE u."email"='${email}'); DELETE FROM "users" WHERE "email"='${email}'`,
      ], { stdio: "pipe" });
    }
    console.log("  swept drill users + orgs via psql");
  } else {
    console.log("  SKIP (set PG_CONTAINER to sweep drill users)");
  }

  idp.close();
  console.log(`\n${failed === 0 ? "✅" : "❌"}  OIDC drill: ${passed} passed, ${failed} failed`);
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
