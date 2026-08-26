/**
 * Invite hardening drill. Runs 5 attack + edge-case scenarios against
 * the /members and /members/invites routes.
 */

const API = "http://127.0.0.1:4346";
const SPA_ORIGIN = "http://127.0.0.1:8988";

async function signup(email, orgName) {
  const res = await fetch(`${API}/api/v1/auth/signup`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Origin: SPA_ORIGIN, "Sec-Fetch-Site": "same-origin" },
    body: JSON.stringify({ email, password: "correcthorse42x", orgName }),
  });
  if (res.status !== 201) throw new Error("signup " + res.status);
  const set = res.headers.get("set-cookie") ?? "";
  const cookie = /(av_session=[^;]+)/.exec(set)?.[1];
  return { cookie };
}

async function invite(cookie, email, role = "member") {
  const res = await fetch(`${API}/api/v1/members/invites`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json", Origin: SPA_ORIGIN,
      "Sec-Fetch-Site": "same-origin", Cookie: cookie,
    },
    body: JSON.stringify({ email, role }),
  });
  const body = await res.json();
  if (res.status !== 201) throw new Error("invite " + res.status + " " + JSON.stringify(body));
  const url = body.invite.acceptUrlDev ?? "";
  const hashQs = url.split("#/")[1]?.split("?")[1] ?? "";
  const params = new URLSearchParams(hashQs);
  return { inviteId: body.invite.id, token: params.get("token") ?? "" };
}

async function accept(email, token, password = "sneaky12345678") {
  return fetch(`${API}/api/v1/members/invites/accept`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Origin: SPA_ORIGIN, "Sec-Fetch-Site": "same-origin" },
    body: JSON.stringify({ email, token, password }),
  });
}

async function main() {
  const results = [];

  // ============ Setup ============
  const { cookie: aliceCookie } = await signup(`alice-${Date.now()}@inv-hard.example`, "InvHardOrg");
  const aliceMe = await (await fetch(`${API}/api/v1/auth/me`, { headers: { Cookie: aliceCookie, Origin: SPA_ORIGIN } })).json();
  const orgId = aliceMe.org.id;

  // ============ 1. Expired invite ============
  console.log("[1] Expired invite");
  const bobEmail = `bob-${Date.now()}@inv-hard.example`;
  const bobInv = await invite(aliceCookie, bobEmail);
  // Force expiresAt into the past.
  const { execSync } = await import("node:child_process");
  execSync(`docker exec av-pg-r44 psql -U avtest -d avtest -c "UPDATE invites SET \\"expiresAt\\" = NOW() - INTERVAL '1 hour' WHERE id='${bobInv.inviteId}';"`);
  const expiredRes = await accept(bobEmail, bobInv.token);
  const expiredBody = await expiredRes.text();
  results.push({ drill: "expired-invite", status: expiredRes.status, expect: 401, body: expiredBody.slice(0, 80) });

  // Restore expiresAt for the next drills.
  execSync(`docker exec av-pg-r44 psql -U avtest -d avtest -c "UPDATE invites SET \\"expiresAt\\" = NOW() + INTERVAL '1 hour' WHERE id='${bobInv.inviteId}';"`);

  // ============ 2. Revoked invite ============
  console.log("[2] Revoked invite");
  await fetch(`${API}/api/v1/members/invites/${bobInv.inviteId}`, {
    method: "DELETE",
    headers: { Cookie: aliceCookie, Origin: SPA_ORIGIN, "Sec-Fetch-Site": "same-origin" },
  });
  const revokedRes = await accept(bobEmail, bobInv.token);
  results.push({ drill: "revoked-invite", status: revokedRes.status, expect: 401 });

  // ============ 3. Single-use replay ============
  console.log("[3] Accept token single-use");
  // Fresh invite for a NEW user, accept it, then replay.
  const carolEmail = `carol-${Date.now()}@inv-hard.example`;
  const carolInv = await invite(aliceCookie, carolEmail);
  const first = await accept(carolEmail, carolInv.token, "carolpwd12345678");
  console.log("  first accept:", first.status);
  const replay = await accept(carolEmail, carolInv.token, "carolpwd12345678");
  results.push({ drill: "accept-replay", status: replay.status, expect: 401 });

  // ============ 4. Member cannot invite/revoke ============
  console.log("[4] Member cannot invite/revoke");
  // Carol is now a member. Log carol in.
  const carolLogin = await fetch(`${API}/api/v1/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Origin: SPA_ORIGIN, "Sec-Fetch-Site": "same-origin" },
    body: JSON.stringify({ email: carolEmail, password: "carolpwd12345678" }),
  });
  const carolCookie = /(av_session=[^;]+)/.exec(carolLogin.headers.get("set-cookie") ?? "")?.[1];
  const carolInvite = await fetch(`${API}/api/v1/members/invites`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json", Origin: SPA_ORIGIN,
      "Sec-Fetch-Site": "same-origin", Cookie: carolCookie,
    },
    body: JSON.stringify({ email: `bogus-${Date.now()}@inv-hard.example`, role: "member" }),
  });
  results.push({ drill: "member-cannot-invite", status: carolInvite.status, expect: 403 });

  // Alice sends a fresh invite so carol can try to revoke it.
  const daveInv = await invite(aliceCookie, `dave-${Date.now()}@inv-hard.example`);
  const carolRevoke = await fetch(`${API}/api/v1/members/invites/${daveInv.inviteId}`, {
    method: "DELETE",
    headers: { Cookie: carolCookie, Origin: SPA_ORIGIN, "Sec-Fetch-Site": "same-origin" },
  });
  results.push({ drill: "member-cannot-revoke", status: carolRevoke.status, expect: 403 });

  // ============ 5. Last-owner protection ============
  console.log("[5] Cannot demote / remove last owner");
  // Alice tries to demote herself (self-role change refused up-front).
  const selfDemote = await fetch(`${API}/api/v1/members/${aliceMe.user.id}`, {
    method: "PATCH",
    headers: {
      "Content-Type": "application/json", Origin: SPA_ORIGIN,
      "Sec-Fetch-Site": "same-origin", Cookie: aliceCookie,
    },
    body: JSON.stringify({ role: "member" }),
  });
  results.push({ drill: "self-demote-refused", status: selfDemote.status, expect: 400 });

  // Alice can't be removed because she's the last owner.
  const removeLastOwner = await fetch(`${API}/api/v1/members/${aliceMe.user.id}`, {
    method: "DELETE",
    headers: {
      Origin: SPA_ORIGIN, "Sec-Fetch-Site": "same-origin", Cookie: aliceCookie,
    },
  });
  results.push({ drill: "last-owner-cant-leave", status: removeLastOwner.status, expect: 400 });

  console.log("\n============ RESULTS ============");
  let allPass = true;
  for (const r of results) {
    const ok = r.status === r.expect;
    if (!ok) allPass = false;
    console.log(`${ok ? "✅" : "❌"} ${r.drill}: got ${r.status}, expected ${r.expect}${r.body ? " — " + r.body : ""}`);
  }
  if (!allPass) process.exit(1);
  console.log("\n✅  All invite hardening drills PASSED");
}

main().catch((err) => {
  console.error("❌", err);
  process.exit(1);
});
