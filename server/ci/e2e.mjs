import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
// Repo layout: <root>/server/ci/e2e.mjs — datasource.js is two levels up.
const datasourcePath = resolve(__dirname, "..", "..", "docs", "app", "datasource.js");

let cookies = {};
const origFetch = globalThis.fetch;
globalThis.fetch = async (url, opts={}) => {
  opts.headers = { ...(opts.headers||{}) };
  const cookieHeader = Object.entries(cookies).map(([k,v])=>`${k}=${v}`).join("; ");
  if (cookieHeader) opts.headers.Cookie = cookieHeader;
  const res = await origFetch(url, opts);
  const setCookie = res.headers.getSetCookie ? res.headers.getSetCookie() : [res.headers.get("set-cookie")].filter(Boolean);
  for (const c of setCookie) {
    const [pair] = c.split(";");
    const [k, v] = pair.split("=");
    cookies[k] = v;
  }
  return res;
};

const src = readFileSync(datasourcePath, "utf8");
globalThis.window = { MOCK_MODE: false, API_BASE: "http://127.0.0.1:8985" };
new Function(src)();
const ds = globalThis.window.dataSource;

const rand = Math.random().toString(36).slice(2,8);
const email = `e2e-${rand}@test.dev`;
const results = [];
const check = (n, c, x) => results.push({n, ok:!!c, x});

try {
  await ds.signup({email, password:"correcthorse", orgName:"E2E Co"});
  check("signup", true);

  const me = await ds.getSession();
  check("session persisted", me && me.user.email === email, me?.user?.email);

  const dep = await ds.createDeployment({name:"e2e-prod", environment:"production", region:"us-west-1"});
  check("createDeployment", !!dep.ingestToken && !!dep.deployment.id, dep.deployment.id);
  check("createDeployment.deployment.name", dep.deployment.name === "e2e-prod");

  const deps = await ds.listDeployments();
  check("listDeployments has 1", deps.length === 1);
  check("normalized dep has environment", deps[0].environment === "production");
  check("normalized dep has ingestTokenHint", !!deps[0].ingestTokenHint, deps[0].ingestTokenHint);
  check("normalized dep has status", !!deps[0].status, deps[0].status);

  // Ingest session
  const openedAt = new Date().toISOString();
  const ingest = async (path, body) => {
    const r = await origFetch(`http://127.0.0.1:8985${path}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${dep.ingestToken}`,
        "X-AV-Deployment": dep.deployment.id,
      },
      body: JSON.stringify(body),
    });
    return { status: r.status, data: r.status < 400 ? await r.json() : await r.text() };
  };

  const sessionRes = await ingest("/api/v1/ingest/sessions", {
    externalId: "sess_e2e_"+rand,
    agent: "e2e-agent",
    workflow: "signed",
    status: "live",
    policyVersion: 1,
    openedAt,
    closedAt: new Date().toISOString(),
  });
  check("ingest session", sessionRes.status === 200, JSON.stringify(sessionRes.data));

  const now = new Date().toISOString();
  const evRes = await ingest("/api/v1/ingest/events", [
    { sessionExternalId:"sess_e2e_"+rand, seq:1, kind:"sys", tag:"start", body:"session opened", occurredAt: now },
    { sessionExternalId:"sess_e2e_"+rand, seq:2, kind:"tool", tag:"TOOL ✓ allow", body:"search_inventory()", occurredAt: now, addToolsAllowed: 1, addCostUsdMicros: 45000, policyName: "e2e.vendor_allowlist" },
    { sessionExternalId:"sess_e2e_"+rand, seq:3, kind:"block", tag:"TOOL BLOCKED", body:"create_po() vendor not allowlisted", occurredAt: now, addToolsBlocked: 1, addBlockedPayoutUsdMicros: 8400000000, policyName: "e2e.vendor_allowlist" },
    { sessionExternalId:"sess_e2e_"+rand, seq:4, kind:"sys", tag:"end", body:"session sealed", occurredAt: now },
  ]);
  check("ingest events", evRes.status === 200, JSON.stringify(evRes.data));

  // Seal via the sanctioned lifecycle: register the daemon's signing
  // pubkey, then post a signed receipt. Direct status:"sealed" session
  // ingests are refused (cannot_direct_seal_session) since the
  // R141/R144/R151 hardening — a compromised ingest token must not be
  // able to force-seal a live session and censor the rest of its trail.
  const { generateKeyPairSync, sign: edSign, createHash } = await import("node:crypto");
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pubRaw = publicKey.export({ type: "spki", format: "der" }).subarray(-32);
  const pkRes = await ingest("/api/v1/ingest/pubkey", { publicKeyHex: pubRaw.toString("hex"), daemonVersion: "0.1.0-e2e" });
  check("ingest pubkey", pkRes.status === 200, JSON.stringify(pkRes.data));
  // Daemon version round-trips into the deployments list.
  const depsAfterPubkey = await ds.listDeployments();
  check("deployment reports daemon version", depsAfterPubkey[0].version === "0.1.0-e2e", depsAfterPubkey[0].version);
  const receiptBody = JSON.stringify({ v: 2, session: "sess_e2e_"+rand, eventCount: 4 });
  const rcptRes = await ingest("/api/v1/ingest/receipts", {
    sessionExternalId: "sess_e2e_"+rand,
    receiptId: "rcpt_e2e_"+rand,
    body: receiptBody,
    sigB64: edSign(null, Buffer.from(receiptBody), privateKey).toString("base64"),
    keyIdHex: createHash("sha256").update(pubRaw).digest("hex").slice(0, 32),
    eventCount: 4,
    issuedAt: new Date().toISOString(),
    stopReason: "normal",
    stopReasonId: 0,
  });
  check("ingest receipt seals session", rcptRes.status === 200, JSON.stringify(rcptRes.data));

  const ov = await ds.getOverview();
  check("overview sessions=1", ov.sessions === 1, "got="+ov.sessions);
  check("overview toolsAllowed=1", ov.toolsAllowed === 1);
  check("overview toolsBlocked=1", ov.toolsBlocked === 1);
  check("overview blockedSpendUsd>0", parseFloat(ov.blockedSpendUsd) > 0, "$"+ov.blockedSpendUsd);
  check("overview llmSpendUsd", parseFloat(ov.llmSpendUsd) > 0, "$"+ov.llmSpendUsd);
  check("overview deployments=1", ov.deployments === 1);
  // R-series: /overview now returns real bucketed series in live mode
  // (was `series: null` — "hourly buckets not wired yet").
  check("overview series has 24 hourly buckets", Array.isArray(ov.series) && ov.series.length === 24, "len="+(ov.series||[]).length);
  const serAllowed = (ov.series||[]).reduce((a,b)=>a+b.allowed, 0);
  const serBlocked = (ov.series||[]).reduce((a,b)=>a+b.blocked, 0);
  check("overview series sums match aggregates", serAllowed === ov.toolsAllowed && serBlocked === ov.toolsBlocked, `allowed=${serAllowed} blocked=${serBlocked}`);
  check("overview series buckets labeled", (ov.series||[]).every(b => typeof b.label === "string" && b.label.length > 0));
  const ov7 = await ds.getOverview("7d");
  check("overview range=7d has 7 daily buckets", Array.isArray(ov7.series) && ov7.series.length === 7, "len="+(ov7.series||[]).length);

  const list = await ds.listSessions();
  check("listSessions has 1", list.sessions.length === 1);
  const first = list.sessions[0];
  check("session.startedAt normalized", !!first.startedAt);
  check("session.status normalized to completed", first.status === "completed", first.status);
  check("session.externalId", first.externalId === "sess_e2e_"+rand);
  check("session.costUsdMicros is string", typeof first.costUsdMicros === "string");

  const detail = await ds.getSessionById(first.id);
  check("detail has session", !!detail.session && !!detail.session.startedAt);
  check("detail has events", detail.events.length === 4, "n="+detail.events.length);
  const blocked = detail.events.find(e=>e.severity==="err");
  check("detail marks blocked event", !!blocked, blocked?.msg);

  // Policies — full CRUD through the real API (was mock-only).
  const created = await ds.createPolicy({ name: "e2e.vendor_allowlist", kind: "allowlist", scope: "tool.create_po", description: "e2e", body: "effect = block" });
  check("policy create returns id", !!created.id && created.enabled === true, created.id);
  const pols = await ds.listPolicies();
  check("policy list has 1", pols.length === 1 && pols[0].name === "e2e.vendor_allowlist");
  // Attribution: the two events above carried policyName matching this
  // policy — real 24h counters, not fixtures.
  check("policy counters from attributed events", pols[0].hits24h === 2 && pols[0].blocks24h === 1, `hits=${pols[0].hits24h} blocks=${pols[0].blocks24h}`);
  const toggled = await ds.togglePolicy(created.id);
  check("policy toggle disables", toggled.enabled === false);
  const fetched = await ds.getPolicy(created.id);
  check("policy get reflects toggle", fetched.enabled === false && fetched.body === "effect = block");
  let dupCode = "";
  try { await ds.createPolicy({ name: "e2e.vendor_allowlist" }); } catch (e) { dupCode = e.errorCode || e.message; }
  check("policy duplicate name 409", dupCode === "policy_name_in_use", dupCode);

  // Rotate
  const rot = await ds.rotateDeploymentToken(dep.deployment.id);
  check("rotate returns token", !!rot.ingestToken);

  // API key rename
  const k1 = await ds.createApiKey("e2e-key");
  check("create key", !!k1.key.id);
  const kRenamed = await ds.renameApiKey(k1.key.id, "e2e-key-renamed");
  check("key rename", kRenamed && kRenamed.name === "e2e-key-renamed");
  let kBlank = "";
  try { await ds.renameApiKey(k1.key.id, "   "); } catch (e) { kBlank = e.errorCode || e.message; }
  check("key rename blank 400", kBlank === "invalid_input", kBlank);
  let kGhost = "";
  try { await ds.renameApiKey("cmnope000000000000000", "x"); } catch (e) { kGhost = e.errorCode || e.message; }
  check("key rename ghost 404", kGhost === "not_found", kGhost);
  await ds.revokeApiKey(k1.key.id);

  // Invite resend = upsert: same email re-invited answers 201 again
  const inv1 = await ds.inviteMember({ email: `resend-${rand}@test.dev`, role: "member" });
  check("invite created", !!inv1);
  const inv2 = await ds.inviteMember({ email: `resend-${rand}@test.dev`, role: "member" });
  check("invite resend (upsert) ok", !!inv2);
  const pend = (await ds.listInvites()).invites || [];
  check("resend keeps ONE pending row", pend.filter(i => i.email === `resend-${rand}@test.dev`).length === 1);
  await ds.revokeInvite(pend.find(i => i.email === `resend-${rand}@test.dev`).id);

  // Edit metadata: rename + environment flip; ID stays; guards
  const edited = await ds.updateDeployment(dep.deployment.id, { name: "e2e-prod-renamed", environment: "development" });
  check("deployment edit", edited && edited.name === "e2e-prod-renamed" && edited.environment === "development" && edited.id === dep.deployment.id);
  let emptyPatch = "";
  try { await ds.updateDeployment(dep.deployment.id, {}); } catch (e) { emptyPatch = e.errorCode || e.message; }
  check("deployment empty patch 400", emptyPatch === "invalid_input", emptyPatch);
  let badEnv = "";
  try { await ds.updateDeployment(dep.deployment.id, { environment: "qa" }); } catch (e) { badEnv = e.errorCode || e.message; }
  check("deployment bad env 400", badEnv === "invalid_input", badEnv);
  let ghostDep = "";
  try { await ds.updateDeployment("cmnope0000000000000000000", { name: "x" }); } catch (e) { ghostDep = e.errorCode || e.message; }
  check("deployment ghost 404", ghostDep === "not_found", ghostDep);

  // Sign out other devices: caller's cookie is re-minted and survives
  const lo = await ds.logoutOtherDevices();
  check("logout-all ok", lo && lo.ok === true);
  const meAfterLo = await ds.getSession();
  check("session survives logout-all", meAfterLo && meAfterLo.user.email === email, meAfterLo?.user?.email);

  // Delete: a deployment holding sealed receipts refuses a plain
  // DELETE (409 deployment_has_sealed_receipts) — assert the guard
  // fires, then force-delete exactly like the SPA's confirm flow.
  let refusedCode = "";
  try { await ds.deleteDeployment(dep.deployment.id); }
  catch (e) { refusedCode = (e && (e.errorCode || (e.data && (e.data.errorCode || e.data.error)) || e.message)) || ""; }
  check("plain delete refused (sealed receipts)", /sealed_receipts/.test(refusedCode), refusedCode);
  await ds.deleteDeployment(dep.deployment.id, { force: true });
  const depsAfter = await ds.listDeployments();
  check("force delete removes", depsAfter.length === 0);

  // Change password: step-up denials, weak/unchanged rejects, then the
  // real rotation — and prove the response re-mints THIS session's
  // cookie (subsequent authed call works despite the revocation fence).
  let cpWrong = "";
  try { await ds.changePassword({ currentPassword: "not-my-password", newPassword: "an-entirely-new-pw-1" }); }
  catch (e) { cpWrong = e.errorCode || e.message; }
  check("change-password wrong current 401", cpWrong === "invalid_password", cpWrong);
  let cpWeak = "";
  try { await ds.changePassword({ currentPassword: "correcthorse", newPassword: "short" }); }
  catch (e) { cpWeak = e.errorCode || e.message; }
  check("change-password weak new 400", cpWeak === "weak_password", cpWeak);
  let cpSame = "";
  try { await ds.changePassword({ currentPassword: "correcthorse", newPassword: "correcthorse" }); }
  catch (e) { cpSame = e.errorCode || e.message; }
  check("change-password unchanged 400", cpSame === "password_unchanged", cpSame);
  const cpOk = await ds.changePassword({ currentPassword: "correcthorse", newPassword: "rotated-e2e-pw-2026" });
  check("change-password succeeds", cpOk && cpOk.ok === true);
  const meAfterCp = await ds.getSession();
  check("session survives own rotation", meAfterCp && meAfterCp.user.email === email, meAfterCp?.user?.email);
  await ds.logout();
  // Wrong-credential logins answer 200 {mfaRequired:true} uniformly
  // (R85 F3 anti-oracle) — the OLD password must now take that path.
  const oldPwLogin = await ds.login({ email, password: "correcthorse" });
  check("old password refused after change", oldPwLogin && oldPwLogin.mfaRequired === true && !oldPwLogin.user, JSON.stringify(oldPwLogin));
  const reLogin = await ds.login({ email, password: "rotated-e2e-pw-2026" });
  check("new password logs in", reLogin && reLogin.user && reLogin.user.email === email);

  // Org rename + profile edits
  const renamed = await ds.renameOrg("E2E Renamed Co");
  check("org rename", renamed && renamed.name === "E2E Renamed Co");
  const meRenamed = await ds.getSession();
  check("rename reflected on /me", meRenamed.org.name === "E2E Renamed Co", meRenamed.org.name);
  check("slug stable across rename", meRenamed.org.slug && /e2e-co/.test(meRenamed.org.slug), meRenamed.org.slug);
  let badName = "";
  try { await ds.renameOrg("x".repeat(81)); } catch (e) { badName = e.errorCode || e.message; }
  check("rename 81 chars rejected", badName === "invalid_name", badName);
  const prof = await ds.updateProfile({ displayName: "E2E Tester" });
  check("displayName set", prof && prof.displayName === "E2E Tester");
  const profClear = await ds.updateProfile({ displayName: "" });
  check("displayName cleared", profClear && profClear.displayName === null, String(profClear && profClear.displayName));

  // Email change guards (full round-trip needs a mailbox — covered by
  // browser/curl drills; here we pin the API contract).
  let ceWrong = "";
  try { await ds.requestEmailChange({ newEmail: "other@test.dev", password: "not-my-password" }); }
  catch (e) { ceWrong = e.errorCode || e.message; }
  check("change-email wrong password 401", ceWrong === "invalid_password", ceWrong);
  let ceSame = "";
  try { await ds.requestEmailChange({ newEmail: email, password: "rotated-e2e-pw-2026" }); }
  catch (e) { ceSame = e.errorCode || e.message; }
  check("change-email same address 400", ceSame === "same_as_current", ceSame);
  const ceReq = await ds.requestEmailChange({ newEmail: `new-${rand}@test.dev`, password: "rotated-e2e-pw-2026" });
  check("change-email request 202", ceReq && ceReq.ok === true && ceReq.pendingEmail === `new-${rand}@test.dev`);
  const mePending = await ds.getSession();
  check("pendingEmail on /me", mePending.user.pendingEmail === `new-${rand}@test.dev`, mePending.user.pendingEmail);
  let ceBadTok = "";
  try { await ds.confirmEmailChange({ email, token: "AAAAAAAAAAAAAAAAAAAAAAAA" }); }
  catch (e) { ceBadTok = e.errorCode || e.message; }
  check("change-email bad token 401", ceBadTok === "invalid_token", ceBadTok);
  const ceCancel = await ds.cancelEmailChange();
  check("change-email cancel", ceCancel && ceCancel.ok === true);
  const meCancelled = await ds.getSession();
  check("pendingEmail cleared after cancel", meCancelled.user.pendingEmail == null, String(meCancelled.user.pendingEmail));

  // Admin MFA reset guards (the full lifecycle needs a WebAuthn
  // authenticator — browser drills cover it; here we pin the API's
  // guard rails, which need no credential).
  let selfMfa = "";
  try { await ds.resetMemberMfa(me.user.id, "rotated-e2e-pw-2026"); }
  catch (e) { selfMfa = e.errorCode || e.message; }
  check("reset-mfa self refused", selfMfa === "use_self_service_revoke", selfMfa);
  let ghostMfa = "";
  try { await ds.resetMemberMfa("cmnonexistent000000000000", "rotated-e2e-pw-2026"); }
  catch (e) { ghostMfa = e.errorCode || e.message; }
  check("reset-mfa unknown target 404", ghostMfa === "not_found", ghostMfa);
  let wrongPwMfa = "";
  try { await ds.resetMemberMfa("cmnonexistent000000000000", "not-my-password"); }
  catch (e) { wrongPwMfa = e.errorCode || e.message; }
  check("reset-mfa wrong password 401", wrongPwMfa === "invalid_password", wrongPwMfa);
  const mem = await ds.listMembers();
  check("members carry mfaEnrolled flag", mem.length === 1 && mem[0].mfaEnrolled === false, JSON.stringify(mem[0] && mem[0].mfaEnrolled));

  await ds.logout();
  const s2 = await ds.getSession();
  check("logout clears session", s2 === null);

  // Danger zone: single-org owner delete removes org AND account
  // (accountDeleted flag). Doubles as suite cleanup.
  await ds.login({ email, password: "rotated-e2e-pw-2026" });
  const del = await ds.deleteMyAccount("rotated-e2e-pw-2026");
  check("delete-account accountDeleted flag", del && del.ok === true && del.accountDeleted === true, JSON.stringify(del));
  const s3 = await ds.getSession();
  check("session gone after delete", s3 === null);

  let ok=0, fail=0;
  results.forEach(r => { if (r.ok){ok++;console.log("PASS",r.n,r.x||"");} else {fail++;console.log("FAIL",r.n,r.x||"");} });
  console.log(`\n${ok}/${ok+fail} e2e checks passed`);
  process.exit(fail>0?1:0);
} catch (e) {
  console.error("threw:", e.message, e.stack.split("\n").slice(0,5).join("\n"), e.data||"");
  process.exit(1);
}
