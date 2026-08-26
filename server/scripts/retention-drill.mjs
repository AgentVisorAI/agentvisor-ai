/*
 * Data retention drill.
 *
 * Scenarios:
 *   1. GET /org/retention -> default { 90, 365 }
 *   2. PATCH /org/retention as owner -> { 30, 30 } persists
 *   3. Member (carol) PATCH -> 403 forbidden
 *   4. Seed a session dated 100 days ago + a fresh session + audit
 *      rows spanning ancient+recent; sweep-now -> old ones purged
 *      but recent kept.
 *   5. Cross-org isolation: bob's sweep must not touch alice's rows.
 *   6. sessionRetentionDays=0 (keep forever) -> ancient session survives.
 *   7. Audit trail includes org.retention_updated + org.retention_swept.
 */
import { execSync } from "node:child_process";

const BASE = process.env.BASE ?? "http://127.0.0.1:8749";
const PG = process.env.PG_CONTAINER ?? "av-pg-r49";
const nonce = Math.random().toString(36).slice(2, 6);

async function jr(state, method, path, body) {
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
function fail(m) { console.log("❌", m); process.exit(1); }
function sql(q) {
  return execSync(`docker exec ${PG} psql -U av -d avdb -t -A -c "${q.replace(/"/g, "\\\"")}"`).toString().trim();
}

// Setup alice + bob (two orgs). Each will get a deployment + old/new sessions.
const alice = {}, bob = {};
{
  const r1 = await jr(alice, "POST", "/api/v1/auth/signup", {
    email: `alice+${nonce}@example.com`, password: "s3cret-drill-pw-1234!",
    orgName: `Alice-${nonce}`, displayName: "Alice",
  });
  if (r1.status !== 200 && r1.status !== 201) fail(`alice signup ${r1.status}`);
  const r2 = await jr(bob, "POST", "/api/v1/auth/signup", {
    email: `bob+${nonce}@example.com`, password: "s3cret-drill-pw-1234!",
    orgName: `Bob-${nonce}`, displayName: "Bob",
  });
  if (r2.status !== 200 && r2.status !== 201) fail(`bob signup ${r2.status}`);
}

const aliceMe = await (await jr(alice, "GET", "/api/v1/auth/me")).json();
const bobMe = await (await jr(bob, "GET", "/api/v1/auth/me")).json();
const aliceOrg = aliceMe.org?.id;
const bobOrg = bobMe.org?.id;
console.log(`Setup: alice=${aliceOrg} bob=${bobOrg}`);

// 1. Default retention
{
  const r = await jr(alice, "GET", "/api/v1/org/retention");
  if (r.status !== 200) fail(`GET retention ${r.status}`);
  const j = await r.json();
  if (j.retention.sessionRetentionDays !== 90) fail(`default session: ${JSON.stringify(j)}`);
  if (j.retention.auditRetentionDays !== 365) fail(`default audit: ${JSON.stringify(j)}`);
  console.log("✅ default retention: 90 / 365");
}

// 2. Owner PATCH
{
  const r = await jr(alice, "PATCH", "/api/v1/org/retention", {
    sessionRetentionDays: 30, auditRetentionDays: 30,
  });
  if (r.status !== 200) fail(`PATCH retention ${r.status}`);
  const j = await r.json();
  if (j.retention.sessionRetentionDays !== 30) fail(`after patch: ${JSON.stringify(j)}`);
  console.log("✅ owner PATCH retention -> 30 / 30");
}

// 3. Member 403
{
  const carol = {};
  const inv = await jr(alice, "POST", "/api/v1/members/invites", {
    email: `carol+${nonce}@example.com`, role: "member",
  });
  if (inv.status !== 201) fail(`invite carol ${inv.status}`);
  const invBody = await inv.json();
  const params = new URLSearchParams(invBody.invite.acceptUrlDev.split("?")[1] || "");
  const acc = await jr(carol, "POST", "/api/v1/members/invites/accept", {
    token: params.get("token"), email: params.get("email"),
    password: "s3cret-drill-pw-1234!", displayName: "Carol",
  });
  if (acc.status !== 200) fail(`carol accept ${acc.status}`);
  const r = await jr(carol, "PATCH", "/api/v1/org/retention", { sessionRetentionDays: 999 });
  if (r.status !== 403) fail(`carol PATCH ${r.status}, expected 403`);
  const r2 = await jr(carol, "POST", "/api/v1/org/retention/sweep-now");
  if (r2.status !== 403) fail(`carol sweep-now ${r2.status}, expected 403`);
  console.log("✅ member -> 403 on PATCH + sweep-now");
}

// 4. Seed data: ancient + recent session, ancient + recent audit
{
  // Create deployment first (via API to get orgId denorm right).
  const d = await jr(alice, "POST", "/api/v1/deployments", { name: "prod-" + nonce, environment: "production" });
  if (d.status !== 201) fail(`create deployment ${d.status}: ${await d.text()}`);
  const dep = (await d.json()).deployment;
  // Insert one ancient session (100 days ago) and one recent (yesterday).
  sql(`INSERT INTO sessions (id, "deploymentId", "orgId", "externalId", agent, status, "openedAt") VALUES ('sess_old_${nonce}', '${dep.id}', '${aliceOrg}', 'ext_old', 'demo-agent', 'sealed', NOW() - INTERVAL '100 days')`);
  sql(`INSERT INTO sessions (id, "deploymentId", "orgId", "externalId", agent, status, "openedAt") VALUES ('sess_new_${nonce}', '${dep.id}', '${aliceOrg}', 'ext_new', 'demo-agent', 'sealed', NOW() - INTERVAL '1 day')`);
  // Audit rows: ancient + recent
  sql(`INSERT INTO audit_entries (id, "orgId", event, "actorEmail", at) VALUES ('a_old_${nonce}', '${aliceOrg}', 'demo.old', 'demo@test', NOW() - INTERVAL '100 days')`);
  sql(`INSERT INTO audit_entries (id, "orgId", event, "actorEmail", at) VALUES ('a_new_${nonce}', '${aliceOrg}', 'demo.new', 'demo@test', NOW() - INTERVAL '1 day')`);

  const beforeSessions = sql(`SELECT COUNT(*) FROM sessions WHERE "orgId"='${aliceOrg}'`);
  const beforeAudit = sql(`SELECT COUNT(*) FROM audit_entries WHERE "orgId"='${aliceOrg}'`);
  if (parseInt(beforeSessions) < 2) fail(`seed sessions failed: ${beforeSessions}`);
  console.log(`Seed: sessions=${beforeSessions} audit=${beforeAudit}`);

  // Trigger sweep-now.
  const r = await jr(alice, "POST", "/api/v1/org/retention/sweep-now");
  if (r.status !== 200) fail(`sweep-now ${r.status}: ${await r.text()}`);
  const rj = await r.json();
  if (rj.result.sessionsPurged < 1) fail(`sessionsPurged=${rj.result.sessionsPurged}, expected >=1`);
  if (rj.result.auditPurged < 1) fail(`auditPurged=${rj.result.auditPurged}, expected >=1`);

  // Verify: ancient rows gone, recent rows kept.
  const oldSess = sql(`SELECT COUNT(*) FROM sessions WHERE id='sess_old_${nonce}'`);
  const newSess = sql(`SELECT COUNT(*) FROM sessions WHERE id='sess_new_${nonce}'`);
  const oldAudit = sql(`SELECT COUNT(*) FROM audit_entries WHERE id='a_old_${nonce}'`);
  const newAudit = sql(`SELECT COUNT(*) FROM audit_entries WHERE id='a_new_${nonce}'`);
  if (oldSess !== "0") fail(`old session survived: ${oldSess}`);
  if (newSess !== "1") fail(`new session purged! ${newSess}`);
  if (oldAudit !== "0") fail(`old audit survived: ${oldAudit}`);
  if (newAudit !== "1") fail(`new audit purged! ${newAudit}`);
  console.log(`✅ sweep: purged ${rj.result.sessionsPurged} sessions + ${rj.result.auditPurged} audit; recent kept`);
}

// 5. Cross-org isolation — seed data in bob's org, sweep alice, bob untouched.
{
  const d = await jr(bob, "POST", "/api/v1/deployments", { name: "bob-prod-" + nonce, environment: "production" });
  const dep = (await d.json()).deployment;
  sql(`INSERT INTO sessions (id, "deploymentId", "orgId", "externalId", agent, status, "openedAt") VALUES ('sess_bob_old_${nonce}', '${dep.id}', '${bobOrg}', 'ext_bob_old', 'demo-agent', 'sealed', NOW() - INTERVAL '365 days')`);
  await jr(alice, "POST", "/api/v1/org/retention/sweep-now");
  const bobOld = sql(`SELECT COUNT(*) FROM sessions WHERE id='sess_bob_old_${nonce}'`);
  if (bobOld !== "1") fail(`alice sweep touched bob: ${bobOld}`);
  console.log("✅ cross-org isolation: alice sweep left bob's rows alone");
}

// 6. sessionRetentionDays=0 -> keep forever
{
  await jr(alice, "PATCH", "/api/v1/org/retention", { sessionRetentionDays: 0 });
  // Insert one MORE ancient row
  const d = await jr(alice, "POST", "/api/v1/deployments", { name: "eternal-" + nonce, environment: "production" });
  const dep = (await d.json()).deployment;
  sql(`INSERT INTO sessions (id, "deploymentId", "orgId", "externalId", agent, status, "openedAt") VALUES ('sess_eternal_${nonce}', '${dep.id}', '${aliceOrg}', 'ext_eternal', 'demo-agent', 'sealed', NOW() - INTERVAL '1000 days')`);
  const r = await jr(alice, "POST", "/api/v1/org/retention/sweep-now");
  const rj = await r.json();
  if (rj.result.sessionsPurged !== 0) fail(`retention=0 still purged: ${rj.result.sessionsPurged}`);
  const survived = sql(`SELECT COUNT(*) FROM sessions WHERE id='sess_eternal_${nonce}'`);
  if (survived !== "1") fail(`retention=0: row purged anyway`);
  console.log("✅ retention=0 keeps ancient rows forever");
}

// 7. Audit trail entries
{
  const r = await jr(alice, "GET", "/api/v1/audit?limit=200");
  const j = await r.json();
  const events = j.entries.map((e) => e.event);
  if (!events.includes("org.retention_updated")) fail(`retention_updated missing: ${events}`);
  if (!events.includes("org.retention_swept")) fail(`retention_swept missing: ${events}`);
  console.log("✅ audit trail contains retention_updated + retention_swept");
}

console.log("\nAll 7 retention drill scenarios passed.");
