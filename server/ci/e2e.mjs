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
    status: "sealed",
    policyVersion: 1,
    openedAt,
    closedAt: new Date().toISOString(),
  });
  check("ingest session", sessionRes.status === 200, JSON.stringify(sessionRes.data));

  const now = new Date().toISOString();
  const evRes = await ingest("/api/v1/ingest/events", [
    { sessionExternalId:"sess_e2e_"+rand, seq:1, kind:"sys", tag:"start", body:"session opened", occurredAt: now },
    { sessionExternalId:"sess_e2e_"+rand, seq:2, kind:"tool", tag:"TOOL ✓ allow", body:"search_inventory()", occurredAt: now, addToolsAllowed: 1, addCostUsdMicros: 45000 },
    { sessionExternalId:"sess_e2e_"+rand, seq:3, kind:"tool", tag:"TOOL BLOCKED", body:"create_po() vendor not allowlisted", occurredAt: now, addToolsBlocked: 1, addBlockedPayoutUsdMicros: 8400000000 },
    { sessionExternalId:"sess_e2e_"+rand, seq:4, kind:"sys", tag:"end", body:"session sealed", occurredAt: now },
  ]);
  check("ingest events", evRes.status === 200, JSON.stringify(evRes.data));

  const ov = await ds.getOverview();
  check("overview sessions=1", ov.sessions === 1, "got="+ov.sessions);
  check("overview toolsAllowed=1", ov.toolsAllowed === 1);
  check("overview toolsBlocked=1", ov.toolsBlocked === 1);
  check("overview blockedSpendUsd>0", parseFloat(ov.blockedSpendUsd) > 0, "$"+ov.blockedSpendUsd);
  check("overview llmSpendUsd", parseFloat(ov.llmSpendUsd) > 0, "$"+ov.llmSpendUsd);
  check("overview deployments=1", ov.deployments === 1);

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

  // Rotate
  const rot = await ds.rotateDeploymentToken(dep.deployment.id);
  check("rotate returns token", !!rot.ingestToken);

  // Delete
  await ds.deleteDeployment(dep.deployment.id);
  const depsAfter = await ds.listDeployments();
  check("delete removes", depsAfter.length === 0);

  await ds.logout();
  const s2 = await ds.getSession();
  check("logout clears session", s2 === null);

  let ok=0, fail=0;
  results.forEach(r => { if (r.ok){ok++;console.log("PASS",r.n,r.x||"");} else {fail++;console.log("FAIL",r.n,r.x||"");} });
  console.log(`\n${ok}/${ok+fail} e2e checks passed`);
  process.exit(fail>0?1:0);
} catch (e) {
  console.error("threw:", e.message, e.stack.split("\n").slice(0,5).join("\n"), e.data||"");
  process.exit(1);
}
