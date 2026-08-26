/*
 * Webhook adapter drill.
 *
 * Spins up 4 local receivers on different paths, each pretending to
 * be a different platform (Slack / Teams / Discord / raw). Each
 * endpoint URL is crafted so pickAdapter() returns the right adapter.
 *
 * Then registers 4 webhooks pointing at those URLs, fires one 'test'
 * event, and verifies the bodies each receiver got are shaped
 * correctly for their platform.
 *
 * For adapter detection, the URL host has to look real, but the
 * endpoint has to be routable. We use /etc/hosts-style mapping by
 * pointing the drill at fake hosts via a local DNS override. Simpler
 * approach: use the drill script as the local receiver and rely on
 * pickAdapter looking only at the URL string. So we craft URLs like
 * http://hooks.slack.com.local.test:PORT/path where the .local.test
 * TLD forces DNS to resolve via /etc/hosts.
 *
 * Even simpler: bypass the SSRF resolution by using URLs that end at
 * 127.0.0.1 explicitly BUT include a Host header override. Not
 * portable. Instead: monkey-patch pickAdapter for the drill by
 * setting `X-Test-Adapter: slack` header client-side... no, that's
 * ugly.
 *
 * Cleanest solution: expose a Node env var
 * WEBHOOK_ADAPTER_HOST_OVERRIDE that treats /slack, /teams, /discord
 * path prefixes on the local URL as if they were the real hosts.
 * Adding it just for the drill inflates the surface — instead we
 * use a hostfile-independent trick: point the URL at
 * hooks.slack.com but override DNS resolution to 127.0.0.1 via
 * Node's `dns.setDefaultResultOrder` doesn't help either.
 *
 * Concrete approach: our SSRF guard rejects localhost / private IPs.
 * BUT it also rejects any DNS name that resolves to those. So we
 * cannot point hooks.slack.com at 127.0.0.1 via /etc/hosts.
 *
 * Simplest solution: register 4 webhooks with hostnames like
 * hooks.slack.com/services/X (real hostname, real DNS, unreachable).
 * Fire the test event. Verify the DELIVERY row's `payload` column
 * (stored pre-send) reflects the correctly-formatted body. That
 * proves pickAdapter + formatForAdapter picked the right shape,
 * without any real network round-trip.
 */
import { execSync } from "node:child_process";
import { writeFileSync, unlinkSync } from "node:fs";

const BASE = process.env.BASE ?? "http://127.0.0.1:8752";
const PG = process.env.PG_CONTAINER ?? "av-pg-r52";
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
  const path = "/tmp/av-drill-" + Math.random().toString(36).slice(2, 8) + ".sql";
  writeFileSync(path, q);
  const out = execSync(`docker cp ${path} ${PG}:/tmp/q.sql && docker exec ${PG} psql -U av -d avdb -t -A -f /tmp/q.sql`).toString().trim();
  unlinkSync(path);
  return out;
}

const alice = {};
{
  const r = await jr(alice, "POST", "/api/v1/auth/signup", {
    email: `wa+${nonce}@example.com`, password: "s3cret-drill-pw-1234!",
    orgName: `WA-${nonce}`, displayName: "WA",
  });
  if (r.status !== 200 && r.status !== 201) fail(`signup ${r.status}`);
}

const targets = [
  { name: "slack",   url: "https://hooks.slack.com/services/T00000000/B00000000/deadbeef" },
  { name: "teams",   url: "https://acme.webhook.office.com/webhookb2/deadbeef@guid/IncomingWebhook/xyz/deadbeef" },
  { name: "discord", url: "https://discord.com/api/webhooks/123456/deadbeef" },
  { name: "raw",     url: "https://relay.example.com/av/hook" },
];

const created = [];
for (const t of targets) {
  const r = await jr(alice, "POST", "/api/v1/webhooks", {
    name: t.name,
    url: t.url,
    events: ["test", "policy.block"],
  });
  if (r.status !== 201) fail(`create ${t.name} -> ${r.status}: ${await r.text()}`);
  const j = await r.json();
  created.push({ ...t, id: j.endpoint.id });
  console.log("✅ created", t.name, "->", j.endpoint.id);
}

// Fire test on each. Their targets are unreachable so the delivery
// will get to 'retrying' state — but the payload row is what we
// verify, not delivery success.
for (const c of created) {
  const r = await jr(alice, "POST", `/api/v1/webhooks/${c.id}/test`);
  if (r.status !== 200) fail(`test fire ${c.name} -> ${r.status}: ${await r.text()}`);
}
// Give the dispatcher time to write the row.
await new Promise((r) => setTimeout(r, 1500));

// Query the delivery payload column directly via docker exec.
for (const c of created) {
  const payload = sql(`SELECT payload FROM webhook_deliveries WHERE "endpointId"='${c.id}' ORDER BY "createdAt" DESC LIMIT 1`);
  if (!payload) fail(`no delivery row for ${c.name}`);
  const j = JSON.parse(payload);
  if (c.name === "slack") {
    if (!j.attachments) fail(`slack: missing attachments, got ${payload.slice(0, 200)}`);
    if (!j.text?.startsWith("AgentVisor")) fail(`slack: bad text: ${j.text}`);
    if (!Array.isArray(j.attachments[0].blocks)) fail("slack: no blocks");
    console.log("✅ slack: attachments + blocks + colored bar");
  } else if (c.name === "teams") {
    if (j["@type"] !== "MessageCard") fail(`teams: bad @type: ${j["@type"]}`);
    if (!j.themeColor) fail(`teams: no themeColor`);
    if (!Array.isArray(j.sections)) fail(`teams: no sections`);
    console.log("✅ teams: MessageCard + themeColor + sections");
  } else if (c.name === "discord") {
    if (!Array.isArray(j.embeds)) fail(`discord: no embeds: ${payload.slice(0, 200)}`);
    if (!j.embeds[0].title?.startsWith("AgentVisor")) fail(`discord: bad title`);
    if (typeof j.embeds[0].color !== "number") fail(`discord: no color`);
    console.log("✅ discord: embeds + title + numeric color");
  } else if (c.name === "raw") {
    if (j.event !== "test") fail(`raw: expected event=test, got ${j.event}`);
    if (!j.data) fail(`raw: no data`);
    if (!j.createdAt) fail(`raw: no createdAt`);
    console.log("✅ raw: neutral envelope preserved for unknown hosts");
  }
}

console.log("\nAll 4 adapter formats produce valid platform-native bodies.");
