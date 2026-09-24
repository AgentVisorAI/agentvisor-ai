// Exercise crash evidence through the real API. Set SPA_ORIGIN to also
// exercise the live console in Chromium (configured for this API origin).
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, randomUUID, sign } from "node:crypto";

const API = process.env.API_BASE || "http://127.0.0.1:8985";
const QUARANTINED = "quarantined_crash_evidence";
let checks = 0;
function check(label, condition) {
  assert.ok(condition, label);
  console.log("PASS " + label);
  checks++;
}
async function request(path, method = "GET", body, headers = {}, retried = false) {
  const response = await fetch(API + "/api/v1" + path, {
    method, headers: { ...(body === undefined ? {} : { "Content-Type": "application/json" }), ...headers },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (response.status === 429 && !retried) {
    const seconds = Math.min(61, Math.max(1, Number(response.headers.get("retry-after")) || 60));
    await response.arrayBuffer();
    await new Promise((resolve) => setTimeout(resolve, seconds * 1000 + 100));
    return request(path, method, body, headers, true);
  }
  return { status: response.status, body: await response.json(), cookie: response.headers.get("set-cookie")?.split(";")[0] };
}
async function signup() {
  const result = await request("/auth/signup", "POST", {
    email: `quarantine-${randomUUID()}@example.test`, password: "quarantine-test-password-1234", orgName: "Crash evidence drill",
  });
  assert.equal(result.status, 201, JSON.stringify(result.body));
  return { Cookie: result.cookie };
}
const auth = await signup();
const created = await request("/deployments", "POST", { name: "crash-drill", environment: "development" }, auth);
assert.equal(created.status, 201);
const deployment = created.body.deployment.id;
const daemon = { Authorization: "Bearer " + created.body.ingestToken, "X-AV-Deployment": deployment };
const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const publicKeyHex = publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("hex");
const keyIdHex = createHash("sha256").update(Buffer.from(publicKeyHex, "hex")).digest("hex").slice(0, 32);
assert.equal((await request("/ingest/pubkey", "POST", { publicKeyHex }, daemon)).status, 200);
const openedAt = new Date().toISOString();
async function upsert(externalId, status = "live", overrides = {}) {
  return request("/ingest/sessions", "POST", { externalId, status, agent: "recovered-agent", workflow: "unsigned", openedAt, ...overrides }, daemon);
}
function receipt(externalId) {
  const receiptId = randomUUID();
  const issued = Date.now();
  const body = JSON.stringify({ receipt_version: 2, receipt_id: receiptId, session_id: externalId, issued_at: issued, stop_reason: "completed", stop_reason_id: 0, subject: { kind: "event_chain", event_count: 1 } });
  const size = Buffer.alloc(8); size.writeBigUInt64BE(BigInt(Buffer.byteLength(body)));
  return { sessionExternalId: externalId, receiptId, body, sigB64: sign(null, Buffer.concat([Buffer.from("agentvisor-receipt-v2\0"), size, Buffer.from(body)]), privateKey).toString("base64"), keyIdHex, eventCount: 1, issuedAt: new Date(issued).toISOString() };
}
async function detail(externalId) {
  const list = await request("/sessions?q=" + encodeURIComponent(externalId), "GET", undefined, auth);
  const row = list.body.sessions.find((s) => s.externalId === externalId);
  assert.ok(row, "session must exist in tenant list");
  return (await request("/sessions/" + row.id, "GET", undefined, auth)).body.session;
}

const id = "quarantine-" + randomUUID();
check("live session is accepted", (await upsert(id)).status === 200);
check("quarantine status is accepted", (await upsert(id, QUARANTINED)).status === 200);
const event = { sessionExternalId: id, seq: 0, kind: "block", tag: "BLOCKED", body: "Recovered blocked call", occurredAt: openedAt, addToolsBlocked: 1 };
const first = await request("/ingest/events", "POST", [event], daemon);
const retry = await request("/ingest/events", "POST", [event], daemon);
check("recovered events append once after quarantine", first.body.inserted === 1 && retry.body.inserted === 0);
await upsert(id, "live", { agent: "rewritten", workflow: "signed", policyVersion: 999 });
const row = await detail(id);
check("API exposes the total event count", row.eventCount === 1);
check("quarantine survives stale retry and freezes metadata", row.status === QUARANTINED && row.agent === "recovered-agent" && row.workflow === "unsigned" && row.policyVersion === 1);
check("recovered blocked count is retained", row.toolsBlocked === 1 && row.events.length === 1);
const seal = await request("/ingest/receipts", "POST", receipt(id), daemon);
check("valid signature cannot seal incomplete evidence", seal.status === 409 && seal.body.errorCode === "session_evidence_incomplete");
check("quarantined evidence has no receipt", (await request("/receipts/" + row.id, "GET", undefined, auth)).status === 404);
const overview = await request("/overview", "GET", undefined, auth);
check("quarantined evidence is not counted live or sealed", overview.body.stats.live === 0 && overview.body.stats.sealed === 0);

const other = await signup();
check("another tenant cannot read recovered evidence", (await request("/sessions/" + row.id, "GET", undefined, other)).status === 404);
const sealedId = "sealed-" + randomUUID();
await upsert(sealedId);
assert.equal((await request("/ingest/receipts", "POST", receipt(sealedId), daemon)).status, 200);
await upsert(sealedId, QUARANTINED);
check("signed seals cannot be downgraded to quarantine", (await detail(sealedId)).status === "sealed");

for (let n = 0; n < 8; n++) {
  const raceId = "race-" + randomUUID();
  await upsert(raceId);
  const [quarantine, sealing] = await Promise.all([upsert(raceId, QUARANTINED), request("/ingest/receipts", "POST", receipt(raceId), daemon)]);
  assert.equal(quarantine.status, 200);
  assert.ok([200, 409].includes(sealing.status), JSON.stringify(sealing));
  const raced = await detail(raceId);
  check("concurrent seal/quarantine stays consistent " + n, raced.status === "sealed" ? !!raced.receipt : raced.status === QUARANTINED && !raced.receipt);
}

if (process.env.SPA_ORIGIN) {
  const { chromium } = await import("playwright");
  const browser = await chromium.launch();
  try {
    const context = await browser.newContext();
    const separator = auth.Cookie.indexOf("=");
    await context.addCookies([{ name: auth.Cookie.slice(0, separator), value: auth.Cookie.slice(separator + 1), url: API }]);
    const page = await context.newPage();
    const errors = [];
    page.on("pageerror", (e) => errors.push(e.message));
    const spa = process.env.SPA_ORIGIN.replace(/\/$/, "");
    await page.goto(spa + "/#/sessions", { waitUntil: "networkidle" });
    const tableRow = page.locator(`tr[data-id="${row.id}"]`);
    await tableRow.waitFor();
    check("browser marks recovered row incomplete", (await tableRow.innerText()).includes("quarantined · incomplete"));
    check("browser list shows the recovered event count", await tableRow.locator("td").nth(2).innerText() === "1");
    await tableRow.click();
    await page.waitForSelector("#dlRcpt");
    const text = await page.locator("#view").innerText();
    check("browser explains partial counts and unavailable receipt", text.includes("All counts and totals are partial") && text.includes("No receipt is available"));
    check("browser disables receipt export/share/copy", await page.locator("#dlRcpt").isDisabled() && await page.locator("#shareRcpt").isDisabled() && await page.locator("#copyRcpt").isDisabled());
    await page.emulateMedia({ media: "print" });
    check("printed evidence carries incomplete warning", (await page.locator(".print-only").innerText()).includes("INCOMPLETE CRASH EVIDENCE"));
    check("browser has no uncaught JavaScript error", errors.length === 0);
  } finally { await browser.close(); }
}
console.log(`quarantine-drill: ${checks} checks passed`);
