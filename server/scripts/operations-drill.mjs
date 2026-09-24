// Isolated production-mode API, two-instance tenant/SSE, workload, and restore
// drill. Run from server/ after npm ci, prisma generate, and npm run build.
// Defaults: 100,000 fixture events, 1,000 sessions, 3,000 mixed requests
// offered at 50 requests/second for 60 seconds. This is not a capacity limit.
// A small correctness run: EVENTS=1000 REQUESTS=80 node scripts/operations-drill.mjs
// Requires an already-present PostgreSQL image (PG_IMAGE defaults to postgres:15).
// It never connects to a caller-supplied database or deletes existing resources.
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, randomBytes, randomUUID, sign, verify } from "node:crypto";
import { createReadStream, createWriteStream } from "node:fs";
import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import { createServer } from "node:net";
import { once } from "node:events";
import { pipeline } from "node:stream/promises";
import pg from "pg";

const serverRoot = fileURLToPath(new URL("../", import.meta.url));
const integer = (name, fallback, min, max) => {
  const value = Number(process.env[name] ?? fallback);
  assert.ok(Number.isInteger(value) && value >= min && value <= max, `${name} must be ${min}..${max}`);
  return value;
};
const eventTarget = integer("EVENTS", 100_000, 1000, 1_000_000);
const requestTarget = integer("REQUESTS", 3000, 40, 5000);
const concurrency = integer("CONCURRENCY", 12, 1, 32);
const offeredRps = integer("OFFERED_RPS", 50, 1, 100);
const id = "av-console-ops-" + randomBytes(6).toString("hex");
const output = await mkdtemp(join(tmpdir(), id + "-"));
await chmod(output, 0o700);
const password = randomBytes(24).toString("hex");
const jwt = randomBytes(48).toString("hex");
const apps = [];
const streams = [];
const clients = [];
let containerCreated = false;
const report = { id, startedAt: new Date().toISOString(), node: process.version, platform: process.platform, architecture: process.arch,
  eventTarget, requestTarget, concurrency, offeredRps, checks: [], workload: {}, plans: {}, restore: {} };
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
function check(label, condition) {
  assert.ok(condition, label);
  report.checks.push(label);
  console.log("PASS " + label);
}
async function command(binary, args, options = {}) {
  const child = spawn(binary, args, { cwd: serverRoot, stdio: ["ignore", "pipe", "pipe"], ...options });
  let stdout = "", stderr = "";
  child.stdout?.on("data", (chunk) => { stdout += chunk; });
  child.stderr?.on("data", (chunk) => { stderr += chunk; });
  const timer = setTimeout(() => child.kill("SIGKILL"), 120_000);
  try {
    const [code] = await once(child, "exit");
    assert.equal(code, 0, `${binary} ${args[0]} failed: ${stderr.slice(-2000)}`);
    return stdout.trim();
  } finally { clearTimeout(timer); }
}
async function port() {
  const socket = createServer();
  socket.listen(0, "127.0.0.1");
  await once(socket, "listening");
  const chosen = socket.address().port;
  await new Promise((resolve) => socket.close(resolve));
  return chosen;
}
async function startApi(database, label) {
  const chosen = await port();
  const log = createWriteStream(join(output, label + ".log"), { mode: 0o600 });
  const child = spawn(process.execPath, [join(serverRoot, "dist/index.js")], {
    // Do not load a developer's server/.env or inherit provider credentials.
    cwd: output,
    env: { PATH: process.env.PATH, HOME: process.env.HOME, NODE_ENV: "production",
      DATABASE_URL: database, JWT_SECRET: jwt, PORT: String(chosen), HOST: "127.0.0.1",
      APP_BASE_URL: "https://console.example.test", API_PUBLIC_URL: "https://api.example.test",
      SMTP_URL: "smtp://fixture:fixture@127.0.0.1:1", LOG_LEVEL: "warn", TZ: "Asia/Tokyo",
      ALLOWED_ORIGINS: "https://console.example.test", TRUSTED_PROXY_HOP_COUNT: "1" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.stdout.pipe(log, { end: false }); child.stderr.pipe(log, { end: false });
  const app = { child, log, url: `http://127.0.0.1:${chosen}`, label };
  apps.push(app);
  for (let n = 0; n < 120; n++) {
    if (child.exitCode !== null) throw new Error(`${label} exited; inspect ${label}.log`);
    const ready = await fetch(app.url + "/readyz", { signal: AbortSignal.timeout(1000) }).then((r) => r.json()).catch(() => null);
    if (ready?.checks?.db === "ok" && ready?.checks?.bus === "ok") return app;
    await sleep(250);
  }
  throw new Error(`${label} readiness timed out`);
}
async function stopApi(app) {
  if (app.child.exitCode === null && app.child.signalCode === null) {
    const done = once(app.child, "exit");
    app.child.kill("SIGTERM");
    const timer = setTimeout(() => app.child.kill("SIGKILL"), 12_000);
    await done; clearTimeout(timer);
  }
  app.log.end();
  assert.equal(app.child.exitCode, 0, `${app.label} did not exit cleanly (signal ${app.child.signalCode})`);
}
async function request(app, path, { method = "GET", body, auth, ip = "198.51.100.10", expected = 200 } = {}) {
  const began = performance.now();
  const response = await fetch(app.url + "/api/v1" + path, {
    method, headers: { "Content-Type": "application/json", "X-Forwarded-Proto": "https",
      "X-Forwarded-For": ip, "X-Requested-With": "XMLHttpRequest", ...auth },
    body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(60_000),
  });
  const text = await response.text();
  let data; try { data = JSON.parse(text); } catch { data = text; }
  if (expected !== null) assert.equal(response.status, expected, `${method} ${path}: ${text.slice(0, 600)}`);
  return { status: response.status, data, ms: performance.now() - began, headers: response.headers };
}
async function tenant(app, label) {
  const user = await request(app, "/auth/signup", { method: "POST", expected: 201,
    body: { email: `${id}-${label}@example.test`, password, orgName: `${id}-${label}` } });
  const cookie = user.headers.getSetCookie().find((c) => c.startsWith("av_session="))?.split(";")[0];
  assert.ok(cookie);
  const auth = { Cookie: cookie };
  const deployment = await request(app, "/deployments", { method: "POST", expected: 201, auth,
    body: { name: label, environment: "development" } });
  return { label, auth, deployment: deployment.data.deployment.id,
    daemon: { Authorization: "Bearer " + deployment.data.ingestToken, "X-AV-Deployment": deployment.data.deployment.id } };
}
async function stream(app, owner, ip) {
  const abort = new AbortController();
  const response = await fetch(app.url + "/api/v1/stream", { headers: { ...owner.auth,
    "X-Forwarded-Proto": "https", "X-Forwarded-For": ip }, signal: abort.signal });
  assert.equal(response.status, 200);
  const events = [];
  let pending = "";
  const reading = (async () => {
    const decoder = new TextDecoder();
    for await (const chunk of response.body) {
      pending += decoder.decode(chunk, { stream: true });
      let split;
      while ((split = pending.indexOf("\n\n")) >= 0) {
        const frame = pending.slice(0, split); pending = pending.slice(split + 2);
        const name = frame.match(/^event: (.+)$/m)?.[1];
        const data = frame.match(/^data: (.+)$/m)?.[1];
        if (name && data) events.push({ type: name, data: JSON.parse(data) });
      }
    }
  })().catch((error) => { if (!abort.signal.aborted) throw error; });
  // Register immediately so even a later assertion failure closes the socket.
  const result = { abort, events, reading }; streams.push(result);
  await until(() => events.some((e) => e.type === "hello"), "SSE hello");
  return result;
}
async function until(predicate, label) {
  for (let n = 0; n < 120; n++) { if (predicate()) return; await sleep(100); }
  throw new Error(label + " timed out");
}
async function parallel(items, limit, run) {
  let next = 0;
  await Promise.all(Array.from({ length: limit }, async () => {
    while (next < items.length) { const index = next++; await run(items[index], index); }
  }));
}
function event(externalId, seq, label) {
  return { sessionExternalId: externalId, seq, kind: seq % 5 ? "tool" : "block", tag: "OPS",
    body: `${label}: synthetic event ${seq}`, occurredAt: new Date().toISOString(),
    addToolsAllowed: seq % 5 ? 1 : 0, addToolsBlocked: seq % 5 ? 0 : 1, addCostUsdMicros: 7 };
}
async function fingerprints(db) {
  const tables = (await db.query("SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename")).rows;
  const result = {};
  for (const { tablename } of tables) {
    assert.match(tablename, /^[a-zA-Z0-9_]+$/);
    result[tablename] = (await db.query(`SELECT count(*)::text AS count, md5(coalesce(string_agg(hash, '' ORDER BY hash), '')) AS digest FROM (SELECT md5(row_to_json(t)::text) AS hash FROM "${tablename}" t) rows`)).rows[0];
  }
  return result;
}

console.log(`Operational fixture ${id}; logs: ${output}`);
try {
  const image = process.env.PG_IMAGE || "postgres:15";
  const imageInfo = JSON.parse(await command("docker", ["image", "inspect", image]))[0];
  report.postgresImage = { name: image, id: imageInfo.Id, digests: imageInfo.RepoDigests };
  const envFile = join(output, "postgres.env");
  await writeFile(envFile, `POSTGRES_USER=avops\nPOSTGRES_PASSWORD=${password}\nPOSTGRES_DB=avops\n`, { mode: 0o600 });
  await command("docker", ["run", "--detach", "--pull=never", "--name", id, "--label", `agentvisor.drill=${id}`,
    "--memory", "512m", "--cpus", "2", "--env-file", envFile, "-p", "127.0.0.1::5432", image]);
  containerCreated = true;
  const binding = JSON.parse(await command("docker", ["inspect", id]))[0].NetworkSettings.Ports["5432/tcp"][0];
  const database = `postgresql://avops:${password}@127.0.0.1:${binding.HostPort}/avops`;
  for (let n = 0; ; n++) {
    try { await command("docker", ["exec", id, "pg_isready", "-U", "avops", "-d", "avops"]); break; }
    catch (error) { if (n === 60) throw error; await sleep(250); }
  }
  // pg_isready can see the image's temporary initialization server before
  // host TCP forwarding and the final postmaster are available.
  let db;
  for (let n = 0; n < 120; n++) {
    const candidate = new pg.Client({ connectionString: database, connectionTimeoutMillis: 1000 });
    try { await candidate.connect(); db = candidate; clients.push(db); break; }
    catch (error) { await candidate.end().catch(() => {}); if (n === 119) throw error; await sleep(250); }
  }
  await command(process.execPath, [join(serverRoot, "node_modules/prisma/build/index.js"), "migrate", "deploy", "--schema", join(serverRoot, "prisma/schema.prisma")],
    { cwd: output, env: { PATH: process.env.PATH, HOME: process.env.HOME, DATABASE_URL: database } });
  const a = await startApi(database, "api-a"), b = await startApi(database, "api-b");
  const owners = [await tenant(a, "alpha"), await tenant(b, "beta")];
  for (const owner of owners) owner.org = (await db.query('SELECT "orgId" FROM deployments WHERE id=$1', [owner.deployment])).rows[0].orgId;
  const feedA = await stream(b, owners[0], "198.51.100.11");
  const feedB = await stream(a, owners[1], "198.51.100.12");
  for (const [index, owner] of owners.entries()) {
    owner.external = "shared-external-id";
    owner.session = (await request(index ? b : a, "/ingest/sessions", { method: "POST", auth: owner.daemon,
      body: { externalId: owner.external, agent: owner.label, openedAt: new Date().toISOString() } })).data.session.id;
  }
  await until(() => feedA.events.some((e) => e.type === "session.upsert") && feedB.events.some((e) => e.type === "session.upsert"), "cross-instance session fanout");
  const concurrent = Array.from({ length: 16 }, (_, i) => i);
  await parallel(concurrent, 4, async (i) => {
    const owner = owners[i % 2], app = i % 3 ? a : b;
    const payload = Array.from({ length: 20 }, (_, n) => event(owner.external, Math.floor(i / 2) * 20 + n, owner.label));
    // The same retry races through both application instances.
    const results = await Promise.all([a, b].map((instance) => request(instance, "/ingest/events", { method: "POST", auth: owner.daemon, body: payload })));
    assert.equal(results.reduce((sum, r) => sum + r.data.inserted, 0), 20);
    const detail = await request(app, "/sessions/" + owner.session, { auth: owner.auth, ip: `198.51.100.${20 + i}` });
    assert.ok(detail.data.session.events.every((e) => e.body.startsWith(owner.label + ":")));
    const other = owners[1 - i % 2];
    await request(app, "/sessions/" + other.session, { auth: owner.auth, ip: `198.51.100.${20 + i}`, expected: 404 });
  });
  const delivered = (feed) => feed.events.filter((e) => e.type === "events.appended").reduce((sum, e) => sum + e.data.count, 0);
  await until(() => [feedA, feedB].every((feed) => delivered(feed) >= 160), "complete cross-instance event fanout");
  check("two-instance concurrent duplicate ingest commits exactly once", (await db.query('SELECT count(*)::int AS n FROM events')).rows[0].n === 320);
  check("both SSE streams contain only their own tenant", [feedA, feedB].every((feed, i) => feed.events.filter((e) => e.type !== "hello").every((e) => e.data.orgId === owners[i].org)));
  check("cross-instance SSE counts every committed event once", [feedA, feedB].every((feed) => delivered(feed) === 160 && feed.events.filter((e) => e.type === "session.upsert").length === 1));
  for (const owner of owners) {
    const detail = await request(a, "/sessions/" + owner.session, { auth: owner.auth });
    check(`${owner.label} rollups match concurrent unique events`, detail.data.session.eventCount === 160 && detail.data.session.toolsAllowed === 128 && detail.data.session.toolsBlocked === 32 && detail.data.session.costUsdMicros === "1120");
  }
  await request(b, "/ingest/events", { method: "POST", auth: { ...owners[0].daemon, "X-AV-Deployment": owners[1].deployment }, body: [event(owners[1].external, 900, "foreign")], expected: 401 });
  check("one tenant's ingest token cannot write the other deployment", true);
  for (const feed of streams) feed.abort.abort();
  await Promise.all(streams.map((feed) => feed.reading));

  // Include signed receipts and quarantined evidence in the restored dataset.
  for (const owner of owners) {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    owner.publicKey = publicKey;
    const rawKey = publicKey.export({ format: "der", type: "spki" }).subarray(-32);
    await request(a, "/ingest/pubkey", { method: "POST", auth: owner.daemon, body: { publicKeyHex: rawKey.toString("hex") } });
    owner.sealed = (await request(a, "/ingest/sessions", { method: "POST", auth: owner.daemon,
      body: { externalId: "sealed-restore", agent: owner.label, openedAt: new Date().toISOString() } })).data.session.id;
    await request(a, "/ingest/events", { method: "POST", auth: owner.daemon, body: [event("sealed-restore", 0, owner.label)] });
    const receiptId = randomUUID(), issued = Date.now();
    const body = JSON.stringify({ receipt_version: 2, receipt_id: receiptId, session_id: "sealed-restore", issued_at: issued,
      stop_reason: "completed", stop_reason_id: 0, subject: { kind: "event_chain", event_count: 1 } });
    const size = Buffer.alloc(8); size.writeBigUInt64BE(BigInt(Buffer.byteLength(body)));
    owner.receiptMessage = Buffer.concat([Buffer.from("agentvisor-receipt-v2\0"), size, Buffer.from(body)]);
    owner.receiptBody = body;
    await request(a, "/ingest/receipts", { method: "POST", auth: owner.daemon, body: { sessionExternalId: "sealed-restore",
      receiptId, body, sigB64: sign(null, owner.receiptMessage, privateKey).toString("base64"),
      keyIdHex: createHash("sha256").update(rawKey).digest("hex").slice(0, 32), eventCount: 1, issuedAt: new Date(issued).toISOString() } });
    owner.quarantined = (await request(a, "/ingest/sessions", { method: "POST", auth: owner.daemon,
      body: { externalId: "quarantined-restore", agent: owner.label, openedAt: new Date().toISOString(), status: "quarantined_crash_evidence" } })).data.session.id;
  }

  // Isolate the rate bucket from setup using a new simulated client address.
  const rateIp = "192.0.2.200";
  const statuses = [];
  for (let n = 0; n < 301; n++) statuses.push((await request(a, "/deployments", { auth: owners[n % 2].auth, ip: rateIp, expected: null })).status);
  check("global rate bucket shares 300 requests across users at one IP", statuses.slice(0, 300).every((s) => s === 200) && statuses[300] === 429);
  await request(a, "/deployments", { auth: { Cookie: "av_session=" + randomBytes(24).toString("hex") }, ip: rateIp, expected: 429 });
  check("changing an unvalidated cookie does not bypass the IP bucket", true);
  await request(a, "/ingest/events", { method: "POST", auth: owners[0].daemon, ip: rateIp, body: [] });
  check("authenticated ingest remains exempt after the IP bucket is exhausted", true);
  const otherInstance = await request(b, "/deployments", { auth: owners[0].auth, ip: rateIp, expected: null });
  check("rate-limit state is independent on the second application instance", otherInstance.status === 200);
  const routeStatuses = [];
  for (let n = 0; n < 31; n++) routeStatuses.push((await request(a, "/sessions", { auth: owners[0].auth, ip: "192.0.2.201", expected: null })).status);
  check("cookie session listing stops at its 30-per-minute route limit", routeStatuses.slice(0, 30).every((s) => s === 200) && routeStatuses[30] === 429);
  report.rateLimit = { globalAccepted: 300, nextStatus: statuses[300], otherInstanceStatus: otherInstance.status, listingAccepted: 30, scope: "per client IP, per application process; route overrides replace the global bucket" };

  // Synthetic scale data is inserted directly, separately from the genuine
  // authenticated ingest checks above and the measured mixed workload below.
  const sessionCount = Math.max(100, Math.ceil(eventTarget / 100));
  for (const [tenantIndex, owner] of owners.entries()) {
    const count = Math.floor(sessionCount / 2) + (tenantIndex === 0 ? sessionCount % 2 : 0);
    await db.query(`INSERT INTO sessions (id,"deploymentId","orgId","externalId",agent,"openedAt") SELECT $1 || '-session-' || n, $2, $3, 'scale-' || n, $4, (now() AT TIME ZONE 'UTC') - (n || ' seconds')::interval FROM generate_series(1,$5::int) n`, [id + owner.label, owner.deployment, owner.org, owner.label, count]);
    const tenantEvents = Math.floor(eventTarget / 2) + (tenantIndex === 0 ? eventTarget % 2 : 0);
    await db.query(`INSERT INTO events (id,"sessionId",seq,kind,tag,body,"occurredAt") SELECT $1 || '-event-' || n, $1 || '-session-' || (1 + ((n-1) % $2::int)), ((n-1) / $2::int), 'tool', 'SCALE', $3 || ': synthetic scale event ' || n || repeat('x',256), now() AT TIME ZONE 'UTC' FROM generate_series(1,$4::int) n`, [id + owner.label, count, owner.label, tenantEvents]);
  }
  await db.query("ANALYZE sessions; ANALYZE events");
  check("meaningful scale dataset is present", (await db.query("SELECT count(*)::int AS n FROM events")).rows[0].n === eventTarget + 322);
  const queries = {
    session_page: ['SELECT id,"openedAt" FROM sessions WHERE "orgId"=$1 ORDER BY "openedAt" DESC,id DESC LIMIT 51', [owners[0].org]],
    event_page: ['SELECT * FROM events WHERE "sessionId"=$1 AND seq>30 ORDER BY seq LIMIT 51', [id + owners[0].label + "-session-1"]],
    event_count: ['SELECT count(*) FROM events WHERE "sessionId"=$1', [id + owners[0].label + "-session-1"]],
    overview: ['SELECT status,count(*),sum("toolsAllowed"),sum("toolsBlocked") FROM sessions WHERE "orgId"=$1 AND "openedAt">(now() AT TIME ZONE \'UTC\')-interval \'24 hours\' GROUP BY status', [owners[0].org]],
  };
  for (const [name, [sql, values]] of Object.entries(queries)) report.plans[name] = { sql, plan: (await db.query("EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) " + sql, values)).rows[0]["QUERY PLAN"] };
  const indexes = (await db.query("SELECT indexname FROM pg_indexes WHERE schemaname='public'")).rows.map((r) => r.indexname);
  check("session and event compound indexes are installed", indexes.includes("sessions_orgId_openedAt_id_idx") && indexes.includes("events_sessionId_seq_key"));
  // Retain the optimizer's real decision: a small or unselective fixture may
  // legitimately use a sequential scan. Never force a favorable index plan.
  await writeFile(join(output, "query-plans.json"), JSON.stringify(report.plans, null, 2));

  const measurements = [];
  const began = performance.now();
  await parallel(Array.from({ length: requestTarget }, (_, i) => i), concurrency, async (i) => {
    const scheduled = began + i * 1000 / offeredRps;
    await sleep(Math.max(0, scheduled - performance.now()));
    const scheduleDelayMs = Math.max(0, performance.now() - scheduled);
    const owner = owners[i % 2], app = Math.floor(i / 128) % 2 ? a : b;
    const ip = `203.0.113.${1 + Math.floor(i / 2) % 64}`;
    const mode = Math.floor(i / 2) % 4;
    const path = mode === 0 ? "/overview" : mode === 1 ? "/sessions?limit=25" : mode === 2 ? "/sessions/" + owner.session + "?eventLimit=20" : "/ingest/events";
    const result = await request(app, path, mode === 3
      ? { method: "POST", auth: owner.daemon, ip, body: Array.from({ length: 20 }, (_, n) => event(owner.external, 1000 + i * 20 + n, owner.label)) }
      : { auth: owner.auth, ip });
    if (mode === 3) assert.equal(result.data.inserted, 20);
    else if (mode === 2) assert.equal(result.data.session.agent, owner.label);
    else assert.ok(result.data.sessions.every((session) => session.agent === owner.label));
    measurements.push({ endpoint: mode, ms: result.ms, status: result.status, scheduleDelayMs });
  });
  const elapsedMs = performance.now() - began;
  for (const mode of [0, 1, 2, 3]) {
    const times = measurements.filter((r) => r.endpoint === mode).map((r) => r.ms).sort((x, y) => x - y);
    report.workload[["overview", "sessions", "session_detail", "ingest_20_events"][mode]] = { count: times.length, p50Ms: times[Math.ceil(times.length * .5) - 1], p95Ms: times[Math.ceil(times.length * .95) - 1], p99Ms: times[Math.ceil(times.length * .99) - 1], maxMs: times.at(-1) };
  }
  const delays = measurements.map((r) => r.scheduleDelayMs).sort((x, y) => x - y);
  report.workload.total = { requests: measurements.length, elapsedMs, offeredRps, requestsPerSecond: requestTarget / (elapsedMs / 1000),
    status200: measurements.filter((r) => r.status === 200).length, scheduleDelayP95Ms: delays[Math.ceil(delays.length * .95) - 1] };
  check("bounded mixed authenticated workload has no unexpected status or tenant leak", measurements.length === requestTarget && measurements.every((r) => r.status === 200));
  console.log("WORKLOAD " + JSON.stringify(report.workload));

  // Stop writers before measuring an exact snapshot; pg_dump is still a
  // transactionally consistent backup, but fingerprints must share its state.
  await Promise.all([a, b].map(stopApi));
  const before = await fingerprints(db);
  report.restore.databaseBytes = (await db.query("SELECT pg_database_size(current_database())::text AS bytes")).rows[0].bytes;
  const dump = join(output, "database.dump");
  const dumpStarted = performance.now();
  const dumping = spawn("docker", ["exec", id, "pg_dump", "-U", "avops", "-d", "avops", "-Fc", "--no-owner"], { stdio: ["ignore", "pipe", "inherit"] });
  const dumpExit = once(dumping, "exit");
  await pipeline(dumping.stdout, createWriteStream(dump, { mode: 0o600 }));
  assert.equal((await dumpExit)[0], 0);
  report.restore.dumpMs = performance.now() - dumpStarted;
  await command("docker", ["exec", id, "createdb", "-U", "avops", "restored"]);
  const restoreStarted = performance.now();
  const restoring = spawn("docker", ["exec", "-i", id, "pg_restore", "-U", "avops", "-d", "restored", "--no-owner", "--exit-on-error"], { stdio: ["pipe", "ignore", "inherit"] });
  const restoreExit = once(restoring, "exit");
  await pipeline(createReadStream(dump), restoring.stdin);
  assert.equal((await restoreExit)[0], 0);
  report.restore.restoreMs = performance.now() - restoreStarted;
  const restoredUrl = database.replace(/\/avops$/, "/restored");
  const restoredDb = new pg.Client({ connectionString: restoredUrl }); clients.push(restoredDb); await restoredDb.connect();
  const after = await fingerprints(restoredDb);
  assert.deepEqual(after, before);
  report.restore.tables = before;
  report.restore.dumpSha256 = createHash("sha256").update(await readFile(dump)).digest("hex");
  check("backup restored every public table with identical row counts and content", true);
  const restoredApp = await startApi(restoredUrl, "api-restored");
  for (const owner of owners) {
    const result = await request(restoredApp, "/sessions/" + owner.session, { auth: owner.auth });
    const expected = (await restoredDb.query('SELECT count(*)::int AS n FROM events WHERE "sessionId"=$1', [owner.session])).rows[0].n;
    check(`${owner.label} restored cookie and event pagination work`, result.data.session.eventCount === expected && result.data.session.events.every((e) => e.body.startsWith(owner.label + ":")));
    if (result.data.nextEventCursor !== null) {
      const next = await request(restoredApp, `/sessions/${owner.session}?eventCursor=${result.data.nextEventCursor}`, { auth: owner.auth });
      check(`${owner.label} restored pagination advances without duplicates`, next.data.session.events.length > 0 && next.data.session.events.every((e) => e.seq > result.data.nextEventCursor && e.body.startsWith(owner.label + ":")));
    }
    await request(restoredApp, "/sessions/" + owners.find((o) => o !== owner).session, { auth: owner.auth, expected: 404 });
    const receipt = (await request(restoredApp, "/receipts/" + owner.sealed, { auth: owner.auth })).data.receipt;
    check(`${owner.label} restored receipt retains its signed bytes`, receipt.body === owner.receiptBody && verify(null, owner.receiptMessage, owner.publicKey, Buffer.from(receipt.sigB64, "base64")));
    const quarantined = (await request(restoredApp, "/sessions/" + owner.quarantined, { auth: owner.auth })).data.session;
    check(`${owner.label} restored quarantine cannot appear sealed`, quarantined.status === "quarantined_crash_evidence" && !quarantined.receipt);
    const append = await request(restoredApp, "/ingest/events", { method: "POST", auth: owner.daemon, body: [event(owner.external, 900_000, owner.label)] });
    check(`${owner.label} restored ingest credential remains usable`, append.data.inserted === 1);
  }
  report.ok = true;
} catch (error) {
  report.ok = false; report.error = error.stack;
  console.error(error);
  process.exitCode = 1;
} finally {
  for (const feed of streams) feed.abort.abort();
  const cleanupErrors = [];
  for (const tasks of [streams.map((feed) => feed.reading), apps.map(stopApi), clients.map((client) => client.end())]) {
    for (const result of await Promise.allSettled(tasks)) if (result.status === "rejected") cleanupErrors.push(String(result.reason));
  }
  if (containerCreated) {
    try {
      const own = JSON.parse(await command("docker", ["inspect", id]))[0];
      assert.equal(own.Config.Labels["agentvisor.drill"], id, "refuse cleanup of an unowned container");
      await command("docker", ["rm", "--force", "--volumes", id]);
    } catch (error) { cleanupErrors.push(String(error)); }
  }
  // Preserve measurements and logs, remove password material and database dump.
  await rm(join(output, "postgres.env"), { force: true });
  await rm(join(output, "database.dump"), { force: true });
  report.cleanup = { applications: apps.map((app) => ({ label: app.label, pid: app.child.pid, exitCode: app.child.exitCode })), container: id, errors: cleanupErrors };
  if (cleanupErrors.length) { report.ok = false; process.exitCode = 1; }
  report.finishedAt = new Date().toISOString();
  await writeFile(join(output, "report.json"), JSON.stringify(report, null, 2), { mode: 0o600 });
  console.log(`Result ${report.ok ? "PASS" : "FAIL"}; report: ${join(output, "report.json")}`);
}
