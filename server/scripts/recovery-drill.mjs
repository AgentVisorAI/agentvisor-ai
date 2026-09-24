// Two production-mode APIs, one private disposable database, and bounded
// failures of LISTEN, database access, and logout persistence. No load test.
// Run after npm run build. Requires an existing postgres:15 image.
// On macOS: DOCKER_HOST=unix://$HOME/.colima/default/docker.sock node scripts/recovery-drill.mjs
// To run both APIs from one exact production image instead of native dist:
// CONSOLE_RECOVERY_IMAGE=<image-id-or-tag> node scripts/recovery-drill.mjs
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { createWriteStream } from "node:fs";
import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import { createServer } from "node:net";
import { once } from "node:events";
import pg from "pg";
import { closeDrillClient } from "./auth-drill-cleanup.mjs";

const root = fileURLToPath(new URL("../", import.meta.url));
const id = "av-console-recovery-" + randomBytes(6).toString("hex");
const output = await mkdtemp(join(tmpdir(), id + "-"));
await chmod(output, 0o700);
const password = randomBytes(24).toString("hex");
const jwt = randomBytes(48).toString("hex");
const fixtureSecrets = new Set([password, jwt]);
const redact = (text) => [...fixtureSecrets].reduce((value, secret) => value.replaceAll(secret, "[REDACTED]"), text);
const apiImage = process.env.CONSOLE_RECOVERY_IMAGE;
const apps = [], streams = [], clients = [], commands = new Set();
const containerIntents = [];
const privateFiles = [];
const networkName = `${id}-network`;
const cancelled = new AbortController();
const dockerEnv = { ...process.env };
if (process.platform === "darwin") {
  dockerEnv.DOCKER_HOST = process.env.DOCKER_HOST || `unix://${process.env.HOME}/.colima/default/docker.sock`;
}
delete dockerEnv.DOCKER_CONTEXT; // Preserve the normal Docker config and credentials.
let networkCreationAttempted = false;
let cleaningUp = false;
const report = { id, startedAt: new Date().toISOString(), checks: [], status: "running" };
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
function check(label, condition) { assert.ok(condition, label); report.checks.push(label); console.log("PASS " + label); }
function cancel() {
  // A second signal must not interrupt resource cleanup after cancellation.
  if (cleaningUp || cancelled.signal.aborted) return;
  cancelled.abort();
  for (const child of commands) child.kill("SIGTERM");
  for (const app of apps) if (app.child?.exitCode === null) app.child.kill("SIGTERM");
}
process.on("SIGTERM", cancel);
process.on("SIGINT", cancel);
const deadline = setTimeout(cancel, 180_000);

async function command(binary, args, options = {}) {
  const { includeStderr = false, ...spawnOptions } = options;
  const child = spawn(binary, args, { cwd: root, env: binary === "docker" ? dockerEnv : process.env,
    stdio: ["ignore", "pipe", "pipe"], ...spawnOptions });
  commands.add(child);
  let stdout = "", stderr = "";
  child.stdout.on("data", (chunk) => { stdout += chunk; });
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  const timer = setTimeout(() => child.kill("SIGKILL"), 30_000);
  try {
    const [code] = await once(child, "close");
    assert.equal(code, 0, `${binary} ${args[0]} failed: ${stderr.slice(-1500)}`);
    return (stdout + (includeStderr ? stderr : "")).trim();
  } finally { clearTimeout(timer); commands.delete(child); }
}
async function until(predicate, label, timeoutMs = 10_000, intervalMs = 100) {
  const expires = Date.now() + timeoutMs;
  while (Date.now() < expires) {
    cancelled.signal.throwIfAborted();
    if (await predicate()) return;
    await sleep(intervalMs);
  }
  throw new Error(label + " timed out");
}
async function port() {
  const socket = createServer();
  socket.listen(0, "127.0.0.1"); await once(socket, "listening");
  const value = socket.address().port;
  await new Promise((resolve) => socket.close(resolve));
  return value;
}
async function startApi(database, label) {
  const url = new URL(database);
  url.searchParams.set("application_name", `${id}-${label}`);
  const appEnv = { NODE_ENV: "production", DATABASE_URL: url.toString(), JWT_SECRET: jwt,
    APP_BASE_URL: "https://console.example.test", API_PUBLIC_URL: "https://api.example.test",
    SMTP_URL: "smtp://fixture:fixture@127.0.0.1:1", LOG_LEVEL: "warn",
    ALLOWED_ORIGINS: "https://console.example.test", TRUSTED_PROXY_HOP_COUNT: "1" };
  let app;
  if (apiImage) {
    const container = `${id}-${label}`;
    const envFile = join(output, `${label}.env`);
    privateFiles.push(envFile);
    await writeFile(envFile, Object.entries({ ...appEnv, PORT: "8080", HOST: "0.0.0.0" })
      .map(([key, value]) => `${key}=${value}`).join("\n") + "\n", { mode: 0o600 });
    containerIntents.push(container);
    await command("docker", ["run", "--detach", "--pull=never", "--name", container,
      "--label", `agentvisor.drill=${id}`, "--network", networkName,
      "--read-only", "--tmpfs", "/tmp:uid=65532,gid=65532,mode=0700",
      "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
      "--memory", "512m", "--cpus", "1", "--env-file", envFile, "-p", "127.0.0.1::8080", apiImage]);
    const info = JSON.parse(await command("docker", ["inspect", container]))[0];
    assert.equal(info.HostConfig.ReadonlyRootfs, true, `${label} must use a read-only root filesystem`);
    for (const option of ["uid=65532", "gid=65532", "mode=0700"]) {
      assert.ok(info.HostConfig.Tmpfs?.["/tmp"]?.split(",").includes(option), `${label} private tmpfs lacks ${option}`);
    }
    assert.ok(info.HostConfig.CapDrop?.includes("ALL"), `${label} must drop Linux capabilities`);
    assert.ok(info.HostConfig.SecurityOpt?.includes("no-new-privileges"), `${label} must prevent privilege escalation`);
    assert.equal(info.Config.User, "65532:65532", `${label} must use the production non-root user`);
    report.apiImages ??= {};
    report.apiImages[label] = { requested: apiImage, imageId: info.Image, runtime: {
      readOnlyRootfs: info.HostConfig.ReadonlyRootfs, tmpfs: info.HostConfig.Tmpfs,
      capDrop: info.HostConfig.CapDrop, securityOpt: info.HostConfig.SecurityOpt, user: info.Config.User,
    } };
    app = { container: info.Id, url: `http://127.0.0.1:${info.NetworkSettings.Ports["8080/tcp"][0].HostPort}`, label };
  } else {
    const chosen = await port();
    const log = createWriteStream(join(output, label + ".log"), { mode: 0o600 });
    const child = spawn(process.execPath, [join(root, "dist/index.js")], {
      cwd: output,
      env: { PATH: process.env.PATH, HOME: process.env.HOME, ...appEnv, PORT: String(chosen), HOST: "127.0.0.1" },
      stdio: ["ignore", "pipe", "pipe"],
    });
    child.stdout.pipe(log, { end: false }); child.stderr.pipe(log, { end: false });
    app = { child, log, url: `http://127.0.0.1:${chosen}`, label };
  }
  apps.push(app);
  await until(async () => {
    if (app.child) assert.equal(app.child.exitCode, null, `${label} exited before readiness`);
    const ready = await fetch(app.url + "/readyz", { signal: AbortSignal.timeout(1000) }).then((r) => r.json()).catch(() => null);
    return ready?.checks?.db === "ok" && ready?.checks?.bus === "ok";
  }, label + " readiness");
  return app;
}
async function stopApi(app) {
  if (app.container) {
    if (app.stopped) return;
    const owner = await command("docker", ["inspect", "--format", '{{ index .Config.Labels "agentvisor.drill" }}', app.container]);
    assert.equal(owner, id, "refusing to stop a container without this drill's ownership label");
    await command("docker", ["stop", "--time", "5", app.container]);
    const info = JSON.parse(await command("docker", ["inspect", app.container]))[0];
    assert.equal(info.State.Running, false, `${app.label} remains running`);
    assert.equal(info.State.ExitCode, 0, `${app.label} did not exit cleanly`);
    app.stopped = true;
    return;
  }
  if (app.child.exitCode === null && app.child.signalCode === null) {
    const stopped = once(app.child, "exit");
    app.child.kill("SIGTERM");
    const timer = setTimeout(() => app.child.kill("SIGKILL"), 5000);
    await stopped; clearTimeout(timer);
  }
  app.log.end();
  assert.equal(app.child.exitCode, 0, `${app.label} did not exit cleanly`);
}
async function request(app, path, { method = "GET", body, auth, expected = 200 } = {}) {
  const response = await fetch(app.url + "/api/v1" + path, {
    method, headers: { ...(body === undefined ? {} : { "Content-Type": "application/json" }), "X-Forwarded-Proto": "https",
      "X-Requested-With": "XMLHttpRequest", ...auth },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.any([cancelled.signal, AbortSignal.timeout(10_000)]),
  });
  const data = await response.json();
  if (typeof data?.ingestToken === "string" && data.ingestToken) fixtureSecrets.add(data.ingestToken);
  for (const cookie of response.headers.getSetCookie()) {
    const token = cookie.split(";")[0].split("=").slice(1).join("=");
    if (token) fixtureSecrets.add(token);
  }
  if (expected !== null) assert.equal(response.status, expected, `${method} ${path}: ${redact(JSON.stringify(data))}`);
  return { status: response.status, data, headers: response.headers };
}
async function tenant(app, label) {
  const signup = await request(app, "/auth/signup", { method: "POST", expected: 201,
    body: { email: `${id}-${label}@example.test`, password, orgName: label } });
  const cookie = signup.headers.getSetCookie().find((c) => c.startsWith("av_session="))?.split(";")[0];
  assert.ok(cookie);
  const auth = { Cookie: cookie };
  const deployment = await request(app, "/deployments", { method: "POST", expected: 201, auth,
    body: { name: label, environment: "development" } });
  return { auth, userId: signup.data.user.id, orgId: signup.data.org.id,
    daemon: { Authorization: "Bearer " + deployment.data.ingestToken, "X-AV-Deployment": deployment.data.deployment.id } };
}
async function stream(app, owner) {
  const abort = new AbortController();
  const response = await fetch(app.url + "/api/v1/stream", { headers: { ...owner.auth,
    "X-Forwarded-Proto": "https" }, signal: AbortSignal.any([abort.signal, cancelled.signal]) });
  assert.equal(response.status, 200);
  const feed = { abort, events: [], closed: false, error: null };
  streams.push(feed);
  feed.reading = (async () => {
    const decoder = new TextDecoder(); let pending = "";
    for await (const chunk of response.body) {
      pending += decoder.decode(chunk, { stream: true });
      let split;
      while ((split = pending.indexOf("\n\n")) >= 0) {
        const frame = pending.slice(0, split); pending = pending.slice(split + 2);
        const type = frame.match(/^event: (.+)$/m)?.[1], data = frame.match(/^data: (.+)$/m)?.[1];
        if (type && data) feed.events.push({ type, data: JSON.parse(data) });
      }
    }
  })().catch((error) => { feed.error = error.name; }).finally(() => { feed.closed = true; });
  await until(() => feed.events.some((event) => event.type === "hello"), "SSE hello");
  return feed;
}
async function connect(database) {
  const client = new pg.Client({ connectionString: database, connectionTimeoutMillis: 1000, query_timeout: 5000 });
  client.on("error", () => {});
  try { await client.connect(); clients.push(client); return client; }
  catch (error) { await closeDrillClient(client).catch(() => {}); throw error; }
}

console.log(`Recovery fixture ${id}; logs: ${output}`);
try {
  const envFile = join(output, "postgres.env");
  privateFiles.push(envFile);
  await writeFile(envFile, `POSTGRES_USER=avrecovery\nPOSTGRES_PASSWORD=${password}\nPOSTGRES_DB=avrecovery\n`, { mode: 0o600 });
  if (apiImage) {
    networkCreationAttempted = true;
    await command("docker", ["network", "create", "--label", `agentvisor.drill=${id}`, networkName]);
  }
  // The daemon can accept creation before the CLI response fails or is
  // cancelled. Record intent before dispatch and inspect ownership later.
  containerIntents.push(id);
  await command("docker", ["run", "--detach", "--pull=never", "--name", id, "--label", `agentvisor.drill=${id}`,
    ...(apiImage ? ["--network", networkName] : []),
    "--memory", "512m", "--cpus", "2", "--env-file", envFile, "-p", "127.0.0.1::5432", process.env.PG_IMAGE || "postgres:15"]);
  const info = JSON.parse(await command("docker", ["inspect", id]))[0];
  report.postgresImage = info.Image;
  const database = `postgresql://avrecovery:${password}@127.0.0.1:${info.NetworkSettings.Ports["5432/tcp"][0].HostPort}/avrecovery`;
  let db;
  await until(async () => { try { db = await connect(database); return true; } catch { return false; } }, "database startup");
  const admin = await connect(database.replace(/\/avrecovery$/, "/postgres"));
  if (!apiImage) await command(process.execPath, [join(root, "node_modules/prisma/build/index.js"), "migrate", "deploy", "--schema", join(root, "prisma/schema.prisma")],
    { cwd: output, env: { PATH: process.env.PATH, HOME: process.env.HOME, DATABASE_URL: database } });
  // The image's normal entrypoint applies its own bundled migrations.
  const apiDatabase = apiImage ? `postgresql://avrecovery:${password}@${id}:5432/avrecovery` : database;
  const a = await startApi(apiDatabase, "api-a"), b = await startApi(apiDatabase, "api-b");
  const alpha = await tenant(a, "alpha"), beta = await tenant(b, "beta");
  const feed = await stream(a, alpha), foreign = await stream(b, beta);
  await until(async () => {
    const rows = (await admin.query("SELECT pid FROM pg_stat_activity WHERE datname='avrecovery' AND application_name=$1 AND state='idle' AND query='SELECT 1 /* av_bus listener heartbeat */'", [`${id}-api-a`])).rows;
    return rows.length === 1;
  }, "the fixture listener heartbeat reaches actual PostgreSQL", 20_000);
  check("the dedicated listener heartbeat completes against PostgreSQL", true);
  // The dedicated listener periodically probes its established connection;
  // either exact statement identifies it, within this fixture's application.
  const listener = (await admin.query("SELECT pid FROM pg_stat_activity WHERE datname='avrecovery' AND application_name=$1 AND query IN ('LISTEN av_bus', 'SELECT 1 /* av_bus listener heartbeat */')", [`${id}-api-a`])).rows;
  assert.equal(listener.length, 1, "identify only this fixture instance's LISTEN socket");
  await admin.query("SELECT pg_terminate_backend($1)", [listener[0].pid]);
  const session = await request(b, "/ingest/sessions", { method: "POST", auth: alpha.daemon,
    body: { externalId: "during-listener-recovery", agent: "fixture", openedAt: new Date().toISOString() } });
  await until(() => feed.closed && foreign.closed, "bridge recovery must reset local and peer SSE sockets");
  check("LISTEN recovery resets existing local and peer SSE connections", [feed, foreign].every((f) => f.events.some((e) => e.type === "stream_reset")));
  const detail = await request(a, "/sessions/" + session.data.session.id, { auth: alpha.auth });
  check("authoritative read after reconnect includes the committed session", detail.data.session.id === session.data.session.id);
  await request(a, "/sessions/" + session.data.session.id, { auth: beta.auth, expected: 404 });
  check("peer reset exposes no other tenant's event data", foreign.events.every((e) => !e.data.orgId || e.data.orgId === beta.orgId));

  await db.query(`CREATE FUNCTION fail_fixture_logout() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN IF NEW."sessionRevokedAt" IS DISTINCT FROM OLD."sessionRevokedAt" THEN RAISE EXCEPTION 'injected logout persistence outage'; END IF; RETURN NEW; END $$;
    CREATE TRIGGER fail_fixture_logout BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION fail_fixture_logout()`);
  const failed = await request(a, "/auth/logout", { method: "POST", auth: alpha.auth, expected: 503 });
  check("failed logout preserves its cookie so durable revocation can be retried", failed.headers.getSetCookie().length === 0);
  await request(b, "/auth/me", { auth: alpha.auth });
  const audit = await db.query("SELECT count(*)::int AS n FROM audit_entries WHERE event='auth.logout' AND \"actorId\"=$1", [alpha.userId]);
  check("failed logout does not claim successful revocation in the audit log", audit.rows[0].n === 0);
  await db.query("DROP TRIGGER fail_fixture_logout ON users; DROP FUNCTION fail_fixture_logout()");
  const logout = await request(a, "/auth/logout", { method: "POST", auth: alpha.auth });
  check("successful retry clears the session cookie", logout.headers.getSetCookie().some((c) => c.includes("Max-Age=0")));
  await request(b, "/auth/me", { auth: alpha.auth, expected: 401 });
  check("a successful logout revokes captured cookies on the other instance", true);

  await db.end();
  await admin.query("ALTER DATABASE avrecovery WITH ALLOW_CONNECTIONS false");
  await admin.query("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='avrecovery'");
  for (const app of apps) {
    const ready = await fetch(app.url + "/readyz", { signal: AbortSignal.timeout(10_000) });
    check(`${app.label} reports database outage through readiness`, ready.status === 503);
    const read = await request(app, "/sessions", { auth: beta.auth, expected: null });
    check(`${app.label} fails closed while session authorization cannot reach the database`, read.status >= 500 && read.status < 600);
  }
  await admin.query("ALTER DATABASE avrecovery WITH ALLOW_CONNECTIONS true");
  report.databaseRestoredAt = new Date().toISOString();
  const direct = await connect(database);
  assert.equal((await direct.query("SELECT 1 AS healthy")).rows[0].healthy, 1);
  report.recoverySamples = [];
  await until(async () => {
    const checks = await Promise.all(apps.map(async (app) => {
    const ready = await fetch(app.url + "/readyz", { signal: AbortSignal.timeout(1000) }).then((r) => r.json()).catch(() => null);
    return { instance: app.label, checks: ready?.checks ?? null };
    }));
    report.recoverySamples.push({ at: new Date().toISOString(), instances: checks });
    return checks.every((result) => result.checks?.db === "ok" && result.checks?.bus === "ok");
  // The bridge's existing maximum reconnect backoff is 30 seconds.
  // This bound permits one such delay without changing runtime settings.
  }, "both database pools and bridges recover", 40_000, 500);
  await request(a, "/auth/me", { auth: beta.auth });
  await request(b, "/auth/me", { auth: beta.auth });
  check("both instances recover existing authenticated sessions after database access returns", true);
  const shutdownFeeds = [await stream(a, beta), await stream(b, beta)];
  for (const app of apps) await stopApi(app);
  await until(() => shutdownFeeds.every((f) => f.closed), "SSE closes on graceful shutdown");
  check("SIGTERM exits both APIs cleanly with authenticated SSE clients still connected", true);
  report.status = "passed";
} catch (error) {
  report.status = "failed";
  report.error = redact(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
  console.error(report.error);
} finally {
  cleaningUp = true;
  clearTimeout(deadline);
  for (const feed of streams) feed.abort.abort();
  await Promise.allSettled(streams.map((feed) => feed.reading));
  const cleanup = await Promise.allSettled(apps.map(stopApi));
  cleanup.push(...await Promise.allSettled(clients.map((client) => closeDrillClient(client))));
  for (const container of [...containerIntents].reverse()) cleanup.push(...await Promise.allSettled([(async () => {
    // A successful empty query establishes absence. A failed Docker query
    // must remain a cleanup error, rather than claiming the container is gone.
    const ids = (await command("docker", ["container", "ls", "--all", "--filter", `name=^/${container}$`, "--format", "{{.ID}}"])).split(/\s+/).filter(Boolean);
    for (const containerId of ids) {
      const owner = await command("docker", ["inspect", "--format", '{{ index .Config.Labels "agentvisor.drill" }}', containerId]);
      assert.equal(owner, id, "refusing cleanup of a container without this drill's ownership label");
      if (container !== id) {
        // A log read failure must not prevent removal of the owned resource.
        try {
          const logs = await command("docker", ["logs", containerId], { includeStderr: true });
          await writeFile(join(output, container.slice(id.length + 1) + ".log"), redact(logs) + "\n", { mode: 0o600 });
        } catch (error) { cleanup.push({ status: "rejected", reason: error }); }
      }
      // PostgreSQL declares an anonymous data volume; remove it with the
      // exact owned container so failed drills retain no database contents.
      await command("docker", ["rm", "-f", "-v", containerId]);
    }
  })()]));
  if (networkCreationAttempted) cleanup.push(...await Promise.allSettled([(async () => {
    const ids = (await command("docker", ["network", "ls", "--filter", `name=^${networkName}$`, "--format", "{{.ID}}"])).split(/\s+/).filter(Boolean);
    for (const networkId of ids) {
      const owner = await command("docker", ["network", "inspect", "--format", '{{ index .Labels "agentvisor.drill" }}', networkId]);
      assert.equal(owner, id, "refusing cleanup of a network without this drill's ownership label");
      await command("docker", ["network", "rm", networkId]);
    }
  })()]));
  cleanup.push(...await Promise.allSettled(privateFiles.map((path) => rm(path, { force: true }))));
  report.cleanupErrors = cleanup.filter((r) => r.status === "rejected").map((r) => redact(String(r.reason)));
  if (cancelled.signal.aborted) { report.status = "failed"; process.exitCode = 1; }
  if (report.cleanupErrors.length) { report.status = "failed"; process.exitCode = 1; }
  report.finishedAt = new Date().toISOString();
  await writeFile(join(output, "report.json"), JSON.stringify(report, null, 2) + "\n", { mode: 0o600 });
  console.log(`Result: ${report.status}; ${report.checks.length} checks; ${join(output, "report.json")}`);
}
