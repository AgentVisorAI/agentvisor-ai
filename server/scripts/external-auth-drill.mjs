// Production-image auth contracts against private PostgreSQL, HTTPS discovery,
// and SMTP fixtures. Requires an already-built image; it never builds or pulls.
// CONSOLE_AUTH_IMAGE=<image> node scripts/external-auth-drill.mjs
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { once } from "node:events";
import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import pg from "pg";
import { closeDrillClient } from "./auth-drill-cleanup.mjs";

const image = process.env.CONSOLE_AUTH_IMAGE;
assert.ok(image, "CONSOLE_AUTH_IMAGE must select an already-built production image");
const pgImage = process.env.AUTH_POSTGRES_IMAGE || "postgres:16-alpine@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea";
const root = fileURLToPath(new URL("../", import.meta.url));
const id = "av-auth-" + randomBytes(6).toString("hex");
const output = await mkdtemp(join(process.env.AUTH_DRILL_OUTPUT_PARENT || tmpdir(), id + "-"));
await chmod(output, 0o700);
const password = randomBytes(24).toString("hex"), jwt = randomBytes(48).toString("hex");
const controlToken = randomBytes(32).toString("hex");
const secrets = new Set([password, jwt, controlToken]);
const resetTokens = new Set();
const privateFiles = [], containers = [], commands = new Set(), clients = [];
const cancelled = new AbortController();
const dockerEnv = { ...process.env };
if (process.platform === "darwin") dockerEnv.DOCKER_HOST = process.env.DOCKER_HOST || `unix://${process.env.HOME}/.colima/default/docker.sock`;
delete dockerEnv.DOCKER_CONTEXT;
let cleaningUp = false, networkAttempted = false, controlUrl;
const report = { id, startedAt: new Date().toISOString(), checks: [], status: "running" };
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const redact = (value) => {
  let result = String(value);
  for (const secret of secrets) if (secret) result = result.replaceAll(secret, "[fixture-secret]");
  return result;
};
function check(label, condition) { assert.ok(condition, label); report.checks.push(label); console.log("PASS " + label); }
function cancel() {
  if (cleaningUp || cancelled.signal.aborted) return;
  cancelled.abort();
  for (const child of commands) child.kill("SIGTERM");
}
process.on("SIGTERM", cancel); process.on("SIGINT", cancel);
const deadline = setTimeout(cancel, 300_000);

async function command(binary, args, options = {}) {
  if (!cleaningUp) cancelled.signal.throwIfAborted();
  const child = spawn(binary, args, { cwd: root, env: binary === "docker" ? dockerEnv : process.env,
    stdio: ["ignore", "pipe", "pipe"], ...options });
  commands.add(child);
  let stdout = "", stderr = "";
  child.stdout.on("data", (chunk) => { stdout += chunk; });
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  const timer = setTimeout(() => child.kill("SIGKILL"), cleaningUp ? 10_000 : 45_000);
  try {
    const [code] = await once(child, "close");
    assert.equal(code, 0, redact(`${binary} ${args[0]} failed: ${stderr.slice(-2000)}`));
    return (args[0] === "logs" ? stdout + stderr : stdout).trim();
  } finally { clearTimeout(timer); commands.delete(child); }
}
async function until(predicate, label, timeoutMs = 20_000) {
  const expires = Date.now() + timeoutMs;
  while (Date.now() < expires) {
    cancelled.signal.throwIfAborted();
    if (await predicate()) return;
    await sleep(50);
  }
  throw new Error(label + " timed out");
}
async function envFile(label, values) {
  const path = join(output, label + ".env"); privateFiles.push(path);
  await writeFile(path, Object.entries(values).map(([key, value]) => `${key}=${value}`).join("\n") + "\n", { mode: 0o600 });
  return path;
}
async function runContainer(label, args, copies = []) {
  const name = id + "-" + label;
  // Register intent before dispatch: Docker can create the resource even if
  // its response fails or the caller is cancelled.
  containers.push(name);
  await command("docker", ["create", "--pull=never", "--name", name,
    "--label", `agentvisor.auth-drill=${id}`, "--network", id, ...args]);
  // Copy through the Docker API, so remote engines need not share host /tmp.
  for (const [source, destination] of copies) await command("docker", ["cp", source, `${name}:${destination}`]);
  await command("docker", ["start", name]);
  return name;
}
async function endpoint(name, port) {
  const ports = JSON.parse(await command("docker", ["inspect", "--format", "{{json .NetworkSettings.Ports}}", name]));
  if (!ports[`${port}/tcp`]?.[0]) {
    report.endpointFailure = { name, port, ports,
      state: JSON.parse(await command("docker", ["inspect", "--format", "{{json .State}}", name])),
      bindings: JSON.parse(await command("docker", ["inspect", "--format", "{{json .HostConfig.PortBindings}}", name])) };
  }
  assert.equal(ports[`${port}/tcp`]?.[0]?.HostIp, "127.0.0.1");
  return "http://127.0.0.1:" + ports[`${port}/tcp`][0].HostPort;
}
async function connect(url) {
  const client = new pg.Client({ connectionString: url, connectionTimeoutMillis: 1000, query_timeout: 20_000 });
  client.on("error", () => {});
  try { await client.connect(); clients.push(client); return client; }
  catch (error) { await closeDrillClient(client).catch(() => {}); throw error; }
}
async function control(values) {
  const response = await fetch(controlUrl, { method: values ? "POST" : "GET",
    headers: { Authorization: "Bearer " + controlToken, "Content-Type": "application/json" },
    body: values ? JSON.stringify(values) : undefined,
    signal: AbortSignal.any([cancelled.signal, AbortSignal.timeout(3000)]) });
  assert.equal(response.status, 200); return response.json();
}
async function request(app, path, { method = "GET", body, cookie, bearer, expected = 200, ip = "198.18.0.1" } = {}) {
  const response = await fetch(app + "/api/v1" + path, {
    method, redirect: "manual", headers: { "X-Forwarded-Proto": "https", "X-Forwarded-For": ip,
      "X-Requested-With": "XMLHttpRequest", ...(body === undefined ? {} : { "Content-Type": "application/json" }),
      ...(cookie ? { Cookie: cookie } : {}), ...(bearer ? { Authorization: "Bearer " + bearer } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.any([cancelled.signal, AbortSignal.timeout(15_000)]),
  });
  const text = await response.text();
  let data; try { data = JSON.parse(text); } catch { data = null; }
  if (expected !== null) assert.equal(response.status, expected, redact(`${method} ${path}: ${text}`));
  return { status: response.status, data, headers: response.headers };
}
async function tenant(app, label) {
  const email = `${id}-${label}@example.test`;
  const result = await request(app, "/auth/signup", { method: "POST", expected: 201,
    body: { email, password, orgName: label } });
  const cookie = result.headers.getSetCookie().find((value) => value.startsWith("av_session="))?.split(";")[0];
  assert.ok(cookie); secrets.add(cookie.split("=")[1]);
  return { email, cookie, userId: result.data.user.id, orgId: result.data.org.id };
}
function decodedMail(message) {
  return message.data.replace(/=\r?\n/g, "").replace(/=([0-9a-f]{2})/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
}
async function resetToken(app, owner, ip) {
  const before = (await control()).messages.length;
  await request(app, "/auth/reset-request", { method: "POST", body: { email: owner.email }, expected: 202, ip });
  let message;
  await until(async () => {
    message = (await control()).messages.slice(before).find((item) => item.to === owner.email && decodedMail(item).includes("/reset?token="));
    return message;
  }, "reset email");
  assert.equal(message.accepted, true);
  const token = decodedMail(message).match(/\/reset\?token=([^&\s"<>]+)/)?.[1];
  assert.ok(token); secrets.add(token); resetTokens.add(token); return decodeURIComponent(token);
}
async function startApi(label, cert) {
  const db = new URL(`postgresql://avapp:${password}@auth-db:5432/avauth`);
  db.searchParams.set("application_name", id + "-" + label);
  const file = await envFile(label, { NODE_ENV: "production", HOST: "0.0.0.0", PORT: "8080",
    DATABASE_URL: db.toString(), JWT_SECRET: jwt, APP_BASE_URL: "https://console.example.test",
    API_PUBLIC_URL: "https://api.example.test", ALLOWED_ORIGINS: "https://console.example.test",
    SMTP_URL: "smtp://auth-provider:2525", EMAIL_FROM: "fixture@example.test", RESEND_API_KEY: "",
    LOG_LEVEL: "info", TRUSTED_PROXY_HOP_COUNT: "1", NODE_EXTRA_CA_CERTS: "/tmp/provider-ca.pem",
    OIDC_ISSUER_URL: "https://auth-provider:8443", OIDC_CLIENT_ID: "fixture", OIDC_CLIENT_SECRET: "fixture-secret" });
  const name = await runContainer(label, ["--env-file", file, "-p", "127.0.0.1::8080", image],
    [[cert, "/tmp/provider-ca.pem"]]);
  const url = await endpoint(name, 8080);
  await until(async () => {
    const state = await fetch(url + "/readyz", { signal: AbortSignal.timeout(1000) }).then((r) => r.json()).catch(() => null);
    return state?.checks?.db === "ok" && state?.checks?.bus === "ok";
  }, label + " readiness", 45_000);
  return url;
}

console.log(`Authentication fixture ${id}; evidence: ${output}`);
try {
  report.fixtureSha256 = {};
  for (const file of ["external-auth-drill.mjs", "auth-provider-fixture.mjs", "auth-drill-cleanup.mjs"]) {
    report.fixtureSha256[file] = createHash("sha256").update(await readFile(join(root, "scripts", file))).digest("hex");
  }
  report.consoleImageId = await command("docker", ["image", "inspect", "--format", "{{.Id}}", image]);
  report.postgresImageId = await command("docker", ["image", "inspect", "--format", "{{.Id}}", pgImage]);
  networkAttempted = true;
  // A separate bridge and loopback-only published ports keep fixture traffic
  // isolated from other containers. All configured services are owned here.
  await command("docker", ["network", "create", "--label", `agentvisor.auth-drill=${id}`, id]);
  const cert = join(output, "provider-ca.pem"), key = join(output, "provider-key.pem");
  privateFiles.push(cert, key);
  await command("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
    "-subj", "/CN=auth-provider", "-addext", "subjectAltName=DNS:auth-provider", "-keyout", key, "-out", cert]);
  // Only these ephemeral fixture files are readable by the image's non-root UID.
  await chmod(key, 0o644); await chmod(cert, 0o644);
  const providerFile = await envFile("provider", { FIXTURE_CONTROL_TOKEN: controlToken });
  const provider = await runContainer("provider", ["--network-alias", "auth-provider", "--env-file", providerFile,
    "--entrypoint", "/nodejs/bin/node", "-p", "127.0.0.1::8081", image, "/tmp/provider.mjs"],
    [[join(root, "scripts/auth-provider-fixture.mjs"), "/tmp/provider.mjs"],
      [cert, "/tmp/provider-ca.pem"], [key, "/tmp/provider-key.pem"]]);
  controlUrl = await endpoint(provider, 8081);
  await until(() => control().then(() => true).catch(() => false), "provider control");
  const pgFile = await envFile("postgres", { POSTGRES_USER: "avadmin", POSTGRES_PASSWORD: password, POSTGRES_DB: "avauth" });
  const postgres = await runContainer("postgres", ["--network-alias", "auth-db", "--env-file", pgFile,
    "-p", "127.0.0.1::5432", pgImage]);
  const pgPort = new URL(await endpoint(postgres, 5432)).port;
  let admin;
  await until(async () => {
    try { admin = await connect(`postgresql://avadmin:${password}@127.0.0.1:${pgPort}/avauth`); return true; }
    catch { return false; }
  }, "database startup");
  // Generated hex password, never supplied on a process command line.
  await admin.query(`CREATE ROLE avapp LOGIN PASSWORD '${password}'; ALTER DATABASE avauth OWNER TO avapp`);
  report.postgresVersion = (await admin.query("SHOW server_version")).rows[0].server_version;
  assert.equal((await admin.query("SELECT rolsuper FROM pg_roles WHERE rolname='avapp'")).rows[0].rolsuper, false);
  const a = await startApi("api-a", cert), b = await startApi("api-b", cert);
  check("Two production containers migrate and share the private database", true);

  const unavailable = "https://console.example.test/app/#/login?err=oauth_provider_unavailable";
  const failedStart = await request(a, "/auth/oauth/oidc/start", { expected: 302 });
  check("OIDC discovery failure redirects the browser without a session", failedStart.headers.get("location") === unavailable &&
    !failedStart.headers.getSetCookie().some((value) => value.startsWith("av_session=")));
  await control({ discoveryAvailable: true });
  const start = await request(a, "/auth/oauth/oidc/start", { expected: 302 });
  const location = new URL(start.headers.get("location"));
  const stateCookie = start.headers.getSetCookie().find((value) => value.startsWith("av_oauth_state="))?.split(";")[0];
  check("OIDC discovery recovers and begins PKCE with a signed state cookie", location.origin === "https://auth-provider:8443" &&
    location.searchParams.has("code_challenge") && !!stateCookie);
  secrets.add(stateCookie.split("=")[1]);
  await control({ discoveryAvailable: false });
  const failedCallback = await request(b, `/auth/oauth/oidc/callback?code=fixture&state=${encodeURIComponent(location.searchParams.get("state"))}`,
    { cookie: stateCookie, expected: 302 });
  check("Fresh replica callback discovery failure redirects without a session", failedCallback.headers.get("location") === unavailable &&
    !failedCallback.headers.getSetCookie().some((value) => value.startsWith("av_session=")));
  await control({ discoveryAvailable: true });
  const retry = await request(b, "/auth/oauth/oidc/start", { expected: 302 });
  check("Fresh replica retries discovery successfully", new URL(retry.headers.get("location")).origin === "https://auth-provider:8443");

  const samlUser = await tenant(a, "saml"), resetUser = await tenant(a, "reset"), raceUser = await tenant(a, "race");
  await admin.query(`INSERT INTO saml_configs (id,"orgId","displayName","ssoUrl","entityIdIdp","x509Cert","updatedAt")
    VALUES ($1,$2,'Fixture','https://idp.example.test/sso','fixture','unused-local-logout-fixture',now())`, [id, samlUser.orgId]);
  await admin.query(`CREATE FUNCTION fixture_deny_logout() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
    IF NEW.id = '${samlUser.userId}' AND NEW."sessionRevokedAt" IS DISTINCT FROM OLD."sessionRevokedAt"
    THEN RAISE EXCEPTION 'injected logout persistence failure'; END IF; RETURN NEW; END $$;
    CREATE TRIGGER fixture_deny_logout BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION fixture_deny_logout()`);
  const failedLogout = await request(a, `/auth/saml/${id}/slo`, { method: "POST", cookie: samlUser.cookie, expected: 503 });
  report.samlFailureResponse = { status: failedLogout.status, body: failedLogout.data,
    setCookieCount: failedLogout.headers.getSetCookie().length };
  check("SAML logout refuses success and preserves the cookie on a real SQL write failure",
    failedLogout.data.errorCode === "session_revocation_unavailable" && failedLogout.headers.getSetCookie().length === 0);
  await request(b, "/auth/me", { cookie: samlUser.cookie });
  const absentAudit = await admin.query('SELECT count(*)::int AS n FROM audit_entries WHERE event=$1 AND "actorId"=$2', ["auth.saml.slo", samlUser.userId]);
  check("Failed SAML logout neither revokes the peer session nor writes a success audit", absentAudit.rows[0].n === 0);
  await admin.query("DROP TRIGGER fixture_deny_logout ON users; DROP FUNCTION fixture_deny_logout()");
  const loggedOut = await request(a, `/auth/saml/${id}/slo`, { method: "POST", cookie: samlUser.cookie });
  await request(b, "/auth/me", { cookie: samlUser.cookie, expected: 401 });
  await until(async () => (await admin.query('SELECT count(*)::int AS n FROM audit_entries WHERE event=$1 AND "actorId"=$2',
    ["auth.saml.slo", samlUser.userId])).rows[0].n === 1, "SAML success audit");
  check("SAML retry durably revokes the peer cookie and records one success", loggedOut.headers.getSetCookie().some((value) => value.includes("Max-Age=0")));

  // Hold the reset lookup's old MVCC snapshot while another transaction
  // commits an email change. A statement trigger also observes a zero-row
  // conditional UPDATE, so absence of mail is checked after work completed.
  const lock = 419872;
  await admin.query(`CREATE TABLE fixture_reset_attempts (at timestamptz DEFAULT now());
    GRANT INSERT ON fixture_reset_attempts TO avapp;
    CREATE FUNCTION fixture_reset_lookup_gate(user_id text) RETURNS boolean LANGUAGE plpgsql VOLATILE AS $$ BEGIN
      IF user_id = '${raceUser.userId}' AND current_setting('application_name') = '${id}-api-a'
      THEN PERFORM pg_advisory_lock(${lock}); PERFORM pg_advisory_unlock(${lock}); END IF; RETURN true; END $$;
    ALTER TABLE users ENABLE ROW LEVEL SECURITY; ALTER TABLE users FORCE ROW LEVEL SECURITY;
    CREATE POLICY fixture_read ON users FOR SELECT USING (fixture_reset_lookup_gate(id));
    CREATE POLICY fixture_write ON users FOR UPDATE USING (true) WITH CHECK (true);
    CREATE FUNCTION fixture_mark_reset_attempt() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
      IF current_setting('application_name') = '${id}-api-a' THEN INSERT INTO fixture_reset_attempts DEFAULT VALUES; END IF;
      RETURN NULL; END $$;
    CREATE TRIGGER fixture_mark_reset_attempt AFTER UPDATE ON users FOR EACH STATEMENT EXECUTE FUNCTION fixture_mark_reset_attempt()`);
  await admin.query("SELECT pg_advisory_lock($1)", [lock]);
  const mailCount = (await control()).messages.length;
  await request(a, "/auth/reset-request", { method: "POST", body: { email: raceUser.email }, expected: 202, ip: "198.18.0.2" });
  await until(async () => (await admin.query(`SELECT count(*)::int AS n FROM pg_stat_activity
    WHERE application_name=$1 AND wait_event='advisory'`, [id + "-api-a"])).rows[0].n === 1, "reset SELECT blocked on old snapshot");
  const newEmail = `${id}-changed@example.test`;
  await admin.query('UPDATE users SET email=$1,"resetTokenHash"=NULL,"resetTokenAt"=NULL WHERE id=$2', [newEmail, raceUser.userId]);
  await admin.query("SELECT pg_advisory_unlock($1)", [lock]);
  await until(async () => (await admin.query("SELECT count(*)::int AS n FROM fixture_reset_attempts")).rows[0].n > 0, "conditional reset write completed");
  const racedUser = (await admin.query('SELECT email,"resetTokenHash","resetTokenAt" FROM users WHERE id=$1', [raceUser.userId])).rows[0];
  const racedMail = (await control()).messages.slice(mailCount).filter((message) => message.to === raceUser.email && decodedMail(message).includes("/reset?token="));
  check("A stale reset lookup cannot reinstall a token after committed email change", racedUser.email === newEmail &&
    racedUser.resetTokenHash === null && racedUser.resetTokenAt === null && racedMail.length === 0);
  await admin.query(`DROP TRIGGER fixture_mark_reset_attempt ON users; DROP FUNCTION fixture_mark_reset_attempt();
    DROP POLICY fixture_read ON users; DROP POLICY fixture_write ON users;
    ALTER TABLE users DISABLE ROW LEVEL SECURITY; ALTER TABLE users NO FORCE ROW LEVEL SECURITY;
    DROP FUNCTION fixture_reset_lookup_gate(text); DROP TABLE fixture_reset_attempts`);

  const keyResult = await request(a, "/keys", { method: "POST", cookie: resetUser.cookie, expected: 201, body: { name: "reset fixture" } });
  const apiKey = keyResult.data.plaintextToken; assert.ok(apiKey); secrets.add(apiKey);
  for (const app of [a, b]) {
    await request(app, "/keys", { bearer: apiKey });
    await request(app, "/auth/me", { cookie: resetUser.cookie });
  }
  const token = await resetToken(a, resetUser, "198.18.0.3");
  const before = (await admin.query('SELECT "passwordHash","resetTokenHash","resetTokenAt","sessionRevokedAt" FROM users WHERE id=$1', [resetUser.userId])).rows[0];
  check("Reset mail is delivered only to the fixture and the database stores a hash", !!before.resetTokenHash && before.resetTokenHash !== token);
  await admin.query(`CREATE FUNCTION fixture_deny_key_revoke() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
    IF NEW."createdById" = '${resetUser.userId}' AND NEW."revokedAt" IS DISTINCT FROM OLD."revokedAt"
    THEN RAISE EXCEPTION 'injected key revocation failure'; END IF; RETURN NEW; END $$;
    CREATE TRIGGER fixture_deny_key_revoke BEFORE UPDATE ON api_keys FOR EACH ROW EXECUTE FUNCTION fixture_deny_key_revoke()`);
  const newPassword = randomBytes(24).toString("hex"); secrets.add(newPassword);
  const confirm = { email: resetUser.email, token, newPassword };
  await request(a, "/auth/reset-confirm", { method: "POST", body: confirm, expected: 500, ip: "198.18.0.4" });
  const rolledBack = (await admin.query('SELECT "passwordHash","resetTokenHash","resetTokenAt","sessionRevokedAt" FROM users WHERE id=$1', [resetUser.userId])).rows[0];
  await request(b, "/keys", { bearer: apiKey });
  check("Failed API-key revocation rolls back password, token consumption, and session fence", JSON.stringify(before) === JSON.stringify(rolledBack));
  await admin.query("DROP TRIGGER fixture_deny_key_revoke ON api_keys; DROP FUNCTION fixture_deny_key_revoke()");
  const results = await Promise.all([a, b].map((app) => request(app, "/auth/reset-confirm", {
    method: "POST", body: confirm, expected: null, ip: "198.18.0.5" })));
  check("Concurrent reset confirmation on two replicas consumes the token once", results.map((value) => value.status).sort().join(",") === "200,401");
  const after = (await admin.query('SELECT "passwordHash","resetTokenHash","resetTokenAt","sessionRevokedAt" FROM users WHERE id=$1', [resetUser.userId])).rows[0];
  for (const app of [a, b]) {
    await request(app, "/auth/me", { cookie: resetUser.cookie, expected: 401 });
    await request(app, "/keys", { bearer: apiKey, expected: 401 });
  }
  check("Successful reset atomically clears its token and revokes old cookies and API keys", after.passwordHash !== before.passwordHash &&
    after.resetTokenHash === null && after.resetTokenAt === null && after.sessionRevokedAt !== null);
  const oldLogin = await request(a, "/auth/login", { method: "POST", body: { email: resetUser.email, password } });
  // Login deliberately returns the decoy MFA response for invalid credentials.
  // A 200 alone is not evidence of authentication; check the minted authority.
  assert.equal(oldLogin.data.mfaRequired, true);
  assert.ok(!oldLogin.headers.getSetCookie().some((value) => value.startsWith("av_session=")));
  const newLogin = await request(b, "/auth/login", { method: "POST", body: { email: resetUser.email, password: newPassword } });
  const newCookie = newLogin.headers.getSetCookie().find((value) => value.startsWith("av_session="))?.split(";")[0];
  assert.ok(newCookie); secrets.add(newCookie.split("=")[1]);
  await request(a, "/auth/me", { cookie: newCookie });
  check("Only the replacement password authenticates after reset", newLogin.data.user.id === resetUser.userId);

  await control({ rejectMail: true });
  const beforeReject = (await control()).messages.length;
  const rejected = await request(a, "/auth/reset-request", { method: "POST", body: { email: resetUser.email }, expected: 202, ip: "198.18.0.6" });
  let failedMail;
  await until(async () => {
    failedMail = (await control()).messages.slice(beforeReject).find((message) => message.to === resetUser.email && decodedMail(message).includes("/reset?token="));
    return failedMail;
  }, "rejected SMTP delivery");
  check("SMTP rejection preserves the uniform public response without claiming delivery", rejected.data.ok === true && failedMail.accepted === false);
  const rejectedToken = decodedMail(failedMail).match(/\/reset\?token=([^&\s"<>]+)/)?.[1];
  if (rejectedToken) { secrets.add(rejectedToken); resetTokens.add(rejectedToken); }
  await until(async () => (await command("docker", ["logs", id + "-api-a"])).includes("password_reset_deferred_failed"), "mail failure logging");
  const aLog = await command("docker", ["logs", id + "-api-a"]);
  const bLog = await command("docker", ["logs", id + "-api-b"]);
  check("The packaged application records SMTP failure without a false delivery log", aLog.split("\n").filter((line) =>
    line.includes("password_reset_email_sent") && line.includes(resetUser.userId)).length === 1);
  check("Production API logs contain no plaintext password-reset tokens", [...resetTokens].every((value) => !aLog.includes(value) && !bLog.includes(value)));
  report.status = "passed";
} catch (error) {
  report.status = "failed"; report.error = redact(error.stack || error);
  console.error(report.error); process.exitCode = 1;
} finally {
  cleaningUp = true; clearTimeout(deadline);
  const cleanupErrors = [];
  for (const client of clients) await closeDrillClient(client).catch((error) => cleanupErrors.push("database client: " + error.message));
  for (const name of [...containers].reverse()) {
    try {
      const found = await command("docker", ["container", "ls", "--all", "--filter", `name=^/${name}$`, "--format", "{{.ID}}"]);
      if (!found) continue;
      assert.ok(!found.includes("\n"), "ambiguous owned container query");
      const owner = await command("docker", ["inspect", "--format", '{{index .Config.Labels "agentvisor.auth-drill"}}', found]);
      assert.equal(owner, id, "refusing to remove a container with the wrong ownership label");
      try {
        const logs = await command("docker", ["logs", found]);
        await writeFile(join(output, name.slice(id.length + 1) + ".log"), redact(logs), { mode: 0o600 });
      } catch (error) { cleanupErrors.push(`${name} logs: ${redact(error.message)}`); }
      await command("docker", ["rm", "-f", "-v", found]);
    } catch (error) { cleanupErrors.push(`${name}: ${redact(error.message)}`); }
  }
  if (networkAttempted) {
    try {
      const found = await command("docker", ["network", "ls", "--filter", `name=^${id}$`, "--format", "{{.ID}}"]);
      if (found) {
        assert.ok(!found.includes("\n"), "ambiguous owned network query");
        const owner = await command("docker", ["network", "inspect", "--format", '{{index .Labels "agentvisor.auth-drill"}}', found]);
        assert.equal(owner, id, "refusing to remove a network with the wrong ownership label");
        await command("docker", ["network", "rm", found]);
      }
    } catch (error) { cleanupErrors.push("network: " + redact(error.message)); }
  }
  for (const file of privateFiles) await rm(file, { force: true }).catch((error) => cleanupErrors.push("private fixture file: " + error.message));
  report.cleanupErrors = cleanupErrors; report.finishedAt = new Date().toISOString();
  if (cleanupErrors.length) { report.status = "failed"; process.exitCode = 1; }
  await writeFile(join(output, "report.json"), JSON.stringify(report, null, 2) + "\n", { mode: 0o600 });
  console.log(`${report.status}: ${report.checks.length} checks; evidence: ${output}`);
}
