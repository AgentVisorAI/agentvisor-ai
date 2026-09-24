// Signed SAML responses across two real APIs and a disposable PostgreSQL DB.
// Run after npm run build, or set CONSOLE_SAML_IMAGE to an already-built image.
// No request is sent to the advertised example.test IdP or to an external SMTP server.
import assert from "node:assert/strict";
import { randomBytes, createHash, createHmac } from "node:crypto";
import { once } from "node:events";
import { createWriteStream } from "node:fs";
import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import { createServer } from "node:net";
import { inflateRawSync } from "node:zlib";
import { SignedXml } from "xml-crypto";
import pg from "pg";
import { closeDrillClient } from "./auth-drill-cleanup.mjs";

const root = fileURLToPath(new URL("../", import.meta.url));
const id = "av-saml-shared-" + randomBytes(6).toString("hex");
const output = await mkdtemp(join(process.env.SAML_DRILL_OUTPUT_PARENT || tmpdir(), id + "-"));
await chmod(output, 0o700);
const image = process.env.CONSOLE_SAML_IMAGE;
const pgImage = process.env.SAML_POSTGRES_IMAGE || "postgres:16-alpine@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea";
const password = randomBytes(24).toString("hex"), jwt = randomBytes(48).toString("hex");
const secrets = new Set([password, jwt]);
const privateFiles = [], containers = [], apps = [], clients = [], commands = new Set();
const cancelled = new AbortController();
const dockerEnv = { ...process.env };
if (process.platform === "darwin") dockerEnv.DOCKER_HOST = process.env.DOCKER_HOST || `unix://${process.env.HOME}/.colima/default/docker.sock`;
delete dockerEnv.DOCKER_CONTEXT;
let cleanup = false, networkAttempted = false, database, admin;
const report = { id, startedAt: new Date().toISOString(), status: "running", checks: [], responses: [] };
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const redact = (value) => { let text = String(value); for (const secret of secrets) text = text.replaceAll(secret, "[fixture-secret]"); return text; };
function check(label, condition) { assert.ok(condition, label); report.checks.push(label); console.log("PASS " + label); }
function cancel() { if (cleanup || cancelled.signal.aborted) return; cancelled.abort(); for (const child of commands) child.kill("SIGTERM"); }
process.on("SIGTERM", cancel); process.on("SIGINT", cancel);
const deadline = setTimeout(cancel, 300_000);
async function command(binary, args, options = {}) {
  if (!cleanup) cancelled.signal.throwIfAborted();
  const child = spawn(binary, args, { cwd: root, env: binary === "docker" ? dockerEnv : process.env,
    stdio: ["ignore", "pipe", "pipe"], ...options });
  commands.add(child); let stdout = "", stderr = "";
  child.stdout.on("data", (chunk) => { stdout += chunk; }); child.stderr.on("data", (chunk) => { stderr += chunk; });
  const timer = setTimeout(() => child.kill("SIGKILL"), cleanup ? 10_000 : 45_000);
  try { const [code] = await once(child, "close"); assert.equal(code, 0, redact(`${binary} ${args[0]}: ${stderr.slice(-2000)}`));
    return (args[0] === "logs" ? stdout + stderr : stdout).trim();
  } finally { clearTimeout(timer); commands.delete(child); }
}
async function until(predicate, label, timeout = 20_000) {
  const end = Date.now() + timeout;
  while (Date.now() < end) { cancelled.signal.throwIfAborted(); if (await predicate()) return; await sleep(50); }
  throw new Error(label + " timed out");
}
async function envFile(label, values) {
  const file = join(output, label + ".env"); privateFiles.push(file);
  await writeFile(file, Object.entries(values).map(([key, value]) => `${key}=${value}`).join("\n") + "\n", { mode: 0o600 }); return file;
}
async function container(label, args) {
  const name = id + "-" + label; containers.push(name);
  await command("docker", ["run", "--pull=never", "-d", "--name", name, "--label", `agentvisor.saml-drill=${id}`,
    "--network", id, ...args]); return name;
}
async function endpoint(name, port) {
  const ports = JSON.parse(await command("docker", ["inspect", "--format", "{{json .NetworkSettings.Ports}}", name]));
  assert.equal(ports[`${port}/tcp`]?.[0]?.HostIp, "127.0.0.1");
  return "http://127.0.0.1:" + ports[`${port}/tcp`][0].HostPort;
}
async function freePort() {
  const socket = createServer(); socket.listen(0, "127.0.0.1"); await once(socket, "listening");
  const port = socket.address().port; await new Promise((resolve) => socket.close(resolve)); return port;
}
async function connect() {
  const client = new pg.Client({ connectionString: database, connectionTimeoutMillis: 1000, query_timeout: 10_000 });
  client.on("error", () => {});
  try { await client.connect(); clients.push(client); return client; }
  catch (error) { await closeDrillClient(client).catch(() => {}); throw error; }
}
async function ready(app) {
  await until(async () => {
    if (app.startError) throw app.startError;
    if (app.child) assert.equal(app.child.exitCode, null, app.label + " exited");
    const value = await fetch(app.url + "/readyz", { signal: AbortSignal.timeout(1000) }).then((r) => r.json()).catch(() => null);
    return value?.checks?.db === "ok" && value?.checks?.bus === "ok";
  }, app.label + " readiness", 45_000);
}
async function startApi(label, existing) {
  const app = existing || { label, generation: 0 }; if (!existing) apps.push(app); app.generation++;
  const db = image ? `postgresql://avapp:${password}@${id}-postgres:5432/avsaml` : database.replace("avadmin:", "avapp:");
  const port = image ? 8080 : await freePort();
  const env = { NODE_ENV: "production", HOST: image ? "0.0.0.0" : "127.0.0.1", PORT: String(port),
    DATABASE_URL: db, JWT_SECRET: jwt, APP_BASE_URL: "https://console.example.test", API_PUBLIC_URL: "https://api.example.test",
    ALLOWED_ORIGINS: "https://console.example.test", SMTP_URL: "smtp://127.0.0.1:1", RESEND_API_KEY: "", LOG_LEVEL: "info",
    TRUSTED_PROXY_HOP_COUNT: "1" };
  if (image) {
    if (existing) await command("docker", ["start", app.name]);
    else { const file = await envFile(label, env); app.name = await container(label, ["--env-file", file, "-p", "127.0.0.1::8080", image]); }
    app.url = await endpoint(app.name, 8080);
  } else {
    const log = createWriteStream(join(output, `${label}-${app.generation}.log`), { mode: 0o600 });
    app.log = log;
    app.child = spawn(process.execPath, [join(root, "dist/index.js")], { cwd: output,
      env: { PATH: process.env.PATH, HOME: process.env.HOME, ...env }, stdio: ["ignore", "pipe", "pipe"] });
    app.child.on("error", (error) => { app.startError = error; });
    app.child.stdout.pipe(log, { end: false }); app.child.stderr.pipe(log, { end: false });
    app.url = `http://127.0.0.1:${port}`;
  }
  await ready(app); return app;
}
async function stopApi(app) {
  if (image) { await command("docker", ["stop", "-t", "5", app.name]); return; }
  if (app.child?.pid && app.child.exitCode === null && app.child.signalCode === null) {
    const stopped = once(app.child, "exit"); app.child.kill("SIGTERM");
    const timer = setTimeout(() => app.child.kill("SIGKILL"), 5000);
    await stopped; clearTimeout(timer);
  }
  if (app.log && !app.log.writableEnded) await new Promise((resolve) => app.log.end(resolve));
}
async function request(app, path, { method = "GET", body, cookie, form = false, expected = 200 } = {}) {
  const response = await fetch(app.url + "/api/v1" + path, { method, redirect: "manual",
    headers: { "X-Forwarded-Proto": "https", "X-Requested-With": "XMLHttpRequest", Origin: "https://console.example.test",
      ...(cookie ? { Cookie: cookie } : {}), ...(body ? { "Content-Type": form ? "application/x-www-form-urlencoded" : "application/json" } : {}) },
    body: body ? (form ? new URLSearchParams(body).toString() : JSON.stringify(body)) : undefined,
    signal: AbortSignal.any([cancelled.signal, AbortSignal.timeout(20_000)]) });
  const text = await response.text(); let data; try { data = JSON.parse(text); } catch { data = null; }
  if (expected !== null) assert.equal(response.status, expected, redact(`${path}: ${text}`));
  return { status: response.status, headers: response.headers, data, text };
}
function cookie(response, name) { const value = response.headers.getSetCookie().find((item) => item.startsWith(name + "="))?.split(";")[0];
  if (value) secrets.add(value.slice(name.length + 1)); return value; }
async function signup(app, suffix) {
  const email = `${id}-${suffix}@example.test`;
  const result = await request(app, "/auth/signup", { method: "POST", body: { email, password, orgName: suffix }, expected: 201 });
  return { email, userId: result.data.user.id, orgId: result.data.org.id, cookie: cookie(result, "av_session") };
}
async function config(app, owner, label, cert) {
  return (await request(app, "/auth/saml", { method: "POST", cookie: owner.cookie, expected: 201,
    body: { displayName: label, ssoUrl: "https://idp.example.test/sso", entityIdIdp: "https://idp.example.test/entity",
      x509Cert: cert, wantAssertionsSigned: true, wantResponseSigned: false, jitEnabled: true,
      jitDefaultRole: "member", allowedDomains: "example.test", allowEncryptedAssertions: false } })).data.config;
}
async function begin(app, cfg) {
  const result = await request(app, `/auth/saml/${cfg.id}/login`, { expected: 302 });
  const location = new URL(result.headers.get("location"));
  assert.equal(location.origin, "https://idp.example.test");
  const xml = inflateRawSync(Buffer.from(location.searchParams.get("SAMLRequest"), "base64")).toString();
  const requestId = xml.match(/\bID="([^"]+)"/)?.[1], txnCookie = cookie(result, "av_saml_txn");
  assert.ok(requestId && txnCookie);
  secrets.add(decodeURIComponent(txnCookie.split("=").slice(1).join("=")).split(".")[0]);
  return { requestId, cookie: txnCookie };
}
const escapeXml = (value) => String(value).replace(/[<>&"']/g, (char) => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;", '"': "&quot;", "'": "&apos;" })[char]);
function signedResponse(cfg, login, email, key, cert, options = {}) {
  const now = new Date().toISOString(), until = new Date(Date.now() + 300_000).toISOString();
  const assertionId = "_" + randomBytes(16).toString("hex"), responseId = "_" + randomBytes(16).toString("hex");
  const subjectRequest = options.omitSubjectRequest ? "" : ` InResponseTo="${escapeXml(login.requestId)}"`;
  const issuer = options.issuer || cfg.entityIdIdp, audience = options.audience || cfg.spEntityId;
  const assertion = `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${assertionId}" IssueInstant="${now}" Version="2.0">
    <saml:Issuer>${escapeXml(issuer)}</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${escapeXml(email)}</saml:NameID>
    <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="${until}" Recipient="${escapeXml(cfg.spAcsUrl)}"${subjectRequest}/></saml:SubjectConfirmation></saml:Subject>
    <saml:Conditions NotBefore="${new Date(Date.now() - 60_000).toISOString()}" NotOnOrAfter="${until}"><saml:AudienceRestriction><saml:Audience>${escapeXml(audience)}</saml:Audience></saml:AudienceRestriction></saml:Conditions>
    <saml:AuthnStatement AuthnInstant="${now}" SessionIndex="${assertionId}"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>
    <saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue>${escapeXml(email)}</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion>`;
  const signature = new SignedXml({ privateKey: key, signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#", getKeyInfoContent: () => `<X509Data><X509Certificate>${cert.replace(/-----(BEGIN|END) CERTIFICATE-----/g, "").replace(/\s/g, "")}</X509Certificate></X509Data>` });
  signature.addReference({ xpath: "//*[local-name(.)='Assertion']", transforms: ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/2001/10/xml-exc-c14n#"], digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256" });
  signature.computeSignature(assertion, { location: { reference: "//*[local-name(.)='Issuer']", action: "after" } });
  const xml = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${responseId}" InResponseTo="${escapeXml(login.requestId)}" Version="2.0" IssueInstant="${now}" Destination="${escapeXml(cfg.spAcsUrl)}"><saml:Issuer>${escapeXml(issuer)}</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>${options.unsigned ? assertion : signature.getSignedXml()}</samlp:Response>`;
  return Buffer.from(xml).toString("base64");
}
async function consume(app, cfg, login, response, label) {
  const result = await request(app, `/auth/saml/${cfg.id}/acs`, { method: "POST", form: true,
    cookie: login?.cookie, body: { SAMLResponse: response }, expected: null });
  const session = cookie(result, "av_session");
  report.responses.push({ label, status: result.status, location: result.headers.get("location"), mintedSession: !!session });
  return { ...result, session };
}
console.log(`SAML shared-state fixture ${id}; evidence: ${output}`);
try {
  report.fixtureSha256 = createHash("sha256").update(await readFile(fileURLToPath(import.meta.url))).digest("hex");
  if (image) report.consoleImageId = await command("docker", ["image", "inspect", "--format", "{{.Id}}", image]);
  else report.samlImplementationSha256 = createHash("sha256").update(await readFile(join(root, "dist/lib/saml.js"))).digest("hex");
  networkAttempted = true; await command("docker", ["network", "create", "--label", `agentvisor.saml-drill=${id}`, id]);
  const pgFile = await envFile("postgres", { POSTGRES_USER: "avadmin", POSTGRES_PASSWORD: password, POSTGRES_DB: "avsaml" });
  // Docker can reassign an ephemeral published port on stop/start. Reserve a
  // fixed owned port for this drill so the database outage test keeps the
  // existing API connection URLs valid after restart.
  const pgPort = await freePort();
  const pgName = await container("postgres", ["--env-file", pgFile, "-p", `127.0.0.1:${pgPort}:5432`, pgImage]);
  database = `postgresql://avadmin:${password}@127.0.0.1:${new URL(await endpoint(pgName, 5432)).port}/avsaml`;
  await until(async () => { try { admin = await connect(); return true; } catch { return false; } }, "PostgreSQL startup");
  await admin.query(`CREATE ROLE avapp LOGIN PASSWORD '${password}'; ALTER DATABASE avsaml OWNER TO avapp`);
  report.postgresVersion = (await admin.query("SHOW server_version")).rows[0].server_version;
  if (!image) await command(process.execPath, [join(root, "node_modules/prisma/build/index.js"), "migrate", "deploy", "--schema", join(root, "prisma/schema.prisma")],
    { env: { PATH: process.env.PATH, HOME: process.env.HOME, DATABASE_URL: database.replace("avadmin:", "avapp:") } });
  const a = await startApi("api-a"), b = await startApi("api-b");
  const keyPath = join(output, "idp-key.pem"), certPath = join(output, "idp-cert.pem"); privateFiles.push(keyPath, certPath);
  await command("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes", "-days", "1", "-subj", "/CN=OwnedSamlFixture", "-keyout", keyPath, "-out", certPath]);
  const key = await readFile(keyPath, "utf8"), cert = await readFile(certPath, "utf8");
  const owner = await signup(a, "owner"), foreign = await signup(b, "foreign");
  const cfg = await config(a, owner, "Primary", cert), sibling = await config(a, owner, "Sibling", cert), other = await config(b, foreign, "Foreign", cert);
  const metadata = await request(a, `/auth/saml/${cfg.id}/metadata.xml`);
  check("Metadata advertises an ACS but no unsupported SAML Single Logout service", metadata.text.includes("AssertionConsumerService") && !metadata.text.includes("SingleLogoutService"));
  const local = await begin(a, cfg);
  const localResult = await consume(a, cfg, local, signedResponse(cfg, local, owner.email, key, cert), "same-instance control");
  check("A real signed assertion completes on the issuing replica", !!localResult.session);
  await request(b, "/auth/me", { cookie: localResult.session });
  const cross = await begin(a, cfg);
  const crossResult = await consume(b, cfg, cross, signedResponse(cfg, cross, owner.email, key, cert), "cross-instance login");
  check("A signed response completes on another replica", !!crossResult.session);
  await request(a, "/auth/me", { cookie: crossResult.session });
  const restarted = await begin(a, cfg);
  const restartResponse = signedResponse(cfg, restarted, owner.email, key, cert);
  await stopApi(a); await startApi("api-a", a);
  const restored = await consume(a, cfg, restarted, restartResponse, "restart with pending request");
  check("Pending SAML browser state survives an issuing-process restart", !!restored.session);
  await stopApi(b); await startApi("api-b", b);
  const replay = await consume(b, cfg, restarted, restartResponse, "consumed response after restart");
  check("A consumed response stays refused after another replica restarts", !replay.session && replay.status === 302);

  // Distinct assertions prevent assertion-ID replay protection from hiding a
  // missing request CAS. Hold the first DELETE, and prove both replicas have
  // submitted their DELETE after successful library validation, before release.
  const raced = await begin(a, cfg), raceLock = 749263;
  await admin.query(`CREATE FUNCTION fixture_hold_saml_delete() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
    IF OLD.id='${raced.requestId}' THEN PERFORM pg_advisory_xact_lock(${raceLock}); END IF; RETURN OLD; END $$;
    CREATE TRIGGER fixture_hold_saml_delete BEFORE DELETE ON saml_authn_requests FOR EACH ROW EXECUTE FUNCTION fixture_hold_saml_delete()`);
  await admin.query("SELECT pg_advisory_lock($1)", [raceLock]);
  const racing = Promise.all([a, b].map((app, index) => consume(app, cfg, raced,
    signedResponse(cfg, raced, owner.email, key, cert), "distinct assertion race " + index)));
  racing.catch(() => {});
  await until(async () => (await admin.query(`SELECT count(*)::int AS n FROM pg_stat_activity WHERE usename='avapp'
    AND state='active' AND query ILIKE '%DELETE%saml_authn_requests%'`)).rows[0].n === 2, "both callback DELETE statements reached PostgreSQL");
  await admin.query("SELECT pg_advisory_unlock($1)", [raceLock]);
  const raceResults = await racing;
  await admin.query("DROP TRIGGER fixture_hold_saml_delete ON saml_authn_requests; DROP FUNCTION fixture_hold_saml_delete()");
  check("Two distinct signed assertions sharing one request/browser mint exactly one session", raceResults.filter((result) => result.session).length === 1);
  check("The request CAS leaves no reusable state after concurrent callbacks", (await admin.query("SELECT count(*)::int AS n FROM saml_authn_requests WHERE id=$1", [raced.requestId])).rows[0].n === 0);

  const browser = await begin(a, cfg), wrongBrowser = await begin(b, cfg);
  const bound = signedResponse(cfg, browser, owner.email, key, cert);
  const mismatch = await consume(b, cfg, wrongBrowser, bound, "wrong signed browser cookie");
  const absent = await consume(b, cfg, null, bound, "missing browser cookie");
  check("Wrong-browser and missing-cookie callbacks never mint a session", !mismatch.session && !absent.session);
  const nonce = decodeURIComponent(browser.cookie.split("=").slice(1).join("=")).split(".")[0];
  const stored = (await admin.query('SELECT "nonceHash","configId","orgId","expiresAt","createdAt" FROM saml_authn_requests WHERE id=$1', [browser.requestId])).rows[0];
  check("The shared row stores a nonce hash, exact config/tenant, and finite expiry", stored.nonceHash === createHash("sha256").update(nonce).digest("hex") &&
    stored.nonceHash !== nonce && stored.configId === cfg.id && stored.orgId === owner.orgId && stored.expiresAt - stored.createdAt > 0 && stored.expiresAt - stored.createdAt <= 601_000);
  check("A wrong browser cannot erase another browser's valid pending request", !!(await consume(a, cfg, browser, bound, "legitimate browser retry")).session);
  const unknownRequest = { ...wrongBrowser, requestId: "_" + randomBytes(16).toString("hex") };
  check("An unknown request ID has no authority even with a valid signature and browser cookie",
    !(await consume(b, cfg, unknownRequest, signedResponse(cfg, unknownRequest, owner.email, key, cert), "unknown request ID")).session);
  const unknownNonce = randomBytes(16).toString("hex"); secrets.add(unknownNonce);
  const signedNonce = unknownNonce + "." + createHmac("sha256", jwt).update(unknownNonce).digest("base64").replace(/=/g, "");
  check("A correctly signed but unknown browser nonce has no authority", !(await consume(a, cfg,
    { ...wrongBrowser, cookie: "av_saml_txn=" + encodeURIComponent(signedNonce) },
    signedResponse(cfg, wrongBrowser, owner.email, key, cert), "unknown browser nonce")).session);

  for (const [label, target, targetOwner] of [["configuration", sibling, owner], ["tenant", other, foreign]]) {
    const login = await begin(a, cfg);
    const refused = await consume(b, target, login, signedResponse(target, login, targetOwner.email, key, cert), `wrong ${label} binding`);
    check(`A valid signature cannot move request state to another ${label}`, !refused.session);
    check(`A wrong ${label} callback cannot consume the original request`, !!(await consume(b, cfg, login, signedResponse(cfg, login, owner.email, key, cert), `original request after wrong ${label}`)).session);
  }
  const expired = await begin(a, cfg);
  await admin.query('UPDATE saml_authn_requests SET "expiresAt"=now()-interval \'1 second\' WHERE id=$1', [expired.requestId]);
  const expiredResult = await consume(b, cfg, expired, signedResponse(cfg, expired, owner.email, key, cert), "expired request");
  check("An expired request is refused even with a fresh valid assertion and cookie", !expiredResult.session);
  const compatible = await begin(a, cfg);
  check("Validated responses without SubjectConfirmation InResponseTo still require and consume the shared request",
    !!(await consume(b, cfg, compatible, signedResponse(cfg, compatible, owner.email, key, cert, { omitSubjectRequest: true }), "compatible subject confirmation")).session);

  for (const [label, options] of [["unsigned assertion", { unsigned: true }], ["wrong issuer", { issuer: "https://other-idp.example.test" }],
    ["wrong audience", { audience: "https://other-app.example.test" }]]) {
    const login = await begin(a, cfg);
    check(`Shared state does not bypass ${label} refusal`, !(await consume(b, cfg, login, signedResponse(cfg, login, owner.email, key, cert, options), label)).session);
  }
  await admin.query(`CREATE FUNCTION fixture_deny_saml_insert() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected SAML state insert failure'; END $$;
    CREATE TRIGGER fixture_deny_saml_insert BEFORE INSERT ON saml_authn_requests FOR EACH ROW EXECUTE FUNCTION fixture_deny_saml_insert()`);
  const failedStart = await request(a, `/auth/saml/${cfg.id}/login`, { expected: 302 });
  check("Failed shared-state persistence issues neither an IdP redirect nor a browser nonce", failedStart.headers.get("location").includes("err=saml_request_unavailable") && !cookie(failedStart, "av_saml_txn"));
  await admin.query("DROP TRIGGER fixture_deny_saml_insert ON saml_authn_requests; DROP FUNCTION fixture_deny_saml_insert()");
  const retryStart = await begin(a, cfg);
  const deleteResponse = signedResponse(cfg, retryStart, owner.email, key, cert);
  await admin.query(`CREATE FUNCTION fixture_deny_saml_delete() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected SAML state consume failure'; END $$;
    CREATE TRIGGER fixture_deny_saml_delete BEFORE DELETE ON saml_authn_requests FOR EACH ROW EXECUTE FUNCTION fixture_deny_saml_delete()`);
  const failedDelete = await consume(b, cfg, retryStart, deleteResponse, "failed atomic consume");
  check("A failed atomic consume cannot mint a session", !failedDelete.session && failedDelete.headers.get("location").includes("request_state_unavailable"));
  check("A failed consume retains the request for an explicit retry", (await admin.query("SELECT count(*)::int AS n FROM saml_authn_requests WHERE id=$1", [retryStart.requestId])).rows[0].n === 1);
  await admin.query("DROP TRIGGER fixture_deny_saml_delete ON saml_authn_requests; DROP FUNCTION fixture_deny_saml_delete()");
  check("A valid response can retry after the database write fault is removed", !!(await consume(a, cfg, retryStart, deleteResponse, "consume retry")).session);

  await admin.query('DELETE FROM saml_authn_requests WHERE "expiresAt" <= now()');
  await admin.query(`INSERT INTO saml_authn_requests (id,"configId","orgId","requestTimestamp","nonceHash","expiresAt")
    SELECT 'expired-fixture-'||n,$1,$2,'2020-01-01T00:00:00Z',repeat('a',64),now()-interval '1 hour' FROM generate_series(1,1001) n`, [cfg.id, owner.orgId]);
  await begin(a, cfg);
  check("Expiry cleanup removes one bounded batch per new ceremony", (await admin.query("SELECT count(*)::int AS n FROM saml_authn_requests WHERE id LIKE 'expired-fixture-%'")).rows[0].n === 1);

  const outage = await begin(a, cfg), outageResponse = signedResponse(cfg, outage, owner.email, key, cert);
  await command("docker", ["stop", "-t", "3", pgName]);
  const down = await consume(b, cfg, outage, outageResponse, "database offline");
  check("An unavailable PostgreSQL backend fails closed without a session", down.status >= 500 && !down.session);
  await command("docker", ["start", pgName]);
  await until(async () => { try { admin = await connect(); return true; } catch { return false; } }, "database restart");
  await ready(a); await ready(b);
  check("Pending signed login survives the owned database restart", !!(await consume(a, cfg, outage, outageResponse, "database recovery")).session);
  await stopApi(a); await stopApi(b);
  let rawLogs = "";
  for (const app of apps) {
    if (image) rawLogs += await command("docker", ["logs", app.name]);
    else for (let n = 1; n <= app.generation; n++) rawLogs += await readFile(join(output, `${app.label}-${n}.log`), "utf8");
  }
  check("Production API logs contain no plaintext nonces, cookies, passwords, or JWT secret",
    [...secrets].every((secret) => !rawLogs.includes(secret)));
  report.status = "passed";
} catch (error) { report.status = "failed"; report.error = redact(error.stack || error); console.error(report.error); process.exitCode = 1; }
finally {
  cleanup = true; clearTimeout(deadline); const errors = [];
  for (const app of apps) await stopApi(app).catch((error) => errors.push("API stop: " + redact(error.message)));
  for (const client of clients) await closeDrillClient(client).catch((error) => errors.push("database close: " + error.message));
  for (const name of containers.reverse()) {
    try {
      const found = await command("docker", ["container", "ls", "--all", "--filter", `name=^/${name}$`, "--format", "{{.ID}}"]);
      if (!found) continue; assert.ok(!found.includes("\n"));
      assert.equal(await command("docker", ["inspect", "--format", '{{index .Config.Labels "agentvisor.saml-drill"}}', found]), id);
      try { await writeFile(join(output, name.slice(id.length + 1) + ".log"), redact(await command("docker", ["logs", found])), { mode: 0o600 }); }
      catch (error) { errors.push("container logs: " + redact(error.message)); }
      await command("docker", ["rm", "-f", "-v", found]);
    } catch (error) { errors.push("container: " + redact(error.message)); }
  }
  if (networkAttempted) try {
    const found = await command("docker", ["network", "ls", "--filter", `name=^${id}$`, "--format", "{{.ID}}"]);
    if (found) { assert.ok(!found.includes("\n")); assert.equal(await command("docker", ["network", "inspect", "--format", '{{index .Labels "agentvisor.saml-drill"}}', found]), id);
      await command("docker", ["network", "rm", found]); }
  } catch (error) { errors.push("network: " + redact(error.message)); }
  for (const file of privateFiles) await rm(file, { force: true }).catch((error) => errors.push("private file: " + error.message));
  // Native API logs were streamed privately; sanitize generated credentials
  // before retaining them as evidence, just as for Docker logs above.
  if (!image) for (const app of apps) for (let n = 1; n <= app.generation; n++) {
    const file = join(output, `${app.label}-${n}.log`);
    try { await writeFile(file, redact(await readFile(file, "utf8")), { mode: 0o600 }); }
    catch (error) { errors.push("API log: " + error.message); }
  }
  report.cleanupErrors = errors; report.finishedAt = new Date().toISOString();
  if (errors.length) { report.status = "failed"; process.exitCode = 1; }
  await writeFile(join(output, "report.json"), JSON.stringify(report, null, 2) + "\n", { mode: 0o600 });
  console.log(`${report.status}: ${report.checks.length} checks; evidence: ${output}`);
}
