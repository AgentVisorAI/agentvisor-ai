// Exercise the complete daemon -> crash recovery -> console-sync -> API
// contract. The API and PostgreSQL must already be running. Supply current
// AGENTVISORD and AVCTL binaries; this runner never builds or downloads them.
import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import { access, mkdtemp, rm, writeFile } from "node:fs/promises";
import { constants } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";

const API = (process.env.API_BASE || "http://127.0.0.1:8985").replace(/\/$/, "");
const repo = fileURLToPath(new URL("../../", import.meta.url));
// Missing binaries must fail, rather than letting a crash-only run pass
// while the console synchronization leg is silently skipped.
for (const name of ["AGENTVISORD", "AVCTL"]) {
  assert.ok(process.env[name], `${name} must name a current executable`);
  await access(process.env[name], constants.X_OK);
}
const fixture = await mkdtemp(join(tmpdir(), "av-console-drill-"));
const password = randomBytes(32).toString("hex");
let cookie;

async function request(path, body, retry = true) {
  const r = await fetch(API + "/api/v1" + path, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...(cookie ? { Cookie: cookie } : {}) },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(30_000),
  });
  if (r.status === 429 && retry) {
    const wait = Math.min(61, Math.max(1, Number(r.headers.get("retry-after")) || 60));
    await r.arrayBuffer();
    await new Promise((resolve) => setTimeout(resolve, (wait + 1) * 1000));
    return request(path, body, false);
  }
  if (!r.ok) throw new Error(`${path} failed with HTTP ${r.status}: ${await r.text()}`);
  return { data: await r.json(), cookie: r.headers.getSetCookie().find((c) => c.startsWith("av_session="))?.split(";")[0] };
}

try {
  const signup = await request("/auth/signup", { email: `daemon-drill-${randomUUID()}@example.test`, password, orgName: "Daemon console regression" });
  cookie = signup.cookie;
  assert.ok(cookie, "signup must issue the session cookie used by the crash drill");
  const { data } = await request("/deployments", { name: "crash-regression", environment: "development" });
  const tokenFile = join(fixture, "ingest-token");
  const cookieJar = join(fixture, "owner.jar");
  await writeFile(tokenFile, data.ingestToken, { mode: 0o600 });
  const host = new URL(API).hostname;
  await writeFile(cookieJar, `# Netscape HTTP Cookie File\n${host}\tFALSE\t/\tFALSE\t0\tav_session\t${cookie.slice("av_session=".length)}\n`, { mode: 0o600 });
  const child = spawn(process.execPath, [join(repo, "scripts/crash-drill.mjs")], {
    cwd: repo,
    stdio: "inherit",
    env: { ...process.env, CONSOLE_URL: API, DEPLOYMENT_ID: data.deployment.id, TOKEN_FILE: tokenFile, COOKIE_JAR: cookieJar },
  });
  const code = await new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (exitCode, signal) => signal ? reject(new Error(`crash drill terminated by ${signal}`)) : resolve(exitCode));
  });
  assert.equal(code, 0, "real daemon/console crash drill must pass");
  console.log("PASS daemon-console-drill: real crash recovery and console synchronization verified");
} finally {
  // Delete only the account created by this runner. Do not reset the
  // database: local invocations may share it with other test suites.
  if (cookie) {
    await request("/auth/me/delete-account", { password, confirm: "DELETE MY ACCOUNT" }).catch((error) => {
      console.warn("Test-account cleanup failed:", error.message);
    });
  }
  await rm(fixture, { recursive: true, force: true });
}
