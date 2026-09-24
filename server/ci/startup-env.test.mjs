import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import test from "node:test";

const execute = promisify(execFile);
const databaseUrl = "postgresql://synthetic:synthetic@127.0.0.1:1/fixture";
const aliases = ["POSTGRES_URL", "POSTGRES_PRISMA_URL", "NETLIFY_DATABASE_URL",
  "NEON_DATABASE_URL", "PG_URL", "PGURL", "DATABASE_URL_POOLED"];
const source = new URL("../src/env.ts", import.meta.url).href;
const loader = fileURLToPath(new URL("../node_modules/tsx/dist/loader.mjs", import.meta.url));

async function parseEnvironment(overrides = {}) {
  // No inherited application settings or .env file may influence these cases.
  const cwd = await mkdtemp(join(tmpdir(), "av-startup-env-"));
  const env = {
    PATH: process.env.PATH,
    NODE_ENV: "production", JWT_SECRET: "synthetic-startup-secret-at-least-32-characters",
    DATABASE_URL: databaseUrl, APP_BASE_URL: "https://console.example.test",
    API_PUBLIC_URL: "https://api.example.test", ...overrides,
  };
  const script = `const { env, apiPublicBase } = await import(${JSON.stringify(source)});
    console.log('RESULT ' + JSON.stringify({ database: env.DATABASE_URL,
      app: env.APP_BASE_URL, api: env.API_PUBLIC_URL, publicBase: apiPublicBase(),
      secureCookie: env.SESSION_COOKIE_SECURE }));`;
  try {
    const result = await execute(process.execPath, ["--import", loader, "--input-type=module", "-e", script],
      { cwd, env, timeout: 5000 });
    return { code: 0, ...result, value: JSON.parse(result.stdout.split("RESULT ")[1]) };
  } catch (error) {
    return { code: error.code, stdout: error.stdout ?? "", stderr: error.stderr ?? "" };
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
}

test("the API accepts every supported database alias", { timeout: 15000 }, async () => {
  for (const alias of aliases) {
    const result = await parseEnvironment({ DATABASE_URL: undefined, [alias]: databaseUrl });
    assert.equal(result.code, 0, `${alias}: ${result.stderr}`);
    assert.equal(result.value.database, databaseUrl);
  }
});

test("primary database precedence and alias order agree with migration startup", async () => {
  const other = "postgresql://other.example.test/other";
  const primary = await parseEnvironment({ ...Object.fromEntries(aliases.map((key) => [key, other])) });
  assert.equal(primary.code, 0, primary.stderr);
  assert.equal(primary.value.database, databaseUrl);
  const fallback = await parseEnvironment({ DATABASE_URL: "", POSTGRES_URL: databaseUrl, POSTGRES_PRISMA_URL: other });
  assert.equal(fallback.code, 0, fallback.stderr);
  assert.equal(fallback.value.database, databaseUrl);
});

test("valid HTTPS public base URLs and an empty API override are preserved", { timeout: 15000 }, async () => {
  for (const url of ["https://console.example.test", "HTTPS://console.example.test/console/", "https://[2001:db8::1]:8443/app"]) {
    const result = await parseEnvironment({ APP_BASE_URL: url, API_PUBLIC_URL: "" });
    assert.equal(result.code, 0, result.stderr);
    assert.equal(result.value.app, url);
    assert.equal(result.value.publicBase, url.replace(/\/$/, ""));
    assert.equal(result.value.secureCookie, true);
  }
});

test("production public URLs reject non-HTTPS, malformed and ambiguous link bases without leaking credentials", { timeout: 30000 }, async () => {
  const invalid = ["http://console.example.test", "HTTP://console.example.test", "javascript:alert(1)",
    "ftp://console.example.test", "not-a-url", "//console.example.test", "https:console.example.test",
    "https://", "https://user:DO_NOT_LOG_THIS_PASSWORD@console.example.test", "https://console.example.test?",
    "https://console.example.test#", "https://console.example.test/path?redirect=elsewhere", " https://console.example.test"];
  for (const field of ["APP_BASE_URL", "API_PUBLIC_URL"]) {
    for (const value of invalid) {
      const result = await parseEnvironment({ [field]: value });
      assert.equal(result.code, 1, `${field} accepted ${value}`);
      assert.match(result.stderr, new RegExp(field));
      assert.doesNotMatch(result.stdout + result.stderr, /DO_NOT_LOG_THIS_PASSWORD/);
    }
  }
});

test("development keeps localhost defaults and explicit HTTP URLs", async () => {
  const defaults = await parseEnvironment({ NODE_ENV: "development", APP_BASE_URL: undefined, API_PUBLIC_URL: undefined });
  assert.equal(defaults.code, 0, defaults.stderr);
  assert.equal(defaults.value.app, "http://localhost:8787");
  assert.equal(defaults.value.publicBase, "http://localhost:8787");
  assert.equal(defaults.value.secureCookie, false);
  const explicit = await parseEnvironment({ NODE_ENV: "development", APP_BASE_URL: "http://localhost:8787/app", API_PUBLIC_URL: "http://127.0.0.1:8985" });
  assert.equal(explicit.code, 0, explicit.stderr);
  assert.equal(explicit.value.publicBase, "http://127.0.0.1:8985");
  const malformed = await parseEnvironment({ NODE_ENV: "development", APP_BASE_URL: "not-a-url" });
  assert.equal(malformed.code, 1);
});

test("missing production credentials and database still fail startup", async () => {
  for (const field of ["JWT_SECRET", "DATABASE_URL"]) {
    const result = await parseEnvironment({ [field]: undefined });
    assert.equal(result.code, 1);
    assert.match(result.stderr, new RegExp(field));
  }
});
