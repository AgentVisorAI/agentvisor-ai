import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, mkdir, copyFile, writeFile, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

async function fixture(t, migration, api, environment = {}) {
  const dir = await mkdtemp(join(tmpdir(), "av-container-entrypoint-"));
  await mkdir(join(dir, "node_modules/prisma/build"), { recursive: true });
  await mkdir(join(dir, "dist"));
  await mkdir(join(dir, "prisma"));
  await copyFile(new URL("../container-entrypoint.mjs", import.meta.url), join(dir, "entrypoint.mjs"));
  await copyFile(new URL("../database-url.mjs", import.meta.url), join(dir, "database-url.mjs"));
  await writeFile(join(dir, "package.json"), '{"type":"module"}');
  await writeFile(join(dir, "prisma/schema.prisma"), "// fixture");
  // CommonJS fixtures also work below node_modules without package metadata.
  await writeFile(join(dir, "node_modules/prisma/build/index.js"), migration);
  await writeFile(join(dir, "dist/index.js"), api);
  const child = spawn(process.execPath, [join(dir, "entrypoint.mjs")], {
    cwd: dir, env: { ...process.env, ...environment }, stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  child.stdout.on("data", (chunk) => { output += chunk; });
  child.stderr.on("data", (chunk) => { output += chunk; });
  const closed = once(child, "close");
  t.after(async () => {
    if (child.exitCode === null && child.signalCode === null) child.kill("SIGTERM");
    await closed;
    await rm(dir, { recursive: true, force: true });
  });
  return {
    child, dir, closed,
    output: () => output,
    async ready(text) {
      const deadline = Date.now() + 5000;
      while (!output.includes(text)) {
        if (child.exitCode !== null || child.signalCode !== null || Date.now() > deadline) {
          throw new Error(`Fixture did not reach ${text}: ${output}`);
        }
        await new Promise((resolve) => setTimeout(resolve, 10));
      }
    },
  };
}

const databaseAliases = ["POSTGRES_URL", "POSTGRES_PRISMA_URL", "NETLIFY_DATABASE_URL",
  "NEON_DATABASE_URL", "PG_URL", "PGURL", "DATABASE_URL_POOLED"];
const noDatabase = Object.fromEntries(["DATABASE_URL", ...databaseAliases].map((key) => [key, undefined]));
const databaseUrl = "postgresql://synthetic:synthetic@127.0.0.1:1/fixture";

for (const alias of databaseAliases) {
  test(`${alias} selects the same database before migration and API startup`, { timeout: 10000 }, async (t) => {
    const f = await fixture(t,
      `require('node:assert/strict').equal(process.env.DATABASE_URL, ${JSON.stringify(databaseUrl)});
       require('node:fs').writeFileSync('migration-url', process.env.DATABASE_URL);`,
      `import assert from 'node:assert/strict'; import { readFileSync } from 'node:fs';
       assert.equal(process.env.DATABASE_URL, ${JSON.stringify(databaseUrl)});
       assert.equal(readFileSync('migration-url', 'utf8'), process.env.DATABASE_URL);`,
      { ...noDatabase, [alias]: databaseUrl });
    assert.deepEqual(await f.closed, [0, null], f.output());
  });
}

test("an explicit DATABASE_URL wins over every provider alias during migration and API startup", { timeout: 10000 }, async (t) => {
  const f = await fixture(t,
    `require('node:assert/strict').equal(process.env.DATABASE_URL, ${JSON.stringify(databaseUrl)});`,
    `import assert from 'node:assert/strict'; assert.equal(process.env.DATABASE_URL, ${JSON.stringify(databaseUrl)});`,
    { ...Object.fromEntries(databaseAliases.map((key) => [key, "postgresql://other.example.test/other"])), DATABASE_URL: databaseUrl });
  assert.deepEqual(await f.closed, [0, null], f.output());
});

test("migration failure still prevents the API from starting when a database alias is used", { timeout: 10000 }, async (t) => {
  const f = await fixture(t,
    `require('node:assert/strict').equal(process.env.DATABASE_URL, ${JSON.stringify(databaseUrl)}); process.exit(37);`,
    "console.log('API MUST NOT START')", { ...noDatabase, POSTGRES_URL: databaseUrl });
  assert.deepEqual(await f.closed, [37, null], f.output());
  assert.doesNotMatch(f.output(), /API MUST NOT START/);
});

test("migration completes before the API starts", { timeout: 10000 }, async (t) => {
  const f = await fixture(t,
    `require('node:assert/strict').deepEqual(process.argv.slice(2, 5), ['migrate', 'deploy', '--schema']);
     require('node:fs').writeFileSync('migrated', 'yes');`,
    `import { readFileSync } from 'node:fs';
     if (readFileSync('migrated', 'utf8') !== 'yes') process.exit(99);`);
  assert.deepEqual(await f.closed, [0, null], f.output());
});

test("migration failure preserves its code and prevents API startup", { timeout: 10000 }, async (t) => {
  const f = await fixture(t, "process.exit(37)", "console.log('API MUST NOT START')");
  assert.deepEqual(await f.closed, [37, null]);
  assert.doesNotMatch(f.output(), /API MUST NOT START/);
});

test("migration killed by a signal is a failure", { timeout: 10000 }, async (t) => {
  const f = await fixture(t, "process.kill(process.pid, 'SIGTERM')", "console.log('API MUST NOT START')");
  assert.deepEqual(await f.closed, [143, null]);
  assert.doesNotMatch(f.output(), /API MUST NOT START/);
});

test("API failure preserves its code", { timeout: 10000 }, async (t) => {
  const f = await fixture(t, "process.exit(0)", "process.exit(42)");
  assert.deepEqual(await f.closed, [42, null]);
});

for (const signal of ["SIGTERM", "SIGINT"]) {
  test(`${signal} reaches the API and preserves graceful exit`, { timeout: 10000 }, async (t) => {
    const f = await fixture(t, "process.exit(0)",
      `process.on('${signal}', () => { console.log('API stopped'); process.exit(0); });
       console.log('API ready'); setInterval(() => {}, 1000);`);
    await f.ready("API ready");
    f.child.kill(signal);
    assert.deepEqual(await f.closed, [0, null]);
    assert.match(f.output(), /API stopped/);
  });
}

test("shutdown reaches migration descendants and never starts the API", { timeout: 10000 }, async (t) => {
  const f = await fixture(t,
    `const { spawn } = require('node:child_process');
     const grandchild = spawn(process.execPath, ['-e', \
       "process.on('SIGTERM', () => {require('node:fs').writeFileSync('engine-stopped', 'yes'); process.exit(0)}); console.log('engine ready'); setInterval(()=>{},1000)"], {stdio:'inherit'});
     process.on('SIGTERM', () => grandchild.once('close', () => process.exit(0)));`,
    "console.log('API MUST NOT START')");
  await f.ready("engine ready");
  f.child.kill("SIGTERM");
  assert.deepEqual(await f.closed, [0, null]);
  assert.equal(await readFile(join(f.dir, "engine-stopped"), "utf8"), "yes");
  assert.doesNotMatch(f.output(), /API MUST NOT START/);
});
