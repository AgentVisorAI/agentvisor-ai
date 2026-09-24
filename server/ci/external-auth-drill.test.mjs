import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { chmod, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { closeDrillClient } from "../scripts/auth-drill-cleanup.mjs";

const root = fileURLToPath(new URL("../", import.meta.url));
// These processes model ambiguous Docker replies only. They never contact a
// Docker daemon, database, SMTP server, or identity provider.
const fakeDocker = `#!/usr/bin/env node
const fs = require('node:fs'), path = require('node:path');
const work=process.env.AUTH_CLEANUP_TEST, mode=process.env.AUTH_CLEANUP_MODE;
const args=process.argv.slice(2), file=path.join(work,'state.json');
const state=fs.existsSync(file)?JSON.parse(fs.readFileSync(file)):{};
const save=()=>fs.writeFileSync(file,JSON.stringify(state));
fs.appendFileSync(path.join(work,'commands.jsonl'),JSON.stringify(args)+'\\n');
if(args[0]==='image') process.stdout.write('sha256:fixture');
else if(args[0]==='network' && args[1]==='create') { state.owner=args.at(-1);state.network=true;save(); }
else if(args[0]==='create') {
  state.name=args[args.indexOf('--name')+1];state.container=true;save();
  if(mode==='cancel') { fs.writeFileSync(path.join(work,'accepted'),'ready');setInterval(()=>{},1000); }
  else { process.stderr.write('ambiguous fixture creation failure');process.exitCode=17; }
} else if(args[0]==='container' && args[1]==='ls') {
  if(args[args.indexOf('--filter')+1]!=='name=^/'+state.name+'$') process.exit(25);
  if(state.container) process.stdout.write('container-id');
} else if(args[0]==='inspect') {
  if(args.at(-1)!=='container-id') process.exit(26);
  process.stdout.write(mode==='foreign'?'foreign-owner':state.owner);
} else if(args[0]==='logs') {
  if(mode==='logs-fail') { process.stderr.write('log retrieval failure');process.exitCode=18; }
} else if(args[0]==='rm') {
  if(args.at(-1)!=='container-id'||!args.includes('-v')) process.exit(27);
  state.container=false;state.volumeRemoved=true;save();
} else if(args[0]==='network' && args[1]==='ls') {
  if(state.network) process.stdout.write('network-id');
} else if(args[0]==='network' && args[1]==='inspect') process.stdout.write(state.owner);
else if(args[0]==='network' && args[1]==='rm') { state.network=false;save(); }
else { process.stderr.write('unexpected fake Docker operation');process.exitCode=28; }
`;
const fakeOpenSsl = `#!/usr/bin/env node
const fs=require('node:fs'),args=process.argv.slice(2);
for(const flag of ['-keyout','-out']) fs.writeFileSync(args[args.indexOf(flag)+1],'fixture');
`;
async function fixture(t, mode) {
  const work = await mkdtemp(join(tmpdir(), "av-auth-cleanup-test-"));
  t.after(() => rm(work, { force: true, recursive: true }));
  for (const [name, source] of [["docker", fakeDocker], ["openssl", fakeOpenSsl]]) {
    await writeFile(join(work, name), source); await chmod(join(work, name), 0o700);
  }
  const child = spawn(process.execPath, [join(root, "scripts/external-auth-drill.mjs")], {
    cwd: root, detached: true, stdio: ["ignore", "pipe", "pipe"],
    env: { ...process.env, PATH: work + ":" + process.env.PATH, CONSOLE_AUTH_IMAGE: "fixture-image",
      AUTH_DRILL_OUTPUT_PARENT: work, AUTH_CLEANUP_TEST: work, AUTH_CLEANUP_MODE: mode },
  });
  let logs = "";
  child.stdout.on("data", (chunk) => { logs += chunk; }); child.stderr.on("data", (chunk) => { logs += chunk; });
  const kill = () => { try { process.kill(-child.pid, "SIGKILL"); } catch (error) { if (error.code !== "ESRCH") throw error; } };
  const timeout = setTimeout(kill, 10_000);
  t.after(() => { clearTimeout(timeout); if (child.exitCode === null && child.signalCode === null) kill(); });
  const exited = once(child, "close");
  if (mode === "cancel") {
    const until = Date.now() + 5000;
    while (!(await readFile(join(work, "accepted")).then(() => true).catch(() => false))) {
      assert.ok(Date.now() < until, "creation marker never appeared");
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    child.kill("SIGTERM");
  }
  const [code, signal] = await exited; clearTimeout(timeout);
  assert.equal(signal, null, logs); assert.equal(code, 1, logs);
  const output = (await readdir(work)).find((name) => name.startsWith("av-auth-"));
  assert.ok(output);
  const report = JSON.parse(await readFile(join(work, output, "report.json"), "utf8"));
  const state = JSON.parse(await readFile(join(work, "state.json"), "utf8"));
  assert.equal(report.status, "failed"); assert.equal(report.checks.length, 0);
  assert.match(report.error, /docker create failed/);
  assert.ok(!(await readdir(join(work, output))).some((name) => /\.(env|pem)$/.test(name)), "private fixture files survived cleanup");
  return { report, state };
}
test("auth drill cleans accepted resources after an ambiguous creation reply", async (t) => {
  const { report, state } = await fixture(t, "create-fail");
  assert.deepEqual(report.cleanupErrors, []);
  assert.equal(state.container, false); assert.equal(state.volumeRemoved, true); assert.equal(state.network, false);
});
test("auth drill cleans accepted resources after cancellation", async (t) => {
  const { report, state } = await fixture(t, "cancel");
  assert.deepEqual(report.cleanupErrors, []);
  assert.equal(state.container, false); assert.equal(state.volumeRemoved, true); assert.equal(state.network, false);
});
test("auth drill still removes owned containers when log retrieval fails", async (t) => {
  const { report, state } = await fixture(t, "logs-fail");
  assert.match(report.cleanupErrors.join("\n"), /log retrieval failure/);
  assert.equal(state.container, false); assert.equal(state.volumeRemoved, true); assert.equal(state.network, false);
});
test("auth drill refuses to delete a container with a foreign label", async (t) => {
  const { report, state } = await fixture(t, "foreign");
  assert.match(report.cleanupErrors.join("\n"), /ownership label/);
  assert.equal(state.container, true); assert.equal(state.volumeRemoved, undefined);
});
test("a stalled PostgreSQL close destroys its owned socket and releases cleanup", async () => {
  let destroyed = false;
  await assert.rejects(closeDrillClient({ end: () => new Promise(() => {}),
    connection: { stream: { destroy: () => { destroyed = true; } } } }, 10), /database close timed out/);
  assert.equal(destroyed, true);
});
