import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { chmod, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createServer } from "node:net";
import test from "node:test";

const root = fileURLToPath(new URL("../", import.meta.url));
const script = join(root, "scripts/recovery-drill.mjs");
// This executable models Docker accepting a request before its CLI loses the
// response. No Docker socket, database, API, or external service is contacted.
const fakeDocker = `#!/usr/bin/env node
const fs = require("node:fs");
const path = require("node:path");
const work = process.env.RECOVERY_TEST_WORK;
const mode = process.env.RECOVERY_TEST_MODE;
const args = process.argv.slice(2);
const statePath = path.join(work, "state.json");
fs.appendFileSync(path.join(work, "commands.jsonl"), JSON.stringify(args)+"\\n");
const load = () => fs.existsSync(statePath) ? JSON.parse(fs.readFileSync(statePath)) : null;
if (args[0] === "run") {
  const name = args[args.indexOf("--name")+1];
  if (mode !== "absent") fs.writeFileSync(statePath, JSON.stringify({
    name, id: "owned-container-id", exists: true,
    owner: mode === "foreign" ? "somebody-else" : name,
  }));
  if (mode === "cancel" || mode === "repeat-cancel") {
    fs.writeFileSync(path.join(work, "creation-accepted"), "ready");
    setInterval(() => {}, 1000);
  } else {
    process.stderr.write("injected ambiguous creation failure");
    process.exitCode = 17;
  }
} else if (args[0] === "container" && args[1] === "ls") {
  if (mode === "query-failure") {
    process.stderr.write("injected cleanup query failure"); process.exitCode = 19;
  } else {
    const state = load();
    if (state && state.exists) {
      if (args[args.indexOf("--filter")+1] !== "name=^/"+state.name+"$") process.exit(25);
      process.stdout.write(state.id);
    }
  }
} else if (args[0] === "inspect") {
  const state = load();
  if (args.at(-1) !== state.id) process.exit(26);
  process.stdout.write(state.owner);
} else if (args[0] === "rm") {
  const state = load();
  if (args.at(-1) !== state.id || !args.includes("-v")) process.exit(27);
  if (mode === "remove-failure") {
    process.stderr.write("injected removal failure"); process.exitCode = 23;
  } else {
    const finish = () => fs.writeFileSync(statePath, JSON.stringify({ ...state, exists: false, volumeRemoved: true }));
    if (mode === "repeat-cancel") {
      fs.writeFileSync(path.join(work, "cleanup-started"), "ready");
      setTimeout(finish, 400);
    } else finish();
  }
} else { process.stderr.write("unexpected fake Docker command"); process.exitCode = 28; }
`;

async function waitForFile(path) {
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    try { await readFile(path); return; } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error("fixture marker did not appear: " + path);
}

async function runFixture(t, mode) {
  const work = await mkdtemp(join(tmpdir(), "av-recovery-cleanup-test-"));
  t.after(() => rm(work, { recursive: true, force: true }));
  const docker = join(work, "docker");
  await writeFile(docker, fakeDocker);
  await chmod(docker, 0o700);
  const child = spawn(process.execPath, [script], {
    cwd: root,
    detached: process.platform !== "win32",
    env: { ...process.env, PATH: work + ":" + process.env.PATH, TMPDIR: work,
      RECOVERY_TEST_WORK: work, RECOVERY_TEST_MODE: mode },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "", stderr = "";
  child.stdout.on("data", (chunk) => { stdout += chunk; });
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  const killOwned = () => {
    try {
      if (process.platform === "win32") child.kill("SIGKILL");
      else process.kill(-child.pid, "SIGKILL");
    } catch (error) { if (error.code !== "ESRCH") throw error; }
  };
  const timeout = setTimeout(killOwned, 12_000);
  t.after(() => { clearTimeout(timeout); killOwned(); });
  const closed = once(child, "close");
  if (mode === "cancel" || mode === "repeat-cancel") {
    await waitForFile(join(work, "creation-accepted"));
    child.kill("SIGTERM");
    if (mode === "repeat-cancel") {
      await waitForFile(join(work, "cleanup-started"));
      child.kill("SIGTERM");
      child.kill("SIGINT");
    }
  }
  const [code, signal] = await closed;
  clearTimeout(timeout);
  assert.equal(signal, null, stdout + stderr);
  assert.equal(code, 1, "the original creation failure/cancellation must remain a failure");
  const outputs = (await readdir(work)).filter((name) => name.startsWith("av-console-recovery-"));
  assert.equal(outputs.length, 1);
  const output = join(work, outputs[0]);
  const report = JSON.parse(await readFile(join(output, "report.json"), "utf8"));
  assert.equal(report.status, "failed");
  assert.equal(report.checks.length, 0, "no application assertions ran in this failure fixture");
  assert.match(report.error, /docker run failed/);
  assert.ok(!(await readdir(output)).includes("postgres.env"), "fixture credentials must be removed");
  const commands = (await readFile(join(work, "commands.jsonl"), "utf8")).trim().split("\n").map(JSON.parse);
  const state = await readFile(join(work, "state.json"), "utf8").then(JSON.parse).catch((error) => {
    if (error.code === "ENOENT") return null;
    throw error;
  });
  return { report, commands, state };
}

test("an accepted container is removed with its volume after the creation reply fails", async (t) => {
  const { report, commands, state } = await runFixture(t, "accepted-failure");
  assert.deepEqual(report.cleanupErrors, []);
  assert.equal(state.exists, false);
  assert.equal(state.volumeRemoved, true);
  assert.deepEqual(commands.at(-1), ["rm", "-f", "-v", state.id]);
});

test("a successful empty Docker query establishes that no container needs cleanup", async (t) => {
  const { report, commands, state } = await runFixture(t, "absent");
  assert.deepEqual(report.cleanupErrors, []);
  assert.equal(state, null);
  assert.ok(commands.some((args) => args[0] === "container" && args[1] === "ls"));
  assert.ok(!commands.some((args) => args[0] === "rm"));
});

test("cleanup refuses a container with a different ownership label", async (t) => {
  const { report, commands, state } = await runFixture(t, "foreign");
  assert.equal(state.exists, true);
  assert.match(report.cleanupErrors.join("\n"), /ownership label/);
  assert.ok(!commands.some((args) => args[0] === "rm"));
});

test("failed Docker queries do not masquerade as successful cleanup", async (t) => {
  const { report, commands, state } = await runFixture(t, "query-failure");
  assert.equal(state.exists, true);
  assert.match(report.cleanupErrors.join("\n"), /cleanup query failure/);
  assert.ok(!commands.some((args) => args[0] === "rm"));
});

test("removal failure preserves both original and cleanup diagnostics", async (t) => {
  const { report, state } = await runFixture(t, "remove-failure");
  assert.equal(state.exists, true);
  assert.match(report.error, /ambiguous creation failure/);
  assert.match(report.cleanupErrors.join("\n"), /injected removal failure/);
});

test("cancellation after creation was accepted still removes the owned container", async (t) => {
  const { report, state } = await runFixture(t, "cancel");
  assert.deepEqual(report.cleanupErrors, []);
  assert.equal(state.exists, false);
  assert.equal(state.volumeRemoved, true);
});

test("repeated cancellation does not interrupt owned-container cleanup", async (t) => {
  const { report, state } = await runFixture(t, "repeat-cancel");
  assert.deepEqual(report.cleanupErrors, []);
  assert.equal(state.exists, false);
  assert.equal(state.volumeRemoved, true);
});

const fakeImageDocker = `#!/usr/bin/env node
const fs = require("node:fs");
const path = require("node:path");
const work = process.env.RECOVERY_TEST_WORK, mode = process.env.RECOVERY_TEST_MODE;
const args = process.argv.slice(2), statePath = path.join(work, "state.json");
const state = fs.existsSync(statePath) ? JSON.parse(fs.readFileSync(statePath)) : { containers: [] };
const save = () => fs.writeFileSync(statePath, JSON.stringify(state));
fs.appendFileSync(path.join(work, "commands.jsonl"), JSON.stringify(args)+"\\n");
const fail = (message) => { process.stderr.write(message); process.exitCode = 17; };
if (args[0] === "network" && args[1] === "create") {
  const name = args.at(-1), owner = args[args.indexOf("--label") + 1].split("=")[1];
  state.network = { name, id: "owned-network", owner: mode === "network-foreign" ? "foreign" : owner, exists: true }; save();
  if (mode.startsWith("network-")) fail("injected ambiguous network creation failure");
  else process.stdout.write(state.network.id);
} else if (args[0] === "run") {
  const name = args[args.indexOf("--name") + 1], owner = args[args.indexOf("--label") + 1].split("=")[1];
  const item = { name, owner, id: "owned-container-" + state.containers.length, exists: true };
  if (name.endsWith("-api-a")) {
    if (!args.includes("--read-only") || args[args.indexOf("--tmpfs") + 1] !== "/tmp:uid=65532,gid=65532,mode=0700"
        || args[args.indexOf("--cap-drop") + 1] !== "ALL"
        || args[args.indexOf("--security-opt") + 1] !== "no-new-privileges") process.exit(29);
    const contents = fs.readFileSync(args[args.indexOf("--env-file") + 1], "utf8");
    item.secret = contents.split("\\n").find(line => line.startsWith("JWT_SECRET=")).slice("JWT_SECRET=".length);
  }
  state.containers.push(item); save();
  if (name.endsWith("-api-a")) {
    if (mode === "image-cancel") {
      fs.writeFileSync(path.join(work, "creation-accepted"), "ready"); setInterval(() => {}, 1000);
    } else fail("injected ambiguous API creation failure");
  } else process.stdout.write(item.id);
} else if (args[0] === "inspect") {
  const item = state.containers.find(c => c.id === args.at(-1) || c.name === args.at(-1));
  if (!item) process.exit(21);
  if (args.includes("--format")) process.stdout.write(item.owner);
  else process.stdout.write(JSON.stringify([{ Id: item.id, Image: "fixture-postgres-image", NetworkSettings: { Ports: { "5432/tcp": [{ HostPort: process.env.RECOVERY_TEST_PG_PORT }] } } }]));
} else if (args[0] === "container" && args[1] === "ls") {
  const wanted = args[args.indexOf("--filter") + 1];
  process.stdout.write(state.containers.filter(c => c.exists && wanted === "name=^/" + c.name + "$").map(c => c.id).join("\\n"));
} else if (args[0] === "logs") {
  if (mode === "image-log-failure") fail("injected API log failure");
  else { process.stdout.write("owned fixture stdout"); process.stderr.write("owned fixture stderr " + state.containers.at(-1).secret); }
} else if (args[0] === "rm") {
  const item = state.containers.find(c => c.id === args.at(-1));
  if (!item || !args.includes("-v")) process.exit(22);
  item.exists = false; item.volumeRemoved = true; save();
} else if (args[0] === "network" && args[1] === "ls") {
  if (args[args.indexOf("--filter")+1] !== "name=^" + state.network.name + "$") process.exit(23);
  if (state.network.exists) process.stdout.write(state.network.id);
} else if (args[0] === "network" && args[1] === "inspect") {
  if (args.at(-1) !== state.network.id) process.exit(24);
  process.stdout.write(state.network.owner);
} else if (args[0] === "network" && args[1] === "rm") {
  if (args.at(-1) !== state.network.id) process.exit(25);
  if (mode === "network-remove-failure") fail("injected network removal failure");
  else { state.network.exists = false; save(); }
} else { fail("unexpected image fixture Docker command"); }
`;

async function runImageFailure(t, mode) {
  const work = await mkdtemp(join(tmpdir(), "av-recovery-image-cleanup-"));
  t.after(() => rm(work, { recursive: true, force: true }));
  const sockets = new Set();
  // Only authentication is needed: image creation deliberately fails before
  // SQL/API assertions. This is not a mock claim that migrations succeeded.
  const server = createServer((socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
    socket.on("error", () => {});
    let started = false;
    socket.on("data", (bytes) => {
      if (!started) { started = true; socket.write(Buffer.from("5200000008000000005a0000000549", "hex")); }
      else if (bytes[0] === 88) socket.end();
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(async () => {
    for (const socket of sockets) socket.destroy();
    await new Promise((resolve) => server.close(resolve));
  });
  await writeFile(join(work, "docker"), fakeImageDocker, { mode: 0o700 });
  const child = spawn(process.execPath, [script], { cwd: root, detached: process.platform !== "win32",
    env: { ...process.env, PATH: work + ":" + process.env.PATH, TMPDIR: work,
      CONSOLE_RECOVERY_IMAGE: "fixture-never-contact-real-docker", RECOVERY_TEST_WORK: work,
      RECOVERY_TEST_MODE: mode, RECOVERY_TEST_PG_PORT: String(server.address().port) },
    stdio: ["ignore", "pipe", "pipe"] });
  let output = "";
  child.stdout.on("data", (chunk) => { output += chunk; });
  child.stderr.on("data", (chunk) => { output += chunk; });
  const kill = () => { try { process.kill(-child.pid, "SIGKILL"); } catch (error) { if (error.code !== "ESRCH") throw error; } };
  const timer = setTimeout(kill, 12_000);
  t.after(() => { clearTimeout(timer); kill(); });
  const closed = once(child, "close");
  if (mode === "image-cancel") { await waitForFile(join(work, "creation-accepted")); child.kill("SIGTERM"); }
  const [code, signal] = await closed;
  clearTimeout(timer);
  assert.equal(signal, null, output);
  assert.equal(code, 1, output);
  const resultDir = join(work, (await readdir(work)).find((name) => name.startsWith("av-console-recovery-")));
  const report = JSON.parse(await readFile(join(resultDir, "report.json"), "utf8"));
  const state = JSON.parse(await readFile(join(work, "state.json"), "utf8"));
  assert.equal(report.status, "failed");
  assert.equal(report.checks.length, 0);
  assert.ok(!(await readdir(resultDir)).some((name) => name.endsWith(".env")), "every generated credential file must be removed");
  return { report, state, resultDir };
}

for (const mode of ["network-accepted", "image-accepted", "image-cancel"]) {
  test(`${mode}: ambiguous image-mode creation removes only owned resources`, async (t) => {
    const { report, state, resultDir } = await runImageFailure(t, mode);
    assert.deepEqual(report.cleanupErrors, []);
    assert.equal(state.network.exists, false);
    assert.equal(state.containers.length, mode.startsWith("network") ? 0 : 2);
    assert.ok(state.containers.every((c) => !c.exists && c.volumeRemoved));
    if (state.containers.length) {
      const log = await readFile(join(resultDir, "api-a.log"), "utf8");
      assert.match(log, /owned fixture stdoutowned fixture stderr \[REDACTED\]/);
      assert.ok(!log.includes(state.containers.at(-1).secret), "known generated credentials must be excluded from saved diagnostics");
    }
  });
}

test("image-mode cleanup refuses a foreign network", async (t) => {
  const { report, state } = await runImageFailure(t, "network-foreign");
  assert.equal(state.network.exists, true);
  assert.match(report.cleanupErrors.join("\n"), /network without this drill's ownership label/);
});

test("image-mode network removal errors remain visible", async (t) => {
  const { report, state } = await runImageFailure(t, "network-remove-failure");
  assert.equal(state.network.exists, true);
  assert.match(report.cleanupErrors.join("\n"), /injected network removal failure/);
});

test("image-mode log failure does not bypass container and network removal", async (t) => {
  const { report, state } = await runImageFailure(t, "image-log-failure");
  assert.match(report.cleanupErrors.join("\n"), /injected API log failure/);
  assert.ok(state.containers.every((c) => !c.exists && c.volumeRemoved));
  assert.equal(state.network.exists, false);
});
