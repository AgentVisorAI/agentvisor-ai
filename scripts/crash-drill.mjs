#!/usr/bin/env node
/*
 * Daemon crash-durability drill.
 *
 * The product claim is "Enforce before. Prove after." — the PROOF must
 * survive the daemon dying at the worst moment. This drill:
 *
 *   1. boots agentvisord with scripted LLM + tool mocks (same shapes as
 *      scripts/demo-agent.mjs),
 *   2. runs an allowed call and a BLOCKED $8,400 call in session S,
 *   3. holds another request upstream and SIGKILLs the daemon,
 *   4. restarts it on the SAME config/spool/bridge dirs,
 *   5. finishes the story (allowed $84, close → signed receipt),
 *   6. optionally console-syncs spool+bridge and verifies that incomplete
 *      evidence is explicitly quarantined without a complete receipt.
 *
 * Durability invariants asserted (resume semantics are NOT pinned —
 * a restarted daemon may open a fresh internal session for S):
 *   A. restart on a crashed spool succeeds (no corruption refusal)
 *   B. post-restart calls enforce + seal + sign exactly like before
 *   C. console-sync ingests without failures
 *   D. the console distinguishes incomplete pre-crash evidence from the
 *      separately sealed, complete post-restart session
 *
 * Usage:
 *   node scripts/crash-drill.mjs                     # steps 1-5 only
 *   CONSOLE_URL=http://127.0.0.1:60971 DEPLOYMENT_ID=… TOKEN_FILE=… \
 *     COOKIE_JAR=/tmp/owner.jar node scripts/crash-drill.mjs   # + sync leg
 */

import { createServer } from "node:http";
import { spawn, execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, existsSync, readdirSync, statSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const PORT_BASE = Number(process.env.PORT_BASE ?? 60640);
const LLM_PORT = PORT_BASE;
const TOOL_PORT = PORT_BASE + 1;
const DAEMON_PORT = PORT_BASE + 2;
const repoRoot = new URL("..", import.meta.url).pathname;
const daemonBin = process.env.AGENTVISORD ?? [join(repoRoot, "target/release/agentvisord"), join(repoRoot, "target/debug/agentvisord")].find(existsSync);
const avctlBin = process.env.AVCTL ?? [join(repoRoot, "target/release/avctl"), join(repoRoot, "target/debug/avctl")].find(existsSync);
if (!daemonBin) {
  console.error("build first: cargo build --release -p av-harness");
  process.exit(2);
}

const fetch = (input, init = {}) => globalThis.fetch(input, {
  ...init, signal: init.signal ?? AbortSignal.timeout(15000),
});
let failures = 0;
const beat = (ok, label, extra = "") => {
  if (!ok) failures++;
  console.log(`  ${ok ? "✅" : "❌"} ${label}${extra ? "  — " + extra : ""}`);
};

// Scripted LLM: same tool-call shapes as demo-agent, indexed by turn.
let llmTurn = 0;
let holdNextChat = false;
let heldChat;
const upstreamHeld = new Promise((resolve) => { heldChat = resolve; });
const SCRIPT = [
  { tool: "search_inventory", args: { sku: "NW-1240" } },
  { tool: "create_purchase_order", args: { vendor: "Apex Supply Co", amount_usd: 8400 } },
  { tool: "create_purchase_order", args: { vendor: "Contoso", amount_usd: 84 } },
  { text: "done" },
];
const llmSrv = createServer((req, res) => {
  req.on("data", () => {});
  req.on("end", () => {
    if (holdNextChat) {
      holdNextChat = false;
      heldChat();
      return; // Keep the admitted request incomplete until SIGKILL.
    }
    const step = SCRIPT[Math.min(llmTurn, SCRIPT.length - 1)];
    llmTurn++;
    const message = step.tool
      ? { role: "assistant", content: null, tool_calls: [{ id: "call_" + llmTurn, type: "function", function: { name: step.tool, arguments: JSON.stringify(step.args) } }] }
      : { role: "assistant", content: step.text };
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ id: "cc-" + llmTurn, object: "chat.completion", created: Math.floor(Date.now() / 1000), model: "crash-drill-1", choices: [{ index: 0, message, finish_reason: step.tool ? "tool_calls" : "stop" }], usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 } }));
  });
});
const toolSrv = createServer((req, res) => {
  let body = "";
  req.on("data", (c) => (body += c));
  req.on("end", () => {
    let rpc = {}; try { rpc = JSON.parse(body); } catch { /* tolerate */ }
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ jsonrpc: "2.0", id: rpc.id ?? 1, result: { content: [{ type: "text", text: "{}" }] } }));
  });
});

const workDir = mkdtempSync(join(tmpdir(), "av-crash-"));
const configPath = join(workDir, "harness.toml");
writeFileSync(configPath, `config_version = 1
listen = "127.0.0.1:${DAEMON_PORT}"
upstream_url = "http://127.0.0.1:${LLM_PORT}"
tool_upstream_url = "http://127.0.0.1:${TOOL_PORT}"
ignore_client_authorization = true
default_workflow = "signed"
atif_spool_dir = "${workDir}/spool/atif"
bridge_data_dir = "${workDir}/data/bridge"
require_tool_schema = false

[budget]
max_payout_usd_micros = 500000000
`);

const daemonUrl = `http://127.0.0.1:${DAEMON_PORT}`;
let SESSION = "crash-" + Date.now().toString(36);
const crashedSession = SESSION;

function startDaemon() {
  const d = spawn(daemonBin, ["--config", configPath], {
    stdio: ["ignore", "pipe", "pipe"],
    env: { ...process.env, AV_SIGNING_SEED_FILE: join(workDir, "signing.seed") },
  });
  let log = "";
  d.stdout.on("data", (c) => (log += c));
  d.stderr.on("data", (c) => (log += c));
  return { proc: d, log: () => log };
}
async function waitHealthy(timeoutMs = 15000) {
  const until = Date.now() + timeoutMs;
  while (Date.now() < until) {
    try { const r = await fetch(`${daemonUrl}/health`); if (r.ok) return true; } catch { /* booting */ }
    await new Promise((r) => setTimeout(r, 250));
  }
  return false;
}
const chat = (text) => fetch(`${daemonUrl}/v1/chat/completions`, {
  method: "POST",
  headers: { "content-type": "application/json", "x-av-session": SESSION },
  body: JSON.stringify({ model: "crash-drill-1", messages: [{ role: "user", content: text }] }),
}).then(async (r) => ({ status: r.status, body: await r.json().catch(() => ({})) }));
const callTool = (name, args, id) => fetch(`${daemonUrl}/mcp`, {
  method: "POST",
  headers: { "content-type": "application/json", "x-av-session": SESSION },
  body: JSON.stringify({ jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: args } }),
}).then(async (r) => ({ status: r.status, body: await r.json().catch(() => ({})) }));

function spoolFiles() {
  const dir = join(workDir, "spool/atif");
  if (!existsSync(dir)) return [];
  const out = [];
  const walk = (d) => { for (const f of readdirSync(d)) { const p = join(d, f); statSync(p).isDirectory() ? walk(p) : out.push(p); } };
  walk(dir);
  return out;
}

let daemon;
const shutdown = async (code) => {
  const child = daemon?.proc;
  if (child && child.exitCode === null && child.signalCode === null) {
    child.kill("SIGTERM");
    await Promise.race([
      new Promise((resolve) => child.once("exit", resolve)),
      new Promise((resolve) => setTimeout(resolve, 5000)),
    ]);
    if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
  }
  llmSrv.closeAllConnections();
  toolSrv.closeAllConnections();
  llmSrv.close();
  toolSrv.close();
  process.exit(code);
};

const main = async () => {
  console.log("daemon crash-durability drill");
  await new Promise((r) => llmSrv.listen(LLM_PORT, "127.0.0.1", r));
  await new Promise((r) => toolSrv.listen(TOOL_PORT, "127.0.0.1", r));

  daemon = startDaemon();
  const booted = await waitHealthy();
  beat(booted, "boot: daemon healthy", `pid ${daemon.proc.pid}`);
  if (!booted) {
    const logPath = join(workDir, "daemon-boot.log");
    writeFileSync(logPath, daemon.log(), { mode: 0o600 });
    throw new Error(`Daemon did not become healthy within 15 seconds. Log: ${logPath}\n${daemon.log().slice(-4000)}`);
  }

  // Pre-crash story: one allowed, one BLOCKED.
  const t1 = await chat("restock");
  await callTool("search_inventory", JSON.parse(t1.body?.choices?.[0]?.message?.tool_calls?.[0]?.function?.arguments ?? "{}"), "t1");
  const t2 = await chat("order more");
  const x2 = await callTool("create_purchase_order", JSON.parse(t2.body?.choices?.[0]?.message?.tool_calls?.[0]?.function?.arguments ?? "{}"), "t2");
  beat(!!x2.body?.error, "pre-crash: $8,400 order BLOCKED", JSON.stringify(x2.body?.error ?? {}).slice(0, 80));
  const preFiles = spoolFiles();
  beat(preFiles.length > 0, "pre-crash: spool has persisted frames", `${preFiles.length} file(s)`);

  // Make the crash point deterministic: admission has reached the upstream,
  // while its response and response-capture completion cannot have happened.
  holdNextChat = true;
  const interruptedChat = chat("hold until crash").catch(() => null);
  await Promise.race([
    upstreamHeld,
    new Promise((_, reject) => setTimeout(() => reject(new Error("pending request did not reach upstream")), 5000)),
  ]);
  beat(true, "pre-crash: admitted request is still awaiting its response");

  // The worst moment: SIGKILL. No flush, no shutdown handler.
  process.kill(daemon.proc.pid, "SIGKILL");
  await interruptedChat;
  llmSrv.closeAllConnections();
  await new Promise((r) => setTimeout(r, 600));
  const deadNow = !(await fetch(`${daemonUrl}/health`).then((r) => r.ok).catch(() => false));
  beat(deadNow, "SIGKILL delivered, daemon dead");

  // A: restart on the same (crashed) spool/bridge.
  daemon = startDaemon();
  const upAgain = await waitHealthy();
  beat(upAgain, "A: restart on crashed spool succeeds", upAgain ? "" : daemon.log().slice(-300));
  if (!upAgain) return shutdown(1);

  // B1: the crashed session is CRASH-SEALED — its evidence is frozen and
  // the daemon refuses post-hoc appends (same rule as normal seals:
  // sealed sessions refuse events forever). Anything else would let a
  // crash become an evidence-injection window.
  const xDead = await callTool("create_purchase_order", { vendor: "Contoso", amount_usd: 84 }, "t-dead");
  beat(xDead.status === 400 && /already closed/i.test(JSON.stringify(xDead.body)), "B1: crashed session refuses appends (crash-sealed)", JSON.stringify(xDead.body).slice(0, 100));

  // B2: a NEW session on the recovered daemon enforces + seals + signs.
  SESSION = SESSION + "-after";
  const t3 = await chat("order within policy");
  const tc3 = t3.body?.choices?.[0]?.message?.tool_calls?.[0];
  const x3 = await callTool("create_purchase_order", JSON.parse(tc3?.function?.arguments ?? "{}"), "t3");
  beat(x3.status === 200 && !x3.body?.error, "B2: post-restart $84 order ALLOWED (new session)");
  const closeRes = await fetch(`${daemonUrl}/v1/sessions/${SESSION}/close`, { method: "POST" });
  const closeBody = await closeRes.json().catch(() => ({}));
  const rcpt = closeBody?.receipt ?? {};
  beat(closeRes.status === 200 && closeBody?.kind === "receipt" && typeof rcpt.signature_b64 === "string",
    "B2: post-restart close seals with a SIGNED receipt",
    `allowed ${rcpt.tool_calls?.allowed} · blocked ${rcpt.tool_calls?.blocked}`);

  // C+D: sync everything into a console and count across sessions.
  const CONSOLE_URL = process.env.CONSOLE_URL;
  if (!CONSOLE_URL || !avctlBin) {
    console.log("  (sync leg skipped — set CONSOLE_URL/DEPLOYMENT_ID/TOKEN_FILE and build avctl)");
  } else {
    const syncOut = execFileSync(avctlBin, [
      "console-sync",
      "--spool-dir", join(workDir, "spool/atif"),
      "--bridge-dir", join(workDir, "data/bridge"),
      "--console-url", CONSOLE_URL,
      "--deployment", process.env.DEPLOYMENT_ID,
      "--token-file", process.env.TOKEN_FILE,
      "--state-file", join(workDir, "sync-state.json"),
    ], { encoding: "utf8" });
    let stats = {};
    try { stats = JSON.parse(syncOut.trim().split("\n").pop()); } catch { /* shape drift */ }
    beat(stats.failed === 0 && (stats.succeeded ?? 0) > 0, "C: console-sync ingests with zero failures", syncOut.trim().split("\n").pop());
    // D: partial evidence must have an explicit terminal quarantine status.
    // A private crash journal cannot justify a complete signed receipt.
    const jar = process.env.COOKIE_JAR;
    if (!jar) {
      beat(false, "D: console verification requires COOKIE_JAR");
    } else {
      const cookie = readFileSync(jar, "utf8").split("\n").filter((line) => line.includes("av_session"))
        .map((line) => "av_session=" + line.trim().split(/\s+/).pop()).pop() ?? "";
      const response = await fetch(`${CONSOLE_URL}/api/v1/sessions?q=${encodeURIComponent(crashedSession)}&limit=20`, { headers: { cookie } });
      beat(response.ok, "D: console session query succeeds");
      const sessions = await response.json();
      const quarantined = (sessions.sessions ?? []).find((session) => session.externalId === crashedSession);
      beat(quarantined?.status === "quarantined_crash_evidence",
        "D: pre-crash session is explicitly quarantined in the console");
      if (quarantined) {
        const detail = await fetch(`${CONSOLE_URL}/api/v1/sessions/${quarantined.id}`, { headers: { cookie } }).then((r) => r.json());
        const session = detail.session ?? detail;
        beat(!session.receipt, "D: incomplete capture has no signed receipt");
      }
      const recovered = (sessions.sessions ?? []).find((session) => session.externalId === SESSION);
      beat(recovered?.status === "sealed", "D: complete post-restart session is sealed separately");
    }
  }

  console.log("");
  console.log(failures === 0 ? (process.env.CONSOLE_URL ? "✅  crash drill: daemon and console invariants hold" : "✅  crash drill: daemon checks pass; console synchronization was not tested") : `❌  crash drill: ${failures} failure(s)`);
  await shutdown(failures === 0 ? 0 : 1);
};

main().catch((err) => { console.error(err); shutdown(1); });
