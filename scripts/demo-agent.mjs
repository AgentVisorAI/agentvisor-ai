#!/usr/bin/env node
/**
 * Demo agent with an offline-safe upstream — the Demo Day set piece as
 * ONE command, no network, no API keys, deterministic every run:
 *
 *   node scripts/demo-agent.mjs
 *
 * What it does:
 *   1. Boots an in-process mock LLM provider (OpenAI chat shape) and a
 *      mock MCP tool backend. Zero external calls — works on venue
 *      wifi, airplane mode, or a dead OpenAI region.
 *   2. Writes a throwaway daemon config (tmp spool, $500 payout cap)
 *      and spawns agentvisord against the mocks.
 *   3. Plays the pitch storyline through the REAL enforcement path:
 *        turn 1  search_inventory("NW-1240")            → allowed
 *        turn 2  create_purchase_order(Apex,  $8,400)   → ⛔ BLOCKED (budget cap)
 *        turn 3  create_purchase_order(Contoso, $84)    → allowed
 *   4. Closes the session and checks the signed receipt that comes
 *      back: 2 allowed, 1 blocked, Ed25519 signature present.
 *
 * Flags:
 *   --daemon-bin <path>   agentvisord binary (default: target/release,
 *                         then target/debug, then $PATH)
 *   --keep                leave the daemon + mocks running after the
 *                         story (for a live console-sync follow-up);
 *                         prints the spool dir + session id
 *   --port-base <n>       first of three consecutive ports (default 9640)
 *
 * Exit code 0 only when every beat lands exactly as scripted.
 */
import { createServer } from "node:http";
import { spawn, execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const args = process.argv.slice(2);
const flag = (name) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : null;
};
const KEEP = args.includes("--keep");
const PORT_BASE = Number(flag("--port-base") ?? 9640);
const LLM_PORT = PORT_BASE;      // mock provider
const TOOL_PORT = PORT_BASE + 1; // mock MCP tool backend
const DAEMON_PORT = PORT_BASE + 2;

const repoRoot = new URL("..", import.meta.url).pathname;
const daemonBin =
  flag("--daemon-bin") ??
  [join(repoRoot, "target/release/agentvisord"), join(repoRoot, "target/debug/agentvisord")]
    .find(existsSync) ?? "agentvisord";

const c = { g: "\x1b[32m", r: "\x1b[31m", y: "\x1b[33m", d: "\x1b[2m", b: "\x1b[1m", x: "\x1b[0m" };
const say = (s) => console.log(s);
let failures = 0;
const beat = (ok, label, extra = "") => {
  if (!ok) failures++;
  say(`  ${ok ? c.g + "✅" : c.r + "❌"} ${label}${c.x}${extra ? c.d + "  " + extra + c.x : ""}`);
};

// ---------------------------------------------------------------- mocks
// Scripted LLM: answers depend on how many times the agent has asked.
// Each reply is a plain (non-streaming) OpenAI chat completion.
let llmTurn = 0;
const LLM_SCRIPT = [
  { tool: "search_inventory", args: { sku: "NW-1240" } },
  { tool: "create_purchase_order", args: { vendor: "Apex Supply Co", amount_usd: 8400 } },
  { tool: "create_purchase_order", args: { vendor: "Contoso", amount_usd: 84 } },
  { text: "Restock complete: PO placed with Contoso for $84. The $8,400 Apex order was refused by policy." },
];
const llmSrv = createServer((req, res) => {
  let body = "";
  req.on("data", (ch) => (body += ch));
  req.on("end", () => {
    const step = LLM_SCRIPT[Math.min(llmTurn, LLM_SCRIPT.length - 1)];
    llmTurn++;
    const message = step.tool
      ? {
          role: "assistant",
          content: null,
          tool_calls: [{
            id: "call_" + llmTurn,
            type: "function",
            function: { name: step.tool, arguments: JSON.stringify(step.args) },
          }],
        }
      : { role: "assistant", content: step.text };
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({
      id: "chatcmpl-demo-" + llmTurn,
      object: "chat.completion",
      created: Math.floor(Date.now() / 1000),
      model: "demo-scripted-1",
      choices: [{ index: 0, message, finish_reason: step.tool ? "tool_calls" : "stop" }],
      usage: { prompt_tokens: 120, completion_tokens: 40, total_tokens: 160 },
    }));
  });
});

// Mock MCP tool backend: what the daemon forwards ALLOWED calls to.
const toolSrv = createServer((req, res) => {
  let body = "";
  req.on("data", (ch) => (body += ch));
  req.on("end", () => {
    let rpc = {};
    try { rpc = JSON.parse(body); } catch { /* tolerate */ }
    const name = rpc?.params?.name ?? "unknown";
    const result =
      name === "search_inventory"
        ? { content: [{ type: "text", text: JSON.stringify({ sku: "NW-1240", in_stock: 0, reorder: true }) }] }
        : { content: [{ type: "text", text: JSON.stringify({ po: "PO-29841", vendor: rpc?.params?.arguments?.vendor, amount_usd: rpc?.params?.arguments?.amount_usd }) }] };
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ jsonrpc: "2.0", id: rpc.id ?? 1, result }));
  });
});

// ---------------------------------------------------------------- daemon
const workDir = mkdtempSync(join(tmpdir(), "av-demo-"));
const configPath = join(workDir, "harness.toml");
writeFileSync(configPath, `# Generated by scripts/demo-agent.mjs — throwaway demo config.
config_version = 1
listen = "127.0.0.1:${DAEMON_PORT}"
upstream_url = "http://127.0.0.1:${LLM_PORT}"
tool_upstream_url = "http://127.0.0.1:${TOOL_PORT}"
ignore_client_authorization = true
default_workflow = "signed"
atif_spool_dir = "${workDir}/spool/atif"
bridge_data_dir = "${workDir}/data/bridge"
# Demo tools use ad-hoc shapes; schema enforcement is a different beat.
require_tool_schema = false

# The star of the show: a $500 payout cap. Turn 2's $8,400 order dies here.
[budget]
max_payout_usd_micros = 500000000
`);

const daemon = spawn(daemonBin, ["--config", configPath], {
  stdio: ["ignore", "pipe", "pipe"],
});
daemon.on("error", (e) => {
  say(`${c.r}could not start the daemon (${daemonBin}): ${e.message}${c.x}`);
  say(`${c.d}build it first:  cargo build --release -p av-harness${c.x}`);
  llmSrv.close(); toolSrv.close();
  try { rmSync(workDir, { recursive: true, force: true }); } catch { /* fine */ }
  process.exit(1);
});
let daemonLog = "";
daemon.stdout.on("data", (d) => (daemonLog += d));
daemon.stderr.on("data", (d) => (daemonLog += d));

const shutdown = (code) => {
  if (!KEEP) {
    try { daemon.kill("SIGTERM"); } catch { /* gone */ }
    llmSrv.close();
    toolSrv.close();
    // Give the daemon its drain window before removing the spool.
    setTimeout(() => { try { rmSync(workDir, { recursive: true, force: true }); } catch { /* busy */ } process.exit(code); }, 1200);
  } else {
    say(`\n${c.y}--keep: daemon still running${c.x}`);
    say(`${c.d}  daemon   http://127.0.0.1:${DAEMON_PORT}`);
    say(`  config   ${configPath}`);
    say(`  spool    ${workDir}/spool/atif`);
    say(`  next     avctl console-sync --spool-dir ${workDir}/spool/atif --bridge-dir ${workDir}/data/bridge --console-url https://api.agentvisorai.me --deployment <id> --token-file <f>`);
    say(`${c.d}  (keep --bridge-dir: a receipt-only sync seals the session on the console FIRST, and sealed sessions refuse events forever)${c.x}`);
    process.exit(code);
  }
};

const waitFor = async (url, tries = 60) => {
  for (let i = 0; i < tries; i++) {
    try { const r = await fetch(url); if (r.ok) return true; } catch { /* booting */ }
    await new Promise((r) => setTimeout(r, 250));
  }
  return false;
};

// ---------------------------------------------------------------- story
const SESSION = "demo-" + Date.now().toString(36);
const daemonUrl = `http://127.0.0.1:${DAEMON_PORT}`;

const chat = async (userText) => {
  const r = await fetch(`${daemonUrl}/v1/chat/completions`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-av-session": SESSION,
      "authorization": "Bearer demo-sdk-placeholder",
    },
    body: JSON.stringify({
      model: "demo-scripted-1",
      messages: [{ role: "user", content: userText }],
    }),
  });
  return { status: r.status, body: await r.json().catch(() => ({})) };
};

const callTool = async (name, toolArgs, id) => {
  const r = await fetch(`${daemonUrl}/mcp`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-av-session": SESSION },
    body: JSON.stringify({ jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: toolArgs } }),
  });
  return { status: r.status, body: await r.json().catch(() => ({})) };
};

const main = async () => {
  say(`${c.b}AgentVisor demo agent${c.x} ${c.d}(offline-safe: scripted provider + tool backend)${c.x}`);
  say(`${c.d}  daemon: ${daemonBin}${c.x}\n`);

  await new Promise((r) => llmSrv.listen(LLM_PORT, "127.0.0.1", r));
  await new Promise((r) => toolSrv.listen(TOOL_PORT, "127.0.0.1", r));
  const up = await waitFor(`${daemonUrl}/health`);
  beat(up, "daemon healthy", up ? `pid ${daemon.pid}, session ${SESSION}` : daemonLog.slice(-400));
  if (!up) return shutdown(1);

  // Turn 1 — the agent asks, the (scripted) model wants inventory.
  const t1 = await chat("We're out of NW-1240 servo mounts. Restock.");
  const tc1 = t1.body?.choices?.[0]?.message?.tool_calls?.[0];
  beat(t1.status === 200 && tc1?.function?.name === "search_inventory", "turn 1: model asks for search_inventory");
  const x1 = await callTool("search_inventory", JSON.parse(tc1?.function?.arguments ?? "{}"), "t1");
  beat(x1.status === 200 && !!x1.body?.result && !x1.body?.error, "turn 1: search_inventory ALLOWED through Gate 3", "stock: 0 → reorder");

  // Turn 2 — the model tries an $8,400 PO with an unapproved vendor.
  const t2 = await chat("Nothing in stock. Order more.");
  const tc2 = t2.body?.choices?.[0]?.message?.tool_calls?.[0];
  const a2 = JSON.parse(tc2?.function?.arguments ?? "{}");
  beat(tc2?.function?.name === "create_purchase_order" && a2.amount_usd === 8400, "turn 2: model wants create_purchase_order($8,400)");
  const x2 = await callTool("create_purchase_order", a2, "t2");
  const denied = !!x2.body?.error || x2.status >= 400;
  beat(denied, `turn 2: $8,400 order ${c.r}⛔ BLOCKED${c.x} by the $500 payout cap`, JSON.stringify(x2.body?.error ?? x2.body).slice(0, 120));

  // Turn 3 — the model retries within policy.
  const t3 = await chat("That was refused. Order within policy.");
  const tc3 = t3.body?.choices?.[0]?.message?.tool_calls?.[0];
  const a3 = JSON.parse(tc3?.function?.arguments ?? "{}");
  beat(tc3?.function?.name === "create_purchase_order" && a3.amount_usd === 84, "turn 3: model retries with $84 (Contoso)");
  const x3 = await callTool("create_purchase_order", a3, "t3");
  beat(x3.status === 200 && !!x3.body?.result && !x3.body?.error, "turn 3: $84 order ALLOWED", "PO-29841");

  // Wrap-up narration turn (keeps the transcript story-complete).
  await chat("Summarize.");

  // Close → the daemon seals the session and answers with the receipt.
  const closeRes = await fetch(`${daemonUrl}/v1/sessions/${SESSION}/close`, { method: "POST" });
  const closeBody = await closeRes.json().catch(() => ({}));
  const rcpt = closeBody?.receipt ?? {};
  beat(closeRes.status === 200 && closeBody?.kind === "receipt", "session sealed on close");
  beat(typeof rcpt.signature_b64 === "string" && rcpt.signature_b64.length > 40 && typeof rcpt.public_key_b64 === "string",
    "signed receipt returned",
    rcpt.key_id ? `key ${rcpt.key_id.slice(0, 12)}… sig ${String(rcpt.signature_b64).slice(0, 16)}…` : "");
  const tc = rcpt.tool_calls ?? {};
  beat(tc.allowed === 2 && tc.blocked === 1 && tc.total === 3,
    "receipt counts the story exactly", `allowed ${tc.allowed} · blocked ${tc.blocked} · total ${tc.total}`);

  say("");
  if (failures === 0) {
    say(`${c.g}${c.b}Demo storyline ✔ — 2 allowed, 1 blocked, receipt signed.${c.x}`);
    if (!KEEP) say(`${c.d}(daemon and mocks torn down; --keep leaves them up for console-sync)${c.x}`);
  } else {
    say(`${c.r}${c.b}${failures} beat(s) missed.${c.x} Daemon log tail:\n${c.d}${daemonLog.slice(-800)}${c.x}`);
  }
  shutdown(failures === 0 ? 0 : 1);
};

main().catch((e) => {
  say(`${c.r}fatal: ${e.message}${c.x}\n${c.d}${daemonLog.slice(-600)}${c.x}`);
  shutdown(1);
});
