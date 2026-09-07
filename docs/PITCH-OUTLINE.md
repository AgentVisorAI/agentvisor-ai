# Pitch outline — workshop draft (Mon 9/8), Demo Day 23/9

A 3-minute arc plus the Q&A ammunition. Built to survive the workshop:
every section names its *claim*, the *evidence behind it*, and *what to
cut if time shrinks*. The demo beats reference
[DEMO-SCENARIO.md](./DEMO-SCENARIO.md).

---

## 0. One-liner

> **AgentVisor is the policy checkpoint between AI agents and the real
> world: it blocks unauthorized actions before they execute, and signs
> cryptographic receipts of everything — so companies can give agents
> autonomy without giving up control or evidence.**

Shorter: *"Enforce before. Prove after."*

## 1. Hook (0:00–0:20)

Agents stopped being chatbots. They file purchase orders, issue
refunds, move money. The question every buyer's compliance team asks
is brutal and simple: **"What stops it, and can you prove what it
did?"** Today the honest answer is "a system prompt" and "our logs,
trust us."

*Cut nothing here; the hook is the pitch.*

## 2. Problem (0:20–0:45)

- Prompts are suggestions, not controls — one injection or one bad
  plan and the agent acts.
- Observability tools tell you what happened *after* the money moved.
- Compliance can't sign off on "we log things." They need enforcement
  at a boundary they control and evidence they can verify without
  trusting the vendor's database.

## 3. Solution (0:45–1:10)

AgentVisor is a daemon that sits between the agent and everything it
touches (LLM + tools):

1. **Gates in the request path** — identity, rate, size, budgets
   (tokens, per-tool calls, **payout caps in USD**), custom WASM
   policies, loop breaker. Fail-closed.
2. **Signed receipts** — every session seals with an Ed25519 receipt
   (counts, cost, event-chain head). Verifiable **offline** against
   the deployment's public key.
3. **One-line adoption** — OpenAI-compatible proxy + MCP; change the
   base URL, done. Hosted console for the team: sessions, policies,
   audit trail, SSO/MFA, the whole enterprise checklist.

## 4. Demo (1:10–2:30) — see DEMO-SCENARIO.md

The $8,400 story: blocked mid-flight → compliant retry allowed →
signed receipt → verified in the hosted console. Offline-safe.

## 5. Why us / why now (2:30–2:50)

- **Why now:** agent frameworks won the "can it act" race in 2025-26;
  nobody owns the "may it act" layer. Procurement is starting to ask
  for it by name (EU AI Act logging duties, SOC 2 scoping of agent
  actions).
- **Differentiation:** enforcement *and* evidence in one boundary.
  Guardrail SDKs live inside the agent's process (the thing you don't
  trust); observability vendors watch but can't stop; we sit outside,
  fail closed, and hand auditors math instead of dashboards.
- **Proof of seriousness** (say only if asked): 1,200+ engine tests,
  12 adversarial drill suites (SSRF, IDOR, replay, injection,
  enumeration-oracle), disaster-recovery restore with receipts still
  verifying, uniform-timing auth throughout.

## 6. Status & ask (2:50–3:00)

- Live today: installer, daemon, hosted console
  (agentvisorai.me — public demo needs no signup), signed receipts,
  the security/enterprise surface finished.
- Ask: **[design partners running agents that move money / seed
  conversation — pick per audience]**.

---

## Q&A ammunition

| Likely question | Answer |
|---|---|
| Latency overhead? | Checkpoint work is local (no extra network hop for policy); full signed pipeline sustained ~140 req/s on a laptop in our bench. For agent workloads (seconds per step) it's noise. |
| What if the daemon dies? | Fail-closed by default; sessions seal on close or idle sweep; spool survives restarts (single-instance lock). |
| Why not just prompts/guardrails in the agent? | The agent's process is the untrusted thing. Controls must live outside it, like a firewall vs. asking apps nicely. |
| Receipts — blockchain? | No. Ed25519 signatures over a canonical event-chain frame; verify offline with the public key. Auditors get math, not consensus. |
| Multi-tenant / team story? | Orgs, roles with rank guards, SAML + passkey MFA (incl. admin recovery), IP allowlists, retention windows, full audit trail with export. |
| Data privacy? | Self-hosted daemon: prompts stay in your infra; console gets metadata + what you choose to sync. GDPR export + delete are one click. |
| Policy management at fleet scale? | Console manages policy definitions today; daemons enforce local files — fleet auto-sync is on the roadmap and the UI says so honestly. |
| What breaks if OpenAI changes the API? | We speak the wire shape, tested against provider adapters; local Ollama works too (demo runs with zero network). |

## Workshop questions to resolve tomorrow (owner: Zach)

1. The ask: design partners, seed, or both — one sentence.
2. Team slide content (not in this repo).
3. Market sizing framing the mentors prefer (top-down vs. "every
   agent deployment needs this").
4. Whether the live-sync beat stays (runbook proves it's 2 s and
   safe) or the offline set piece alone carries the demo.
