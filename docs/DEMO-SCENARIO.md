# Demo scenario — the 3–5 minute storyline (Demo Day 23/9)

The narrative layer. Commands, timings, and the reset live in
[DEMO-RUNBOOK.md](./DEMO-RUNBOOK.md); this file is what you *say* and
*show*. One protagonist, one number, one payoff:

> **A procurement agent tries to move $8,400 to an unapproved vendor.
> AgentVisor blocks it mid-flight, lets the compliant $84 retry
> through, and hands you cryptographic proof of both decisions.**

Every claim below was executed against the shipped release and the
live hosted stack (2026-09-07). Nothing is mocked except the LLM
script — and we *say* it's scripted, because that's a feature
(deterministic demos, no venue-wifi roulette).

---

## Cold open (20 s) — the fear

*Screen: nothing yet. Just talk.*

"Companies are giving AI agents credit cards. An agent that can file
POs, issue refunds, move money. The first time one of them buys
$8,400 of servo mounts from the wrong vendor, two questions get asked:
**why could it do that**, and **prove what happened**. Today most
teams can answer neither."

## Beat A (60 s) — watch it get blocked, live, offline

*Terminal, big font:* `node scripts/demo-agent.mjs`

Narrate over the ~8 s run (it prints the story as checkmarks):

- "Real agent, real enforcement daemon. The model is scripted so you
  can watch every decision — this demo needs no network at all."
- ✅ "It checks inventory — allowed. Policy says read-only tools are
  fine."
- ⛔ "**Now it tries the $8,400 purchase order. Blocked.** Not by a
  prompt, not by a guideline — by a $500 payout cap enforced *in the
  request path*, before the tool ever executes. The agent gets a
  machine-readable refusal: `action budget exceeded`."
- ✅ "It retries within policy — $84 to an approved vendor. Allowed."
- "And the session seals with an **Ed25519-signed receipt: 2 allowed,
  1 blocked, 3 total.** That's the evidence."

## Beat B (60 s) — the control plane

*Browser: hosted console (already signed in, per runbook preflight).
Terminal 2 runs the 2-second `console-sync`.*

- "Same session, now in the hosted console." *Click the session.*
- "Here's the exact moment it was stopped — the blocked call, the
  reason, the policy that fired." *Point at the blocked event.*
- "And the receipt: **Signature verified** against this deployment's
  anchored public key. Anyone can re-verify this offline — auditors
  don't have to trust our database, or us." *Open the receipt card,
  optionally the public verifier.*

## Beat C (45 s) — this is a product, not a demo

*Stay in the console, move fast — this is a montage, not a tour.*

- Flash Settings: "Team, roles, SAML and passkeys, IP allowlists,
  retention, a full audit trail — the boring enterprise things,
  because the buyer is compliance, not the ML team."
- One line on integration: "Adopting it is one base-URL change —
  it speaks the OpenAI wire shape and MCP. No SDK."

## Close (20 s) — the ask

"Agents are getting autonomy faster than companies are getting
control. AgentVisor is the checkpoint in between: **enforce before,
prove after.** It's live today — install script, hosted console,
signed receipts. [ask]."

---

## Numbers you can say out loud (all verified this cycle)

| Claim | Basis |
|---|---|
| "Blocks in the request path, fail-closed" | Budget/policy denial returned as JSON-RPC error before tool execution; WASM policy traps fail closed |
| "Signed, offline-verifiable receipts" | Ed25519 over a canonical frame; re-verified against the anchored key on the hosted console this week |
| "One base-URL integration" | OpenAI-compatible proxy + MCP passthrough |
| "~140 requests/sec of fully signed pipeline on a laptop" | Local loadgen, zero daemon-side drops at burst sizes the OS could deliver |
| "1,200+ engine tests, 89-check API e2e, 12 security drill suites, 3-browser matrix" | CI + this cycle's verification sweeps |
| "Disaster recovery proven" | Encrypted nightly backup → restore → receipts still cryptographically verify |

## Things NOT to claim

- No customers/revenue numbers — there are none yet; say "live today,
  looking for design partners."
- Don't call receipts "blockchain" (they're signed evidence chains).
- Don't promise console→daemon policy *sync* — the console manages
  policies; daemons enforce local files today, and the UI says so
  honestly.

## Failure choreography

- Set piece fails (never has): switch to the mock console tour
  (`?live=0`, ⚡ Simulate an attack) — same story, canned data, say so.
- Console/wifi fails: Beat A already landed the whole argument
  offline; show the 41.6 s walkthrough video for the console half.
- Question you can't answer: "That's exactly the kind of thing we
  drill — I'll follow up with the receipt." (And do.)
