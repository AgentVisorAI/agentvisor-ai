# Demo Day runbook — 23/9 (rehearse from 9/8)

One page. The demo is three beats, ~4 minutes, with a fallback for
every beat. Every command below was executed and timed on 2026-09-07
against the shipped release + live prod stack.

## Preflight (night before + 30 min before going on)

```sh
# 1. Binaries exist and are healthy
target/release/agentvisord --version && target/release/avctl --version

# 2. The offline set piece is green (10/10 beats, ~8 s)
node scripts/demo-agent.mjs

# 3. Prod is up
curl -fsS https://api.agentvisorai.me/healthz
curl -fsS -o /dev/null https://agentvisorai.me/app/

# 4. Console signed in as the demo owner in a CLEAN browser profile
#    (debug6667@proton.me — password in the usual vault). Park the tab
#    on #/overview with ?live=1.

# 5. Demo deployment exists + token saved (see Reset below if not)
cat /tmp/demo-token >/dev/null && cat /tmp/demo-dep.txt
```

## Beat A — the offline set piece (~30 s, zero network)

> "This is a real agent, a real enforcement daemon, and a scripted
> model so you can see every decision. Watch the $8,400 order."

```sh
node scripts/demo-agent.mjs
```

Talking points while it runs: search allowed → **$8,400 PO blocked by
the $500 cap** (`action budget exceeded`) → $84 retry allowed → sealed
with a signed receipt: `allowed 2 · blocked 1 · total 3`.

Works in airplane mode — the model and tool backend are in-process.

## Beat B — the same story lands in the hosted console (~30 s)

```sh
node scripts/demo-agent.mjs --keep          # terminal 1: leaves stack up
# terminal 2 (SPOOL is printed by --keep; DEP/token from preflight #5):
target/release/avctl console-sync \
  --spool-dir  <SPOOL>/spool/atif \
  --bridge-dir <SPOOL>/data/bridge \
  --console-url https://api.agentvisorai.me \
  --deployment $(awk '{print $2}' /tmp/demo-dep.txt) \
  --token-file /tmp/demo-token \
  --state-file /tmp/demo-state.json
```

Sync measured at **2 s**. Refresh the console: the session is
**sealed, blocked 1 / allowed 2**, and the receipt shows
**Signature verified** against the deployment's anchored key
(re-verified cryptographically on 2026-09-07: ed25519 over the
`agentvisor-receipt-v2` frame → `true`).

> ⚠️ **Always pass `--spool-dir` AND `--bridge-dir` in ONE sync.**
> A receipt-only sync seals the console session first, and sealed
> sessions refuse events forever — the counters stay 0 and no reset
> short of deleting the session fixes it.

## Beat C — console walkthrough (~2 min)

Session detail (blocked event + narrative) → receipt card → "Verify"
→ offline verifier goes green → Settings › Audit (the trail) →
optionally ⚡ Simulate an attack on the mock demo (`?live=0`).

## Reset procedure (between rehearsals / before going on)

```sh
# Wipe the demo deployment (cascades its sessions + receipts), recreate:
B=https://api.agentvisorai.me/api/v1
H='-H Content-Type:application/json -H X-Requested-With:fetch -H Origin:https://agentvisorai.me'
curl -s -c /tmp/prod.jar $H -X POST $B/auth/login \
  -d '{"email":"debug6667@proton.me","password":"<vault>"}'
curl -s -b /tmp/prod.jar $H -X DELETE \
  "$B/deployments/$(awk '{print $2}' /tmp/demo-dep.txt)?force=1"
R=$(curl -s -b /tmp/prod.jar $H -X POST $B/deployments \
  -d '{"name":"demo-day-live","environment":"production"}')
echo "$R" | python3 -c 'import json,sys; d=json.load(sys.stdin); \
  open("/tmp/demo-token","w").write(d["ingestToken"]); \
  print("dep", d["deployment"]["id"])' | tee /tmp/demo-dep.txt
chmod 600 /tmp/demo-token
rm -f /tmp/demo-state.json     # sync state must reset with the deployment
```

Local side: nothing to reset — every `demo-agent.mjs` run uses a fresh
tmp spool and a fresh session id.

## Fallbacks (in order)

1. **Live sync flaky / venue wifi dead** → Beat A alone still lands the
   whole story offline; narrate the console from the mock demo
   (`agentvisorai.me/app/?live=0` — tour + ⚡ attack work without auth).
2. **Laptop trouble** → walkthrough video (41.6 s, re-recorded 2026-09-07
   against the current UI): session files `walkthrough-2026-09-07.webm`.
3. **Prod API down mid-demo** → `docs/RUNBOOK.md` §1-3; the mock console
   and the offline set piece don't depend on it.

## Known timings (measured)

| Step | Time |
|---|---|
| `demo-agent.mjs` full story | ~8 s |
| `console-sync` to prod | ~2 s |
| Console reflects the session | immediate on refresh (SSE pushes it live if the tab was open) |
| Reset procedure | ~10 s |
