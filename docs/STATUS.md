# AgentVisor AI status

Real-time SLO tracker. Curated by the on-call.

## Current status

**Demo surfaces operational · hosted API not yet launched** — last
verified: 2026-08-30.

- **Console** (`agentvisorai.me/app/`) — nominal (mock mode: the full
  product experience against built-in fixtures; nothing leaves the
  browser)
- **Site + verifier** (`agentvisorai.me`, `/verify/`) — nominal
- **Installer + public repo** (`agentvisorai.me/install.sh`,
  `github.com/AgentVisorAI/agentvisor`) — nominal, exercised nightly
  by the `public-consumer` workflow
- **Hosted API** (`api.agentvisorai.me`) — **not launched**. The
  backend ships in this repo (`server/`, deployable image built by
  `deploy.yml`) and its full E2E suite runs in CI, but no public
  instance is up and the DNS record does not exist yet. It goes live
  with the beta — the SLO table below is the launch template, not a
  live measurement. Anything here marked "(fill in)" is unmeasured
  BY DEFINITION until then; treat any claim to the contrary as a bug
  in this page.

## Service level objectives

The demo runs on the free tier of everything. These SLOs are what the
demo-scale deployment aims for; anything above 100 daily active users
should upgrade to paid plans (see `server/DEPLOY.md`).

| SLI | Target | Current | Measured over |
|---|---|---|---|
| API availability (`GET /readyz` 2xx) | 99.5% | (fill in from uptime monitor) | 30 days |
| API p95 latency | < 200 ms | (fill in from Prometheus) | 30 days |
| API p99 latency | < 500 ms | (fill in) | 30 days |
| Ingest success rate | 99.9% | (fill in) | 30 days |
| Real-time delivery latency | < 1 s | (fill in) | 30 days |

## Incident history

_(new deployments log incidents here — one row per incident)_

| Date (UTC) | Duration | Impact | Postmortem |
|---|---|---|---|
| _(none yet)_ | | | |

## Uptime monitoring

The pitch demo uses a single external prober checking `/healthz` every
60 s. Recommended free-tier providers:

- [BetterStack](https://betterstack.com/uptime) — free 10 monitors, 3 min
  cadence, email + Slack alerts.
- [Cronitor](https://cronitor.io) — free 5 monitors + heartbeat checks
  for the nightly `backup.yml` cron.
- [UptimeRobot](https://uptimerobot.com) — free 50 monitors, 5 min
  cadence.

Point the monitor at (once the hosted API launches with the beta —
the host does not resolve before then):

```
https://api.agentvisorai.me/healthz
```

Expect a 200 with `{"ok":true,"version":"…"}`. Until launch, monitor
the live demo surfaces instead: `https://agentvisorai.me/app/` and
`https://agentvisorai.me/build.txt` (the deploy-convergence marker).

For deeper checks, prod-mode healthchecks should hit `/readyz` too — a
503 there means the DB (or the LISTEN/NOTIFY bridge) is degraded.

## Contact

Incidents: post in-repo issues tagged `incident:` or email
security@agentvisorai.me for anything sensitive.
