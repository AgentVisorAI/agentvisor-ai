# AgentVisor AI status

Real-time SLO tracker. Curated by the on-call.

## Current status

**All systems operational** — last verified: (edit this line on
every deploy).

- **Console** (`agentvisorai.me/app/`) — nominal
- **API** (`api.agentvisorai.me`) — nominal
- **Ingest** (`api.agentvisorai.me/api/v1/ingest`) — nominal
- **Real-time bus** (SSE) — nominal

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

Point the monitor at:

```
https://api.agentvisorai.me/healthz
```

Expect a 200 with `{"ok":true,"version":"…"}`.

For deeper checks, prod-mode healthchecks should hit `/readyz` too — a
503 there means the DB (or the LISTEN/NOTIFY bridge) is degraded.

## Contact

Incidents: post in-repo issues tagged `incident:` or email
security@agentvisorai.me for anything sensitive.
