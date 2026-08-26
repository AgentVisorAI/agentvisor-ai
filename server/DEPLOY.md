# Deploying AgentVisor AI

This backend is designed to run for free at seed-stage, autoscale to millions
of requests without a rewrite, and stay portable across cloud providers.

## Free tier one-click deploys

Pick any of these — the same `server/Dockerfile` runs on every one. Add or
change providers later with `pg_dump | pg_restore` and a container push.

| Provider | Free tier | Config file | One-click |
|---|---|---|---|
| **Cloudflare Pages** (frontend) | Unlimited bandwidth, HTTP/3, global edge | `docs/_headers`, `docs/_redirects` | [Deploy](https://dash.cloudflare.com/?to=/:account/pages/new/provider/github) |
| **Fly.io** (API) | 3 × shared-cpu-1x, 256 MB, auto-stop | `server/fly.toml` | `fly launch --copy-config` |
| **Render** (API + Postgres) | 750 hrs/mo web + 90-day free 1 GB PG | `render.yaml` | [Deploy](https://render.com/deploy?repo=https://github.com/AgentVisorAI/agentvisor-ai) |
| **Railway** (API + Postgres) | $5/mo credit, no card | `railway.json` | [Deploy](https://railway.app/new/template?template=https://github.com/AgentVisorAI/agentvisor-ai) |
| **Koyeb** (API) | 2 nano services, scale-to-zero | `koyeb.yaml` | [Deploy](https://app.koyeb.com/deploy?type=git&repository=github.com/AgentVisorAI/agentvisor-ai&branch=main&name=agentvisor-api&dockerfile=server/Dockerfile) |
| **Google Cloud Run** (API) | 2M requests/mo, scale-to-zero | `server/Dockerfile` | [Deploy](https://deploy.cloud.run/?git_repo=https://github.com/AgentVisorAI/agentvisor-ai&dir=server) |
| **Neon** (Postgres) | 0.5 GB, auto-scale, autosuspend | `postgres://…` env var | [Sign up](https://neon.tech) |
| **Supabase** (Postgres) | 500 MB, unlimited API | `postgres://…` env var | [Sign up](https://supabase.com) |

Total cost to run the whole demo: **$0**. Total time to move to any other
provider: ~10 minutes.

## Architecture

```
        ┌────────────────────────┐        ┌──────────────────────┐
Console │  agentvisorai.me/app/  │───────▶│  api.agentvisorai.me │───┐
        │  Static SPA            │  HTTPS │  Fastify + Prisma    │   │
        │  MOCK_MODE=false       │        │  Docker container    │   │
        └────────────────────────┘        └──────────┬───────────┘   │
              ▲  (any static host)                   │               │
              │                            postgres://               │
              │                                      ▼               │
Daemon        │                            ┌──────────────────────┐  │
(customer)    └──────── HTTPS ─────────────│  Managed Postgres    │  │
                    ****** X-AV-Deployment│  Neon / Supabase / …│  │
                                          └──────────┬───────────┘  │
                                                     │              │
                                        LISTEN/NOTIFY av_bus        │
                                                     ▼              │
                                          [SSE fan-out across       │
                                           all API instances]       │
                                                                    │
                                            All traffic:  ──────────┘
                                            HSTS 2y, CSP strict,
                                            SameSite cookies, argon2id,
                                            per-user rate limits,
                                            Origin-match CSRF check.
```

Nothing above is provider-specific:

- **Frontend** = static files → any static host
- **Backend** = Docker image → any container host
- **Database** = standard Postgres → any provider that speaks `postgres://`
- **Real-time bus** = `LISTEN/NOTIFY av_bus` on the same Postgres → no
  Redis, no Kafka, no proprietary broker

Swap any of the three without touching the other two.

## Free tier: full walkthrough (frontend + backend + database)

### 1. Frontend — Cloudflare Pages (recommended)

`docs/` is a static SPA + landing page. The recommended free host is
**Cloudflare Pages** (unlimited bandwidth, HTTP/3, Argo edge routing).

```bash
npx wrangler pages deploy docs --project-name agentvisor-console
```

Or connect the repo in the Cloudflare dashboard → `docs/` build root →
auto-deploy on every push.

Bundled with the SPA:

- `docs/_headers` — strict CSP, HSTS 2y+preload, `Permissions-Policy`,
  cross-origin isolation. Cloudflare + Netlify honor this format.
- `docs/_redirects` — proxies `/api/*` and `/healthz` to the API host so
  cookies stay same-origin (skips a CORS preflight).
- `docs/.well-known/security.txt` — RFC 9116 disclosure contact.

Alternative free hosts (identical files, no code changes):

| Host | Command | Free tier |
|---|---|---|
| GitHub Pages | (already wired via `.github/workflows/pages.yml`) | 100 GB/mo bandwidth |
| Netlify | `netlify deploy --dir=docs --prod` | 100 GB/mo bandwidth |
| Vercel | `vercel --cwd docs --prod` | 100 GB/mo bandwidth |
| S3 + CloudFront | `aws s3 sync docs/ s3://bucket/` | 12 mo trial |

### 2. Database — Neon Postgres (recommended)

1. Sign up at [neon.tech](https://neon.tech) — no credit card.
2. Create a project → grab the connection string. It looks like:
   `******ep-xxxxxx-pooler.us-east-2.aws.neon.tech/agentvisor?sslmode=require`
3. Free tier includes:
   - 0.5 GB storage (~250k sessions with signed receipts)
   - Auto-scale compute from 0.25 vCPU
   - 7-day point-in-time recovery
   - Auto-pause when idle → **$0 while nobody's using the app**

Alternatives (all free-tier, all `pg_dump`-compatible, all portable):

- **Supabase** — 500 MB, unlimited API calls, built-in row-level security
- **Fly Postgres** — 3 GB free with a Fly VM
- **Railway** — $5/mo credit, includes Postgres
- **CockroachDB Serverless** — 5 GB, wire-compatible with Postgres

The API auto-detects several PG env-var names — no code tweak needed:
`DATABASE_URL`, `POSTGRES_URL`, `POSTGRES_PRISMA_URL`, `NETLIFY_DATABASE_URL`,
`NEON_DATABASE_URL`, `PGURL`, `DATABASE_URL_POOLED`. Whatever your platform
injects, it works out of the box.

### 3. Backend — Fly.io (recommended)

```bash
brew install flyctl && fly auth signup

cd server
fly launch --copy-config --no-deploy    # picks up fly.toml

# Set secrets (Fly encrypts these at rest; they never appear in the image)
fly secrets set \
  DATABASE_URL="postgres://…your neon url…" \
  JWT_SECRET="$(openssl rand -hex 48)"

fly deploy

# Custom subdomain
fly certs add api.agentvisorai.me
```

Free tier gives you:

- 3 shared-cpu-1x machines (256 MB each)
- Auto-stop when idle → wakes in ~250 ms on next request
- 160 GB egress/month
- Automatic Let's Encrypt certificates
- Global anycast — one deploy, seven+ regions

To flip the frontend to live mode, edit `docs/app/index.html`:

```js
window.MOCK_MODE = false;
window.API_BASE = "https://api.agentvisorai.me/api/v1";
```

Commit + push → Pages redeploys in ~30 s.

### 4. Mailer + SSO (required for a real launch)

Beyond the `$0` demo, two things must be wired before customers can
sign up in production:

**Mailer** (password reset + welcome emails):

- **Resend** (recommended) — 10k emails/mo free, easiest setup. Sign
  up at [resend.com](https://resend.com), verify your domain, grab the
  API key. Set `RESEND_API_KEY=re_…` as a secret. Prod refuses to boot
  without either this or `SMTP_URL`.
- **SMTP** (Postmark, SES, Mailgun, any provider that speaks SMTP)
  — set `SMTP_URL=smtps://user:pass@host:465`. Uses nodemailer's
  standard URL syntax — same URL works on every SMTP provider.
- **Dev**: leave both unset. `NODE_ENV=development` logs the would-be
  email to stdout so you can copy the reset link out of the terminal.

`EMAIL_FROM` defaults to `AgentVisor AI <no-reply@agentvisorai.me>`;
override per environment.

**OIDC login** (Google + Microsoft):

- **Google**: [Google Cloud → APIs & Services → OAuth 2.0 Client IDs](https://console.cloud.google.com/apis/credentials).
  Create a Web application client. Add authorized redirect URI:
  `https://api.agentvisorai.me/api/v1/auth/oauth/google/callback`
  (swap the host for your API origin). Grab client id + secret.
- **Microsoft**: [Azure Portal → App registrations](https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade).
  Register a new app. Redirect URI (Web):
  `https://api.agentvisorai.me/api/v1/auth/oauth/microsoft/callback`.
  Under *Certificates & secrets* create a client secret. Set
  `MICROSOFT_TENANT=common` for multi-tenant + personal, or a specific
  tenant id for enterprise single-tenant.

Set the four secrets:

```bash
fly secrets set \
  GOOGLE_CLIENT_ID="…" GOOGLE_CLIENT_SECRET="…" \
  MICROSOFT_CLIENT_ID="…" MICROSOFT_CLIENT_SECRET="…"
```

The login page automatically shows/hides each button based on which
env vars are populated. No frontend flag to flip. Users signing in via
OIDC land in a new org named after their email domain on first login;
subsequent logins land in their existing org.

**SAML / Okta**: not shipped. The login page's SAML button opens a
`mailto:sales@` for enterprise inquiries — honest about the roadmap
rather than presenting a fake button.

### Alternative backend: Render, Railway, Koyeb, Cloud Run

Each provider has a first-class config file already committed:

- `render.yaml` — Render blueprint (web + Postgres, both on free plans).
- `railway.json` — Railway spec (attach a Postgres plugin in the dashboard).
- `koyeb.yaml` — Koyeb app spec (2 nano services, scale-to-zero).
- `server/fly.toml` — Fly.io machines config.

All four consume the same `server/Dockerfile`. Environment variables
follow the same names (`DATABASE_URL`, `JWT_SECRET`, `ALLOWED_ORIGINS`).
There is no platform-specific code inside the container.

### Alternative backend: self-hosted VPS

`docker compose up -d` on any Linux box with Docker installed. The
`server/docker-compose.yml` runs Postgres + the API side-by-side. Add a
Caddy or nginx reverse proxy for HTTPS, or put Cloudflare Tunnel in
front. No public IP needed.

## Scaling path (100 → 1,000,000 users)

The stack was chosen so the same code and container run at every scale.
No rewrite when demand grows.

| Traffic | Fly.io config | Neon plan | Real-time bus | Monthly cost |
|---|---|---|---|---|
| Pitch demo → 100 users | 1 × shared-cpu-1x, 256 MB, auto-stop | Free | in-process | **$0** |
| 1,000 daily users | 1 × shared-cpu-1x, min_machines=1 | Free | in-process | **$0** |
| 10,000 daily users | `fly autoscale set min=1 max=5` | Launch ($19) | Postgres LISTEN/NOTIFY | **~$29** |
| 100,000 daily users | Multi-region (`fly scale count 3`), shared-cpu-2x | Scale ($69) | Postgres LISTEN/NOTIFY | **~$150** |
| 1,000,000 daily users | Autoscale max=20 across 5 regions, shared-cpu-4x | Business (~$500) | Postgres LISTEN/NOTIFY + optional Redis | **~$1,200** |

The real-time bus scales **without adding a new service** all the way to
~5,000 concurrent SSE subscribers per instance and ~500 events/sec cross-
instance (Postgres LISTEN/NOTIFY comfort zone). Beyond that, drop in
Upstash Redis (free 10k cmd/day → $10/mo → $50/mo tiers) — the same
`bus.ts` module can toggle backends without any route changes.

## Portability & escape hatches

Every piece has a one-command way off it. This is deliberate — nothing
in the stack requires a proprietary service.

**Move off Fly.io** → Cloud Run / Render / Railway / Koyeb / Kubernetes / VPS

```bash
docker build -t agentvisor-api server/
docker push $REG/agentvisor-api

# On the new host — env names below match every platform we tested.
docker run -p 8080:8080 \
  -e DATABASE_URL="postgres://…" \
  -e JWT_SECRET="…" \
  -e ALLOWED_ORIGINS="https://agentvisorai.me" \
  $REG/agentvisor-api
```

**Move off Neon** → any other Postgres

```bash
pg_dump "$OLD_DATABASE_URL" | psql "$NEW_DATABASE_URL"
fly secrets set DATABASE_URL="$NEW_DATABASE_URL"
# The app picks up the new URL on next restart. No migration needed.
```

**Move off Cloudflare Pages** → any static host

```bash
rsync -av docs/ new-host:/var/www/agentvisor-console/
# Update DNS. Done.
```

There is no proprietary schema, no closed-source SDK, no lock-in tier.
Every path off every platform is a single command.

## Security posture (2026 baseline)

- **TLS everywhere.** HSTS is set for 2 years with `preload`. Cloudflare
  or Fly's edge terminates TLS with automatically renewed Let's Encrypt
  certificates.
- **Cookies.** `httpOnly`, `SameSite=Lax`, `Secure` in production. JWT
  is signed HS256 with a 48-byte secret. Rotate `JWT_SECRET` with
  `fly secrets set` — old tokens expire on the next boot.
- **CSP.** `default-src 'none'` on every API response. The SPA has a
  strict CSP via `docs/_headers` allowing `'self'` scripts only,
  plus explicit `connect-src` for the API + SSE. Frame ancestors `'none'`.
- **Password hashing.** Argon2id via the `argon2` native module. Cost:
  19 MiB × 2 iterations × 1 lane — meets OWASP 2024 recommendation.
- **Rate limits.**
  - Global: 300 req/min per authenticated user or IP.
  - `/login`: 10/min per IP (credential stuffing).
  - `/signup`: 5/min per IP (registration spam).
  - `/reset-request`: 3/hour per IP (mailbox spam / mailer cost).
  - `/reset-confirm`: 10/min per IP (token spraying).
- **Password reset.** 32-byte random token, argon2-hashed at rest, 24h
  TTL, single-use. Uniform 202 response regardless of email existence.
  Plaintext token is **never** logged in production (only in dev, so
  you can hand-test locally).
- **CSRF.** SameSite=Lax cookies plus a defense-in-depth Origin/Referer
  match against `ALLOWED_ORIGINS` on every state-changing method. Any
  cross-site POST/PUT/PATCH/DELETE that carries a mismatched Origin is
  rejected before it reaches Prisma.
- **Tenant isolation.** Every read query goes through `session.orgId`.
  There is no user-supplied `orgId` parameter on any endpoint. Tenant
  boundaries are enforced by the database via foreign keys and by the
  application via the session claim.
- **Container hardening.**
  - Runs as `node` (uid 1000), never root.
  - `dumb-init` as PID 1 → fast, correct SIGTERM handling.
  - Multi-stage build, no shell in the runtime CMD.
  - Prisma migrations run on startup — a fresh DB is bootstrapped in
    ~2 s before the API serves the first request.
- **Signed receipts.** Every session ends with an Ed25519-signed receipt
  posted by the daemon. The `deployment.publicKeyHex` is stored so the
  console can verify signatures client-side without trusting the API.
- **Secrets.** `.env` is git-ignored. Deploy secrets live in the
  platform's secret store (`fly secrets`, Render env, Railway variables,
  Koyeb secrets, GCP Secret Manager, Kubernetes `Secret`), not in the
  image. Pino redact catches `password`, `newPassword`, `token`,
  `plaintextToken`, `devOnlyResetToken`, `resetLinkHint` in body/args as
  a last-resort belt-and-suspenders.
- **RFC 9116 disclosure.** Both the API and the static SPA serve
  `/.well-known/security.txt` — researchers can find a coordinated
  disclosure contact by scanning either origin.
- **Audit trail.** The `events` table is append-only in practice — no
  code path updates or deletes an event. Cascading deletes at the
  tenant boundary only fire when the org is deleted by its owner.

Additional hardening for production (not required for the demo):

- Turn on Neon IP allowlist so only the Fly outbound range can connect.
- Enable Fly's WAF (`fly deploy --wg`).
- Enable Postgres row-level security on `sessions`/`events`/`receipts`
  as a defense-in-depth layer (the app already scopes reads by `orgId`,
  but RLS blocks any query that forgets to).
- Wire a real mailer (Postmark / Resend / SES) so password reset tokens
  arrive by email in production. Currently the token is only logged in
  non-production; production emits `{userId}` metadata only.
