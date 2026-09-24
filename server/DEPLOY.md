# Deploying AgentVisor AI

The console API is a Node.js application backed by PostgreSQL. This guide
describes deployment templates and the local checks performed against them.
Validate the selected provider's current pricing, limits, and configuration
before deploying. Local results do not establish capacity on a managed host.

## Selecting a release image

The Deploy workflow tests and scans local OCI archives before a separate
main-only job receives registry write permission. Both amd64 and arm64 must
pass, and the required console regression workflow must succeed. Pull requests
publish no registry tags and receive no deployment credentials. The job copies the tested bytes without rebuilding, preserves
BuildKit SBOM/provenance descriptors, and verifies the final multiarch digest.
Deploy `ghcr.io/agentvisorai/agentvisor-api@sha256:...` from a successful
promotion. The optional Fly job uses that exact digest automatically.

The `validated-*` tags are internal staging references, not production release
outputs. Do not select one because it exists in GHCR. Convenience tags
`latest`, `main`, and `sha-<full revision>` can change; record the approved
digest for deployment and rollback. Full scan artifacts include unfixed
findings, which still require review. See [the image lifecycle](../CI-CD.md#container-image-lifecycle)
for the publication boundary and its limits.

## Deployment options

The repository includes container and static-site configuration for these
options. Their presence does not mean each provider has been deployed and
tested. Database migration uses `pg_dump` and `pg_restore`; validate the
restore and application behavior before directing traffic to a new host.

| Provider | Component | Config file | Setup entry point |
|---|---|---|---|
| **Cloudflare Pages** | Frontend | `docs/_headers`, `docs/_redirects` | [Deploy](https://dash.cloudflare.com/?to=/:account/pages/new/provider/github) |
| **Fly.io** | API | `server/fly.toml` | `fly launch --copy-config` |
| **Render** | API + Postgres | `render.yaml` | [Deploy](https://render.com/deploy?repo=https://github.com/AgentVisorAI/agentvisor-ai) |
| **Railway** | API + Postgres | `railway.json` | [Deploy](https://railway.app/new/template?template=https://github.com/AgentVisorAI/agentvisor-ai) |
| **Koyeb** | API | `koyeb.yaml` | [Deploy](https://app.koyeb.com/deploy?type=git&repository=github.com/AgentVisorAI/agentvisor-ai&branch=main&name=agentvisor-api&dockerfile=server/Dockerfile) |
| **Google Cloud Run** | API | `server/Dockerfile` | [Deploy](https://deploy.cloud.run/?git_repo=https://github.com/AgentVisorAI/agentvisor-ai&dir=server) |
| **Neon** | Postgres | `DATABASE_URL` | [Provider](https://neon.tech) |
| **Supabase** | Postgres | `DATABASE_URL` | [Provider](https://supabase.com) |

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
                                            per-IP rate limits,
                                            Origin-match CSRF check.
```

Nothing above is provider-specific:

- **Frontend** = static files → any static host
- **Backend** = Docker image → any container host
- **Database** = standard Postgres → any provider that speaks `postgres://`
- **Real-time bus** = `LISTEN/NOTIFY av_bus` on the same Postgres → no
  Redis, no Kafka, no proprietary broker

Swap any of the three without touching the other two.

## Deployment walkthrough (frontend + backend + database)

### 1. Frontend — Cloudflare Pages (recommended)

`docs/` is a static SPA + landing page. **Cloudflare Pages** is one option:

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

Alternative static hosts:

| Host | Command or configuration |
|---|---|
| GitHub Pages | `.github/workflows/pages.yml` |
| Netlify | `netlify deploy --dir=docs --prod` |
| Vercel | `vercel --cwd docs --prod` |
| S3 + CloudFront | `aws s3 sync docs/ s3://bucket/`, plus CDN configuration |

### 2. Database — Neon Postgres (recommended)

1. Create a project at [neon.tech](https://neon.tech), or use another PostgreSQL service.
2. Configure its connection string as `DATABASE_URL` and require TLS for a
   remote database according to the provider's instructions.
3. Choose an endpoint that supports persistent `LISTEN` connections. Confirm
   that `/readyz` reports `checks.bus: "ok"` on every API instance before
   relying on cross-instance SSE updates.
4. Select storage, connection limits, backups, and recovery retention for the
   actual workload. Test restoration; a provider plan alone does not verify it.

The API auto-detects several PG env-var names — no code tweak needed:
`DATABASE_URL`, `POSTGRES_URL`, `POSTGRES_PRISMA_URL`, `NETLIFY_DATABASE_URL`,
`NEON_DATABASE_URL`, `PGURL`, `DATABASE_URL_POOLED`. Variable-name detection
does not establish that the endpoint supports the required connection behavior.

### 3. Backend — Fly.io (recommended)

Configure a Resend API key or an SMTP URL before the first deployment.
Production refuses to boot without a mailer; see the provider setup in
[Mailer + SSO](#4-mailer--sso-required-for-a-real-launch).

```bash
brew install flyctl && fly auth signup

cd server
fly launch --copy-config --no-deploy    # picks up fly.toml

# Set secrets (Fly encrypts these at rest; they never appear in the image)
fly secrets set \
  DATABASE_URL="postgres://…your neon url…" \
  JWT_SECRET="$(openssl rand -hex 48)" \
  RESEND_API_KEY="re_…your verified-domain API key…"
# For SMTP instead, replace RESEND_API_KEY above with:
#   SMTP_URL="smtps://user:pass@host:465"

fly deploy

# Custom subdomain
fly certs add api.agentvisorai.me
```

Choose machine memory, minimum running instances, regions, and idle behavior
using measurements on the target deployment. Cold starts, proxy buffering,
database latency, and memory limits were not represented by the local workload.

To flip the frontend to live mode, append `?live=1` to the console URL
(sticky via `localStorage`; `?live=0` reverts), or edit `docs/app/config.js`:

```js
window.MOCK_MODE = false;
window.API_BASE = "https://api.agentvisorai.me";   // origin only — paths already include /api/v1
```

Commit + push → Pages redeploys in ~30 s.

### 4. Mailer + SSO (required for a real launch)

Two things must be wired before customers can
sign up in production:

**Mailer** (password reset + welcome emails):

- **Resend** — sign
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

**Split origins** (SPA on Pages, API elsewhere): set `API_PUBLIC_URL`
to the API's own public origin (e.g. `https://api.agentvisorai.me`).
SAML SP URLs (entityId / ACS / metadata) and OAuth redirect URIs are
built from it; without it they fall back to `APP_BASE_URL` — the SPA
origin — and every IdP round-trip 404s (found the hard way; see the
`API_PUBLIC_URL` commit trail).

**Background sweepers**: `RETENTION_SWEEPER_INTERVAL_MS` (default 1h)
and `WEBHOOK_SWEEPER_INTERVAL_MS` (default 15s, floor 1s) control the
retention purge and webhook retry cadence. Multi-instance safe — the
webhook sweeper claims rows with `FOR UPDATE SKIP LOCKED`.

**Webhook SSRF guard**: endpoint targets resolving to loopback,
RFC1918, link-local, or cloud-metadata addresses are refused. For
local development against a receiver on your own machine set
`ALLOW_INTERNAL_WEBHOOK_TARGETS=true` (never in production).

**OIDC login** (Google + Microsoft + any generic issuer):

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
- **Generic OIDC** (Keycloak / Okta / Auth0 / Authentik / any
  spec-compliant issuer): set `OIDC_ISSUER_URL` to the issuer base (the
  server discovers `<issuer>/.well-known/openid-configuration`),
  `OIDC_CLIENT_ID` + `OIDC_CLIENT_SECRET` from the client you register
  there, and optionally `OIDC_DISPLAY_NAME` (login button reads
  "Continue with <name>", default "SSO"). Register redirect URI
  `https://api.agentvisorai.me/api/v1/auth/oauth/oidc/callback` and
  auth method `client_secret_post`. Same rules as the branded
  providers: PKCE S256, nonce, and `email_verified: true` required in
  the id_token — issuers that don't verify emails are refused.
  `OIDC_ISSUER_URL` must be https:// in production.

Set the secrets:

```bash
fly secrets set \
  GOOGLE_CLIENT_ID="…" GOOGLE_CLIENT_SECRET="…" \
  MICROSOFT_CLIENT_ID="…" MICROSOFT_CLIENT_SECRET="…" \
  OIDC_ISSUER_URL="https://sso.example.com/realms/acme" \
  OIDC_CLIENT_ID="…" OIDC_CLIENT_SECRET="…" OIDC_DISPLAY_NAME="Acme SSO"
```

The login page automatically shows/hides each button based on which
env vars are populated. No frontend flag to flip. Users signing in via
OIDC land in a new org named after their email domain on first login;
subsequent logins land in their existing org.

**SAML 2.0** is implemented. Workspace owners configure the IdP issuer,
sign-in URL, signing certificate, and allowed email domains in Settings > SSO.
Use the displayed SP entity ID, assertion-consumer URL, and metadata endpoint
when configuring the identity provider. Login starts through the application;
unsolicited IdP-initiated responses are refused. The assertion must pass
signature, issuer, audience, time-window, replay, and browser-binding checks.
Verify the complete flow with the selected identity provider before rollout.
The SAML logout route revokes the local application session; it does not
implement the IdP's SAML Single Logout protocol.

Apply migration `20260924140000_shared_saml_authn_requests` before routing
traffic to updated replicas. All updated replicas share request state through
PostgreSQL and must use the same cookie-signing secret and public API origin.
The initial upgrade cannot transfer pending logins from an older process's
memory. Drain older replicas and have users restart any interrupted sign-in;
a mixture of old and new replicas does not share pending ceremonies. Once all
replicas are updated, a login can complete on another replica or after a
process restart without sticky routing.

### Alternative backend: Render, Railway, Koyeb, Cloud Run

Each provider has a first-class config file already committed:

- `render.yaml` — Render blueprint (web + Postgres; review the selected plans).
- `railway.json` — Railway spec (attach a Postgres plugin in the dashboard).
- `koyeb.yaml` — Koyeb app spec.
- `server/fly.toml` — Fly.io machines config.

All four consume the same `server/Dockerfile`. Environment variables
follow the same names (`DATABASE_URL`, `JWT_SECRET`, `ALLOWED_ORIGINS`).
There is no platform-specific code inside the container.

**Proxy hop depth — verify per provider.** `TRUSTED_PROXY_HOP_COUNT`
must equal the number of proxy layers between the client and the app
or per-IP rate limits, IP allowlists, and audit IPs silently key on a
rotating edge IP instead of the client (drill-verified 2026-09-06:
with the wrong value, 14 rapid wrong-password logins produced zero
429s). Measured values: **Render = 3** (Cloudflare edge → Render
router → internal hop), Fly/Cloud Run/Heroku bare = 1, anything
behind your own CF + LB = 2. To verify a deployment: make a failed
login, then check the IP recorded in the audit log matches your real
public IP — and confirm an 11th rapid login attempt returns 429.

### Alternative backend: self-hosted VPS

`docker compose up -d` on any Linux box with Docker installed. The
`server/docker-compose.yml` runs Postgres + the API side-by-side. Add a
Caddy or nginx reverse proxy for HTTPS, or put Cloudflare Tunnel in
front. No public IP needed.

## Measured workload and capacity planning

The 2026-09-24 local operational drill used two production-mode API processes,
two tenants, and 100,000 seeded events. A 60-second mixed workload completed
3,000 authenticated requests at an offered 50 requests/second, with zero
unexpected errors or tenant leaks. The four endpoint groups had p95 latency
between 23.97 and 66.20 ms. The restored database contained 115,322 events and
1,006 sessions; every public table matched its pre-backup content fingerprint.
See [the validation record](VALIDATION.md#authenticated-workload-and-database-restoration)
for commands, query plans, resource limits, and measurements.

These results describe one workload on a local host, not maximum capacity,
an availability SLA, or a supported number of daily users. The cross-instance
SSE check used two subscribers; thousands of subscribers were not tested.
The application currently uses PostgreSQL LISTEN/NOTIFY and an in-process
event bus; it does not ship a selectable Redis bus backend.

Before choosing instance counts, test the actual request mix, event payload
sizes, dataset growth, concurrent subscribers, database connection limits,
network latency, and failure recovery in the target environment. Repeat the
workload for a sustained period and measure CPU, memory, latency, and cost.

## Portability & escape hatches

Every piece has a one-command way off it. This is deliberate — nothing
in the stack requires a proprietary service.

**Move off Fly.io** → Cloud Run / Render / Railway / Koyeb / Kubernetes / VPS

```bash
docker build -t "$REG/agentvisor-api" server/
docker push "$REG/agentvisor-api"

# On the new host, supply the production settings through a private env file.
docker run --read-only --tmpfs /tmp:uid=65532,gid=65532,mode=0700 \
  --cap-drop ALL --security-opt no-new-privileges \
  --env-file /secure/path/agentvisor-api.env -p 8080:8080 \
  "$REG/agentvisor-api"
```

The environment file must include `DATABASE_URL`, `JWT_SECRET`, the allowed
origin and public URLs, and a configured mailer (`SMTP_URL` or `RESEND_API_KEY`).
Keep the image's default entrypoint so migrations complete before traffic is
served. See [the runtime instructions](README.md#production-container) for
diagnostics that work without a shell inside the container.

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
  - Global: 300 req/min per client IP on each API instance. Buckets live in
    process memory, reset on restart, and are not shared between replicas.
    Configure a fleet-wide ingress limit if the deployment requires one.
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
  - The pinned Debian 13 Distroless runtime runs as UID 65532 and contains
    Node 22 with its shared libraries, without a shell or package manager.
  - A Node entrypoint forwards SIGTERM and SIGINT to the active child process
    group and preserves its exit status. Keep the image's default command.
  - Prisma migrations must succeed before the API starts. Migration duration
    depends on the database and pending schema changes.
  - The runtime supports a read-only root filesystem with writable `/tmp`.
    See [the container instructions](README.md#production-container) for the
    exact mounts, diagnostics, and executable validation commands.
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
