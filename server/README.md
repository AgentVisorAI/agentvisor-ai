# AgentVisor AI hosted console — API server

Multi-tenant control plane for the AgentVisor console. Users sign up here,
register `agentvisord` deployments, and view sessions/receipts posted by
those daemons. Live LLM and tool requests run through the customer's daemon.
Console sync uploads session metadata, captured event messages and observations,
and Ed25519 signed receipts. Event content can include prompts, completions, and
tool payloads after the daemon's configured redaction; this API stores those
uploaded fields and restricts their visibility by role.

**For deployment (Fly.io, Cloud Run, Neon, self-host) see [DEPLOY.md](./DEPLOY.md).**

## Architecture

```
┌────────────────┐        ┌───────────────────────┐        ┌──────────────┐
│  agentvisord   │──HTTPS─▶  api.agentvisorai.me  │──HTTPS─▶  console UI  │
│ (self-hosted   │  ingest│  (this server)        │  read  │  (Pages)     │
│  by customer)  │◀───────│  Postgres (any host)  │◀───────│              │
└────────────────┘        └───────────────────────┘        └──────────────┘
       │                          ▲                                 │
       └── LLM + tool traffic stays local; captured evidence is uploaded
                                  └── auth (JWT cookie) ────────────┘
```

## Requirements

- Node.js ≥ 22
- Postgres 15+ (any provider — Neon / Supabase / Fly Postgres / self-host)
- Docker (for local reproducibility via `docker-compose`)

## Local dev

```sh
cd server
cp .env.example .env               # edit JWT_SECRET (openssl rand -hex 48)
docker compose up -d db            # local Postgres on :5433
npm install
npm run prisma:migrate:dev
npm run dev                        # http://localhost:8080
```

Point the console at it by editing `docs/app/config.js`:

```js
window.MOCK_MODE = false;
window.API_BASE = "http://localhost:8080"; // bare origin — paths already carry /api/v1
```

Two footguns (both caught by CI's Browser E2E job, which makes these
exact edits before driving the SPA in headless Chromium):

- `API_BASE` is the **origin only**. The datasource calls
  `apiFetch("/api/v1/…")`, so a base that already ends in `/api/v1`
  doubles the prefix and 404s everything.
- `docs/app/index.html` ships a strict meta CSP whose `connect-src`
  allows only `'self'` and `https://api.agentvisorai.me`. Add your API
  origin there or the browser silently blocks every fetch.
- Serve the SPA **under `/app/` with `logo.png` one level up** (the
  production topology). The console references `../logo.png` for the
  brand mark and favicon; a flat copy of `docs/app` alone 404s both.

## Production container

Build the image with `docker build -t agentvisor-api server/` from the repository
root. The pinned runtime uses Node 22 on Debian 13 Distroless, runs as UID 65532,
and contains no shell or package manager. The build generates the Prisma client
on Debian 13 and retains the Prisma CLI and migrations as production dependencies.

The image starts `container-entrypoint.mjs` directly with Node. It runs the
packaged `prisma migrate deploy` first and starts the API only after migrations
succeed. A migration failure preserves its nonzero exit status. SIGTERM and
SIGINT reach the active child and its process group, including Prisma's schema
engine. Deployment platforms should use the image's entrypoint and command.

Supply the production settings described in [DEPLOY.md](./DEPLOY.md), including
the database, JWT secret, allowed origin, public URLs, and mailer. The runtime
supports a read-only root filesystem with a writable temporary directory:

```sh
docker run --read-only --tmpfs /tmp:uid=65532,gid=65532,mode=0700 \
  --cap-drop ALL --security-opt no-new-privileges \
  --env-file /secure/path/agentvisor-api.env -p 8080:8080 agentvisor-api
```

The container healthcheck requests `/readyz`, which checks database availability.
Use `docker logs` for diagnostics. For a one-off Prisma command, run the packaged
CLI with Node, for example `docker exec <container> node
/app/node_modules/prisma/build/index.js migrate status`. Do not rely on `sh`,
`npm`, or `npx` inside the runtime.

Run `node --test server/ci/container-entrypoint.test.mjs` to verify process exit
and signal handling. `python3 scripts/container-smoke.py --console-image
agentvisor-api` tests the actual image with its own temporary PostgreSQL container,
including migration refusal, native engine loading, API calls, database recovery,
and clean shutdown. Add `--agentvisord /path/to/agentvisord --avctl /path/to/avctl`
to include the daemon crash and console synchronization drill.

## API surface

All routes are prefixed `/api/v1`.

### Auth (cookie session)

| Method | Path | Notes |
|---|---|---|
| `POST` | `/auth/signup` | `{ email, password, orgName, displayName? }` — creates user + owner org, sets `av_session` cookie |
| `POST` | `/auth/login` | `{ email, password }`; answers `{ mfaRequired: true }` uniformly for passkey-enrolled accounts **and** bad credentials (no oracle) |
| `POST` | `/auth/logout` | Clears the cookie and fences prior JWTs |
| `POST` | `/auth/logout-all` | `{ password }` step-up; fences every session, re-mints the caller's cookie — "sign out other devices" |
| `GET`  | `/auth/me` | `{ user (incl. pendingEmail), org, memberships[] }` for the active session |
| `POST` | `/auth/switch-org` | `{ orgId }` — re-mints the cookie bound to another membership |
| `POST` | `/auth/change-password` | `{ currentPassword, newPassword }` — fences other sessions, keeps API keys |
| `POST` | `/auth/change-email` | `{ newEmail, password }` — uniform 202; confirm link goes to the new mailbox |
| `POST` | `/auth/change-email/confirm` | `{ email, token }` — anonymous; rotates the address, fences all sessions |
| `POST` | `/auth/change-email/cancel` | Clears the pending change |
| `PATCH`| `/auth/me/profile` | `{ displayName }` — empty clears |
| `POST` | `/auth/me/export` | Password step-up; streams the whole org as NDJSON (owner only) |
| `POST` | `/auth/me/delete-account` | Password + type-phrase; deletes org (+ account unless other memberships remain — response carries `accountDeleted`) |
| `POST` | `/auth/reset-request` / `/auth/reset-confirm` | Email reset flow; confirm revokes sessions **and** API keys (break-glass) |

### MFA / SSO

| Method | Path | Notes |
|---|---|---|
| `POST` | `/auth/webauthn/register/challenge` + `/verify` | Passkey enrollment (verify requires the account password) |
| `POST` | `/auth/webauthn/authenticate/challenge` + `/verify` | Passkey MFA step at login; requires the single-use `av_mfa_gate` cookie `/auth/login` sets on its `mfaRequired` response (passkey possession alone cannot sign in) |
| `GET`/`PATCH`/`DELETE` | `/auth/webauthn/credentials[/:id]` | List / rename / revoke (revoke = break-glass: fences sessions, revokes keys) |
| `GET`  | `/auth/oauth/providers`, `/auth/oauth/:provider/start` + `/callback` | Google / Microsoft / generic-OIDC sign-in when configured |
| — | `/auth/saml/*` | SAML 2.0 SP: config CRUD, `/:configId/metadata.xml`, `/login`, `/acs`, `/slo`, `/keypair`, `/discover` |

### Org & members

| Method | Path | Notes |
|---|---|---|
| `PATCH`| `/org` | Rename the workspace (owner; slug/id stable) |
| `GET`/`PATCH` | `/org/retention` (+ `POST /org/retention/sweep-now`) | Retention windows + manual sweep |
| `GET`/`PATCH` | `/org/ip-allowlist` | CIDR allowlist (refuses to lock the caller out) |
| `GET`  | `/members` | Members incl. `mfaEnrolled` flag |
| `PATCH`/`DELETE` | `/members/:userId` | Role change / remove (rank guards, last-owner guard; self-DELETE = leave) |
| `POST` | `/members/:userId/reset-mfa` | Admin break-glass for a lost passkey (own-password step-up) |
| `POST`/`GET`/`DELETE` | `/members/invites[/:id]` | Invite CRUD; re-POST the same email = resend (fresh token, old link dies) |
| `POST` | `/members/invites/accept` | Anonymous accept (`{ token, email, password? }`) |

### Deployments, keys, policies, webhooks

| Method | Path | Notes |
|---|---|---|
| `GET`/`POST` | `/deployments` | Token returned **once** on create |
| `PATCH`/`DELETE` | `/deployments/:id` (+ `POST /:id/rotate-token`) | Rename/env edit (labels only), delete (409 if sealed receipts unless forced), rotate |
| `GET`/`POST`/`PATCH`/`DELETE` | `/keys[/:id]` | API keys: list / mint (shown once) / rename / revoke — rank-guarded |
| `GET`/`POST`/`PATCH`/`DELETE` | `/policies[/:id]` | Policy CRUD (name/description/body/enabled) |
| `GET`/`POST`/`PATCH`/`DELETE` | `/webhooks[/:id]` (+ `POST /:id/test`, `GET /:id/deliveries`) | Endpoints (SSRF-guarded), HMAC-signed deliveries with retries, cursor-paginated delivery log |

### Ingest (daemon → API)

Auth: `Authorization: Bearer <ingest_token>` + `X-AV-Deployment: <deployment_id>`.

| Method | Path | Notes |
|---|---|---|
| `POST` | `/ingest/pubkey` | `{ publicKeyHex }` — anchored on first set; rotation refused |
| `POST` | `/ingest/sessions` | Upsert a session (idempotent on `externalId`); `quarantined_crash_evidence` permanently marks incomplete recovered evidence |
| `POST` | `/ingest/events` | Array of events, deduped on `(session, seq)` |
| `POST` | `/ingest/receipts` | Signed receipt at seal (key-id must match the anchor) |

### Read (authed user)

| Method | Path | Notes |
|---|---|---|
| `GET`  | `/overview` | Session totals and time-series for the selected UTC bucket window, plus fleet counts and recent sessions |
| `GET`  | `/sessions` (+ `/sessions/:id`) | Cursor-paginated list; detail with cursor-paginated events + receipt; `eventCount` remains the total across all pages |
| `GET`  | `/receipts/:sessionId` | Raw receipt + deployment public key for offline verify |
| `GET`  | `/audit` (+ `/audit.csv`) | Cursor-paginated audit trail; CSV streams up to 10k rows |
| `GET`  | `/stream` | SSE: session/event/receipt updates, multi-instance via PG LISTEN/NOTIFY |

## Testing

Four layers, all runnable locally and (except the browser drills'
prod target) wired into CI:

- **`ci/e2e.mjs`** — API contract suite. Boot the server,
  then `API_BASE=http://127.0.0.1:<port> node ci/e2e.mjs`. Runs in the
  Console + API workflow.
- **`scripts/run-drill-battery.sh`** — the 15 DB-backed attack drills
  (apikey ×2, invite ×2, ip-allowlist, retention, saml ×2, webauthn ×2,
  webhook ×3, oidc, crash-evidence quarantine). Boots a fresh server per drill
  on 204xx and 207xx ports. Needs a Postgres the drills can `docker exec psql` into:
  `PG_CONTAINER=<container> PG_USER=av PG_DB=avdb bash scripts/run-drill-battery.sh [drill…]`.
  Runs in CI on every `server/**` change (api-drills workflow).
  Set `SPA_ORIGIN` when running `scripts/quarantine-drill.mjs` directly
  to also check the live browser's incomplete-evidence warning and disabled
  receipt actions. Recovered events remain appendable and idempotent;
  quarantined sessions cannot return to live status or receive a receipt.
- **Browser drills** (`scripts/a11y-audit.mjs`, `interactive-drill.mjs`,
  `mobile-smoke.mjs`, `engine-matrix.mjs`, …) — Playwright suites the
  console-smoke workflow runs against the deployed console after every
  Pages deploy. Point `SITE=` at any served copy for local runs.
- **Daemon drills** (repo root `scripts/`) — `demo-agent.mjs` (offline
  storyline, exit 0 = 10 beats), `crash-drill.mjs` (SIGKILL durability
  + quarantine semantics; sync leg needs `CONSOLE_URL`/`DEPLOYMENT_ID`/
  `TOKEN_FILE`). Probe gotcha: `/mcp` tool executions are
  idempotency-keyed by (session, JSON-RPC id, tool, args) — reuse an id
  and you get the cached outcome, not a re-execution; use unique ids
  unless you are testing replay.
  With current binaries already built, run the complete console contract with
  `API_BASE=http://127.0.0.1:8985 AGENTVISORD=/absolute/path/agentvisord AVCTL=/absolute/path/avctl node scripts/daemon-console-drill.mjs`.
  This runner creates its own test workspace and credentials, runs the real
  SIGKILL/restart/sync drill, and deletes only that workspace afterward.
  Missing binaries fail the run instead of skipping synchronization.

## Security posture

Full production checklist is in [DEPLOY.md](./DEPLOY.md#security-posture-2026-baseline).
In short:

- Argon2id password hashing.
- HttpOnly, SameSite=Lax, Secure session cookies. HS256 JWT.
- Uniform login response time regardless of user existence.
- Every read query is org-scoped through the session claim — no route
  accepts a user-supplied org id.
- Ingest tokens are argon2-hashed at rest; plaintext returned only once.
- Global rate limit: 300 rpm per client IP on each API instance (not per user — the global
  bucket keys on `req.ip` per R93 F1 / R100 F1 in `src/index.ts`;
  a cookie/sub-derived key would let an attacker plant a fresh random
  cookie per request and bypass the cap). Buckets are held in process memory:
  restarting an instance resets them, and requests spread across multiple
  instances receive a separate allowance on each. Enforce a fleet-wide limit
  at the ingress if the deployment requires one. Auth-tree endpoints
  (`/login`, `/signup`, `/reset-*`, `/webauthn/*`) use tighter per-IP route
  buckets that replace the global bucket. Cookie session listing and detail
  reads have limits of 30 and 60 requests/minute respectively; authenticated
  API-key clients are exempt from those two route limits. Ingest is exempt
  from the global limit.
- CORS locked to `ALLOWED_ORIGINS`.
- `helmet` sets HSTS 2y (preload), strict CSP, X-Frame-Options: deny.
- The container runs as UID 65532. Its Node entrypoint forwards shutdown signals
  to the API or migration process group and preserves the child's exit status.
- Request body cap: 4 MiB.

## Evidence storage

Uploaded event content can contain prompts, completions, and tool arguments
after the daemon's configured redaction. The console stores that captured
content along with session metadata and signed receipts, and restricts access
by organization and role. The customer's daemon runs on their infrastructure
and controls which evidence it uploads. Configured provider API keys remain
with the daemon and are not part of console synchronization.
