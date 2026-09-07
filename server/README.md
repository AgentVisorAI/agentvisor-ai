# AgentVisor AI hosted console — API server

Multi-tenant control plane for the AgentVisor console. Users sign up here,
register `agentvisord` deployments, and view sessions/receipts posted by
those daemons. Provider keys, prompts, and completions do **not** flow
through this server; only session metadata, event summaries, and Ed25519
signed receipts do.

**For deployment (Fly.io, Cloud Run, Neon, self-host) see [DEPLOY.md](./DEPLOY.md).**

## Architecture

```
┌────────────────┐        ┌───────────────────────┐        ┌──────────────┐
│  agentvisord   │──HTTPS─▶  api.agentvisorai.me  │──HTTPS─▶  console UI  │
│ (self-hosted   │  ingest│  (this server)        │  read  │  (Pages)     │
│  by customer)  │◀───────│  Postgres (any host)  │◀───────│              │
└────────────────┘        └───────────────────────┘        └──────────────┘
       │                          ▲                                 │
       └── LLM + tool traffic ─────┴── auth (JWT cookie) ────────────┘
           (stays on customer infra — never enters here)
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
| `POST` | `/ingest/sessions` | Upsert a session (idempotent on `externalId`) |
| `POST` | `/ingest/events` | Array of events, deduped on `(session, seq)` |
| `POST` | `/ingest/receipts` | Signed receipt at seal (key-id must match the anchor) |

### Read (authed user)

| Method | Path | Notes |
|---|---|---|
| `GET`  | `/overview` | Fleet stats + time-series + recent sessions |
| `GET`  | `/sessions` (+ `/sessions/:id`) | Cursor-paginated list; detail with cursor-paginated events + receipt |
| `GET`  | `/receipts/:sessionId` | Raw receipt + deployment public key for offline verify |
| `GET`  | `/audit` (+ `/audit.csv`) | Cursor-paginated audit trail; CSV streams up to 10k rows |
| `GET`  | `/stream` | SSE: session/event/receipt updates, multi-instance via PG LISTEN/NOTIFY |

## Security posture

Full production checklist is in [DEPLOY.md](./DEPLOY.md#security-posture-2026-baseline).
In short:

- Argon2id password hashing.
- HttpOnly, SameSite=Lax, Secure session cookies. HS256 JWT.
- Uniform login response time regardless of user existence.
- Every read query is org-scoped through the session claim — no route
  accepts a user-supplied org id.
- Ingest tokens are argon2-hashed at rest; plaintext returned only once.
- Global rate limit: 300 rpm per client IP (not per user — the global
  bucket keys on `req.ip` per R93 F1 / R100 F1 in `src/index.ts`;
  a cookie/sub-derived key would let an attacker plant a fresh random
  cookie per request and bypass the cap). Auth-tree endpoints
  (`/login`, `/signup`, `/reset-*`, `/webauthn/*`) apply tighter
  per-IP buckets on top.
- CORS locked to `ALLOWED_ORIGINS`.
- `helmet` sets HSTS 2y (preload), strict CSP, X-Frame-Options: deny.
- Container runs as non-root under `dumb-init` PID 1.
- Request body cap: 4 MiB.

## What is **not** stored

- Provider API keys (they stay on the customer's box).
- Prompts, completions, or tool arguments (only summarized event bodies).
- Anything the daemon doesn't post to us. The customer's daemon runs on
  their own infra and decides what to send.
