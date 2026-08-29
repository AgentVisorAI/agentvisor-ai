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

Point the console at it by editing `docs/app/index.html`:

```js
window.MOCK_MODE = false;
window.API_BASE = "http://localhost:8080/api/v1";
```

## API surface

All routes are prefixed `/api/v1`.

### Auth (cookie session)

| Method | Path | Notes |
|---|---|---|
| `POST` | `/auth/signup` | `{ email, password, orgName, displayName? }` — creates user + owner org, sets `av_session` cookie |
| `POST` | `/auth/login` | `{ email, password }` |
| `POST` | `/auth/logout` | Clears the cookie |
| `GET`  | `/auth/me` | Returns `{ user, org }` for the active session |

### Deployments (authed user)

| Method | Path | Notes |
|---|---|---|
| `GET`  | `/deployments` | List deployments in the caller's org |
| `POST` | `/deployments` | `{ name, environment? }` — returns `{ deployment, ingestToken }`; token is shown **once** |
| `POST` | `/deployments/:id/rotate-token` | Rotate |
| `DELETE` | `/deployments/:id` | Delete |

### Ingest (daemon → API)

Auth: `Authorization: Bearer <ingestToken>` + `X-AV-Deployment: <deployment_id>`.

| Method | Path | Notes |
|---|---|---|
| `POST` | `/ingest/pubkey` | `{ publicKeyHex }` — one-shot on first startup |
| `POST` | `/ingest/sessions` | Upsert a session (idempotent on `externalId`) |
| `POST` | `/ingest/events` | Array of events, deduped on `(session, seq)` |
| `POST` | `/ingest/receipts` | Signed receipt at seal |

### Read (authed user)

| Method | Path | Notes |
|---|---|---|
| `GET`  | `/overview` | Fleet stats + recent sessions |
| `GET`  | `/sessions/:id` | Session + events + receipt |
| `GET`  | `/receipts/:sessionId` | Raw receipt + deployment public key for offline verify |

## Security posture

Full production checklist is in [DEPLOY.md](./DEPLOY.md#security-posture).
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
