# Deploying AgentVisor AI

This backend is designed to run for free at seed-stage, autoscale to millions
of requests without a rewrite, and stay portable across cloud providers.

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
                    Bearer + X-AV-Deployment│  Neon / Supabase / …│  │
                                          └──────────────────────┘  │
                                                                     │
                                            All traffic:  ───────────┘
                                            HSTS 2y, CSP strict,
                                            SameSite cookies, argon2id,
                                            per-user rate limits.
```

Nothing above is provider-specific. Frontend is static files, backend is a
Docker image, database is standard Postgres — swap any of the three without
touching the other two.

## Free tier: full walkthrough (frontend + backend + database)

### 1. Frontend (already deployed)

`docs/app/` is a static SPA. It's live on GitHub Pages at
`https://agentvisorai.github.io/agentvisor-ai/app/` and mirrored at the
custom domain `https://agentvisorai.me/app/`.

To move it to a different free host:

| Host | Command | Free tier |
|---|---|---|
| Cloudflare Pages | `wrangler pages deploy docs` | Unlimited requests, unlimited bandwidth |
| Netlify | `netlify deploy --dir=docs --prod` | 100 GB/mo bandwidth |
| Vercel | `vercel --cwd docs --prod` | 100 GB/mo bandwidth |
| S3 + CloudFront | `aws s3 sync docs/ s3://bucket/` | 12 mo trial |

Same files, same URL structure, no code changes. Point DNS at the new host.

### 2. Database — Neon Postgres (free tier)

1. Sign up at [neon.tech](https://neon.tech) — no credit card required.
2. Create a project → grab the connection string. It looks like:
   `postgres://user:pass@ep-xxxxxx-pooler.us-east-2.aws.neon.tech/agentvisor?sslmode=require`
3. That's it. Free tier includes:
   - 0.5 GB storage (~250k sessions with signed receipts)
   - Auto-scale compute from 0.25 vCPU
   - 7-day point-in-time recovery
   - Auto-pause when idle → $0 while nobody's using the app

Alternatives (all free-tier, all `pg_dump`-compatible):
- **Supabase** — 500 MB, unlimited API calls
- **Fly Postgres** — 3 GB free with Fly VM
- **Railway** — $5/mo credit, includes Postgres
- **CockroachDB Serverless** — 5 GB, wire-compatible with Postgres

Migration between any of these is one `pg_dump | pg_restore`.

### 3. Backend — Fly.io (free tier)

```bash
# One-time setup
brew install flyctl
fly auth signup

cd server
fly launch --copy-config --no-deploy    # picks up fly.toml

# Set secrets (Fly encrypts these at rest; they never appear in the image)
fly secrets set \
  DATABASE_URL="postgres://…your neon url…" \
  JWT_SECRET="$(openssl rand -hex 48)"

# Deploy
fly deploy

# Custom subdomain
fly certs add api.agentvisorai.me
# then add the CNAME/A records Fly prints to your DNS
```

Free tier gives you:
- 3 shared-CPU machines (256 MB each)
- Auto-stop when idle → wakes in ~250 ms on next request
- 160 GB egress/month
- Automatic Let's Encrypt certificates
- Global anycast — one deploy, seven+ regions

To flip the frontend to live mode, edit `docs/app/index.html`:

```js
window.MOCK_MODE = false;
window.API_BASE = "https://api.agentvisorai.me/api/v1";
```

Commit + push → GitHub Pages redeploys in ~30 s.

### Alternative: Google Cloud Run (also free tier)

Cloud Run gives you 2M requests/month free and true scale-to-zero:

```bash
gcloud auth login
gcloud config set project YOUR-PROJECT

# Push the image
gcloud builds submit --tag gcr.io/YOUR-PROJECT/agentvisor-api server/

# Deploy
gcloud run deploy agentvisor-api \
  --image gcr.io/YOUR-PROJECT/agentvisor-api \
  --set-env-vars ALLOWED_ORIGINS=https://agentvisorai.me \
  --set-secrets DATABASE_URL=agentvisor-db:latest,JWT_SECRET=agentvisor-jwt:latest \
  --allow-unauthenticated \
  --region us-east1 \
  --min-instances 0 \
  --max-instances 100
```

Same container, different platform.

### Alternative: self-hosted VPS (any provider)

`docker-compose up -d` on any Linux box with Docker installed. The included
`docker-compose.yml` runs Postgres + the API side-by-side. Add a Caddy or
nginx reverse proxy for HTTPS.

## Scaling path (100 → 1,000,000 users)

The stack was chosen so the same code and container run at every scale. No
rewrite when demand grows.

| Traffic | Fly.io config | Neon plan | Monthly cost |
|---|---|---|---|
| Pitch demo → 100 users | 1 × shared-cpu-1x, 256 MB, auto-stop | Free | **$0** |
| 1,000 daily users | 1 × shared-cpu-1x, min_machines=1 | Free | **$0** |
| 10,000 daily users | `fly autoscale set min=1 max=5` | Launch ($19) | **~$29** |
| 100,000 daily users | Multi-region (`fly scale count 3`), shared-cpu-2x | Scale ($69) | **~$150** |
| 1,000,000 daily users | Autoscale max=20 across 5 regions, shared-cpu-4x | Business (~$500) | **~$1,200** |

Above 1M/day, add:
- Redis (Upstash free 10k cmd/day → $10/mo → $50/mo tiers) for pub/sub if
  SSE fan-out exceeds Postgres LISTEN comfort zone (roughly 5k concurrent).
- Read replicas via Neon — same connection string, `pgbouncer` transparent
  routing, no code change.
- Cloudflare in front of `api.agentvisorai.me` — caches nothing sensitive,
  absorbs DDoS.

## Portability & escape hatches

Every piece has a one-command way off it. This is deliberate.

**Move off Fly.io** → Cloud Run / Render / Railway / Kubernetes / VPS

```bash
docker build -t agentvisor-api server/
docker push registry.example.com/agentvisor-api

# On the new host
docker run -p 8080:8080 \
  -e DATABASE_URL=postgres://… \
  -e JWT_SECRET=… \
  -e ALLOWED_ORIGINS=https://agentvisorai.me \
  registry.example.com/agentvisor-api
```

**Move off Neon** → any other Postgres

```bash
pg_dump "$OLD_DATABASE_URL" | psql "$NEW_DATABASE_URL"
fly secrets set DATABASE_URL="$NEW_DATABASE_URL"
# The app picks up the new URL on next restart. No migration needed.
```

**Move off GitHub Pages** → any static host

```bash
rsync -av docs/ new-host:/var/www/
# Update DNS. Done.
```

There is no proprietary schema, no closed-source SDK, no lock-in tier.

## Security posture

- **TLS everywhere.** HSTS is set for 2 years with `preload`. Add
  `agentvisorai.me` to [hstspreload.org](https://hstspreload.org) once you
  ship TLS to prod.
- **Cookies.** `httpOnly`, `SameSite=Lax`, `Secure` in production. JWT is
  signed HS256 with a 48-byte secret. Rotate `JWT_SECRET` with
  `fly secrets set` — old tokens expire on the next boot.
- **CSP.** `default-src 'none'` on every API response. Frame ancestors
  `'none'` blocks clickjacking. The console is on a separate origin so
  nothing loads back into the API.
- **Password hashing.** Argon2id via the `argon2` native module. Default
  cost is 3 iterations × 64 MB memory. Bump memory in production by editing
  `server/src/lib/auth.ts`.
- **Rate limits.** 300 req/min per authenticated user (keyed off `sub`
  claim) — a shared IP doesn't rate-limit unrelated tenants.
- **Tenant isolation.** Every read query goes through `session.orgId`.
  There is no user-supplied `orgId` parameter on any endpoint. Tenant
  boundaries are enforced by the database via foreign keys and by the
  application via the session claim.
- **Container hardening.**
  - Runs as `node` (uid 1000), never root.
  - `dumb-init` as PID 1 → fast, correct SIGTERM handling.
  - `docker-compose.yml` mounts the filesystem read-only with `tmpfs` for `/tmp`.
- **Signed receipts.** Every session ends with an Ed25519-signed receipt
  posted by the daemon. The `deployment.publicKeyHex` is stored so the
  console can verify signatures client-side without trusting the API.
- **Secrets.** `.env` is git-ignored. Deploy secrets live in the platform's
  secret store (`fly secrets`, `gcloud secrets`, Kubernetes `Secret`), not
  in the image.
- **Audit trail.** The `events` table is append-only in practice — no code
  path updates or deletes an event. Cascading deletes at the tenant boundary
  only fire when the org is deleted by its owner.

Additional hardening for production (not required for the demo):
- Turn on Neon IP allowlist so only the Fly outbound range can connect.
- Enable Fly's WAF (`fly deploy --wg`).
- Enable Postgres `row-level security` on `sessions`/`events`/`receipts`
  as a defense-in-depth layer (the app already scopes reads by `orgId`,
  but RLS blocks any query that forgets to).
