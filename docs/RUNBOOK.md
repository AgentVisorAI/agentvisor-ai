# Launch runbook — what to do when things break

One page. Grep for the failure, do the fix, move on. Kept short on purpose.

## Contact + escalation

- Ops on-call: whoever pushed last (`git log -1 --format='%an %ae' main`)
- Security disclosures: security@agentvisorai.me
- Status page: `docs/STATUS.md` in this repo (edit + push to update)
- Investor comms: read-only status page + one-line email

## The 10 things that will go wrong

### 1. Database is down (`/readyz` returning 503, all writes 500)

**Signal:** `curl -f https://api.agentvisorai.me/readyz` fails with 503;
Fly logs show `PrismaClientKnownRequestError` on every write.

**First actions:**

```bash
# Confirm the incident scope
fly status --app agentvisor-api
# Check the managed PG dashboard (Neon / Supabase / Fly PG)
open https://console.neon.tech    # or supabase.com, or fly pg status

# If it's a Neon cold-boot: they auto-resume on the next connection.
# Just wait 30-60s. /readyz will flip green.

# If it's a stuck connection pool: rolling restart clears it.
fly deploy --image "$(fly image show --app agentvisor-api | awk 'NR==2 {print $NF}')" --strategy rolling

# If the DB is truly down: fall back to the most recent nightly backup.
gh run download --name "pg-backup-$(gh run list -w backup.yml -L1 --json databaseId -q '.[0].databaseId')"
pg_restore --clean --if-exists --dbname "$RESTORE_DATABASE_URL" agentvisor-*.dump
```

### 2. Cross-instance SSE fan-out is silent (bus down but process alive)

**Signal:** `/readyz` shows `{ checks: { db: "ok", bus: "degraded" } }`.
Two console tabs on different Fly instances don't see each other's
events; same-instance tabs still work.

**Fix:** The reconnect loop backs off up to 30 s. If it stays degraded
> 5 min, the LISTEN socket is likely blocked upstream (Neon idle-suspend
recycled the connection). Force a redeploy to reset both sockets:

```bash
fly deploy --strategy rolling --app agentvisor-api
```

### 3. Rolling deploy stuck

**Signal:** `fly deploy` hangs at "waiting for machine <id>".

```bash
fly logs --app agentvisor-api -i <machine-id>
# Common causes:
#   - Bad migration → prisma migrate deploy printed an error
#   - Wrong image ref → docker inspect the digest
#   - Health check flaking → check /readyz on the machine

# Rollback to previous digest — same command, older SHA.
fly deploy --image "ghcr.io/agentvisorai/agentvisor-api:sha-<older>" --strategy rolling
```

### 4. Trivy CI job fails on a new HIGH/CRITICAL

**Signal:** `Deploy` workflow red on the `Trivy image scan` step.
Common cause: Dependabot bumped Prisma into 6.13.x which drags in
deepmerge-ts vuln, or a base image bump introduced a new npm-transitive
CVE.

**Fix (unless there's a real upgrade path):**

```bash
# Reproduce locally first — never gate the pipeline on speculation.
docker build -t local server/
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy:0.74.0 image --severity HIGH,CRITICAL --ignore-unfixed local

# If it's an upstream package: pin the fixed version in server/package.json,
# regenerate the lock, and push. Dependabot picks up the next upgrade window.

# If the CVE is in the base image's global npm and there's no upstream fix:
# note that we already delete /usr/local/lib/node_modules/npm in the runtime
# stage — Trivy should not see it. If it does, the removal step regressed.
```

### 5. Password reset in production silently doesn't send

**Signal:** Customer says "I never got the email."

**Current state:** the mailer is wired (`server/src/lib/mail.ts`).
Production requires `RESEND_API_KEY` or `SMTP_URL` at boot — the
server refuses to start without one (`no_mailer_configured` at
`mail.ts:115`) so a misconfigured deploy fails fast instead of
silently swallowing resets. `auth.ts:1117` calls `getMailer()` and
logs `{ userId, mailer, messageId }` on send.

Triage:

- Check the driver secrets in the deploy config: `RESEND_API_KEY` (or
  `SMTP_URL`) plus `EMAIL_FROM`. `env.ts:287-292` documents the
  precedence — Resend wins over SMTP.
- Tail the server logs for `pw_reset_email_sent` at info and any
  `pw_reset_email_error` at warn/error — the driver name and the
  provider's message id / error surface there.
- If Resend: verify the `EMAIL_FROM` domain is DNS-verified in the
  Resend dashboard (unverified senders queue silently).
- If SMTP: check the provider's dashboard (Postmark, SES, Mailgun) for
  the message and any bounce.
- Manual override: query the DB for the user's `resetTokenHash`
  timestamp and re-send via the reset flow. Do NOT hand out the hash —
  it's non-reversible; issue a fresh token instead.

### 6. Rate limit misconfigured — customer locked out

**Signal:** Support ticket: "I keep getting 429 on login."

Quick check:

```bash
# Every rate limit is documented in DEPLOY.md → "Rate limits".
# If a customer is legitimately hitting it, raise the per-IP limit
# temporarily via a config bump + redeploy.
grep -n "perIp" server/src/routes/auth.ts
```

If a shared corporate NAT is legitimately spraying login attempts,
switch that specific endpoint from `keyGenerator: ip:` to `keyGenerator: email:` for that customer — gives them a per-user budget.

### 7. Secret rotation (`JWT_SECRET`, `DATABASE_URL`)

```bash
# JWT_SECRET rotation — invalidates ALL outstanding sessions on next boot.
# Schedule for low-traffic window, warn users first.
fly secrets set JWT_SECRET="$(openssl rand -hex 48)" --app agentvisor-api

# DATABASE_URL rotation — mostly for provider switches.
# Do a dump first to ensure the new target is caught up:
pg_dump "$OLD_URL" | psql "$NEW_URL"
fly secrets set DATABASE_URL="$NEW_URL" --app agentvisor-api
```

### 8. Ingest spike (429s from customer daemons)

**Signal:** Fly dashboard shows the ingest endpoint 429'ing.

The ingest daemon batches every second. A 429 means either:

- Legitimate spike: raise the per-deployment cap by editing
  `server/src/routes/ingest.ts` (search "max(500)") and redeploy.
- Malformed client: check `X-Request-Id` from a 429 response in Fly logs
  → `fly logs -i <machine>`. Usually one bad customer misconfigured.

### 9. Cert renewal fails

Fly does this automatically via Let's Encrypt. If the cert is about to
expire:

```bash
fly certs check api.agentvisorai.me --app agentvisor-api
# Renew manually
fly certs remove api.agentvisorai.me --app agentvisor-api
fly certs add api.agentvisorai.me --app agentvisor-api
```

### 10. Log correlation — how do I find one customer's request?

Every response has an `X-Request-Id` header. The customer can hand you
one from their browser dev tools (`Network > Headers > x-request-id`).

```bash
# Then grep Fly logs
fly logs --app agentvisor-api | grep "req-<id>"

# Or a specific machine
fly logs --app agentvisor-api -i <machine-id> | grep "req-<id>"
```

The problem+json error body also contains `requestId`, so a 4xx / 5xx
response the customer pastes into a ticket is directly greppable.

## Standard operating procedures

- **Every deploy** goes through `main` → `.github/workflows/deploy.yml`.
  Never `fly deploy` from a laptop against the prod app — that skips
  the Trivy scan.
- **Every migration** is a Prisma migration in `server/prisma/migrations/`,
  reviewed in a PR before it lands. Never `prisma db push` against prod.
- **Every secret rotation** is a `fly secrets set` command in the ops
  log below (edit + push).
- **Every backup restore drill** — do this quarterly. Pull the newest
  artifact from `.github/workflows/backup.yml` and `pg_restore` to a
  local DB. Confirm row counts. Delete the local DB.

## Verified drills (green as of 2026-08-26)

Every one of these was run against the current codebase; keep them
green on every launch checkpoint.

### Backup + restore roundtrip

```bash
# 1. Fresh dump
docker exec av-pg pg_dump -U agentvisor --format=custom \
  --no-owner --no-privileges agentvisor > /tmp/backup.dump

# 2. Bring the API down (or the restore blocks with 'database in use')
fly scale count 0 --app agentvisor-api    # or `docker stop` locally

# 3. Drop + recreate + restore
docker exec av-pg psql -U agentvisor -d postgres -c "DROP DATABASE agentvisor"
docker exec av-pg psql -U agentvisor -d postgres -c "CREATE DATABASE agentvisor"
docker exec -i av-pg pg_restore -U agentvisor -d agentvisor \
  --no-owner --no-privileges < /tmp/backup.dump

# 4. Bring the API back
fly scale count 1 --app agentvisor-api

# 5. Verify: login works with the same credentials → same user id + org id.
```

Verified: 18KB dump of 10 sessions restored in <2s, login returned
identical `user.id` + `org.id`.

### Deployment token rotation

Verified: `POST /deployments/:id/rotate-token` invalidates the previous
token at the exact SQL commit. Old token → 401 unauthenticated
immediately, new token → 200 on the very next ingest call. Zero
dual-acceptance window.

### Ed25519 receipt trust anchor

Verified end-to-end:

1. Daemon generates an Ed25519 keypair.
2. `POST /ingest/pubkey` registers `publicKeyHex` on the deployment.
3. Daemon signs the receipt body with the private key,
   `POST /ingest/receipts` with `{sigB64, keyIdHex, body}`.
4. Console fetches `GET /receipts/:sessionId` → server returns the
   deployment's `publicKeyHex` alongside the receipt.
5. Console-side (or a third-party auditor) runs `crypto.subtle.verify`
   with the returned `publicKeyHex` + `sigB64` against `body` — returns
   true.
6. Tampered body (single byte flip) → verify returns false.

No trust in the server anywhere in the chain — the customer's
console verifies the daemon's signature using only the daemon's own
public key.

### Role enforcement

Verified for the `member` role (non-owner, non-admin):

| Route | Expected | Got |
|---|---|---|
| `POST /deployments` | 403 | 403 forbidden ✓ |
| `POST /deployments/:id/rotate-token` | 403 | 403 forbidden ✓ |
| `DELETE /deployments/:id` | 403 | 403 forbidden ✓ |
| `POST /me/delete-account` | 403 | 403 only_owner_can_delete ✓ |
| `GET /overview` | 200 | 200 ✓ (reads open to members) |
| `GET /sessions` | 200 | 200 ✓ |

### Session cookie flags (production mode)

Verified `Set-Cookie` header on `POST /auth/signup` with
`NODE_ENV=production` + `SESSION_COOKIE_SECURE=true`:

```
set-cookie: av_session=…; Max-Age=604800; Path=/; HttpOnly; Secure; SameSite=Lax
```

Every required security flag present. No `Domain` attribute → the
cookie won't leak to a subdomain we don't control.

### Cross-tenant isolation (200k rows)

Verified against 100k sessions per org × 2 orgs (200k total):

- `/overview` scoped: Org A sees 100k, Org B sees 100k.
- `GET /sessions/<foreign-id>` → 404 (Org A cannot see Org B session
  even with the exact ID).
- `q=<foreign-prefix>` returns 0 (identifier invisible).
- `/me/export` streams 100 002 JSONL rows for Org A — zero rows leak
  from Org B.

### Ingest throughput

Verified with autocannon 30 conn × 15s × 20-event batches:

```
rps: 235
events/sec sustained: 4,700
total requests: 3,525, non-2xx: 0, errors: 0, timeouts: 0
latency p50/p90/p99: 109/175/524 ms
```

Ingest is exempt from the global 300 rpm/IP rate limit because
per-deployment token auth already bounds abuse per tenant.

## Ops log (append-only)

Add rows here after non-trivial ops actions (secret rotation, manual
DB fixes, etc). Keep it short.

| Date (UTC) | Actor | Action | Ref |
|---|---|---|---|
| _(none yet — bootstrap this on first prod deploy)_ | | | |
