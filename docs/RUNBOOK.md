# Launch runbook — what to do when things break

One page. Grep for the failure, do the fix, move on. Kept short on purpose.

> **Scope note:** sections referencing `api.agentvisorai.me` / Fly.io
> apply to the hosted API, which launches with the beta (no public
> instance or DNS today — `docs/STATUS.md` tracks that). The live
> surfaces before then are the static site + mock-mode console on
> GitHub Pages; their failure modes are the Pages/CDN sections below.

## Contact + escalation

- Ops on-call: whoever pushed last (`git log -1 --format='%an %ae' main`)
- Security disclosures: security@agentvisorai.me
- Status page: `docs/STATUS.md` in this repo (edit + push to update)
- Investor comms: read-only status page + one-line email

## The 11 things that will go wrong

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

# If restoration is required, use the isolated restore procedure below.
# Nightly artifacts are encrypted .dump.gpg files, not directly restorable dumps.
# Restore and validate a separate empty database before changing DATABASE_URL.
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

### 4. Trivy CI job fails on a fixable HIGH/CRITICAL

**Signal:** the [Deploy workflow](../.github/workflows/deploy.yml) fails at
`Trivy image scan (fail on fixable HIGH/CRITICAL)`. Scanner errors also fail
this step. The gate uses `--ignore-unfixed`; passing it does not mean the full
image has no vulnerabilities. The workflow separately saves the unfiltered
`trivy-full.json` as the `console-image-vulnerabilities` artifact.

Reproduce both views for the exact image under review:

```bash
docker build -t agentvisor-console-scan server/
mkdir -p "$HOME/.cache/trivy"
# Retain all severities and unfixed findings, without an ignore file.
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$HOME/.cache/trivy:/root/.cache/trivy" -v "$PWD:/reports" \
  aquasec/trivy:0.74.0 image --scanners vuln --ignorefile /dev/null \
  --format json --output /reports/trivy-full.json agentvisor-console-scan
# Apply the CI severity/fixability gate using the same cached database.
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$HOME/.cache/trivy:/root/.cache/trivy" \
  aquasec/trivy:0.74.0 image --skip-db-update --scanners vuln \
  --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 agentvisor-console-scan
```

Upgrade affected dependencies or the maintained runtime base when a fix is
available, rebuild, and rescan. Review unfixed findings in the full report;
do not remove package metadata or add ignore rules merely to obtain a pass.
The current console runtime is pinned Distroless Node 22/Debian 13 and contains
no npm package manager. The dated 2026-09-24 local full scan with Trivy 0.72.0
found zero HIGH/CRITICAL, 15 MEDIUM, and seven LOW findings; all remaining
findings were unfixed. That result applies to the recorded image and database
snapshot. See the [container security review](PRODUCTION-VALIDATION.md#container-security-review)
for its image identity, retained findings, and validation limits.

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

**Signal:** a customer receives HTTP 429, for example on login.

The global allowance is 300 requests per minute per client IP **on each API
process**. Buckets reset when that process restarts and are not shared between
replicas. Users behind the same NAT share a bucket; changing a cookie does not
create a new allowance. Route-specific limits replace the global route limit:
login allows 10/minute per IP, signup 5/minute, and cookie-authenticated session
listing 30/minute. Ingestion is exempt from the global bucket. See the
[deployment security settings](../server/DEPLOY.md#security-posture-2026-baseline)
and [rate-limit implementation](../server/src/lib/rate-limit.ts).

Check the requested route, response headers, emitting API instance, and
configured trusted proxy hops before changing a limit. An incorrect proxy
setting can group unrelated clients under the proxy's IP. Keep login limits
keyed to the verified client IP; using an unvalidated email or cookie as the
key would let callers create fresh buckets. If the deployment requires a
fleet-wide allowance, enforce it at the ingress and document its separate
policy. Adding API replicas does not preserve a fixed fleet-wide quota.

The 2026-09-24 [operational drill](../server/VALIDATION.md#authenticated-workload-and-database-restoration)
confirmed the global 300-request allowance, the next-request 429, shared usage
across users, a separate allowance on the second instance, the cookie list
limit, and authenticated ingestion after the global bucket was exhausted.

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

### 8. Ingest spike or unexpected 429

**Signal:** customer daemons receive 429 or ingestion latency rises.

The current API exempts `/api/v1/ingest` routes from its global rate limiter.
A 429 on ingestion therefore requires checking the proxy, gateway, and exact
response origin before changing application limits. Correlate the response's
`X-Request-Id` with the API logs. Deployment-token authentication identifies the
caller; it does not establish a per-deployment request-rate quota.

The [event ingest route](../server/src/routes/ingest.ts) accepts at most 500
events per batch. That is an input-size limit: an oversized batch returns
400 `invalid_input`, not 429. For slow valid batches, inspect PostgreSQL health,
connection pressure, and query timing. Compare the workload with the measured
60-second fixture below; do not infer sustained production capacity from its
success or raise the batch cap as a rate-limit fix.

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

### 11. Customer daemon's clock is hours off (TZ set as local-time-UTC)

**Signal:** customer reports sessions stuck `live` with no timeline, and
`avctl console-sync` printing
`warning: console dropped timestamp-skewed events … leaving that batch retryable`
plus `receiptsSkipped` > 0 in the summary line. With
`require_identity = true` the same skew locks out every honest client
(all 401) — the daemon log then says which way the clock is off:
`issued-at timestamp … is in the future` (host behind) or
`…s past expiry — longer than the maximum token TTL; this host's
clock is likely ahead (check NTP)` (host ahead).

**What's happening (verified end-to-end, round 106, +6h faketime):** the
console clamps session `openedAt`/`closedAt` to `now+5min`, refuses
events dated >5 min in the future, and avctl then **defers the receipt**
so a sealed session never appears with an empty timeline. Nothing is
lost — the daemon's spool keeps everything and every batch stays
retryable. A daemon *behind* real time syncs fully (past-dated events
are honest replay).

**Fix:** correct the machine's clock/NTP (`timedatectl set-ntp true`,
or fix the container host), which stops new sessions from skewing.
Evidence already stamped in the future is immutable (MAC'd spool /
signed receipts) and lands automatically once the wall clock passes
the stamps — for a +6h skew that means up to 6 hours later; re-run
`avctl console-sync` (or let the timer tick) after the catch-up.
avctl defers the session's receipt until every frozen record has
landed, so the console never shows a sealed-but-incomplete session.
The signed receipt's `issued_at` keeps the daemon's original attested
clock claim by design.

## Standard operating procedures

- **Every deploy** goes through `main` → `.github/workflows/deploy.yml`.
  Never `fly deploy` from a laptop against the prod app — that skips
  the Trivy scan.
- **Every migration** is a Prisma migration in `server/prisma/migrations/`,
  reviewed in a PR before it lands. Never `prisma db push` against prod.
- **Every secret rotation** is a `fly secrets set` command in the ops
  log below (edit + push).
- **Every backup restore drill** should use a separate empty database. Decrypt
  a recent [nightly backup](../.github/workflows/backup.yml) using the vaulted
  passphrase, restore with a compatible PostgreSQL client, and verify data,
  authentication, tenant boundaries, and receipt signatures before any cutover.
  Remove only the resources created for that drill.

## Validation evidence

The 2026-09-24 console results below are local measurements with explicit scope,
not certification of a deployed production environment. Older entries are
retained as dated history; they do not establish current release behavior.
The complete current console evidence is in [server/VALIDATION.md](../server/VALIDATION.md).

### Backup + restore roundtrip

The [reusable operational drill](../server/scripts/operations-drill.mjs) creates
its own PostgreSQL container and API processes and refuses an existing database
URL. From `server/`, with dependencies generated and the PostgreSQL image
already available locally:

```bash
npm run build
TMPDIR=/tmp node scripts/operations-drill.mjs
```

On 2026-09-24, all **25 checks** passed. The drill seeded 100,000 events across
1,000 sessions, then performed authenticated concurrent work through two API
instances. After stopping writers, it dumped and restored **115,322 events,
1,006 sessions, two signed receipts, and two tenants** into a separate empty
database. All 18 public tables matched their source row counts and sorted
row-content fingerprints. The 78.8 MiB source took 0.599 seconds to dump and
2.525 seconds to restore on that local fixture; these are not production
recovery-time guarantees.

The restored API accepted the original cookies and ingest credentials,
preserved tenant isolation and event pagination, kept quarantined sessions
without receipts, and returned the original receipt bodies with valid Ed25519
signatures. The fixture reused its JWT secret intentionally: a database backup
does not replace the vault containing external application secrets.

For a drill using a scheduled backup, use its encrypted artifact and a newly
provisioned empty PostgreSQL 18 database. Use the PostgreSQL 18 `pg_restore`
client, and treat every restore error as a failed drill. Restoring onto an
older major version is not established by these checks.

Retrieve the passphrase into an owner-readable file from the vault. Also
prepare a private libpq service file (`PGSERVICEFILE`) with a section named
`agentvisor_restore` that identifies only the empty test database. Specify
its `host`, `port`, `dbname`, and `user`; for a remote database, configure
`sslmode=verify-full` and the appropriate `sslrootcert`. Keep the password
out of that service file and provide it through a separate `PGPASSFILE`.
The password file uses libpq's `host:port:database:user:password` format;
escape literal colons and backslashes with a backslash. Both files must be
owned by the operator and have mode `0600`. Populate them through the vault
or a local editor, without putting passwords in shell history.

```bash
# Set the three private file paths and ENCRYPTED_DUMP before running.
# PG_RESTORE_18 is the absolute path to the PostgreSQL 18 pg_restore binary.
(
  set -eu
  umask 077
  export PGSERVICEFILE="${RESTORE_SERVICE_FILE:?}"
  export PGPASSFILE="${RESTORE_PASSWORD_FILE:?}"
  : "${BACKUP_PASSPHRASE_FILE:?}" "${ENCRYPTED_DUMP:?}" "${PG_RESTORE_18:?}"
  test -r "$PGSERVICEFILE"
  test -r "$PGPASSFILE"
  test -r "$BACKUP_PASSPHRASE_FILE"
  # Do not let an inherited password override the private password file.
  unset PGPASSWORD
  restore_workdir=$(mktemp -d)
  trap 'rm -f "$restore_workdir/backup.dump"; rmdir "$restore_workdir"' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  gpg --batch --no-symkey-cache --pinentry-mode loopback \
    --passphrase-file "$BACKUP_PASSPHRASE_FILE" \
    --decrypt "$ENCRYPTED_DUMP" > "$restore_workdir/backup.dump"
  "$PG_RESTORE_18" \
    --no-owner --no-privileges --single-transaction --exit-on-error \
    --no-password --dbname=service=agentvisor_restore "$restore_workdir/backup.dump"
)
# Complete the data/API checks above before considering a production cutover.
```

The command arguments contain only the service name and file paths. The
private credential files remain under the operator's control; the temporary
plaintext dump is removed when the subshell exits.

The encrypted-backup drill also ran against a separate PostgreSQL 18.6 fixture
using GnuPG 2.2.40. It restored 10,000 rows with identical content, including
Unicode, JSON, and binary values; identity sequences and foreign-key checks
still worked. Incorrect passphrases and modified ciphertext were rejected.
The helper publishes only ciphertext after archive validation and a successful
decryption comparison. Its 17 failure and confidentiality tests cover partial
writes, timeouts, repeated termination signals, and private-file cleanup.

```bash
python3 scripts/test-postgres-backup.py
python3 scripts/test-postgres-backup-drill.py
# Set DOCKER_HOST if the local Docker engine needs an explicit endpoint.
python3 scripts/postgres-backup-test.py --output-dir /tmp/agentvisor-backup-results
```

The local drills did not validate retrieval or decryption of a
production backup artifact. Verify that path separately, including access to
the vaulted passphrase, backup freshness, and the deployment's recovery target.

### Deployment token rotation

Historical record from 2026-08-26; this exact fixture was not rerun in the
2026-09-24 operational drill.

Verified: `POST /deployments/:id/rotate-token` invalidates the previous
token at the exact SQL commit. Old token → 401 unauthenticated
immediately, new token → 200 on the very next ingest call. Zero
dual-acceptance window.

### Ed25519 receipt trust anchor

Historical record from 2026-08-26; this exact fixture was not rerun in the
2026-09-24 operational drill.

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

Historical record from 2026-08-26; this exact fixture was not rerun in the
2026-09-24 operational drill.

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

Historical record from 2026-08-26; this exact fixture was not rerun in the
2026-09-24 operational drill.

Verified `Set-Cookie` header on `POST /auth/signup` with
`NODE_ENV=production` + `SESSION_COOKIE_SECURE=true`:

```
set-cookie: av_session=…; Max-Age=604800; Path=/; HttpOnly; Secure; SameSite=Lax
```

Every required security flag present. No `Domain` attribute → the
cookie won't leak to a subdomain we don't control.

### Cross-tenant isolation (200k rows)

Historical record from 2026-08-26; this exact fixture was not rerun in the
2026-09-24 operational drill.

Verified against 100k sessions per org × 2 orgs (200k total):

- `/overview` scoped: Org A sees 100k, Org B sees 100k.
- `GET /sessions/<foreign-id>` → 404 (Org A cannot see Org B session
  even with the exact ID).
- `q=<foreign-prefix>` returns 0 (identifier invisible).
- `/me/export` streams 100 002 JSONL rows for Org A — zero rows leak
  from Org B.

### Authenticated workload and capacity

The 2026-09-24 operational drill offered **3,000 authenticated requests over
60 seconds at 50 requests/second**, with at most 12 in flight. Each of overview,
session list, session detail with 20 events, and ingestion of 20 events received
750 requests. All 3,000 returned HTTP 200; achieved throughput was 50.00
requests/second. The p95 latencies were 66.20 ms, 44.16 ms, 23.97 ms, and 50.74 ms,
respectively. The 100,000-event SQL seed was preparation, separate from the
15,000 events added through the measured authenticated ingest requests.

The fixture ran two production-mode Node 26.8.1 API processes on macOS arm64
against PostgreSQL 15.19 limited to two CPUs and 512 MiB. The API processes had
no container resource limits; compilation and image scans were paused. It
simulated 64 client IPs over local HTTP. Concurrent duplicate ingestion committed
320 unique events once, and each tenant's subscriber received its 160 events
through the other API instance without exposing the other tenant's data.

This validates the stated offered workload, not maximum capacity, prolonged
availability, production TLS/ingress latency, or large SSE fan-out. Only two
SSE subscribers were used. Representative cached query plans used the expected
session/event indexes; see the [measurements and query plans](../server/VALIDATION.md#authenticated-workload-and-database-restoration)
for exact results and environment limits. Repeat the drill under the target
resource limits and deployment network before setting a capacity commitment.

The Console + API CI load check exercises **`/healthz` only**. It does not
exercise authentication or PostgreSQL and must not be reported as database or
authenticated API capacity.

## Verify a configured model provider

Build the daemon and CLI, then configure `OPENAI_API_KEY` privately in the
environment. Run this from the repository root with an explicit model that the
account can access. The output directory must be new or empty and owner-only.

```sh
cargo build --locked --release -p av-harness --bin agentvisord -p av-cli --bin avctl
python3 scripts/provider-smoke.py --allow-live-request \
  --model YOUR_MODEL --output-dir /tmp/agentvisor-provider-result
```

The explicit flag authorizes one potentially billable greeting request capped
at 32 generated tokens. The drill starts its own loopback daemon, requires local
identity and operation scopes, and forwards the provider key from the environment.
It requires actual text, a complete SSE stream, final usage, a signed receipt
with matching usage, and rejection of a modified receipt. Private signing and
identity keys, the spool, and the owned process are removed afterward. The
retained result contains checks, binary hashes, the receipt and public key, and
sanitized diagnostics. It does not validate the production identity provider,
ingress, provider quota at sustained load, or remote deployment configuration.

For another OpenAI-compatible provider, use `--base-url https://PROVIDER_HOST`.
This accepts an HTTPS origin, not a URL with credentials or a path; the daemon
appends `/v1/chat/completions`. HTTP is restricted to local test fixtures. The
request uses `stream_options.include_usage` and `max_completion_tokens` from the
[OpenAI Chat Completions API](https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create).
Choose a model supporting those parameters. A failed credential check is a
failed validation, not evidence of successful inference.

The offline regression suite uses real daemon and CLI binaries with a loopback
provider. It does not require a provider account and never contacts an external
API. Run it with `AGENTVISORD` and `AVCTL` set to the desired binaries, or build
the default debug binaries first, then execute
`python3 scripts/test-provider-smoke.py`. CI runs this suite after building both
binaries.

## Ops log (append-only)

Add rows here after non-trivial ops actions (secret rotation, manual
DB fixes, etc). Keep it short.

| Date (UTC) | Actor | Action | Ref |
|---|---|---|---|
| _(none yet — bootstrap this on first prod deploy)_ | | | |
