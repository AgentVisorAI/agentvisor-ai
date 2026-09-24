# Console validation — 2026-09-24

These are dated local validation results, not a certification of a deployed
production environment. Later sections record subsequent source changes and
their separate evidence. The initial run used macOS arm64, Node 26.8.1,
npm 11.19.0, and a dedicated PostgreSQL 15.19 container. Existing databases and
services were not reset. The API ran with `TZ=Asia/Tokyo`; PostgreSQL used UTC.

See the [notification recovery follow-up](#notification-connection-recovery-follow-up)
for the newest runtime changes and their separate verification.

## API and database checks

From `server/`, after `npm ci`, `prisma generate`, and `prisma migrate deploy`:

```sh
npm run typecheck
npm run build
API_BASE=http://127.0.0.1:8985 python3 ci/smoke.py
API_BASE=http://127.0.0.1:8985 node ci/e2e.mjs
DATABASE_URL=postgresql://USER:PASSWORD@127.0.0.1:PORT/DATABASE \
  JWT_SECRET=YOUR_TEST_SECRET_AT_LEAST_32_CHARACTERS NODE_ENV=test \
  PG_CONTAINER=YOUR_ISOLATED_CONTAINER PG_USER=USER PG_DB=DATABASE \
  bash scripts/run-drill-battery.sh
```

- TypeScript checking and compilation passed.
- The Python smoke suite passed 22 checks. The API datasource contract suite
  passed 110 checks, including event totals across pagination, deployment
  counts before the first session, and exclusion/inclusion of historical
  usage when switching from 24-hour to seven-day dashboard windows.
- Both suites also passed against a separate database with
  `NODE_ENV=production`, HTTPS public URL configuration, and the SMTP mailer
  configured. The SMTP endpoint was a dummy local endpoint: this does not
  demonstrate delivery of real mail.
- All 15 database drill suites passed: quarantine, API keys (two suites),
  invites (two), IP allowlists, retention, SAML (two), WebAuthn (two), webhooks
  (three), and OIDC. Identity-provider and authentication-device fixtures are
  test fixtures, not live enterprise integrations.
- `npm audit --json` reported zero advisories for both `server/` and
  `docs/app/` at the time of this run.

Two early database drills timed out while the Rust release build saturated the
machine. Both passed in the subsequent complete 15-suite run after compilation
finished. No database timeout was hidden by changing production settings.

## Browser checks

The mock console was served from the repository's `docs/` directory. A second
copy was configured with `MOCK_MODE=false`, the local API origin, and matching
CSP `connect-src`; the API allowed that browser origin. See README.md for these
self-hosting settings. Production source CSP was not weakened for the tests.

```sh
API_BASE=http://127.0.0.1:8985 SPA_ORIGIN=http://127.0.0.1:44126/app \
  node ci/browser-e2e.mjs
API_BASE=http://127.0.0.1:8985 SPA_ORIGIN=http://127.0.0.1:44126/app \
  node scripts/quarantine-drill.mjs
API_BASE=http://127.0.0.1:8985 node scripts/spa-smoke.mjs
SITE=http://127.0.0.1:44125/app/ node scripts/interactive-drill.mjs
SITE=http://127.0.0.1:44125/app/ node scripts/engine-matrix.mjs
```

The real API browser suite passed 12 checks, including visible error states
when key/webhook APIs return 503. The live SPA suite passed 24 checks, including
ingestion, event rendering, counters, and SSE updates without a reload. The
quarantine suite passed 25 API/browser checks, including concurrent sealing,
tenant isolation, idempotent recovered events, immutable quarantine status,
partial-count warnings on screen and in print, and disabled receipt actions.

The mock-console browser suites also passed:

| Suite | Result |
| --- | --- |
| `live-site-smoke.mjs`, with local `SITE` | 11 checks |
| `interactive-drill.mjs` | 35 checks |
| `engine-matrix.mjs` | 11 features in each of Chromium, WebKit, and Firefox |
| `mobile-smoke.mjs` | All configured viewport checks, including 280px, passed |
| `a11y-audit.mjs` | No serious/critical findings across 11 console routes and nine modal states in both themes, plus three static pages in both schemes |
| `full-flow-rehearsal.mjs` | Desktop and `PROFILE=phone` runs passed |
| `csp-drill.mjs`, with site-root `SITE` | Passed, including functional verification under CSP |
| `receipt-verify-drill.mjs` | Eight download/offline-verification and tampering checks |
| `share-receipt-drill.mjs` | Four share-link and tampering checks |
| `verify-page-drill.mjs`, with site-root `SITE` | 15 checks |

## Real daemon crash recovery

This run used current debug daemon and CLI executables, not an HTTP simulation:

```sh
API_BASE=http://127.0.0.1:8985 \
  AGENTVISORD=/absolute/path/target/debug/agentvisord \
  AVCTL=/absolute/path/target/debug/avctl \
  PORT_BASE=60980 node scripts/daemon-console-drill.mjs
```

The wrapper passed all 14 assertions in the real SIGKILL/restart/synchronization
drill. The incomplete pre-crash session appeared as
`quarantined_crash_evidence` without a receipt, and the complete post-restart
session sealed separately. The wrapper creates and removes only its own test
workspace and private temporary credentials. It refuses missing binaries so
the synchronization leg cannot silently skip. The Console + API workflow
builds current-source binaries and runs this wrapper.

## Performance measurements and limits

```sh
node node_modules/.bin/autocannon --duration 15 --connections 20 \
  --pipelining 1 --json http://127.0.0.1:8985/healthz
SITE=http://127.0.0.1:44125/app/ node scripts/lighthouse-audit.mjs
```

The 15-second **`/healthz`-only** run returned 469,772 successful responses,
averaged 31,318 requests/second, and measured p99 latency of 1ms, with zero
errors, timeouts, or non-2xx responses. This endpoint does not exercise database
queries, authentication, ingestion, or production network latency. It is not
an authenticated API capacity or availability claim.

Lighthouse measured performance scores of 94 for the landing page, 75 for the
console, 88 for the pitch page, and 97 for the verifier. Accessibility and
best-practices scores were 100 on each page. The console required the script's
existing remeasurement. The enforced thresholds are 75/90/85, respectively;
the script's introductory comment now matches these existing thresholds.
These were local runs while other Rust compilation work was active, not
production RUM.

## Authenticated workload and database restoration

The reusable operational drill passed **25 checks** on 2026-09-24:

```sh
# From server/, with dependencies generated and PostgreSQL image already local:
npm run typecheck
npm run build
TMPDIR=/tmp node scripts/operations-drill.mjs
# Smaller correctness fixture, useful while preparing a change:
TMPDIR=/tmp EVENTS=1000 REQUESTS=80 node scripts/operations-drill.mjs
```

The runner creates a uniquely named PostgreSQL container and two API processes
in production mode, using generated credentials and a dummy SMTP endpoint. It
never accepts an existing database URL. Cleanup checks its container ownership
label, removes only its own container and volumes, and deletes the temporary
password file and database dump. Logs and measurements remain. All three API
processes, including the restored instance, exited with code zero, and cleanup
reported no errors.

This run used native Node 26.8.1 on macOS arm64 and PostgreSQL 15.19 in Docker,
with PostgreSQL limited to two CPUs and 512 MiB. The API processes were not
given container CPU or memory limits. Other compilation and image scans were
paused for the measurement. The fixture simulated 64 client IPs through one
trusted proxy hop over local HTTP; production TLS and ingress latency were
not measured. The two processes shared PostgreSQL and a generated JWT secret.

The correctness checks ran concurrent authenticated ingestion and reads for
two tenants through both instances. Duplicate batches committed exactly once,
rollups matched the 320 unique events, and neither reads nor SSE exposed another
tenant's data. Each tenant's subscriber received all 160 committed events once
through the cross-instance bus. A mismatched deployment token was refused.

Rate-limit checks confirmed 300 requests per IP per process, shared across
users, and a 429 on the next request. Changing an unvalidated cookie did not
create a new allowance. A second instance retained its separate allowance.
Cookie session listing returned 429 after 30 requests; authenticated ingestion
remained exempt from the exhausted global bucket. These are process-local
limits, not a fleet-wide quota.

The scale fixture directly seeded **100,000 events across 1,000 sessions**.
That preparation is separate from the measured authenticated workload: 3,000
requests offered at 50 requests/second over 60 seconds, with at most 12 in
flight. Every response was HTTP 200, with no tenant mismatch. Achieved throughput
was 50.00 requests/second and p95 client scheduling delay was 1.87 ms.

| Authenticated operation | Requests | p50 | p95 | p99 |
| --- | ---: | ---: | ---: | ---: |
| Overview | 750 | 25.32 ms | 66.20 ms | 127.05 ms |
| Session list | 750 | 22.19 ms | 44.16 ms | 83.98 ms |
| Session detail, 20 events | 750 | 7.61 ms | 23.97 ms | 61.08 ms |
| Ingest batch, 20 events | 750 | 18.67 ms | 50.74 ms | 126.32 ms |

The ingestion requests added 15,000 events through the real authenticated API.
This is evidence for the stated offered workload, not a measurement of maximum
capacity or long-duration availability. Only two simultaneous SSE subscribers
were used; no large subscriber-capacity claim follows from this run.

Representative SQL plans were captured with `EXPLAIN (ANALYZE, BUFFERS,
FORMAT JSON)` after `ANALYZE`, without forcing indexes. These plans check the
read predicates and ordering; they exclude authentication and the other queries
within each HTTP request. All reported reads came from PostgreSQL's cache.

| Query | Observed access path | Rows visited | Execution time |
| --- | --- | ---: | ---: |
| Session page | `sessions_orgId_openedAt_id_idx`, index-only scan | 51 | 0.059 ms |
| Event page | `events_sessionId_seq_key`, index scan | 51 | 0.121 ms |
| Session event count | `events_sessionId_occurredAt_idx`, index-only scan | 100 | 0.151 ms |
| Tenant overview aggregation | `sessions_orgId_toolsBlocked_idx`, bitmap scan | 503 | 0.184 ms |

After stopping writers, `pg_dump -Fc --no-owner` backed up the fixture and
`pg_restore --no-owner --exit-on-error` restored it into a separate empty
database. The source occupied 78.8 MiB and contained **115,322 events, 1,006
sessions, two signed receipts, and two tenants**. All 18 public tables matched
their source row counts and sorted row-content fingerprints. Dump and restore
took 0.599 and 2.525 seconds respectively. These times apply to this local
dataset and do not establish recovery time at production scale.

The restored API accepted the original cookies and ingest credentials, kept
tenant isolation, advanced event pagination without duplicates, preserved
quarantined sessions without receipts, and returned both original signed
receipt bodies with valid Ed25519 signatures. Reusing the fixture JWT secret
was intentional; the database backup does not replace external secret backup.

The full result is in
`/tmp/av-console-ops-af7351db662a-Wuur55/report.json`, with exact query plans in
the sibling `query-plans.json` and API logs in that directory. The run log is
`/tmp/agentvisor-console-ops-full.log`. The final small fixture report is
`/tmp/av-console-ops-9fa48e76add9-p6ILSi/report.json`.

## Targeted multi-instance recovery follow-up — 2026-09-24

The console follow-up corrected three reproduced failures: logout reported
success when its database revocation write failed, a reconnected PostgreSQL
notification bridge left existing SSE subscribers unaware of missed updates,
and active SSE responses prevented graceful shutdown from completing. A
connection-generation check also prevents a failed, partially connected
bridge from replacing or closing a newer healthy connection pair. Runtime
source was frozen after these changes and handed to the image validation
work; the earlier broad results above remain dated evidence from their
original runs.

```sh
npm run typecheck
npm run build
node --import tsx --test ci/multi-instance.test.mjs
node scripts/recovery-drill.mjs
```

TypeScript checking and compilation passed. The nine focused Node tests use
real local HTTP streams and controlled PostgreSQL/client failures. They cover
logout failure and retry across two application instances, tenant isolation,
local and remote notification loss, rejected publication queries, shutdown,
partial connection cleanup, and overlapping reconnect attempts. A real TCP
peer that accepts startup bytes but never answers also verifies that closing
the bridge cancels the pending handshake and releases its socket. Handshakes
now have a five-second connection limit as a separate recovery backstop.

The real recovery drill passed **13 checks** using two production-mode API
processes and a disposable PostgreSQL 15 container. It terminated only its
own LISTEN connection, verified that local and peer streams reset and that
authoritative reads contain committed data, and retained tenant isolation.
A trigger injected a failed logout write: the API returned 503, preserved the
retry cookie, and omitted the success audit. After the trigger was removed,
logout succeeded and the other instance rejected the captured cookie.

The drill then refused connections to its own database and terminated its
existing connections. Both APIs returned failed readiness and refused
authenticated reads. After access returned, the notification bridges recovered
first; both Prisma pools became ready approximately **14.15 seconds** after
the first recovery sample. Existing authenticated sessions then worked again.
Both processes exited cleanly on SIGTERM while authenticated SSE clients were
still connected. The fixture removed its two API processes, generated
credential file, and database container; its cleanup error list is empty.

The first recovery attempt used a 10-second diagnostic wait and timed out
while Prisma still returned `P1017`. The completed drill records readiness
samples within a **40-second diagnostic bound**, which also permits the
bridge's existing 30-second maximum reconnect backoff. No production timeout
was increased. This observation is not a production recovery-time guarantee.
An earlier fixture-only failure sent an empty POST with a JSON content type;
the request helper was corrected before the complete run.

A targeted Chromium check of the real page with an injected datasource
failure passed four assertions: the retry message is visible, the signed-in
page remains usable, exactly one live subscription resumes without an
unhandled rejection, and a successful retry returns to login. The real API
browser suite now also includes failed-logout and resumed-stream assertions;
the workflow runs these and the real database recovery drill as required
steps. This follow-up did not repeat the entire earlier browser battery.

Logs for the nine tests, their reproduced failures, and the targeted browser
check are under `/tmp/agentvisor-production-validation/console-recovery/`.
The complete database report and API logs are under
`/tmp/av-console-recovery-ff3abd1e8df3-sGsU1Q/`. After the pending-handshake
fix, the same 13 checks passed again against the rebuilt API, with both pools
and bridges ready after approximately 0.53 seconds of sampled recovery. That
final report is `/tmp/av-console-recovery-4792f507c7db-rYX5Rm/report.json`;
cleanup again completed without errors. The different observed recovery
times reinforce that this drill does not establish a recovery-time guarantee.
The failed 10-second attempt
remains under `/tmp/av-console-recovery-e7d94e8c0284-8lMw5T/`.

A final fixture review found that an accepted Docker creation could be left
running when the CLI failed before acknowledging it. The drill now checks
the exact generated name after every creation attempt, verifies the ownership
label, and removes only that container and its anonymous data volume. Failed
inspection or removal remains a failed cleanup, and repeated cancellation
cannot interrupt cleanup. The original failure stays in the report.

Seven tests using a fake Docker executable passed, covering ambiguous creation,
confirmed absence, foreign ownership, inspection and removal failures, and
single or repeated cancellation. The nine application regressions and these
seven fixture tests also passed together, with **16 passes and no skips**:

```sh
node --import tsx --test ci/multi-instance.test.mjs ci/recovery-drill.test.mjs
```

This command is required in console CI. Its local log is
`/tmp/agentvisor-production-validation/console-recovery/closure-tests.log`.
These checks used no real Docker service or database and did not repeat the
earlier real recovery workload. No application code changed in this cleanup fix.

Rate limits remain per client IP and per application process, as measured in
the operational drill above. This follow-up adds no fleet-wide rate limiter
and makes no additional capacity claim.

## Authentication and mail contracts — 2026-09-24

A focused follow-up reproduced and corrected three failures. SAML's local
logout endpoint returned success and cleared the cookie when its revocation
write failed; it now returns 503, retains the retry cookie, and omits the
success audit. OIDC discovery failures at login start or a callback on a fresh
replica returned raw HTTP 500 responses; both now redirect to the existing
login error display and permit retry after provider recovery. A deferred
password reset could install credentials after an email change had cleared
them, then send the token to the former address. Its write now requires the
user ID and email address to still match the original lookup.

Seven new contracts passed using Fastify request injection, controlled database
methods, and owned loopback HTTP and SMTP servers. They verify SAML failure
and retry with captured-cookie rejection on a peer, tenant configuration
isolation, discovery failure and recovery at both OIDC entry points, actual
SMTP acceptance and rejection, uniform reset-request responses, no false
email-delivery success log, refusal of invalid/expired tokens, one successful
concurrent reset consumption, and refusal of the stale-address reset write.
The reset test checks that credential consumption and API-key revocation are
requested through the same transaction callback; it does not replace a real
PostgreSQL rollback test.

```sh
npm run typecheck
npm run build
node --import tsx --test ci/external-auth.test.mjs
node --import tsx --test ci/multi-instance.test.mjs ci/recovery-drill.test.mjs ci/external-auth.test.mjs
```

TypeScript checking and compilation passed. The combined command passed
**23 tests with no failures or skips**. Console CI requires the new contract
suite separately, preserving the existing application and fixture tests.
Before-fix failures, final results, and compiler logs are retained under
`/tmp/agentvisor-production-validation/auth-followup/`. All local sockets
closed when the suites completed; no Docker service or real recipient was
used. These checks do not verify production delivery, DNS/mail reputation,
or a real enterprise identity provider. The new OIDC cases cover discovery;
they do not repeat the earlier signed-token drill. At this stage, SAML request
and browser nonce caches still required sticky routing. The shared SAML
follow-up below supersedes that limitation. The local logout route does not
implement IdP-initiated signed SAML logout.

The subsequent production-image drill passed **17 checks** with two console
containers and a disposable PostgreSQL **16.15** database. Both APIs ran the
same image, `sha256:c508f90ff0a38dded02d510d17b56aa4fe9d7658bb425664e413b1a7682d781a`,
with `NODE_ENV=production`. A generated certificate was trusted only inside
the fixture containers through `NODE_EXTRA_CA_CERTS`; host trust was unchanged.
The HTTPS discovery and SMTP services were owned fixtures, and the SMTP
server accepted only generated `example.test` recipients without forwarding
mail. This is not evidence of real enterprise-provider login or mail delivery.

The database tests verified these additional boundaries:

- An actual SQL exception during SAML logout produced 503 with
  `errorCode=session_revocation_unavailable`, no cookie clearing, and no
  success audit. Removing the fault permitted retry, with one success audit
  and rejection of the captured cookie on the other API.
- A PostgreSQL advisory lock and temporary row policy held an old reset
  lookup snapshot while a separate transaction changed the email address
  and cleared reset state. A statement trigger confirmed that the subsequent
  conditional update completed without reinstalling a token or sending mail
  to the former address. This tests the committed email-change state rather
  than repeating the complete email-verification ceremony.
- A failed API-key revocation rolled back the password change, reset hash
  and timestamp, and session revocation timestamp in the same transaction.
  Concurrent retries on the two APIs produced one 200 and one 401. Both the
  old cookie and API key worked on both APIs before reset and were refused
  on both afterward. The old password produced no session; the replacement
  password minted a cookie accepted by the peer.
- Real SMTP rejection retained the uniform 202 response, produced a failure
  log without an extra delivery-success log, and exposed no plaintext reset
  tokens in either production API log. OIDC discovery failure and recovery
  also passed over HTTPS, including a callback arriving on a fresh replica.

```sh
# Use an already-built production image. The pinned PostgreSQL image used
# by scripts/container-smoke.py must also be present; the drill never pulls.
CONSOLE_AUTH_IMAGE=agentvisor-api:ci node scripts/external-auth-drill.mjs
node --test ci/external-auth-drill.test.mjs
```

The five cleanup regressions passed without contacting Docker. They cover an
ambiguous creation reply, cancellation, failed log retrieval, refusal to
remove a foreign container, and a PostgreSQL close that never settles. The
final combined run of `multi-instance.test.mjs`, `recovery-drill.test.mjs`,
`external-auth.test.mjs`, and `external-auth-drill.test.mjs` passed **28 tests
with no failures or skips**. The
live drill removed its four containers, database volume, network, and private
credential/certificate files with no cleanup errors. Console CI now requires
this drill against the existing `agentvisor-api:ci` build and retains only its
logs and report. The workflow is reusable with read-only permissions so the
release workflow can require these same checks.

The successful report is
`/tmp/agentvisor-production-validation/auth-followup/av-auth-feb8cff83a06-rzqMWB/report.json`;
the run log is `auth-followup/postgres-auth-drill-verified.log` under the same
validation root. The report records the Docker image ID separately from the
three fixture source hashes, since the helper scripts were copied into the
containers after the image build. Earlier setup failures and fixture response
expectation failures are retained. The fixture was corrected to copy files
through Docker rather than depend on host temporary-directory mounts, and to
assert the application's public problem-response and decoy-MFA contracts.
No production behavior or acceptance condition was relaxed for this run.

## Shared SAML ceremonies — 2026-09-24

A real signed assertion reproduced the routing failure in the prior production
image: login completed on the initiating replica, but an identical ceremony
whose callback reached the other replica was refused. The failing image was
`sha256:c508f90ff0a38dded02d510d17b56aa4fe9d7658bb425664e413b1a7682d781a`.
Its result remains in `saml-shared/baseline.log` under the validation root.

The console now persists each request ID, browser nonce hash, configuration,
tenant, and expiration in PostgreSQL. After the SAML library validates the
response, a conditional database deletion must consume exactly one matching
request before login can succeed. The library's own cache removal does not
elect the winner, because its result is ignored by the pinned dependency.
Failed database operations refuse authentication. Raw browser nonces are not
stored. New logins remove at most 1,000 expired records through the expiration
index; this bounded cleanup is not a throughput measurement.

The updated application passed **29 checks** using two production-mode Node
processes, an isolated PostgreSQL 16.15 database, and locally generated signed
SAML responses. They cover callbacks on either replica, process restarts,
replay refusal, wrong or missing browser cookies, unknown request IDs and
nonces, configuration and tenant mismatches, expiration, unsigned responses,
issuer and audience refusal, database write faults, a complete database
outage and recovery, and absence of plaintext fixture secrets from API logs.
Metadata advertises the assertion consumer endpoint without advertising an
unsupported SAML SingleLogoutService.

The concurrency case uses two distinct, valid signed assertion IDs for the
same request and browser. An advisory lock holds both database consumption
attempts after signature validation; releasing it produces exactly one
session and no remaining request record. This prevents the separate assertion
replay table from masking a broken request-consumption operation. The fixture
also preserves the existing accepted form whose SubjectConfirmation omits
its own InResponseTo while the response supplies the validated request ID.

The successful native report is
`/tmp/agentvisor-production-validation/saml-shared/av-saml-shared-fd077138d51b-PCm7oh/report.json`;
its log is `saml-shared/shared-native-final.log`. A prior run passed 25 checks
before a fixture port changed during PostgreSQL restart. That evidence is
retained; choosing a fixed owned database port corrected the fixture without
changing application behavior or the recovery deadline. All owned resources
were removed without cleanup errors. The final image runs below use a later
fixture revision that additionally handles native process-spawn errors.

The preceding SAML-stage production images each passed the same **29 shared SAML checks and
17 external-authentication checks**, for 46 checks per architecture. Both
were built from the same frozen 63-file source snapshot. The amd64 image ran
under the host's existing Rosetta support; this verifies the actual image's
execution and authentication contracts, not native amd64 capacity.

| Architecture | Docker image ID | Shared SAML report directory | External-auth report directory |
| --- | --- | --- | --- |
| arm64 | `sha256:23b91fb0bee2ecadf7f72418ec6cb097e36d038877e74cab3a085550d5e35cc2` | `av-saml-shared-0b7dac85c910-AkGEbe` | `av-auth-59cab9f0e327-ldG0Dw` |
| amd64 | `sha256:62fc24101525f2c7048af157b11a2056f68ecfc8ea70efac51773845aa177584` | `av-saml-shared-7f2fe7aa5311-4evamf` | `av-auth-1cb1c8226b47-bhS7Lc` |

Each directory contains `report.json` beneath
`/tmp/agentvisor-production-validation/saml-shared/`. The matching run logs
are `arm64-saml.log`, `arm64-auth.log`, `amd64-saml.log`, and `amd64-auth.log`.
All four reports record the expected image ID and zero cleanup errors. Each
drill removed its owned containers, database volume, network, and private
fixture files. The shared SAML fixture hash was identical across both image
runs; each external-auth report separately records its three fixture hashes.
The frozen build inputs are recorded in
`/tmp/agentvisor-production-validation/amd64-console/build-inputs.json`.

That arm64 console also passed all **14 daemon crash/recovery assertions**
with the release daemon and CLI from that stage. The drill verified explicit quarantine
after an interrupted capture, refusal of a receipt for incomplete evidence,
and a separately sealed healthy session after restart. Its result records
daemon SHA256 `be82ce32f10cd4a7333449f68c087c2f83f4ea88fc65443a739b8ca2099fdaac`
and CLI SHA256 `0678189b9089cacc1a0c37fad9e86ce2a215bf73484482c8be8f6c12d4f2677e`.
The original assertions and deadlines were unchanged. The wrapper confirmed
that its exact containers, network, anonymous database volume, signing seed,
and environment files were removed. The result, helper hashes, and logs are
under `/tmp/agentvisor-production-validation/durable-tool-images/console-crash/`.
Both binary hashes matched before and after that run. The earlier
pairing remains recorded under `saml-tool-images/console-crash/`; the shared
SAML evidence index identifies the pairing from that stage and preserves that
earlier report as history. These 63-input images and daemon pairing are historical;
the follow-up below records the current 65-input console images and updated daemon.
Their current image evidence is indexed in
`/tmp/agentvisor-production-validation/startup-console-images/final-image-provenance.json`.

```sh
# Run from server/ with the pinned PostgreSQL fixture image already present.
npm run build
node scripts/saml-shared-drill.mjs
# Alternatively, test an already-built production image without rebuilding it.
CONSOLE_SAML_IMAGE=agentvisor-api:ci node scripts/saml-shared-drill.mjs
```

Console CI requires the production-image form after the existing external
authentication drill and retains its logs and report. The TypeScript check
and all **28 existing authentication, recovery, and fixture cleanup contracts**
also passed after the database model changed. Their current logs are
`saml-shared/final-typecheck.log` and `saml-shared/existing-contracts.log`.

The SAML browser regression passed **seven checks in each of Chromium,
Firefox, and WebKit**, for 21 checks. It verifies the usable SAML login button,
discovery failure reporting, and actionable messages for unavailable request
state. The test first reproduced four failures before the UI corrections.
The logs are under `/tmp/agentvisor-production-validation/saml-browser/`.
CI requires the Chromium version. These controlled browser responses test
the UI; the separate 29-check drill performs actual signature verification.

Apply migration `20260924140000_shared_saml_authn_requests` before starting the
updated application; the production image's startup command runs migrations.
The first upgrade cannot recover ceremonies held only in an old process's
memory. During a mixed-version rollout, those ceremonies may fail and users
must restart login once the rollout completes. This is not a promise of
uninterrupted in-flight authentication during the initial migration. Once all
replicas run the updated code, new pending ceremonies survive process restarts
and can complete on either replica. Replicas must share the database, cookie
signing secret, and public API URL. Pending requests expire after ten minutes.
These local fixtures do not certify a real enterprise IdP, production mail
delivery, or IdP-initiated SAML logout.

## Packaged console follow-up — 2026-09-24

At this earlier stage, the console source including the pending-handshake fix was built
as `av-deployment-console:20260924-recovery`. Its local image identifier is
`sha256:2e5f68cc8d873f3525ddf5e5b1cd08fcd7bd6601b8b74468f0c4fef25f3cae9a`.
The image runs Node 22.23.3 and Prisma 6.12.0 on the pinned Debian 13 Distroless
base. Its 62 build inputs still matched the repository after validation.
The prior `20260924-distroless` image remains available as a rollback.

The actual image passed all **22 Python API checks, 110 API datasource checks,
14 daemon crash/recovery assertions, and seven packaged startup tests**.
Migrations completed under UID 65532 with a read-only root filesystem, and the
packaged Prisma engine loaded OpenSSL 3, libcrypto, and zlib. Invalid migration
credentials prevented API startup. Stopping the fixture database made
readiness return 503 while liveness stayed 200; readiness recovered after the
database restarted. SIGTERM shut down the API cleanly with exit code zero.

The crash drill used the retained `revocation-final` release executables and
a private signing seed, with the original assertions and deadlines. Their
exact hashes remain in the image provenance. This drill uses embedded state;
the subsequent Redis pool correction is covered by separate Linux contracts
and the new gateway image validation, rather than an additional console run.

The unfiltered Trivy scan reported **15 medium and seven low OS findings**,
with no high or critical findings and no fixed versions listed. Twenty
findings concern `libc6` and two concern `zlib1g`. The scan retained every
severity, used an empty ignore file, and did not exclude unfixed findings.
The maintained runtime alternatives reviewed for this pass did not establish
a safer supported replacement, so the proven base was preserved. These
remaining findings are still open; the result is not a claim of zero
vulnerabilities.

Two earlier attempts remain recorded. An external VM restart interrupted the
first run. The next passed 107 of 110 API checks because three test requests
sent a development Origin outside the production fixture's allowlist. The
test now accepts `SPA_ORIGIN`, and the container runner passes its configured
origin. All original assertions then passed against the unchanged image;
production origin checks were not relaxed.

The complete logs, unfiltered scan, source hashes, and cleanup record are in
`/tmp/agentvisor-recovery/deployment/console-recovery-runtime/configured-origin/`.
`/tmp/agentvisor-recovery/deployment/final-image-provenance.json` indexes this
image and the separately validated gateway and Cloud Foundry images. Cleanup
verified that this run's containers and network were removed, its private SSH forward stopped, and its
temporary environment files and signing seed were deleted. Existing user
services were not modified by this validation.

## Ingest text and browser recovery follow-up — 2026-09-24

The actual ingest route, daemon authentication, Prisma, and an isolated
PostgreSQL 16 fixture reproduced a permanent server error for a NUL character
in an event's `body` or `sub`. Both fields returned 500 on two identical
attempts, with PostgreSQL error 22021. No event or counter change committed.
Retrying was safe from duplicate writes but could never succeed unchanged.
The route now rejects NUL with the existing `400 invalid_input` response
before event mutation. Other event identifiers already reject that character.
Newlines, tabs, and Unicode content remain unchanged in storage.

The corrected route passed **11 focused checks against real PostgreSQL and
loopback HTTP**. They cover repeated refusals, unchanged events and counters,
a corrected retry using the same sequence, exact text preservation, and the
existing cumulative counter-overflow response and rollback. That overflow
still returns `422 counter_overflow`. The maintained
[API suite](ci/e2e.mjs) adds **18 assertions**, including a mixed valid/invalid
batch and five legal API batches that reach the PostgreSQL integer maximum.
The expanded suite passed all **128 assertions**, plus the separate **22 smoke
checks**, against each new production image. The ARM64 image ran natively;
the AMD64 image ran under the host's existing Rosetta emulation. Their results
are recorded in `startup-console-images/actual-{arm64,amd64}/result.json` under
the validation evidence directory. The final ARM64 daemon-console pairing
also passed all **14 unchanged crash/recovery assertions**, as detailed below.

Source review found no new incompatibility in the current `avctl console-sync`
event producer: message bodies are serialized JSON, ATIF display and tool
names are validated before mapping, and bridge tool names have controls
removed. This establishes the producer's code path, not a separate live test
of an otherwise unreachable raw-NUL event.

The browser adapter also fixed three reproduced failures: audit errors no
longer appear as empty history, JSON `null` error bodies preserve HTTP status
and session-expiry handling, and overlapping stream reconnect paths cannot
leave an extra connection open. All **five new recovery test cases** failed
before the correction and passed afterward. The actual audit UI retains its
existing rows and enabled retry button during an outage, then retrieves the
same cursor successfully. Stream tests check retired callbacks, timer
cancellation, and complete unsubscribe cleanup.

The same five cases passed against the frozen minified console with explicit
Chromium, Firefox, and WebKit selection. Four cases exercise the adapter in a
controlled JavaScript context; the fifth drives the real SPA in the selected
browser. Firefox's first attempt timed out during initial navigation, before
the UI assertions; an unchanged repeat passed. Both logs remain available.
The separate minified SAML UI fixture passed seven checks in each browser.
These controlled API responses do not measure production network reliability.

Run the maintained browser tests from `server/` after installing Playwright:

```sh
node --test ci/datasource-recovery.test.mjs
BROWSER=firefox CONSOLE_DOCS_ROOT=/path/to/frozen/docs \
  node --test ci/datasource-recovery.test.mjs
```

TypeScript, JavaScript syntax, and whitespace checks passed. Evidence is under
`/tmp/agentvisor-production-validation/console-trust-followup/`, including
`datasource-before.log`, `datasource-after.log`, `ingest-before.json`,
`ingest-after.json`, the three minified browser logs, and the unchanged
Firefox retry log. `minified-final/result.json` records source and minified
hashes. The source datasource hash is
`cf07576c1081cff23f279cf28527bd4dbb21c06a188a3562aa91b43c06623925`.
The three production JavaScript bundles total 82,252 gzip bytes in that
snapshot; this is an asset measurement, not an end-user performance claim.

All owned PostgreSQL containers, volumes, and private environment files were
removed. An intermediate migration attempt failed before API validation;
its failure and cleanup records are preserved. The successful fixture used
a TCP readiness check to avoid observing PostgreSQL's temporary initialization
server. No shared service, production database, external mail provider, or
identity provider was modified or contacted by these checks.

The first final daemon-console pairing attempt used console image
`sha256:2cb985a6c7b5f141f60ed3e914558670217addd9417abaed361b27b381aaa58d`
with the immutable `expiry-final` release binaries. The console became ready,
but the daemon missed the unchanged 15-second startup deadline with an empty
boot log. No crash/recovery assertion passed in that attempt. Binary and
script hashes remained unchanged, and all owned processes, containers,
volumes, networks, and secrets were removed. The failure is retained under
`/tmp/agentvisor-production-validation/expiry-images/console-crash/`.
`expiry-images/console-crash-index.json` records that failure and the unchanged
repeat. Once the host was idle, the repeat
passed all 14 assertions in 23.1241 seconds with the original startup deadline
and assertions. It proved zero-failure console synchronization, explicit
quarantine without a receipt for the incomplete session, and a separate signed
post-restart session. The successful report is
`expiry-images/console-crash-repeat/result.json`; its
`post-run-verification.json` confirms unchanged binary/script hashes and the
absence of the owned process group and Docker resources. All generated
credentials were removed. No global process scan or wrapper adjustment was
needed.

The final pairing used these immutable native executables:

- `agentvisord`: `c7219f43746a8ccb23ac1810cfdea76e2c910b265e87b5c9c1038748d2f280ef`.
- `avctl`: `0678189b9089cacc1a0c37fad9e86ce2a215bf73484482c8be8f6c12d4f2677e`.

The earlier failed attempt remains in the index; the successful repeat does
not establish a cause for the initial startup delay or certify production
availability under contention.

## Notification connection recovery follow-up

The notification bridge now uses five-second query deadlines, a 15-second idle
listener heartbeat, and a limit of 256 pending publications. The per-query
deadline takes precedence over a conflicting `query_timeout` in the database
URL. Readiness reports the bridge as healthy only after PostgreSQL acknowledges
its reset notification. On a stall or queue overflow, local events still reach
their tenant; the bridge closes its database clients, reconnects, and resets SSE
streams so peer clients refetch committed changes.

Five actual-protocol tests first reproduced stalled setup, stalled reset,
stalled publication, unbounded queuing, and an idle listener blackhole. The final
27-test run passed those five tests, nine existing multi-instance contracts,
and 13 fixture cleanup cases. TypeScript checking passed. An intermediate
fixture cleanup assertion ran before queued socket-close events; waiting for
all those events corrected the fixture without relaxing its zero-socket check.
The failed and successful logs remain under
`/tmp/agentvisor-production-validation/console-stream-followup`.

The same protocol test can target the compiled production module with
`BUS_TEST_DIST=1` and the fixture at `/app/ci/bus-query-recovery.test.mjs`.
The real PostgreSQL drill also accepts `CONSOLE_RECOVERY_IMAGE` to run both API
replicas from the supplied image through its normal migration entrypoint.
It observes the actual listener heartbeat before terminating that exact fixture
connection, then checks stream resets, authoritative refetch, tenant isolation,
logout persistence, database outage/recovery, and graceful shutdown. Its owned
containers and network carry unique labels; cleanup verifies ownership and
removes private environment files. CI requires both packaged checks.

## Local evidence files

Logs were retained under `/tmp/agentvisor-console-` on the validation host.
They are not repository artifacts and may disappear when that host cleans
temporary files. Useful suffixes are:

- `battery-final.log`, `e2e-final.log`, `production-e2e.log`, and
  `production-smoke.log` for the final API runs.
- `live-e2e.log`, `spa-smoke.log`, `quarantine-browser-final.log`,
  `daemon-wrapper.log`, `interactive.log`, `engines.log`, `mobile.log`,
  `a11y.log`, `full-flow.log`, `full-flow-phone.log`, and `csp.log`.
- `receipt-final.log`, `share.log`, and `verify-page.log` for receipt checks.
- `load.json`, `lighthouse.log`, `npm-audit.json`, and `build-audit.json`.

No live email provider, production identity provider, deployed CDN, production
database scale, long-duration availability, or real-user performance was
certified by this run.
