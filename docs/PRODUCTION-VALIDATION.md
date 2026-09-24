# Validation record — 2026-09-24

This record describes the recovered implementation and local verification of
the daemon, CLI, console, storage adapters, and deployment artifacts. It is
evidence for the source in this workspace, not certification of an unspecified
production deployment. No remote Kubernetes or Cloud Foundry deployment was
performed.

The [latest follow-up](#notification-and-deployment-follow-up) records the
notification recovery, deployment defaults, and CI changes separately from
the earlier broad validation runs.

A production rollout still needs a valid model-provider credential and checks
against the selected identity provider, email service, and target infrastructure.
The available model-provider credential returned HTTP 401. The console image
also retains 15 medium and seven low vulnerability findings, all currently
unfixed; no high or critical findings were reported. Apply the SAML database
migration before updated replicas receive login traffic, as described below.

## Changes verified

Identity and token handling now isolate holder revocation by issuer while
preserving deployment-wide operator revocation. Exchanged credentials carry
issuer-bound revocation ancestry. Unsupported JOSE extensions, ambiguous
credential types, invalid scopes, and unusable revocation identifiers are
refused. Older exchanged tokens without issuer ancestry must be reissued.

Holder revocation also accepts trusted external tokens whose key identifier
matches the gateway's identifier. A reproduced bug previously returned success
without revoking those tokens. Origin is now checked using the actual gateway
signature, and external tokens undergo full identity validation. Regression
tests cover Ed25519 and HMAC collisions, forged signatures, malformed gateway
profiles, and unknown delegation-parent keys. As with other invalid inputs,
HTTP 200 alone does not confirm a revocation; an unloaded external key sharing
the gateway identifier can receive the same harmless response.

A 10,000-connection test exposed a concurrency regression: small requests
waited in the same blocking-worker queue as durable filesystem operations.
Validated requests without token quotas now prepare inline when their bodies
are at most 16 KiB. Configured authentication, quota checks, and larger
requests remain offloaded. Tests with a saturated worker verify this boundary
and preserve validation, principal binding, and cancellation behavior.

The recovered implementation also includes per-backend tool credentials,
token exchange and introspection, mission and intent authorization, signed
operator revocation records, redaction before evidence persistence, and
tenant-specific trace export. Live daemon tests exercise the security routes
and verify that caller credentials never reach tool backends.

Incomplete capture produces a durable quarantine notification and an explicit
console status, never a complete receipt. Acknowledged notifications are
retained outside the active outbox so incident history cannot consume its
bounded replay capacity. The CLI preserves quarantine even when a display
event exceeds sequence or timestamp limits. Existing console seals remain
immutable. HTTP redirects cannot forward captured evidence from console sync.

Console fixes also cover event totals across pagination, usage within the
selected time window, deployment counts before the first session, and visible
errors when inventory APIs fail. The privacy documentation now states that
captured content can be uploaded after configured redaction.

Compose delivers private secrets with ownership readable by the non-root
daemon. Supported NATS and Redpanda images are pinned by digest. Bundled MinIO
is a local test fixture; production cold storage must use a maintained
S3-compatible service. Kubernetes requires explicit identity credentials.
The production Kubernetes and Cloud Foundry templates require Redis; its
persistence and backups must be configured so revocations survive restarts.
Both templates now require operation scopes as well as a valid identity.
The Kubernetes template also mounts an operator-supplied CA bundle for verified
private Redis TLS and documents the public roots needed by other destinations.

Redis storage now enables certificate-verified TLS and explicitly initializes
its cryptographic provider. It rejects insecure TLS URLs and mixed encrypted
and plaintext cluster seeds. The new isolated live TLS drill passed all eight
storage contracts, all seven shared revocation contracts, and positive/negative
certificate and authentication checks. The TLS fixture uses generated private
certificates and a dedicated non-root Redis container; it never changes the
host trust store or existing services. The follow-up also exercised TLS and
Cluster together: all 17 Rust storage, trust, and shared-revocation contracts,
plus six transport/topology groups, passed with four test threads inside Linux.
All six nodes used TLS for clients, replication, and the cluster bus. Invalid
credentials, untrusted certificates, hostname mismatches, insecure URLs,
redirection, and cross-slot behavior were checked. Three primaries and three
replicas shared one container network namespace; this does not prove
independent-host failover.

Atomic audit writes now report a directory synchronization failure even when
the preceding rename has already made the complete file visible. The file stays
available for recovery or an idempotent retry. This preserves the existing
fail-closed dispatch contract when an in-flight audit marker is not durable.
Recovery also synchronizes existing lifecycle intents, provenance, and receipts
before publication or adoption. Directory creation confirms existing ancestors
as well as new ones, covering failed synchronization retries and concurrent
creators. Failure-injection tests exercise these boundaries. The native Unix
and Linux container checks do not establish an equivalent Windows power-loss
guarantee or test physical storage failure.

## Follow-up hardening

The combined Cluster/TLS test reproduced a startup failure while the Docker
engine and Redis nodes remained healthy. The pinned pool library interpreted
an unspecified minimum as the maximum, so startup waited for 32 cluster
connections per pool. Four concurrent revocation tests exhausted the existing
two-second initialization deadline; the same tests passed sequentially. Both
Redis backends now verify one real connection at startup and grow on demand,
retaining the 32-connection cap and two-second checkout deadline. Two regression
tests cover verified startup, growth and exhaustion, and unavailable-backend
refusal. The unchanged four-thread Linux contracts then passed in 7.38 seconds.
Their failed and passing results, source hashes, and cleanup record are under
`/tmp/agentvisor-production-validation/cluster-tls-final`.

A second pass reproduced and fixed console failures during database outages
and shutdown. Logout now reports a retryable failure when the shared revocation
write fails, retains the cookie for retry, and avoids a misleading success
audit. The browser displays the failure and resumes its live stream. After a
notification bridge recovers, clients on local and peer API instances reconnect
and refetch committed database state. Generation checks and explicit cancellation
prevent failed or stalled connection attempts from leaving live sockets behind.
PostgreSQL handshakes have a five-second bound, and shutdown closes active SSE
responses before waiting for the HTTP server to stop.

Nine focused console regressions, thirteen real two-instance recovery checks,
and four browser logout assertions passed. Seven additional fixture regressions
verify ownership-checked cleanup after ambiguous Docker failures, cancellation,
and repeated signals; cleanup removes the owned PostgreSQL volume as well. Database readiness recovered in
0.531 seconds on the last repeat; an earlier attempt took about 14.15 seconds.
The recovery drill records samples within a 40-second diagnostic bound. These
observations are not a production recovery-time guarantee. See the updated
[console record](../server/VALIDATION.md) for the source and evidence paths.

The nightly backup now uses a private connection service file, keeps database
credentials and the encryption passphrase out of command arguments, and uploads
only a verified encrypted archive. It decrypts the archive and compares its
bytes before publishing. Temporary plaintext and owned child processes are
removed on handled failures, deadlines, and repeated cancellation signals.
Seventeen helper regressions and ten disposable-fixture cleanup regressions
passed. An actual PostgreSQL 18.6/GnuPG 2.2.40
fixture passed six restore and encryption checks over 10,000 rows, including
incorrect-passphrase and modified-ciphertext rejection. The database, temporary
credentials, and image were removed. The workflow has a 15-minute helper deadline
and a 25-minute job bound; tests and the restore drill now run in console CI.
This does not prove access to production backup artifacts or their vaulted key.

The preceding console image `av-deployment-console:20260924-recovery` was rebuilt from
62 verified source inputs. It passed 22 basic API checks, all 110 API/data-adapter
assertions, 14 real daemon crash-to-console assertions, and seven packaged
entrypoint lifecycle tests. Migration refusal, non-root read-only operation,
native library loading, database outage recovery, and SIGTERM exit were also
verified. A fixture-origin mismatch initially caused three expected CSRF
rejections; the runner now supplies the configured allowed origin, and the
production allowlist and test assertions remain unchanged. Earlier interrupted
and failed attempts are retained beside the passing result under
`/tmp/agentvisor-recovery/deployment/console-recovery-runtime/configured-origin`.

A further review found no verified safer supported replacement for the current
console base. Its 22 reported operating-system findings remain visible, with
zero HIGH or CRITICAL findings. Alternative images were rejected where source
patch coverage did not substantiate a scanner improvement. No findings were
suppressed to obtain a lower count.

The next runtime review reproduced two MCP execution defects before fixing them.
A backend that sent small chunks within every idle timeout could retain an
admission slot indefinitely. Outbound MCP requests now have a separate total
network deadline, including response-body reads, configured with
`mcp_request_timeout_s` and defaulting to 60 seconds. Tests cover both a connected
caller and a caller that disconnects during the response. For these response-body
timeouts, the daemon records one durable failure outcome, prevents a retry from
repeating the tool effect, and releases the admission slot, session lease, and
pending work. A timeout before response headers can leave execution uncertain;
the existing claimed intent prevents an unsafe repeat of possible remote effects.

The second defect allowed a synchronous database refund to block the asynchronous
request executor. Refunds now run on a blocking worker and remain owned by the
detached request until both session and principal compensation complete. A
controlled blocked refund proves that other asynchronous work can proceed,
caller cancellation does not abandon compensation, and the same previously
unexecuted request can retry without a stranded claim or exhausted budget.
All six targeted MCP tests and 58 configuration tests passed; the two slow-stream
tests and refund test also have recorded failures against the previous code.
Evidence and frozen source hashes are under
`/tmp/agentvisor-production-validation/runtime-followup`.

This deadline bounds the outbound HTTP operation. It does not cancel effects
already performed by a remote tool or bound local authentication, storage,
audit publication, or the entire incoming request. Chat streaming retains its
separate read-idle semantics. Shutdown derives from both configured network
timeouts, while an explicit shutdown limit continues to take precedence.

The new provider drill passed nine tests against the fresh release binaries,
including actual loopback HTTP forwarding, complete SSE validation, usage in a
signed receipt, signature and tamper checks, credential isolation, refused
provider authentication, malformed completion markers, startup failure, and
cancellation cleanup. Independent review caught and closed false-success cases
for invalid completion reasons and mismatched choice indexes. Evidence is under
`/tmp/agentvisor-production-validation/provider-followup`; the real-provider
credential limitation is recorded below.

Release publication now depends on the complete reusable console workflow as
well as image validation. Pull-request build jobs have read-only credentials.
Each required architecture builds a local OCI archive, runs its packaged API
and startup checks, and retains an unfiltered vulnerability report. A separate
main-only job verifies the archive hashes, runtime configuration, filesystem,
scan binding, and embedded provenance/SBOM before copying the tested bytes.
Convenience tags move only after the required attestations succeed, and Fly
receives the checked immutable digest. Standalone and reusable console runs
have distinct cancellation groups.

All 27 release-policy regressions passed. A real loopback registry rehearsal
preserved the two platform archive digests and all four runtime/attestation
descriptors through index assembly and promotion. It also exposed a BuildKit
requirement missed by the fake-registry tests: the local export needs an image
name for its attestations to bind their subject. The workflow now supplies that
name without publishing during validation. The actual arm64 console image passed
22 API checks, 110 end-to-end assertions, seven entrypoint tests, database
outage/recovery, and graceful shutdown. Its full scan still reports 15 MEDIUM
and seven LOW findings, with no HIGH or CRITICAL findings. The first local copy rehearsal used a small scratch amd64 fixture. A later
repeat used both real application artifacts, as described below; native amd64
CI remains required. No GHCR publication, GitHub OIDC signing, or Fly deployment
was performed locally. The initial evidence remains under
`/tmp/agentvisor-production-validation/release-followup/result.json`.

The console follow-up fixed three reproduced authentication defects: SAML
logout could report success after a failed revocation write, OIDC discovery
failures escaped the browser error redirect, and a deferred password-reset
request could install a token after the account's email address changed. The
last write now matches both the user identifier and the email originally read.
The final combined Node run passed 28 tests, including seven new authentication
contracts, the existing recovery tests, and five fixture cleanup tests.

The new image then passed 17 checks against actual PostgreSQL 16.15 with two
production-mode API containers and private HTTPS/SMTP fixtures. A SQL barrier
reproduced the stale email lookup; concurrent reset confirmations consumed one
token exactly once. An injected API-key revocation failure rolled back password,
reset-token, and session-fence changes. Successful reset rejected old cookies
and API keys on both replicas. SAML revocation failure retained retry state,
and its retry revoked the peer session. Discovery recovery, accepted/rejected
mail, and absence of reset tokens in application logs also passed.

Five fixture cleanup tests cover ambiguous Docker creation, cancellation,
diagnostic failures, foreign ownership, and a stalled database close. The
successful real run removed its owned containers, network, and private files
with no cleanup errors. Earlier setup failures and mismatches in fixture
expectations remain preserved; they are not counted as passes. The proof does
not establish external enterprise SSO or mailbox delivery. Distributed SAML
request state was subsequently implemented and verified below. Details and
required CI invocation are in the
[console validation record](../server/VALIDATION.md).

A subsequent SAML drill reproduced successful signed login on one API replica
and failure when the callback reached another. AuthnRequest state now resides
in PostgreSQL with the browser nonce hash, tenant, configuration, and expiry.
A conditional deletion after cryptographic validation permits exactly one
callback to succeed. The migration is additive, but in-flight ceremonies from
older processes cannot be transferred from their private memory; users must
restart those logins during an upgrade.

The native production-mode drill passed 29 checks with two API processes and
actual PostgreSQL. It held both replica deletions at a SQL barrier and used
two different valid assertion IDs for one request, proving that the request
check itself enforces single consumption. Process and database restart,
wrong browser/configuration/tenant, unknown request, expiry, invalid signature,
issuer and audience, failed inserts and deletions, bounded cleanup, and raw-log
secret checks passed. Evidence is under
`/tmp/agentvisor-production-validation/saml-shared`.

The shipped browser flow now labels SAML as an available sign-in option,
propagates discovery failures instead of reporting missing configuration, and
explains how to retry unavailable request state. Seven checks passed in each
of Chromium, Firefox, and WebKit (21 total) against an owned discovery fixture.
These browser checks cover rendered messages, entered email, navigation,
return paths, and recovery; signed callbacks use the independent PostgreSQL
drill above. The required CI workflow includes both drills. Browser evidence
is under `/tmp/agentvisor-production-validation/saml-browser`.

The preceding SAML console image was built for both actual architectures from the same
63-file source snapshot. Each passed 22 API, 110 end-to-end, seven entrypoint,
29 SAML, and 17 external-authentication checks, including migrations, read-only
non-root execution, database outage/recovery, and graceful shutdown. ARM64 ran
natively; the AMD64 application and its native dependencies ran under the
host's existing Rosetta support. This is functional execution evidence, not
native AMD64 performance evidence. Full Trivy 0.74.0 scans found no HIGH or
CRITICAL issues and retained all 15 MEDIUM and seven LOW findings per image.

A second owned loopback registry rehearsal used the real policy verification,
staging, and promotion code with both complete application archives. It
preserved all four runtime/attestation descriptors and the immutable merged
digest `sha256:d378b0ba7d1396e9301afaca772d6a4aba3f86be1a1b1495a8d6559dd831d2ae`.
The workflow identity was explicitly synthetic and the destination local;
this does not claim GitHub OIDC signing or GHCR publication. All owned registry,
API, database, and private fixture resources were removed. The source hashes,
image IDs, archives, scans, reports, and cleanup record are indexed in
`/tmp/agentvisor-production-validation/amd64-console/final-image-provenance.json`.

A separate failure-injection pass found that a tool could perform its effect
before sending response headers, then time out without a durable outcome.
The daemon now marks that session's capture incomplete before releasing its
lease. Close retains the primary authenticated intent, and repeated recovery
continues to refuse duplicate execution. A failed outcome write receives the
same protection. Completed records are archived only when both the typed
outcome and its completion-audit marker authenticate successfully.

Further tests reproduced receipt creation after the affected session was
evicted from the bounded registry, and after startup found an authenticated
intent without recoverable session metadata. Close and fresh unsigned receipt
promotion now inspect durable tool evidence after draining active work.
Unresolved evidence, scan limits, authentication failures, and read failures
refuse finalization without deleting evidence. The failure is retryable, so a
valid outcome awaiting its completion audit can still finish through replay.
Startup checks unresolved intents independently of the bounded quarantine cache;
missing or invalid session metadata prevents the listener from starting.
Authentic metadata deferred by bounded recovery remains eligible for a later
pass. The lifecycle check protects receipt integrity after eviction; it does
not promise that every new chat reusing an evicted identifier is refused at
admission. Operator recovery and complete-spool backup requirements are in
[spool and recovery](reference/SPOOL-AND-RECOVERY.md).

All 23 targeted MCP tests passed, including the seven reproduced orphan,
eviction, unsigned-promotion, missing-audit, and storage-read regressions.
The maintained release-binary drill then passed 55 checks with actual loopback
HTTP effects, withheld response headers, signed and unsigned workflows,
close/promotion refusals, process restart, unchanged authenticated intents,
and exactly one remote effect per workflow. Deliberately removing metadata from separate
owned spool copies caused explicit startup refusal without losing the intent
or changing the healthy original. The daemon hash matched before and after,
and all private fixtures were removed. Failed test-first cases, passing tests,
and the final drill are retained under
`/tmp/agentvisor-production-validation/mcp-header-timeout`; the final result is
`release-drill-durable/result.json`. CI now runs the maintained drill after its
release build and retains selected daemon logs and result JSON on failure,
excluding private fixture files.

## Expiry, startup, and browser follow-up

The next pass reproduced a token-introspection race using both a bounded Rust
test and the previous release daemon with actual Redis. The revocation read
began before expiry and returned after expiry, while the old daemon still
reported the token active. Introspection now checks the clock again after the
read. Three Rust regressions preserve live-token behavior, inactive expired
tokens, and the unavailable response for storage outages. The fresh daemon
passed all 11 real-Redis checks with an approximately 1.10-second delayed read,
below the unchanged two-second storage timeout. Failed and passing evidence,
binary hashes, timing, and owned-fixture cleanup are under
`/tmp/agentvisor-production-validation/identity-expiry-followup`.

Console migration startup previously ignored the documented database aliases
until after Prisma had already failed. A shared normalization module now makes
the entrypoint and API select the same database, preserving explicit
`DATABASE_URL` precedence. Public link settings now require valid absolute
HTTPS URLs in production and reject credentials, fragments, and queries;
development HTTP remains supported. All 22 startup regressions, TypeScript
checks, and the build passed. The actual Prisma CLI also advanced from its
old missing-variable error to the deliberately unavailable loopback database.
Evidence is under `startup-boundary-followup` in the same validation directory.

Browser recovery no longer treats an audit outage as an empty final page.
Failed pagination preserves displayed rows and the cursor for a visible retry.
Non-object JSON errors retain their HTTP status, authentication expiry event,
and rate-limit handling. Stream recovery now queues one replacement, ignores
events from retired connections, and cancels pending reconnects on unsubscribe.
The five focused regressions include the actual audit page. They passed against
a frozen, minified console in Chromium, Firefox, and WebKit. Firefox initially
timed out during navigation before the UI assertions; an unchanged repeat passed,
and both attempts remain recorded. SAML recovery separately passed seven checks
in each of the three browsers against that snapshot.
CI now exercises this pinned Pages minification recipe for console browser
tests. The three minified application scripts total 82,252 bytes with gzip;
the old 28KB checklist claim was corrected. This measurement excludes HTML,
CSS, images, and other scripts and is not a complete page-load measurement.

An isolated PostgreSQL fixture also reproduced deterministic ingest errors for
NUL characters in event body or subtitle text. Those fields now reject NUL
before event writes and return HTTP 400. Eleven real-database checks verified
repeated refusal, rollback, corrected retries, verbatim Unicode/newline/tab
content, and the existing HTTP 422 response for cumulative counter overflow.
The maintained API suite adds 18 assertions for these boundaries. These records
and the browser source hashes are under `console-trust-followup` in the same
validation directory. No existing service was restarted for these fixtures.

A subsequent compatibility check confirmed that the CLI needs no NUL handling
change. Its event bodies already serialize payload text as JSON, which escapes
NUL. Strict ATIF validation rejects control characters in model names and tool
identifiers; bridge tool subtitles are sanitized before upload. Four actual CLI
capture cases, each run twice, verified these boundaries, unchanged evidence
bytes, and no duplicate accepted events on the second pass. The capture used
synthetic strict-format evidence and a loopback validator; it did not claim
daemon signatures or a PostgreSQL round trip. Evidence is under
`/tmp/agentvisor-production-validation/console-nul-followup`.

## Notification and deployment follow-up

A later bounded review reproduced five PostgreSQL notification failures using
real `pg` clients and an owned protocol peer: a stalled `LISTEN`, a stalled
initial reset, a stalled publication, an unbounded publication queue, and an
idle listener that stopped receiving traffic while its publisher remained healthy.
The console now puts a five-second deadline on each query, even when the database
URL requests a longer timeout. It probes an idle listener every 15 seconds and
limits pending publications to 256. A failed query or overflowing queue closes
the affected clients and reconnects; the recovery notification resets SSE streams
so clients refetch committed data. Local delivery remains available during the
interruption. The readiness response marks the bridge healthy only after the
initial reset is acknowledged; database health still determines its HTTP status.

All 27 focused tests passed: five actual-protocol regressions, nine existing
multi-instance contracts, and 13 fixture cleanup tests. TypeScript checking also
passed. The protocol peer verifies driver and socket behavior; the separate
PostgreSQL drill exercises actual database recovery. One intermediate fixture
asserted cleanup before Node delivered its socket-close events. The fixture now
awaits those events and still requires zero remaining sockets; the failed log
is preserved under `console-stream-followup` in the validation directory.

The authenticated full-stack Compose configuration previously enabled the
unauthenticated dashboard on the container network. It now disables that surface
and removes the wildcard-bind exception. With the same frozen daemon, anonymous
requests to the HTML dashboard and both tested JSON endpoints changed from 200
to 404; anonymous chat remained 401. All 59 parsed configuration tests passed.
The Cloud Foundry manifest now declares HTTP readiness at `/readyz`. Its guide
records the required platform versions and operator-confirmed shutdown grace:
120 seconds is a minimum for the explicitly timed phases, not an overall bound
on cooperative background work. Twelve local configuration checks passed; no
Cloud Foundry foundation was accessed.

The delayed-Redis expiry drill is now required on every PR and main push.
Its 11 assertions passed again against both the retained full-feature daemon
and a newly built Redis-only daemon matching the new job's feature selection.
The release scanner is pinned by its verified multi-platform digest. Console CI
also requires source and packaged notification fault tests and the packaged
two-instance database drill. These workflow changes passed local linting;
no hosted GitHub run or external deployment was performed.

The new gateway is a configuration-only derivative of the preceding tested
image. Comparison of all 185 retained inputs found only the shipped Compose
TOML and one test-only Rust addition; production Rust source is unchanged.
Both rebuilt console architectures share one 65-input snapshot whose sole
change from the startup baseline is `src/lib/bus.ts`. The new local images are:

| Image | Local image identifier |
| --- | --- |
| `av-deployment-gateway:20260924-compose-auth` | `sha256:d9e05bc719b1ba6eff241ffbf6e531f5dad6f6f70ed4c9dc334e2e84616e555d` |
| `av-deployment-cf:20260924-compose-auth` | `sha256:7dd8675d722e49e82de45b22f8707d80b764a2e1e43030ab510d516553838c49` |
| `av-release-console:20260924-bus-recovery-arm64` | `sha256:f98431e81e4d080eb6c83d117170fef321f1319f9589d475ff6bcfcec8f80d7f` |
| `av-release-console:20260924-bus-recovery-amd64` | `sha256:a4973ab2c4289b95459dc1035c0713366202ea86445450672bb83a2a031155ac` |

Evidence for this follow-up is under `continuous-followup`,
`console-stream-followup`, `deployment-contract-followup`, and
`deployment-contract-images` within `/tmp/agentvisor-production-validation`.
The earlier broad suite and immutable image records below retain their original
source and scope; they are not new runs of every suite after this follow-up.

## Evidence

| Check | Result and scope |
| --- | --- |
| Rust correctness | The final isolated all-feature workspace run passed 1,654 tests across 85 suites in 388.93 seconds with zero failures. Three release-only performance tests were excluded from this debug run. Live Redis, Kafka, NATS, Qdrant, MiniLM, and S3-compatible endpoints were configured. The run used four test threads and two compiler jobs. |
| Rust build checks | Strict all-target/all-feature Clippy passed. Rust 1.94, workspace without default features, isolated sandbox/cold-store feature checks, warning-denied rustdoc, and schema/config checks passed. |
| Dependencies | `cargo deny --all-features check` passed advisories, licenses, bans, and sources. The TLS stack uses rustls 0.23.45 for RUSTSEC-2026-0285. Cargo audit reported zero unignored vulnerability findings; transitive maintenance warnings remain. |
| Live security behavior | The real-daemon security drill passed 83 checks with local state and 114 with shared Redis, including revocation across replicas, restart, storage outage, recovery, authorization, and credential isolation. Six release-binary quickstart and receipt checks also passed, including tamper and forgery refusal. |
| MCP uncertainty and recovery | All 23 targeted tests and 55 real-daemon assertions passed. The latter used the final release binary, real loopback effects, two workflows, restart, and deliberately damaged spool copies. No duplicate effect or incomplete receipt occurred; evidence and original metadata were preserved. |
| Secure broker contracts | NATS 2.15.0 TLS/authentication passed 1/1; Redpanda 26.2.2 TLS/SCRAM passed 1/1. Certificate and invalid-credential rejection were also checked. |
| Redis Cluster | Storage contracts passed 8/8 and shared revocation passed 7/7 against three masters and three replicas. All six nodes shared one container; independent-host failover was not tested. |
| Console | A two-instance operational drill passed 25 checks using 100,000 seeded events and 3,000 authenticated requests at an offered 50 requests/s for 60 seconds. It used native Node 26.8.1, at most 12 requests in flight, 64 simulated client IPs, and two SSE subscribers. All workload requests returned HTTP 200 without tenant leaks. The 82.6 MB database, containing 115,322 final events, restored with identical table fingerprints and working API credentials, receipts, and quarantine. This bounded workload is separate from the Node 22 container smoke test and does not establish maximum capacity. The current packaged API contracts passed 128 checks per architecture, in addition to 22 basic API checks. Fifteen database drill suites, browser engines, mobile, accessibility, and receipt verification passed. See [console validation](../server/VALIDATION.md) for exact commands, counts, and limitations. |
| Crash to console | The actual daemon SIGKILL/restart/CLI synchronization drill passed all 14 unchanged assertions against the startup-fix console image and final expiry binaries in 23.12 seconds on its isolated repeat. The fixture used its own private signing key across both starts. The interrupted session was quarantined without a receipt; a new complete session sealed separately. The exact binary/image pairing and cleanup are recorded under `expiry-images/console-crash-repeat`; the first startup failure is preserved separately. This path is required in console CI, which preserves startup diagnostics on failure. |
| Buildpacks | Twelve unit tests passed. Actual CNB detect/build/export/non-root launch and classic supply lifecycle checks passed using isolated fixture distributions. No real Cloud Foundry foundation was accessed. |
| Helpers | Ten live-helper unit tests and syntax/whitespace checks passed. ShellCheck findings in the database drill runner were corrected. |
| Fuzzing | All six seeded targets passed, with 9,061,521 executions in total and no reported crashes, sanitizer errors, or timeouts. Each target ran for approximately 61 seconds after compilation, starting from 40 committed seeds across the suite. |
| Release performance | The preceding Redis-pool source passed the core gate, authenticated Redis diagnostic, and strict concurrent gate. All 10,000 exact SSE responses completed in 139.604 seconds; admission p95/p99 were 0.727/1.286 ms. Audit work drained in another 263.744 seconds with zero pending jobs and zero worker errors. The authenticated diagnostic measured p95/p99 of 7.413/46.248 ms and has no latency acceptance threshold. These benchmarks were not repeated after the later MCP and introspection changes. Before/after service records were healthy and unchanged. Earlier watchdog-interrupted failures remain preserved. See [benchmarks](../BENCHMARKS.md) for exact scope and evidence. |
| Container images | The current gateway and console images built and passed non-root, read-only-root runtime checks. The daemon streamed a real mock-provider response, verified receipts, refused tampering, and preserved the original stored receipt and signing key across restart without duplicate publication. The console passed migrations, 22 API checks, crash synchronization, database outage/recovery, and graceful shutdown. |
| Container dependencies | The daemon image's full Trivy scan reported zero vulnerabilities. The console now uses pinned Distroless Node 22/Debian 13. Its unfiltered scan reports zero critical or high findings; 15 medium and seven low findings remain, all unfixed. No findings were suppressed. See the release-review detail below. |
| Kubernetes | All 36 checks passed against the final expiry-evidence gateway image on Kubernetes 1.35.0 in an isolated local kind cluster in 255.81 seconds. Actual Secret projection, non-root/read-only execution, probes, identity and scope refusal, complete SSE and tool forwarding, receipt verification, pod replacement, and stable signing/receipt state passed. Authenticated TLS Redis failed closed during an outage and retained revocations through pod recreation and snapshot restoration onto a fresh volume. All fixture resources and credentials were removed; existing service start times and VM boot identity stayed unchanged. This single-node test does not establish production CSI, ingress, external identity, or multi-host behavior. |

The expiry follow-up passed all six native gates in the serialized repeat:
release build, 1,654 tests across 85 suites, strict all-target/all-feature Clippy,
Rust 1.94, minimal features, and warning-denied rustdoc. Three release-only
performance tests remain intentionally excluded from the debug run. This result
is recorded under `/tmp/agentvisor-production-validation/expiry-final-repeat`.
The failed concurrent run remains under `expiry-final`, with no source changes
between attempts. The native daemon SHA-256 is
`c7219f43746a8ccb23ac1810cfdea76e2c910b265e87b5c9c1038748d2f280ef`;
the CLI SHA-256 is
`0678189b9089cacc1a0c37fad9e86ce2a215bf73484482c8be8f6c12d4f2677e`.
Those exact binaries passed all 203 live assertions: 83 with local state, 114
with shared Redis, and six quickstart/receipt checks. The runs took 20.567,
47.564, and 4.440 seconds. Hashes matched before and after; every observed owned
process group and temporary fixture was removed. The completed record is
`expiry-final-repeat/live/attempt-i1075vvm/result.json` in the validation directory.
The preceding durable-evidence run passed 1,651 tests and 203 live assertions;
its distinct source and logs remain under `durable-tool-final`.
The preceding timeout/persistence pass, before the final orphan and eviction
guards, passed 1,642 Rust tests and all 203 live checks; that separate evidence
remains under `/tmp/agentvisor-production-validation/saml-tool-final`.

The preceding native release build, 1,634-test workspace run, strict Clippy, Rust
1.94 check, minimal-feature check, and warning-denied rustdoc all passed.
The same frozen release binaries then passed all 203 live checks: 83 local-state
checks, 114 shared-Redis checks, and six quickstart/receipt checks. All observed
owned processes and fixture directories were removed, and binary hashes matched
before and after. This evidence is under
`/tmp/agentvisor-production-validation/runtime-final`. That daemon SHA-256 is
`7dee692e2c18e7dd9ebb97721fc3dd59e4ffe99fe5e24da9eacac2896f1a6720`;
the CLI SHA-256 is
`93e3b5939e2667c374dc86287eab00504630315689cfe5a104c8e9a542f392e8`.

The preceding native build, 1,630-test workspace run, and compiler/documentation
checks are recorded under `/tmp/agentvisor-production-validation/pool-final`.
The stable release binaries then passed all 203 live security and receipt
checks on the first attempt: 83 local-state checks, 114 shared-Redis checks,
and six quickstart/verification checks. The separate single-node Redis TLS
repeat passed all 17 Rust contracts with no skipped tests. Binary hashes,
exact commands, elapsed times, and owned-fixture cleanup records accompany the
logs. The daemon hash is
`8122542aecd564e4b2a8721681d07081dfa6a6d010a924f95ab762b3667d36d4`;
the CLI hash is
`fee970735a5a5bf64bba0eb88a3981f48efde09b5dbddaec867ec88aa6331cce`.

## Reproduction

The regular gates remain `make ci`, `cargo deny --all-features check`, and the
console CI workflows. Endpoint-gated tests count as live tests only when the
corresponding environment variables point to working services.

```sh
cargo test --workspace --all-features
cargo build --release -p av-harness --bin agentvisord \
  -p av-cli --bin avctl --features av-harness/redis,av-cli/redis
scripts/live-pillars.sh
scripts/live-pillars.sh --redis redis://127.0.0.1:6379
python3 scripts/redis-tls-test.py --output-dir /tmp/agentvisor-redis-tls-results
python3 scripts/mcp-uncertainty-test.py --agentvisord target/release/agentvisord \
  --output-dir /tmp/agentvisor-mcp-uncertainty-results
# Requires a local redis-server executable; creates its own private instance.
python3 scripts/introspection-expiry-test.py --agentvisord target/release/agentvisord \
  --output-dir /tmp/agentvisor-introspection-expiry-results
python3 scripts/secure-contract-fixtures.py start
# Use the printed private directory, add Kafka, and source its env.sh.
python3 scripts/secure-contract-fixtures.py add-kafka PRIVATE_DIRECTORY
(
  . PRIVATE_DIRECTORY/env.sh
  cargo test -p av-bridge --all-features --test live_contract
  cargo test -p av-state --all-features --test redis_contract
  cargo test -p av-harness --all-features --test revocation_redis
)
python3 scripts/secure-contract-fixtures.py stop PRIVATE_DIRECTORY
make fuzz-smoke
python3 buildpack/tests/lifecycle.py --download-pack
python3 scripts/compose-secrets-test.py
AVCTL=target/release/avctl python3 scripts/kubernetes-runtime-test.py \
  --image agentvisor-ai:local
```

The Kubernetes drill requires a locally built `agentvisor-ai:local` gateway
image, kind, and kubectl. Its prerequisites and deployment boundaries are in
the [Kubernetes guide](../deploy/kubernetes/README.md).

The fuzz runner retains seed hashes, exact commands, exit codes, and any crash
artifacts in a fresh ignored corpus directory. Its default is 60 seconds per
target, with a fixed random seed, a per-input timeout, and memory/input limits.
This bounded run is a smoke test, not proof that every input is safe.

## Container security review

The preceding gateway and Cloud Foundry images include the introspection expiry
fix and were built from 185 verified workspace inputs plus a recorded generated
build recipe. Both console architectures use one 65-file snapshot that includes
the startup and ingest fixes. The source archive and per-platform evidence are
under `startup-console-images`; the combined evidence index for that stage is
`/tmp/agentvisor-production-validation/expiry-images/final-evidence-index.json`.

| Earlier expiry/startup image | Local image identifier |
| --- | --- |
| `av-deployment-gateway:20260924-expiry-evidence` | `sha256:33e51416da9270c4b802948c3cb977e662fce698134e585e6ac97daef645385b` |
| `av-deployment-cf:20260924-expiry-evidence` | `sha256:a40b4f1bdd045fee510675b9ef7e1819826b4d3db96a4fba05e04d456cb1a45c` |
| `av-release-console:20260924-startup-arm64` | `sha256:2cb985a6c7b5f141f60ed3e914558670217addd9417abaed361b27b381aaa58d` |
| `av-release-console:20260924-startup-amd64` | `sha256:08b1639ded91878cc967f163fcbfb16e274311c2bcd439ac3e727db52b57598e` |

The gateway passed non-root operation with a read-only root filesystem,
complete streaming, receipt signature and tamper checks, and restart persistence
without duplicate receipt publication. The Cloud Foundry configuration validated
using its packaged CLI. Each received one complete scan with the pinned CI
scanner, Trivy 0.74.0, reporting zero findings with no filters or ignore rules.
The reports bind to the exact image IDs and inventory the operating system and
both Rust executables.

Each console image applied all 22 migrations with only `POSTGRES_URL`, and
passed 22 basic API checks, 128 end-to-end checks, 16 entrypoint lifecycle tests,
29 shared-SAML checks, and 17 external-authentication checks. Non-root/read-only
execution, failed-primary-database precedence, database outage/recovery, and
SIGTERM exit also passed. Their full pinned Trivy 0.74.0 scans retained
15 MEDIUM and seven LOW findings each, with no HIGH or CRITICAL findings.
ARM64 executed natively; AMD64 used the host's existing Rosetta support.
No native AMD64 performance result is claimed.

Those console archives also passed the local release-policy rehearsal.
It preserved all four runtime/attestation descriptors through verification,
staging, and promotion, with merged digest
`sha256:739699c78c558e97091bca20f37ffc55a2834b5629b5823cd3f028abecc33e6c`.
The destination was an owned loopback registry and its workflow identity was
synthetic. The result does not establish GitHub OIDC signing, GHCR publication,
or cloud deployment. Its source, image, scan, and cleanup records are indexed in
`/tmp/agentvisor-production-validation/startup-console-images/final-image-provenance.json`.

The preceding durable-tool images and their distinct source, scans, runtime
checks, and crash pairing remain indexed under
`/tmp/agentvisor-production-validation/durable-tool-images/final-image-provenance.json`.

The preceding deadline-fix images below remain available locally. Their 185
gateway source inputs and 62 console inputs were checked against the workspace.
That source snapshot, scans, runtime logs, and crash pairing remain indexed in
`/tmp/agentvisor-production-validation/runtime-followup-images/final-image-provenance.json`.
The earlier SAML console artifacts used a separate 63-input snapshot; the
startup-fix artifacts and both architectures from that stage are recorded above.

| Image | Local image identifier |
| --- | --- |
| `av-deployment-gateway:20260924-runtime-deadlines` | `sha256:724f5bf8fcd219cacd2ee0a9a4d080465689eea84fb9c7ab9b4309e07ff88575` |
| `av-deployment-cf:20260924-runtime-deadlines` | `sha256:5488d7e20bb8f07f5772ae89e8bc030fb6c652962a0b2aecefc1b051960dc4f3` |
| `av-release-console:20260924-auth` | `sha256:c508f90ff0a38dded02d510d17b56aa4fe9d7658bb425664e413b1a7682d781a` |

The new gateway passed non-root, read-only runtime, complete streaming, receipt
signature/tamper, and restart persistence checks without repeating the receipt
event. The packaged Cloud Foundry configuration validated. Both unfiltered image
scans contain zero findings. The console passed the packaged API, authentication,
startup, outage/recovery, shutdown, and current-binary crash checks described
above. The exact CI scanner, Trivy 0.74.0, was also run against that image; its
report bound to the tested image and passed the release policy, retaining all
15 MEDIUM and seven LOW findings. GitHub execution and cloud deployment remain
outside this local result. The previous images and evidence below are retained
for comparison and rollback.

The console now uses pinned Google Distroless Node 22/Debian 13. Its runtime
contains Node, Prisma, and required libraries, with no shell or package manager.
A Node entrypoint applies migrations, preserves migration failures, forwards
shutdown signals to the child process group, and starts the API only after
successful migration. Both the health check and startup use executable form.
The previous Node/Trixie image remains available locally for rollback.

The preceding full, unfiltered Trivy 0.72.0 console report contains zero critical
and zero high findings, 15 medium findings, and seven low findings. All remaining
findings are unfixed: 13 medium and seven low findings concern `libc6`, and two
medium findings concern `zlib1g`. No ignore rules, unfixed filtering, or package
metadata removal was used. Trivy still inventories 14 OS and 156 Node packages.
The eight high-severity CVEs affecting unnecessary packages in the previous
runtime are absent from this smaller runtime. This is a dated scan result,
not a guarantee against future vulnerabilities or deployment-specific risk.

The preceding console image is `av-deployment-console:20260924-recovery`, with
local image ID
`sha256:2e5f68cc8d873f3525ddf5e5b1cd08fcd7bd6601b8b74468f0c4fef25f3cae9a`.
It is Linux arm64, approximately 131 MB, and runs as UID/GID 65532. Actual
migrations, migration refusal, native Prisma/OpenSSL compatibility, 22 basic API
checks, 110 API/data-adapter assertions, 14 daemon crash-to-console assertions,
database outage/recovery, and SIGTERM exit status zero passed with a read-only
root filesystem. All seven entrypoint lifecycle tests passed inside the actual
Linux/Node 22 image. The crash drill used the preceding revocation-fix native
daemon and the unchanged CLI; it uses local state and does not exercise the
later Redis pool change. Exact binary hashes, all 62 packaged source inputs,
failed attempts, and cleanup evidence are retained under
`/tmp/agentvisor-recovery/deployment/console-recovery-runtime/configured-origin`.
The previous Distroless image remains available locally for rollback.

The preceding gateway image is `av-deployment-gateway:20260924-redis-pool`, with local
image ID `sha256:77e713529916c558e73af5991f7d921ad05e4dcf6a18c074ee607dc4404086a3`.
It is Linux arm64 and approximately 128 MB. Its unfiltered scan reports zero
vulnerabilities across the Wolfi runtime and both Rust executables. Checks passed
for non-root execution, streaming with a read-only root filesystem, receipt
verification, tamper refusal, and persistent restart. The receipt event was not
duplicated after restart. The Cloud Foundry image is
`av-deployment-cf:20260924-redis-pool`, with local image ID
`sha256:563734a0af1736b5a55186f9683fd67eafb1bdfcf04474c10cf75ed096db633f`;
its packaged CLI accepted the deployment configuration, and its full scan also
reported zero vulnerabilities. The 185 workspace build inputs matched that source snapshot; the additional
generated Dockerfile is hash-verified in the retained build archive.
Reports and owned-resource cleanup evidence are retained under
`/tmp/agentvisor-recovery/deployment/gateway-redis-pool-runtime`.

## Environment and remaining deployment checks

The first full run of the expiry follow-up passed 1,652 tests and failed two
checks during concurrent builds: a five-second signed-audit drain wait and a
two-second Qdrant request. Qdrant's logs show that the write completed in
2.53 seconds. Its uniquely identified test collection was verified and removed.
The first final daemon/console attempt also missed its unchanged 15-second
startup deadline before any crash/recovery assertions ran. Source and binary
hashes stayed unchanged. Those failures, cleanup records, and a bounded resource
diagnostic remain under `expiry-final/failure-review` and
`expiry-images/console-crash` in the validation directory. The diagnostic found
substantial host swap usage while shared services remained healthy. That makes
resource contention plausible; it does not prove a single cause for every timeout.
Subsequent validation runs were serialized without relaxing deadlines or assertions.

An outer live-check wrapper also timed out while collecting an unscoped host
process inventory, although its local helper logged all 83 passing checks and
removed its private fixture. The wrapper now inspects only its own process group
with the same five-second bound and cleans up on inspection errors. The complete
203-check repeat passed. The original wrapper failure remains under
`expiry-final-repeat/live/attempt-8do3vdmc`; the application was unchanged.


The host was macOS on an Apple M4 Pro with 24 GiB of memory. Rust tests used 1.97.1, with a separate
minimum-version check on 1.94. Docker images ran on Linux arm64 through Colima.
Colima's host forwarding failed during the first full test run while its VM
and services remained healthy. Temporary SSH connections restored access
without restarting user services; the affected Redis contracts then passed.
That temporary connection later closed. Normal Docker access subsequently
recovered outside this task, and the final release measurements used the
restored normal connection. The task's temporary tunnel is no longer active.

The Docker VM also rebooted during an earlier 10,000-request audit drain,
stopping its services around 09:42 UTC and restoring them at 09:43:12 UTC.
That run failed with 1,568 reported worker-job errors and is not counted as
successful. The earlier successful repeat passed the unchanged latency and zero-error
checks, with unchanged container start times. Audit drain took 371.344 seconds
after response completion; it must not be hidden inside an admission-only
performance claim. A later investigation identified the external Docker
watchdog as the source of the restart commands, including this incident.

A later watchdog restart at approximately 10:13 UTC interrupted a container build;
the unchanged build passed after Docker recovered. No agent restarted the VM
or the existing user services. During concurrent validation, an interim debug
run also hit five existing ten-second pipeline deadlines. The unchanged
49-test pipeline suite passed in isolation; the final workspace sequence uses
four test threads and two compiler jobs. No test deadlines were increased.
Another run caught the outdated assertion that `rustls-pemfile` was absent;
the security audit and its consistency test now record the Redis TLS dependency
and its maintenance warning.

During concurrent final-binary validation, one operator revocation request
returned a retryable HTTP 503, leaving the shared Redis drill at 113/114 checks.
The following introspection refused the token. Redis connection errors were
logged nearby, but the exact failed storage operation was not captured.
The unchanged suite then passed all 114 checks in 25.928 seconds after competing
builds and tests finished. Together with 83 local-state and six receipt checks,
all 203 live checks passed against the preceding revocation-fix binaries. Both attempts are retained
under `/tmp/agentvisor-production-validation/revocation-final`; no assertions or
timeouts were relaxed.

One debug daemon attempt exceeded the crash drill's 15-second readiness bound.
The unchanged binary subsequently became healthy in 3.634 seconds, and the
complete release-binary crash drill passed with the original bound. The failed
attempt remains recorded. Boot failures now preserve a private diagnostic log;
the crash fixture also uses its own signing seed rather than the workspace key.

An intermediate 10,000-request run, before the final revocation fix, was also
interrupted by that watchdog.
Its log records `colima restart` at 10:52:54 UTC; guest Docker shutdown began
at 10:52:55 UTC, and all five existing services restarted at 10:54:53 UTC.
The task stopped only its failed test process group, after 641 worker-failure
log entries, and retained the result. The external LaunchAgent runs
`/Users/zacharie/waterfalls_app/scripts/docker-watchdog.sh` every 120 seconds.
It previously restarted Colima when `docker info` failed. Subsequent simultaneous read-only
checks found its default Docker Desktop socket unresponsive while the Colima
socket returned healthy. The recorded live client failure also targeted that
Desktop socket. A process-scoped Colima target and direct health-probe
replacement passed 17 checks. The proposed diff and results are retained under
`/tmp/agentvisor-production-validation/watchdog-proposal`. After the user instructed
the task to proceed, the reviewed fix was applied at 11:04:55 UTC with the original
owner and mode preserved. An old invocation had already initiated one more restart
at 11:04:32 UTC; that in-progress command was allowed to finish. No agent restarted
or stopped the existing services. The next scheduled invocation exited successfully
by 11:15:03 UTC without restarting the VM or any of the five existing services.
Their start times remained unchanged from the 11:05:23 UTC baseline. The subsequent
concurrent repeat passed after service health was restored, using the corrected
Colima endpoint explicitly. Its before/after snapshots confirmed healthy services
with unchanged runtime records; the audit drain completed without worker errors.

Local API tests used simulated identity providers and a dummy SMTP endpoint.
Daemon integration drills used local mock model and tool providers; they did
not call paid external model APIs. A read-only OpenAI credential preflight at
12:58:17 UTC returned HTTP 401 with `invalid_api_key`; no billable generation
was attempted. The sanitized result is under
`/tmp/agentvisor-production-validation/provider-followup/credential-preflight.json`.
The opt-in [provider drill](../scripts/provider-smoke.py) now provides a repeatable
authenticated stream, usage, receipt-signature, and tamper check once a valid
key and explicit model are configured. Verify the selected production provider's
credentials, protocol, quotas, and streaming behavior in the target environment.
The local Kubernetes drill used a private CA, mock providers, one kind node,
and local-path volumes. Its final-image result and cleanup record are under
`/tmp/agentvisor-production-validation/kubernetes-staging-expiry`.
The preceding durable-tool and runtime-deadlines results remain in their separate evidence directories.
During the final repeat, Docker's local `docker-ai` plugin hung while kind
requested client metadata. A bounded fixture watcher terminated only the
verified metadata children descended from that drill. The node then started;
Docker configuration, credentials, and existing services were preserved.
Production email delivery, the selected enterprise identity provider, public
TLS/DNS, ingress and network policies, production CSI storage, backup restoration
at production data volume, multi-host failover, sustained workload capacity,
and a real target cluster/foundation still require validation in the deployment
environment. The Kubernetes manifest is a template requiring operator
configuration; no remote cluster was modified.

The follow-up Cluster/TLS and console image tests encountered a separate host
transport failure. The guest Docker engine remained reachable through a private
SSH connection while Colima's host Docker socket and forwarded TCP ports stopped
responding. One owned SSH forward recorded `poll: Invalid argument`; the exact
cause was not established. Child-only descriptor limits were bounded, and the
combined cluster tests were moved into Linux to avoid the host forwarding path.
The external watchdog initiated further Colima restarts at 12:09:32 and 12:19:41
UTC, interrupting test attempts and restarting the existing services. No agent
initiated those restarts. Interrupted logs and unchanged-binary retry results
are retained separately; interrupted commands are not counted as passes.

A narrowly scoped watchdog patch now checks the Docker engine inside the guest
before taking recovery actions when host forwarding is unavailable. Eleven
extracted tests and a live read-only guest probe passed. Following the user's
instruction to finish the remaining work, the reviewed patch was applied to the
separate `waterfalls_app` project at 12:57:42 UTC. The original hash, owner, group,
and mode were checked, and replacement was atomic. The watchdog was not invoked
and no VM or service was restarted by the task. Evidence is under
`/tmp/agentvisor-production-validation/watchdog-followup/applied-followup.json`.
The patch does not repair forwarding or establish its underlying cause.

Raw logs are retained on the validation host under
`/tmp/agentvisor-production-validation`, `/tmp/agentvisor-console-*`, and
`/tmp/agentvisor-recovery`. Temporary logs are not durable release artifacts;
CI should retain the corresponding logs for the commit being released.
