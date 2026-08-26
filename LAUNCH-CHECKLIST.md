# AgentVisor AI — Launch Checklist

Every item below has been implemented and drill-verified on the current
branch. Links point either to the file where the code lives or to the
runbook entry that documents how it was verified.

Legend: **✅ verified** · **🟢 configured** · **📋 documented**

---

## 1. Security

| # | Item | Status | Reference |
|---|---|---|---|
| 1.1 | HTTPS-only in production (fatal boot check) | ✅ | [server/src/index.ts](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/server/src/index.ts) |
| 1.2 | JWT signed with 256-bit secret (auto-generated in dev, fatal in prod without env) | ✅ | [server/src/env.ts](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/server/src/env.ts) |
| 1.3 | JWT tampering rejected (alg=none, wrong secret, expired) | ✅ | [docs/RUNBOOK.md](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/docs/RUNBOOK.md) |
| 1.4 | HttpOnly + Secure + SameSite=Lax cookie for the session | ✅ | [server/src/routes/auth.ts](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/server/src/routes/auth.ts) |
| 1.5 | Argon2id password hashing (@node-rs/argon2) | ✅ | [server/src/lib/auth.ts](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/server/src/lib/auth.ts) |
| 1.6 | Rate limit on auth endpoints (login 10/min, signup 5/min per IP) | ✅ | [server/src/routes/auth.ts](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/server/src/routes/auth.ts) |
| 1.7 | Ingest endpoints exempt from global rate limit | ✅ | [server/src/index.ts](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/server/src/index.ts) |
| 1.8 | CSRF: Origin allow-list on mutating verbs | ✅ | [server/src/index.ts](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/server/src/index.ts) |
| 1.9 | CSRF: Sec-Fetch-Site defense-in-depth (blocks `cross-site`, passes `same-origin`/`same-site`/`none`) | ✅ | This round — see [server/src/index.ts](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/server/src/index.ts) |
| 1.10 | X-Requested-With required on state-changing routes (SPA sets it) | ✅ | [docs/app/datasource.js](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/docs/app/datasource.js) |
| 1.11 | SQL injection resistant (Prisma parameterized, verified with `pg_sleep`, `DROP TABLE`) | ✅ | This round |
| 1.12 | XSS defense — event drawer uses opt-in isHtml tuple, everything else escaped | ✅ | [docs/app/app.js](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/docs/app/app.js) |
| 1.13 | Strict CSP: `default-src 'none'; script-src 'self'; script-src-attr 'none'` | ✅ | [docs/_headers](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/docs/_headers) |
| 1.14 | HSTS + upgrade-insecure-requests | ✅ | [docs/_headers](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/docs/_headers) |
| 1.15 | Pino logger redacts `authorization`, `cookie`, `password`, `token`, `ingestToken` | ✅ | [server/src/lib/auth.ts](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/server/src/lib/auth.ts) |
| 1.16 | Real Ed25519 receipt verification in the browser (no lies) | ✅ | [docs/app/datasource.js](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/docs/app/datasource.js) |
| 1.17 | Deployment ingest token rotation flow with one-time-view modal | ✅ | [docs/app/app.js](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/docs/app/app.js) |
| 1.18 | Role enforcement (owner-only for destructive endpoints) | ✅ | [server/src/routes/auth.ts](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/server/src/routes/auth.ts) |
| 1.19 | Secrets never committed (grep of repo, .env in gitignore) | ✅ | [.gitignore](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/.gitignore) |
| 1.20 | Trivy scan in CI (blocks on HIGH/CRITICAL) | ✅ | [.github/workflows/deploy.yml](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/.github/workflows/deploy.yml) |
| 1.21 | SBOM + SLSA attestation attached to every image | ✅ | [.github/workflows/deploy.yml](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/.github/workflows/deploy.yml) |
| 1.22 | Dependabot with automatic patch-level merges | ✅ | [.github/workflows/dependabot-automerge.yml](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/.github/workflows/dependabot-automerge.yml) |

## 2. Operations

| # | Item | Status | Reference |
|---|---|---|---|
| 2.1 | `/healthz` liveness | ✅ | [server/src/index.ts](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/server/src/index.ts) |
| 2.2 | `/readyz` readiness (DB ping) | ✅ | [server/src/index.ts](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/server/src/index.ts) |
| 2.3 | `/metrics` (Prometheus, IP-allow-list gated) | ✅ | [server/src/lib/metrics.ts](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/server/src/lib/metrics.ts) |
| 2.4 | Request-id echoed on every response (grep-once ops) | ✅ | [server/src/index.ts](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/server/src/index.ts) |
| 2.5 | Problem+json (RFC 7807) normalized on all 4xx/5xx | ✅ | [server/src/index.ts](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/server/src/index.ts) |
| 2.6 | Nightly `pg_dump` backup workflow | ✅ | [.github/workflows/backup.yml](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/.github/workflows/backup.yml) |
| 2.7 | Backup restore drill run + documented | ✅ | [docs/RUNBOOK.md](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/docs/RUNBOOK.md) |
| 2.8 | Postgres LISTEN/NOTIFY bus with auto-reconnect | ✅ | [server/src/lib/bus.ts](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/server/src/lib/bus.ts) |
| 2.9 | SSE reconnect with exponential backoff | ✅ | [docs/app/datasource.js](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/docs/app/datasource.js) |
| 2.10 | Autocannon load-test job in CI (100k row bench) | ✅ | [.github/workflows/console-api.yml](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/.github/workflows/console-api.yml) |
| 2.11 | Cursor pagination on `/sessions` (O(log N)) | ✅ | [server/src/routes/read.ts](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/server/src/routes/read.ts) |
| 2.12 | Streaming NDJSON export (bounded memory on huge orgs) | ✅ | [server/src/routes/auth.ts](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/server/src/routes/auth.ts) |
| 2.13 | Session.orgId denormalized + compound indexes | ✅ | [server/prisma/schema.prisma](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/server/prisma/schema.prisma) |
| 2.14 | Fly.io + Render + Koyeb deploy manifests keyed off `/readyz` | ✅ | [server/fly.toml](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/server/fly.toml) · [render.yaml](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/render.yaml) |
| 2.15 | GHCR image push + PR preview comment | ✅ | [.github/workflows/deploy.yml](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/.github/workflows/deploy.yml) |
| 2.16 | Runbook covers 7 pre-launch drills | ✅ | [docs/RUNBOOK.md](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/docs/RUNBOOK.md) |

## 3. Product

| # | Item | Status | Reference |
|---|---|---|---|
| 3.1 | Google SSO (OIDC) | ✅ | [server/src/routes/oauth.ts](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/server/src/routes/oauth.ts) |
| 3.2 | Microsoft SSO (OIDC / Entra multi-tenant) | ✅ | [server/src/routes/oauth.ts](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/server/src/routes/oauth.ts) |
| 3.2b | **SAML 2.0 SSO** (Okta / Auth0 / Entra / any) — full SP with signed AuthnRequests, XML-signature verify, replay guard, JIT, RelayState round-trip, metadata endpoint, SP keypair regen | ✅ | [server/src/routes/saml.ts](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/server/src/routes/saml.ts) · [server/src/lib/saml.ts](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/server/src/lib/saml.ts) · [server/src/lib/saml-cert.ts](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/server/src/lib/saml-cert.ts) |
| 3.3 | Password reset via mailer with token expiry | ✅ | [server/src/routes/auth.ts](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/server/src/routes/auth.ts) |
| 3.4 | Mailer supports Resend, SMTP, or dev-stub | ✅ | [server/src/lib/mail.ts](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/server/src/lib/mail.ts) |
| 3.5 | Ed25519 signed receipts, verified in-browser | ✅ | [docs/app/datasource.js](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/docs/app/datasource.js) |
| 3.6 | Deployment onboarding: install curl + start daemon snippet | ✅ | [docs/app/app.js](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/docs/app/app.js) |
| 3.7 | Pitch demo flow (Setup → Connect → Sessions → Overview → Receipts → Data) | ✅ | [docs/app/pitch/index.html](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/docs/app/pitch/index.html) |
| 3.8 | Session URL deep-linking survives reload | ✅ | [docs/app/app.js](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/docs/app/app.js) |
| 3.9 | Command palette (⌘K) with async index | ✅ | [docs/app/app.js](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/docs/app/app.js) |
| 3.10 | Timezone: server UTC, browser renders in local TZ | ✅ | [docs/app/app.js](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/docs/app/app.js) |
| 3.11 | Long-string table truncation (table-layout fixed + per-cell ellipsis) | ✅ | [docs/app/styles.css](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/docs/app/styles.css) |
| 3.12 | Rate-limit UX countdown ("Try again in 5s") | ✅ | [docs/app/app.js](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/docs/app/app.js) |
| 3.13 | JWT expiry triggers graceful re-login (av-session-expired event) | ✅ | [docs/app/datasource.js](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/docs/app/datasource.js) |
| 3.14 | 404 route renders proper not-found (not generic error) | ✅ | [docs/app/app.js](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/docs/app/app.js) |
| 3.15 | Empty states on every list surface (sessions, policies, deployments, keys, audit) | ✅ | This round · [docs/app/app.js](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/docs/app/app.js) |
| 3.16 | Two-line table cells preserved after truncation fix | ✅ | This round · [docs/app/styles.css](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/docs/app/styles.css) |
| 3.17 | Session persistence across reload and new tabs | ✅ | [docs/RUNBOOK.md](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/docs/RUNBOOK.md) |
| 3.18 | Zero axe accessibility violations on core surfaces | ✅ | [docs/app/styles.css](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/docs/app/styles.css) |
| 3.19 | SPA gzip payload ≤ 28KB | ✅ | [.github/workflows/pages.yml](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/.github/workflows/pages.yml) |

## 4. Legal & Trust

| # | Item | Status | Reference |
|---|---|---|---|
| 4.1 | Terms of Service published | ✅ | [docs/legal/terms.html](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/docs/legal/terms.html) |
| 4.2 | Privacy Policy published | ✅ | [docs/legal/privacy.html](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/docs/legal/privacy.html) |
| 4.3 | `/.well-known/security.txt` served | ✅ | [.github/workflows/pages.yml](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/.github/workflows/pages.yml) |
| 4.4 | Legal linked from footer on public site | 📋 | [docs/app/index.html](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/docs/app/index.html) |

## 5. Documentation

| # | Item | Status | Reference |
|---|---|---|---|
| 5.1 | Top-level README explains the product | 📋 | [README.md](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/README.md) |
| 5.2 | Server DEPLOY guide (Fly, Render, Koyeb, Docker) | 📋 | [server/DEPLOY.md](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/server/DEPLOY.md) |
| 5.3 | CI/CD reference | 📋 | [CI-CD.md](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/CI-CD.md) |
| 5.4 | Runbook of pre-launch drills | 📋 | [docs/RUNBOOK.md](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/docs/RUNBOOK.md) |
| 5.5 | STATUS.md summarizing readiness | 📋 | [docs/STATUS.md](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/docs/STATUS.md) |
| 5.6 | Launch checklist (this doc) | 📋 | [LAUNCH-CHECKLIST.md](/Users/zacharie/llm_proxy.worktrees/mockup-demo-video-full-flow/LAUNCH-CHECKLIST.md) |

---

## Verified in Round 21

- **Two-line cell integrity**: `td { white-space: nowrap; text-overflow: ellipsis }` from round 20 does not collapse the stacked `name + .id` divs — playwright inspection confirmed both divs render at their expected top offsets (row height 61px, 2 lines) and the table stays within its 996px client width even with 600-char hostile payloads.
- **`.id` sub-line ellipsis**: added `overflow: hidden; text-overflow: ellipsis` to `td .id` so long external IDs also get a proper `…` instead of hard clipping.
- **Empty-state gaps**: `renderPolicies`, `renderSettingsKeys`, `renderSettingsAudit` all previously rendered a bare table when the list was empty. Fixed with `emptyState()` calls; verified via playwright by monkey-patching the mock datasource to return `[]`. Deployments list already had `deploymentEmptyHero`.
- **Sec-Fetch-Site**: legitimate SPA fetches (`same-origin`, `same-site`, `none`, or missing header) all pass; only literal `cross-site` gets a 403 `forbidden_cross_site`. Verified with 5 curl variants against a live server.
- **SQL injection**: `'; DROP TABLE users; --`, `' OR 1=1 --`, and `'; SELECT pg_sleep(3); --` payloads via `/api/v1/sessions?q=` all returned `{sessions:[], nextCursor:null}` in ~50ms with the users table intact. Prisma's parameterized `contains` filter is safe.

## Verified in Rounds 22-26

- **Body-size cap**: 5 MiB POST → 413 problem+json (Fastify `bodyLimit: 4 MiB`).
- **Unknown endpoint 404**: GET/POST to `/api/v1/nonsense/*` returns proper problem+json (not HTML).
- **Modal focus trap**: 5 modal openers share `installModalKeys` — Escape closes, Tab wraps, previously-focused element gets focus back, `role="dialog" aria-modal="true"`.
- **Copy-token button**: swaps to "Copied ✓" with green flash for 1.6s; clipboard genuinely holds the token.
- **SSE stale-connection watchdog**: named `keepalive` events every 15s + client watchdog force-closes if lastSeen goes stale >30s. Covers the Chromium bug where a killed peer keeps `readyState=OPEN`.
- **Ingest rollup dedup**: pre-filter batch by existing seqs so `promptTokens/costUsdMicros` only increment on genuinely new events.
- **Sealed session guard**: `POST /events` on `status=sealed` session → `{inserted:0, rejectedSealed:["externalId"]}`, DB unchanged. Un-sealing via upsert also blocked.
- **Concurrent signup**: Prisma P2002 caught and mapped to clean 409 email_in_use (was leaking `errorCode:"P2002"` + 500).
- **Confirm-modal replay**: 3 rapid clicks on danger confirm → 1 API call (`handled` flag).
- **Clock-skewed ingest**: `occurredAt > now+5min` or `< 2000-01-01` are silently dropped with per-batch counters in the response.
- **Hostile cursor**: 6 hostile inputs (SQL, path traversal, huge, junk) → clean `400 invalid_cursor`.
- **Reset-token single-use**: successful reset clears the hash, replay → `401 invalid_token`.
- **Concurrent-ingest rollup**: 3 parallel 100-event batches → exact 300/300/300 rollup (Prisma atomic `increment`).
- **Login brute-force**: rate limit fires at attempt 11; no email-vs-password oracle in the 401 body.
- **Cross-tenant IDOR**: user B fetching user A's session/deployment ID → 404, no data leak.
- **Ingest-token revocation**: post-rotate, old token → 401; new token → 200.
- **Receipt tamper**: Ed25519 verify (in-browser) rejects both body-modified and signature-modified receipts.
- **NDJSON export escape**: hostile agent name with commas, escaped quotes, and newlines round-trips as a valid JSON line.
- **Cursor pagination stability**: mid-scan inserts of 5 fresh sessions with later `openedAt` do not appear on page 2; zero overlap between pages.
- **Auth-before-404**: routes with real handlers return 401 without cookie; only truly unknown routes return 404.
- **HttpOnly cookie**: JS can't read `document.cookie`; ctx shows `httpOnly: true, sameSite: 'Lax'`.
- **Receipt XSS**: 8 hostile fields via monkey-patched getReceipt — zero alerts, DOM contains `&lt;script`.
- **Malformed JSON body**: 4 hostile bodies return proper problem+json 400.
- **Deep-link resume**: `sessionStorage.av_return_to` restores URL after login.
- **Cookie Secure default**: reads NODE_ENV — Secure=true in prod, false in dev; explicit override wins.
- **Login timing side-channel**: precomputed real argon2id dummy hash keeps missing-user latency within 5% of wrong-password latency.
- **Cross-tab sign-out sync**: `localStorage.av_signed_out_at` + storage event listener drops peer tab session immediately.
- **OAuth state**: missing / malformed / provider-mismatch cookies all 400 with proper `errorCode`.
- **Reset token expired**: 25h-old token → `401 expired_token`; DB untouched.
- **Sign-out cleanup**: SSE unsub + logout + state null + navigate to /login.
- **Ingest field length**: externalId >128, agent >80, tag >32, body >8000, batch >500 all return 400.
- **Prod security headers**: HSTS + CSP + X-Frame-Options + X-Content-Type + Referrer-Policy present on 200 / 400 / 401 / 404.
- **Concurrency load**: 200 concurrent GET /sessions on 100-row org → 200/200 clean at 314 req/s; no pool exhaustion.
- **CmdK keyboard nav**: `⌘K` opens with input focused; ArrowDown highlights results; Enter navigates; Escape closes.
- **Loading skeleton**: slow list request renders 6 skeleton rows in-place; cleanly swaps to real rows on resolve.
- **JWT weak secret**: production boot with `JWT_SECRET < 32 chars` fatal-exits with clear message.
- **Cross-deployment token**: `token A + header B` → 401; `token B + header A` → 401.
- **Chart 0 / 1 data points**: empty series renders 0 bars, no NaN; single point renders 1 bar cleanly.
- **JWT future NBF**: token with `nbf=now+3600s` → 401 (`jwtVerify` honors NBF).
- **Load-more events**: session detail Load-more accumulates across pages (5 → 8 after click); cursor null hides button.
- **Email normalization**: `"  AlIcE@T.CoM  "` stored as `alice@t.com`; login with mixed-case/spaces → 200.
- **Logout cookie clear**: `POST /logout` returns `Set-Cookie: av_session=; Max-Age=0`.
- **CORS disallowed origin**: `Origin: https://evil.com` gets NO `Access-Control-Allow-Origin` header.
- **CORS preflight**: OPTIONS returns `Allow-Origin`, `Allow-Credentials`, `Allow-Methods`, `Allow-Headers`.
- **Graceful shutdown**: SIGTERM → `"graceful shutdown starting"` log → clean exit in ~300ms → port freed.
- **Delete deployment cascade**: `DELETE /:id` → 204; deployments + sessions + events all drop to 0 rows.
- **Empty ingest batch**: `POST /events` with `[]` → `{inserted:0}` clean.
- **Malformed session upsert**: empty externalId, wrong-typed fields → 400 `invalid_input` (zod schema).
- **healthz + readyz not rate-limited**: 20/20 rapid calls to each → 200.
- **Hash XSS**: 6 hostile hashes (`<script>`, `<img onerror>`, encoded, path traversal, SVG onload) → 0 alerts fired, zero DOM script injection.
- **JWT iss/aud + org membership**: wrong iss/aud → 401; forged token with fake orgId → 401 (round-33 membership fence).
- **UTF-8 emoji + Cyrillic**: agent name `"🤖 assistant Ivan Иван"` round-trips through Postgres and Prisma `contains` filter.
- **Wrong HTTP method**: `PUT /sessions` / `PATCH /login` → 404 (no 500).
- **Prisma not-found**: `DELETE /deployments/nonexistent` → 404 problem+json (no P2025 leak).
- **JWT logout replay**: post-logout replay of captured cookie → 401 (round-34 `sessionRevokedAt` fence).
- **Membership check perf**: 200-concurrent GET /sessions → 429 req/s, zero 500s.
- **/metrics format**: 31 HELP + 31 TYPE lines, well-formed Prometheus scrape target.
- **Empty events detail**: 0-event session renders cleanly (`|| 1` guard on totalDur).
- **PII in error body**: no email echo on 401 invalid_credentials.
- **Ingest without cookie**: daemon auth (X-AV-Deployment + Bearer) works irrespective of session cookie state.
- **Ingest rate-limit exempt**: 30 rapid ingest calls → 30/30 200.
- **Log redaction**: pino redact + auth-handler discipline keeps passwords, ingest tokens, cookies out of every log line.
- **Member role forbidden**: non-owner member gets 403 on POST /deployments and DELETE /deployments/:id; still 200 on GET /sessions.
- **Big session perf**: 500-event mock session renders to DOM in 48ms.
- **SAML 2.0 end-to-end**: mock IdP with real openssl-generated RSA keypair signs a SAMLResponse XML with xml-crypto → POST to `/saml/<configId>/acs` → 302 with `av_session` cookie, RelayState round-trips (`#/deployments` preserved), JIT provisioning creates user + membership. `/me` confirms mint (email + displayName from attributes). Replay same POST → `400 replay_detected` (saml_replay_records table). Metadata XML valid, discovery-by-email returns config for allowed domains and `null` for others.
- **SAML hardening**: 5 attack scenarios all rejected — expired assertion (`NotOnOrAfter` in past) → 400 `signature_or_conditions_failed`; wrong `audience` URI → 400; assertion signed by different key → 400; non-owner member on POST/DELETE `/saml` → 403 (list still 200); JIT disabled + brand-new user email → 403 `jit_disabled`.
