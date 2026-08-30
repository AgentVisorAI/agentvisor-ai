# Console engineering handbook

The console under `docs/app/` graduates into the final product. This file is
the institutional memory of the 100+ hardening rounds that shaped it: the
invariants the code relies on, the bug classes we already paid for, and the
traps that bit the test harness. **Read this before changing `app.js`,
`styles.css`, or any drill** — every rule below exists because its absence
shipped a real bug that CI now guards.

For what the console *is* (modes, fixtures, tour), see [README.md](./README.md).
For the test suites, see [`server/scripts/`](../../server/scripts/) and the
catalog at the bottom.

---

## Architecture in one minute

- **Hash-routed SPA, no framework.** `render()` in `app.js` parses
  `location.hash`, rebuilds the shell (`renderShell()`), and dispatches to a
  route renderer. `renderShell()` **replaces `#view` wholesale on every route
  change** — which is why late async continuations from an abandoned route
  paint into a *detached* node and can't stale-paint (do not "optimize" this
  away without adding per-route render tokens everywhere).
- **Swappable datasource.** `window.dataSource` (mock or api) is bound once to
  `state.ds`. The mock mirrors real API semantics deliberately: cursor
  pagination, event paging (500/page), member redaction sentinels, single-use
  reset tokens, live audit entries for every mutation. Keep it honest — every
  place the mock lied ("Preview as member" showed unredacted LLM bodies, the
  audit log ignored your own actions) eventually embarrassed a demo.
- **URL is the state of record.** Filters, sort, ranges, and event selection
  live in the hash (`#/sessions?q=…&status=blocked&sort=cost.desc`,
  `#/overview?range=7d`, `?evt=<seq>`) via `replaceState` (no history spam).
  Back/forward, reload, and shared links must all reproduce the view.

## Invariants (violating any of these re-introduces a shipped bug)

**Rendering & async**
1. `navigate()` renders. Never call `render()` right after `navigate()` —
   the double render races parallel list fetches (clobbered `sessionsLoaded`).
2. Quiet refreshes (stream-driven, visibility/online catch-up) go through the
   `schedule*Refresh` helpers: **fetch first, repaint only on success, re-check
   the route after every `await`.** A failing background refresh must never
   replace a live view with the error card, and a mid-fetch navigation must
   never be painted over.
3. Same-route re-renders (sessions filters) use the monotonic
   `_sessionsFetchSeq` token: only the newest fetch may touch
   `sessionsLoaded`/`sessionsCursor` or paint. The filter bar keeps its
   listeners until a *winning* response repaints (repaint-then-fetch dropped
   keystrokes mid-debounce).
4. Buttons painted during a loading skeleton must be wired through a
   **document-level delegated listener** (`#addPol`, `#addDep`, the
   whole sessions filter bar — `#fSearch`/`#fRange`/`#fDep`/`#fAgent`/
   `#fBlocked` — and the overview `.range-group`): direct wiring after
   the fetch left dead controls for the first ~500 ms; typed text sat
   in the search box while the unfiltered list painted below.
   The static-page variant: buttons in `/verify/` HTML ship `disabled`
   and `verify.js` enables them once handlers attach — on a slow CDN the
   script arrives well after first paint, and a pre-wire click silently
   did nothing (caught by the venue-wifi rehearsal in CI, run 33224907811).

**Modals & overlays**
5. The modal contract, all call sites: double-open guard on `body.locked` →
   append → lock → capture `previouslyFocused` → `installModalKeys(backdrop,
   close)` → `close()` removes, unlocks, uninstalls, restores focus.
   `installModalKeys` without a close callback poisons every later Escape.
   `showTokenModal` **no-ops while the body is locked** — close your own
   modal first (the regenerated SP cert was silently never shown).
   Dirty-modal discard guard (in `installModalKeys`): Escape or a
   backdrop mis-click on a modal with unsaved edits blocks once +
   toasts; the second attempt within 2s discards. Explicit Cancel
   (`data-close`) stays immediate. Navigation-forced closes (browser
   Back / Android gesture → hashchange) can't be vetoed after the
   fact — a dirty discard there toasts "unsaved changes … discarded"
   instead of dying silently. Dirtiness = value vs defaultValue /
   defaultChecked / defaultSelected — prefill via HTML attributes, not
   post-render property writes, or the guard will false-positive.
6. The palette closes on `hashchange` and on a **capture-phase document
   Escape** (the input-level Escape missed the pre-autofocus window and
   wedged the backdrop). The body-level hashchange sweep removes both
   `.modal-backdrop` and `.cmdk-backdrop`. It re-fetches its dynamic
   entries (sessions/policies/deployments) on **every open** — never
   cache the index, or deleted entities become ghost links (drill 32).
   The app registers **no unload/beforeunload handlers** — that keeps
   every engine's bfcache eligible; freshness after a Back-restore is
   `visibilitychange` + `online` → `refreshCurrentView()` (drill 32
   asserts the zero-handler invariant via the `__lc` listener census).
7. Global shortcuts (`g`-nav, `/`, `?`, `[`/`]`) no-op while `body.locked` —
   g-nav's hashchange used to destroy an open form modal.
8. Stacking scale (documented at the `.tabbar` rule): topbar 20 · tabbar 90 ·
   modal 100 · palette 200 · hint 300 · account menu 500 · launcher 900
   (hidden while locked) · tour 950 · toasts 1000 (pointer-transparent).
   New floating chrome picks a slot deliberately; nothing interactive may sit
   above a backdrop (tab bar at 400 destroyed modals; the launcher at 900
   covered Save/Cancel on phones).
9. `.modal .actions` is a sticky bottom bar so long forms (SAML) keep
   Save/Cancel reachable on phones without scrolling.

**Input & interaction**
10. Row-click navigation is suppressed while a text selection is live
    (`textSelActive()`), in the global delegate and per-table delegates —
    selecting an id to copy used to navigate away.
11. Every mutating control carries an in-flight guard (`disabled`/
    `aria-busy`, re-enabled on error). A double-click once created two
    identical webhooks with two secrets.
12. `pushToast()` caps the stack at 4. Toasts are informational only —
    `#toastStack` is pointer-transparent.
13. Scroll memory: `render()` saves `scrollY` per exact hash on the way out
    (never zero — a stale restore-to-0 raced user scrolls); list renderers
    call `restoreScrollFor(location.hash)` once after the data paint.

**Data & hostile input**
14. Every render sink goes through `esc()`. `decodeURIComponent` is always
    try/caught. Unknown settings tabs redirect; unknown ids hit the
    not-found card. The `?evt=` auto-pager is bounded (cursor end + 5000
    cap). The router fuzz in drill check 9 keeps this true.
15. Formatters never emit `NaN`/`Invalid Date` — `timeAgo`, `usdMicros`,
    and the CSV writers all guard garbage (dash / $0.00 / 0.0000).
16. Every `localStorage`/`sessionStorage` **write** is try/caught (Safari
    private mode throws; the quota fuzz enforces this).
17. RBAC in the UI mirrors the API: members see no mutating controls
    (settings tabs redirect; SSO/members/invites are view-only; the details
    modal hides keypair regen). If the API would 403 it, don't render it.

**Theming & motion**
18. `config.js` applies the saved theme **pre-paint** (strict CSP forbids an
    inline head snippet). The OS-scheme `matchMedia` listener follows live
    flips only when no explicit choice is saved, and never persists.
    Theme changes must **never call `render()`** — theming is entirely
    CSS-variable-driven off `data-theme` (charts included; zero
    `getComputedStyle` reads), the account menu rebuilds its label per
    open, and a re-render wipes live widget state (typed filters, the
    selected event + drawer, loaded pages, scroll). All three paths
    (in-app toggle, OS flip, cross-tab storage follower) are
    `applyTheme`-only; drill check 30 guards it.
19. Reduced motion is a **global kill-switch** (0.01 ms durations, not
    `none`). Never go back to enumerating animated elements — the list
    drifted twice.
20. CSS source order: equal-specificity rules appended at file end silently
    beat earlier responsive overrides. Mobile overrides live AT FILE END of
    `styles.css`, on purpose, with a comment. Append below them or raise
    specificity.
21. Cross-tab: sign-out (`av_signed_out_at`), sign-in (`av_signed_in_at` via
    `announceSignIn()` at every auth-success site), and theme all sync via
    storage events. Signup drops `av_return_to`; login honors it.
22. `announceRoute` focuses `#view` after navigation ONLY when focus has
    collapsed to `<body>` (or was inside the old `#view`). Focus sitting
    in a persistent body-level overlay (tour card) must survive route
    changes — the unconditional steal stranded keyboard users mid-tour
    on every cross-route step (drill check 31).
23. Fresh-workspace truth: everything a fresh org sees or creates
    belongs to THAT org. Mutations write to `freshRuntime()` (keyed on
    the raw t0 value), never to the Northwind `MOCK_*` fixtures — a
    fresh create that touches a fixture array is invisible in the
    fresh list AND leaks into the showcase org. Identity surfaces
    (sim-daemon name, `org.created` audit target, the members list,
    the attack-sim user) derive from `freshIdentity()`; canned session
    clones re-time their event trails via `_retime` (proportional
    squeeze into the fresh window) and receipts sign the DISPLAYED
    fresh values. Chronology is monotonic: org.created(t0) → defaults
    seeded → deployment.create → pubkey_first_set → sessions — nothing
    may predate t0, and every derivation reads ONE stable epoch
    (freshT0Ms(), the raw storage value): recomputing `Date.now()−el`
    took a second clock read a millisecond later, so each fetch
    re-timed the workspace by its own jitter and a receipt fetched
    twice signed different bytes (drill check 33 caught the 1ms
    straddle once in dozens of runs — clock reads are per-derivation
    nondeterminism, hoist them). Showcase-only
    affordances hide there too: the guided tour (launcher pill,
    palette entry, AND `?tour=1` autostart — it narrates Northwind's
    numbers) and the 30-day-dataset toggle (fresh `listSessions`
    ignores the flag; the entry would be a lying no-op). The attack
    sim gates on `ds.freshDaemonReady()` — hidden until the daemon
    connects (a staged session can't exist while deployments still
    says "run the install command") and again after the daemon is
    deleted; the overview ⚡ button and the palette entry consult the
    SAME gate so the two surfaces can't disagree. Fresh-key presence
    flips (signup set / reset removal) propagate cross-tab: a storage
    follower reloads parked tabs so none wears the old org's chrome
    over the new org's data — latched on PRESENCE (not value; clock
    rewrites of the same workspace are ignored) and re-synced via
    announceSignIn after this tab's own auth writes (self-writes fire
    no storage event).
24. Boot fails LOUDLY when the data layer is missing: app.js throws at
    top level if `window.dataSource` is undefined (datasource.js
    aborted by a proxy / 404 mid-deploy), so the crash guard's card
    takes over. Without it, boot() succeeded, the login render cleared
    `#app` and died on `state.ds.*` — but `__avBooted` had already
    pacified the guard AND the empty-`#app` watchdog, leaving a
    permanent blank page. The guard's three nets: pre-boot
    window.error → card; unhandledrejection → card; 6s watchdog for
    scripts that never EXECUTE. Post-boot errors only log (an
    extension throwing mid-demo must not wipe a working console).
    Storage-denied boot (Safari lockdown: both storages THROW on
    access) works end-to-end — invariant 16's try/catch discipline
    covers reads too. WebCrypto can be absent ENTIRELY (old corporate
    webviews): every crypto.subtle call in the mock is wrapped or
    fallback'd — the one bare inline digest (the receipt's
    contentHash) used to error-card the whole session detail. The
    verify head degrades to its honest "?" unsupported state, /verify/
    names the supported browsers + the CLI alternative, and the crash
    card is role=alert + focused (drill check 34).

**Evidence & print**
22. The printed evidence pack is COMPLETE: `@media print` forces
    `.evt-hidden` rows visible, and the provenance footer states the event
    count + a partial-trail warning. On-screen triage never crops evidence.

## Harness traps (each cost a debugging session)

- `page.goto` to the **same hash URL** is a same-document navigation — it
  renders nothing. Enter checks via a real route change.
- `?tour=1` in a boot URL **survives `page.reload()`**; the tour autostart is
  once-per-tab via sessionStorage, but fresh contexts re-arm it.
- In-memory sessions bounce public routes (`#/reset`, `#/accept-invite`)
  before a reload: set the signed-out flag, reload, **then** set the hash.
- Programmatic `.click()` does not collapse a prior drag-selection the way a
  real mouse click does — clear the selection or use Playwright clicks.
- After a form-swap re-render, wait for the *new* form's sentinel value
  (e.g. `#token`) before interacting — clicking mid-swap grabs the detached
  old form.
- Chromium drops elements from `elementsFromPoint` when their edge enters an
  `overflow:hidden` ancestor's padding zone — action columns have explicit
  `th.act-N` widths sized for the widest label variant.
- `input` elements without a `type` attribute do not match `[type=text]`.
- Uniform injected latency hides ordering races — make the FIRST request
  slow and the second fast to prove last-write-wins bugs.
- Zero-match probes are worse than none: ground-truth checks must **fail
  loudly when a probe query matches nothing** (fixture drift tripwire).
- Probe pages in the SHARED drill context write to the same
  per-origin localStorage as every other check: a probe that sets
  `av_mock_signed_out` / fresh-mode keys and closes without cleanup
  breaks the NEXT check (empty webhooks in fresh mode, login bounces).
  Always restore the keys before `page.close()` — this bit THRICE
  (the third bite: check 29's `addInitScript` fresh keys put checks
  30–32 into a fresh workspace; they "passed" there by coincidence
  until the palette check created a deployment and it vanished —
  which turned out to be a REAL fresh-mode bug, not just a leak).
  Corollary since the cross-tab fresh follower: REMOVING (or first
  SETTING) `av_mock_fresh_t0` from a probe page fires a presence
  flip in every parked page of the shared context, which reloads
  itself mid-whatever-the-next-check-does ("interrupted by another
  navigation" on the next goto). After a probe restores fresh keys,
  wait for the parked main page to settle (`waitForSelector
  .app-shell`); same-presence value rewrites are safe.
- Suites default `SITE` to **production**. A positional arg passed to a
  script that only reads the env var is silently ignored — an entire
  "local" drill once ran green against the live site while the local
  changes under test were never exercised. The drills now accept the
  target as env `SITE` or `argv[2]`; when a "local" failure makes no
  sense, first check `location.href` inside the page.

## Test suite catalog (`server/scripts/`, run with `SITE=` override)

| Script | Guards |
|---|---|
| `interactive-drill.mjs` | 35 checks: tour, attack story, onboarding ages, billing math, reset flows, hit-tests + unsized-svg blowouts, storage/router fuzz, pagination + deep links, Back/overlays, double-submit, failure paths + catch-up, cross-tab + FOUC, focus rings/traps + reduced motion + shortcut guards, garbage data, filter/sort/chart/audit/detail ground truth, deployment + key lifecycles, member RBAC, leak soak, form semantics (native validation + Enter submits), skeleton-phase filter liveness, dirty-modal discard guard, theme-toggle state preservation, keyboard-only tour, palette mutation-truth + bfcache eligibility (no unload handlers), fresh-workspace truth (org-named daemon, isolated mutations, founder identity, org audit story, showcase-affordance hiding), hostile environment (storage-denied boot, dead-script crash card role=alert+focus + Reload recovery, WebCrypto-less detail + honest ? state), scripted-pitch manual walk (verify green → tamper red) + de-DE locale |

**Audit-slug parity**: mock `recordAudit` slugs and the `MOCK_AUDIT`
fixtures mirror the REAL taxonomy in `server/src/lib/audit.ts`
(`deployment.create`/`.delete`, `saml.config_*`, `saml.keypair_rotated`,
`member.invite_revoked`, `org.retention_updated`, `auth.login`/`.logout`,
`audit.exported_csv`, `deployment.pubkey_first_set` for the fresh
"daemon connected" moment). Webhook pause/resume records
`webhook.updated` with a paused/resumed NOTE — the real PATCH writes no
dedicated slug. Documented demo-forward exceptions (no server
equivalent yet): `policy.created/updated/enabled/disabled` and
`policies.defaults_seeded` (server has no policy CRUD routes).
Never invent a slug — check audit.ts first; the audit chips
self-generate from the category prefix, so a renamed slug silently
re-files its rows.

**Receipts exist only at seal**: the real API 404s a running session's
receipt (the daemon posts it AT seal) and the console renders "No
signed receipt yet". Mock `getReceipt` mirrors this for
`status === "in_progress"` with the SAME note string — signing a
running session showed "✓ verified" on bytes that then CHANGED at
seal, the exact opposite of the tamper-evidence pitch. The detail
header's Copy/Share/Download disable (with the reason in `title`)
while unsealed; Print stays (it truthfully prints the trail + note).
The attack demo's staged rerenders pass the session id so a viewer
parked on the detail page sees the panel flip live at seal+300ms
(the random subscribe tick almost never matches that session id) —
drill check 2 pins the whole unsealed→sealed transition.
| `live-site-smoke.mjs` | 11 checks: link/media crawl, captions, alias stubs, 404, OG/Twitter link previews, video-metadata truth (durations + zero MediaErrors), install-promise (the exact URL app.js prints serves the real installer; live runs also assert the public README leads with working commands) |
| `a11y-audit.mjs` | 46 axe scans: 11 routes + 9 modal states × 2 themes, 3 static pages × 2 schemes |
| `mobile-smoke.mjs` | phone/tablet: tab bar, taps, modals fit + hittable + stacking, static pages |
| `verify-page-drill.mjs` | 12 checks incl. download→drop→green / tamper→red |
| `receipt-verify-drill.mjs` | download → CLI verifier + tamper matrix |
| `full-flow-rehearsal.mjs` | ONE continuous session in narrative order: landing CTA → tour → verify finale → attack → receipt → fresh signup → reset. `PROFILE=phone` reruns it as the QR-code path on an iPhone profile; `SLOW=1` adds 300–700ms venue-wifi jitter to every datasource call |
| `engine-matrix.mjs` | nightly: 11 features × chromium/webkit/firefox (incl. sticky headers, dirty-guard, theme-state) |
| `lighthouse-audit.mjs` | budgets, re-measures once on a miss (runner variance ±23) |

CI: `console-smoke.yml` (22-min timeout; nightly adds engines).
`server/`-only changes don't trigger the Pages deploy — dispatch
`console-smoke` manually to prove them against production. The Pages workflow
**cherry-picks published files** — new static assets (e.g. `.vtt`) must be
added to its copy list or they 404 only in production. Live CDN caches for up
to ~20 min post-deploy; verify with etags or functional probes, not comments
(assets are terser-minified in the workflow).

## Repo topology (public monorepo, public exports)

This monorepo is **public again** (flipped back 2026-08-30: the
private stretch after the R228 restructure billed every Actions
minute against the org's free pool — 11,689 minutes exhausted it and
all workflows started refusing with zero-step instant failures;
public repos get free minutes; a secret scan of tracked content and
post-privatization history preceded the flip). The deploy pipeline
still uses two public snapshot repos — do NOT re-point Pages at the
monorepo; the site-repo pipeline is certified and the domain claim
lives there. Both snapshots are force-pushed content exports (no
history, never edit them directly — the next export overwrites
everything):

- `AgentVisorAI/agentvisorai.github.io` — the ASSEMBLED site.
  `pages.yml` builds (rustdoc + terser) and pushes over SSH using the
  `SITE_DEPLOY_KEY` secret. Its Pages serves `agentvisorai.me`
  (legacy branch build off `main`, `.nojekyll` in the artifact).
- `AgentVisorAI/agentvisor` — the public binary tool: the Rust
  workspace + every compile-time-included path + the offline
  verifier at `tools/verify-receipt.mjs`. `publish-tool.yml` exports
  an explicit INCLUDE list via `TOOL_DEPLOY_KEY`. If a crate gains a
  new `include_str!` outside the list, the public build breaks —
  extend the list AND the workflow's `paths:` trigger.

Public site pages link `github.com/AgentVisorAI/agentvisor` (the
curated tool repo) — keep it that way even while the monorepo is
public; the tool repo is the stable public artifact. EXTERNAL
PROMISES (URLs/commands the product tells users to run elsewhere)
must be guarded: the onboarding install command shipped for weeks
pointing at get.agentvisorai.me, a host that never existed in DNS —
the installer now lives at agentvisorai.me/install.sh (same Pages
artifact, no DNS dependency), installs agentvisord + avctl via
`cargo install --git` from the public repo, and smoke check 11
fetches the EXACT URL the deployed app.js prints. Public-consumer
chain certified BY EXECUTION (R270–R272): fresh clone compiles; real
`cargo install --locked --git` produced both binaries; the printed
`agentvisord start --token` was REFUSED by the fail-closed CLI (fixed
to `avctl setup`); `avctl setup` exits gracefully on non-TTY EOF;
`doctor --offline` fails loudly on exactly the unset provider key and
passes with it; `avctl start` served /health and PROXIED a live
chat/completions request (upstream's own 401 for a dummy key proves
the pipe); tools/verify-receipt.mjs accepts a production receipt.
The public README's `cargo install av-harness av-cli` pointed at
crates.io entries that were NEVER published — quickstart now leads
with the installer one-liner + --git form (crates.io note stays for
the future release). Re-run the chain by hand when the export
include-list or CLI surface changes. Beware squatters: another
worktree's daemon on :8484 answered a health probe meant for a
daemon that had failed to start — always probe on an overridden
AV_LISTEN port. deploy.yml's
attestation steps gate on `!github.event.repository.private` (the
attestations API 403s for private repos on this plan) and resume
automatically on pushes made while public. If the repo ever goes
private again, budget Actions minutes FIRST.
