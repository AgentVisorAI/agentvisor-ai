# Changelog

All notable changes are documented here. The project follows Semantic Versioning.

## Unreleased

### Review rounds 37–39: fourth-model residual measurement (2026-08-16)

A fourth reviewer model measured the residual after three on the three
historically richest files: seven findings, all prose, several
empirically disproven in the fixing (numeric IPv6 zone ids parse on
stable rustc 1.97.1 — `sa.ip()` is what discards the scope, contrary
to three comments; the single-winner provision primitive is
`hard_link(2)` EEXIST, not `create_new`/O_EXCL; the recovery-scan
256 MiB constant only classifies the `too_large` metric while the
64 MiB read cap does the buffering defence; a cited `write_config`
guard and a `write_cold_object_exclusive` function never existed; and
round 28's own edit had orphaned `probe_endpoint`'s doc line onto the
redactor). Sixteen borderlines adjudicated and rejected on the record.

Rounds 38–39 extended the measurement to eleven more files (pipeline,
session, cold_store, receipt; then routes, worker, config, main —
~18k lines): yields of 2 and 2, with routes.rs, main.rs, session.rs,
cold_store.rs and receipt.rs fully clean. All four finds were stale
shadows of earlier behavior changes: an accept-and-warn identity
bullet the shipped 401 rejection superseded (contradicted by its own
comment's closing paragraph), a phantom next-tick retry on the
response-slot drop path, a `None`-disables-timeout claim that
round-32 F4's unconditional 60 s floor had obsoleted, and a
Drop-ordering guarantee named bindings never provided.
Marginal-yield curve across the QC program: model 2: 40, model 3: 18,
model 4: 7→2→2 with rejection ratios near 10:1; every find since
round 27 has been prose, with the code correct at every site.

### Review round 36: third-model test-suite QC — three-model coverage complete (2026-08-16)

The third reviewer finished the integration-test suites, closing the
program at three independent models over every file in the repository.
Nine findings; the important ones were resolved by strengthening tests
rather than weakening docs: the CLI "help mentions every subcommand"
lists were missing five of the fourteen subcommands
(setup/start/init/doctor/health — both the discoverability and the
per-subcommand `--help` loops now cover all 14); the
Ed25519-determinism assertion was unreachable (all 200 oracle bodies
distinct — an explicit identical-body pair now proves RFC 8032
determinism); the 2^53-boundary receipt is verified, not just signed;
the tiny-inputs test now actually covers a single character. Prose
fixes: the all-zero Ed25519 key is the order-4 small-order point
(y = 0), not "the identity"; deep nesting lives in `stop_reason`, not
the receipt subject; "cross-workflow AND cross-identity" had no
cross-identity half here; the breaker coverage list promised "loop
convergence" where the design keeps the breaker Open until manual
reset (the mislabeled near-epsilon test is now
`progressing_content_never_falsely_trips`). Twenty-five borderline
candidates adjudicated and rejected on the record.

Program totals across rounds 17–36: three models × 100 % of src and
tests; ≈ 90 prose corrections, 7 strengthened assertions, 4 new tests,
3 code fixes (both halves of the doctor credential leak; a Drop-timing
release that a named `_`-binding could not deliver), ≈ 80 borderlines
adjudicated with recorded reasons, all echo families extinguished.

### Review rounds 33–35: third-model QC (2026-08-16)

Escalated the QC program to a third independent reviewer model on the
highest-stakes files. Fifteen findings across fourteen files, severity
still declining but nonzero — including the session's second genuine
code fix: `ResponsePermit::submit` documented an early permit release
that a named `_`-prefixed binding cannot deliver (named bindings live
to end of scope; NLL shortens borrows, not `Drop` timing) — the code
now performs the explicit `drop()` the comment always described.
Other notable corrections: `enforce_retention`'s headline claimed
unconditional cold export over a `cold_uri` guard (unset means expired
records drop without export — both arms now documented);
`verify()`'s numbered checklist was in reverse execution order; the
JWT validation checklist omitted its own first check (pre-auth 8 KiB
cap) and the `exp > iat` guard; a cited "manifest override" for the
cold outbox never existed; `budget.max_tokens` was mislabeled a
completion budget; seven stale absolute line references were
symbolized to rot-proof anchors. The reviewers also adjudicated and
rejected 33 borderline candidates with recorded reasons so future
audits do not relitigate them. Round 35 closed the doctor leak's other
half — the upstream-failure line still printed the configured URL
verbatim (reqwest additionally embeds it in the error Display); it now
redacts userinfo and strips the error's URL copy — and extinguished
the last two claim echoes (the 429 in the breaker *field* doc; the
phantom budget keys in av-sandbox's module doc, whose `$50` literal
would have meant 50 micro-USD under the real `_micros` field). A
dedicated pairing-claims sweep ("partner"/"mirrors"/"must match"/
"lockstep") then verified every such cross-reference in the workspace
intact.

### Review rounds 30–32: test-suite QC, self-review closure, echo sweep (2026-08-16)

The cross-model QC program's final surface: the standalone integration
test suites (~14k lines, 36 files). 13 test docs claimed things their
assertions do not check — banners describing retention-dedup behavior
the test (correctly) asserts the opposite of, a "hijack is refused"
test where nothing is refused (the real invariant: headers cannot swap
identity), a wasm "must trap" over a Deny-or-Allow assertion, and
loop-breaker docs promising strictness the embedder-tolerant
assertions deliberately avoid. Two tests were strengthened to match
their docs instead (receipt-verify stdout pinned to the documented
`verified <id>` shape; tampered-signature errors pinned to the opaque
`Verification` variant), and one QC finding was rejected as a
tooling artifact (byte-level inspection proved the "vacuous
bearer-leak test" really sends the secret; the session's masking had
redacted the reviewer's view). Self-review of the rewrites then caught
one over-claim of ours — a banner deferring unicode-tag byte-survival
to golden tests that contained no tag characters — resolved by adding
the missing test: tag-smuggled messages survive the typed round trip
bit-exactly and pass both validators. A final echo sweep re-grepped
every corrected claim across the prose docs and found two survivors in
PLAN.md (the brief's illustrative budget keys presented as the config
surface; the top-level-only `unmapped` nuance), both aligned with the
code-comment fixes they echoed.

Final certification: fmt, workspace clippy -D warnings all-features,
cargo-deny (4 checks), and the full 69-binary / 895-test all-features
suite green locally; the full CI pipeline (live services, release SLA,
container build, Harbor interop) green on the same commit.

### Review rounds 18–29: runtime-prose sweeps and the cross-model QC program (2026-08-16)

Rounds 18–25 extended the audit beyond code comments to every other
claim-bearing surface, each swept as an explicit class: the round-17
fixes themselves (self-review caught one overreach), TODO/promise
markers (the compression-marker limitation is now tracked in
SECURITY-AUDIT.md instead of only in its own comment), runtime error
strings (the zero-config quick start recommended the nonexistent
`agentvisor-ai` binary; five feature-gate bails named it too — all now
name `agentvisord` with the rebuild command), the generated
`avctl init` config template and clap help (verified drift-proof via
the from_toml round-trip), Prometheus HELP text (one divergent family
unified), `avctl doctor` diagnostics (no-schema warnings now state the
configured posture's real consequence), and the issue template
(`avctl --version` instead of a command that never existed).

Rounds 26–29 ran an independent cross-model QC program: a second
model re-reviewed every source file in the workspace (~50 files, four
tranches). It found 25 genuine misses, all in headline doc summaries —
rounded-off conditionals ("all"/"every"/"never" where the code has
caps, role filters, or opt-ins), mechanisms that had been refactored
away (a render()-panics claim, a global-lock test narrative, a p50/3×
bound that is actually aggregate 10×N), self-contradicting quantile
docs, and one promise that produced a real fix: `avctl doctor` said it
never prints secrets, but its *success* lines printed configured
endpoints verbatim — a `redis://user:pass@host` state endpoint leaked
credentials on every healthy run. A new `redact_userinfo()` display
helper (unit-tested across all doctor display shapes) now backs the
stronger, true promise. Also: NATS ack offsets documented as JetStream
stream sequences rather than partition-local offsets, and the
loop-detect Δ formula now documents the nearest-prior-step tightening.

### Review round 17: full-codebase comment↔code audit (2026-08-16)

Four parallel reviewers read every comment in all 12 crates (54k lines,
9.2k comment lines) and verified each checkable claim against the code;
a fifth pass covered the non-Rust surfaces (Dockerfile, Cargo.toml,
configs, deploy). 17 stale or false comments fixed — none reflected a
code bug; in every case the code was right and the prose had drifted:

- **False security/behavior claims**: `/metrics` described as
  authenticated and surfacing a nonexistent `av_build_info` metric
  (routes.rs — no harness endpoint exposes build info; the version
  appears only in the outbound upstream User-Agent); metrics label
  values attributed to a nonexistent render-time escaper
  (`escape_prom_label_value` never existed — the real guard is
  registration-time byte refusal in `validate_metric_key`, twice);
  `ResponsePermit` claimed admission "whenever the shard has room"
  (a global worker-capacity slot is also required — the adjacent test
  proves it); `worker_channel_capacity` cap justified by a tokio mpsc
  preallocation-OOM that tokio does not do (contradicting the
  authoritative const doc four lines up).
- **Stale after refactors**: reconciler test docs still described the
  removed global `lifecycle_lock` (now per-session `SessionLockTable`,
  three sites); recovery-scan cost rationale predated round-44 F1's
  refuse-before-read sidecar check; depth-bomb test called the
  round-40 F5 recursion cap "a valid future hardening" (it shipped);
  `dispatch` stage described as covering 15-90 s upstream streaming
  (it times only local job assembly); "up to 16 shards" (always
  exactly 16); "Fold gives min/max" over a plain for-loop; duplicate
  X-AV-Session refusal described as a 503 (it is a 400); Dockerfile
  build-stage `COPY config` justified by an `include_str!` that
  round-45 moved inside the crate — the COPY is gone (compile
  independence proven by building a tree with `config/` deleted) and
  av-harness/build.rs no longer claims the assets live outside the
  crate root.
- **Drifted line-number references** (9 sites): replaced absolute
  `L1308`/`:578`-style references — every one already pointing at the
  wrong line — with function-name or grep-able anchors in
  reconciler.rs, pipeline.rs, setup.rs, and av-atif's golden tests;
  receipt nesting-boundary doc now states the true off-by-one
  (`MAX_NESTED_DEPTH - 1` parses, `MAX_NESTED_DEPTH` refused).
- **Rebrand stragglers** (identifiers, not comments): pipeline test
  names `x_ab_*` → `x_av_*`; internal `DUP_KEY_SENTINEL` `"__ab_dup:"`
  → `"__av_dup:"` (never persisted or exposed — stripped before the
  error maps to `ReceiptError`).
- Race-suite module doc no longer claims retention-rollover coverage
  that lives in `embedded_contract.rs` (pointer added instead).

Verified-correct highlights from the same audit: all cross-crate
constant mirrors (4 MiB payload, 16 MiB provider capture, 2^53 JCS
bound, depth 128/64, JWKS 256, JWT 8 KiB, breaker ε=0.30), the
MAC-before-index journal order, seal-before-insert recovery race fix,
genesis-hash domain tag, Redis Lua TTLs, and every `AV_*` env name a
comment mentions.

### Review round 16: ATIF dual-validator agreement contract (2026-08-16)

A consistency sweep of schema surfaces found that the shipped
`schemas/atif-v1.7.schema.json` was only ever exercised against the
single golden trajectory, while the Rust strict validator is a separate
hand-rolled implementation — the two could silently diverge on any
other document, and external consumers validate our exports with the
JSON Schema. Added
`rust_strict_valid_v17_documents_always_pass_the_shipped_schema`
(av-atif golden suite): a seven-document corpus (minimal, root `extra`,
`tool_definitions`, system observation, multimodal message, omitted
`session_id`, golden) must be accepted by *both* validators. The
inverse direction is intentionally unenforced — strict mode checks
Harbor semantics JSON Schema cannot express (sequential step ids,
version-gated fields). The other three shipped schemas need no such
contract: bridge manifests are validated *by* the JSON Schema itself
(single source of truth), and receipts/OCSF events are machine-generated
shapes already covered by golden schema-conformance tests.

### Review round 15: fix the red CI supply-chain gate (2026-08-16)

The first CI run on the renamed repo failed `cargo-deny --all-features`:
the round-1 `ssl-vendored` addition to rdkafka violated the workspace's
rustls-only ban, and the rskafka 0.5 TLS stack pinned an EOL rustls 0.21
line carrying RUSTSEC-2026-0098 (rustls-webpki URI name constraints) and
the archived rustls-pemfile (RUSTSEC-2025-0134). Fixed properly:

- **rskafka 0.5 → 0.6**: the Kafka event path now uses rustls 0.23
  (shared line with async-nats; vulnerable webpki 0.101 and
  rustls-pemfile dropped from the lock entirely; CA parsing via
  rustls-pki-types). rskafka 0.6 brings native SASL SCRAM support:
  new `AV_KAFKA_SASL_MECHANISM` (`SCRAM-SHA-256` default — Redpanda's
  native credential store — `SCRAM-SHA-512`, or `PLAIN`; unsupported
  values refused loudly), applied consistently to both the rskafka
  event path and the librdkafka admin path. Live-validated against
  Redpanda TLS+SASL: SCRAM-256 default, explicit PLAIN, loud failure
  for a server-side-unconfigured SCRAM-512, plaintext regression.
- **deny.toml**: `openssl-sys` ban scoped with `wrappers =
  ["rdkafka-sys"]` — the vendored librdkafka admin client (topic
  provisioning + retention verification) is the single sanctioned
  OpenSSL surface; every other parent still fails the gate. All four
  cargo-deny checks green under `--all-features`.

### Review round 8: soak test findings (2026-08-16)

A 15,600-session soak (release daemon, live Kafka bridge + 3-node Redis
Cluster + mock upstream, `avctl loadgen` waves) surfaced two cold-tier
defects; memory and fd behavior were otherwise clean (fds stable, RSS
reclaimed from 72 MB to 29 MB once the idle sweep finalized sessions —
retention by design, not a leak; zero failed requests across all waves).

- **Shipped example manifest could never cold-export outside the
  container** — `manifests/bridge.example.yaml` hardcoded
  `file:///app/data/cold` (container-absolute). A local run with the
  documented default accumulated an unbounded durable retry outbox
  (13,314 intents / 52 MB in one soak) with a WARN per event, forever.
  The manifest now uses the portable relative `data/cold`, which
  resolves identically in the container (`WORKDIR /app`).
- **Relative `cold_uri` never worked** — `cold_url` created the
  directory and then failed provisioning, because
  `Url::from_directory_path` rejects relative paths. It now
  canonicalizes against the CWD first (same resolution rule as the
  cold-outbox default). Post-fix soak: 0 retry warnings, cold objects
  land on disk, outbox drains to 0.

### Review round 4: supply chain + NATS credential downgrade (2026-08-16)

- **quick-xml RUSTSEC advisory (unbounded allocation)** — the `aws` feature
  of `object_store` 0.12 pinned quick-xml 0.38, which `cargo deny` flags.
  Upgraded workspace `object_store` to 0.14 (quick-xml 0.41, fixed),
  adapting to its API (`ObjectStoreExt` import, `Path::join`). Live
  MinIO S3 contract re-validated on the new client; `cargo deny check`
  fully green (advisories, bans, licenses, sources).
- **NATS credentials could still cross plaintext** (independent-review
  finding): `require_tls(true)` was only forced when a CA file was
  pinned, so `AV_NATS_USER`/`AV_NATS_PASSWORD` with a `nats://` URL and
  no CA (e.g. WebPKI endpoints) sent the CONNECT password over a
  plaintext socket and stayed MITM-downgradeable. Credentials now force
  `require_tls(true)` too — live-tested: refused against a plaintext
  server, works against TLS.

### Connector-security review fixes (2026-08-16)

Implementation review of the secured-transport work surfaced three defects:

- **Kafka bootstrap lists actually work on the event path** — config
  documents `bridge_endpoint` as `host:port[,host:port]` and the rdkafka
  admin client accepts that, but the rskafka event path received the joined
  string as a single address, so every multi-broker bootstrap list failed
  to connect. The list is now split per-entry (live-tested single and
  multi-entry forms).
- **NATS partial credentials failed silently** — setting only one of
  `AV_NATS_USER`/`AV_NATS_PASSWORD` silently connected anonymously
  (a D13 silent-error violation, and inconsistent with the Kafka
  connector). Now refused loudly, unit- and live-tested.
- **NATS plaintext downgrade on endpoint typo** — a pinned
  `AV_NATS_CA_FILE` with a `nats://` (instead of `tls://`) URL could
  yield a plaintext connection. A pinned CA now forces
  `require_tls(true)`; live-tested to negotiate TLS on `nats://`.
- **Cold-store env over-capture** — lowercasing the whole environment for
  `object_store::parse_url_opts` let generic variable names (`ENDPOINT`,
  `REGION`, `TIMEOUT`, `TOKEN`, `PROXY_URL`) silently reconfigure the
  S3 client. Only `AWS_*`-prefixed variables are honored now
  (`aws_env_options`, unit-tested).

Also: `KafkaSecurity` gained a testable `from_lookup` seam (harness
`apply_env_overrides_from` pattern) plus unit tests for credential
pairing, the SASL-requires-TLS guard, protocol selection, and CA-file
error paths — deliberately without `derive(Debug)`, which would have
made the SASL password printable.

### Rebrand: AgentBridge → AgentVisor AI (2026-08-15)

Full pre-release rename; entries below this one keep the historical names.

- **Brand** — all docs, CLI text, dashboards, and crate descriptions now say
  AgentVisor AI. References to the source brief keep its original filename
  (`AgentBridge.docx`).
- **Binaries** — the daemon is `agentvisord` (was `agentbridged`); the CLI is
  `avctl` (was `abctl`). `find_server_binary` prefers `agentvisord` and
  falls back to the legacy `agentbridged` / `agent-bridge` names so
  source-built older installs keep working.
- **Crates** — all 12 workspace crates renamed `ab-*` → `av-*`
  (`av-core`, `av-events`, `av-atif`, `av-receipts`, `av-state`,
  `av-bridge`, `av-identity`, `av-compress`, `av-loopdetect`, `av-sandbox`,
  `av-harness`, `av-cli`). Nothing had been published to crates.io yet.
- **Wire protocol** — HTTP headers `X-AB-Session` / `X-AB-Workflow` (and the
  `x-ab-agent-version`, `x-ab-instance-uid`, `x-ab-middleware-us` response
  headers) renamed to `X-AV-*` / `x-av-*`. The event-chain genesis
  domain-separation tag changed `"ab-genesis"` → `"av-genesis"`, so receipts
  issued by pre-rename builds do not verify against post-rename chains
  (pre-release, nothing published).
- **Persisted formats** — further pre-release breaks carried by the rename:
  NATS JetStream stream names are now `av_<topic>` (old `ab_*` streams are
  orphaned, re-provisioned fresh); the cold-outbox HMAC domain changed to
  `agentvisor-cold-outbox-v1`, so pre-rename pending intents fail
  authentication loudly (drain the outbox before upgrading); Kafka records
  carry the dedupe header `agentvisor-event-uid` (was `agentbridge-…`); the
  OCSF `metadata.product.name` is `agentvisor-ai`; the default NHI JWT
  `audience` is `agentvisor-ai`, so tokens minted for the old audience are
  rejected until re-issued.
- **Env vars** — `AB_*` → `AV_*` (e.g. `AV_UPSTREAM_URL`, `AV_REDIS_URL`,
  `AV_KAFKA_CA_FILE`, `AV_NATS_CA_FILE`, `AV_COLD_S3_URL`, `AV_SLA_*`).
- **Metrics** — Prometheus names `ab_*` → `av_*`
  (e.g. `av_events_dropped_total`).
- **Paths & deploy** — setup root is `~/.agentvisor/`; systemd unit and
  Kubernetes manifest renamed to `agentvisor-ai.service` /
  `agentvisor-ai.yaml`; Docker/Compose, release archives, and the publish
  workflow updated. Repository URLs now point at `agentvisor-ai` (the
  GitHub repo must be renamed to match before the next release).

### Secured-transport and cluster live coverage (2026-08-15)

Closed the three environment limits recorded in VERIFICATION.md:

- **Kafka TLS/SASL** — `KafkaBus::provision` now honors `AB_KAFKA_CA_FILE`
  (private-CA TLS on both the rskafka event path and the librdkafka admin
  path; rskafka gains `transport-tls`, rdkafka gains `ssl-vendored`) and
  `AB_KAFKA_SASL_USERNAME`/`AB_KAFKA_SASL_PASSWORD` (SASL/PLAIN). Credentials
  without a CA are refused client-side — PLAIN must not cross the wire
  without TLS. Live contract passed against Redpanda with a
  `sasl`-authenticated TLS listener; plaintext path regression-tested
  unchanged.
- **NATS TLS/auth** — `NatsBus::provision` now honors `AB_NATS_CA_FILE` and
  `AB_NATS_USER`/`AB_NATS_PASSWORD`. Live contract passed over `tls://`
  against nats-server requiring TLS + user/password.
- **S3-compatible cold tier** — new `cold-store-aws` feature enables
  `s3://` `cold_uri` targets. Fixed a latent bug where
  `ColdArchive::from_manifest` passed raw `std::env::vars()` to
  `object_store::parse_url_opts`, which only parses lowercase config keys —
  standard `AWS_ACCESS_KEY_ID`/`AWS_ENDPOINT`/… were silently ignored; keys
  are now lowercased. New `AB_COLD_S3_URL`-gated live contract
  (`ab-bridge/tests/cold_store_live.rs`) passed against MinIO, covering the
  staged intent → conditional put → idempotent re-put path.
- **Redis Cluster** — new `AB_REDIS_URL` contract test drives the multi-key
  `try_spend_many` Lua script with the production `budget:{hash-tag}:` key
  shape; passed against a live 3-master cluster (CROSSSLOT safety and
  cross-key atomicity of a refused spend on a real slot map).

### Distribution

- **crates.io publishing** — added `.github/workflows/publish-crates.yml`
  which packages and uploads all 12 workspace crates in topological
  dependency order on every `v[0-9]+.[0-9]+.[0-9]+` tag push. A
  `workflow_dispatch` trigger with `dry_run=true` (default) smoke-tests
  the packaging without uploading. `CARGO_REGISTRY_TOKEN` secret must
  be set on the repo before the first tag lands.
- **Binary rename `agent-bridge` → `agentbridged`** — the name
  `agent-bridge` on crates.io is taken by an unrelated project (a
  Codex/Claude/Gemini CLI). To avoid `cargo install agent-bridge`
  installing someone else's tool, the harness binary is now
  `agentbridged` (daemon-style suffix) and the crate remains
  `ab-harness`. `abctl` and `ab-cli` are unchanged. `find_server_binary`
  in setup.rs prefers `agentbridged` and falls back to the legacy
  `agent-bridge` for smooth upgrades. Dockerfile ENTRYPOINT, systemd
  ExecStart, and CI release archives updated to match.
- **Embedded WAT relocation** — `crates/ab-harness/src/main.rs` used
  `include_str!("../../../config/policies/payload_limit.wat")`, which
  reaches outside the crate root and would fail on a crates.io
  consumer build (`cargo package` excludes parent-directory paths).
  Relocated to `crates/ab-harness/policies/payload_limit.wat`
  (packaged with the crate); the operator-facing mirror at
  `<repo>/config/policies/payload_limit.wat` stays for
  Docker/systemd/k8s deploy-time editing.
- **Workspace crate metadata** — every crate now inherits
  `repository`, `homepage`, `documentation`, `keywords`, and
  `categories` from `[workspace.package]` so crates.io landing pages
  render cleanly on first publish.

Post-0.1.0 hardening across rounds 11–32 of a systematic bug audit.
Highlights, grouped by class:

### Security

- **CVE-2026-25537** — bumped `jsonwebtoken` 9.3 → 10.4 to close the
  `nbf`/`exp` string-type-confusion bypass (round-11).
- **Signing-seed hardening** — refuse known-weak Ed25519 seeds
  (all-zero, all-0xFF); ed25519-dalek `zeroize` feature enabled;
  `Ed25519Signer::seed()` returns `Zeroizing<[u8; 32]>` and
  `from_seed(&[u8; 32])` takes a reference so no bare temp slot
  lingers (rounds 14, 18, 19).
- **Duplicate-header refusal** — `X-AB-Session`, `X-AB-Workflow`,
  and `Authorization` are all refused when multi-valued
  (identity split-brain hardening; rounds 13, 14).
- **RFC 7235 §2.1 Bearer scheme** — case-insensitive scheme match
  + SP/HTAB separator (round-15).
- **Receipt strict-load** — `Receipt::from_json_slice` walks the
  JSON with a bounded-depth visitor that refuses duplicate keys
  at any nesting level; `verify_semantic_invariants` enforces
  `AtifTrajectory.retroactive == true` (rounds 15, 16).
- **JWKS body cap** — 4 MiB Content-Length + streamed-body cap +
  256-key outer-array cap; case-insensitive scheme match; intra-
  document duplicate-`kid` refusal (rounds 12, 14, 15).
- **Docker + k8s signing-seed relocation** — moved off shared
  volumes into a docker secret (mode 0400) and a k8s Secret
  copied via non-root initContainer into an in-memory emptyDir
  (rounds 15, 17).
- **Systemd hardening** — `TimeoutStopSec=125s`,
  `KillMode=mixed`, `StartLimitBurst=5`,
  `StartLimitIntervalSec=60s`; signing seed moved to
  `/etc/agent-bridge/signing.seed` outside `ReadWritePaths`
  (rounds 17, 18, 19).

### Resource caps

- `MAX_RECEIPT_BYTES` (16 MiB), `MAX_ATIF_BYTES` (64 MiB), and
  `MAX_CONTROL_BYTES` (1 MiB) in `ab_core::fsutil`; TOCTOU-hardened
  `read_capped` / `read_capped_string` used by every CLI file
  loader and every hot-path reconciler / worker read (rounds 17,
  18).
- `abctl loadgen` cap 100k → 10k (matches the stated SLA gate;
  round 11).
- Reconciler `warned_artifacts` bounded by a constructor-bound
  FIFO (VecDeque + HashSet) so a rotating-timestamp attacker
  cannot force a log storm (rounds 17, 18, 19).
- Prometheus `HELP` text is now escape-encoded (backslash and LF)
  so a stray newline cannot corrupt scrape output (round 19).

### Reliability

- **Recovery no longer HOL-blocks** on a single bad
  `journal_version` sidecar (round 15).
- **Torn journal quarantine** — refuse to silently truncate a
  no-newline journal; move to `<path>.corrupt-<uid>` and preserve
  the sealed metadata sidecar via `quarantine_sibling_exists`
  (rounds 13, 14).
- **Worker shutdown supervision** — `PendingGuard` RAII so a
  panic in `process_envelope` cannot leak `worker_pending`;
  `catch_unwind` widened around JWKS refresh; JWKS
  `JoinHandle` aborted on shutdown; bridge maintenance error +
  join counters (rounds 11, 12).
- **Journal metadata durability** — `TempPathGuard` RAII prevents
  `.tmp` orphan class; `write_atomic`'s post-rename dirent fsync
  is best-effort with a warn (rounds 11, 12).
- **Journal HMAC field cap** — `hex::decode` refuses len > 128
  in both `journal.rs` and `cold_store.rs` (round 17).
- **Metric registry base-kind guard** — Prometheus TYPE conflicts
  panic at registration; every stage uses the wide-latency
  histogram bounds (round 10).

### Diagnostics

- **Dashboard JSON** — `no_store_json_response` on
  `list_sessions` / `session_detail` / `stats` sets
  `Cache-Control: no-store`, `Pragma: no-cache`, and
  `Vary: Authorization` (round 17).
- **`atif_capture_from_request` diagnostics** discriminate
  missing / wrong-type / empty `messages` (round 11).
- **Receipt duplicate-key error** — sentinel-based mapping so
  malformed JSON is `Serde`, not misattributed to `DuplicateKey`;
  offending key names are `escape_debug`'d (round 16).
- **ATIF validation error rendering** capped to the first 16
  issues + total (round 19).
- **Trace-span session id** sanitized through `SessionId::parse`
  before the span binds it; the rejected-value sentinel starts
  with `\x20` (outside the visible-ASCII predicate) so no client
  value can collide (rounds 13, 14).

### Documentation

- **Deploy install docs** — systemd instructs `abctl keygen`
  before daemon-reload; k8s instructs `kubectl create secret
  generic agent-bridge-signing-seed`; docker-compose.minimal.yml
  banner explains that its tmpfs seed regenerates on every
  restart (rounds 17, 18).

### Rounds 20–32 (highlights)

- **Cross-backend consistency** — `try_spend_many` (round-21 F1)
  and `COUNTER_MAX` (round-20 F1/F7) share a `JCS_SAFE_MAX`
  ceiling across `InMemoryStore` and `RedisStore` so a config
  typo cannot succeed in dev and fail in prod.
- **Cold outbox integrity** — `ColdArchive::set_control_key`
  refuses `[0; 32]` / `[0xFF; 32]` (round-21 F3) and
  `pending_mac` / `verify_pending_mac` refuse those patterns at
  sign/verify time so the constructor's default-init window
  cannot produce a forgeable envelope (round-22 F2). All
  cold-outbox rewrites now use `TempPathGuard` so a transient
  ENOSPC/EIO cannot leave a `.tmp` orphan with signed material
  on disk (round-22 F3, round-23 F1, round-27 F3).
- **Kafka fetch surfaces decode errors** — parity with NatsBus /
  EmbeddedBroker; a corrupt record no longer creates a silent
  offset gap in the audit trail (round-22 F1).
- **Deploy hardening** — `docker-compose.yml` `vector` service
  no longer mounts `/var/run/docker.sock`; all services now
  carry `restart: unless-stopped`; redpanda/nats moved to
  persistent named volumes; docker-compose.minimal.yml gained
  `cap_drop: [ALL]` / `pids_limit` / `security_opt`; the k8s
  ATIF spool moved from `emptyDir` to a `subPath` on the
  durable PVC and the initContainer gained
  `seccompProfile: RuntimeDefault` (rounds 24, 26).
- **Bridge maintenance shutdown** — cooperative
  `tokio::sync::Notify` replaces `JoinHandle::abort()` so the
  `spawn_blocking` closure quiesces before process exit
  (round-24 F5).
- **JWKS strictness** — refuses `use=enc` and non-EdDSA `alg` on
  OKP/Ed25519 (round-25 F1); `add_key` refuses to shadow
  JWKS-tracked kids (round-25 F2).
- **SSE detection is case-insensitive + parameter-tolerant**
  (round-25 F3); ATIF validator bounded by
  `MAX_NESTED_DEPTH = 128` (round-25 F4).
- **ATIF schema strictness** — `additionalProperties: false` on
  `metrics` and `agent` closes a smuggle path into the signed
  digest (round-26 F1, F2). Journal `open` verifies MAC before
  comparing positions to close the position oracle
  (round-26 F3). Prometheus HELP escaper now scrubs DEL and C1
  controls (round-26 F4). `TokenVelocity` uses
  `saturating_add` (round-26 F5).
- **Recovery robustness** — `recover_spooled_sessions` and
  `retry_marked_promotions` no longer abort the whole scan on
  one bad file; orphan `.promote` markers are cleaned up on
  the `is_promoted()` early-return; `promote_session` on a
  still-open session additionally requires `session_close_scope`
  (round-27 F1, F2, F3, F4). `BridgeManifest` /
  `TopicSpec` / `RetentionSpec` gained `deny_unknown_fields` +
  numeric caps (partitions ≤ 1024, hot_hours ≤ 10 years); the
  dashboard `session_detail` returns `atif_filename` instead
  of the absolute path (round-27 F5, F6).
- **CLI + Dashboard** — `probe_endpoint` uses scheme-driven
  default ports and strips userinfo (round-28 F1, F5);
  dashboard responses now carry a strict CSP + `X-Frame-
  Options: DENY` + `Referrer-Policy: no-referrer`
  (round-28 F2); attacker-influencable strings run through
  `sanitize_for_terminal` before println (round-28 F3);
  `session_promote` and `loadgen` stream response bodies with
  hard caps (round-28 F4); `abctl event-tail --max` capped at
  100 000 (round-24 F7).
- **Upstream relay** — non-JSON upstream error bodies no longer
  collapse to 502; the true status + `Retry-After` propagate to
  the client so SDK backoff works (round-29 F1). Every
  upstream-relayed response now carries
  `X-Content-Type-Options: nosniff` (round-29 F4). `/health`
  no longer discloses `CARGO_PKG_VERSION` to unauthenticated
  callers (round-29 F6). `StopReason` gained
  `#[serde(other)]` fallback for forward-compat during
  heterogeneous cluster upgrades (round-29 F7).
- **CI supply chain** — every third-party action pinned to a
  commit SHA; pydantic/shortuuid pinned to exact versions with
  transitive closure (round-29 F2, F3).
- **Config validate** — refuses
  `enforce_identity_scopes = true && require_identity = false`
  (round-30 F1); per-backend URL scheme allowlist on
  `identity_jwks_url` / `qdrant_url` / `state_endpoint` /
  `bridge_endpoint` (round-30 F2); `atif_spool_dir` /
  `bridge_data_dir` reject empty strings; scope names require
  non-empty visible-ASCII (round-31 F1, F2).
- **CORS deny** — explicit `cors_deny` OPTIONS handler on every
  mutating route: `204 No Content` with NO
  `Access-Control-Allow-*` headers; browsers correctly refuse
  cross-origin requests. Test guards against a future
  `CorsLayer::permissive()` regression (round-31 F5).
- **MCP tool-call Content-Type preserved** — the upstream tool
  response's `Content-Type` now round-trips through the on-
  disk `ToolOutcome` journal and re-emits on cached-outcome
  replay, so strict JSON-RPC 2.0 clients see
  `application/json` instead of the axum default
  `application/octet-stream` (round-32 F2).
- **Upstream read-timeout floor** — a 60 s read timeout is now
  applied to the shared reqwest client unconditionally (was
  opt-in), so a hung tool upstream cannot pin a session lease
  + WorkerPermit + tool-intent claim indefinitely
  (round-32 F4).

## 0.1.0 - 2026-08-10

### Added

- OpenAI-compatible Axum proxy and MCP interception routes.
- Bounded asynchronous workers with loop detection, OCSF emission, Bridge publication, ATIF capture, and signed chains.
- Idempotent session close, client-abort finalization, idle reconciliation, and retroactive receipts.
- Embedded, Kafka/Redpanda, and NATS Bridge backends with manifest provisioning.
- In-memory and Redis atomic state backends.
- Hash and ONNX embedding backends plus optional Qdrant persistence.
- Ed25519 JWKS refresh and HS256 development identity support.
- `abctl` operations, load generation, schemas, Docker Compose, and Vector configuration.
- Bounded byte-oriented SSE/non-SSE capture with fragmented UTF-8 and tool-call reassembly.
- Authenticated, torn-tail-tolerant signed and unsigned crash journals with exact receipt reuse.
- Durable lifecycle and cold-export outboxes with persisted acknowledgments.
- JSON-RPC-id tool execution claims, cached outcomes, and close-through-completion leases.
- Session-ordered parallel worker shards and concurrent deadline-bounded broker connectors.
- Qdrant similarity participation, masked ONNX mean pooling, and strict output-shape checks.
- Kafka retention verification, AOF-backed Redis, customer-volume cold tier, and object-store retries.
- Batched OTLP/HTTP traces to Vector with request/worker parent propagation and bounded shutdown.
- Harbor reference-validator CI over a trajectory emitted by the real HTTP harness flow.
- Mandatory CI image build, live backend contracts, and a true 10,000-connection release gate.
