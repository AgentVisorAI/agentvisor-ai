# AgentVisor AI Operations Guide

This document is the operator's tour of the harness. It covers boot,
health probes, upgrade, key rotation, spool recovery, and the metrics
you should alert on.

## Boot

`agentvisord` reads its TOML from `$AV_CONFIG` (if set), then
`./agentvisor.toml`, `./config/harness.toml`, and
`$HOME/.agentvisor/agentvisor.toml`. The example file
(`config/harness.example.toml`) is NOT searched.

On boot the harness logs a dedicated event on the `trust_anchor`
target:

```
signer_key_id=<32-hex fingerprint>
signer_public_key_hex=<64-hex Ed25519 public key>
signer_seed_path=<path the seed was loaded from>
freshly_generated=<true only when the seed was created this boot>
```

Every restart re-emits this pair unconditionally: the `trust_anchor`
target is pinned to INFO inside the process regardless of `RUST_LOG`,
so it survives `RUST_LOG=warn`, `error`, and even `off`. When the seed
is freshly generated at startup (no seed file was present at the
configured path), a WARN is added on the same always-on target: this is
normal for a first-run container but is a hard escalation for a
persistent deployment — you've lost your seed file and the new key
won't verify old receipts.

Pipe these lines into your log store and diff them across restarts;
any change is a rotation event that must be reflected in the
downstream trust store.

## Health probes

Three routes with distinct semantics:

| Route | Purpose | Failure mode |
| --- | --- | --- |
| `/health` | Legacy composite: 200 while all subsystems are healthy. | Do **not** wire new probes at this; it flaps as subsystems briefly hiccup. |
| `/livez` | Kubernetes-style liveness. Returns 200 constant. | Only fails when the axum runtime is dead; use as `livenessProbe`. |
| `/readyz` | Kubernetes-style readiness. 200 while accepting new traffic; 503 during drain. | Fails immediately when SIGTERM is received AND while the spool is not **writable** (probe file create+remove — a full disk or read-only remount flips readiness even though the directory stays readable). Use as `readinessProbe`. |

`readinessProbe` is the one that turns off the tap during pod
deregistration — flip a request-counter graph and you'll see the
last 5 seconds of traffic drop off before the process actually
terminates.

The included Kubernetes manifest at
`deploy/kubernetes/agentvisor-ai.yaml` wires all three, plus a
`preStop` hook that sleeps 5 seconds so the endpoint churn overlaps
the drain window.

## Shutdown

`agentvisord` shuts down cleanly on SIGTERM. The order is:

1. Set the `draining` flag → `/readyz` starts returning 503.
2. If `shutdown_ready_drain_s > 0` (default 0), keep ACCEPTING
   connections for that long so an external load balancer polling
   `/readyz` actually observes the 503 before the listener closes.
   Without it, step 3 begins immediately and a fresh readiness probe
   sees connection-refused instead — fine on Kubernetes (the preStop
   sleep provides this window before SIGTERM is even sent), but
   docker-compose / systemd / bare-LB deployments have no preStop
   equivalent, so set this to your LB's poll interval plus one
   reconciliation.
3. Await axum's graceful shutdown (in-flight requests complete;
   new TCP accepts are refused).
4. Abort background tasks (reconciler tick, retention sweep, etc.).
5. Flush and close the state store, broker, and Bridge.

Step-3 tail latency that exhausts the drain budget shows up as
`av_http_shutdown_drain_timeouts_total`. Alert on any increase — it
usually means a request was stuck waiting on the upstream and the
worker pool couldn't drain before the timeout. The pre-drain window
counts against the orchestrator's kill grace period ON TOP of the
drain budget.

## Key rotation

1. Generate a new seed: `avctl keygen --output signer.new.seed`.
2. Publish its public key to your downstream trust store BEFORE the
   next step. Use `avctl pubkey --seed signer.new.seed` to derive
   `public_key_hex` and `key_id` without exposing the seed.
3. Replace the running seed file atomically (`mv`, not `cp`).
4. `SIGHUP` is **not** wired for reloading; you must restart the
   process. Rolling restarts across a fleet are fine — each pod
   emits a startup log with the new key id.
5. The `av_receipts::keys::Keyring` on the verifier side must have
   the new key added; old receipts continue to verify against the
   old key until they age past your retention.

## Spool recovery

The reconciler runs every `reconcile_tick_s` seconds and handles:

* **Pending-close sessions:** an ATIF spool file exists but the
  close bridge event wasn't emitted (crash mid-close). Recovery
  re-adopts the on-disk journal, emits `SESSION_CLOSE`, and
  finalizes.
* **Orphan .json files (round 51 §8.5):** a `.json` with no
  `.atif-auth` sidecar is quarantine-renamed to
  `<name>.json.corrupt-<uid>` — but only after (a) age > 60s and
  (b) the stem is not that of a currently-open session. The
  live-stem check closes the race where a mid-close write is
  quarantined out from under the finalize path.
* **Sealed pair retention (round 51 §8.1):** when
  `atif_retention_days` is set, sealed pairs are pruned every hour.
  Unpaired remnants are LEFT for the orphan sweep. The same sweep is
  available manually as `avctl spool-prune --spool <atif_spool_dir>
  --retention-days N` (external cron, one-off reclaims).
* **Signed-workflow recovery:** if a signed session's receipt is
  missing but its journal is intact, recovery re-signs and emits.

Recovery is idempotent — a killed-then-restarted-then-killed pod
does the same work each tick without duplicating events.

### Releasing a quarantined session id

A SIGKILL / OOMKill / node loss mid-request leaves a sealed marker
under `<atif_spool_dir>/inflight-responses/`. On restart the
reconciler quarantines that session ("quarantining sessions with
incomplete effects") and the id returns
`400 session is already closed` from then on — by design, because
the provider may have observed a request whose response was never
captured, and silently resuming would put an unattested turn in the
audit chain.

If an agent derives its session id from a stable conversation id,
that conversation is locked out until an operator intervenes. The
manual release procedure:

1. Confirm the turn's outcome out of band (provider dashboard,
   upstream logs). You are asserting the uncaptured response either
   never happened or is acceptable to lose from the trail.
2. Stop routing traffic for that session id (or drain the pod).
3. Delete the session's marker file under
   `<atif_spool_dir>/inflight-responses/` — the filename embeds the
   session-id hash (`sha256(session_id)[..32]`). Keep a copy if your
   compliance posture requires evidence of the intervention.
4. Restart the harness (or wait one reconcile tick). The quarantine
   set is rebuilt from the markers, so the id admits traffic again.

Do NOT delete markers as routine hygiene — each one is the only
evidence that a crash window may contain an unaudited provider
interaction.

## Metrics you should alert on

| Metric | Alert condition | What it means |
| --- | --- | --- |
| `av_atif_retention_pruned_total` | Sudden increase | Retention sweep ran (usually just noise, but confirm the `atif_retention_days` you set). |
| `av_reconciler_last_tick_completed_seconds` | `time() - value > 5 × tick interval` | The reconciler tick is stalled (hung filesystem, lifecycle-lock deadlock) or has never completed since boot. Closes, promotion retries, idle finalization and outbox replay are all stopped with it. The series exists from boot and reads 0 until the first tick completes. |
| `av_atif_recovery_skipped_total{reason="unauthenticated"}` | Rate > 0 sustained | Someone/something is planting sidecar-less .json files. Escalate. |
| `av_atif_recovery_skipped_total{reason="too_large"}` | Rate > 0 | Adversarial ATIF payload attempts. Investigate the spool contents. |
| `av_incomplete_sessions_total` | Sudden increase | Sessions where `capture_failed` was set on the audit chain. After round 51 §6.2 (D7) this is genuinely rare and represents unrecoverable pipeline state, not client disconnects. Escalate. |
| `av_events_dropped_total{stage="response_slot"}` | Rate > 0 sustained | Response capture backpressure — the worker pool is saturated or the state store is slow. Scale up workers or investigate the state backend. |
| `av_http_shutdown_drain_timeouts_total` | Any increase | A graceful drain hit its timeout with requests still in flight; usually upstream latency. |
| `av_ephemeral_close_failures_total` | Any increase | The auto-close spawned for a stock-SDK one-shot session (no `X-AV-Session` header — the OpenAI-compatibility contract auto-closes it after the response) failed. The session is stranded open until the idle sweeper (`session_idle_close_s`) reaps it, delaying the receipt. If this fires steadily, the finalizer is unhealthy — investigate. |
| `av_stream_abort_close_failures_total` | Any increase | A background close spawned from a stream-abort drop path failed. Same class as ephemeral-close: the session is left open until the idle sweeper. Steady-state 0 on healthy nodes. |
| `av_stream_abort_no_runtime_total` | Any increase | A stream-abort drop path ran with no live Tokio runtime (harness shutdown, blocking-thread drop). Capture is marked failed so the reconciler retries on next tick. Any increase after boot suggests unclean shutdown ordering. |

## Backup

You need **three** things to reconstruct evidence for an audit:

1. The signer seed file (`signer.seed`) — filesystem, offline, GPG.
2. The spool dir (`atif_spool_dir`) — all `.atif-auth` sidecars
   must be preserved; the corresponding `.json` trajectories are
   recoverable from the broker if lost.
3. The receipt topic (`agent.receipt` on the broker) — either the
   embedded Bridge's data-dir or the external broker's log
   retention.

Losing (1) permanently invalidates every past receipt: they still
verify against the historical public key, but you can no longer
prove that key was yours. Losing (2) sacrifices operational
forensics but does NOT compromise the cryptographic chain. Losing
(3) means downstream consumers depend on the harness's live disk
copy — restore quickly.

## Upgrade

The workspace's SemVer contract:

* Signed receipts: canonical (JCS + Ed25519) format is
  frozen. Any change is a MAJOR version bump.
* ATIF trajectories: v1.7 shape is frozen. New fields are added as
  optional; removals or renames are MAJOR bumps.
* Config: new keys added with `#[serde(default)]` and documented in
  `docs/reference/CONFIGURATION.md`. Removals are MAJOR bumps.
* `avctl` CLI surface: adding subcommands is minor; removing them
  or renaming flags is MAJOR.

Rolling upgrades within a MAJOR version are safe: mix old and new
pods behind the same LB and the audit chain remains verifiable
under any pinned key that either version signed with.
