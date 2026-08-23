# AgentVisor AI Spool and Recovery

The spool is where AgentVisor AI's audit chain becomes durable. This
document explains what lives there, what the reconciler does on
every tick, and how to reason about incidents that touch it.

For the operator's *day-to-day* view (metrics, alerts, backup), see
[OPERATIONS.md](OPERATIONS.md).

## What "the spool" is

`atif_spool_dir` (default `./data/atif`) holds the on-disk state of
every open, closing, and recently-closed session. Its file
inventory:

| File | Contents | Written by | Removed by |
| --- | --- | --- | --- |
| `{stem}.session.json` | Sealed metadata: session id, identity, workflow, journal version | worker (`append_active_event_journal`) at first event | `remove_step_journal` after successful close |
| `{stem}.events.ndjson` | Append-only sealed journal — one JSON line per audit event | worker (`append_journal`) | `remove_step_journal` after successful close |
| `{stem}.json` | ATIF trajectory (unsigned workflow) OR receipt subject (signed workflow) | finalizer at close | retention sweep OR archive on collision |
| `{stem}.atif-auth` | Provenance sidecar: signature + key_id + integrity claim over `{stem}.json` | finalizer immediately after `write_atomic({stem}.json)` | retention sweep (paired with `.json`) |
| `{stem}.close-complete` | Marker: close ran to completion (both bridge event and receipt/ATIF durably committed) | finalizer at end of close | retention sweep |
| `{stem}.promote` | Promotion intent (unsigned → signed retrofit) | promote route handler | finalizer after receipt lands |
| `{stem}.promote-archived` | Archived-on-collision promote intent | finalizer collision path | retention sweep |
| `{stem}.session.close-complete` | Marker for signed-workflow closes | close_session_locked | retention sweep |
| `{stem}.session.lifecycle-outbox.ndjson` | Bridge events queued when the bus was unavailable at close time | close_session_locked | outbox drain after successful bridge emit |
| `{stem}.acks.ndjson` | Sealed broker acks, one line per published event: proves an event we tried to publish actually landed | worker after successful emit (appended; one `sync_data` per ack — round-51 §7.3) | `remove_step_journal` at close, with the other journals |
| `broker-acks/{stem}/{event_uid}.json` | Legacy pre-round-51 per-event ack layout; still read as a fallback so mid-session upgrades see their earlier acks | (no longer written) | `remove_step_journal` at close |

Every one of these files carries a `{stem}` derived as
`sha256_hex(session_id.as_bytes())[..32]` — a 128-bit fixed-width
truncation. Collision probability at 10⁹ sessions is ~10⁻²⁰,
comfortably below the audit-chain-tamper threshold set by the
Ed25519 verifier. Session ids of >128 UTF-8 code points are refused
at admission for the same reason.

## Why not a database

The spool is a filesystem because every state transition needs to
survive a hard reboot at any instruction boundary. Filesystems give
POSIX ordering guarantees (`write` → `sync_data` → `sync_all` on
containing dir) that are cheap to reason about and portable across
Linux/macOS/BSD. A database would give ACID transactions per row but
would sit above the same POSIX primitives — its atomicity is our
`write_atomic`, its durability is our per-event `sync_data`, and its
recovery log is our journal replay.

## Recovery: what runs every tick

`Finalizer::recover_spooled_sessions` runs at process start and every
`reconcile_tick_s` seconds. It walks the spool and does five things,
in order:

### 1. Consolidate step journals

For every `{stem}.session.json` + `{stem}.events.ndjson` pair whose
session id is NOT already registered, decrypt the session-metadata,
re-hydrate a Session, and insert it into the registry. Events from
`.events.ndjson` are replayed to reconstruct token counts, budget
debits, and provenance. Broker acks from `{stem}.acks.ndjson` (and
the legacy `broker-acks/{stem}/` fallback) are
folded in to skip re-emitting events the previous incarnation
already published.

Skips (with metrics):
* Per-session decryption failures → `av_signed_recovery_skipped_total`
  or `av_unsigned_recovery_skipped_total`. The broken session stays
  on disk for forensic inspection; other sessions continue to be
  processed.
* Corrupt receipt → `av_atif_trajectory_recovery_skipped_total`.
* Failed pending-close completion tail →
  `av_pending_close_completion_failed_total`.

### 2. Reap signed candidates

For every `{stem}.json` with a sibling `{stem}.atif-auth` that
represents a signed workflow whose journal is consistent but whose
receipt was never emitted (crash mid-close): re-emit the receipt to
the broker, write the `close-complete` marker, remove the journal.

### 3. Retry marked promotions

For every `{stem}.promote` file: run the promotion path. On
success, write `close-complete` and remove `promote`. On collision
(the target ATIF path already has a different-signed sibling), rename
to `promote-archived`.

### 4. Quarantine orphan `.json` files

For every `{stem}.json` whose:
* extension is `.json`,
* file name does not end with `.session.json`,
* has NO `.atif-auth` sidecar,
* is older than `MIN_ORPHAN_AGE` (60s),
* and whose stem is NOT in the live-session set snapshot taken at
  the start of the sweep,

rename to `{stem}.json.corrupt-{uid}`. The 60s age gate is defense
against races on an in-flight close's mid-write; the live-stem
check is defense in depth for closes that started after the
snapshot but before the rename. Corrupt files are counted in
`av_atif_recovery_skipped_total{reason="unauthenticated"}` and
never automatically deleted — they're on-disk forensics.

### 5. Retention sweep (independent task, hourly)

If `atif_retention_days` is set, an independent hourly task
(`prune_sealed_atif`) removes SEALED pairs (`.json` +
`.atif-auth`) whose mtime is older than N days. Unpaired remnants
are left for step 4 to quarantine. Counted in
`av_atif_retention_pruned_total`.

## Race analysis: the three tight windows

### 1. Write / sidecar seal (round-16 stress)

`finalizer.close_session_locked` writes `{stem}.json` via
`write_atomic`, then immediately writes `{stem}.atif-auth`. Between
those two calls, the reconciler's step 4 would see a sidecar-less
`.json` and quarantine it. Mitigation:

1. Per-session lifecycle lock — the close holds
   `acquire_lifecycle(session_id)` across both writes so a second
   close on the same session can't interleave.
2. `MIN_ORPHAN_AGE = 60s` gate — a `.json` newer than 60s is
   skipped this tick.
3. Live-stem check (§8.5 fix, round 51) — a `.json` whose stem is
   in the currently-open-sessions snapshot is skipped even if
   aged.

The three gates layer: (1) prevents intra-process races, (2)
prevents inter-tick races on very-quick closes, (3) prevents races
where the tick's snapshot was taken before the close but the
close is still in-flight when the sweep visits the file.

### 2. Journal append / broker emit (round-27)

A worker appends to `{stem}.events.ndjson` and then attempts to
emit the corresponding event to the broker. If the process crashes
between append and emit, the event is durable on disk but not on
the wire. Recovery step 1 detects this by comparing the journal's
last event to the `{stem}.acks.ndjson` inventory (legacy
`broker-acks/{stem}/` files are consulted as a fallback), re-emits
any event missing an ack, and appends a fresh ack.

There is one race here: a broker that fully accepted an event but
crashed before delivering the ack causes the recovered process to
re-emit. The event is idempotent-keyed on `event_uid`, so
downstream consumers dedup on the `event_uid` field. A broker
without dedup capability WILL land the event twice — this is a
known limit and the `av_events_dropped_total{stage="broker_ack"}`
counter tracks the emit-succeeded-but-ack-lost case.

### 3. Retention prune / live session (round-51 §8.1-§8.2)

The retention task and the live-session close path can both touch
`{stem}.json` and `{stem}.atif-auth`. Retention only touches SEALED
pairs (both files present) whose mtime is past the threshold; a
live session's freshly-closed pair has mtime = now, which is
comfortably inside any reasonable retention window.

## Backup and disaster recovery

The spool is safe to `rsync` while the harness is running (POSIX
guarantees on `.ndjson` append semantics), but not safe to
partial-restore: a spool where some sessions are complete and some
are half-migrated will cause the reconciler to emit truncated
receipts. Snapshot the entire directory or nothing.

Rebuild the audit chain from a fresh disk:

1. `stat atif_spool_dir/*.json | count` — should be roughly the
   number of `agent.receipt` events the broker has for the same
   window.
2. `avctl receipt-verify` against a known-trusted receipt (from
   before the incident) — proves the signer's public key is intact.
3. For each recovered session on disk, tail the broker and diff
   `subject.event_count` — divergence is a torn recovery.

## What the reconciler will NEVER do

* **Delete unpaired `.json` files.** These are either an in-progress
  close or forensic evidence of an attack. Quarantine + operator
  review only.
* **Retry a `.corrupt-*` file.** Once quarantined, the file is
  out-of-band; recovery skips it in O(1) on every future tick.
* **Cross-session locking.** Every action holds the per-session
  lifecycle lock only; different sessions are always processed
  concurrently. This is what gives the finalizer its
  `close_latency_scales_reasonably_under_lock_contention` shape.
* **Silent retention.** Every prune emits a counter increment; every
  quarantine emits both a counter AND a warn. An operator monitoring
  only metrics sees the shape; an operator monitoring only logs
  sees the reason. Both together triangulate.

## Round-N tags in the source

You will see comments like "Round-51 F1: …" and "Round-16 F4: …"
across the codebase. These are archaeological anchors: each Round
corresponds to a review pass, and each F-M numbers a finding within
that pass. The tags are load-bearing history — they explain WHY a
given guard exists so that a future refactor doesn't quietly remove
it. If you're editing a Round-tagged block, follow the anchor:
grep for the tag in
[EVOLUTION.md](../EVOLUTION.md) or in the git log to find the
incident that motivated it.
