import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import { db } from "../db.js";
import { verifyPassword } from "../lib/auth.js";
import { bus } from "../lib/bus.js";
import { dispatchEvent } from "../lib/webhooks.js";
import { writeAudit } from "../lib/audit.js";

// ── Auth for the ingest endpoint ────────────────────────────────────────────
//
// Daemons authenticate with `Authorization: Bearer <ingest_token>` plus the
// deployment id in a header. We verify the plaintext token against the
// argon2 hash on file. This lookup is intentionally by deployment id (fast,
// indexed) — never by scanning every deployment.

async function authenticateDaemon(
  req: FastifyRequest,
  reply: FastifyReply,
): Promise<{ deploymentId: string; orgId: string } | null> {
  const deploymentId = req.headers["x-av-deployment"];
  const auth = req.headers.authorization;
  if (typeof deploymentId !== "string" || !auth?.startsWith("Bearer ")) {
    reply.code(401).send({ error: "unauthenticated" });
    return null;
  }
  const token = auth.slice("Bearer ".length);
  const deployment = await db.deployment.findUnique({
    where: { id: deploymentId },
    select: { id: true, orgId: true, ingestTokenHash: true },
  });
  if (!deployment) {
    reply.code(401).send({ error: "unauthenticated" });
    return null;
  }
  const ok = await verifyPassword(deployment.ingestTokenHash, token);
  if (!ok) {
    reply.code(401).send({ error: "unauthenticated" });
    return null;
  }
  // Best-effort — don't fail ingest if the timestamp write races.
  db.deployment
    .update({
      where: { id: deployment.id },
      data: { lastIngestAt: new Date() },
    })
    .catch(() => void 0);
  return { deploymentId: deployment.id, orgId: deployment.orgId };
}

// ── Payload schemas ─────────────────────────────────────────────────────────

const sessionUpsert = z.object({
  externalId: z.string().min(1).max(128),
  agent: z.string().min(1).max(80),
  workflow: z.enum(["signed", "unsigned"]).default("signed"),
  status: z.enum(["live", "sealed", "blocked"]).default("live"),
  policyVersion: z.number().int().min(0).default(1),
  openedAt: z.coerce.date(),
  closedAt: z.coerce.date().optional(),
});

const eventPayload = z.object({
  sessionExternalId: z.string().min(1).max(128),
  seq: z.number().int().min(0),
  kind: z.enum(["sys", "user", "llm", "tool", "block", "guard", "audit"]),
  tag: z.string().min(1).max(32),
  body: z.string().max(8000),
  sub: z.string().max(2000).optional(),
  occurredAt: z.coerce.date(),
  journalCount: z.number().int().min(0).default(1),
  // Delta rollups the daemon reports for this event, if any.
  addPromptTokens: z.number().int().min(0).default(0),
  addCompletionTokens: z.number().int().min(0).default(0),
  addCostUsdMicros: z.number().int().min(0).default(0),
  addPayoutUsdMicros: z.number().int().min(0).default(0),
  addBlockedPayoutUsdMicros: z.number().int().min(0).default(0),
  addToolsAllowed: z.number().int().min(0).default(0),
  addToolsBlocked: z.number().int().min(0).default(0),
});

const receiptPayload = z.object({
  sessionExternalId: z.string().min(1).max(128),
  receiptId: z.string().min(1).max(128),
  body: z.string().min(1).max(65_536),
  sigB64: z.string().min(1).max(4096),
  keyIdHex: z.string().min(1).max(128),
  eventCount: z.number().int().min(0),
  issuedAt: z.coerce.date(),
  stopReasonId: z.number().int().optional(),
  stopReason: z.string().max(80).optional(),
});

const publicKeyPayload = z.object({
  publicKeyHex: z.string().regex(/^[0-9a-f]{64}$/),
});

export async function ingestRoutes(app: FastifyInstance): Promise<void> {
  app.post("/pubkey", async (req, reply) => {
    const daemon = await authenticateDaemon(req, reply);
    if (!daemon) return;
    const body = publicKeyPayload.safeParse(req.body);
    if (!body.success) return reply.code(400).send({ error: "invalid_input" });
    // R91 F3: silent trust-anchor rotation is the exact class the
    // R78 pinning + R79 verifier hardening tried to close, and
    // this endpoint was silently ROTATING the anchor without any
    // audit entry or admin approval flow. A stolen ingest token
    // (or a routinely re-provisioned daemon) could:
    //   1. POST /pubkey {publicKeyHex: <attacker key>}
    //   2. All prior receipts for that deployment now fail verify
    //      (the console + /verify page compare against the
    //      current deployment.publicKeyHex, not the receipt's
    //      own keyIdHex).
    //   3. Forged sessions/events signed with the attacker's new
    //      key verify GREEN.
    // Fix: allow FIRST-SET (empty column → new key) without
    // ceremony but require the ingest layer to reject any
    // subsequent CHANGE to a different key. A legitimate rotation
    // needs an owner/admin-authenticated console flow (out of
    // scope for this hardening — the endpoint isn't wired up
    // yet — so rejecting mid-flight rotation is the correct
    // fail-closed posture). Always emit an audit entry so
    // operators see first-set events.
    const dep = await db.deployment.findUnique({
      where: { id: daemon.deploymentId },
      select: { orgId: true, name: true, publicKeyHex: true },
    });
    if (!dep) return reply.code(404).send({ error: "deployment_not_found" });
    // R92 F3: fold the check + write into a conditional atomic
    // updateMany scoped by `publicKeyHex: null` so that two
    // concurrent /pubkey calls at first-set time can't both
    // observe null and both silently win with last-writer
    // semantics. The daemon-vs-stolen-token race (daemon on
    // first boot, attacker holding the same ingest token) is
    // real: whoever's write reached Postgres LAST previously
    // won the trust anchor and BOTH would then log
    // `deployment.pubkey_first_set`, letting an operator
    // misread the audit trail as "the daemon just retried".
    // With the conditional predicate, exactly one first-set
    // wins; the loser gets `count === 0` and falls into the
    // existing "already-set" branch (409 if different key,
    // idempotent 200 if same key).
    if (!dep.publicKeyHex) {
      const upd = await db.deployment.updateMany({
        where: { id: daemon.deploymentId, publicKeyHex: null },
        data: { publicKeyHex: body.data.publicKeyHex },
      });
      if (upd.count === 1) {
        writeAudit(
          {
            orgId: dep.orgId,
            event: "deployment.pubkey_first_set",
            actorId: `daemon:${daemon.deploymentId}`,
            actorEmail: `daemon@${dep.name}`,
            target: dep.name,
            metadata: {
              deploymentId: daemon.deploymentId,
              publicKeyHex: body.data.publicKeyHex,
            },
            req,
          },
          req.log,
        );
        return reply.send({ ok: true });
      }
      // Lost the first-set race. Re-fetch the current key and
      // fall through to the same-key vs different-key branch.
      const refetched = await db.deployment.findUnique({
        where: { id: daemon.deploymentId },
        select: { publicKeyHex: true },
      });
      dep.publicKeyHex = refetched?.publicKeyHex ?? null;
    }
    if (dep.publicKeyHex && dep.publicKeyHex !== body.data.publicKeyHex) {
      // Refuse silent rotation. Log at warn so an operator can
      // investigate a rogue daemon or a stolen token.
      req.log.warn(
        {
          deploymentId: daemon.deploymentId,
          orgId: dep.orgId,
          old: dep.publicKeyHex,
          proposed: body.data.publicKeyHex,
        },
        "ingest_pubkey_rotation_refused",
      );
      writeAudit(
        {
          orgId: dep.orgId,
          event: "deployment.pubkey_rotation_refused",
          actorId: `daemon:${daemon.deploymentId}`,
          actorEmail: `daemon@${dep.name}`,
          target: dep.name,
          metadata: {
            deploymentId: daemon.deploymentId,
            currentPublicKeyHex: dep.publicKeyHex,
            proposedPublicKeyHex: body.data.publicKeyHex,
          },
          req,
        },
        req.log,
      );
      return reply.code(409).send({ error: "pubkey_already_set" });
    }
    // Idempotent same-key repost is a no-op.
    return reply.send({ ok: true });
  });

  // Upsert a session (idempotent on externalId).
  app.post("/sessions", async (req, reply) => {
    const daemon = await authenticateDaemon(req, reply);
    if (!daemon) return;
    const body = sessionUpsert.safeParse(req.body);
    if (!body.success) return reply.code(400).send({ error: "invalid_input" });
    const s = body.data;
    // Look up existing session first so we can protect a sealed status
    // from being "un-sealed" by a buggy daemon retrying with status=live.
    // Once a session is sealed the totals are finalized and the receipt
    // is signed; reverting the status would corrupt the audit trail.
    const existing = await db.session.findUnique({
      where: {
        deploymentId_externalId: {
          deploymentId: daemon.deploymentId,
          externalId: s.externalId,
        },
      },
      select: { status: true },
    });
    // R119 F2: post-seal metadata freeze. R93 F4 + R118 F2
    // locked the receipt row and session.stopReason once sealed.
    // Prior shape here only locked `status` (via nextStatus) —
    // an ingest-token holder could re-POST /ingest/sessions with
    // status:"sealed" (satisfies the gate) and mutated agent /
    // workflow / policyVersion / closedAt to relabel a sealed
    // session. The signed receipt.body is unchanged so the
    // Ed25519 verifier at /verify still passes, but the SPA
    // session list + /me/export render session.agent /
    // session.workflow / session.policyVersion — post-seal
    // audit-trail defacement (e.g. mutating workflow to
    // "unsigned" makes a legitimately signed session appear
    // unsigned in the list). Same threat model as R92 F2 / R93
    // F4 / R118 F2 (leaked AV_INGEST_TOKEN). First-write-wins
    // matches the sealed-receipt posture across the file.
    // R141 F3: refuse pre-sealed CREATE. The R119 F2 update-branch
    // freeze covered rewrites of already-sealed rows, but the
    // create branch (row didn't exist yet) had no such guard. If
    // retention purges Session rows (sessionRetentionDays elapsed)
    // but preserves audit rows referencing them, a compromised
    // ingest-token holder can POST /ingest/sessions with the
    // historical externalId + status:"sealed" + attacker-chosen
    // agent/openedAt — Prisma happily inserts. Downstream
    // /read/sessions/:id then renders a "sealed but no receipt"
    // row (Receipt was cascade-purged), producing plausible-
    // deniability defacement of forensic history. Same threat
    // model as R118 F2 / R119 F2 (leaked AV_INGEST_TOKEN). The
    // seal transition is by design the receipt row's job
    // (/ingest/receipts sets status:"sealed" atomically with
    // the receipt) — an ingest client should never POST a new
    // session that's already sealed. Refuse cleanly.
    // R144 F1: refuse ANY POST /ingest/sessions with
    // s.status === "sealed" — not just the CREATE case. R141 F3
    // only guarded `!existing`; on an existing live session
    // nextStatus would collapse to s.status="sealed" and the
    // UPDATE branch flipped the row without ever running
    // /ingest/receipts. Result: session.status="sealed" with NO
    // Receipt row, stopReason/stopReasonId null, /events guard at
    // ingest.ts:362 silently drops all further events for that
    // session — a compromised AV_INGEST_TOKEN holder can race an
    // in-flight session, force-seal it, and censor the rest of
    // the trail. Same threat model as R141 F3; the invariant
    // needs to hold on UPDATE too.
    if (s.status === "sealed") {
      req.log.warn(
        {
          deploymentId: daemon.deploymentId,
          externalId: s.externalId,
          existingStatus: existing?.status ?? null,
        },
        "ingest_session_direct_seal_refused",
      );
      writeAudit(
        {
          orgId: daemon.orgId,
          event: "deployment.direct_seal_refused",
          actorId: `daemon:${daemon.deploymentId}`,
          actorEmail: `daemon@${daemon.deploymentId}`,
          target: s.externalId,
          metadata: {
            deploymentId: daemon.deploymentId,
            externalId: s.externalId,
            existingStatus: existing?.status ?? null,
          },
          req,
        },
        req.log,
      );
      return reply
        .code(400)
        .send({ error: "cannot_direct_seal_session" });
    }
    // R151 F1: atomic sealed-guard via conditional updateMany.
    // Prior shape branched on `isSealed = existing?.status ===
    // "sealed"` read from findUnique above, then chose
    // `upsert.update = isSealed ? {} : {full field set}`. TOCTOU
    // race with /ingest/receipts's concurrent seal at :~763:
    // if the receipt handler commits `session.update({status:
    // "sealed"})` between our findUnique and the upsert, our
    // JS snapshot showed "live", `isSealed=false`, and Postgres'
    // ON CONFLICT DO UPDATE has no sealed guard — it blindly
    // overwrote the just-sealed row back to "live" with the
    // attacker-supplied agent / workflow / policyVersion /
    // closedAt fields. Signed receipt.eventCount then mismatched
    // session.events, the /events guard at line 402 stopped
    // rejecting further appends, and the SPA/exports rendered
    // the mutated fields — the same post-seal defacement class
    // R119 F2 / R141 F3 / R144 F1 closed for the non-concurrent
    // paths. R144's own header comment named the invariant but
    // enforced it only against attacker-supplied s.status ===
    // "sealed"; a race against a legitimate concurrent seal
    // slipped through. Fix: move the sealed guard onto the DB
    // WHERE clause. Postgres evaluates `status: { not: "sealed" }`
    // under the same row lock the UPDATE takes, so no snapshot
    // can lie about the sealed state.
    const upd = await db.session.updateMany({
      where: {
        deploymentId: daemon.deploymentId,
        externalId: s.externalId,
        status: { not: "sealed" },
      },
      data: {
        agent: s.agent,
        workflow: s.workflow,
        status: s.status,
        policyVersion: s.policyVersion,
        closedAt: s.closedAt,
      },
    });
    let session: { id: string; externalId: string; agent: string };
    if (upd.count === 0) {
      // Two cases collapse here:
      //   1. Row doesn't exist yet → CREATE branch.
      //   2. Row exists AND is sealed → R119 F2 freeze; leave
      //      it untouched via `update: {}`.
      // Upsert.create handles case 1 atomically; if a concurrent
      // writer wins the create race the `update: {}` no-op keeps
      // us safe on case 2 as well.
      session = await db.session.upsert({
        where: {
          deploymentId_externalId: {
            deploymentId: daemon.deploymentId,
            externalId: s.externalId,
          },
        },
        create: {
          deploymentId: daemon.deploymentId,
          orgId: daemon.orgId,
          externalId: s.externalId,
          agent: s.agent,
          workflow: s.workflow,
          status: s.status,
          policyVersion: s.policyVersion,
          openedAt: s.openedAt,
          closedAt: s.closedAt,
        },
        update: {},
        // R123 F2: return the PERSISTED agent (which is the
        // pre-seal canonical value on a sealed row) rather than
        // the caller-supplied s.agent, so bus.publish below
        // doesn't forward attacker-controlled agent on the
        // no-op branch.
        select: { id: true, externalId: true, agent: true },
      });
    } else {
      const found = await db.session.findUnique({
        where: {
          deploymentId_externalId: {
            deploymentId: daemon.deploymentId,
            externalId: s.externalId,
          },
        },
        // R123 F2: forward the persisted agent (matches the
        // no-op branch above).
        select: { id: true, externalId: true, agent: true },
      });
      if (!found) {
        // updateMany reported 1 row updated but the row is gone
        // by the time we look it up — a retention purge or a
        // hard delete raced in between. Treat as no-op.
        return reply.code(409).send({ error: "session_race" });
      }
      session = found;
    }
    bus.publish({
      type: "session.upsert",
      orgId: daemon.orgId,
      deploymentId: daemon.deploymentId,
      sessionId: session.id,
      externalId: session.externalId,
      agent: session.agent,
    });
    return reply.send({ session });
  });

  // Append events. Idempotent per (session, seq) — a retrying daemon can't
  // duplicate rows.
  app.post("/events", async (req, reply) => {
    const daemon = await authenticateDaemon(req, reply);
    if (!daemon) return;
    const body = z.array(eventPayload).max(500).safeParse(req.body);
    if (!body.success) return reply.code(400).send({ error: "invalid_input" });
    const events = body.data;
    if (events.length === 0) return reply.send({ inserted: 0 });

    // Group by sessionExternalId so we do one lookup per session.
    const byExt = new Map<string, typeof events>();
    for (const ev of events) {
      const arr = byExt.get(ev.sessionExternalId) ?? [];
      arr.push(ev);
      byExt.set(ev.sessionExternalId, arr);
    }

    let inserted = 0;
    const rejectedSealed: string[] = [];
    // Reject events whose occurredAt is more than 5 minutes in the future
    // (allows NTP drift + reasonable batch send delay). Similarly reject
    // events dated before Jan 1 2000 — no legitimate agent runs predate
    // that. Both are silent per-event drops rather than a whole-batch 400
    // so a mostly-good batch still lands.
    const now = Date.now();
    const maxFutureMs = 5 * 60_000;
    const minPastMs = new Date("2000-01-01T00:00:00Z").getTime();
    let droppedSkewed = 0;
    let droppedAncient = 0;

    for (const [externalId, batch] of byExt) {
      const session = await db.session.findUnique({
        where: {
          deploymentId_externalId: {
            deploymentId: daemon.deploymentId,
            externalId,
          },
        },
        select: { id: true, status: true },
      });
      if (!session) continue; // ignore events for a session the daemon didn't upsert first

      // A sealed session's totals were finalized when the daemon issued
      // the receipt. Allowing more events after that would silently
      // corrupt the rollup. Reject the batch for this session; the
      // daemon should never send more events for a session it sealed.
      if (session.status === "sealed") {
        rejectedSealed.push(externalId);
        continue;
      }

      // Idempotency: filter the batch down to *new* seqs before touching
      // the rollup counters. A retrying daemon that sends the same events
      // twice must not double-count tokens / cost / payout — this was a
      // real bug where session totals grew every retry even though the
      // event rows were skipped by createMany.skipDuplicates.
      const existing = await db.event.findMany({
        where: { sessionId: session.id, seq: { in: batch.map((e) => e.seq) } },
        select: { seq: true },
      });
      const existingSeqs = new Set(existing.map((e) => e.seq));
      // R96 F2: dedupe within the batch itself before touching the
      // rollup. Prior shape filtered ONLY against DB-existing seqs
      // — an intra-batch duplicate seq passed the guard, hit
      // event.create (first succeeds, second throws P2002 caught +
      // continue), then the rollup loop ran twice for the same seq
      // because `insertedSeqs.has(e.seq)` was true for both
      // iterations. A daemon (buggy or malicious with a compromised
      // ingest token) that posts [{seq:5, addCostUsdMicros:1000},
      // {seq:5, addCostUsdMicros:9000}] committed one event row but
      // inflated session.costUsdMicros by 10 000. The receipt then
      // signed the inflated total — same compliance-story downgrade
      // class R93 F2 / R94 F1 closed for the inter-batch race,
      // just via the intra-batch vector. Keep first occurrence.
      const seenSeqs = new Set<number>();
      const fresh = batch.filter((e) => {
        if (existingSeqs.has(e.seq)) return false;
        if (seenSeqs.has(e.seq)) return false;
        seenSeqs.add(e.seq);
        const t = e.occurredAt.getTime();
        if (t > now + maxFutureMs) { droppedSkewed++; return false; }
        if (t < minPastMs) { droppedAncient++; return false; }
        return true;
      });
      if (fresh.length === 0) continue;

      const rows = fresh.map((e) => ({
        sessionId: session.id,
        seq: e.seq,
        kind: e.kind,
        tag: e.tag,
        body: e.body,
        sub: e.sub,
        occurredAt: e.occurredAt,
        journalCount: e.journalCount,
      }));
      // R93 F2: prior shape ran createMany({skipDuplicates:true}) then
      // computed rollup deltas over the FULL `fresh` array. Two
      // concurrent POSTs (daemon retry vs live daemon, spool replay
      // vs live) both saw existingSeqs=∅, both computed the full
      // deltas, one won the unique-constraint insert, the other's
      // createMany.count went to 0 — but BOTH called session.update
      // with the full deltas. Session totals silently doubled; the
      // finalized receipt then signed the inflated numbers, breaking
      // the compliance story. Fix: replace createMany with per-row
      // create() so P2002 unique violations identify which seqs are
      // OURS. Rollup deltas are computed only over the actually-
      // inserted subset; concurrent duplicates count once. Cost is N
      // round trips per batch, but ingest batches are small (10-100
      // events typical) and event throughput is bounded by the
      // daemon's tick anyway.
      // R93 F2 + R94 F1: wrap the per-row inserts AND the rollup
      // update in ONE transaction so a mid-batch failure (P1001
      // connection lost, P2024 pool timeout, statement timeout,
      // DB restart) rolls back every row that already succeeded.
      // Prior R93 shape ran the per-row create() loop OUTSIDE any
      // transaction — a failure at row 6/10 committed rows 1..5
      // and skipped the rollup update, so the daemon's next retry
      // pulled rows 1..5 into `existingSeqs`, skipped their
      // deltas as "already applied", and PERMANENTLY under-
      // counted promptTokens/costUsdMicros/toolsBlocked. The
      // sealed receipt then signed the undercount, breaking the
      // compliance story from the OTHER direction. With the tx
      // wrapper, either every fresh row + the rollup increment
      // commit together, or nothing does — the daemon retries a
      // clean slate.
      const insertedSeqs = new Set<number>();
      let dPrompt = 0;
      let dCompletion = 0;
      let dCost = 0;
      let dPayout = 0;
      let dBlockedPayout = 0;
      let dToolsOk = 0;
      let dToolsBad = 0;
      await db.$transaction(async (tx) => {
        for (const row of rows) {
          try {
            await tx.event.create({ data: row });
            insertedSeqs.add(row.seq);
          } catch (err) {
            if (
              typeof err === "object" &&
              err !== null &&
              (err as { code?: string }).code === "P2002"
            ) {
              // Concurrent batch already inserted this seq. Skip
              // silently — matches prior skipDuplicates behavior.
              continue;
            }
            throw err;
          }
        }
        for (const e of fresh) {
          if (!insertedSeqs.has(e.seq)) continue;
          dPrompt += e.addPromptTokens;
          dCompletion += e.addCompletionTokens;
          dCost += e.addCostUsdMicros;
          dPayout += e.addPayoutUsdMicros;
          dBlockedPayout += e.addBlockedPayoutUsdMicros;
          dToolsOk += e.addToolsAllowed;
          dToolsBad += e.addToolsBlocked;
        }
        if (
          dPrompt || dCompletion || dCost || dPayout || dBlockedPayout ||
          dToolsOk || dToolsBad
        ) {
          await tx.session.update({
            where: { id: session.id },
            data: {
              promptTokens: { increment: dPrompt },
              completionTokens: { increment: dCompletion },
              costUsdMicros: { increment: BigInt(dCost) },
              payoutUsdMicros: { increment: BigInt(dPayout) },
              blockedPayoutUsdMicros: { increment: BigInt(dBlockedPayout) },
              toolsAllowed: { increment: dToolsOk },
              toolsBlocked: { increment: dToolsBad },
            },
          });
        }
      }, {
        // R95 F1: Prisma's default \$transaction timeout is 5 s.
        // The route's zod cap is .max(500), and each event.create
        // is a serial round trip inside the tx. On hosted Postgres
        // (Neon, Supabase, RDS) with 10-20 ms RTT the tx spans
        // 5-10 s for a full 500-row single-session batch and
        // consistently throws P2028 'Transaction already closed'.
        // The route re-raises → 500 → daemon retries the same
        // batch → hits the same timeout → session livelocked
        // FOREVER. Exchanging the R93 F2 double-count for hard
        // stuck is worse. Bump the tx timeout to 30 s (covers
        // 500 rows × 60 ms RTT × 2 safety) and maxWait to 10 s
        // (default 2 s risks queue-storm 429s under contention).
        timeout: 30_000,
        maxWait: 10_000,
      });
      inserted += insertedSeqs.size;

      if (insertedSeqs.size > 0 || dToolsOk || dToolsBad) {
        // R124 F3: cap dToolsBad / dBlockedPayout for the OUTBOUND
        // webhook fan-out. Prior shape forwarded the raw sums
        // verbatim, but they are integer accumulations of the
        // request-supplied addToolsBlocked / addBlockedPayoutUsdMicros
        // fields (line ~455) — NOT re-derived from the DB. On the
        // ingest-token-leak threat model that R119 F2 / R123 F2 close
        // for session.upsert, an attacker POSTing a batch with
        // inflated blocked counts fans out policy.block webhooks
        // to Slack / PagerDuty / Datadog with the poisoned numbers.
        // Downstream consumers key blockedCount for severity and
        // blockedPayoutUsdMicros for financial impact — a fake
        // "blocked $9,999,999" wakes on-call and burns SIEM ingest.
        // Sanity ceiling: you can't block more tools than events
        // in the batch (one event = one tool call attempt), so
        // clamp dToolsBad to insertedSeqs.size. blockedPayout is
        // similarly clamped by insertedSeqs.size × a per-event
        // payout ceiling; here we forward the smaller of the
        // supplied sum and (blocked-count × MAX_PER_EVENT_PAYOUT)
        // where MAX_PER_EVENT_PAYOUT is set high enough not to
        // clip legitimate traffic (1e9 micros = $1000 per tool
        // call, well above realistic single-call spend). SIEM
        // consumers now can't be waked by a fabricated $9M block.
        const clampedBlockedCount = Math.min(dToolsBad, insertedSeqs.size);
        const MAX_PER_EVENT_BLOCKED_PAYOUT = 1_000_000_000;
        const clampedBlockedPayout = Math.min(
          dBlockedPayout,
          clampedBlockedCount * MAX_PER_EVENT_BLOCKED_PAYOUT,
        );
        bus.publish({
          type: "events.appended",
          orgId: daemon.orgId,
          deploymentId: daemon.deploymentId,
          sessionId: session.id,
          count: insertedSeqs.size,
          allowed: dToolsOk,
          blocked: clampedBlockedCount,
        });
        // Any block in this batch triggers policy.block webhooks so
        // Slack / PagerDuty / Datadog can wake an on-call responder.
        if (clampedBlockedCount > 0) {
          dispatchEvent({
            orgId: daemon.orgId,
            event: "policy.block",
            data: {
              deploymentId: daemon.deploymentId,
              sessionId: session.id,
              sessionExternalId: externalId,
              blockedCount: clampedBlockedCount,
              blockedPayoutUsdMicros: clampedBlockedPayout,
            },
            logger: req.log,
          });
        }
      }
    }
    return reply.send({
      inserted,
      ...(rejectedSealed.length > 0 ? { rejectedSealed } : {}),
      ...(droppedSkewed > 0 ? { droppedFuture: droppedSkewed } : {}),
      ...(droppedAncient > 0 ? { droppedAncient } : {}),
    });
  });

  // Post a signed receipt at session seal.
  app.post("/receipts", async (req, reply) => {
    const daemon = await authenticateDaemon(req, reply);
    if (!daemon) return;
    const body = receiptPayload.safeParse(req.body);
    if (!body.success) return reply.code(400).send({ error: "invalid_input" });
    const r = body.data;
    const session = await db.session.findUnique({
      where: {
        deploymentId_externalId: {
          deploymentId: daemon.deploymentId,
          externalId: r.sessionExternalId,
        },
      },
      select: { id: true },
    });
    if (!session) return reply.code(404).send({ error: "unknown_session" });
    // R93 F4: first-write-wins on the receipt row. Prior shape ran
    // an unconditional upsert, so an ingest-token holder (or an
    // attacker with a leaked token — the same threat model R92 F2
    // named for `ingestTokenHint`) could POST /receipts a second
    // time for a session that already sealed and silently replace
    // the body / sigB64 / keyIdHint / eventCount / receiptId.
    // Because the session status was already 'sealed' and stayed
    // 'sealed', no other guard fired. Overwriting a sealed
    // receipt destroys the prior authentic row a customer/auditor
    // may already have referenced, and can replace it with a
    // body whose signature no longer verifies against the pinned
    // pubkey — a downgrade attack on the compliance story
    // (verifier now renders 'verify failed' against the same
    // sessionId the customer trusted).
    //
    // Legitimate daemon retry semantics: mid-flight seal retries
    // carry the SAME receiptId, so match by receiptId to preserve
    // idempotency. A different receiptId means an intentional
    // rewrite → refuse with 409 + audit so a compromised token
    // surfaces in the trail.
    // R93 F4 + R94 F2: same-receiptId path must be BYTE-EXACT
    // idempotent — a legitimate daemon retry sends the SAME body
    // + sigB64 + keyIdHex, so a value-equal re-post is a no-op.
    // Prior R93 shape guarded only on receiptId inequality; an
    // attacker who observed the legitimate receiptId (via CI log,
    // Dockerfile leak, or an insider's own prior sealing) could
    // then POST {receiptId: <same>, body: <forged>,
    // sigB64: attacker_sign(forged)} — the guard passed, upsert
    // rewrote all payload fields, verifier now returns 'signature
    // does not verify' against the pinned pubkey for a sessionId
    // the customer already accepted. Downgrade attack that R93 F4
    // was supposed to close. Now: on any existing receipt, fetch
    // ALL fields and reject with 409 if any of {receiptId, body,
    // sigB64, keyIdHint, eventCount, issuedAt} differ from the
    // stored row. Byte-exact re-post → 200 (idempotent no-op).
    const existingReceipt = await db.receipt.findUnique({
      where: { sessionId: session.id },
      select: {
        receiptId: true,
        body: true,
        sigB64: true,
        keyIdHint: true,
        eventCount: true,
        issuedAt: true,
      },
    });
    if (existingReceipt) {
      const proposedKeyIdHint = r.keyIdHex.slice(0, 8);
      const differs =
        existingReceipt.receiptId !== r.receiptId ||
        existingReceipt.body !== r.body ||
        existingReceipt.sigB64 !== r.sigB64 ||
        existingReceipt.keyIdHint !== proposedKeyIdHint ||
        existingReceipt.eventCount !== r.eventCount ||
        existingReceipt.issuedAt.getTime() !== r.issuedAt.getTime();
      if (differs) {
        req.log.warn(
          {
            deploymentId: daemon.deploymentId,
            sessionId: session.id,
            existingReceiptId: existingReceipt.receiptId,
            proposedReceiptId: r.receiptId,
          },
          "ingest_receipt_overwrite_refused",
        );
        writeAudit(
          {
            orgId: daemon.orgId,
            event: "deployment.receipt_overwrite_refused",
            actorId: `daemon:${daemon.deploymentId}`,
            actorEmail: `daemon@${daemon.deploymentId}`,
            target: session.id,
            metadata: {
              deploymentId: daemon.deploymentId,
              sessionId: session.id,
              currentReceiptId: existingReceipt.receiptId,
              proposedReceiptId: r.receiptId,
              // Distinguish 'different-id' from 'same-id-different-payload'
              // in the trail so ops sees the exact bypass class.
              sameReceiptIdDifferentPayload:
                existingReceipt.receiptId === r.receiptId,
            },
            req,
          },
          req.log,
        );
        return reply.code(409).send({ error: "receipt_already_sealed" });
      }
      // R118 F2: byte-exact idempotent re-post. Return the
      // idempotent 200 WITHOUT touching session.stopReason /
      // stopReasonId — those aren't part of the byte-equality
      // check above (which only compares receiptId, body,
      // sigB64, keyIdHint, eventCount, issuedAt per R93 F4), so
      // an ingest-token holder could otherwise re-POST the
      // byte-identical receipt payload with a mutated top-level
      // stopReason to flip an already-sealed session's stop
      // reason indefinitely (e.g., relabel a legitimate
      // 'normal' completion as 'policy_block'). The signed
      // receipt.body is unchanged so the crypto verifier still
      // passes, but session.stopReason is what the SPA session
      // drawer + /me/export display — post-seal audit-trail
      // defacement, same class as R93 F4 at a sibling scope.
      // First-write-wins matches the receipt-row posture.
      bus.publish({
        type: "receipt.finalized",
        orgId: daemon.orgId,
        deploymentId: daemon.deploymentId,
        sessionId: session.id,
        receiptId: r.receiptId,
      });
      return reply.send({ ok: true });
    } else {
      // R120 F1: receipt.create + session.update MUST be atomic.
      // Prior shape was two independent DB round trips with no
      // $transaction wrapping. If the process died between them
      // (P1001 connection lost, P2024 pool timeout, statement
      // timeout, container SIGTERM during rolling deploy) or the
      // second call threw, the receipt row would commit but the
      // session would stay status="live" with stopReason=null.
      // On the daemon's next retry, the byte-exact check at line
      // ~590 would match the committed receipt → return idempotent
      // 200 at line 646 WITHOUT re-running session.update, leaving
      // the session permanently "live" with a fully-signed receipt.
      // Downstream: POST /ingest/events (line ~332) only rejects on
      // status==="sealed" so a "live" session accepts arbitrary
      // post-seal events, drifting session.promptTokens /
      // costUsdMicros away from the signed receipt.body's totals —
      // compliance defect. Same class as R94 F1 (events tx) and
      // R93 F4 / R118 F2 / R119 F2 (post-seal defacement).
      await db.$transaction(async (tx) => {
        await tx.receipt.create({
          data: {
            sessionId: session.id,
            receiptId: r.receiptId,
            body: r.body,
            sigB64: r.sigB64,
            keyIdHint: r.keyIdHex.slice(0, 8),
            eventCount: r.eventCount,
            issuedAt: r.issuedAt,
          },
        });
        await tx.session.update({
          where: { id: session.id },
          data: {
            status: "sealed",
            stopReasonId: r.stopReasonId,
            stopReason: r.stopReason,
          },
        });
      });
    }
    bus.publish({
      type: "receipt.finalized",
      orgId: daemon.orgId,
      deploymentId: daemon.deploymentId,
      sessionId: session.id,
      receiptId: r.receiptId,
    });
    return reply.send({ ok: true });
  });
}
