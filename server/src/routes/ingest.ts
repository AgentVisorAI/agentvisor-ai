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
    const nextStatus =
      existing?.status === "sealed" && s.status !== "sealed" ? existing.status : s.status;
    const session = await db.session.upsert({
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
      update: {
        agent: s.agent,
        workflow: s.workflow,
        status: nextStatus,
        policyVersion: s.policyVersion,
        closedAt: s.closedAt,
      },
      select: { id: true, externalId: true },
    });
    bus.publish({
      type: "session.upsert",
      orgId: daemon.orgId,
      deploymentId: daemon.deploymentId,
      sessionId: session.id,
      externalId: session.externalId,
      agent: s.agent,
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
      const fresh = batch.filter((e) => {
        if (existingSeqs.has(e.seq)) return false;
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
      const insertedSeqs = new Set<number>();
      for (const row of rows) {
        try {
          await db.event.create({ data: row });
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
      inserted += insertedSeqs.size;

      // Recompute deltas from the actually-inserted subset.
      let dPrompt = 0;
      let dCompletion = 0;
      let dCost = 0;
      let dPayout = 0;
      let dBlockedPayout = 0;
      let dToolsOk = 0;
      let dToolsBad = 0;
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
        await db.session.update({
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

      if (insertedSeqs.size > 0 || dToolsOk || dToolsBad) {
        bus.publish({
          type: "events.appended",
          orgId: daemon.orgId,
          deploymentId: daemon.deploymentId,
          sessionId: session.id,
          count: insertedSeqs.size,
          allowed: dToolsOk,
          blocked: dToolsBad,
        });
        // Any block in this batch triggers policy.block webhooks so
        // Slack / PagerDuty / Datadog can wake an on-call responder.
        if (dToolsBad > 0) {
          dispatchEvent({
            orgId: daemon.orgId,
            event: "policy.block",
            data: {
              deploymentId: daemon.deploymentId,
              sessionId: session.id,
              sessionExternalId: externalId,
              blockedCount: dToolsBad,
              blockedPayoutUsdMicros: dBlockedPayout,
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
    const existingReceipt = await db.receipt.findUnique({
      where: { sessionId: session.id },
      select: { receiptId: true },
    });
    if (existingReceipt && existingReceipt.receiptId !== r.receiptId) {
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
          },
          req,
        },
        req.log,
      );
      return reply.code(409).send({ error: "receipt_already_sealed" });
    }
    await db.receipt.upsert({
      where: { sessionId: session.id },
      create: {
        sessionId: session.id,
        receiptId: r.receiptId,
        body: r.body,
        sigB64: r.sigB64,
        keyIdHint: r.keyIdHex.slice(0, 8),
        eventCount: r.eventCount,
        issuedAt: r.issuedAt,
      },
      update: {
        receiptId: r.receiptId,
        body: r.body,
        sigB64: r.sigB64,
        keyIdHint: r.keyIdHex.slice(0, 8),
        eventCount: r.eventCount,
        issuedAt: r.issuedAt,
      },
    });
    await db.session.update({
      where: { id: session.id },
      data: {
        status: "sealed",
        stopReasonId: r.stopReasonId,
        stopReason: r.stopReason,
      },
    });
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
