import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import { db } from "../db.js";
import { verifyPassword } from "../lib/auth.js";
import { bus } from "../lib/bus.js";

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
    await db.deployment.update({
      where: { id: daemon.deploymentId },
      data: { publicKeyHex: body.data.publicKeyHex },
    });
    return reply.send({ ok: true });
  });

  // Upsert a session (idempotent on externalId).
  app.post("/sessions", async (req, reply) => {
    const daemon = await authenticateDaemon(req, reply);
    if (!daemon) return;
    const body = sessionUpsert.safeParse(req.body);
    if (!body.success) return reply.code(400).send({ error: "invalid_input" });
    const s = body.data;
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
        status: s.status,
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
    for (const [externalId, batch] of byExt) {
      const session = await db.session.findUnique({
        where: {
          deploymentId_externalId: {
            deploymentId: daemon.deploymentId,
            externalId,
          },
        },
        select: { id: true },
      });
      if (!session) continue; // ignore events for a session the daemon didn't upsert first

      // Rollups.
      let dPrompt = 0;
      let dCompletion = 0;
      let dCost = 0;
      let dPayout = 0;
      let dBlockedPayout = 0;
      let dToolsOk = 0;
      let dToolsBad = 0;
      for (const e of batch) {
        dPrompt += e.addPromptTokens;
        dCompletion += e.addCompletionTokens;
        dCost += e.addCostUsdMicros;
        dPayout += e.addPayoutUsdMicros;
        dBlockedPayout += e.addBlockedPayoutUsdMicros;
        dToolsOk += e.addToolsAllowed;
        dToolsBad += e.addToolsBlocked;
      }

      const rows = batch.map((e) => ({
        sessionId: session.id,
        seq: e.seq,
        kind: e.kind,
        tag: e.tag,
        body: e.body,
        sub: e.sub,
        occurredAt: e.occurredAt,
        journalCount: e.journalCount,
      }));
      const result = await db.event.createMany({
        data: rows,
        // Postgres supports skipDuplicates natively — duplicate seq values
        // from a daemon retry are dropped silently, keeping /events idempotent.
        skipDuplicates: true,
      });
      inserted += result.count;

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

      if (result.count > 0 || dToolsOk || dToolsBad) {
        bus.publish({
          type: "events.appended",
          orgId: daemon.orgId,
          deploymentId: daemon.deploymentId,
          sessionId: session.id,
          count: result.count,
          allowed: dToolsOk,
          blocked: dToolsBad,
        });
      }
    }
    return reply.send({ inserted });
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
