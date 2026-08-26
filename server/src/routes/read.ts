import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { db } from "../db.js";
import { requireSession } from "../lib/session-middleware.js";

export async function readRoutes(app: FastifyInstance): Promise<void> {
  // Fleet overview: aggregate stats + session list, scoped to the caller's org.
  app.get("/overview", async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    const query = z
      .object({
        deploymentId: z.string().optional(),
        limit: z.coerce.number().int().min(1).max(200).default(50),
      })
      .safeParse(req.query);
    if (!query.success) return reply.code(400).send({ error: "invalid_query" });

    const deploymentFilter = query.data.deploymentId
      ? {
          deployment: {
            orgId: claims.orgId,
            id: query.data.deploymentId,
          },
        }
      : { deployment: { orgId: claims.orgId } };

    const sessions = await db.session.findMany({
      where: deploymentFilter,
      orderBy: { openedAt: "desc" },
      take: query.data.limit,
      select: {
        id: true,
        externalId: true,
        agent: true,
        status: true,
        openedAt: true,
        closedAt: true,
        promptTokens: true,
        completionTokens: true,
        costUsdMicros: true,
        payoutUsdMicros: true,
        blockedPayoutUsdMicros: true,
        toolsAllowed: true,
        toolsBlocked: true,
        stopReason: true,
        deployment: { select: { id: true, name: true, environment: true } },
      },
    });

    // Rollups over the returned window.
    const stats = {
      sessions: sessions.length,
      live: sessions.filter((s) => s.status === "live").length,
      sealed: sessions.filter((s) => s.status === "sealed").length,
      blocked: sessions.filter((s) => s.status === "blocked").length,
      costUsdMicros: 0n,
      toolsAllowed: 0,
      toolsBlocked: 0,
      blockedPayoutUsdMicros: 0n,
    };
    for (const s of sessions) {
      stats.costUsdMicros += s.costUsdMicros;
      stats.toolsAllowed += s.toolsAllowed;
      stats.toolsBlocked += s.toolsBlocked;
      stats.blockedPayoutUsdMicros += s.blockedPayoutUsdMicros;
    }

    return reply.send({
      sessions: sessions.map((s) => ({
        ...s,
        costUsdMicros: s.costUsdMicros.toString(),
        payoutUsdMicros: s.payoutUsdMicros.toString(),
        blockedPayoutUsdMicros: s.blockedPayoutUsdMicros.toString(),
      })),
      stats: {
        ...stats,
        costUsdMicros: stats.costUsdMicros.toString(),
        blockedPayoutUsdMicros: stats.blockedPayoutUsdMicros.toString(),
      },
    });
  });

  // One session's event stream + rollup.
  app.get("/sessions/:id", async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    const params = z.object({ id: z.string() }).safeParse(req.params);
    if (!params.success) return reply.code(400).send({ error: "invalid_id" });
    const session = await db.session.findFirst({
      where: {
        id: params.data.id,
        deployment: { orgId: claims.orgId },
      },
      include: {
        deployment: { select: { id: true, name: true, environment: true } },
        events: { orderBy: { seq: "asc" } },
        receipt: true,
      },
    });
    if (!session) return reply.code(404).send({ error: "not_found" });
    return reply.send({
      session: {
        ...session,
        costUsdMicros: session.costUsdMicros.toString(),
        payoutUsdMicros: session.payoutUsdMicros.toString(),
        blockedPayoutUsdMicros: session.blockedPayoutUsdMicros.toString(),
      },
    });
  });

  // A signed receipt (verification is client-side using the deployment's
  // public key).
  app.get("/receipts/:sessionId", async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    const params = z
      .object({ sessionId: z.string() })
      .safeParse(req.params);
    if (!params.success) return reply.code(400).send({ error: "invalid_id" });
    const receipt = await db.receipt.findFirst({
      where: {
        sessionId: params.data.sessionId,
        session: { deployment: { orgId: claims.orgId } },
      },
      include: {
        session: {
          include: {
            deployment: { select: { publicKeyHex: true, name: true } },
          },
        },
      },
    });
    if (!receipt) return reply.code(404).send({ error: "not_found" });
    return reply.send({ receipt });
  });
}
