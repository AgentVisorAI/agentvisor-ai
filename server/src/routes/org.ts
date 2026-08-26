/**
 * Org-level settings routes.
 *
 * Endpoints:
 *   GET   /retention              — current retention windows
 *   PATCH /retention              — update; owner+admin only
 *   POST  /retention/sweep-now    — manually trigger a sweep for the
 *                                    caller's org (owner+admin only).
 *                                    Returns counts so the operator can
 *                                    see what got deleted before the
 *                                    next scheduled tick.
 */
import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { db } from "../db.js";
import { requireSession } from "../lib/session-middleware.js";
import { writeAudit } from "../lib/audit.js";
import { sweepRetentionForOrg } from "../lib/retention.js";

export async function orgRoutes(app: FastifyInstance): Promise<void> {
  app.get("/retention", async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    const org = await db.org.findUnique({
      where: { id: claims.orgId },
      select: {
        sessionRetentionDays: true,
        auditRetentionDays: true,
      },
    });
    if (!org) return reply.code(404).send({ error: "not_found" });
    return reply.send({ retention: org });
  });

  app.patch("/retention", async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    if (claims.membershipRole === "member") {
      return reply.code(403).send({ error: "forbidden" });
    }
    const body = z
      .object({
        // 0 = keep forever. Otherwise 1-3650 (roughly 10 years) —
        // anything beyond that is almost certainly a typo.
        sessionRetentionDays: z.number().int().min(0).max(3650).optional(),
        auditRetentionDays: z.number().int().min(0).max(3650).optional(),
      })
      .safeParse(req.body);
    if (!body.success) return reply.code(400).send({ error: "invalid_input" });
    const updated = await db.org.update({
      where: { id: claims.orgId },
      data: body.data,
      select: {
        sessionRetentionDays: true,
        auditRetentionDays: true,
      },
    });
    writeAudit(
      {
        orgId: claims.orgId,
        event: "org.retention_updated",
        actorId: claims.sub,
        target: claims.orgId,
        metadata: {
          sessionRetentionDays: updated.sessionRetentionDays,
          auditRetentionDays: updated.auditRetentionDays,
        },
        req,
      },
      req.log,
    );
    return reply.send({ retention: updated });
  });

  app.post("/retention/sweep-now", async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    if (claims.membershipRole === "member") {
      return reply.code(403).send({ error: "forbidden" });
    }
    const result = await sweepRetentionForOrg(claims.orgId, req.log);
    writeAudit(
      {
        orgId: claims.orgId,
        event: "org.retention_swept",
        actorId: claims.sub,
        target: claims.orgId,
        metadata: {
          sessionsPurged: result.sessionsPurged,
          auditPurged: result.auditPurged,
          webhookDeliveriesPurged: result.webhookDeliveriesPurged,
        },
        req,
      },
      req.log,
    );
    return reply.send({ result });
  });
}
