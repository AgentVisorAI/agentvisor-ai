/**
 * Webhook endpoint CRUD + delivery observability.
 *
 * Endpoints:
 *   GET    /            list endpoints for the org
 *   POST   /            create endpoint. Body: { name, url, events[] }.
 *                       Returns the secret ONE TIME (never returned again).
 *   PATCH  /:id         update name / url / events / isActive
 *   DELETE /:id         delete + cascade deliveries
 *   GET    /:id/deliveries[?cursor][?limit]
 *                       list delivery log
 *   POST   /:id/redeliver/:deliveryId
 *                       retry a delivery immediately (bypass sweeper)
 *   POST   /:id/test    fire a test event through the full pipeline
 *
 * All routes are RBAC-gated: owners + admins only. Members: 403.
 */

import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { db } from "../db.js";
import { requireSession } from "../lib/session-middleware.js";
import { writeAudit } from "../lib/audit.js";
import { dispatchEvent, generateWebhookSecret, validateWebhookUrl } from "../lib/webhooks.js";

const urlSchema = z
  .string()
  .url()
  .max(2048)
  .refine(
    (v) => v.startsWith("http://") || v.startsWith("https://"),
    "must_be_http_or_https",
  );

const eventsSchema = z
  .array(z.string().max(80))
  .min(1)
  .max(64);

function assertNotMember(claims: { membershipRole: string }): boolean {
  return claims.membershipRole !== "member";
}

export async function webhookRoutes(app: FastifyInstance): Promise<void> {
  app.get("/", async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    const rows = await db.webhookEndpoint.findMany({
      where: { orgId: claims.orgId },
      orderBy: { createdAt: "desc" },
      select: {
        id: true,
        name: true,
        url: true,
        events: true,
        isActive: true,
        createdAt: true,
        updatedAt: true,
      },
    });
    return reply.send({ endpoints: rows });
  });

  app.post("/", async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    if (!assertNotMember(claims)) {
      return reply.code(403).send({ error: "forbidden" });
    }
    const body = z
      .object({
        name: z.string().min(1).max(80).trim(),
        url: urlSchema,
        events: eventsSchema,
      })
      .safeParse(req.body);
    if (!body.success) return reply.code(400).send({ error: "invalid_input" });
    const ssrf = await validateWebhookUrl(body.data.url);
    if (!ssrf.ok) {
      return reply.code(400).send({ error: "ssrf_" + (ssrf.reason ?? "blocked") });
    }
    const secret = generateWebhookSecret();
    const ep = await db.webhookEndpoint.create({
      data: {
        orgId: claims.orgId,
        name: body.data.name,
        url: body.data.url,
        secret,
        events: body.data.events,
        isActive: true,
      },
      select: {
        id: true,
        name: true,
        url: true,
        events: true,
        isActive: true,
        createdAt: true,
      },
    });
    writeAudit(
      {
        orgId: claims.orgId,
        event: "webhook.created",
        actorId: claims.sub,
        target: ep.name,
        metadata: { endpointId: ep.id, url: ep.url, events: ep.events },
        req,
      },
      req.log,
    );
    return reply.code(201).send({ endpoint: ep, secret });
  });

  app.patch<{ Params: { id: string } }>("/:id", async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    if (!assertNotMember(claims)) {
      return reply.code(403).send({ error: "forbidden" });
    }
    const body = z
      .object({
        name: z.string().min(1).max(80).trim().optional(),
        url: urlSchema.optional(),
        events: eventsSchema.optional(),
        isActive: z.boolean().optional(),
      })
      .safeParse(req.body);
    if (!body.success) return reply.code(400).send({ error: "invalid_input" });
    if (body.data.url) {
      const ssrf = await validateWebhookUrl(body.data.url);
      if (!ssrf.ok) {
        return reply.code(400).send({ error: "ssrf_" + (ssrf.reason ?? "blocked") });
      }
    }
    const existing = await db.webhookEndpoint.findFirst({
      where: { id: req.params.id, orgId: claims.orgId },
    });
    if (!existing) return reply.code(404).send({ error: "not_found" });
    const updated = await db.webhookEndpoint.update({
      where: { id: existing.id },
      data: body.data,
      select: {
        id: true,
        name: true,
        url: true,
        events: true,
        isActive: true,
        updatedAt: true,
      },
    });
    writeAudit(
      {
        orgId: claims.orgId,
        event: "webhook.updated",
        actorId: claims.sub,
        target: updated.name,
        metadata: { endpointId: updated.id, changes: Object.keys(body.data) },
        req,
      },
      req.log,
    );
    return reply.send({ endpoint: updated });
  });

  app.delete<{ Params: { id: string } }>("/:id", async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    if (!assertNotMember(claims)) {
      return reply.code(403).send({ error: "forbidden" });
    }
    const existing = await db.webhookEndpoint.findFirst({
      where: { id: req.params.id, orgId: claims.orgId },
    });
    if (!existing) return reply.code(404).send({ error: "not_found" });
    await db.webhookEndpoint.delete({ where: { id: existing.id } });
    writeAudit(
      {
        orgId: claims.orgId,
        event: "webhook.deleted",
        actorId: claims.sub,
        target: existing.name,
        metadata: { endpointId: existing.id },
        req,
      },
      req.log,
    );
    return reply.code(204).send();
  });

  app.get<{ Params: { id: string }; Querystring: { limit?: string; cursor?: string } }>(
    "/:id/deliveries",
    async (req, reply) => {
      const claims = requireSession(req, reply);
      if (!claims) return;
      const ep = await db.webhookEndpoint.findFirst({
        where: { id: req.params.id, orgId: claims.orgId },
      });
      if (!ep) return reply.code(404).send({ error: "not_found" });
      const limit = Math.min(Math.max(parseInt(req.query.limit ?? "25", 10) || 25, 1), 200);
      const rows = await db.webhookDelivery.findMany({
        where: { endpointId: ep.id },
        orderBy: { createdAt: "desc" },
        take: limit + 1,
        ...(req.query.cursor
          ? { cursor: { id: req.query.cursor }, skip: 1 }
          : {}),
        select: {
          id: true,
          event: true,
          status: true,
          attempt: true,
          responseCode: true,
          errorMessage: true,
          createdAt: true,
          deliveredAt: true,
          nextRetryAt: true,
        },
      });
      const hasMore = rows.length > limit;
      const nextCursor = hasMore ? rows[limit - 1]?.id ?? null : null;
      return reply.send({
        deliveries: rows.slice(0, limit),
        nextCursor,
      });
    },
  );

  app.post<{ Params: { id: string } }>("/:id/test", async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    if (!assertNotMember(claims)) {
      return reply.code(403).send({ error: "forbidden" });
    }
    const ep = await db.webhookEndpoint.findFirst({
      where: { id: req.params.id, orgId: claims.orgId, isActive: true },
    });
    if (!ep) return reply.code(404).send({ error: "not_found" });
    dispatchEvent({
      orgId: claims.orgId,
      event: "test",
      data: { message: "This is a test event from AgentVisor.", endpointId: ep.id },
      logger: req.log,
    });
    writeAudit(
      {
        orgId: claims.orgId,
        event: "webhook.test_fired",
        actorId: claims.sub,
        target: ep.name,
        metadata: { endpointId: ep.id },
        req,
      },
      req.log,
    );
    return reply.send({ ok: true });
  });
}
