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
 *   POST   /:id/rotate-secret
 *                       mint a new HMAC signing secret. Returns the
 *                       plaintext ONE TIME. Old secret invalidated
 *                       atomically — receiving service must swap.
 *
 * All routes are RBAC-gated: owners + admins only. Members: 403.
 */

import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { db } from "../db.js";
import { requireSession } from "../lib/session-middleware.js";
import { writeAudit, resolveActor } from "../lib/audit.js";
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
    // R89 F3: webhook URLs commonly ARE authentication material —
    // Slack incoming-webhook tokens (`hooks.slack.com/services/…`),
    // Discord tokens (`discord.com/api/webhooks/…/…`), PagerDuty
    // integration URLs, etc. The module's header comment claims
    // 'All routes are RBAC-gated: owners + admins only. Members:
    // 403.' but the two GET routes were missing the check. A plain
    // member could list every endpoint's URL and POST to it
    // directly to bypass AgentVisor entirely (post as the org into
    // Slack, fire fake pages, etc). Matches the CRUD gate.
    if (!assertNotMember(claims)) {
      return reply.code(403).send({ error: "forbidden" });
    }
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
        // R211 F1: .max().trim().min() ordering — see auth.ts
        // orgNameSchema. Prior `.min(1).max(80).trim()` accepted
        // "    " (4 chars) → trimmed to "" and stored.
        name: z.string().max(80).trim().min(1),
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
        ...(await resolveActor(claims.sub)),
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
        // R211 F1: .max().trim().min() ordering — see auth.ts
        // orgNameSchema.
        name: z.string().max(80).trim().min(1).optional(),
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
        ...(await resolveActor(claims.sub)),
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
        ...(await resolveActor(claims.sub)),
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
      // R89 F3: deliveries include event names, error messages
      // (may leak partial URL or secret material via HTTP-error
      // bodies stored in errorMessage / responseBody), and
      // response codes for the destination integration. Match
      // GET / and CRUD RBAC.
      if (!assertNotMember(claims)) {
        return reply.code(403).send({ error: "forbidden" });
      }
      // R130 F3: swap the parseInt/manual clamp for a proper zod
      // schema so we get invalid_input on garbage limit + a
      // length cap on cursor. Matches the read.ts /audit shape.
      // Also gates cursor length so a hostile client can't send
      // a 10 MB string in the querystring.
      const q = z
        .object({
          limit: z.coerce.number().int().min(1).max(200).default(25),
          cursor: z.string().max(128).optional(),
        })
        .safeParse(req.query);
      if (!q.success) return reply.code(400).send({ error: "invalid_input" });
      const ep = await db.webhookEndpoint.findFirst({
        where: { id: req.params.id, orgId: claims.orgId },
      });
      if (!ep) return reply.code(404).send({ error: "not_found" });
      // R130 F1: same cursor guard as R129 F3. Stale cursor
      // (retention purged, sweeper deleted the row, forged
      // input) → Prisma P2016/P2032 → uncaught 500 through
      // setErrorHandler. This endpoint is worse than R129 F3's
      // sites because the console webhook-deliveries pane
      // paginates on it — an owner scrolling past a retention
      // deletion would hit it in normal use.
      let rows;
      try {
        rows = await db.webhookDelivery.findMany({
          where: { endpointId: ep.id },
          // R212 F1: id as secondary sort key so cursor pagination
          // is stable across rows tied on `createdAt`. Prisma emits
          // `ORDER BY "createdAt" DESC` with no tiebreaker on the
          // prior shape, and this table's `createdAt` ties are
          // routine: schema.prisma:443 sets `DateTime @default(now())`
          // and the webhook fanout (dispatchEvent → bulk enqueue on
          // policy.block etc.) plus the sweeper's 15 s batch inserts
          // often land many rows in the same millisecond. Without
          // the tiebreaker the cursor's `id` continues from an
          // arbitrary tied row: siblings sharing the boundary
          // `createdAt` are silently skipped (invisible to the
          // console operator scrolling the deliveries pane) or
          // reappear on the next page. Matches the sibling shape
          // at read.ts:238 (sessions), auth.ts:808 (export),
          // read.ts:537 (audit). No index change needed —
          // @@index([endpointId, createdAt]) covers the where +
          // first-key path; the id tiebreaker is a small
          // in-memory sort per page.
          orderBy: [{ createdAt: "desc" }, { id: "desc" }],
          take: q.data.limit + 1,
          ...(q.data.cursor
            ? { cursor: { id: q.data.cursor }, skip: 1 }
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
      } catch (err) {
        const code = (err as { code?: string } | null)?.code;
        const msg = (err as { message?: string } | null)?.message ?? "";
        if (code === "P2016" || code === "P2032" || /cursor/i.test(msg)) {
          return reply.code(400).send({ error: "invalid_cursor" });
        }
        throw err;
      }
      const hasMore = rows.length > q.data.limit;
      const nextCursor = hasMore ? rows[q.data.limit - 1]?.id ?? null : null;
      return reply.send({
        deliveries: rows.slice(0, q.data.limit),
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
    // R227 F2: split the lookup so we can distinguish "paused" from
    // "not found". Prior shape queried `where: { id, orgId, isActive:
    // true }` and returned 404 for both — SPA users clicking Send
    // test on a paused row (the exact case where they want to smoke
    // it before resuming) got an alarming "not_found" toast that
    // suggested the endpoint had been deleted.
    const ep = await db.webhookEndpoint.findFirst({
      where: { id: req.params.id, orgId: claims.orgId },
    });
    if (!ep) return reply.code(404).send({ error: "not_found" });
    if (!ep.isActive) {
      return reply.code(409).send({ error: "webhook_paused" });
    }
    dispatchEvent({
      orgId: claims.orgId,
      event: "test",
      // R94 F3: scope to the target endpoint. Prior shape fanned
      // out to every endpoint subscribing to 'test'/'*' — an
      // admin clicking 'Send test' on webhook A woke up on-call
      // via PagerDuty webhook B.
      onlyEndpointId: ep.id,
      data: { message: "This is a test event from AgentVisor.", endpointId: ep.id },
      logger: req.log,
    });
    writeAudit(
      {
        orgId: claims.orgId,
        event: "webhook.test_fired",
        ...(await resolveActor(claims.sub)),
        target: ep.name,
        metadata: { endpointId: ep.id },
        req,
      },
      req.log,
    );
    return reply.send({ ok: true });
  });

  // R100 F3: implement the redeliver endpoint documented in the
  // header docblock. Prior state was: docblock claimed the route
  // existed but no handler was registered → operators wiring a
  // "Retry delivery" button in the console received 404, failed
  // deliveries silently stayed in `failed`. Reuse the retry
  // sweeper's mechanism: flip the delivery row to
  // status='retrying' with nextRetryAt=now() so the next tick
  // picks it up cleanly. This avoids double-fire semantics
  // (dispatching a fresh event would fan out to ALL subscribers
  // of that event's name, wrong for a single-endpoint replay).
  app.post<{ Params: { id: string; deliveryId: string } }>(
    "/:id/redeliver/:deliveryId",
    async (req, reply) => {
      const claims = requireSession(req, reply);
      if (!claims) return;
      if (!assertNotMember(claims)) {
        return reply.code(403).send({ error: "forbidden" });
      }
      const ep = await db.webhookEndpoint.findFirst({
        where: { id: req.params.id, orgId: claims.orgId, isActive: true },
      });
      if (!ep) return reply.code(404).send({ error: "not_found" });
      const delivery = await db.webhookDelivery.findFirst({
        where: {
          id: req.params.deliveryId,
          endpointId: ep.id,
        },
        select: { id: true, status: true, event: true },
      });
      if (!delivery) return reply.code(404).send({ error: "delivery_not_found" });
      // Only failed / delivered deliveries can be manually
      // redelivered. Retrying is already the sweeper's job; a
      // pending row is mid-flight. Guarding here prevents an
      // impatient operator from stacking retries.
      if (delivery.status === "pending" || delivery.status === "retrying") {
        return reply.code(409).send({ error: "delivery_already_in_flight" });
      }
      await db.webhookDelivery.update({
        where: { id: delivery.id },
        data: {
          status: "retrying",
          nextRetryAt: new Date(),
          errorMessage: null,
          // R100 F3 + R101 F1: reset the attempt counter. Prior
          // R100 shape flipped status to 'retrying' but left
          // attempt at its final value (up to MAX_ATTEMPT=6 for
          // exhausted rows). The sweeper's deliverOne branch
          // then invoked with attempt+1=7 and scheduleRetry saw
          // 7 >= MAX_ATTEMPT → immediate re-fail with zero
          // backoff cycles. Net: the 'Retry delivery' button
          // gave the operator exactly one dead-end attempt with
          // no automatic follow-up, defeating the primary use
          // case (recovering from a transient failure that
          // exhausted the budget while the destination was
          // down). Reset to 0 so the sweeper drives a full
          // fresh backoff ladder.
          attempt: 0,
        },
      });
      writeAudit(
        {
          orgId: claims.orgId,
          event: "webhook.delivery_redelivered",
          ...(await resolveActor(claims.sub)),
          target: ep.name,
          metadata: {
            endpointId: ep.id,
            deliveryId: delivery.id,
            originalEvent: delivery.event,
          },
          req,
        },
        req.log,
      );
      return reply.send({ ok: true });
    },
  );

  // R112 F3: rotate the HMAC signing secret in place. Prior state:
  // WebhookEndpoint.secret was minted once at create and was
  // unrecoverable and immutable via the API. If a consumer's
  // secret store was compromised (Slack/PagerDuty side, CI log
  // leak, backup export), the ONLY remediation was DELETE +
  // recreate — the new endpoint got a new id and URL binding,
  // breaking every downstream integration referring to the old
  // endpoint and losing WebhookDelivery history. Meanwhile
  // attackers could continue forging X-AgentVisor-Signature
  // payloads against consumers until the endpoint was destroyed.
  // Compare the sibling deployment token which correctly exposes
  // POST /:id/rotate-token. This adds the analog for webhooks:
  // owner/admin only, atomic secret swap, plaintext returned
  // exactly once, audited.
  app.post<{ Params: { id: string } }>(
    "/:id/rotate-secret",
    async (req, reply) => {
      const claims = requireSession(req, reply);
      if (!claims) return;
      if (!assertNotMember(claims)) {
        return reply.code(403).send({ error: "forbidden" });
      }
      const ep = await db.webhookEndpoint.findFirst({
        where: { id: req.params.id, orgId: claims.orgId },
      });
      if (!ep) return reply.code(404).send({ error: "not_found" });
      const newSecret = generateWebhookSecret();
      await db.webhookEndpoint.update({
        where: { id: ep.id },
        data: { secret: newSecret },
      });
      writeAudit(
        {
          orgId: claims.orgId,
          event: "webhook.secret_rotated",
          ...(await resolveActor(claims.sub)),
          target: ep.name,
          metadata: { endpointId: ep.id },
          req,
        },
        req.log,
      );
      return reply.send({ secret: newSecret });
    },
  );
}
