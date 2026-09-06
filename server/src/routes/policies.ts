/**
 * Governance policies — the org's declarative policy inventory.
 *
 * These rows are what the console's Policies surface lists and edits.
 * Enforcement itself happens in the daemon (local WASM / schema policy
 * files); this API is the org-visible source of truth for what SHOULD
 * be enforced, who last touched it, and whether it is enabled. The
 * hits24h/blocks24h columns the SPA renders are aggregated from ingest
 * events carrying a policyName attribution (see policyCounters below);
 * policies with no attributed events in the window report zero rather
 * than an invented number.
 *
 * Endpoints:
 *   GET    /api/v1/policies       list (all roles — members need read)
 *   GET    /api/v1/policies/:id   detail
 *   POST   /api/v1/policies       create (owner/admin)
 *   PATCH  /api/v1/policies/:id   edit / enable / disable (owner/admin)
 *   DELETE /api/v1/policies/:id   remove (owner/admin)
 */

import type { FastifyInstance } from "fastify";
import { Prisma } from "@prisma/client";
import { z } from "zod";
import { db } from "../db.js";
import { writeAudit, resolveActor } from "../lib/audit.js";
import { requireSession } from "../lib/session-middleware.js";

// Same trim-then-min ordering as deployments.ts (R211 F1). Name is an
// identifier rendered in tables and audit lines; scope/kind are short
// labels; body is the policy source text (bounded so a hostile editor
// can't stuff megabytes into a text column the SPA re-renders).
const nameSchema = z.string().max(80).trim().min(1);
const kindSchema = z
  .string()
  .max(32)
  .regex(/^[a-z][a-z0-9_-]*$/, "kind must be a lowercase slug");
const scopeSchema = z.string().max(120).trim().min(1);
const descriptionSchema = z.string().max(500);
const bodySchema = z.string().max(16_384);

const policySelect = {
  id: true,
  name: true,
  kind: true,
  scope: true,
  enabled: true,
  description: true,
  body: true,
  updatedBy: true,
  createdAt: true,
  updatedAt: true,
} as const;

// Per-policy 24h counters, aggregated from ingest events that carry a
// policyName attribution (events.policyName ← eventPayload.policyName).
// Scoped through sessions.orgId so one org can never observe another's
// hit volume; the (policyName, occurredAt) index keeps this a range
// scan. Names with no matching Policy row are simply not returned —
// the console joins on the org's own policy names.
async function policyCounters(
  orgId: string,
): Promise<Map<string, { hits: number; blocks: number }>> {
  const rows = await db.$queryRaw<
    Array<{ policyname: string; hits: bigint; blocks: bigint }>
  >(Prisma.sql`
    SELECT e."policyName"                                   AS policyname,
           COUNT(*)::bigint                                 AS hits,
           COUNT(*) FILTER (WHERE e.kind = 'block')::bigint AS blocks
    FROM events e
    JOIN sessions s ON s.id = e."sessionId"
    WHERE s."orgId" = ${orgId}
      AND e."policyName" IS NOT NULL
      AND e."occurredAt" >= ${new Date(Date.now() - 24 * 3_600_000)}
    GROUP BY 1
  `);
  const map = new Map<string, { hits: number; blocks: number }>();
  for (const r of rows)
    map.set(r.policyname, { hits: Number(r.hits), blocks: Number(r.blocks) });
  return map;
}

// Counters come from the attribution aggregate when present; zero when
// the org's daemons haven't attributed any events in the window.
function toWire(
  p: { name: string } & Record<string, unknown>,
  counters?: Map<string, { hits: number; blocks: number }>,
) {
  const c = counters?.get(p.name);
  return { ...p, hits24h: c?.hits ?? 0, blocks24h: c?.blocks ?? 0 };
}

export async function policyRoutes(app: FastifyInstance): Promise<void> {
  app.get("/", async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    const rows = await db.policy.findMany({
      where: { orgId: claims.orgId },
      orderBy: [{ enabled: "desc" }, { updatedAt: "desc" }],
      select: policySelect,
    });
    const counters = await policyCounters(claims.orgId);
    return reply.send({ policies: rows.map((p) => toWire(p, counters)) });
  });

  app.get("/:id", async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    const params = z.object({ id: z.string().max(64) }).safeParse(req.params);
    if (!params.success) return reply.code(400).send({ error: "invalid_id" });
    // findFirst with orgId — never findUnique by id alone (cross-tenant
    // IDOR fence, same posture as deployments.ts).
    const row = await db.policy.findFirst({
      where: { id: params.data.id, orgId: claims.orgId },
      select: policySelect,
    });
    if (!row) return reply.code(404).send({ error: "not_found" });
    const counters = await policyCounters(claims.orgId);
    return reply.send({ policy: toWire(row, counters) });
  });

  app.post("/", async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    if (claims.membershipRole === "member") {
      return reply.code(403).send({ error: "forbidden" });
    }
    const body = z
      .object({
        name: nameSchema,
        kind: kindSchema.default("guardrail"),
        scope: scopeSchema.default("tool.*"),
        description: descriptionSchema.default(""),
        body: bodySchema.default(""),
        enabled: z.boolean().default(true),
      })
      .safeParse(req.body);
    if (!body.success) return reply.code(400).send({ error: "invalid_input" });

    const actor = await resolveActor(claims.sub);
    let policy;
    try {
      policy = await db.policy.create({
        data: {
          orgId: claims.orgId,
          ...body.data,
          updatedBy: actor.actorEmail ?? "",
        },
        select: policySelect,
      });
    } catch (err) {
      // Two policies with the same name in one org would make the
      // policies list and audit lines ambiguous — reject at write time
      // (same P2002 mapping as deployments.ts).
      if (
        typeof err === "object" && err !== null &&
        (err as { code?: string }).code === "P2002"
      ) {
        return reply.code(409).send({ error: "policy_name_in_use" });
      }
      throw err;
    }
    writeAudit(
      {
        orgId: claims.orgId,
        event: "policy.create",
        ...actor,
        target: policy.name,
        metadata: { policyId: policy.id, kind: policy.kind, scope: policy.scope },
        req,
      },
      req.log,
    );
    return reply.code(201).send({ policy: toWire(policy) });
  });

  app.patch("/:id", async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    if (claims.membershipRole === "member") {
      return reply.code(403).send({ error: "forbidden" });
    }
    const params = z.object({ id: z.string().max(64) }).safeParse(req.params);
    if (!params.success) return reply.code(400).send({ error: "invalid_id" });
    const body = z
      .object({
        name: nameSchema.optional(),
        kind: kindSchema.optional(),
        scope: scopeSchema.optional(),
        description: descriptionSchema.optional(),
        body: bodySchema.optional(),
        enabled: z.boolean().optional(),
      })
      .safeParse(req.body);
    if (!body.success) return reply.code(400).send({ error: "invalid_input" });

    const owned = await db.policy.findFirst({
      where: { id: params.data.id, orgId: claims.orgId },
      select: { id: true, name: true, enabled: true },
    });
    if (!owned) return reply.code(404).send({ error: "not_found" });

    const actor = await resolveActor(claims.sub);
    let policy;
    try {
      policy = await db.policy.update({
        where: { id: owned.id },
        data: { ...body.data, updatedBy: actor.actorEmail ?? "" },
        select: policySelect,
      });
    } catch (err) {
      if (
        typeof err === "object" && err !== null &&
        (err as { code?: string }).code === "P2002"
      ) {
        return reply.code(409).send({ error: "policy_name_in_use" });
      }
      throw err;
    }
    // Enable/disable is the security-relevant edge — give it its own
    // audit event names so a compliance reviewer can grep "who turned
    // the vendor allowlist off" without diffing metadata blobs.
    const event =
      body.data.enabled !== undefined && body.data.enabled !== owned.enabled
        ? body.data.enabled
          ? "policy.enabled"
          : "policy.disabled"
        : "policy.update";
    writeAudit(
      {
        orgId: claims.orgId,
        event,
        ...actor,
        target: policy.name,
        metadata: { policyId: policy.id, changed: Object.keys(body.data) },
        req,
      },
      req.log,
    );
    return reply.send({ policy: toWire(policy) });
  });

  app.delete("/:id", async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    if (claims.membershipRole === "member") {
      return reply.code(403).send({ error: "forbidden" });
    }
    const params = z.object({ id: z.string().max(64) }).safeParse(req.params);
    if (!params.success) return reply.code(400).send({ error: "invalid_id" });
    const owned = await db.policy.findFirst({
      where: { id: params.data.id, orgId: claims.orgId },
      select: { id: true, name: true },
    });
    if (!owned) return reply.code(404).send({ error: "not_found" });
    await db.policy.delete({ where: { id: owned.id } });
    const actor = await resolveActor(claims.sub);
    writeAudit(
      {
        orgId: claims.orgId,
        event: "policy.delete",
        ...actor,
        target: owned.name,
        metadata: { policyId: owned.id },
        req,
      },
      req.log,
    );
    return reply.code(204).send();
  });
}
