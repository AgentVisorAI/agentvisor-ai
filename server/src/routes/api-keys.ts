/**
 * Server-side API keys — programmatic access to the console API.
 *
 * Wire a CI job / Grafana dashboard / internal script as an *org*
 * rather than as a user. Keys are argon2-hashed at rest; plaintext
 * (av_srv_xxxx) is returned once at create time.
 *
 * Authenticate by sending:
 *   Authorization: Bearer av_srv_<plaintext>
 *
 * This is picked up in lib/session-middleware.ts alongside the JWT
 * cookie flow; a valid key grants a synthesized session with the key's
 * configured `role`.
 *
 * Endpoints:
 *   GET    /api/v1/keys       list active keys
 *   POST   /api/v1/keys       create; returns plaintext once
 *   DELETE /api/v1/keys/:id   revoke
 */

import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { db } from "../db.js";
import { hashPassword, randomToken } from "../lib/auth.js";
import { writeAudit } from "../lib/audit.js";
import { requireSession } from "../lib/session-middleware.js";

const roleSchema = z.enum(["owner", "admin", "member"]);

export async function apiKeyRoutes(app: FastifyInstance): Promise<void> {
  app.get("/", async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    const rows = await db.apiKey.findMany({
      where: { orgId: claims.orgId, revokedAt: null },
      orderBy: { createdAt: "desc" },
      select: {
        id: true,
        name: true,
        tokenHint: true,
        role: true,
        createdByEmail: true,
        lastUsedAt: true,
        createdAt: true,
      },
    });
    return reply.send({
      keys: rows.map((r) => ({
        id: r.id,
        name: r.name,
        hint: "av_srv_" + r.tokenHint + "…",
        role: r.role,
        createdByEmail: r.createdByEmail,
        lastUsedAt: r.lastUsedAt,
        createdAt: r.createdAt,
      })),
    });
  });

  app.post("/", async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    if (claims.membershipRole === "member") {
      return reply.code(403).send({ error: "forbidden" });
    }
    const body = z
      .object({
        name: z.string().min(1).max(80).trim(),
        role: roleSchema.default("admin"),
      })
      .safeParse(req.body);
    if (!body.success) return reply.code(400).send({ error: "invalid_input" });

    const plaintextBody = randomToken(28); // 224 bits of randomness
    const plaintext = "av_srv_" + plaintextBody;
    const tokenHash = await hashPassword(plaintext);
    const key = await db.apiKey.create({
      data: {
        orgId: claims.orgId,
        name: body.data.name,
        tokenHash,
        tokenHint: plaintextBody.slice(0, 8),
        role: body.data.role,
        createdById: claims.sub,
      },
      select: { id: true, name: true, tokenHint: true, role: true, createdAt: true },
    });
    // Snapshot the creator's email now (so a later user delete doesn't
    // blank the audit trail label).
    const me = await db.user.findUnique({
      where: { id: claims.sub },
      select: { email: true },
    });
    if (me) {
      await db.apiKey.update({
        where: { id: key.id },
        data: { createdByEmail: me.email },
      });
    }
    writeAudit(
      {
        orgId: claims.orgId,
        event: "apikey.created",
        actorId: claims.sub,
        target: key.name,
        metadata: { apiKeyId: key.id, role: key.role },
        req,
      },
      req.log,
    );
    return reply.code(201).send({
      key: {
        id: key.id,
        name: key.name,
        hint: "av_srv_" + key.tokenHint + "…",
        role: key.role,
        createdAt: key.createdAt,
      },
      // Shown once. If lost, the operator revokes + creates a new one.
      plaintextToken: plaintext,
    });
  });

  app.delete<{ Params: { id: string } }>("/:id", async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    if (claims.membershipRole === "member") {
      return reply.code(403).send({ error: "forbidden" });
    }
    const existing = await db.apiKey.findFirst({
      where: { id: req.params.id, orgId: claims.orgId, revokedAt: null },
    });
    if (!existing) return reply.code(404).send({ error: "not_found" });
    await db.apiKey.update({
      where: { id: existing.id },
      data: { revokedAt: new Date() },
    });
    writeAudit(
      {
        orgId: claims.orgId,
        event: "apikey.revoked",
        actorId: claims.sub,
        target: existing.name,
        metadata: { apiKeyId: existing.id },
        req,
      },
      req.log,
    );
    return reply.code(204).send();
  });
}
