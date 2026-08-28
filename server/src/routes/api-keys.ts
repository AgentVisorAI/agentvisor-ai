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
import { canGrantRole, hashPassword, randomToken } from "../lib/auth.js";
import { writeAudit } from "../lib/audit.js";
import { requireSession } from "../lib/session-middleware.js";

const roleSchema = z.enum(["owner", "admin", "member"]);

export async function apiKeyRoutes(app: FastifyInstance): Promise<void> {
  app.get("/", async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    // R90 F2: API keys are more sensitive than webhook URLs
    // (R89 F3): they are the org's non-user auth material.
    // Prior shape gated only POST / and DELETE /:id on
    // membershipRole !== 'member'; GET / would return, to a
    // plain member: every key's name, role (including
    // owner/admin), tokenHint (8-char plaintext prefix —
    // enough to match a leaked key in a public gist against
    // the org's inventory), createdByEmail, lastUsedAt. Recon
    // for social-engineering ("please rotate the prod-CI key
    // you own") and for correlating leaks to specific
    // creators. Same RBAC posture as the CRUD path.
    if (claims.membershipRole === "member") {
      return reply.code(403).send({ error: "forbidden" });
    }
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
    // R83 F1: block admin minting an OWNER-scoped API key
    // (owner unlocks whole-org delete + SAML keypair rotate).
    if (!canGrantRole(claims.membershipRole, body.data.role)) {
      return reply.code(403).send({ error: "cannot_grant_role_above_own" });
    }

    const plaintextBody = randomToken(28); // 224 bits of randomness
    const plaintext = "av_srv_" + plaintextBody;
    const tokenHash = await hashPassword(plaintext);
    // R104 F1 + F2: resolve claims.sub to the ULTIMATE human user
    // id before persisting createdById. For a cookie session
    // claims.sub is already the user's cuid; for an API-key
    // session claims.sub is the string 'apikey:<K1.id>' — the
    // literal parent-key id. Prior shape stored the 'apikey:...'
    // literal, which meant:
    //   (F1 HIGH) R103's revocation query filtered on
    //     createdById: userId, which never matched sub-keys →
    //     every K2 minted via K1 survived K1's creator's
    //     demotion/removal → persistent-privilege primitive
    //     survived the R103 fence.
    //   (F2 LOW-MED) The subsequent user.findUnique lookup by
    //     'apikey:...' returned null → createdByEmail stayed
    //     null → Console list rendered every sub-key as
    //     unknown-creator, breaking forensic chain-of-custody.
    // Walk the chain: at each step, if claims.sub starts with
    // 'apikey:', look up the parent key by id and take its
    // createdById; loop until we hit a real user id or a null
    // (bounded to 8 hops for safety against a pathological
    // cycle from historical data). Also snapshot the ultimate
    // user's email at create time.
    let effectiveCreatorId: string | null = claims.sub;
    let hops = 0;
    while (effectiveCreatorId && effectiveCreatorId.startsWith("apikey:") && hops < 8) {
      const parentId: string = effectiveCreatorId.slice("apikey:".length);
      const parent: { createdById: string | null } | null = await db.apiKey.findUnique({
        where: { id: parentId },
        select: { createdById: true },
      });
      effectiveCreatorId = parent?.createdById ?? null;
      hops++;
    }
    const creatorUser = effectiveCreatorId
      ? await db.user.findUnique({
          where: { id: effectiveCreatorId },
          select: { id: true, email: true },
        })
      : null;
    const key = await db.apiKey.create({
      data: {
        orgId: claims.orgId,
        name: body.data.name,
        tokenHash,
        tokenHint: plaintextBody.slice(0, 8),
        role: body.data.role,
        createdById: creatorUser?.id ?? null,
        createdByEmail: creatorUser?.email ?? null,
      },
      select: { id: true, name: true, tokenHint: true, role: true, createdAt: true },
    });
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
