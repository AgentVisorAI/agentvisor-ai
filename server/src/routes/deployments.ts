import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { db } from "../db.js";
import { hashPassword, randomToken } from "../lib/auth.js";
import { requireSession } from "../lib/session-middleware.js";

const envSchema = z.enum(["production", "staging", "development"]);

function tokenHint(token: string): string {
  return token.slice(0, 8);
}

export async function deploymentRoutes(app: FastifyInstance): Promise<void> {
  // List every deployment in the caller's active org.
  app.get("/", async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    const deployments = await db.deployment.findMany({
      where: { orgId: claims.orgId },
      orderBy: { createdAt: "asc" },
      select: {
        id: true,
        name: true,
        environment: true,
        publicKeyHex: true,
        ingestTokenHint: true,
        lastIngestAt: true,
        createdAt: true,
      },
    });
    return reply.send({ deployments });
  });

  // Create a new deployment. The plaintext ingest token is returned once and
  // only once — the client must show it to the operator and let them copy it
  // into the daemon's config file.
  app.post("/", async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    if (claims.membershipRole === "member") {
      return reply.code(403).send({ error: "forbidden" });
    }
    const body = z
      .object({
        name: z.string().min(1).max(80).trim(),
        environment: envSchema.default("production"),
      })
      .safeParse(req.body);
    if (!body.success) {
      return reply.code(400).send({ error: "invalid_input" });
    }
    const plaintextToken = randomToken(24);
    const ingestTokenHash = await hashPassword(plaintextToken);
    const deployment = await db.deployment.create({
      data: {
        orgId: claims.orgId,
        name: body.data.name,
        environment: body.data.environment,
        ingestTokenHash,
        ingestTokenHint: tokenHint(plaintextToken),
      },
      select: {
        id: true,
        name: true,
        environment: true,
        ingestTokenHint: true,
        createdAt: true,
      },
    });
    return reply.code(201).send({
      deployment,
      // Shown once. If lost, the user rotates.
      ingestToken: plaintextToken,
    });
  });

  // Rotate the ingest token. Invalidates any existing daemon posts using the
  // old value at the next call.
  app.post("/:id/rotate-token", async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    if (claims.membershipRole === "member") {
      return reply.code(403).send({ error: "forbidden" });
    }
    const params = z.object({ id: z.string() }).safeParse(req.params);
    if (!params.success) return reply.code(400).send({ error: "invalid_id" });
    const owned = await db.deployment.findFirst({
      where: { id: params.data.id, orgId: claims.orgId },
      select: { id: true },
    });
    if (!owned) return reply.code(404).send({ error: "not_found" });
    const plaintextToken = randomToken(24);
    const ingestTokenHash = await hashPassword(plaintextToken);
    await db.deployment.update({
      where: { id: owned.id },
      data: { ingestTokenHash, ingestTokenHint: tokenHint(plaintextToken) },
    });
    return reply.send({ ingestToken: plaintextToken });
  });

  app.delete("/:id", async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    if (claims.membershipRole === "member") {
      return reply.code(403).send({ error: "forbidden" });
    }
    const params = z.object({ id: z.string() }).safeParse(req.params);
    if (!params.success) return reply.code(400).send({ error: "invalid_id" });
    const owned = await db.deployment.findFirst({
      where: { id: params.data.id, orgId: claims.orgId },
      select: { id: true },
    });
    if (!owned) return reply.code(404).send({ error: "not_found" });
    await db.deployment.delete({ where: { id: owned.id } });
    return reply.code(204).send();
  });
}
