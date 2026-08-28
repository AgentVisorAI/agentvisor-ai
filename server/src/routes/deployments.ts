import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { db } from "../db.js";
import { hashPassword, randomToken } from "../lib/auth.js";
import { writeAudit } from "../lib/audit.js";
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
    const isMember = claims.membershipRole === "member";
    const deployments = await db.deployment.findMany({
      where: { orgId: claims.orgId },
      orderBy: { createdAt: "asc" },
      select: {
        id: true,
        name: true,
        environment: true,
        publicKeyHex: true,
        // R92 F2: `ingestTokenHint` is the first 8 chars of the
        // plaintext ingest token — 48 bits of the auth material.
        // R90 F2's rationale for hiding API-key hints from members
        // applies verbatim: ingest tokens routinely leak via
        // Dockerfiles, k8s manifests, CI logs; a hostile member
        // who greps a public gist for `AV_INGEST_TOKEN=` and
        // matches against the org's hint inventory can bind a
        // leaked token to a specific deployment. Similarly
        // `lastIngestAt` reveals "which deployment is currently
        // quiet" — target-selection recon. Both fields are
        // useful for owner/admin dashboards but not needed for
        // a member's read-only session/receipt view. Members
        // still see id/name/environment/publicKeyHex (needed
        // to render receipt trust status).
        ingestTokenHint: !isMember,
        lastIngestAt: !isMember,
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
    let deployment;
    try {
      deployment = await db.deployment.create({
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
    } catch (err) {
      // Compound unique (orgId, name) — friendlier 409 than a 500 with
      // the Prisma error code leaked to the client. Two deployments
      // named 'prod' in the same org would confuse the deployments list
      // and the sessions filter dropdown, so we reject at write time.
      if (
        typeof err === "object" && err !== null &&
        (err as { code?: string }).code === "P2002"
      ) {
        return reply.code(409).send({ error: "deployment_name_in_use" });
      }
      throw err;
    }
    writeAudit(
      {
        orgId: claims.orgId,
        event: "deployment.create",
        actorId: claims.sub,
        target: deployment.name,
        metadata: {
          deploymentId: deployment.id,
          environment: deployment.environment,
        },
        req,
      },
      req.log,
    );
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
      select: { id: true, name: true },
    });
    if (!owned) return reply.code(404).send({ error: "not_found" });
    const plaintextToken = randomToken(24);
    const ingestTokenHash = await hashPassword(plaintextToken);
    await db.deployment.update({
      where: { id: owned.id },
      data: { ingestTokenHash, ingestTokenHint: tokenHint(plaintextToken) },
    });
    writeAudit(
      {
        orgId: claims.orgId,
        event: "deployment.token_rotated",
        actorId: claims.sub,
        target: owned.name,
        metadata: { deploymentId: owned.id },
        req,
      },
      req.log,
    );
    return reply.send({ ingestToken: plaintextToken });
  });

  app.delete<{ Params: { id: string }; Querystring: { force?: string } }>(
    "/:id",
    async (req, reply) => {
      const claims = requireSession(req, reply);
      if (!claims) return;
      if (claims.membershipRole === "member") {
        return reply.code(403).send({ error: "forbidden" });
      }
      const params = z.object({ id: z.string() }).safeParse(req.params);
      if (!params.success) return reply.code(400).send({ error: "invalid_id" });
      const owned = await db.deployment.findFirst({
        where: { id: params.data.id, orgId: claims.orgId },
        select: { id: true, name: true },
      });
      if (!owned) return reply.code(404).send({ error: "not_found" });
      // R94 F4: refuse to cascade-delete a deployment that still
      // has sealed receipts unless the caller passes ?force=1.
      // The schema has ON DELETE CASCADE all the way through
      // Deployment → Session → Event/Receipt, so a single admin
      // DELETE (or a phished admin's DELETE, or a compromised-
      // owner's DELETE) atomically vaporizes every signed receipt
      // for the deployment plus deployment.publicKeyHex — external
      // verifier bundles are then unverifiable (no anchor to
      // pin against), so this is a compliance-story downgrade
      // sibling of the R93 F4 receipt-overwrite path. Refusing
      // by default forces the operator to opt in with a
      // force=1 query flag AND we audit-log the force decision
      // with the receipt count so the trail shows the intent.
      // R94 F4 + R95 F2: run the receipt-count check + the delete
      // inside ONE serializable transaction so a mid-flight
      // /receipts seal that lands BETWEEN the count and the
      // delete can't slip through the guard and get vaporized by
      // the CASCADE. Prior R94 shape ran count() → check → delete
      // as three independent queries; the race window was
      // milliseconds but real, and the operator had NO signal in
      // the audit trail that a receipt had been destroyed
      // (forceDeletedReceipts: undefined because receiptCount at
      // check time was 0). Now: recount inside the tx immediately
      // before the delete, and refuse the whole tx if a fresh
      // seal landed. The audit metadata is always accurate.
      const force = req.query.force === "1" || req.query.force === "true";
      let receiptCount = 0;
      try {
        receiptCount = await db.$transaction(async (tx) => {
          const n = await tx.receipt.count({
            where: { session: { deploymentId: owned.id } },
          });
          if (n > 0 && !force) {
            throw new Error(`__has_sealed_receipts__${n}`);
          }
          await tx.deployment.delete({ where: { id: owned.id } });
          return n;
        }, {
          isolationLevel: "Serializable",
          // R99 F2: Prisma's default $transaction timeout is 5 s
          // which the cascade tree (Deployment → Session →
          // Event/Receipt, all ON DELETE CASCADE) doesn't fit on
          // realistic tenants. Same shape R95 F1 fixed for
          // /events and R98 F1 for /me/delete-account. This
          // sibling call site was missed. Prior behavior on a
          // busy deployment: P2028 escaped the catch block
          // (which only handled __has_sealed_receipts__ and
          // P2034), returning an uninformative 500 while the
          // tx rolled back. Owner retries → same result → the
          // deployment is effectively un-deletable. Bump to 60 s
          // to match R98 F1's shape; maxWait 10 s prevents
          // queue-storm 429s.
          timeout: 60_000,
          maxWait: 10_000,
        });
      } catch (e) {
        if (e instanceof Error && e.message.startsWith("__has_sealed_receipts__")) {
          const n = Number(e.message.split("__")[2] ?? "0");
          return reply.code(409).send({
            error: "deployment_has_sealed_receipts",
            receiptCount: n,
            hint: "pass ?force=1 to acknowledge cascade-deletion of receipts",
          });
        }
        if (
          typeof e === "object" && e !== null &&
          (e as { code?: string }).code === "P2034"
        ) {
          // Serializable write conflict — some other writer
          // touched Deployment/Session/Receipt concurrently.
          // Caller can retry.
          // R96 F4: audit the near-miss so investigators can
          // reconstruct that the operator was warned mid-flight
          // — the compliance-story concern R95 F2 raised
          // (concurrent seal race) leaves NO trail if we only
          // audit the eventual force-delete. The
          // deployment.delete_conflict event carries just the
          // deploymentId + timestamp; no leaky metadata.
          writeAudit(
            {
              orgId: claims.orgId,
              event: "deployment.delete_conflict",
              actorId: claims.sub,
              target: owned.name,
              metadata: { deploymentId: owned.id },
              req,
            },
            req.log,
          );
          return reply.code(409).send({ error: "concurrent_modification_retry" });
        }
        if (
          typeof e === "object" && e !== null &&
          (e as { code?: string }).code === "P2028"
        ) {
          // R99 F2: tx exceeded the 60 s budget. Surface a
          // retryable 409 with guidance rather than a generic
          // 500 so the operator (or CLI) knows to retry with
          // a lull between ingest bursts, or contact us for
          // a batched-delete path if the tenant is genuinely
          // too large for one tx.
          req.log.warn(
            { deploymentId: owned.id, orgId: claims.orgId },
            "deployment_delete_tx_timeout",
          );
          return reply.code(409).send({
            error: "deployment_delete_timeout",
            hint: "the cascade exceeded the transaction budget; retry, or contact support for a batched-delete path",
          });
        }
        throw e;
      }
      writeAudit(
        {
          orgId: claims.orgId,
          event: "deployment.delete",
          actorId: claims.sub,
          target: owned.name,
          metadata: {
            deploymentId: owned.id,
            forceDeletedReceipts: force && receiptCount > 0
              ? receiptCount
              : undefined,
          },
          req,
        },
        req.log,
      );
      return reply.code(204).send();
    },
  );
}
