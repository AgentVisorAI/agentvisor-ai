import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { db } from "../db.js";
import { hashPassword, randomToken } from "../lib/auth.js";
import { writeAudit, resolveActor } from "../lib/audit.js";
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
    // R145 F3: enrich actor email via resolveActor so the audit
    // renderer surfaces the operator's email instead of a raw cuid.
    const actor = await resolveActor(claims.sub);
    writeAudit(
      {
        orgId: claims.orgId,
        event: "deployment.create",
        ...actor,
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
    // R145 F3: enrich actor email.
    const actor = await resolveActor(claims.sub);
    writeAudit(
      {
        orgId: claims.orgId,
        event: "deployment.token_rotated",
        ...actor,
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
      // R147 F1: `?force=1` destroys signed receipts and
      // deployment.publicKeyHex — the anchor external verifier
      // bundles pin against. Same "admin uses org-wide primitive
      // to destroy compliance data" class R145 F1 closed for
      // retention narrowing and R146 F1 closed for
      // ip_allowlist writes. R94 F4's audit-metadata trail
      // (forceRequested + forceDeletedReceipts) records the
      // intent but doesn't stop the action — the operator whose
      // cookie is stolen doesn't have to be an owner. Gate the
      // force path on owner-only. Non-force DELETE (empty
      // deployments, 409 deployment_has_sealed_receipts) stays
      // admin-writable.
      const force = req.query.force === "1" || req.query.force === "true";
      if (force && claims.membershipRole !== "owner") {
        const forceDeniedActor = await resolveActor(claims.sub);
        writeAudit(
          {
            orgId: claims.orgId,
            event: "auth.step_up_denied",
            ...forceDeniedActor,
            note: "not_owner",
            metadata: {
              endpoint: "deployment.delete.force",
              deploymentId: owned.id,
            },
            req,
          },
          req.log,
        );
        return reply
          .code(403)
          .send({ error: "only_owner_can_force_delete_receipts" });
      }
      // R94 F4 + R95 F2: recount receipts + delete inside ONE
      // serializable transaction so a mid-flight /receipts seal
      // that lands BETWEEN the count and the delete can't slip
      // through the guard and get vaporized by the CASCADE. Audit
      // metadata (forceRequested + forceDeletedReceipts) is
      // written after commit so the trail is always accurate.
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
          // R146 F2: enrich actor email — the delete SUCCESS
          // sibling already uses resolveActor per R145 F3; the
          // conflict branch should match for consistent audit
          // rendering.
          const conflictActor = await resolveActor(claims.sub);
          writeAudit(
            {
              orgId: claims.orgId,
              event: "deployment.delete_conflict",
              ...conflictActor,
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
      // R145 F3: enrich actor email — the success path of
      // deployment.delete is a headliner event operators want
      // to see attributed by email.
      const actor = await resolveActor(claims.sub);
      writeAudit(
        {
          orgId: claims.orgId,
          event: "deployment.delete",
          ...actor,
          target: owned.name,
          metadata: {
            deploymentId: owned.id,
            // R107 F2: persist the force flag unconditionally so
            // forensics can distinguish 'operator explicitly
            // acknowledged cascade' from 'ordinary empty
            // deployment cleanup' even when receiptCount was 0
            // at tx-open time. R94 F4's intent was 'the trail
            // shows the intent'; prior shape omitted the field
            // entirely when receiptCount was 0, making the two
            // cases indistinguishable in the audit log.
            forceRequested: force,
            // R107 F2 + R113 F3: distinguish 'operator asked
            // to force-cascade an already-empty deployment'
            // (force=true, count=0) from 'ordinary empty
            // deployment cleanup' (force=false, count=0)
            // when downstream audit consumers scan the
            // numeric field only. Prior shape wrote 0 for
            // both cases; a query like
            // WHERE (metadata->>'forceDeletedReceipts')::int > 0
            // missed force=true-count=0 which R107 F2's
            // stated intent wanted surfaced. Now: null when
            // force=false (nothing was force-deleted); real
            // count otherwise (0 if empty, N if not). The
            // null vs 0 distinction survives the query.
            forceDeletedReceipts: force ? receiptCount : null,
          },
          req,
        },
        req.log,
      );
      return reply.code(204).send();
    },
  );
}
