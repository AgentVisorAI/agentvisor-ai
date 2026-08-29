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
import { writeAudit, resolveActor } from "../lib/audit.js";
import { sweepRetentionForOrg } from "../lib/retention.js";
import { ipMatchesAny, tryParseCidr } from "../lib/cidr.js";

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
    // R145 F1: admins could historically wipe forensic evidence by
    // (1) lowering auditRetentionDays to 1, (2) POST /retention/sweep-now
    // to purge every auditEntry older than now-1day, (3) re-raising
    // auditRetentionDays back to normal. Result: member.role_changed,
    // deployment.token_rotated, saml.*, mfa.credential_revoked, etc.
    // gone; the only telltale is a single org.retention_updated row
    // showing "1", which the admin trivially explains away.
    // Same "admin destroys compliance data" class R94 F4 gated for
    // deployment.delete (?force=1) and R118 F1 gated for
    // owner-scoped API-key DELETE — retention was the outstanding
    // sibling. Require owner for RETENTION NARROWING (either
    // dimension shrinking); loosening or holding steady still
    // works at admin.
    const currentRetention = await db.org.findUnique({
      where: { id: claims.orgId },
      select: { sessionRetentionDays: true, auditRetentionDays: true },
    });
    if (!currentRetention) return reply.code(404).send({ error: "not_found" });
    const narrowingSession =
      body.data.sessionRetentionDays !== undefined &&
      body.data.sessionRetentionDays !== 0 &&
      (currentRetention.sessionRetentionDays === 0 ||
        body.data.sessionRetentionDays < currentRetention.sessionRetentionDays);
    const narrowingAudit =
      body.data.auditRetentionDays !== undefined &&
      body.data.auditRetentionDays !== 0 &&
      (currentRetention.auditRetentionDays === 0 ||
        body.data.auditRetentionDays < currentRetention.auditRetentionDays);
    if ((narrowingSession || narrowingAudit) && claims.membershipRole !== "owner") {
      writeAudit(
        {
          orgId: claims.orgId,
          event: "auth.step_up_denied",
          actorId: claims.sub,
          note: "not_owner",
          metadata: { endpoint: "org.retention.narrow" },
          req,
        },
        req.log,
      );
      return reply
        .code(403)
        .send({ error: "only_owner_can_narrow_retention" });
    }
    const updated = await db.org.update({
      where: { id: claims.orgId },
      data: body.data,
      select: {
        sessionRetentionDays: true,
        auditRetentionDays: true,
      },
    });
    // R145 F3: enrich actor email — retention changes are exactly
    // the class of admin action ops wants attributed by email.
    const retentionActor = await resolveActor(claims.sub);
    writeAudit(
      {
        orgId: claims.orgId,
        event: "org.retention_updated",
        ...retentionActor,
        target: claims.orgId,
        metadata: {
          sessionRetentionDays: updated.sessionRetentionDays,
          auditRetentionDays: updated.auditRetentionDays,
          // R145 F1: include prior values so a narrowing attempt
          // is spelled out for reviewers grepping the audit trail
          // — auditor can `SELECT * WHERE event='org.retention_updated'
          // AND metadata->>'previousAuditRetentionDays' > metadata->>'auditRetentionDays'`.
          previousSessionRetentionDays: currentRetention.sessionRetentionDays,
          previousAuditRetentionDays: currentRetention.auditRetentionDays,
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
    // R145 F1: same rationale as PATCH /retention narrowing above.
    // sweep-now is the destructive execution leg — admin who
    // couldn't lower the window can't invoke the sweep either
    // (without narrowing first, this is a no-op purge of already-
    // expired rows, but by fencing owner-only we keep the primitive
    // consistent with the retention control itself).
    if (claims.membershipRole !== "owner") {
      writeAudit(
        {
          orgId: claims.orgId,
          event: "auth.step_up_denied",
          actorId: claims.sub,
          note: "not_owner",
          metadata: { endpoint: "org.retention.sweep_now" },
          req,
        },
        req.log,
      );
      return reply.code(403).send({ error: "only_owner_can_sweep" });
    }
    const result = await sweepRetentionForOrg(claims.orgId, req.log);
    // R145 F3: enrich actor email — destructive purge deserves
    // clear attribution.
    const sweepActor = await resolveActor(claims.sub);
    writeAudit(
      {
        orgId: claims.orgId,
        event: "org.retention_swept",
        ...sweepActor,
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

  app.get("/ip-allowlist", async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    // R93 F3: same read/write asymmetry as R92 F1 (invites) and
    // R91 F2 (audit). Members were able to read the org's trusted
    // CIDR blocks (recon: which corp VPN/bastion do admins egress
    // from) and their own detected req.ip (confirms whether their
    // stolen cookie would work from anywhere without alarm). The
    // sibling PATCH at line 117 already gates on non-member.
    if (claims.membershipRole === "member") {
      return reply.code(403).send({ error: "forbidden" });
    }
    const org = await db.org.findUnique({
      where: { id: claims.orgId },
      select: { ipAllowlist: true },
    });
    return reply.send({
      cidrs: org?.ipAllowlist ?? [],
      yourIp: req.ip,
    });
  });

  app.patch("/ip-allowlist", async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    if (claims.membershipRole === "member") {
      return reply.code(403).send({ error: "forbidden" });
    }
    const body = z
      .object({
        cidrs: z.array(z.string().min(1).max(64)).max(200),
      })
      .safeParse(req.body);
    if (!body.success) return reply.code(400).send({ error: "invalid_input" });

    // Reject any malformed CIDR — never silently drop rows.
    const cleaned: string[] = [];
    for (const raw of body.data.cidrs) {
      const trimmed = raw.trim();
      // Accept bare IP as /32 (v4) or /128 (v6) sugar.
      const withPrefix = trimmed.includes("/")
        ? trimmed
        : trimmed.includes(":")
          ? trimmed + "/128"
          : trimmed + "/32";
      const parsed = tryParseCidr(withPrefix);
      if (!parsed) {
        return reply.code(400).send({ error: "invalid_cidr", cidr: raw });
      }
      cleaned.push(withPrefix);
    }
    // Self-lockout guard: refuse to save a non-empty allowlist that
    // wouldn't include the caller's own current IP. The operator can
    // still deliberately shut themselves out by first opening a shell
    // and hitting the API directly, but the console UI can't do it by
    // accident.
    if (cleaned.length > 0 && !ipMatchesAny(req.ip, cleaned)) {
      return reply.code(400).send({ error: "would_lock_yourself_out", yourIp: req.ip });
    }
    const updated = await db.org.update({
      where: { id: claims.orgId },
      data: { ipAllowlist: cleaned },
      select: { ipAllowlist: true },
    });
    writeAudit(
      {
        orgId: claims.orgId,
        event: "org.ip_allowlist_updated",
        actorId: claims.sub,
        target: claims.orgId,
        metadata: { cidrs: updated.ipAllowlist, byIp: req.ip },
        req,
      },
      req.log,
    );
    return reply.send({ cidrs: updated.ipAllowlist });
  });
}
