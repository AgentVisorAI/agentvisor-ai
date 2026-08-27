/**
 * Team members + invites API.
 *
 *   GET    /members                   — list current members of caller's org
 *   PATCH  /members/:userId           — change role (owner/admin only)
 *   DELETE /members/:userId           — remove from org (owner/admin, not self)
 *
 *   POST   /members/invites           — send invite (owner/admin)
 *   GET    /members/invites           — list pending invites
 *   DELETE /members/invites/:id       — revoke pending invite
 *
 *   POST   /members/invites/accept    — anonymous. Body: { token, email,
 *                                       [password], [displayName] }.
 *                                       Creates a user + membership if new,
 *                                       or just adds membership if the
 *                                       email already has an account, then
 *                                       mints an av_session.
 *
 * Invite tokens are argon2-hashed. Plaintext is emailed once; the row
 * only stores the hash. A 7-day TTL is enforced at accept time.
 */

import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { randomBytes } from "node:crypto";
import { db } from "../db.js";
import { env } from "../env.js";
import {
  SESSION_COOKIE_OPTS,
  hashPassword,
  mintSession,
  randomToken,
  verifyPassword,
} from "../lib/auth.js";
import { writeAudit } from "../lib/audit.js";
import { dispatchEvent } from "../lib/webhooks.js";
import { getMailer, inviteMail } from "../lib/mail.js";
import { requireSession } from "../lib/session-middleware.js";

const roleSchema = z.enum(["owner", "admin", "member"]);
const emailSchema = z
  .string()
  .toLowerCase()
  .trim()
  .min(3)
  .max(320)
  .regex(/^[^\s@]+@[^\s@]+\.[^\s@]+$/, "must be a valid email");

export async function memberRoutes(app: FastifyInstance): Promise<void> {
  // -------------------------------------------------------------------
  // MEMBERS
  // -------------------------------------------------------------------

  app.get("/", async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    const rows = await db.membership.findMany({
      where: { orgId: claims.orgId },
      include: { user: true },
      orderBy: { createdAt: "asc" },
    });
    return reply.send({
      members: rows.map((m) => ({
        userId: m.userId,
        email: m.user.email,
        displayName: m.user.displayName,
        role: m.role,
        joinedAt: m.createdAt,
      })),
    });
  });

  app.patch<{ Params: { userId: string } }>("/:userId", async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    if (claims.membershipRole === "member") {
      return reply.code(403).send({ error: "forbidden" });
    }
    const body = z
      .object({ role: roleSchema })
      .safeParse(req.body);
    if (!body.success) return reply.code(400).send({ error: "invalid_input" });
    if (claims.sub === req.params.userId && body.data.role !== claims.membershipRole) {
      // Prevent an owner from demoting themselves and locking out the
      // org. If they want to leave, use DELETE /members/:userId — that
      // path also refuses if they'd be the last owner.
      return reply.code(400).send({ error: "cannot_change_own_role" });
    }
    const existing = await db.membership.findFirst({
      where: { userId: req.params.userId, orgId: claims.orgId },
    });
    if (!existing) return reply.code(404).send({ error: "not_found" });
    // R79 HIGH (Class B): serialize the last-owner check with the
    // role update so two concurrent PATCH-to-non-owner or one
    // PATCH+one DELETE can't both pass the `count() <= 1` guard
    // and leave the org with ZERO owners. Prior shape ran
    // count() and update() as separate statements; two concurrent
    // owner-demotions each read count=2, each pass the check,
    // each mutate → tenant silently bricked (owner-only endpoints
    // become unreachable). Prisma's Serializable isolation
    // catches the read-write dependency and aborts one of the
    // transactions; caller sees a retryable error surface.
    let updated;
    try {
      updated = await db.$transaction(
        async (tx) => {
          const stillOwner =
            (await tx.membership.findUnique({ where: { id: existing.id } }))?.role ===
            "owner";
          if (stillOwner && body.data.role !== "owner") {
            const ownerCount = await tx.membership.count({
              where: { orgId: claims.orgId, role: "owner" },
            });
            if (ownerCount <= 1) {
              throw new Error("last_owner");
            }
          }
          return await tx.membership.update({
            where: { id: existing.id },
            data: { role: body.data.role },
          });
        },
        { isolationLevel: "Serializable" },
      );
    } catch (e) {
      if (e instanceof Error && e.message === "last_owner") {
        return reply.code(400).send({ error: "last_owner" });
      }
      // Serializable isolation aborts with P2034 (write conflict);
      // client retries the whole flow safely.
      if (
        typeof e === "object" && e !== null &&
        (e as { code?: string }).code === "P2034"
      ) {
        return reply.code(409).send({ error: "concurrent_modification_retry" });
      }
      throw e;
    }
    writeAudit(
      {
        orgId: claims.orgId,
        event: "member.role_changed",
        actorId: claims.sub,
        target: (await db.user.findUnique({ where: { id: existing.userId }, select: { email: true } }))?.email ?? existing.userId,
        metadata: { fromRole: existing.role, toRole: updated.role },
        req,
      },
      req.log,
    );
    return reply.send({ ok: true });
  });

  app.delete<{ Params: { userId: string } }>("/:userId", async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    if (claims.membershipRole === "member" && claims.sub !== req.params.userId) {
      return reply.code(403).send({ error: "forbidden" });
    }
    const existing = await db.membership.findFirst({
      where: { userId: req.params.userId, orgId: claims.orgId },
      include: { user: true },
    });
    if (!existing) return reply.code(404).send({ error: "not_found" });
    // R79 HIGH (Class B): same serializable transaction discipline
    // as the PATCH path above. Two concurrent owner-leaves (or one
    // PATCH-demote + one DELETE-leave) must not both pass the
    // `count() <= 1` guard.
    try {
      await db.$transaction(
        async (tx) => {
          const current = await tx.membership.findUnique({
            where: { id: existing.id },
          });
          if (!current) throw new Error("not_found");
          if (current.role === "owner") {
            const ownerCount = await tx.membership.count({
              where: { orgId: claims.orgId, role: "owner" },
            });
            if (ownerCount <= 1) {
              throw new Error("last_owner");
            }
          }
          await tx.membership.delete({ where: { id: existing.id } });
        },
        { isolationLevel: "Serializable" },
      );
    } catch (e) {
      if (e instanceof Error && e.message === "last_owner") {
        return reply.code(400).send({ error: "last_owner" });
      }
      if (e instanceof Error && e.message === "not_found") {
        return reply.code(404).send({ error: "not_found" });
      }
      if (
        typeof e === "object" && e !== null &&
        (e as { code?: string }).code === "P2034"
      ) {
        return reply.code(409).send({ error: "concurrent_modification_retry" });
      }
      throw e;
    }
    writeAudit(
      {
        orgId: claims.orgId,
        event: claims.sub === req.params.userId ? "member.left" : "member.removed",
        actorId: claims.sub,
        target: existing.user.email,
        metadata: { removedUserId: existing.userId },
        req,
      },
      req.log,
    );
    return reply.code(204).send();
  });

  // -------------------------------------------------------------------
  // INVITES
  // -------------------------------------------------------------------

  app.post("/invites", async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    if (claims.membershipRole === "member") {
      return reply.code(403).send({ error: "forbidden" });
    }
    const body = z
      .object({
        email: emailSchema,
        role: roleSchema.default("member"),
      })
      .safeParse(req.body);
    if (!body.success) return reply.code(400).send({ error: "invalid_input" });

    const inviter = await db.user.findUnique({ where: { id: claims.sub } });
    const org = await db.org.findUnique({ where: { id: claims.orgId } });
    if (!inviter || !org) return reply.code(404).send({ error: "not_found" });

    // If a membership already exists for this email in this org, short-circuit.
    const existingUser = await db.user.findUnique({
      where: { email: body.data.email },
      include: { memberships: { where: { orgId: claims.orgId } } },
    });
    if (existingUser?.memberships.length) {
      return reply.code(409).send({ error: "already_a_member" });
    }

    const plaintextToken = randomToken(32);
    const tokenHash = await hashPassword(plaintextToken);
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

    // Upsert — if there's already a pending invite for this email, refresh
    // it with a new token instead of erroring. Op-friendly.
    const inv = await db.invite.upsert({
      where: { orgId_email: { orgId: claims.orgId, email: body.data.email } },
      create: {
        orgId: claims.orgId,
        email: body.data.email,
        role: body.data.role,
        tokenHash,
        invitedById: inviter.id,
        invitedByEmail: inviter.email,
        expiresAt,
      },
      update: {
        tokenHash,
        role: body.data.role,
        invitedById: inviter.id,
        invitedByEmail: inviter.email,
        expiresAt,
        acceptedAt: null,
        revokedAt: null,
      },
    });

    // Send email — fire-and-forget so a stuck mailer doesn't 30s a request.
    const link = `${env.APP_BASE_URL.replace(/\/$/, "")}/app/#/accept-invite?token=${encodeURIComponent(plaintextToken)}&email=${encodeURIComponent(inv.email)}`;
    void (async () => {
      try {
        const mail = getMailer(req.log);
        const template = inviteMail(org.name, inviter.email, link);
        await mail.send({
          to: inv.email,
          subject: template.subject,
          text: template.text,
          html: template.html,
        });
        req.log.info({ inviteId: inv.id, mailer: mail.driver }, "invite_email_sent");
      } catch (err) {
        req.log.error({ err, inviteId: inv.id }, "invite_email_failed");
      }
    })();

    writeAudit(
      {
        orgId: claims.orgId,
        event: "member.invited",
        actorId: claims.sub,
        actorEmail: inviter.email,
        target: inv.email,
        metadata: { role: inv.role, inviteId: inv.id },
        req,
      },
      req.log,
    );
    dispatchEvent({
      orgId: claims.orgId,
      event: "member.invited",
      data: {
        inviteId: inv.id,
        email: inv.email,
        role: inv.role,
        invitedByEmail: inviter.email,
        expiresAt: inv.expiresAt.toISOString(),
      },
      logger: req.log,
    });

    return reply.code(201).send({
      invite: {
        id: inv.id,
        email: inv.email,
        role: inv.role,
        expiresAt: inv.expiresAt,
        createdAt: inv.createdAt,
        // Dev-only: return the accept URL so local drills / tests can
        // complete the flow without scraping the mailer log. In prod the
        // caller relies on the emailed link; this branch is stripped by
        // the boot check that requires a real mailer.
        ...(env.NODE_ENV !== "production"
          ? { acceptUrlDev: link }
          : {}),
      },
    });
  });

  app.get("/invites", async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    const rows = await db.invite.findMany({
      where: {
        orgId: claims.orgId,
        acceptedAt: null,
        revokedAt: null,
        expiresAt: { gt: new Date() },
      },
      orderBy: { createdAt: "desc" },
    });
    return reply.send({
      invites: rows.map((r) => ({
        id: r.id,
        email: r.email,
        role: r.role,
        invitedByEmail: r.invitedByEmail,
        expiresAt: r.expiresAt,
        createdAt: r.createdAt,
      })),
    });
  });

  app.delete<{ Params: { id: string } }>("/invites/:id", async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    if (claims.membershipRole === "member") {
      return reply.code(403).send({ error: "forbidden" });
    }
    const existing = await db.invite.findFirst({
      where: { id: req.params.id, orgId: claims.orgId },
    });
    if (!existing) return reply.code(404).send({ error: "not_found" });
    await db.invite.update({
      where: { id: existing.id },
      data: { revokedAt: new Date() },
    });
    writeAudit(
      {
        orgId: claims.orgId,
        event: "member.invite_revoked",
        actorId: claims.sub,
        target: existing.email,
        req,
      },
      req.log,
    );
    return reply.code(204).send();
  });

  // Anonymous — the invitee accepts. If they don't have an account we
  // create one with the provided password.
  app.post("/invites/accept", async (req, reply) => {
    const body = z
      .object({
        token: z.string().min(16).max(256),
        email: emailSchema,
        password: z.string().min(12).max(1024).optional(),
        displayName: z.string().max(80).optional(),
      })
      .safeParse(req.body);
    if (!body.success) return reply.code(400).send({ error: "invalid_input" });

    const inv = await db.invite.findUnique({
      where: { orgId_email: { orgId: "n/a", email: body.data.email } },
    }).catch(() => null);
    // The orgId isn't in the request — look up by email + verify by token.
    const candidates = await db.invite.findMany({
      where: {
        email: body.data.email,
        acceptedAt: null,
        revokedAt: null,
        expiresAt: { gt: new Date() },
      },
    });
    let matched: (typeof candidates)[number] | null = null;
    for (const c of candidates) {
      if (await verifyPassword(c.tokenHash, body.data.token)) {
        matched = c;
        break;
      }
    }
    if (!matched) return reply.code(401).send({ error: "invalid_or_expired_invite" });

    // Look up existing user; create if missing.
    let user = await db.user.findUnique({ where: { email: matched.email } });
    if (!user) {
      if (!body.data.password) {
        return reply.code(400).send({ error: "password_required_for_new_user" });
      }
      const passwordHash = await hashPassword(body.data.password);
      user = await db.user.create({
        data: {
          email: matched.email,
          passwordHash,
          displayName: body.data.displayName ?? null,
        },
      });
    }

    // R79 MEDIUM (Class B): mark the invite consumed atomically
    // via `updateMany({ where: { id, acceptedAt: null } })` and
    // abort on `count === 0`. Prior shape ran the membership
    // upsert and `invite.update` inside a transaction but the
    // update's where-clause only matched by `id` — no
    // `acceptedAt: null` guard. Two concurrent `/invites/accept`
    // calls with the same token both pass `verifyPassword` (same
    // hash), both enter the transaction, both flip `acceptedAt`,
    // both mint session cookies. Combined with a phished/stolen
    // invite link, both attacker and legitimate invitee end up
    // with authenticated sessions before the invite is marked
    // consumed. `updateMany` with the null-guard makes the second
    // caller's UPDATE affect 0 rows; we detect that and abort
    // the whole flow.
    const [_, inviteConsumed] = await db.$transaction([
      db.membership.upsert({
        where: { userId_orgId: { userId: user.id, orgId: matched.orgId } },
        create: {
          userId: user.id,
          orgId: matched.orgId,
          role: matched.role,
        },
        update: {}, // Already a member? Fine, just proceed.
      }),
      db.invite.updateMany({
        where: {
          id: matched.id,
          acceptedAt: null,
          revokedAt: null,
        },
        data: { acceptedAt: new Date() },
      }),
    ]);
    if (inviteConsumed.count === 0) {
      // Lost the race with another concurrent /invites/accept.
      // The other call has already accepted this invite and
      // minted its own session. Refuse to mint a duplicate.
      return reply.code(409).send({ error: "invite_already_consumed" });
    }

    const token = await mintSession({
      sub: user.id,
      orgId: matched.orgId,
      membershipRole: matched.role as "owner" | "admin" | "member",
    });
    reply.setCookie(env.SESSION_COOKIE_NAME, token, SESSION_COOKIE_OPTS);
    writeAudit(
      {
        orgId: matched.orgId,
        event: "member.invite_accepted",
        actorId: user.id,
        actorEmail: user.email,
        target: user.email,
        metadata: { role: matched.role, inviteId: matched.id },
        req,
      },
      req.log,
    );
    return reply.send({
      user: { id: user.id, email: user.email, displayName: user.displayName },
      org: { id: matched.orgId, role: matched.role },
    });
  });
}
