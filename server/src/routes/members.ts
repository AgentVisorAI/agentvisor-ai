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
  canGrantRole,
  getDummyPasswordHash,
  hashPassword,
  mintSession,
  randomToken,
  verifyPassword,
} from "../lib/auth.js";
import { writeAudit, resolveActor } from "../lib/audit.js";
import { dispatchEvent } from "../lib/webhooks.js";
import { getMailer, inviteMail, adminMfaResetMail } from "../lib/mail.js";
import { perIpCookieOnly } from "../lib/rate-limit.js";
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
    // Per-member MFA flag so the console can offer "Reset MFA" only
    // where it means something. One groupBy, not N queries.
    const counts = await db.webauthnCredential.groupBy({
      by: ["userId"],
      where: { userId: { in: rows.map((m) => m.userId) } },
      _count: { userId: true },
    });
    const mfaByUser = new Set(counts.map((c) => c.userId));
    return reply.send({
      members: rows.map((m) => ({
        userId: m.userId,
        email: m.user.email,
        displayName: m.user.displayName,
        role: m.role,
        joinedAt: m.createdAt,
        mfaEnrolled: mfaByUser.has(m.userId),
      })),
    });
  });

  // Break-glass MFA recovery. A lost/destroyed passkey is a PERMANENT
  // lockout without this: password reset deliberately does not clear
  // MFA (that would gut it — mailbox compromise ⇒ MFA bypass), and
  // the self-service revoke in Settings requires being signed IN,
  // which the locked-out user can't do. Every serious IdP ships an
  // admin-side reset for exactly this reason. Threat posture:
  //   - owner/admin only, and never above the caller's own rank
  //     (admin can't strip an owner's MFA as a takeover step),
  //   - never self (the signed-in self-service path in Settings › SSO
  //     has its own password gate; allowing self here would just be a
  //     second, differently-shaped copy of it),
  //   - caller's OWN password as step-up (a stolen admin cookie must
  //     not be able to soften a victim account for ATO),
  //   - break-glass transaction on the TARGET mirrors the self-revoke
  //     leg (webauthn.ts DELETE): wipe credentials + fence all their
  //     sessions + revoke API keys they created — the credential being
  //     reset may be an attacker's enrollment, so everything minted
  //     under it is suspect,
  //   - the target is emailed (can't-unsee notice) — if they did NOT
  //     ask for this reset, their recovery path is a password reset.
  app.post<{ Params: { userId: string } }>("/:userId/reset-mfa", {
    config: { rateLimit: perIpCookieOnly(3, 60_000) },
  }, async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    if (claims.sub.startsWith("apikey:")) {
      return reply.code(403).send({ error: "cookie_session_required" });
    }
    if (claims.membershipRole === "member") {
      return reply.code(403).send({ error: "forbidden" });
    }
    if (claims.sub === req.params.userId) {
      return reply.code(400).send({ error: "use_self_service_revoke" });
    }
    const body = z
      .object({ password: z.string().min(1).max(1024) })
      .safeParse(req.body);
    if (!body.success) return reply.code(400).send({ error: "invalid_input" });
    // Uniform argon2 verify against a dummy hash on the no-user branch
    // — same anti-oracle shape as every step-up sibling.
    const stepUpUser = await db.user.findUnique({ where: { id: claims.sub } });
    const stepUpHash = stepUpUser?.passwordHash ?? (await getDummyPasswordHash());
    const stepUpOk = await verifyPassword(stepUpHash, body.data.password);
    if (!stepUpUser || !stepUpOk) {
      writeAudit(
        {
          orgId: claims.orgId,
          event: "auth.step_up_denied",
          actorId: claims.sub,
          ...(stepUpUser ? { actorEmail: stepUpUser.email } : {}),
          note: "invalid_password",
          metadata: { endpoint: "members.reset_mfa" },
          req,
        },
        req.log,
      );
      return reply.code(401).send({ error: "invalid_password" });
    }
    const target = await db.membership.findFirst({
      where: { userId: req.params.userId, orgId: claims.orgId },
      include: { user: true },
    });
    // Uniform 404: no oracle for user ids outside the org.
    if (!target) return reply.code(404).send({ error: "not_found" });
    if (!canGrantRole(claims.membershipRole, target.role as "owner" | "admin" | "member")) {
      return reply.code(403).send({ error: "cannot_mutate_target_above_own_rank" });
    }
    const credCount = await db.webauthnCredential.count({
      where: { userId: target.userId },
    });
    if (credCount === 0) {
      return reply.code(400).send({ error: "no_mfa_enrolled" });
    }
    await db.$transaction([
      db.webauthnCredential.deleteMany({ where: { userId: target.userId } }),
      db.user.update({
        where: { id: target.userId },
        data: {
          sessionRevokedAt: new Date(),
          // Same break-glass posture as reset-confirm: if the wiped
          // credential was an attacker's enrollment, a pending email
          // change they requested must not outlive the cleanup.
          pendingEmail: null,
          pendingEmailTokenHash: null,
          pendingEmailAt: null,
        },
      }),
      db.apiKey.updateMany({
        where: { createdById: target.userId, revokedAt: null },
        data: { revokedAt: new Date() },
      }),
    ]);
    writeAudit(
      {
        orgId: claims.orgId,
        event: "mfa.credentials_admin_reset",
        ...(await resolveActor(claims.sub)),
        target: target.user.email,
        metadata: { targetUserId: target.userId, credentialsRemoved: credCount },
        req,
      },
      req.log,
    );
    void (async () => {
      try {
        const mail = getMailer(req.log);
        await mail.send({
          to: target.user.email,
          ...adminMfaResetMail(stepUpUser.email),
        });
      } catch (e) {
        req.log.warn({ err: e }, "admin mfa reset mail send failed");
      }
    })();
    return reply.send({ ok: true, credentialsRemoved: credCount });
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
    // R83 F1: reject role escalation. Prior shape let an admin
    // grant OWNER to any target because the only gate was
    // `membershipRole !== "member"`. See lib/auth.ts canGrantRole
    // for the full attack surface (owner unlocks whole-org delete
    // + SAML keypair rotate).
    if (!canGrantRole(claims.membershipRole, body.data.role)) {
      return reply.code(403).send({ error: "cannot_grant_role_above_own" });
    }
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
    // R84 F1: block admins from MUTATING owners. R83 F1 only
    // checked the requested NEW role, so an admin could still
    // `PATCH /members/<owner> {role:"member"}` — canGrantRole
    // (admin, member) = true, and the R79 last-owner tx only
    // fires when the target is the LAST owner. Net effect: an
    // admin could quietly demote every-owner-but-one, stripping
    // the victim of manage-members/mint-owner-key/cascade-delete
    // /SAML-keypair-rotate rights, and (because R79's
    // cannot_change_own_role forbids self-elevation) the victim
    // could not recover on their own. Threat model is symmetric
    // to R83 F1: stripping owner is nearly as damaging as
    // granting it. Requires: the caller's rank ≥ the target's
    // current rank too. Owners can mutate anyone; admins can
    // only mutate admin/member rows; owner rows are immutable
    // to admins.
    if (!canGrantRole(claims.membershipRole, existing.role as "owner" | "admin" | "member")) {
      return reply.code(403).send({ error: "cannot_mutate_target_above_own_rank" });
    }
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
          // R84 F1 recheck under the serializable tx: the rank gate
          // above ran on a snapshot read OUTSIDE the transaction, so a
          // target promoted (e.g. member→owner by a concurrent owner
          // PATCH) between that read and this tx would be mutated by an
          // admin whose rank no longer covers them. Re-read and
          // re-apply the same gate on the current role.
          const current = await tx.membership.findUnique({ where: { id: existing.id } });
          if (!current) throw new Error("not_found");
          if (!canGrantRole(claims.membershipRole, current.role as "owner" | "admin" | "member")) {
            throw new Error("target_rank_changed");
          }
          const stillOwner = current.role === "owner";
          if (stillOwner && body.data.role !== "owner") {
            const ownerCount = await tx.membership.count({
              where: { orgId: claims.orgId, role: "owner" },
            });
            if (ownerCount <= 1) {
              throw new Error("last_owner");
            }
          }
          const upd = await tx.membership.update({
            where: { id: existing.id },
            data: { role: body.data.role },
          });
          // R90 F1: invalidate the demoted/promoted user's live JWT.
          // requireSession() populates req.session from the JWT
          // membershipRole claim verbatim, so a demoted admin/owner
          // holding a pre-change 7-day cookie retains prior
          // privileges — enough to mint an owner-scoped API key
          // (POST /api/v1/keys), invite a new admin, register a
          // webhook that exfiltrates data on next event, or (if
          // owner→member) rotate the SAML keypair / delete the
          // org. The only fence that voids an outstanding JWT is
          // user.sessionRevokedAt vs the JWT iat, so bump it
          // inside the same serializable tx as the role change.
          // Target must re-log in with the new role reflected in
          // a fresh JWT.
          await tx.user.update({
            where: { id: existing.userId },
            data: { sessionRevokedAt: new Date() },
          });
          // R103 F1: revoke every API key the target created that
          // still bears their pre-change role. session-middleware's
          // API-key auth path synthesizes membershipRole from
          // ApiKey.role WITHOUT consulting Membership.role — so a
          // demoted admin whose plaintext av_srv_ token is still
          // known continues to authenticate at the prior privilege
          // level, indefinitely. R90 F1 closes the JWT-cookie
          // vector; this closes the sibling API-key vector.
          // Only revoke keys whose role EXCEEDS the new role
          // (privilege downgrade); a same-level or upgrade change
          // doesn't need to invalidate.
          const RANK: Record<string, number> = { owner: 3, admin: 2, member: 1 };
          const newRank = RANK[body.data.role] ?? 0;
          await tx.apiKey.updateMany({
            where: {
              orgId: claims.orgId,
              createdById: existing.userId,
              revokedAt: null,
              role: {
                in: (["owner", "admin", "member"] as const).filter(
                  (r) => (RANK[r] ?? 0) > newRank,
                ),
              },
            },
            data: { revokedAt: new Date() },
          });
          return upd;
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
      if (e instanceof Error && e.message === "target_rank_changed") {
        return reply.code(403).send({ error: "cannot_mutate_target_above_own_rank" });
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
        ...(await resolveActor(claims.sub)),
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
    // R84 F1: DELETE has the same target-rank hole as PATCH.
    // Admin removing an owner via DELETE was gated only by the
    // R79 last-owner check, which fires only when the removed
    // member is the LAST remaining owner. So an admin could
    // remove every-owner-but-one and (after leaving the "last
    // owner" alone or racing with them) starve the org of
    // higher-privilege recovery. Self-removal is always
    // allowed — the last-owner tx below still catches the
    // "you'd be the last owner leaving" case.
    if (
      claims.sub !== req.params.userId &&
      !canGrantRole(claims.membershipRole, existing.role as "owner" | "admin" | "member")
    ) {
      return reply.code(403).send({ error: "cannot_mutate_target_above_own_rank" });
    }
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
          // R84 F1 recheck under the tx (same rationale as the PATCH
          // path): the rank gate above ran on a pre-transaction
          // snapshot; re-apply it on the current role so a target
          // promoted concurrently cannot be removed by a lower rank.
          if (
            claims.sub !== req.params.userId &&
            !canGrantRole(claims.membershipRole, current.role as "owner" | "admin" | "member")
          ) {
            throw new Error("target_rank_changed");
          }
          if (current.role === "owner") {
            const ownerCount = await tx.membership.count({
              where: { orgId: claims.orgId, role: "owner" },
            });
            if (ownerCount <= 1) {
              throw new Error("last_owner");
            }
          }
          await tx.membership.delete({ where: { id: existing.id } });
          // R103 F1: revoke every API key the removed user
          // created in this org. session-middleware's API-key
          // auth path synthesizes membershipRole from ApiKey.role
          // WITHOUT consulting Membership.role — the cookie path
          // correctly fails on memberships.length === 0, but the
          // API-key path has NO membership check, so an
          // ex-member's still-known av_srv_ token continues to
          // authenticate at the prior privilege level. Sibling
          // of R90 F1's JWT invalidation. Revoke ALL keys the
          // user created (not just above-rank) since they no
          // longer belong to the org.
          await tx.apiKey.updateMany({
            where: {
              orgId: claims.orgId,
              createdById: existing.userId,
              revokedAt: null,
            },
            data: { revokedAt: new Date() },
          });
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
      if (e instanceof Error && e.message === "target_rank_changed") {
        return reply.code(403).send({ error: "cannot_mutate_target_above_own_rank" });
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
        ...(await resolveActor(claims.sub)),
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
    // R83 F1: block admin inviting an attacker-controlled email as
    // OWNER (attacker accepts, gains org-delete power).
    if (!canGrantRole(claims.membershipRole, body.data.role)) {
      return reply.code(403).send({ error: "cannot_grant_role_above_own" });
    }

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

    // R122 F1: rung parity on the UPSERT PATH. R83 F1 above only
    // gates the caller's REQUESTED role — but the upsert can
    // silently rewrite an existing pending invite that was
    // minted at a higher tier. Chain:
    //   1. Outgoing owner O1 invites bob@x as role="owner",
    //      row stored with tokenHash=H_owner, invitedById=O1.
    //   2. Admin A1 invites bob@x as role="admin" —
    //      canGrantRole(admin,admin) passes → upsert hits UPDATE
    //      → row overwritten with role="admin", tokenHash=H_new,
    //      invitedById=A1. Bob's original owner-token
    //      argon2-fails at /invites/accept (silent DoS), the
    //      invite trail attributes to A1 (audit-laundering), and
    //      the role is silently downgraded to admin.
    // Same tier-boundary breach class as R84 F1 (member PATCH),
    // R118 F1 (api-keys DELETE), R119 F1 (invites DELETE) —
    // this is the CREATE/UPDATE-via-upsert leg. Fix: symmetric
    // rank check against the existing row's role. Consumed
    // (acceptedAt) or revoked (revokedAt) rows are inert — safe
    // to refresh regardless of prior rank.
    // R153 F1: race the rank check + upsert under Serializable
    // isolation. R122 F1 landed the rank check as a JS-side
    // findUnique OUTSIDE any tx, then upserted with an
    // unguarded UPDATE clause. Two concurrent POST /invites for
    // the same email — owner O1 minting role="owner" while
    // admin A1 concurrently mints role="admin" — both read the
    // null (or same lower-rank) pre-image at snapshot time,
    // both pass the rank check, and race the upsert. Whichever
    // tx commits SECOND falls into ON CONFLICT DO UPDATE and
    // blindly rewrites role / tokenHash / invitedById /
    // invitedByEmail. If A1 lands second: owner-tier invite
    // silently DOWNGRADED to admin, O1's already-emailed owner
    // token argon2-fails at /invites/accept (silent DoS on the
    // owner's link), invite trail attributes to A1 (audit
    // laundering), and role is silently downgraded — the exact
    // harm R122 F1's comment names, delivered via race rather
    // than sequential ordering. Threat model: admin insider
    // racing owner onboarding. Same read-then-write race class
    // R151 F1 / R152 F1 closed for /ingest paths via DB-side
    // WHERE guards; here the natural shape is the sibling
    // members.ts PATCH-role Serializable tx at :132-208, which
    // already catches P2034 as `concurrent_modification_retry`.
    const plaintextToken = randomToken(32);
    const tokenHash = await hashPassword(plaintextToken);
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

    let inv;
    try {
      inv = await db.$transaction(
        async (tx) => {
          const existingInv = await tx.invite.findUnique({
            where: { orgId_email: { orgId: claims.orgId, email: body.data.email } },
            select: { role: true, acceptedAt: true, revokedAt: true },
          });
          if (
            existingInv &&
            !existingInv.acceptedAt &&
            !existingInv.revokedAt &&
            !canGrantRole(
              claims.membershipRole,
              existingInv.role as "owner" | "admin" | "member",
            )
          ) {
            throw new Error("rank_guard");
          }
          // Upsert — if there's already a pending invite for this
          // email, refresh it with a new token instead of erroring.
          // Op-friendly. Serializable isolation makes the pre-read
          // above + this write atomic against concurrent writers:
          // a racer who reads the same pre-image aborts with P2034
          // and the client retries the whole flow.
          return tx.invite.upsert({
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
        },
        { isolationLevel: "Serializable" },
      );
    } catch (e) {
      if (e instanceof Error && e.message === "rank_guard") {
        return reply
          .code(403)
          .send({ error: "cannot_mutate_invite_above_own_rank" });
      }
      if (
        typeof e === "object" && e !== null &&
        (e as { code?: string }).code === "P2034"
      ) {
        return reply
          .code(409)
          .send({ error: "concurrent_modification_retry" });
      }
      throw e;
    }

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
        // R148 F3: `inviter` is already loaded (used at :405/:406
        // for invitedById/invitedByEmail on the upsert), and
        // `claims.sub === inviter.id`, so the R147 F3 sed
        // `actorId: claims.sub, → ...(await resolveActor(claims.sub)),`
        // fetches the same user row and immediately discards
        // its actorEmail via the `actorEmail: inviter.email`
        // override below. Restore the direct pattern the 3
        // auth.ts sites (:598/:631/:880) intentionally use
        // when the user is already in hand — one fewer
        // db.user.findUnique per invite.
        actorId: inviter.id,
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
    // R92 F1: same posture as R91 F2 (/audit gated to non-member)
    // — a pending-invites list is target-selection material for a
    // hostile member (upcoming admin/owner emails + roles + when
    // their invite expires). Sibling POST /invites at line 283
    // and DELETE /invites/:id at line 428 already require
    // membershipRole !== 'member'. Match here.
    if (claims.membershipRole === "member") {
      return reply.code(403).send({ error: "forbidden" });
    }
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
    // R119 F1: rung parity with POST /members/invites (R83 F1)
    // and DELETE /keys/:id (R118 F1). The create path blocks an
    // admin from MINTING an owner-scoped invite; the revoke path
    // must symmetrically block an admin from KILLING a pending
    // owner-scoped invite. Otherwise a departing-owner scenario
    // where the outgoing owner mailed an invite role="owner" to
    // the incoming owner can be sabotaged by an admin — the
    // magic-link 401s at /invites/accept (revokedAt filter) and
    // owner onboarding stalls. Same tier-boundary breach as R84
    // F1 / R103 F1 / R118 F1.
    if (
      !canGrantRole(
        claims.membershipRole,
        existing.role as "owner" | "admin" | "member",
      )
    ) {
      return reply.code(403).send({ error: "cannot_revoke_role_above_own" });
    }
    await db.invite.update({
      where: { id: existing.id },
      data: { revokedAt: new Date() },
    });
    writeAudit(
      {
        orgId: claims.orgId,
        event: "member.invite_revoked",
        ...(await resolveActor(claims.sub)),
        target: existing.email,
        req,
      },
      req.log,
    );
    return reply.code(204).send();
  });

  // R121 F3: per-route rate limit matches /login (auth.ts:274) and
  // /webauthn/authenticate/verify (webauthn.ts:527). Prior shape
  // inherited the global 300/min/IP; combined with R80 F3's cap of
  // 5 argon2 verifies per request, an unauthenticated attacker
  // could burn 300 x 5 = 1500 argon2 verifies/min/IP as cheap
  // amplification. F1 raised the value of this endpoint to
  // attackers (any invite token + any existing user email = mint
  // gate), so a tight per-route cap is now table stakes.
  const perIp = (max: number, windowMs: number) => ({
    max,
    timeWindow: windowMs,
    keyGenerator: (req: { ip: string }) => `ip:${req.ip}`,
  });

  // Anonymous — the invitee accepts. If they don't have an account we
  // create one with the provided password.
  app.post("/invites/accept", {
    config: { rateLimit: perIp(10, 60_000) },
  }, async (req, reply) => {
    const body = z
      .object({
        token: z.string().min(16).max(256),
        email: emailSchema,
        password: z.string().min(12).max(1024).optional(),
        // R184 F1: reject CRLF/NUL to prevent email header injection
        // via welcomeMail's displayName interpolation. Same rationale
        // as orgNameSchema in auth.ts.
        displayName: z.string().max(80).refine((v) => !/[\r\n\u0000]/.test(v), "must not contain CR/LF/NUL").optional(),
      })
      .safeParse(req.body);
    if (!body.success) return reply.code(400).send({ error: "invalid_input" });

    // The orgId isn't in the request — look up by email + verify by token.
    // R80 F3: cap the number of candidates to N to prevent an
    // unauthenticated argon2-amplification DoS. Prior shape ran
    // one argon2 verify per candidate — an attacker who convinced
    // multiple orgs to invite the same email address could force
    // N × ~50 ms of CPU per anonymous request. Argon2 is CPU-
    // parking by design (memory + time cost tuned for password
    // hashing), so N=100 candidates = ~5 s per request; global
    // 300/min/IP rate limit permits ~1.5 s of CPU/s from one IP
    // via that channel alone. Legitimate users typically have
    // 1-3 pending invites; capping at 5 preserves the UX while
    // bounding the argon2 spend at ~250 ms/request even before
    // any additional rate limit kicks in.
    //
    // Take the 5 MOST RECENT candidates so a hostile
    // pre-population by expired-first invites can't hide the
    // legitimate one at the tail — real recent invites are
    // what an actual user would be redeeming.
    const candidates = await db.invite.findMany({
      where: {
        email: body.data.email,
        acceptedAt: null,
        revokedAt: null,
        expiresAt: { gt: new Date() },
      },
      orderBy: { createdAt: "desc" },
      take: 5,
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
    // R121 F1: an invite token authenticates only the INVITEE'S
    // right to be added to `matched.orgId`. It MUST NOT double as
    // authentication of the user's identity — that requires
    // password + (if enrolled) WebAuthn. If we mint a session
    // cookie for a PRE-EXISTING user just because they hold a
    // valid invite token, ANY attacker who can invite the target
    // email to any org (attacker's own org, self-created, one
    // click) walks away with a cookie in `claims.sub =
    // target.id`. From there /webauthn/register/challenge binds
    // to target.id and the attacker registers THEIR OWN device
    // as a passkey on the TARGET'S user row → target's home org
    // is compromised at the next /login → mfaGateResponse →
    // /webauthn/authenticate/verify → session for target's HOME
    // org. Same defeat-of-passkey class R120 F2 just closed on
    // OAuth, but this variant needs only an attacker-controlled
    // AV account. Fix: refuse the cookie mint on the existing-
    // user branch. Consume the invite (membership grant is still
    // legitimate — a real invitee can complete the flow via
    // /login with their existing password) and return
    // requiresLogin so the SPA routes to /#/login. On the
    // new-user branch we KEEP the mint: the user was created THIS
    // request from body.data.password (they own the credential
    // they just set) and cannot have prior passkeys by
    // construction.
    const isPreexistingUser = user !== null;
    let newUserPasswordHash: string | null = null;
    if (!user) {
      if (!body.data.password) {
        return reply.code(400).send({ error: "password_required_for_new_user" });
      }
      // Hash outside the transaction (argon2 is deliberately slow;
      // holding a tx open across it would pin a connection and widen
      // every race window below).
      newUserPasswordHash = await hashPassword(body.data.password);
    }

    // R79 MEDIUM (Class B), rewritten: consume the invite FIRST
    // inside an INTERACTIVE transaction, then grant the membership.
    // Two defects in the prior batch-$transaction shape
    // ([membership.upsert, invite.updateMany] + post-commit count
    // check):
    //   1. A zero-row UPDATE is not an error, so BOTH statements
    //      committed: the caller received the 409 while their
    //      membership grant silently persisted. The loser of two
    //      concurrent accepts kept the membership; worse, a token
    //      holder whose invite an admin had already REVOKED (or
    //      that expired) between candidate lookup and the
    //      transaction still became a member while the API
    //      reported refusal — an access grant with no audit row.
    //   2. The consumption predicate matched only {id, unaccepted,
    //      unrevoked} — not the token hash or expiry — so an owner
    //      reissuing the invite (fresh tokenHash, downgraded role)
    //      mid-flight let the OLD token consume the NEW invite and
    //      grant the stale pre-reissue role.
    // Now: the updateMany predicate pins the FULL verified snapshot
    // (tokenHash + expiresAt + unaccepted + unrevoked); a count of 0
    // throws inside the transaction so nothing else commits.
    //
    // New-user creation ALSO lives inside the transaction, AFTER the
    // consume: the prior shape created the User row first, so a
    // consume failure (revoked/expired mid-flight) returned 409 while
    // leaving an orphan zero-membership account behind — an email
    // that could no longer sign up ("email exists") NOR sign in
    // (zero-membership logins are refused), stuck until someone
    // re-invited it. `upsert` (not `create` + P2002 catch) because a
    // unique-violation error inside a Postgres transaction aborts the
    // whole tx — the old catch-and-requery pattern cannot work here;
    // ON CONFLICT returns the concurrent winner's row exactly like
    // the R80 F5 requery used to.
    const INVITE_NOT_CONSUMABLE = "__invite_not_consumable__";
    try {
      user = await db.$transaction(async (tx) => {
        const consumed = await tx.invite.updateMany({
          where: {
            id: matched.id,
            tokenHash: matched.tokenHash,
            acceptedAt: null,
            revokedAt: null,
            expiresAt: { gt: new Date() },
          },
          data: { acceptedAt: new Date() },
        });
        if (consumed.count === 0) {
          throw new Error(INVITE_NOT_CONSUMABLE);
        }
        const grantee =
          user ??
          (await tx.user.upsert({
            where: { email: matched.email },
            create: {
              email: matched.email,
              passwordHash: newUserPasswordHash!,
              displayName: body.data.displayName ?? null,
            },
            update: {},
          }));
        await tx.membership.upsert({
          where: { userId_orgId: { userId: grantee.id, orgId: matched.orgId } },
          create: {
            userId: grantee.id,
            orgId: matched.orgId,
            role: matched.role,
          },
          update: {}, // Already a member? Fine, just proceed.
        });
        return grantee;
      });
    } catch (err) {
      if (err instanceof Error && err.message === INVITE_NOT_CONSUMABLE) {
        // Lost the race with a concurrent accept, an admin revoke, a
        // reissue (different tokenHash), or expiry. Nothing was
        // granted — the transaction rolled back (including any
        // would-be new User row).
        return reply.code(409).send({ error: "invite_already_consumed" });
      }
      throw err;
    }

    // R121 F1: refuse to mint a session cookie for a pre-existing
    // user (see the isPreexistingUser comment block above). Return
    // requiresLogin so the SPA routes to /#/login where the user
    // supplies their real password (and, if enrolled, completes
    // the WebAuthn ceremony).
    // R122 track A cosmetic: include org.name so the SPA toast
    // ("Welcome to <name>") renders the workspace name instead of
    // silently falling to "the workspace". `org` was already
    // loaded upstream at line 345 for the create-path email.
    if (isPreexistingUser) {
      const targetOrg = await db.org.findUnique({
        where: { id: matched.orgId },
        select: { name: true },
      });
      writeAudit(
        {
          orgId: matched.orgId,
          event: "member.invite_accepted_requires_login",
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
        org: {
          id: matched.orgId,
          role: matched.role,
          name: targetOrg?.name ?? null,
        },
        requiresLogin: true,
      });
    }

    const targetOrgForMint = await db.org.findUnique({
      where: { id: matched.orgId },
      select: { name: true },
    });
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
      org: {
        id: matched.orgId,
        role: matched.role,
        name: targetOrgForMint?.name ?? null,
      },
    });
  });
}
