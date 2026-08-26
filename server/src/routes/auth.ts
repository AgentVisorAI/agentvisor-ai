import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { db } from "../db.js";
import { env } from "../env.js";
import {
  SESSION_COOKIE_OPTS,
  getDummyPasswordHash,
  hashPassword,
  mintSession,
  randomToken,
  verifyPassword,
} from "../lib/auth.js";
import { writeAudit } from "../lib/audit.js";
import { getMailer, passwordResetMail, welcomeMail } from "../lib/mail.js";
import {
  clearSessionCookie,
  requireSession,
} from "../lib/session-middleware.js";

// Zod's built-in .email() uses a strict allow-list of TLDs and rejects
// legitimate ones (.vc, .travel, .app). Practical constraint: local-part +
// @ + domain with at least one dot, no whitespace, ≤320 total.
const emailSchema = z
  .string()
  .max(320)
  .trim()
  .toLowerCase()
  .regex(/^[^\s@]+@[^\s@]+\.[^\s@]+$/, "Invalid email");
const passwordSchema = z.string().min(12).max(1024);
const orgNameSchema = z.string().min(1).max(80).trim();

function orgSlug(name: string, salt: string): string {
  const base = name
    .toLowerCase()
    .normalize("NFKD")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 40);
  return base ? `${base}-${salt}` : `org-${salt}`;
}

export async function authRoutes(app: FastifyInstance): Promise<void> {
  // Per-endpoint rate limits are tighter than the global 300rpm backstop.
  // Anonymous auth endpoints get a per-IP cap because there's no user
  // identity to rate-limit against yet. Numbers here are conservative
  // for a real product (Auth0 defaults to 300/hr on signup; Cognito
  // is 5/min on login). See OWASP ASVS 4.0 §11.1.4.
  //
  // Note: when @fastify/rate-limit's `config` accessor sees a route
  // definition, it overrides the global keyGenerator + budget for that
  // route only. Everything else on the API still uses the 300rpm global.
  const perIp = (max: number, windowMs: number) => ({
    max,
    timeWindow: windowMs,
    keyGenerator: (req: { ip: string }) => `ip:${req.ip}`,
  });

  app.post("/signup", {
    // 5/min per IP — signup is an expensive path (argon2 + org create).
    config: { rateLimit: perIp(5, 60_000) },
  }, async (req, reply) => {
    const parsed = z
      .object({
        email: emailSchema,
        password: passwordSchema,
        displayName: z.string().min(1).max(80).trim().optional(),
        orgName: orgNameSchema,
      })
      .safeParse(req.body);
    if (!parsed.success) {
      // Never log the request body — it contains the plaintext password.
      // The flatten()'d issues describe field paths + messages only.
      req.log.warn(
        { issues: parsed.error.flatten() },
        "signup_reject",
      );
      return reply
        .code(400)
        .send({ error: "invalid_input", issues: parsed.error.flatten() });
    }
    const { email, password, displayName, orgName } = parsed.data;

    // Reject if email is already registered. Do not disclose which case in
    // production — this handler is only reached anonymously, so returning 409
    // is acceptable here. The findUnique check is a fast-path; the create
    // below is wrapped in try/catch to also catch the TOCTOU race where two
    // concurrent signups slip past the check.
    const existing = await db.user.findUnique({ where: { email } });
    if (existing) {
      return reply.code(409).send({ error: "email_in_use" });
    }

    const passwordHash = await hashPassword(password);
    const salt = Math.random().toString(36).slice(2, 8);
    const slug = orgSlug(orgName, salt);

    let user, org;
    try {
      const result = await db.$transaction(async (tx) => {
        const org = await tx.org.create({
          data: { name: orgName, slug },
        });
        const user = await tx.user.create({
          data: {
            email,
            passwordHash,
            displayName,
            memberships: {
              create: { orgId: org.id, role: "owner" },
            },
          },
        });
        return { user, org };
      });
      user = result.user;
      org = result.org;
    } catch (err) {
      // Prisma P2002 = unique constraint violation. Two concurrent signups
      // with the same email hit this — one wins, the rest get 409 Conflict
      // (not a 500 with the Prisma error code leaked to the client).
      if (
        typeof err === "object" && err !== null &&
        (err as { code?: string }).code === "P2002"
      ) {
        return reply.code(409).send({ error: "email_in_use" });
      }
      throw err;
    }

    const token = await mintSession({
      sub: user.id,
      orgId: org.id,
      membershipRole: "owner",
    });
    reply.setCookie(env.SESSION_COOKIE_NAME, token, SESSION_COOKIE_OPTS);
    writeAudit(
      {
        orgId: org.id,
        event: "auth.signup",
        actorId: user.id,
        actorEmail: user.email,
        target: user.email,
        note: `Org "${org.name}" created`,
        req,
      },
      req.log,
    );
    // Fire-and-forget welcome email. Failures don't block the signup
    // response — a stuck mailer would otherwise turn a hot-path signup
    // into a 30s timeout.
    void (async () => {
      try {
        const mail = getMailer(req.log);
        const template = welcomeMail(user.displayName ?? user.email);
        await mail.send({
          to: user.email,
          subject: template.subject,
          text: template.text,
          html: template.html,
        });
      } catch (err) {
        req.log.warn({ err, userId: user.id }, "welcome_email_failed");
      }
    })();
    return reply.code(201).send({
      user: { id: user.id, email: user.email, displayName: user.displayName },
      org: { id: org.id, slug: org.slug, name: org.name, role: "owner" },
    });
  });

  app.post("/login", {
    // 10/min per IP is deliberate: a shared NAT still has plenty of
    // budget for legitimate users, but credential-stuffing bursts get
    // cut off quickly. Combine with argon2's built-in ~100ms cost per
    // attempt for a hard ceiling on brute-force throughput.
    config: { rateLimit: perIp(10, 60_000) },
  }, async (req, reply) => {
    // Login accepts any well-formed input and lets the credential check
    // return a uniform 401. Rejecting on password length would leak the
    // signup constraint and give attackers a legit-vs-typo distinguisher.
    const body = z
      .object({ email: emailSchema, password: z.string().min(1).max(1024) })
      .safeParse(req.body);
    if (!body.success) {
      return reply.code(400).send({ error: "invalid_input" });
    }
    const { email, password } = body.data;
    const user = await db.user.findUnique({
      where: { email },
      include: { memberships: { include: { org: true } } },
    });
    // Uniform response time by always running argon2 verify, even when
    // the user doesn't exist. The dummy is a real precomputed argon2id
    // hash (from getDummyPasswordHash) so verify actually spends its
    // full ~100ms — the previous ill-formed dummy failed decode in
    // <1ms and defeated the entire posture.
    const hashToCheck = user?.passwordHash ?? (await getDummyPasswordHash());
    const ok = await verifyPassword(hashToCheck, password);
    if (!user || !ok) {
      return reply.code(401).send({ error: "invalid_credentials" });
    }
    const membership = user.memberships[0];
    if (!membership) {
      return reply.code(403).send({ error: "no_org" });
    }

    // MFA gate — if the user has any WebAuthn credentials, we do NOT
    // mint the session cookie here. Instead we return { mfaRequired:
    // true } and the SPA runs the WebAuthn ceremony to complete auth.
    // Password alone is not sufficient once a passkey exists.
    const credentialCount = await db.webauthnCredential.count({
      where: { userId: user.id },
    });
    if (credentialCount > 0) {
      writeAudit(
        {
          orgId: membership.orgId,
          event: "auth.password_ok_mfa_required",
          actorId: user.id,
          actorEmail: user.email,
          target: user.email,
          req,
        },
        req.log,
      );
      return reply.send({
        mfaRequired: true,
        email: user.email,
      });
    }

    const token = await mintSession({
      sub: user.id,
      orgId: membership.orgId,
      membershipRole: membership.role as "owner" | "admin" | "member",
    });
    reply.setCookie(env.SESSION_COOKIE_NAME, token, SESSION_COOKIE_OPTS);
    writeAudit(
      {
        orgId: membership.orgId,
        event: "auth.login",
        actorId: user.id,
        actorEmail: user.email,
        target: user.email,
        req,
      },
      req.log,
    );
    return reply.send({
      user: { id: user.id, email: user.email, displayName: user.displayName },
      org: {
        id: membership.org.id,
        slug: membership.org.slug,
        name: membership.org.name,
        role: membership.role,
      },
    });
  });

  app.post("/logout", async (req, reply) => {
    // Bump the user's sessionRevokedAt fence so a captured cookie can't
    // be replayed after logout, even though the JWT itself is still
    // cryptographically valid until its 7-day exp. authenticate()
    // checks jwt.iat < user.sessionRevokedAt and rejects.
    if (req.session) {
      await db.user
        .update({
          where: { id: req.session.sub },
          data: { sessionRevokedAt: new Date() },
        })
        .catch((err) => {
          // Log but don't fail logout — clearing the cookie is the
          // essential piece; the fence bump is defense in depth.
          req.log.warn({ err }, "logout_revoke_bump_failed");
        });
      writeAudit(
        {
          orgId: req.session.orgId,
          event: "auth.logout",
          actorId: req.session.sub,
          req,
        },
        req.log,
      );
    }
    clearSessionCookie(reply);
    return reply.send({ ok: true });
  });

  app.get("/me", async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    const user = await db.user.findUnique({
      where: { id: claims.sub },
      include: { memberships: { include: { org: true } } },
    });
    if (!user) {
      clearSessionCookie(reply);
      return reply.code(401).send({ error: "user_not_found" });
    }
    const active = user.memberships.find((m) => m.orgId === claims.orgId);
    if (!active) {
      clearSessionCookie(reply);
      return reply.code(403).send({ error: "membership_revoked" });
    }
    return reply.send({
      user: { id: user.id, email: user.email, displayName: user.displayName },
      org: {
        id: active.org.id,
        slug: active.org.slug,
        name: active.org.name,
        role: active.role,
      },
    });
  });

  // GDPR data export. Returns everything the org has stored:
  // deployments, sessions, events, receipts, memberships, users.
  // Password hashes and reset tokens are excluded — the export is meant
  // for the customer, not an attacker with a stolen session.
  //
  // Gated on a fresh password check so a stolen session cookie can't
  // extract the whole org history in one call.
  app.post("/me/export", {
    config: { rateLimit: perIp(3, 60_000) },
  }, async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    const body = z
      .object({ password: z.string().min(1).max(1024) })
      .safeParse(req.body);
    if (!body.success) {
      return reply.code(400).send({ error: "password_required" });
    }
    const user = await db.user.findUnique({ where: { id: claims.sub } });
    if (!user) return reply.code(401).send({ error: "unauthenticated" });
    const ok = await verifyPassword(user.passwordHash, body.data.password);
    if (!ok) return reply.code(401).send({ error: "invalid_password" });

    // Streaming JSON-Lines export. Each line is a self-contained JSON
    // object; the first line is a header. Sessions and events are
    // paged (batch size below) so we NEVER materialize the whole org
    // in memory — a 1M-session tenant streams safely on a 256 MB Fly
    // machine. Long TTL friendly: consumers can restart mid-download
    // by discarding the header and resuming.
    //
    // Password hashes and reset tokens are excluded — the export is
    // meant for the customer, not for anyone with a stolen session.
    const SESSION_PAGE = 500;
    const EVENT_PAGE = 1000;

    reply.header(
      "Content-Disposition",
      `attachment; filename="agentvisor-export-${claims.orgId}-${Date.now()}.jsonl"`,
    );
    reply.type("application/x-ndjson");
    // Hijack Fastify's response pipeline so we can push line-by-line.
    reply.raw.setHeader("Cache-Control", "no-store");
    reply.raw.flushHeaders();
    const write = (obj: unknown) => {
      reply.raw.write(JSON.stringify(obj) + "\n");
    };

    try {
      // Row 1: header. Consumers key on schemaVersion for future
      // evolutions of this format.
      const org = await db.org.findUnique({
        where: { id: claims.orgId },
        include: {
          members: {
            include: {
              user: { select: { id: true, email: true, displayName: true } },
            },
          },
          deployments: {
            select: {
              id: true,
              name: true,
              environment: true,
              publicKeyHex: true,
              createdAt: true,
            },
          },
        },
      });
      write({
        type: "header",
        exportedAt: new Date().toISOString(),
        schemaVersion: 2,
        org,
      });

      // Rows 2..N: sessions paginated by (openedAt, id). Same cursor
      // pattern as the /sessions endpoint — O(log N) per page.
      let lastKey: { openedAt: Date; id: string } | null = null;
      // Loop until an empty page. Guard against runaway loops via a
      // sanity cap on iterations — 1M sessions / SESSION_PAGE = 2000
      // pages, and even 10M would be 20k pages, well below this.
      for (let iter = 0; iter < 200_000; iter++) {
        // Typed as any-ish: Prisma infers the generic from the where,
        // and TS complains about self-referential inference in the
        // control-flow analysis. The runtime type is
        // (Session & { receipt: Receipt | null })[].
        const sessions: Array<{
          id: string;
          openedAt: Date;
          costUsdMicros: bigint;
          payoutUsdMicros: bigint;
          blockedPayoutUsdMicros: bigint;
          [k: string]: unknown;
        }> = await db.session.findMany({
          where: { orgId: claims.orgId },
          orderBy: [{ openedAt: "asc" }, { id: "asc" }],
          take: SESSION_PAGE,
          ...(lastKey
            ? {
                skip: 1,
                cursor: { id: lastKey.id },
              }
            : {}),
          include: { receipt: true },
        });
        if (sessions.length === 0) break;
        for (const s of sessions) {
          write({
            type: "session",
            session: {
              ...s,
              costUsdMicros: s.costUsdMicros.toString(),
              payoutUsdMicros: s.payoutUsdMicros.toString(),
              blockedPayoutUsdMicros: s.blockedPayoutUsdMicros.toString(),
            },
          });
          // Events for this session in EVENT_PAGE-sized pages.
          let lastEventSeq: number | null = null;
          for (let ei = 0; ei < 20_000; ei++) {
            const events: Array<{ seq: number; [k: string]: unknown }> = await db.event.findMany({
              where: {
                sessionId: s.id,
                ...(lastEventSeq !== null ? { seq: { gt: lastEventSeq } } : {}),
              },
              orderBy: { seq: "asc" },
              take: EVENT_PAGE,
            });
            if (events.length === 0) break;
            const nextLast = events[events.length - 1];
            if (!nextLast) break;
            for (const ev of events) {
              write({ type: "event", sessionId: s.id, event: ev });
            }
            lastEventSeq = nextLast.seq;
            if (events.length < EVENT_PAGE) break;
          }
        }
        const last = sessions[sessions.length - 1];
        if (!last || sessions.length < SESSION_PAGE) break;
        lastKey = { openedAt: last.openedAt, id: last.id };
      }
      write({ type: "trailer", exportCompleteAt: new Date().toISOString() });
    } catch (err) {
      // Write a trailer so consumers can distinguish a truncated
      // download from a completed one. Then close.
      req.log.error({ err, orgId: claims.orgId }, "export_stream_failed");
      write({
        type: "error",
        message: err instanceof Error ? err.message : "export_failed",
        exportFailedAt: new Date().toISOString(),
      });
    } finally {
      reply.raw.end();
    }
    return reply;
  });

  // Account + org deletion. Owner-only. Requires password + explicit
  // confirmation string to prevent a mis-click from nuking a whole
  // tenant.
  //
  // Cascading deletes fire down the tree — Prisma's onDelete:Cascade
  // handles deployments → sessions → events → receipts. Memberships
  // and Users are removed last.
  app.post("/me/delete-account", {
    config: { rateLimit: perIp(3, 60_000) },
  }, async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    if (claims.membershipRole !== "owner") {
      return reply.code(403).send({ error: "only_owner_can_delete" });
    }
    const body = z
      .object({
        password: z.string().min(1).max(1024),
        confirm: z.literal("DELETE MY ACCOUNT"),
      })
      .safeParse(req.body);
    if (!body.success) {
      return reply.code(400).send({ error: "confirmation_required" });
    }
    const user = await db.user.findUnique({ where: { id: claims.sub } });
    if (!user) return reply.code(401).send({ error: "unauthenticated" });
    const ok = await verifyPassword(user.passwordHash, body.data.password);
    if (!ok) return reply.code(401).send({ error: "invalid_password" });

    await db.$transaction(async (tx) => {
      // Delete the org first — cascades to deployments, sessions,
      // events, receipts, memberships.
      await tx.org.delete({ where: { id: claims.orgId } });
      // Then remove the user. Other orgs they belonged to (unlikely
      // at MVP; multi-org membership not exposed yet) would keep them.
      const otherMemberships = await tx.membership.count({
        where: { userId: claims.sub },
      });
      if (otherMemberships === 0) {
        await tx.user.delete({ where: { id: claims.sub } });
      }
    });

    clearSessionCookie(reply);
    return reply.send({ ok: true });
  });

  // Password reset — two-step flow. The first endpoint always returns 202,
  // regardless of whether the email exists, so we don't leak account
  // membership. The plaintext token is delivered ONLY via the configured
  // email path; it is never logged in production (log-read access would
  // otherwise be sufficient to take over any account).
  app.post("/reset-request", {
    // 3/hour per IP. Reset-request is anonymous, so an attacker could
    // spam it to burn our mail budget or DOS a specific mailbox.
    config: { rateLimit: perIp(3, 60 * 60_000) },
  }, async (req, reply) => {
    const body = z.object({ email: emailSchema }).safeParse(req.body);
    // Uniform response even on malformed input — no oracle for enumeration.
    if (!body.success) return reply.code(202).send({ ok: true });
    const user = await db.user.findUnique({ where: { email: body.data.email } });
    if (user) {
      const plaintextToken = randomToken(32);
      const resetTokenHash = await hashPassword(plaintextToken);
      await db.user.update({
        where: { id: user.id },
        data: { resetTokenHash, resetTokenAt: new Date() },
      });
      // Build the reset link the user will click.
      const resetLink = `${env.APP_BASE_URL.replace(/\/$/, "")}/app/#/reset?token=${encodeURIComponent(plaintextToken)}&email=${encodeURIComponent(user.email)}`;
      // Send it. Uses whichever mailer driver is configured (Resend,
      // SMTP, or dev-stub). We never log the token itself — only the
      // driver + message id — so a log leak can't lead to account takeover.
      try {
        const mail = getMailer(req.log);
        const template = passwordResetMail(resetLink);
        const result = await mail.send({
          to: user.email,
          subject: template.subject,
          text: template.text,
          html: template.html,
        });
        req.log.info(
          { userId: user.id, mailer: result.driver, messageId: result.id },
          "password_reset_email_sent",
        );
      } catch (err) {
        // Log — but still return 202 to the caller so we don't leak
        // whether the email exists. Ops can investigate via the log.
        req.log.error(
          { err, userId: user.id },
          "password_reset_email_failed",
        );
      }
    }
    return reply.code(202).send({ ok: true });
  });

  const resetTtlMs = 24 * 60 * 60 * 1000;
  app.post("/reset-confirm", {
    // 10/min per IP. Consumes a random-looking 32-byte token, so brute
    // force is already infeasible cryptographically; this just prevents
    // an attacker from burning API budget while spraying candidate tokens.
    config: { rateLimit: perIp(10, 60_000) },
  }, async (req, reply) => {
    const body = z
      .object({
        email: emailSchema,
        token: z.string().min(16).max(256),
        newPassword: passwordSchema,
      })
      .safeParse(req.body);
    if (!body.success) return reply.code(400).send({ error: "invalid_input" });
    const user = await db.user.findUnique({ where: { email: body.data.email } });
    if (!user || !user.resetTokenHash || !user.resetTokenAt) {
      return reply.code(401).send({ error: "invalid_token" });
    }
    if (Date.now() - user.resetTokenAt.getTime() > resetTtlMs) {
      return reply.code(401).send({ error: "expired_token" });
    }
    const ok = await verifyPassword(user.resetTokenHash, body.data.token);
    if (!ok) return reply.code(401).send({ error: "invalid_token" });
    const passwordHash = await hashPassword(body.data.newPassword);
    await db.user.update({
      where: { id: user.id },
      // Clear the reset fields — one-shot use. Also bump the
      // sessionRevokedAt fence so any live cookie minted before this
      // password change is invalidated on next request. A leaked
      // cookie should stop working the moment the password is reset.
      data: {
        passwordHash,
        resetTokenHash: null,
        resetTokenAt: null,
        sessionRevokedAt: new Date(),
      },
    });
    return reply.send({ ok: true });
  });
}
