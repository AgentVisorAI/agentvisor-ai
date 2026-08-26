import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { db } from "../db.js";
import { env } from "../env.js";
import {
  SESSION_COOKIE_OPTS,
  hashPassword,
  mintSession,
  randomToken,
  verifyPassword,
} from "../lib/auth.js";
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
    // is acceptable here.
    const existing = await db.user.findUnique({ where: { email } });
    if (existing) {
      return reply.code(409).send({ error: "email_in_use" });
    }

    const passwordHash = await hashPassword(password);
    const salt = Math.random().toString(36).slice(2, 8);
    const slug = orgSlug(orgName, salt);

    const { user, org } = await db.$transaction(async (tx) => {
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

    const token = await mintSession({
      sub: user.id,
      orgId: org.id,
      membershipRole: "owner",
    });
    reply.setCookie(env.SESSION_COOKIE_NAME, token, SESSION_COOKIE_OPTS);
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
    // Uniform response time by always running the verify, even on a miss.
    const hashToCheck =
      user?.passwordHash ??
      "$argon2id$v=19$m=19456,t=2,p=1$aaaaaaaaaaaaaaaaaaaaaa$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const ok = await verifyPassword(hashToCheck, password);
    if (!user || !ok) {
      return reply.code(401).send({ error: "invalid_credentials" });
    }
    const membership = user.memberships[0];
    if (!membership) {
      return reply.code(403).send({ error: "no_org" });
    }
    const token = await mintSession({
      sub: user.id,
      orgId: membership.orgId,
      membershipRole: membership.role as "owner" | "admin" | "member",
    });
    reply.setCookie(env.SESSION_COOKIE_NAME, token, SESSION_COOKIE_OPTS);
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

  app.post("/logout", async (_req, reply) => {
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
      // TODO: send via mailer (Postmark/Resend/SES).
      // Metadata-only in production; the plaintext token is emitted ONLY in
      // non-production for local development. Logging it in production would
      // hand any log-reader a one-shot account takeover, since /reset-confirm
      // requires only {email, token, newPassword} — no session, no MFA.
      if (env.NODE_ENV === "production") {
        req.log.info(
          { userId: user.id },
          "password_reset_token_issued",
        );
      } else {
        req.log.info(
          { userId: user.id, devOnlyResetToken: plaintextToken },
          "password_reset_token_issued (dev only — token in log)",
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
      // Clear the reset fields — one-shot use.
      data: { passwordHash, resetTokenHash: null, resetTokenAt: null },
    });
    return reply.send({ ok: true });
  });
}
