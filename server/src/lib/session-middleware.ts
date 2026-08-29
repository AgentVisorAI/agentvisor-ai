import type { FastifyReply, FastifyRequest } from "fastify";
import { env } from "../env.js";
import { SESSION_COOKIE_OPTS, verifyPassword, verifySession } from "../lib/auth.js";
import { db } from "../db.js";
import { ipMatchesAny } from "./cidr.js";

/**
 * Populates `request.session` when a valid session cookie is present. Never
 * throws — routes that require auth call `requireSession()` below.
 *
 * Two auth flavors:
 *   1. av_session cookie (JWT) — the console SPA / OAuth / SAML users.
 *   2. Authorization: Bearer av_srv_<plaintext> — programmatic API keys.
 *
 * Cookie path also confirms that:
 *   1. the (userId, orgId) pair in the token is still an active membership
 *      — closes the gap where a user removed from an org would keep
 *      read/write access via their existing JWT for the remainder of the
 *      7-day TTL;
 *   2. the token's iat is not before the user's sessionRevokedAt fence
 *      — closes the JWT logout replay gap where a captured cookie would
 *      keep working after the user logged out. Bumping sessionRevokedAt
 *      on logout and password change immediately invalidates every JWT
 *      minted before that moment.
 *
 * One findUnique on users (with a joined membership include) covers both
 * checks in a single sub-millisecond query against indexed columns. The
 * org's ipAllowlist is also loaded in that same query so `requireSession`
 * can enforce it without an additional round-trip.
 */
export async function authenticate(
  req: FastifyRequest,
  _reply: FastifyReply,
): Promise<void> {
  // ---------- API key path ----------
  const auth = req.headers.authorization;
  if (typeof auth === "string" && auth.startsWith("Bearer av_srv_")) {
    const plaintext = auth.slice("Bearer ".length);
    const hint = plaintext.slice("av_srv_".length, "av_srv_".length + 8);
    const candidates = await db.apiKey.findMany({
      where: { tokenHint: hint, revokedAt: null },
      select: {
        id: true,
        orgId: true,
        role: true,
        tokenHash: true,
        createdById: true,
        org: { select: { ipAllowlist: true } },
      },
    });
    for (const c of candidates) {
      const ok = await verifyPassword(c.tokenHash, plaintext);
      if (!ok) continue;
      req.session = {
        sub: "apikey:" + c.id,
        orgId: c.orgId,
        membershipRole: c.role as "owner" | "admin" | "member",
        iat: Math.floor(Date.now() / 1000),
      };
      req.orgIpAllowlist = c.org.ipAllowlist ?? [];
      void db.apiKey
        .update({ where: { id: c.id }, data: { lastUsedAt: new Date() } })
        .catch(() => void 0);
      return;
    }
    // R100 F2: fall through to the cookie path when the API-key
    // lookup finds no match. Prior shape returned early here —
    // any Authorization header carrying the av_srv_ prefix
    // (attacker-injected via a compromised browser extension,
    // a misconfigured API gateway that appends a stale bearer,
    // or an attacker-controlled fetch from same-site) suppressed
    // the cookie fallback and silently downgraded an
    // authenticated user to 401. Session-DoS primitive against
    // any victim whose Authorization header can be forced.
    // Now: if the presented api key hint yields no live match,
    // continue to the cookie path so a valid cookie still
    // authenticates. A legitimate API-key consumer never sends
    // a cookie alongside, so no ambiguity is introduced.
  }

  // ---------- Cookie path ----------
  const token = req.cookies[env.SESSION_COOKIE_NAME];
  if (!token) return;
  const claims = await verifySession(token);
  if (!claims) return;
  const user = await db.user.findUnique({
    where: { id: claims.sub },
    select: {
      sessionRevokedAt: true,
      memberships: {
        where: { orgId: claims.orgId },
        select: {
          id: true,
          org: { select: { ipAllowlist: true } },
        },
      },
    },
  });
  if (!user) return;
  if (user.memberships.length === 0) return;
  if (
    user.sessionRevokedAt &&
    // R210 F1: compare in the same unit as claims.iat (unix
    // seconds — jose's SignJWT.setIssuedAt() calls
    // Math.floor(Date.now()/1000), see lib/auth.ts:119).
    // sessionRevokedAt is written with `new Date()` at
    // millisecond precision (logout, credential-revoke,
    // saml SLO, member role change, password reset).
    // Prior shape `claims.iat * 1000 < revokedAt.getTime()`
    // compared a seconds-boundary iat against a
    // millisecond-precision fence, so any JWT minted in the
    // SAME wall-clock second as a revoke bump was strictly
    // less than the fence and refused forever. Concrete
    // scenario: /logout at t=10:00:00.100 bumps revokedAt
    // to the millisecond; /login at t=10:00:00.500 mints a
    // JWT with iat=10; next request compares
    // `10*1000=10:00:00.000 < 10:00:00.100` → 401. The
    // freshly-set cookie was DOA. Fix: floor revokedAt to
    // the same second boundary before comparing.
    claims.iat < Math.floor(user.sessionRevokedAt.getTime() / 1000)
  ) {
    return;
  }
  req.session = claims;
  req.orgIpAllowlist = user.memberships[0]?.org.ipAllowlist ?? [];
}

export function requireSession(req: FastifyRequest, reply: FastifyReply) {
  if (!req.session) {
    reply.code(401).send({ error: "unauthenticated" });
    return null;
  }
  // Per-org IP allowlist. Empty allowlist = allow-all. Otherwise the
  // caller's remote IP must match one of the CIDRs. This runs AFTER
  // authenticate() has resolved the org, so we don't need a second
  // DB round-trip. IP is taken from req.ip which Fastify populates
  // using the trustProxy config — set correctly at boot so a leading
  // proxy's X-Forwarded-For is honored.
  const cidrs = req.orgIpAllowlist;
  if (cidrs && cidrs.length > 0 && !ipMatchesAny(req.ip, cidrs)) {
    reply.code(403).send({ error: "forbidden_ip" });
    return null;
  }
  return req.session;
}

/** Confirms the org in the session token still has this user as a member. */
export async function assertOrgMembership(
  userId: string,
  orgId: string,
): Promise<boolean> {
  const m = await db.membership.findUnique({
    where: { userId_orgId: { userId, orgId } },
    select: { id: true },
  });
  return !!m;
}

export function clearSessionCookie(reply: FastifyReply): void {
  reply.setCookie(env.SESSION_COOKIE_NAME, "", {
    ...SESSION_COOKIE_OPTS,
    maxAge: 0,
  });
}
