import type { FastifyReply, FastifyRequest } from "fastify";
import { env } from "../env.js";
import { SESSION_COOKIE_OPTS, verifySession } from "../lib/auth.js";
import { db } from "../db.js";

/**
 * Populates `request.session` when a valid session cookie is present. Never
 * throws — routes that require auth call `requireSession()` below.
 *
 * Also confirms that:
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
 * checks in a single sub-millisecond query against indexed columns.
 */
export async function authenticate(
  req: FastifyRequest,
  _reply: FastifyReply,
): Promise<void> {
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
        select: { id: true },
      },
    },
  });
  if (!user) return;
  if (user.memberships.length === 0) return;
  if (
    user.sessionRevokedAt &&
    claims.iat * 1000 < user.sessionRevokedAt.getTime()
  ) {
    return;
  }
  req.session = claims;
}

export function requireSession(req: FastifyRequest, reply: FastifyReply) {
  if (!req.session) {
    reply.code(401).send({ error: "unauthenticated" });
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
