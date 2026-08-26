import type { FastifyReply, FastifyRequest } from "fastify";
import { env } from "../env.js";
import { SESSION_COOKIE_OPTS, verifySession } from "../lib/auth.js";
import { db } from "../db.js";

/**
 * Populates `request.session` when a valid session cookie is present. Never
 * throws — routes that require auth call `requireSession()` below.
 */
export async function authenticate(
  req: FastifyRequest,
  _reply: FastifyReply,
): Promise<void> {
  const token = req.cookies[env.SESSION_COOKIE_NAME];
  if (!token) return;
  const claims = await verifySession(token);
  if (!claims) return;
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
