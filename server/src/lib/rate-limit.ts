/**
 * Rate-limit helpers used across auth-tree endpoints.
 *
 * `perIpCookieOnly(max, windowMs)` returns a route-scoped
 * @fastify/rate-limit config that keys the bucket by
 * `ip:${req.ip}` — but ALLOWS (skips) any request carrying
 * `Authorization: Bearer …`. That covers api-key sessions that
 * every step-up handler in the auth tree rejects at a
 * `cookie_session_required` branch before touching argon2. The
 * skip prevents an attacker with ANY valid `av_srv_` token on the
 * same IP as a legitimate cookie caller from burning the cookie
 * caller's rate-limit budget by hammering the endpoint with a
 * bearer header — the covert lock-out primitive R141 F4 closed
 * on DELETE /credentials/:id. This helper generalizes the same
 * pattern to /register/verify + /me/export + /me/delete-account
 * (all three siblings named in R141 F4's own comment).
 *
 * Reused across webauthn.ts + auth.ts so the four call-sites
 * don't drift out of sync.
 *
 * The cookie-absence requirement in the allowList is load-bearing:
 * session-middleware's R100 F2 fallthrough resolves a perfectly valid
 * cookie session when the presented bearer token matches no live API
 * key. Skipping on bearer PRESENCE alone therefore let a stolen-cookie
 * attacker attach a garbage bearer header to every request and grind
 * argon2 step-up checks (or drain the read/export endpoints) with NO
 * rate limit at all — the route-scoped bucket was skipped, and
 * @fastify/rate-limit never attaches the global backstop to routes
 * that carry their own config. R100 F2's own rationale ("a legitimate
 * API-key consumer never sends a cookie alongside") is exactly the
 * discriminator: bearer + session cookie is never a legitimate shape,
 * so it pays the per-IP cookie bucket like any other cookie caller.
 * @fastify/cookie registers before @fastify/rate-limit (index.ts), so
 * `req.cookies` is populated when this allowList runs.
 */
import { env } from "../env.js";

export function perIpCookieOnly(max: number, windowMs: number) {
  return {
    max,
    timeWindow: windowMs,
    keyGenerator: (req: { ip: string }) => `ip:${req.ip}`,
    allowList: (req: {
      headers: Record<string, unknown>;
      cookies?: Record<string, string | undefined>;
    }) => {
      const auth = req.headers["authorization"];
      const bearer =
        typeof auth === "string" &&
        auth.toLowerCase().startsWith("bearer ");
      if (!bearer) return false;
      return !req.cookies?.[env.SESSION_COOKIE_NAME];
    },
  };
}
