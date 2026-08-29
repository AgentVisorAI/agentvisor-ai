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
 */
export function perIpCookieOnly(max: number, windowMs: number) {
  return {
    max,
    timeWindow: windowMs,
    keyGenerator: (req: { ip: string }) => `ip:${req.ip}`,
    allowList: (req: { headers: Record<string, unknown> }) => {
      const auth = req.headers["authorization"];
      return (
        typeof auth === "string" &&
        auth.toLowerCase().startsWith("bearer ")
      );
    },
  };
}
