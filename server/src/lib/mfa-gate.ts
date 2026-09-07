/**
 * MFA gate: proof-of-password binding for the WebAuthn login ceremony.
 *
 * Before this gate, /webauthn/authenticate/challenge required only an
 * email and /authenticate/verify minted a full session — so POSSESSION
 * of a registered authenticator alone signed a user in, silently
 * downgrading "password AND passkey" (the documented model: `Password
 * alone is not sufficient once a passkey exists`, auth.ts) to
 * "passkey alone", with `requireUserVerification: false` meaning no
 * PIN/biometric backstop either. A stolen or cloned security key was a
 * complete account takeover with zero knowledge factors.
 *
 * The gate is a short-lived signed cookie set by /login on EVERY
 * `{mfaRequired:true}` response (the R85 F3 uniform shape):
 *   - correct password → value carries HMAC(JWT_SECRET, userId ‖ iat)
 *   - wrong password / unknown email → value carries random bytes of
 *     identical length
 * Cookies are SIGNED, not encrypted, so the holder can read the value —
 * but an HMAC over the (cuid, non-secret) userId and random bytes are
 * indistinguishable without JWT_SECRET, preserving every
 * R76/R85/R86/R87/R143/R144 anti-oracle property: the wire shape,
 * cookie shape, and timing are uniform across "password right" and
 * "password wrong".
 *
 * /authenticate/challenge treats a missing/expired/mismatched gate
 * exactly like an unknown email (decoy credentials, R210 F2 path);
 * /authenticate/verify re-checks the gate before minting the session.
 */
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import type { FastifyReply, FastifyRequest } from "fastify";
import { env } from "../env.js";
import { SESSION_COOKIE_OPTS } from "./auth.js";

export const MFA_GATE_COOKIE = "av_mfa_gate";
/** Matches the ceremony-challenge TTL: 5 minutes to touch the key. */
export const MFA_GATE_TTL_S = 300;

function gateMac(userId: string, iat: number): Buffer {
  const h = createHmac("sha256", env.JWT_SECRET);
  h.update("webauthn:mfa-gate:");
  h.update(userId);
  h.update(":");
  h.update(String(iat));
  return h.digest();
}

/**
 * Set the gate cookie. `verifiedUserId` is null when the password check
 * failed — a decoy value of identical shape is set so the cookie's
 * presence/absence cannot become the password-validity oracle R85 F3
 * closed on the response body.
 */
export function setMfaGateCookie(reply: FastifyReply, verifiedUserId: string | null): void {
  const iat = Math.floor(Date.now() / 1000);
  const mac = verifiedUserId === null ? randomBytes(32) : gateMac(verifiedUserId, iat);
  reply.setCookie(MFA_GATE_COOKIE, JSON.stringify({ mac: mac.toString("base64url"), iat }), {
    ...SESSION_COOKIE_OPTS,
    signed: true,
    maxAge: MFA_GATE_TTL_S,
    // Rides only to the ceremony endpoints, like the challenge cookies.
    path: "/api/v1/auth/webauthn",
  });
}

/** True when the request carries a live gate proving a recent password
 * check for exactly `userId`. Constant-time MAC comparison. */
export function mfaGateAuthorizes(req: FastifyRequest, userId: string): boolean {
  const raw = req.cookies[MFA_GATE_COOKIE];
  if (!raw) return false;
  const unsigned = req.unsignCookie(raw);
  if (!unsigned.valid || unsigned.value === null) return false;
  let bag: { mac?: unknown; iat?: unknown };
  try {
    bag = JSON.parse(unsigned.value) as { mac?: unknown; iat?: unknown };
  } catch {
    return false;
  }
  if (typeof bag.mac !== "string" || typeof bag.iat !== "number") return false;
  const age = Math.floor(Date.now() / 1000) - bag.iat;
  if (age < 0 || age > MFA_GATE_TTL_S) return false;
  let presented: Buffer;
  try {
    presented = Buffer.from(bag.mac, "base64url");
  } catch {
    return false;
  }
  const expected = gateMac(userId, bag.iat);
  return presented.length === expected.length && timingSafeEqual(presented, expected);
}

export function clearMfaGateCookie(reply: FastifyReply): void {
  reply.clearCookie(MFA_GATE_COOKIE, { path: "/api/v1/auth/webauthn" });
}
