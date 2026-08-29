import { hash, verify } from "@node-rs/argon2";
import { SignJWT, jwtVerify } from "jose";
import crypto from "node:crypto";
import { env } from "../env.js";

const secretKey = new TextEncoder().encode(env.JWT_SECRET);

// Argon2id parameters chosen to hit ~100ms on modern hardware — well above
// the standard bar for password hashing and comfortably above the OWASP 2024
// recommendation.
const ARGON2_OPTS = {
  memoryCost: 19_456, // 19 MiB
  timeCost: 2,
  parallelism: 1,
} as const;

export async function hashPassword(plaintext: string): Promise<string> {
  return hash(plaintext, ARGON2_OPTS);
}

// Precomputed dummy hash so login for a missing user still runs a real
// argon2 verify — closes the timing side-channel that would otherwise
// let an attacker distinguish "user exists" from "user missing" by
// clocking a 12ms 401 vs a 100ms 401. The previous dummy was an
// ill-formed argon2 string that argon2 threw on in <1ms, defeating the
// entire uniform-response-time posture. See lib/auth.verifyPassword.
//
// Generated once at module load. The password we hash here is a fixed
// throwaway; nobody ever tries to log in with it and it doesn't need
// to be secret.
let dummyHashPromise: Promise<string> | null = null;
export function getDummyPasswordHash(): Promise<string> {
  if (!dummyHashPromise) {
    dummyHashPromise = hash(
      "not-a-real-password-e5f2c7ac-timing-dummy",
      ARGON2_OPTS,
    );
  }
  return dummyHashPromise;
}
// Kick off the compute at import time so the first login isn't slower
// than the second.
void getDummyPasswordHash();

export async function verifyPassword(
  hashStr: string,
  plaintext: string,
): Promise<boolean> {
  // R86 F3: burn full argon2 time even when hashStr isn't a
  // valid argon2 PHC string. Prior shape called `verify(hashStr,
  // …)` and let @node-rs/argon2 throw immediately on a
  // non-argon2 header — dropping the ~50-120 ms cost down to
  // sub-ms. That's a WIRE-VISIBLE timing oracle: OAuth-
  // provisioned users had `passwordHash = "oidc:google:<hex>"`
  // (see oauth.ts:393) that failed decode instantly, so a
  // credential-stuffing attacker observing round-trip time on
  // /login could enumerate which addresses were OAuth-
  // registered users and target them with a fake consent-screen
  // phishing pack. Detect the non-argon2 case and run the
  // verify against the timing dummy so the response spends the
  // full argon2 budget regardless of the persistence detail.
  if (!hashStr.startsWith("$argon2")) {
    try {
      await verify(await getDummyPasswordHash(), plaintext);
    } catch {
      // ignored
    }
    return false;
  }
  try {
    return await verify(hashStr, plaintext);
  } catch {
    return false;
  }
}

export interface SessionClaims {
  sub: string; // user id
  orgId: string; // active org
  membershipRole: "owner" | "admin" | "member";
  iat: number; // JWT issued-at, seconds since epoch — checked against user.sessionRevokedAt
}

// R83 F1: role-hierarchy rank used to enforce "no grant above your own".
// Prior shape gated role-mutating endpoints (PATCH /members/:userId,
// POST /invites, POST /api/v1/keys) on `membershipRole !== "member"`
// and then accepted an arbitrary `role: "owner" | "admin" | "member"`
// from the request body. Result: any admin could (a) invite an
// attacker-controlled address as OWNER, (b) promote an existing
// member/admin to OWNER, or (c) mint an OWNER-scoped API key —
// all three paths hand out roles STRICTLY GREATER than the caller's
// own. Owner grants owner-only endpoints such as `POST
// /me/delete-account` (whole-org cascade delete) and `POST
// /saml/:configId/keypair` (DOSes SAML IdP trust). This helper
// centralizes the "cannot grant above your rank" check so a caller
// with role R can only grant roles ≤ R. Owners can grant any role;
// admins can grant admin or member; members can't reach these
// endpoints at all.
const ROLE_RANK: Record<SessionClaims["membershipRole"], number> = {
  owner: 3,
  admin: 2,
  member: 1,
};

export function canGrantRole(
  callerRole: SessionClaims["membershipRole"],
  targetRole: SessionClaims["membershipRole"],
): boolean {
  return ROLE_RANK[callerRole] >= ROLE_RANK[targetRole];
}

const SESSION_TTL_SECONDS = 60 * 60 * 24 * 7; // 7 days

export async function mintSession(claims: Omit<SessionClaims, "iat">): Promise<string> {
  return new SignJWT({ ...claims })
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setIssuer(env.JWT_ISSUER)
    .setAudience(env.JWT_AUDIENCE)
    .setIssuedAt()
    .setExpirationTime(`${SESSION_TTL_SECONDS}s`)
    .setSubject(claims.sub)
    .sign(secretKey);
}

export async function verifySession(
  token: string,
): Promise<SessionClaims | null> {
  try {
    const { payload } = await jwtVerify(token, secretKey, {
      issuer: env.JWT_ISSUER,
      audience: env.JWT_AUDIENCE,
    });
    if (
      typeof payload.sub !== "string" ||
      typeof payload.orgId !== "string" ||
      typeof payload.iat !== "number" ||
      (payload.membershipRole !== "owner" &&
        payload.membershipRole !== "admin" &&
        payload.membershipRole !== "member")
    ) {
      return null;
    }
    return {
      sub: payload.sub,
      orgId: payload.orgId,
      membershipRole: payload.membershipRole,
      iat: payload.iat,
    };
  } catch {
    return null;
  }
}

export const SESSION_COOKIE_OPTS = {
  httpOnly: true,
  sameSite: "lax" as const,
  secure: env.SESSION_COOKIE_SECURE,
  path: "/",
  maxAge: SESSION_TTL_SECONDS,
};

/** Cryptographically random URL-safe token (24 bytes → 32 chars base64url). */
export function randomToken(bytes = 24): string {
  return crypto.randomBytes(bytes).toString("base64url");
}
