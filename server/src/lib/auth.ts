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
}

const SESSION_TTL_SECONDS = 60 * 60 * 24 * 7; // 7 days

export async function mintSession(claims: SessionClaims): Promise<string> {
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
