/**
 * WebAuthn / passkey routes.
 *
 * Two ceremonies, four endpoints each side:
 *
 *   Registration (adding a new passkey):
 *     POST /register/challenge  — signed-in user asks for a challenge +
 *                                 registration options; server writes the
 *                                 challenge to a short-lived HttpOnly cookie.
 *     POST /register/verify     — user's browser posts the attestation; server
 *                                 verifies against the cookie'd challenge and
 *                                 persists the credential.
 *
 *   Authentication (signing in with a passkey):
 *     POST /authenticate/challenge  — anonymous. Client passes the email
 *                                     (looked up post-password). Server returns
 *                                     allowCredentials matching the user, sets
 *                                     a challenge cookie tied to that user id.
 *     POST /authenticate/verify     — client posts the assertion. Server
 *                                     verifies, mints an av_session.
 *
 *   CRUD:
 *     GET    /credentials
 *     PATCH  /credentials/:id      (rename)
 *     DELETE /credentials/:id
 *
 * The Relying Party ID is the console's host (derived from APP_BASE_URL).
 * Origins we accept during verify are the SPA's origins (ALLOWED_ORIGINS).
 * WebAuthn signCount is stored + strictly increasing checked so we detect
 * cloned authenticators.
 */

import type { FastifyInstance, FastifyReply } from "fastify";
import { z } from "zod";
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import { db } from "../db.js";
import { env } from "../env.js";
import {
  SESSION_COOKIE_OPTS,
  mintSession,
} from "../lib/auth.js";
import { writeAudit } from "../lib/audit.js";
import { requireSession } from "../lib/session-middleware.js";

// ---------------------------------------------------------------------------
// RP identity — used by SimpleWebAuthn to fill authenticator prompts.
// ---------------------------------------------------------------------------

function rpID(): string {
  try {
    return new URL(env.APP_BASE_URL).hostname;
  } catch {
    return "localhost";
  }
}

function acceptedOrigins(): string[] {
  // R103 F3: strip trailing slash on the APP_BASE_URL fallback.
  // R102 F2 normalized ALLOWED_ORIGINS but did NOT normalize
  // the raw APP_BASE_URL used here. SimpleWebAuthn's
  // verifyRegistrationResponse / verifyAuthenticationResponse
  // compare expectedOrigin BYTE-EXACT against the browser-
  // supplied origin field in the client-data JSON, and
  // browsers emit origin as scheme://host[:port] with NO
  // trailing slash. Operators who set
  // APP_BASE_URL=https://x.com/ (matching the R102 F2
  // motivating misconfig) with empty ALLOWED_ORIGINS would
  // silently break every passkey ceremony with 'Unexpected
  // registration response origin'. Trailing-slash strip
  // applied per-call is defense-in-depth even if env.ts
  // ever normalizes APP_BASE_URL upstream.
  return env.ALLOWED_ORIGINS.length
    ? env.ALLOWED_ORIGINS
    : [env.APP_BASE_URL.replace(/\/+$/, "")];
}

// Challenge cookies. Short-lived, HttpOnly. We split by ceremony so a
// registration cookie can never satisfy an authentication verify.
const REG_CHALLENGE_COOKIE = "av_wa_reg_challenge";
const AUTH_CHALLENGE_COOKIE = "av_wa_auth_challenge";
const CHALLENGE_TTL_S = 300; // 5 min — plenty for user prompt

function setChallengeCookie(
  reply: FastifyReply,
  name: string,
  value: string,
): void {
  reply.setCookie(name, value, {
    ...SESSION_COOKIE_OPTS,
    maxAge: CHALLENGE_TTL_S,
    // Ceremony cookies scoped to /api/v1/auth/webauthn so they never
    // ride with unrelated requests.
    path: "/api/v1/auth/webauthn",
  });
}

function clearChallengeCookie(reply: FastifyReply, name: string): void {
  reply.setCookie(name, "", {
    ...SESSION_COOKIE_OPTS,
    maxAge: 0,
    path: "/api/v1/auth/webauthn",
  });
}

// Helpers for base64url <-> Uint8Array. SimpleWebAuthn talks base64url
// on the wire but stores raw bytes for us to persist. Prisma Bytes column
// takes Buffer.
function b64uToBuffer(s: string): Buffer {
  const pad = 4 - (s.length % 4);
  const padded = s + (pad === 4 ? "" : "=".repeat(pad));
  return Buffer.from(padded.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

function bufferToB64u(b: Buffer | Uint8Array): string {
  return Buffer.from(b)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

// R76 MEDIUM #4 (landed R77): deterministic decoy credentials
// used by `/authenticate/challenge` to mask
// account-existence + passkey-presence from an anonymous
// caller. Seeded from HMAC-SHA256(JWT_SECRET, email) so the
// count AND the credential-id bytes are stable per email
// (a repeat probe for the same email gets the same decoys —
// otherwise varying decoys per probe would themselves become
// a "user does not exist" signal via correlation).
//
// Count varies 1-3 to match the natural distribution of real
// accounts (most users have 1-2 passkeys). Length of each
// decoy credential id is 32 bytes (typical for a real passkey).
// Verifying against these will fail authentically — the
// verify path treats userId=null as an authentication failure
// with the same shape as a real credential mismatch, so the
// caller cannot distinguish "wrong passkey" from "decoy
// challenge because the user doesn't exist".
async function deriveDecoyCredentials(
  email: string,
): Promise<{ id: string; transports?: undefined }[]> {
  const crypto = await import("node:crypto");
  const h = crypto.createHmac("sha256", env.JWT_SECRET);
  h.update("webauthn:decoy:");
  h.update(email);
  const seed = h.digest();
  // R87 F3: bump decoy count range 1–3 → 1–6 so power-users
  // (admins with laptop platform passkey + phone hybrid +
  // security key + backup key = 4+ real creds) can no longer
  // be identified by array length. R76 F4 hid the individual-
  // cred oracle; R86 F5 hid the transports oracle; R87 F3
  // closes the count oracle for realistic real-user
  // registrations. Real accounts with 7+ credentials remain
  // technically distinguishable but that's a very rare tail
  // and the real fix (cap real emissions too) would break
  // authentication for users whose current authenticator is
  // outside the emitted subset.
  const count = 1 + ((seed[0] ?? 0) % 6);
  const out: { id: string; transports?: undefined }[] = [];
  for (let i = 0; i < count; i++) {
    const idHmac = crypto.createHmac("sha256", env.JWT_SECRET);
    idHmac.update("webauthn:decoy:");
    idHmac.update(email);
    idHmac.update(Buffer.from([i]));
    out.push({ id: bufferToB64u(idHmac.digest()) });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

export async function webauthnRoutes(app: FastifyInstance): Promise<void> {
  // R88 F3: rate-limit siblings match /login (10/min/IP) and
  // /reset-request (3/hr/IP) patterns. R76/R86/R87 spent three
  // fixes hardening decoy indistinguishability for per-request
  // enumeration — but without a per-endpoint budget, an
  // attacker sharing the global 300 rpm/IP cap can still burn
  // ~299 probes/min at the /authenticate/challenge and
  // /authenticate/verify endpoints (which have no argon2 cost
  // to slow them down). Adding 10/min/IP matches the /login
  // sibling. Registration endpoints are session-gated so
  // don't need per-endpoint rate limits (the session cost
  // already blocks unauthenticated abuse).
  const perIp = (max: number, windowMs: number) => ({
    max,
    timeWindow: windowMs,
    keyGenerator: (req: { ip: string }) => `ip:${req.ip}`,
  });

  // -----------------------------------------------------------------------
  // Registration ceremony — signed-in user adds a new passkey.
  // -----------------------------------------------------------------------

  app.post("/register/challenge", async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    // R107 F1: API-key sessions have no user row and can't own a
    // passkey (the auth material is the plaintext av_srv_ token,
    // not a hardware credential). Reject up-front with the same
    // slug siblings use — /saml/slo (R105 F5), /logout (R106 F2),
    // stream (R100). The prior implicit guard here (findUnique
    // → 401) worked but returned a misleading 'unauthenticated'
    // slug; sibling /register/verify had no guard at all and
    // returned P2003 → 500 to the caller.
    if (claims.sub.startsWith("apikey:")) {
      return reply.code(400).send({ error: "cookie_session_required" });
    }
    const user = await db.user.findUnique({
      where: { id: claims.sub },
      include: { webauthnCredentials: true },
    });
    if (!user) return reply.code(401).send({ error: "unauthenticated" });

    const options = await generateRegistrationOptions({
      rpName: "AgentVisor AI",
      rpID: rpID(),
      userID: Buffer.from(user.id, "utf8"),
      userName: user.email,
      userDisplayName: user.displayName ?? user.email,
      // Exclude already-registered credentials so the browser doesn't
      // let the user re-add the same key.
      excludeCredentials: user.webauthnCredentials.map((c) => ({
        id: bufferToB64u(c.credentialId),
        transports: c.transports
          ? (c.transports.split(",") as ("usb" | "nfc" | "ble" | "internal" | "hybrid")[])
          : undefined,
      })),
      authenticatorSelection: {
        residentKey: "preferred",
        userVerification: "preferred",
      },
      // sha-256 + P-256 covers 99% of authenticators. Add ed25519 and RSA
      // as fallbacks so hardware keys with alternate curves work too.
      supportedAlgorithmIDs: [-7, -8, -257],
    });
    setChallengeCookie(reply, REG_CHALLENGE_COOKIE, options.challenge);
    return reply.send({ options });
  });

  app.post("/register/verify", async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    // R107 F1: reject api-key sessions — see /register/challenge
    // comment. Prior shape passed claims.sub through to
    // webauthnCredential.create as the userId, which threw
    // P2003 (FK violation) on 'apikey:<id>' → 500.
    if (claims.sub.startsWith("apikey:")) {
      return reply.code(400).send({ error: "cookie_session_required" });
    }
    const cookieChallenge = req.cookies[REG_CHALLENGE_COOKIE];
    if (!cookieChallenge) {
      return reply.code(400).send({ error: "no_challenge_cookie" });
    }
    const body = z
      .object({
        response: z.record(z.unknown()),
        label: z.string().min(1).max(80).default("Passkey"),
      })
      .safeParse(req.body);
    if (!body.success) return reply.code(400).send({ error: "invalid_input" });

    let verified;
    try {
      verified = await verifyRegistrationResponse({
        response: body.data.response as never,
        expectedChallenge: cookieChallenge,
        expectedOrigin: acceptedOrigins(),
        expectedRPID: rpID(),
        requireUserVerification: false,
      });
    } catch (err) {
      req.log.warn({ err }, "webauthn_register_verify_failed");
      clearChallengeCookie(reply, REG_CHALLENGE_COOKIE);
      // R105 F1: don't echo the internal library error message to
      // the wire. SimpleWebAuthn throws descriptive messages
      // like 'Unexpected registration response origin "X",
      // expected "Y"' — leaks the operator's canonical RP
      // origin / APP_BASE_URL to any unauthenticated caller
      // probing the ceremony. Server-side warn log already
      // captures err for ops.
      return reply.code(400).send({ error: "verify_failed" });
    }
    if (!verified.verified || !verified.registrationInfo) {
      clearChallengeCookie(reply, REG_CHALLENGE_COOKIE);
      return reply.code(400).send({ error: "not_verified" });
    }
    const info = verified.registrationInfo;

    // Persist the credential. If it already exists for this user (shouldn't
    // because of excludeCredentials, but a racing browser could beat it),
    // update the label instead of failing. Force fresh Buffer copies —
    // Prisma's Bytes column expects Buffer, and SimpleWebAuthn's Uint8Array
    // may be a subarray view whose slice-copy semantics don't survive a
    // JSON round trip if a subset were persisted by mistake.
    const credentialId = b64uToBuffer(info.credential.id);
    const publicKey = Buffer.from(info.credential.publicKey);
    try {
      await db.webauthnCredential.create({
        data: {
          userId: claims.sub,
          credentialId,
          publicKey,
          counter: BigInt(info.credential.counter ?? 0),
          transports: (body.data.response as { response?: { transports?: string[] } })
            ?.response?.transports?.join(",") ?? "",
          label: body.data.label,
          aaguid: info.aaguid ?? null,
        },
      });
    } catch (err) {
      if (
        typeof err === "object" && err !== null &&
        (err as { code?: string }).code === "P2002"
      ) {
        return reply.code(409).send({ error: "credential_already_registered" });
      }
      throw err;
    }
    clearChallengeCookie(reply, REG_CHALLENGE_COOKIE);
    writeAudit(
      {
        orgId: claims.orgId,
        event: "mfa.credential_registered",
        actorId: claims.sub,
        target: body.data.label,
        metadata: { credentialLabel: body.data.label },
        req,
      },
      req.log,
    );
    return reply.send({ ok: true });
  });

  // -----------------------------------------------------------------------
  // Authentication ceremony — anonymous. Called after successful password
  // login when the account has at least one credential.
  // -----------------------------------------------------------------------

  app.post("/authenticate/challenge", {
    // R88 F3: 10/min per IP matches /login.
    config: { rateLimit: perIp(10, 60_000) },
  }, async (req, reply) => {
    const body = z
      .object({ email: z.string().min(3).max(320).toLowerCase().trim() })
      .safeParse(req.body);
    if (!body.success) return reply.code(400).send({ error: "invalid_input" });
    const user = await db.user.findUnique({
      where: { email: body.data.email },
      include: { webauthnCredentials: true },
    });
    // R76 MEDIUM #4 (landed R77): eliminate the credential-
    // enumeration side channel. Prior shape returned an empty
    // `allowCredentials` for unknown emails AND emitted a
    // `hasCredential` boolean, letting an anonymous attacker
    // build a directory of {email -> account_exists, has_passkey,
    // credentialId} — cross-referenced with
    // `/auth/password`'s `mfaRequired` this drove targeted
    // phishing / credential-stuffing.
    //
    // Fix: for unknown emails or accounts with no real
    // credentials, seed a deterministic decoy list from
    // HMAC(JWT_SECRET, email) so the response shape is
    // indistinguishable across existent / nonexistent /
    // no-credential accounts. The count varies 1-3 seeded from
    // the same HMAC so the LIST LENGTH is not a signal either.
    // The verify endpoint will fail these attempts uniformly
    // (userId=null triggers the same rejection as a real
    // credential mismatch). Drop `hasCredential` from the
    // response.
    const realCreds = user?.webauthnCredentials ?? [];
    // R86 F5: strip `transports` from the real-cred emission
    // so real accounts and decoys look identical on the wire.
    // Prior shape mapped `c.transports` to a non-empty array
    // (`internal,hybrid` for platform passkeys, `usb` for
    // security keys — virtually every modern registration is
    // non-empty), while decoys always had `transports:
    // undefined`. Attacker distinguishes decoy from real by
    // inspecting `options.allowCredentials[i].transports` in
    // the response. Dropping transports on both paths costs
    // the client only the ability to filter by physical
    // authenticator hint — SimpleWebAuthn still verifies
    // correctly, browsers still show all registered
    // authenticators. Small UX cost for a real enumeration
    // fix.
    const allowCredentials = realCreds.length > 0
      ? realCreds.map((c) => ({
          id: bufferToB64u(c.credentialId),
        }))
      : await deriveDecoyCredentials(body.data.email);
    const options = await generateAuthenticationOptions({
      rpID: rpID(),
      allowCredentials,
      userVerification: "preferred",
    });
    setChallengeCookie(
      reply,
      AUTH_CHALLENGE_COOKIE,
      JSON.stringify({ challenge: options.challenge, userId: user?.id ?? null }),
    );
    // Drop `hasCredential` — it explicitly leaked account
    // presence. Clients that gated their UI on it should switch
    // to always calling `/authenticate/verify` and treating any
    // failure as "wrong or missing passkey" (indistinguishable
    // by design).
    return reply.send({ options });
  });

  app.post("/authenticate/verify", {
    // R88 F3: 10/min per IP matches /login.
    config: { rateLimit: perIp(10, 60_000) },
  }, async (req, reply) => {
    const cookieRaw = req.cookies[AUTH_CHALLENGE_COOKIE];
    if (!cookieRaw) return reply.code(400).send({ error: "no_challenge_cookie" });
    let bag: { challenge: string; userId: string | null };
    try {
      bag = JSON.parse(cookieRaw);
    } catch {
      return reply.code(400).send({ error: "malformed_challenge_cookie" });
    }
    if (!bag.userId) {
      // R86 F4 (revised R87 F1): decoy path — the challenge was
      // issued against an unknown email or one with no real
      // credentials. All exits must match the REAL path so decoy
      // vs real is indistinguishable across every wire-visible
      // outcome. Parse the body, burn a DB lookup, clear cookie,
      // return the same `unknown_credential` string.
      const bodyDecoy = z
        .object({ response: z.record(z.unknown()) })
        .safeParse(req.body);
      void bodyDecoy; // parsed for timing parity only
      // Match the real path's DB timing by running a lookup that
      // always returns null.
      await db.webauthnCredential.findFirst({
        where: { userId: "__decoy__" },
      }).catch(() => null);
      clearChallengeCookie(reply, AUTH_CHALLENGE_COOKIE);
      return reply.code(400).send({ error: "unknown_credential" });
    }
    // R87 F1: real path early exits (malformed body, missing rawId)
    // used to return `invalid_input` / `no_credential_id` while the
    // decoy path returned `unknown_credential`. Same wire-visible
    // input hitting both paths therefore leaked account existence:
    //   body {"response":{}} → real:  no_credential_id
    //                       → decoy: unknown_credential
    //   body "garbage"       → real:  invalid_input
    //                       → decoy: unknown_credential
    // The R86 F4 commit message claimed decoy/real fail identically
    // but only the "unknown cred" branch was collapsed. Fix: mirror
    // the decoy path exactly (parse body, burn a DB lookup, clear
    // cookie, return unknown_credential) whenever the real path
    // would take an early exit before the credential lookup.
    const body = z
      .object({ response: z.record(z.unknown()) })
      .safeParse(req.body);
    const rawId = body.success
      ? ((body.data.response as { rawId?: string; id?: string }).rawId
        ?? (body.data.response as { id?: string }).id
        ?? "")
      : "";
    if (!body.success || !rawId) {
      // Burn the same DB round-trip the credential-lookup path
      // would spend, so timing parity with the real "cred not
      // found" branch is preserved.
      await db.webauthnCredential.findFirst({
        where: { userId: bag.userId },
      }).catch(() => null);
      clearChallengeCookie(reply, AUTH_CHALLENGE_COOKIE);
      return reply.code(400).send({ error: "unknown_credential" });
    }
    const cred = await db.webauthnCredential.findFirst({
      where: {
        userId: bag.userId,
        credentialId: b64uToBuffer(rawId),
      },
    });
    if (!cred) {
      clearChallengeCookie(reply, AUTH_CHALLENGE_COOKIE);
      return reply.code(400).send({ error: "unknown_credential" });
    }

    let verified;
    try {
      // Prisma's Bytes column returns a Buffer whose .buffer may be a
      // shared pool slice; SimpleWebAuthn's CBOR decoder can misread
      // subarrays as short. Copy into a fresh Uint8Array so the
      // .buffer / byteOffset / byteLength triple is well-formed.
      const pubKeyCopy = new Uint8Array(cred.publicKey.byteLength);
      pubKeyCopy.set(new Uint8Array(cred.publicKey));
      verified = await verifyAuthenticationResponse({
        response: body.data.response as never,
        expectedChallenge: bag.challenge,
        expectedOrigin: acceptedOrigins(),
        expectedRPID: rpID(),
        credential: {
          id: bufferToB64u(cred.credentialId),
          publicKey: pubKeyCopy,
          counter: Number(cred.counter),
          transports: cred.transports
            ? (cred.transports.split(",") as ("usb" | "nfc" | "ble" | "internal" | "hybrid")[])
            : undefined,
        },
        requireUserVerification: false,
      });
    } catch (err) {
      req.log.warn({ err }, "webauthn_auth_verify_failed");
      clearChallengeCookie(reply, AUTH_CHALLENGE_COOKIE);
      // R105 F1: see webauthn_register_verify_failed above —
      // don't echo the internal library error message.
      return reply.code(400).send({ error: "verify_failed" });
    }
    if (!verified.verified) {
      clearChallengeCookie(reply, AUTH_CHALLENGE_COOKIE);
      return reply.code(400).send({ error: "not_verified" });
    }

    // Clone detection — signCount must strictly increase.
    const newCounter = BigInt(verified.authenticationInfo.newCounter);
    if (newCounter <= cred.counter && cred.counter !== BigInt(0)) {
      req.log.warn(
        { credId: cred.id, storedCounter: String(cred.counter), newCounter: String(newCounter) },
        "webauthn_clone_detected",
      );
      clearChallengeCookie(reply, AUTH_CHALLENGE_COOKIE);
      return reply.code(400).send({ error: "clone_detected" });
    }

    // Bump the counter + last-used.
    await db.webauthnCredential.update({
      where: { id: cred.id },
      data: {
        counter: newCounter,
        lastUsedAt: new Date(),
      },
    });
    clearChallengeCookie(reply, AUTH_CHALLENGE_COOKIE);

    // Mint the session — same shape as password login.
    const user = await db.user.findUnique({
      where: { id: cred.userId },
      // R105 F4: deterministic membership ordering (see auth.ts).
      include: { memberships: { include: { org: true }, orderBy: { createdAt: "asc" } } },
    });
    if (!user) return reply.code(401).send({ error: "user_disappeared" });
    const membership = user.memberships[0];
    if (!membership) return reply.code(403).send({ error: "no_org" });
    const token = await mintSession({
      sub: user.id,
      orgId: membership.orgId,
      membershipRole: membership.role as "owner" | "admin" | "member",
    });
    reply.setCookie(env.SESSION_COOKIE_NAME, token, SESSION_COOKIE_OPTS);
    writeAudit(
      {
        orgId: membership.orgId,
        event: "mfa.authenticate",
        actorId: user.id,
        actorEmail: user.email,
        target: cred.label,
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

  // -----------------------------------------------------------------------
  // CRUD on the current user's credentials.
  // -----------------------------------------------------------------------

  app.get("/credentials", async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    const rows = await db.webauthnCredential.findMany({
      where: { userId: claims.sub },
      orderBy: { createdAt: "asc" },
    });
    return reply.send({
      credentials: rows.map((r) => ({
        id: r.id,
        label: r.label,
        transports: r.transports.split(",").filter(Boolean),
        aaguid: r.aaguid,
        createdAt: r.createdAt,
        lastUsedAt: r.lastUsedAt,
      })),
    });
  });

  app.patch<{ Params: { id: string } }>("/credentials/:id", async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    const body = z.object({ label: z.string().min(1).max(80) }).safeParse(req.body);
    if (!body.success) return reply.code(400).send({ error: "invalid_input" });
    const cred = await db.webauthnCredential.findFirst({
      where: { id: req.params.id, userId: claims.sub },
    });
    if (!cred) return reply.code(404).send({ error: "not_found" });
    const updated = await db.webauthnCredential.update({
      where: { id: cred.id },
      data: { label: body.data.label },
    });
    return reply.send({ credential: { id: updated.id, label: updated.label } });
  });

  app.delete<{ Params: { id: string } }>("/credentials/:id", async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    const cred = await db.webauthnCredential.findFirst({
      where: { id: req.params.id, userId: claims.sub },
    });
    if (!cred) return reply.code(404).send({ error: "not_found" });
    await db.webauthnCredential.delete({ where: { id: cred.id } });
    writeAudit(
      {
        orgId: claims.orgId,
        event: "mfa.credential_revoked",
        actorId: claims.sub,
        target: cred.label,
        req,
      },
      req.log,
    );
    return reply.code(204).send();
  });
}
