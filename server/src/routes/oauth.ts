/*
 * OIDC login for Google and Microsoft.
 *
 * One code path, two providers. openid-client handles the whole
 * discovery + PKCE + state + nonce + code-exchange sequence per the
 * OpenID Connect 1.0 spec. Each provider's authorization server is
 * discovered from its well-known metadata URL:
 *
 *   Google:     https://accounts.google.com
 *   Microsoft:  https://login.microsoftonline.com/{tenant}/v2.0
 *
 * State + PKCE verifier + nonce are stashed in a short-lived signed
 * cookie so we don't need Redis or a session store. Cookie is
 * httpOnly, SameSite=Lax, Secure in prod — same posture as the main
 * session cookie.
 *
 * On successful callback we either sign in an existing user (matched
 * by email) or create a new user + org named after the email domain.
 * Same behavior as Vercel, Linear, Notion — email owns the account.
 */

import type { FastifyInstance } from "fastify";
import * as oidc from "openid-client";
import { z } from "zod";
import crypto from "node:crypto";
import { db } from "../db.js";
import { env } from "../env.js";
import {
  SESSION_COOKIE_OPTS,
  hashPassword,
  mintSession,
  randomToken,
} from "../lib/auth.js";
import { writeAudit } from "../lib/audit.js";

interface ProviderCfg {
  id: "google" | "microsoft";
  displayName: string;
  discoveryUrl: string;
  clientId: string;
  clientSecret: string;
  scope: string;
}

function providerConfigs(): ProviderCfg[] {
  const out: ProviderCfg[] = [];
  if (env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET) {
    out.push({
      id: "google",
      displayName: "Google",
      discoveryUrl: "https://accounts.google.com",
      clientId: env.GOOGLE_CLIENT_ID,
      clientSecret: env.GOOGLE_CLIENT_SECRET,
      scope: "openid email profile",
    });
  }
  if (env.MICROSOFT_CLIENT_ID && env.MICROSOFT_CLIENT_SECRET) {
    // 'common' works for both work/school and personal MSA accounts.
    // A specific tenant id restricts to that org — good for single-
    // tenant enterprise deploys.
    out.push({
      id: "microsoft",
      displayName: "Microsoft",
      discoveryUrl: `https://login.microsoftonline.com/${env.MICROSOFT_TENANT}/v2.0`,
      clientId: env.MICROSOFT_CLIENT_ID,
      clientSecret: env.MICROSOFT_CLIENT_SECRET,
      scope: "openid email profile",
    });
  }
  return out;
}

// Cache Configuration objects across requests. openid-client discovery
// is one HTTPS round-trip per provider; caching keeps callbacks fast.
const configCache: Map<string, oidc.Configuration> = new Map();

async function getConfig(p: ProviderCfg): Promise<oidc.Configuration> {
  const cached = configCache.get(p.id);
  if (cached) return cached;
  const cfg = await oidc.discovery(
    new URL(p.discoveryUrl),
    p.clientId,
    undefined,
    oidc.ClientSecretPost(p.clientSecret),
  );
  configCache.set(p.id, cfg);
  return cfg;
}

// Signed cookie holding {state, codeVerifier, nonce, provider}. Short
// TTL — the whole redirect dance is normally 5-30 s. 10 min is generous
// but bounded.
const OAUTH_STATE_COOKIE = "av_oauth_state";
const OAUTH_STATE_TTL_S = 600;

function orgSlug(domain: string): string {
  const salt = randomToken(4).toLowerCase().slice(0, 6);
  const base = domain
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 32);
  return base ? `${base}-${salt}` : `org-${salt}`;
}

export async function oauthRoutes(app: FastifyInstance): Promise<void> {
  // GET /providers — lets the login page know which SSO buttons to
  // show. Buttons for providers without env config are hidden — no
  // point clicking a button that will 404.
  app.get("/providers", {
    // R134 F3: per-IP rate limit at 60/min (2× sibling cadence
    // since the response is genuinely cheap — env-derived
    // array, no DB, no crypto). Was the last anonymous auth-
    // tree GET without a per-route bucket after R132 F2 patched
    // /oauth/start and R133 F1 patched /saml/login. Cheap
    // symmetry: 60/min doesn't break the SPA (one hit per
    // login-page render) but denies a targeted attacker a
    // low-cost heartbeat probe on the API during a targeted
    // outage.
    config: {
      rateLimit: {
        max: 60,
        timeWindow: 60_000,
        keyGenerator: (req: { ip: string }) => `ip:${req.ip}`,
      },
    },
  }, async () => {
    return {
      providers: providerConfigs().map((p) => ({
        id: p.id,
        displayName: p.displayName,
      })),
    };
  });

  // GET /:provider/start — kicks off the auth code + PKCE flow.
  // Sets a short-lived signed cookie with the state + verifier, then
  // redirects the browser to the provider's authorize endpoint.
  // R132 F2: perIp(30, 60_000) per-route rate limit. Prior shape
  // fell to the global 300/min/IP — every other anonymous
  // auth-tree endpoint (login perIp(10), signup perIp(5),
  // reset-request perIp(3, 1h), reset-confirm perIp(10),
  // webauthn/authenticate perIp(10), members/invites/accept
  // perIp(10), saml/discover 30/min after R131 F3) has one.
  // Not currently exploitable but a lone attacker looping /start
  // could pin an entire corporate NAT's IP quota. 30/min/IP
  // matches the /discover cadence (both are cheap pre-login
  // handshakes). Sibling /callback fast-fails on missing/
  // tampered state cookie before any expensive work so it's fine
  // on the global bucket.
  app.get("/:provider/start", {
    config: {
      rateLimit: {
        max: 30,
        timeWindow: 60_000,
        keyGenerator: (req: { ip: string }) => `ip:${req.ip}`,
      },
    },
  }, async (req, reply) => {
    // R123 F1: kickoff endpoint is a top-level browser navigation
    // (docs/app/datasource.js window.location.assign to /start).
    // R122 F2 fixed /callback; this closes the sibling error paths.
    // R132 F4: encodeURIComponent the slug so future callers that
    // interpolate a value can't emit malformed URLs.
    const errRedirect = (slug: string) =>
      reply.redirect(
        `${env.APP_BASE_URL.replace(/\/$/, "")}/app/#/login?err=${encodeURIComponent(slug)}`,
      );
    const params = z
      .object({ provider: z.enum(["google", "microsoft"]) })
      .safeParse(req.params);
    if (!params.success) {
      return errRedirect("oauth_provider_not_found");
    }
    const providers = providerConfigs();
    const p = providers.find((x) => x.id === params.data.provider);
    if (!p) {
      return errRedirect("oauth_provider_not_configured");
    }

    const cfg = await getConfig(p);
    const codeVerifier = oidc.randomPKCECodeVerifier();
    const codeChallenge = await oidc.calculatePKCECodeChallenge(codeVerifier);
    const state = oidc.randomState();
    const nonce = oidc.randomNonce();

    const redirectUri = `${env.APP_BASE_URL.replace(/\/$/, "")}/api/v1/auth/oauth/${p.id}/callback`;
    const authUrl = oidc.buildAuthorizationUrl(cfg, {
      redirect_uri: redirectUri,
      scope: p.scope,
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
      state,
      nonce,
    });

    reply.setCookie(
      OAUTH_STATE_COOKIE,
      JSON.stringify({ state, codeVerifier, nonce, provider: p.id }),
      {
        ...SESSION_COOKIE_OPTS,
        maxAge: OAUTH_STATE_TTL_S,
        path: "/api/v1/auth/oauth",
        // R95 F4: HMAC-signed via the @fastify/cookie secret
        // registered at index.ts. Closes the login-CSRF /
        // OIDC-fixation variant where an attacker with a
        // parent-domain cookie primitive plants a valid
        // state bag in the victim's browser. Read path uses
        // req.unsignCookie() to verify + strip the signature.
        signed: true,
      },
    );

    return reply.redirect(authUrl.toString());
  });

  // GET /:provider/callback — the provider redirects here after user
  // consent. We validate the state + PKCE, fetch the id_token +
  // userinfo, then upsert the user + org and mint our own session
  // cookie.
  app.get("/:provider/callback", async (req, reply) => {
    // R122 F2: OAuth callback is a top-level browser navigation
    // (the IdP redirects the user-agent to this GET). Every
    // reply.code(4xx).send({error}) below rendered as raw JSON
    // in an otherwise-blank tab — dead-end UX. Sibling of the
    // R121 F2 mfa-required refusal; convert all errors to
    // redirects so the SPA .auth-note banner surfaces a
    // friendly explanation. Log lines preserve forensic detail.
    // R132 F4: encodeURIComponent the slug for consistency
    // across every errRedirect helper.
    const errRedirect = (slug: string) =>
      reply.redirect(
        `${env.APP_BASE_URL.replace(/\/$/, "")}/app/#/login?err=${encodeURIComponent(slug)}`,
      );
    const params = z
      .object({ provider: z.enum(["google", "microsoft"]) })
      .safeParse(req.params);
    if (!params.success) {
      return errRedirect("oauth_provider_not_found");
    }
    // R95 F4: signed cookies arrive via req.cookies as-is; use
    // req.unsignCookie to verify + strip the HMAC. On tamper the
    // valid flag is false; treat that as missing_state_cookie so
    // the wire response doesn't distinguish 'no cookie' from
    // 'forged cookie'.
    const stateRawSigned = req.cookies[OAUTH_STATE_COOKIE];
    if (!stateRawSigned) {
      return errRedirect("oauth_missing_state_cookie");
    }
    const unsigned = req.unsignCookie(stateRawSigned);
    if (!unsigned.valid || unsigned.value == null) {
      return errRedirect("oauth_missing_state_cookie");
    }
    const stateRaw = unsigned.value;
    let stateBag: {
      state: string;
      codeVerifier: string;
      nonce: string;
      provider: string;
    };
    try {
      stateBag = JSON.parse(stateRaw);
    } catch {
      return errRedirect("oauth_malformed_state_cookie");
    }
    if (stateBag.provider !== params.data.provider) {
      return errRedirect("oauth_provider_mismatch");
    }

    const providers = providerConfigs();
    const p = providers.find((x) => x.id === params.data.provider);
    if (!p) {
      return errRedirect("oauth_provider_not_configured");
    }
    const cfg = await getConfig(p);

    // R97 F-D: reconstruct the callback URL from APP_BASE_URL,
    // not from raw request headers. Prior shape read
    // `req.headers['x-forwarded-proto']` and `req.headers.host`
    // directly — the XFP header can legitimately arrive
    // comma-joined ('https, http') on a multi-hop stack, which
    // makes `new URL(req.url, 'https, http://host')` throw
    // TypeError → uncaught 500. It also bypasses R96 F1's
    // TRUSTED_PROXY_HOP_COUNT gate: even in dev with
    // hopCount=0, a caller-supplied XFP flowed through
    // untrusted. APP_BASE_URL is the same source that the
    // /start endpoint's redirect_uri contract is anchored to
    // (line 140), so the IdP's `redirect_uri` check requires
    // this exact host anyway — no external-header dependency.
    const base = env.APP_BASE_URL.replace(/\/$/, "");
    const currentUrl = new URL(req.url, base);

    let tokens;
    try {
      tokens = await oidc.authorizationCodeGrant(cfg, currentUrl, {
        pkceCodeVerifier: stateBag.codeVerifier,
        expectedState: stateBag.state,
        expectedNonce: stateBag.nonce,
      });
    } catch (err) {
      req.log.warn({ err }, "oauth_code_exchange_failed");
      return errRedirect("oauth_exchange_failed");
    }

    // id_token claims give us email + name without a second round-trip.
    const claims = tokens.claims();
    // R135 F2: cap IdP-asserted email + displayName before they
    // hit db.user.create / db.user.findUnique (line ~337). Direct
    // OIDC sibling of R134 F4's SAML fix — Prisma.User.email +
    // displayName are unbounded String / String?. An attacker
    // running their own IdP (self-hosted Keycloak / dev workspace)
    // can JIT-provision users with megabyte email / name claims
    // that balloon /members list render + /me/export bundles.
    // RFC 5321 max email = 320; console signup enforces
    // displayName max(80), so 200 gives IdP-asserted legitimate
    // names some slack while still bounded. Also caps the
    // `domain.split(".")[0]` slug feed at RFC 1035's 63-char
    // label max so a 1 MB email doesn't produce a 1 MB org.name.
    const email = typeof claims?.email === "string"
      ? claims.email.toLowerCase().slice(0, 320)
      : null;
    // R76 MEDIUM #5 (landed R77): only accept the JSON boolean
    // `true` for `email_verified`. Prior shape accepted the string
    // `"true"` too, which widened the acceptance surface to
    // permissive IdPs that emit stringly-typed unverified addresses
    // (some Azure AD B2C multi-tenant / personal MSA flows, some
    // custom IdP appliances). An attacker who registers an
    // outlook.com / gmail alias mimicking `victim@corp.com` via a
    // misconfigured MSA tenant would then pass the `emailVerified`
    // gate and be upserted onto the victim's existing account
    // (line 241 `db.user.findUnique({ where: { email } })`) — an
    // account-takeover primitive. If interop with a specific
    // stringly-typed IdP is required, add a per-issuer allowlist
    // that opts THAT `iss` in explicitly.
    const emailVerified = claims?.email_verified === true;
    const displayName = typeof claims?.name === "string"
      ? claims.name.slice(0, 200)
      : null;

    if (!email) {
      return errRedirect("oauth_no_email_in_id_token");
    }
    // Refuse unverified emails — otherwise an attacker who controls
    // an SMTP server can register with someone else's address.
    // Google always sets email_verified=true; Microsoft may not for
    // MSA accounts.
    if (!emailVerified) {
      return errRedirect("oauth_email_not_verified");
    }

    // Upsert. Email owns the account.
    let user = await db.user.findUnique({
      where: { email },
      // R105 F4: deterministic membership ordering (see auth.ts).
      include: { memberships: { include: { org: true }, orderBy: { createdAt: "asc" } } },
    });
    if (!user) {
      const domain = email.split("@")[1] ?? "personal";
      // R135 F2: cap the org.name derived from `domain.split(".")[0]`
      // at RFC 1035's 63-char DNS label maximum. Belt-and-suspenders
      // against a 1 MB email producing a 1 MB org.name (the email
      // itself is now capped at 320 above, so this is defense-in-
      // depth for future-proofing).
      // R137 F2: wrap org.create + user.create in a single
      // $transaction so a partial failure (P2024 pool timeout,
      // connection loss, SIGTERM mid-rollout, or a concurrent
      // /signup landing the same email in the sub-second window
      // between findUnique above and here) can't leave:
      //   (a) an orphan Org row with a burned unique slug that
      //       blocks the next legitimate signup with that domain
      //       (DoS primitive if attacker can trigger user.create
      //       failures reliably), or
      //   (b) a spurious org.created audit row for an org that
      //       has no owner and can never be logged into — the
      //       R135 F4 forensic query "which orgs came into
      //       existence via OAuth-JIT" would then return lies.
      // Also delay the org.created writeAudit until after the tx
      // commits so a rollback doesn't leave a phantom breadcrumb.
      // /signup at auth.ts:105 uses the same shape.
      const created = await db.$transaction(async (tx) => {
        const newOrg = await tx.org.create({
          data: {
            name: (domain.split(".")[0] || "Personal").slice(0, 63),
            slug: orgSlug(domain),
          },
        });
        const newUser = await tx.user.create({
          data: {
            email,
            displayName,
            // R86 F3: use a real argon2 hash of random bytes so
            // that verifyPassword timing matches password-set
            // users. Prior shape stored `oidc:${provider}:${hex}`
            // — @node-rs/argon2 threw on the malformed PHC
            // header in sub-ms and gave the login endpoint a
            // wire-visible timing oracle for OAuth-registered
            // accounts. verifyPassword now falls back to the
            // dummy hash for non-argon2 strings (defensive layer);
            // this line stores a real argon2 string so the fallback
            // isn't exercised.
            passwordHash: await hashPassword(
              crypto.randomUUID() + crypto.randomUUID(),
            ),
            memberships: {
              create: { orgId: newOrg.id, role: "owner" },
            },
          },
          include: { memberships: { include: { org: true }, orderBy: { createdAt: "asc" } } },
        });
        return { org: newOrg, user: newUser };
      });
      // R135 F4 audit — post-commit so a rolled-back tx doesn't
      // leave a phantom org.created audit row.
      writeAudit(
        {
          orgId: created.org.id,
          event: "org.created",
          actorId: null,
          actorEmail: email,
          target: created.org.name,
          metadata: {
            provider: params.data.provider,
            viaOauthJit: true,
            orgSlug: created.org.slug,
          },
          req,
        },
        req.log,
      );
      user = created.user;
    }

    const membership = user.memberships[0];
    if (!membership) {
      // Shouldn't happen — every user has at least one membership by
      // construction. R122 F2: redirect for browser-UX consistency
      // (top-level nav, sibling of the other errors above).
      return errRedirect("oauth_no_membership");
    }
    // R120 F2 (resolves the R110 F4 deferred item): OAuth login
    // MUST NOT bypass the WebAuthn MFA gate that /login enforces
    // (auth.ts:326-340). Otherwise the whole point of a passkey
    // — "password compromise ≠ account takeover" — is silently
    // invalidated any time a user has a linked OAuth account:
    //   1. User signs up with password + adds a hardware passkey.
    //   2. User also links Google OAuth (email matches).
    //   3. Attacker phishes / SIM-swaps the Google account.
    //   4. Attacker hits /api/v1/auth/oauth/callback → email
    //      verified → prior shape minted a full-role AV session
    //      cookie with ZERO passkey ceremony.
    // Fail-closed refusal is the smallest surgical change — the
    // user is told to use password login (which will then trigger
    // the R85 F3 mfaGateResponse flow and complete the passkey
    // ceremony). Product-policy call (per R110 F4 deferred queue)
    // resolved via ask_user; recommended safest-option chosen.
    // SAML ACS in saml.ts is a sibling but SAML MFA is
    // conventionally delegated to the IdP — out of scope here.
    const credentialCount = await db.webauthnCredential.count({
      where: { userId: user.id },
    });
    if (credentialCount > 0) {
      writeAudit(
        {
          orgId: membership.orgId,
          event: "auth.oauth_refused_mfa_required",
          actorId: user.id,
          actorEmail: user.email,
          target: user.email,
          req,
        },
        req.log,
      );
      // R121 F2 / R122 F2: use the shared errRedirect helper for
      // consistency with the other callback error exits.
      return errRedirect("mfa_required_use_password_login");
    }
    const token = await mintSession({
      sub: user.id,
      orgId: membership.orgId,
      membershipRole: membership.role as "owner" | "admin" | "member",
    });
    reply.setCookie(env.SESSION_COOKIE_NAME, token, SESSION_COOKIE_OPTS);
    // Clear the oauth state cookie now that we're done.
    reply.clearCookie(OAUTH_STATE_COOKIE, {
      path: "/api/v1/auth/oauth",
    });

    // R134 F2: every other sign-in path emits an audit row
    // (auth.ts login → auth.login, saml.ts ACS → saml.signin,
    // webauthn.ts step-up → mfa.authenticate). OAuth was the
    // only pipeline minting a session cookie without a
    // forensic breadcrumb, so an admin investigating "who
    // logged in via Google at 03:12 from IP X" found nothing.
    // The MFA-refused sibling already audits
    // auth.oauth_refused_mfa_required at line ~389, so the
    // imports + call shape are already wired here.
    writeAudit(
      {
        orgId: membership.orgId,
        event: "auth.oauth_signin",
        actorId: user.id,
        actorEmail: user.email,
        target: user.email,
        metadata: { provider: params.data.provider },
        req,
      },
      req.log,
    );

    // Redirect the browser back into the SPA. The console picks up the
    // freshly-set session cookie on the next /me call.
    return reply.redirect(`${env.APP_BASE_URL.replace(/\/$/, "")}/app/#/overview`);
  });
}
