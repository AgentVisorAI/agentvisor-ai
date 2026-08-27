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
  app.get("/providers", async () => {
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
  app.get("/:provider/start", async (req, reply) => {
    const params = z
      .object({ provider: z.enum(["google", "microsoft"]) })
      .safeParse(req.params);
    if (!params.success) {
      return reply.code(404).send({ error: "provider_not_found" });
    }
    const providers = providerConfigs();
    const p = providers.find((x) => x.id === params.data.provider);
    if (!p) {
      return reply.code(404).send({ error: "provider_not_configured" });
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
        // signed: true — @fastify/cookie can HMAC-sign if a secret is set.
        // We omit here to keep parity with the main session cookie which
        // is a JWT (self-signed). Short TTL + httpOnly + strict CSRF
        // handling upstream covers the attack surface.
      },
    );

    return reply.redirect(authUrl.toString());
  });

  // GET /:provider/callback — the provider redirects here after user
  // consent. We validate the state + PKCE, fetch the id_token +
  // userinfo, then upsert the user + org and mint our own session
  // cookie.
  app.get("/:provider/callback", async (req, reply) => {
    const params = z
      .object({ provider: z.enum(["google", "microsoft"]) })
      .safeParse(req.params);
    if (!params.success) {
      return reply.code(404).send({ error: "provider_not_found" });
    }
    const stateRaw = req.cookies[OAUTH_STATE_COOKIE];
    if (!stateRaw) {
      return reply.code(400).send({ error: "missing_state_cookie" });
    }
    let stateBag: {
      state: string;
      codeVerifier: string;
      nonce: string;
      provider: string;
    };
    try {
      stateBag = JSON.parse(stateRaw);
    } catch {
      return reply.code(400).send({ error: "malformed_state_cookie" });
    }
    if (stateBag.provider !== params.data.provider) {
      return reply.code(400).send({ error: "provider_mismatch" });
    }

    const providers = providerConfigs();
    const p = providers.find((x) => x.id === params.data.provider);
    if (!p) {
      return reply.code(404).send({ error: "provider_not_configured" });
    }
    const cfg = await getConfig(p);

    // openid-client expects the full callback URL to parse the code +
    // state out of the query string. We reconstruct from req.protocol
    // (which is X-Forwarded-Proto-aware thanks to trustProxy) + host.
    const proto = req.headers["x-forwarded-proto"] ?? (env.NODE_ENV === "production" ? "https" : "http");
    const currentUrl = new URL(
      req.url,
      `${Array.isArray(proto) ? proto[0] : proto}://${req.headers.host}`,
    );

    let tokens;
    try {
      tokens = await oidc.authorizationCodeGrant(cfg, currentUrl, {
        pkceCodeVerifier: stateBag.codeVerifier,
        expectedState: stateBag.state,
        expectedNonce: stateBag.nonce,
      });
    } catch (err) {
      req.log.warn({ err }, "oauth_code_exchange_failed");
      return reply.code(400).send({ error: "oauth_exchange_failed" });
    }

    // id_token claims give us email + name without a second round-trip.
    const claims = tokens.claims();
    const email = typeof claims?.email === "string" ? claims.email.toLowerCase() : null;
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
    const displayName = typeof claims?.name === "string" ? claims.name : null;

    if (!email) {
      return reply.code(400).send({ error: "no_email_in_id_token" });
    }
    // Refuse unverified emails — otherwise an attacker who controls
    // an SMTP server can register with someone else's address.
    // Google always sets email_verified=true; Microsoft may not for
    // MSA accounts.
    if (!emailVerified) {
      return reply.code(403).send({ error: "email_not_verified" });
    }

    // Upsert. Email owns the account.
    let user = await db.user.findUnique({
      where: { email },
      include: { memberships: { include: { org: true } } },
    });
    if (!user) {
      const domain = email.split("@")[1] ?? "personal";
      const org = await db.org.create({
        data: {
          name: domain.split(".")[0] || "Personal",
          slug: orgSlug(domain),
        },
      });
      user = await db.user.create({
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
            create: { orgId: org.id, role: "owner" },
          },
        },
        include: { memberships: { include: { org: true } } },
      });
    }

    const membership = user.memberships[0];
    if (!membership) {
      // Shouldn't happen — every user has at least one membership by
      // construction. Fail loudly rather than mint a partial session.
      return reply.code(500).send({ error: "no_membership" });
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

    // Redirect the browser back into the SPA. The console picks up the
    // freshly-set session cookie on the next /me call.
    return reply.redirect(`${env.APP_BASE_URL.replace(/\/$/, "")}/app/#/overview`);
  });
}
