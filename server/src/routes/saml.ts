/**
 * SAML 2.0 SSO endpoints.
 *
 * Public (no-auth) endpoints:
 *   • GET  /api/v1/auth/saml/:configId/metadata.xml
 *   • GET  /api/v1/auth/saml/:configId/login   — SP-initiated: redirect to IdP
 *   • POST /api/v1/auth/saml/:configId/acs     — Assertion Consumer
 *   • POST /api/v1/auth/saml/:configId/slo     — Single Logout (best-effort)
 *
 * Owner/admin CRUD (session-cookie protected):
 *   • GET    /api/v1/auth/saml                 — list configs on the caller's org
 *   • POST   /api/v1/auth/saml                 — create a config
 *   • PATCH  /api/v1/auth/saml/:configId       — update
 *   • DELETE /api/v1/auth/saml/:configId       — delete
 *   • POST   /api/v1/auth/saml/:configId/keypair  — regenerate SP keypair
 *
 * All the crypto lives in ../lib/saml.ts. This file is the routing +
 * plumbing layer only.
 */

import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { generateKeyPairSync, createHash } from "node:crypto";
import { db } from "../db.js";
import { env } from "../env.js";
import { writeAudit } from "../lib/audit.js";
import {
  SESSION_COOKIE_OPTS,
  mintSession,
} from "../lib/auth.js";
import { requireSession } from "../lib/session-middleware.js";
import {
  buildLoginUrl,
  consumeSamlResponse,
  findConfigForEmail,
  generateMetadata,
  isSha1Legacy,
  spUrls,
} from "../lib/saml.js";

/**
 * Public-facing shape of a SamlConfig. Never expose the SP private key
 * to the console — only ops with DB access can see it (or use the
 * regenerate endpoint to get a fresh one).
 */
function serializeConfig(c: {
  id: string;
  orgId: string;
  displayName: string;
  ssoUrl: string;
  sloUrl: string | null;
  entityIdIdp: string;
  x509Cert: string;
  wantAssertionsSigned: boolean;
  wantResponseSigned: boolean;
  allowEncryptedAssertions: boolean;
  signatureAlgorithm: string;
  digestAlgorithm: string;
  nameIdFormat: string;
  jitEnabled: boolean;
  jitDefaultRole: string;
  allowedDomains: string;
  spCertPem: string | null;
  isActive: boolean;
  createdAt: Date;
  updatedAt: Date;
}) {
  const urls = spUrls(c as never);
  return {
    id: c.id,
    displayName: c.displayName,
    ssoUrl: c.ssoUrl,
    sloUrl: c.sloUrl,
    entityIdIdp: c.entityIdIdp,
    // Never send the private key. Cert is safe (it's public info).
    spCertPem: c.spCertPem,
    hasSpKeypair: !!c.spCertPem,
    wantAssertionsSigned: c.wantAssertionsSigned,
    wantResponseSigned: c.wantResponseSigned,
    allowEncryptedAssertions: c.allowEncryptedAssertions,
    signatureAlgorithm: c.signatureAlgorithm,
    digestAlgorithm: c.digestAlgorithm,
    nameIdFormat: c.nameIdFormat,
    jitEnabled: c.jitEnabled,
    jitDefaultRole: c.jitDefaultRole,
    allowedDomains: c.allowedDomains,
    isActive: c.isActive,
    // What the IdP admin needs:
    spEntityId: urls.entityId,
    spAcsUrl: urls.acsUrl,
    spSloUrl: urls.sloUrl,
    spLoginUrl: urls.loginUrl,
    spMetadataUrl: urls.metadataUrl,
    // Cert fingerprint for a quick "yes this is the right cert" check
    // in the console — sha256 of the PEM's DER form.
    x509CertFingerprint: fingerprintPem(c.x509Cert),
    createdAt: c.createdAt,
    updatedAt: c.updatedAt,
  };
}

function fingerprintPem(pem: string): string {
  const body = pem
    .replace(/-----BEGIN[^-]+-----/g, "")
    .replace(/-----END[^-]+-----/g, "")
    .replace(/\s+/g, "");
  try {
    const der = Buffer.from(body, "base64");
    return createHash("sha256")
      .update(der)
      .digest("hex")
      .match(/../g)!
      .join(":");
  } catch {
    return "";
  }
}

// ---------- Zod validation ---------------------------------------------

const createConfigSchema = z.object({
  displayName: z.string().min(1).max(80).trim(),
  ssoUrl: z.string().url().max(2048),
  sloUrl: z.string().url().max(2048).optional().nullable(),
  entityIdIdp: z.string().min(1).max(2048),
  x509Cert: z.string().min(1).max(16_000),
  wantAssertionsSigned: z.boolean().default(true),
  wantResponseSigned: z.boolean().default(false),
  allowEncryptedAssertions: z.boolean().default(true),
  // R88 F5: dropped "sha1". SHA-1 is chosen-prefix collision-broken
  // since Leurent/Peyrin 2020 (SHAmbles — ~$45k of cloud compute).
  // With SHA-1 as the digest, an attacker with access to a legitimate
  // signed assertion (or with SAML config write access, e.g. via a
  // phished owner credential) can forge a colliding assertion that
  // the XMLDSig verifier accepts as valid. NIST disallowed SHA-1 for
  // digital signatures in 2013; all modern IdPs (Okta, Entra, Auth0)
  // default to SHA-256. The self-service SHA-1 toggle was a silent
  // downgrade knob with no operator warning. If a legacy IdP truly
  // requires SHA-1, the fix is an env-gated allow-list (not a per-org
  // schema field) so security posture is a deployment decision, not
  // a form-field.
  signatureAlgorithm: z.enum(["sha256", "sha512"]).default("sha256"),
  digestAlgorithm: z.enum(["sha256", "sha512"]).default("sha256"),
  nameIdFormat: z.string().max(256).default(
    "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
  ),
  jitEnabled: z.boolean().default(true),
  jitDefaultRole: z.enum(["member", "admin"]).default("member"),
  allowedDomains: z.string().max(2048).default(""),
});
const updateConfigSchema = createConfigSchema.partial().extend({
  isActive: z.boolean().optional(),
});

// -----------------------------------------------------------------------

export async function samlRoutes(app: FastifyInstance): Promise<void> {
  // =========================================================================
  // PUBLIC ROUTES — no session required. Anyone can start SAML.
  // =========================================================================

  app.get<{ Params: { configId: string } }>(
    "/:configId/metadata.xml",
    async (req, reply) => {
      const cfg = await db.samlConfig.findUnique({
        where: { id: req.params.configId },
      });
      if (!cfg || !cfg.isActive) {
        return reply.code(404).send({ error: "config_not_found" });
      }
      // R114 F1: treat legacy sha1 configs as inactive at the route
      // layer so the IdP admin gets a clean 410 with a specific
      // slug instead of a generic 500 from buildAdapter's throw
      // propagating uncaught. Fixes the code/comment mismatch —
      // the R88 F5 comment says 'treat any surviving sha1 config
      // as inactive' but the throw was routed as a 500.
      if (isSha1Legacy(cfg)) {
        return reply.code(410).send({ error: "saml_config_uses_sha1_reject" });
      }
      reply.type("application/xml");
      return reply.send(generateMetadata(cfg));
    },
  );

  app.get<{
    Params: { configId: string };
    Querystring: { RelayState?: string };
  }>("/:configId/login", {
    // R133 F1: perIp(30, 60_000) per-route rate limit. Direct
    // SAML analog to the /oauth/:provider/start bucket added in
    // R132 F2. Strictly worse amplification than the OAuth
    // sibling: per hit does findUnique + buildAdapter (no
    // caching) + getAuthorizeUrlAsync, which RSA-signs the
    // AuthnRequest XML when cfg.spPrivateKeyPem is set (common;
    // ADFS/Okta require signed AuthnRequests) — ~1-2 ms of CPU
    // vs oauth /start's microseconds of SHA-256 PKCE. A lone
    // attacker looping this on a corp NAT eats the 300/min/IP
    // global quota AND burns real CPU. 30/min/IP matches
    // /discover (R131 F3) and /oauth/start (R132 F2).
    // Sibling /:configId/acs stays on the global bucket — the
    // SAMLResponse signature check fast-fails on malformed
    // input, same rationale as /oauth/callback.
    config: {
      rateLimit: {
        max: 30,
        timeWindow: 60_000,
        keyGenerator: (req: { ip: string }) => `ip:${req.ip}`,
      },
    },
  }, async (req, reply) => {
    // R123 F1: kickoff endpoint is a top-level browser navigation
    // (docs/app/app.js:1063 does window.location.assign(loginUrl)).
    // R122 F2 fixed the ACS side but missed this — same dead-end
    // raw-JSON class. Redirect to the SPA banner so admin misconfigs
    // (deactivated config, SHA-1 legacy) surface as friendly text.
    // R132 F4: encodeURIComponent the slug — the acs handler
    // below interpolates `saml_assertion_${result.error}` where
    // result.error is caller-controlled through the SAMLResponse.
    // Consistent shape across all errRedirect helpers.
    const errRedirect = (slug: string) =>
      reply.redirect(
        `${env.APP_BASE_URL.replace(/\/$/, "")}/app/#/login?err=${encodeURIComponent(slug)}`,
      );
    const cfg = await db.samlConfig.findUnique({
      where: { id: req.params.configId },
    });
    if (!cfg || !cfg.isActive) {
      return errRedirect("saml_config_not_found");
    }
    // R114 F1: same sha1-legacy gate as /metadata.xml.
    if (isSha1Legacy(cfg)) {
      return errRedirect("saml_config_uses_sha1_reject");
    }
    const relayState = typeof req.query.RelayState === "string"
      ? req.query.RelayState.slice(0, 1024)
      : null;
    const url = await buildLoginUrl(cfg, relayState);
    return reply.redirect(url);
  });

  app.post<{ Params: { configId: string } }>(
    "/:configId/acs",
    async (req, reply) => {
      // R122 F2: SAML ACS is a top-level browser navigation (the
      // IdP autosubmits SAMLResponse via HTML form to this URL
      // with `_top` target). Success path already reply.redirects
      // (line 367); prior shape returned bare JSON on every
      // error exit, dead-ending the user in an otherwise-blank
      // tab with no CTA. Same UX class R121 F2 closed on
      // /api/v1/auth/oauth/callback. Redirect to the auth screen
      // with a slug so the SPA can render a friendly banner
      // via .auth-note. Machine consumers of /acs are always
      // browsers (SAML AuthnResponse posters — no API clients
      // hit /acs) so JSON→redirect is a safe transition.
      // R132 F4: encodeURIComponent the slug —
      // `saml_assertion_${result.error}` below interpolates a
      // caller-controlled value from consumeSamlResponse. Without
      // the encoder, a hostile IdP could inject `#`/`&`/`?` into
      // the slug and split the redirect into arbitrary hash
      // fragments.
      const errRedirect = (slug: string) =>
        reply.redirect(
          `${env.APP_BASE_URL.replace(/\/$/, "")}/app/#/login?err=${encodeURIComponent(slug)}`,
        );
      const cfg = await db.samlConfig.findUnique({
        where: { id: req.params.configId },
      });
      if (!cfg || !cfg.isActive) {
        return errRedirect("saml_config_not_found");
      }
      // R114 F1: same sha1-legacy gate — the IdP gets a specific
      // 410 slug it can surface to its admin instead of a bare
      // 500 with no forensic signal. R122 F2: redirect for
      // browser-UX consistency; the log line still preserves
      // the forensic signal.
      if (isSha1Legacy(cfg)) {
        req.log.warn(
          { orgId: cfg.orgId, configId: cfg.id },
          "saml_acs_rejected_sha1_legacy",
        );
        return errRedirect("saml_config_uses_sha1_reject");
      }
      const result = await consumeSamlResponse(cfg, req.body as never);
      if (!result.ok) {
        req.log.warn(
          { orgId: cfg.orgId, configId: cfg.id, error: result.error },
          "saml_acs_rejected",
        );
        return errRedirect(`saml_assertion_${result.error}`);
      }

      // Resolve or JIT-provision the user.
      let user = await db.user.findUnique({
        where: { email: result.email },
        include: { memberships: true },
      });

      // Membership check: is this user already in this org?
      let membership = user?.memberships.find((m) => m.orgId === cfg.orgId);
      if (!membership) {
        if (!cfg.jitEnabled) {
          return errRedirect("saml_jit_disabled");
        }
        // R76 HIGH #1: refuse JIT attach-across-orgs. Prior
        // shape allowed the SAML ACS to silently create a
        // membership in `cfg.orgId` for a user record that
        // ALREADY belonged to some other tenant, driven only
        // by the caller-asserted email. An owner/admin of ANY
        // tenant could then post a signed AuthnResponse
        // asserting `email = victim@othercorp.com` and pull
        // the victim's identity into their org — cross-tenant
        // identity contamination. JIT must ONLY create fresh
        // users; cross-org linking of an existing account has
        // to go through an out-of-band claim/challenge, not a
        // silent server-side attach. Refuse loudly so the
        // operator sees the misconfig or attack in the audit
        // log.
        if (user) {
          req.log.warn(
            {
              orgId: cfg.orgId,
              configId: cfg.id,
              existingUserId: user.id,
              assertedEmail: result.email,
            },
            "saml_jit_refused_existing_user_in_other_org",
          );
          return errRedirect("saml_user_exists_in_other_org");
        }
        // Domain check: only allow provisioning within the configured
        // domains (defense against a misconfigured IdP asserting a
        // random email).
        const at = result.email.lastIndexOf("@");
        const domain = at >= 0 ? result.email.slice(at + 1).toLowerCase() : "";
        const domains = cfg.allowedDomains
          .split(",")
          .map((d) => d.trim().toLowerCase())
          .filter(Boolean);
        // R76 HIGH #1 (companion): refuse an empty allowlist.
        // Prior shape returned `ok` when `domains.length === 0`,
        // effectively opting out of the domain guard when the
        // operator left the field blank (schema default `""`).
        // An empty allowlist is almost always a misconfig; make
        // it fail-closed so JIT provisioning cannot be enabled
        // without an explicit domain scope.
        if (domains.length === 0) {
          req.log.warn(
            { orgId: cfg.orgId, configId: cfg.id },
            "saml_jit_refused_empty_domain_allowlist",
          );
          return errRedirect("saml_domain_allowlist_required");
        }
        if (!domains.includes(domain)) {
          return errRedirect("saml_domain_not_allowed");
        }

        // Create the user + membership atomically.
        const provisioned = await db.$transaction(async (tx) => {
          const u = await tx.user.create({
                data: {
                  email: result.email,
                  // A JIT user has no password. Login endpoint uses the
                  // dummy hash on lookup miss so this doesn't create a
                  // timing side channel — but the row still needs a
                  // valid argon2 string. Generate a random one that no
                  // human will ever type.
                  passwordHash: await import(
                    "@node-rs/argon2"
                  ).then(({ hash }) =>
                    hash(
                      crypto.randomUUID() + crypto.randomUUID(),
                      { memoryCost: 19_456, timeCost: 2, parallelism: 1 },
                    ),
                  ),
                  displayName: result.displayName,
                },
              });
          const m = await tx.membership.create({
            data: {
              userId: u.id,
              orgId: cfg.orgId,
              role: cfg.jitDefaultRole,
            },
          });
          return { user: u, membership: m };
        });
        user = { ...provisioned.user, memberships: [provisioned.membership] };
        membership = provisioned.membership;
      }

      // Everything lines up. Mint an av_session JWT.
      const token = await mintSession({
        sub: user!.id,
        orgId: cfg.orgId,
        membershipRole: membership.role as "owner" | "admin" | "member",
      });
      reply.setCookie(env.SESSION_COOKIE_NAME, token, SESSION_COOKIE_OPTS);
      writeAudit(
        {
          orgId: cfg.orgId,
          event: "saml.signin",
          actorId: user!.id,
          actorEmail: user!.email,
          target: cfg.displayName,
          note: "SAML sign-in via " + cfg.displayName,
          metadata: {
            samlConfigId: cfg.id,
            nameIDFormat: result.nameIDFormat,
            assertionId: result.assertionId,
          },
          req,
        },
        req.log,
      );

      // RelayState round-trip — restore the caller's deep link.
      const relay = result.relayState;
      const base = env.APP_BASE_URL.replace(/\/$/, "");
      // Only allow app-hash redirects (safe against open-redirect).
      let dest = `${base}/app/`;
      if (relay && relay.startsWith("#/")) dest = `${base}/app/${relay}`;
      else if (relay && relay.startsWith("/app/#/")) dest = `${base}${relay}`;
      return reply.redirect(dest);
    },
  );

  app.post<{ Params: { configId: string } }>(
    "/:configId/slo",
    async (req, reply) => {
      // R88 F2/F4: harden the SLO endpoint.
      //
      // Prior shape did NO validation: no session cookie check,
      // no configId lookup, no LogoutRequest signature verify. Any
      // origin could POST here (SLO was CSRF-exempt) and force
      // `Set-Cookie: av_session=; Max-Age=0` on any authenticated
      // visitor — a session-DoS primitive. Combined with the fact
      // that the handler previously didn't even validate the
      // configId param (destructured as `_req`), an attacker
      // guessing any UUID could reach the cookie-clear.
      //
      // Defense in depth (without shipping a full SAML
      // LogoutRequest signature parser this round):
      //   1. Remove /slo from the CSRF exemption in
      //      index.ts (done alongside this fix) so only same-
      //      origin POSTs reach the handler.
      //   2. Require a valid session cookie.
      //   3. Require a real, active configId belonging to the
      //      caller's org — a caller can't log themselves out
      //      via another org's SLO endpoint.
      // A follow-up round should parse the SAMLRequest form
      // field, verify the signature against cfg.x509Cert, and
      // match the NameID to the session user before clearing —
      // but the CSRF+session+configId gate here already closes
      // the anonymous session-DoS primitive.
      const claims = requireSession(req, reply);
      if (!claims) return;
      // R105 F5: reject API-key sessions up front. SLO is a
      // cookie-session-only ceremony (there's no cookie to
      // clear on an API-key request). Prior shape let the
      // handler continue and then swallowed the resulting
      // P2025 (user id 'apikey:<id>' doesn't exist in User)
      // in the .catch() below, giving the caller a
      // false-successful 200 while nothing was actually
      // revoked. Match the same guard stream.ts already
      // has.
      if (claims.sub.startsWith("apikey:")) {
        return reply.code(400).send({ error: "cookie_session_required" });
      }
      const cfg = await db.samlConfig.findFirst({
        where: {
          id: req.params.configId,
          orgId: claims.orgId,
          isActive: true,
        },
      });
      if (!cfg) return reply.code(404).send({ error: "not_found" });
      // R103 F2: bump sessionRevokedAt so any captured JWT
      // cookie for this user is immediately dead. Prior SLO
      // shape only cleared the cookie in the CURRENT browser's
      // response — a JWT captured from that user's browser
      // (XSS on a compromised subdomain, session-fixation, or
      // a stolen device before SLO) remained cryptographically
      // valid for the whole 7-day exp, so the attacker held
      // the user's session for a week after SLO. Sibling of
      // /logout's own sessionRevokedAt bump (auth.ts) which
      // R79 established. Catch is defensive — a user row that
      // was already removed shouldn't fail the SLO response.
      await db.user
        .update({
          where: { id: claims.sub },
          data: { sessionRevokedAt: new Date() },
        })
        .catch((err) => {
          req.log.warn(
            { err, userId: claims.sub },
            "saml_slo_session_revoke_failed",
          );
        });
      writeAudit(
        {
          orgId: claims.orgId,
          event: "auth.saml.slo",
          actorId: claims.sub,
          target: cfg.id,
          metadata: { configId: cfg.id },
          req,
        },
        req.log,
      );
      reply.setCookie(env.SESSION_COOKIE_NAME, "", {
        ...SESSION_COOKIE_OPTS,
        maxAge: 0,
      });
      return reply.send({ ok: true });
    },
  );

  // Endpoint the SPA calls before login to see if this email's org has
  // an SSO config it can bounce through. Anonymous so it works pre-auth.
  app.get<{ Querystring: { email?: string } }>(
    "/discover",
    {
      // R131 F3: rate-limit per IP + zod-validate the email so a
      // 64 KB query string doesn't materialize + lowercase + hit
      // every active SamlConfig org-wide per request. Not a data
      // leak (response is at most { configId }, and IdP-initiated
      // flows already expose that mapping publicly), but this
      // was the only anonymous unvalidated GET in the auth tree.
      // Match the /webauthn/authenticate/challenge cadence:
      // 30/min/IP is generous for a pre-login "does my domain
      // have SSO?" check.
      config: {
        rateLimit: {
          max: 30,
          timeWindow: 60_000,
          keyGenerator: (req: { ip: string }) => `ip:${req.ip}`,
        },
      },
    },
    async (req, reply) => {
      const q = z
        .object({ email: z.string().min(3).max(320) })
        .safeParse(req.query);
      if (!q.success) return reply.send({ ssoConfig: null });
      const cfg = await findConfigForEmail(q.data.email.trim().toLowerCase());
      if (!cfg) return reply.send({ ssoConfig: null });
      const urls = spUrls(cfg);
      return reply.send({
        ssoConfig: {
          id: cfg.id,
          displayName: cfg.displayName,
          loginUrl: urls.loginUrl,
        },
      });
    },
  );

  // =========================================================================
  // AUTHENTICATED ROUTES — settings CRUD. Owner/admin only.
  // =========================================================================

  app.get("/", async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    // R108 F1: gate on non-member matching the CRUD siblings
    // (POST, PATCH, DELETE, /:configId/keypair all already
    // reject membershipRole === 'member'). Module docblock:
    // 'Owner/admin CRUD (session-cookie protected)'. The list
    // response includes IdP ssoUrl/sloUrl/entityIdIdp,
    // x509CertFingerprint, jitEnabled/jitDefaultRole,
    // allowedDomains, wantAssertionsSigned, spCertPem,
    // signatureAlgorithm — recon material for targeting or
    // for correlating a cert fingerprint to a known
    // compromised IdP tenant. Same class R89 F3 closed for
    // webhooks list.
    if (claims.membershipRole === "member") {
      return reply.code(403).send({ error: "forbidden" });
    }
    const configs = await db.samlConfig.findMany({
      where: { orgId: claims.orgId },
      orderBy: { createdAt: "asc" },
    });
    return reply.send({ configs: configs.map(serializeConfig) });
  });

  app.post("/", async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    if (claims.membershipRole === "member") {
      return reply.code(403).send({ error: "forbidden" });
    }
    const body = createConfigSchema.safeParse(req.body);
    if (!body.success) {
      return reply.code(400).send({ error: "invalid_input" });
    }
    // R76 review Q6 (landed R77): reject `jitEnabled=true` with
    // an empty `allowedDomains` at CONFIG WRITE TIME. The R76
    // ACS-time guard fails-closed at login time with 403
    // `domain_allowlist_required_for_jit` — but the misconfig
    // persists silently in the DB, and operators only see the
    // problem when users can't log in. Fail early so the operator
    // fixes the config at the point of change.
    if (body.data.jitEnabled && body.data.allowedDomains.trim() === "") {
      return reply.code(400).send({
        error: "invalid_input",
        detail:
          "allowedDomains is required (non-empty comma-separated list) when jitEnabled=true — an empty allowlist would let a signed AuthnResponse with any asserted email JIT-create a user in this org",
      });
    }
    try {
      const cfg = await db.samlConfig.create({
        data: {
          orgId: claims.orgId,
          ...body.data,
          sloUrl: body.data.sloUrl ?? null,
        },
      });
      writeAudit(
        {
          orgId: claims.orgId,
          event: "saml.config_created",
          actorId: claims.sub,
          target: cfg.displayName,
          metadata: {
            samlConfigId: cfg.id,
            entityIdIdp: cfg.entityIdIdp,
            allowedDomains: cfg.allowedDomains,
          },
          req,
        },
        req.log,
      );
      return reply.code(201).send({ config: serializeConfig(cfg) });
    } catch (err) {
      if (
        typeof err === "object" && err !== null &&
        (err as { code?: string }).code === "P2002"
      ) {
        return reply.code(409).send({ error: "displayname_in_use" });
      }
      throw err;
    }
  });

  app.patch<{ Params: { configId: string } }>(
    "/:configId",
    async (req, reply) => {
      const claims = requireSession(req, reply);
      if (!claims) return;
      if (claims.membershipRole === "member") {
        return reply.code(403).send({ error: "forbidden" });
      }
      const body = updateConfigSchema.safeParse(req.body);
      if (!body.success) {
        return reply.code(400).send({ error: "invalid_input" });
      }
      const existing = await db.samlConfig.findFirst({
        where: { id: req.params.configId, orgId: claims.orgId },
      });
      if (!existing) return reply.code(404).send({ error: "not_found" });
      // R76 review Q6 (landed R77): same config-write-time guard
      // as POST above, but check the RESULTING config after the
      // partial patch — a caller could send just
      // `{ allowedDomains: "" }` on a config that already has
      // `jitEnabled=true`, or `{ jitEnabled: true }` on one with
      // an empty allowlist.
      const resultingJitEnabled =
        body.data.jitEnabled ?? existing.jitEnabled;
      const resultingDomains =
        body.data.allowedDomains ?? existing.allowedDomains;
      if (resultingJitEnabled && resultingDomains.trim() === "") {
        return reply.code(400).send({
          error: "invalid_input",
          detail:
            "allowedDomains is required (non-empty comma-separated list) when jitEnabled=true — an empty allowlist would let a signed AuthnResponse with any asserted email JIT-create a user in this org",
        });
      }
      const cfg = await db.samlConfig.update({
        where: { id: existing.id },
        data: {
          ...body.data,
          sloUrl:
            body.data.sloUrl === undefined
              ? undefined
              : body.data.sloUrl ?? null,
        },
      });
      writeAudit(
        {
          orgId: claims.orgId,
          event: "saml.config_updated",
          actorId: claims.sub,
          target: cfg.displayName,
          metadata: {
            samlConfigId: cfg.id,
            changed: Object.keys(body.data),
          },
          req,
        },
        req.log,
      );
      return reply.send({ config: serializeConfig(cfg) });
    },
  );

  app.delete<{ Params: { configId: string } }>(
    "/:configId",
    async (req, reply) => {
      const claims = requireSession(req, reply);
      if (!claims) return;
      if (claims.membershipRole === "member") {
        return reply.code(403).send({ error: "forbidden" });
      }
      const existing = await db.samlConfig.findFirst({
        where: { id: req.params.configId, orgId: claims.orgId },
      });
      if (!existing) return reply.code(404).send({ error: "not_found" });
      await db.samlConfig.delete({ where: { id: existing.id } });
      writeAudit(
        {
          orgId: claims.orgId,
          event: "saml.config_deleted",
          actorId: claims.sub,
          target: existing.displayName,
          metadata: { samlConfigId: existing.id },
          req,
        },
        req.log,
      );
      return reply.code(204).send();
    },
  );

  // Generate a fresh SP RSA-2048 keypair. Used when the operator wants
  // to enable AuthnRequest signing / assertion encryption after the
  // fact, or to rotate. Only the cert is returned — the key stays in
  // the DB and never leaves the server.
  app.post<{ Params: { configId: string } }>(
    "/:configId/keypair",
    async (req, reply) => {
      const claims = requireSession(req, reply);
      if (!claims) return;
      if (claims.membershipRole !== "owner") {
        return reply.code(403).send({ error: "owner_only" });
      }
      const existing = await db.samlConfig.findFirst({
        where: { id: req.params.configId, orgId: claims.orgId },
      });
      if (!existing) return reply.code(404).send({ error: "not_found" });

      const { privateKey, publicKey } = generateKeyPairSync("rsa", {
        modulusLength: 2048,
      });
      const privatePem = privateKey.export({
        type: "pkcs8",
        format: "pem",
      }) as string;
      // For AuthnRequest signing @node-saml just needs the private key.
      // For metadata + encryption they need an X.509 self-signed cert
      // wrapping the public key. Build a self-signed cert here.
      const { generateSelfSignedCert } = await import(
        "../lib/saml-cert.js"
      );
      const certPem = await generateSelfSignedCert(privateKey, publicKey, {
        subjectCN: `AgentVisor SP for ${existing.id}`,
        days: 365 * 5,
      });

      const cfg = await db.samlConfig.update({
        where: { id: existing.id },
        data: {
          spPrivateKeyPem: privatePem,
          spCertPem: certPem,
        },
      });
      // R134 F1: rotating spPrivateKeyPem + spCertPem invalidates
      // every pending signed AuthnRequest and forces IdP-side
      // metadata re-upload — a stolen owner cookie can silently
      // DoS SSO for the whole org or stage a downgrade against a
      // future assertion-encryption push. This was the only
      // mutating route in saml.ts without a writeAudit() call
      // (sibling POST / at 618, PATCH /:configId at 688, DELETE
      // /:configId at 719 all audit correctly). Mechanical
      // omission of the same 12-line block; add it here so
      // incident forensics has the breadcrumb. Direct parity
      // with deployments.ts:143 (deployment.token_rotated) and
      // webhooks.ts:425 (webhook.secret_rotated).
      writeAudit(
        {
          orgId: claims.orgId,
          event: "saml.keypair_rotated",
          actorId: claims.sub,
          target: existing.displayName,
          metadata: { samlConfigId: existing.id },
          req,
        },
        req.log,
      );
      return reply.send({
        config: serializeConfig(cfg),
        spCertPem: certPem,
      });
    },
  );
}
