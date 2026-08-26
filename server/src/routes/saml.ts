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
  signatureAlgorithm: z.enum(["sha1", "sha256", "sha512"]).default("sha256"),
  digestAlgorithm: z.enum(["sha1", "sha256", "sha512"]).default("sha256"),
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
      reply.type("application/xml");
      return reply.send(generateMetadata(cfg));
    },
  );

  app.get<{
    Params: { configId: string };
    Querystring: { RelayState?: string };
  }>("/:configId/login", async (req, reply) => {
    const cfg = await db.samlConfig.findUnique({
      where: { id: req.params.configId },
    });
    if (!cfg || !cfg.isActive) {
      return reply.code(404).send({ error: "config_not_found" });
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
      const cfg = await db.samlConfig.findUnique({
        where: { id: req.params.configId },
      });
      if (!cfg || !cfg.isActive) {
        return reply.code(404).send({ error: "config_not_found" });
      }
      const result = await consumeSamlResponse(cfg, req.body as never);
      if (!result.ok) {
        req.log.warn(
          { orgId: cfg.orgId, configId: cfg.id, error: result.error },
          "saml_acs_rejected",
        );
        return reply.code(400).send({ error: result.error });
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
          return reply.code(403).send({ error: "jit_disabled" });
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
        if (domains.length > 0 && !domains.includes(domain)) {
          return reply.code(403).send({ error: "domain_not_allowed" });
        }

        // Create the user + membership atomically.
        const provisioned = await db.$transaction(async (tx) => {
          const u = user
            ? user
            : await tx.user.create({
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
    async (_req, reply) => {
      // Minimal SLO acknowledgement — we accept the LogoutRequest,
      // don't try to re-post to every other SP the user might be
      // signed into (out of scope). Clear our cookie and return 200.
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
    async (req, reply) => {
      if (typeof req.query.email !== "string") {
        return reply.send({ ssoConfig: null });
      }
      const cfg = await findConfigForEmail(req.query.email);
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
    try {
      const cfg = await db.samlConfig.create({
        data: {
          orgId: claims.orgId,
          ...body.data,
          sloUrl: body.data.sloUrl ?? null,
        },
      });
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
      return reply.send({
        config: serializeConfig(cfg),
        spCertPem: certPem,
      });
    },
  );
}
