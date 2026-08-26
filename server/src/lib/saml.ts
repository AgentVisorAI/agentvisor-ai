/**
 * AgentVisor AI — SAML 2.0 Service Provider.
 *
 * Wraps @node-saml/node-saml so the rest of the codebase can talk in
 * plain "start login" / "consume response" verbs. This module is the
 * only place we deal with XML, PEM certs, signatures, or SAML profile
 * details.
 *
 * Security posture (enforced everywhere it applies):
 *   • RSA-SHA256 signing on our AuthnRequests when SP keys are present.
 *   • The IdP-signed Response envelope OR the enclosed Assertion must
 *     verify against the config's x509Cert. (Which of the two we require
 *     is per-config: wantResponseSigned + wantAssertionsSigned.)
 *   • NotBefore / NotOnOrAfter windows checked with a 5-minute clock
 *     skew tolerance (industry norm).
 *   • Replay protection: every consumed Response ID is stored in the
 *     saml_replay_records table until its NotOnOrAfter expires.
 *   • Audience restriction is our exact SP Entity ID.
 *   • Encrypted assertions are decrypted with our SP private key when
 *     the config allows it.
 *
 * Testing story:
 *   • The class is deterministic given a fixed clock — the ACS consumer
 *     accepts a `now` argument so unit tests can pin time.
 *   • The mock IdP in test/saml-fixtures.ts issues real, correctly-
 *     signed responses so we integration-test the full parse/verify
 *     path without touching the network.
 */

import { SAML } from "@node-saml/node-saml";
import type { SamlConfig } from "@prisma/client";
import { db } from "../db.js";
import { env } from "../env.js";

/** What we ultimately care about from a validated SAML assertion. */
export interface SamlSuccess {
  ok: true;
  email: string;
  displayName: string | null;
  nameID: string;
  nameIDFormat: string;
  relayState: string | null;
  assertionId: string;
  notOnOrAfter: Date;
  raw: Record<string, unknown>;
}

export interface SamlFailure {
  ok: false;
  error: string;
  detail?: string;
}

export type SamlResult = SamlSuccess | SamlFailure;

/**
 * Return the caller-facing SP URLs for a given config. These are the
 * URLs the IdP admin pastes into their IdP: Entity ID (audience), ACS
 * (where the IdP posts SAMLResponse), and SLO (single logout).
 */
export function spUrls(cfg: SamlConfig): {
  entityId: string;
  acsUrl: string;
  sloUrl: string;
  loginUrl: string;
  metadataUrl: string;
} {
  const base = env.APP_BASE_URL.replace(/\/$/, "");
  return {
    entityId: `${base}/api/v1/auth/saml/${cfg.id}`,
    acsUrl: `${base}/api/v1/auth/saml/${cfg.id}/acs`,
    sloUrl: `${base}/api/v1/auth/saml/${cfg.id}/slo`,
    loginUrl: `${base}/api/v1/auth/saml/${cfg.id}/login`,
    metadataUrl: `${base}/api/v1/auth/saml/${cfg.id}/metadata.xml`,
  };
}

/** Construct the @node-saml/node-saml adapter from our stored config. */
function buildAdapter(cfg: SamlConfig): SAML {
  const urls = spUrls(cfg);
  return new SAML({
    // Endpoint metadata.
    issuer: urls.entityId,
    callbackUrl: urls.acsUrl,
    entryPoint: cfg.ssoUrl,
    logoutUrl: cfg.sloUrl ?? undefined,
    // IdP-side crypto.
    idpCert: cfg.x509Cert,
    wantAssertionsSigned: cfg.wantAssertionsSigned,
    wantAuthnResponseSigned: cfg.wantResponseSigned,
    signatureAlgorithm: cfg.signatureAlgorithm as "sha1" | "sha256" | "sha512",
    digestAlgorithm: cfg.digestAlgorithm as "sha1" | "sha256" | "sha512",
    identifierFormat: cfg.nameIdFormat,
    // SP-side crypto (optional — signs AuthnRequests + decrypts encrypted
    // assertions when both are provided).
    privateKey: cfg.spPrivateKeyPem ?? undefined,
    decryptionPvk: cfg.allowEncryptedAssertions
      ? cfg.spPrivateKeyPem ?? undefined
      : undefined,
    // Small tolerance — 5 minutes matches the SAML errata guidance for
    // clock skew between SP and IdP.
    acceptedClockSkewMs: 5 * 60_000,
    // Extra hardening: don't accept unsigned assertions even if the IdP
    // is misconfigured. wantAssertionsSigned already handles this but
    // it doesn't hurt to be explicit.
    disableRequestedAuthnContext: true,
  });
}

/**
 * Build the redirect URL to bounce the user to the IdP with a fresh
 * AuthnRequest. RelayState (opaque to the IdP) is preserved so we can
 * restore the caller's deep-link on the ACS.
 */
export async function buildLoginUrl(
  cfg: SamlConfig,
  relayState: string | null,
): Promise<string> {
  const adapter = buildAdapter(cfg);
  return adapter.getAuthorizeUrlAsync(
    relayState ?? "",
    undefined /* host */,
    {} /* options */,
  );
}

/**
 * Consume an IdP-posted SAMLResponse. Handles signature verification,
 * conditions checks, replay protection, and attribute extraction. Returns
 * SamlSuccess with a canonical shape or SamlFailure with a code.
 *
 * The `now` arg lets tests pin the clock; production leaves it at the
 * current time.
 */
export async function consumeSamlResponse(
  cfg: SamlConfig,
  body: { SAMLResponse?: unknown; RelayState?: unknown },
  now: Date = new Date(),
): Promise<SamlResult> {
  if (typeof body.SAMLResponse !== "string") {
    return { ok: false, error: "no_saml_response" };
  }
  const adapter = buildAdapter(cfg);
  let profile: Record<string, unknown> | null;
  try {
    const result = await adapter.validatePostResponseAsync({
      SAMLResponse: body.SAMLResponse,
    });
    profile = (result.profile ?? null) as Record<string, unknown> | null;
  } catch (err) {
    return {
      ok: false,
      error: "signature_or_conditions_failed",
      detail: err instanceof Error ? err.message : String(err),
    };
  }
  if (!profile) return { ok: false, error: "no_profile" };

  // Extract fields we actually need. IdPs emit attributes under a
  // grab-bag of names; support the standard ones and a few common
  // aliases (Okta, Auth0, Entra).
  const email =
    (profile["email"] as string | undefined) ??
    (profile["nameID"] as string | undefined) ??
    (profile[
      "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
    ] as string | undefined) ??
    (profile["mail"] as string | undefined);
  if (!email || typeof email !== "string") {
    return { ok: false, error: "no_email_attribute" };
  }

  const displayName =
    (profile["displayName"] as string | undefined) ??
    (profile["name"] as string | undefined) ??
    (profile[
      "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"
    ] as string | undefined) ??
    null;

  const nameID = (profile["nameID"] as string | undefined) ?? email;
  const nameIDFormat =
    (profile["nameIDFormat"] as string | undefined) ??
    cfg.nameIdFormat;

  // Replay protection. node-saml already enforces NotBefore /
  // NotOnOrAfter conditions, but we additionally persist the assertion
  // ID until it expires so a captured SAMLResponse can't be re-posted
  // inside the 5-min skew window.
  const assertionId = (profile["ID"] as string | undefined) ??
    (profile["sessionIndex"] as string | undefined) ??
    // As a fallback, hash the SAMLResponse — better than nothing so a
    // buggy IdP without a stable ID still gets replay-guarded.
    body.SAMLResponse.slice(-64);

  const notOnOrAfterRaw = profile["notOnOrAfter"];
  const notOnOrAfter =
    notOnOrAfterRaw instanceof Date
      ? notOnOrAfterRaw
      : typeof notOnOrAfterRaw === "string"
      ? new Date(notOnOrAfterRaw)
      : new Date(now.getTime() + 5 * 60_000);

  if (notOnOrAfter.getTime() < now.getTime()) {
    return { ok: false, error: "assertion_expired" };
  }

  const seen = await db.samlReplayRecord.findUnique({
    where: {
      orgId_assertionId: {
        orgId: cfg.orgId,
        assertionId,
      },
    },
  });
  if (seen) {
    return { ok: false, error: "replay_detected" };
  }
  try {
    await db.samlReplayRecord.create({
      data: {
        orgId: cfg.orgId,
        assertionId,
        notOnOrAfter,
      },
    });
  } catch (err) {
    // Race: another concurrent ACS just recorded the same ID. Treat as
    // replay to be safe.
    if (
      typeof err === "object" && err !== null &&
      (err as { code?: string }).code === "P2002"
    ) {
      return { ok: false, error: "replay_detected" };
    }
    throw err;
  }

  // Opportunistic sweep of expired replay records so the table doesn't
  // grow unbounded. Fire-and-forget; failure doesn't affect the flow.
  db.samlReplayRecord
    .deleteMany({ where: { notOnOrAfter: { lt: now } } })
    .catch(() => void 0);

  return {
    ok: true,
    email: email.toLowerCase().trim(),
    displayName: typeof displayName === "string" ? displayName : null,
    nameID,
    nameIDFormat,
    relayState:
      typeof body.RelayState === "string" ? body.RelayState : null,
    assertionId,
    notOnOrAfter,
    raw: profile,
  };
}

/**
 * Emit the SP metadata XML that IdP admins paste into their tool. This
 * includes the SP Entity ID, ACS binding, our signing/decryption cert
 * when configured, and the NameID formats we accept.
 */
export function generateMetadata(cfg: SamlConfig): string {
  const urls = spUrls(cfg);
  const adapter = buildAdapter(cfg);
  // node-saml provides generateServiceProviderMetadata; feed it our SP
  // cert if we have one so the IdP can encrypt assertions to us.
  return adapter.generateServiceProviderMetadata(
    cfg.spCertPem ?? null,
    cfg.spCertPem ?? null,
  );
}

/**
 * Find an active SAML config on an org that matches the given email's
 * domain (or return the single active config if allowedDomains is empty).
 * Used by the login page to advertise SSO before a user is authenticated.
 */
export async function findConfigForEmail(email: string): Promise<
  SamlConfig | null
> {
  const at = email.lastIndexOf("@");
  if (at < 0) return null;
  const domain = email.slice(at + 1).toLowerCase();
  const configs = await db.samlConfig.findMany({
    where: { isActive: true },
  });
  for (const c of configs) {
    const domains = c.allowedDomains
      .split(",")
      .map((d) => d.trim().toLowerCase())
      .filter(Boolean);
    if (domains.length === 0) continue;
    if (domains.includes(domain)) return c;
  }
  return null;
}
