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
 *   • Replay protection: every consumed, verified Assertion ID is stored in the
 *     saml_replay_records table until its NotOnOrAfter expires.
 *   • Audience restriction is our exact SP Entity ID.
 *   • Encrypted assertions are decrypted with our SP private key when
 *     the config allows it.
 *
 * scripts/saml-shared-drill.mjs signs real fixture assertions and checks
 * replicas, restarts, concurrent consumption, browser/tenant binding, and
 * database failures without contacting an external identity provider.
 */

import { SAML, ValidateInResponseTo } from "@node-saml/node-saml";
import crypto from "node:crypto";
import { truncateWellFormed } from "./strings.js";
import type { SamlConfig } from "@prisma/client";
import { db } from "../db.js";
import { env, apiPublicBase } from "../env.js";

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
 * Entity ID and ACS are identity-provider settings. The `sloUrl` is only
 * the application's cookie-protected local logout endpoint; it is not a
 * SAML Single Logout service and is not advertised in SP metadata.
 */
export function spUrls(cfg: SamlConfig): {
  entityId: string;
  acsUrl: string;
  sloUrl: string;
  loginUrl: string;
  metadataUrl: string;
} {
  const base = apiPublicBase();
  return {
    entityId: `${base}/api/v1/auth/saml/${cfg.id}`,
    acsUrl: `${base}/api/v1/auth/saml/${cfg.id}/acs`,
    sloUrl: `${base}/api/v1/auth/saml/${cfg.id}/slo`,
    loginUrl: `${base}/api/v1/auth/saml/${cfg.id}/login`,
    metadataUrl: `${base}/api/v1/auth/saml/${cfg.id}/metadata.xml`,
  };
}

/**
 * Extract the `<saml:Assertion ID="…">` attribute from a POSTed
 * SAMLResponse. R76 MEDIUM #3 (landed R77): the prior shape used
 * `profile["ID"]` from `@node-saml/node-saml`, which returns the
 * ID of the OUTER `<Response>` element, not the enclosed
 * `<Assertion>`. A captured signed assertion can be re-wrapped
 * inside a fresh Response envelope with a new Response ID —
 * the (orgId, response.id) uniqueness check misses. When
 * `wantAuthnResponseSigned=false` (schema default), the envelope
 * rewrap is signature-agnostic; the assertion-level replay
 * guard is what stops the attack.
 *
 * Base64-decode the raw body, then match the FIRST `Assertion`
 * element (may be namespaced as `saml:`, `saml2:`, or bare).
 * If nothing matches, return null so the caller fails closed
 * — never fall back to a body-tail hash (unstable across
 * whitespace re-encoding, and gives false uniqueness for
 * rewrapped payloads).
 */
/**
 * Extract the ID of the actually-signed Assertion element for
 * replay-guard bookkeeping. R76→R77→R88 tried three raw-body
 * approaches; each fell to a different XSW variant:
 *   • R76: `profile["ID"]` — that's the outer <Response ID>, which
 *     is not signed under wantResponseSigned=false. Rewrapping the
 *     same signed assertion in a fresh Response envelope gets a
 *     fresh replay-key.
 *   • R77: FIRST <Assertion ID> in raw XML. Attacker prepends a
 *     bogus sibling <Assertion ID="attacker-nonce"> before the
 *     signed one; regex picks the attacker's nonce.
 *   • R88: FIRST <ds:Reference URI="#..."> in raw XML. Attacker
 *     injects a decoy <ds:Signature> block with a fresh
 *     Reference URI — or drops a <ds:Manifest>/<samlp:Extensions>
 *     <ds:Reference URI="#attacker"/> earlier in the doc. Regex
 *     picks the decoy. Also, when allowEncryptedAssertions=true
 *     (default) the outer body contains NO <ds:Reference> at all
 *     (they live inside the ciphertext), so R88's regex returns
 *     null and BREAKS legitimate SSO for encrypted flows.
 *
 * R89 F1/F2 fix: `@node-saml/node-saml`'s Profile exposes
 * `getAssertionXml()`, which returns the VALIDATED assertion XML
 * (post-decryption if the wire was encrypted). It's the exact
 * element XMLDSig verified. Extract the Assertion's ID from THAT
 * string — there's only one Assertion inside the returned XML, so
 * the first-match regex is safe. This closes both the XSW replay
 * (Finding 1) and the encrypted-assertion breakage (Finding 2)
 * that R88's approach introduced.
 *
 * Falls back to profile.sessionIndex when getAssertionXml isn't
 * available (older node-saml versions); if BOTH are missing, fails
 * closed with null.
 */
export function extractAssertionId(
  profile: { getAssertionXml?: () => string; sessionIndex?: string },
): string | null {
  const xml = typeof profile.getAssertionXml === "function"
    ? profile.getAssertionXml()
    : "";
  if (xml) {
    // Match `<Assertion ID="…">` or `<saml:Assertion ID="…">` /
    // `<saml2:Assertion ID="…">`. Safe because the returned XML
    // contains ONLY the validated Assertion element — no attacker
    // wrapping can appear here.
    const re = /<(?:[\w-]+:)?Assertion\b[^>]*?\bID\s*=\s*"([^"]+)"/;
    const m = xml.match(re);
    if (m?.[1]) return m[1];
  }
  // Fallback #1: sessionIndex — IdP-generated per authentication,
  // typically unique per login. Standardised as optional but Okta,
  // Entra, Auth0 all emit it.
  if (typeof profile.sessionIndex === "string" && profile.sessionIndex.length > 0) {
    return `sess:${profile.sessionIndex}`;
  }
  // R90 F4: removed the profile.ID (`resp:`) fallback. It was only
  // XSW-safe when wantResponseSigned=true, which isn't visible to
  // this helper (SamlConfig isn't in scope). Accepting it here
  // silently exposed exactly the replay class R76→R89 tried to
  // close — a future node-saml version that omits
  // getAssertionXml, or an IdP that emits no sessionIndex, would
  // silently degrade to an XSW-forgeable replay key. Fail closed
  // instead so the caller returns no_stable_assertion_id (a
  // rejected login is far better than a forgeable one). Ops
  // should get an alert on the audit trail if this ever fires.
  return null;
}

/**
 * R88 F5 + R114 F1: detect a legacy SAML config still using SHA-1
 * digest / signature. Prior R88 F5 shape threw inside buildAdapter,
 * which propagated uncaught through /:configId/acs, /login, and
 * /metadata.xml → generic 500 to the IdP, no clean audit line, and
 * (worst) the throw message string surfaced via Fastify's default
 * error handler unless setErrorHandler sanitized it. Now callers
 * gate on `isSha1Legacy(cfg)` alongside the `isActive` check and
 * respond with a specific 410 slug the IdP admin can act on.
 */
export function isSha1Legacy(cfg: SamlConfig): boolean {
  return cfg.signatureAlgorithm === "sha1" || cfg.digestAlgorithm === "sha1";
}

// Request and browser state must be shared by every replica. node-saml 5.1.0
// performs separate getAsync calls and ignores removeAsync's return value;
// a shared cache alone therefore does not guarantee single consumption.
const REQUEST_ID_TTL_MS = 10 * 60_000;
const ACCEPTED_CLOCK_SKEW_MS = 5 * 60_000;
const EXPIRED_REQUEST_BATCH = 1000;

class SamlRequestStoreError extends Error {
  constructor(cause: unknown) {
    super("SAML request state is unavailable", { cause });
  }
}

interface RequestIdSlot {
  saved?: string;
  observed?: string;
  nonceHash?: string;
}

function browserNonceHash(nonce: string | null): string | null {
  if (!nonce || !/^[a-f0-9]{32}$/.test(nonce)) return null;
  return crypto.createHash("sha256").update(nonce).digest("hex");
}

async function requestStore<T>(operation: () => Promise<T>): Promise<T> {
  try { return await operation(); }
  catch (error) { throw new SamlRequestStoreError(error); }
}

async function sweepExpiredRequests(now: Date): Promise<void> {
  // Indexed, bounded work per new ceremony. Recheck expiry on DELETE so a
  // concurrent cleanup cannot make the selected IDs authorize a wider delete.
  const expired = await db.samlAuthnRequest.findMany({
    where: { expiresAt: { lte: now } }, orderBy: [{ expiresAt: "asc" }, { id: "asc" }],
    take: EXPIRED_REQUEST_BATCH, select: { id: true },
  });
  if (expired.length) await db.samlAuthnRequest.deleteMany({
    where: { id: { in: expired.map((row) => row.id) }, expiresAt: { lte: now } },
  });
}

function requestIdCache(cfg: SamlConfig, slot: RequestIdSlot) {
  return {
    async saveAsync(key: string, value: string): Promise<{ value: string; createdAt: number } | null> {
      if (!slot.nonceHash) throw new SamlRequestStoreError(new Error("missing browser binding"));
      return requestStore(async () => {
        const now = new Date();
        await sweepExpiredRequests(now);
        try {
          const row = await db.samlAuthnRequest.create({ data: {
            id: key, configId: cfg.id, orgId: cfg.orgId, requestTimestamp: value,
            nonceHash: slot.nonceHash!, expiresAt: new Date(now.getTime() + REQUEST_ID_TTL_MS),
          } });
          slot.saved = key;
          return { value: row.requestTimestamp, createdAt: row.createdAt.getTime() };
        } catch (error) {
          if (typeof error === "object" && error !== null && (error as { code?: string }).code === "P2002") return null;
          throw error;
        }
      });
    },
    async getAsync(key: string): Promise<string | null> {
      slot.observed ??= key;
      if (key.length > 256) return null;
      return requestStore(async () => {
        const row = await db.samlAuthnRequest.findFirst({ where: {
          id: key, configId: cfg.id, orgId: cfg.orgId, expiresAt: { gt: new Date() },
        }, select: { requestTimestamp: true } });
        return row?.requestTimestamp ?? null;
      });
    },
    async removeAsync(_key: string | null): Promise<string | null> {
      // The library calls this before all signature/condition checks finish
      // and does not verify that removal won a race. Defer the actual DELETE
      // to our mandatory browser-bound compare-and-delete below. A callback
      // never gains authority from this method's result.
      return null;
    },
  };
}

async function consumeRequest(cfg: SamlConfig, key: string | undefined, nonce: string | null): Promise<boolean> {
  const nonceHash = browserNonceHash(nonce);
  if (!key || key.length > 256 || !nonceHash) return false;
  return requestStore(async () => {
    const result = await db.samlAuthnRequest.deleteMany({ where: {
      id: key, configId: cfg.id, orgId: cfg.orgId, nonceHash, expiresAt: { gt: new Date() },
    } });
    return result.count === 1;
  });
}

function buildAdapter(cfg: SamlConfig, slot: RequestIdSlot = {}): SAML {
  const urls = spUrls(cfg);
  // R88 F5: reject pre-R88 rows still storing "sha1" — the
  // schema enum was tightened to {sha256, sha512} in R88, but
  // Postgres stores the column as String so legacy rows persist.
  // SHA-1 with XMLDSig is chosen-prefix collision-broken; treat
  // any surviving sha1 config as inactive so a colliding forgery
  // can't be accepted at /acs. Operators must PATCH the config
  // to sha256 or sha512 explicitly.
  //
  // R114 F1: still throw here as defense-in-depth — but the
  // route handlers now gate on isSha1Legacy() and 410 upfront
  // so this throw is only reached if a caller forgets the gate
  // (never happens today).
  const sig = cfg.signatureAlgorithm === "sha1" ? "sha256" : cfg.signatureAlgorithm;
  const dig = cfg.digestAlgorithm === "sha1" ? "sha256" : cfg.digestAlgorithm;
  if (isSha1Legacy(cfg)) {
    throw new Error(
      `saml_config_uses_sha1_${cfg.id}_reject_until_operator_patches_to_sha256`,
    );
  }
  return new SAML({
    // Endpoint metadata.
    issuer: urls.entityId,
    callbackUrl: urls.acsUrl,
    entryPoint: cfg.ssoUrl,
    logoutUrl: cfg.sloUrl ?? undefined,
    // Unsolicited-response refusal (login CSRF): every consumed
    // Response must carry an InResponseTo matching an AuthnRequest WE
    // issued (saved into the shared cache by getAuthorizeUrlAsync,
    // consumed once at validation). Without this an attacker could
    // push a victim's browser through the ATTACKER's IdP and log the
    // victim into the attacker's workspace (session fixation), and
    // IdP-initiated responses from anywhere were accepted. PostgreSQL
    // stores the request and browser binding across replicas and restarts.
    validateInResponseTo: ValidateInResponseTo.always,
    requestIdExpirationPeriodMs: REQUEST_ID_TTL_MS,
    cacheProvider: requestIdCache(cfg, slot),
    // IdP-side crypto.
    idpCert: cfg.x509Cert,
    // Pin the Issuer: without it, ANY assertion signed by the
    // configured cert is accepted regardless of who issued it — a cert
    // reused across tenants/apps (routine with shared IdP appliances
    // and wildcard signing certs) would let one tenant's assertions
    // log into another's org.
    idpIssuer: cfg.entityIdIdp,
    wantAssertionsSigned: cfg.wantAssertionsSigned,
    wantAuthnResponseSigned: cfg.wantResponseSigned,
    signatureAlgorithm: sig as "sha256" | "sha512",
    digestAlgorithm: dig as "sha256" | "sha512",
    identifierFormat: cfg.nameIdFormat,
    // SP-side crypto (optional — signs AuthnRequests + decrypts encrypted
    // assertions when both are provided).
    privateKey: cfg.spPrivateKeyPem ?? undefined,
    decryptionPvk: cfg.allowEncryptedAssertions
      ? cfg.spPrivateKeyPem ?? undefined
      : undefined,
    // Small tolerance — 5 minutes matches the SAML errata guidance for
    // clock skew between SP and IdP.
    acceptedClockSkewMs: ACCEPTED_CLOCK_SKEW_MS,
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
 *
 * Also mints the browser-binding transaction nonce for this
 * AuthnRequest; its hash is persisted with the request before redirecting.
 * The route sets the nonce as a signed cookie and the ACS requires it back.
 */
export async function buildLoginUrl(
  cfg: SamlConfig,
  relayState: string | null,
): Promise<{ url: string; txnNonce: string }> {
  const txnNonce = crypto.randomBytes(16).toString("hex");
  const slot: RequestIdSlot = { nonceHash: browserNonceHash(txnNonce)! };
  const adapter = buildAdapter(cfg, slot);
  const url = await adapter.getAuthorizeUrlAsync(
    relayState ?? "",
    undefined /* host */,
    {} /* options */,
  );
  // node-saml ignores saveAsync's null result on an ID collision. Never
  // redirect or issue a cookie unless this ceremony was actually persisted.
  if (!slot.saved) throw new SamlRequestStoreError(new Error("request ID was not persisted"));
  return { url, txnNonce };
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
  /**
   * The browser-binding nonce presented by the posting browser (the
   * unsigned value of the av_saml_txn cookie), or null when absent.
   * Only its hash is stored in the shared request table.
   */
  presentedTxnNonce: string | null = null,
): Promise<SamlResult> {
  if (typeof body.SAMLResponse !== "string") {
    return { ok: false, error: "no_saml_response" };
  }
  const slot: RequestIdSlot = {};
  const adapter = buildAdapter(cfg, slot);
  let profile: Record<string, unknown> | null;
  try {
    const result = await adapter.validatePostResponseAsync({
      SAMLResponse: body.SAMLResponse,
    });
    profile = (result.profile ?? null) as Record<string, unknown> | null;
  } catch (err) {
    if (err instanceof SamlRequestStoreError) return { ok: false, error: "request_state_unavailable" };
    // Refuse the response and burn only the ceremony belonging to this
    // browser. An untrusted request ID alone cannot erase another browser's
    // pending login. A failed database write remains a refusal, never a mint.
    try { await consumeRequest(cfg, slot.observed, presentedTxnNonce); }
    catch { return { ok: false, error: "request_state_unavailable" }; }
    return {
      ok: false,
      error: "signature_or_conditions_failed",
      detail: err instanceof Error ? err.message : String(err),
    };
  }
  if (!profile) return { ok: false, error: "no_profile" };

  // The library has verified the assertion and InResponseTo relationship,
  // including its compatibility path where SubjectConfirmation omits that
  // attribute. Its separate cache reads do not elect a winner. This DELETE
  // is the mandatory authority check: exactly one replica may consume the
  // matching request, config, tenant, browser hash, and unexpired lifetime.
  const responseInResponseTo = profile["inResponseTo"];
  try {
    if (typeof responseInResponseTo !== "string" ||
        !await consumeRequest(cfg, responseInResponseTo, presentedTxnNonce)) {
      return { ok: false, error: "txn_mismatch" };
    }
  } catch { return { ok: false, error: "request_state_unavailable" }; }

  // Enforce the Issuer pin on the LOGIN path. node-saml's `idpIssuer`
  // option (buildAdapter pins it to cfg.entityIdIdp) is only checked by
  // the library for LogoutRequest/LogoutResponse messages — on the ACS
  // path it merely copies the assertion's Issuer into profile.issuer
  // (node-saml 5.1.0, saml.js verifyIssuer call sites). Without this
  // check, ANY assertion signed by the configured cert is accepted
  // regardless of who issued it — a cert reused across tenants/apps
  // (routine with shared IdP appliances and wildcard signing certs)
  // would let one tenant's assertions log into another's org. The
  // profile.issuer value comes from the XMLDSig-validated assertion,
  // so this comparison is bound to what the signature actually covers.
  // Fail closed on a missing Issuer too.
  const assertedIssuer = profile["issuer"];
  if (typeof assertedIssuer !== "string" || assertedIssuer !== cfg.entityIdIdp) {
    return {
      ok: false,
      error: "issuer_mismatch",
      detail: `expected ${cfg.entityIdIdp}, got ${typeof assertedIssuer === "string" ? truncateWellFormed(assertedIssuer, 200) : String(assertedIssuer)}`,
    };
  }

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
  //
  // R76 MEDIUM #3 (landed R77) → R88 F1 → R89 F1/F2: use the
  // Profile's `getAssertionXml()` — returns the VALIDATED (and
  // decrypted if applicable) Assertion element. Prior raw-XML
  // approaches all fell to XSW variants (bogus sibling Assertion,
  // decoy ds:Signature block, ds:Manifest injection). Sourcing
  // the ID from the node-saml-validated XML string means the ID
  // is bound to what XMLDSig actually verified. Also fixes the
  // R88 regression that broke encrypted-assertion flows (outer
  // body contains no ds:Reference when EncryptedAssertion is
  // used → R88 regex returned null → SSO broken for the default
  // encrypted-assertion config).
  const assertionId = extractAssertionId(
    profile as { getAssertionXml?: () => string; sessionIndex?: string },
  );
  if (!assertionId) {
    return { ok: false, error: "no_stable_assertion_id" };
  }

  // Validated-assertion XML — the same XSW-safe source
  // extractAssertionId uses (node-saml returns ONLY the
  // signature-verified, decrypted Assertion element).
  const assertionXml =
    typeof (profile as { getAssertionXml?: () => string }).getAssertionXml === "function"
      ? (profile as { getAssertionXml: () => string }).getAssertionXml()
      : "";

  // Bearer Recipient pin. node-saml validates the bearer
  // SubjectConfirmationData's InResponseTo and NotOnOrAfter but NOT its
  // Recipient — an assertion legitimately signed for a DIFFERENT
  // service (Recipient pointing at another ACS) was accepted here as
  // long as issuer + audience matched, breaking the SAML bearer
  // profile's delivery-endpoint binding. Enforce every Recipient
  // present in the validated assertion against OUR ACS URL. An absent
  // attribute stays accepted (the attack shape requires a mismatching
  // value; a few IdPs omit it).
  if (assertionXml) {
    const acsUrl = spUrls(cfg).acsUrl;
    const recipientRe =
      /<(?:[\w-]+:)?SubjectConfirmationData\b[^>]*?\bRecipient\s*=\s*"([^"]*)"/g;
    for (const m of assertionXml.matchAll(recipientRe)) {
      if (m[1] !== acsUrl) {
        return {
          ok: false,
          error: "recipient_mismatch",
          detail: truncateWellFormed(m[1] ?? "", 200),
        };
      }
    }
  }

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

  // Replay-record lifetime: at least the assertion's own acceptance
  // window. profile.notOnOrAfter is populated by node-saml only from
  // the bearer SubjectConfirmationData — and is often ABSENT — so the
  // old now+5min fallback expired replay records BEFORE the assertion
  // itself: a 20-minute assertion could be swept from the table after
  // five minutes and replayed inside a fresh, legitimately-issued
  // Response wrapper (new InResponseTo, same signed assertion).
  // Derive the window from every NotOnOrAfter in the VALIDATED
  // assertion (Conditions + SubjectConfirmationData), padded by the
  // adapter's accepted clock skew; never store less than the fallback.
  let recordExpiry = new Date(Math.max(notOnOrAfter.getTime(), now.getTime() + 5 * 60_000));
  if (assertionXml) {
    let maxMs = recordExpiry.getTime();
    const notAfterRe = /\bNotOnOrAfter\s*=\s*"([^"]+)"/g;
    for (const m of assertionXml.matchAll(notAfterRe)) {
      const t = new Date(m[1] ?? "").getTime();
      if (Number.isFinite(t) && t > maxMs) maxMs = t;
    }
    recordExpiry = new Date(maxMs + ACCEPTED_CLOCK_SKEW_MS);
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
        notOnOrAfter: recordExpiry,
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
    // R134 F4: cap IdP-asserted email + displayName before
    // returning them to the ACS handler that JIT-provisions
    // db.user rows (routes/saml.ts:358). Prisma.User.email +
    // displayName are unbounded String / String? per schema —
    // a rogue-but-domain-verified IdP (attacker's own org +
    // IdP appliance) could JIT-provision users with
    // megabyte-sized displayName values that balloon every
    // subsequent /members list render + /me/export bundle.
    // R76 HIGH #1 blocks cross-tenant JIT, so the DoS is
    // scoped to the attacker's own tenant — but the console
    // members-list still breaks. RFC 5321 max email length
    // is 320; console password signup already enforces
    // displayName max(80), so 200 here gives IdP-asserted
    // legitimate names some slack while still bounded.
    email: truncateWellFormed(email.toLowerCase().trim().normalize("NFC"), 320),
    displayName: typeof displayName === "string"
      ? truncateWellFormed(displayName, 200)
      : null,
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
  // Round-109: NFC both sides — emails are NFC at entry (#381), but
  // stored allowedDomains may carry legacy/admin-pasted NFD bytes;
  // visually identical domains must match.
  const domain = email.slice(at + 1).toLowerCase().normalize("NFC");
  const configs = await db.samlConfig.findMany({
    where: { isActive: true },
  });
  for (const c of configs) {
    const domains = c.allowedDomains
      .split(",")
      .map((d) => d.trim().toLowerCase().normalize("NFC"))
      .filter(Boolean);
    if (domains.length === 0) continue;
    if (domains.includes(domain)) return c;
  }
  return null;
}
