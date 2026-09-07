/**
 * SAML hardening drills. Reuses the same mock-IdP + xml-crypto approach
 * as saml-drill.mjs, but varies the assertion to prove each guard fires.
 */

import { execSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { promises as fs } from "node:fs";

const API = "http://127.0.0.1:4341";
const SPA_ORIGIN = "http://127.0.0.1:8988";

async function signup(email, orgName) {
  const res = await fetch(`${API}/api/v1/auth/signup`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Origin: SPA_ORIGIN,
      "Sec-Fetch-Site": "same-origin",
    },
    body: JSON.stringify({ email, password: "correcthorse42x", orgName }),
  });
  if (res.status !== 201) throw new Error("signup failed " + res.status + " " + await res.text());
  const setCookie = res.headers.get("set-cookie") ?? "";
  return /(av_session=[^;]+)/.exec(setCookie)?.[1];
}

async function createConfig(cookie, opts) {
  const res = await fetch(`${API}/api/v1/auth/saml`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Origin: SPA_ORIGIN,
      "Sec-Fetch-Site": "same-origin",
      Cookie: cookie,
    },
    body: JSON.stringify(opts),
  });
  if (res.status !== 201) throw new Error("create saml " + res.status + " " + await res.text());
  return (await res.json()).config;
}

// Reusable openssl-based cert factory.
async function generateIdpKeys(name) {
  const dir = `/tmp/saml-hard-${name}`;
  await fs.mkdir(dir, { recursive: true });
  execSync(
    `openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
     -keyout ${dir}/key.pem -out ${dir}/crt.pem -subj "/CN=${name}"`,
    { stdio: "pipe" },
  );
  return {
    privateKey: await fs.readFile(`${dir}/key.pem`, "utf8"),
    certPem: await fs.readFile(`${dir}/crt.pem`, "utf8"),
    certBody: (await fs.readFile(`${dir}/crt.pem`, "utf8"))
      .replace(/-----(BEGIN|END) CERTIFICATE-----/g, "")
      .replace(/\s+/g, ""),
  };
}

async function craftSignedResponse({
  privateKey,
  certBody,
  audience,
  acs,
  idpIssuer,
  email,
  notBefore = new Date(Date.now() - 60_000),
  notOnOrAfter = new Date(Date.now() + 300_000),
  // Echo of a real AuthnRequest ID (validateInResponseTo=always).
  // null crafts an UNSOLICITED response — refused at the outer gate,
  // which the dedicated probe asserts.
  inResponseTo = null,
}) {
  const responseId = "_" + randomBytes(16).toString("hex");
  const assertionId = "_" + randomBytes(16).toString("hex");
  const now = new Date();
  const assertionXml = `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${assertionId}" IssueInstant="${now.toISOString()}" Version="2.0">
  <saml:Issuer>${idpIssuer}</saml:Issuer>
  <saml:Subject>
    <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${email}</saml:NameID>
    <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
      <saml:SubjectConfirmationData NotOnOrAfter="${notOnOrAfter.toISOString()}" Recipient="${acs}"${inResponseTo ? ` InResponseTo="${inResponseTo}"` : ""}/>
    </saml:SubjectConfirmation>
  </saml:Subject>
  <saml:Conditions NotBefore="${notBefore.toISOString()}" NotOnOrAfter="${notOnOrAfter.toISOString()}">
    <saml:AudienceRestriction><saml:Audience>${audience}</saml:Audience></saml:AudienceRestriction>
  </saml:Conditions>
  <saml:AuthnStatement AuthnInstant="${now.toISOString()}" SessionIndex="_${randomBytes(8).toString("hex")}">
    <saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext>
  </saml:AuthnStatement>
  <saml:AttributeStatement>
    <saml:Attribute Name="email"><saml:AttributeValue>${email}</saml:AttributeValue></saml:Attribute>
  </saml:AttributeStatement>
</saml:Assertion>`.trim();

  const { SignedXml } = await import("xml-crypto");
  const sig = new SignedXml({
    privateKey,
    signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
    getKeyInfoContent: () => `<X509Data><X509Certificate>${certBody}</X509Certificate></X509Data>`,
  });
  sig.addReference({
    xpath: "//*[local-name(.)='Assertion']",
    transforms: [
      "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
      "http://www.w3.org/2001/10/xml-exc-c14n#",
    ],
    digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
  });
  sig.computeSignature(assertionXml, { location: { reference: "//*[local-name(.)='Issuer']", action: "after" } });
  const signedAssertion = sig.getSignedXml();

  const responseXml = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${responseId}"${inResponseTo ? ` InResponseTo="${inResponseTo}"` : ""} Version="2.0" IssueInstant="${now.toISOString()}" Destination="${acs}">
  <saml:Issuer>${idpIssuer}</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  ${signedAssertion}
</samlp:Response>`.trim();
  return Buffer.from(responseXml, "utf8").toString("base64");
}

async function postToAcs(acsUrl, samlResponse) {
  return fetch(acsUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ SAMLResponse: samlResponse }).toString(),
    redirect: "manual",
  });
}


// SP-initiated prelude: issue a real AuthnRequest via /login and pull
// its ID out of the deflated SAMLRequest, exactly like a live IdP
// would. Each crafted probe needs a FRESH id (they are single-use).
async function spInitiate(configId) {
  const res = await fetch(`${API}/api/v1/auth/saml/${configId}/login`, { redirect: "manual" });
  if (res.status !== 302) throw new Error("sp login start " + res.status);
  const url = new URL(res.headers.get("location"));
  const req = url.searchParams.get("SAMLRequest");
  if (!req) throw new Error("no SAMLRequest in redirect");
  const { inflateRawSync } = await import("node:zlib");
  const xml = inflateRawSync(Buffer.from(req, "base64")).toString("utf8");
  const id = /ID="([^"]+)"/.exec(xml)?.[1];
  if (!id) throw new Error("no AuthnRequest ID");
  return id;
}

async function main() {
  const results = [];

  // ---------- Setup owner + real IdP ----------
  const ownerCookie = await signup(`owner-${Date.now()}@hardening.example`, "HardOrg");
  const idp = await generateIdpKeys("real-idp");
  const cfg = await createConfig(ownerCookie, {
    displayName: "Prod IdP",
    ssoUrl: "https://real-idp.example/sso",
    entityIdIdp: "https://real-idp.example/entity",
    x509Cert: idp.certPem,
    wantAssertionsSigned: true,
    wantResponseSigned: false,
    jitEnabled: true,
    jitDefaultRole: "member",
    allowedDomains: "hardening.example",
    allowEncryptedAssertions: false,
  });
  console.log("cfg id:", cfg.id);

  // ============ 1. Expired assertion ============
  console.log("\n[1] Expired assertion (NotOnOrAfter in past)");
  const irt_expiredResp = await spInitiate(cfg.id);
  const expiredResp = await craftSignedResponse({
    inResponseTo: irt_expiredResp,
    privateKey: idp.privateKey,
    certBody: idp.certBody,
    audience: cfg.spEntityId,
    acs: cfg.spAcsUrl,
    idpIssuer: "https://real-idp.example/entity",
    email: "u@hardening.example",
    notBefore: new Date(Date.now() - 3600_000),
    notOnOrAfter: new Date(Date.now() - 1800_000),
  });
  const r1 = await postToAcs(cfg.spAcsUrl, expiredResp);
  const b1 = await r1.text();
  // R122 F2: ACS errors are browser-UX redirects (302 to
  // /app/#/login?err=<slug>), not bare 4xx JSON — /acs is always a
  // top-level IdP form post. Assert the redirect carries the slug.
  results.push({ drill: "expired-assertion", status: r1.status, expect: 302, body: (r1.headers.get("location") ?? b1).slice(0, 100), ok: r1.status === 302 && /err=saml_assertion/.test(r1.headers.get("location") ?? "") });

  // ============ 2. Wrong audience ============
  console.log("\n[2] Wrong audience");
  const irt_wrongAudResp = await spInitiate(cfg.id);
  const wrongAudResp = await craftSignedResponse({
    inResponseTo: irt_wrongAudResp,
    privateKey: idp.privateKey,
    certBody: idp.certBody,
    audience: "https://not-us.example/entity",
    acs: cfg.spAcsUrl,
    idpIssuer: "https://real-idp.example/entity",
    email: "u2@hardening.example",
  });
  const r2 = await postToAcs(cfg.spAcsUrl, wrongAudResp);
  const b2 = await r2.text();
  results.push({ drill: "wrong-audience", status: r2.status, expect: 302, body: (r2.headers.get("location") ?? b2).slice(0, 100), ok: r2.status === 302 && /err=saml_assertion/.test(r2.headers.get("location") ?? "") });

  // ============ 3. Wrong signing cert ============
  console.log("\n[3] Assertion signed by different key");
  const attacker = await generateIdpKeys("attacker-idp");
  const irt_attackerResp = await spInitiate(cfg.id);
  const attackerResp = await craftSignedResponse({
    inResponseTo: irt_attackerResp,
    privateKey: attacker.privateKey, // Wrong key!
    certBody: attacker.certBody,
    audience: cfg.spEntityId,
    acs: cfg.spAcsUrl,
    idpIssuer: "https://real-idp.example/entity",
    email: "attacker@hardening.example",
  });
  const r3 = await postToAcs(cfg.spAcsUrl, attackerResp);
  const b3 = await r3.text();
  results.push({ drill: "wrong-signing-cert", status: r3.status, expect: 302, body: (r3.headers.get("location") ?? b3).slice(0, 100), ok: r3.status === 302 && /err=saml_assertion/.test(r3.headers.get("location") ?? "") });

  // ============ 4. Member can't CRUD ============
  console.log("\n[4] Member cannot CRUD SAML configs");
  // Round-33 hardened the membership fence: the role claim inside the
  // JWT is re-resolved against the memberships table on every request,
  // so the old forged-JWT approach now (correctly) yields 401. Create a
  // REAL member through the invite flow instead — the same path the
  // product uses (acceptUrlDev is surfaced in dev builds).
  const memberEmail = `member-${Date.now()}@hardening.example`;
  const invRes = await fetch(`${API}/api/v1/members/invites`, {
    method: "POST",
    headers: { Cookie: ownerCookie, Origin: SPA_ORIGIN, "Sec-Fetch-Site": "same-origin", "Content-Type": "application/json" },
    body: JSON.stringify({ email: memberEmail, role: "member" }),
  });
  const inv = await invRes.json();
  const acceptToken = /token=([^&]+)/.exec(inv.invite?.acceptUrlDev ?? "")?.[1];
  if (!acceptToken) throw new Error(`no dev accept URL on invite: ${JSON.stringify(inv).slice(0, 120)}`);
  const acceptRes = await fetch(`${API}/api/v1/members/invites/accept`, {
    method: "POST",
    headers: { Origin: SPA_ORIGIN, "Sec-Fetch-Site": "same-origin", "Content-Type": "application/json" },
    body: JSON.stringify({ email: memberEmail, token: decodeURIComponent(acceptToken), password: "correcthorse42x-member", displayName: "Drill Member" }),
  });
  const memberCookie = /av_session=([^;]+)/.exec(acceptRes.headers.get("set-cookie") ?? "")
    ? `av_session=${/av_session=([^;]+)/.exec(acceptRes.headers.get("set-cookie") ?? "")[1]}`
    : null;
  if (!memberCookie) throw new Error(`invite accept minted no session: ${acceptRes.status} ${(await acceptRes.text()).slice(0, 120)}`);
  const memberListReq = await fetch(`${API}/api/v1/auth/saml`, {
    headers: { Cookie: memberCookie, Origin: SPA_ORIGIN, "Sec-Fetch-Site": "same-origin" },
  });
  // R108 F1 made the SAML list owner/admin-only (ssoUrl, cert
  // fingerprints, JIT config are recon material — same class as the
  // R89/R90 list gates). A member must get 403, not the config list.
  results.push({ drill: "member-list-403", status: memberListReq.status, expect: 403 });

  const memberCreateReq = await fetch(`${API}/api/v1/auth/saml`, {
    method: "POST",
    headers: {
      Cookie: memberCookie,
      Origin: SPA_ORIGIN,
      "Sec-Fetch-Site": "same-origin",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ displayName: "hi", ssoUrl: "https://x", entityIdIdp: "x", x509Cert: idp.certPem }),
  });
  results.push({ drill: "member-create-403", status: memberCreateReq.status, expect: 403 });

  const memberDeleteReq = await fetch(`${API}/api/v1/auth/saml/${cfg.id}`, {
    method: "DELETE",
    headers: { Cookie: memberCookie, Origin: SPA_ORIGIN, "Sec-Fetch-Site": "same-origin" },
  });
  results.push({ drill: "member-delete-403", status: memberDeleteReq.status, expect: 403 });

  // ============ 5. JIT disabled + user not in DB → 403 ============
  console.log("\n[5] JIT disabled + user not in DB");
  await fetch(`${API}/api/v1/auth/saml/${cfg.id}`, {
    method: "PATCH",
    headers: {
      Cookie: ownerCookie,
      Origin: SPA_ORIGIN,
      "Sec-Fetch-Site": "same-origin",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ jitEnabled: false }),
  });
  const irt_jitOffResp = await spInitiate(cfg.id);
  const jitOffResp = await craftSignedResponse({
    inResponseTo: irt_jitOffResp,
    privateKey: idp.privateKey,
    certBody: idp.certBody,
    audience: cfg.spEntityId,
    acs: cfg.spAcsUrl,
    idpIssuer: "https://real-idp.example/entity",
    email: "brandnew@hardening.example",
  });
  const r5 = await postToAcs(cfg.spAcsUrl, jitOffResp);
  const b5 = await r5.text();
  results.push({ drill: "jit-disabled", status: r5.status, expect: 302, body: (r5.headers.get("location") ?? b5).slice(0, 100), ok: r5.status === 302 && /err=saml/.test(r5.headers.get("location") ?? "") });

  // ============ Unsolicited response refused (login CSRF gate) ============
  // Since validateInResponseTo=always, a response that answers NO
  // AuthnRequest of ours must be refused regardless of its signature —
  // this is also the gate every crafted probe above now hits first,
  // which is correct defense-in-depth: hostile responses die at the
  // outermost check.
  console.log("[5b] Unsolicited (IdP-initiated) response refused");
  const unsolicited = await craftSignedResponse({
    privateKey: idp.privateKey,
    certBody: idp.certBody,
    audience: cfg.spEntityId,
    acs: cfg.spAcsUrl,
    idpIssuer: "https://real-idp.example/entity",
    email: "unsolicited@saml-hard.example",
  });
  const rUn = await fetch(cfg.spAcsUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ SAMLResponse: unsolicited, RelayState: "" }).toString(),
    redirect: "manual",
  });
  results.push({ drill: "unsolicited-refused", status: rUn.status, expect: 302, ok: rUn.status === 302 && /err=saml_assertion/.test(rUn.headers.get("location") ?? "") && !(rUn.headers.get("set-cookie") ?? "").includes("av_session=") });

  // Print
  console.log("\n============ RESULTS ============");
  let allPass = true;
  for (const r of results) {
    // Rows that carry their own verdict (redirect-slug assertions)
    // use it; plain rows compare status to expect.
    const ok = r.ok !== undefined ? r.ok : r.status === r.expect;
    if (!ok) allPass = false;
    console.log(`${ok ? "✅" : "❌"} ${r.drill}: got ${r.status}, expected ${r.expect}${r.body ? " — " + r.body : ""}`);
  }
  if (!allPass) process.exit(1);
  console.log("\n✅  All SAML hardening drills PASSED");
}


main().catch((err) => {
  console.error("❌", err);
  process.exit(1);
});
