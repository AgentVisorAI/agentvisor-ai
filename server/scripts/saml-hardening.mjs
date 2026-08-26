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
}) {
  const responseId = "_" + randomBytes(16).toString("hex");
  const assertionId = "_" + randomBytes(16).toString("hex");
  const now = new Date();
  const assertionXml = `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${assertionId}" IssueInstant="${now.toISOString()}" Version="2.0">
  <saml:Issuer>${idpIssuer}</saml:Issuer>
  <saml:Subject>
    <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${email}</saml:NameID>
    <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
      <saml:SubjectConfirmationData NotOnOrAfter="${notOnOrAfter.toISOString()}" Recipient="${acs}"/>
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

  const responseXml = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${responseId}" Version="2.0" IssueInstant="${now.toISOString()}" Destination="${acs}">
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
  const expiredResp = await craftSignedResponse({
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
  results.push({ drill: "expired-assertion", status: r1.status, expect: 400, body: b1.slice(0, 100) });

  // ============ 2. Wrong audience ============
  console.log("\n[2] Wrong audience");
  const wrongAudResp = await craftSignedResponse({
    privateKey: idp.privateKey,
    certBody: idp.certBody,
    audience: "https://not-us.example/entity",
    acs: cfg.spAcsUrl,
    idpIssuer: "https://real-idp.example/entity",
    email: "u2@hardening.example",
  });
  const r2 = await postToAcs(cfg.spAcsUrl, wrongAudResp);
  const b2 = await r2.text();
  results.push({ drill: "wrong-audience", status: r2.status, expect: 400, body: b2.slice(0, 100) });

  // ============ 3. Wrong signing cert ============
  console.log("\n[3] Assertion signed by different key");
  const attacker = await generateIdpKeys("attacker-idp");
  const attackerResp = await craftSignedResponse({
    privateKey: attacker.privateKey, // Wrong key!
    certBody: attacker.certBody,
    audience: cfg.spEntityId,
    acs: cfg.spAcsUrl,
    idpIssuer: "https://real-idp.example/entity",
    email: "attacker@hardening.example",
  });
  const r3 = await postToAcs(cfg.spAcsUrl, attackerResp);
  const b3 = await r3.text();
  results.push({ drill: "wrong-signing-cert", status: r3.status, expect: 400, body: b3.slice(0, 100) });

  // ============ 4. Member can't CRUD ============
  console.log("\n[4] Member cannot CRUD SAML configs");
  // Set up a member user by inserting directly via DB - too complex. Use the /me/members flow instead? We don't have one.
  // Skip: forge a JWT with role=member and try.
  const memberJwt = await forgeMemberJwt(ownerCookie);
  const memberCookie = `av_session=${memberJwt}`;
  const memberListReq = await fetch(`${API}/api/v1/auth/saml`, {
    headers: { Cookie: memberCookie, Origin: SPA_ORIGIN, "Sec-Fetch-Site": "same-origin" },
  });
  results.push({ drill: "member-list-ok", status: memberListReq.status, expect: 200 });

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
  const jitOffResp = await craftSignedResponse({
    privateKey: idp.privateKey,
    certBody: idp.certBody,
    audience: cfg.spEntityId,
    acs: cfg.spAcsUrl,
    idpIssuer: "https://real-idp.example/entity",
    email: "brandnew@hardening.example",
  });
  const r5 = await postToAcs(cfg.spAcsUrl, jitOffResp);
  const b5 = await r5.text();
  results.push({ drill: "jit-disabled", status: r5.status, expect: 403, body: b5.slice(0, 100) });

  // Print
  console.log("\n============ RESULTS ============");
  let allPass = true;
  for (const r of results) {
    const ok = r.status === r.expect;
    if (!ok) allPass = false;
    console.log(`${ok ? "✅" : "❌"} ${r.drill}: got ${r.status}, expected ${r.expect}${r.body ? " — " + r.body : ""}`);
  }
  if (!allPass) process.exit(1);
  console.log("\n✅  All SAML hardening drills PASSED");
}

async function forgeMemberJwt(_ownerCookie) {
  // Look up the org id via /me, then mint a JWT with role=member. We do
  // NOT insert a real member row — the check we care about is "role in
  // the JWT gets rejected by the CRUD handlers regardless".
  const meRes = await fetch(`${API}/api/v1/auth/me`, {
    headers: { Cookie: _ownerCookie, Origin: SPA_ORIGIN },
  });
  const me = await meRes.json();
  const orgId = me.org.id;
  const userId = me.user.id;
  const { SignJWT } = await import("jose");
  const secret = new TextEncoder().encode(
    "thisisatestsecret_atleast32bytes_long_ok!",
  );
  const now = Math.floor(Date.now() / 1000);
  return await new SignJWT({ sub: userId, orgId, membershipRole: "member" })
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setIssuer("agentvisor-ai")
    .setAudience("agentvisor-console")
    .setIssuedAt()
    .setExpirationTime(now + 3600)
    .sign(secret);
}

main().catch((err) => {
  console.error("❌", err);
  process.exit(1);
});
