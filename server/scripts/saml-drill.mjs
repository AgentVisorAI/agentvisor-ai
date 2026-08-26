/**
 * Full SAML integration drill.
 *
 * Spins up a mock IdP that:
 *   1. Generates its own RSA-2048 keypair + self-signed cert.
 *   2. Registers itself as a SamlConfig on the API using the IdP's public cert.
 *   3. Crafts a signed SAMLResponse XML for a test user.
 *   4. POSTs it to /api/v1/auth/saml/<configId>/acs.
 *   5. Verifies the response is 302 to /app/... and we got an av_session cookie.
 *   6. Uses the cookie to hit /api/v1/sessions — proves the mint succeeded.
 *   7. Tries to replay the same SAMLResponse — expects the second attempt to
 *      fail with replay_detected.
 */

import { execSync } from "node:child_process";
import { generateKeyPairSync, createSign, randomBytes } from "node:crypto";
import { promises as fs } from "node:fs";

const API = "http://127.0.0.1:4340";
const SPA_ORIGIN = "http://127.0.0.1:8988";

async function main() {
  // 1. Sign up the org owner so we can create a SAML config through the console API.
  const email = `owner-${Date.now()}@saml-drill.example`;
  const signup = await fetch(`${API}/api/v1/auth/signup`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Origin: SPA_ORIGIN,
      "Sec-Fetch-Site": "same-origin",
    },
    body: JSON.stringify({
      email,
      password: "correcthorse42x",
      orgName: "SamlDrillOrg",
    }),
  });
  if (signup.status !== 201) {
    throw new Error("signup failed: " + signup.status + " " + await signup.text());
  }
  const setCookie = signup.headers.get("set-cookie") ?? "";
  const cookie = /(av_session=[^;]+)/.exec(setCookie)?.[1];
  if (!cookie) throw new Error("no session cookie");

  // 2. Generate the IdP's RSA keypair + a real self-signed X.509 cert.
  //    We could reuse our own saml-cert.ts but let's use openssl to keep the
  //    test independent of the code under test.
  await fs.mkdir("/tmp/saml-drill", { recursive: true });
  execSync(
    `openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
     -keyout /tmp/saml-drill/idp.key.pem -out /tmp/saml-drill/idp.crt.pem \
     -subj "/CN=MockIdP"`,
    { stdio: "pipe" },
  );
  const idpPrivPem = await fs.readFile("/tmp/saml-drill/idp.key.pem", "utf8");
  const idpCertPem = await fs.readFile("/tmp/saml-drill/idp.crt.pem", "utf8");
  const idpCertBody = idpCertPem
    .replace(/-----(BEGIN|END) CERTIFICATE-----/g, "")
    .replace(/\s+/g, "");

  // 3. Register the SAML config with the API.
  const create = await fetch(`${API}/api/v1/auth/saml`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Origin: SPA_ORIGIN,
      "Sec-Fetch-Site": "same-origin",
      Cookie: cookie,
    },
    body: JSON.stringify({
      displayName: "Mock Okta",
      ssoUrl: "https://mock-idp.example/sso",
      entityIdIdp: "https://mock-idp.example/entity",
      x509Cert: idpCertPem,
      wantAssertionsSigned: true,
      wantResponseSigned: false,
      jitEnabled: true,
      jitDefaultRole: "member",
      allowedDomains: "saml-drill.example",
      allowEncryptedAssertions: false,
    }),
  });
  if (create.status !== 201) {
    throw new Error("create saml failed: " + create.status + " " + await create.text());
  }
  const { config } = await create.json();
  console.log("[1/6] created config", config.id, "with ACS", config.spAcsUrl);

  // 4. Craft the SAMLResponse XML.
  const userEmail = "alice@saml-drill.example";
  const now = new Date();
  const notBefore = new Date(now.getTime() - 60_000).toISOString();
  const notOnOrAfter = new Date(now.getTime() + 300_000).toISOString();
  const responseId = "_" + randomBytes(16).toString("hex");
  const assertionId = "_" + randomBytes(16).toString("hex");
  const sessionIndex = "_" + randomBytes(16).toString("hex");

  const audience = config.spEntityId;
  const acs = config.spAcsUrl;
  const idpIssuer = "https://mock-idp.example/entity";

  // Build the assertion, then sign it, then wrap in the Response envelope.
  const assertionXml =
`<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${assertionId}" IssueInstant="${now.toISOString()}" Version="2.0">
  <saml:Issuer>${idpIssuer}</saml:Issuer>
  <saml:Subject>
    <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${userEmail}</saml:NameID>
    <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
      <saml:SubjectConfirmationData NotOnOrAfter="${notOnOrAfter}" Recipient="${acs}"/>
    </saml:SubjectConfirmation>
  </saml:Subject>
  <saml:Conditions NotBefore="${notBefore}" NotOnOrAfter="${notOnOrAfter}">
    <saml:AudienceRestriction>
      <saml:Audience>${audience}</saml:Audience>
    </saml:AudienceRestriction>
  </saml:Conditions>
  <saml:AuthnStatement AuthnInstant="${now.toISOString()}" SessionIndex="${sessionIndex}">
    <saml:AuthnContext>
      <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
    </saml:AuthnContext>
  </saml:AuthnStatement>
  <saml:AttributeStatement>
    <saml:Attribute Name="email"><saml:AttributeValue>${userEmail}</saml:AttributeValue></saml:Attribute>
    <saml:Attribute Name="displayName"><saml:AttributeValue>Alice From SAML</saml:AttributeValue></saml:Attribute>
  </saml:AttributeStatement>
</saml:Assertion>`.trim();

  // Sign the assertion with xml-crypto.
  const { SignedXml } = await import("xml-crypto");
  const sig = new SignedXml({
    privateKey: idpPrivPem,
    signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
    getKeyInfoContent: () => `<X509Data><X509Certificate>${idpCertBody}</X509Certificate></X509Data>`,
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

  const responseXml =
`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${responseId}" Version="2.0" IssueInstant="${now.toISOString()}" Destination="${acs}">
  <saml:Issuer>${idpIssuer}</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  ${signedAssertion}
</samlp:Response>`.trim();

  const samlResponse = Buffer.from(responseXml, "utf8").toString("base64");

  // 5. POST it to ACS.
  const relayState = "#/deployments";
  const acsRes = await fetch(config.spAcsUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      // IdP-posted requests are cross-site — no Origin, no cookie.
    },
    body: new URLSearchParams({ SAMLResponse: samlResponse, RelayState: relayState }).toString(),
    redirect: "manual",
  });
  console.log("[2/6] ACS status", acsRes.status);
  if (acsRes.status < 300 || acsRes.status >= 400) {
    console.log("body:", await acsRes.text());
    throw new Error("ACS should be a redirect");
  }
  const acsSetCookie = acsRes.headers.get("set-cookie") ?? "";
  const jwtCookie = /(av_session=[^;]+)/.exec(acsSetCookie)?.[1];
  if (!jwtCookie) throw new Error("no av_session cookie from ACS");
  console.log("[3/6] got av_session cookie");
  const location = acsRes.headers.get("location") ?? "";
  console.log("[4/6] redirect Location:", location);
  if (!location.includes("#/deployments")) {
    throw new Error("RelayState round-trip failed");
  }

  // 6. Use the cookie to prove auth worked.
  const meRes = await fetch(`${API}/api/v1/auth/me`, {
    headers: { Cookie: jwtCookie, Origin: SPA_ORIGIN },
  });
  const me = await meRes.json();
  console.log("[5/6] /me:", meRes.status, JSON.stringify(me).slice(0, 200));
  if (me?.user?.email !== "alice@saml-drill.example") {
    throw new Error("me.email mismatch: " + JSON.stringify(me));
  }

  // 7. Replay attempt.
  const replay = await fetch(config.spAcsUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ SAMLResponse: samlResponse, RelayState: "" }).toString(),
    redirect: "manual",
  });
  const replayBody = await replay.text();
  console.log("[6/6] replay:", replay.status, replayBody.slice(0, 120));
  if (replay.status < 400 || !replayBody.includes("replay_detected")) {
    throw new Error("replay guard did not fire");
  }

  console.log("\n✅  SAML full-flow drill: PASSED");
}

main().catch((err) => {
  console.error("\n❌  SAML drill FAILED:", err);
  process.exit(1);
});
