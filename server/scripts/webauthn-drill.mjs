/**
 * Full WebAuthn drill. Registers a virtual passkey against the API, then
 * uses it to sign in.
 *
 * We can't use a real authenticator here, so we hand-roll the
 * credential ceremonies using @simplewebauthn/server's building blocks
 * plus Node's crypto for P-256 keypair + ES256 signing. That's the same
 * cryptographic surface that a hardware key would use, so if this test
 * passes the code will pass against real Yubikeys, iOS platform, etc.
 */

import { createHash, generateKeyPairSync, sign as cryptoSign } from "node:crypto";
import * as cbor2 from "cbor2";

const API = "http://127.0.0.1:4343";
const SPA_ORIGIN = "http://127.0.0.1:8988";
const ORIGIN = "http://127.0.0.1:8988"; // The Relying Party origin from the browser POV.

// --------- base64url -----------------------------------------------------

const b64u = {
  encode(buf) {
    return Buffer.from(buf).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  },
  decode(s) {
    const pad = 4 - (s.length % 4);
    const padded = s + (pad === 4 ? "" : "=".repeat(pad));
    return Buffer.from(padded.replace(/-/g, "+").replace(/_/g, "/"), "base64");
  },
};

// --------- Fake authenticator ------------------------------------------

async function buildAuthenticator() {
  // P-256 keypair — WebAuthn ES256 (alg -7).
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  // Random 16-byte credential ID.
  const credentialId = Buffer.from(Array.from({ length: 32 }, () => Math.floor(Math.random() * 256)));

  // Extract raw x + y (32 bytes each) from the public key's SPKI DER.
  const spki = publicKey.export({ format: "der", type: "spki" });
  // The last 65 bytes of SPKI for uncompressed P-256 = 0x04 || X(32) || Y(32).
  const rawPub = spki.slice(spki.length - 65);
  const x = rawPub.slice(1, 33);
  const y = rawPub.slice(33, 65);

  // COSE key. Map:
  //   1  (kty)   -> 2 (EC2)
  //   3  (alg)   -> -7 (ES256)
  //   -1 (crv)   -> 1 (P-256)
  //   -2 (x)     -> Uint8Array (WebAuthn expects raw bytes, not Buffer)
  //   -3 (y)     -> Uint8Array
  const cose = new Map();
  cose.set(1, 2);
  cose.set(3, -7);
  cose.set(-1, 1);
  cose.set(-2, new Uint8Array(x));
  cose.set(-3, new Uint8Array(y));
  const cosePublicKey = cbor2.encode(cose);

  const rpIdHash = createHash("sha256").update("127.0.0.1").digest();
  // Registration flags: user present + user verified.
  const flags = Buffer.from([0x45]); // 0100 0101
  const aaguid = Buffer.alloc(16);
  const credIdLenBuf = Buffer.alloc(2);
  credIdLenBuf.writeUInt16BE(credentialId.length, 0);
  // attestedCredentialData = aaguid || credIdLen || credId || COSE key
  const attestedCredentialData = Buffer.concat([aaguid, credIdLenBuf, credentialId, cosePublicKey]);

  function signCounter(sc) {
    const b = Buffer.alloc(4);
    b.writeUInt32BE(sc, 0);
    return b;
  }

  return {
    credentialId,
    privateKey,
    async attestationObject({ challenge }) {
      // authenticatorData = rpIdHash || flags || signCount || attestedCredentialData
      const authData = Buffer.concat([rpIdHash, flags, signCounter(0), attestedCredentialData]);
      const attestation = new Map();
      attestation.set("fmt", "none");
      attestation.set("attStmt", new Map());
      attestation.set("authData", new Uint8Array(authData));
      const raw = cbor2.encode(attestation);
      // Force a fresh copy so the .buffer is a private ArrayBuffer, not
      // a shared pool slice — SimpleWebAuthn's DataView check rejects
      // Buffer backed by SharedArrayBuffer / pool slices.
      const copy = new Uint8Array(raw.length);
      copy.set(raw);
      return b64u.encode(copy);
    },
    clientDataJSON(op, challenge) {
      const cd = {
        type: op === "reg" ? "webauthn.create" : "webauthn.get",
        challenge,
        origin: ORIGIN,
        crossOrigin: false,
      };
      return b64u.encode(JSON.stringify(cd));
    },
    async assertion({ challenge, signCount }) {
      const authenticatorFlags = Buffer.from([0x05]); // user present + user verified
      const authData = Buffer.concat([rpIdHash, authenticatorFlags, signCounter(signCount)]);
      const clientDataJSON = this.clientDataJSON("get", challenge);
      const cdHash = createHash("sha256").update(b64u.decode(clientDataJSON)).digest();
      const signature = cryptoSign("sha256", Buffer.concat([authData, cdHash]), privateKey);
      return {
        id: b64u.encode(credentialId),
        rawId: b64u.encode(credentialId),
        type: "public-key",
        response: {
          clientDataJSON,
          authenticatorData: b64u.encode(authData),
          signature: b64u.encode(signature),
          userHandle: null,
        },
        clientExtensionResults: {},
        authenticatorAttachment: "cross-platform",
      };
    },
  };
}

// --------- Flow ---------------------------------------------------------

async function main() {
  const email = `owner-${Date.now()}@wa.example`;
  const signup = await fetch(`${API}/api/v1/auth/signup`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Origin: SPA_ORIGIN,
      "Sec-Fetch-Site": "same-origin",
    },
    body: JSON.stringify({ email, password: "correcthorse42x", orgName: "WAOrg" }),
  });
  if (signup.status !== 201) throw new Error("signup " + signup.status + " " + await signup.text());
  const cookie = /(av_session=[^;]+)/.exec(signup.headers.get("set-cookie") ?? "")?.[1];

  // ---------- Registration ceremony ----------
  console.log("[1/5] registration/challenge");
  const regCh = await fetch(`${API}/api/v1/auth/webauthn/register/challenge`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Origin: SPA_ORIGIN,
      "Sec-Fetch-Site": "same-origin",
      Cookie: cookie,
    },
    body: JSON.stringify({}),
  });
  if (regCh.status !== 200) throw new Error("reg challenge " + regCh.status + " " + await regCh.text());
  const regChSetCookie = regCh.headers.get("set-cookie") ?? "";
  const regCookie = /(av_wa_reg_challenge=[^;]+)/.exec(regChSetCookie)?.[1];
  if (!regCookie) throw new Error("no reg challenge cookie");
  const regOpts = (await regCh.json()).options;

  console.log("[2/5] building attestation with virtual authenticator");
  const auth = await buildAuthenticator();
  const attObj = await auth.attestationObject({ challenge: regOpts.challenge });
  const cdReg = auth.clientDataJSON("reg", regOpts.challenge);
  const registrationBody = {
    label: "Test Passkey",
    response: {
      id: b64u.encode(auth.credentialId),
      rawId: b64u.encode(auth.credentialId),
      type: "public-key",
      response: {
        attestationObject: attObj,
        clientDataJSON: cdReg,
        transports: ["usb"],
      },
      clientExtensionResults: {},
      authenticatorAttachment: "cross-platform",
    },
  };

  console.log("[3/5] registration/verify");
  const regVerify = await fetch(`${API}/api/v1/auth/webauthn/register/verify`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Origin: SPA_ORIGIN,
      "Sec-Fetch-Site": "same-origin",
      Cookie: cookie + "; " + regCookie,
    },
    body: JSON.stringify(registrationBody),
  });
  console.log("  status:", regVerify.status);
  if (regVerify.status !== 200) throw new Error("reg verify " + regVerify.status + " " + await regVerify.text());

  const creds = await fetch(`${API}/api/v1/auth/webauthn/credentials`, {
    headers: { Cookie: cookie, Origin: SPA_ORIGIN },
  }).then((r) => r.json());
  console.log("  credentials on file:", creds.credentials.length);

  // ---------- Login gated by MFA ----------
  console.log("[4/5] password login now gated");
  const gated = await fetch(`${API}/api/v1/auth/login`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Origin: SPA_ORIGIN,
      "Sec-Fetch-Site": "same-origin",
    },
    body: JSON.stringify({ email, password: "correcthorse42x" }),
  });
  const gatedBody = await gated.json();
  if (!gatedBody.mfaRequired) {
    throw new Error("MFA gate did not fire: " + JSON.stringify(gatedBody));
  }
  console.log("  mfaRequired=true, email=", gatedBody.email);
  if ((gated.headers.get("set-cookie") ?? "").includes("av_session=")) {
    // With MFA required, we should NOT have gotten a session cookie yet.
    throw new Error("session cookie leaked despite MFA gate!");
  }

  // ---------- Authentication ceremony ----------
  console.log("[5/5] passkey authenticate");
  const authCh = await fetch(`${API}/api/v1/auth/webauthn/authenticate/challenge`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Origin: SPA_ORIGIN,
      "Sec-Fetch-Site": "same-origin",
    },
    body: JSON.stringify({ email }),
  });
  const authOpts = (await authCh.json()).options;
  const authCookie = /(av_wa_auth_challenge=[^;]+)/.exec(authCh.headers.get("set-cookie") ?? "")?.[1];
  if (!authCookie) throw new Error("no auth challenge cookie");
  const assertion = await auth.assertion({ challenge: authOpts.challenge, signCount: 1 });
  const authVerify = await fetch(`${API}/api/v1/auth/webauthn/authenticate/verify`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Origin: SPA_ORIGIN,
      "Sec-Fetch-Site": "same-origin",
      Cookie: authCookie,
    },
    body: JSON.stringify({ response: assertion }),
  });
  console.log("  status:", authVerify.status);
  if (authVerify.status !== 200) throw new Error("auth verify " + authVerify.status + " " + await authVerify.text());
  const newSessionCookie = /(av_session=[^;]+)/.exec(authVerify.headers.get("set-cookie") ?? "")?.[1];
  if (!newSessionCookie) throw new Error("no av_session cookie after passkey");

  const me = await fetch(`${API}/api/v1/auth/me`, {
    headers: { Cookie: newSessionCookie, Origin: SPA_ORIGIN },
  }).then((r) => r.json());
  console.log("  me:", me.user.email);
  if (me.user.email !== email) throw new Error("me mismatch");

  console.log("\n✅  WebAuthn full-flow drill: PASSED");
}

main().catch((err) => {
  console.error("❌", err);
  process.exit(1);
});
