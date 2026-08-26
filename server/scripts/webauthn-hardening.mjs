/**
 * WebAuthn hardening drills. Uses the same virtual authenticator as
 * webauthn-drill.mjs but drives 5 attack scenarios to prove the guards
 * fire.
 */

import { createHash, generateKeyPairSync, sign as cryptoSign } from "node:crypto";
import * as cbor2 from "cbor2";

const API = "http://127.0.0.1:4344";
const SPA_ORIGIN = "http://127.0.0.1:8988";
const ORIGIN = SPA_ORIGIN;

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

function buildAuthenticator() {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const credentialId = Buffer.from(Array.from({ length: 32 }, () => Math.floor(Math.random() * 256)));
  const spki = publicKey.export({ format: "der", type: "spki" });
  const rawPub = spki.slice(spki.length - 65);
  const x = rawPub.slice(1, 33);
  const y = rawPub.slice(33, 65);
  const cose = new Map();
  cose.set(1, 2); cose.set(3, -7); cose.set(-1, 1);
  cose.set(-2, new Uint8Array(x)); cose.set(-3, new Uint8Array(y));
  const cosePublicKey = cbor2.encode(cose);
  const rpIdHash = createHash("sha256").update("127.0.0.1").digest();
  const flags = Buffer.from([0x45]);
  const aaguid = Buffer.alloc(16);
  const credIdLen = Buffer.alloc(2); credIdLen.writeUInt16BE(credentialId.length, 0);
  const attested = Buffer.concat([aaguid, credIdLen, credentialId, cosePublicKey]);

  function counterBuf(sc) { const b = Buffer.alloc(4); b.writeUInt32BE(sc, 0); return b; }

  return {
    credentialId,
    privateKey,
    async attestationObject({ tampered = false }) {
      const authData = Buffer.concat([rpIdHash, flags, counterBuf(0), attested]);
      if (tampered) authData[10] = (authData[10] ?? 0) ^ 0x55; // flip a byte in flags/signcount area
      const att = new Map();
      att.set("fmt", "none");
      att.set("attStmt", new Map());
      att.set("authData", new Uint8Array(authData));
      const raw = cbor2.encode(att);
      const copy = new Uint8Array(raw.length); copy.set(raw);
      return b64u.encode(copy);
    },
    clientDataJSON(op, challenge) {
      return b64u.encode(JSON.stringify({
        type: op === "reg" ? "webauthn.create" : "webauthn.get",
        challenge, origin: ORIGIN, crossOrigin: false,
      }));
    },
    async assertion({ challenge, signCount, key = privateKey }) {
      const authenticatorFlags = Buffer.from([0x05]);
      const authData = Buffer.concat([rpIdHash, authenticatorFlags, counterBuf(signCount)]);
      const clientDataJSON = this.clientDataJSON("get", challenge);
      const cdHash = createHash("sha256").update(b64u.decode(clientDataJSON)).digest();
      const signature = cryptoSign("sha256", Buffer.concat([authData, cdHash]), key);
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

async function signup(email) {
  const res = await fetch(`${API}/api/v1/auth/signup`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Origin: SPA_ORIGIN, "Sec-Fetch-Site": "same-origin" },
    body: JSON.stringify({ email, password: "correcthorse42x", orgName: "HardOrg" }),
  });
  if (res.status !== 201) throw new Error("signup " + res.status);
  const cookie = /(av_session=[^;]+)/.exec(res.headers.get("set-cookie") ?? "")?.[1];
  return { cookie };
}

async function registerCredential(cookie, auth) {
  const ch = await fetch(`${API}/api/v1/auth/webauthn/register/challenge`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json", Origin: SPA_ORIGIN,
      "Sec-Fetch-Site": "same-origin", Cookie: cookie,
    },
    body: JSON.stringify({}),
  });
  const regCookie = /(av_wa_reg_challenge=[^;]+)/.exec(ch.headers.get("set-cookie") ?? "")?.[1];
  const opts = (await ch.json()).options;
  const attObj = await auth.attestationObject({});
  const cdReg = auth.clientDataJSON("reg", opts.challenge);
  const body = {
    label: "hard drill",
    response: {
      id: b64u.encode(auth.credentialId),
      rawId: b64u.encode(auth.credentialId),
      type: "public-key",
      response: { attestationObject: attObj, clientDataJSON: cdReg, transports: ["usb"] },
      clientExtensionResults: {},
    },
  };
  const verify = await fetch(`${API}/api/v1/auth/webauthn/register/verify`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json", Origin: SPA_ORIGIN,
      "Sec-Fetch-Site": "same-origin", Cookie: cookie + "; " + regCookie,
    },
    body: JSON.stringify(body),
  });
  return { status: verify.status, body: await verify.text() };
}

async function main() {
  const results = [];

  // ============ 1. Register without a challenge cookie ============
  console.log("\n[1] Register/verify without challenge cookie");
  const { cookie: aliceCookie } = await signup(`h1-${Date.now()}@wa-hard.example`);
  const aliceAuth = buildAuthenticator();
  // Get real challenge but drop the challenge cookie.
  const chRes = await fetch(`${API}/api/v1/auth/webauthn/register/challenge`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json", Origin: SPA_ORIGIN,
      "Sec-Fetch-Site": "same-origin", Cookie: aliceCookie,
    },
    body: JSON.stringify({}),
  });
  const opts = (await chRes.json()).options;
  const attObj = await aliceAuth.attestationObject({});
  const cdReg = aliceAuth.clientDataJSON("reg", opts.challenge);
  const withoutCookie = await fetch(`${API}/api/v1/auth/webauthn/register/verify`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json", Origin: SPA_ORIGIN,
      "Sec-Fetch-Site": "same-origin", Cookie: aliceCookie, // NO av_wa_reg_challenge cookie
    },
    body: JSON.stringify({
      label: "no-ch",
      response: {
        id: b64u.encode(aliceAuth.credentialId),
        rawId: b64u.encode(aliceAuth.credentialId),
        type: "public-key",
        response: { attestationObject: attObj, clientDataJSON: cdReg, transports: ["usb"] },
        clientExtensionResults: {},
      },
    }),
  });
  results.push({ drill: "no-challenge-cookie", status: withoutCookie.status, expect: 400, body: (await withoutCookie.text()).slice(0, 80) });

  // ============ 2. Tampered attestation ============
  console.log("[2] Tampered attestation");
  const chRes2 = await fetch(`${API}/api/v1/auth/webauthn/register/challenge`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Origin: SPA_ORIGIN, "Sec-Fetch-Site": "same-origin", Cookie: aliceCookie },
    body: JSON.stringify({}),
  });
  const reg2Cookie = /(av_wa_reg_challenge=[^;]+)/.exec(chRes2.headers.get("set-cookie") ?? "")?.[1];
  const opts2 = (await chRes2.json()).options;
  const tamperedAtt = await aliceAuth.attestationObject({ tampered: true });
  const cd2 = aliceAuth.clientDataJSON("reg", opts2.challenge);
  const tampered = await fetch(`${API}/api/v1/auth/webauthn/register/verify`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Origin: SPA_ORIGIN, "Sec-Fetch-Site": "same-origin", Cookie: aliceCookie + "; " + reg2Cookie },
    body: JSON.stringify({
      label: "tampered",
      response: {
        id: b64u.encode(aliceAuth.credentialId),
        rawId: b64u.encode(aliceAuth.credentialId),
        type: "public-key",
        response: { attestationObject: tamperedAtt, clientDataJSON: cd2, transports: ["usb"] },
        clientExtensionResults: {},
      },
    }),
  });
  results.push({ drill: "tampered-attestation", status: tampered.status, expect: 400 });

  // For steps 3-4 we need a valid registered credential.
  console.log("[3.pre] Registering valid credential");
  const good = await registerCredential(aliceCookie, aliceAuth);
  if (good.status !== 200) throw new Error("baseline register failed: " + good.body);

  // ============ 3. Assertion signed by different key ============
  console.log("[3] Wrong signer");
  const email3 = `h1-${Date.now()}@wa-hard.example`;
  // Use alice's account so the credential lookup succeeds; sign with an
  // unrelated keypair.
  const start3 = await fetch(`${API}/api/v1/auth/webauthn/authenticate/challenge`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Origin: SPA_ORIGIN, "Sec-Fetch-Site": "same-origin" },
    body: JSON.stringify({ email: (await (await fetch(`${API}/api/v1/auth/me`, { headers: { Cookie: aliceCookie, Origin: SPA_ORIGIN } })).json()).user.email }),
  });
  const authCookie3 = /(av_wa_auth_challenge=[^;]+)/.exec(start3.headers.get("set-cookie") ?? "")?.[1];
  const opts3 = (await start3.json()).options;
  const attackerAuth = buildAuthenticator();
  attackerAuth.credentialId = aliceAuth.credentialId; // Use victim's credential ID
  const badAssertion = await aliceAuth.assertion({
    challenge: opts3.challenge,
    signCount: 5,
    key: attackerAuth.privateKey, // Sign with attacker's key
  });
  const wrongSigner = await fetch(`${API}/api/v1/auth/webauthn/authenticate/verify`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Origin: SPA_ORIGIN, "Sec-Fetch-Site": "same-origin", Cookie: authCookie3 },
    body: JSON.stringify({ response: badAssertion }),
  });
  results.push({ drill: "wrong-signer", status: wrongSigner.status, expect: 400 });

  // ============ 4. Counter regression -> clone_detected ============
  console.log("[4] Counter regression");
  // First successful auth with signCount = 5
  const start4a = await fetch(`${API}/api/v1/auth/webauthn/authenticate/challenge`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Origin: SPA_ORIGIN, "Sec-Fetch-Site": "same-origin" },
    body: JSON.stringify({ email: (await (await fetch(`${API}/api/v1/auth/me`, { headers: { Cookie: aliceCookie, Origin: SPA_ORIGIN } })).json()).user.email }),
  });
  const authCookie4a = /(av_wa_auth_challenge=[^;]+)/.exec(start4a.headers.get("set-cookie") ?? "")?.[1];
  const opts4a = (await start4a.json()).options;
  const goodAssertion = await aliceAuth.assertion({ challenge: opts4a.challenge, signCount: 5 });
  const ok4 = await fetch(`${API}/api/v1/auth/webauthn/authenticate/verify`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Origin: SPA_ORIGIN, "Sec-Fetch-Site": "same-origin", Cookie: authCookie4a },
    body: JSON.stringify({ response: goodAssertion }),
  });
  console.log("  baseline auth (sc=5):", ok4.status);
  // Now try with sc = 3 (regression)
  const start4b = await fetch(`${API}/api/v1/auth/webauthn/authenticate/challenge`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Origin: SPA_ORIGIN, "Sec-Fetch-Site": "same-origin" },
    body: JSON.stringify({ email: (await (await fetch(`${API}/api/v1/auth/me`, { headers: { Cookie: aliceCookie, Origin: SPA_ORIGIN } })).json()).user.email }),
  });
  const authCookie4b = /(av_wa_auth_challenge=[^;]+)/.exec(start4b.headers.get("set-cookie") ?? "")?.[1];
  const opts4b = (await start4b.json()).options;
  const regressed = await aliceAuth.assertion({ challenge: opts4b.challenge, signCount: 3 });
  const clone = await fetch(`${API}/api/v1/auth/webauthn/authenticate/verify`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Origin: SPA_ORIGIN, "Sec-Fetch-Site": "same-origin", Cookie: authCookie4b },
    body: JSON.stringify({ response: regressed }),
  });
  const cloneBody = await clone.text();
  results.push({ drill: "clone-detected", status: clone.status, expect: 400, body: cloneBody.slice(0, 100) });

  // ============ 5. CRUD IDOR ============
  console.log("[5] CRUD IDOR");
  // Bob signs up in another org
  const { cookie: bobCookie } = await signup(`bob-${Date.now()}@wa-hard.example`);
  // Look up alice's credential id
  const aliceCreds = (await (await fetch(`${API}/api/v1/auth/webauthn/credentials`, {
    headers: { Cookie: aliceCookie, Origin: SPA_ORIGIN },
  })).json()).credentials;
  const targetId = aliceCreds[0].id;
  const bobRevoke = await fetch(`${API}/api/v1/auth/webauthn/credentials/${targetId}`, {
    method: "DELETE",
    headers: { Cookie: bobCookie, Origin: SPA_ORIGIN, "Sec-Fetch-Site": "same-origin" },
  });
  results.push({ drill: "cred-idor-delete", status: bobRevoke.status, expect: 404 });
  const bobRename = await fetch(`${API}/api/v1/auth/webauthn/credentials/${targetId}`, {
    method: "PATCH",
    headers: {
      "Content-Type": "application/json", Cookie: bobCookie, Origin: SPA_ORIGIN, "Sec-Fetch-Site": "same-origin",
    },
    body: JSON.stringify({ label: "hijacked" }),
  });
  results.push({ drill: "cred-idor-patch", status: bobRename.status, expect: 404 });

  // Print
  console.log("\n============ RESULTS ============");
  let allPass = true;
  for (const r of results) {
    const ok = r.status === r.expect;
    if (!ok) allPass = false;
    console.log(`${ok ? "✅" : "❌"} ${r.drill}: got ${r.status}, expected ${r.expect}${r.body ? " — " + r.body : ""}`);
  }
  if (!allPass) process.exit(1);
  console.log("\n✅  All WebAuthn hardening drills PASSED");
}

main().catch((err) => {
  console.error("❌", err);
  process.exit(1);
});
