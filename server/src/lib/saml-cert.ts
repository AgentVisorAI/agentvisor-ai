/**
 * Self-signed X.509 cert generation for our SAML SP.
 *
 * Node's built-in crypto can produce keypairs but not X.509 certs
 * directly. We hand-build a minimal, spec-conformant DER cert wrapping
 * the SP public key, then base64-encode into PEM.
 *
 * Why not add a heavy `node-forge` dep just for this? Because we already
 * have `xml-crypto` (transitive from @node-saml) which ships the exact
 * primitives we need — sha256 hashing and RSA sign. Node's `crypto`
 * covers the rest.
 *
 * The cert has:
 *   • Issuer = Subject (self-signed).
 *   • Subject CN = "AgentVisor SP for <configId>".
 *   • notBefore = now, notAfter = now + `days` (default 5 years).
 *   • Signature alg = sha256WithRSAEncryption.
 *   • Serial number = 128 random bits.
 *
 * That's the full toolkit for `SPSSODescriptor / KeyDescriptor` in SAML
 * metadata; nothing else is required by @node-saml or by common IdPs.
 */

import { createSign, randomBytes, type KeyObject } from "node:crypto";

interface CertOpts {
  subjectCN: string;
  days: number;
}

// ============================================================================
// Minimal DER encoder — enough to construct an X.509 v3 cert.
// ============================================================================

function encLen(n: number): Buffer {
  if (n < 0x80) return Buffer.from([n]);
  const bytes: number[] = [];
  let x = n;
  while (x > 0) {
    bytes.unshift(x & 0xff);
    x >>= 8;
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function tlv(tag: number, value: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), encLen(value.length), value]);
}

function seq(...children: Buffer[]): Buffer {
  return tlv(0x30, Buffer.concat(children));
}

function set(...children: Buffer[]): Buffer {
  return tlv(0x31, Buffer.concat(children));
}

function integer(n: Buffer): Buffer {
  // Prepend 0x00 if high bit of first byte is set (to keep it positive).
  const first = n[0] ?? 0;
  const buf = first & 0x80 ? Buffer.concat([Buffer.from([0]), n]) : n;
  return tlv(0x02, buf);
}

function oid(dotted: string): Buffer {
  const parts = dotted.split(".").map((x) => parseInt(x, 10));
  const p0 = parts[0] ?? 0;
  const p1 = parts[1] ?? 0;
  const bytes: number[] = [];
  bytes.push(40 * p0 + p1);
  for (let i = 2; i < parts.length; i++) {
    let v = parts[i] ?? 0;
    const stack: number[] = [v & 0x7f];
    v >>= 7;
    while (v > 0) {
      stack.unshift((v & 0x7f) | 0x80);
      v >>= 7;
    }
    bytes.push(...stack);
  }
  return tlv(0x06, Buffer.from(bytes));
}

function utf8String(s: string): Buffer {
  return tlv(0x0c, Buffer.from(s, "utf8"));
}

function printableString(s: string): Buffer {
  return tlv(0x13, Buffer.from(s, "ascii"));
}

function utcTime(d: Date): Buffer {
  // YYMMDDHHMMSSZ
  const pad = (n: number) => (n < 10 ? "0" + n : String(n));
  const yy = d.getUTCFullYear() % 100;
  const t = pad(yy) +
    pad(d.getUTCMonth() + 1) +
    pad(d.getUTCDate()) +
    pad(d.getUTCHours()) +
    pad(d.getUTCMinutes()) +
    pad(d.getUTCSeconds()) +
    "Z";
  return tlv(0x17, Buffer.from(t, "ascii"));
}

function bitString(inner: Buffer): Buffer {
  return tlv(0x03, Buffer.concat([Buffer.from([0]), inner]));
}

function contextConstructed(tag: number, inner: Buffer): Buffer {
  return tlv(0xa0 | tag, inner);
}

// ============================================================================
// Extract the DER SubjectPublicKeyInfo from Node's PEM export.
// ============================================================================

function extractSpki(publicKey: KeyObject): Buffer {
  // Node's SPKI export IS the DER SubjectPublicKeyInfo we want.
  return publicKey.export({ format: "der", type: "spki" }) as Buffer;
}

// ============================================================================
// The build.
// ============================================================================

export async function generateSelfSignedCert(
  privateKey: KeyObject,
  publicKey: KeyObject,
  opts: CertOpts,
): Promise<string> {
  // OIDs we need.
  const OID_RSA_SHA256 = "1.2.840.113549.1.1.11"; // sha256WithRSAEncryption
  const OID_COMMON_NAME = "2.5.4.3";

  // Subject / issuer name = single-attribute RDN with commonName = subjectCN.
  const name = seq(
    set(seq(oid(OID_COMMON_NAME), utf8String(opts.subjectCN))),
  );

  const notBefore = new Date();
  const notAfter = new Date(
    notBefore.getTime() + opts.days * 24 * 60 * 60 * 1000,
  );

  const validity = seq(utcTime(notBefore), utcTime(notAfter));

  const spki = extractSpki(publicKey);
  const version = contextConstructed(0, integer(Buffer.from([2]))); // v3

  const serial = integer(randomBytes(16));

  const sigAlg = seq(oid(OID_RSA_SHA256), tlv(0x05, Buffer.alloc(0))); // NULL

  // Extensions: basicConstraints=CA:FALSE, keyUsage = digitalSignature +
  // keyEncipherment, extendedKeyUsage = clientAuth (SP posts to IdP).
  const OID_BASIC_CONSTRAINTS = "2.5.29.19";
  const OID_KEY_USAGE = "2.5.29.15";
  const OID_EXT_KEY_USAGE = "2.5.29.37";
  const OID_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2";

  const basicConstraintsExt = seq(
    oid(OID_BASIC_CONSTRAINTS),
    tlv(0x01, Buffer.from([0xff])), // critical=true
    tlv(0x04, seq()), // OCTET STRING wrapping empty SEQUENCE (CA:FALSE)
  );
  // keyUsage bits: digitalSignature(0)=bit 7, keyEncipherment(2)=bit 5.
  // Encoded as BIT STRING with unused-bits count.
  const keyUsageExt = seq(
    oid(OID_KEY_USAGE),
    tlv(0x01, Buffer.from([0xff])), // critical
    tlv(0x04, tlv(0x03, Buffer.from([0x05, 0xa0]))), // OCTET String > BIT STRING(5 unused, 0xa0)
  );
  const extKeyUsageExt = seq(
    oid(OID_EXT_KEY_USAGE),
    tlv(0x04, seq(oid(OID_CLIENT_AUTH))),
  );
  const extensions = contextConstructed(
    3,
    seq(basicConstraintsExt, keyUsageExt, extKeyUsageExt),
  );

  // tbsCertificate.
  const tbs = seq(
    version,
    serial,
    sigAlg,
    name, // issuer
    validity,
    name, // subject (self)
    spki,
    extensions,
  );

  // Sign tbsCertificate with the private key using RSA-SHA256.
  const signer = createSign("RSA-SHA256");
  signer.update(tbs);
  const signature = signer.sign(privateKey);

  const cert = seq(tbs, sigAlg, bitString(signature));

  return derToPem(cert, "CERTIFICATE");
}

function derToPem(der: Buffer, label: string): string {
  const b64 = der.toString("base64");
  const chunks: string[] = [];
  for (let i = 0; i < b64.length; i += 64) chunks.push(b64.slice(i, i + 64));
  return (
    `-----BEGIN ${label}-----\n` +
    chunks.join("\n") +
    `\n-----END ${label}-----\n`
  );
}
