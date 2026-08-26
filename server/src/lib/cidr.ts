/**
 * IPv4 + IPv6 CIDR matching for the per-org IP allowlist.
 *
 * Kept dependency-free so we don't have to trust a third-party module
 * for a security-critical decision. The algorithm:
 *
 *   1. Parse "a.b.c.d/n" -> BigInt address + prefix.
 *   2. Parse the client IP into a BigInt.
 *   3. Check `(client XOR base) >> (bits - prefix) === 0n`.
 *
 * IPv4 and IPv6 use different bit widths (32 vs 128). We normalize
 * so both are Uint128-ish BigInts.
 */
import { isIP } from "node:net";

export interface ParsedCidr {
  version: 4 | 6;
  base: bigint;
  prefix: number;
}

function ipv4ToBigInt(ip: string): bigint {
  const parts = ip.split(".");
  if (parts.length !== 4) throw new Error("bad_ipv4");
  let out = 0n;
  for (const p of parts) {
    const n = parseInt(p, 10);
    if (isNaN(n) || n < 0 || n > 255) throw new Error("bad_ipv4");
    out = (out << 8n) | BigInt(n);
  }
  return out;
}

function ipv6ToBigInt(ip: string): bigint {
  // Handle IPv4-mapped IPv6 like ::ffff:127.0.0.1
  if (ip.includes(".")) {
    const idx = ip.lastIndexOf(":");
    const v6part = ip.slice(0, idx + 1);
    const v4part = ip.slice(idx + 1);
    const v4 = ipv4ToBigInt(v4part);
    ip = v6part + ((Number(v4 >> 16n) & 0xffff).toString(16)) + ":" + ((Number(v4) & 0xffff).toString(16));
  }
  // Split on ::
  const dblIdx = ip.indexOf("::");
  let head: string[] = [];
  let tail: string[] = [];
  if (dblIdx >= 0) {
    head = ip.slice(0, dblIdx).split(":").filter(Boolean);
    tail = ip.slice(dblIdx + 2).split(":").filter(Boolean);
  } else {
    head = ip.split(":");
  }
  const zeros = 8 - head.length - tail.length;
  if (zeros < 0) throw new Error("bad_ipv6");
  const groups = [...head, ...Array(zeros).fill("0"), ...tail];
  if (groups.length !== 8) throw new Error("bad_ipv6");
  let out = 0n;
  for (const g of groups) {
    const n = parseInt(g, 16);
    if (isNaN(n) || n < 0 || n > 0xffff) throw new Error("bad_ipv6");
    out = (out << 16n) | BigInt(n);
  }
  return out;
}

export function parseCidr(cidr: string): ParsedCidr {
  const [addr, prefixStr] = cidr.split("/");
  if (!addr || prefixStr === undefined) throw new Error("missing_prefix");
  const prefix = parseInt(prefixStr, 10);
  const version = isIP(addr);
  if (version === 4) {
    if (prefix < 0 || prefix > 32) throw new Error("bad_prefix");
    return { version: 4, base: ipv4ToBigInt(addr), prefix };
  }
  if (version === 6) {
    if (prefix < 0 || prefix > 128) throw new Error("bad_prefix");
    return { version: 6, base: ipv6ToBigInt(addr), prefix };
  }
  throw new Error("bad_ip");
}

/**
 * True if the given IP falls inside the CIDR.
 * IP version mismatch is a fast false — no cross-family matches.
 */
export function ipInCidr(ip: string, cidr: ParsedCidr): boolean {
  const clientVersion = isIP(ip);
  if (clientVersion === 0) return false;
  // Cross-family: v4 IP can still match a v6 CIDR that's actually a
  // v4-mapped range like ::ffff:0:0/96. Simpler: convert v4-in-v6
  // sentinels back to plain v4 when needed. For now, require exact
  // family match — RFC 4291 says v4 should be tested with v4 CIDRs.
  if (clientVersion !== cidr.version) return false;
  let clientBig: bigint;
  try {
    clientBig = cidr.version === 4 ? ipv4ToBigInt(ip) : ipv6ToBigInt(ip);
  } catch {
    return false;
  }
  const bits = cidr.version === 4 ? 32 : 128;
  const shift = BigInt(bits - cidr.prefix);
  if (shift < 0n) return false;
  if (shift >= BigInt(bits)) return true; // /0 = match anything
  return (clientBig >> shift) === (cidr.base >> shift);
}

export function ipMatchesAny(ip: string, cidrs: string[]): boolean {
  if (cidrs.length === 0) return true; // empty = allow-all
  // Normalize v4-mapped v6 like ::ffff:1.2.3.4 into 1.2.3.4 for
  // matching against v4 CIDRs (common on dual-stack listeners).
  let ipToMatch = ip;
  if (ip.startsWith("::ffff:")) {
    const stripped = ip.slice("::ffff:".length);
    if (isIP(stripped) === 4) ipToMatch = stripped;
  }
  for (const c of cidrs) {
    try {
      if (ipInCidr(ipToMatch, parseCidr(c))) return true;
    } catch {
      // Malformed row in DB — skip. PATCH refuses malformed inputs so
      // this shouldn't happen in practice.
    }
  }
  return false;
}

/**
 * Try to parse a CIDR; return null on any error rather than throw.
 * Used by PATCH validation to give the operator a clean error message.
 */
export function tryParseCidr(cidr: string): ParsedCidr | null {
  try { return parseCidr(cidr); } catch { return null; }
}
