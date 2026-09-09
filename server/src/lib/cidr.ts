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
  const parts = cidr.split("/");
  // Exactly one slash: "10.0.0.0/0/24" used to destructure into
  // addr="10.0.0.0", prefix="0" — the trailing "/24" silently vanished
  // and the stored rule matched EVERYTHING (allow-all from a typo'd
  // row, the fail-open direction an allowlist must never take).
  if (parts.length !== 2) throw new Error("missing_prefix");
  const [addr, prefixStr] = parts;
  if (!addr || prefixStr === undefined) throw new Error("missing_prefix");
  // R203 F1: strict integer parse. Prior shape used
  // `parseInt(prefixStr, 10)` which returns:
  //   * NaN on "" / "abc" / whitespace-only — every subsequent
  //     comparison against NaN is false, so the range guards
  //     below silently pass and `parseCidr` returned a
  //     ParsedCidr with `prefix: NaN`.
  //   * A truncated integer on prefixes like "12abc" (parseInt
  //     stops at the first non-digit), which the range guard
  //     accepts too.
  // Downstream `tryParseCidr` folds the throw into null but only
  // when parseCidr THROWS — a NaN prefix returned quietly. The
  // ip-allowlist PATCH validator at org.ts:250 uses tryParseCidr
  // to decide whether the operator's proposed CIDR is legal;
  // NaN entries slipped past the validator and stored in DB as
  // silently-dead rules that could never match anyone
  // (ipInCidr's `BigInt(bits - NaN)` throws, ipMatchesAny's
  // try/catch swallows, returns false). The block comment at
  // org.ts:240 explicitly states "Reject any malformed CIDR —
  // never silently drop rows" — this restores that invariant.
  // Number(str.trim()) is strict full-string parse:
  //   Number("12abc") === NaN, Number("") === 0 (caught
  //   by the explicit empty-prefix check on the next
  //   statement — DO NOT remove it trusting this comment,
  //   see R203 F1 rationale below), Number(" 24") === 24
  //   (trim handles that case). Number.isInteger then
  //   rejects fractional / NaN / Infinity in one gate.
  const prefix = Number(prefixStr.trim());
  // R203 F1: also reject empty prefix (Number("") === 0, would
  // otherwise accept "1.2.3.4/" as /0 = match-anything — almost
  // certainly not what a fat-fingered operator meant).
  if (prefixStr.trim().length === 0) throw new Error("bad_prefix");
  if (!Number.isInteger(prefix)) throw new Error("bad_prefix");
  // Decimal digits only. Number() accepts hex/binary/octal literal
  // strings — "0x0" parsed to 0 and turned a malformed row into a /0
  // allow-all. A prefix is 1-3 decimal digits, nothing else.
  if (!/^\d{1,3}$/.test(prefixStr.trim())) throw new Error("bad_prefix");
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
 * Every (version, value) form a client address legitimately embodies.
 * IPv4-mapped IPv6 is detected NUMERICALLY (value inside ::ffff:0:0/96),
 * so `::FFFF:192.0.2.1` (case), `::ffff:c000:201` (hex groups) and
 * `::ffff:192.0.2.1` (dotted) all yield the same two forms. The old
 * string `startsWith("::ffff:")` strip made equivalent encodings of one
 * address take different allowlist decisions — and stripping DISCARDED
 * the v6 form, so a dotted mapped client failed a ::ffff:0:0/96 rule
 * the hex form matched. Symmetrically, a plain v4 client also gets its
 * mapped-v6 form so operators can write either rule family.
 */
const MAPPED_BASE = 0xffffn << 32n;
function clientForms(ip: string): { version: 4 | 6; value: bigint }[] {
  const version = isIP(ip);
  if (version === 4) {
    try {
      const v4 = ipv4ToBigInt(ip);
      return [
        { version: 4, value: v4 },
        { version: 6, value: MAPPED_BASE | v4 },
      ];
    } catch {
      return [];
    }
  }
  if (version === 6) {
    try {
      const v6 = ipv6ToBigInt(ip);
      const forms: { version: 4 | 6; value: bigint }[] = [{ version: 6, value: v6 }];
      if (v6 >> 32n === 0xffffn) {
        forms.push({ version: 4, value: v6 & 0xffffffffn });
      }
      return forms;
    } catch {
      return [];
    }
  }
  return [];
}

function formInCidr(form: { version: 4 | 6; value: bigint }, cidr: ParsedCidr): boolean {
  if (form.version !== cidr.version) return false;
  const bits = cidr.version === 4 ? 32 : 128;
  const shift = BigInt(bits - cidr.prefix);
  if (shift < 0n) return false;
  if (shift >= BigInt(bits)) return true; // /0 = match anything
  return (form.value >> shift) === (cidr.base >> shift);
}

/**
 * True if the given IP falls inside the CIDR.
 * Cross-family matches only via the IPv4-mapped equivalence
 * (see `clientForms`).
 */
export function ipInCidr(ip: string, cidr: ParsedCidr): boolean {
  return clientForms(ip).some((form) => formInCidr(form, cidr));
}

/**
 * Malformed allowlist rows already warned about, so the warn below
 * fires once per distinct value per process (bounded — a hostile flood
 * of distinct malformed rows is capped by the PATCH validator).
 */
const warnedMalformedCidrs = new Set<string>();

export function ipMatchesAny(ip: string, cidrs: string[]): boolean {
  if (cidrs.length === 0) return true; // empty = allow-all
  const forms = clientForms(ip);
  if (forms.length === 0) return false;
  for (const c of cidrs) {
    try {
      const parsed = parseCidr(c);
      if (forms.some((form) => formInCidr(form, parsed))) return true;
    } catch {
      // Malformed row — SKIPPED (fail-closed: it can allow nobody).
      // The PATCH validator refuses malformed inputs today, but rows
      // stored under older, laxer parsing (multi-slash, hex/exponent
      // prefixes — shapes that used to match EVERYTHING) go from
      // allow-all to inert at upgrade. That direction is correct; the
      // warn is the operational breadcrumb, because an org whose list
      // was ONLY such rows flips to deny-all and locks its operators
      // out of the console (recovery = fix the row in the DB).
      if (warnedMalformedCidrs.size < 1024 && !warnedMalformedCidrs.has(c)) {
        warnedMalformedCidrs.add(c);
        // eslint-disable-next-line no-console
        console.warn(
          `ip-allowlist: skipping malformed CIDR ${JSON.stringify(c)} — stored under older ` +
            "parsing rules; it matches nobody until corrected (PATCH /org/ip-allowlist)",
        );
      }
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
