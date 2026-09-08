/**
 * Unicode-safe truncation (round 117).
 *
 * `s.slice(0, n)` counts UTF-16 code units, so a cap landing between
 * the halves of a surrogate pair (any emoji, and all astral-plane CJK)
 * strands a lone high surrogate at the end. Lone surrogates cannot be
 * encoded as UTF-8: every downstream boundary (Postgres via the driver,
 * outbound webhook JSON to Slack/Teams, log sinks) silently replaces
 * them with U+FFFD — persistent, checksummed corruption from what
 * looked like an innocent length cap.
 *
 * This trims the dangling half instead, yielding a well-formed string
 * of at most `n` code units with no replacement characters.
 */
export function truncateWellFormed(s: string, n: number): string {
  if (s.length <= n) return s;
  let cut = s.slice(0, n);
  const last = cut.charCodeAt(cut.length - 1);
  // High surrogate left without its partner → drop it.
  if (last >= 0xd800 && last <= 0xdbff) cut = cut.slice(0, -1);
  return cut;
}
