/**
 * Outbound webhook dispatcher.
 *
 * When a subscribable event happens (policy.block, session.blocked,
 * apikey.created, member.invited, etc.) the caller invokes
 * `dispatchEvent(orgId, event, payload)`. We:
 *
 *   1. Load every ACTIVE endpoint for that org whose `events` list
 *      includes the event name (or "*"). Zero endpoints — fast return.
 *   2. Serialize the payload once. Attach:
 *        X-AgentVisor-Event, X-AgentVisor-Delivery, X-AgentVisor-Timestamp,
 *        X-AgentVisor-Signature: sha256=<HMAC>
 *      The signature is over `${timestamp}.${body}` so a replay of an old
 *      captured request can't be re-sent hours later against the same
 *      endpoint.
 *   3. Record a WebhookDelivery row up front (status=pending) so the UI
 *      can show queued deliveries even if the process crashes before
 *      finishing.
 *   4. POST the body with a 5s timeout. On 2xx, mark delivered. On 5xx,
 *      timeout, or network error: bump attempt, schedule nextRetryAt at
 *      exp backoff (30s, 2m, 10m, 30m, 2h, then give up at attempt 6).
 *   5. On 4xx (client rejected): mark failed permanently — the endpoint
 *      is misconfigured and retrying won't fix that.
 *
 * Retries are driven by a lightweight in-process sweeper started once on
 * boot (`startWebhookSweeper()`). It scans for status='retrying' AND
 * nextRetryAt < now() every 15s. That keeps the delivery pipeline
 * self-healing without needing a queue broker for the demo tier;
 * production deployments would swap in Sidekiq / BullMQ.
 */
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { truncateWellFormed } from "./strings.js";
import { isIP } from "node:net";
import { promises as dns } from "node:dns";
import { Agent, fetch as undiciFetch } from "undici";
import type { FastifyBaseLogger } from "fastify";
import { db } from "../db.js";
import { env } from "../env.js";
import { formatForAdapter, pickAdapter } from "./webhook-adapters.js";

const MAX_ATTEMPT = 6;
const BACKOFF_SECONDS = [30, 120, 600, 1800, 7200];
const DELIVERY_TIMEOUT_MS = 5000;
// Claim lease for in-flight rows. A delivery sits in status='pending'
// only while a deliverOne is actively executing — bounded by
// DELIVERY_TIMEOUT_MS (5 s) plus small overhead — so a 'pending' row
// whose lease expired belongs to a process that died (SIGTERM during a
// rolling deploy, crash, dropped microtask) between claiming the row
// and writing its terminal status. Without the lease those rows were
// orphaned FOREVER: the sweeper only re-scans status='retrying', so a
// claimed-but-never-delivered row was silent permanent delivery loss —
// contradicting the "self-healing without a queue broker" contract in
// the module docstring. 5 min = 60× the in-flight bound; generous
// enough that a legitimately-executing delivery can never be
// double-claimed, tight enough that a lost delivery retries within
// minutes. Keep the SQL interval in the sweeper's claim query in sync.
const PENDING_LEASE_MS = 5 * 60 * 1000;

/**
 * SSRF guard — refuse to send outbound requests to internal / metadata
 * / link-local / loopback / RFC-1918 destinations.
 *
 * In production we're strict: any private-range IP fails validation.
 * The cloud metadata endpoints (AWS 169.254.169.254, GCP
 * metadata.google.internal, Azure 169.254.169.254) are the most
 * dangerous — a compromised operator could otherwise register a
 * webhook that exfiltrates instance-role credentials.
 *
 * R185 F1: non-production modes are ALSO default-strict — private-range
 * / metadata / loopback / link-local destinations are refused unless the
 * operator explicitly opts in via `ALLOW_INTERNAL_WEBHOOK_TARGETS=true`.
 * Prior shape fell open when NODE_ENV was unset or "development"/"test",
 * so an unattended dev-mode deploy was a silent SSRF primitive. The env
 * opt-in is what makes local-receiver testing possible without disabling
 * the guard entirely.
 */
const BLOCKED_HOSTS_ALWAYS = new Set([
  "metadata.google.internal",
  "metadata.goog",
  "169.254.169.254",
  "fd00:ec2::254",
  "instance-data",
]);

// R86 F1: parse an IPv6 hostname into its 16 raw bytes so we can
// check for private / metadata prefixes across ALL forms —
// dotted-quad `::ffff:169.254.169.254`, pure-hex `::ffff:a9fe:a9fe`,
// expanded `0:0:0:0:0:ffff:169.254.169.254`, 6to4 tunnel
// `2002:a9fe:a9fe::`, NAT64 well-known prefix `64:ff9b::a9fe:a9fe`.
// R85 F1's regex-based unmap only caught the dotted-quad form; the
// pure-hex, 6to4, and NAT64 forms all escaped. On dual-stack Linux
// (default), GKE dual-stack, EKS IPv6-only, and AKS CNI Overlay
// the kernel routes 6to4/NAT64 addresses transparently to their
// embedded IPv4 quad, so IMDS (`169.254.169.254`) was reachable
// via any of the escaped forms. Returns null if not a well-formed
// IPv6.
function parseIPv6Bytes(ip: string): Uint8Array | null {
  const lc = ip.toLowerCase();
  // Handle embedded IPv4 quad tail (::ffff:1.2.3.4, ::1.2.3.4).
  const dotted = lc.match(/(.*:)(\d+\.\d+\.\d+\.\d+)$/);
  let normalized = lc;
  if (dotted) {
    const parts = dotted[2]!.split(".").map((s) => parseInt(s, 10));
    if (parts.length !== 4 || parts.some((n) => isNaN(n) || n < 0 || n > 255)) {
      return null;
    }
    const hi = ((parts[0]! << 8) | parts[1]!).toString(16);
    const lo = ((parts[2]! << 8) | parts[3]!).toString(16);
    normalized = dotted[1]! + hi + ":" + lo;
  }
  // Expand `::` into the right number of zero groups.
  const halves = normalized.split("::");
  if (halves.length > 2) return null;
  let groups: string[];
  if (halves.length === 2) {
    const left = halves[0]!.length ? halves[0]!.split(":") : [];
    const right = halves[1]!.length ? halves[1]!.split(":") : [];
    const zeros = 8 - left.length - right.length;
    if (zeros < 0) return null;
    groups = [...left, ...Array(zeros).fill("0"), ...right];
  } else {
    groups = normalized.split(":");
  }
  if (groups.length !== 8) return null;
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    if (!/^[0-9a-f]{1,4}$/.test(groups[i]!)) return null;
    const n = parseInt(groups[i]!, 16);
    bytes[i * 2] = (n >> 8) & 0xff;
    bytes[i * 2 + 1] = n & 0xff;
  }
  return bytes;
}

function isBlockedIp(ip: string): boolean {
  // R86 F1: IPv6 rules — parse to raw bytes and check
  // (a) IPv4-mapped `::ffff:X.X.X.X` (any encoding)
  // (b) 6to4 tunnel `2002::/16` (embedded IPv4 in bytes 2-5)
  // (c) NAT64 well-known prefix `64:ff9b::/96` (embedded quad in bytes 12-15)
  // (d) loopback `::1`, unspecified `::`
  // (e) link-local `fe80::/10`, unique-local `fc00::/7`
  if (isIP(ip) === 6) {
    const b = parseIPv6Bytes(ip);
    if (!b) return true; // unparseable → treat as suspicious
    let allZero = true;
    for (let i = 0; i < 15; i++) if (b[i] !== 0) { allZero = false; break; }
    if (allZero && b[15] === 0) return true; // ::
    if (allZero && b[15] === 1) return true; // ::1
    // (a) ::ffff:0:0/96 IPv4-mapped — recurse into IPv4 rules on the embedded quad
    let mappedZero = true;
    for (let i = 0; i < 10; i++) if (b[i] !== 0) { mappedZero = false; break; }
    if (mappedZero && b[10] === 0xff && b[11] === 0xff) {
      return isBlockedIp(`${b[12]}.${b[13]}.${b[14]}.${b[15]}`);
    }
    // (b) 2002::/16 6to4 — embedded IPv4 in bytes 2-5
    if (b[0] === 0x20 && b[1] === 0x02) {
      return isBlockedIp(`${b[2]}.${b[3]}.${b[4]}.${b[5]}`);
    }
    // (c) 64:ff9b::/96 NAT64 WKP (RFC 6052) — embedded IPv4 in bytes 12-15
    if (b[0] === 0x00 && b[1] === 0x64 && b[2] === 0xff && b[3] === 0x9b) {
      let allZeroMid = true;
      for (let i = 4; i < 12; i++) if (b[i] !== 0) { allZeroMid = false; break; }
      if (allZeroMid) {
        return isBlockedIp(`${b[12]}.${b[13]}.${b[14]}.${b[15]}`);
      }
    }
    // (e) fe80::/10 link-local
    if (b[0]! === 0xfe && (b[1]! & 0xc0) === 0x80) return true;
    // (e) fc00::/7 unique-local
    if ((b[0]! & 0xfe) === 0xfc) return true;
    return false;
  }
  // IPv4
  const parts = ip.split(".").map((n) => parseInt(n, 10));
  if (parts.length !== 4 || parts.some((n) => isNaN(n))) return true;
  const [a = 0, b = 0] = parts;
  if (a === 10) return true;                 // 10.0.0.0/8
  if (a === 127) return true;                // 127.0.0.0/8
  if (a === 169 && b === 254) return true;   // 169.254.0.0/16 (link-local + metadata)
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
  if (a === 192 && b === 168) return true;   // 192.168.0.0/16
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT 100.64.0.0/10
  if (a === 0) return true;                  // 0.0.0.0/8
  return false;
}

// R86 F1: normalize any IPv6 encoding that carries an embedded
// IPv4 quad down to that quad, so exact-match metadata blocks
// catch every encoding of 169.254.169.254 (dotted-quad mapped,
// pure-hex mapped, 6to4, NAT64). Returns the original string for
// non-embedded addresses.
function unmapV4(ip: string): string {
  if (isIP(ip) !== 6) return ip;
  const b = parseIPv6Bytes(ip);
  if (!b) return ip;
  // Mapped `::ffff:X.X.X.X`
  let mappedZero = true;
  for (let i = 0; i < 10; i++) if (b[i] !== 0) { mappedZero = false; break; }
  if (mappedZero && b[10] === 0xff && b[11] === 0xff) {
    return `${b[12]}.${b[13]}.${b[14]}.${b[15]}`;
  }
  // 6to4 `2002:X.X:X.X::`
  if (b[0] === 0x20 && b[1] === 0x02) {
    return `${b[2]}.${b[3]}.${b[4]}.${b[5]}`;
  }
  // NAT64 `64:ff9b::X.X.X.X`
  if (b[0] === 0x00 && b[1] === 0x64 && b[2] === 0xff && b[3] === 0x9b) {
    let allZeroMid = true;
    for (let i = 4; i < 12; i++) if (b[i] !== 0) { allZeroMid = false; break; }
    if (allZeroMid) return `${b[12]}.${b[13]}.${b[14]}.${b[15]}`;
  }
  return ip;
}

export interface SsrfCheckResult {
  ok: boolean;
  reason?: string;
}

export async function validateWebhookUrl(rawUrl: string): Promise<SsrfCheckResult> {
  let u: URL;
  try {
    u = new URL(rawUrl);
  } catch {
    return { ok: false, reason: "invalid_url" };
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") {
    return { ok: false, reason: "unsupported_scheme" };
  }
  const host = u.hostname.toLowerCase();
  if (BLOCKED_HOSTS_ALWAYS.has(host)) {
    return { ok: false, reason: "blocked_metadata_host" };
  }
  // Explicit IP literal — check directly. This is the most common attack
  // vector because it dodges DNS resolution.
  if (isIP(host)) {
    // R85 F1: normalize IPv4-mapped IPv6 (`::ffff:169.254.169.254`)
    // to `169.254.169.254` so the metadata literal check catches
    // the mapped form (dual-stack Linux transparently routes to
    // the IPv4 address).
    const canonHost = unmapV4(host);
    // Metadata (169.254.169.254) is *always* refused, even in dev —
    // there's no legitimate reason a webhook target would live there.
    if (canonHost === "169.254.169.254" || canonHost === "fd00:ec2::254") {
      return { ok: false, reason: "blocked_metadata_ip" };
    }
    if (env.NODE_ENV === "production" && isBlockedIp(host)) {
      return { ok: false, reason: "private_ip_blocked" };
    }
    // R185 F1: block internal IPs in ALL non-production modes too
    // unless explicitly opted out via ALLOW_INTERNAL_WEBHOOK_TARGETS.
    // Prior shape (production-only) fell open when NODE_ENV was
    // unset or set to "development"/"test" — an admin/owner in a
    // dev-mode deploy could register `http://10.0.0.1/admin` as a
    // webhook URL and the server would fetch it, SSRF into the
    // private network. R176 warns operators when NODE_ENV was
    // defaulted but the warning is soft; the SSRF-gate side needs
    // to fail-closed by default so an unattended dev-mode deploy
    // isn't a silent SSRF primitive.
    if (
      env.NODE_ENV !== "production" &&
      !env.ALLOW_INTERNAL_WEBHOOK_TARGETS &&
      isBlockedIp(host)
    ) {
      return { ok: false, reason: "private_ip_blocked_dev" };
    }
    return { ok: true };
  }
  // Hostname — resolve to A/AAAA and check every result. Attackers can
  // register a DNS name that points at 127.0.0.1 or a metadata IP; the
  // literal string 'evil.com' looks innocent but resolves to 169.254.169.254.
  try {
    const addrs = await dns.lookup(host, { all: true, verbatim: true });
    if (addrs.length === 0) return { ok: false, reason: "unresolvable" };
    if (env.NODE_ENV === "production") {
      for (const a of addrs) {
        if (isBlockedIp(a.address)) {
          return { ok: false, reason: "resolves_to_private_ip" };
        }
      }
    } else if (!env.ALLOW_INTERNAL_WEBHOOK_TARGETS) {
      // R185 F1: default-strict in non-production modes.
      // See the IP-literal branch above for rationale.
      for (const a of addrs) {
        if (isBlockedIp(a.address)) {
          return { ok: false, reason: "resolves_to_private_ip_dev" };
        }
      }
    }
  } catch {
    // In production, unresolvable == suspicious. In dev, tolerate it so
    // ephemeral test hosts don't break the flow.
    if (env.NODE_ENV === "production") {
      return { ok: false, reason: "dns_failed" };
    }
  }
  return { ok: true };
}

export function generateWebhookSecret(): string {
  return randomBytes(32).toString("hex");
}

export function signPayload(
  secret: string,
  timestamp: string,
  body: string,
): string {
  const h = createHmac("sha256", secret);
  h.update(timestamp);
  h.update(".");
  h.update(body);
  return "sha256=" + h.digest("hex");
}

// Consumers export this so their own verifiers can share logic.
export function verifySignature(
  secret: string,
  timestamp: string,
  body: string,
  signature: string,
): boolean {
  try {
    const expected = signPayload(secret, timestamp, body);
    const a = Buffer.from(expected);
    const b = Buffer.from(signature);
    if (a.length !== b.length) return false;
    return timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

interface DispatchOpts {
  orgId: string;
  event: string;
  data: Record<string, unknown>;
  // R94 F3: optional endpoint scoping. When set, ONLY the given
  // endpointId receives the dispatch — used by /:id/test so a
  // smoke test doesn't fan out to every unrelated subscriber
  // (Slack, PagerDuty, Datadog). Without it, a "Send test"
  // click on webhook A woke up on-call responders on webhook B.
  onlyEndpointId?: string;
  logger?: FastifyBaseLogger;
}

/**
 * Fan out `event` to every subscribed endpoint. Fire-and-forget — the
 * caller's response is never blocked by webhook I/O. Errors are logged
 * but never thrown to the caller.
 */
export function dispatchEvent(opts: DispatchOpts): void {
  void (async () => {
    try {
      // R94 F3: when scoping to a specific endpoint (the /:id/test
      // path), don't filter by the events array — the operator
      // explicitly clicked "Send test" on THIS endpoint. Without
      // this override, an endpoint that subscribes to
      // ["policy.block"] but not "test"/"*" would silently drop
      // its own test click.
      const endpoints = await db.webhookEndpoint.findMany({
        where: opts.onlyEndpointId
          ? {
              id: opts.onlyEndpointId,
              orgId: opts.orgId,
              isActive: true,
            }
          : {
              orgId: opts.orgId,
              isActive: true,
              OR: [{ events: { hasSome: [opts.event, "*"] } }],
            },
        select: { id: true, url: true, secret: true },
      });
      if (endpoints.length === 0) return;
      const envelope = {
        event: opts.event,
        createdAt: new Date().toISOString(),
        data: opts.data,
      };
      for (const ep of endpoints) {
        // Each endpoint might resolve to a different adapter (one org
        // could have Slack + Datadog + custom webhooks all subscribed).
        // Format per-endpoint so the signature is over what we actually
        // send.
        const adapter = pickAdapter(ep.url);
        const body = formatForAdapter(adapter, envelope);
        // R116 F2: attach .catch. deliverOne does DB writes BEFORE
        // entering its own try/catch (create the WebhookDelivery
        // row, SSRF/DNS re-check updates), so a concurrent
        // DELETE /:id (which cascades WebhookDelivery via the
        // onDelete: Cascade FK) can throw P2003/P2025 out of
        // deliverOne — the bare `void` prefix lets that rejection
        // become an unhandledRejection. Node 15+ throws on
        // unhandledRejection by default. Log at warn with the
        // endpointId so ops can correlate.
        void deliverOne(ep.id, ep.url, ep.secret, opts.event, body, 1, opts.logger).catch((err) => {
          opts.logger?.warn(
            { err, endpointId: ep.id, event: opts.event },
            "webhook_dispatch_deliverOne_rejected",
          );
        });
      }
    } catch (e) {
      opts.logger?.warn({ err: e, event: opts.event }, "webhook_dispatch_failed");
    }
  })();
}

/**
 * Read at most `maxBytes` of a fetch Response body, then cancel the
 * rest of the stream. Never throws — an abort/reset mid-body returns
 * whatever was collected. Used instead of `res.text()`, which buffers
 * the ENTIRE body and only resolves at end-of-stream: a hostile
 * endpoint could stream gigabytes (memory) or trickle bytes forever
 * (socket + delivery-loop stall) after a fast 200 header.
 */
async function readBodyCapped(
  res: {
    body: {
      getReader(): {
        read(): Promise<{ done: boolean; value?: Uint8Array }>;
        cancel(): Promise<unknown>;
      };
    } | null;
  },
  maxBytes: number,
): Promise<string> {
  if (!res.body) return "";
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (total < maxBytes) {
      const { done, value } = (await reader.read()) as {
        done: boolean;
        value?: Uint8Array;
      };
      if (done) break;
      if (value) {
        chunks.push(value);
        total += value.byteLength;
      }
    }
  } catch {
    // Partial body is fine — it's only used for the operator-facing
    // delivery log excerpt.
  } finally {
    // Cancel whatever the endpoint is still trying to send; ignore
    // failures (stream may already be closed/errored).
    await reader.cancel().catch(() => undefined);
  }
  const joined = Buffer.concat(
    chunks.map((c) => Buffer.from(c.buffer, c.byteOffset, c.byteLength)),
  );
  return joined.subarray(0, maxBytes).toString("utf8");
}

async function deliverOne(
  endpointId: string,
  url: string,
  secret: string,
  event: string,
  body: string,
  attempt: number,
  logger?: FastifyBaseLogger,
  existingDeliveryId?: string,
): Promise<void> {
  // On the first attempt, create a new WebhookDelivery row. On retries
  // driven by the sweeper, we reuse the existing row so the operator sees
  // one row per (event, endpoint) with an `attempt` counter that grows,
  // not one row per retry attempt.
  let deliveryId: string;
  if (existingDeliveryId) {
    deliveryId = existingDeliveryId;
    await db.webhookDelivery.update({
      where: { id: existingDeliveryId },
      // nextRetryAt doubles as the claim lease while status='pending'
      // (see PENDING_LEASE_MS): if this process dies mid-POST, the
      // sweeper reclaims the row after the lease instead of orphaning
      // it. Terminal updates (delivered / failed / scheduleRetry)
      // overwrite it.
      data: {
        attempt,
        status: "pending",
        nextRetryAt: new Date(Date.now() + PENDING_LEASE_MS),
      },
    });
  } else {
    const row = await db.webhookDelivery.create({
      data: {
        endpointId,
        event,
        payload: body,
        attempt,
        status: "pending",
        // First-attempt rows carry the same claim lease: a crash
        // between this create and the terminal update is reclaimed by
        // the sweeper rather than stuck 'pending' forever.
        nextRetryAt: new Date(Date.now() + PENDING_LEASE_MS),
      },
      select: { id: true },
    });
    deliveryId = row.id;
  }

  const timestamp = String(Math.floor(Date.now() / 1000));
  const sig = signPayload(secret, timestamp, body);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), DELIVERY_TIMEOUT_MS);

  // R77-defer-1 (landed R78): pin the resolved IP for THIS
  // delivery so the DNS-rebinding TOCTOU is closed entirely.
  // Prior R76 shape ran `validateWebhookUrl` immediately
  // before `fetch`, then let undici do ITS OWN independent
  // `getaddrinfo` — a fast-authoritative-rebind attacker could
  // flip the record between our lookup and undici's (ms-scale
  // window on a resolver that respects TTL=0). Now:
  //   1. Resolve every A/AAAA for the URL's hostname here.
  //   2. Refuse if any address is in the blocklist (metadata /
  //      RFC 1918 / loopback etc.) or if resolution failed.
  //   3. Build a one-shot `undici.Agent` whose `connect.lookup`
  //      returns the pre-vetted IP for THIS hostname; any
  //      other lookup call throws.
  //   4. Pass the Agent as the fetch `dispatcher`; TLS SNI
  //      still uses the URL's hostname (correct for cert
  //      validation), but the TCP connection goes to the
  //      pinned IP — the DNS record cannot be flipped between
  //      our check and undici's because undici's lookup IS
  //      our lookup.
  //   5. Close the Agent in the `finally` block so per-
  //      delivery Agents don't leak connection pool state.
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(url);
  } catch {
    clearTimeout(timer);
    await db.webhookDelivery.update({
      where: { id: deliveryId },
      data: {
        status: "failed",
        responseCode: 0,
        responseBody: "invalid webhook URL",
        errorMessage: "invalid_webhook_url",
        deliveredAt: new Date(),
      },
    });
    return;
  }
  const hostname = parsedUrl.hostname.toLowerCase();
  // Same enforcement contract as creation-time validateWebhookUrl and
  // the env flag's own doc ("block internal IPs in ALL modes,
  // including dev"): delivery-time re-checks previously gated on
  // NODE_ENV === "production" only, so a dev/staging deployment with
  // the default strict setting could pass creation with a public DNS
  // answer and then be rebound to 127.0.0.1/RFC1918 at delivery.
  const enforceSsrf = env.NODE_ENV === "production" || !env.ALLOW_INTERNAL_WEBHOOK_TARGETS;
  let pinnedAddr: { address: string; family: 4 | 6 } | null = null;
  if (isIP(hostname)) {
    // Literal IP — validateWebhookUrl already blocked private
    // and metadata IPs in `production`. Re-check here for
    // defence-in-depth and skip the DNS lookup.
    if (enforceSsrf && isBlockedIp(hostname)) {
      clearTimeout(timer);
      await db.webhookDelivery.update({
        where: { id: deliveryId },
        data: {
          status: "failed",
          responseCode: 0,
          responseBody: "SSRF re-check failed at delivery time: private_ip_blocked",
          errorMessage: "ssrf_private_ip_blocked",
          deliveredAt: new Date(),
        },
      });
      return;
    }
    if (hostname === "169.254.169.254" || hostname === "fd00:ec2::254" || unmapV4(hostname) === "169.254.169.254") {
      clearTimeout(timer);
      await db.webhookDelivery.update({
        where: { id: deliveryId },
        data: {
          status: "failed",
          responseCode: 0,
          responseBody: "SSRF re-check failed at delivery time: blocked_metadata_ip",
          errorMessage: "ssrf_blocked_metadata_ip",
          deliveredAt: new Date(),
        },
      });
      return;
    }
    pinnedAddr = { address: hostname, family: isIP(hostname) as 4 | 6 };
  } else {
    try {
      const addrs = await dns.lookup(hostname, { all: true, verbatim: true });
      if (addrs.length === 0) {
        throw new Error("unresolvable");
      }
      // Every returned address must be public whenever SSRF
      // enforcement is on (production, or any mode without the
      // explicit internal-targets opt-in).
      if (enforceSsrf) {
        for (const a of addrs) {
          if (isBlockedIp(a.address)) {
            throw new Error(`resolves_to_private_ip:${a.address}`);
          }
        }
      }
      // Pin the FIRST returned address. Any subsequent lookup for
      // this hostname (by undici) will return the same value —
      // no chance for a rebinding attacker to flip the record.
      pinnedAddr = { address: addrs[0]!.address, family: addrs[0]!.family as 4 | 6 };
    } catch (err) {
      clearTimeout(timer);
      const reason = err instanceof Error ? err.message : String(err);
      await db.webhookDelivery.update({
        where: { id: deliveryId },
        data: {
          status: "failed",
          responseCode: 0,
          responseBody: `SSRF re-check failed at delivery time: ${reason}`,
          errorMessage: "ssrf_recheck_failed",
          deliveredAt: new Date(),
        },
      });
      return;
    }
  }

  const dispatcher = new Agent({
    connect: {
      // Pin DNS: any lookup for the target hostname returns the
      // pre-vetted IP. Any OTHER hostname throws so a regression
      // can't silently re-open the TOCTOU. undici ≥8 invokes this
      // with `{ all: true }` and expects the addresses-array
      // callback shape (Node's dns.lookup `all` contract); the
      // legacy 3-arg `(err, address, family)` shape here used to
      // hard-fail every DNS-hostname delivery with "Invalid IP
      // address: undefined", so honor `opts.all` explicitly.
      lookup: (
        h: string,
        opts: { all?: boolean },
        cb: (
          err: NodeJS.ErrnoException | null,
          address: string | { address: string; family: number }[],
          family?: number,
        ) => void,
      ): void => {
        if (h.toLowerCase() === hostname && pinnedAddr) {
          if (opts?.all) {
            cb(null, [{ address: pinnedAddr.address, family: pinnedAddr.family }]);
          } else {
            cb(null, pinnedAddr.address, pinnedAddr.family);
          }
        } else {
          cb(
            Object.assign(
              new Error(`unexpected DNS lookup for ${h}; expected ${hostname}`),
              { code: "ENOTFOUND" },
            ) as NodeJS.ErrnoException,
            "",
            0,
          );
        }
      },
    },
  });

  try {
    const res = await undiciFetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "User-Agent": "AgentVisor-Webhook/1.0",
        "X-AgentVisor-Event": event,
        "X-AgentVisor-Delivery": deliveryId,
        "X-AgentVisor-Timestamp": timestamp,
        "X-AgentVisor-Signature": sig,
      },
      body,
      signal: controller.signal,
      dispatcher,
      // Never follow redirects: WHATWG fetch defaults to
      // `redirect: "follow"`, and a 30x from a "public" webhook
      // endpoint to an IP-literal target (169.254.169.254, RFC 1918,
      // localhost) would connect WITHOUT consulting the pinned
      // `lookup` above — a full SSRF-check bypass. A webhook
      // receiver must answer 2xx at its registered URL.
      redirect: "manual",
    });
    const responseCode = res.status;
    // Body read runs with the abort timer still armed: a compromised
    // endpoint returning headers then trickling (or streaming
    // multi-GB) otherwise held the socket + buffered unboundedly —
    // res.text() only resolves at end-of-stream. The capped reader
    // stops at 2 KiB and cancels the rest; the timer bounds total
    // wall time.
    const respText = await readBodyCapped(res, 2048);
    clearTimeout(timer);
    const truncated =
      respText.length > 2000 ? truncateWellFormed(respText, 2000) + "…" : respText;
    if (responseCode >= 200 && responseCode < 300) {
      await db.webhookDelivery.update({
        where: { id: deliveryId },
        data: {
          status: "delivered",
          responseCode,
          responseBody: truncated,
          deliveredAt: new Date(),
          // Clear the retry bookkeeping: the deliveries drawer sorts
          // its badge from errorMessage (#307 fixed the four failure
          // paths but missed this 2xx path), so a success-after-retry
          // otherwise kept rendering the PREVIOUS attempt's error on a
          // row that actually delivered. nextRetryAt held the claim
          // lease — also stale once delivered.
          errorMessage: null,
          nextRetryAt: null,
        },
      });
      return;
    }
    // 3xx = give up: redirects are refused outright (see
    // `redirect: "manual"` above — following one would bypass the
    // SSRF pinning), and retrying a redirecting endpoint would just
    // redirect again. Surface it as its own error class so the
    // operator sees "fix your endpoint URL", not a retried 5xx.
    if (responseCode >= 300 && responseCode < 400) {
      await db.webhookDelivery.update({
        where: { id: deliveryId },
        data: {
          status: "failed",
          responseCode,
          responseBody: truncated,
          errorMessage: "redirect_refused_" + responseCode,
          deliveredAt: new Date(),
        },
      });
      return;
    }
    // 4xx = give up (endpoint misconfigured); 5xx = retry with backoff.
    if (responseCode >= 400 && responseCode < 500) {
      await db.webhookDelivery.update({
        where: { id: deliveryId },
        data: {
          status: "failed",
          responseCode,
          responseBody: truncated,
          errorMessage: "client_error_" + responseCode,
        },
      });
      return;
    }
    await scheduleRetry(deliveryId, attempt, "server_error_" + responseCode, truncated, responseCode, logger);
  } catch (e) {
    clearTimeout(timer);
    const msg = e instanceof Error ? e.message : String(e);
    await scheduleRetry(deliveryId, attempt, msg, null, null, logger);
  } finally {
    // R77-defer-1: close the per-delivery Agent so its
    // connection pool releases the sockets. Long-lived Agents
    // would keep the pinned-DNS lookup fn alive across
    // deliveries — we intentionally scope to one delivery so
    // each delivery's DNS is re-vetted.
    await dispatcher.close().catch(() => undefined);
  }
}

async function scheduleRetry(
  deliveryId: string,
  attempt: number,
  errorMessage: string,
  responseBody: string | null,
  responseCode: number | null,
  logger?: FastifyBaseLogger,
): Promise<void> {
  if (attempt >= MAX_ATTEMPT) {
    await db.webhookDelivery.update({
      where: { id: deliveryId },
      data: {
        status: "failed",
        errorMessage,
        responseBody: responseBody ?? undefined,
        responseCode: responseCode ?? undefined,
        // Clear the claim lease — a failed row with a future
        // nextRetryAt would mislead the drawer.
        nextRetryAt: null,
      },
    });
    logger?.warn({ deliveryId }, "webhook_delivery_gave_up");
    return;
  }
  const backoff =
    BACKOFF_SECONDS[Math.min(attempt - 1, BACKOFF_SECONDS.length - 1)] ?? 30;
  const nextRetryAt = new Date(Date.now() + backoff * 1000);
  await db.webhookDelivery.update({
    where: { id: deliveryId },
    data: {
      status: "retrying",
      errorMessage,
      responseBody: responseBody ?? undefined,
      responseCode: responseCode ?? undefined,
      nextRetryAt,
    },
  });
}

let sweeperTimer: NodeJS.Timeout | null = null;

const SWEEPER_INTERVAL_MS = env.WEBHOOK_SWEEPER_INTERVAL_MS;

/**
 * Start the retry sweeper. Idempotent — safe to call multiple times
 * (Fastify plugin encapsulation might otherwise cause double-registration
 * during hot-reload).
 */
export function startWebhookSweeper(logger?: FastifyBaseLogger): void {
  if (sweeperTimer) return;
  const tick = async () => {
    try {
      // R85 F2: atomically CLAIM up to 20 rows using
      // `FOR UPDATE SKIP LOCKED` inside the same UPDATE that
      // flips status → 'pending'. Prior shape ran a plain
      // findMany({status:'retrying', nextRetryAt<=now}) with
      // no locking, so N replicas each picked the SAME rows
      // on the same 15 s tick and each fired deliverOne —
      // N× delivery per replica for non-idempotent customer
      // endpoints. Postgres' SKIP LOCKED gives each replica
      // a disjoint slice: the losing replica returns 0 rows
      // and the winner runs deliverOne exactly once.
      const claimed = await db.$queryRaw<Array<{
        id: string;
        endpointId: string;
        event: string;
        payload: string;
        attempt: number;
      }>>`
        UPDATE "webhook_deliveries"
        SET status = 'pending',
            -- Renew the claim lease (mirrors PENDING_LEASE_MS): if THIS
            -- process dies before deliverOne writes a terminal status,
            -- a later tick reclaims the row via the lease arm below.
            "nextRetryAt" = (now() AT TIME ZONE 'UTC') + interval '5 minutes'
        WHERE id IN (
          SELECT id FROM "webhook_deliveries"
          -- Round-104 TZ fix: nextRetryAt is a naive-UTC timestamp
          -- (Prisma DateTime); bare now() is timestamptz and the
          -- comparison casts it through the SESSION TimeZone. With a
          -- non-UTC database (TZ=America/New_York) retries stalled ~4-5
          -- hours. Normalize now() to naive UTC explicitly.
          WHERE ((status = 'retrying' AND "nextRetryAt" <= (now() AT TIME ZONE 'UTC'))
             -- Expired claim lease: a row stays 'pending' only while a
             -- deliverOne is executing (bounded by DELIVERY_TIMEOUT_MS,
             -- 5 s). A lease in the past means the claiming process died
             -- mid-flight (deploy SIGTERM, crash, dropped microtask);
             -- without this arm the row was orphaned FOREVER — the
             -- sweeper only re-scanned 'retrying' — i.e. silent
             -- permanent delivery loss on any restart.
             OR (status = 'pending' AND "nextRetryAt" IS NOT NULL
                 AND "nextRetryAt" <= (now() AT TIME ZONE 'UTC'))
             -- Pre-lease orphans (rows claimed by code that nulled
             -- nextRetryAt while pending, then died). Restricted to
             -- FIRST-attempt rows: their createdAt ≈ claim time (the
             -- create and the POST happen in the same request, in-flight
             -- ≤ DELIVERY_TIMEOUT_MS), so 15 min of age genuinely means
             -- the claimer died. Retry rows (attempt ≥ 2) are EXCLUDED:
             -- their createdAt is the original enqueue time — during the
             -- rolling deploy that ships this lease, an OLD-code replica
             -- still claims retries with nextRetryAt = NULL, and a
             -- ≥15-min-old row it is actively delivering would match an
             -- age-on-createdAt arm instantly, double-POSTing with no
             -- crash involved. Old-code retry orphans stay wedged (the
             -- pre-fix status quo, visible in the drawer); every claim
             -- made by THIS code carries a lease and heals via the arm
             -- above.
             OR (status = 'pending' AND "nextRetryAt" IS NULL
                 AND attempt <= 1
                 AND "createdAt" <= (now() AT TIME ZONE 'UTC') - interval '15 minutes'))
          ORDER BY "nextRetryAt" ASC
          LIMIT 20
          FOR UPDATE SKIP LOCKED
        )
        RETURNING id, "endpointId", event, payload, attempt
      `;
      if (claimed.length === 0) return;
      const endpoints = await db.webhookEndpoint.findMany({
        where: { id: { in: claimed.map((c) => c.endpointId) } },
        select: { id: true, url: true, secret: true, isActive: true },
      });
      const endpointMap = new Map(endpoints.map((e) => [e.id, e]));
      for (const d of claimed) {
        // R86 F2: wrap each per-row body in its own try/catch so
        // one row's failure doesn't strand the rest of the batch
        // in `status='pending'` (they'd be invisible to the next
        // tick's `WHERE status='retrying'` filter → permanent
        // silent delivery loss). Also handle the CASCADE-delete
        // race: if an admin DELETEs an endpoint between our
        // claim UPDATE and the followup findMany, the schema's
        // `ON DELETE CASCADE` FK removes the delivery rows too
        // — the update-to-failed then throws P2025 and, prior
        // to R86 F2, the outer try/catch swallowed it while
        // leaving every remaining claimed row stranded. Detect
        // the deleted-endpoint case by checking the row still
        // exists before writing; if it's gone, silently skip.
        try {
          const endpoint = endpointMap.get(d.endpointId);
          if (!endpoint) {
            // Endpoint was deleted mid-tick. CASCADE FK dropped
            // this delivery row too — nothing to update. Skip.
            continue;
          }
          if (!endpoint.isActive) {
            await db.webhookDelivery.update({
              where: { id: d.id },
              data: { status: "failed", errorMessage: "endpoint_disabled", nextRetryAt: null },
            });
            continue;
          }
          // Reclaimed-lease rows re-enter with their persisted attempt
          // counter; a row whose process crashed on every one of its
          // MAX_ATTEMPT deliveries must fail here rather than loop at
          // lease cadence forever (scheduleRetry's give-up only runs
          // when an attempt FAILS in-process, never on a crash).
          if (d.attempt >= MAX_ATTEMPT) {
            await db.webhookDelivery.update({
              where: { id: d.id },
              data: {
                status: "failed",
                errorMessage: "max_attempts_exceeded",
                nextRetryAt: null,
              },
            });
            logger?.warn({ deliveryId: d.id }, "webhook_delivery_gave_up");
            continue;
          }
          // deliverOne with existingDeliveryId reuses this row rather than
          // creating a new one — attempt counter bumps in place.
          // R116 F2: attach .catch — same rationale as
          // dispatchEvent above. The sweeper's per-row try/catch
          // wraps only the sync spawn; the async deliverOne
          // rejection escapes it. Concurrent DELETE /:id cascade
          // during the millisecond gap between claim and update
          // yields P2025/P2003.
          void deliverOne(
            d.endpointId,
            endpoint.url,
            endpoint.secret,
            d.event,
            d.payload,
            d.attempt + 1,
            logger,
            d.id,
          ).catch((err) => {
            logger?.warn(
              { err, deliveryId: d.id, endpointId: d.endpointId },
              "webhook_sweeper_deliverOne_rejected",
            );
          });
        } catch (rowErr) {
          // Don't let one row poison the whole batch.
          logger?.warn(
            { err: rowErr, deliveryId: d.id, endpointId: d.endpointId },
            "webhook_sweeper_row_failed",
          );
        }
      }
    } catch (e) {
      logger?.warn({ err: e }, "webhook_sweeper_iteration_failed");
    }
  };
  sweeperTimer = setInterval(tick, SWEEPER_INTERVAL_MS);
  // First tick immediately so tests don't have to wait 15s.
  void tick();
}

export function stopWebhookSweeper(): void {
  if (sweeperTimer) {
    clearInterval(sweeperTimer);
    sweeperTimer = null;
  }
}
