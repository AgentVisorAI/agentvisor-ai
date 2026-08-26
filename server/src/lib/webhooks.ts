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
 * In development we allow 127.0.0.1 + link-local so operators can
 * point at their local receiver for testing. The env-driven allowlist
 * is what makes the drill work without disabling the guard entirely.
 */
const BLOCKED_HOSTS_ALWAYS = new Set([
  "metadata.google.internal",
  "metadata.goog",
  "169.254.169.254",
  "fd00:ec2::254",
  "instance-data",
]);

function isBlockedIp(ip: string): boolean {
  // IPv6
  if (isIP(ip) === 6) {
    // ::1 loopback
    if (ip === "::1" || ip.startsWith("::ffff:127.")) return true;
    // link-local fe80::/10 and unique-local fc00::/7
    const lc = ip.toLowerCase();
    if (lc.startsWith("fe80:") || lc.startsWith("fc") || lc.startsWith("fd")) {
      return true;
    }
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
    // Metadata (169.254.169.254) is *always* refused, even in dev —
    // there's no legitimate reason a webhook target would live there.
    if (host === "169.254.169.254" || host === "fd00:ec2::254") {
      return { ok: false, reason: "blocked_metadata_ip" };
    }
    if (env.NODE_ENV === "production" && isBlockedIp(host)) {
      return { ok: false, reason: "private_ip_blocked" };
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
      const endpoints = await db.webhookEndpoint.findMany({
        where: {
          orgId: opts.orgId,
          isActive: true,
          // Postgres array `?|` operator via Prisma's `hasSome`.
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
        void deliverOne(ep.id, ep.url, ep.secret, opts.event, body, 1, opts.logger);
      }
    } catch (e) {
      opts.logger?.warn({ err: e, event: opts.event }, "webhook_dispatch_failed");
    }
  })();
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
      data: { attempt, status: "pending", nextRetryAt: null },
    });
  } else {
    const row = await db.webhookDelivery.create({
      data: {
        endpointId,
        event,
        payload: body,
        attempt,
        status: "pending",
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
        deliveredAt: new Date(),
      },
    });
    return;
  }
  const hostname = parsedUrl.hostname.toLowerCase();
  let pinnedAddr: { address: string; family: 4 | 6 } | null = null;
  if (isIP(hostname)) {
    // Literal IP — validateWebhookUrl already blocked private
    // and metadata IPs in `production`. Re-check here for
    // defence-in-depth and skip the DNS lookup.
    if (env.NODE_ENV === "production" && isBlockedIp(hostname)) {
      clearTimeout(timer);
      await db.webhookDelivery.update({
        where: { id: deliveryId },
        data: {
          status: "failed",
          responseCode: 0,
          responseBody: "SSRF re-check failed at delivery time: private_ip_blocked",
          deliveredAt: new Date(),
        },
      });
      return;
    }
    if (hostname === "169.254.169.254" || hostname === "fd00:ec2::254") {
      clearTimeout(timer);
      await db.webhookDelivery.update({
        where: { id: deliveryId },
        data: {
          status: "failed",
          responseCode: 0,
          responseBody: "SSRF re-check failed at delivery time: blocked_metadata_ip",
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
      // In production, every returned address must be public.
      if (env.NODE_ENV === "production") {
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
          deliveredAt: new Date(),
        },
      });
      return;
    }
  }

  const dispatcher = new Agent({
    connect: {
      // Pin DNS: any lookup for the target hostname returns the
      // pre-vetted IP. Any OTHER hostname (shouldn't happen —
      // fetch is scoped to `url` only, and undici doesn't
      // follow redirects by default under fetch()) throws so a
      // regression can't silently re-open the TOCTOU.
      lookup: (
        h: string,
        _opts: unknown,
        cb: (err: NodeJS.ErrnoException | null, address: string, family: number) => void,
      ): void => {
        if (h.toLowerCase() === hostname && pinnedAddr) {
          cb(null, pinnedAddr.address, pinnedAddr.family);
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
    });
    clearTimeout(timer);
    const responseCode = res.status;
    const respText = await res.text().catch(() => "");
    const truncated = respText.length > 2000 ? respText.slice(0, 2000) + "…" : respText;
    if (responseCode >= 200 && responseCode < 300) {
      await db.webhookDelivery.update({
        where: { id: deliveryId },
        data: {
          status: "delivered",
          responseCode,
          responseBody: truncated,
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

const SWEEPER_INTERVAL_MS = Number(process.env.WEBHOOK_SWEEPER_INTERVAL_MS ?? 15_000);

/**
 * Start the retry sweeper. Idempotent — safe to call multiple times
 * (Fastify plugin encapsulation might otherwise cause double-registration
 * during hot-reload).
 */
export function startWebhookSweeper(logger?: FastifyBaseLogger): void {
  if (sweeperTimer) return;
  const tick = async () => {
    try {
      const due = await db.webhookDelivery.findMany({
        where: {
          status: "retrying",
          nextRetryAt: { lte: new Date() },
        },
        take: 20,
        orderBy: { nextRetryAt: "asc" },
        select: {
          id: true,
          endpointId: true,
          event: true,
          payload: true,
          attempt: true,
          endpoint: { select: { url: true, secret: true, isActive: true } },
        },
      });
      for (const d of due) {
        if (!d.endpoint.isActive) {
          await db.webhookDelivery.update({
            where: { id: d.id },
            data: { status: "failed", errorMessage: "endpoint_disabled" },
          });
          continue;
        }
        // deliverOne with existingDeliveryId reuses this row rather than
        // creating a new one — attempt counter bumps in place.
        void deliverOne(
          d.endpointId,
          d.endpoint.url,
          d.endpoint.secret,
          d.event,
          d.payload,
          d.attempt + 1,
          logger,
          d.id,
        );
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
