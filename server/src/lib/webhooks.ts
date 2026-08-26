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
import type { FastifyBaseLogger } from "fastify";
import { db } from "../db.js";

const MAX_ATTEMPT = 6;
const BACKOFF_SECONDS = [30, 120, 600, 1800, 7200];
const DELIVERY_TIMEOUT_MS = 5000;

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
      const body = JSON.stringify({
        event: opts.event,
        createdAt: new Date().toISOString(),
        data: opts.data,
      });
      for (const ep of endpoints) {
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
): Promise<void> {
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

  const timestamp = String(Math.floor(Date.now() / 1000));
  const sig = signPayload(secret, timestamp, body);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), DELIVERY_TIMEOUT_MS);

  try {
    const res = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "User-Agent": "AgentVisor-Webhook/1.0",
        "X-AgentVisor-Event": event,
        "X-AgentVisor-Delivery": row.id,
        "X-AgentVisor-Timestamp": timestamp,
        "X-AgentVisor-Signature": sig,
      },
      body,
      signal: controller.signal,
    });
    clearTimeout(timer);
    const responseCode = res.status;
    const respText = await res.text().catch(() => "");
    const truncated = respText.length > 2000 ? respText.slice(0, 2000) + "…" : respText;
    if (responseCode >= 200 && responseCode < 300) {
      await db.webhookDelivery.update({
        where: { id: row.id },
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
        where: { id: row.id },
        data: {
          status: "failed",
          responseCode,
          responseBody: truncated,
          errorMessage: "client_error_" + responseCode,
        },
      });
      return;
    }
    await scheduleRetry(row.id, attempt, "server_error_" + responseCode, truncated, responseCode, logger);
  } catch (e) {
    clearTimeout(timer);
    const msg = e instanceof Error ? e.message : String(e);
    await scheduleRetry(row.id, attempt, msg, null, null, logger);
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
        // Mark pending so a concurrent sweeper doesn't double-fire.
        await db.webhookDelivery.update({
          where: { id: d.id },
          data: { status: "pending", nextRetryAt: null },
        });
        void deliverOne(
          d.endpointId,
          d.endpoint.url,
          d.endpoint.secret,
          d.event,
          d.payload,
          d.attempt + 1,
          logger,
        );
      }
    } catch (e) {
      logger?.warn({ err: e }, "webhook_sweeper_iteration_failed");
    }
  };
  sweeperTimer = setInterval(tick, 15_000);
  // First tick immediately so tests don't have to wait 15s.
  void tick();
}

export function stopWebhookSweeper(): void {
  if (sweeperTimer) {
    clearInterval(sweeperTimer);
    sweeperTimer = null;
  }
}
