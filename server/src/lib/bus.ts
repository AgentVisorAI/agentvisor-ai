/*
 * Multi-instance event bus for real-time tenant updates.
 *
 * Two backends, same interface (publish + subscribeOrg):
 *
 *   1. In-process EventEmitter — the default; used when no Postgres URL
 *      is available (tests, local dev without a DB, etc). Free, zero
 *      moving parts, works up to a single node.
 *
 *   2. Postgres LISTEN/NOTIFY bridge — enabled automatically whenever a
 *      DATABASE_URL is present. Every instance opens ONE persistent
 *      `LISTEN av_bus` connection; publishers `NOTIFY av_bus, '<json>'`.
 *      This is exactly what horizontal scaling needs on Fly.io, Cloud
 *      Run, Kubernetes, Render, etc. No new managed service (Redis,
 *      RabbitMQ) — we reuse the Postgres we already pay for.
 *
 * The dedicated `pg` client is required because Prisma's connection pool
 * checks connections in/out per query; LISTEN needs a long-lived socket.
 * `pg` is the standard, minimal, portable Postgres driver — same one
 * every other Node app in the ecosystem uses. No vendor lock-in.
 *
 * Failure mode: if the LISTEN connection ever drops we log, back off,
 * and reconnect. During the reconnect window each instance falls back
 * to in-process delivery — no messages lost within an instance, only
 * cross-instance until the LISTEN comes back.
 */

import { EventEmitter } from "node:events";
import { randomBytes } from "node:crypto";
import { Client as PgClient } from "pg";
import { env } from "../env.js";

export type EventPayload =
  | { type: "session.upsert"; orgId: string; deploymentId: string; sessionId: string; externalId: string; agent: string }
  | { type: "events.appended"; orgId: string; deploymentId: string; sessionId: string; count: number; blocked: number; allowed: number }
  | { type: "receipt.finalized"; orgId: string; deploymentId: string; sessionId: string; receiptId: string };

// R110 F3 + R111 F3: NOTIFY payload wire format. The R110 F3 shape
// was `{ev, originId}` which broke pre-R110 receivers (they did
// `parsed.orgId` and got undefined, silently dropping cross-
// instance events during any rolling deploy window). Symmetric
// backward-compat: embed the EventPayload fields at the TOP LEVEL
// alongside originId, so pre-R110 receivers keep parsing
// `parsed.orgId` correctly and R110+ receivers use the extra
// originId field to skip self-delivery. An old sender's untagged
// payload deserializes with originId=undefined, doesn't match
// PROCESS_ORIGIN_ID, so a new receiver still re-emits it.
// Symmetric in both directions across the rolling window.
type WirePayload = EventPayload & { originId?: string };

const PROCESS_ORIGIN_ID = randomBytes(8).toString("hex");

const NOTIFY_CHANNEL = "av_bus";
// Postgres NOTIFY payload cap is 8000 bytes. Our payloads are small
// (~200-400 bytes) but we guard against a runaway anyway.
const MAX_PAYLOAD_BYTES = 7500;

class Bus extends EventEmitter {
  private pgListener: PgClient | null = null;
  private pgPublisher: PgClient | null = null;
  private reconnecting = false;
  private reconnectDelayMs = 500;
  private closed = false;

  publish(ev: EventPayload): void {
    // Always deliver locally first so single-instance and same-node tabs
    // see the update with zero DB round-trip latency.
    this.emit(`org:${ev.orgId}`, ev);
    this.emit("*", ev);

    // Then fan out cross-instance via Postgres if the bridge is up.
    // Fire-and-forget — the local deliver above is authoritative for the
    // caller's tenant on this node.
    if (this.pgPublisher) {
      // R111 F3: flat wire shape — EventPayload fields at top level
      // + originId sibling. Pre-R110 receivers reading `payload.orgId`
      // still work; R110+ receivers use `payload.originId` to skip
      // self-delivery. See WirePayload type comment.
      const wire: WirePayload = { ...ev, originId: PROCESS_ORIGIN_ID };
      const payload = JSON.stringify(wire);
      if (Buffer.byteLength(payload) > MAX_PAYLOAD_BYTES) {
        // Skip cross-instance for oversized payloads; local delivery
        // already succeeded so the origin tenant still sees the update.
        //
        // R132 F3: prior shape returned silently — no metric, no log,
        // no signal. The originator sees local delivery succeed and
        // moves on, so the drop stays invisible until a debugging
        // session correlates "tab on instance A didn't see the event
        // instance B fired." EventPayload shapes are 200-400 bytes
        // today so this is unreachable in practice, but if a field
        // grows (agent 80 + externalId 128 + a longer session URL
        // + deployment name is not far off), cross-instance delivery
        // starts silently failing on a rolling basis with zero
        // telemetry. Emit a warn so ops has the signal.
        // eslint-disable-next-line no-console
        console.warn("bus: oversized payload dropped for cross-instance fanout", {
          type: ev.type,
          orgId: ev.orgId,
          bytes: Buffer.byteLength(payload),
          limit: MAX_PAYLOAD_BYTES,
        });
        return;
      }
      this.pgPublisher
        .query("SELECT pg_notify($1::text, $2::text)", [NOTIFY_CHANNEL, payload])
        .catch(() => {
          // Publisher gone — the reconnect loop will replace it.
        });
    }
  }

  subscribeOrg(orgId: string, listener: (ev: EventPayload) => void): () => void {
    const key = `org:${orgId}`;
    this.on(key, listener);
    return () => this.off(key, listener);
  }

  /**
   * Connect the LISTEN + NOTIFY sidecar. Safe to call once at boot.
   * Silent no-op when DATABASE_URL is unavailable — the in-process bus
   * still works. Returns whether the bridge came online.
   */
  async connectPgBridge(): Promise<boolean> {
    if (!env.DATABASE_URL || !isPostgresUrl(env.DATABASE_URL)) return false;
    try {
      await this.openConnections();
      return true;
    } catch (err) {
      // Log once — the reconnect loop retries silently on cadence.
      // eslint-disable-next-line no-console
      console.warn("bus: pg bridge unavailable at boot, falling back to in-process only", err instanceof Error ? err.message : err);
      this.scheduleReconnect();
      return false;
    }
  }

  private async openConnections(): Promise<void> {
    const listener = new PgClient({ connectionString: env.DATABASE_URL });
    await listener.connect();
    await listener.query(`LISTEN ${NOTIFY_CHANNEL}`);
    listener.on("notification", (msg) => {
      if (msg.channel !== NOTIFY_CHANNEL || !msg.payload) return;
      try {
        // R110 F3 + R111 F3: flat wire shape — EventPayload fields
        // at top level + optional originId sibling. Pre-R110 senders
        // send bare EventPayload with no originId; those come through
        // as originId=undefined and are re-emitted. R110+ senders
        // include their PROCESS_ORIGIN_ID; if it matches this
        // process's own id, we skip re-emit (publish() already
        // delivered locally). Symmetric backward-compat across a
        // rolling deploy.
        const parsed = JSON.parse(msg.payload) as WirePayload;
        if (parsed.originId === PROCESS_ORIGIN_ID) return;
        // Re-emit locally so any SSE subscribers on THIS node see the
        // cross-instance update. Skip the fan-out back to pg by not
        // going through publish() — we're already inside a NOTIFY.
        // Extract the raw EventPayload (strip the originId key so
        // downstream consumers keying on `ev` fields don't see a
        // spurious originId).
        const { originId: _ignored, ...ev } = parsed;
        this.emit(`org:${ev.orgId}`, ev as EventPayload);
        this.emit("*", ev as EventPayload);
      } catch {
        // Ignore malformed payloads — a future protocol bump would
        // be shipped with an explicit version tag, not silently.
      }
    });
    listener.on("error", (err) => {
      // eslint-disable-next-line no-console
      console.warn("bus: pg listener error, reconnecting", err.message);
      this.scheduleReconnect();
    });
    listener.on("end", () => {
      if (!this.closed) this.scheduleReconnect();
    });

    const publisher = new PgClient({ connectionString: env.DATABASE_URL });
    await publisher.connect();
    publisher.on("error", (err) => {
      // eslint-disable-next-line no-console
      console.warn("bus: pg publisher error, reconnecting", err.message);
      this.scheduleReconnect();
    });
    publisher.on("end", () => {
      if (!this.closed) this.scheduleReconnect();
    });

    this.pgListener = listener;
    this.pgPublisher = publisher;
    this.reconnectDelayMs = 500; // reset backoff after a successful open
  }

  private scheduleReconnect(): void {
    if (this.reconnecting || this.closed) return;
    this.reconnecting = true;
    const listener = this.pgListener;
    const publisher = this.pgPublisher;
    this.pgListener = null;
    this.pgPublisher = null;
    // Drain any lingering handlers before we open new sockets.
    listener?.removeAllListeners();
    publisher?.removeAllListeners();
    listener?.end().catch(() => {});
    publisher?.end().catch(() => {});

    const delay = this.reconnectDelayMs;
    this.reconnectDelayMs = Math.min(this.reconnectDelayMs * 2, 30_000);
    setTimeout(async () => {
      this.reconnecting = false;
      if (this.closed) return;
      try {
        await this.openConnections();
      } catch (err) {
        // eslint-disable-next-line no-console
        console.warn(
          "bus: reconnect failed, retrying",
          err instanceof Error ? err.message : err,
        );
        this.scheduleReconnect();
      }
    }, delay);
  }

  /**
   * True when the pg LISTEN/NOTIFY bridge is up. Same-instance delivery
   * still works when this is false — only cross-instance fan-out
   * degrades. Used by /readyz to distinguish "fully healthy" from
   * "degraded but serving".
   */
  isReady(): boolean {
    return this.pgListener !== null && this.pgPublisher !== null;
  }

  /** Close both pg sockets. Fastify graceful shutdown hook calls this. */
  async close(): Promise<void> {
    this.closed = true;
    const listener = this.pgListener;
    const publisher = this.pgPublisher;
    this.pgListener = null;
    this.pgPublisher = null;
    listener?.removeAllListeners();
    publisher?.removeAllListeners();
    await Promise.allSettled([listener?.end(), publisher?.end()]);
  }
}

function isPostgresUrl(url: string): boolean {
  return url.startsWith("postgres://") || url.startsWith("postgresql://");
}

// Node's default max listeners = 10; a console with many open tabs across an
// org would trip that. Uncap here — the SSE handler is the only listener kind
// and each open tab is one listener.
const bus = new Bus();
bus.setMaxListeners(0);

export { bus };
