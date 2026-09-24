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
 * cross-instance until the LISTEN comes back. Recovery resets open SSE
 * streams locally and on other instances so clients refetch any missed
 * changes from the database.
 */

import { EventEmitter } from "node:events";
import { randomBytes } from "node:crypto";
import { Client as PgClient } from "pg";
import { env } from "../env.js";
import { pgBusReconnectsTotal } from "./metrics.js";

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
type WirePayload = (EventPayload | { type: "bridge.reset" }) & { originId?: string };

const NOTIFY_CHANNEL = "av_bus";
// Postgres NOTIFY payload cap is 8000 bytes. Our payloads are small
// (~200-400 bytes) but we guard against a runaway anyway.
const MAX_PAYLOAD_BYTES = 7500;
const QUERY_TIMEOUT_MS = 5000;
const LISTENER_HEARTBEAT_MS = 15_000;
// Bound retained payloads/promises when PostgreSQL stops answering. Overflow
// preserves local delivery, then reconnects and resets peers so they refetch
// committed changes from the database instead of retaining an unbounded queue.
const MAX_PENDING_PUBLICATIONS = 256;

function bridgeQuery(client: PgClient, text: string, values?: string[]) {
  // pg accepts per-query timeouts, but its current QueryConfig typings omit
  // that field. A structurally compatible object preserves all normal types.
  // These deadlines take precedence over DATABASE_URL query_timeout options.
  const query = { text, values, query_timeout: QUERY_TIMEOUT_MS };
  return client.query(query);
}

export class Bus extends EventEmitter {
  private readonly originId = randomBytes(8).toString("hex");
  private pgListener: PgClient | null = null;
  private pgPublisher: PgClient | null = null;
  private bridgeReady = false;
  private pendingPublications = 0;
  private reconnecting = false;
  private reconnectDelayMs = 500;
  private closed = false;
  private reconnectTimer: NodeJS.Timeout | undefined;
  private listenerHeartbeatTimer: NodeJS.Timeout | undefined;
  private connectionGeneration = 0;
  private readonly openingClients = new Set<PgClient>();
  private readonly pendingConnects = new Map<PgClient, () => void>();
  private readonly closingClients = new WeakMap<PgClient, Promise<void>>();

  private async connectClient(client: PgClient): Promise<void> {
    const cancelled = new Promise<never>((_resolve, reject) => {
      this.pendingConnects.set(client, () => reject(new Error("bus_connect_cancelled")));
    });
    try {
      // pg.end() does not settle pg.connect() during authentication.
      // Race an explicit cancellation so shutdown also settles callers.
      await Promise.race([client.connect(), cancelled]);
    } finally {
      this.pendingConnects.delete(client);
    }
  }

  private closeClient(client: PgClient): Promise<void> {
    const closing = this.closingClients.get(client);
    if (closing) return closing;
    client.removeAllListeners();
    client.on("error", () => {});
    // Share the same close between shutdown and a failed opening attempt.
    // Weak keys retain no finished client solely for this bookkeeping.
    const ended = Promise.resolve().then(() => client.end()).catch(() => {});
    this.closingClients.set(client, ended);
    return ended;
  }

  private scheduleListenerHeartbeat(listener: PgClient, generation: number): void {
    const current = (): boolean => !this.closed
      && generation === this.connectionGeneration && this.pgListener === listener;
    if (!current()) return;
    // LISTEN is otherwise idle indefinitely. TCP can stay established while
    // all incoming data disappears, even when the separate publisher works.
    // Keep only one liveness query/timer, with the same query deadline as setup.
    const timer = setTimeout(() => {
      if (this.listenerHeartbeatTimer === timer) this.listenerHeartbeatTimer = undefined;
      if (!current()) return;
      bridgeQuery(listener, "SELECT 1 /* av_bus listener heartbeat */").then(() => {
        if (current()) this.scheduleListenerHeartbeat(listener, generation);
      }, () => {
        if (current()) this.scheduleReconnect();
      });
    }, LISTENER_HEARTBEAT_MS);
    this.listenerHeartbeatTimer = timer;
    timer.unref();
  }

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
      const wire: WirePayload = { ...ev, originId: this.originId };
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
      const publisher = this.pgPublisher;
      if (this.pendingPublications >= MAX_PENDING_PUBLICATIONS) {
        this.scheduleReconnect();
        return;
      }
      this.pendingPublications++;
      bridgeQuery(publisher, "SELECT pg_notify($1::text, $2::text)", [NOTIFY_CHANNEL, payload])
        .then(() => {
          if (this.pgPublisher === publisher) this.pendingPublications--;
        }, () => {
          // Query failures need not emit a Client error. A failed
          // publication lost an update for other instances: reconnect
          // and broadcast a reset before resuming normal delivery. In pg,
          // query_timeout alone does not close a non-pipelined active query;
          // reconnect also closes that socket and rejects its queued work.
          if (this.pgPublisher === publisher) this.scheduleReconnect();
        });
    }
  }

  subscribeOrg(orgId: string, listener: (ev: EventPayload) => void): () => void {
    const key = `org:${orgId}`;
    this.on(key, listener);
    return () => this.off(key, listener);
  }

  subscribeReset(listener: () => void): () => void {
    this.on("bridge:reset", listener);
    return () => this.off("bridge:reset", listener);
  }

  /**
   * Connect the LISTEN + NOTIFY sidecar. Safe to call once at boot.
   * Silent no-op when DATABASE_URL is unavailable — the in-process bus
   * still works. Returns whether the bridge came online.
   */
  async connectPgBridge(): Promise<boolean> {
    if (!env.DATABASE_URL || !isPostgresUrl(env.DATABASE_URL)) return false;
    const generation = this.connectionGeneration;
    try {
      await this.openConnections();
      return true;
    } catch (err) {
      // Log once — the reconnect loop retries silently on cadence.
      // eslint-disable-next-line no-console
      console.warn("bus: pg bridge unavailable at boot, falling back to in-process only", err instanceof Error ? err.message : err);
      if (generation === this.connectionGeneration) this.scheduleReconnect();
      return false;
    }
  }

  private async openConnections(): Promise<void> {
    const generation = this.connectionGeneration;
    const current = (): boolean => !this.closed && generation === this.connectionGeneration;
    const listener = new PgClient({
      connectionString: env.DATABASE_URL, connectionTimeoutMillis: 5000,
      query_timeout: QUERY_TIMEOUT_MS,
    });
    this.openingClients.add(listener);
    let publisher: PgClient | undefined;
    // R233 F1: attach the drain/reconnect handlers IMMEDIATELY, before
    // `.connect()`. Prior shape wired them at lines 180+ after
    // connect + LISTEN succeeded, leaving a race window where an
    // error emitted during connect or on the very first query (pg
    // 57P01 FATAL if the server is bouncing on your connect) fires
    // on a Client with no `error` listener — node then crashes on
    // the uncaught event. E2E round 11's Postgres-chaos scenario
    // reproduced this by SIGTERM'ing pg mid-connection. Attach the
    // handlers pre-connect so the first byte of any error path is
    // always caught. `scheduleReconnect()` is re-entrant-safe.
    const listenerErr = (err: Error) => {
      if (!current()) return;
      // eslint-disable-next-line no-console
      console.warn("bus: pg listener error, reconnecting", err.message);
      this.scheduleReconnect();
    };
    const listenerEnd = () => {
      if (current()) this.scheduleReconnect();
    };
    listener.on("error", listenerErr);
    listener.on("end", listenerEnd);
    // R145 F2: wrap both connections and LISTEN in try/catch
    // so a partial-connect failure (Postgres briefly at
    // max_connections, TLS renegotiation, transient DNS on the
    // publisher's connect, .on wiring throwing synchronously)
    // doesn't orphan the LISTEN-ing socket. Prior shape assigned
    // this.pgListener only at the tail; if publisher.connect
    // threw, the caller's catch called scheduleReconnect() which
    // saw this.pgListener === null and ended nothing. Repeated
    // flaps dripped permanent Postgres connections until the
    // pool ceiling was hit.
    try {
      await this.connectClient(listener);
      await bridgeQuery(listener, `LISTEN ${NOTIFY_CHANNEL}`);
      if (!current()) throw new Error("bus_disconnected_during_connect");
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
          if (parsed.originId === this.originId) return;
          if (parsed.type === "bridge.reset") {
            // This contains no tenant data. Any publisher could have
            // missed notifications for any connected tenant while its
            // bridge was down, including tenants on healthy instances.
            this.emit("bridge:reset");
            return;
          }
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

      publisher = new PgClient({
        connectionString: env.DATABASE_URL, connectionTimeoutMillis: 5000,
        query_timeout: QUERY_TIMEOUT_MS,
      });
      this.openingClients.add(publisher);
      // R233 F1: same pre-connect error-listener discipline as the
      // listener above.
      publisher.on("error", (err) => {
        if (!current()) return;
        // eslint-disable-next-line no-console
        console.warn("bus: pg publisher error, reconnecting", err.message);
        this.scheduleReconnect();
      });
      publisher.on("end", () => {
        if (current()) this.scheduleReconnect();
      });
      await this.connectClient(publisher);

      // A close or reconnect may have invalidated this attempt while
      // either connection was pending. Never resurrect its sockets or
      // let its later errors tear down a newer, healthy bridge.
      if (!current()) throw new Error("bus_disconnected_during_connect");
      this.pgListener = listener;
      this.pgPublisher = publisher;
      await bridgeQuery(publisher, "SELECT pg_notify($1::text, $2::text)", [
        NOTIFY_CHANNEL, JSON.stringify({ type: "bridge.reset", originId: this.originId }),
      ]);
      if (!current() || this.pgListener !== listener || this.pgPublisher !== publisher) {
        throw new Error("bus_disconnected_during_connect");
      }
      this.bridgeReady = true;
      this.emit("bridge:reset");
      this.reconnectDelayMs = 500; // reset backoff after a successful open
      this.scheduleListenerHeartbeat(listener, generation);
    } catch (err) {
      // Drain the already-connected listener socket before rethrowing
      // so the caller can retry cleanly.
      if (this.pgListener === listener) {
        this.pgListener = null;
        this.bridgeReady = false;
      }
      if (this.pgPublisher === publisher) {
        this.pgPublisher = null;
        this.pendingPublications = 0;
        this.bridgeReady = false;
      }
      await Promise.all([this.closeClient(listener), publisher ? this.closeClient(publisher) : undefined]);
      throw err;
    } finally {
      this.openingClients.delete(listener);
      if (publisher) this.openingClients.delete(publisher);
    }
  }

  private scheduleReconnect(): void {
    if (this.reconnecting || this.closed) return;
    this.connectionGeneration++;
    if (this.listenerHeartbeatTimer !== undefined) clearTimeout(this.listenerHeartbeatTimer);
    this.listenerHeartbeatTimer = undefined;
    // R213 F1: increment the previously-dead Prometheus counter.
    // Counter is declared at lib/metrics.ts:44 with the comment
    // "useful signal that Neon or whichever managed PG we're on
    // is bouncing our LISTEN socket" — but nothing ever wired
    // it up, so every Grafana panel / alert built on
    // `agentvisor_api_pg_bus_reconnects_total` renders as a
    // flat zero forever. Counting after the re-entrancy guard
    // (not before) so this reports SCHEDULED reconnects, one
    // per socket flap, matching the metric name's intent.
    pgBusReconnectsTotal.inc();
    this.reconnecting = true;
    const listener = this.pgListener;
    const publisher = this.pgPublisher;
    this.pgListener = null;
    this.pgPublisher = null;
    this.bridgeReady = false;
    this.pendingPublications = 0;
    // Drain any lingering handlers before we open new sockets.
    // R233 F1: `removeAllListeners()` also strips the `error` handler
    // we wired at openConnections(). If the server-side connection is
    // simultaneously emitting a FATAL error (e.g. PG 57P01
    // admin_shutdown from a pg-side restart), an unhandled `error`
    // event on a `pg.Client` with no listeners takes down the whole
    // node process — the exact crash caught in E2E round 11's
    // Postgres-chaos scenario. Re-add a passthrough noop handler so
    // any error that races the drain gets swallowed, then let
    // scheduleReconnect() spin up fresh sockets on the backoff timer.
    for (const cancel of this.pendingConnects.values()) cancel();
    for (const client of new Set([...this.openingClients, listener, publisher])) {
      if (client) void this.closeClient(client);
    }

    const delay = this.reconnectDelayMs;
    this.reconnectDelayMs = Math.min(this.reconnectDelayMs * 2, 30_000);
    this.reconnectTimer = setTimeout(async () => {
      this.reconnectTimer = undefined;
      this.reconnecting = false;
      if (this.closed) return;
      const generation = this.connectionGeneration;
      try {
        await this.openConnections();
      } catch (err) {
        // eslint-disable-next-line no-console
        console.warn(
          "bus: reconnect failed, retrying",
          err instanceof Error ? err.message : err,
        );
        if (generation === this.connectionGeneration) this.scheduleReconnect();
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
    return this.bridgeReady;
  }

  /** Close both pg sockets. Fastify graceful shutdown hook calls this. */
  async close(): Promise<void> {
    this.closed = true;
    this.connectionGeneration++;
    if (this.reconnectTimer !== undefined) clearTimeout(this.reconnectTimer);
    this.reconnectTimer = undefined;
    if (this.listenerHeartbeatTimer !== undefined) clearTimeout(this.listenerHeartbeatTimer);
    this.listenerHeartbeatTimer = undefined;
    const listener = this.pgListener;
    const publisher = this.pgPublisher;
    this.pgListener = null;
    this.pgPublisher = null;
    this.bridgeReady = false;
    this.pendingPublications = 0;
    for (const cancel of this.pendingConnects.values()) cancel();
    await Promise.all([...new Set([...this.openingClients, listener, publisher])]
      .map((client) => client ? this.closeClient(client) : undefined));
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
