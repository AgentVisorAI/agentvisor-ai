/*
 * In-process event bus. Fan-out for real-time updates: ingest routes publish,
 * SSE consumers subscribe by orgId.
 *
 * At scale this becomes a Postgres LISTEN/NOTIFY bridge (or Redis pub-sub);
 * the interface stays the same so nothing above cares. Keep publishers dumb.
 */

import { EventEmitter } from "node:events";

export type EventPayload =
  | { type: "session.upsert"; orgId: string; deploymentId: string; sessionId: string; externalId: string; agent: string }
  | { type: "events.appended"; orgId: string; deploymentId: string; sessionId: string; count: number; blocked: number; allowed: number }
  | { type: "receipt.finalized"; orgId: string; deploymentId: string; sessionId: string; receiptId: string };

class Bus extends EventEmitter {
  publish(ev: EventPayload): void {
    // Emit two events: one keyed by orgId (for tenant-scoped listeners),
    // one broadcast (unused by console but handy for tests + audit).
    this.emit(`org:${ev.orgId}`, ev);
    this.emit("*", ev);
  }
  subscribeOrg(orgId: string, listener: (ev: EventPayload) => void): () => void {
    const key = `org:${orgId}`;
    this.on(key, listener);
    return () => this.off(key, listener);
  }
}

// Node's default max listeners = 10; a console with many open tabs across an
// org would trip that. Uncap here — the SSE handler is the only listener kind
// and each open tab is one listener.
const bus = new Bus();
bus.setMaxListeners(0);

export { bus };
