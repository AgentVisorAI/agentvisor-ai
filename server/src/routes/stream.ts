import type { FastifyInstance } from "fastify";
import { requireSession } from "../lib/session-middleware.js";
import { bus, type EventPayload } from "../lib/bus.js";
import { db } from "../db.js";
import { env } from "../env.js";

export async function streamRoutes(app: FastifyInstance): Promise<void> {
  // Server-Sent Events endpoint. Console tabs open a long-lived connection
  // and receive tenant-scoped events as they happen. One line of HTTP kept
  // open per open tab; server memory scales linearly.
  app.get("/stream", async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;

    // R84 F3: reject API-key auth for /stream. The R79 revalidate
    // loop queries `db.user.findUnique({ where: { id: claims.sub }})`;
    // for API-key sessions the middleware sets
    // `claims.sub = "apikey:" + apiKey.id` (see
    // lib/session-middleware.ts:55), which never matches a user
    // row. `revalidate()` therefore returns `false` on the FIRST
    // 15 s tick and the stream sends a bogus
    // `stream_terminated { reason: "session_revoked_or_membership_removed" }`
    // then closes. Server-to-server API-key integrations that
    // hit /stream would connect, receive `hello`, then get torn
    // down 15 s later — reconnect churn, misleading revocation
    // reason in client logs. SSE is designed for browser-tab
    // affinity anyway; API-key consumers should poll the REST
    // endpoints. Refuse cleanly instead of the confusing 15 s
    // teardown loop.
    if (claims.sub.startsWith("apikey:")) {
      return reply.code(400).send({ error: "sse_requires_cookie_session" });
    }
    // Set CORS headers ourselves — we're about to bypass Fastify's response
    // pipeline and stream to `reply.raw`, so the @fastify/cors plugin's
    // headers won't get flushed. Mirror the same allowlist logic here.
    //
    // R105 F3: honor the CORS plugin's dev-mode empty-list fallback.
    // Prior shape only echoed the origin when
    // ALLOWED_ORIGINS.includes(origin) — so in dev with an unset
    // ALLOWED_ORIGINS, fetch() from a Vite SPA on a different origin
    // worked (CORS plugin allows-any) but `new EventSource(...)`
    // silently failed with no Access-Control-Allow-Origin header.
    // Same allow-any-in-dev-if-empty fallback the plugin at
    // index.ts:104-114 applies.
    const origin = req.headers.origin;
    const allowByAllowlist = typeof origin === "string" && env.ALLOWED_ORIGINS.includes(origin);
    const allowByDevFallback = typeof origin === "string" &&
      env.ALLOWED_ORIGINS.length === 0 &&
      env.NODE_ENV !== "production";
    if (allowByAllowlist || allowByDevFallback) {
      reply.raw.setHeader("Access-Control-Allow-Origin", origin!);
      reply.raw.setHeader("Access-Control-Allow-Credentials", "true");
      reply.raw.setHeader("Vary", "Origin");
    }

    reply.raw.setHeader("Content-Type", "text/event-stream");
    reply.raw.setHeader("Cache-Control", "no-store, no-transform");
    reply.raw.setHeader("Connection", "keep-alive");
    reply.raw.setHeader("X-Accel-Buffering", "no");
    reply.raw.flushHeaders();

    // R83 F3: SSE backpressure protection. Prior shape discarded
    // the return value of `reply.raw.write(...)` in every write
    // site (initial hello, per-event `send`, keepalive,
    // stream_terminated). Node's writable stream returns `false`
    // when the internal buffer exceeds `highWaterMark` (default
    // 16 KB), but continues to queue writes in memory unbounded
    // — the return value is an ADVISORY signal to pause, not a
    // cap. A partially-stalled peer (paused tab, throttled
    // connection, dead-but-not-FIN'd TCP, buffered intermediary
    // like Cloudflare under load) can therefore accumulate
    // megabytes of queued events per connection. Multiply by N
    // stalled tabs on a busy org and the process RSS climbs
    // toward OOM before the R82 F3 heartbeat revalidate loop
    // even notices.
    //
    // Track backpressure per-connection. When the socket signals
    // backpressure (write() returns false), start a bounded
    // timer; if drain doesn't fire within
    // BACKPRESSURE_TIMEOUT_MS, treat the peer as dead and tear
    // the connection down (the client's auto-reconnect will
    // re-establish through the authoritative /stream + session
    // check path). We also drop mid-flight event writes while
    // paused — a lagging tab receiving stale data is worse than
    // a tab that reconnects and reads current state.
    const BACKPRESSURE_TIMEOUT_MS = 10_000;
    let paused = false;
    let backpressureTimer: NodeJS.Timeout | undefined;
    const armBackpressureTimer = (): void => {
      if (backpressureTimer !== undefined) return;
      backpressureTimer = setTimeout(() => {
        // Peer never drained. Give up.
        try {
          req.log.warn(
            { orgId: claims.orgId, userId: claims.sub },
            "sse_backpressure_timeout_tearing_down",
          );
        } catch { /* noop */ }
        teardown();
        try { reply.raw.destroy(); } catch { /* already destroyed */ }
      }, BACKPRESSURE_TIMEOUT_MS);
    };
    const clearBackpressureTimer = (): void => {
      if (backpressureTimer !== undefined) {
        clearTimeout(backpressureTimer);
        backpressureTimer = undefined;
      }
    };
    // R84 F2: on drain, don't silently resume — the client
    // already MISSED events (rawWrite dropped them while paused).
    // If we resume streaming as if nothing happened, the tab's
    // model drifts: missed `receipt.finalized` leaves sessions
    // pending; missed `events.appended` drifts counters; missed
    // `session.upsert` hides new rows. Force teardown on the
    // first drain after a backpressure event so the client's
    // EventSource auto-reconnect re-establishes through
    // /stream open, where the client refetches org state
    // authoritatively (the tab-open flow already reloads
    // sessions and receipts on connect). Better than
    // "silently drop, silently resume, silently show stale data".
    let hadBackpressure = false;
    reply.raw.on("drain", () => {
      paused = false;
      clearBackpressureTimer();
      if (hadBackpressure && !closed) {
        try {
          reply.raw.write(
            `event: stream_reset\ndata: ${JSON.stringify({ reason: "backpressure_recovered_refetch_state" })}\n\n`,
          );
        } catch { /* peer gone */ }
        teardown();
        try { reply.raw.end(); } catch { /* already ended */ }
      }
    });

    const rawWrite = (chunk: string): boolean => {
      // Returns false if we're currently paused (drop the event)
      // or if the write returned false (peer is backing up).
      if (paused) return false;
      let ok: boolean;
      try {
        ok = reply.raw.write(chunk);
      } catch {
        return false;
      }
      if (!ok) {
        paused = true;
        hadBackpressure = true;
        armBackpressureTimer();
      }
      return ok;
    };

    // Initial hello — makes browser EventSource fire onopen even under
    // load-balancer buffering.
    rawWrite(`event: hello\ndata: ${JSON.stringify({ ok: true })}\n\n`);

    const send = (ev: EventPayload): void => {
      const payload = JSON.stringify(ev);
      // SSE spec: each message is `event: <name>\ndata: <json>\n\n`.
      rawWrite(`event: ${ev.type}\ndata: ${payload}\n\n`);
    };
    const unsub = bus.subscribeOrg(claims.orgId, send);

    // R79 MEDIUM (Class D): periodically re-verify authorization
    // so a session revoked AFTER the SSE connection opened (logout,
    // password reset via `user.sessionRevokedAt` bump at
    // `auth.ts:635`, or membership removal via `DELETE /members/
    // :userId`) actually stops the stream. `requireSession`
    // ran ONCE at connection open; prior shape left an open tab
    // streaming `session.upsert` / `events.appended` /
    // `receipt.finalized` events to a revoked / ex-member session
    // until the tab was closed or the server restarted —
    // insider data-leak on removed members.
    //
    // Re-check on every 15 s keepalive tick (piggybacks on the
    // liveness ping, no extra DB round-trip cadence). On revoke:
    // write a `stream_terminated` event so the client can render
    // a "re-authenticate" prompt, then `.end()` the raw response,
    // which fires the `close` handler and cleans up bus + timer.
    //
    // R81 F3 (revised R82 F3): track consecutive DB errors + minimum
    // elapsed time between failed revalidates. R80's commit-message
    // noted "silent bypass of R79 fix under partial DB
    // degradation" but the code kept failing OPEN on every DB
    // exception. R81 landed a plain consecutive-count threshold
    // (>=2 errors → fail closed). R82 F3 audit surfaced a
    // thundering-herd amplification: `consecutiveErrors` is
    // per-connection, but the trigger (pool saturation) is
    // per-node — under a real DB outage every open stream on a
    // node hits errors on every 15 s tick, all cross the
    // threshold within ~30 s, all `res.end()`, all clients
    // auto-reconnect, all reconnects call `requireSession`
    // against the same saturated pool → cascade AMPLIFYING the
    // outage.
    //
    // Fix: require the two failures to be spaced apart by
    // MIN_MS_BETWEEN_FAILED_REVALIDATES. A single-window pool
    // blip (multiple 15 s ticks landing during one 30 s
    // saturation) counts as ONE failure; only a sustained
    // failure across a longer window trips the fail-closed
    // path. R79's narrow insider-leak surface (revoked session
    // during a genuine sustained DB outage) still closes;
    // fleet-wide reconnect storms on transient pool
    // saturation are avoided.
    const MAX_CONSECUTIVE_REVALIDATE_ERRORS = 2;
    const MIN_MS_BETWEEN_FAILED_REVALIDATES = 60_000;
    let consecutiveErrors = 0;
    let lastErrorAt = 0;
    const revalidate = async (): Promise<boolean> => {
      try {
        const user = await db.user.findUnique({
          where: { id: claims.sub },
          select: {
            sessionRevokedAt: true,
            memberships: {
              where: { orgId: claims.orgId },
              select: { id: true },
            },
          },
        });
        consecutiveErrors = 0;
        lastErrorAt = 0;
        if (!user) return false;
        if (user.memberships.length === 0) return false;
        if (
          user.sessionRevokedAt &&
          // R210 F1: same second-precision fix as
          // session-middleware.ts:102-105 — see that file for
          // full rationale. Comparing seconds-boundary iat
          // against millisecond-precision revokedAt refused
          // same-wall-clock-second logouts→logins as dead JWTs
          // until the next second ticked over.
          claims.iat < Math.floor(user.sessionRevokedAt.getTime() / 1000)
        ) {
          return false;
        }
        return true;
      } catch (err) {
        const now = Date.now();
        if (now - lastErrorAt < MIN_MS_BETWEEN_FAILED_REVALIDATES) {
          // Same pool blip; don't count. Keep the stream open;
          // the next tick will re-check.
          req.log.debug(
            { err, orgId: claims.orgId, userId: claims.sub, sinceLastMs: now - lastErrorAt },
            "sse_revalidate_transient_error_within_window_keep_open",
          );
          return true;
        }
        lastErrorAt = now;
        consecutiveErrors += 1;
        if (consecutiveErrors >= MAX_CONSECUTIVE_REVALIDATE_ERRORS) {
          // Fall closed. The client auto-reconnects and its next
          // /stream request runs `requireSession` at connection
          // open — the authoritative path.
          req.log.warn(
            { err, orgId: claims.orgId, userId: claims.sub, consecutiveErrors },
            "sse_revalidate_fail_closed",
          );
          return false;
        }
        req.log.debug(
          { err, orgId: claims.orgId, userId: claims.sub, consecutiveErrors },
          "sse_revalidate_transient_error_keep_open",
        );
        return true;
      }
    };

    // Named keepalive every 15s serves double duty: (1) survives intermediary
    // idle timeouts (Cloudflare 100s, Fly 60s, Heroku 55s), and (2) fires a
    // real EventSource listener on the client so the browser can detect
    // "server crashed but TCP FIN never arrived" — Chromium can hold a dead
    // EventSource in readyState=OPEN for tens of seconds after the peer dies.
    // The client tracks last-heard time and force-closes if the interval
    // between keepalives grows too long (default 30s stale threshold).
    //
    // R80 F2: guard against (a) re-entry (a slow `revalidate()` DB call
    // >15 s used to let a second callback pile up in the event loop
    // holding a DB connection) and (b) leaked interval + unsub after
    // the revalidate=false branch tore down the response (prior shape
    // relied entirely on `req.raw` firing 'close', which SSE keep-alive
    // can delay tens of seconds while the interval keeps ticking and
    // writes-after-end pollute error logs).
    let closed = false;
    let revalidateInFlight = false;
    let keepalive: NodeJS.Timeout | undefined;
    const teardown = (): void => {
      if (closed) return;
      closed = true;
      if (keepalive !== undefined) clearInterval(keepalive);
      clearBackpressureTimer();
      unsub();
    };
    keepalive = setInterval(async () => {
      if (closed || revalidateInFlight) return;
      revalidateInFlight = true;
      let stillAuthorized: boolean;
      try {
        stillAuthorized = await revalidate();
      } finally {
        revalidateInFlight = false;
      }
      if (closed) return;
      if (!stillAuthorized) {
        try {
          rawWrite(
            `event: stream_terminated\ndata: ${JSON.stringify({ reason: "session_revoked_or_membership_removed" })}\n\n`,
          );
        } catch {
          // Peer already gone; nothing to do.
        }
        teardown();
        try { reply.raw.end(); } catch { /* already ended */ }
        return;
      }
      try {
        rawWrite(`event: keepalive\ndata: ${JSON.stringify({ t: Date.now() })}\n\n`);
      } catch {
        teardown();
      }
    }, 15_000);

    req.raw.on("close", teardown);
  });
}
