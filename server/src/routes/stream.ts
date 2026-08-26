import type { FastifyInstance } from "fastify";
import { requireSession } from "../lib/session-middleware.js";
import { bus, type EventPayload } from "../lib/bus.js";
import { env } from "../env.js";

export async function streamRoutes(app: FastifyInstance): Promise<void> {
  // Server-Sent Events endpoint. Console tabs open a long-lived connection
  // and receive tenant-scoped events as they happen. One line of HTTP kept
  // open per open tab; server memory scales linearly.
  app.get("/stream", async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;

    // Set CORS headers ourselves — we're about to bypass Fastify's response
    // pipeline and stream to `reply.raw`, so the @fastify/cors plugin's
    // headers won't get flushed. Mirror the same allowlist logic here.
    const origin = req.headers.origin;
    if (typeof origin === "string" && env.ALLOWED_ORIGINS.includes(origin)) {
      reply.raw.setHeader("Access-Control-Allow-Origin", origin);
      reply.raw.setHeader("Access-Control-Allow-Credentials", "true");
      reply.raw.setHeader("Vary", "Origin");
    }

    reply.raw.setHeader("Content-Type", "text/event-stream");
    reply.raw.setHeader("Cache-Control", "no-store, no-transform");
    reply.raw.setHeader("Connection", "keep-alive");
    reply.raw.setHeader("X-Accel-Buffering", "no");
    reply.raw.flushHeaders();

    // Initial hello — makes browser EventSource fire onopen even under
    // load-balancer buffering.
    reply.raw.write(`event: hello\ndata: ${JSON.stringify({ ok: true })}\n\n`);

    const send = (ev: EventPayload): void => {
      const payload = JSON.stringify(ev);
      // SSE spec: each message is `event: <name>\ndata: <json>\n\n`.
      reply.raw.write(`event: ${ev.type}\ndata: ${payload}\n\n`);
    };
    const unsub = bus.subscribeOrg(claims.orgId, send);

    // Comment-only keepalive every 25s to survive intermediary idle timeouts
    // (Cloudflare defaults to 100s, Fly LB to 60s, Heroku to 55s).
    const keepalive = setInterval(() => {
      reply.raw.write(`: keepalive ${Date.now()}\n\n`);
    }, 25_000);

    req.raw.on("close", () => {
      clearInterval(keepalive);
      unsub();
    });
  });
}
