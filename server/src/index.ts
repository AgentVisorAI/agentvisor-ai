import cors from "@fastify/cors";
import cookie from "@fastify/cookie";
import helmet from "@fastify/helmet";
import rateLimit from "@fastify/rate-limit";
import Fastify from "fastify";
import { env } from "./env.js";
import { bus } from "./lib/bus.js";
import { authenticate } from "./lib/session-middleware.js";
import { authRoutes } from "./routes/auth.js";
import { deploymentRoutes } from "./routes/deployments.js";
import { ingestRoutes } from "./routes/ingest.js";
import { readRoutes } from "./routes/read.js";
import { streamRoutes } from "./routes/stream.js";

// `types.d.ts` declares the `request.session` typing. It's picked up by the
// TypeScript compiler via `include`, no runtime import required.


async function main(): Promise<void> {
  const app = Fastify({
    logger: {
      level: env.LOG_LEVEL,
      // Belt-and-suspenders: even if a handler accidentally passes a
      // request body to the logger, these paths get replaced with
      // `[Redacted]` before serialization. Auth handlers are also
      // audited to never pass `req.body` at all — this is defense in
      // depth in case a future refactor slips.
      redact: [
        "req.headers.authorization",
        "req.headers.cookie",
        "res.headers[set-cookie]",
        "*.password",
        "*.newPassword",
        "*.token",
        "*.plaintextToken",
        "*.devOnlyResetToken",
        "*.resetLinkHint",
        "req.body.password",
        "req.body.newPassword",
        "req.body.token",
      ],
    },
    // Trust one proxy hop in front of us — most PaaS providers add exactly one.
    trustProxy: true,
    bodyLimit: 4 * 1024 * 1024, // 4 MiB — matches the daemon's own request cap
  });

  await app.register(helmet, {
    // Every request is API JSON — the console is served from a separate
    // static origin. Deny inline scripts + external loads entirely to shrink
    // the exploit surface if something ever does render HTML.
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        defaultSrc: ["'none'"],
        baseUri: ["'none'"],
        frameAncestors: ["'none'"],
        formAction: ["'none'"],
      },
    },
    // 2 years, apply to subdomains, allow HSTS preload submission.
    strictTransportSecurity: {
      maxAge: 63072000,
      includeSubDomains: true,
      preload: true,
    },
    referrerPolicy: { policy: "no-referrer" },
    crossOriginOpenerPolicy: { policy: "same-origin" },
    crossOriginResourcePolicy: { policy: "same-site" },
    xFrameOptions: { action: "deny" },
    xContentTypeOptions: true,
  });
  await app.register(cors, {
    origin: (origin, cb) => {
      // Same-origin (server-to-server, curl, etc.) has no Origin header.
      if (!origin) return cb(null, true);
      // In production an empty allow-list would fail-open — reject.
      if (env.ALLOWED_ORIGINS.length === 0) {
        if (env.NODE_ENV === "production") return cb(null, false);
        // Dev: allow anything so `npm run dev` on any port works.
        return cb(null, true);
      }
      cb(null, env.ALLOWED_ORIGINS.includes(origin));
    },
    credentials: true,
    // Include DELETE + PATCH + PUT in the preflight response — @fastify/cors
    // defaults to just GET/POST/HEAD which silently breaks the console's
    // deployment/token-rotation flows on cross-origin deploys.
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    exposedHeaders: ["X-Request-Id"],
  });
  await app.register(cookie);
  await app.register(rateLimit, {
    // Global backstop against IP-level abuse. Per-user limits live at the
    // route level (auth/signup are tighter, ingest is looser to accommodate
    // busy daemons batching every second).
    max: 300,
    timeWindow: "1 minute",
    keyGenerator: (req) => {
      // Prefer the authenticated user's ID for rate-limit accounting so a
      // shared NAT doesn't get punished for one abusive tenant. Falls back
      // to IP when the request is unauthenticated.
      return (req as unknown as { session?: { sub: string } }).session?.sub ?? req.ip;
    },
  });

  // Defense-in-depth CSRF check for state-changing methods. SameSite=Lax
  // cookies + JSON-only endpoints already block cross-site form posts,
  // but a strict Origin/Referer allow-list closes the remaining slivers
  // (e.g. old browsers, subdomain takeovers). See OWASP Cross-Site
  // Request Forgery Prevention Cheat Sheet §2.2 (2024 edition).
  //
  // Skipped when:
  //   • Method is safe (GET/HEAD/OPTIONS).
  //   • Path is /api/v1/ingest — daemons attach an X-AV-Deployment token
  //     which is cryptographically verified before any state mutation.
  //   • No Origin/Referer at all — same-origin fetches from most modern
  //     browsers, curl/scripts (no cookie either), and health checks.
  //
  // Registered BEFORE authenticate so a forbidden origin never touches
  // Prisma or the JWT verify.
  app.addHook("preHandler", async (req, reply) => {
    const method = req.method.toUpperCase();
    if (method === "GET" || method === "HEAD" || method === "OPTIONS") return;
    if (typeof req.url === "string" && req.url.startsWith("/api/v1/ingest")) return;

    const origin = typeof req.headers.origin === "string" ? req.headers.origin : "";
    const referer = typeof req.headers.referer === "string" ? req.headers.referer : "";
    let refererOrigin = "";
    if (referer) {
      try {
        refererOrigin = new URL(referer).origin;
      } catch {
        // Malformed Referer → treat as absent.
      }
    }
    const rawSource = origin || refererOrigin;
    if (!rawSource) return; // No cross-origin marker present.

    const allowed = env.ALLOWED_ORIGINS;
    // In dev with an empty allow-list we skip (matches the CORS choice).
    if (allowed.length === 0 && env.NODE_ENV !== "production") return;
    if (allowed.includes(rawSource)) return;

    return reply.code(403).send({ error: "forbidden_origin" });
  });

  app.addHook("preHandler", authenticate);

  app.get("/healthz", async () => ({ ok: true, version: "0.1.0" }));

  // RFC 9116 — advertise a security contact + policy on the API too, not
  // just the static docs. Researchers scanning the origin should always
  // find a machine-readable disclosure path.
  const securityTxt = [
    "Contact: mailto:security@agentvisorai.me",
    "Expires: 2027-08-25T00:00:00.000Z",
    "Preferred-Languages: en",
    "Canonical: https://api.agentvisorai.me/.well-known/security.txt",
    "Policy: https://github.com/AgentVisorAI/agentvisor-ai/blob/main/SECURITY.md",
    "",
  ].join("\n");
  app.get("/.well-known/security.txt", async (_req, reply) => {
    reply.header("Content-Type", "text/plain; charset=utf-8");
    return securityTxt;
  });

  await app.register(async (r) => r.register(authRoutes), {
    prefix: "/api/v1/auth",
  });
  await app.register(async (r) => r.register(deploymentRoutes), {
    prefix: "/api/v1/deployments",
  });
  await app.register(async (r) => r.register(ingestRoutes), {
    prefix: "/api/v1/ingest",
  });
  await app.register(async (r) => r.register(readRoutes), {
    prefix: "/api/v1",
  });
  await app.register(async (r) => r.register(streamRoutes), {
    prefix: "/api/v1",
  });

  await app.listen({ port: env.PORT, host: env.HOST });

  // Wire up the cross-instance SSE bridge. Non-fatal if it fails at boot —
  // the in-process bus keeps working, and a reconnect loop retries the
  // bridge on cadence. This is what lets us scale from 1 → N instances
  // on Fly / Cloud Run / Render / k8s without adding Redis.
  const bridgeUp = await bus.connectPgBridge();
  app.log.info({ bridgeUp }, "pg listen/notify bridge status");

  // Graceful shutdown — Fly/Cloud Run/Kubernetes all send SIGTERM before
  // the hard kill window. Close the HTTP server (drains in-flight requests),
  // release the bus sockets, disconnect Prisma, then exit. Target:
  // sub-second in the common case.
  const shutdown = async (signal: string) => {
    app.log.info({ signal }, "graceful shutdown starting");
    try {
      await app.close();
      await bus.close();
    } catch (err) {
      app.log.error({ err }, "shutdown error");
    }
    process.exit(0);
  };
  process.on("SIGTERM", () => void shutdown("SIGTERM"));
  process.on("SIGINT", () => void shutdown("SIGINT"));
}

main().catch((err) => {
  // eslint-disable-next-line no-console
  console.error("fatal:", err);
  process.exit(1);
});
