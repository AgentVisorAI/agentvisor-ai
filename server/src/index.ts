import cors from "@fastify/cors";
import cookie from "@fastify/cookie";
import helmet from "@fastify/helmet";
import rateLimit from "@fastify/rate-limit";
import Fastify from "fastify";
import { env } from "./env.js";
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
      redact: [
        "req.headers.authorization",
        "req.headers.cookie",
        "res.headers[set-cookie]",
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
      if (env.ALLOWED_ORIGINS.length === 0) return cb(null, true);
      cb(null, env.ALLOWED_ORIGINS.includes(origin));
    },
    credentials: true,
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

  app.addHook("preHandler", authenticate);

  app.get("/healthz", async () => ({ ok: true, version: "0.1.0" }));

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

  // Graceful shutdown — Fly/Cloud Run/Kubernetes all send SIGTERM before
  // the hard kill window. Close the HTTP server (drains in-flight requests),
  // disconnect Prisma, then exit. Target: sub-second in the common case.
  const shutdown = async (signal: string) => {
    app.log.info({ signal }, "graceful shutdown starting");
    try {
      await app.close();
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
