import cors from "@fastify/cors";
import cookie from "@fastify/cookie";
import formbody from "@fastify/formbody";
import helmet from "@fastify/helmet";
import rateLimit from "@fastify/rate-limit";
import Fastify from "fastify";
import crypto from "node:crypto";
import { db } from "./db.js";
import { env } from "./env.js";
import { bus } from "./lib/bus.js";
import { ipMatchesAny } from "./lib/cidr.js";
import { getMailer } from "./lib/mail.js";
import {
  httpRequestDurationSeconds,
  httpRequestsTotal,
  registry as metricsRegistry,
} from "./lib/metrics.js";
import { authenticate } from "./lib/session-middleware.js";
import { apiKeyRoutes } from "./routes/api-keys.js";
import { authRoutes } from "./routes/auth.js";
import { deploymentRoutes } from "./routes/deployments.js";
import { ingestRoutes } from "./routes/ingest.js";
import { memberRoutes } from "./routes/members.js";
import { oauthRoutes } from "./routes/oauth.js";
import { orgRoutes } from "./routes/org.js";
import { readRoutes } from "./routes/read.js";
import { samlRoutes } from "./routes/saml.js";
import { streamRoutes } from "./routes/stream.js";
import { webauthnRoutes } from "./routes/webauthn.js";
import { webhookRoutes } from "./routes/webhooks.js";
import { startWebhookSweeper, stopWebhookSweeper } from "./lib/webhooks.js";
import { startRetentionSweeper, stopRetentionSweeper } from "./lib/retention.js";

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
    // R95 F3 + R96 F1: trust EXACTLY `TRUSTED_PROXY_HOP_COUNT`
    // hops. R95 hardcoded a single-hop function which silently
    // regressed Cloudflare + ALB deployments (real users
    // bucketed into cf_edge_ip because the second hop wasn't
    // trusted → session-middleware.ts IP allowlist, rate-limit
    // key, and audit.ts AuditEntry.ip all recorded the edge IP
    // instead of the client). Now configurable via env; default
    // 1 covers 'PaaS + one LB in front' (Fly, Cloud Run, Heroku
    // bare). Set TRUSTED_PROXY_HOP_COUNT=2 for CF+LB;
    // TRUSTED_PROXY_HOP_COUNT=0 for local dev with no proxy.
    // Function form: proxy-addr calls this once per hop; return
    // true iff the hop index is inside the trusted range.
    trustProxy: (_addr: string, hop: number): boolean =>
      hop < env.TRUSTED_PROXY_HOP_COUNT,
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
  // R95 F4 + R96 F3: HMAC-signed OAuth state cookie via
  // @fastify/cookie. Accept a comma-separated COOKIE_SECRETS
  // env var (first entry signs, all verify) for key rotation
  // without breaking in-flight OAuth flows. Falls back to
  // JWT_SECRET for backward-compat with deployments that
  // haven't set COOKIE_SECRETS yet. Defense-in-depth: a
  // dedicated COOKIE_SECRETS decouples cookie HMAC from
  // JWT signing key so a disclosure of one doesn't
  // automatically compromise the other.
  const cookieSecrets = env.COOKIE_SECRETS.length > 0
    ? env.COOKIE_SECRETS
    : [env.JWT_SECRET];
  await app.register(cookie, { secret: cookieSecrets });
  // application/x-www-form-urlencoded body parser — required for SAML
  // Assertion Consumer Service (IdP posts SAMLResponse in this shape).
  await app.register(formbody);
  await app.register(rateLimit, {
    // Global backstop against IP-level abuse. Per-user limits live at the
    // route level (auth/signup are tighter, ingest is looser to accommodate
    // busy daemons batching every second).
    max: 300,
    timeWindow: "1 minute",
    // Never rate-limit the ops endpoints. LB health probes hit /healthz
    // and /readyz on a 15-30s cadence; a metrics scraper hits /metrics
    // every 15s. A dozen instances × a couple of probers would eat the
    // 300/min budget and make the API look down. .well-known is also
    // always public (RFC 9116 disclosure lookup).
    //
    // Also exempt /api/v1/ingest/*. Daemons authenticate per-deployment
    // via a cryptographically verified token (argon2), and legitimate
    // production traffic can burst to thousands of events/sec on a
    // single deployment. Rate-limiting them at 300rpm/IP would throttle
    // every real customer as soon as they scale. Per-tenant abuse is
    // bounded by the daemon token itself (only that deployment's org
    // is affected).
    allowList: (req) => {
      const u = req.url ?? "";
      return u === "/healthz" || u === "/readyz" || u === "/metrics" ||
        u.startsWith("/.well-known/") ||
        u.startsWith("/api/v1/ingest") ||
        // SAML ACS + login redirects should never hit rate limits. If the
        // IdP posts a valid response it's a real user; if not, the SAML
        // signature check itself is the DoS guard (no DB writes beyond
        // that check).
        /^\/api\/v1\/auth\/saml\/[^/]+\/(acs|slo|metadata\.xml|login)/.test(u);
    },
    keyGenerator: (req) => {
      // R93 F1: `authenticate` runs as a preHandler; @fastify/rate-limit
      // invokes keyGenerator in onRequest. `req.session` was ALWAYS
      // undefined here, so every request keyed on req.ip regardless of
      // the (stated) intent to key per-user. That silently made every
      // corp-NAT/CGNAT tenant share ONE bucket — well-behaved users
      // hit 429s alongside a single abuser, and a single hostile user
      // rotating IPv6 privacy addresses had infinite per-user quota.
      // Fix without moving hook order (which would touch every other
      // route's expectations): derive a stable bucket key from the
      // session cookie or API-key header ourselves, pre-auth. We
      // don't verify the JWT here (async verify + secret access is
      // too heavy for every request); the opaque cookie's sha256 is
      // enough for stable per-user bucketing because a stolen cookie
      // is per-user by definition. Same for API-key Authorization
      // headers.
      const cookieHdr = req.headers.cookie ?? "";
      const m = /(?:^|;\s*)av_session=([^;]+)/.exec(cookieHdr);
      if (m) {
        return "s:" + crypto.createHash("sha256").update(m[1]!).digest("hex").slice(0, 16);
      }
      const auth = req.headers.authorization ?? "";
      if (typeof auth === "string" && auth.startsWith("Bearer ")) {
        return "a:" + crypto.createHash("sha256").update(auth.slice(7)).digest("hex").slice(0, 16);
      }
      return "ip:" + req.ip;
    },
  });

  // Force HTTPS in production. The proxy in front of us (Fly LB / Cloud
  // Run / Cloudflare) terminates TLS and forwards on http, setting
  // X-Forwarded-Proto to record the original scheme. Reject anything
  // that arrives with X-Forwarded-Proto=http so a customer with a stale
  // http:// bookmark doesn't accidentally send credentials in the clear.
  //
  // Requests without ANY X-Forwarded-Proto header are on the internal
  // pod network (loopback healthchecks, container-to-container smoke
  // tests) — we let those through because there is no external hop that
  // could have downgraded the scheme.
  if (env.NODE_ENV === "production") {
    app.addHook("onRequest", async (req, reply) => {
      if (req.url === "/healthz" || req.url === "/readyz" || req.url.startsWith("/.well-known/")) {
        return;
      }
      const xfp = req.headers["x-forwarded-proto"];
      const forwarded = Array.isArray(xfp) ? xfp[0] : xfp;
      if (typeof forwarded === "string" && forwarded !== "https") {
        return reply.code(400).send({ error: "https_required" });
      }
    });
  }

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
    // SAML ACS receives form-encoded POSTs from the IdP itself
    // (cross-site by definition — that's the point). Its crypto layer
    // does the CSRF-equivalent check by verifying the IdP-signed
    // assertion. The route is also idempotent w.r.t. auth (it mints
    // a fresh cookie); ambient cookies aren't consulted.
    //
    // R88 F2/F4: SLO is NO LONGER exempt. The SLO handler previously
    // did no signature check, no configId lookup, and no session
    // check — any cross-origin POST forced a cookie-clear on any
    // authenticated visitor. Enforcing CSRF on SLO forces the
    // handler down the origin-verified path where it can safely
    // require a session cookie + valid configId.
    if (
      typeof req.url === "string" &&
      /^\/api\/v1\/auth\/saml\/[^/]+\/acs(\?|$)/.test(req.url)
    ) {
      return;
    }

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

    // If neither Origin nor Referer is present the request is coming
    // from a script or curl (browsers always attach one on cross-site
    // requests). Allow — those requests don't ride ambient cookies
    // unless the caller explicitly passed one, and if they did they're
    // authenticated via the JWT anyway.
    if (!rawSource) return;

    const allowed = env.ALLOWED_ORIGINS;
    // In dev with an empty allow-list we skip (matches the CORS choice).
    if (allowed.length === 0 && env.NODE_ENV !== "production") return;
    if (!allowed.includes(rawSource)) {
      return reply.code(403).send({ error: "forbidden_origin" });
    }

    // Sec-Fetch-Site defense-in-depth. Modern browsers set this to
    // 'same-origin' or 'same-site' on legitimate SPA requests. A
    // form-triggered CSRF from a different site would arrive as
    // 'cross-site'. Older browsers omit the header entirely — those we
    // still let through because the Origin check above already caught
    // any cross-site attempt.
    const secFetchSite = typeof req.headers["sec-fetch-site"] === "string"
      ? req.headers["sec-fetch-site"]
      : "";
    if (secFetchSite === "cross-site") {
      return reply.code(403).send({ error: "forbidden_cross_site" });
    }
  });

  app.addHook("preHandler", authenticate);

  // Echo the request-id back on every response (and every problem+json
  // error body) so ops can grep the logs from a customer's browser
  // console in one step. Fastify already generates req.id for logging;
  // we surface it here.
  //
  // Also normalizes any legacy { error: "..." } response body on a 4xx/5xx
  // into RFC 7807 problem+json. Routes still write the terse shape (less
  // ceremony), and the wire stays consistent. Successful 2xx responses
  // pass through untouched.
  app.addHook("onSend", async (req, reply, payload) => {
    reply.header("X-Request-Id", String(req.id));
    if (reply.statusCode < 400) return payload;
    if (typeof payload !== "string") return payload;
    // Only transform JSON bodies — HTML error pages (helmet, static) pass through.
    const ct = String(reply.getHeader("content-type") || "");
    if (!ct.includes("json")) return payload;
    let parsed: unknown;
    try {
      parsed = JSON.parse(payload);
    } catch {
      return payload;
    }
    // Already problem+json — nothing to do.
    if (parsed && typeof parsed === "object" && "type" in parsed && "title" in parsed) return payload;
    const legacy = parsed as { error?: string; issues?: unknown; [k: string]: unknown };
    if (typeof legacy.error !== "string") return payload;
    reply.type("application/problem+json");
    const problem = {
      type: "about:blank",
      title: reply.statusCode === 500 ? "Internal Server Error" : "Request Failed",
      status: reply.statusCode,
      detail: legacy.error,
      instance: req.url,
      errorCode: legacy.error,
      requestId: String(req.id),
      ...(legacy.issues !== undefined ? { issues: legacy.issues } : {}),
    };
    return JSON.stringify(problem);
  });

  // RFC 7807 Problem+JSON error envelope. Every non-2xx response goes
  // through this handler so clients see one stable shape:
  //
  //   { type, title, status, detail, instance, errorCode, requestId }
  //
  // The `errorCode` is a string clients can switch on without regexing
  // the human-readable title. That gives us room to iterate on wording
  // without breaking every SDK consumer.
  app.setErrorHandler(async (rawErr: unknown, req, reply) => {
    // Fastify's typings pass FastifyError but strict tsconfig treats
    // it as `unknown` in the handler — assert the loose shape we need.
    const err = rawErr as {
      statusCode?: number;
      code?: string;
      message?: string;
      name?: string;
      validation?: unknown[];
    };
    const status = err.statusCode ?? 500;
    // Zod / Fastify schema validation errors surface with err.validation.
    const isValidation = Array.isArray(err.validation);
    const errorCode = err.code ?? (isValidation ? "invalid_input" : status === 500 ? "internal_error" : "error");
    const title = err.name && err.name !== "Error" ? err.name : status === 500 ? "Internal Server Error" : "Request Failed";

    if (status >= 500) {
      req.log.error({ err: rawErr }, "unhandled error");
    } else {
      req.log.warn({ err: rawErr }, "request rejected");
    }

    reply.header("X-Request-Id", String(req.id));
    reply.type("application/problem+json");
    return reply.status(status).send({
      type: `about:blank`,
      title,
      status,
      // Never leak internal error messages to the client on 5xx — those
      // may reveal stack frames, table names, or config values. 4xx
      // errors are safe to surface (we produced them deliberately).
      detail: status >= 500 ? "An unexpected error occurred." : err.message ?? "Request failed",
      instance: req.url,
      errorCode,
      requestId: String(req.id),
      ...(isValidation ? { issues: err.validation } : {}),
    });
  });

  // 404 fallback also uses the problem+json shape so a wrong path from
  // an SDK debugging session lands consistently.
  app.setNotFoundHandler(async (req, reply) => {
    reply.header("X-Request-Id", String(req.id));
    reply.type("application/problem+json");
    return reply.status(404).send({
      type: "about:blank",
      title: "Not Found",
      status: 404,
      detail: `No route matches ${req.method} ${req.url}`,
      instance: req.url,
      errorCode: "not_found",
      requestId: String(req.id),
    });
  });

  app.get("/healthz", async () => ({ ok: true, version: "0.1.0" }));

  // Prometheus metrics endpoint. Emits process metrics (heap, event
  // loop, GC) + our own HTTP counters and latency histogram. Gated
  // behind ALLOW_METRICS_IPS so we don't leak traffic patterns to the
  // public internet — allow-list contains the scraper's egress IPs
  // (Grafana Cloud, Prometheus server, k8s cluster ranges, etc). Set
  // ALLOW_METRICS_IPS="0.0.0.0/0" only if the metrics scraper is on the
  // same private network.
  app.get("/metrics", async (req, reply) => {
    const allowed = env.ALLOW_METRICS_IPS;
    if (allowed.length > 0) {
      const ip = req.ip;
      // R77 F2 (MEDIUM-HIGH): route allowlist checks through
      // `ipMatchesAny` (lib/cidr.ts) so a naive `startsWith`
      // prefix-match cannot silently widen the accepted set.
      // Prior shape `ip === a || ip.startsWith(a)` treated
      // `ALLOW_METRICS_IPS=10.0.0.1` as admitting `10.0.0.1`,
      // `10.0.0.10..19`, `10.0.0.100..199` (30 addresses); a
      // fat-finger `ALLOW_METRICS_IPS=1` admitted every IP
      // starting with `1` (~30% of the v4 space). Prometheus
      // counters leak tenant traffic patterns / model IDs /
      // customer counts so widening the ACL by mistake is a
      // real telemetry-exfiltration hazard.
      //
      // `ipMatchesAny` accepts either an exact IP (`10.0.0.1`)
      // or a CIDR (`10.0.0.0/24`), and does a proper prefix-bit
      // comparison — never a lexicographic startsWith on the
      // string form. Operators can now express both single-IP
      // and subnet allowlists correctly, and typos don't
      // silently accept 30% of the internet.
      const ok = ipMatchesAny(ip, allowed);
      if (!ok) return reply.code(403).send({ error: "forbidden" });
    }
    reply.header("Content-Type", metricsRegistry.contentType);
    return reply.send(await metricsRegistry.metrics());
  });

  // Measure every request. Hooks fire around every route (including
  // /healthz + /readyz) so we get a full picture without opting each
  // handler in. Latency uses the `onRequest` -> `onResponse` diff which
  // includes queueing, middleware, and handler time.
  app.addHook("onRequest", async (req) => {
    (req as unknown as { _startAt: [number, number] })._startAt = process.hrtime();
  });
  app.addHook("onResponse", async (req, reply) => {
    const start = (req as unknown as { _startAt?: [number, number] })._startAt;
    if (!start) return;
    const diff = process.hrtime(start);
    const seconds = diff[0] + diff[1] / 1e9;
    // routeOptions.url is the parameterized template (e.g. /api/v1/sessions/:id)
    // so we don't blow cardinality on session-id-shaped URLs. Fastify 5.x
    // moved this from req.routerPath — an old req.routerPath fallback was
    // silently returning "unmatched" for every request in prod.
    const routeLabel = req.routeOptions?.url ?? "unmatched";
    const labels = {
      method: req.method,
      route: routeLabel,
      status: String(reply.statusCode),
    };
    httpRequestDurationSeconds.observe(labels, seconds);
    httpRequestsTotal.inc(labels);
  });

  // /readyz separates process-alive (healthz) from ready-to-serve. Fly.io
  // + Cloud Run + Kubernetes all recommend this pattern: liveness stays
  // cheap so a hiccup doesn't restart the container; readiness probes the
  // real dependencies and returns 503 so the platform stops routing
  // traffic during an outage instead of serving 500s from every request.
  //
  // We probe Postgres directly (Prisma will lazily reconnect on a healthy
  // pool, so a bare SELECT 1 is enough). Bus liveness is checked via the
  // Bus.isReady() flag — the bridge auto-reconnects, but if it's DOWN we
  // still serve READ traffic; only SSE fan-out degrades to same-instance.
  app.get("/readyz", async (_req, reply) => {
    const started = Date.now();
    let dbOk = false;
    let dbErr: string | undefined;
    try {
      await db.$queryRawUnsafe("SELECT 1");
      dbOk = true;
    } catch (err) {
      dbErr = err instanceof Error ? err.message : String(err);
    }
    const busReady = bus.isReady();
    const ok = dbOk;
    const body = {
      ok,
      version: "0.1.0",
      checks: {
        db: dbOk ? "ok" : "fail",
        bus: busReady ? "ok" : "degraded",
      },
      elapsedMs: Date.now() - started,
      ...(dbErr ? { dbError: dbErr } : {}),
    };
    return reply.code(ok ? 200 : 503).send(body);
  });

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
  await app.register(async (r) => r.register(oauthRoutes), {
    prefix: "/api/v1/auth/oauth",
  });
  await app.register(async (r) => r.register(samlRoutes), {
    prefix: "/api/v1/auth/saml",
  });
  await app.register(async (r) => r.register(webauthnRoutes), {
    prefix: "/api/v1/auth/webauthn",
  });
  await app.register(async (r) => r.register(memberRoutes), {
    prefix: "/api/v1/members",
  });
  await app.register(async (r) => r.register(apiKeyRoutes), {
    prefix: "/api/v1/keys",
  });
  await app.register(async (r) => r.register(webhookRoutes), {
    prefix: "/api/v1/webhooks",
  });
  await app.register(async (r) => r.register(orgRoutes), {
    prefix: "/api/v1/org",
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

  // Fail-fast on missing mailer in production. In dev we allow the
  // stub driver (logs the reset link) — in prod, silently swallowing
  // reset requests would be a security bug (users locked out and no
  // signal to ops).
  try {
    const m = getMailer(app.log);
    app.log.info({ mailer: m.driver }, "mailer configured");
  } catch (err) {
    app.log.error({ err }, "fatal: mailer required in production");
    process.exit(1);
  }

  // Wire up the cross-instance SSE bridge. Non-fatal if it fails at boot —
  // the in-process bus keeps working, and a reconnect loop retries the
  // bridge on cadence. This is what lets us scale from 1 → N instances
  // on Fly / Cloud Run / Render / k8s without adding Redis.
  const bridgeUp = await bus.connectPgBridge();
  app.log.info({ bridgeUp }, "pg listen/notify bridge status");

  // Start the webhook retry sweeper. 15s cadence; scans for
  // status='retrying' deliveries whose nextRetryAt has passed and
  // re-fires them. Idempotent — safe against double-registration.
  startWebhookSweeper(app.log);
  startRetentionSweeper(app.log);

  const shutdown = async (signal: string) => {
    app.log.info({ signal }, "graceful shutdown starting");
    try {
      stopWebhookSweeper();
      stopRetentionSweeper();
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
