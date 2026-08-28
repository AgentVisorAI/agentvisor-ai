import { config } from "dotenv";
import { z } from "zod";
import crypto from "node:crypto";

config();

// Free-tier PaaS providers inject the Postgres URL under DIFFERENT env
// names. Normalizing here means the same code deploys with zero config
// tweaks anywhere. Priority order: explicit DATABASE_URL wins, then the
// provider-native names in order of specificity.
if (!process.env.DATABASE_URL) {
  const aliases = [
    "POSTGRES_URL",         // Vercel Postgres, Vercel-linked Neon
    "POSTGRES_PRISMA_URL",  // Vercel (pooled — Prisma preference)
    "NETLIFY_DATABASE_URL", // Netlify Postgres
    "NEON_DATABASE_URL",    // Neon Vercel integration
    "PG_URL",               // ad-hoc
    "PGURL",                // libpq convention
    "DATABASE_URL_POOLED",  // Fly Postgres pooler
  ];
  for (const name of aliases) {
    const val = process.env[name];
    if (val && typeof val === "string") {
      process.env.DATABASE_URL = val;
      break;
    }
  }
}

// In production a missing JWT_SECRET is fatal (see the schema). In
// non-production we generate an ephemeral one so `npm run dev` works
// out of the box — the tradeoff is sessions don't survive restarts,
// which is fine for local development.
if (!process.env.JWT_SECRET && process.env.NODE_ENV !== "production") {
  process.env.JWT_SECRET = crypto.randomBytes(48).toString("hex");
}

const Env = z.object({
  PORT: z.coerce.number().int().min(1).max(65535).default(8080),
  // Listen on all interfaces via IPv6 wildcard `::`. Modern OS kernels map
  // this to accept both IPv4 and IPv6 connections (v4-mapped IPv6), so a
  // single bind covers dual-stack cloud providers (Fly.io, GCP, K8s IPv6
  // service meshes) without needing two sockets. Explicit HOST env still
  // wins if the operator wants a stricter bind (e.g. 127.0.0.1 for a
  // sidecar-only deployment).
  HOST: z.string().default("::"),
  NODE_ENV: z.enum(["development", "production", "test"]).default("development"),
  LOG_LEVEL: z.string().default("info"),
  JWT_SECRET: z.string().min(32, "JWT_SECRET must be at least 32 chars"),
  // R96 F3: optional comma-separated list of cookie-signing
  // secrets. First entry signs; all entries verify. Enables key
  // rotation without breaking in-flight OAuth flows (users
  // mid-Google-consent otherwise get missing_state_cookie on
  // callback). Also decouples cookie HMAC from JWT_SECRET
  // (defense-in-depth — a JWT-key disclosure no longer
  // simultaneously compromises cookie signatures). If unset,
  // falls back to JWT_SECRET (single entry) so existing
  // deployments don't need to change env config.
  COOKIE_SECRETS: z
    .string()
    .optional()
    .transform((v) =>
      (v ?? "")
        .split(",")
        .map((s) => s.trim())
        .filter((s) => s.length >= 32),
    ),
  JWT_ISSUER: z.string().default("agentvisor-ai"),
  JWT_AUDIENCE: z.string().default("agentvisor-console"),
  SESSION_COOKIE_NAME: z.string().default("av_session"),
  // Explicit override wins. Otherwise: Secure in production, plain in
  // dev so devs can use localhost without HTTPS. Guards against the
  // footgun of forgetting to set this in a real deployment.
  SESSION_COOKIE_SECURE: z
    .string()
    .optional()
    .transform((v) => {
      if (v === "true") return true;
      if (v === "false") return false;
      return process.env.NODE_ENV === "production";
    }),
  DATABASE_URL: z.string().min(1),
  // R96 F1: number of proxy hops in front of the API. Cloudflare
  // + LB stacks use 2; Fly.io / Cloud Run / Heroku bare are 1;
  // local dev is 0. R95 hardcoded a single-hop function which
  // silently regressed 2+ hop deploys (real users bucketed into
  // Cloudflare edge IPs). Configurable now.
  TRUSTED_PROXY_HOP_COUNT: z
    .string()
    .default("1")
    .transform((v) => {
      const n = parseInt(v, 10);
      return isNaN(n) || n < 0 || n > 8 ? 1 : n;
    }),
  ALLOWED_ORIGINS: z
    .string()
    .default("")
    .transform((v) =>
      v
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean),
    ),
  // IPs (or IP prefixes) allowed to scrape /metrics. Empty = allow
  // everyone (dev). In production keep this scoped to the scraper's
  // egress addresses so we don't leak traffic patterns.
  ALLOW_METRICS_IPS: z
    .string()
    .default("")
    .transform((v) =>
      v
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean),
    ),
  // Public base URL of the console. Used to build OAuth redirect_uri
  // and password-reset links. e.g. https://agentvisorai.me
  APP_BASE_URL: z.string().default("http://localhost:8787"),
  // OIDC providers. All optional — the login page only shows a
  // provider button when the corresponding client-id is set.
  GOOGLE_CLIENT_ID: z.string().optional(),
  GOOGLE_CLIENT_SECRET: z.string().optional(),
  MICROSOFT_CLIENT_ID: z.string().optional(),
  MICROSOFT_CLIENT_SECRET: z.string().optional(),
  // Microsoft tenant id or 'common' (both work / school and personal).
  MICROSOFT_TENANT: z.string().default("common"),
  // Mailer. Priority: RESEND_API_KEY > SMTP_URL > dev-only stub. In
  // production the app refuses to boot if neither is set (checked in
  // main() so misconfigured deployments crash immediately, not on the
  // first reset request weeks later).
  RESEND_API_KEY: z.string().optional(),
  SMTP_URL: z.string().optional(),
  EMAIL_FROM: z.string().default("AgentVisor AI <no-reply@agentvisorai.me>"),
});

const parsed = Env.safeParse(process.env);
if (!parsed.success) {
  // eslint-disable-next-line no-console
  console.error("Environment validation failed. Missing or invalid:");
  for (const issue of parsed.error.issues) {
    // eslint-disable-next-line no-console
    console.error("  •", issue.path.join("."), "→", issue.message);
  }
  process.exit(1);
  // Unreachable, but tells the type checker that env below is never
  // undefined even in environments where @types/node hasn't loaded the
  // `process.exit(): never` signature yet.
  throw new Error("unreachable");
}
export const env = parsed.data;
export type Env = z.infer<typeof Env>;
