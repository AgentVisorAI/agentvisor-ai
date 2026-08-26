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
  HOST: z.string().default("0.0.0.0"),
  NODE_ENV: z.enum(["development", "production", "test"]).default("development"),
  LOG_LEVEL: z.string().default("info"),
  JWT_SECRET: z.string().min(32, "JWT_SECRET must be at least 32 chars"),
  JWT_ISSUER: z.string().default("agentvisor-ai"),
  JWT_AUDIENCE: z.string().default("agentvisor-console"),
  SESSION_COOKIE_NAME: z.string().default("av_session"),
  SESSION_COOKIE_SECURE: z
    .string()
    .default("false")
    .transform((v) => v === "true"),
  DATABASE_URL: z.string().min(1),
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
