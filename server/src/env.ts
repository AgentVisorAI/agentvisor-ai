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

// R176 F1: snapshot whether NODE_ENV was set BEFORE the Zod schema
// injects its "development" default. If an operator boots
// `npm run start` without setting NODE_ENV (bare Docker,
// systemd unit that forgot Environment=, ad-hoc launch on a
// self-hosted host — the platform automatons like Vercel/
// Heroku/Fly.io/K8s Deployment typically set it, but not
// everyone deploys through those), the whole app silently runs
// in dev mode: SESSION_COOKIE_SECURE auto-false → cookies over
// HTTP, HTTPS-force hook disabled at index.ts:223, empty
// ALLOWED_ORIGINS opens CORS at index.ts:110, dev-stub mailer
// allowed, and R175 F1's APP_BASE_URL production guard is
// bypassed. Zod's `.default("development")` fires
// indistinguishably from an explicit `NODE_ENV=development`
// export. Capture the boolean now so the runtime can flag it
// (main() below picks it up after Env parses).
const NODE_ENV_WAS_UNSET = process.env.NODE_ENV === undefined;

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
  // R96 F3 + R97 F-B: optional comma-separated list of
  // cookie-signing secrets. First entry signs; all entries
  // verify. Enables key rotation without breaking in-flight
  // OAuth flows. Also decouples cookie HMAC from JWT_SECRET
  // (defense-in-depth). If unset OR unparseable, falls back to
  // JWT_SECRET (single entry) so existing deployments don't
  // need to change env config.
  //
  // Fail-fast on partial config: if COOKIE_SECRETS is set but
  // every entry fails the min-32 length gate (common mistake:
  // 20 raw bytes → 27 base64 chars, forgotten leading quotes),
  // prior R96 shape silently dropped them all and fell back to
  // JWT_SECRET — reinstating exactly the coupling this env
  // was meant to break, with NO log line. Now: refine
  // rejects the config so the process crashes at boot with a
  // clear message.
  COOKIE_SECRETS: z
    .string()
    .optional()
    .transform((v) => ({
      raw: v,
      list: (v ?? "")
        .split(",")
        .map((s) => s.trim())
        .filter((s) => s.length > 0),
    }))
    .refine(
      (o) => o.raw === undefined || o.list.every((s) => s.length >= 32),
      "COOKIE_SECRETS entries must each be at least 32 chars",
    )
    .refine(
      (o) => o.raw === undefined || o.list.length > 0,
      "COOKIE_SECRETS was set but empty after parsing",
    )
    .transform((o) => o.list),
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
  // R96 F1 + R97 F-C + R98 F4: number of proxy hops in front
  // of the API. Cloudflare + LB stacks use 2; Fly.io / Cloud
  // Run / Heroku bare are 1; local dev is 0. R95 hardcoded a
  // single-hop function which silently regressed 2+ hop
  // deploys.
  //
  // R98 F4 hardens the parse: parseInt(v, 10) partial-parses
  // digit-prefixed strings — `parseInt("2 hops", 10) === 2`,
  // `parseInt("2.9", 10) === 2`, `parseInt("3abc", 10) === 3`
  // — all passed the R97 F-C refine and booted at a value
  // the operator never wrote. Ops dropping a comment into the
  // .env like TRUSTED_PROXY_HOP_COUNT="2 (CF+LB)" would load
  // as 2 with no signal. Number(v) is strict full-string
  // parse: Number("3abc") is NaN, Number("2.9") is 2.9;
  // Number.isInteger refine then rejects both.
  TRUSTED_PROXY_HOP_COUNT: z
    .string()
    .default("1")
    .transform((v) => Number(v.trim()))
    .refine(
      (n) => Number.isInteger(n) && n >= 0 && n <= 8,
      "TRUSTED_PROXY_HOP_COUNT must be an integer 0..8",
    ),
  // R99 F3: retention sweeper interval, in milliseconds.
  // Prior shape (retention.ts:29) did Number(process.env.X)
  // with no validation — Number('') = 0 and Number('6h') = NaN
  // (which Node clamps to 1 ms), both causing setInterval to
  // fire every ~1 ms and hammer Postgres with full org scans.
  // Bounds: 1 min (safety floor — prevents DoS-by-typo) to 24 h
  // (safety ceiling — retention must actually run). Default is
  // 6 hours.
  RETENTION_SWEEPER_INTERVAL_MS: z
    .string()
    .default(String(6 * 60 * 60 * 1000))
    .transform((v) => Number(v.trim()))
    .refine(
      (n) => Number.isInteger(n) && n >= 60_000 && n <= 86_400_000,
      "RETENTION_SWEEPER_INTERVAL_MS must be integer ms in [60000, 86400000]",
    ),
  // R151 F2: webhook retry sweeper interval, in milliseconds.
  // Same footgun as RETENTION_SWEEPER_INTERVAL_MS above (R99 F3):
  // prior shape (lib/webhooks.ts:635) did
  // `Number(process.env.WEBHOOK_SWEEPER_INTERVAL_MS ?? 15_000)`
  // with no validation — Number("") === 0, Number("15s") === NaN,
  // Number("15_000") === NaN (underscores rejected), all of which
  // Node's setInterval clamps to ~1 ms → sweeper hammers Postgres
  // with the FOR UPDATE SKIP LOCKED claim UPDATE every event-loop
  // tick. Ops-config typo only (not attacker-triggered) so LOW,
  // but the retention sibling got the full guard for the same
  // failure mode. Bounds: 1 s floor (retry latency ceiling for
  // failed webhook deliveries — anything longer starves customer
  // endpoints) to 5 min ceiling (safety net so operators don't
  // silently disable retries by setting it enormous). Default is
  // 15 s to match the historical constant.
  WEBHOOK_SWEEPER_INTERVAL_MS: z
    .string()
    .default("15000")
    .transform((v) => Number(v.trim()))
    .refine(
      (n) => Number.isInteger(n) && n >= 1_000 && n <= 300_000,
      "WEBHOOK_SWEEPER_INTERVAL_MS must be integer ms in [1000, 300000]",
    ),
  // R185 F1: opt-in relaxation of the webhook SSRF gate for
  // internal / RFC 1918 / loopback destinations. Prior shape at
  // lib/webhooks.ts:228 & :239 checked `env.NODE_ENV ===
  // "production"` — so any dev-mode deploy (or, worse, an
  // operator who forgot to set NODE_ENV in production per
  // R176's warning) fell open: an admin/owner could register
  // `http://10.0.0.1/admin` or `http://internal.corp.svc/` as
  // a webhook URL and the server would happily fetch it,
  // turning the webhook endpoint into an SSRF primitive
  // against the deployment's own private network. Fix: gate on
  // this explicit env var instead of NODE_ENV. Default false
  // (block internal IPs in ALL modes, including dev). Dev
  // workflows that legitimately need to POST to localhost /
  // 127.0.0.1 / an in-cluster address for testing set
  // `ALLOW_INTERNAL_WEBHOOK_TARGETS=true` explicitly — same
  // opt-in-to-danger discipline as any HTTPS-off, plaintext-
  // cookie override. Never legitimately set in production.
  ALLOW_INTERNAL_WEBHOOK_TARGETS: z
    .string()
    .optional()
    .transform((v) => v === "true" || v === "1"),
  ALLOWED_ORIGINS: z
    .string()
    .default("")
    .transform((v) =>
      v
        .split(",")
        .map((s) => s.trim())
        // R102 F2: strip any trailing slash. Browsers send Origin
        // per RFC 6454 as scheme+host+port with NO trailing slash
        // and no path. An operator who pastes a URL from the
        // browser bar (e.g. 'https://console.example.com/') would
        // otherwise store an entry that never matches the
        // browser-sent Origin — every downstream gate
        // (CORS at index.ts, SSE at stream.ts, WebAuthn RP at
        // webauthn.ts, CSRF preHandler at index.ts) uses
        // env.ALLOWED_ORIGINS.includes(origin), so ALL four
        // silently 403 every request from the legitimate origin.
        // Normalize on parse so operator config errors are
        // shrugged off.
        .map((s) => s.replace(/\/+$/, ""))
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
  // R175 F1: refuse to boot in production if left at the localhost
  // default (or on http://). APP_BASE_URL flows into:
  //   * reset-request emails (auth.ts:1042)
  //   * invite emails (members.ts:469)
  //   * SAML EntityID + ACS + SLO + LoginURL + metadata (lib/saml.ts:68)
  //   * OAuth redirect_uri sent to Google/Microsoft (oauth.ts:187)
  //   * OAuth error redirects (oauth.ts:167 & many)
  //   * WebAuthn rpID + expected origins (webauthn.ts:59, :82)
  //   * SAML redirects (saml.ts:222 & many)
  // If an operator boots a real deployment without setting
  // APP_BASE_URL, every one of those flows silently misroutes:
  // reset/invite links point at localhost:8787 (broken on any
  // remote machine; on shared or compromised machines, a local
  // attacker listening on :8787 would intercept the plaintext
  // token in the URL); OAuth redirect_uri mismatches with the
  // IdP registration → cascading failure or, if the IdP was
  // registered against localhost for dev testing, code goes to
  // localhost; WebAuthn passkeys register against rpID
  // "localhost" and stop working the moment the operator later
  // corrects APP_BASE_URL (registered passkeys are pinned to
  // their rpID). Same failure-fast posture as the mailer guard
  // at lib/mail.ts:111-117 — misconfiguration should crash at
  // boot, not on the first reset three weeks later. Dev
  // (NODE_ENV != production) still defaults to the local URL
  // so `npm run dev` works out of the box.
  APP_BASE_URL: z
    .string()
    .default("http://localhost:8787")
    .refine(
      (v) => {
        if (process.env.NODE_ENV !== "production") return true;
        // Production requires an explicit non-default value on
        // https://. Reject the localhost default and any http://
        // URL (a real deployment always has TLS; the R105 F2
        // HTTPS-force hook at index.ts:223 would 400 every
        // request otherwise, but reset/invite email links are
        // baked in at send-time and don't go through that hook).
        if (v === "http://localhost:8787") return false;
        if (v.startsWith("http://")) return false;
        return true;
      },
      "APP_BASE_URL must be an https:// URL in production; the localhost default is unsafe for reset-links, invite-links, OAuth redirect_uri, and WebAuthn rpID.",
    ),
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

// R176 F1: emit a loud, single-line stderr warning at boot when
// NODE_ENV was defaulted rather than explicitly set. See the
// NODE_ENV_WAS_UNSET snapshot above for the full rationale.
// Uses a leading string that ops log-aggregation rules can
// alert on (grep-friendly slug) and includes the resolved env
// so operators immediately see which fail-open branches
// activated. Warning-only (not fatal) because plenty of dev
// workflows legitimately omit NODE_ENV, but the presence of
// this line in a production log stream is a red flag.
if (NODE_ENV_WAS_UNSET) {
  // eslint-disable-next-line no-console
  console.warn(
    `env_warn_node_env_defaulted: NODE_ENV was not set in the environment; ` +
      `defaulting to "${env.NODE_ENV}". If this is a production deployment, ` +
      `set NODE_ENV=production explicitly — otherwise SESSION_COOKIE_SECURE ` +
      `auto-falses (cookies over HTTP), HTTPS-force is disabled, dev-stub ` +
      `mailer is allowed, and the R175 APP_BASE_URL production guard is ` +
      `bypassed.`,
  );
}
