import { config } from "dotenv";
import { z } from "zod";

config();

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
