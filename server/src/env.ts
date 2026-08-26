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

export const env = Env.parse(process.env);
export type Env = z.infer<typeof Env>;
