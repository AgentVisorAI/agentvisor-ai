import type { SessionClaims } from "./lib/auth.js";

declare module "fastify" {
  interface FastifyRequest {
    session?: SessionClaims;
  }
}
