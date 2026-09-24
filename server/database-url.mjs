// Keep migration startup and the API on the same explicitly selected database.
// This module has no imports or side effects beyond the supplied environment.
export function normalizeDatabaseUrl(environment) {
  if (environment.DATABASE_URL) return;
  for (const name of [
    "POSTGRES_URL",
    "POSTGRES_PRISMA_URL",
    "NETLIFY_DATABASE_URL",
    "NEON_DATABASE_URL",
    "PG_URL",
    "PGURL",
    "DATABASE_URL_POOLED",
  ]) {
    if (environment[name]) {
      environment.DATABASE_URL = environment[name];
      return;
    }
  }
}
