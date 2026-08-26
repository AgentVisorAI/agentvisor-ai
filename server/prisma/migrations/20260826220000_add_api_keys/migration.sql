CREATE TABLE "api_keys" (
  "id" TEXT PRIMARY KEY,
  "orgId" TEXT NOT NULL,
  "name" TEXT NOT NULL,
  "tokenHash" TEXT NOT NULL,
  "tokenHint" TEXT NOT NULL,
  "createdById" TEXT,
  "createdByEmail" TEXT,
  "role" TEXT NOT NULL DEFAULT 'admin',
  "lastUsedAt" TIMESTAMP(3),
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "revokedAt" TIMESTAMP(3),
  CONSTRAINT "api_keys_orgId_fkey"
    FOREIGN KEY ("orgId") REFERENCES "orgs"("id") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE INDEX "api_keys_orgId_idx" ON "api_keys"("orgId");
