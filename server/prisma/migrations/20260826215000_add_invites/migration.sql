CREATE TABLE "invites" (
  "id" TEXT PRIMARY KEY,
  "orgId" TEXT NOT NULL,
  "email" TEXT NOT NULL,
  "role" TEXT NOT NULL DEFAULT 'member',
  "tokenHash" TEXT NOT NULL,
  "invitedById" TEXT,
  "invitedByEmail" TEXT,
  "expiresAt" TIMESTAMP(3) NOT NULL,
  "acceptedAt" TIMESTAMP(3),
  "revokedAt" TIMESTAMP(3),
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "invites_orgId_fkey"
    FOREIGN KEY ("orgId") REFERENCES "orgs"("id") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE UNIQUE INDEX "invites_orgId_email_key" ON "invites"("orgId", "email");
CREATE INDEX "invites_expiresAt_idx" ON "invites"("expiresAt");
