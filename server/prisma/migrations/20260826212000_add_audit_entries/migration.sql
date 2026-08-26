-- Compliance-grade audit trail.
CREATE TABLE "audit_entries" (
  "id" TEXT PRIMARY KEY,
  "orgId" TEXT NOT NULL,
  "event" TEXT NOT NULL,
  "actorId" TEXT,
  "actorEmail" TEXT,
  "target" TEXT,
  "note" TEXT,
  "metadata" JSONB,
  "ip" TEXT,
  "userAgent" TEXT,
  "at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "audit_entries_orgId_fkey"
    FOREIGN KEY ("orgId") REFERENCES "orgs"("id") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE INDEX "audit_entries_orgId_at_idx" ON "audit_entries"("orgId", "at");
