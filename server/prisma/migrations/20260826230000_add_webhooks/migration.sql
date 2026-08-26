CREATE TABLE "webhook_endpoints" (
  "id" TEXT PRIMARY KEY,
  "orgId" TEXT NOT NULL,
  "name" TEXT NOT NULL,
  "url" TEXT NOT NULL,
  "secret" TEXT NOT NULL,
  "events" TEXT[] NOT NULL DEFAULT '{}',
  "isActive" BOOLEAN NOT NULL DEFAULT true,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "webhook_endpoints_orgId_fkey"
    FOREIGN KEY ("orgId") REFERENCES "orgs"("id") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE INDEX "webhook_endpoints_orgId_idx" ON "webhook_endpoints"("orgId");

CREATE TABLE "webhook_deliveries" (
  "id" TEXT PRIMARY KEY,
  "endpointId" TEXT NOT NULL,
  "event" TEXT NOT NULL,
  "payload" TEXT NOT NULL,
  "responseCode" INT,
  "responseBody" TEXT,
  "attempt" INT NOT NULL DEFAULT 1,
  "status" TEXT NOT NULL DEFAULT 'pending',
  "errorMessage" TEXT,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "deliveredAt" TIMESTAMP(3),
  "nextRetryAt" TIMESTAMP(3),
  CONSTRAINT "webhook_deliveries_endpointId_fkey"
    FOREIGN KEY ("endpointId") REFERENCES "webhook_endpoints"("id") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE INDEX "webhook_deliveries_endpointId_createdAt_idx" ON "webhook_deliveries"("endpointId", "createdAt");
CREATE INDEX "webhook_deliveries_status_nextRetryAt_idx" ON "webhook_deliveries"("status", "nextRetryAt");
