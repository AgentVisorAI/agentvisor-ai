-- AlterTable
ALTER TABLE "deployments" ADD COLUMN     "daemonVersion" TEXT;

-- AlterTable
ALTER TABLE "events" ADD COLUMN     "policyName" TEXT;

-- CreateIndex
CREATE INDEX "events_policyName_occurredAt_idx" ON "events"("policyName", "occurredAt");
