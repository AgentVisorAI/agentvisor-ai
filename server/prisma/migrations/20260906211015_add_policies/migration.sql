-- AlterTable
ALTER TABLE "webhook_endpoints" ALTER COLUMN "events" DROP DEFAULT;

-- CreateTable
CREATE TABLE "policies" (
    "id" TEXT NOT NULL,
    "orgId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "kind" TEXT NOT NULL DEFAULT 'guardrail',
    "scope" TEXT NOT NULL DEFAULT 'tool.*',
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "description" TEXT NOT NULL DEFAULT '',
    "body" TEXT NOT NULL DEFAULT '',
    "updatedBy" TEXT NOT NULL DEFAULT '',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "policies_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "policies_orgId_idx" ON "policies"("orgId");

-- CreateIndex
CREATE UNIQUE INDEX "policies_orgId_name_key" ON "policies"("orgId", "name");

-- AddForeignKey
ALTER TABLE "policies" ADD CONSTRAINT "policies_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "orgs"("id") ON DELETE CASCADE ON UPDATE CASCADE;
