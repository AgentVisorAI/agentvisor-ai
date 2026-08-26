-- Denormalize orgId onto sessions so org-scoped listings + counters
-- become O(log N) index scans instead of an N-row join through
-- deployments. See server/src/routes/read.ts for the query patterns
-- this migration unlocks (cursor pagination + real fleet stats).
--
-- Backfill-safe: add nullable → populate → set NOT NULL. Works on
-- both empty and populated databases.

-- 1. Add the column NULL so we can back-fill without a default.
ALTER TABLE "sessions" ADD COLUMN "orgId" TEXT;

-- 2. Back-fill from the parent deployment. Cheap CTE join, uses the
-- (deploymentId) foreign key + (id) primary key index on deployments.
UPDATE "sessions" s
SET "orgId" = d."orgId"
FROM "deployments" d
WHERE s."deploymentId" = d."id";

-- 3. Enforce NOT NULL now that every row has a value.
ALTER TABLE "sessions" ALTER COLUMN "orgId" SET NOT NULL;

-- 4. Add the compound index. Cursor pagination pages a single index
-- range; toolsBlocked filter can walk it via a bitmap scan.
CREATE INDEX "sessions_orgId_openedAt_id_idx" ON "sessions" ("orgId", "openedAt", "id");
CREATE INDEX "sessions_orgId_toolsBlocked_idx" ON "sessions" ("orgId", "toolsBlocked");
