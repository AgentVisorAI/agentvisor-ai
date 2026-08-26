-- Enforce unique deployment name within an org.
CREATE UNIQUE INDEX "deployments_orgId_name_key" ON "deployments"("orgId", "name");
