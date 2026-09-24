CREATE TABLE "saml_authn_requests" (
    "id" VARCHAR(256) NOT NULL,
    "configId" TEXT NOT NULL,
    "orgId" TEXT NOT NULL,
    "requestTimestamp" VARCHAR(64) NOT NULL,
    "nonceHash" VARCHAR(64) NOT NULL,
    "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMPTZ(3) NOT NULL,
    CONSTRAINT "saml_authn_requests_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "saml_authn_requests_expiresAt_id_idx" ON "saml_authn_requests"("expiresAt", "id");
CREATE INDEX "saml_authn_requests_configId_idx" ON "saml_authn_requests"("configId");
ALTER TABLE "saml_authn_requests" ADD CONSTRAINT "saml_authn_requests_configId_fkey"
    FOREIGN KEY ("configId") REFERENCES "saml_configs"("id") ON DELETE CASCADE ON UPDATE CASCADE;
