-- Enterprise SAML 2.0 SSO tables.

CREATE TABLE "saml_configs" (
  "id" TEXT PRIMARY KEY,
  "orgId" TEXT NOT NULL,
  "displayName" TEXT NOT NULL,
  "ssoUrl" TEXT NOT NULL,
  "sloUrl" TEXT,
  "entityIdIdp" TEXT NOT NULL,
  "x509Cert" TEXT NOT NULL,
  "wantAssertionsSigned" BOOLEAN NOT NULL DEFAULT true,
  "wantResponseSigned" BOOLEAN NOT NULL DEFAULT false,
  "allowEncryptedAssertions" BOOLEAN NOT NULL DEFAULT true,
  "signatureAlgorithm" TEXT NOT NULL DEFAULT 'sha256',
  "digestAlgorithm" TEXT NOT NULL DEFAULT 'sha256',
  "nameIdFormat" TEXT NOT NULL DEFAULT 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
  "jitEnabled" BOOLEAN NOT NULL DEFAULT true,
  "jitDefaultRole" TEXT NOT NULL DEFAULT 'member',
  "allowedDomains" TEXT NOT NULL DEFAULT '',
  "spPrivateKeyPem" TEXT,
  "spCertPem" TEXT,
  "isActive" BOOLEAN NOT NULL DEFAULT true,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "saml_configs_orgId_fkey"
    FOREIGN KEY ("orgId") REFERENCES "orgs"("id") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE UNIQUE INDEX "saml_configs_orgId_displayName_key" ON "saml_configs"("orgId", "displayName");
CREATE INDEX "saml_configs_orgId_idx" ON "saml_configs"("orgId");

CREATE TABLE "saml_replay_records" (
  "id" TEXT PRIMARY KEY,
  "orgId" TEXT NOT NULL,
  "assertionId" TEXT NOT NULL,
  "notOnOrAfter" TIMESTAMP(3) NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "saml_replay_records_orgId_fkey"
    FOREIGN KEY ("orgId") REFERENCES "orgs"("id") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE UNIQUE INDEX "saml_replay_records_orgId_assertionId_key" ON "saml_replay_records"("orgId", "assertionId");
CREATE INDEX "saml_replay_records_notOnOrAfter_idx" ON "saml_replay_records"("notOnOrAfter");
