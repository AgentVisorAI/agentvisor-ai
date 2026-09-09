-- Server-side single-use consumption for WebAuthn ceremony challenges.
-- The challenge cookie is client-held, so cookie-clearing on completion
-- is client-honored only: a captured verify request + cookies replayed
-- within the 5-minute TTL re-minted a session per replay (zero-counter
-- authenticators never trip the clone-detection CAS). sha256(challenge)
-- lands here on first successful verify; the primary key makes the
-- second use a unique violation.

-- CreateTable
CREATE TABLE "webauthn_ceremony_records" (
    "challengeHash" TEXT NOT NULL,
    "usedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "webauthn_ceremony_records_pkey" PRIMARY KEY ("challengeHash")
);

-- CreateIndex
CREATE INDEX "webauthn_ceremony_records_usedAt_idx" ON "webauthn_ceremony_records"("usedAt");
