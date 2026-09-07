-- AlterTable
ALTER TABLE "users" ADD COLUMN     "emailVerifiedAt" TIMESTAMP(3);

-- Grandfather every pre-existing account: the column cannot
-- distinguish how they were provisioned (password signup vs SSO JIT),
-- and refusing OAuth to long-standing SSO-only users would lock them
-- out. The pre-hijack gate protects accounts created AFTER this
-- migration, which is where the attack window lives.
UPDATE "users" SET "emailVerifiedAt" = "createdAt" WHERE "emailVerifiedAt" IS NULL;
