-- AlterTable
ALTER TABLE "users" ADD COLUMN     "pendingEmail" TEXT,
ADD COLUMN     "pendingEmailAt" TIMESTAMP(3),
ADD COLUMN     "pendingEmailTokenHash" TEXT;
