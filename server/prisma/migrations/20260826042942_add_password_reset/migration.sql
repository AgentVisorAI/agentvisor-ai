-- AlterTable
ALTER TABLE "users" ADD COLUMN     "resetTokenAt" TIMESTAMP(3),
ADD COLUMN     "resetTokenHash" TEXT;
