-- CreateEnum
CREATE TYPE "SupplierAssurance" AS ENUM ('recorded', 'reviewed', 'account_verified', 'ownership_verified');

-- AlterTable
ALTER TABLE "Supplier" ADD COLUMN     "assuranceLevel" "SupplierAssurance" NOT NULL DEFAULT 'recorded',
ADD COLUMN     "legalName" TEXT;

-- CreateTable
CREATE TABLE "SupplierVerification" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "supplierId" TEXT NOT NULL,
    "supplierVersion" INTEGER NOT NULL,
    "provider" TEXT NOT NULL,
    "accountStatus" TEXT NOT NULL,
    "ownerNameMatch" TEXT NOT NULL,
    "resultLevel" "SupplierAssurance" NOT NULL,
    "providerReference" TEXT,
    "requestedByUserId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "SupplierVerification_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "SupplierVerification_supplierId_idx" ON "SupplierVerification"("supplierId");


-- Existing second-person-verified suppliers map to the "reviewed" level.
UPDATE "Supplier" SET "assuranceLevel" = 'reviewed' WHERE "verificationStatus" = 'verified';
