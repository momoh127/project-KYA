-- Hardening: workload sessions, versioned suppliers, complete payment binding,
-- payment state machine + reconciliation, nuanced security responses.

-- AlterEnum
ALTER TYPE "AuthorizationStatus" ADD VALUE 'invalidated';

-- AlterEnum
ALTER TYPE "InvoiceStatus" ADD VALUE 'processing';

-- AlterEnum
BEGIN;
CREATE TYPE "TransactionStatus_new" AS ENUM ('executing', 'succeeded', 'failed', 'unknown', 'reconciliation_required');
ALTER TABLE "Transaction" ALTER COLUMN "status" TYPE "TransactionStatus_new" USING ((CASE WHEN "status"::text = 'pending' THEN 'unknown' ELSE "status"::text END)::"TransactionStatus_new");
ALTER TYPE "TransactionStatus" RENAME TO "TransactionStatus_old";
ALTER TYPE "TransactionStatus_new" RENAME TO "TransactionStatus";
DROP TYPE "TransactionStatus_old";
COMMIT;

-- AlterTable
ALTER TABLE "AgentCredential" ADD COLUMN     "flagReason" TEXT,
ADD COLUMN     "flaggedAt" TIMESTAMP(3);

-- AlterTable
ALTER TABLE "Authorization" ADD COLUMN     "authorizationFingerprint" TEXT,
ADD COLUMN     "destinationRef" TEXT,
ADD COLUMN     "invalidatedReason" TEXT,
ADD COLUMN     "paymentRail" TEXT,
ADD COLUMN     "sessionId" TEXT,
ADD COLUMN     "supplierVersion" INTEGER;

-- AlterTable
ALTER TABLE "Supplier" ADD COLUMN     "verificationEvidence" TEXT,
ADD COLUMN     "version" INTEGER NOT NULL DEFAULT 1;

-- AlterTable
ALTER TABLE "Transaction" ADD COLUMN     "attempts" INTEGER NOT NULL DEFAULT 0,
ADD COLUMN     "finalizedAt" TIMESTAMP(3),
ADD COLUMN     "lastAttemptAt" TIMESTAMP(3),
ADD COLUMN     "leaseUntil" TIMESTAMP(3),
ADD COLUMN     "providerIdempotencyKey" TEXT;

-- Backfill: the authorization id has always been the provider idempotency key.
UPDATE "Transaction" SET "providerIdempotencyKey" = "authorizationId" WHERE "providerIdempotencyKey" IS NULL;
ALTER TABLE "Transaction" ALTER COLUMN "providerIdempotencyKey" SET NOT NULL;

-- CreateTable
CREATE TABLE "AgentSession" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "agentId" TEXT NOT NULL,
    "credentialId" TEXT NOT NULL,
    "publicKeyPem" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "revokedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AgentSession_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SecuritySignal" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "agentId" TEXT NOT NULL,
    "keyId" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "reason" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "SecuritySignal_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SupplierVersion" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "supplierId" TEXT NOT NULL,
    "version" INTEGER NOT NULL,
    "changeType" TEXT NOT NULL,
    "changedByUserId" TEXT NOT NULL,
    "snapshot" JSONB NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "SupplierVersion_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "TransactionAttempt" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "transactionId" TEXT NOT NULL,
    "attempt" INTEGER NOT NULL,
    "action" TEXT NOT NULL,
    "outcome" TEXT NOT NULL,
    "providerReference" TEXT,
    "detail" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "TransactionAttempt_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SandboxProviderPayment" (
    "idempotencyKey" TEXT NOT NULL,
    "counterpartyRef" TEXT NOT NULL,
    "amountCents" BIGINT NOT NULL,
    "currency" TEXT NOT NULL,
    "status" TEXT NOT NULL,
    "providerReference" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "SandboxProviderPayment_pkey" PRIMARY KEY ("idempotencyKey")
);

-- CreateTable
CREATE TABLE "SandboxFault" (
    "id" TEXT NOT NULL,
    "fault" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "SandboxFault_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "AgentSession_agentId_idx" ON "AgentSession"("agentId");

-- CreateIndex
CREATE INDEX "SecuritySignal_organizationId_agentId_kind_createdAt_idx" ON "SecuritySignal"("organizationId", "agentId", "kind", "createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "SupplierVersion_supplierId_version_key" ON "SupplierVersion"("supplierId", "version");

-- CreateIndex
CREATE INDEX "TransactionAttempt_transactionId_idx" ON "TransactionAttempt"("transactionId");

-- CreateIndex
CREATE INDEX "Authorization_supplierId_status_idx" ON "Authorization"("supplierId", "status");

-- CreateIndex
CREATE UNIQUE INDEX "Transaction_providerIdempotencyKey_key" ON "Transaction"("providerIdempotencyKey");

-- CreateIndex
CREATE INDEX "Transaction_status_lastAttemptAt_idx" ON "Transaction"("status", "lastAttemptAt");

