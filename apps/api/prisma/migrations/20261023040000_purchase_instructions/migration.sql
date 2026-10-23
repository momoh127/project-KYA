-- CreateEnum
CREATE TYPE "FulfillmentType" AS ENUM ('physical_goods', 'services', 'subscription', 'digital_goods');

-- CreateEnum
CREATE TYPE "InstructionSource" AS ENUM ('human', 'erp');

-- CreateEnum
CREATE TYPE "InstructionStatus" AS ENUM ('pending_approval', 'approved', 'rejected', 'revoked');

-- CreateEnum
CREATE TYPE "ReceiptType" AS ENUM ('goods_received', 'service_completed', 'subscription_activated', 'digital_delivered');

-- CreateEnum
CREATE TYPE "IntegrationStatus" AS ENUM ('active', 'revoked');

-- AlterEnum
ALTER TYPE "ActorType" ADD VALUE 'integration';

-- AlterTable
ALTER TABLE "Authorization" ADD COLUMN     "instructionId" TEXT,
ADD COLUMN     "instructionVersion" INTEGER,
ADD COLUMN     "lines" JSONB,
ADD COLUMN     "linesHash" TEXT;

-- AlterTable
ALTER TABLE "BudgetReservation" ADD COLUMN     "instructionId" TEXT,
ADD COLUMN     "lines" JSONB;

-- AlterTable
ALTER TABLE "Invoice" ADD COLUMN     "createdByIntegrationId" TEXT,
ADD COLUMN     "instructionId" TEXT,
ALTER COLUMN "createdByUserId" DROP NOT NULL;

-- CreateTable
CREATE TABLE "Integration" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "sourceSystem" TEXT NOT NULL,
    "scopes" TEXT[],
    "secretHash" TEXT NOT NULL,
    "status" "IntegrationStatus" NOT NULL DEFAULT 'active',
    "createdByUserId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "revokedAt" TIMESTAMP(3),

    CONSTRAINT "Integration_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "PurchaseInstruction" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "source" "InstructionSource" NOT NULL,
    "sourceSystem" TEXT,
    "externalId" TEXT,
    "externalVersion" TEXT,
    "externalUpdatedAt" TIMESTAMP(3),
    "syncedAt" TIMESTAMP(3),
    "integrationId" TEXT,
    "erpApprovalStatus" TEXT,
    "erpApprovedBy" TEXT,
    "erpApprovedAt" TIMESTAMP(3),
    "agentId" TEXT NOT NULL,
    "supplierId" TEXT NOT NULL,
    "purchaseOrderId" TEXT,
    "fulfillmentType" "FulfillmentType" NOT NULL,
    "currency" TEXT NOT NULL,
    "maxAmountCents" BIGINT NOT NULL,
    "maxUses" INTEGER NOT NULL,
    "validFrom" TIMESTAMP(3) NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "description" TEXT,
    "materialHash" TEXT NOT NULL,
    "linesHash" TEXT NOT NULL,
    "status" "InstructionStatus" NOT NULL,
    "createdByUserId" TEXT,
    "approvedByUserId" TEXT,
    "approvedAt" TIMESTAMP(3),
    "approvalSource" TEXT,
    "revokedAt" TIMESTAMP(3),
    "revokedBy" TEXT,
    "revokeReason" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "PurchaseInstruction_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "PurchaseInstructionLine" (
    "id" TEXT NOT NULL,
    "instructionId" TEXT NOT NULL,
    "lineNumber" INTEGER NOT NULL,
    "sku" TEXT,
    "description" TEXT NOT NULL,
    "unit" TEXT,
    "quantityMilli" BIGINT NOT NULL,
    "unitPriceCents" BIGINT NOT NULL,
    "lineTotalCents" BIGINT NOT NULL,

    CONSTRAINT "PurchaseInstructionLine_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "PurchaseInstructionVersion" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "instructionId" TEXT NOT NULL,
    "version" INTEGER NOT NULL,
    "changeType" TEXT NOT NULL,
    "changedBy" TEXT NOT NULL,
    "snapshot" JSONB NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "PurchaseInstructionVersion_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Receipt" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "instructionId" TEXT NOT NULL,
    "type" "ReceiptType" NOT NULL,
    "lines" JSONB NOT NULL,
    "confirmedByUserId" TEXT,
    "integrationId" TEXT,
    "externalId" TEXT,
    "note" TEXT,
    "voidedAt" TIMESTAMP(3),
    "voidedByUserId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Receipt_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "InvoiceLine" (
    "id" TEXT NOT NULL,
    "invoiceId" TEXT NOT NULL,
    "lineNumber" INTEGER NOT NULL,
    "instructionLineNumber" INTEGER,
    "sku" TEXT,
    "description" TEXT NOT NULL,
    "quantityMilli" BIGINT NOT NULL,
    "unitPriceCents" BIGINT NOT NULL,
    "lineTotalCents" BIGINT NOT NULL,

    CONSTRAINT "InvoiceLine_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "Integration_organizationId_sourceSystem_key" ON "Integration"("organizationId", "sourceSystem");

-- CreateIndex
CREATE INDEX "PurchaseInstruction_organizationId_agentId_status_idx" ON "PurchaseInstruction"("organizationId", "agentId", "status");

-- CreateIndex
CREATE UNIQUE INDEX "PurchaseInstruction_organizationId_sourceSystem_externalId_key" ON "PurchaseInstruction"("organizationId", "sourceSystem", "externalId");

-- CreateIndex
CREATE UNIQUE INDEX "PurchaseInstructionLine_instructionId_lineNumber_key" ON "PurchaseInstructionLine"("instructionId", "lineNumber");

-- CreateIndex
CREATE INDEX "PurchaseInstructionVersion_instructionId_version_idx" ON "PurchaseInstructionVersion"("instructionId", "version");

-- CreateIndex
CREATE INDEX "Receipt_instructionId_idx" ON "Receipt"("instructionId");

-- CreateIndex
CREATE UNIQUE INDEX "InvoiceLine_invoiceId_lineNumber_key" ON "InvoiceLine"("invoiceId", "lineNumber");

-- CreateIndex
CREATE INDEX "Authorization_instructionId_status_idx" ON "Authorization"("instructionId", "status");

-- CreateIndex
CREATE INDEX "BudgetReservation_instructionId_status_idx" ON "BudgetReservation"("instructionId", "status");


-- ---------------------------------------------------------------------------
-- Hand-written integrity constraints for purchase instructions.
-- ---------------------------------------------------------------------------
ALTER TABLE "PurchaseInstruction" ADD CONSTRAINT "PurchaseInstruction_sane"
  CHECK ("maxAmountCents" > 0 AND "maxUses" >= 1 AND "version" >= 1 AND "expiresAt" > "validFrom");
ALTER TABLE "PurchaseInstruction" ADD CONSTRAINT "PurchaseInstruction_erp_identity"
  CHECK (("source" = 'erp') = ("sourceSystem" IS NOT NULL AND "externalId" IS NOT NULL));
ALTER TABLE "PurchaseInstructionLine" ADD CONSTRAINT "PurchaseInstructionLine_exact"
  CHECK ("quantityMilli" > 0 AND "unitPriceCents" >= 0 AND "lineTotalCents" * 1000 = "quantityMilli" * "unitPriceCents");
ALTER TABLE "InvoiceLine" ADD CONSTRAINT "InvoiceLine_exact"
  CHECK ("quantityMilli" > 0 AND "unitPriceCents" >= 0 AND "lineTotalCents" * 1000 = "quantityMilli" * "unitPriceCents");

-- Instruction history is append-only, like the audit log.
CREATE TRIGGER purchase_instruction_version_no_update BEFORE UPDATE ON "PurchaseInstructionVersion"
  FOR EACH ROW EXECUTE FUNCTION agenttrust_audit_append_only();
CREATE TRIGGER purchase_instruction_version_no_delete BEFORE DELETE ON "PurchaseInstructionVersion"
  FOR EACH ROW EXECUTE FUNCTION agenttrust_audit_append_only();
