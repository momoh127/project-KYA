-- CreateEnum
CREATE TYPE "OrgStatus" AS ENUM ('active', 'suspended');

-- CreateEnum
CREATE TYPE "VerificationStatus" AS ENUM ('unverified', 'pending', 'verified');

-- CreateEnum
CREATE TYPE "UserRole" AS ENUM ('admin', 'approver', 'member');

-- CreateEnum
CREATE TYPE "UserStatus" AS ENUM ('active', 'disabled');

-- CreateEnum
CREATE TYPE "AgentStatus" AS ENUM ('active', 'suspended', 'revoked');

-- CreateEnum
CREATE TYPE "CredentialStatus" AS ENUM ('active', 'revoked');

-- CreateEnum
CREATE TYPE "PolicyStatus" AS ENUM ('active', 'superseded');

-- CreateEnum
CREATE TYPE "SupplierStatus" AS ENUM ('active', 'blocked');

-- CreateEnum
CREATE TYPE "PoStatus" AS ENUM ('open', 'closed', 'cancelled');

-- CreateEnum
CREATE TYPE "InvoiceStatus" AS ENUM ('open', 'paid', 'void');

-- CreateEnum
CREATE TYPE "Decision" AS ENUM ('ALLOW', 'REVIEW', 'DENY');

-- CreateEnum
CREATE TYPE "AuthorizationStatus" AS ENUM ('allowed', 'pending_review', 'denied', 'rejected', 'consumed', 'expired');

-- CreateEnum
CREATE TYPE "ApprovalDecision" AS ENUM ('approved', 'rejected');

-- CreateEnum
CREATE TYPE "ReservationStatus" AS ENUM ('active', 'consumed', 'released');

-- CreateEnum
CREATE TYPE "TransactionStatus" AS ENUM ('pending', 'succeeded', 'failed');

-- CreateEnum
CREATE TYPE "ActorType" AS ENUM ('agent', 'user', 'system');

-- CreateTable
CREATE TABLE "Organization" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "status" "OrgStatus" NOT NULL DEFAULT 'active',
    "verificationStatus" "VerificationStatus" NOT NULL DEFAULT 'unverified',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Organization_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "User" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "externalIdentityId" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "role" "UserRole" NOT NULL,
    "status" "UserStatus" NOT NULL DEFAULT 'active',
    "spendingAuthorityCents" BIGINT NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "User_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Agent" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "ownerUserId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "status" "AgentStatus" NOT NULL DEFAULT 'active',
    "statusReason" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Agent_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AgentCredential" (
    "id" TEXT NOT NULL,
    "agentId" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "publicKeyPem" TEXT NOT NULL,
    "status" "CredentialStatus" NOT NULL DEFAULT 'active',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3),
    "revokedAt" TIMESTAMP(3),

    CONSTRAINT "AgentCredential_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AgentRequestNonce" (
    "credentialId" TEXT NOT NULL,
    "nonce" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AgentRequestNonce_pkey" PRIMARY KEY ("credentialId","nonce")
);

-- CreateTable
CREATE TABLE "Delegation" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "agentId" TEXT NOT NULL,
    "grantedByUserId" TEXT NOT NULL,
    "actions" TEXT[],
    "maxTransactionCents" BIGINT NOT NULL,
    "monthlyLimitCents" BIGINT NOT NULL,
    "currency" TEXT NOT NULL,
    "restrictSuppliers" BOOLEAN NOT NULL DEFAULT false,
    "approvedSupplierIds" TEXT[],
    "validFrom" TIMESTAMP(3) NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "revokedAt" TIMESTAMP(3),
    "revokedByUserId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Delegation_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Policy" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "version" INTEGER NOT NULL,
    "rules" JSONB NOT NULL,
    "status" "PolicyStatus" NOT NULL,
    "createdByUserId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Policy_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Supplier" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "externalReference" TEXT,
    "verificationStatus" "VerificationStatus" NOT NULL,
    "paymentDestinationFingerprint" TEXT,
    "paymentDestinationType" TEXT,
    "paymentDestinationLast4" TEXT,
    "paymentCounterpartyRef" TEXT,
    "paymentDestinationChangedByUserId" TEXT,
    "paymentDestinationChangedAt" TIMESTAMP(3),
    "verifiedByUserId" TEXT,
    "verifiedAt" TIMESTAMP(3),
    "status" "SupplierStatus" NOT NULL DEFAULT 'active',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Supplier_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "PurchaseOrder" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "supplierId" TEXT NOT NULL,
    "externalReference" TEXT NOT NULL,
    "approvedAmountCents" BIGINT NOT NULL,
    "currency" TEXT NOT NULL,
    "status" "PoStatus" NOT NULL DEFAULT 'open',
    "approvedByUserId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "PurchaseOrder_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Invoice" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "supplierId" TEXT NOT NULL,
    "purchaseOrderId" TEXT,
    "invoiceNumber" TEXT NOT NULL,
    "amountCents" BIGINT NOT NULL,
    "currency" TEXT NOT NULL,
    "documentHash" TEXT,
    "status" "InvoiceStatus" NOT NULL DEFAULT 'open',
    "paidAt" TIMESTAMP(3),
    "paidByTransactionId" TEXT,
    "createdByUserId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Invoice_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Authorization" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "agentId" TEXT NOT NULL,
    "credentialId" TEXT NOT NULL,
    "delegationId" TEXT,
    "policyId" TEXT,
    "policyVersion" INTEGER,
    "idempotencyKey" TEXT NOT NULL,
    "transactionFingerprint" TEXT NOT NULL,
    "action" TEXT NOT NULL,
    "supplierId" TEXT,
    "paymentDestinationFingerprint" TEXT NOT NULL,
    "amountCents" BIGINT NOT NULL,
    "currency" TEXT NOT NULL,
    "purchaseOrderId" TEXT,
    "invoiceId" TEXT,
    "initialDecision" "Decision" NOT NULL,
    "decision" "Decision" NOT NULL,
    "status" "AuthorizationStatus" NOT NULL,
    "reasonCodes" TEXT[],
    "checks" JSONB NOT NULL,
    "approvable" BOOLEAN NOT NULL DEFAULT false,
    "token" TEXT,
    "tokenNonce" TEXT,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "consumedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Authorization_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Approval" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "authorizationId" TEXT NOT NULL,
    "approverUserId" TEXT NOT NULL,
    "decision" "ApprovalDecision" NOT NULL,
    "transactionFingerprint" TEXT NOT NULL,
    "policyVersion" INTEGER,
    "comment" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Approval_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "BudgetReservation" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "authorizationId" TEXT NOT NULL,
    "agentId" TEXT NOT NULL,
    "delegationId" TEXT NOT NULL,
    "purchaseOrderId" TEXT,
    "invoiceId" TEXT,
    "amountCents" BIGINT NOT NULL,
    "currency" TEXT NOT NULL,
    "status" "ReservationStatus" NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "BudgetReservation_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Transaction" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "authorizationId" TEXT NOT NULL,
    "agentId" TEXT NOT NULL,
    "supplierId" TEXT,
    "invoiceId" TEXT,
    "amountCents" BIGINT NOT NULL,
    "currency" TEXT NOT NULL,
    "status" "TransactionStatus" NOT NULL,
    "provider" TEXT NOT NULL,
    "providerReference" TEXT,
    "failureReason" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Transaction_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AuditEvent" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "sequence" INTEGER NOT NULL,
    "actorType" "ActorType" NOT NULL,
    "actorId" TEXT NOT NULL,
    "eventType" TEXT NOT NULL,
    "subjectId" TEXT,
    "payload" JSONB NOT NULL,
    "payloadHash" TEXT NOT NULL,
    "previousEventHash" TEXT,
    "eventHash" TEXT NOT NULL,
    "signature" TEXT NOT NULL,
    "keyId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "AuditEvent_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AuditChainHead" (
    "organizationId" TEXT NOT NULL,
    "lastSequence" INTEGER NOT NULL DEFAULT 0,
    "lastEventHash" TEXT,

    CONSTRAINT "AuditChainHead_pkey" PRIMARY KEY ("organizationId")
);

-- CreateIndex
CREATE UNIQUE INDEX "User_externalIdentityId_key" ON "User"("externalIdentityId");

-- CreateIndex
CREATE INDEX "User_organizationId_idx" ON "User"("organizationId");

-- CreateIndex
CREATE UNIQUE INDEX "User_organizationId_email_key" ON "User"("organizationId", "email");

-- CreateIndex
CREATE INDEX "Agent_organizationId_idx" ON "Agent"("organizationId");

-- CreateIndex
CREATE INDEX "AgentCredential_agentId_idx" ON "AgentCredential"("agentId");

-- CreateIndex
CREATE INDEX "AgentRequestNonce_createdAt_idx" ON "AgentRequestNonce"("createdAt");

-- CreateIndex
CREATE INDEX "Delegation_organizationId_agentId_createdAt_idx" ON "Delegation"("organizationId", "agentId", "createdAt");

-- CreateIndex
CREATE INDEX "Policy_organizationId_status_idx" ON "Policy"("organizationId", "status");

-- CreateIndex
CREATE UNIQUE INDEX "Policy_organizationId_version_key" ON "Policy"("organizationId", "version");

-- CreateIndex
CREATE INDEX "Supplier_organizationId_idx" ON "Supplier"("organizationId");

-- CreateIndex
CREATE INDEX "PurchaseOrder_organizationId_supplierId_idx" ON "PurchaseOrder"("organizationId", "supplierId");

-- CreateIndex
CREATE UNIQUE INDEX "PurchaseOrder_organizationId_externalReference_key" ON "PurchaseOrder"("organizationId", "externalReference");

-- CreateIndex
CREATE INDEX "Invoice_organizationId_idx" ON "Invoice"("organizationId");

-- CreateIndex
CREATE UNIQUE INDEX "Invoice_organizationId_supplierId_invoiceNumber_key" ON "Invoice"("organizationId", "supplierId", "invoiceNumber");

-- CreateIndex
CREATE INDEX "Authorization_organizationId_createdAt_idx" ON "Authorization"("organizationId", "createdAt");

-- CreateIndex
CREATE INDEX "Authorization_organizationId_status_idx" ON "Authorization"("organizationId", "status");

-- CreateIndex
CREATE UNIQUE INDEX "Authorization_agentId_idempotencyKey_key" ON "Authorization"("agentId", "idempotencyKey");

-- CreateIndex
CREATE UNIQUE INDEX "Approval_authorizationId_key" ON "Approval"("authorizationId");

-- CreateIndex
CREATE UNIQUE INDEX "BudgetReservation_authorizationId_key" ON "BudgetReservation"("authorizationId");

-- CreateIndex
CREATE INDEX "BudgetReservation_agentId_status_createdAt_idx" ON "BudgetReservation"("agentId", "status", "createdAt");

-- CreateIndex
CREATE INDEX "BudgetReservation_purchaseOrderId_status_idx" ON "BudgetReservation"("purchaseOrderId", "status");

-- CreateIndex
CREATE INDEX "BudgetReservation_invoiceId_status_idx" ON "BudgetReservation"("invoiceId", "status");

-- CreateIndex
CREATE UNIQUE INDEX "Transaction_authorizationId_key" ON "Transaction"("authorizationId");

-- CreateIndex
CREATE INDEX "Transaction_organizationId_createdAt_idx" ON "Transaction"("organizationId", "createdAt");

-- CreateIndex
CREATE INDEX "AuditEvent_organizationId_eventType_createdAt_idx" ON "AuditEvent"("organizationId", "eventType", "createdAt");

-- CreateIndex
CREATE INDEX "AuditEvent_organizationId_actorId_createdAt_idx" ON "AuditEvent"("organizationId", "actorId", "createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "AuditEvent_organizationId_sequence_key" ON "AuditEvent"("organizationId", "sequence");

-- ---------------------------------------------------------------------------
-- Defense-in-depth constraints (hand-written; Prisma cannot express these).
-- ---------------------------------------------------------------------------

-- Audit events are append-only: UPDATE and DELETE are rejected by the database.
-- (A superuser can still disable triggers; production must also anchor chain
-- heads in write-once storage. See docs/SECURITY.md.)
CREATE OR REPLACE FUNCTION agenttrust_audit_append_only() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'AuditEvent is append-only (% rejected)', TG_OP;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_event_no_update BEFORE UPDATE ON "AuditEvent"
  FOR EACH ROW EXECUTE FUNCTION agenttrust_audit_append_only();
CREATE TRIGGER audit_event_no_delete BEFORE DELETE ON "AuditEvent"
  FOR EACH ROW EXECUTE FUNCTION agenttrust_audit_append_only();

-- At most one live hold per invoice: two authorizations can never hold the
-- same invoice at the same time, even if application checks were bypassed.
CREATE UNIQUE INDEX "BudgetReservation_one_active_per_invoice"
  ON "BudgetReservation" ("invoiceId")
  WHERE "status" = 'active' AND "invoiceId" IS NOT NULL;

-- Exactly one active policy per organization.
CREATE UNIQUE INDEX "Policy_one_active_per_org"
  ON "Policy" ("organizationId")
  WHERE "status" = 'active';

-- Money and state sanity checks.
ALTER TABLE "Delegation" ADD CONSTRAINT "Delegation_limits_positive"
  CHECK ("maxTransactionCents" > 0 AND "monthlyLimitCents" >= "maxTransactionCents" AND "expiresAt" > "validFrom");
ALTER TABLE "PurchaseOrder" ADD CONSTRAINT "PurchaseOrder_amount_positive" CHECK ("approvedAmountCents" > 0);
ALTER TABLE "Invoice" ADD CONSTRAINT "Invoice_amount_positive" CHECK ("amountCents" > 0);
ALTER TABLE "Authorization" ADD CONSTRAINT "Authorization_amount_positive" CHECK ("amountCents" > 0);
ALTER TABLE "BudgetReservation" ADD CONSTRAINT "BudgetReservation_amount_positive" CHECK ("amountCents" > 0);
ALTER TABLE "Authorization" ADD CONSTRAINT "Authorization_consumed_consistency"
  CHECK (("status" = 'consumed') = ("consumedAt" IS NOT NULL));
