-- Payment lifecycle (T22): provider acceptance is not finality.
-- Rename existing states (data-preserving), then add new ones.
ALTER TYPE "TransactionStatus" RENAME VALUE 'executing' TO 'requested';
ALTER TYPE "TransactionStatus" RENAME VALUE 'succeeded' TO 'settled';
ALTER TYPE "TransactionStatus" ADD VALUE 'accepted';
ALTER TYPE "TransactionStatus" ADD VALUE 'processing';
ALTER TYPE "TransactionStatus" ADD VALUE 'returned';
ALTER TYPE "TransactionStatus" ADD VALUE 'reversed';
ALTER TYPE "InvoiceStatus" ADD VALUE 'payment_exception';

ALTER TABLE "Transaction" ADD COLUMN "acceptedAt" TIMESTAMP(3),
ADD COLUMN "settledAt" TIMESTAMP(3),
ADD COLUMN "resolution" TEXT,
ADD COLUMN "resolvedAt" TIMESTAMP(3),
ADD COLUMN "resolvedByUserId" TEXT;

CREATE TABLE "ProviderEvent" (
    "id" TEXT NOT NULL,
    "provider" TEXT NOT NULL,
    "eventId" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "idempotencyKey" TEXT NOT NULL,
    "transactionId" TEXT,
    "organizationId" TEXT,
    "payloadHash" TEXT NOT NULL,
    "outcome" TEXT NOT NULL,
    "detail" TEXT,
    "occurredAt" TIMESTAMP(3),
    "receivedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "ProviderEvent_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "ProviderEvent_provider_eventId_key" ON "ProviderEvent"("provider", "eventId");
CREATE INDEX "ProviderEvent_idempotencyKey_idx" ON "ProviderEvent"("idempotencyKey");
