-- CreateTable
CREATE TABLE "AuditAnchor" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "fromSequence" INTEGER NOT NULL,
    "toSequence" INTEGER NOT NULL,
    "eventCount" INTEGER NOT NULL,
    "merkleRoot" TEXT NOT NULL,
    "chainHeadHash" TEXT NOT NULL,
    "previousMerkleRoot" TEXT,
    "statement" JSONB NOT NULL,
    "signature" TEXT NOT NULL,
    "keyId" TEXT NOT NULL,
    "storageUri" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AuditAnchor_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "AuditAnchor_organizationId_toSequence_key" ON "AuditAnchor"("organizationId", "toSequence");


-- Anchor index rows are append-only too.
CREATE TRIGGER audit_anchor_no_update BEFORE UPDATE ON "AuditAnchor"
  FOR EACH ROW EXECUTE FUNCTION agenttrust_audit_append_only();
CREATE TRIGGER audit_anchor_no_delete BEFORE DELETE ON "AuditAnchor"
  FOR EACH ROW EXECUTE FUNCTION agenttrust_audit_append_only();
