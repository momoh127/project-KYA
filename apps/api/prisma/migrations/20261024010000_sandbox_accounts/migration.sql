-- CreateTable
CREATE TABLE "SandboxAccount" (
    "organizationId" TEXT NOT NULL,
    "keyHash" TEXT NOT NULL,
    "keyPrefix" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "adminUserId" TEXT NOT NULL,
    "verifierUserId" TEXT NOT NULL,
    "approverUserId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "lastUsedAt" TIMESTAMP(3),

    CONSTRAINT "SandboxAccount_pkey" PRIMARY KEY ("organizationId")
);

-- CreateIndex
CREATE UNIQUE INDEX "SandboxAccount_keyHash_key" ON "SandboxAccount"("keyHash");

-- CreateIndex
CREATE INDEX "SandboxAccount_createdAt_idx" ON "SandboxAccount"("createdAt");

