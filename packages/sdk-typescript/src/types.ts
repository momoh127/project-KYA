import type { CheckResult, Decision, PaymentDestination, ReasonCode } from '@agenttrust/shared';

export type { CheckResult, Decision, PaymentDestination, ReasonCode };

export type AuthorizationStatus =
  | 'allowed'
  | 'pending_review'
  | 'denied'
  | 'rejected'
  | 'consumed'
  | 'expired'
  | 'invalidated';

export interface CreateAuthorizationInput {
  /** Required. Retrying with the same key returns the same authorization. */
  idempotencyKey: string;
  action: 'purchase';
  /** Omit when the payee is not a known supplier (will go to REVIEW or DENY). */
  supplierId?: string;
  /** Where the agent intends to send money (e.g. copied from the invoice). */
  payee: PaymentDestination;
  amountCents: number;
  currency: string;
  purchaseOrderId?: string;
  invoiceId?: string;
  /** The independently approved purchase instruction this payment fulfils (required for ALLOW). */
  purchaseInstructionId?: string;
  /** Which approved instruction lines are being bought; used only when the invoice has no lines. */
  lines?: { instructionLineNumber: number; sku?: string; quantity: string; unitPriceCents: number }[];
}

export interface PurchaseInstruction {
  id: string;
  version: number;
  status: 'pending_approval' | 'approved' | 'rejected' | 'revoked';
  source: 'human' | 'erp';
  agentId: string;
  supplierId: string;
  purchaseOrderId: string | null;
  fulfillmentType: 'physical_goods' | 'services' | 'subscription' | 'digital_goods';
  currency: string;
  maxAmountCents: number;
  maxUses: number;
  expiresAt: string;
  lines: { lineNumber: number; sku: string | null; description: string; unit: string | null; quantity: string; unitPriceCents: number; lineTotalCents: number }[];
}

export interface AuthorizationResponse {
  id: string;
  agentId: string;
  decision: Decision;
  status: AuthorizationStatus;
  reasonCodes: ReasonCode[];
  checks: CheckResult[];
  approvable: boolean;
  policyVersion: number | null;
  transactionFingerprint: string;
  /** Fingerprint of the complete payment instruction (rail, destination, record versions, policy, delegation). */
  authorizationFingerprint: string | null;
  supplierVersion: number | null;
  paymentRail: string | null;
  invalidatedReason: string | null;
  amountCents: number;
  currency: string;
  supplierId: string | null;
  purchaseOrderId: string | null;
  invoiceId: string | null;
  purchaseInstructionId: string | null;
  instructionVersion: number | null;
  expiresAt: string;
  createdAt: string;
  /** Present only while status === 'allowed'. Single-use, short-lived. */
  token?: string;
}

export interface ExecuteTransactionInput {
  token: string;
  /** The exact parameters the caller expects to pay. Must match the authorization. */
  expected: {
    supplierId: string | null;
    amountCents: number;
    currency: string;
    purchaseOrderId: string | null;
    invoiceId: string | null;
  };
}

export interface TransactionResponse {
  id: string;
  authorizationId: string;
  /**
   * Provider ACCEPTANCE is not payment. Only `settled` means money moved and
   * the invoice is paid; a settled payment can later be `returned`/`reversed`.
   * requested / accepted / processing / unknown / reconciliation_required are
   * in flight: never treat them as failure and never request a new
   * authorization to "try again". Retry execute with the same token (it
   * reconciles, never re-pays) or poll.
   */
  status: 'requested' | 'accepted' | 'processing' | 'settled' | 'failed' | 'returned' | 'reversed' | 'unknown' | 'reconciliation_required';
  amountCents: number;
  currency: string;
  supplierId: string | null;
  invoiceId: string | null;
  provider: string;
  providerIdempotencyKey: string;
  providerReference: string | null;
  attempts: number;
  acceptedAt: string | null;
  settledAt: string | null;
  /** True when this response came from reconciling an earlier attempt (no new payment was sent blindly). */
  retried?: boolean;
  createdAt: string;
}

export interface ApiErrorBody {
  error: { code: string; message: string; details?: unknown };
}
