import type { CheckResult, Decision, PaymentDestination, ReasonCode } from '@agenttrust/shared';

export type { CheckResult, Decision, PaymentDestination, ReasonCode };

export type AuthorizationStatus =
  | 'allowed'
  | 'pending_review'
  | 'denied'
  | 'rejected'
  | 'consumed'
  | 'expired';

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
}

export interface AuthorizationResponse {
  id: string;
  decision: Decision;
  status: AuthorizationStatus;
  reasonCodes: ReasonCode[];
  checks: CheckResult[];
  approvable: boolean;
  policyVersion: number | null;
  transactionFingerprint: string;
  amountCents: number;
  currency: string;
  supplierId: string | null;
  purchaseOrderId: string | null;
  invoiceId: string | null;
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
  status: 'pending' | 'succeeded' | 'failed';
  amountCents: number;
  currency: string;
  supplierId: string | null;
  invoiceId: string | null;
  provider: string;
  providerReference: string | null;
  createdAt: string;
}

export interface ApiErrorBody {
  error: { code: string; message: string; details?: unknown };
}
