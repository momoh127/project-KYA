import type { ReasonCode } from '@agenttrust/shared';

export type ReceiptRequirement = 'confirmation_required' | 'human_approval' | 'none';

export interface ThreeWayMatchRules {
  /** When false, no receipt/completion confirmation is required for any purchase. */
  enabled: boolean;
  physicalGoods: ReceiptRequirement;
  services: ReceiptRequirement;
  subscription: ReceiptRequirement;
  digitalGoods: ReceiptRequirement;
}

export interface PolicyRules {
  /**
   * What to do when a purchase does not reference an independently approved
   * purchase instruction. Never ALLOW. A REVIEW here is NOT click-approvable:
   * a human must create and approve an instruction, then the agent resubmits.
   */
  missingInstruction: 'REVIEW' | 'DENY';
  /** Three-way match (PO → receipt → invoice) requirements by fulfillment type. */
  threeWayMatch: ThreeWayMatchRules;
  /** What to do when a required receipt/completion confirmation is missing or short. Never ALLOW. */
  missingReceipt: 'REVIEW' | 'DENY';
  /** What to do when a purchase does not reference a purchase order. */
  missingPurchaseOrder: 'REVIEW' | 'DENY';
  /** What to do when a purchase does not reference an invoice. */
  missingInvoice: 'ALLOW' | 'REVIEW' | 'DENY';
  /** What to do when the payee is not a known supplier of this organization. */
  unknownSupplier: 'REVIEW' | 'DENY';
  /** Amounts at or above this threshold require human approval. null = never. */
  reviewThresholdCents: number | null;
  /** Lifetime of an ALLOW authorization before it must be executed. */
  authorizationTtlSeconds: number;
  /** Lifetime of a REVIEW authorization awaiting a human decision. */
  reviewTtlSeconds: number;
  /**
   * Graded responses to suspicious activity. Only AUTHENTICATED security
   * violations (things only the agent's own key holder can do, such as
   * presenting forged/tampered authorizations or another agent's token) can
   * suspend an agent. Unauthenticated failures and business-policy denials
   * raise alerts but never suspend, because outsiders could trigger them on
   * purpose to knock a legitimate agent offline.
   */
  securityResponse: SecurityResponseRules;
}

export interface SecurityResponseRules {
  /** Authenticated security violations within the window before auto-suspension. */
  violationSuspendThreshold: number;
  violationWindowSeconds: number;
  /** Unauthenticated failures (bad signatures, replays) per credential before an alert + credential flag. */
  authFailureAlertThreshold: number;
  /** Business-policy denials (budget, amount, missing PO, ...) before an alert. */
  denialAlertThreshold: number;
  alertWindowSeconds: number;
}

export const DEFAULT_POLICY_RULES: PolicyRules = {
  missingInstruction: 'REVIEW',
  threeWayMatch: {
    enabled: false,
    physicalGoods: 'confirmation_required',
    services: 'confirmation_required',
    subscription: 'human_approval',
    digitalGoods: 'none',
  },
  missingReceipt: 'REVIEW',
  missingPurchaseOrder: 'REVIEW',
  missingInvoice: 'REVIEW', // invoice required by default (never auto-ALLOW without one)
  unknownSupplier: 'REVIEW',
  reviewThresholdCents: 250_000, // $2,500
  authorizationTtlSeconds: 600, // 10 minutes
  reviewTtlSeconds: 86_400, // 24 hours
  securityResponse: {
    violationSuspendThreshold: 3,
    violationWindowSeconds: 600,
    authFailureAlertThreshold: 10,
    denialAlertThreshold: 10,
    alertWindowSeconds: 3600,
  },
};

export interface PolicyFacts {
  now: Date;
  policy: { id: string; version: number; rules: PolicyRules } | null;
  agent: { id: string; status: 'active' | 'suspended' | 'revoked' } | null;
  delegation: DelegationFacts | null;
  request: PurchaseRequestFacts;
  /** null when the payee is not a supplier of this organization. */
  supplier: SupplierFacts | null;
  /** null when not referenced OR referenced but not found (see request.purchaseOrderId). */
  purchaseOrder: PurchaseOrderFacts | null;
  /** null when not referenced OR referenced but not found (see request.invoiceId). */
  invoice: InvoiceFacts | null;
  /** null when not referenced OR referenced but not found (see request.purchaseInstructionId). */
  instruction: InstructionFacts | null;
  /** What has already been used of the instruction (consumed + live holds, excluding this request). */
  instructionUsage: { uses: number; amountCents: number; quantityMilliByLine: Record<number, number> };
  /** Non-voided receipts / completion confirmations recorded against the instruction. */
  receipts: { type: string; lines: { instructionLineNumber: number; quantityMilli: number }[] }[];
  /** True when another live authorization already holds this invoice. */
  invoiceInFlight: boolean;
  /** Spend this calendar month under the delegation: paid + active reservations (excluding this request). */
  budget: { spentThisPeriodCents: number };
  /** True only when an authenticated human approver approved this exact transaction fingerprint. */
  humanApprovalGranted: boolean;
}

export interface PaymentLineFacts {
  instructionLineNumber: number | null;
  sku: string | null;
  quantityMilli: number;
  unitPriceCents: number;
  lineTotalCents: number;
}

export interface InstructionFacts {
  id: string;
  version: number;
  status: 'pending_approval' | 'approved' | 'rejected' | 'revoked';
  agentId: string;
  supplierId: string;
  purchaseOrderId: string | null;
  fulfillmentType: 'physical_goods' | 'services' | 'subscription' | 'digital_goods';
  currency: string;
  maxAmountCents: number;
  maxUses: number;
  validFrom: Date;
  expiresAt: Date;
  lines: { lineNumber: number; sku: string | null; quantityMilli: number; unitPriceCents: number }[];
}

export interface PurchaseRequestFacts {
  agentId: string;
  purchaseInstructionId: string | null;
  /** Agent-supplied lines (untrusted; only used when the invoice has no lines). */
  lines: PaymentLineFacts[] | null;
  action: string;
  supplierId: string | null;
  amountCents: number;
  currency: string;
  paymentDestinationFingerprint: string;
  purchaseOrderId: string | null;
  invoiceId: string | null;
}

export interface DelegationFacts {
  id: string;
  actions: string[];
  maxTransactionCents: number;
  monthlyLimitCents: number;
  currency: string;
  /** null = any approved supplier of the organization. */
  approvedSupplierIds: string[] | null;
  validFrom: Date;
  expiresAt: Date;
  revokedAt: Date | null;
}

export interface SupplierFacts {
  id: string;
  status: 'active' | 'blocked';
  verificationStatus: 'unverified' | 'pending' | 'verified';
  paymentDestinationFingerprint: string | null;
}

export interface PurchaseOrderFacts {
  id: string;
  supplierId: string;
  approvedAmountCents: number;
  /** Already paid + actively reserved against this PO (excluding this request). */
  committedAmountCents: number;
  currency: string;
  status: 'open' | 'closed' | 'cancelled';
}

export interface InvoiceFacts {
  id: string;
  supplierId: string;
  purchaseOrderId: string | null;
  amountCents: number;
  currency: string;
  instructionId: string | null;
  /** Trusted lines recorded by humans/ERP (may be empty for legacy invoices). */
  lines: PaymentLineFacts[];
  /** `processing` = a payment for it is executing or being reconciled. */
  status: 'open' | 'processing' | 'paid' | 'void';
}

export interface PolicyResult {
  decision: 'ALLOW' | 'REVIEW' | 'DENY';
  checks: import('@agenttrust/shared').CheckResult[];
  /** On ALLOW: all passing codes. Otherwise: only the failing/review codes. */
  reasonCodes: ReasonCode[];
  policyId: string | null;
  policyVersion: number | null;
  /** True when every remaining REVIEW check can be resolved by a human approver. */
  approvable: boolean;
  /** The exact lines this decision covers (from the invoice, else from the request). */
  paymentLines: PaymentLineFacts[] | null;
}
