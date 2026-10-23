export type Decision = 'ALLOW' | 'REVIEW' | 'DENY';

export type CheckOutcome = 'pass' | 'review' | 'deny';

/**
 * Structured reason codes returned with every authorization decision.
 * Codes are stable API surface: add new ones, never repurpose existing ones.
 */
export const ReasonCode = {
  // Policy / system
  POLICY_ACTIVE: 'POLICY_ACTIVE',
  POLICY_MISSING: 'POLICY_MISSING',
  REQUEST_INVALID: 'REQUEST_INVALID',

  // Agent
  AGENT_ACTIVE: 'AGENT_ACTIVE',
  AGENT_NOT_ACTIVE: 'AGENT_NOT_ACTIVE',

  // Delegation (human-granted authority)
  DELEGATION_VALID: 'DELEGATION_VALID',
  DELEGATION_MISSING: 'DELEGATION_MISSING',
  DELEGATION_NOT_YET_VALID: 'DELEGATION_NOT_YET_VALID',
  DELEGATION_EXPIRED: 'DELEGATION_EXPIRED',
  DELEGATION_REVOKED: 'DELEGATION_REVOKED',
  ACTION_NOT_DELEGATED: 'ACTION_NOT_DELEGATED',
  CURRENCY_NOT_DELEGATED: 'CURRENCY_NOT_DELEGATED',
  SUPPLIER_NOT_DELEGATED: 'SUPPLIER_NOT_DELEGATED',

  // Supplier / payee verification
  SUPPLIER_APPROVED: 'SUPPLIER_APPROVED',
  SUPPLIER_UNKNOWN: 'SUPPLIER_UNKNOWN',
  SUPPLIER_UNVERIFIED: 'SUPPLIER_UNVERIFIED',
  SUPPLIER_BLOCKED: 'SUPPLIER_BLOCKED',
  PAYEE_VERIFIED: 'PAYEE_VERIFIED',
  PAYEE_MISMATCH: 'PAYEE_MISMATCH',
  PAYEE_UNVERIFIABLE: 'PAYEE_UNVERIFIABLE',

  // Amount verification
  AMOUNT_WITHIN_LIMIT: 'AMOUNT_WITHIN_LIMIT',
  AMOUNT_EXCEEDS_TRANSACTION_LIMIT: 'AMOUNT_EXCEEDS_TRANSACTION_LIMIT',
  BUDGET_AVAILABLE: 'BUDGET_AVAILABLE',
  BUDGET_EXCEEDED: 'BUDGET_EXCEEDED',

  // Purchase order
  PO_MATCHED: 'PO_MATCHED',
  PO_MISSING: 'PO_MISSING',
  PO_NOT_FOUND: 'PO_NOT_FOUND',
  PO_NOT_OPEN: 'PO_NOT_OPEN',
  PO_SUPPLIER_MISMATCH: 'PO_SUPPLIER_MISMATCH',
  PO_CURRENCY_MISMATCH: 'PO_CURRENCY_MISMATCH',
  AMOUNT_EXCEEDS_PO: 'AMOUNT_EXCEEDS_PO',

  // Invoice
  INVOICE_MATCHED: 'INVOICE_MATCHED',
  INVOICE_NOT_REFERENCED: 'INVOICE_NOT_REFERENCED',
  INVOICE_MISSING: 'INVOICE_MISSING',
  INVOICE_NOT_FOUND: 'INVOICE_NOT_FOUND',
  INVOICE_VOID: 'INVOICE_VOID',
  INVOICE_ALREADY_PAID: 'INVOICE_ALREADY_PAID',
  INVOICE_IN_FLIGHT: 'INVOICE_IN_FLIGHT',
  INVOICE_SUPPLIER_MISMATCH: 'INVOICE_SUPPLIER_MISMATCH',
  INVOICE_PO_MISMATCH: 'INVOICE_PO_MISMATCH',
  INVOICE_CURRENCY_MISMATCH: 'INVOICE_CURRENCY_MISMATCH',
  AMOUNT_MISMATCH_INVOICE: 'AMOUNT_MISMATCH_INVOICE',

  // Human approval
  APPROVAL_NOT_REQUIRED: 'APPROVAL_NOT_REQUIRED',
  APPROVAL_REQUIRED: 'APPROVAL_REQUIRED',
  APPROVAL_GRANTED: 'APPROVAL_GRANTED',
} as const;

export type ReasonCode = (typeof ReasonCode)[keyof typeof ReasonCode];

export interface CheckResult {
  code: ReasonCode;
  outcome: CheckOutcome;
  message: string;
  /**
   * For `review` outcomes: whether a human approver may resolve this check.
   * Supplier/payee verification problems are never approvable: the supplier
   * record must be verified first, so a single click cannot route money to an
   * unverified bank account.
   */
  approvable?: boolean;
}

/** DENY dominates REVIEW, which dominates ALLOW. Empty input fails closed. */
export function combineOutcomes(outcomes: CheckOutcome[]): Decision {
  if (outcomes.length === 0) return 'DENY';
  if (outcomes.includes('deny')) return 'DENY';
  if (outcomes.includes('review')) return 'REVIEW';
  return 'ALLOW';
}
