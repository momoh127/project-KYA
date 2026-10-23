import { canonicalJson } from './canonical';
import { hmacSha256Hex, sha256Hex } from './hash';

/**
 * Payment destination as submitted by an agent (typically copied from an
 * invoice) or entered by a human when onboarding a supplier.
 */
export type PaymentDestination =
  | { type: 'us_ach'; routingNumber: string; accountNumber: string }
  | { type: 'iban'; iban: string };

export interface NormalizedPaymentDestination {
  type: PaymentDestination['type'];
  /** Payment rail implied by the destination type. Bound into authorizations. */
  rail: 'ach' | 'sepa';
  value: Record<string, string>;
  last4: string;
}

const digitsOnly = (s: string) => s.replace(/[\s-]/g, '');

export function normalizePaymentDestination(dest: PaymentDestination): NormalizedPaymentDestination {
  if (dest.type === 'us_ach') {
    const routingNumber = digitsOnly(dest.routingNumber);
    const accountNumber = digitsOnly(dest.accountNumber);
    if (!/^\d{9}$/.test(routingNumber)) throw new RangeError('routingNumber must be 9 digits');
    if (!/^\d{4,17}$/.test(accountNumber)) throw new RangeError('accountNumber must be 4-17 digits');
    return { type: 'us_ach', rail: 'ach', value: { routingNumber, accountNumber }, last4: accountNumber.slice(-4) };
  }
  if (dest.type === 'iban') {
    const iban = dest.iban.replace(/\s/g, '').toUpperCase();
    if (!/^[A-Z]{2}\d{2}[A-Z0-9]{10,30}$/.test(iban)) throw new RangeError('invalid IBAN format');
    return { type: 'iban', rail: 'sepa', value: { iban }, last4: iban.slice(-4) };
  }
  throw new RangeError('unsupported payment destination type');
}

/**
 * Keyed fingerprint of a payment destination. Bank details have low entropy,
 * so a plain hash could be brute-forced; we use HMAC-SHA256 with a server-side
 * secret ("pepper") that is never exposed to agents or stored in the database.
 */
export function paymentDestinationFingerprint(pepper: string, dest: PaymentDestination): string {
  if (!pepper || pepper.length < 32) throw new RangeError('payee pepper must be at least 32 chars');
  const n = normalizePaymentDestination(dest);
  return `pd_${hmacSha256Hex(pepper, canonicalJson({ type: n.type, ...n.value }))}`;
}

/**
 * The exact transaction an authorization is valid for. Every field is bound
 * into the fingerprint, so changing any of them (amount, payee, invoice, ...)
 * produces a different fingerprint and invalidates the authorization.
 */
export interface TransactionIntent {
  organizationId: string;
  agentId: string;
  action: 'purchase';
  supplierId: string | null;
  paymentDestinationFingerprint: string;
  amountCents: number;
  currency: string;
  purchaseOrderId: string | null;
  invoiceId: string | null;
  /** Independently approved purchase instruction the payment claims to fulfil. */
  purchaseInstructionId: string | null;
  /** Hash of agent-supplied lines (null when lines come from the invoice). */
  requestLinesHash: string | null;
}

export const TRANSACTION_FINGERPRINT_VERSION = 2;

/** Fingerprint of the agent's REQUEST (used for idempotency). */
export function transactionFingerprint(intent: TransactionIntent): string {
  const material = canonicalJson({
    v: TRANSACTION_FINGERPRINT_VERSION,
    organizationId: intent.organizationId,
    agentId: intent.agentId,
    action: intent.action,
    supplierId: intent.supplierId,
    paymentDestinationFingerprint: intent.paymentDestinationFingerprint,
    amountCents: intent.amountCents,
    currency: intent.currency,
    purchaseOrderId: intent.purchaseOrderId,
    invoiceId: intent.invoiceId,
    purchaseInstructionId: intent.purchaseInstructionId,
    requestLinesHash: intent.requestLinesHash,
  });
  return `tx_${sha256Hex(material)}`;
}

/**
 * The COMPLETE payment instruction an authorization permits. On top of the
 * request it binds the execution details resolved from trusted records and
 * the exact versions of the authority that allowed it. If the supplier record,
 * policy or delegation changes before execution, the fingerprint recomputed
 * at the gateway no longer matches and payment is refused.
 */
export interface AuthorizationBinding extends TransactionIntent {
  /** e.g. "ach", "sepa". */
  paymentRail: string;
  /** Provider-side destination identifier from the verified supplier record. */
  destinationRef: string;
  supplierVersion: number;
  policyId: string;
  policyVersion: number;
  /** Delegations are immutable grants (changes create a new id), so the id is the version. */
  delegationId: string;
  /** Exact purchase-instruction version (material changes bump it). */
  instructionId: string;
  instructionVersion: number;
  /** Hash of the exact approved-instruction lines being paid. */
  linesHash: string;
}

export const AUTHORIZATION_FINGERPRINT_VERSION = 3;

export function authorizationFingerprint(b: AuthorizationBinding): string {
  const material = canonicalJson({
    v: AUTHORIZATION_FINGERPRINT_VERSION,
    organizationId: b.organizationId,
    agentId: b.agentId,
    action: b.action,
    supplierId: b.supplierId,
    supplierVersion: b.supplierVersion,
    paymentRail: b.paymentRail,
    destinationRef: b.destinationRef,
    paymentDestinationFingerprint: b.paymentDestinationFingerprint,
    amountCents: b.amountCents,
    currency: b.currency,
    purchaseOrderId: b.purchaseOrderId,
    invoiceId: b.invoiceId,
    policyId: b.policyId,
    policyVersion: b.policyVersion,
    delegationId: b.delegationId,
    instructionId: b.instructionId,
    instructionVersion: b.instructionVersion,
    linesHash: b.linesHash,
  });
  return `az_${sha256Hex(material)}`;
}
