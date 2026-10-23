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
    return { type: 'us_ach', value: { routingNumber, accountNumber }, last4: accountNumber.slice(-4) };
  }
  if (dest.type === 'iban') {
    const iban = dest.iban.replace(/\s/g, '').toUpperCase();
    if (!/^[A-Z]{2}\d{2}[A-Z0-9]{10,30}$/.test(iban)) throw new RangeError('invalid IBAN format');
    return { type: 'iban', value: { iban }, last4: iban.slice(-4) };
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
}

export const TRANSACTION_FINGERPRINT_VERSION = 1;

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
  });
  return `tx_${sha256Hex(material)}`;
}
