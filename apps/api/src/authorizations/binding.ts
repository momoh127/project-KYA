import type { Delegation, Policy, PurchaseInstruction, Supplier } from '@prisma/client';
import type { PaymentLineFacts } from '@agenttrust/policy-engine';
import { linesHash, type AuthorizationBinding, type PaymentLine, type TransactionIntent } from '@agenttrust/shared';

export function railFor(destinationType: string | null): string | null {
  if (destinationType === 'us_ach') return 'ach';
  if (destinationType === 'iban') return 'sepa';
  return null;
}

/** Converts policy-engine payment lines (all mapped to instruction lines) to bound PaymentLines. */
export function toPaymentLines(lines: PaymentLineFacts[] | null): PaymentLine[] | null {
  if (!lines || lines.some((l) => l.instructionLineNumber === null)) return null;
  return lines.map((l) => ({
    instructionLineNumber: l.instructionLineNumber!,
    sku: l.sku,
    quantityMilli: l.quantityMilli,
    unitPriceCents: l.unitPriceCents,
    lineTotalCents: l.lineTotalCents,
  }));
}

/**
 * Builds the complete payment instruction from the request intent and the
 * CURRENT trusted records (supplier record, policy, delegation, purchase
 * instruction version, exact lines). Used when issuing an authorization and
 * again at the gateway right before paying; any difference means something
 * changed and payment is refused.
 */
export function buildBinding(
  intent: TransactionIntent,
  supplier: Supplier | null,
  policy: Policy | null,
  delegation: Delegation | null,
  instruction: PurchaseInstruction | null,
  lines: PaymentLine[] | null,
): AuthorizationBinding | null {
  const rail = railFor(supplier?.paymentDestinationType ?? null);
  if (!supplier || !supplier.paymentCounterpartyRef || !rail || !policy || !delegation || !instruction || !lines || lines.length === 0) return null;
  return {
    ...intent,
    paymentRail: rail,
    destinationRef: supplier.paymentCounterpartyRef,
    supplierVersion: supplier.version,
    policyId: policy.id,
    policyVersion: policy.version,
    delegationId: delegation.id,
    instructionId: instruction.id,
    instructionVersion: instruction.version,
    linesHash: linesHash(lines),
  };
}
