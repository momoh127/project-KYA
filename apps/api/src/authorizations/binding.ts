import type { Delegation, Policy, Supplier } from '@prisma/client';
import type { AuthorizationBinding, TransactionIntent } from '@agenttrust/shared';

export function railFor(destinationType: string | null): string | null {
  if (destinationType === 'us_ach') return 'ach';
  if (destinationType === 'iban') return 'sepa';
  return null;
}

/**
 * Builds the complete payment instruction from the request intent and the
 * CURRENT trusted records. Used both when issuing an authorization and at the
 * gateway right before paying; any difference means something changed.
 */
export function buildBinding(
  intent: TransactionIntent,
  supplier: Supplier | null,
  policy: Policy | null,
  delegation: Delegation | null,
): AuthorizationBinding | null {
  const rail = railFor(supplier?.paymentDestinationType ?? null);
  if (!supplier || !supplier.paymentCounterpartyRef || !rail || !policy || !delegation) return null;
  return {
    ...intent,
    paymentRail: rail,
    destinationRef: supplier.paymentCounterpartyRef,
    supplierVersion: supplier.version,
    policyId: policy.id,
    policyVersion: policy.version,
    delegationId: delegation.id,
  };
}
