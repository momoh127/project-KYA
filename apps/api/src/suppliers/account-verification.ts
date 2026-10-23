import { Injectable } from '@nestjs/common';
import { randomBytes } from 'node:crypto';
import { normalizePaymentDestination, type PaymentDestination } from '@agenttrust/shared';

export interface AccountVerificationRequest {
  destination: PaymentDestination;
  /** Supplier's registered legal entity name (for ownership matching). */
  legalName: string | null;
}

/**
 * Independent evidence about a bank account, from a third party rather than
 * from anyone inside the customer organization. This is what defeats two
 * colluding (or compromised) administrators approving a fraudulent change.
 */
export interface AccountVerificationResult {
  /** Does the account exist and accept payments? */
  accountStatus: 'valid' | 'invalid' | 'unknown';
  /** Does the account holder's name match the supplier's legal entity? */
  ownerNameMatch: 'match' | 'partial' | 'no_match' | 'unavailable';
  providerReference: string | null;
}

/**
 * Provider integration point. Real implementations: Nacha-style account
 * validation services, open-banking account/owner lookups, or vendor-payment
 * verification networks (e.g. Trustpair / Eftsure-like providers).
 */
export interface AccountVerificationProvider {
  readonly name: string;
  verify(req: AccountVerificationRequest): Promise<AccountVerificationResult>;
}

export const ACCOUNT_VERIFICATION_PROVIDER = Symbol('ACCOUNT_VERIFICATION_PROVIDER');

/**
 * SANDBOX ONLY. Deterministic stand-in for a verification provider:
 *  - accounts ending in 0000 do not exist (invalid);
 *  - accounts starting with 9999 belong to "Unknown Holdings LLC" (owner mismatch);
 *  - otherwise the account is valid and held by the supplier's legal name
 *    (ownership unavailable if no legal name is on record).
 */
@Injectable()
export class SandboxAccountVerificationProvider implements AccountVerificationProvider {
  readonly name = 'sandbox-account-verification';

  async verify(req: AccountVerificationRequest): Promise<AccountVerificationResult> {
    const n = normalizePaymentDestination(req.destination);
    const account = n.type === 'us_ach' ? n.value.accountNumber! : n.value.iban!;
    const ref = `sbx_av_${randomBytes(6).toString('hex')}`;
    if (account.endsWith('0000')) return { accountStatus: 'invalid', ownerNameMatch: 'unavailable', providerReference: ref };
    if (account.startsWith('9999')) return { accountStatus: 'valid', ownerNameMatch: 'no_match', providerReference: ref };
    return { accountStatus: 'valid', ownerNameMatch: req.legalName ? 'match' : 'unavailable', providerReference: ref };
  }
}
