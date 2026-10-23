import { Inject, Injectable } from '@nestjs/common';
import type { KeyObject } from 'node:crypto';
import { LocalEd25519Signer, type Signer } from '@agenttrust/identity';
import { paymentDestinationFingerprint, normalizePaymentDestination, type PaymentDestination } from '@agenttrust/shared';
import { APP_CONFIG, type AppConfig } from '../config';

/**
 * Holds platform key material. In development the Ed25519 signing key is
 * loaded from the environment; in production `Signer` should be backed by a
 * KMS/HSM so the private key never exists in application memory.
 */
@Injectable()
export class CryptoService {
  readonly signer: Signer;
  private readonly pepper: string;

  constructor(@Inject(APP_CONFIG) config: AppConfig) {
    this.signer = new LocalEd25519Signer(config.signingKeyId, config.signingKeyPem);
    this.pepper = config.payeePepper;
  }

  /** Public keys the platform accepts for verifying its own tokens/audit signatures. */
  resolveKey = (kid: string): KeyObject | null => (kid === this.signer.keyId ? this.signer.publicKey : null);

  payeeFingerprint(dest: PaymentDestination): { fingerprint: string; last4: string; type: string } {
    const normalized = normalizePaymentDestination(dest);
    return {
      fingerprint: paymentDestinationFingerprint(this.pepper, dest),
      last4: normalized.last4,
      type: normalized.type,
    };
  }
}
