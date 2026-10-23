import { Injectable } from '@nestjs/common';
import { randomBytes } from 'node:crypto';

export interface PaymentRequest {
  /** Our authorization id; providers must treat it as an idempotency key. */
  idempotencyKey: string;
  /** Provider-side counterparty from the VERIFIED supplier record (never agent-supplied). */
  counterpartyRef: string;
  amountCents: number;
  currency: string;
  memo: string;
}

export interface PaymentResult {
  status: 'succeeded' | 'failed';
  providerReference: string | null;
  failureReason?: string;
}

/**
 * Boundary to real money movement. Implementations hold the payment-provider
 * credentials; those credentials exist only inside the gateway process and are
 * never exposed to agents or to any API response.
 *
 * Future adapters: Stripe (PaymentIntents / Issuing single-use cards), Modern
 * Treasury (ACH/wire), bank APIs. They MUST be idempotent on `idempotencyKey`.
 */
export interface PaymentAdapter {
  readonly name: string;
  execute(req: PaymentRequest): Promise<PaymentResult>;
}

export const PAYMENT_ADAPTER = Symbol('PAYMENT_ADAPTER');

/** Simulated provider. Moves no money. Idempotent per key. */
@Injectable()
export class SandboxPaymentAdapter implements PaymentAdapter {
  readonly name = 'sandbox';
  private readonly results = new Map<string, PaymentResult>();

  async execute(req: PaymentRequest): Promise<PaymentResult> {
    const prior = this.results.get(req.idempotencyKey);
    if (prior) return prior;
    if (!req.counterpartyRef) {
      const failed: PaymentResult = { status: 'failed', providerReference: null, failureReason: 'missing counterparty' };
      this.results.set(req.idempotencyKey, failed);
      return failed;
    }
    const result: PaymentResult = { status: 'succeeded', providerReference: `sbx_pay_${randomBytes(8).toString('hex')}` };
    this.results.set(req.idempotencyKey, result);
    return result;
  }
}
