import { Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { randomBytes } from 'node:crypto';
import { newId } from '@agenttrust/shared';
import { PrismaService } from '../common/prisma.service';

export interface PaymentRequest {
  /** Stable per transaction; the provider MUST deduplicate on it. */
  idempotencyKey: string;
  /** Provider-side counterparty from the VERIFIED supplier record (never agent-supplied). */
  counterpartyRef: string;
  amountCents: number;
  currency: string;
  memo: string;
}

/**
 * `unknown` means the outcome could not be determined (timeout, connection
 * reset). It is NEVER treated as failure: the payment may have gone through.
 */
export interface PaymentResult {
  status: 'succeeded' | 'failed' | 'unknown';
  providerReference: string | null;
  detail?: string;
}

export interface PaymentStatus {
  status: 'succeeded' | 'failed' | 'pending' | 'not_found';
  providerReference: string | null;
}

/**
 * Boundary to real money movement. Implementations hold the payment-provider
 * credentials, which exist only inside the gateway and are never exposed to
 * agents or API responses.
 *
 * Requirements for any real adapter (Stripe, Modern Treasury, bank APIs):
 *  - `execute` must be idempotent on `idempotencyKey` at the PROVIDER;
 *  - `getStatus` must look up a payment by that key, so the gateway can
 *    reconcile before ever retrying.
 */
export interface PaymentAdapter {
  readonly name: string;
  execute(req: PaymentRequest): Promise<PaymentResult>;
  getStatus(idempotencyKey: string): Promise<PaymentStatus>;
}

export const PAYMENT_ADAPTER = Symbol('PAYMENT_ADAPTER');

/**
 * Thrown by the sandbox to simulate the gateway PROCESS dying right after the
 * provider accepted a payment, before the gateway recorded the result. The
 * gateway deliberately does not catch it.
 */
export class SimulatedProcessCrash extends Error {
  constructor() {
    super('simulated gateway crash after provider accepted the payment');
  }
}

export const SANDBOX_FAULTS = [
  /** Provider declines the payment (definitive failure). */
  'decline',
  /** Provider times out BEFORE processing: no payment exists. */
  'timeout_before_processing',
  /** Provider processes the payment, then the response times out. */
  'timeout_after_processing',
  /** Provider processes the payment, then the gateway process crashes. */
  'crash_after_processing',
  /** Status lookups fail (provider status API unavailable). */
  'status_unavailable',
] as const;
export type SandboxFault = (typeof SANDBOX_FAULTS)[number];

/**
 * Simulated payment provider. Moves no money. Its ledger is persisted in its
 * own table (as an external provider's would be), so it survives gateway
 * crashes, and it deduplicates on the idempotency key like real providers.
 */
@Injectable()
export class SandboxPaymentAdapter implements PaymentAdapter {
  readonly name = 'sandbox';

  constructor(private readonly prisma: PrismaService) {}

  async execute(req: PaymentRequest): Promise<PaymentResult> {
    const existing = await this.prisma.sandboxProviderPayment.findUnique({ where: { idempotencyKey: req.idempotencyKey } });
    if (existing) {
      // Provider-level idempotency: a repeated request returns the original result.
      return { status: existing.status as 'succeeded' | 'failed', providerReference: existing.providerReference, detail: 'idempotent replay at provider' };
    }

    const fault = await this.takeFault(['decline', 'timeout_before_processing', 'timeout_after_processing', 'crash_after_processing']);
    if (fault === 'timeout_before_processing') return { status: 'unknown', providerReference: null, detail: 'provider timeout' };

    const status = fault === 'decline' ? 'failed' : 'succeeded';
    const providerReference = `sbx_pay_${randomBytes(8).toString('hex')}`;
    try {
      await this.prisma.sandboxProviderPayment.create({
        data: { idempotencyKey: req.idempotencyKey, counterpartyRef: req.counterpartyRef, amountCents: BigInt(req.amountCents), currency: req.currency, status, providerReference },
      });
    } catch (e) {
      if (e instanceof Prisma.PrismaClientKnownRequestError && e.code === 'P2002') {
        const raced = await this.prisma.sandboxProviderPayment.findUniqueOrThrow({ where: { idempotencyKey: req.idempotencyKey } });
        return { status: raced.status as 'succeeded' | 'failed', providerReference: raced.providerReference, detail: 'idempotent replay at provider' };
      }
      throw e;
    }

    if (fault === 'timeout_after_processing') return { status: 'unknown', providerReference: null, detail: 'provider timeout after processing' };
    if (fault === 'crash_after_processing') throw new SimulatedProcessCrash();
    return status === 'failed'
      ? { status: 'failed', providerReference, detail: 'declined by provider' }
      : { status: 'succeeded', providerReference };
  }

  async getStatus(idempotencyKey: string): Promise<PaymentStatus> {
    if (await this.takeFault(['status_unavailable'])) throw new Error('provider status API unavailable');
    const p = await this.prisma.sandboxProviderPayment.findUnique({ where: { idempotencyKey } });
    if (!p) return { status: 'not_found', providerReference: null };
    return { status: p.status as 'succeeded' | 'failed', providerReference: p.providerReference };
  }

  /** Test/dev hook: queue faults to inject (FIFO). */
  async queueFaults(faults: SandboxFault[]): Promise<void> {
    const base = Date.now();
    await this.prisma.sandboxFault.createMany({
      data: faults.map((fault, i) => ({ id: newId('sbf'), fault, createdAt: new Date(base + i) })),
    });
  }

  async ledger(idempotencyKey: string) {
    const rows = await this.prisma.sandboxProviderPayment.findMany({ where: { idempotencyKey } });
    return rows.map((r) => ({ ...r, amountCents: Number(r.amountCents), createdAt: r.createdAt.toISOString() }));
  }

  /** Consumes the oldest queued fault if it is one of `applicable`. */
  private async takeFault(applicable: SandboxFault[]): Promise<SandboxFault | null> {
    const next = await this.prisma.sandboxFault.findFirst({ orderBy: [{ createdAt: 'asc' }, { id: 'asc' }] });
    if (!next || !applicable.includes(next.fault as SandboxFault)) return null;
    const deleted = await this.prisma.sandboxFault.deleteMany({ where: { id: next.id } });
    return deleted.count === 1 ? (next.fault as SandboxFault) : null;
  }
}
