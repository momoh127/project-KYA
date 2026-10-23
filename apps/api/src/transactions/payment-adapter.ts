import { Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { createHmac, randomBytes } from 'node:crypto';
import { newId } from '@agenttrust/shared';
import { PrismaService } from '../common/prisma.service';
import type { ObservedStatus } from './lifecycle';

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
 * Result of submitting a payment. `accepted` means the provider took the
 * request, NOT that money settled. `unknown` means the outcome could not be
 * determined (timeout, connection reset) and is never treated as failure.
 */
export interface PaymentResult {
  status: 'accepted' | 'failed' | 'unknown';
  providerReference: string | null;
  detail?: string;
}

export interface PaymentStatus {
  status: ObservedStatus | 'not_found';
  providerReference: string | null;
}

/**
 * Boundary to real money movement. Implementations hold the provider
 * credentials, which exist only inside the gateway.
 *
 * Contract for any real adapter (Stripe, Modern Treasury, bank APIs):
 *  - `execute` is idempotent on `idempotencyKey` at the PROVIDER;
 *  - `getStatus` looks a payment up by that key and maps the provider's own
 *    lifecycle onto accepted / processing / settled / failed / returned / reversed;
 *  - the provider's webhooks are verified and deduplicated by PaymentEventsService.
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
  'decline',
  'timeout_before_processing',
  'timeout_after_processing',
  'crash_after_processing',
  'status_unavailable',
] as const;
export type SandboxFault = (typeof SANDBOX_FAULTS)[number];

export const SANDBOX_LIFECYCLE: ObservedStatus[] = ['accepted', 'processing', 'settled', 'failed', 'returned', 'reversed'];

/**
 * Simulated payment provider (moves no money). Its ledger is persisted in its
 * own table, as an external provider's would be, so it survives gateway
 * crashes. Like real ACH providers it ACCEPTS first; settlement, failure,
 * returns and reversals happen later (driven via `advance`, observed through
 * signed webhooks or status queries).
 */
@Injectable()
export class SandboxPaymentAdapter implements PaymentAdapter {
  readonly name = 'sandbox';

  constructor(private readonly prisma: PrismaService) {}

  async execute(req: PaymentRequest): Promise<PaymentResult> {
    const existing = await this.prisma.sandboxProviderPayment.findUnique({ where: { idempotencyKey: req.idempotencyKey } });
    if (existing) {
      // Provider-level idempotency: a repeated request returns the original submission, never a new payment.
      return { status: existing.status === 'failed' ? 'failed' : 'accepted', providerReference: existing.providerReference, detail: 'idempotent replay at provider' };
    }

    const fault = await this.takeFault(['decline', 'timeout_before_processing', 'timeout_after_processing', 'crash_after_processing']);
    if (fault === 'timeout_before_processing') return { status: 'unknown', providerReference: null, detail: 'provider timeout' };

    const status = fault === 'decline' ? 'failed' : 'accepted';
    const providerReference = `sbx_pay_${randomBytes(8).toString('hex')}`;
    try {
      await this.prisma.sandboxProviderPayment.create({
        data: { idempotencyKey: req.idempotencyKey, counterpartyRef: req.counterpartyRef, amountCents: BigInt(req.amountCents), currency: req.currency, status, providerReference },
      });
    } catch (e) {
      if (e instanceof Prisma.PrismaClientKnownRequestError && e.code === 'P2002') {
        const raced = await this.prisma.sandboxProviderPayment.findUniqueOrThrow({ where: { idempotencyKey: req.idempotencyKey } });
        return { status: raced.status === 'failed' ? 'failed' : 'accepted', providerReference: raced.providerReference, detail: 'idempotent replay at provider' };
      }
      throw e;
    }

    if (fault === 'timeout_after_processing') return { status: 'unknown', providerReference: null, detail: 'provider timeout after processing' };
    if (fault === 'crash_after_processing') throw new SimulatedProcessCrash();
    return status === 'failed'
      ? { status: 'failed', providerReference, detail: 'declined by provider' }
      : { status: 'accepted', providerReference };
  }

  async getStatus(idempotencyKey: string): Promise<PaymentStatus> {
    if (await this.takeFault(['status_unavailable'])) throw new Error('provider status API unavailable');
    const p = await this.prisma.sandboxProviderPayment.findUnique({ where: { idempotencyKey } });
    if (!p) return { status: 'not_found', providerReference: null };
    return { status: p.status as ObservedStatus, providerReference: p.providerReference };
  }

  // ------------------------------------------------------- sandbox-only controls

  /** Moves a payment along the provider's lifecycle (settle, return, reverse, ...). */
  async advance(idempotencyKey: string, status: ObservedStatus) {
    const p = await this.prisma.sandboxProviderPayment.findUnique({ where: { idempotencyKey } });
    if (!p) return null;
    return this.prisma.sandboxProviderPayment.update({ where: { idempotencyKey }, data: { status } });
  }

  /** Builds a signed webhook exactly as the sandbox provider would send it. */
  signEvent(secret: string, event: { id: string; type: string; data: Record<string, unknown> }, at = new Date()) {
    const body = JSON.stringify({ ...event, created: Math.floor(at.getTime() / 1000) });
    const t = Math.floor(at.getTime() / 1000);
    const v1 = createHmac('sha256', secret).update(`${t}.${body}`).digest('hex');
    return { body, signature: `t=${t},v1=${v1}` };
  }

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

  private async takeFault(applicable: SandboxFault[]): Promise<SandboxFault | null> {
    const next = await this.prisma.sandboxFault.findFirst({ orderBy: [{ createdAt: 'asc' }, { id: 'asc' }] });
    if (!next || !applicable.includes(next.fault as SandboxFault)) return null;
    const deleted = await this.prisma.sandboxFault.deleteMany({ where: { id: next.id } });
    return deleted.count === 1 ? (next.fault as SandboxFault) : null;
  }
}
