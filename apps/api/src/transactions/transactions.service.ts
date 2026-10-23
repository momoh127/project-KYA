import { HttpStatus, Inject, Injectable, Logger } from '@nestjs/common';
import type { Transaction, TransactionStatus } from '@prisma/client';
import { tokenMismatches, verifyAuthorizationToken, type AuthorizationClaims } from '@agenttrust/authorization';
import { IdPrefix, newId } from '@agenttrust/shared';
import type { AgentPrincipal, HumanPrincipal } from '../auth/principal';
import { AuditService } from '../audit/audit.service';
import { intentFromRow } from '../authorizations/authorizations.service';
import { buildBinding } from '../authorizations/binding';
import { CryptoService } from '../common/crypto.service';
import { ApiError, Errors } from '../common/errors';
import { cents, PrismaService } from '../common/prisma.service';
import { SECURITY_VIOLATION_CODES, SecurityMonitorService } from '../security/security-monitor.service';
import { PAYMENT_ADAPTER, SimulatedProcessCrash, type PaymentAdapter, type PaymentResult } from './payment-adapter';

export interface ExecuteBody {
  token: string;
  expected: {
    supplierId: string | null;
    amountCents: number;
    currency: string;
    purchaseOrderId: string | null;
    invoiceId: string | null;
  };
}

const NON_FINAL: TransactionStatus[] = ['executing', 'unknown', 'reconciliation_required'];
export const MAX_PROVIDER_ATTEMPTS = 3;
const LEASE_MS = 30_000;

/** A gateway refusal. Recorded as evidence; classified for the security monitor. */
class GatewayRejection extends Error {
  constructor(readonly code: string, message: string, readonly details?: Record<string, unknown>) {
    super(message);
  }
}

/**
 * THE ENFORCEMENT POINT: the only component holding payment credentials and
 * the only path by which an agent's purchase is paid.
 *
 * Payment state machine (Authorization → Reservation → Transaction):
 *
 *   authorization: allowed ──consume──▶ consumed            (single use)
 *   reservation:   active  ──────────▶ consumed | released  (budget/PO/invoice hold)
 *   invoice:       open ─▶ processing ─▶ paid | open
 *   transaction:   executing ─▶ succeeded
 *                            ─▶ failed                       (definitive decline)
 *                            ─▶ unknown ─reconcile─▶ succeeded | failed | reconciliation_required
 *
 * A timeout is NEVER treated as failure. Before any retry the gateway asks
 * the provider what happened to the previous attempt (by idempotency key),
 * and every provider call carries the same idempotency key, so a crash or
 * timeout can never produce a second payment.
 */
@Injectable()
export class TransactionsService {
  private readonly logger = new Logger('Gateway');

  constructor(
    private readonly prisma: PrismaService,
    private readonly crypto: CryptoService,
    private readonly audit: AuditService,
    private readonly security: SecurityMonitorService,
    @Inject(PAYMENT_ADAPTER) private readonly payments: PaymentAdapter,
  ) {}

  async execute(agent: AgentPrincipal, body: ExecuteBody) {
    let claims: AuthorizationClaims | null = null;
    try {
      claims = this.verifyToken(agent, body);
      const prepared = await this.prepare(agent, claims);
      if (prepared.kind === 'retry') {
        // Same authorization presented again while the outcome is not final:
        // reconcile with the provider instead of paying again.
        return { ...(await this.reconcile(prepared.transaction.id, `agent:${agent.agentId}`)), retried: true };
      }
      return { ...(await this.attempt(prepared.transaction, prepared.destinationRef, prepared.memo, 'gateway')), retried: false };
    } catch (e) {
      if (!(e instanceof GatewayRejection)) throw e;
      await this.recordRejection(agent, claims, e);
      const status = e.code === 'AUTHORIZATION_ALREADY_USED' ? HttpStatus.CONFLICT : HttpStatus.FORBIDDEN;
      throw new ApiError(status, e.code, e.message, e.details);
    }
  }

  private verifyToken(agent: AgentPrincipal, body: ExecuteBody): AuthorizationClaims {
    const v = verifyAuthorizationToken(body.token, { resolveKey: this.crypto.resolveKey });
    if (!v.ok) throw new GatewayRejection(`TOKEN_${v.reason}`, 'Authorization token is not valid');
    const c = v.claims;
    if (c.org !== agent.organizationId || c.agt !== agent.agentId) {
      throw new GatewayRejection('TOKEN_NOT_ISSUED_TO_CALLER', 'This authorization was issued to a different agent');
    }
    const e = body.expected;
    const diffs: string[] = [];
    if (e.supplierId !== c.sup) diffs.push('supplierId');
    if (e.amountCents !== c.amt) diffs.push('amountCents');
    if (e.currency !== c.cur) diffs.push('currency');
    if (e.purchaseOrderId !== c.po) diffs.push('purchaseOrderId');
    if (e.invoiceId !== c.inv) diffs.push('invoiceId');
    if (diffs.length) {
      throw new GatewayRejection('TRANSACTION_MISMATCH', 'Requested payment does not match the authorized transaction', { mismatchedFields: diffs });
    }
    return c;
  }

  private prepare(agent: AgentPrincipal, claims: AuthorizationClaims) {
    return this.prisma.tx(async (tx) => {
      const now = new Date();
      const locked = await tx.$queryRaw<{ id: string }[]>`
        SELECT id FROM "Authorization" WHERE id = ${claims.jti} AND "organizationId" = ${agent.organizationId} FOR UPDATE`;
      if (locked.length !== 1) throw new GatewayRejection('AUTHORIZATION_NOT_FOUND', 'Authorization not found');
      const auth = (await tx.authorization.findUnique({ where: { id: claims.jti } }))!;

      if (auth.agentId !== agent.agentId) throw new GatewayRejection('TOKEN_NOT_ISSUED_TO_CALLER', 'Authorization belongs to another agent');
      if (auth.tokenNonce !== claims.nonce) throw new GatewayRejection('TOKEN_SUPERSEDED', 'Token does not match the current authorization');

      if (auth.status === 'consumed') {
        const existing = await tx.transaction.findUnique({ where: { authorizationId: auth.id } });
        if (existing && NON_FINAL.includes(existing.status)) return { kind: 'retry' as const, transaction: existing };
        throw new GatewayRejection('AUTHORIZATION_ALREADY_USED', 'Authorization has already been used', {
          transactionId: existing?.id ?? null,
          transactionStatus: existing?.status ?? null,
        });
      }
      if (auth.status === 'invalidated') {
        throw new GatewayRejection('AUTHORIZATION_INVALIDATED', `Authorization was invalidated: ${auth.invalidatedReason ?? 'underlying record changed'}`);
      }
      if (auth.status !== 'allowed') throw new GatewayRejection('AUTHORIZATION_NOT_ALLOWED', `Authorization is ${auth.status}`);
      if (auth.expiresAt <= now) throw new GatewayRejection('AUTHORIZATION_EXPIRED', 'Authorization has expired');

      // ---- Re-verify the authority and the payment instruction against CURRENT state.
      const agentRow = await tx.agent.findUnique({ where: { id: agent.agentId } });
      if (agentRow?.status !== 'active') throw new GatewayRejection('AGENT_NOT_ACTIVE', `Agent is ${agentRow?.status ?? 'unknown'}`);

      const delegation = await tx.delegation.findFirst({ where: { agentId: agent.agentId, organizationId: agent.organizationId }, orderBy: { createdAt: 'desc' } });
      if (!delegation || delegation.id !== claims.dlg) throw new GatewayRejection('DELEGATION_CHANGED', 'The delegation behind this authorization was superseded');
      if (delegation.revokedAt || delegation.expiresAt <= now || delegation.validFrom > now) {
        throw new GatewayRejection('DELEGATION_NO_LONGER_VALID', 'The delegation behind this authorization is no longer valid');
      }

      const policy = await tx.policy.findFirst({ where: { organizationId: agent.organizationId, status: 'active' } });
      if (!policy || policy.id !== claims.pol || policy.version !== claims.pv) {
        throw new GatewayRejection('POLICY_CHANGED', 'The policy version that approved this authorization is no longer active');
      }

      const supplier = auth.supplierId ? await tx.supplier.findFirst({ where: { id: auth.supplierId, organizationId: agent.organizationId } }) : null;
      if (!supplier || supplier.status !== 'active' || supplier.verificationStatus !== 'verified' || !supplier.paymentCounterpartyRef) {
        throw new GatewayRejection('SUPPLIER_NOT_VERIFIED', 'Supplier is no longer active and verified');
      }
      if (supplier.paymentDestinationFingerprint !== claims.pd || supplier.paymentCounterpartyRef !== claims.dst) {
        throw new GatewayRejection('PAYEE_CHANGED', 'Supplier bank details changed after authorization; re-authorization required');
      }
      if (supplier.version !== claims.sv) {
        throw new GatewayRejection('SUPPLIER_RECORD_CHANGED', `Supplier record changed (v${claims.sv} → v${supplier.version}) after authorization`);
      }

      // Catch-all: the complete instruction rebuilt from current records must equal what was signed.
      const binding = buildBinding(intentFromRow(auth), supplier, policy, delegation);
      const mismatches = binding ? tokenMismatches(claims, binding) : ['binding'];
      if (mismatches.length || auth.authorizationFingerprint !== claims.fp) {
        throw new GatewayRejection('AUTHORIZATION_BINDING_CHANGED', 'The payment instruction no longer matches what was authorized', { mismatchedFields: mismatches });
      }

      let memo = `Authorization ${auth.id}`;
      if (auth.invoiceId) {
        await tx.$queryRaw`SELECT id FROM "Invoice" WHERE id = ${auth.invoiceId} FOR UPDATE`;
        const inv = await tx.invoice.findUnique({ where: { id: auth.invoiceId } });
        if (!inv || inv.status !== 'open') throw new GatewayRejection('INVOICE_NOT_PAYABLE', `Invoice is ${inv?.status ?? 'missing'}`);
        memo = `Invoice ${inv.invoiceNumber}`;
      }

      // ---- Single-use consumption: exactly one concurrent caller can win.
      const consumed = await tx.authorization.updateMany({
        where: { id: auth.id, status: 'allowed', consumedAt: null },
        data: { status: 'consumed', consumedAt: now },
      });
      if (consumed.count !== 1) throw new GatewayRejection('AUTHORIZATION_ALREADY_USED', 'Authorization has already been used');
      await tx.budgetReservation.updateMany({ where: { authorizationId: auth.id, status: 'active' }, data: { status: 'consumed' } });
      if (auth.invoiceId) {
        await tx.invoice.updateMany({ where: { id: auth.invoiceId, status: 'open' }, data: { status: 'processing' } });
      }

      const transaction = await tx.transaction.create({
        data: {
          id: newId(IdPrefix.transaction),
          organizationId: agent.organizationId,
          authorizationId: auth.id,
          agentId: agent.agentId,
          supplierId: auth.supplierId,
          invoiceId: auth.invoiceId,
          amountCents: auth.amountCents,
          currency: auth.currency,
          status: 'executing',
          provider: this.payments.name,
          providerIdempotencyKey: auth.id,
        },
      });
      await this.audit.append(tx, {
        organizationId: agent.organizationId,
        actorType: 'agent',
        actorId: agent.agentId,
        eventType: 'execution.started',
        subjectId: transaction.id,
        payload: {
          authorizationId: auth.id,
          authorizationFingerprint: claims.fp,
          amountCents: cents(auth.amountCents),
          currency: auth.currency,
          supplierId: auth.supplierId,
          supplierVersion: claims.sv,
          paymentRail: claims.rail,
          destinationRef: claims.dst,
          invoiceId: auth.invoiceId,
          providerIdempotencyKey: auth.id,
        },
      });
      return { kind: 'new' as const, transaction, destinationRef: claims.dst, memo };
    });
  }

  /** One provider call. The attempt counter is persisted BEFORE calling out. */
  private async attempt(transaction: Transaction, destinationRef: string, memo: string, actor: string) {
    const bumped = await this.prisma.transaction.update({
      where: { id: transaction.id },
      data: { attempts: { increment: 1 }, lastAttemptAt: new Date() },
    });
    let result: PaymentResult;
    try {
      result = await this.payments.execute({
        idempotencyKey: transaction.providerIdempotencyKey,
        counterpartyRef: destinationRef,
        amountCents: cents(transaction.amountCents),
        currency: transaction.currency,
        memo,
      });
    } catch (e) {
      if (e instanceof SimulatedProcessCrash) throw e; // the process "dies" here; nothing else is recorded
      result = { status: 'unknown', providerReference: null, detail: e instanceof Error ? e.message : 'provider error' };
    }
    await this.recordAttempt(transaction, bumped.attempts, 'execute', result.status, result.providerReference, result.detail);
    return this.applyOutcome(transaction.id, result, actor);
  }

  /**
   * Reconciles a non-final transaction with the provider. Never sends a new
   * payment request without first asking the provider about the previous one.
   */
  async reconcile(transactionId: string, actor: string) {
    const now = new Date();
    const claimed = await this.prisma.transaction.updateMany({
      where: { id: transactionId, status: { in: NON_FINAL }, OR: [{ leaseUntil: null }, { leaseUntil: { lt: now } }] },
      data: { leaseUntil: new Date(now.getTime() + LEASE_MS) },
    });
    if (claimed.count === 0) return serializeTransaction(await this.prisma.transaction.findUniqueOrThrow({ where: { id: transactionId } }));

    try {
      const t = await this.prisma.transaction.findUniqueOrThrow({ where: { id: transactionId } });
      let status: Awaited<ReturnType<PaymentAdapter['getStatus']>> | null = null;
      try {
        status = await this.payments.getStatus(t.providerIdempotencyKey);
      } catch (e) {
        this.logger.warn(`status lookup failed for ${t.id}: ${e instanceof Error ? e.message : String(e)}`);
      }
      await this.recordAttempt(t, t.attempts, 'status_query', status?.status ?? 'unknown', status?.providerReference ?? null, status ? null : 'status lookup failed');

      if (status?.status === 'succeeded' || status?.status === 'failed') {
        return await this.applyOutcome(t.id, { status: status.status, providerReference: status.providerReference, detail: 'resolved by reconciliation' }, `reconciler:${actor}`);
      }
      if (status?.status === 'not_found') {
        // The provider never received the payment. Re-sending with the SAME
        // idempotency key is safe (the provider deduplicates on it).
        if (t.attempts < MAX_PROVIDER_ATTEMPTS) {
          const auth = await this.prisma.authorization.findUniqueOrThrow({ where: { id: t.authorizationId } });
          return await this.attempt(t, auth.destinationRef!, `Authorization ${auth.id} (retry)`, `reconciler:${actor}`);
        }
        return await this.requireManualReconciliation(t, 'provider has no record after maximum attempts');
      }
      // pending / lookup failed: still unknown. Escalate once attempts are exhausted.
      if (t.attempts >= MAX_PROVIDER_ATTEMPTS && t.status !== 'reconciliation_required') {
        return await this.requireManualReconciliation(t, 'outcome still unknown after maximum attempts');
      }
      return serializeTransaction(await this.prisma.transaction.findUniqueOrThrow({ where: { id: t.id } }));
    } finally {
      await this.prisma.transaction.updateMany({ where: { id: transactionId }, data: { leaseUntil: null } });
    }
  }

  /** Applies a provider outcome exactly once (conditional on the transaction still being non-final). */
  private async applyOutcome(transactionId: string, result: PaymentResult, actor: string) {
    return this.prisma.tx(async (tx) => {
      const t = await tx.transaction.findUniqueOrThrow({ where: { id: transactionId } });
      const now = new Date();

      if (result.status === 'unknown') {
        const moved = await tx.transaction.updateMany({ where: { id: t.id, status: 'executing' }, data: { status: 'unknown' } });
        if (moved.count === 1) {
          await this.audit.append(tx, {
            organizationId: t.organizationId, actorType: 'system', actorId: actor, eventType: 'execution.outcome_unknown', subjectId: t.id,
            payload: { authorizationId: t.authorizationId, detail: result.detail ?? null, attempts: t.attempts },
          });
        }
        return serializeTransaction(await tx.transaction.findUniqueOrThrow({ where: { id: t.id } }));
      }

      const finalStatus = result.status;
      const moved = await tx.transaction.updateMany({
        where: { id: t.id, status: { in: NON_FINAL } },
        data: { status: finalStatus, providerReference: result.providerReference, failureReason: finalStatus === 'failed' ? result.detail ?? 'failed' : null, finalizedAt: now },
      });
      if (moved.count === 1) {
        if (finalStatus === 'succeeded') {
          if (t.invoiceId) {
            await tx.invoice.updateMany({ where: { id: t.invoiceId, status: 'processing' }, data: { status: 'paid', paidAt: now, paidByTransactionId: t.id } });
          }
        } else {
          // Money did not move: release the hold and reopen the invoice. The
          // authorization stays consumed; a new authorization is required.
          await tx.budgetReservation.updateMany({ where: { authorizationId: t.authorizationId }, data: { status: 'released' } });
          if (t.invoiceId) await tx.invoice.updateMany({ where: { id: t.invoiceId, status: 'processing' }, data: { status: 'open' } });
        }
        await this.audit.append(tx, {
          organizationId: t.organizationId, actorType: 'system', actorId: actor,
          eventType: finalStatus === 'succeeded' ? 'execution.succeeded' : 'execution.failed', subjectId: t.id,
          payload: { authorizationId: t.authorizationId, providerReference: result.providerReference, detail: result.detail ?? null, attempts: t.attempts },
        });
      }
      return serializeTransaction(await tx.transaction.findUniqueOrThrow({ where: { id: t.id } }));
    });
  }

  private async requireManualReconciliation(t: Transaction, reason: string) {
    const updated = await this.prisma.tx(async (tx) => {
      const moved = await tx.transaction.updateMany({ where: { id: t.id, status: { in: ['executing', 'unknown'] } }, data: { status: 'reconciliation_required', failureReason: reason } });
      if (moved.count === 1) {
        await this.audit.append(tx, {
          organizationId: t.organizationId, actorType: 'system', actorId: 'reconciler', eventType: 'execution.reconciliation_required', subjectId: t.id,
          payload: { authorizationId: t.authorizationId, reason, attempts: t.attempts },
        });
      }
      return tx.transaction.findUniqueOrThrow({ where: { id: t.id } });
    });
    await this.security.raiseAlert(t.organizationId, t.agentId, 'reconciliation_required', new Date(0), {
      severity: 'high', transactionId: t.id, reason,
      message: 'A payment outcome could not be determined automatically. Do not re-pay; confirm with the provider and resolve manually.',
    });
    return serializeTransaction(updated);
  }

  private async recordAttempt(t: Transaction, attempt: number, action: 'execute' | 'status_query', outcome: string, providerReference: string | null, detail?: string | null) {
    await this.prisma.transactionAttempt.create({
      data: { id: newId(IdPrefix.attempt), organizationId: t.organizationId, transactionId: t.id, attempt, action, outcome, providerReference, detail: detail ?? null },
    });
  }

  private async recordRejection(agent: AgentPrincipal, claims: AuthorizationClaims | null, e: GatewayRejection) {
    const details = { message: e.message, ...(e.details ?? {}) };
    if (SECURITY_VIOLATION_CODES.has(e.code)) {
      await this.security.recordViolation(agent.organizationId, agent.agentId, e.code, claims?.jti ?? null, details);
    } else {
      await this.security.recordOperationalRejection(agent.organizationId, agent.agentId, e.code, claims?.jti ?? null, details);
    }
  }

  /** Picks up stale non-final transactions (background reconciler). */
  async reconcileStale(olderThanMs: number, limit = 20): Promise<number> {
    const cutoff = new Date(Date.now() - olderThanMs);
    const stale = await this.prisma.transaction.findMany({
      where: { status: { in: ['executing', 'unknown'] }, OR: [{ lastAttemptAt: null }, { lastAttemptAt: { lt: cutoff } }] },
      take: limit,
      select: { id: true },
    });
    for (const s of stale) {
      try {
        await this.reconcile(s.id, 'background');
      } catch (err) {
        this.logger.error(`reconcile ${s.id} failed: ${err instanceof Error ? err.message : String(err)}`);
      }
    }
    return stale.length;
  }

  async getForAgent(agent: AgentPrincipal, id: string) {
    const t = await this.prisma.transaction.findFirst({ where: { id, organizationId: agent.organizationId, agentId: agent.agentId } });
    if (!t) throw Errors.notFound('Transaction');
    return serializeTransaction(t);
  }

  async getForUser(user: HumanPrincipal, id: string) {
    const t = await this.prisma.transaction.findFirst({ where: { id, organizationId: user.organizationId } });
    if (!t) throw Errors.notFound('Transaction');
    const attempts = await this.prisma.transactionAttempt.findMany({ where: { transactionId: id }, orderBy: { createdAt: 'asc' } });
    return {
      ...serializeTransaction(t),
      providerAttempts: attempts.map((a) => ({ attempt: a.attempt, action: a.action, outcome: a.outcome, providerReference: a.providerReference, detail: a.detail, at: a.createdAt.toISOString() })),
    };
  }

  async reconcileForUser(user: HumanPrincipal, id: string) {
    const t = await this.prisma.transaction.findFirst({ where: { id, organizationId: user.organizationId } });
    if (!t) throw Errors.notFound('Transaction');
    return this.reconcile(id, `user:${user.userId}`);
  }
}

export function serializeTransaction(t: Transaction) {
  return {
    id: t.id,
    authorizationId: t.authorizationId,
    agentId: t.agentId,
    status: t.status,
    amountCents: cents(t.amountCents),
    currency: t.currency,
    supplierId: t.supplierId,
    invoiceId: t.invoiceId,
    provider: t.provider,
    providerIdempotencyKey: t.providerIdempotencyKey,
    providerReference: t.providerReference,
    failureReason: t.failureReason,
    attempts: t.attempts,
    finalizedAt: t.finalizedAt?.toISOString() ?? null,
    createdAt: t.createdAt.toISOString(),
  };
}
