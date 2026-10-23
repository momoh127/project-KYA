import { HttpStatus, Inject, Injectable, Logger } from '@nestjs/common';
import type { Transaction } from '@prisma/client';
import { tokenMismatches, verifyAuthorizationToken, type AuthorizationClaims } from '@agenttrust/authorization';
import { IdPrefix, newId } from '@agenttrust/shared';
import type { AgentPrincipal, HumanPrincipal } from '../auth/principal';
import { AuditService } from '../audit/audit.service';
import { CircuitBreakerService } from '../authorizations/circuit-breaker.service';
import { intentFromRow } from '../authorizations/authorizations.service';
import { CryptoService } from '../common/crypto.service';
import { ApiError, Errors } from '../common/errors';
import { cents, PrismaService } from '../common/prisma.service';
import { PAYMENT_ADAPTER, type PaymentAdapter } from './payment-adapter';

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

/** A gateway refusal. Recorded as evidence and counted by the circuit breaker. */
class GatewayRejection extends Error {
  constructor(readonly code: string, message: string, readonly details?: Record<string, unknown>) {
    super(message);
  }
}

/**
 * THE ENFORCEMENT POINT. This gateway is the only component holding payment
 * credentials, and the only path by which an agent's purchase can be paid.
 *
 * Before paying it:
 *  1. verifies the platform signature on the authorization token,
 *  2. checks the token was issued to the calling agent, in its organization,
 *  3. checks the caller's expected parameters match the token exactly,
 *  4. locks the authorization row and checks it is live, unexpired, unused,
 *  5. re-derives the transaction fingerprint from the stored intent,
 *  6. re-checks live state (agent active, delegation valid, supplier still
 *     verified with the SAME bank details, invoice still unpaid),
 *  7. atomically consumes the authorization (single use), consumes the budget
 *     hold and marks the invoice paid,
 *  8. only then calls the payment provider, paying the supplier's verified
 *     counterparty (never a destination supplied by the agent).
 */
@Injectable()
export class TransactionsService {
  private readonly logger = new Logger('Gateway');

  constructor(
    private readonly prisma: PrismaService,
    private readonly crypto: CryptoService,
    private readonly audit: AuditService,
    private readonly breaker: CircuitBreakerService,
    @Inject(PAYMENT_ADAPTER) private readonly payments: PaymentAdapter,
  ) {}

  async execute(agent: AgentPrincipal, body: ExecuteBody) {
    let claims: AuthorizationClaims | null = null;
    try {
      claims = this.verifyToken(agent, body);
      const prepared = await this.prepare(agent, claims);
      return await this.settle(prepared.transaction, prepared.counterpartyRef, prepared.memo);
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
      if (auth.status === 'consumed' || auth.consumedAt) {
        throw new GatewayRejection('AUTHORIZATION_ALREADY_USED', 'Authorization has already been used');
      }
      if (auth.status !== 'allowed') throw new GatewayRejection('AUTHORIZATION_NOT_ALLOWED', `Authorization is ${auth.status}`);
      if (auth.expiresAt <= now) throw new GatewayRejection('AUTHORIZATION_EXPIRED', 'Authorization has expired');
      if (auth.tokenNonce !== claims.nonce) throw new GatewayRejection('TOKEN_SUPERSEDED', 'Token does not match the current authorization');

      const intent = intentFromRow(auth);
      const mismatches = tokenMismatches(claims, intent);
      if (mismatches.length || auth.transactionFingerprint !== claims.fp) {
        throw new GatewayRejection('TRANSACTION_MISMATCH', 'Token does not bind the stored transaction', { mismatchedFields: mismatches });
      }

      // Live re-checks: things may have changed since authorization was issued.
      const agentRow = await tx.agent.findUnique({ where: { id: agent.agentId } });
      if (agentRow?.status !== 'active') throw new GatewayRejection('AGENT_NOT_ACTIVE', `Agent is ${agentRow?.status ?? 'unknown'}`);
      const delegation = auth.delegationId ? await tx.delegation.findUnique({ where: { id: auth.delegationId } }) : null;
      if (!delegation || delegation.revokedAt || delegation.expiresAt <= now) {
        throw new GatewayRejection('DELEGATION_NO_LONGER_VALID', 'The delegation behind this authorization is no longer valid');
      }
      const supplier = auth.supplierId ? await tx.supplier.findFirst({ where: { id: auth.supplierId, organizationId: agent.organizationId } }) : null;
      if (!supplier || supplier.status !== 'active' || supplier.verificationStatus !== 'verified' || !supplier.paymentCounterpartyRef) {
        throw new GatewayRejection('SUPPLIER_NOT_VERIFIED', 'Supplier is no longer active and verified');
      }
      if (supplier.paymentDestinationFingerprint !== auth.paymentDestinationFingerprint) {
        throw new GatewayRejection('PAYEE_CHANGED', 'Supplier bank details changed after authorization; re-authorization required');
      }

      let invoiceNumber: string | null = null;
      if (auth.invoiceId) {
        await tx.$queryRaw`SELECT id FROM "Invoice" WHERE id = ${auth.invoiceId} FOR UPDATE`;
        const inv = await tx.invoice.findUnique({ where: { id: auth.invoiceId } });
        if (!inv || inv.status !== 'open') throw new GatewayRejection('INVOICE_NOT_PAYABLE', `Invoice is ${inv?.status ?? 'missing'}`);
        invoiceNumber = inv.invoiceNumber;
      }

      // Single-use consumption: exactly one concurrent caller can win this update.
      const consumed = await tx.authorization.updateMany({
        where: { id: auth.id, status: 'allowed', consumedAt: null },
        data: { status: 'consumed', consumedAt: now },
      });
      if (consumed.count !== 1) throw new GatewayRejection('AUTHORIZATION_ALREADY_USED', 'Authorization has already been used');
      await tx.budgetReservation.updateMany({ where: { authorizationId: auth.id, status: 'active' }, data: { status: 'consumed' } });

      const txnId = newId(IdPrefix.transaction);
      if (auth.invoiceId) {
        const paid = await tx.invoice.updateMany({
          where: { id: auth.invoiceId, status: 'open' },
          data: { status: 'paid', paidAt: now, paidByTransactionId: txnId },
        });
        if (paid.count !== 1) throw new GatewayRejection('INVOICE_NOT_PAYABLE', 'Invoice already paid');
      }

      const transaction = await tx.transaction.create({
        data: {
          id: txnId,
          organizationId: agent.organizationId,
          authorizationId: auth.id,
          agentId: agent.agentId,
          supplierId: auth.supplierId,
          invoiceId: auth.invoiceId,
          amountCents: auth.amountCents,
          currency: auth.currency,
          status: 'pending',
          provider: this.payments.name,
        },
      });
      await this.audit.append(tx, {
        organizationId: agent.organizationId,
        actorType: 'agent',
        actorId: agent.agentId,
        eventType: 'execution.authorized',
        subjectId: txnId,
        payload: {
          authorizationId: auth.id,
          transactionFingerprint: auth.transactionFingerprint,
          amountCents: cents(auth.amountCents),
          currency: auth.currency,
          supplierId: auth.supplierId,
          invoiceId: auth.invoiceId,
          paymentDestinationFingerprint: auth.paymentDestinationFingerprint,
        },
      });
      return {
        transaction,
        counterpartyRef: supplier.paymentCounterpartyRef,
        memo: invoiceNumber ? `Invoice ${invoiceNumber}` : `Authorization ${auth.id}`,
      };
    });
  }

  /**
   * Phase 2: call the provider AFTER the consumption commit, keyed by the
   * authorization id (idempotent). If the process crashes in between, the
   * transaction stays `pending` for reconciliation; it can never be paid twice
   * because the authorization is already consumed.
   */
  private async settle(transaction: Transaction, counterpartyRef: string, memo: string) {
    let result;
    try {
      result = await this.payments.execute({
        idempotencyKey: transaction.authorizationId,
        counterpartyRef,
        amountCents: cents(transaction.amountCents),
        currency: transaction.currency,
        memo,
      });
    } catch (e) {
      this.logger.error(`payment provider error for ${transaction.id}: ${e instanceof Error ? e.message : String(e)}`);
      result = { status: 'failed' as const, providerReference: null, failureReason: 'provider error' };
    }

    return this.prisma.tx(async (tx) => {
      const updated = await tx.transaction.update({
        where: { id: transaction.id },
        data: { status: result.status, providerReference: result.providerReference, failureReason: result.failureReason ?? null },
      });
      if (result.status === 'failed') {
        // Money did not move: release the hold and reopen the invoice. The
        // authorization stays consumed; a new authorization is required.
        await tx.budgetReservation.updateMany({ where: { authorizationId: transaction.authorizationId }, data: { status: 'released' } });
        if (transaction.invoiceId) {
          await tx.invoice.updateMany({
            where: { id: transaction.invoiceId, paidByTransactionId: transaction.id },
            data: { status: 'open', paidAt: null, paidByTransactionId: null },
          });
        }
      }
      await this.audit.append(tx, {
        organizationId: transaction.organizationId,
        actorType: 'system',
        actorId: `gateway:${this.payments.name}`,
        eventType: result.status === 'succeeded' ? 'execution.succeeded' : 'execution.failed',
        subjectId: transaction.id,
        payload: {
          authorizationId: transaction.authorizationId,
          providerReference: result.providerReference,
          failureReason: result.failureReason ?? null,
        },
      });
      return serializeTransaction(updated);
    });
  }

  private async recordRejection(agent: AgentPrincipal, claims: AuthorizationClaims | null, e: GatewayRejection) {
    try {
      await this.audit.appendStandalone({
        organizationId: agent.organizationId,
        actorType: 'agent',
        actorId: agent.agentId,
        eventType: 'execution.rejected',
        subjectId: claims?.jti ?? null,
        payload: { code: e.code, message: e.message, details: (e.details ?? null) as Record<string, unknown> | null },
      });
    } catch (err) {
      this.logger.error(`failed to record rejection: ${err instanceof Error ? err.message : String(err)}`);
    }
    await this.breaker.check(agent.organizationId, agent.agentId);
  }

  async getForAgent(agent: AgentPrincipal, id: string) {
    const t = await this.prisma.transaction.findFirst({ where: { id, organizationId: agent.organizationId, agentId: agent.agentId } });
    if (!t) throw Errors.notFound('Transaction');
    return serializeTransaction(t);
  }

  async getForUser(user: HumanPrincipal, id: string) {
    const t = await this.prisma.transaction.findFirst({ where: { id, organizationId: user.organizationId } });
    if (!t) throw Errors.notFound('Transaction');
    return serializeTransaction(t);
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
    providerReference: t.providerReference,
    failureReason: t.failureReason,
    createdAt: t.createdAt.toISOString(),
  };
}
