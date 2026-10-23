import { Injectable } from '@nestjs/common';
import { Prisma, type Authorization } from '@prisma/client';
import { randomBytes } from 'node:crypto';
import { claimsFromBinding, signAuthorizationToken } from '@agenttrust/authorization';
import { evaluatePurchase, type PolicyResult } from '@agenttrust/policy-engine';
import {
  authorizationFingerprint,
  exactLineTotal,
  IdPrefix,
  linesHash,
  newId,
  parseQuantity,
  toSafeNumber,
  transactionFingerprint,
  type AuthorizationBinding,
  type PaymentDestination,
  type PaymentLine,
  type TransactionIntent,
} from '@agenttrust/shared';
import type { AgentPrincipal, HumanPrincipal } from '../auth/principal';
import { AuditService } from '../audit/audit.service';
import { CryptoService } from '../common/crypto.service';
import { Errors } from '../common/errors';
import { cents, PrismaService, type Tx } from '../common/prisma.service';
import { SecurityMonitorService } from '../security/security-monitor.service';
import { buildBinding, toPaymentLines } from './binding';
import { FactsLoader, type LoadedFacts } from './facts.loader';

export interface CreateAuthorizationBody {
  idempotencyKey: string;
  action: 'purchase';
  supplierId?: string;
  payee: PaymentDestination;
  amountCents: number;
  currency: string;
  purchaseOrderId?: string;
  invoiceId?: string;
  purchaseInstructionId?: string;
  /** Agent-supplied lines; only used when the invoice carries no lines. */
  lines?: { instructionLineNumber: number; sku?: string; quantity: string; unitPriceCents: number }[];
}

/** Parses agent-supplied lines with exact arithmetic (rejects totals that would need rounding). */
function parseRequestLines(lines: CreateAuthorizationBody['lines']): PaymentLine[] | null {
  if (!lines || lines.length === 0) return null;
  return lines.map((l) => {
    let quantityMilli: bigint;
    try {
      quantityMilli = parseQuantity(l.quantity);
    } catch (e) {
      throw Errors.invalid(`Line ${l.instructionLineNumber}: ${e instanceof Error ? e.message : 'invalid quantity'}`);
    }
    const total = exactLineTotal(quantityMilli, BigInt(l.unitPriceCents));
    if (total === null) throw Errors.invalid(`Line ${l.instructionLineNumber}: quantity × unit price is not an exact number of cents`);
    return {
      instructionLineNumber: l.instructionLineNumber,
      sku: l.sku ?? null,
      quantityMilli: toSafeNumber(quantityMilli),
      unitPriceCents: l.unitPriceCents,
      lineTotalCents: toSafeNumber(total),
    };
  });
}

const STATUS_FOR: Record<PolicyResult['decision'], Authorization['status']> = {
  ALLOW: 'allowed',
  REVIEW: 'pending_review',
  DENY: 'denied',
};

@Injectable()
export class AuthorizationsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly crypto: CryptoService,
    private readonly audit: AuditService,
    private readonly facts: FactsLoader,
    private readonly security: SecurityMonitorService,
  ) {}

  /**
   * Evaluates a proposed purchase. Organization and agent identity come from
   * the verified request signature; the body may only reference records by id.
   * Issuing an authorization never moves money: execution is a separate,
   * enforced step at the gateway.
   */
  async create(agent: AgentPrincipal, body: CreateAuthorizationBody) {
    let payee: ReturnType<CryptoService['payeeFingerprint']>;
    try {
      payee = this.crypto.payeeFingerprint(body.payee);
    } catch (e) {
      throw Errors.invalid(`Invalid payee: ${e instanceof Error ? e.message : 'unparseable'}`);
    }

    const intent: TransactionIntent = {
      organizationId: agent.organizationId,
      agentId: agent.agentId,
      action: body.action,
      supplierId: body.supplierId ?? null,
      paymentDestinationFingerprint: payee.fingerprint,
      amountCents: body.amountCents,
      currency: body.currency,
      purchaseOrderId: body.purchaseOrderId ?? null,
      invoiceId: body.invoiceId ?? null,
      purchaseInstructionId: body.purchaseInstructionId ?? null,
      requestLinesHash: null,
    };
    const requestLines = parseRequestLines(body.lines);
    intent.requestLinesHash = requestLines ? linesHash(requestLines) : null;
    const fingerprint = transactionFingerprint(intent);

    const prior = await this.findByIdempotencyKey(agent.agentId, body.idempotencyKey);
    if (prior) return this.replay(prior, fingerprint);

    let row: Authorization;
    try {
      row = await this.prisma.tx(async (tx) => {
        const now = new Date();
        const loaded = await this.facts.load(tx, intent, { now, excludeAuthorizationId: null, humanApprovalGranted: false, requestLines });
        const result = evaluatePurchase(loaded.facts);
        return this.persistDecision(tx, agent, body.idempotencyKey, intent, fingerprint, loaded, result, now);
      });
    } catch (e) {
      if (e instanceof Prisma.PrismaClientKnownRequestError && e.code === 'P2002') {
        const raced = await this.findByIdempotencyKey(agent.agentId, body.idempotencyKey);
        if (raced) return this.replay(raced, fingerprint);
      }
      throw e;
    }

    if (row.decision === 'DENY') await this.security.recordDenial(agent.organizationId, agent.agentId, row.id, row.reasonCodes);
    return toView(row, { includeToken: true });
  }

  private async persistDecision(
    tx: Tx,
    agent: AgentPrincipal,
    idempotencyKey: string,
    intent: TransactionIntent,
    fingerprint: string,
    loaded: LoadedFacts,
    result: PolicyResult,
    now: Date,
  ): Promise<Authorization> {
    const id = newId(IdPrefix.authorization);
    const rules = loaded.rules;
    const ttl = result.decision === 'ALLOW' ? rules!.authorizationTtlSeconds : result.decision === 'REVIEW' ? rules!.reviewTtlSeconds : 0;
    const expiresAt = new Date(now.getTime() + ttl * 1000);

    let token: string | null = null;
    let tokenNonce: string | null = null;
    let binding: AuthorizationBinding | null = null;
    const paidLines = toPaymentLines(result.paymentLines);
    if (result.decision === 'ALLOW') {
      binding = buildBinding(intent, loaded.supplier, loaded.policy, loaded.delegation, loaded.instruction, paidLines);
      if (!binding) throw new Error('invariant: ALLOW without a complete payment binding');
      ({ token, tokenNonce } = this.issueToken(id, binding, agent.sessionId, now, expiresAt));
    }

    const row = await tx.authorization.create({
      data: {
        id,
        organizationId: intent.organizationId,
        agentId: intent.agentId,
        credentialId: agent.credentialId,
        sessionId: agent.sessionId,
        delegationId: loaded.delegation?.id ?? null,
        policyId: loaded.policy?.id ?? null,
        policyVersion: loaded.policy?.version ?? null,
        idempotencyKey,
        transactionFingerprint: fingerprint,
        authorizationFingerprint: binding ? authorizationFingerprint(binding) : null,
        action: intent.action,
        supplierId: intent.supplierId,
        supplierVersion: loaded.supplier?.version ?? null,
        paymentRail: binding?.paymentRail ?? null,
        destinationRef: binding?.destinationRef ?? null,
        paymentDestinationFingerprint: intent.paymentDestinationFingerprint,
        amountCents: BigInt(intent.amountCents),
        currency: intent.currency,
        purchaseOrderId: intent.purchaseOrderId,
        invoiceId: intent.invoiceId,
        instructionId: intent.purchaseInstructionId,
        instructionVersion: loaded.instruction?.version ?? null,
        lines: paidLines ? (paidLines as unknown as Prisma.InputJsonArray) : Prisma.JsonNull,
        linesHash: paidLines ? linesHash(paidLines) : null,
        initialDecision: result.decision,
        decision: result.decision,
        status: STATUS_FOR[result.decision],
        reasonCodes: result.reasonCodes,
        checks: result.checks as unknown as Prisma.InputJsonArray,
        approvable: result.approvable,
        token,
        tokenNonce,
        expiresAt,
      },
    });

    // Hold budget, PO capacity and the invoice while the authorization is live.
    const holds = result.decision === 'ALLOW' || (result.decision === 'REVIEW' && result.approvable);
    if (holds && loaded.delegation) {
      await tx.budgetReservation.create({
        data: {
          id: newId(IdPrefix.reservation),
          organizationId: intent.organizationId,
          authorizationId: id,
          agentId: intent.agentId,
          delegationId: loaded.delegation.id,
          purchaseOrderId: intent.purchaseOrderId,
          invoiceId: intent.invoiceId,
          instructionId: loaded.instruction ? intent.purchaseInstructionId : null,
          lines: paidLines ? (paidLines.map((l) => ({ instructionLineNumber: l.instructionLineNumber, quantityMilli: l.quantityMilli })) as Prisma.InputJsonArray) : Prisma.JsonNull,
          amountCents: BigInt(intent.amountCents),
          currency: intent.currency,
          status: 'active',
          expiresAt,
        },
      });
    }

    await this.audit.append(tx, {
      organizationId: intent.organizationId,
      actorType: 'agent',
      actorId: intent.agentId,
      eventType: { ALLOW: 'authorization.allowed', REVIEW: 'authorization.review', DENY: 'authorization.denied' }[result.decision],
      subjectId: id,
      payload: decisionPayload(intent, fingerprint, result, loaded.delegation?.id ?? null, expiresAt, binding),
    });
    return row;
  }

  private issueToken(id: string, binding: AuthorizationBinding, sessionId: string | null, now: Date, expiresAt: Date) {
    const tokenNonce = randomBytes(16).toString('hex');
    const claims = claimsFromBinding(binding, {
      id,
      sessionId,
      iat: Math.floor(now.getTime() / 1000),
      exp: Math.floor(expiresAt.getTime() / 1000),
      nonce: tokenNonce,
    });
    return { token: signAuthorizationToken(claims, this.crypto.signer), tokenNonce };
  }

  async getForAgent(agent: AgentPrincipal, id: string) {
    const row = await this.prisma.authorization.findFirst({ where: { id, organizationId: agent.organizationId, agentId: agent.agentId } });
    if (!row) throw Errors.notFound('Authorization');
    return toView(row, { includeToken: true });
  }

  async getForUser(user: HumanPrincipal, id: string) {
    const row = await this.prisma.authorization.findFirst({ where: { id, organizationId: user.organizationId } });
    if (!row) throw Errors.notFound('Authorization');
    return toView(row, { includeToken: false });
  }

  async list(user: HumanPrincipal, status?: Authorization['status']) {
    const rows = await this.prisma.authorization.findMany({
      where: { organizationId: user.organizationId, ...(status ? { status } : {}) },
      orderBy: { createdAt: 'desc' },
      take: 200,
    });
    return { authorizations: rows.map((r) => toView(r, { includeToken: false })) };
  }

  /**
   * A human approver resolves a REVIEW. The approver is authenticated
   * server-side (fresh login required) and must personally hold enough
   * spending authority. The policy is re-evaluated against CURRENT facts
   * with the approval applied, so an approval can never override a DENY
   * and cannot bypass supplier/payee verification.
   */
  async approve(user: HumanPrincipal, id: string, comment?: string) {
    return this.prisma.tx(async (tx) => {
      const auth = await this.lockForReview(tx, user, id);
      if (cents(auth.amountCents) > user.spendingAuthorityCents) {
        throw Errors.forbidden('INSUFFICIENT_AUTHORITY', 'Amount exceeds your approval authority');
      }
      if (!auth.approvable) {
        throw Errors.conflict('NOT_APPROVABLE', 'This review cannot be resolved by approval (e.g. unknown or unverified supplier). Verify the supplier, then have the agent resubmit.', { reasonCodes: auth.reasonCodes });
      }

      const now = new Date();
      const intent = intentFromRow(auth);
      const requestLines = intentLinesFromRow(auth);
      const loaded = await this.facts.load(tx, intent, { now, excludeAuthorizationId: auth.id, humanApprovalGranted: true, requestLines });
      const result = evaluatePurchase(loaded.facts);

      if (result.decision === 'REVIEW') {
        throw Errors.conflict('NOT_APPROVABLE', 'Remaining checks require supplier verification', { reasonCodes: result.reasonCodes });
      }

      if (result.decision === 'DENY') {
        const updated = await tx.authorization.update({
          where: { id: auth.id },
          data: {
            decision: 'DENY', status: 'denied', reasonCodes: result.reasonCodes,
            checks: result.checks as unknown as Prisma.InputJsonArray, expiresAt: now,
            policyId: loaded.policy?.id ?? null, policyVersion: loaded.policy?.version ?? null,
          },
        });
        await tx.budgetReservation.updateMany({ where: { authorizationId: auth.id, status: 'active' }, data: { status: 'released' } });
        await this.audit.append(tx, {
          organizationId: user.organizationId, actorType: 'user', actorId: user.userId,
          eventType: 'authorization.denied_on_review', subjectId: auth.id,
          payload: { reasonCodes: result.reasonCodes, transactionFingerprint: auth.transactionFingerprint },
        });
        return toView(updated, { includeToken: false });
      }

      const expiresAt = new Date(now.getTime() + loaded.rules!.authorizationTtlSeconds * 1000);
      // Bind to the CURRENT supplier version, policy version, delegation and instruction version.
      const paidLines = toPaymentLines(result.paymentLines);
      const binding = buildBinding(intent, loaded.supplier, loaded.policy, loaded.delegation, loaded.instruction, paidLines);
      if (!binding) throw new Error('invariant: ALLOW without a complete payment binding');
      const { token, tokenNonce } = this.issueToken(auth.id, binding, auth.sessionId, now, expiresAt);
      const updated = await tx.authorization.update({
        where: { id: auth.id },
        data: {
          decision: 'ALLOW', status: 'allowed', reasonCodes: result.reasonCodes,
          checks: result.checks as unknown as Prisma.InputJsonArray, approvable: false,
          token, tokenNonce, expiresAt,
          authorizationFingerprint: authorizationFingerprint(binding),
          supplierVersion: binding.supplierVersion, paymentRail: binding.paymentRail, destinationRef: binding.destinationRef,
          instructionVersion: binding.instructionVersion, linesHash: binding.linesHash, lines: paidLines as unknown as Prisma.InputJsonArray,
          delegationId: binding.delegationId, policyId: binding.policyId, policyVersion: binding.policyVersion,
        },
      });
      const heldLines = paidLines!.map((l) => ({ instructionLineNumber: l.instructionLineNumber, quantityMilli: l.quantityMilli })) as Prisma.InputJsonArray;
      await tx.budgetReservation.upsert({
        where: { authorizationId: auth.id },
        update: { status: 'active', expiresAt, instructionId: binding.instructionId, lines: heldLines },
        create: {
          id: newId(IdPrefix.reservation), organizationId: user.organizationId, authorizationId: auth.id,
          agentId: auth.agentId, delegationId: loaded.delegation!.id, purchaseOrderId: auth.purchaseOrderId,
          invoiceId: auth.invoiceId, instructionId: binding.instructionId, lines: heldLines,
          amountCents: auth.amountCents, currency: auth.currency, status: 'active', expiresAt,
        },
      });
      await tx.approval.create({
        data: {
          id: newId(IdPrefix.approval), organizationId: user.organizationId, authorizationId: auth.id,
          approverUserId: user.userId, decision: 'approved', transactionFingerprint: auth.transactionFingerprint,
          policyVersion: loaded.policy!.version, comment,
        },
      });
      await this.audit.append(tx, {
        organizationId: user.organizationId, actorType: 'user', actorId: user.userId,
        eventType: 'authorization.approved', subjectId: auth.id,
        payload: { transactionFingerprint: auth.transactionFingerprint, policyVersion: loaded.policy!.version, amountCents: cents(auth.amountCents), comment: comment ?? null },
      });
      return toView(updated, { includeToken: false });
    });
  }

  async reject(user: HumanPrincipal, id: string, comment?: string) {
    return this.prisma.tx(async (tx) => {
      const auth = await this.lockForReview(tx, user, id);
      const updated = await tx.authorization.update({ where: { id: auth.id }, data: { status: 'rejected', decision: 'DENY', expiresAt: new Date() } });
      await tx.budgetReservation.updateMany({ where: { authorizationId: auth.id, status: 'active' }, data: { status: 'released' } });
      await tx.approval.create({
        data: {
          id: newId(IdPrefix.approval), organizationId: user.organizationId, authorizationId: auth.id,
          approverUserId: user.userId, decision: 'rejected', transactionFingerprint: auth.transactionFingerprint,
          policyVersion: auth.policyVersion, comment,
        },
      });
      await this.audit.append(tx, {
        organizationId: user.organizationId, actorType: 'user', actorId: user.userId,
        eventType: 'authorization.rejected', subjectId: auth.id,
        payload: { transactionFingerprint: auth.transactionFingerprint, comment: comment ?? null },
      });
      return toView(updated, { includeToken: false });
    });
  }

  private async lockForReview(tx: Tx, user: HumanPrincipal, id: string): Promise<Authorization> {
    const locked = await tx.$queryRaw<{ id: string }[]>`
      SELECT id FROM "Authorization" WHERE id = ${id} AND "organizationId" = ${user.organizationId} FOR UPDATE`;
    if (locked.length !== 1) throw Errors.notFound('Authorization');
    const auth = (await tx.authorization.findUnique({ where: { id } }))!;
    if (auth.status !== 'pending_review') throw Errors.conflict('NOT_PENDING_REVIEW', `Authorization is ${auth.status}`);
    if (auth.expiresAt <= new Date()) throw Errors.conflict('REVIEW_EXPIRED', 'Review window has expired; the agent must resubmit');
    return auth;
  }

  private findByIdempotencyKey(agentId: string, idempotencyKey: string) {
    return this.prisma.authorization.findUnique({ where: { agentId_idempotencyKey: { agentId, idempotencyKey } } });
  }

  private replay(prior: Authorization, fingerprint: string) {
    if (prior.transactionFingerprint !== fingerprint) {
      throw Errors.conflict('IDEMPOTENCY_CONFLICT', 'This idempotency key was already used for a different transaction', { authorizationId: prior.id });
    }
    return toView(prior, { includeToken: true });
  }
}

export function intentFromRow(a: Authorization): TransactionIntent {
  return {
    organizationId: a.organizationId,
    agentId: a.agentId,
    action: 'purchase',
    supplierId: a.supplierId,
    paymentDestinationFingerprint: a.paymentDestinationFingerprint,
    amountCents: cents(a.amountCents),
    currency: a.currency,
    purchaseOrderId: a.purchaseOrderId,
    invoiceId: a.invoiceId,
    purchaseInstructionId: a.instructionId,
    requestLinesHash: null,
  };
}

/** Lines the agent originally supplied (stored on the authorization), for re-evaluation at approval time. */
function intentLinesFromRow(a: Authorization): PaymentLine[] | null {
  return (a.lines as PaymentLine[] | null) ?? null;
}

function decisionPayload(
  intent: TransactionIntent,
  fingerprint: string,
  result: PolicyResult,
  delegationId: string | null,
  expiresAt: Date,
  binding: AuthorizationBinding | null,
) {
  return {
    decision: result.decision,
    reasonCodes: result.reasonCodes,
    amountCents: intent.amountCents,
    currency: intent.currency,
    supplierId: intent.supplierId,
    purchaseOrderId: intent.purchaseOrderId,
    invoiceId: intent.invoiceId,
    paymentDestinationFingerprint: intent.paymentDestinationFingerprint,
    transactionFingerprint: fingerprint,
    authorizationFingerprint: binding ? authorizationFingerprint(binding) : null,
    supplierVersion: binding?.supplierVersion ?? null,
    paymentRail: binding?.paymentRail ?? null,
    destinationRef: binding?.destinationRef ?? null,
    policyId: result.policyId,
    policyVersion: result.policyVersion,
    delegationId,
    expiresAt: expiresAt.toISOString(),
  };
}

export function toView(a: Authorization, opts: { includeToken: boolean }) {
  const live = a.status === 'allowed' || a.status === 'pending_review';
  const status = live && a.expiresAt <= new Date() ? 'expired' : a.status;
  return {
    id: a.id,
    agentId: a.agentId,
    decision: a.decision,
    initialDecision: a.initialDecision,
    status,
    reasonCodes: a.reasonCodes,
    checks: a.checks,
    approvable: a.approvable,
    policyVersion: a.policyVersion,
    transactionFingerprint: a.transactionFingerprint,
    authorizationFingerprint: a.authorizationFingerprint,
    supplierVersion: a.supplierVersion,
    paymentRail: a.paymentRail,
    amountCents: cents(a.amountCents),
    currency: a.currency,
    supplierId: a.supplierId,
    purchaseOrderId: a.purchaseOrderId,
    invoiceId: a.invoiceId,
    purchaseInstructionId: a.instructionId,
    instructionVersion: a.instructionVersion,
    lines: a.lines,
    expiresAt: a.expiresAt.toISOString(),
    consumedAt: a.consumedAt?.toISOString() ?? null,
    invalidatedReason: a.invalidatedReason,
    createdAt: a.createdAt.toISOString(),
    ...(opts.includeToken && status === 'allowed' && a.token ? { token: a.token } : {}),
  };
}
