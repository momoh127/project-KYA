import { Injectable } from '@nestjs/common';
import type { Agent, Delegation, Invoice, Policy, PurchaseOrder, Supplier } from '@prisma/client';
import type { PolicyFacts, PolicyRules } from '@agenttrust/policy-engine';
import type { TransactionIntent } from '@agenttrust/shared';
import { cents, type Tx } from '../common/prisma.service';
import { parseStoredRules } from '../policies/policies.controller';

export interface LoadedFacts {
  facts: PolicyFacts;
  agent: Pick<Agent, 'id' | 'status'> | null;
  delegation: Delegation | null;
  policy: Policy | null;
  rules: PolicyRules | null;
  supplier: Supplier | null;
  purchaseOrder: PurchaseOrder | null;
  invoice: Invoice | null;
}

/**
 * Loads every fact the policy engine needs from trusted database records,
 * inside the caller's transaction, taking row locks in the global order
 * (Agent -> PurchaseOrder -> Invoice). Nothing here comes from agent claims
 * except the IDs it references, and every lookup is scoped to the
 * authenticated organization.
 */
@Injectable()
export class FactsLoader {
  async load(
    tx: Tx,
    intent: TransactionIntent,
    opts: { now: Date; excludeAuthorizationId: string | null; humanApprovalGranted: boolean },
  ): Promise<LoadedFacts> {
    const { organizationId: orgId, agentId } = intent;
    const { now } = opts;
    const exclude = opts.excludeAuthorizationId;

    // 1. Agent row lock: serializes all spending decisions for this agent.
    const agentRows = await tx.$queryRaw<{ id: string; status: Agent['status'] }[]>`
      SELECT id, status FROM "Agent" WHERE id = ${agentId} AND "organizationId" = ${orgId} FOR UPDATE`;
    const agent = agentRows[0] ?? null;

    // 2. Effective delegation = most recent grant (new grants supersede old ones).
    const delegation = await tx.delegation.findFirst({
      where: { agentId, organizationId: orgId },
      orderBy: { createdAt: 'desc' },
    });

    // 3. Active policy version. Unparseable rules => no policy => fail closed.
    const policy = await tx.policy.findFirst({ where: { organizationId: orgId, status: 'active' } });
    const rules = policy ? parseStoredRules(policy.rules) : null;

    // 4. Supplier (trusted payee record).
    const supplier = intent.supplierId
      ? await tx.supplier.findFirst({ where: { id: intent.supplierId, organizationId: orgId } })
      : null;

    const live = { OR: [{ status: 'consumed' as const }, { status: 'active' as const, expiresAt: { gt: now } }] };
    const notSelf = exclude ? { authorizationId: { not: exclude } } : {};

    // 5. Purchase order (locked: capacity is shared across agents).
    let purchaseOrder: PurchaseOrder | null = null;
    let poCommitted = 0;
    if (intent.purchaseOrderId) {
      const locked = await tx.$queryRaw<{ id: string }[]>`
        SELECT id FROM "PurchaseOrder" WHERE id = ${intent.purchaseOrderId} AND "organizationId" = ${orgId} FOR UPDATE`;
      if (locked.length === 1) {
        purchaseOrder = await tx.purchaseOrder.findUnique({ where: { id: intent.purchaseOrderId } });
        const agg = await tx.budgetReservation.aggregate({
          _sum: { amountCents: true },
          where: { purchaseOrderId: intent.purchaseOrderId, ...live, ...notSelf },
        });
        poCommitted = cents(agg._sum.amountCents ?? 0n);
      }
    }

    // 6. Invoice (locked: duplicate-payment protection).
    let invoice: Invoice | null = null;
    let invoiceInFlight = false;
    if (intent.invoiceId) {
      const locked = await tx.$queryRaw<{ id: string }[]>`
        SELECT id FROM "Invoice" WHERE id = ${intent.invoiceId} AND "organizationId" = ${orgId} FOR UPDATE`;
      if (locked.length === 1) {
        invoice = await tx.invoice.findUnique({ where: { id: intent.invoiceId } });
        await this.releaseExpiredHolds(tx, intent.invoiceId, now);
        const holders = await tx.budgetReservation.count({
          where: { invoiceId: intent.invoiceId, status: 'active', expiresAt: { gt: now }, ...notSelf },
        });
        invoiceInFlight = holders > 0;
      }
    }

    // 7. Monthly spend for this agent (all delegations, so re-delegating cannot reset the budget).
    const monthStart = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1));
    const spentAgg = await tx.budgetReservation.aggregate({
      _sum: { amountCents: true },
      where: { agentId, organizationId: orgId, createdAt: { gte: monthStart }, ...live, ...notSelf },
    });

    const facts: PolicyFacts = {
      now,
      policy: policy && rules ? { id: policy.id, version: policy.version, rules } : null,
      agent: agent ? { id: agent.id, status: agent.status } : null,
      delegation: delegation
        ? {
            id: delegation.id,
            actions: delegation.actions,
            maxTransactionCents: cents(delegation.maxTransactionCents),
            monthlyLimitCents: cents(delegation.monthlyLimitCents),
            currency: delegation.currency,
            approvedSupplierIds: delegation.restrictSuppliers ? delegation.approvedSupplierIds : null,
            validFrom: delegation.validFrom,
            expiresAt: delegation.expiresAt,
            revokedAt: delegation.revokedAt,
          }
        : null,
      request: {
        action: intent.action,
        supplierId: intent.supplierId,
        amountCents: intent.amountCents,
        currency: intent.currency,
        paymentDestinationFingerprint: intent.paymentDestinationFingerprint,
        purchaseOrderId: intent.purchaseOrderId,
        invoiceId: intent.invoiceId,
      },
      supplier: supplier
        ? {
            id: supplier.id,
            status: supplier.status,
            verificationStatus: supplier.verificationStatus,
            paymentDestinationFingerprint: supplier.paymentDestinationFingerprint,
          }
        : null,
      purchaseOrder: purchaseOrder
        ? {
            id: purchaseOrder.id,
            supplierId: purchaseOrder.supplierId,
            approvedAmountCents: cents(purchaseOrder.approvedAmountCents),
            committedAmountCents: poCommitted,
            currency: purchaseOrder.currency,
            status: purchaseOrder.status,
          }
        : null,
      invoice: invoice
        ? {
            id: invoice.id,
            supplierId: invoice.supplierId,
            purchaseOrderId: invoice.purchaseOrderId,
            amountCents: cents(invoice.amountCents),
            currency: invoice.currency,
            status: invoice.status,
          }
        : null,
      invoiceInFlight,
      budget: { spentThisPeriodCents: cents(spentAgg._sum.amountCents ?? 0n) },
      humanApprovalGranted: opts.humanApprovalGranted,
    };

    return { facts, agent, delegation, policy, rules, supplier, purchaseOrder, invoice };
  }

  /** Lazily expires stale holds on an invoice (caller holds the invoice lock). */
  private async releaseExpiredHolds(tx: Tx, invoiceId: string, now: Date): Promise<void> {
    const stale = await tx.budgetReservation.findMany({
      where: { invoiceId, status: 'active', expiresAt: { lte: now } },
      select: { id: true, authorizationId: true },
    });
    if (stale.length === 0) return;
    await tx.budgetReservation.updateMany({ where: { id: { in: stale.map((s) => s.id) } }, data: { status: 'released' } });
    await tx.authorization.updateMany({
      where: { id: { in: stale.map((s) => s.authorizationId) }, status: { in: ['allowed', 'pending_review'] } },
      data: { status: 'expired' },
    });
  }
}
