import { Injectable } from '@nestjs/common';
import type { Agent, Delegation, Invoice, InvoiceLine, Policy, PurchaseInstruction, PurchaseInstructionLine, PurchaseOrder, Supplier } from '@prisma/client';
import type { PaymentLineFacts, PolicyFacts, PolicyRules } from '@agenttrust/policy-engine';
import type { PaymentLine, TransactionIntent } from '@agenttrust/shared';
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
  invoice: (Invoice & { lines: InvoiceLine[] }) | null;
  instruction: (PurchaseInstruction & { lines: PurchaseInstructionLine[] }) | null;
}

type HeldLine = { instructionLineNumber: number; quantityMilli: number };

/**
 * Loads every fact the policy engine needs from trusted database records,
 * inside the caller's transaction, taking row locks in the global order
 * (Agent -> PurchaseInstruction -> PurchaseOrder -> Invoice). Nothing here comes from agent claims
 * except the IDs it references, and every lookup is scoped to the
 * authenticated organization.
 */
@Injectable()
export class FactsLoader {
  async load(
    tx: Tx,
    intent: TransactionIntent,
    opts: { now: Date; excludeAuthorizationId: string | null; humanApprovalGranted: boolean; requestLines: PaymentLine[] | null },
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

    // 4b. Purchase instruction (locked: its uses/amount/line quantities are a shared ledger).
    let instruction: LoadedFacts['instruction'] = null;
    const instructionUsage = { uses: 0, amountCents: 0, quantityMilliByLine: {} as Record<number, number> };
    let receipts: PolicyFacts['receipts'] = [];
    if (intent.purchaseInstructionId) {
      const locked = await tx.$queryRaw<{ id: string }[]>`
        SELECT id FROM "PurchaseInstruction" WHERE id = ${intent.purchaseInstructionId} AND "organizationId" = ${orgId} FOR UPDATE`;
      if (locked.length === 1) {
        instruction = await tx.purchaseInstruction.findUnique({ where: { id: intent.purchaseInstructionId }, include: { lines: true } });
        const held = await tx.budgetReservation.findMany({
          where: { instructionId: intent.purchaseInstructionId, ...live, ...notSelf },
          select: { amountCents: true, lines: true },
        });
        for (const h of held) {
          instructionUsage.uses += 1;
          instructionUsage.amountCents += cents(h.amountCents);
          for (const l of (h.lines as HeldLine[] | null) ?? []) {
            instructionUsage.quantityMilliByLine[l.instructionLineNumber] = (instructionUsage.quantityMilliByLine[l.instructionLineNumber] ?? 0) + l.quantityMilli;
          }
        }
        const rows = await tx.receipt.findMany({ where: { instructionId: intent.purchaseInstructionId, voidedAt: null } });
        receipts = rows.map((r) => ({ type: r.type, lines: r.lines as HeldLine[] }));
      }
    }

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
    let invoice: LoadedFacts['invoice'] = null;
    let invoiceInFlight = false;
    if (intent.invoiceId) {
      const locked = await tx.$queryRaw<{ id: string }[]>`
        SELECT id FROM "Invoice" WHERE id = ${intent.invoiceId} AND "organizationId" = ${orgId} FOR UPDATE`;
      if (locked.length === 1) {
        invoice = await tx.invoice.findUnique({ where: { id: intent.invoiceId }, include: { lines: true } });
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

    // 8. Velocity / pattern facts for valid-session abuse checks (all under the agent lock).
    const hourAgo = new Date(now.getTime() - 3_600_000);
    const dayAgo = new Date(now.getTime() - 86_400_000);
    const notSelfAuth = exclude ? { id: { not: exclude } } : {};
    const authorizationsLastHour = await tx.authorization.count({
      where: { agentId, organizationId: orgId, createdAt: { gte: hourAgo }, initialDecision: { in: ['ALLOW', 'REVIEW'] }, ...notSelfAuth },
    });
    const spendHour = await tx.budgetReservation.aggregate({
      _sum: { amountCents: true },
      where: { agentId, organizationId: orgId, createdAt: { gte: hourAgo }, ...live, ...notSelf },
    });
    const supplierPurchasesLast24h = intent.supplierId
      ? await tx.authorization.count({
          where: { agentId, organizationId: orgId, supplierId: intent.supplierId, createdAt: { gte: dayAgo }, initialDecision: { in: ['ALLOW', 'REVIEW'] }, ...notSelfAuth },
        })
      : 0;
    const payeeChange = supplier
      ? await tx.supplierVersion.findFirst({
          where: { supplierId: supplier.id, changeType: 'payment_destination_changed' },
          orderBy: { createdAt: 'desc' },
          select: { createdAt: true },
        })
      : null;

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
        agentId: intent.agentId,
        purchaseInstructionId: intent.purchaseInstructionId,
        lines: opts.requestLines,
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
            assuranceLevel: supplier.assuranceLevel,
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
            instructionId: invoice.instructionId,
            lines: invoice.lines.map(toLineFacts),
          }
        : null,
      instruction: instruction
        ? {
            id: instruction.id,
            version: instruction.version,
            status: instruction.status,
            agentId: instruction.agentId,
            supplierId: instruction.supplierId,
            purchaseOrderId: instruction.purchaseOrderId,
            fulfillmentType: instruction.fulfillmentType,
            currency: instruction.currency,
            maxAmountCents: cents(instruction.maxAmountCents),
            maxUses: instruction.maxUses,
            validFrom: instruction.validFrom,
            expiresAt: instruction.expiresAt,
            lines: instruction.lines.map((l) => ({
              lineNumber: l.lineNumber, sku: l.sku, quantityMilli: cents(l.quantityMilli), unitPriceCents: cents(l.unitPriceCents),
            })),
          }
        : null,
      instructionUsage,
      receipts,
      invoiceInFlight,
      budget: { spentThisPeriodCents: cents(spentAgg._sum.amountCents ?? 0n) },
      humanApprovalGranted: opts.humanApprovalGranted,
      velocity: {
        authorizationsLastHour,
        spendLastHourCents: cents(spendHour._sum.amountCents ?? 0n),
        supplierPurchasesLast24h,
        supplierPayeeChangedAt: payeeChange?.createdAt ?? null,
      },
    };

    return { facts, agent, delegation, policy, rules, supplier, purchaseOrder, invoice, instruction };
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

function toLineFacts(l: InvoiceLine): PaymentLineFacts {
  return {
    instructionLineNumber: l.instructionLineNumber,
    sku: l.sku,
    quantityMilli: cents(l.quantityMilli),
    unitPriceCents: cents(l.unitPriceCents),
    lineTotalCents: cents(l.lineTotalCents),
  };
}
