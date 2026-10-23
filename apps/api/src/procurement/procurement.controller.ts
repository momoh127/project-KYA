import { Body, Controller, Get, Param, Post } from '@nestjs/common';
import { z } from 'zod';
import type { Invoice, InvoiceLine } from '@prisma/client';
import { exactLineTotal, formatQuantity, IdPrefix, newId, parseQuantity } from '@agenttrust/shared';
import { CurrentPrincipal, CurrentUser, Human, HumanOrIntegration, type HumanPrincipal, type Principal } from '../auth/principal';
import { AuditService } from '../audit/audit.service';
import { Errors } from '../common/errors';
import { cents, PrismaService } from '../common/prisma.service';
import { zCents, zCurrency, ZodPipe, zId } from '../common/validation';

const CreatePo = z
  .object({
    supplierId: zId('sup'),
    externalReference: z.string().min(1).max(100),
    approvedAmountCents: zCents,
    currency: zCurrency,
  })
  .strict();

const CreateInvoice = z
  .object({
    supplierId: zId('sup'),
    purchaseOrderId: zId('po').optional(),
    /** The purchase instruction this invoice bills against. */
    purchaseInstructionId: zId('pin').optional(),
    invoiceNumber: z.string().min(1).max(100),
    amountCents: zCents,
    currency: zCurrency,
    /** SHA-256 of the invoice document, for evidence. */
    documentHash: z.string().regex(/^[a-f0-9]{64}$/).optional(),
    /** Trusted line items as recorded by AP / the ERP; must sum exactly to amountCents. */
    lines: z
      .array(
        z
          .object({
            lineNumber: z.number().int().min(1).max(999),
            instructionLineNumber: z.number().int().min(1).max(999).optional(),
            sku: z.string().min(1).max(100).optional(),
            description: z.string().min(1).max(500),
            quantity: z.string().min(1).max(20),
            unitPriceCents: z.number().int().min(0).max(100_000_000_000),
          })
          .strict(),
      )
      .max(200)
      .optional(),
  })
  .strict();

/**
 * Purchase orders and invoices are business records created by humans or by
 * an ERP integration acting on their behalf, never by the agent being
 * governed. In production these typically sync from NetSuite/SAP/Coupa.
 */
@Controller('v1')
export class ProcurementController {
  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
  ) {}

  @Post('purchase-orders')
  @Human('admin', 'approver')
  async createPo(@CurrentUser() user: HumanPrincipal, @Body(new ZodPipe(CreatePo)) body: z.infer<typeof CreatePo>) {
    if (body.approvedAmountCents > user.spendingAuthorityCents) {
      throw Errors.forbidden('INSUFFICIENT_AUTHORITY', 'PO amount exceeds your approval authority');
    }
    const supplier = await this.prisma.supplier.findFirst({ where: { id: body.supplierId, organizationId: user.organizationId } });
    if (!supplier) throw Errors.invalid('supplierId must be a supplier in your organization');
    const id = newId(IdPrefix.purchaseOrder);
    return this.prisma.tx(async (tx) => {
      const po = await tx.purchaseOrder.create({
        data: {
          id,
          organizationId: user.organizationId,
          supplierId: supplier.id,
          externalReference: body.externalReference,
          approvedAmountCents: BigInt(body.approvedAmountCents),
          currency: body.currency,
          approvedByUserId: user.userId,
        },
      });
      await this.audit.append(tx, {
        organizationId: user.organizationId,
        actorType: 'user',
        actorId: user.userId,
        eventType: 'purchase_order.approved',
        subjectId: id,
        payload: { supplierId: supplier.id, externalReference: body.externalReference, approvedAmountCents: body.approvedAmountCents, currency: body.currency },
      });
      return serializePo(po);
    });
  }

  @Get('purchase-orders/:id')
  @Human()
  async getPo(@CurrentUser() user: HumanPrincipal, @Param('id') id: string) {
    const po = await this.prisma.purchaseOrder.findFirst({ where: { id, organizationId: user.organizationId } });
    if (!po) throw Errors.notFound('Purchase order');
    return serializePo(po);
  }

  @Post('invoices')
  @HumanOrIntegration(['admin', 'approver', 'member'], 'invoices:write')
  async createInvoice(@CurrentPrincipal() p: Principal, @Body(new ZodPipe(CreateInvoice)) body: z.infer<typeof CreateInvoice>) {
    if (p.kind === 'agent') throw Errors.forbidden('FORBIDDEN', 'Agents cannot record invoices');
    const orgId = p.organizationId;
    const supplier = await this.prisma.supplier.findFirst({ where: { id: body.supplierId, organizationId: orgId } });
    if (!supplier) throw Errors.invalid('supplierId must be a supplier in your organization');
    if (body.purchaseOrderId) {
      const po = await this.prisma.purchaseOrder.findFirst({ where: { id: body.purchaseOrderId, organizationId: orgId } });
      if (!po) throw Errors.invalid('purchaseOrderId must be a purchase order in your organization');
      if (po.currency !== body.currency) throw Errors.invalid('Purchase order currency differs; currencies are never converted');
    }
    if (body.purchaseInstructionId) {
      const ins = await this.prisma.purchaseInstruction.findFirst({ where: { id: body.purchaseInstructionId, organizationId: orgId } });
      if (!ins) throw Errors.invalid('purchaseInstructionId must be an instruction in your organization');
      if (ins.supplierId !== body.supplierId) throw Errors.invalid('Instruction is for a different supplier');
      if (ins.currency !== body.currency) throw Errors.invalid('Instruction currency differs; currencies are never converted');
    }

    // Exact line arithmetic: every line total is quantity × unit price with no rounding, and lines sum to the amount.
    const seen = new Set<number>();
    const lines = (body.lines ?? []).map((l) => {
      if (seen.has(l.lineNumber)) throw Errors.invalid(`Duplicate invoice line ${l.lineNumber}`);
      seen.add(l.lineNumber);
      let quantityMilli: bigint;
      try {
        quantityMilli = parseQuantity(l.quantity);
      } catch (e) {
        throw Errors.invalid(`Line ${l.lineNumber}: ${e instanceof Error ? e.message : 'invalid quantity'}`);
      }
      const total = exactLineTotal(quantityMilli, BigInt(l.unitPriceCents));
      if (total === null) throw Errors.invalid(`Line ${l.lineNumber}: quantity × unit price is not an exact number of cents`);
      return { ...l, quantityMilli, lineTotalCents: total };
    });
    if (lines.length > 0) {
      const sum = lines.reduce((a, l) => a + l.lineTotalCents, 0n);
      if (sum !== BigInt(body.amountCents)) throw Errors.invalid('Invoice lines do not sum exactly to amountCents');
    }

    const existing = await this.prisma.invoice.findFirst({
      where: { organizationId: orgId, supplierId: supplier.id, invoiceNumber: body.invoiceNumber },
    });
    if (existing) {
      throw Errors.conflict('DUPLICATE_INVOICE', `Invoice ${body.invoiceNumber} from this supplier already exists`, { invoiceId: existing.id, status: existing.status });
    }
    const id = newId(IdPrefix.invoice);
    return this.prisma.tx(async (tx) => {
      await tx.invoice.create({
        data: {
          id,
          organizationId: orgId,
          supplierId: supplier.id,
          purchaseOrderId: body.purchaseOrderId,
          instructionId: body.purchaseInstructionId,
          invoiceNumber: body.invoiceNumber,
          amountCents: BigInt(body.amountCents),
          currency: body.currency,
          documentHash: body.documentHash,
          createdByUserId: p.kind === 'user' ? p.userId : null,
          createdByIntegrationId: p.kind === 'integration' ? p.integrationId : null,
        },
      });
      if (lines.length > 0) {
        await tx.invoiceLine.createMany({
          data: lines.map((l) => ({
            id: newId(IdPrefix.invoiceLine), invoiceId: id, lineNumber: l.lineNumber, instructionLineNumber: l.instructionLineNumber ?? null,
            sku: l.sku ?? null, description: l.description, quantityMilli: l.quantityMilli, unitPriceCents: BigInt(l.unitPriceCents), lineTotalCents: l.lineTotalCents,
          })),
        });
      }
      await this.audit.append(tx, {
        organizationId: orgId,
        actorType: p.kind === 'user' ? 'user' : 'integration',
        actorId: p.kind === 'user' ? p.userId : p.integrationId,
        eventType: 'invoice.recorded',
        subjectId: id,
        payload: {
          supplierId: supplier.id, purchaseOrderId: body.purchaseOrderId ?? null, purchaseInstructionId: body.purchaseInstructionId ?? null,
          invoiceNumber: body.invoiceNumber, amountCents: body.amountCents, documentHash: body.documentHash ?? null, lineCount: lines.length,
        },
      });
      return serializeInvoice((await tx.invoice.findUnique({ where: { id }, include: { lines: true } }))!);
    });
  }

  @Get('invoices/:id')
  @Human()
  async getInvoice(@CurrentUser() user: HumanPrincipal, @Param('id') id: string) {
    const inv = await this.prisma.invoice.findFirst({ where: { id, organizationId: user.organizationId }, include: { lines: true } });
    if (!inv) throw Errors.notFound('Invoice');
    return serializeInvoice(inv);
  }
}

export function serializePo(po: { id: string; organizationId: string; supplierId: string; externalReference: string; approvedAmountCents: bigint; currency: string; status: string; approvedByUserId: string; createdAt: Date }) {
  return { ...po, approvedAmountCents: cents(po.approvedAmountCents), createdAt: po.createdAt.toISOString() };
}

export function serializeInvoice(inv: Invoice & { lines: InvoiceLine[] }) {
  return {
    id: inv.id,
    organizationId: inv.organizationId,
    supplierId: inv.supplierId,
    purchaseOrderId: inv.purchaseOrderId,
    purchaseInstructionId: inv.instructionId,
    invoiceNumber: inv.invoiceNumber,
    amountCents: cents(inv.amountCents),
    currency: inv.currency,
    documentHash: inv.documentHash,
    status: inv.status,
    paidAt: inv.paidAt?.toISOString() ?? null,
    paidByTransactionId: inv.paidByTransactionId,
    createdByUserId: inv.createdByUserId,
    createdByIntegrationId: inv.createdByIntegrationId,
    createdAt: inv.createdAt.toISOString(),
    lines: [...inv.lines].sort((a, b) => a.lineNumber - b.lineNumber).map((l) => ({
      lineNumber: l.lineNumber, instructionLineNumber: l.instructionLineNumber, sku: l.sku, description: l.description,
      quantity: formatQuantity(l.quantityMilli), unitPriceCents: cents(l.unitPriceCents), lineTotalCents: cents(l.lineTotalCents),
    })),
  };
}
