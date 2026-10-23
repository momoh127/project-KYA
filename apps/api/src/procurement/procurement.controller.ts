import { Body, Controller, Get, Param, Post } from '@nestjs/common';
import { z } from 'zod';
import { IdPrefix, newId } from '@agenttrust/shared';
import { CurrentUser, Human, type HumanPrincipal } from '../auth/principal';
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
    invoiceNumber: z.string().min(1).max(100),
    amountCents: zCents,
    currency: zCurrency,
    /** SHA-256 of the invoice document, for evidence. */
    documentHash: z.string().regex(/^[a-f0-9]{64}$/).optional(),
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
  @Human('admin', 'approver', 'member')
  async createInvoice(@CurrentUser() user: HumanPrincipal, @Body(new ZodPipe(CreateInvoice)) body: z.infer<typeof CreateInvoice>) {
    const supplier = await this.prisma.supplier.findFirst({ where: { id: body.supplierId, organizationId: user.organizationId } });
    if (!supplier) throw Errors.invalid('supplierId must be a supplier in your organization');
    if (body.purchaseOrderId) {
      const po = await this.prisma.purchaseOrder.findFirst({ where: { id: body.purchaseOrderId, organizationId: user.organizationId } });
      if (!po) throw Errors.invalid('purchaseOrderId must be a purchase order in your organization');
    }
    const existing = await this.prisma.invoice.findFirst({
      where: { organizationId: user.organizationId, supplierId: supplier.id, invoiceNumber: body.invoiceNumber },
    });
    if (existing) {
      throw Errors.conflict('DUPLICATE_INVOICE', `Invoice ${body.invoiceNumber} from this supplier already exists`, { invoiceId: existing.id, status: existing.status });
    }
    const id = newId(IdPrefix.invoice);
    return this.prisma.tx(async (tx) => {
      const inv = await tx.invoice.create({
        data: {
          id,
          organizationId: user.organizationId,
          supplierId: supplier.id,
          purchaseOrderId: body.purchaseOrderId,
          invoiceNumber: body.invoiceNumber,
          amountCents: BigInt(body.amountCents),
          currency: body.currency,
          documentHash: body.documentHash,
          createdByUserId: user.userId,
        },
      });
      await this.audit.append(tx, {
        organizationId: user.organizationId,
        actorType: 'user',
        actorId: user.userId,
        eventType: 'invoice.recorded',
        subjectId: id,
        payload: { supplierId: supplier.id, purchaseOrderId: body.purchaseOrderId ?? null, invoiceNumber: body.invoiceNumber, amountCents: body.amountCents, documentHash: body.documentHash ?? null },
      });
      return serializeInvoice(inv);
    });
  }

  @Get('invoices/:id')
  @Human()
  async getInvoice(@CurrentUser() user: HumanPrincipal, @Param('id') id: string) {
    const inv = await this.prisma.invoice.findFirst({ where: { id, organizationId: user.organizationId } });
    if (!inv) throw Errors.notFound('Invoice');
    return serializeInvoice(inv);
  }
}

export function serializePo(po: { id: string; organizationId: string; supplierId: string; externalReference: string; approvedAmountCents: bigint; currency: string; status: string; approvedByUserId: string; createdAt: Date }) {
  return { ...po, approvedAmountCents: cents(po.approvedAmountCents), createdAt: po.createdAt.toISOString() };
}

export function serializeInvoice(inv: { id: string; organizationId: string; supplierId: string; purchaseOrderId: string | null; invoiceNumber: string; amountCents: bigint; currency: string; documentHash: string | null; status: string; paidAt: Date | null; paidByTransactionId: string | null; createdByUserId: string; createdAt: Date }) {
  return { ...inv, amountCents: cents(inv.amountCents), paidAt: inv.paidAt?.toISOString() ?? null, createdAt: inv.createdAt.toISOString() };
}
