import { Body, Controller, Get, Param, Post } from '@nestjs/common';
import { z } from 'zod';
import { formatQuantity, IdPrefix, newId, parseQuantity, toSafeNumber } from '@agenttrust/shared';
import { CurrentPrincipal, CurrentUser, Human, HumanOrIntegration, type HumanPrincipal, type Principal } from '../auth/principal';
import { AuditService } from '../audit/audit.service';
import { invalidateLiveAuthorizations, lockLiveAuthorizationsBy } from '../authorizations/invalidation';
import { Errors } from '../common/errors';
import { PrismaService } from '../common/prisma.service';
import { ZodPipe, zId } from '../common/validation';

export const RECEIPT_TYPE_FOR_FULFILLMENT = {
  physical_goods: 'goods_received',
  services: 'service_completed',
  subscription: 'subscription_activated',
  digital_goods: 'digital_delivered',
} as const;

const CreateReceipt = z
  .object({
    purchaseInstructionId: zId('pin'),
    type: z.enum(['goods_received', 'service_completed', 'subscription_activated', 'digital_delivered']),
    lines: z
      .array(z.object({ instructionLineNumber: z.number().int().min(1).max(999), quantity: z.string().min(1).max(20) }).strict())
      .min(1)
      .max(100),
    externalId: z.string().max(200).optional(),
    note: z.string().max(1000).optional(),
  })
  .strict();

const VoidBody = z.object({ reason: z.string().min(3).max(1000) }).strict();

type ReceiptLine = { instructionLineNumber: number; quantityMilli: number };

/**
 * Goods-received / service-completion / activation confirmations for
 * three-way matching. Recorded only by authorized humans or ERP integrations
 * with `receipts:confirm`, never by agents.
 */
@Controller('v1')
export class ReceiptsController {
  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
  ) {}

  @Post('receipts')
  @HumanOrIntegration(['admin', 'approver', 'member'], 'receipts:confirm')
  async create(@CurrentPrincipal() p: Principal, @Body(new ZodPipe(CreateReceipt)) body: z.infer<typeof CreateReceipt>) {
    if (p.kind === 'agent') throw Errors.forbidden('FORBIDDEN', 'Agents cannot confirm receipt');
    const orgId = p.organizationId;
    return this.prisma.tx(async (tx) => {
      const rows = await tx.$queryRaw<{ id: string }[]>`
        SELECT id FROM "PurchaseInstruction" WHERE id = ${body.purchaseInstructionId} AND "organizationId" = ${orgId} FOR UPDATE`;
      if (rows.length !== 1) throw Errors.invalid('purchaseInstructionId must be an instruction in your organization');
      const ins = (await tx.purchaseInstruction.findUnique({ where: { id: body.purchaseInstructionId }, include: { lines: true } }))!;
      if (RECEIPT_TYPE_FOR_FULFILLMENT[ins.fulfillmentType] !== body.type) {
        throw Errors.invalid(`A ${ins.fulfillmentType} instruction requires a ${RECEIPT_TYPE_FOR_FULFILLMENT[ins.fulfillmentType]} confirmation`);
      }
      const prior = await tx.receipt.findMany({ where: { instructionId: ins.id, voidedAt: null, type: body.type } });
      const received: Record<number, bigint> = {};
      for (const r of prior) for (const l of r.lines as ReceiptLine[]) received[l.instructionLineNumber] = (received[l.instructionLineNumber] ?? 0n) + BigInt(l.quantityMilli);

      const seen = new Set<number>();
      const lines: ReceiptLine[] = body.lines.map((l) => {
        if (seen.has(l.instructionLineNumber)) throw Errors.invalid(`Duplicate line ${l.instructionLineNumber}`);
        seen.add(l.instructionLineNumber);
        const approved = ins.lines.find((x) => x.lineNumber === l.instructionLineNumber);
        if (!approved) throw Errors.invalid(`Line ${l.instructionLineNumber} is not on the instruction`);
        let q: bigint;
        try {
          q = parseQuantity(l.quantity);
        } catch (e) {
          throw Errors.invalid(`Line ${l.instructionLineNumber}: ${e instanceof Error ? e.message : 'invalid quantity'}`);
        }
        if ((received[l.instructionLineNumber] ?? 0n) + q > approved.quantityMilli) {
          throw Errors.invalid(`Line ${l.instructionLineNumber}: confirmed quantity would exceed the ordered quantity`);
        }
        return { instructionLineNumber: l.instructionLineNumber, quantityMilli: toSafeNumber(q) };
      });

      const id = newId(IdPrefix.receipt);
      const receipt = await tx.receipt.create({
        data: {
          id, organizationId: orgId, instructionId: ins.id, type: body.type, lines, externalId: body.externalId, note: body.note,
          confirmedByUserId: p.kind === 'user' ? p.userId : null, integrationId: p.kind === 'integration' ? p.integrationId : null,
        },
      });
      await this.audit.append(tx, {
        organizationId: orgId,
        actorType: p.kind === 'user' ? 'user' : 'integration',
        actorId: p.kind === 'user' ? p.userId : p.integrationId,
        eventType: 'receipt.confirmed', subjectId: id,
        payload: { instructionId: ins.id, instructionVersion: ins.version, type: body.type, lines, externalId: body.externalId ?? null },
      });
      return serializeReceipt(receipt);
    });
  }

  /** Voiding a receipt invalidates live authorizations that relied on it. */
  @Post('receipts/:id/void')
  @Human('admin')
  async void(@CurrentUser() admin: HumanPrincipal, @Param('id') id: string, @Body(new ZodPipe(VoidBody)) body: z.infer<typeof VoidBody>) {
    const receipt = await this.prisma.receipt.findFirst({ where: { id, organizationId: admin.organizationId } });
    if (!receipt) throw Errors.notFound('Receipt');
    return this.prisma.tx(async (tx) => {
      await lockLiveAuthorizationsBy(tx, 'instructionId', receipt.instructionId);
      const updated = await tx.receipt.updateMany({ where: { id, voidedAt: null }, data: { voidedAt: new Date(), voidedByUserId: admin.userId } });
      if (updated.count !== 1) throw Errors.conflict('ALREADY_VOIDED', 'Receipt already voided');
      await invalidateLiveAuthorizations(tx, this.audit, {
        organizationId: admin.organizationId, where: { instructionId: receipt.instructionId },
        reason: 'receipt voided', actor: { type: 'user', id: admin.userId },
      });
      await this.audit.append(tx, {
        organizationId: admin.organizationId, actorType: 'user', actorId: admin.userId, eventType: 'receipt.voided', subjectId: id,
        payload: { instructionId: receipt.instructionId, reason: body.reason },
      });
      return serializeReceipt((await tx.receipt.findUnique({ where: { id } }))!);
    });
  }

  @Get('purchase-instructions/:id/receipts')
  @Human()
  async list(@CurrentUser() user: HumanPrincipal, @Param('id') id: string) {
    const rows = await this.prisma.receipt.findMany({ where: { instructionId: id, organizationId: user.organizationId }, orderBy: { createdAt: 'asc' } });
    return { receipts: rows.map(serializeReceipt) };
  }
}

function serializeReceipt(r: { id: string; instructionId: string; type: string; lines: unknown; confirmedByUserId: string | null; integrationId: string | null; externalId: string | null; voidedAt: Date | null; createdAt: Date }) {
  return {
    id: r.id,
    purchaseInstructionId: r.instructionId,
    type: r.type,
    lines: (r.lines as ReceiptLine[]).map((l) => ({ instructionLineNumber: l.instructionLineNumber, quantity: formatQuantity(l.quantityMilli) })),
    confirmedByUserId: r.confirmedByUserId,
    integrationId: r.integrationId,
    externalId: r.externalId,
    voidedAt: r.voidedAt?.toISOString() ?? null,
    createdAt: r.createdAt.toISOString(),
  };
}
