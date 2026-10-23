import { Body, Controller, Get, Param, Post } from '@nestjs/common';
import { z } from 'zod';
import { IdPrefix, newId } from '@agenttrust/shared';
import { CurrentUser, Human, type HumanPrincipal } from '../auth/principal';
import { AuditService } from '../audit/audit.service';
import { Errors } from '../common/errors';
import { cents, PrismaService } from '../common/prisma.service';
import { zCents, zCurrency, ZodPipe, zId } from '../common/validation';

const MAX_DELEGATION_DAYS = 366;

const CreateDelegation = z
  .object({
    agentId: zId('agt'),
    actions: z.array(z.literal('purchase')).min(1),
    maxTransactionCents: zCents,
    monthlyLimitCents: zCents,
    currency: zCurrency,
    /** null/omitted = any approved supplier; array = only these suppliers. */
    approvedSupplierIds: z.array(zId('sup')).max(500).nullable().optional(),
    validFrom: z.string().datetime().optional(),
    expiresAt: z.string().datetime(),
  })
  .strict();

@Controller('v1/delegations')
export class DelegationsController {
  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
  ) {}

  /**
   * A human grants an agent bounded purchasing authority. The granting user is
   * authenticated server-side and must personally hold at least the authority
   * being delegated. Agents can never call this endpoint (human-only), so an
   * agent cannot grant itself authority. A new delegation supersedes (revokes)
   * the agent's previous active delegation.
   */
  @Post()
  @Human('admin', 'approver')
  async create(@CurrentUser() user: HumanPrincipal, @Body(new ZodPipe(CreateDelegation)) body: z.infer<typeof CreateDelegation>) {
    const now = new Date();
    const validFrom = body.validFrom ? new Date(body.validFrom) : now;
    const expiresAt = new Date(body.expiresAt);
    if (expiresAt <= validFrom) throw Errors.invalid('expiresAt must be after validFrom');
    if (expiresAt.getTime() - validFrom.getTime() > MAX_DELEGATION_DAYS * 86_400_000) {
      throw Errors.invalid(`Delegations may not exceed ${MAX_DELEGATION_DAYS} days`);
    }
    if (body.monthlyLimitCents < body.maxTransactionCents) throw Errors.invalid('monthlyLimitCents must be >= maxTransactionCents');
    if (body.maxTransactionCents > user.spendingAuthorityCents) {
      throw Errors.forbidden('INSUFFICIENT_AUTHORITY', 'You cannot delegate more per-transaction authority than you hold');
    }

    const agent = await this.prisma.agent.findFirst({ where: { id: body.agentId, organizationId: user.organizationId } });
    if (!agent) throw Errors.notFound('Agent');
    if (agent.status === 'revoked') throw Errors.conflict('AGENT_REVOKED', 'Cannot delegate to a revoked agent');

    const supplierIds = body.approvedSupplierIds ?? null;
    if (supplierIds && supplierIds.length > 0) {
      const count = await this.prisma.supplier.count({ where: { id: { in: supplierIds }, organizationId: user.organizationId } });
      if (count !== new Set(supplierIds).size) throw Errors.invalid('approvedSupplierIds must all be suppliers in your organization');
    }

    const id = newId(IdPrefix.delegation);
    return this.prisma.tx(async (tx) => {
      const superseded = await tx.delegation.updateMany({
        where: { agentId: agent.id, organizationId: user.organizationId, revokedAt: null, expiresAt: { gt: now } },
        data: { revokedAt: now, revokedByUserId: user.userId },
      });
      const d = await tx.delegation.create({
        data: {
          id,
          organizationId: user.organizationId,
          agentId: agent.id,
          grantedByUserId: user.userId,
          actions: body.actions,
          maxTransactionCents: BigInt(body.maxTransactionCents),
          monthlyLimitCents: BigInt(body.monthlyLimitCents),
          currency: body.currency,
          restrictSuppliers: supplierIds !== null,
          approvedSupplierIds: supplierIds ?? [],
          validFrom,
          expiresAt,
        },
      });
      await this.audit.append(tx, {
        organizationId: user.organizationId,
        actorType: 'user',
        actorId: user.userId,
        eventType: 'delegation.granted',
        subjectId: id,
        payload: {
          agentId: agent.id,
          actions: body.actions,
          maxTransactionCents: body.maxTransactionCents,
          monthlyLimitCents: body.monthlyLimitCents,
          currency: body.currency,
          approvedSupplierIds: supplierIds,
          validFrom: validFrom.toISOString(),
          expiresAt: expiresAt.toISOString(),
          supersededCount: superseded.count,
        },
      });
      return serializeDelegation(d);
    });
  }

  @Get(':id')
  @Human()
  async get(@CurrentUser() user: HumanPrincipal, @Param('id') id: string) {
    const d = await this.prisma.delegation.findFirst({ where: { id, organizationId: user.organizationId } });
    if (!d) throw Errors.notFound('Delegation');
    return serializeDelegation(d);
  }

  @Post(':id/revoke')
  @Human('admin', 'approver')
  revoke(@CurrentUser() user: HumanPrincipal, @Param('id') id: string) {
    return this.prisma.tx(async (tx) => {
      const d = await tx.delegation.findFirst({ where: { id, organizationId: user.organizationId } });
      if (!d) throw Errors.notFound('Delegation');
      if (d.revokedAt) throw Errors.conflict('ALREADY_REVOKED', 'Delegation already revoked');
      const updated = await tx.delegation.update({ where: { id }, data: { revokedAt: new Date(), revokedByUserId: user.userId } });
      await this.audit.append(tx, {
        organizationId: user.organizationId,
        actorType: 'user',
        actorId: user.userId,
        eventType: 'delegation.revoked',
        subjectId: id,
        payload: { agentId: d.agentId },
      });
      return serializeDelegation(updated);
    });
  }
}

export function serializeDelegation(d: {
  id: string; organizationId: string; agentId: string; grantedByUserId: string; actions: string[];
  maxTransactionCents: bigint; monthlyLimitCents: bigint; currency: string; restrictSuppliers: boolean;
  approvedSupplierIds: string[]; validFrom: Date; expiresAt: Date; revokedAt: Date | null; createdAt: Date;
}) {
  return {
    id: d.id,
    organizationId: d.organizationId,
    agentId: d.agentId,
    grantedByUserId: d.grantedByUserId,
    actions: d.actions,
    maxTransactionCents: cents(d.maxTransactionCents),
    monthlyLimitCents: cents(d.monthlyLimitCents),
    currency: d.currency,
    approvedSupplierIds: d.restrictSuppliers ? d.approvedSupplierIds : null,
    validFrom: d.validFrom.toISOString(),
    expiresAt: d.expiresAt.toISOString(),
    revokedAt: d.revokedAt?.toISOString() ?? null,
    createdAt: d.createdAt.toISOString(),
  };
}
