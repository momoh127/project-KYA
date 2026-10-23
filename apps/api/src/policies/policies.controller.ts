import { Body, Controller, Get, Param, Post, Put } from '@nestjs/common';
import type { Prisma } from '@prisma/client';
import { z } from 'zod';
import type { PolicyRules } from '@agenttrust/policy-engine';
import { IdPrefix, newId } from '@agenttrust/shared';
import { CurrentUser, Human, type HumanPrincipal } from '../auth/principal';
import { AuditService } from '../audit/audit.service';
import { Errors } from '../common/errors';
import { PrismaService, type Tx } from '../common/prisma.service';
import { ZodPipe } from '../common/validation';

export const PolicyRulesSchema = z
  .object({
    missingPurchaseOrder: z.enum(['REVIEW', 'DENY']),
    missingInvoice: z.enum(['ALLOW', 'REVIEW', 'DENY']),
    unknownSupplier: z.enum(['REVIEW', 'DENY']),
    reviewThresholdCents: z.number().int().positive().nullable(),
    authorizationTtlSeconds: z.number().int().min(30).max(3600),
    reviewTtlSeconds: z.number().int().min(300).max(7 * 86_400),
    circuitBreaker: z
      .object({ denyThreshold: z.number().int().min(1).max(1000), windowSeconds: z.number().int().min(60).max(86_400) })
      .strict(),
  })
  .strict();

const CreatePolicy = z.object({ name: z.string().min(1).max(200), rules: PolicyRulesSchema }).strict();
const UpdatePolicy = z.object({ name: z.string().min(1).max(200).optional(), rules: PolicyRulesSchema }).strict();

/** Parses stored rules; invalid stored rules fail closed (treated as no policy). */
export function parseStoredRules(raw: unknown): PolicyRules | null {
  const r = PolicyRulesSchema.safeParse(raw);
  return r.success ? r.data : null;
}

/**
 * Policies are immutable, versioned documents. POST/PUT create a new version
 * and atomically supersede the previous active one, so every authorization
 * records exactly which policy version decided it.
 */
@Controller('v1/policies')
export class PoliciesController {
  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
  ) {}

  @Get()
  @Human()
  async list(@CurrentUser() user: HumanPrincipal) {
    const policies = await this.prisma.policy.findMany({ where: { organizationId: user.organizationId }, orderBy: { version: 'desc' } });
    return { policies };
  }

  @Post()
  @Human('admin')
  create(@CurrentUser() admin: HumanPrincipal, @Body(new ZodPipe(CreatePolicy)) body: z.infer<typeof CreatePolicy>) {
    return this.prisma.tx((tx) => this.newVersion(tx, admin, body.name, body.rules));
  }

  @Put(':id')
  @Human('admin')
  update(@CurrentUser() admin: HumanPrincipal, @Param('id') id: string, @Body(new ZodPipe(UpdatePolicy)) body: z.infer<typeof UpdatePolicy>) {
    return this.prisma.tx(async (tx) => {
      const current = await tx.policy.findFirst({ where: { id, organizationId: admin.organizationId } });
      if (!current) throw Errors.notFound('Policy');
      if (current.status !== 'active') throw Errors.conflict('POLICY_SUPERSEDED', 'Only the active policy can be updated');
      return this.newVersion(tx, admin, body.name ?? current.name, body.rules);
    });
  }

  private async newVersion(tx: Tx, admin: HumanPrincipal, name: string, rules: PolicyRules) {
    const latest = await tx.policy.findFirst({ where: { organizationId: admin.organizationId }, orderBy: { version: 'desc' } });
    const version = (latest?.version ?? 0) + 1;
    await tx.policy.updateMany({ where: { organizationId: admin.organizationId, status: 'active' }, data: { status: 'superseded' } });
    const policy = await tx.policy.create({
      data: { id: newId(IdPrefix.policy), organizationId: admin.organizationId, name, version, rules: rules as unknown as Prisma.InputJsonObject, status: 'active', createdByUserId: admin.userId },
    });
    await this.audit.append(tx, {
      organizationId: admin.organizationId,
      actorType: 'user',
      actorId: admin.userId,
      eventType: 'policy.version_created',
      subjectId: policy.id,
      payload: { version, name, rules: rules as unknown as Record<string, unknown> },
    });
    return policy;
  }
}
