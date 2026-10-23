import { Body, Controller, Get, Param, Post, Put } from '@nestjs/common';
import type { Prisma } from '@prisma/client';
import { z } from 'zod';
import { DEFAULT_POLICY_RULES, type PolicyRules } from '@agenttrust/policy-engine';
import { IdPrefix, newId } from '@agenttrust/shared';
import { CurrentUser, Human, type HumanPrincipal } from '../auth/principal';
import { AuditService } from '../audit/audit.service';
import { invalidateLiveAuthorizations } from '../authorizations/invalidation';
import { Errors } from '../common/errors';
import { PrismaService, type Tx } from '../common/prisma.service';
import { ZodPipe } from '../common/validation';

const SecurityResponseSchema = z
  .object({
    violationSuspendThreshold: z.number().int().min(1).max(1000),
    violationWindowSeconds: z.number().int().min(60).max(86_400),
    authFailureAlertThreshold: z.number().int().min(1).max(100_000),
    denialAlertThreshold: z.number().int().min(1).max(100_000),
    alertWindowSeconds: z.number().int().min(60).max(7 * 86_400),
  })
  .strict();

const ReceiptRequirementSchema = z.enum(['confirmation_required', 'human_approval', 'none']);
const ThreeWayMatchSchema = z
  .object({
    enabled: z.boolean(),
    physicalGoods: ReceiptRequirementSchema,
    services: ReceiptRequirementSchema,
    subscription: ReceiptRequirementSchema,
    digitalGoods: ReceiptRequirementSchema,
  })
  .strict();

const RiskControlsSchema = z
  .object({
    enabled: z.boolean(),
    maxAuthorizationsPerHour: z.number().int().min(1).max(100_000),
    maxSpendPerHourBps: z.number().int().min(1).max(10_000),
    maxPurchasesPerSupplierPerDay: z.number().int().min(1).max(100_000),
    recentPayeeChangeHours: z.number().int().min(0).max(24 * 90),
    response: z.enum(['REVIEW', 'DENY']),
  })
  .strict();

const rulesShape = {
  riskControls: RiskControlsSchema,
  missingInstruction: z.enum(['REVIEW', 'DENY']),
  threeWayMatch: ThreeWayMatchSchema,
  missingReceipt: z.enum(['REVIEW', 'DENY']),
  missingPurchaseOrder: z.enum(['REVIEW', 'DENY']),
  missingInvoice: z.enum(['ALLOW', 'REVIEW', 'DENY']),
  unknownSupplier: z.enum(['REVIEW', 'DENY']),
  reviewThresholdCents: z.number().int().positive().nullable(),
  authorizationTtlSeconds: z.number().int().min(30).max(3600),
  reviewTtlSeconds: z.number().int().min(1).max(7 * 86_400),
  securityResponse: SecurityResponseSchema,
};

/** Rules accepted from administrators: strict (unknown keys rejected). */
export const PolicyRulesSchema = z.object(rulesShape).strict();

/** Rules read back from storage: tolerant of retired keys; older versions get default security responses. */
const StoredRulesSchema = z.object({
  ...rulesShape,
  securityResponse: SecurityResponseSchema.default(DEFAULT_POLICY_RULES.securityResponse),
  // Policies stored before v0.3 get the (strict) v0.3 defaults: instructions required, invoice required.
  missingInstruction: rulesShape.missingInstruction.default(DEFAULT_POLICY_RULES.missingInstruction),
  threeWayMatch: ThreeWayMatchSchema.default(DEFAULT_POLICY_RULES.threeWayMatch),
  missingReceipt: rulesShape.missingReceipt.default(DEFAULT_POLICY_RULES.missingReceipt),
  riskControls: RiskControlsSchema.default(DEFAULT_POLICY_RULES.riskControls),
});

const CreatePolicy = z.object({ name: z.string().min(1).max(200), rules: PolicyRulesSchema }).strict();
const UpdatePolicy = z.object({ name: z.string().min(1).max(200).optional(), rules: PolicyRulesSchema }).strict();

/** Parses stored rules; invalid stored rules fail closed (treated as no policy). */
export function parseStoredRules(raw: unknown): PolicyRules | null {
  const r = StoredRulesSchema.safeParse(raw);
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
    // Authorizations issued under the previous version are no longer valid.
    await invalidateLiveAuthorizations(tx, this.audit, {
      organizationId: admin.organizationId,
      where: { policyId: { not: policy.id } },
      reason: `policy changed to v${version}`,
      actor: { type: 'user', id: admin.userId },
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
