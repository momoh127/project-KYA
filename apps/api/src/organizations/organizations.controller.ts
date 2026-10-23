import { Body, Controller, Get, Param, Post } from '@nestjs/common';
import { z } from 'zod';
import { DEFAULT_POLICY_RULES } from '@agenttrust/policy-engine';
import { IdPrefix, newId } from '@agenttrust/shared';
import { Bootstrap, CurrentUser, Human, type HumanPrincipal } from '../auth/principal';
import { AuditService } from '../audit/audit.service';
import { Errors } from '../common/errors';
import { cents, PrismaService } from '../common/prisma.service';
import { zCents, ZodPipe } from '../common/validation';

const CreateOrg = z
  .object({
    name: z.string().min(1).max(200),
    admin: z.object({ email: z.string().email().max(320), spendingAuthorityCents: zCents }).strict(),
  })
  .strict();

const CreateUser = z
  .object({
    email: z.string().email().max(320),
    role: z.enum(['admin', 'approver', 'member']),
    spendingAuthorityCents: z.number().int().min(0).max(100_000_000_000).default(0),
  })
  .strict();

@Controller('v1')
export class OrganizationsController {
  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
  ) {}

  /**
   * Creates an organization, its first administrator, its default policy (v1)
   * and its audit chain. Restricted to the platform operator (bootstrap token).
   * Production: replaced by authenticated self-serve signup via the IdP.
   */
  @Post('organizations')
  @Bootstrap()
  async create(@Body(new ZodPipe(CreateOrg)) body: z.infer<typeof CreateOrg>) {
    const orgId = newId(IdPrefix.organization);
    const userId = newId(IdPrefix.user);
    const policyId = newId(IdPrefix.policy);

    return this.prisma.tx(async (tx) => {
      const org = await tx.organization.create({ data: { id: orgId, name: body.name } });
      const admin = await tx.user.create({
        data: {
          id: userId,
          organizationId: orgId,
          externalIdentityId: `dev|${userId}`,
          email: body.admin.email,
          role: 'admin',
          spendingAuthorityCents: BigInt(body.admin.spendingAuthorityCents),
        },
      });
      await tx.policy.create({
        data: { id: policyId, organizationId: orgId, name: 'Default purchasing policy', version: 1, rules: JSON.parse(JSON.stringify(DEFAULT_POLICY_RULES)), status: 'active' },
      });
      await tx.auditChainHead.create({ data: { organizationId: orgId } });
      await this.audit.append(tx, {
        organizationId: orgId,
        actorType: 'system',
        actorId: 'platform',
        eventType: 'organization.created',
        subjectId: orgId,
        payload: { name: body.name, adminUserId: userId, policyId, policyVersion: 1 },
      });
      return { organization: org, admin: serializeUser(admin), policy: { id: policyId, version: 1 } };
    });
  }

  @Get('organizations/:id')
  @Human()
  async get(@CurrentUser() user: HumanPrincipal, @Param('id') id: string) {
    // Tenant isolation: you can only read your own organization. Return 404
    // (not 403) so other organizations' ids cannot be probed.
    if (id !== user.organizationId) throw Errors.notFound('Organization');
    const org = await this.prisma.organization.findUnique({ where: { id } });
    if (!org) throw Errors.notFound('Organization');
    return org;
  }

  @Post('users')
  @Human('admin')
  async createUser(@CurrentUser() admin: HumanPrincipal, @Body(new ZodPipe(CreateUser)) body: z.infer<typeof CreateUser>) {
    if (body.spendingAuthorityCents > admin.spendingAuthorityCents) {
      throw Errors.forbidden('INSUFFICIENT_AUTHORITY', 'Cannot grant more spending authority than you hold');
    }
    const id = newId(IdPrefix.user);
    return this.prisma.tx(async (tx) => {
      const user = await tx.user.create({
        data: {
          id,
          organizationId: admin.organizationId,
          externalIdentityId: `dev|${id}`,
          email: body.email,
          role: body.role,
          spendingAuthorityCents: BigInt(body.spendingAuthorityCents),
        },
      });
      await this.audit.append(tx, {
        organizationId: admin.organizationId,
        actorType: 'user',
        actorId: admin.userId,
        eventType: 'user.created',
        subjectId: id,
        payload: { role: body.role, spendingAuthorityCents: body.spendingAuthorityCents },
      });
      return serializeUser(user);
    });
  }

  @Get('users')
  @Human('admin')
  async listUsers(@CurrentUser() admin: HumanPrincipal) {
    const users = await this.prisma.user.findMany({ where: { organizationId: admin.organizationId }, orderBy: { createdAt: 'asc' } });
    return { users: users.map(serializeUser) };
  }
}

export function serializeUser(u: { id: string; organizationId: string; email: string; role: string; status: string; spendingAuthorityCents: bigint; createdAt: Date }) {
  return {
    id: u.id,
    organizationId: u.organizationId,
    email: u.email,
    role: u.role,
    status: u.status,
    spendingAuthorityCents: cents(u.spendingAuthorityCents),
    createdAt: u.createdAt.toISOString(),
  };
}
