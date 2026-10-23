import { Body, Controller, Get, Param, Post } from '@nestjs/common';
import { randomBytes } from 'node:crypto';
import { z } from 'zod';
import { IdPrefix, newId, sha256Hex } from '@agenttrust/shared';
import { CurrentUser, FreshAuth, Human, INTEGRATION_SCOPES, type HumanPrincipal } from '../auth/principal';
import { AuditService } from '../audit/audit.service';
import { Errors } from '../common/errors';
import { PrismaService } from '../common/prisma.service';
import { ZodPipe } from '../common/validation';

const CreateIntegration = z
  .object({
    name: z.string().min(1).max(200),
    /** e.g. "netsuite", "sap", "coupa". One integration per source system per organization. */
    sourceSystem: z.string().regex(/^[a-z0-9][a-z0-9_-]{1,40}$/),
    scopes: z.array(z.enum(INTEGRATION_SCOPES)).min(1),
  })
  .strict();

/**
 * ERP integrations are privileged machine identities with narrowly scoped
 * permissions. `instructions:sync` lets an ERP import purchase instructions
 * but NEVER approve them; only `instructions:attest_approval` (granted
 * deliberately by an administrator) lets ERP-side approvals count. The secret
 * is shown once; only its SHA-256 is stored.
 *
 * Production: prefer OAuth client credentials or mTLS over static secrets.
 */
@Controller('v1/integrations')
export class IntegrationsController {
  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
  ) {}

  @Post()
  @Human('admin')
  @FreshAuth(300)
  async create(@CurrentUser() admin: HumanPrincipal, @Body(new ZodPipe(CreateIntegration)) body: z.infer<typeof CreateIntegration>) {
    const id = newId(IdPrefix.integration);
    const secret = randomBytes(32).toString('base64url');
    const scopes = [...new Set(body.scopes)];
    return this.prisma.tx(async (tx) => {
      const existing = await tx.integration.findFirst({ where: { organizationId: admin.organizationId, sourceSystem: body.sourceSystem, status: 'active' } });
      if (existing) throw Errors.conflict('INTEGRATION_EXISTS', `An active ${body.sourceSystem} integration already exists`);
      await tx.integration.deleteMany({ where: { organizationId: admin.organizationId, sourceSystem: body.sourceSystem, status: 'revoked' } });
      const integration = await tx.integration.create({
        data: { id, organizationId: admin.organizationId, name: body.name, sourceSystem: body.sourceSystem, scopes, secretHash: sha256Hex(secret), createdByUserId: admin.userId },
      });
      await this.audit.append(tx, {
        organizationId: admin.organizationId, actorType: 'user', actorId: admin.userId, eventType: 'integration.created', subjectId: id,
        payload: { name: body.name, sourceSystem: body.sourceSystem, scopes },
      });
      return { integration: serialize(integration), token: `itk_${id}.${secret}` };
    });
  }

  @Get()
  @Human('admin')
  async list(@CurrentUser() admin: HumanPrincipal) {
    const rows = await this.prisma.integration.findMany({ where: { organizationId: admin.organizationId }, orderBy: { createdAt: 'asc' } });
    return { integrations: rows.map(serialize) };
  }

  @Post(':id/revoke')
  @Human('admin')
  revoke(@CurrentUser() admin: HumanPrincipal, @Param('id') id: string) {
    return this.prisma.tx(async (tx) => {
      const i = await tx.integration.findFirst({ where: { id, organizationId: admin.organizationId } });
      if (!i) throw Errors.notFound('Integration');
      const updated = await tx.integration.update({ where: { id }, data: { status: 'revoked', revokedAt: new Date() } });
      await this.audit.append(tx, {
        organizationId: admin.organizationId, actorType: 'user', actorId: admin.userId, eventType: 'integration.revoked', subjectId: id, payload: {},
      });
      return serialize(updated);
    });
  }
}

function serialize(i: { id: string; name: string; sourceSystem: string; scopes: string[]; status: string; createdAt: Date; revokedAt: Date | null }) {
  return { id: i.id, name: i.name, sourceSystem: i.sourceSystem, scopes: i.scopes, status: i.status, createdAt: i.createdAt.toISOString(), revokedAt: i.revokedAt?.toISOString() ?? null };
}
