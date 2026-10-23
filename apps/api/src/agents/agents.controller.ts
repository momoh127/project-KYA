import { Body, Controller, Get, Param, Post } from '@nestjs/common';
import { z } from 'zod';
import { parseEd25519PublicKey } from '@agenttrust/identity';
import { IdPrefix, newId } from '@agenttrust/shared';
import { CurrentUser, Human, type HumanPrincipal } from '../auth/principal';
import { AuditService } from '../audit/audit.service';
import { invalidateLiveAuthorizations, lockLiveAuthorizationsBy } from '../authorizations/invalidation';
import { Errors } from '../common/errors';
import { PrismaService } from '../common/prisma.service';
import { ZodPipe, zId } from '../common/validation';

const RegisterAgent = z
  .object({
    name: z.string().min(1).max(200),
    description: z.string().max(2000).optional(),
    ownerUserId: zId('usr'),
    /** Ed25519 public key (SPKI PEM). The private key stays with the agent runtime. */
    publicKeyPem: z.string().min(40).max(1000),
    credentialExpiresAt: z.string().datetime().optional(),
  })
  .strict();

const StatusChange = z.object({ reason: z.string().max(500).optional() }).strict();

@Controller('v1/agents')
export class AgentsController {
  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
  ) {}

  @Post()
  @Human('admin')
  async register(@CurrentUser() admin: HumanPrincipal, @Body(new ZodPipe(RegisterAgent)) body: z.infer<typeof RegisterAgent>) {
    try {
      parseEd25519PublicKey(body.publicKeyPem);
    } catch {
      throw Errors.invalid('publicKeyPem must be an Ed25519 public key in SPKI PEM format');
    }
    const owner = await this.prisma.user.findFirst({ where: { id: body.ownerUserId, organizationId: admin.organizationId, status: 'active' } });
    if (!owner) throw Errors.invalid('ownerUserId must be an active user in your organization');
    const expiresAt = body.credentialExpiresAt ? new Date(body.credentialExpiresAt) : null;
    if (expiresAt && expiresAt <= new Date()) throw Errors.invalid('credentialExpiresAt must be in the future');

    const agentId = newId(IdPrefix.agent);
    const credentialId = newId(IdPrefix.credential);
    return this.prisma.tx(async (tx) => {
      const agent = await tx.agent.create({
        data: { id: agentId, organizationId: admin.organizationId, ownerUserId: owner.id, name: body.name, description: body.description },
      });
      await tx.agentCredential.create({
        data: { id: credentialId, agentId, organizationId: admin.organizationId, publicKeyPem: body.publicKeyPem, expiresAt },
      });
      await this.audit.append(tx, {
        organizationId: admin.organizationId,
        actorType: 'user',
        actorId: admin.userId,
        eventType: 'agent.registered',
        subjectId: agentId,
        payload: { name: body.name, ownerUserId: owner.id, credentialId },
      });
      return { agent: serializeAgent(agent), credential: { id: credentialId, expiresAt: expiresAt?.toISOString() ?? null } };
    });
  }

  @Get()
  @Human()
  async list(@CurrentUser() user: HumanPrincipal) {
    const agents = await this.prisma.agent.findMany({ where: { organizationId: user.organizationId }, orderBy: { createdAt: 'asc' } });
    return { agents: agents.map(serializeAgent) };
  }

  @Get(':id')
  @Human()
  async get(@CurrentUser() user: HumanPrincipal, @Param('id') id: string) {
    const agent = await this.prisma.agent.findFirst({ where: { id, organizationId: user.organizationId } });
    if (!agent) throw Errors.notFound('Agent');
    const credentials = await this.prisma.agentCredential.findMany({
      where: { agentId: id },
      select: { id: true, status: true, createdAt: true, expiresAt: true, revokedAt: true },
    });
    return { ...serializeAgent(agent), credentials };
  }

  /** Kill switch: a revoked agent can never transact again. */
  @Post(':id/revoke')
  @Human('admin')
  revoke(@CurrentUser() admin: HumanPrincipal, @Param('id') id: string, @Body(new ZodPipe(StatusChange)) body: z.infer<typeof StatusChange>) {
    return this.setStatus(admin, id, 'revoked', body.reason ?? 'revoked by administrator');
  }

  /** Lifts a suspension (e.g. after a circuit-breaker trip was investigated). Revocation is permanent. */
  @Post(':id/reactivate')
  @Human('admin')
  reactivate(@CurrentUser() admin: HumanPrincipal, @Param('id') id: string, @Body(new ZodPipe(StatusChange)) body: z.infer<typeof StatusChange>) {
    return this.setStatus(admin, id, 'active', body.reason ?? 'reactivated by administrator');
  }

  private setStatus(admin: HumanPrincipal, id: string, status: 'active' | 'revoked', reason: string) {
    return this.prisma.tx(async (tx) => {
      // Lock order: Authorization rows → Agent → AuditChainHead (same as the approval path).
      if (status === 'revoked') await lockLiveAuthorizationsBy(tx, 'agentId', id);
      const agent = await tx.agent.findFirst({ where: { id, organizationId: admin.organizationId } });
      if (!agent) throw Errors.notFound('Agent');
      if (agent.status === 'revoked') throw Errors.conflict('AGENT_REVOKED', 'Revoked agents cannot be changed');
      if (status === 'active' && agent.status !== 'suspended') throw Errors.conflict('NOT_SUSPENDED', 'Agent is not suspended');
      const updated = await tx.agent.update({ where: { id }, data: { status, statusReason: reason } });
      if (status === 'revoked') {
        await tx.agentSession.updateMany({ where: { agentId: id, revokedAt: null }, data: { revokedAt: new Date() } });
        await invalidateLiveAuthorizations(tx, this.audit, {
          organizationId: admin.organizationId,
          where: { agentId: id },
          reason: 'agent revoked',
          actor: { type: 'user', id: admin.userId },
        });
      }
      await this.audit.append(tx, {
        organizationId: admin.organizationId,
        actorType: 'user',
        actorId: admin.userId,
        eventType: status === 'revoked' ? 'agent.revoked' : 'agent.reactivated',
        subjectId: id,
        payload: { previousStatus: agent.status, reason },
      });
      return serializeAgent(updated);
    });
  }
}

export function serializeAgent(a: { id: string; organizationId: string; ownerUserId: string; name: string; description: string | null; status: string; statusReason: string | null; createdAt: Date }) {
  return {
    id: a.id,
    organizationId: a.organizationId,
    ownerUserId: a.ownerUserId,
    name: a.name,
    description: a.description,
    status: a.status,
    statusReason: a.statusReason,
    createdAt: a.createdAt.toISOString(),
  };
}
