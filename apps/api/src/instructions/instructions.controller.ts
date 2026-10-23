import { Body, Controller, Get, Param, Post, Put, Query } from '@nestjs/common';
import { z } from 'zod';
import {
  AgentOnly,
  CurrentAgent,
  CurrentIntegration,
  CurrentUser,
  FreshAuth,
  Human,
  Integration,
  type AgentPrincipal,
  type HumanPrincipal,
  type IntegrationPrincipal,
} from '../auth/principal';
import { ZodPipe, zId } from '../common/validation';
import { ErpSyncBody, InstructionBody, InstructionsService } from './instructions.service';

const ReasonBody = z.object({ reason: z.string().min(3).max(1000) }).strict();
const ApproveBody = z.object({ comment: z.string().max(1000).optional() }).strict();
const ListQuery = z
  .object({ agentId: zId('agt').optional(), status: z.enum(['pending_approval', 'approved', 'rejected', 'revoked']).optional() })
  .strict();

/**
 * Purchase instructions. Humans create, amend, approve, reject and revoke.
 * ERP integrations sync. Agents may only READ instructions assigned to them.
 * There is deliberately no agent-writable route.
 */
@Controller('v1')
export class InstructionsController {
  constructor(private readonly service: InstructionsService) {}

  @Post('purchase-instructions')
  @Human('admin', 'approver', 'member')
  create(@CurrentUser() user: HumanPrincipal, @Body(new ZodPipe(InstructionBody)) body: z.infer<typeof InstructionBody>) {
    return this.service.createByHuman(user, body);
  }

  @Put('purchase-instructions/:id')
  @Human('admin', 'approver', 'member')
  amend(@CurrentUser() user: HumanPrincipal, @Param('id') id: string, @Body(new ZodPipe(InstructionBody)) body: z.infer<typeof InstructionBody>) {
    return this.service.amendByHuman(user, id, body);
  }

  @Post('purchase-instructions/:id/approve')
  @Human('admin', 'approver')
  @FreshAuth(900)
  approve(@CurrentUser() user: HumanPrincipal, @Param('id') id: string, @Body(new ZodPipe(ApproveBody)) body: z.infer<typeof ApproveBody>) {
    return this.service.approve(user, id, body.comment);
  }

  @Post('purchase-instructions/:id/reject')
  @Human('admin', 'approver')
  reject(@CurrentUser() user: HumanPrincipal, @Param('id') id: string, @Body(new ZodPipe(ReasonBody)) body: z.infer<typeof ReasonBody>) {
    return this.service.reject(user, id, body.reason);
  }

  @Post('purchase-instructions/:id/revoke')
  @Human('admin', 'approver')
  revoke(@CurrentUser() user: HumanPrincipal, @Param('id') id: string, @Body(new ZodPipe(ReasonBody)) body: z.infer<typeof ReasonBody>) {
    return this.service.revoke(user, id, body.reason);
  }

  @Get('purchase-instructions')
  @Human()
  list(@CurrentUser() user: HumanPrincipal, @Query(new ZodPipe(ListQuery)) q: z.infer<typeof ListQuery>) {
    return this.service.list(user.organizationId, q);
  }

  @Get('purchase-instructions/:id')
  @Human()
  get(@CurrentUser() user: HumanPrincipal, @Param('id') id: string) {
    return this.service.get(user.organizationId, id);
  }

  @Get('purchase-instructions/:id/versions')
  @Human('admin', 'approver')
  versions(@CurrentUser() user: HumanPrincipal, @Param('id') id: string) {
    return this.service.versions(user.organizationId, id);
  }

  /** ERP import (scope `instructions:sync`). Sync ≠ approval. */
  @Post('integrations/erp/purchase-instructions')
  @Integration('instructions:sync')
  sync(@CurrentIntegration() integration: IntegrationPrincipal, @Body(new ZodPipe(ErpSyncBody)) body: z.infer<typeof ErpSyncBody>) {
    return this.service.syncFromErp(integration, body);
  }

  /** Read-only: the approved instructions assigned to the calling agent. */
  @Get('agent/purchase-instructions')
  @AgentOnly()
  mine(@CurrentAgent() agent: AgentPrincipal) {
    return this.service.list(agent.organizationId, { agentId: agent.agentId, status: 'approved' });
  }

  @Get('agent/purchase-instructions/:id')
  @AgentOnly()
  mineOne(@CurrentAgent() agent: AgentPrincipal, @Param('id') id: string) {
    return this.service.get(agent.organizationId, id, { agentId: agent.agentId });
  }
}
