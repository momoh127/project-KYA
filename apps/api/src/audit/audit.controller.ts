import { Controller, Get, Param, Post, Query } from '@nestjs/common';
import { z } from 'zod';
import { CurrentUser, Human, type HumanPrincipal } from '../auth/principal';
import { ZodPipe } from '../common/validation';
import { AnchorService } from './anchor.service';
import { AuditService } from './audit.service';

const ListQuery = z
  .object({
    limit: z.coerce.number().int().min(1).max(500).default(100),
    afterSequence: z.coerce.number().int().min(0).optional(),
    eventType: z.string().max(64).optional(),
    actorId: z.string().max(64).optional(),
  })
  .strict();

@Controller('v1/audit')
export class AuditController {
  constructor(
    private readonly audit: AuditService,
    private readonly anchors: AnchorService,
  ) {}

  /** Anchor all not-yet-anchored events now (also runs on a background schedule). */
  @Post('anchors')
  @Human('admin')
  async anchor(@CurrentUser() user: HumanPrincipal) {
    return { anchor: await this.anchors.anchor(user.organizationId) };
  }

  @Get('anchors')
  @Human('admin', 'approver')
  listAnchors(@CurrentUser() user: HumanPrincipal) {
    return this.anchors.list(user.organizationId);
  }

  /** Export for the independent verifier (events + public keys). */
  @Get('export')
  @Human('admin')
  export(@CurrentUser() user: HumanPrincipal) {
    return this.anchors.export(user.organizationId);
  }

  @Get('events')
  @Human('admin', 'approver')
  list(@CurrentUser() user: HumanPrincipal, @Query(new ZodPipe(ListQuery)) q: z.infer<typeof ListQuery>) {
    return this.audit.list(user.organizationId, q).then((events) => ({ events }));
  }

  @Get('events/:id')
  @Human('admin', 'approver')
  get(@CurrentUser() user: HumanPrincipal, @Param('id') id: string) {
    return this.audit.get(user.organizationId, id);
  }

  /** Recomputes every hash and verifies every signature in the organization's chain. */
  @Get('verify')
  @Human('admin')
  verify(@CurrentUser() user: HumanPrincipal) {
    return this.audit.verifyChain(user.organizationId);
  }
}
