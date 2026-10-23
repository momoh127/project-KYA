import { Body, Controller, Get, Param, Post, Query } from '@nestjs/common';
import { z } from 'zod';
import { AgentOnly, CurrentAgent, CurrentPrincipal, CurrentUser, FreshAuth, Human, HumanOrAgent, type AgentPrincipal, type HumanPrincipal, type Principal } from '../auth/principal';
import { zCents, zCurrency, ZodPipe, zId, zPaymentDestination } from '../common/validation';
import { AuthorizationsService } from './authorizations.service';

const CreateAuthorization = z
  .object({
    idempotencyKey: z.string().min(8).max(128).regex(/^[A-Za-z0-9_\-:.]+$/),
    action: z.literal('purchase'),
    supplierId: zId('sup').optional(),
    payee: zPaymentDestination,
    amountCents: zCents,
    currency: zCurrency,
    purchaseOrderId: zId('po').optional(),
    invoiceId: zId('inv').optional(),
    /** The independently approved purchase instruction this payment fulfils. */
    purchaseInstructionId: zId('pin').optional(),
    /** Which approved instruction lines are being bought (used only if the invoice has no lines). */
    lines: z
      .array(
        z
          .object({
            instructionLineNumber: z.number().int().min(1).max(999),
            sku: z.string().min(1).max(100).optional(),
            quantity: z.string().min(1).max(20),
            unitPriceCents: z.number().int().min(0).max(100_000_000_000),
          })
          .strict(),
      )
      .max(100)
      .optional(),
  })
  .strict();

const ReviewBody = z.object({ comment: z.string().max(1000).optional() }).strict();
const ListQuery = z.object({ status: z.enum(['allowed', 'pending_review', 'denied', 'rejected', 'consumed', 'expired']).optional() }).strict();

@Controller('v1/authorizations')
export class AuthorizationsController {
  constructor(private readonly service: AuthorizationsService) {}

  /** Agent asks: "may I make this exact purchase?" → ALLOW / REVIEW / DENY. */
  @Post()
  @AgentOnly()
  create(@CurrentAgent() agent: AgentPrincipal, @Body(new ZodPipe(CreateAuthorization)) body: z.infer<typeof CreateAuthorization>) {
    return this.service.create(agent, body);
  }

  /** Approval queue / history for humans. */
  @Get()
  @Human()
  list(@CurrentUser() user: HumanPrincipal, @Query(new ZodPipe(ListQuery)) q: z.infer<typeof ListQuery>) {
    return this.service.list(user, q.status);
  }

  @Get(':id')
  @HumanOrAgent()
  get(@CurrentPrincipal() p: Principal, @Param('id') id: string) {
    if (p.kind === 'agent') return this.service.getForAgent(p, id);
    if (p.kind === 'user') return this.service.getForUser(p, id);
    throw new Error('unreachable: route admits humans and agents only');
  }

  /** Human-only; agents can never reach these routes, so they cannot approve themselves. */
  @Post(':id/approve')
  @Human('admin', 'approver')
  @FreshAuth(900)
  approve(@CurrentUser() user: HumanPrincipal, @Param('id') id: string, @Body(new ZodPipe(ReviewBody)) body: z.infer<typeof ReviewBody>) {
    return this.service.approve(user, id, body.comment);
  }

  @Post(':id/deny')
  @Human('admin', 'approver')
  @FreshAuth(900)
  deny(@CurrentUser() user: HumanPrincipal, @Param('id') id: string, @Body(new ZodPipe(ReviewBody)) body: z.infer<typeof ReviewBody>) {
    return this.service.reject(user, id, body.comment);
  }
}
