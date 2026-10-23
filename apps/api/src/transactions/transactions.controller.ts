import { Body, Controller, Get, Param, Post, Res } from '@nestjs/common';
import type { Response } from 'express';
import { z } from 'zod';
import { AgentOnly, CurrentAgent, CurrentPrincipal, CurrentUser, FreshAuth, Human, HumanOrAgent, type AgentPrincipal, type HumanPrincipal, type Principal } from '../auth/principal';
import { zCents, zCurrency, ZodPipe, zId } from '../common/validation';
import { HTTP_FINAL } from './lifecycle';
import { TransactionsService } from './transactions.service';

const ResolveBody = z.object({ note: z.string().min(10).max(1000) }).strict();

const ExecuteBody = z
  .object({
    token: z.string().min(1).max(8192),
    expected: z
      .object({
        supplierId: zId('sup').nullable(),
        amountCents: zCents,
        currency: zCurrency,
        purchaseOrderId: zId('po').nullable(),
        invoiceId: zId('inv').nullable(),
      })
      .strict(),
  })
  .strict();

@Controller('v1/transactions')
export class TransactionsController {
  constructor(private readonly service: TransactionsService) {}

  /**
   * The enforcing payment gateway: the only path from an agent to money.
   * 200 = final outcome (settled / failed / returned / reversed).
   * 202 = in flight (accepted / processing / unknown / reconciliation_required):
   * provider ACCEPTANCE is not payment; never treat 202 as failure. Retry the
   * same call (it reconciles, never re-pays) or poll GET /v1/transactions/:id.
   */
  @Post('execute')
  @AgentOnly()
  async execute(@CurrentAgent() agent: AgentPrincipal, @Body(new ZodPipe(ExecuteBody)) body: z.infer<typeof ExecuteBody>, @Res({ passthrough: true }) res: Response) {
    const result = await this.service.execute(agent, body);
    res.status(HTTP_FINAL.includes(result.status) ? 200 : 202);
    return result;
  }

  @Get(':id')
  @HumanOrAgent()
  get(@CurrentPrincipal() p: Principal, @Param('id') id: string) {
    if (p.kind === 'agent') return this.service.getForAgent(p, id);
    if (p.kind === 'user') return this.service.getForUser(p, id);
    throw new Error('unreachable: route admits humans and agents only');
  }

  /**
   * Explicitly release a failed-after-acceptance / returned / reversed payment
   * so the obligation can be re-authorized. Re-confirms with the provider first.
   */
  @Post(':id/resolve')
  @Human('admin')
  @FreshAuth(300)
  resolve(@CurrentUser() user: HumanPrincipal, @Param('id') id: string, @Body(new ZodPipe(ResolveBody)) body: z.infer<typeof ResolveBody>) {
    return this.service.resolveException(user, id, body.note);
  }

  /** Manually reconcile a transaction with the payment provider (never re-pays without checking first). */
  @Post(':id/reconcile')
  @Human('admin')
  reconcile(@CurrentUser() user: HumanPrincipal, @Param('id') id: string) {
    return this.service.reconcileForUser(user, id);
  }
}
