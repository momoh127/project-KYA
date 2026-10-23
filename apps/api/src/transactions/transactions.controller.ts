import { Body, Controller, Get, Param, Post, Res } from '@nestjs/common';
import type { Response } from 'express';
import { z } from 'zod';
import { AgentOnly, CurrentAgent, CurrentPrincipal, CurrentUser, Human, HumanOrAgent, type AgentPrincipal, type HumanPrincipal, type Principal } from '../auth/principal';
import { zCents, zCurrency, ZodPipe, zId } from '../common/validation';
import { TransactionsService } from './transactions.service';

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
   * 200 = final outcome (succeeded/failed). 202 = outcome not yet known
   * (unknown / reconciliation_required): do NOT treat as failure; retry the
   * same call (it reconciles, never re-pays) or poll GET /v1/transactions/:id.
   */
  @Post('execute')
  @AgentOnly()
  async execute(@CurrentAgent() agent: AgentPrincipal, @Body(new ZodPipe(ExecuteBody)) body: z.infer<typeof ExecuteBody>, @Res({ passthrough: true }) res: Response) {
    const result = await this.service.execute(agent, body);
    res.status(result.status === 'succeeded' || result.status === 'failed' ? 200 : 202);
    return result;
  }

  @Get(':id')
  @HumanOrAgent()
  get(@CurrentPrincipal() p: Principal, @Param('id') id: string) {
    return p.kind === 'agent' ? this.service.getForAgent(p, id) : this.service.getForUser(p, id);
  }

  /** Manually reconcile a transaction with the payment provider (never re-pays without checking first). */
  @Post(':id/reconcile')
  @Human('admin')
  reconcile(@CurrentUser() user: HumanPrincipal, @Param('id') id: string) {
    return this.service.reconcileForUser(user, id);
  }
}
