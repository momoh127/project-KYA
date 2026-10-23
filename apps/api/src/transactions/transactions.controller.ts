import { Body, Controller, Get, Param, Post } from '@nestjs/common';
import { z } from 'zod';
import { AgentOnly, CurrentAgent, CurrentPrincipal, HumanOrAgent, type AgentPrincipal, type Principal } from '../auth/principal';
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

  /** The enforcing payment gateway: the only path from an agent to money. */
  @Post('execute')
  @AgentOnly()
  execute(@CurrentAgent() agent: AgentPrincipal, @Body(new ZodPipe(ExecuteBody)) body: z.infer<typeof ExecuteBody>) {
    return this.service.execute(agent, body);
  }

  @Get(':id')
  @HumanOrAgent()
  get(@CurrentPrincipal() p: Principal, @Param('id') id: string) {
    return p.kind === 'agent' ? this.service.getForAgent(p, id) : this.service.getForUser(p, id);
  }
}
