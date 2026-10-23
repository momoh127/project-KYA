import { Body, Controller, Get, Inject, Param, Post } from '@nestjs/common';
import { z } from 'zod';
import { Bootstrap } from '../auth/principal';
import { DevTokenService } from '../auth/human-token';
import { Errors } from '../common/errors';
import { ZodPipe } from '../common/validation';
import { PAYMENT_ADAPTER, SANDBOX_FAULTS, SandboxPaymentAdapter, type PaymentAdapter } from './payment-adapter';

const FaultsBody = z.object({ faults: z.array(z.enum(SANDBOX_FAULTS)).min(1).max(20) }).strict();

/**
 * DEVELOPMENT ONLY: fault injection and ledger inspection for the sandbox
 * payment provider. Requires the bootstrap token and dev mode.
 */
@Controller('v1/dev/sandbox')
export class SandboxController {
  constructor(
    @Inject(PAYMENT_ADAPTER) private readonly payments: PaymentAdapter,
    @Inject(DevTokenService) private readonly dev: DevTokenService,
  ) {}

  private sandbox(): SandboxPaymentAdapter {
    if (!this.dev.enabled || !(this.payments instanceof SandboxPaymentAdapter)) throw Errors.notFound('Endpoint');
    return this.payments;
  }

  /** Queue provider faults (FIFO), e.g. ["crash_after_processing"]. */
  @Post('faults')
  @Bootstrap()
  async faults(@Body(new ZodPipe(FaultsBody)) body: z.infer<typeof FaultsBody>) {
    await this.sandbox().queueFaults(body.faults);
    return { queued: body.faults };
  }

  /** The provider's own ledger for an idempotency key: proves how many payments really happened. */
  @Get('payments/:idempotencyKey')
  @Bootstrap()
  async ledger(@Param('idempotencyKey') key: string) {
    return { payments: await this.sandbox().ledger(key) };
  }
}
