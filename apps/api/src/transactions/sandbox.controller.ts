import { Body, Controller, Get, Inject, Param, Post, Req } from '@nestjs/common';
import type { Request } from 'express';
import { z } from 'zod';
import { newId } from '@agenttrust/shared';
import { APP_CONFIG, type AppConfig } from '../config';
import { Bootstrap, Public } from '../auth/principal';
import { DevTokenService } from '../auth/human-token';
import { Errors } from '../common/errors';
import { ZodPipe } from '../common/validation';
import { PAYMENT_ADAPTER, SANDBOX_FAULTS, SANDBOX_LIFECYCLE, SandboxPaymentAdapter, type PaymentAdapter } from './payment-adapter';
import { PaymentEventsService } from './payment-events.service';
import type { ObservedStatus } from './lifecycle';

const FaultsBody = z.object({ faults: z.array(z.enum(SANDBOX_FAULTS)).min(1).max(20) }).strict();
const AdvanceBody = z
  .object({
    status: z.enum(SANDBOX_LIFECYCLE as [ObservedStatus, ...ObservedStatus[]]),
    /** Deliver a signed webhook for this change (otherwise only status queries will see it). */
    deliverWebhook: z.boolean().default(true),
    /** Deliver the same event twice (provider-side duplicate). */
    duplicateDelivery: z.boolean().default(false),
  })
  .strict();

/** Payment-provider webhooks. Authenticated by the provider's signature, not by our credentials. */
@Controller('v1/webhooks/payments')
export class WebhooksController {
  constructor(private readonly events: PaymentEventsService) {}

  @Post(':provider')
  @Public()
  receive(@Param('provider') provider: string, @Req() req: Request & { rawBody?: Buffer }) {
    return this.events.ingest(provider, req.rawBody ?? Buffer.alloc(0), req.header('x-sandbox-signature') ?? undefined);
  }
}

/**
 * DEVELOPMENT ONLY: fault injection, provider-lifecycle simulation and ledger
 * inspection for the sandbox payment provider. Requires the bootstrap token
 * and dev mode.
 */
@Controller('v1/dev/sandbox')
export class SandboxController {
  constructor(
    @Inject(PAYMENT_ADAPTER) private readonly payments: PaymentAdapter,
    @Inject(DevTokenService) private readonly dev: DevTokenService,
    @Inject(APP_CONFIG) private readonly config: AppConfig,
    private readonly events: PaymentEventsService,
  ) {}

  private sandbox(): SandboxPaymentAdapter {
    if (!this.dev.enabled || !(this.payments instanceof SandboxPaymentAdapter)) throw Errors.notFound('Endpoint');
    return this.payments;
  }

  @Post('faults')
  @Bootstrap()
  async faults(@Body(new ZodPipe(FaultsBody)) body: z.infer<typeof FaultsBody>) {
    await this.sandbox().queueFaults(body.faults);
    return { queued: body.faults };
  }

  /** Simulates the provider moving a payment along its lifecycle (settle, return, reverse...). */
  @Post('payments/:idempotencyKey/advance')
  @Bootstrap()
  async advance(@Param('idempotencyKey') key: string, @Body(new ZodPipe(AdvanceBody)) body: z.infer<typeof AdvanceBody>) {
    const sandbox = this.sandbox();
    const updated = await sandbox.advance(key, body.status);
    if (!updated) throw Errors.notFound('Sandbox payment');
    const deliveries: unknown[] = [];
    if (body.deliverWebhook) {
      if (!this.config.sandboxWebhookSecret) throw Errors.unavailable('Webhook secret not configured');
      const signed = sandbox.signEvent(this.config.sandboxWebhookSecret, {
        id: newId('evt_sbx'), type: `payment.${body.status}`,
        data: { idempotencyKey: key, providerReference: updated.providerReference, status: body.status },
      });
      for (let i = 0; i < (body.duplicateDelivery ? 2 : 1); i++) {
        deliveries.push(await this.events.ingest('sandbox', Buffer.from(signed.body), signed.signature));
      }
    }
    return { providerStatus: updated.status, deliveries };
  }

  @Get('payments/:idempotencyKey')
  @Bootstrap()
  async ledger(@Param('idempotencyKey') key: string) {
    return { payments: await this.sandbox().ledger(key) };
  }
}
