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
export const AdvanceBody = z
  .object({
    status: z.enum(SANDBOX_LIFECYCLE as [ObservedStatus, ...ObservedStatus[]]),
    /** Deliver a signed webhook for this change (otherwise only status queries will see it). */
    deliverWebhook: z.boolean().default(true),
    /** Deliver the same event twice (provider-side duplicate). */
    duplicateDelivery: z.boolean().default(false),
  })
  .strict();

/**
 * Moves a sandbox provider payment along its lifecycle and (optionally)
 * delivers the provider's signed webhook through the normal ingestion path,
 * exactly as an external provider would. Shared by the operator endpoint and
 * the org-scoped self-service sandbox endpoint.
 */
export async function advanceSandboxPayment(
  sandbox: SandboxPaymentAdapter,
  events: PaymentEventsService,
  config: AppConfig,
  idempotencyKey: string,
  body: z.infer<typeof AdvanceBody>,
) {
  const updated = await sandbox.advance(idempotencyKey, body.status);
  if (!updated) throw Errors.notFound('Sandbox payment');
  const deliveries: Awaited<ReturnType<PaymentEventsService['ingest']>>[] = [];
  if (body.deliverWebhook) {
    if (!config.sandboxWebhookSecret) throw Errors.unavailable('Webhook secret not configured');
    const signed = sandbox.signEvent(config.sandboxWebhookSecret, {
      id: newId('evt_sbx'), type: `payment.${body.status}`,
      data: { idempotencyKey, providerReference: updated.providerReference, status: body.status },
    });
    for (let i = 0; i < (body.duplicateDelivery ? 2 : 1); i++) {
      deliveries.push(await events.ingest('sandbox', Buffer.from(signed.body), signed.signature));
    }
  }
  return { providerStatus: updated.status, deliveries };
}

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
    return advanceSandboxPayment(this.sandbox(), this.events, this.config, key, body);
  }

  @Get('payments/:idempotencyKey')
  @Bootstrap()
  async ledger(@Param('idempotencyKey') key: string) {
    return { payments: await this.sandbox().ledger(key) };
  }
}
