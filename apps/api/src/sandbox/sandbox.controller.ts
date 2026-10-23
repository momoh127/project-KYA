import { Body, Controller, Get, Inject, Param, Post, Req } from '@nestjs/common';
import { Throttle } from '@nestjs/throttler';
import type { Request } from 'express';
import { z } from 'zod';
import { APP_CONFIG, type AppConfig } from '../config';
import { Bootstrap, Public } from '../auth/principal';
import { Errors } from '../common/errors';
import { PrismaService } from '../common/prisma.service';
import { ZodPipe } from '../common/validation';
import { PAYMENT_ADAPTER, SandboxPaymentAdapter, type PaymentAdapter } from '../transactions/payment-adapter';
import { PaymentEventsService } from '../transactions/payment-events.service';
import { AdvanceBody, advanceSandboxPayment } from '../transactions/sandbox.controller';
import { SANDBOX_KEY_HEADER, SANDBOX_PERSONAS, SandboxAccountsService } from './sandbox-accounts.service';

const SignupBody = z
  .object({
    organizationName: z.string().trim().min(1).max(200),
    email: z.string().email().max(320),
  })
  .strict();

const TokenBody = z.object({ persona: z.enum(SANDBOX_PERSONAS) }).strict();

/**
 * Self-service hosted sandbox. Disabled unless AGENTTRUST_SANDBOX_SIGNUP=true
 * (which config refuses in production). Routes are `@Public()` for the global
 * guard because they authenticate with the sandbox key (header
 * `x-agenttrust-sandbox-key`) inside the service; signup itself is
 * unauthenticated and rate-limited per client and platform-wide.
 */
@Controller('v1/sandbox')
export class SandboxOnboardingController {
  constructor(
    private readonly accounts: SandboxAccountsService,
    private readonly prisma: PrismaService,
    private readonly events: PaymentEventsService,
    @Inject(PAYMENT_ADAPTER) private readonly payments: PaymentAdapter,
    @Inject(APP_CONFIG) private readonly config: AppConfig,
  ) {}

  @Post('signup')
  @Public()
  @Throttle({ default: { limit: 20, ttl: 3_600_000 } })
  signup(@Body(new ZodPipe(SignupBody)) body: z.infer<typeof SignupBody>) {
    return this.accounts.signup(body);
  }

  /** Exchanges the sandbox key for a short-lived token for one of the three sandbox personas. */
  @Post('token')
  @Public()
  async token(@Req() req: Request, @Body(new ZodPipe(TokenBody)) body: z.infer<typeof TokenBody>) {
    const account = await this.accounts.authenticate(req.header(SANDBOX_KEY_HEADER));
    return this.accounts.token(account, body.persona);
  }

  /**
   * Plays the payment provider for THIS sandbox's own payments: settle, fail,
   * return or reverse a transaction. The change arrives as a signed provider
   * webhook through the normal ingestion path, so AgentTrust's finality rules
   * (only `settled` pays an invoice) apply exactly as in tests.
   */
  @Post('transactions/:id/advance')
  @Public()
  async advance(@Req() req: Request, @Param('id') id: string, @Body(new ZodPipe(AdvanceBody)) body: z.infer<typeof AdvanceBody>) {
    const account = await this.accounts.authenticate(req.header(SANDBOX_KEY_HEADER));
    if (!(this.payments instanceof SandboxPaymentAdapter)) throw Errors.notFound('Endpoint');
    const tx = await this.prisma.transaction.findUnique({ where: { id } });
    // Tenant isolation: another organization's transaction is indistinguishable from a missing one.
    if (!tx || tx.organizationId !== account.organizationId) throw Errors.notFound('Transaction');
    const result = await advanceSandboxPayment(this.payments, this.events, this.config, tx.providerIdempotencyKey, body);
    const after = await this.prisma.transaction.findUniqueOrThrow({ where: { id } });
    return { transactionId: id, providerStatus: result.providerStatus, transactionStatus: after.status, deliveries: result.deliveries };
  }

  /** How far this sandbox has progressed through the integration, with timings. */
  @Get('progress')
  @Public()
  async progress(@Req() req: Request) {
    return this.accounts.progress(await this.accounts.authenticate(req.header(SANDBOX_KEY_HEADER)));
  }

  /** Platform operator: time-to-first-settled-payment across all sandboxes. */
  @Get('metrics')
  @Bootstrap()
  metrics() {
    if (!this.accounts.enabled) throw Errors.notFound('Endpoint');
    return this.accounts.metrics();
  }
}
