import { Inject, Injectable, Logger } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { z } from 'zod';
import { hmacSha256Hex, IdPrefix, newId, safeEqual, sha256Hex } from '@agenttrust/shared';
import { APP_CONFIG, type AppConfig } from '../config';
import { ApiError, Errors } from '../common/errors';
import { PrismaService } from '../common/prisma.service';
import { SecurityMonitorService } from '../security/security-monitor.service';
import { SANDBOX_LIFECYCLE } from './payment-adapter';
import { TransactionsService } from './transactions.service';

const SIGNATURE_TOLERANCE_SECONDS = 300;

const SandboxEvent = z
  .object({
    id: z.string().min(1).max(200),
    type: z.string().regex(/^payment\.[a-z_]+$/),
    created: z.number().int(),
    data: z
      .object({
        idempotencyKey: z.string().min(1).max(200),
        providerReference: z.string().max(200).nullable().optional(),
        status: z.enum(SANDBOX_LIFECYCLE as [string, ...string[]]),
      })
      .strict(),
  })
  .strict();

/**
 * Ingests payment-provider events (webhooks):
 *  1. verifies the provider signature and timestamp (replay window),
 *  2. deduplicates on (provider, event id); a redelivered identical event is a
 *     no-op, a DIFFERENT payload under the same event id is rejected + alerted,
 *  3. applies the observed state through the transaction state machine, which
 *     ignores stale or out-of-order events.
 * Every event is recorded with its outcome.
 */
@Injectable()
export class PaymentEventsService {
  private readonly logger = new Logger('PaymentEvents');

  constructor(
    private readonly prisma: PrismaService,
    private readonly transactions: TransactionsService,
    private readonly security: SecurityMonitorService,
    @Inject(APP_CONFIG) private readonly config: AppConfig,
  ) {}

  async ingest(provider: string, rawBody: Buffer, signatureHeader: string | undefined) {
    if (provider !== 'sandbox') throw Errors.notFound('Provider');
    const secret = this.config.sandboxWebhookSecret;
    if (!secret) throw Errors.unavailable('Webhook secret not configured; events are refused');

    // 1. Signature: "t=<unix>,v1=<hex hmac(secret, `${t}.${body}`)>"
    const m = /^t=(\d{1,12}),v1=([a-f0-9]{64})$/.exec(signatureHeader ?? '');
    if (!m) throw Errors.unauthenticated('Missing or malformed webhook signature');
    const t = Number(m[1]);
    if (Math.abs(Math.floor(Date.now() / 1000) - t) > SIGNATURE_TOLERANCE_SECONDS) throw Errors.unauthenticated('Webhook timestamp outside allowed window');
    const expected = hmacSha256Hex(secret, Buffer.concat([Buffer.from(`${t}.`), rawBody]));
    if (!safeEqual(expected, m[2]!)) throw Errors.unauthenticated('Invalid webhook signature');

    let event: z.infer<typeof SandboxEvent>;
    try {
      event = SandboxEvent.parse(JSON.parse(rawBody.toString('utf8')));
    } catch {
      throw Errors.invalid('Malformed webhook payload');
    }
    const payloadHash = sha256Hex(rawBody);

    // 2. Deduplicate.
    const id = newId(IdPrefix.providerEvent);
    try {
      await this.prisma.providerEvent.create({
        data: {
          id, provider, eventId: event.id, type: event.type, idempotencyKey: event.data.idempotencyKey, payloadHash,
          outcome: 'received', occurredAt: new Date(event.created * 1000),
        },
      });
    } catch (e) {
      if (!(e instanceof Prisma.PrismaClientKnownRequestError && e.code === 'P2002')) throw e;
      const prior = await this.prisma.providerEvent.findUniqueOrThrow({ where: { provider_eventId: { provider, eventId: event.id } } });
      if (prior.payloadHash === payloadHash) return { received: true, duplicate: true, outcome: prior.outcome };
      if (prior.organizationId && prior.transactionId) {
        await this.security.raiseAlert(prior.organizationId, prior.transactionId, 'provider_event_conflict', new Date(0), {
          severity: 'high', provider, eventId: event.id,
          message: 'The payment provider sent two different payloads under the same event id. The second was rejected; investigate.',
        });
      }
      throw new ApiError(409, 'EVENT_CONFLICT', 'A different payload was already received under this event id');
    }

    // 3. Apply through the state machine.
    const txn = await this.prisma.transaction.findUnique({ where: { providerIdempotencyKey: event.data.idempotencyKey } });
    if (!txn) {
      await this.prisma.providerEvent.update({ where: { id }, data: { outcome: 'unknown_transaction' } });
      this.logger.warn(`event ${event.id} for unknown payment ${event.data.idempotencyKey}`);
      return { received: true, duplicate: false, outcome: 'unknown_transaction' };
    }
    const applied = await this.transactions.applyObserved(
      txn.id,
      event.data.status as Parameters<TransactionsService['applyObserved']>[1],
      event.data.providerReference ?? null,
      `webhook:${provider}:${event.id}`,
      `provider event ${event.type}`,
    );
    await this.prisma.providerEvent.update({
      where: { id },
      data: { outcome: applied.outcome, transactionId: txn.id, organizationId: txn.organizationId },
    });
    return { received: true, duplicate: false, outcome: applied.outcome, transactionStatus: applied.transaction.status };
  }
}
