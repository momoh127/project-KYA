import { PipeTransform } from '@nestjs/common';
import { z, type ZodTypeAny } from 'zod';
import { isValidAmountCents, isValidCurrency } from '@agenttrust/shared';
import { Errors } from './errors';

/**
 * Validates request bodies with strict Zod schemas. Unknown fields are
 * rejected, so callers can never smuggle in fields like `organizationId`
 * or `approved: true`; identity and tenancy come only from credentials.
 */
export class ZodPipe<S extends ZodTypeAny> implements PipeTransform<unknown, z.infer<S>> {
  constructor(private readonly schema: S) {}

  transform(value: unknown): z.infer<S> {
    const result = this.schema.safeParse(value);
    if (!result.success) {
      throw Errors.invalid(
        'Request validation failed',
        result.error.issues.map((i) => ({ path: i.path.join('.'), message: i.message })),
      );
    }
    return result.data;
  }
}

export const zCents = z.number().refine(isValidAmountCents, 'must be a positive integer number of cents');
export const zCurrency = z.string().refine(isValidCurrency, 'must be a 3-letter ISO 4217 code');
export const zId = (prefix: string) => z.string().regex(new RegExp(`^${prefix}_[a-f0-9]{32}$`), `must be a ${prefix}_ id`);
export const zPaymentDestination = z.discriminatedUnion('type', [
  z.object({ type: z.literal('us_ach'), routingNumber: z.string().max(32), accountNumber: z.string().max(34) }).strict(),
  z.object({ type: z.literal('iban'), iban: z.string().max(42) }).strict(),
]);
