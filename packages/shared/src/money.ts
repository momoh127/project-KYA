/**
 * Money is always represented as an integer number of minor units (cents).
 * Floating point is never used for amounts.
 */
export const MAX_AMOUNT_CENTS = 100_000_000_000; // $1B per transaction hard ceiling

export function isValidAmountCents(value: unknown): value is number {
  return (
    typeof value === 'number' &&
    Number.isSafeInteger(value) &&
    value > 0 &&
    value <= MAX_AMOUNT_CENTS
  );
}

export function assertAmountCents(value: unknown, field = 'amount'): number {
  if (!isValidAmountCents(value)) {
    throw new RangeError(`${field} must be a positive integer number of cents`);
  }
  return value;
}

const CURRENCY_RE = /^[A-Z]{3}$/;

export function isValidCurrency(value: unknown): value is string {
  return typeof value === 'string' && CURRENCY_RE.test(value);
}

export function formatCents(amountCents: number, currency = 'USD'): string {
  const sign = amountCents < 0 ? '-' : '';
  const abs = Math.abs(amountCents);
  const units = Math.floor(abs / 100).toLocaleString('en-US');
  const cents = String(abs % 100).padStart(2, '0');
  const symbol = currency === 'USD' ? '$' : `${currency} `;
  return `${sign}${symbol}${units}.${cents}`;
}
