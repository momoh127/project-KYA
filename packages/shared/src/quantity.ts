import { canonicalJson } from './canonical';
import { sha256Hex } from './hash';

/**
 * Exact quantity arithmetic. Quantities are decimal strings with at most 3
 * fractional digits ("2", "2.5", "0.125") stored as integer thousandths
 * ("milli-units"). Line totals must be an EXACT number of cents; anything that
 * would need rounding is rejected rather than silently rounded.
 */
export const QUANTITY_SCALE = 1000n;
const QUANTITY_RE = /^(\d{1,12})(?:\.(\d{1,3}))?$/;

export function parseQuantity(input: string): bigint {
  const m = QUANTITY_RE.exec(input);
  if (!m) throw new RangeError('quantity must be a positive decimal with at most 3 fractional digits');
  const whole = BigInt(m[1]!);
  const frac = BigInt((m[2] ?? '').padEnd(3, '0') || '0');
  const milli = whole * QUANTITY_SCALE + frac;
  if (milli <= 0n) throw new RangeError('quantity must be greater than zero');
  return milli;
}

export function formatQuantity(milli: bigint | number): string {
  const v = BigInt(milli);
  const whole = v / QUANTITY_SCALE;
  const frac = v % QUANTITY_SCALE;
  return frac === 0n ? whole.toString() : `${whole}.${frac.toString().padStart(3, '0').replace(/0+$/, '')}`;
}

/** quantity × unit price, or null when the result is not an exact number of cents. */
export function exactLineTotal(quantityMilli: bigint, unitPriceCents: bigint): bigint | null {
  const product = quantityMilli * unitPriceCents;
  return product % QUANTITY_SCALE === 0n ? product / QUANTITY_SCALE : null;
}

/** A line being paid, mapped to a line of the approved purchase instruction. */
export interface PaymentLine {
  instructionLineNumber: number;
  sku: string | null;
  quantityMilli: number;
  unitPriceCents: number;
  lineTotalCents: number;
}

/** Order-independent hash of a set of payment lines. */
export function linesHash(lines: PaymentLine[]): string {
  const sorted = [...lines].sort((a, b) => a.instructionLineNumber - b.instructionLineNumber);
  return `ln_${sha256Hex(
    canonicalJson(
      sorted.map((l) => ({
        n: l.instructionLineNumber,
        sku: l.sku,
        q: l.quantityMilli,
        p: l.unitPriceCents,
        t: l.lineTotalCents,
      })),
    ),
  )}`;
}

export function toSafeNumber(v: bigint, field = 'value'): number {
  const n = Number(v);
  if (!Number.isSafeInteger(n)) throw new RangeError(`${field} out of safe range`);
  return n;
}
