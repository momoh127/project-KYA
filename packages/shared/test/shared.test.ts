import { describe, expect, it } from 'vitest';
import {
  canonicalJson,
  combineOutcomes,
  formatCents,
  paymentDestinationFingerprint,
  transactionFingerprint,
  type TransactionIntent,
} from '@agenttrust/shared';

const PEPPER = 'test-pepper-0123456789-0123456789-abcdef';

describe('canonicalJson', () => {
  it('sorts keys and is stable regardless of insertion order', () => {
    expect(canonicalJson({ b: 1, a: { d: true, c: null } })).toBe('{"a":{"c":null,"d":true},"b":1}');
    expect(canonicalJson({ a: { c: null, d: true }, b: 1 })).toBe(canonicalJson({ b: 1, a: { d: true, c: null } }));
  });

  it('omits undefined members but rejects floats, dates and undefined array items', () => {
    expect(canonicalJson({ a: undefined, b: 'x' })).toBe('{"b":"x"}');
    expect(() => canonicalJson({ amount: 10.5 })).toThrow();
    expect(() => canonicalJson({ at: new Date() })).toThrow();
    expect(() => canonicalJson([undefined])).toThrow();
  });
});

describe('payment destination fingerprint', () => {
  it('normalizes formatting so the same account yields the same fingerprint', () => {
    const a = paymentDestinationFingerprint(PEPPER, { type: 'us_ach', routingNumber: '021000021', accountNumber: '123456789' });
    const b = paymentDestinationFingerprint(PEPPER, { type: 'us_ach', routingNumber: '0210-00021', accountNumber: '1234 56789' });
    expect(a).toBe(b);
  });

  it('changes when a single digit changes, and depends on the secret pepper', () => {
    const a = paymentDestinationFingerprint(PEPPER, { type: 'us_ach', routingNumber: '021000021', accountNumber: '123456789' });
    const b = paymentDestinationFingerprint(PEPPER, { type: 'us_ach', routingNumber: '021000021', accountNumber: '123456780' });
    const c = paymentDestinationFingerprint(`${PEPPER}-other`, { type: 'us_ach', routingNumber: '021000021', accountNumber: '123456789' });
    expect(a).not.toBe(b);
    expect(a).not.toBe(c);
  });

  it('rejects weak peppers and malformed bank details', () => {
    expect(() => paymentDestinationFingerprint('short', { type: 'iban', iban: 'DE89370400440532013000' })).toThrow();
    expect(() => paymentDestinationFingerprint(PEPPER, { type: 'us_ach', routingNumber: '123', accountNumber: '1234' })).toThrow();
  });
});

describe('transactionFingerprint', () => {
  const base: TransactionIntent = {
    organizationId: 'org_1',
    agentId: 'agt_1',
    action: 'purchase',
    supplierId: 'sup_1',
    paymentDestinationFingerprint: 'pd_abc',
    amountCents: 50_000,
    currency: 'USD',
    purchaseOrderId: 'po_1',
    invoiceId: 'inv_1',
  };

  it('binds every field', () => {
    const fp = transactionFingerprint(base);
    const variants: Partial<TransactionIntent>[] = [
      { amountCents: 50_001 },
      { supplierId: 'sup_2' },
      { paymentDestinationFingerprint: 'pd_def' },
      { invoiceId: 'inv_2' },
      { purchaseOrderId: null },
      { agentId: 'agt_2' },
      { organizationId: 'org_2' },
      { currency: 'EUR' },
    ];
    for (const v of variants) expect(transactionFingerprint({ ...base, ...v })).not.toBe(fp);
    expect(transactionFingerprint({ ...base })).toBe(fp);
  });
});

describe('combineOutcomes / formatCents', () => {
  it('DENY dominates REVIEW dominates ALLOW; empty fails closed', () => {
    expect(combineOutcomes(['pass', 'review', 'deny'])).toBe('DENY');
    expect(combineOutcomes(['pass', 'review'])).toBe('REVIEW');
    expect(combineOutcomes(['pass'])).toBe('ALLOW');
    expect(combineOutcomes([])).toBe('DENY');
  });

  it('formats integer cents', () => {
    expect(formatCents(480_000)).toBe('$4,800.00');
    expect(formatCents(5)).toBe('$0.05');
  });
});
