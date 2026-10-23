import { describe, expect, it } from 'vitest';
import { DEFAULT_POLICY_RULES, evaluatePurchase, type PolicyFacts } from '@agenttrust/policy-engine';

const NOW = new Date('2026-10-22T12:00:00Z');
const PD_GOOD = 'pd_good';

/** A fully valid $500 purchase. Each test mutates one thing. */
function baseline(): PolicyFacts {
  return {
    now: NOW,
    policy: { id: 'pol_1', version: 3, rules: { ...DEFAULT_POLICY_RULES } },
    agent: { id: 'agt_104', status: 'active' },
    delegation: {
      id: 'dlg_1',
      actions: ['purchase'],
      maxTransactionCents: 500_000,
      monthlyLimitCents: 2_000_000,
      currency: 'USD',
      approvedSupplierIds: null,
      validFrom: new Date('2026-10-01T00:00:00Z'),
      expiresAt: new Date('2026-11-30T23:59:59Z'),
      revokedAt: null,
    },
    request: {
      action: 'purchase',
      supplierId: 'sup_100',
      amountCents: 50_000,
      currency: 'USD',
      paymentDestinationFingerprint: PD_GOOD,
      purchaseOrderId: 'po_200',
      invoiceId: 'inv_900',
    },
    supplier: { id: 'sup_100', status: 'active', verificationStatus: 'verified', paymentDestinationFingerprint: PD_GOOD },
    purchaseOrder: { id: 'po_200', supplierId: 'sup_100', approvedAmountCents: 50_000, committedAmountCents: 0, currency: 'USD', status: 'open' },
    invoice: { id: 'inv_900', supplierId: 'sup_100', purchaseOrderId: 'po_200', amountCents: 50_000, currency: 'USD', status: 'open' },
    invoiceInFlight: false,
    budget: { spentThisPeriodCents: 0 },
    humanApprovalGranted: false,
  };
}

describe('policy engine', () => {
  it('ALLOWs a valid purchase with full positive reason codes', () => {
    const r = evaluatePurchase(baseline());
    expect(r.decision).toBe('ALLOW');
    expect(r.reasonCodes).toEqual(expect.arrayContaining([
      'AGENT_ACTIVE', 'DELEGATION_VALID', 'SUPPLIER_APPROVED', 'PAYEE_VERIFIED',
      'AMOUNT_WITHIN_LIMIT', 'BUDGET_AVAILABLE', 'PO_MATCHED', 'INVOICE_MATCHED', 'APPROVAL_NOT_REQUIRED',
    ]));
    expect(r.policyVersion).toBe(3);
  });

  it('is deterministic', () => {
    expect(evaluatePurchase(baseline())).toEqual(evaluatePurchase(baseline()));
  });

  it('DENYs $5,000 against a $500 approval (amount verification)', () => {
    const f = baseline();
    f.request.amountCents = 500_000;
    const r = evaluatePurchase(f);
    expect(r.decision).toBe('DENY');
    expect(r.reasonCodes).toContain('AMOUNT_EXCEEDS_PO');
    expect(r.reasonCodes).toContain('AMOUNT_MISMATCH_INVOICE');
  });

  it('DENYs amounts over the delegated per-transaction limit', () => {
    const f = baseline();
    f.delegation!.maxTransactionCents = 10_000;
    expect(evaluatePurchase(f).reasonCodes).toContain('AMOUNT_EXCEEDS_TRANSACTION_LIMIT');
  });

  it('sends unknown suppliers to REVIEW that a human click cannot resolve', () => {
    const f = baseline();
    f.request.supplierId = null;
    f.request.purchaseOrderId = null;
    f.request.invoiceId = null;
    f.supplier = null;
    f.purchaseOrder = null;
    f.invoice = null;
    const r = evaluatePurchase(f);
    expect(r.decision).toBe('REVIEW');
    expect(r.reasonCodes).toContain('SUPPLIER_UNKNOWN');
    expect(r.approvable).toBe(false);

    f.humanApprovalGranted = true;
    const r2 = evaluatePurchase(f);
    expect(r2.decision).toBe('REVIEW'); // approval does not bypass supplier verification
  });

  it('can DENY unknown suppliers outright when policy says so', () => {
    const f = baseline();
    f.policy!.rules.unknownSupplier = 'DENY';
    f.request.supplierId = null;
    f.supplier = null;
    f.request.purchaseOrderId = null;
    f.purchaseOrder = null;
    f.request.invoiceId = null;
    f.invoice = null;
    expect(evaluatePurchase(f).decision).toBe('DENY');
  });

  it('DENYs a changed bank account (payee verification)', () => {
    const f = baseline();
    f.request.paymentDestinationFingerprint = 'pd_attacker';
    const r = evaluatePurchase(f);
    expect(r.decision).toBe('DENY');
    expect(r.reasonCodes).toContain('PAYEE_MISMATCH');
  });

  it('DENYs an already-paid invoice and an invoice held by another live authorization', () => {
    const paid = baseline();
    paid.invoice!.status = 'paid';
    expect(evaluatePurchase(paid).reasonCodes).toContain('INVOICE_ALREADY_PAID');

    const inFlight = baseline();
    inFlight.invoiceInFlight = true;
    expect(evaluatePurchase(inFlight).reasonCodes).toContain('INVOICE_IN_FLIGHT');
  });

  it('DENYs when the budget would be exceeded', () => {
    const f = baseline();
    f.budget.spentThisPeriodCents = 1_980_000;
    const r = evaluatePurchase(f);
    expect(r.decision).toBe('DENY');
    expect(r.reasonCodes).toContain('BUDGET_EXCEEDED');
  });

  it('DENYs inactive agents and missing/expired/revoked/out-of-scope delegations', () => {
    const suspended = baseline();
    suspended.agent!.status = 'revoked';
    expect(evaluatePurchase(suspended).reasonCodes).toContain('AGENT_NOT_ACTIVE');

    const none = baseline();
    none.delegation = null;
    expect(evaluatePurchase(none).reasonCodes).toContain('DELEGATION_MISSING');

    const expired = baseline();
    expired.delegation!.expiresAt = new Date('2026-10-01T00:00:00Z');
    expect(evaluatePurchase(expired).reasonCodes).toContain('DELEGATION_EXPIRED');

    const revoked = baseline();
    revoked.delegation!.revokedAt = new Date('2026-10-20T00:00:00Z');
    expect(evaluatePurchase(revoked).reasonCodes).toContain('DELEGATION_REVOKED');

    const scoped = baseline();
    scoped.delegation!.approvedSupplierIds = ['sup_other'];
    expect(evaluatePurchase(scoped).reasonCodes).toContain('SUPPLIER_NOT_DELEGATED');
  });

  it('DENYs PO and invoice inconsistencies', () => {
    const wrongSupplierPo = baseline();
    wrongSupplierPo.purchaseOrder!.supplierId = 'sup_999';
    expect(evaluatePurchase(wrongSupplierPo).reasonCodes).toContain('PO_SUPPLIER_MISMATCH');

    const poNotFound = baseline();
    poNotFound.purchaseOrder = null;
    expect(evaluatePurchase(poNotFound).reasonCodes).toContain('PO_NOT_FOUND');

    const poConsumed = baseline();
    poConsumed.purchaseOrder!.committedAmountCents = 10_000;
    expect(evaluatePurchase(poConsumed).reasonCodes).toContain('AMOUNT_EXCEEDS_PO');

    const invWrongPo = baseline();
    invWrongPo.invoice!.purchaseOrderId = 'po_other';
    expect(evaluatePurchase(invWrongPo).reasonCodes).toContain('INVOICE_PO_MISMATCH');
  });

  it('requires human approval at the threshold, and an approval resolves it', () => {
    const f = baseline();
    f.request.amountCents = 300_000;
    f.purchaseOrder!.approvedAmountCents = 300_000;
    f.invoice!.amountCents = 300_000;
    const r = evaluatePurchase(f);
    expect(r.decision).toBe('REVIEW');
    expect(r.reasonCodes).toEqual(['APPROVAL_REQUIRED']);
    expect(r.approvable).toBe(true);

    f.humanApprovalGranted = true;
    const approved = evaluatePurchase(f);
    expect(approved.decision).toBe('ALLOW');
    expect(approved.reasonCodes).toContain('APPROVAL_GRANTED');
  });

  it('an approval never overrides a DENY', () => {
    const f = baseline();
    f.request.amountCents = 300_000;
    f.humanApprovalGranted = true; // PO is only $500
    expect(evaluatePurchase(f).decision).toBe('DENY');
  });

  it('fails closed with no policy or an invalid request', () => {
    const noPolicy = baseline();
    noPolicy.policy = null;
    expect(evaluatePurchase(noPolicy).decision).toBe('DENY');

    for (const amountCents of [0, -1, 10.5, Number.NaN]) {
      const bad = baseline();
      bad.request.amountCents = amountCents;
      const r = evaluatePurchase(bad);
      expect(r.decision).toBe('DENY');
      expect(r.reasonCodes).toContain('REQUEST_INVALID');
    }
  });
});
