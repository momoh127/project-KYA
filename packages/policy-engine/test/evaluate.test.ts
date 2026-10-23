import { describe, expect, it } from 'vitest';
import { DEFAULT_POLICY_RULES, evaluatePurchase, type PolicyFacts } from '@agenttrust/policy-engine';

const NOW = new Date('2026-10-22T12:00:00Z');
const PD_GOOD = 'pd_good';

/** A fully valid purchase (default $500). Each test mutates one thing. */
function baseline(amount = 50_000): PolicyFacts {
  const line = { instructionLineNumber: 1, sku: 'SKU-1', quantityMilli: 1000, unitPriceCents: amount, lineTotalCents: amount };
  return {
    now: NOW,
    policy: { id: 'pol_1', version: 3, rules: structuredClone(DEFAULT_POLICY_RULES) },
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
      agentId: 'agt_104',
      purchaseInstructionId: 'pin_1',
      lines: null,
      action: 'purchase',
      supplierId: 'sup_100',
      amountCents: amount,
      currency: 'USD',
      paymentDestinationFingerprint: PD_GOOD,
      purchaseOrderId: 'po_200',
      invoiceId: 'inv_900',
    },
    supplier: { id: 'sup_100', status: 'active', verificationStatus: 'verified', paymentDestinationFingerprint: PD_GOOD },
    purchaseOrder: { id: 'po_200', supplierId: 'sup_100', approvedAmountCents: amount, committedAmountCents: 0, currency: 'USD', status: 'open' },
    invoice: { id: 'inv_900', supplierId: 'sup_100', purchaseOrderId: 'po_200', amountCents: amount, currency: 'USD', status: 'open', instructionId: 'pin_1', lines: [line] },
    instruction: {
      id: 'pin_1',
      version: 1,
      status: 'approved',
      agentId: 'agt_104',
      supplierId: 'sup_100',
      purchaseOrderId: 'po_200',
      fulfillmentType: 'physical_goods',
      currency: 'USD',
      maxAmountCents: amount,
      maxUses: 1,
      validFrom: new Date('2026-10-01T00:00:00Z'),
      expiresAt: new Date('2026-11-30T00:00:00Z'),
      lines: [{ lineNumber: 1, sku: 'SKU-1', quantityMilli: 1000, unitPriceCents: amount }],
    },
    instructionUsage: { uses: 0, amountCents: 0, quantityMilliByLine: {} },
    receipts: [],
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
      'AMOUNT_WITHIN_LIMIT', 'BUDGET_AVAILABLE', 'PO_MATCHED', 'INVOICE_MATCHED', 'INSTRUCTION_MATCHED', 'APPROVAL_NOT_REQUIRED',
    ]));
    expect(r.paymentLines).toHaveLength(1);
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
    f.request.purchaseInstructionId = null;
    f.supplier = null;
    f.purchaseOrder = null;
    f.invoice = null;
    f.instruction = null;
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
    f.request.purchaseInstructionId = null;
    f.instruction = null;
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

    const processing = baseline();
    processing.invoice!.status = 'processing';
    expect(evaluatePurchase(processing).reasonCodes).toContain('INVOICE_IN_FLIGHT');
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
});

describe('purchase instructions (independently approved business intent)', () => {
  it('never ALLOWs without an instruction; REVIEW cannot be click-approved', () => {
    const f = baseline();
    f.request.purchaseInstructionId = null;
    f.instruction = null;
    f.invoice!.instructionId = null;
    const r = evaluatePurchase(f);
    expect(r.decision).toBe('REVIEW');
    expect(r.reasonCodes).toContain('INSTRUCTION_MISSING');
    expect(r.approvable).toBe(false);
    f.humanApprovalGranted = true;
    expect(evaluatePurchase(f).decision).toBe('REVIEW');
    f.policy!.rules.missingInstruction = 'DENY';
    expect(evaluatePurchase(f).decision).toBe('DENY');
  });

  it('DENYs another agent\'s instruction, a revoked/expired one, and a different supplier or PO', () => {
    const other = baseline();
    other.instruction!.agentId = 'agt_999';
    expect(evaluatePurchase(other).reasonCodes).toContain('INSTRUCTION_AGENT_MISMATCH');

    const revoked = baseline();
    revoked.instruction!.status = 'revoked';
    expect(evaluatePurchase(revoked).reasonCodes).toContain('INSTRUCTION_REVOKED');

    const expired = baseline();
    expired.instruction!.expiresAt = new Date('2026-10-22T11:00:00Z');
    expect(evaluatePurchase(expired).reasonCodes).toContain('INSTRUCTION_EXPIRED');

    const po = baseline();
    po.instruction!.purchaseOrderId = 'po_other';
    expect(evaluatePurchase(po).reasonCodes).toContain('INSTRUCTION_PO_MISMATCH');

    const currency = baseline();
    currency.instruction!.currency = 'EUR';
    expect(evaluatePurchase(currency).reasonCodes).toContain('INSTRUCTION_CURRENCY_MISMATCH');
  });

  it('an instruction awaiting approval yields a non-approvable REVIEW', () => {
    const f = baseline();
    f.instruction!.status = 'pending_approval';
    const r = evaluatePurchase(f);
    expect(r.decision).toBe('REVIEW');
    expect(r.reasonCodes).toContain('INSTRUCTION_NOT_APPROVED');
    expect(r.approvable).toBe(false);
  });

  it('DENYs reuse beyond maxUses and amounts beyond what remains', () => {
    const reused = baseline();
    reused.instructionUsage = { uses: 1, amountCents: 50_000, quantityMilliByLine: { 1: 1000 } };
    const r = evaluatePurchase(reused);
    expect(r.reasonCodes).toEqual(expect.arrayContaining(['INSTRUCTION_USES_EXHAUSTED', 'AMOUNT_EXCEEDS_INSTRUCTION', 'LINE_QUANTITY_EXCEEDS_INSTRUCTION']));
  });

  it('DENYs substituted line items, prices, quantities and totals', () => {
    const noInvoiceLines = () => {
      const f = baseline();
      f.invoice!.lines = [];
      return f;
    };
    const sku = noInvoiceLines();
    sku.request.lines = [{ instructionLineNumber: 1, sku: 'GIFT-CARDS', quantityMilli: 1000, unitPriceCents: 50_000, lineTotalCents: 50_000 }];
    expect(evaluatePurchase(sku).reasonCodes).toContain('LINE_ITEM_MISMATCH');

    const price = noInvoiceLines();
    price.request.lines = [{ instructionLineNumber: 1, sku: 'SKU-1', quantityMilli: 500, unitPriceCents: 100_000, lineTotalCents: 50_000 }];
    expect(evaluatePurchase(price).reasonCodes).toContain('LINE_PRICE_MISMATCH');

    const qty = noInvoiceLines();
    qty.request.amountCents = 100_000;
    qty.request.lines = [{ instructionLineNumber: 1, sku: 'SKU-1', quantityMilli: 2000, unitPriceCents: 50_000, lineTotalCents: 100_000 }];
    expect(evaluatePurchase(qty).reasonCodes).toContain('LINE_QUANTITY_EXCEEDS_INSTRUCTION');

    const notInIns = noInvoiceLines();
    notInIns.request.lines = [{ instructionLineNumber: 7, sku: null, quantityMilli: 1000, unitPriceCents: 50_000, lineTotalCents: 50_000 }];
    expect(evaluatePurchase(notInIns).reasonCodes).toContain('LINE_NOT_IN_INSTRUCTION');

    const total = noInvoiceLines();
    total.request.lines = [{ instructionLineNumber: 1, sku: 'SKU-1', quantityMilli: 1000, unitPriceCents: 50_000, lineTotalCents: 49_999 }];
    expect(evaluatePurchase(total).reasonCodes).toEqual(expect.arrayContaining(['LINE_TOTAL_INVALID', 'LINES_TOTAL_MISMATCH']));

    const none = noInvoiceLines();
    expect(evaluatePurchase(none).reasonCodes).toContain('LINES_REQUIRED');

    const conflict = baseline();
    conflict.request.lines = [{ instructionLineNumber: 1, sku: 'OTHER', quantityMilli: 1000, unitPriceCents: 50_000, lineTotalCents: 50_000 }];
    expect(evaluatePurchase(conflict).reasonCodes).toContain('LINES_CONFLICT');
  });

  it('DENYs an invoice that bills a different instruction', () => {
    const f = baseline();
    f.invoice!.instructionId = 'pin_other';
    expect(evaluatePurchase(f).reasonCodes).toContain('INVOICE_INSTRUCTION_MISMATCH');
  });

  it('missing invoice is REVIEW (never ALLOW) by default', () => {
    const f = baseline();
    f.request.invoiceId = null;
    f.invoice = null;
    f.request.lines = [{ instructionLineNumber: 1, sku: 'SKU-1', quantityMilli: 1000, unitPriceCents: 50_000, lineTotalCents: 50_000 }];
    const r = evaluatePurchase(f);
    expect(r.decision).toBe('REVIEW');
    expect(r.reasonCodes).toContain('INVOICE_MISSING');
  });
});

describe('three-way match', () => {
  const withMatching = (fulfillment: 'physical_goods' | 'services' | 'subscription' | 'digital_goods' = 'physical_goods') => {
    const f = baseline();
    f.policy!.rules.threeWayMatch.enabled = true;
    f.instruction!.fulfillmentType = fulfillment;
    return f;
  };

  it('physical goods without a goods receipt → REVIEW (never ALLOW), or DENY by policy', () => {
    const f = withMatching();
    const r = evaluatePurchase(f);
    expect(r.decision).toBe('REVIEW');
    expect(r.reasonCodes).toContain('RECEIPT_MISSING');
    expect(r.approvable).toBe(false);
    f.policy!.rules.missingReceipt = 'DENY';
    expect(evaluatePurchase(f).decision).toBe('DENY');
  });

  it('partial receipt is insufficient; full receipt matches', () => {
    const partial = withMatching();
    partial.receipts = [{ type: 'goods_received', lines: [{ instructionLineNumber: 1, quantityMilli: 500 }] }];
    expect(evaluatePurchase(partial).reasonCodes).toContain('RECEIPT_QUANTITY_INSUFFICIENT');

    const full = withMatching();
    full.receipts = [{ type: 'goods_received', lines: [{ instructionLineNumber: 1, quantityMilli: 1000 }] }];
    const r = evaluatePurchase(full);
    expect(r.decision).toBe('ALLOW');
    expect(r.reasonCodes).toContain('RECEIPT_MATCHED');
  });

  it('the wrong confirmation type does not count (goods receipt ≠ service completion)', () => {
    const f = withMatching('services');
    f.receipts = [{ type: 'goods_received', lines: [{ instructionLineNumber: 1, quantityMilli: 1000 }] }];
    expect(evaluatePurchase(f).reasonCodes).toContain('RECEIPT_MISSING');
    f.receipts = [{ type: 'service_completed', lines: [{ instructionLineNumber: 1, quantityMilli: 1000 }] }];
    expect(evaluatePurchase(f).decision).toBe('ALLOW');
  });

  it('subscriptions use an alternative human-approval workflow; digital goods need nothing by default', () => {
    const sub = withMatching('subscription');
    const r = evaluatePurchase(sub);
    expect(r.decision).toBe('REVIEW');
    expect(r.approvable).toBe(true);
    sub.humanApprovalGranted = true;
    expect(evaluatePurchase(sub).decision).toBe('ALLOW');

    const digital = withMatching('digital_goods');
    expect(evaluatePurchase(digital).reasonCodes).toContain('RECEIPT_NOT_REQUIRED');
  });

  it('requires human approval at the threshold, and an approval resolves it', () => {
    const f = baseline(300_000);
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
