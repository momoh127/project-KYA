import {
  combineOutcomes,
  formatCents,
  isValidAmountCents,
  isValidCurrency,
  ReasonCode as R,
  safeEqual,
  type CheckResult,
} from '@agenttrust/shared';
import type { PaymentLineFacts, PolicyFacts, PolicyResult } from './types';

/**
 * Deterministic purchase authorization.
 *
 * This function is pure: given the same facts it always returns the same
 * result. It performs no I/O and calls no AI model. All facts must be loaded
 * by the caller from trusted records (database), never from agent claims.
 *
 * Every check runs (no short-circuit) so the caller gets a complete
 * explanation. Combination rule: any DENY -> DENY, else any REVIEW -> REVIEW,
 * else ALLOW. Missing inputs fail closed.
 */
export function evaluatePurchase(facts: PolicyFacts): PolicyResult {
  const checks: CheckResult[] = [];
  const pass = (code: CheckResult['code'], message: string) =>
    checks.push({ code, outcome: 'pass', message });
  const deny = (code: CheckResult['code'], message: string) =>
    checks.push({ code, outcome: 'deny', message });
  const review = (code: CheckResult['code'], message: string, approvable: boolean) =>
    checks.push({ code, outcome: 'review', message, approvable });

  const { request: req, now } = facts;
  const money = (c: number) => formatCents(c, req.currency);

  // ---- 0. Request sanity + policy presence (fail closed) -------------------
  if (!isValidAmountCents(req.amountCents) || !isValidCurrency(req.currency) || req.action !== 'purchase') {
    deny(R.REQUEST_INVALID, 'Request has an invalid amount, currency, or action.');
    return finalize(checks, facts);
  }
  const policy = facts.policy;
  if (!policy) {
    deny(R.POLICY_MISSING, 'No active policy for this organization; failing closed.');
    return finalize(checks, facts);
  }
  pass(R.POLICY_ACTIVE, `Policy v${policy.version} applied.`);
  const rules = policy.rules;

  // ---- 1. Agent -------------------------------------------------------------
  if (facts.agent?.status === 'active') pass(R.AGENT_ACTIVE, 'Agent is active.');
  else deny(R.AGENT_NOT_ACTIVE, `Agent is ${facts.agent?.status ?? 'unknown'}.`);

  // ---- 2. Delegation (human-granted authority) -------------------------------
  const d = facts.delegation;
  if (!d) {
    deny(R.DELEGATION_MISSING, 'No delegation grants this agent purchasing authority.');
  } else if (d.revokedAt && d.revokedAt <= now) {
    deny(R.DELEGATION_REVOKED, 'Delegation has been revoked.');
  } else if (d.validFrom > now) {
    deny(R.DELEGATION_NOT_YET_VALID, 'Delegation is not yet valid.');
  } else if (d.expiresAt <= now) {
    deny(R.DELEGATION_EXPIRED, 'Delegation has expired.');
  } else if (!d.actions.includes(req.action)) {
    deny(R.ACTION_NOT_DELEGATED, `Delegation does not include "${req.action}".`);
  } else if (d.currency !== req.currency) {
    deny(R.CURRENCY_NOT_DELEGATED, `Delegation is for ${d.currency}, not ${req.currency}.`);
  } else {
    pass(R.DELEGATION_VALID, 'Delegation is valid and covers this action.');
  }

  // ---- 3. Payee verification --------------------------------------------------
  const s = facts.supplier;
  if (!s) {
    review(R.SUPPLIER_UNKNOWN, 'Payee is not a known supplier. Onboard and verify the supplier first.', false);
    if (rules.unknownSupplier === 'DENY') {
      deny(R.SUPPLIER_UNKNOWN, 'Policy denies payments to unknown suppliers.');
    }
    review(R.PAYEE_UNVERIFIABLE, 'Payment destination cannot be verified against a supplier record.', false);
  } else {
    if (s.status === 'blocked') {
      deny(R.SUPPLIER_BLOCKED, 'Supplier is blocked.');
    } else if (s.verificationStatus !== 'verified') {
      review(R.SUPPLIER_UNVERIFIED, `Supplier verification is "${s.verificationStatus}".`, false);
    } else {
      pass(R.SUPPLIER_APPROVED, 'Supplier is approved and verified.');
    }

    if (d?.approvedSupplierIds && !d.approvedSupplierIds.includes(s.id)) {
      deny(R.SUPPLIER_NOT_DELEGATED, 'Supplier is not in the delegation\'s approved list.');
    }

    if (!s.paymentDestinationFingerprint) {
      review(R.PAYEE_UNVERIFIABLE, 'Supplier has no verified payment destination on file.', false);
    } else if (!safeEqual(s.paymentDestinationFingerprint, req.paymentDestinationFingerprint)) {
      deny(R.PAYEE_MISMATCH, 'Payment destination does not match the verified supplier record.');
    } else if (s.verificationStatus === 'verified') {
      pass(R.PAYEE_VERIFIED, 'Payment destination matches the verified supplier record.');
    } else {
      review(R.PAYEE_UNVERIFIABLE, 'Payment destination matches an unverified supplier record.', false);
    }
  }

  // ---- 4. Amount: delegation limits + budget ---------------------------------
  if (d) {
    if (req.amountCents > d.maxTransactionCents) {
      deny(R.AMOUNT_EXCEEDS_TRANSACTION_LIMIT,
        `${money(req.amountCents)} exceeds the agent's per-transaction limit of ${money(d.maxTransactionCents)}.`);
    } else {
      pass(R.AMOUNT_WITHIN_LIMIT, `${money(req.amountCents)} is within the ${money(d.maxTransactionCents)} limit.`);
    }

    const remaining = d.monthlyLimitCents - facts.budget.spentThisPeriodCents;
    if (req.amountCents > remaining) {
      deny(R.BUDGET_EXCEEDED,
        `${money(req.amountCents)} exceeds remaining monthly budget of ${money(Math.max(0, remaining))}.`);
    } else {
      pass(R.BUDGET_AVAILABLE, `Remaining monthly budget ${money(remaining)} covers this purchase.`);
    }
  }

  // ---- 5. Purchase order -------------------------------------------------------
  const po = facts.purchaseOrder;
  if (!req.purchaseOrderId) {
    if (rules.missingPurchaseOrder === 'DENY') deny(R.PO_MISSING, 'Policy requires a purchase order.');
    else review(R.PO_MISSING, 'No purchase order referenced; human approval required.', true);
  } else if (!po) {
    deny(R.PO_NOT_FOUND, 'Referenced purchase order does not exist.');
  } else {
    const before = checks.length;
    if (po.status !== 'open') deny(R.PO_NOT_OPEN, `Purchase order is ${po.status}.`);
    if (po.supplierId !== req.supplierId) deny(R.PO_SUPPLIER_MISMATCH, 'Purchase order is for a different supplier.');
    if (po.currency !== req.currency) deny(R.PO_CURRENCY_MISMATCH, 'Purchase order currency differs.');
    const poRemaining = po.approvedAmountCents - po.committedAmountCents;
    if (req.amountCents > poRemaining) {
      deny(R.AMOUNT_EXCEEDS_PO,
        `${money(req.amountCents)} exceeds the purchase order's remaining approved amount of ${money(Math.max(0, poRemaining))}.`);
    }
    if (checks.length === before) pass(R.PO_MATCHED, 'Purchase order matches supplier, currency and amount.');
  }

  // ---- 6. Invoice / duplicate protection ---------------------------------------
  const inv = facts.invoice;
  if (!req.invoiceId) {
    if (rules.missingInvoice === 'DENY') deny(R.INVOICE_MISSING, 'Policy requires an invoice.');
    else if (rules.missingInvoice === 'REVIEW') review(R.INVOICE_MISSING, 'No invoice referenced; human approval required.', true);
    else pass(R.INVOICE_NOT_REFERENCED, 'No invoice referenced (allowed by policy).');
  } else if (!inv) {
    deny(R.INVOICE_NOT_FOUND, 'Referenced invoice does not exist.');
  } else {
    const before = checks.length;
    if (inv.status === 'paid') deny(R.INVOICE_ALREADY_PAID, 'Invoice has already been paid.');
    else if (inv.status === 'void') deny(R.INVOICE_VOID, 'Invoice is void.');
    else if (inv.status === 'processing') deny(R.INVOICE_IN_FLIGHT, 'A payment for this invoice is in flight (accepted, processing or being reconciled).');
    else if (inv.status === 'payment_exception') deny(R.INVOICE_PAYMENT_EXCEPTION, 'A previous payment for this invoice failed after acceptance, was returned or reversed; it must be reconciled and explicitly released first.');
    else if (facts.invoiceInFlight) deny(R.INVOICE_IN_FLIGHT, 'Invoice is already held by another live authorization.');
    if (inv.supplierId !== req.supplierId) deny(R.INVOICE_SUPPLIER_MISMATCH, 'Invoice is from a different supplier.');
    if (req.purchaseOrderId && inv.purchaseOrderId !== req.purchaseOrderId) {
      deny(R.INVOICE_PO_MISMATCH, 'Invoice is not linked to the referenced purchase order.');
    }
    if (inv.currency !== req.currency) deny(R.INVOICE_CURRENCY_MISMATCH, 'Invoice currency differs.');
    if (inv.instructionId && inv.instructionId !== req.purchaseInstructionId) {
      deny(R.INVOICE_INSTRUCTION_MISMATCH, 'Invoice bills a different purchase instruction.');
    }
    if (inv.amountCents !== req.amountCents) {
      deny(R.AMOUNT_MISMATCH_INVOICE,
        `${money(req.amountCents)} does not match the invoice amount of ${money(inv.amountCents)}.`);
    }
    if (checks.length === before) pass(R.INVOICE_MATCHED, 'Invoice matches and has not been paid.');
  }

  // ---- 6b. Purchase instruction: does this payment match independently approved business intent?
  const paymentLines = checkInstruction(facts, { pass, deny, review }, money);

  // ---- 6c. Three-way match (PO → receipt → invoice) -------------------------------
  checkReceipts(facts, paymentLines, { pass, deny, review });

  // ---- 7. Human approval threshold ------------------------------------------------
  if (rules.reviewThresholdCents !== null && req.amountCents >= rules.reviewThresholdCents) {
    if (facts.humanApprovalGranted) pass(R.APPROVAL_GRANTED, 'A human approver approved this exact transaction.');
    else review(R.APPROVAL_REQUIRED,
      `Amounts of ${money(rules.reviewThresholdCents)} or more require human approval.`, true);
  } else {
    pass(R.APPROVAL_NOT_REQUIRED, 'Amount is below the human approval threshold.');
  }

  return finalize(checks, facts, paymentLines);
}

type Recorders = {
  pass: (code: CheckResult['code'], message: string) => void;
  deny: (code: CheckResult['code'], message: string) => void;
  review: (code: CheckResult['code'], message: string, approvable: boolean) => void;
};

/**
 * Verifies the payment against an independently approved purchase instruction:
 * right agent, supplier, currency, PO, validity, remaining uses/amount, and the
 * exact approved line items (item, unit price, remaining quantity), with an
 * exact line-total check. Returns the lines this decision covers.
 */
function checkInstruction(facts: PolicyFacts, r: Recorders, money: (c: number) => string): PaymentLineFacts[] | null {
  const { request: req, now } = facts;
  const ins = facts.instruction;
  const rules = facts.policy!.rules;

  if (!req.purchaseInstructionId) {
    if (rules.missingInstruction === 'DENY') r.deny(R.INSTRUCTION_MISSING, 'Policy requires an approved purchase instruction.');
    else r.review(R.INSTRUCTION_MISSING, 'No approved purchase instruction referenced. A human must create and approve one; the agent then resubmits.', false);
    return null;
  }
  if (!ins) {
    r.deny(R.INSTRUCTION_NOT_FOUND, 'Referenced purchase instruction does not exist.');
    return null;
  }

  let problems = 0;
  const deny = (code: CheckResult['code'], msg: string) => { problems++; r.deny(code, msg); };

  if (ins.status === 'revoked') deny(R.INSTRUCTION_REVOKED, 'Purchase instruction has been revoked.');
  else if (ins.status === 'rejected') deny(R.INSTRUCTION_REJECTED, 'Purchase instruction was rejected.');
  else if (ins.status !== 'approved') {
    problems++;
    r.review(R.INSTRUCTION_NOT_APPROVED, 'Purchase instruction is awaiting independent approval.', false);
  }
  if (ins.validFrom > now) deny(R.INSTRUCTION_NOT_YET_VALID, 'Purchase instruction is not yet valid.');
  if (ins.expiresAt <= now) deny(R.INSTRUCTION_EXPIRED, 'Purchase instruction has expired.');
  if (ins.agentId !== req.agentId) deny(R.INSTRUCTION_AGENT_MISMATCH, 'Purchase instruction is assigned to a different agent.');
  if (ins.supplierId !== req.supplierId) deny(R.INSTRUCTION_SUPPLIER_MISMATCH, 'Purchase instruction is for a different supplier.');
  if (ins.currency !== req.currency) deny(R.INSTRUCTION_CURRENCY_MISMATCH, `Purchase instruction is in ${ins.currency}; currencies are never converted.`);
  if (ins.purchaseOrderId !== req.purchaseOrderId) deny(R.INSTRUCTION_PO_MISMATCH, 'Purchase order does not match the purchase instruction.');

  const usage = facts.instructionUsage;
  if (usage.uses >= ins.maxUses) deny(R.INSTRUCTION_USES_EXHAUSTED, `Purchase instruction allows ${ins.maxUses} use(s); all are used or held.`);
  const remaining = ins.maxAmountCents - usage.amountCents;
  if (req.amountCents > remaining) {
    deny(R.AMOUNT_EXCEEDS_INSTRUCTION, `${money(req.amountCents)} exceeds the instruction's remaining ${money(Math.max(0, remaining))}.`);
  }

  // Lines: trusted invoice lines take precedence; agent lines only if the invoice has none.
  const invoiceLines = facts.invoice?.lines ?? [];
  const requestLines = req.lines;
  let lines: PaymentLineFacts[] | null = null;
  if (invoiceLines.length > 0) {
    lines = invoiceLines;
    if (requestLines && requestLines.length > 0 && !sameLines(invoiceLines, requestLines)) {
      deny(R.LINES_CONFLICT, 'Agent-supplied lines differ from the recorded invoice lines.');
    }
  } else if (requestLines && requestLines.length > 0) {
    lines = requestLines;
  }

  if (!lines) {
    deny(R.LINES_REQUIRED, 'The payment must identify which approved instruction lines it pays.');
  } else {
    const seen = new Set<number>();
    let total = 0n;
    for (const line of lines) {
      total += BigInt(line.lineTotalCents);
      if (line.instructionLineNumber === null) {
        deny(R.LINE_NOT_IN_INSTRUCTION, 'A billed line is not mapped to the purchase instruction.');
        continue;
      }
      if (seen.has(line.instructionLineNumber)) {
        deny(R.LINE_DUPLICATED, `Instruction line ${line.instructionLineNumber} appears more than once.`);
        continue;
      }
      seen.add(line.instructionLineNumber);
      const approved = ins.lines.find((l) => l.lineNumber === line.instructionLineNumber);
      if (!approved) {
        deny(R.LINE_NOT_IN_INSTRUCTION, `Line ${line.instructionLineNumber} is not part of the approved instruction.`);
        continue;
      }
      if (approved.sku !== null && line.sku !== approved.sku) {
        deny(R.LINE_ITEM_MISMATCH, `Line ${line.instructionLineNumber} item "${line.sku ?? '(none)'}" differs from approved item "${approved.sku}".`);
      }
      if (line.unitPriceCents !== approved.unitPriceCents) {
        deny(R.LINE_PRICE_MISMATCH, `Line ${line.instructionLineNumber} unit price ${money(line.unitPriceCents)} differs from approved ${money(approved.unitPriceCents)}.`);
      }
      const exact = exactTotal(line.quantityMilli, line.unitPriceCents);
      if (exact === null || exact !== BigInt(line.lineTotalCents)) {
        deny(R.LINE_TOTAL_INVALID, `Line ${line.instructionLineNumber} total is not exactly quantity × unit price.`);
      }
      const used = usage.quantityMilliByLine[line.instructionLineNumber] ?? 0;
      if (used + line.quantityMilli > approved.quantityMilli) {
        deny(R.LINE_QUANTITY_EXCEEDS_INSTRUCTION, `Line ${line.instructionLineNumber} quantity exceeds what remains on the approved instruction.`);
      }
    }
    if (total !== BigInt(req.amountCents)) {
      deny(R.LINES_TOTAL_MISMATCH, `Lines total ${money(Number(total))} does not equal the payment amount ${money(req.amountCents)}.`);
    }
  }

  if (problems === 0) r.pass(R.INSTRUCTION_MATCHED, `Matches approved instruction v${ins.version}: agent, supplier, items, quantities, prices and remaining amount.`);
  return lines;
}

const RECEIPT_TYPE_FOR = {
  physical_goods: 'goods_received',
  services: 'service_completed',
  subscription: 'subscription_activated',
  digital_goods: 'digital_delivered',
} as const;

const REQUIREMENT_KEY = {
  physical_goods: 'physicalGoods',
  services: 'services',
  subscription: 'subscription',
  digital_goods: 'digitalGoods',
} as const;

/** Three-way match: billed quantities must not exceed what was confirmed received/completed. */
function checkReceipts(facts: PolicyFacts, lines: PaymentLineFacts[] | null, r: Recorders): void {
  const ins = facts.instruction;
  const rules = facts.policy!.rules.threeWayMatch;
  if (!ins || !rules.enabled) return;
  const requirement = rules[REQUIREMENT_KEY[ins.fulfillmentType]];
  const missing = (code: CheckResult['code'], msg: string) =>
    facts.policy!.rules.missingReceipt === 'DENY' ? r.deny(code, msg) : r.review(code, `${msg} Record the confirmation, then resubmit.`, false);

  if (requirement === 'none') {
    r.pass(R.RECEIPT_NOT_REQUIRED, `Policy does not require confirmation for ${ins.fulfillmentType}.`);
    return;
  }
  if (requirement === 'human_approval') {
    if (facts.humanApprovalGranted) r.pass(R.ALTERNATIVE_APPROVAL_REQUIRED, `${ins.fulfillmentType} approved by a human (alternative to receipt).`);
    else r.review(R.ALTERNATIVE_APPROVAL_REQUIRED, `Policy requires human approval for ${ins.fulfillmentType} purchases.`, true);
    return;
  }

  const type = RECEIPT_TYPE_FOR[ins.fulfillmentType];
  const relevant = facts.receipts.filter((x) => x.type === type);
  if (relevant.length === 0) {
    missing(R.RECEIPT_MISSING, `No ${type.replace('_', ' ')} confirmation recorded for this instruction.`);
    return;
  }
  const received: Record<number, number> = {};
  for (const rc of relevant) for (const l of rc.lines) received[l.instructionLineNumber] = (received[l.instructionLineNumber] ?? 0) + l.quantityMilli;
  const short = (lines ?? []).filter((l) => {
    if (l.instructionLineNumber === null) return false;
    const billed = (facts.instructionUsage.quantityMilliByLine[l.instructionLineNumber] ?? 0) + l.quantityMilli;
    return (received[l.instructionLineNumber] ?? 0) < billed;
  });
  if (short.length > 0) {
    missing(R.RECEIPT_QUANTITY_INSUFFICIENT, `Billed quantity exceeds confirmed ${type.replace('_', ' ')} quantity on line(s) ${short.map((l) => l.instructionLineNumber).join(', ')}.`);
    return;
  }
  r.pass(R.RECEIPT_MATCHED, `Billed quantities are covered by recorded ${type.replace('_', ' ')} confirmations.`);
}

function exactTotal(quantityMilli: number, unitPriceCents: number): bigint | null {
  const product = BigInt(quantityMilli) * BigInt(unitPriceCents);
  return product % 1000n === 0n ? product / 1000n : null;
}

function sameLines(a: PaymentLineFacts[], b: PaymentLineFacts[]): boolean {
  const key = (l: PaymentLineFacts) => `${l.instructionLineNumber}|${l.sku}|${l.quantityMilli}|${l.unitPriceCents}|${l.lineTotalCents}`;
  const sa = a.map(key).sort();
  const sb = b.map(key).sort();
  return sa.length === sb.length && sa.every((v, i) => v === sb[i]);
}

function finalize(checks: CheckResult[], facts: PolicyFacts, paymentLines: PaymentLineFacts[] | null = null): PolicyResult {
  // A human approval resolves approvable REVIEW checks only (missing PO,
  // approval threshold). Supplier/payee reviews are never resolvable by click.
  const effective: CheckResult[] = checks.map((c) =>
    c.outcome === 'review' && c.approvable && facts.humanApprovalGranted
      ? { ...c, outcome: 'pass', message: `${c.message} (accepted by human approver)` }
      : c,
  );

  const decision = combineOutcomes(effective.map((c) => c.outcome));
  const failing = effective.filter((c) => c.outcome !== 'pass');
  const reasonCodes = [...new Set((decision === 'ALLOW' ? effective : failing).map((c) => c.code))];
  const approvable = decision === 'REVIEW' && failing.every((c) => c.outcome === 'review' && c.approvable === true);

  return {
    decision,
    checks: effective,
    reasonCodes,
    policyId: facts.policy?.id ?? null,
    policyVersion: facts.policy?.version ?? null,
    approvable,
    paymentLines,
  };
}
