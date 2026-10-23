import {
  combineOutcomes,
  formatCents,
  isValidAmountCents,
  isValidCurrency,
  ReasonCode as R,
  safeEqual,
  type CheckResult,
} from '@agenttrust/shared';
import type { PolicyFacts, PolicyResult } from './types';

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
    else if (facts.invoiceInFlight) deny(R.INVOICE_IN_FLIGHT, 'Invoice is already held by another live authorization.');
    if (inv.supplierId !== req.supplierId) deny(R.INVOICE_SUPPLIER_MISMATCH, 'Invoice is from a different supplier.');
    if (req.purchaseOrderId && inv.purchaseOrderId !== req.purchaseOrderId) {
      deny(R.INVOICE_PO_MISMATCH, 'Invoice is not linked to the referenced purchase order.');
    }
    if (inv.currency !== req.currency) deny(R.INVOICE_CURRENCY_MISMATCH, 'Invoice currency differs.');
    if (inv.amountCents !== req.amountCents) {
      deny(R.AMOUNT_MISMATCH_INVOICE,
        `${money(req.amountCents)} does not match the invoice amount of ${money(inv.amountCents)}.`);
    }
    if (checks.length === before) pass(R.INVOICE_MATCHED, 'Invoice matches and has not been paid.');
  }

  // ---- 7. Human approval threshold ------------------------------------------------
  if (rules.reviewThresholdCents !== null && req.amountCents >= rules.reviewThresholdCents) {
    if (facts.humanApprovalGranted) pass(R.APPROVAL_GRANTED, 'A human approver approved this exact transaction.');
    else review(R.APPROVAL_REQUIRED,
      `Amounts of ${money(rules.reviewThresholdCents)} or more require human approval.`, true);
  } else {
    pass(R.APPROVAL_NOT_REQUIRED, 'Amount is below the human approval threshold.');
  }

  return finalize(checks, facts);
}

function finalize(checks: CheckResult[], facts: PolicyFacts): PolicyResult {
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
  };
}
