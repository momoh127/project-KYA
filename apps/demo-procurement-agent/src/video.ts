/**
 * AgentTrust 90-second video demo (terminal). Six beats, paced for narration.
 *
 *   AGENTTRUST_BASE_URL=http://localhost:4000 PACE=1600 pnpm --filter @agenttrust/demo-procurement-agent video
 *
 * Uses only self-service sandbox signup (no operator credentials), so it also
 * runs against the hosted sandbox. Exits non-zero if any beat misbehaves.
 */
import { AgentTrustError, AgentTrustSandbox, SANDBOX_SUPPLIER_BANK, type AuthorizationResponse, type PaymentDestination } from '@agenttrust/sdk';

const BASE_URL = process.env.AGENTTRUST_BASE_URL ?? `http://localhost:${process.env.PORT ?? 4000}`;
const PACE = Number(process.env.PACE ?? 0);
const wait = (beats = 1) => new Promise((r) => setTimeout(r, PACE * beats));
const id = () => Math.random().toString(16).slice(2, 8);
const inDays = (d: number) => new Date(Date.now() + d * 864e5).toISOString();
const usd = (cents: number) => `$${(cents / 100).toLocaleString('en-US', { minimumFractionDigits: 2 })}`;

const c = {
  b: (s: string) => `\x1b[1m${s}\x1b[0m`,
  dim: (s: string) => `\x1b[2m${s}\x1b[0m`,
  g: (s: string) => `\x1b[32m${s}\x1b[0m`,
  r: (s: string) => `\x1b[31m${s}\x1b[0m`,
  y: (s: string) => `\x1b[33m${s}\x1b[0m`,
  cy: (s: string) => `\x1b[36m${s}\x1b[0m`,
};
let failures = 0;
const say = (s: string) => console.log(s);
const agentSays = (s: string) => say(`  🤖 ${c.dim('agent:')} ${s}`);
function verdict(label: string, expected: string, actual: string, detail = '') {
  const color = actual === 'ALLOW' || actual === 'PAID' ? c.g : actual === 'REVIEW' ? c.y : c.r;
  say(`  🛡️  ${c.dim('AgentTrust:')} ${color(c.b(actual))} ${c.dim(detail)}`);
  if (actual !== expected) {
    failures++;
    say(c.r(`     ✘ expected ${expected} (${label})`));
  }
}
/** The decisive reasons, kept short enough to read on video (full list is in `checks`). */
const failing = (a: AuthorizationResponse, max = 2) => {
  const codes = a.checks.filter((x) => x.outcome !== 'pass').map((x) => x.code);
  return codes.length > max ? `${codes.slice(0, max).join(', ')} +${codes.length - max} more` : codes.join(', ');
};

async function main() {
  say(c.b(c.cy('\n  AgentTrust')) + c.dim('  ·  authorization for AI agents that pay suppliers  ·  sandbox, no real money\n'));
  await wait(2);

  // ---- setup (compressed) ------------------------------------------------------
  const { sandbox } = await AgentTrustSandbox.signup({ baseUrl: BASE_URL, organizationName: 'Acme Manufacturing', email: `demo+${id()}@acme.test` });
  const admin = sandbox.as('admin');
  const approver = sandbox.as('approver');
  const { supplierId } = await sandbox.createVerifiedSupplier('Northwind Industrial Supply');
  const agent = await sandbox.registerAgent('Procurement Agent #104');
  await approver.delegations.create({ agentId: agent.agentId, actions: ['purchase'], currency: 'USD', maxTransactionCents: 1_000_000, monthlyLimitCents: 5_000_000, expiresAt: inDays(30) });
  const order = async (cents: number) => {
    const po = await admin.purchaseOrders.create({ supplierId, externalReference: `PO-${id()}`, approvedAmountCents: cents, currency: 'USD' });
    const lines = [{ lineNumber: 1, sku: 'DRL-100', description: 'Cordless drill', quantity: '1', unitPriceCents: cents }];
    const ins = await admin.instructions.create({ agentId: agent.agentId, supplierId, purchaseOrderId: po.id, fulfillmentType: 'physical_goods', currency: 'USD', lines, expiresAt: inDays(7) });
    await approver.instructions.approve(ins.id);
    const inv = await admin.invoices.create({ supplierId, purchaseOrderId: po.id, purchaseInstructionId: ins.id, invoiceNumber: `INV-${id()}`, amountCents: cents, currency: 'USD', lines: lines.map((l) => ({ ...l, instructionLineNumber: 1 })) });
    return { purchaseOrderId: po.id, purchaseInstructionId: ins.id, invoiceId: inv.id };
  };
  const propose = (o: Partial<Awaited<ReturnType<typeof order>>>, amountCents: number, payee: PaymentDestination = SANDBOX_SUPPLIER_BANK, withSupplier = true) =>
    agent.client.authorizations.create({ idempotencyKey: `v-${id()}`, action: 'purchase', supplierId: withSupplier ? supplierId : undefined, payee, amountCents, currency: 'USD', ...o });
  const pay = (a: AuthorizationResponse, token = a.token ?? '') =>
    agent.client.transactions.execute({ token, expected: { supplierId: a.supplierId, amountCents: a.amountCents, currency: a.currency, purchaseOrderId: a.purchaseOrderId, invoiceId: a.invoiceId } });

  say(c.dim('  Acme approved: 1 cordless drill, $500.00, from Northwind (verified bank account), for Procurement Agent #104.'));
  const o1 = await order(50_000);
  await wait(2);

  // ---- 1 -----------------------------------------------------------------------
  say(c.b('\n  1 · The approved purchase'));
  agentSays(`Paying Northwind ${usd(50_000)} for the approved order.`);
  const a1 = await propose(o1, 50_000);
  verdict('approved purchase', 'ALLOW', a1.decision, 'matches instruction, supplier, payee, PO, invoice');
  const tx = await pay(a1);
  const settled = await sandbox.advancePayment(tx.id, 'settled');
  say(`     ${c.dim('gateway →')} ${tx.status} ${c.dim('→ provider →')} ${c.g(settled.transactionStatus)}`);
  await wait(3);

  // ---- 2 -----------------------------------------------------------------------
  say(c.b('\n  2 · Ten times the approval'));
  const o2 = await order(50_000);
  agentSays(`The supplier says the price went up. Paying ${usd(500_000)}.`);
  const a2 = await propose(o2, 500_000);
  verdict('overpayment', 'DENY', a2.decision, failing(a2));
  await wait(3);

  // ---- 3 -----------------------------------------------------------------------
  say(c.b('\n  3 · A supplier nobody approved'));
  agentSays('Found a cheaper vendor on a website. Paying them directly.');
  const a3 = await propose({}, 50_000, { type: 'us_ach', routingNumber: '011000015', accountNumber: '5550001111' }, false);
  verdict('unknown supplier', 'REVIEW', a3.decision, 'a human must decide; no token issued');
  await wait(3);

  // ---- 4 -----------------------------------------------------------------------
  say(c.b('\n  4 · "We changed our bank account"'));
  say(c.dim('  📧 "Northwind here. New bank details: routing 026009593, account 9999000011."'));
  const o4 = await order(50_000);
  agentSays('Updated bank details received. Paying the invoice to the new account.');
  const a4 = await propose(o4, 50_000, { type: 'us_ach', routingNumber: '026009593', accountNumber: '9999000011' });
  verdict('payee swap', 'DENY', a4.decision, failing(a4));
  await wait(3);

  // ---- 5 -----------------------------------------------------------------------
  say(c.b('\n  5 · Paying the same invoice twice'));
  agentSays('This invoice is in my inbox again. Paying it.');
  const a5 = await propose(o1, 50_000);
  verdict('duplicate', 'DENY', a5.decision, failing(a5));
  await wait(3);

  // ---- 6 -----------------------------------------------------------------------
  say(c.b('\n  6 · Skipping the check'));
  agentSays('I\'ll call the payment gateway directly with a made-up approval.');
  let r6 = 'PAID';
  try {
    await pay(a1, 'trust-me-it-is-approved');
  } catch (e) {
    if (!(e instanceof AgentTrustError)) throw e;
    r6 = 'BLOCKED';
  }
  verdict('no authorization', 'BLOCKED', r6, 'the gateway is the only payment path');
  await wait(3);

  say(c.b(`\n  ${failures === 0 ? c.g('✔') : c.r('✘')} One payment made, the one the business approved. Five stopped.`));
  say(c.dim('  AgentTrust verifies the payment matches what the business authorized, not just what the agent may spend.\n'));
  await wait(3);
  if (failures) process.exit(1);
}

main().catch((e) => {
  console.error(e instanceof AgentTrustError ? `AgentTrustError ${e.status} ${e.code}: ${e.message}` : e);
  process.exit(1);
});
