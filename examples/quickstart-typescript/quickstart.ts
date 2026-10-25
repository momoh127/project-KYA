/**
 * AgentTrust quickstart (TypeScript): from nothing to a settled sandbox payment,
 * then two attacks that the gateway blocks.
 *
 *   AGENTTRUST_BASE_URL=https://<sandbox> npx tsx quickstart.ts
 *
 * Optional: AGENTTRUST_SANDBOX_KEY to reuse an existing sandbox.
 */
import { AgentTrustError, AgentTrustSandbox, SANDBOX_SUPPLIER_BANK, type AuthorizationResponse } from '@agenttrust/sdk';

const baseUrl = process.env.AGENTTRUST_BASE_URL ?? 'http://localhost:4000';
const inDays = (d: number) => new Date(Date.now() + d * 86_400_000).toISOString();
const id = () => Math.random().toString(16).slice(2, 10);
const step = (n: number, text: string) => console.log(`\n${n}. ${text}`);

async function main() {
  // 1. A sandbox organization with three personas (admin = you, verifier, approver).
  step(1, 'Sandbox');
  const sandbox = process.env.AGENTTRUST_SANDBOX_KEY
    ? new AgentTrustSandbox({ baseUrl, sandboxKey: process.env.AGENTTRUST_SANDBOX_KEY })
    : await AgentTrustSandbox.signup({ baseUrl, organizationName: 'Quickstart Co', email: `dev+${id()}@example.com` }).then(({ sandbox, account }) => {
        console.log(`   sandbox key (save it, shown once): ${account.sandboxKey}`);
        return sandbox;
      });
  const admin = sandbox.as('admin');
  const approver = sandbox.as('approver');

  // 2. Trusted business records. In production these come from your ERP / procurement tool.
  step(2, 'Supplier with bank details entered by admin and verified by a second admin (dual control)');
  const { supplierId } = await sandbox.createVerifiedSupplier('Northwind Industrial Supply');
  console.log(`   supplier ${supplierId}`);

  // 3. The agent. Its private key stays in the agent runtime (production: sidecar / KMS).
  step(3, 'Register the agent and give it a spending ceiling');
  const agent = await sandbox.registerAgent('Procurement agent');
  await approver.delegations.create({
    agentId: agent.agentId, actions: ['purchase'], currency: 'USD', maxTransactionCents: 100_000, monthlyLimitCents: 500_000, expiresAt: inDays(30),
  });
  console.log(`   agent ${agent.agentId} may spend up to $1,000.00 per payment`);

  // 4. What the business actually approved: 4 drills at $120.00 from this supplier, for this agent, once.
  step(4, 'Approved purchase instruction (created by admin, approved by approver) + PO + invoice');
  const po = await admin.purchaseOrders.create({ supplierId, externalReference: `PO-${id()}`, approvedAmountCents: 48_000, currency: 'USD' });
  const lines = [{ lineNumber: 1, sku: 'DRL-100', description: 'Cordless drill', quantity: '4', unitPriceCents: 12_000 }];
  const instruction = await admin.instructions.create({
    agentId: agent.agentId, supplierId, purchaseOrderId: po.id, fulfillmentType: 'physical_goods', currency: 'USD', lines, maxUses: 1, expiresAt: inDays(7),
  });
  await approver.instructions.approve(instruction.id, 'Quickstart approval');
  const invoice = await admin.invoices.create({
    supplierId, purchaseOrderId: po.id, purchaseInstructionId: instruction.id, invoiceNumber: `INV-${id()}`, amountCents: 48_000, currency: 'USD',
    lines: lines.map((l) => ({ ...l, instructionLineNumber: l.lineNumber })),
  });

  // 5. The agent asks before paying. First, what a compromised agent (or a poisoned invoice) might try.
  step(5, 'Agent requests authorization');
  const request = {
    action: 'purchase' as const, supplierId, payee: SANDBOX_SUPPLIER_BANK, amountCents: 48_000, currency: 'USD',
    purchaseOrderId: po.id, invoiceId: invoice.id, purchaseInstructionId: instruction.id,
  };
  const swapped = await agent.client.authorizations.create({
    ...request, idempotencyKey: `buy-${id()}`, payee: { type: 'us_ach', routingNumber: '026009593', accountNumber: '9999000011' },
  });
  console.log(`   attack: same invoice, bank account changed → ${swapped.decision} (${failing(swapped).join(', ')}), no token issued: ${swapped.token === undefined}`);
  const auth = await agent.client.authorizations.create({ ...request, idempotencyKey: `buy-${id()}` });
  report(auth);
  if (auth.decision !== 'ALLOW' || !auth.token) throw new Error('expected ALLOW');

  // 6. Pay through the gateway: the only payment path the agent has.
  step(6, 'Execute through the enforcing gateway, then the (sandbox) provider settles');
  const expected = { supplierId, amountCents: 48_000, currency: 'USD', purchaseOrderId: po.id, invoiceId: invoice.id };
  const tx = await agent.client.transactions.execute({ token: auth.token, expected });
  console.log(`   transaction ${tx.id}: ${tx.status} (accepted is NOT paid)`);
  const settled = await sandbox.advancePayment(tx.id, 'settled');
  console.log(`   provider webhook → ${settled.transactionStatus}; invoice is now ${(await admin.invoices.get(invoice.id)).status}`);

  // 7. Replaying the single-use token for a different amount.
  step(7, 'Attack: reuse the token for more money');
  try {
    await agent.client.transactions.execute({ token: auth.token, expected: { ...expected, amountCents: 58_000 } });
    console.log('   reuse the token for $580.00 → UNEXPECTEDLY ALLOWED');
    process.exitCode = 1;
  } catch (e) {
    if (!(e instanceof AgentTrustError)) throw e;
    console.log(`   reuse the token for $580.00 → blocked (${e.status} ${e.code})`);
  }
  if (swapped.decision !== 'DENY') process.exitCode = 1;

  const progress = await sandbox.progress();
  console.log(`\nDone: first settled payment ${progress.minutesToFirstSettledPayment} min after signup.`);
}

function failing(a: AuthorizationResponse) {
  return a.checks.filter((c) => c.outcome !== 'pass').map((c) => c.code);
}

function report(a: AuthorizationResponse) {
  console.log(`   decision: ${a.decision}`);
  for (const c of a.checks) console.log(`     ${c.outcome === 'pass' ? '✔' : c.outcome === 'review' ? '…' : '✘'} ${c.code}`);
}

main().catch((e) => {
  console.error(e instanceof AgentTrustError ? `AgentTrustError ${e.status} ${e.code}: ${e.message}` : e);
  process.exit(1);
});
