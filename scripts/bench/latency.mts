/**
 * Local latency lower bound for authorize + execute against a sandbox.
 *   AGENTTRUST_BASE_URL=http://localhost:4000 npx tsx scripts/bench/latency.mts
 * Creates a throwaway sandbox org; disables its risk controls so 60 rapid purchases are not throttled.
 */
import { AgentTrustSandbox, SANDBOX_SUPPLIER_BANK } from '@agenttrust/sdk';
const baseUrl = process.env.AGENTTRUST_BASE_URL!;
const inDays = (d: number) => new Date(Date.now() + d * 864e5).toISOString();
const { sandbox } = await AgentTrustSandbox.signup({ baseUrl, organizationName: 'Bench', email: 'bench@example.com' });
const admin = sandbox.as('admin'), approver = sandbox.as('approver');
const { supplierId } = await sandbox.createVerifiedSupplier();
const agent = await sandbox.registerAgent();
await approver.delegations.create({ agentId: agent.agentId, actions: ['purchase'], currency: 'USD', maxTransactionCents: 100_000, monthlyLimitCents: 100_000_000, expiresAt: inDays(30) });
const policies = await admin.policies.list(); const active = policies.policies.find((p) => p.status === 'active')!;
await admin.policies.update(active.id, { ...active.rules, riskControls: { ...(active.rules as any).riskControls, enabled: false } });
const N = 60, authMs: number[] = [], execMs: number[] = [];
for (let i = 0; i < N; i++) {
  const po = await admin.purchaseOrders.create({ supplierId, externalReference: `PO-${i}-${Date.now()}`, approvedAmountCents: 1000, currency: 'USD' });
  const lines = [{ lineNumber: 1, sku: 'S', description: 'Item', quantity: '1', unitPriceCents: 1000 }];
  const ins = await admin.instructions.create({ agentId: agent.agentId, supplierId, purchaseOrderId: po.id, fulfillmentType: 'digital_goods', currency: 'USD', lines, expiresAt: inDays(2) });
  await approver.instructions.approve(ins.id);
  const inv = await admin.invoices.create({ supplierId, purchaseOrderId: po.id, purchaseInstructionId: ins.id, invoiceNumber: `INV-${i}-${Date.now()}`, amountCents: 1000, currency: 'USD', lines: lines.map((l) => ({ ...l, instructionLineNumber: 1 })) });
  let t = performance.now();
  const a = await agent.client.authorizations.create({ idempotencyKey: `bench-${i}-${Date.now()}`, action: 'purchase', supplierId, payee: SANDBOX_SUPPLIER_BANK, amountCents: 1000, currency: 'USD', purchaseOrderId: po.id, invoiceId: inv.id, purchaseInstructionId: ins.id });
  authMs.push(performance.now() - t);
  if (a.decision !== 'ALLOW') { console.log('not allowed', a.reasonCodes.filter((c) => !c.endsWith('MATCHED'))); continue; }
  t = performance.now();
  await agent.client.transactions.execute({ token: a.token!, expected: { supplierId, amountCents: 1000, currency: 'USD', purchaseOrderId: po.id, invoiceId: inv.id } });
  execMs.push(performance.now() - t);
}
const pct = (xs: number[], p: number) => { const s = [...xs].sort((a, b) => a - b); return s[Math.min(s.length - 1, Math.floor((p / 100) * s.length))]!.toFixed(1); };
const drop = (xs: number[]) => xs.slice(5); // warm-up
console.log(`authorize: n=${drop(authMs).length} p50=${pct(drop(authMs), 50)}ms p95=${pct(drop(authMs), 95)}ms`);
console.log(`execute:   n=${drop(execMs).length} p50=${pct(drop(execMs), 50)}ms p95=${pct(drop(execMs), 95)}ms`);
