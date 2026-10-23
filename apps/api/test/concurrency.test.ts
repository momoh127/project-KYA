/**
 * Concurrency across agents. Agent budgets are per agent (serialized by the
 * Agent row lock), but a purchase order's capacity is SHARED across agents.
 * It must be protected by a lock on the shared record itself (the
 * PurchaseOrder row), not by any agent lock. These tests fire simultaneous
 * requests from different agents against one PO.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createWorld, purchase, startServer, uniq, type Agent, type TestServer, type World } from './helpers';

let server: TestServer;
let world: World;
let agentA: Agent;
let agentB: Agent;
const future = () => new Date(Date.now() + 7 * 86_400_000).toISOString();

beforeAll(async () => {
  server = await startServer();
  world = await createWorld(server.baseUrl, 'Shared PO Corp');
  agentA = await world.createAgent('Agent A', { maxTransactionCents: 500_000, monthlyLimitCents: 50_000_000 });
  agentB = await world.createAgent('Agent B', { maxTransactionCents: 500_000, monthlyLimitCents: 50_000_000 });
});
afterAll(async () => server?.close());

/** One shared PO; each agent gets its own instruction on it and `n` invoices of `each` cents. */
async function sharedPo(poCents: number, each: number, nPerAgent: number) {
  const po = await world.admin.post<{ id: string }>('/v1/purchase-orders', {
    supplierId: world.supplierId, externalReference: `PO-${uniq()}`, approvedAmountCents: poCents, currency: 'USD',
  });
  const requests: { agent: Agent; body: Parameters<typeof purchase>[1] }[] = [];
  for (const agent of [agentA, agentB]) {
    const sku = `PART-${uniq()}`;
    const ins = await world.admin.post<{ id: string }>('/v1/purchase-instructions', {
      agentId: agent.id, supplierId: world.supplierId, purchaseOrderId: po.id, fulfillmentType: 'physical_goods', currency: 'USD',
      lines: [{ lineNumber: 1, sku, description: 'Part', quantity: String(nPerAgent), unitPriceCents: each }],
      maxAmountCents: Math.min(poCents, each * nPerAgent), maxUses: nPerAgent, expiresAt: future(),
    });
    await world.approver.post(`/v1/purchase-instructions/${ins.id}/approve`, {});
    for (let i = 0; i < nPerAgent; i++) {
      const inv = await world.admin.post<{ id: string }>('/v1/invoices', {
        supplierId: world.supplierId, purchaseOrderId: po.id, purchaseInstructionId: ins.id, invoiceNumber: `INV-${uniq()}`,
        amountCents: each, currency: 'USD',
        lines: [{ lineNumber: 1, instructionLineNumber: 1, sku, description: 'Part', quantity: '1', unitPriceCents: each }],
      });
      requests.push({ agent, body: { supplierId: world.supplierId, poId: po.id, instructionId: ins.id, invoiceId: inv.id, amountCents: each } });
    }
  }
  return requests;
}

describe('two agents drawing against the same purchase order', () => {
  it('two agents racing for capacity only one of them can have: exactly one wins, every round', async () => {
    for (let round = 0; round < 12; round++) {
      const requests = await sharedPo(100_000, 60_000, 1); // $1,000 PO; A and B each want $600 at the same instant
      const results = await Promise.all(requests.map((r) => purchase(r.agent, r.body)));
      expect(results.filter((r) => r.decision === 'ALLOW'), `round ${round}`).toHaveLength(1);
    }
  });

  it('simultaneous requests from two agents never exceed the shared PO amount (repeated rounds)', async () => {
    for (let round = 0; round < 3; round++) {
      const requests = await sharedPo(100_000, 40_000, 2); // $1,000 PO; 4 × $400 requested at once
      const results = await Promise.all(requests.map((r) => purchase(r.agent, r.body)));
      const allowed = results.filter((r) => r.decision === 'ALLOW');
      expect(allowed).toHaveLength(2); // $800 fits; a third $400 would exceed $1,000
      expect(allowed.reduce((s, r) => s + r.amountCents, 0)).toBeLessThanOrEqual(100_000);
      for (const d of results.filter((r) => r.decision !== 'ALLOW')) expect(d.reasonCodes).toContain('AMOUNT_EXCEEDS_PO');
    }
  });

  it('stress: six agents racing for one PO never overspend it', async () => {
    const extra = await Promise.all([3, 4, 5, 6].map((i) => world.createAgent(`Agent ${i}`, { maxTransactionCents: 500_000, monthlyLimitCents: 50_000_000 })));
    for (let round = 0; round < 5; round++) {
      const po = await world.admin.post<{ id: string }>('/v1/purchase-orders', { supplierId: world.supplierId, externalReference: `PO-${uniq()}`, approvedAmountCents: 100_000, currency: 'USD' });
      const reqs = await Promise.all([agentA, agentB, ...extra].map(async (agent) => {
        const sku = `PART-${uniq()}`;
        const ins = await world.admin.post<{ id: string }>('/v1/purchase-instructions', {
          agentId: agent.id, supplierId: world.supplierId, purchaseOrderId: po.id, fulfillmentType: 'physical_goods', currency: 'USD',
          lines: [{ lineNumber: 1, sku, description: 'Part', quantity: '1', unitPriceCents: 40_000 }], expiresAt: future(),
        });
        await world.approver.post(`/v1/purchase-instructions/${ins.id}/approve`, {});
        const inv = await world.admin.post<{ id: string }>('/v1/invoices', {
          supplierId: world.supplierId, purchaseOrderId: po.id, purchaseInstructionId: ins.id, invoiceNumber: `INV-${uniq()}`, amountCents: 40_000, currency: 'USD',
          lines: [{ lineNumber: 1, instructionLineNumber: 1, sku, description: 'Part', quantity: '1', unitPriceCents: 40_000 }],
        });
        return { agent, body: { supplierId: world.supplierId, poId: po.id, instructionId: ins.id, invoiceId: inv.id, amountCents: 40_000 } };
      }));
      const results = await Promise.all(reqs.map((r) => purchase(r.agent, r.body)));
      expect(results.filter((r) => r.decision === 'ALLOW'), `round ${round}`).toHaveLength(2); // 2 × $400 ≤ $1,000 < 3 × $400
    }
  });

  it('ten simultaneous requests (five per agent) allocate exactly the PO capacity', async () => {
    const requests = await sharedPo(100_000, 20_000, 5); // $1,000 PO; 10 × $200
    const results = await Promise.all(requests.map((r) => purchase(r.agent, r.body)));
    const allowed = results.filter((r) => r.decision === 'ALLOW');
    expect(allowed).toHaveLength(5);
    expect(allowed.reduce((s, r) => s + r.amountCents, 0)).toBe(100_000);
  });
});
