import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { AgentTrustError, AgentTrustSandbox, SANDBOX_SUPPLIER_BANK } from '@agenttrust/sdk';
import { startServer, uniq, type TestServer } from './helpers';

/**
 * The TypeScript SDK as an external developer uses it: only the typed public
 * surface (no raw paths), against a self-service sandbox.
 */
let server: TestServer;
beforeAll(async () => {
  server = await startServer();
});
afterAll(async () => {
  await server.close();
});

const inAWeek = () => new Date(Date.now() + 7 * 86_400_000).toISOString();

async function setup() {
  const { sandbox, account } = await AgentTrustSandbox.signup({ baseUrl: server.baseUrl, organizationName: `SDK Eval ${uniq()}`, email: `sdk+${uniq()}@eval.test` });
  const admin = sandbox.as('admin');
  const approver = sandbox.as('approver');
  const { supplierId } = await sandbox.createVerifiedSupplier();
  const agent = await sandbox.registerAgent();
  await approver.delegations.create({
    agentId: agent.agentId, actions: ['purchase'], currency: 'USD', maxTransactionCents: 100_000, monthlyLimitCents: 500_000, expiresAt: inAWeek(),
  });
  const po = await admin.purchaseOrders.create({ supplierId, externalReference: `PO-${uniq()}`, approvedAmountCents: 48_000, currency: 'USD' });
  const lines = [{ lineNumber: 1, sku: 'DRL-100', description: 'Cordless drill', quantity: '4', unitPriceCents: 12_000 }];
  const instruction = await admin.instructions.create({
    agentId: agent.agentId, supplierId, purchaseOrderId: po.id, fulfillmentType: 'physical_goods', currency: 'USD', lines, expiresAt: inAWeek(),
  });
  await approver.instructions.approve(instruction.id, 'Approved in sandbox');
  const invoice = await admin.invoices.create({
    supplierId, purchaseOrderId: po.id, purchaseInstructionId: instruction.id, invoiceNumber: `INV-${uniq()}`, amountCents: 48_000, currency: 'USD',
    lines: lines.map((l) => ({ ...l, instructionLineNumber: l.lineNumber })),
  });
  return { sandbox, account, admin, approver, agent, supplierId, poId: po.id, instructionId: instruction.id, invoiceId: invoice.id };
}

describe('TypeScript SDK against the hosted sandbox', () => {
  it('quickstart path: ALLOW → execute → settle → invoice paid, then the agent can see its instruction is used up', async () => {
    const w = await setup();
    const { instructions } = await w.agent.client.instructions.list();
    expect(instructions.map((i) => i.id)).toContain(w.instructionId);

    const auth = await w.agent.client.authorizations.create({
      idempotencyKey: `buy-${uniq()}`, action: 'purchase', supplierId: w.supplierId, payee: SANDBOX_SUPPLIER_BANK, amountCents: 48_000, currency: 'USD',
      purchaseOrderId: w.poId, invoiceId: w.invoiceId, purchaseInstructionId: w.instructionId,
    });
    expect(auth.decision).toBe('ALLOW');
    const tx = await w.agent.client.transactions.execute({
      token: auth.token!, expected: { supplierId: w.supplierId, amountCents: 48_000, currency: 'USD', purchaseOrderId: w.poId, invoiceId: w.invoiceId },
    });
    expect(tx.status).toBe('accepted');

    const advanced = await w.sandbox.advancePayment(tx.id, 'settled');
    expect(advanced.transactionStatus).toBe('settled');
    expect((await w.admin.invoices.get(w.invoiceId)).status).toBe('paid');
    expect((await w.admin.transactions.get(tx.id)).status).toBe('settled');
    expect((await w.admin.audit.verify()).valid).toBe(true);
    expect((await w.sandbox.progress()).completed).toBe(true);
  });

  it('a payee that differs from the verified supplier record is DENIED, and no token is issued', async () => {
    const w = await setup();
    const auth = await w.agent.client.authorizations.create({
      idempotencyKey: `buy-${uniq()}`, action: 'purchase', supplierId: w.supplierId,
      payee: { type: 'us_ach', routingNumber: '026009593', accountNumber: '9999000011' },
      amountCents: 48_000, currency: 'USD', purchaseOrderId: w.poId, invoiceId: w.invoiceId, purchaseInstructionId: w.instructionId,
    });
    expect(auth.decision).toBe('DENY');
    expect(auth.token).toBeUndefined();
  });

  it('errors are typed: executing without a valid token throws AgentTrustError (fail closed)', async () => {
    const w = await setup();
    const err = await w.agent.client.transactions
      .execute({ token: 'not-a-token', expected: { supplierId: w.supplierId, amountCents: 48_000, currency: 'USD', purchaseOrderId: w.poId, invoiceId: w.invoiceId } })
      .catch((e) => e);
    expect(err).toBeInstanceOf(AgentTrustError);
    expect(err.status).toBeGreaterThanOrEqual(400);
  });

  it('agents cannot use admin capabilities: the agent client has no write path to instructions', async () => {
    const w = await setup();
    expect(Object.keys(w.agent.client.instructions).sort()).toEqual(['get', 'list']);
  });

  it('persona tokens are cached and refreshed transparently', async () => {
    const w = await setup();
    const t1 = await w.sandbox.token('admin');
    const t2 = await w.sandbox.token('admin');
    expect(t1).toBe(t2);
    expect((await w.admin.users.list()).users.length).toBe(3);
  });
});
