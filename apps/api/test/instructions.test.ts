/**
 * T21: a compromised agent with a VALID session must not be able to pay for
 * anything that does not match an independently approved, currently valid
 * purchase instruction, including ERP-synced instructions and three-way matching.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { AgentTrustAdmin } from '@agenttrust/sdk';
import {
  apiError, createWorld, executeFor, patchPolicy, purchase, rawSession, signedFetch, startServer, uniq,
  type Agent, type TestServer, type World,
} from './helpers';

let server: TestServer;
let world: World;
let agent: Agent;
let otherAgent: Agent;
const future = (days = 7) => new Date(Date.now() + days * 86_400_000).toISOString();

beforeAll(async () => {
  server = await startServer();
  world = await createWorld(server.baseUrl, 'Initech');
  await patchPolicy(world, (r) => ({ ...r, securityResponse: { ...r.securityResponse, violationSuspendThreshold: 100 } }));
  agent = await world.createAgent('Procurement Agent #201', { maxTransactionCents: 500_000, monthlyLimitCents: 5_000_000 });
  otherAgent = await world.createAgent('Procurement Agent #202', { maxTransactionCents: 500_000, monthlyLimitCents: 5_000_000 });
});
afterAll(async () => server?.close());

async function erpClient(scopes: string[], sourceSystem = `erp${uniq()}`) {
  const { token } = await world.admin.post<{ token: string }>('/v1/integrations', { name: `ERP ${sourceSystem}`, sourceSystem, scopes });
  return { erp: new AgentTrustAdmin({ baseUrl: server.baseUrl, accessToken: token }), sourceSystem };
}

function erpInstruction(over: Record<string, unknown> = {}) {
  return {
    externalId: `PR-${uniq()}`, externalVersion: '1', externalUpdatedAt: new Date().toISOString(),
    agentId: agent.id, supplierId: world.supplierId, fulfillmentType: 'physical_goods', currency: 'USD',
    lines: [{ lineNumber: 1, sku: 'DRILL-18V', description: '18V drill', quantity: '2', unitPriceCents: 15_000 }],
    expiresAt: future(),
    erpApproval: { status: 'approved', approvedBy: 'erp-user:jdoe', approvedAt: new Date().toISOString() },
    ...over,
  };
}

describe('agents cannot touch purchase instructions or receipts', () => {
  it('no agent route can create, amend, approve, sync instructions or confirm receipts', async () => {
    const s = await rawSession(server.baseUrl, agent);
    const { instructionId } = await world.order(agent, 10_000);
    const attempts: [string, string, unknown][] = [
      ['POST', '/v1/purchase-instructions', { agentId: agent.id }],
      ['PUT', `/v1/purchase-instructions/${instructionId}`, {}],
      ['POST', `/v1/purchase-instructions/${instructionId}/approve`, {}],
      ['POST', '/v1/integrations/erp/purchase-instructions', erpInstruction()],
      ['POST', '/v1/receipts', { purchaseInstructionId: instructionId, type: 'goods_received', lines: [] }],
      ['POST', '/v1/invoices', {}],
    ];
    for (const [method, path, body] of attempts) {
      const res = await signedFetch(server.baseUrl, s.sessionId, s.privateKeyPem, method as 'POST', path, body);
      expect(res.status, `${method} ${path}`).toBe(401);
    }
    // ...but it can READ the approved instructions assigned to it.
    const { instructions } = await agent.client.instructions.list();
    expect(instructions.some((i) => i.id === instructionId)).toBe(true);
    expect((await apiError(otherAgent.client.instructions.get(instructionId))).status).toBe(404);
  });
});

describe('compromised agent with a valid session', () => {
  it('cannot use another agent\'s instruction', async () => {
    const o = await world.order(otherAgent, 20_000);
    const r = await purchase(agent, { ...o, amountCents: 20_000 });
    expect(r.decision).toBe('DENY');
    expect(r.reasonCodes).toContain('INSTRUCTION_AGENT_MISMATCH');
  });

  it('cannot pay without an instruction (REVIEW that no one can click-approve), or with an invoice billing another instruction', async () => {
    const billed = await world.order(agent, 20_000);
    const mismatch = await purchase(agent, { ...billed, instructionId: undefined, amountCents: 20_000 });
    expect(mismatch.decision).toBe('DENY');
    expect(mismatch.reasonCodes).toContain('INVOICE_INSTRUCTION_MISMATCH');

    const o = await world.order(agent, 20_000, { invoice: false });
    const r = await purchase(agent, { ...o, instructionId: undefined, amountCents: 20_000 });
    expect(r.decision).toBe('REVIEW');
    expect(r.reasonCodes).toContain('INSTRUCTION_MISSING');
    expect((await apiError(world.approver.post(`/v1/authorizations/${r.id}/approve`, {}))).code).toBe('NOT_APPROVABLE');
  });

  it('cannot draw an unrelated purchase on a valid PO for the same supplier (the T21 attack)', async () => {
    const legit = await world.order(agent, 200_000); // a real, approved $2,000 order
    // Attacker submits $1,900 "for something else" against the same valid PO, no instruction.
    const r = await purchase(agent, { supplierId: world.supplierId, poId: legit.poId, amountCents: 190_000 });
    expect(r.decision).not.toBe('ALLOW');
    // ...or reuses the legit instruction with its own lines for a different item.
    const sub = await purchase(agent, {
      supplierId: world.supplierId, poId: legit.poId, instructionId: legit.instructionId, amountCents: 190_000,
      lines: [{ instructionLineNumber: 1, sku: 'GIFT-CARDS', quantity: '1', unitPriceCents: 190_000 }],
    });
    expect(sub.decision).toBe('DENY');
    expect(sub.reasonCodes).toEqual(expect.arrayContaining(['LINE_ITEM_MISMATCH', 'LINE_PRICE_MISMATCH']));
  });

  it('cannot substitute line items: agent lines, supplier invoice lines, prices or quantities', async () => {
    const lines = [
      { lineNumber: 1, sku: 'BEARING-6204', description: 'Bearing', quantity: '10', unitPriceCents: 450 },
      { lineNumber: 2, sku: 'SEAL-6204', description: 'Seal', quantity: '10', unitPriceCents: 150 },
    ];
    // (a) agent-supplied lines with a substituted item (no invoice)
    const a = await world.order(agent, 6_000, { lines, invoice: false });
    const subA = await purchase(agent, { ...a, amountCents: 4_500, lines: [{ instructionLineNumber: 1, sku: 'LAPTOP', quantity: '10', unitPriceCents: 450 }] });
    expect(subA.reasonCodes).toContain('LINE_ITEM_MISMATCH');

    // (b) a recorded supplier invoice that bills a different item / price
    const b = await world.order(agent, 6_000, {
      lines,
      invoiceLines: [
        { lineNumber: 1, instructionLineNumber: 1, sku: 'BEARING-6204', description: 'Bearing', quantity: '10', unitPriceCents: 450 },
        { lineNumber: 2, instructionLineNumber: 2, sku: 'SEAL-PREMIUM', description: 'Seal', quantity: '6', unitPriceCents: 250 },
      ],
    });
    const subB = await purchase(agent, { ...b, amountCents: 6_000 });
    expect(subB.decision).toBe('DENY');
    expect(subB.reasonCodes).toEqual(expect.arrayContaining(['LINE_ITEM_MISMATCH', 'LINE_PRICE_MISMATCH']));

    // (c) more units than approved
    const c = await world.order(agent, 6_000, { lines, invoice: false });
    const subC = await purchase(agent, { ...c, amountCents: 9_000, lines: [{ instructionLineNumber: 1, sku: 'BEARING-6204', quantity: '20', unitPriceCents: 450 }] });
    expect(subC.reasonCodes).toEqual(expect.arrayContaining(['LINE_QUANTITY_EXCEEDS_INSTRUCTION', 'AMOUNT_EXCEEDS_INSTRUCTION']));

    // (d) agent lines that contradict the trusted invoice lines
    const d = await world.order(agent, 6_000, { lines });
    const subD = await purchase(agent, { ...d, amountCents: 6_000, lines: [{ instructionLineNumber: 1, sku: 'BEARING-6204', quantity: '10', unitPriceCents: 600 }] });
    expect(subD.reasonCodes).toContain('LINES_CONFLICT');
  });

  it('cannot reuse a single-use instruction; multi-use instructions are bounded by uses and quantities', async () => {
    const once = await world.order(agent, 12_000);
    const first = await purchase(agent, { ...once, amountCents: 12_000 });
    expect((await executeFor(agent, first)).status).toBe('accepted');
    const inv2 = await world.admin.post<{ id: string }>('/v1/invoices', {
      supplierId: world.supplierId, purchaseOrderId: once.poId, purchaseInstructionId: once.instructionId, invoiceNumber: `INV-${uniq()}`,
      amountCents: 12_000, currency: 'USD', lines: [{ lineNumber: 1, instructionLineNumber: 1, sku: once.sku, description: 'Tooling item', quantity: '1', unitPriceCents: 12_000 }],
    });
    const reuse = await purchase(agent, { ...once, invoiceId: inv2.id, amountCents: 12_000 });
    expect(reuse.decision).toBe('DENY');
    expect(reuse.reasonCodes).toEqual(expect.arrayContaining(['INSTRUCTION_USES_EXHAUSTED', 'LINE_QUANTITY_EXCEEDS_INSTRUCTION']));

    // Multi-use: 3 partial deliveries of 4 units (10 approved) → third partial exceeds quantity.
    const multi = await world.order(agent, 10_000, {
      maxUses: 3, invoice: false, poAmountCents: 10_000,
      lines: [{ lineNumber: 1, sku: 'GLOVES', description: 'Gloves', quantity: '10', unitPriceCents: 1_000 }],
    });
    const part = (q: string, cents: number) => purchase(agent, { ...multi, amountCents: cents, lines: [{ instructionLineNumber: 1, sku: 'GLOVES', quantity: q, unitPriceCents: 1_000 }] });
    const p1 = await part('4', 4_000);
    const p2 = await part('4', 4_000);
    const p3 = await part('4', 4_000);
    expect([p1.decision, p2.decision]).toEqual(['REVIEW', 'REVIEW']); // invoice missing → human review, never auto-ALLOW
    expect(p3.decision).toBe('DENY');
    expect(p3.reasonCodes).toContain('LINE_QUANTITY_EXCEEDS_INSTRUCTION');
  });

  it('cannot pay after the instruction\'s approval is revoked', async () => {
    const o = await world.order(agent, 15_000);
    const auth = await purchase(agent, { ...o, amountCents: 15_000 });
    expect(auth.decision).toBe('ALLOW');
    await world.approver.post(`/v1/purchase-instructions/${o.instructionId}/revoke`, { reason: 'project cancelled' });
    expect((await apiError(executeFor(agent, auth))).code).toBe('AUTHORIZATION_INVALIDATED');
    const again = await purchase(agent, { ...o, amountCents: 15_000 });
    expect(again.reasonCodes).toContain('INSTRUCTION_REVOKED');
  });

  it('a material amendment invalidates outstanding authorizations and needs re-approval', async () => {
    const o = await world.order(agent, 16_000);
    const auth = await purchase(agent, { ...o, amountCents: 16_000 });
    expect(auth.instructionVersion).toBe(1);
    const amended = await world.admin.put<{ version: number; status: string }>(`/v1/purchase-instructions/${o.instructionId}`, {
      agentId: agent.id, supplierId: world.supplierId, purchaseOrderId: o.poId, fulfillmentType: 'physical_goods', currency: 'USD',
      lines: [{ lineNumber: 1, sku: o.sku, description: 'Tooling item', quantity: '1', unitPriceCents: 15_000 }], expiresAt: future(),
    });
    expect(amended).toMatchObject({ version: 2, status: 'pending_approval' });
    expect((await apiError(executeFor(agent, auth))).code).toBe('AUTHORIZATION_INVALIDATED');
    const versions = await world.admin.get<{ versions: { version: number; changeType: string }[] }>(`/v1/purchase-instructions/${o.instructionId}/versions`);
    expect(versions.versions.map((v) => `${v.version}:${v.changeType}`)).toEqual(['1:created', '1:approved', '2:amended']);
  });
});

describe('independent approval of instructions', () => {
  it('the requester cannot approve their own instruction; approvers need enough authority', async () => {
    const o = await world.order(agent, 20_000, { approve: false });
    expect((await apiError(world.admin.post(`/v1/purchase-instructions/${o.instructionId}/approve`, {}))).code).toBe('SEPARATION_OF_DUTIES');
    const pending = await purchase(agent, { ...o, amountCents: 20_000 });
    expect(pending.decision).toBe('REVIEW');
    expect(pending.reasonCodes).toContain('INSTRUCTION_NOT_APPROVED');
    expect(pending.approvable).toBe(false);

    const big = await world.order(agent, 1_500_000, { approve: false }); // $15,000 > approver's $10,000 authority
    expect((await apiError(world.approver.post(`/v1/purchase-instructions/${big.instructionId}/approve`, {}))).code).toBe('INSUFFICIENT_AUTHORITY');

    await world.approver.post(`/v1/purchase-instructions/${o.instructionId}/approve`, {});
    expect((await purchase(agent, { ...o, amountCents: 20_000 })).decision).toBe('ALLOW');
  });
});

describe('ERP-synced instructions', () => {
  it('a successful sync does NOT mean approved unless the integration may attest approvals', async () => {
    const { erp } = await erpClient(['instructions:sync']);
    const synced = await erp.post<{ id: string; status: string; source: string; externalId: string; syncedAt: string }>('/v1/integrations/erp/purchase-instructions', erpInstruction());
    expect(synced).toMatchObject({ status: 'pending_approval', source: 'erp' });
    expect(synced.syncedAt).toBeTruthy();
    // A human approves in AgentTrust.
    const approved = await world.approver.post<{ status: string; approvalSource: string }>(`/v1/purchase-instructions/${synced.id}/approve`, {});
    expect(approved).toMatchObject({ status: 'approved', approvalSource: 'agenttrust_user' });

    const { erp: trusted } = await erpClient(['instructions:sync', 'instructions:attest_approval']);
    const attested = await trusted.post<{ status: string; approvalSource: string }>('/v1/integrations/erp/purchase-instructions', erpInstruction());
    expect(attested).toMatchObject({ status: 'approved', approvalSource: 'erp_attested' });
    const notApprovedInErp = await trusted.post<{ status: string }>('/v1/integrations/erp/purchase-instructions', erpInstruction({ erpApproval: { status: 'pending' } }));
    expect(notApprovedInErp.status).toBe('pending_approval');
  });

  it('rejects stale syncs, re-versions material changes, and invalidates outstanding authorizations', async () => {
    const { erp } = await erpClient(['instructions:sync', 'instructions:attest_approval', 'invoices:write']);
    const po = await world.admin.post<{ id: string }>('/v1/purchase-orders', { supplierId: world.supplierId, externalReference: `PO-${uniq()}`, approvedAmountCents: 30_000, currency: 'USD' });
    const base = erpInstruction({ purchaseOrderId: po.id });
    const v1 = await erp.post<{ id: string; version: number }>('/v1/integrations/erp/purchase-instructions', base);
    const inv = await erp.post<{ id: string }>('/v1/invoices', {
      supplierId: world.supplierId, purchaseOrderId: po.id, purchaseInstructionId: v1.id, invoiceNumber: `INV-${uniq()}`, amountCents: 30_000, currency: 'USD',
      lines: [{ lineNumber: 1, instructionLineNumber: 1, sku: 'DRILL-18V', description: '18V drill', quantity: '2', unitPriceCents: 15_000 }],
    });
    const auth = await purchase(agent, { supplierId: world.supplierId, poId: po.id, invoiceId: inv.id, instructionId: v1.id, amountCents: 30_000 });
    expect(auth.decision).toBe('ALLOW');

    const stale = await apiError(erp.post('/v1/integrations/erp/purchase-instructions', { ...base, externalUpdatedAt: new Date(Date.now() - 86_400_000).toISOString() }));
    expect(stale.code).toBe('STALE_SYNC');

    const unchanged = await erp.post<{ version: number }>('/v1/integrations/erp/purchase-instructions', { ...base, externalVersion: '2', externalUpdatedAt: new Date().toISOString() });
    expect(unchanged.version).toBe(1);
    expect((await world.admin.get<{ status: string }>(`/v1/authorizations/${auth.id}`)).status).toBe('allowed');

    const changed = await erp.post<{ version: number }>('/v1/integrations/erp/purchase-instructions', {
      ...base, externalVersion: '3', externalUpdatedAt: new Date(Date.now() + 1000).toISOString(),
      lines: [{ lineNumber: 1, sku: 'DRILL-18V', description: '18V drill', quantity: '3', unitPriceCents: 15_000 }], purchaseOrderId: undefined,
    });
    expect(changed.version).toBe(2);
    expect((await apiError(executeFor(agent, auth))).code).toBe('AUTHORIZATION_INVALIDATED');
    // Humans cannot edit ERP-managed instructions directly.
    expect((await apiError(world.admin.put(`/v1/purchase-instructions/${v1.id}`, { ...base, externalId: undefined }))).status).toBe(400);
  });

  it('integrations are narrowly scoped and revocable', async () => {
    const { erp } = await erpClient(['receipts:confirm']);
    expect((await apiError(erp.post('/v1/integrations/erp/purchase-instructions', erpInstruction()))).code).toBe('SCOPE_REQUIRED');
    const list = await world.admin.get<{ integrations: { id: string; scopes: string[] }[] }>('/v1/integrations');
    const target = list.integrations.find((i) => i.scopes.length === 1 && i.scopes[0] === 'receipts:confirm')!;
    await world.admin.post(`/v1/integrations/${target.id}/revoke`, {});
    expect((await apiError(erp.post('/v1/receipts', {}))).status).toBe(401);
    // Integration credentials never work on human-only routes.
    const { erp: other } = await erpClient(['instructions:sync']);
    expect((await apiError(other.get('/v1/agents'))).status).toBe(401);
  });
});

describe('three-way matching (PO → receipt → invoice)', () => {
  beforeAll(async () => {
    await patchPolicy(world, (r) => ({ ...r, threeWayMatch: { ...r.threeWayMatch, enabled: true } }));
  });

  it('physical goods: no receipt → REVIEW (never ALLOW); authorized receipt → ALLOW; over-receipt rejected', async () => {
    const o = await world.order(agent, 20_000, { lines: [{ lineNumber: 1, sku: 'PUMP', description: 'Pump', quantity: '2', unitPriceCents: 10_000 }] });
    const before = await purchase(agent, { ...o, amountCents: 20_000 });
    expect(before.decision).toBe('REVIEW');
    expect(before.reasonCodes).toContain('RECEIPT_MISSING');
    expect(before.approvable).toBe(false);

    expect((await apiError(world.member.post('/v1/receipts', { purchaseInstructionId: o.instructionId, type: 'goods_received', lines: [{ instructionLineNumber: 1, quantity: '3' }] }))).status).toBe(400);
    await world.member.post('/v1/receipts', { purchaseInstructionId: o.instructionId, type: 'goods_received', lines: [{ instructionLineNumber: 1, quantity: '1' }] });
    const partial = await purchase(agent, { ...o, amountCents: 20_000 });
    expect(partial.reasonCodes).toContain('RECEIPT_QUANTITY_INSUFFICIENT');

    await world.member.post('/v1/receipts', { purchaseInstructionId: o.instructionId, type: 'goods_received', lines: [{ instructionLineNumber: 1, quantity: '1' }] });
    const after = await purchase(agent, { ...o, amountCents: 20_000 });
    expect(after.decision).toBe('ALLOW');
    expect(after.reasonCodes).toContain('RECEIPT_MATCHED');
  });

  it('services need a service-completion confirmation (a goods receipt is rejected), which an ERP may record', async () => {
    const o = await world.order(agent, 50_000, { fulfillmentType: 'services', lines: [{ lineNumber: 1, sku: 'INSTALL', description: 'Installation', quantity: '2.5', unitPriceCents: 20_000 }] });
    expect((await apiError(world.member.post('/v1/receipts', { purchaseInstructionId: o.instructionId, type: 'goods_received', lines: [{ instructionLineNumber: 1, quantity: '2.5' }] }))).status).toBe(400);
    const { erp } = await erpClient(['receipts:confirm']);
    await erp.post('/v1/receipts', { purchaseInstructionId: o.instructionId, type: 'service_completed', lines: [{ instructionLineNumber: 1, quantity: '2.5' }], externalId: 'GRN-1' });
    expect((await purchase(agent, { ...o, amountCents: 50_000 })).decision).toBe('ALLOW');
  });

  it('subscriptions use an alternative human-approval workflow', async () => {
    const o = await world.order(agent, 9_900, { fulfillmentType: 'subscription' });
    const r = await purchase(agent, { ...o, amountCents: 9_900 });
    expect(r.decision).toBe('REVIEW');
    expect(r.reasonCodes).toContain('ALTERNATIVE_APPROVAL_REQUIRED');
    expect(r.approvable).toBe(true);
    const approved = await world.approver.post<{ decision: string }>(`/v1/authorizations/${r.id}/approve`, {});
    expect(approved.decision).toBe('ALLOW');
  });

  it('voiding a receipt invalidates authorizations that relied on it; DENY policy is honored', async () => {
    const o = await world.order(agent, 7_000);
    const receipt = await world.member.post<{ id: string }>('/v1/receipts', { purchaseInstructionId: o.instructionId, type: 'goods_received', lines: [{ instructionLineNumber: 1, quantity: '1' }] });
    const auth = await purchase(agent, { ...o, amountCents: 7_000 });
    expect(auth.decision).toBe('ALLOW');
    await world.admin.post(`/v1/receipts/${receipt.id}/void`, { reason: 'goods returned damaged' });
    expect((await apiError(executeFor(agent, auth))).code).toBe('AUTHORIZATION_INVALIDATED');

    await patchPolicy(world, (r) => ({ ...r, missingReceipt: 'DENY' }));
    const denied = await purchase(agent, { ...o, amountCents: 7_000 });
    expect(denied.decision).toBe('DENY');
    expect(denied.reasonCodes).toContain('RECEIPT_MISSING');
    await patchPolicy(world, (r) => ({ ...r, missingReceipt: 'REVIEW', threeWayMatch: { ...r.threeWayMatch, enabled: false } }));
  });
});

describe('financial correctness', () => {
  it('exact quantity arithmetic: fractional quantities work, rounding is rejected', async () => {
    const ok = await world.order(agent, 10_000, { lines: [{ lineNumber: 1, sku: 'HOURS', description: 'Consulting', quantity: '2.5', unitPriceCents: 4_000 }] });
    expect((await purchase(agent, { ...ok, amountCents: 10_000 })).decision).toBe('ALLOW');

    const err = await apiError(world.admin.post('/v1/purchase-instructions', {
      agentId: agent.id, supplierId: world.supplierId, fulfillmentType: 'services', currency: 'USD', expiresAt: future(),
      lines: [{ lineNumber: 1, description: 'x', quantity: '1.5', unitPriceCents: 333 }],
    }));
    expect(err.message).toMatch(/exact number of cents/);
    const badInvoice = await apiError(world.admin.post('/v1/invoices', {
      supplierId: world.supplierId, invoiceNumber: `INV-${uniq()}`, amountCents: 1_000, currency: 'USD',
      lines: [{ lineNumber: 1, description: 'x', quantity: '1', unitPriceCents: 999 }],
    }));
    expect(badInvoice.message).toMatch(/sum exactly/);
  });

  it('mismatched currencies are rejected, never converted', async () => {
    const po = await world.admin.post<{ id: string }>('/v1/purchase-orders', { supplierId: world.supplierId, externalReference: `PO-${uniq()}`, approvedAmountCents: 10_000, currency: 'USD' });
    const err = await apiError(world.admin.post('/v1/purchase-instructions', {
      agentId: agent.id, supplierId: world.supplierId, purchaseOrderId: po.id, fulfillmentType: 'physical_goods', currency: 'EUR', expiresAt: future(),
      lines: [{ lineNumber: 1, description: 'x', quantity: '1', unitPriceCents: 10_000 }],
    }));
    expect(err.message).toMatch(/never converted/);
    const o = await world.order(agent, 10_000);
    const r = await purchase(agent, { ...o, amountCents: 10_000, currency: 'EUR' });
    expect(r.decision).toBe('DENY');
    expect(r.reasonCodes).toContain('INSTRUCTION_CURRENCY_MISMATCH');
  });
});
