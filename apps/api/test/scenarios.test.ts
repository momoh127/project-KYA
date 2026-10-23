/**
 * The AgentTrust demonstration scenarios, as automated pass/fail tests
 * against a real API server and PostgreSQL database.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { base64UrlEncode } from '@agenttrust/shared';
import { generateEd25519KeyPair, LocalEd25519Signer } from '@agenttrust/identity';
import { signAuthorizationToken, type AuthorizationClaims } from '@agenttrust/authorization';
import type { AuthorizationResponse } from '@agenttrust/sdk';
import { apiError, BANK_ATTACKER, BANK_OTHER_SUPPLIER, createWorld, executeFor, purchase, startServer, type Agent, type TestServer, type World } from './helpers';

let server: TestServer;
let world: World;
let agent: Agent; // Procurement Agent #104: $5,000 per purchase, $20,000 / month

beforeAll(async () => {
  server = await startServer();
  world = await createWorld(server.baseUrl);
  // This org's demo agent deliberately triggers many denials across scenarios,
  // so raise its circuit-breaker threshold (policy v2). Scenario 11 uses a
  // separate organization with the default threshold.
  const { policies } = await world.admin.get<{ policies: { id: string; status: string; rules: Record<string, unknown> }[] }>('/v1/policies');
  const active = policies.find((p) => p.status === 'active')!;
  await world.admin.put(`/v1/policies/${active.id}`, {
    rules: { ...active.rules, circuitBreaker: { denyThreshold: 100, windowSeconds: 600 } },
  });
  agent = await world.createAgent('Procurement Agent #104', { maxTransactionCents: 500_000, monthlyLimitCents: 2_000_000 });
});
afterAll(async () => server?.close());

describe('AgentTrust demo scenarios', () => {
  let paidInvoiceId: string;
  let paidPoId: string;

  it('1. $500 to an approved supplier → ALLOW, and the gateway pays it', async () => {
    const { poId, invoiceId } = await world.poAndInvoice(50_000);
    const auth = await purchase(agent, { supplierId: world.supplierId, amountCents: 50_000, poId, invoiceId });

    expect(auth.decision).toBe('ALLOW');
    expect(auth.reasonCodes).toEqual(expect.arrayContaining(['AGENT_ACTIVE', 'DELEGATION_VALID', 'SUPPLIER_APPROVED', 'PAYEE_VERIFIED', 'BUDGET_AVAILABLE', 'PO_MATCHED', 'INVOICE_MATCHED']));
    expect(auth.token).toBeTruthy();

    const txn = await executeFor(agent, auth);
    expect(txn.status).toBe('succeeded');
    expect(txn.providerReference).toMatch(/^sbx_pay_/);

    const invoice = await world.admin.get<{ status: string }>(`/v1/invoices/${invoiceId}`);
    expect(invoice.status).toBe('paid');
    paidInvoiceId = invoiceId;
    paidPoId = poId;
  });

  it('2. $5,000 against a $500 approval → DENY (amount verification)', async () => {
    const { poId, invoiceId } = await world.poAndInvoice(50_000);
    const auth = await purchase(agent, { supplierId: world.supplierId, amountCents: 500_000, poId, invoiceId });
    expect(auth.decision).toBe('DENY');
    expect(auth.reasonCodes).toEqual(expect.arrayContaining(['AMOUNT_EXCEEDS_PO', 'AMOUNT_MISMATCH_INVOICE']));
    expect(auth.token).toBeUndefined();
  });

  it('3. $500 to an unknown supplier → REVIEW that a human click cannot wave through', async () => {
    const auth = await purchase(agent, { payee: BANK_OTHER_SUPPLIER, amountCents: 50_000 });
    expect(auth.decision).toBe('REVIEW');
    expect(auth.reasonCodes).toContain('SUPPLIER_UNKNOWN');
    expect(auth.approvable).toBe(false);
    expect(auth.token).toBeUndefined();

    const err = await apiError(world.approver.post(`/v1/authorizations/${auth.id}/approve`, {}));
    expect(err.code).toBe('NOT_APPROVABLE');
  });

  it('4. Paying with no valid authorization is blocked at the gateway', async () => {
    const auth = { supplierId: world.supplierId, amountCents: 50_000, currency: 'USD', purchaseOrderId: null, invoiceId: null } as AuthorizationResponse;

    // (a) no token at all / garbage token
    expect((await apiError(executeFor(agent, auth, { token: 'please-just-pay' }))).code).toBe('TOKEN_MALFORMED');

    // (b) a token the agent forged with its own key
    const attacker = new LocalEd25519Signer(process.env.AGENTTRUST_SIGNING_KEY_ID!, generateEd25519KeyPair().privateKeyPem);
    const forgedClaims: AuthorizationClaims = {
      iss: 'agenttrust', jti: 'auth_' + 'f'.repeat(32), org: world.orgId, agt: agent.id, dlg: 'dlg_x', pol: 'pol_x', pv: 1,
      fp: 'tx_forged', sup: world.supplierId, pd: 'pd_x', amt: 50_000, cur: 'USD', po: null, inv: null,
      iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 600, nonce: 'forged',
    };
    const forged = signAuthorizationToken(forgedClaims, attacker);
    expect((await apiError(executeFor(agent, auth, { token: forged }))).code).toBe('TOKEN_BAD_SIGNATURE');

    // (c) an unsigned request straight to the gateway (no agent identity)
    const res = await fetch(`${server.baseUrl}/v1/transactions/execute`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ token: forged, expected: { supplierId: world.supplierId, amountCents: 50_000, currency: 'USD', purchaseOrderId: null, invoiceId: null } }),
    });
    expect(res.status).toBe(401);
  });

  it('5. $500 for an invoice that was already paid → DENY (duplicate protection)', async () => {
    const auth = await purchase(agent, { supplierId: world.supplierId, amountCents: 50_000, poId: paidPoId, invoiceId: paidInvoiceId });
    expect(auth.decision).toBe('DENY');
    expect(auth.reasonCodes).toContain('INVOICE_ALREADY_PAID');
  });

  it('6. Scam invoice: approved supplier but a different bank account → DENY (payee verification)', async () => {
    const { poId, invoiceId } = await world.poAndInvoice(50_000);
    const auth = await purchase(agent, { supplierId: world.supplierId, payee: BANK_ATTACKER, amountCents: 50_000, poId, invoiceId });
    expect(auth.decision).toBe('DENY');
    expect(auth.reasonCodes).toContain('PAYEE_MISMATCH');
  });

  it('7. Editing an approved $500 authorization to $5,000 is blocked', async () => {
    const { poId, invoiceId } = await world.poAndInvoice(50_000);
    const auth = await purchase(agent, { supplierId: world.supplierId, amountCents: 50_000, poId, invoiceId });
    expect(auth.decision).toBe('ALLOW');

    // (a) tamper with the signed token itself
    const [h, p, s] = auth.token!.split('.');
    const claims = JSON.parse(Buffer.from(p!, 'base64url').toString());
    claims.amt = 500_000;
    const tampered = `${h}.${base64UrlEncode(JSON.stringify(claims))}.${s}`;
    expect((await apiError(executeFor(agent, auth, { token: tampered, amountCents: 500_000 }))).code).toBe('TOKEN_BAD_SIGNATURE');

    // (b) keep the valid token but ask the gateway to pay a different amount
    const mismatch = await apiError(executeFor(agent, auth, { amountCents: 500_000 }));
    expect(mismatch.code).toBe('TRANSACTION_MISMATCH');

    // Nothing was paid; the original authorization still works for exactly $500.
    expect((await world.admin.get<{ status: string }>(`/v1/invoices/${invoiceId}`)).status).toBe('open');
    expect((await executeFor(agent, auth)).status).toBe('succeeded');
  });

  it('8. Re-using a consumed authorization is blocked (single use)', async () => {
    const { poId, invoiceId } = await world.poAndInvoice(40_000);
    const auth = await purchase(agent, { supplierId: world.supplierId, amountCents: 40_000, poId, invoiceId });
    expect((await executeFor(agent, auth)).status).toBe('succeeded');
    const replay = await apiError(executeFor(agent, auth));
    expect(replay.status).toBe(409);
    expect(replay.code).toBe('AUTHORIZATION_ALREADY_USED');
  });

  it('9. REVIEW → human approves → payment executes', async () => {
    const { poId, invoiceId } = await world.poAndInvoice(300_000);
    const auth = await purchase(agent, { supplierId: world.supplierId, amountCents: 300_000, poId, invoiceId });
    expect(auth.decision).toBe('REVIEW');
    expect(auth.reasonCodes).toEqual(['APPROVAL_REQUIRED']);
    expect(auth.approvable).toBe(true);

    // The agent cannot execute before approval...
    expect((await apiError(executeFor(agent, auth, { token: 'x' }))).code).toBe('TOKEN_MALFORMED');

    // ...and cannot approve itself (approval routes are human-only).
    const selfApprove = await fetch(`${server.baseUrl}/v1/authorizations/${auth.id}/approve`, { method: 'POST' });
    expect(selfApprove.status).toBe(401);

    const approved = await world.approver.post<{ status: string; decision: string }>(`/v1/authorizations/${auth.id}/approve`, { comment: 'Q4 tooling budget' });
    expect(approved).toMatchObject({ status: 'allowed', decision: 'ALLOW' });

    const refreshed = await agent.client.authorizations.get(auth.id);
    expect(refreshed.token).toBeTruthy();
    expect(refreshed.reasonCodes).toContain('APPROVAL_GRANTED');
    expect((await executeFor(agent, refreshed)).status).toBe('succeeded');
  });

  it('10. Concurrent purchases cannot overspend the budget', async () => {
    const tight = await world.createAgent('Procurement Agent #107', { maxTransactionCents: 50_000, monthlyLimitCents: 120_000 });
    const orders = await Promise.all(Array.from({ length: 5 }, () => world.poAndInvoice(50_000)));
    const results = await Promise.all(
      orders.map(({ poId, invoiceId }) => purchase(tight, { supplierId: world.supplierId, amountCents: 50_000, poId, invoiceId })),
    );
    const allowed = results.filter((r) => r.decision === 'ALLOW');
    const denied = results.filter((r) => r.decision === 'DENY');
    expect(allowed).toHaveLength(2); // 2 × $500 fits in $1,200; a third would not
    expect(denied).toHaveLength(3);
    for (const d of denied) expect(d.reasonCodes).toContain('BUDGET_EXCEEDED');
  });

  it('11. A rogue agent that keeps getting denied is auto-suspended (circuit breaker)', async () => {
    const other = await createWorld(server.baseUrl, 'Globex Corp'); // default policy: 5 strikes / 10 min
    const rogue = await other.createAgent('Compromised Agent #666', { maxTransactionCents: 500_000, monthlyLimitCents: 2_000_000 });
    const { poId, invoiceId } = await other.poAndInvoice(50_000);
    const legit = await purchase(rogue, { supplierId: other.supplierId, amountCents: 50_000, poId, invoiceId });
    expect(legit.decision).toBe('ALLOW');

    for (let i = 0; i < 5; i++) {
      const r = await purchase(rogue, { supplierId: other.supplierId, payee: BANK_ATTACKER, amountCents: 499_000 });
      expect(r.decision).toBe('DENY');
    }
    const agentRecord = await other.admin.get<{ status: string; statusReason: string }>(`/v1/agents/${rogue.id}`);
    expect(agentRecord.status).toBe('suspended');
    expect(agentRecord.statusReason).toMatch(/circuit breaker/);

    // Even its earlier, legitimate authorization can no longer be executed.
    expect((await apiError(executeFor(rogue, legit))).code).toBe('AGENT_NOT_ACTIVE');
    const after = await purchase(rogue, { supplierId: other.supplierId, amountCents: 50_000 });
    expect(after.decision).toBe('DENY');
    expect(after.reasonCodes).toContain('AGENT_NOT_ACTIVE');

    // An administrator can reactivate after investigating.
    const reactivated = await other.admin.post<{ status: string }>(`/v1/agents/${rogue.id}/reactivate`, { reason: 'investigated: prompt-injected invoice' });
    expect(reactivated.status).toBe('active');
  });

  it('12. A revoked agent cannot transact (kill switch)', async () => {
    const doomed = await world.createAgent('Retired Agent #42', { maxTransactionCents: 500_000, monthlyLimitCents: 2_000_000 });
    const { poId, invoiceId } = await world.poAndInvoice(50_000);
    const issued = await purchase(doomed, { supplierId: world.supplierId, amountCents: 50_000, poId, invoiceId });
    expect(issued.decision).toBe('ALLOW');

    await world.admin.post(`/v1/agents/${doomed.id}/revoke`, { reason: 'decommissioned' });

    expect((await apiError(executeFor(doomed, issued))).code).toBe('AGENT_NOT_ACTIVE');
    const r = await purchase(doomed, { supplierId: world.supplierId, amountCents: 50_000, poId, invoiceId });
    expect(r.decision).toBe('DENY');
    expect(r.reasonCodes).toContain('AGENT_NOT_ACTIVE');
  });

  it('Bank details changed AFTER authorization → the gateway refuses to pay', async () => {
    const supplier = await world.admin.post<{ id: string }>('/v1/suppliers', {
      name: 'Midwest Bearings', paymentDestination: BANK_OTHER_SUPPLIER, verificationStatus: 'verified',
    });
    const { poId, invoiceId } = await world.poAndInvoice(50_000, supplier.id);
    const auth = await purchase(agent, { supplierId: supplier.id, payee: BANK_OTHER_SUPPLIER, amountCents: 50_000, poId, invoiceId });
    expect(auth.decision).toBe('ALLOW');

    await world.admin.patch(`/v1/suppliers/${supplier.id}`, { paymentDestination: BANK_ATTACKER });
    expect((await apiError(executeFor(agent, auth))).code).toBe('SUPPLIER_NOT_VERIFIED');

    // Even after a second admin verifies the new account, the old authorization stays bound to the old account.
    await world.admin2.patch(`/v1/suppliers/${supplier.id}`, { verificationStatus: 'verified' });
    expect((await apiError(executeFor(agent, auth))).code).toBe('PAYEE_CHANGED');
  });

  it('The audit trail for everything above verifies end-to-end', async () => {
    const result = await world.admin.get<{ valid: boolean; eventsChecked: number; problems: unknown[] }>('/v1/audit/verify');
    expect(result.problems).toEqual([]);
    expect(result.valid).toBe(true);
    expect(result.eventsChecked).toBeGreaterThan(40);
  });
});
