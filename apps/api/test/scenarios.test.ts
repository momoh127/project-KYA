/**
 * The AgentTrust demonstration scenarios, as automated pass/fail tests
 * against a real API server and PostgreSQL database.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { PrismaClient } from '@prisma/client';
import { base64UrlEncode } from '@agenttrust/shared';
import { generateEd25519KeyPair, LocalEd25519Signer } from '@agenttrust/identity';
import { claimsFromBinding, signAuthorizationToken } from '@agenttrust/authorization';
import type { AuthorizationResponse } from '@agenttrust/sdk';
import { apiError, BANK_ATTACKER, BANK_OTHER_SUPPLIER, createWorld, executeFor, purchase, startServer, type Agent, type TestServer, type World } from './helpers';

let server: TestServer;
let world: World;
let agent: Agent; // Procurement Agent #104: $5,000 per purchase, $20,000 / month
const prisma = new PrismaClient();

async function raiseViolationThreshold(w: World) {
  // This org's demo agent deliberately triggers many forged/tampered-token
  // violations across scenarios, so raise its suspension threshold. Scenario
  // 11 uses a separate organization with the default policy.
  const { policies } = await w.admin.get<{ policies: { id: string; status: string; rules: Record<string, any> }[] }>('/v1/policies');
  const active = policies.find((p) => p.status === 'active')!;
  await w.admin.put(`/v1/policies/${active.id}`, {
    rules: { ...active.rules, securityResponse: { ...active.rules.securityResponse, violationSuspendThreshold: 100 } },
  });
}

beforeAll(async () => {
  server = await startServer();
  world = await createWorld(server.baseUrl);
  await raiseViolationThreshold(world);
  agent = await world.createAgent('Procurement Agent #104', { maxTransactionCents: 500_000, monthlyLimitCents: 2_000_000 });
});
afterAll(async () => {
  await prisma.$disconnect();
  await server?.close();
});

describe('AgentTrust demo scenarios', () => {
  let paidInvoiceId: string;
  let paidPoId: string;

  it('1. $500 to an approved supplier → ALLOW, and the gateway pays it', async () => {
    const { poId, invoiceId } = await world.poAndInvoice(50_000);
    const auth = await purchase(agent, { supplierId: world.supplierId, amountCents: 50_000, poId, invoiceId });

    expect(auth.decision).toBe('ALLOW');
    expect(auth.reasonCodes).toEqual(expect.arrayContaining(['AGENT_ACTIVE', 'DELEGATION_VALID', 'SUPPLIER_APPROVED', 'PAYEE_VERIFIED', 'BUDGET_AVAILABLE', 'PO_MATCHED', 'INVOICE_MATCHED']));
    expect(auth.token).toBeTruthy();
    expect(auth.authorizationFingerprint).toMatch(/^az_/);
    expect(auth.paymentRail).toBe('ach');

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

    expect((await apiError(executeFor(agent, auth, { token: 'please-just-pay' }))).code).toBe('TOKEN_MALFORMED');

    const attacker = new LocalEd25519Signer(process.env.AGENTTRUST_SIGNING_KEY_ID!, generateEd25519KeyPair().privateKeyPem);
    const now = Math.floor(Date.now() / 1000);
    const forged = signAuthorizationToken(
      claimsFromBinding(
        {
          organizationId: world.orgId, agentId: agent.id, action: 'purchase', supplierId: world.supplierId, paymentDestinationFingerprint: 'pd_x',
          amountCents: 50_000, currency: 'USD', purchaseOrderId: null, invoiceId: null, paymentRail: 'ach', destinationRef: 'cp_x',
          supplierVersion: 2, policyId: 'pol_x', policyVersion: 1, delegationId: 'dlg_x',
        },
        { id: 'auth_' + 'f'.repeat(32), sessionId: null, iat: now, exp: now + 600, nonce: 'forged' },
      ),
      attacker,
    );
    expect((await apiError(executeFor(agent, auth, { token: forged }))).code).toBe('TOKEN_BAD_SIGNATURE');

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

    const [h, p, s] = auth.token!.split('.');
    const claims = JSON.parse(Buffer.from(p!, 'base64url').toString());
    claims.amt = 500_000;
    const tampered = `${h}.${base64UrlEncode(JSON.stringify(claims))}.${s}`;
    expect((await apiError(executeFor(agent, auth, { token: tampered, amountCents: 500_000 }))).code).toBe('TOKEN_BAD_SIGNATURE');

    const mismatch = await apiError(executeFor(agent, auth, { amountCents: 500_000 }));
    expect(mismatch.code).toBe('TRANSACTION_MISMATCH');

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
    expect((await world.platform.sandboxLedger(auth.id)).payments).toHaveLength(1);
  });

  it('9. REVIEW → human approves → payment executes', async () => {
    const { poId, invoiceId } = await world.poAndInvoice(300_000);
    const auth = await purchase(agent, { supplierId: world.supplierId, amountCents: 300_000, poId, invoiceId });
    expect(auth.decision).toBe('REVIEW');
    expect(auth.reasonCodes).toEqual(['APPROVAL_REQUIRED']);
    expect(auth.approvable).toBe(true);

    expect((await apiError(executeFor(agent, auth, { token: 'x' }))).code).toBe('TOKEN_MALFORMED');
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
    expect(allowed).toHaveLength(2);
    expect(denied).toHaveLength(3);
    for (const d of denied) expect(d.reasonCodes).toContain('BUDGET_EXCEEDED');
  });

  it('11. Graded response: scam-invoice denials alert but do NOT suspend; forged/tampered tokens DO', async () => {
    const other = await createWorld(server.baseUrl, 'Globex Corp'); // default policy: 3 violations / 10 min
    const rogue = await other.createAgent('Compromised Agent #666', { maxTransactionCents: 500_000, monthlyLimitCents: 2_000_000 });
    const { poId, invoiceId } = await other.poAndInvoice(50_000);
    const legit = await purchase(rogue, { supplierId: other.supplierId, amountCents: 50_000, poId, invoiceId });
    expect(legit.decision).toBe('ALLOW');

    // (a) An outsider can make the agent read scam invoices: these are denied and
    //     alerted on, but must not knock the agent offline.
    for (let i = 0; i < 6; i++) {
      const r = await purchase(rogue, { supplierId: other.supplierId, payee: BANK_ATTACKER, amountCents: 49_000 });
      expect(r.decision).toBe('DENY');
    }
    expect((await other.admin.get<{ status: string }>(`/v1/agents/${rogue.id}`)).status).toBe('active');
    const { alerts } = await other.admin.get<{ alerts: { category?: string; type: string }[] }>('/v1/alerts');
    expect(alerts.some((a) => a.category === 'fraud_signal')).toBe(true);

    // (b) Forging / tampering with authorizations requires the agent's own valid
    //     session key: high-confidence compromise → suspended at the threshold.
    const [h, p, s] = legit.token!.split('.');
    const claims = JSON.parse(Buffer.from(p!, 'base64url').toString());
    for (const amt of [60_000, 70_000, 80_000]) {
      claims.amt = amt;
      const tampered = `${h}.${base64UrlEncode(JSON.stringify(claims))}.${s}`;
      expect((await apiError(executeFor(rogue, legit, { token: tampered, amountCents: amt }))).code).toBe('TOKEN_BAD_SIGNATURE');
    }
    const record = await other.admin.get<{ status: string; statusReason: string }>(`/v1/agents/${rogue.id}`);
    expect(record.status).toBe('suspended');
    expect(record.statusReason).toMatch(/security violations/);

    // Its legitimate authorization is dead, and so are its sessions.
    expect((await apiError(executeFor(rogue, legit))).status).toBe(401);

    const reactivated = await other.admin.post<{ status: string }>(`/v1/agents/${rogue.id}/reactivate`, { reason: 'investigated' });
    expect(reactivated.status).toBe('active');
  });

  it('12. A revoked agent cannot transact (kill switch)', async () => {
    const doomed = await world.createAgent('Retired Agent #42', { maxTransactionCents: 500_000, monthlyLimitCents: 2_000_000 });
    const { poId, invoiceId } = await world.poAndInvoice(50_000);
    const issued = await purchase(doomed, { supplierId: world.supplierId, amountCents: 50_000, poId, invoiceId });
    expect(issued.decision).toBe('ALLOW');

    await world.admin.post(`/v1/agents/${doomed.id}/revoke`, { reason: 'decommissioned' });

    // Sessions are revoked with the agent, so it cannot even authenticate.
    expect((await apiError(executeFor(doomed, issued))).status).toBe(401);
    const auth = await world.admin.get<{ status: string; invalidatedReason: string }>(`/v1/authorizations/${issued.id}`);
    expect(auth.status).toBe('invalidated');
    // A fresh session cannot be minted either.
    const fresh = await apiError(doomed.client.sessions.rotate());
    expect(fresh.code).toBe('AGENT_NOT_ACTIVE');
  });

  it('13. [required] Supplier bank details change after authorization → execution blocked', async () => {
    const supplierId = await world.verifiedSupplier('Midwest Bearings', BANK_OTHER_SUPPLIER);
    const { poId, invoiceId } = await world.poAndInvoice(50_000, supplierId);
    const auth = await purchase(agent, { supplierId, payee: BANK_OTHER_SUPPLIER, amountCents: 50_000, poId, invoiceId });
    expect(auth.decision).toBe('ALLOW');
    expect(auth.supplierVersion).toBe(2);

    await world.admin.patch(`/v1/suppliers/${supplierId}`, { paymentDestination: BANK_ATTACKER });

    const refreshed = await world.admin.get<{ status: string; invalidatedReason: string }>(`/v1/authorizations/${auth.id}`);
    expect(refreshed.status).toBe('invalidated');
    expect(refreshed.invalidatedReason).toMatch(/supplier record changed/);
    expect((await apiError(executeFor(agent, auth))).code).toBe('AUTHORIZATION_INVALIDATED');

    // Even after a second admin verifies the new account, the old authorization stays dead.
    await world.admin2.post(`/v1/suppliers/${supplierId}/verify-payment-destination`, {
      evidence: 'Supplier confirmed new account by phone on the contract number.', confirmedLast4: '0011',
    });
    expect((await apiError(executeFor(agent, auth))).code).toBe('AUTHORIZATION_INVALIDATED');
    expect((await world.platform.sandboxLedger(auth.id)).payments).toHaveLength(0);
  });

  it('14. [required] Provider succeeds but the gateway crashes → no duplicate payment on retry', async () => {
    const { poId, invoiceId } = await world.poAndInvoice(45_000);
    const auth = await purchase(agent, { supplierId: world.supplierId, amountCents: 45_000, poId, invoiceId });
    expect(auth.decision).toBe('ALLOW');

    await world.platform.sandboxFaults(['crash_after_processing']);
    const crashed = await apiError(executeFor(agent, auth));
    expect(crashed.status).toBe(500); // the process "died" after the provider accepted the payment

    const stuck = await prisma.transaction.findUniqueOrThrow({ where: { authorizationId: auth.id } });
    expect(stuck.status).toBe('executing');
    expect((await world.admin.get<{ status: string }>(`/v1/invoices/${invoiceId}`)).status).toBe('processing');

    // The agent retries with the same authorization: the gateway reconciles first.
    const retried = await executeFor(agent, auth);
    expect(retried.status).toBe('succeeded');
    expect(retried.retried).toBe(true);
    expect(retried.attempts).toBe(1); // no second execute call was sent

    const ledger = await world.platform.sandboxLedger(auth.id);
    expect(ledger.payments).toHaveLength(1); // exactly one payment at the provider
    expect((await world.admin.get<{ status: string }>(`/v1/invoices/${invoiceId}`)).status).toBe('paid');

    const again = await apiError(executeFor(agent, auth));
    expect(again.code).toBe('AUTHORIZATION_ALREADY_USED');
    expect((await world.platform.sandboxLedger(auth.id)).payments).toHaveLength(1);
  });

  it('15. [required] Human approves after the delegation was revoked → transaction denied', async () => {
    const a = await world.createAgent('Agent #108', { maxTransactionCents: 500_000, monthlyLimitCents: 2_000_000 });
    const { poId, invoiceId } = await world.poAndInvoice(300_000);
    const review = await purchase(a, { supplierId: world.supplierId, amountCents: 300_000, poId, invoiceId });
    expect(review.decision).toBe('REVIEW');

    const delegation = await prisma.delegation.findFirstOrThrow({ where: { agentId: a.id } });
    await world.approver.post(`/v1/delegations/${delegation.id}/revoke`, {});

    const err = await apiError(world.approver.post(`/v1/authorizations/${review.id}/approve`, {}));
    expect(err.code).toBe('NOT_PENDING_REVIEW');
    const after = await world.admin.get<{ status: string; invalidatedReason: string }>(`/v1/authorizations/${review.id}`);
    expect(after.status).toBe('invalidated');
    expect(after.invalidatedReason).toBe('delegation revoked');
    expect((await a.client.authorizations.get(review.id)).token).toBeUndefined();
  });

  it('15b. Approval re-evaluates every rule: a delegation that EXPIRED during review → DENY', async () => {
    const a = await world.createAgent('Agent #109', null);
    await world.approver.post('/v1/delegations', {
      agentId: a.id, actions: ['purchase'], currency: 'USD', maxTransactionCents: 500_000, monthlyLimitCents: 2_000_000,
      expiresAt: new Date(Date.now() + 2_500).toISOString(),
    });
    const { poId, invoiceId } = await world.poAndInvoice(300_000);
    const review = await purchase(a, { supplierId: world.supplierId, amountCents: 300_000, poId, invoiceId });
    expect(review.decision).toBe('REVIEW');
    await new Promise((r) => setTimeout(r, 3_000));

    const result = await world.approver.post<{ status: string; decision: string; reasonCodes: string[] }>(`/v1/authorizations/${review.id}/approve`, {});
    expect(result.decision).toBe('DENY');
    expect(result.status).toBe('denied');
    expect(result.reasonCodes).toContain('DELEGATION_EXPIRED');
  });

  it('16. Provider timeout after processing → outcome UNKNOWN (not failure) → reconciled, one payment', async () => {
    const { poId, invoiceId } = await world.poAndInvoice(30_000);
    const auth = await purchase(agent, { supplierId: world.supplierId, amountCents: 30_000, poId, invoiceId });
    await world.platform.sandboxFaults(['timeout_after_processing']);
    const first = await executeFor(agent, auth);
    expect(first.status).toBe('unknown');

    // A new authorization for the same invoice is refused while the outcome is unknown.
    const dup = await purchase(agent, { supplierId: world.supplierId, amountCents: 30_000, poId, invoiceId });
    expect(dup.decision).toBe('DENY');
    expect(dup.reasonCodes).toContain('INVOICE_IN_FLIGHT');

    const txn = await prisma.transaction.findUniqueOrThrow({ where: { authorizationId: auth.id } });
    const reconciled = await world.admin.post<{ status: string; attempts: number }>(`/v1/transactions/${txn.id}/reconcile`, {});
    expect(reconciled.status).toBe('succeeded');
    expect(reconciled.attempts).toBe(1);
    expect((await world.platform.sandboxLedger(auth.id)).payments).toHaveLength(1);
  });

  it('17. Provider timeout BEFORE processing → reconciliation finds nothing → safe resend with same key', async () => {
    const { poId, invoiceId } = await world.poAndInvoice(31_000);
    const auth = await purchase(agent, { supplierId: world.supplierId, amountCents: 31_000, poId, invoiceId });
    await world.platform.sandboxFaults(['timeout_before_processing']);
    expect((await executeFor(agent, auth)).status).toBe('unknown');
    expect((await world.platform.sandboxLedger(auth.id)).payments).toHaveLength(0);

    const retried = await executeFor(agent, auth);
    expect(retried.status).toBe('succeeded');
    expect(retried.attempts).toBe(2);
    expect((await world.platform.sandboxLedger(auth.id)).payments).toHaveLength(1);

    const txn = await world.admin.get<{ providerAttempts: { action: string; outcome: string }[] }>(`/v1/transactions/${retried.id}`);
    expect(txn.providerAttempts.map((x) => `${x.action}:${x.outcome}`)).toEqual(['execute:unknown', 'status_query:not_found', 'execute:succeeded']);
  });

  it('18. Provider declines → FAILED; hold released and invoice reopened', async () => {
    const { poId, invoiceId } = await world.poAndInvoice(32_000);
    const auth = await purchase(agent, { supplierId: world.supplierId, amountCents: 32_000, poId, invoiceId });
    await world.platform.sandboxFaults(['decline']);
    expect((await executeFor(agent, auth)).status).toBe('failed');
    expect((await world.admin.get<{ status: string }>(`/v1/invoices/${invoiceId}`)).status).toBe('open');
    const retry = await purchase(agent, { supplierId: world.supplierId, amountCents: 32_000, poId, invoiceId });
    expect(retry.decision).toBe('ALLOW');
  });

  it('19. Policy changes after authorization → old authorization is invalid', async () => {
    const { poId, invoiceId } = await world.poAndInvoice(33_000);
    const auth = await purchase(agent, { supplierId: world.supplierId, amountCents: 33_000, poId, invoiceId });
    expect(auth.decision).toBe('ALLOW');
    await raiseViolationThreshold(world); // creates a new policy version
    expect((await apiError(executeFor(agent, auth))).code).toBe('AUTHORIZATION_INVALIDATED');
  });

  it('The audit trail for everything above verifies end-to-end', async () => {
    const result = await world.admin.get<{ valid: boolean; eventsChecked: number; problems: unknown[] }>('/v1/audit/verify');
    expect(result.problems).toEqual([]);
    expect(result.valid).toBe(true);
    expect(result.eventsChecked).toBeGreaterThan(60);
  });
});
