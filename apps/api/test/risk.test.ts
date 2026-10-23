/**
 * Valid-session abuse: an attacker holding a VALID session spends within the
 * agent's limits. Deterministic thresholds route such activity to human
 * approval (or a temporary restriction), raise an alert, and never suspend.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { BANK_ATTACKER, BANK_OTHER_SUPPLIER, createWorld, last4, patchPolicy, purchase, startServer, type TestServer, type World } from './helpers';

let server: TestServer;
let world: World;

beforeAll(async () => {
  server = await startServer();
  world = await createWorld(server.baseUrl, 'Cyberdyne', { riskControls: true }); // default-on checks stay enabled
});
afterAll(async () => server?.close());

describe('suspicious but authenticated activity', () => {
  it('rapid budget depletion within limits → REVIEW + alert, agent stays active, a human can approve', async () => {
    const agent = await world.createAgent('Agent R1', { maxTransactionCents: 400_000, monthlyLimitCents: 1_000_000 }); // $10k / month
    const a = await world.order(agent, 300_000);
    const b = await world.order(agent, 300_000);
    expect((await purchase(agent, { ...a, amountCents: 300_000 })).decision).toBe('REVIEW'); // ≥ $2,500 approval threshold
    // The approval-threshold REVIEW above holds $3,000; the next $3,000 would exceed 50% of the monthly limit in one hour.
    const second = await purchase(agent, { ...b, amountCents: 300_000 });
    expect(second.decision).toBe('REVIEW');
    expect(second.reasonCodes).toContain('RISK_BUDGET_DEPLETION');
    expect(second.approvable).toBe(true);

    expect((await world.admin.get<{ status: string }>(`/v1/agents/${agent.id}`)).status).toBe('active');
    const { alerts } = await world.admin.get<{ alerts: { category?: string; subjectId: string }[] }>('/v1/alerts');
    expect(alerts.some((x) => x.category === 'suspicious_activity' && x.subjectId === agent.id)).toBe(true);

    const approved = await world.approver.post<{ decision: string }>(`/v1/authorizations/${second.id}/approve`, {});
    expect(approved.decision).toBe('ALLOW');
  });

  it('paying a supplier whose bank details changed recently → REVIEW even when everything else matches', async () => {
    const agent = await world.createAgent('Agent R2', { maxTransactionCents: 500_000, monthlyLimitCents: 5_000_000 });
    const supplierId = await world.verifiedSupplier('Recently Changed Ltd', BANK_OTHER_SUPPLIER);
    const before = await world.order(agent, 10_000, { supplierId });
    expect((await purchase(agent, { ...before, payee: BANK_OTHER_SUPPLIER, amountCents: 10_000 })).decision).toBe('ALLOW');

    await world.admin.patch(`/v1/suppliers/${supplierId}`, { paymentDestination: BANK_ATTACKER });
    await world.admin2.post(`/v1/suppliers/${supplierId}/verify-payment-destination`, {
      evidence: 'Supplier called us to confirm the new account; verified against contract.', confirmedLast4: last4(BANK_ATTACKER),
    });
    const after = await world.order(agent, 10_000, { supplierId });
    const r = await purchase(agent, { ...after, payee: BANK_ATTACKER, amountCents: 10_000 });
    expect(r.decision).toBe('REVIEW');
    expect(r.reasonCodes).toEqual(['RISK_RECENT_PAYEE_CHANGE']);
  });

  it('velocity and supplier-frequency limits; DENY mode temporarily restricts without suspending', async () => {
    await patchPolicy(world, (r) => ({ ...r, riskControls: { ...r.riskControls, maxAuthorizationsPerHour: 3, maxPurchasesPerSupplierPerDay: 100 } }));
    const fast = await world.createAgent('Agent R3', { maxTransactionCents: 500_000, monthlyLimitCents: 50_000_000 });
    const decisions: string[] = [];
    for (let i = 0; i < 4; i++) {
      const o = await world.order(fast, 1_000);
      const r = await purchase(fast, { ...o, amountCents: 1_000 });
      decisions.push(r.decision);
      if (i === 3) expect(r.reasonCodes).toContain('RISK_VELOCITY');
    }
    expect(decisions).toEqual(['ALLOW', 'ALLOW', 'ALLOW', 'REVIEW']);

    await patchPolicy(world, (r) => ({ ...r, riskControls: { ...r.riskControls, response: 'DENY' } }));
    const o = await world.order(fast, 1_000);
    const restricted = await purchase(fast, { ...o, amountCents: 1_000 });
    expect(restricted.decision).toBe('DENY');
    expect(restricted.reasonCodes).toContain('RISK_VELOCITY');
    expect((await world.admin.get<{ status: string }>(`/v1/agents/${fast.id}`)).status).toBe('active');

    await patchPolicy(world, (r) => ({ ...r, riskControls: { ...r.riskControls, response: 'REVIEW', maxAuthorizationsPerHour: 100, maxPurchasesPerSupplierPerDay: 2 } }));
    const freq = await world.createAgent('Agent R4', { maxTransactionCents: 500_000, monthlyLimitCents: 50_000_000 });
    const results: string[] = [];
    for (let i = 0; i < 3; i++) {
      const x = await world.order(freq, 1_000);
      results.push((await purchase(freq, { ...x, amountCents: 1_000 })).reasonCodes.includes('RISK_SUPPLIER_FREQUENCY') ? 'FLAGGED' : 'OK');
    }
    expect(results).toEqual(['OK', 'OK', 'FLAGGED']);
  });
});
