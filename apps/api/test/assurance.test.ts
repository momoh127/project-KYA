/**
 * Supplier assurance levels: recorded → reviewed → account_verified →
 * ownership_verified. Independent provider-backed verification defeats two
 * colluding (or compromised) internal approvers.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { apiError, BANK_ATTACKER, BANK_GOOD, createWorld, last4, patchPolicy, purchase, startServer, uniq, type Agent, type TestServer, type World } from './helpers';

let server: TestServer;
let world: World;
let agent: Agent;
const evidence = 'Called supplier AP at the number on the signed master agreement; confirmed account.';

beforeAll(async () => {
  server = await startServer();
  world = await createWorld(server.baseUrl, 'Wayne Industrial');
  agent = await world.createAgent('Agent A1', { maxTransactionCents: 500_000, monthlyLimitCents: 5_000_000 });
});
afterAll(async () => server?.close());

async function supplier(legalName: string | undefined, bank = BANK_GOOD) {
  const s = await world.admin.post<{ id: string; assuranceLevel: string }>('/v1/suppliers', { name: `Supplier ${uniq()}`, legalName, paymentDestination: bank });
  return s;
}

describe('explicit assurance levels', () => {
  it('recorded → reviewed (second person) → ownership_verified (provider), each a new version', async () => {
    const s = await supplier('Gotham Tools LLC');
    expect(s.assuranceLevel).toBe('recorded');
    const reviewed = await world.admin2.post<{ assuranceLevel: string }>(`/v1/suppliers/${s.id}/verify-payment-destination`, { evidence, confirmedLast4: last4(BANK_GOOD) });
    expect(reviewed.assuranceLevel).toBe('reviewed');
    const v = await world.admin.post<{ supplier: { assuranceLevel: string; version: number }; verification: { accountStatus: string; ownerNameMatch: string } }>(
      `/v1/suppliers/${s.id}/account-verification`, { paymentDestination: BANK_GOOD },
    );
    expect(v.verification).toMatchObject({ accountStatus: 'valid', ownerNameMatch: 'match' });
    expect(v.supplier).toMatchObject({ assuranceLevel: 'ownership_verified', version: 3 });
  });

  it('without a legal name on record, the provider can only confirm the account (account_verified)', async () => {
    const s = await supplier(undefined);
    const v = await world.admin.post<{ supplier: { assuranceLevel: string } }>(`/v1/suppliers/${s.id}/account-verification`, { paymentDestination: BANK_GOOD });
    expect(v.supplier.assuranceLevel).toBe('account_verified');
  });

  it('the re-entered bank details must match the destination on record', async () => {
    const s = await supplier('Match Check Inc');
    expect((await apiError(world.admin.post(`/v1/suppliers/${s.id}/account-verification`, { paymentDestination: BANK_ATTACKER }))).status).toBe(400);
  });

  it('a bank change resets assurance to recorded', async () => {
    const s = await supplier('Reset Corp');
    await world.admin.post(`/v1/suppliers/${s.id}/account-verification`, { paymentDestination: BANK_GOOD });
    const changed = await world.admin.patch<{ assuranceLevel: string }>(`/v1/suppliers/${s.id}`, { paymentDestination: BANK_ATTACKER });
    expect(changed.assuranceLevel).toBe('recorded');
  });
});

describe('collusion between two internal approvers', () => {
  it('two admins can push an attacker account to "reviewed", but the provider shows it is not the supplier\'s, and policy blocks large payments', async () => {
    await patchPolicy(world, (r) => ({ ...r, supplierAssurance: { minimum: 'reviewed', byAmount: [{ minAmountCents: 100_000, level: 'ownership_verified' }], insufficient: 'REVIEW' } }));
    const s = await supplier('Legit Supplies Inc');
    await world.admin2.post(`/v1/suppliers/${s.id}/verify-payment-destination`, { evidence, confirmedLast4: last4(BANK_GOOD) });
    await world.admin.post(`/v1/suppliers/${s.id}/account-verification`, { paymentDestination: BANK_GOOD });

    // Colluding admins swap in the attacker's account and "review" it.
    await world.admin.patch(`/v1/suppliers/${s.id}`, { paymentDestination: BANK_ATTACKER });
    const colluded = await world.admin2.post<{ assuranceLevel: string }>(`/v1/suppliers/${s.id}/verify-payment-destination`, { evidence, confirmedLast4: last4(BANK_ATTACKER) });
    expect(colluded.assuranceLevel).toBe('reviewed');

    // Independent verification: the account is NOT held by the supplier → no assurance raise + fraud alert.
    const v = await world.admin.post<{ supplier: { assuranceLevel: string }; verification: { ownerNameMatch: string } }>(
      `/v1/suppliers/${s.id}/account-verification`, { paymentDestination: BANK_ATTACKER },
    );
    expect(v.verification.ownerNameMatch).toBe('no_match');
    expect(v.supplier.assuranceLevel).toBe('reviewed');
    const { alerts } = await world.admin.get<{ alerts: { category?: string; subjectId: string }[] }>('/v1/alerts');
    expect(alerts.some((a) => a.category === 'fraud_signal' && a.subjectId === s.id)).toBe(true);

    // A large payment needs ownership_verified → blocked (not click-approvable).
    const big = await world.order(agent, 200_000, { supplierId: s.id });
    const r = await purchase(agent, { ...big, payee: BANK_ATTACKER, amountCents: 200_000 });
    expect(r.decision).toBe('REVIEW');
    expect(r.reasonCodes).toContain('SUPPLIER_ASSURANCE_INSUFFICIENT');
    expect(r.approvable).toBe(false);
    expect((await apiError(world.approver.post(`/v1/authorizations/${r.id}/approve`, {}))).code).toBe('NOT_APPROVABLE');

    await patchPolicy(world, (r2) => ({ ...r2, supplierAssurance: { minimum: 'reviewed', byAmount: [], insufficient: 'REVIEW' } }));
  });

  it('an account that does not exist never gains assurance', async () => {
    const s = await supplier('Ghost Vendor', { type: 'us_ach', routingNumber: '021000021', accountNumber: '1234560000' });
    const v = await world.admin.post<{ supplier: { assuranceLevel: string }; verification: { accountStatus: string } }>(
      `/v1/suppliers/${s.id}/account-verification`, { paymentDestination: { type: 'us_ach', routingNumber: '021000021', accountNumber: '1234560000' } },
    );
    expect(v.verification.accountStatus).toBe('invalid');
    expect(v.supplier.assuranceLevel).toBe('recorded');
  });
});
