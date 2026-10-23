/**
 * T22: payment finality and reconciliation. Provider acceptance is not
 * payment; webhooks are verified and deduplicated; out-of-order events never
 * move a payment backwards; returns/reversals are never auto-eligible for a
 * new payment.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createHmac } from 'node:crypto';
import { PrismaClient } from '@prisma/client';
import { DevTokenService } from '../src/auth/human-token';
import { loadConfig } from '../src/config';
import { AgentTrustAdmin } from '@agenttrust/sdk';
import { apiError, createWorld, executeFor, patchPolicy, purchase, startServer, uniq, type Agent, type TestServer, type World } from './helpers';

let server: TestServer;
let world: World;
let agent: Agent;
const prisma = new PrismaClient();

beforeAll(async () => {
  server = await startServer();
  world = await createWorld(server.baseUrl, 'Umbrella Supply');
  await patchPolicy(world, (r) => ({ ...r, securityResponse: { ...r.securityResponse, violationSuspendThreshold: 100 } }));
  agent = await world.createAgent('AP Agent #301', { maxTransactionCents: 500_000, monthlyLimitCents: 5_000_000 });
});
afterAll(async () => {
  await prisma.$disconnect();
  await server?.close();
});

async function paid(amount: number) {
  const o = await world.order(agent, amount);
  const auth = await purchase(agent, { ...o, amountCents: amount });
  expect(auth.decision).toBe('ALLOW');
  const txn = await executeFor(agent, auth);
  return { o, auth, txn };
}

const invoiceStatus = async (id: string) => (await world.admin.get<{ status: string }>(`/v1/invoices/${id}`)).status;
const txnStatus = async (id: string) => (await world.admin.get<{ status: string }>(`/v1/transactions/${id}`)).status;

function signedWebhook(event: Record<string, unknown>, opts: { secret?: string; at?: number } = {}) {
  const body = JSON.stringify(event);
  const t = opts.at ?? Math.floor(Date.now() / 1000);
  const v1 = createHmac('sha256', opts.secret ?? process.env.AGENTTRUST_SANDBOX_WEBHOOK_SECRET!).update(`${t}.${body}`).digest('hex');
  return fetch(`${server.baseUrl}/v1/webhooks/payments/sandbox`, {
    method: 'POST', headers: { 'content-type': 'application/json', 'x-sandbox-signature': `t=${t},v1=${v1}` }, body,
  });
}

describe('provider acceptance is not finality', () => {
  it('accepted → processing → settled; the invoice is paid only at settlement and stays blocked meanwhile', async () => {
    const { o, auth, txn } = await paid(25_000);
    expect(txn.status).toBe('accepted');
    expect(await invoiceStatus(o.invoiceId!)).toBe('processing');

    const dup = await purchase(agent, { ...o, amountCents: 25_000 });
    expect(dup.decision).toBe('DENY');
    expect(dup.reasonCodes).toContain('INVOICE_IN_FLIGHT');

    await world.platform.sandboxAdvance(auth.id, 'processing');
    expect(await txnStatus(txn.id)).toBe('processing');
    expect(await invoiceStatus(o.invoiceId!)).toBe('processing');

    await world.platform.sandboxAdvance(auth.id, 'settled');
    expect(await txnStatus(txn.id)).toBe('settled');
    expect(await invoiceStatus(o.invoiceId!)).toBe('paid');
  });

  it('delayed confirmation without webhooks is picked up by reconciliation polling', async () => {
    const { o, auth, txn } = await paid(26_000);
    await world.platform.sandboxAdvance(auth.id, 'settled', { deliverWebhook: false });
    expect(await txnStatus(txn.id)).toBe('accepted'); // we have not been told yet
    const r = await world.admin.post<{ status: string }>(`/v1/transactions/${txn.id}/reconcile`, {});
    expect(r.status).toBe('settled');
    expect(await invoiceStatus(o.invoiceId!)).toBe('paid');
  });

  it('a timeout is not failure: unknown → reconciled to the provider\'s actual (accepted) state', async () => {
    const o = await world.order(agent, 27_000);
    const auth = await purchase(agent, { ...o, amountCents: 27_000 });
    await world.platform.sandboxFaults(['timeout_after_processing']);
    const first = await executeFor(agent, auth);
    expect(first.status).toBe('unknown');
    const again = await executeFor(agent, auth);
    expect(again).toMatchObject({ status: 'accepted', retried: true, attempts: 1 });
    expect((await world.platform.sandboxLedger(auth.id)).payments).toHaveLength(1);
  });
});

describe('webhooks: authenticity, deduplication, ordering', () => {
  it('a duplicate delivery of the same event is applied once', async () => {
    const { auth, txn } = await paid(28_000);
    const res = await world.platform.sandboxAdvance(auth.id, 'settled', { duplicateDelivery: true });
    expect(res.deliveries.map((d) => [d.outcome, d.duplicate])).toEqual([['applied', false], ['applied', true]]);
    const settledEvents = await prisma.auditEvent.count({ where: { subjectId: txn.id, eventType: 'payment.settled' } });
    expect(settledEvents).toBe(1);
  });

  it('a different payload under an already-seen event id is rejected', async () => {
    const { auth } = await paid(29_000);
    const id = `evt_${uniq()}`;
    const ok = await signedWebhook({ id, type: 'payment.processing', created: Math.floor(Date.now() / 1000), data: { idempotencyKey: auth.id, status: 'processing' } });
    expect(ok.status).toBe(201);
    const conflict = await signedWebhook({ id, type: 'payment.settled', created: Math.floor(Date.now() / 1000), data: { idempotencyKey: auth.id, status: 'settled' } });
    expect(conflict.status).toBe(409);
  });

  it('out-of-order events never move a payment backwards', async () => {
    const { auth, txn } = await paid(30_000);
    await world.platform.sandboxAdvance(auth.id, 'settled');
    const late = await signedWebhook({ id: `evt_${uniq()}`, type: 'payment.processing', created: Math.floor(Date.now() / 1000) - 60, data: { idempotencyKey: auth.id, status: 'processing' } });
    expect(((await late.json()) as { outcome: string }).outcome).toBe('ignored_stale');
    expect(await txnStatus(txn.id)).toBe('settled');
  });

  it('forged, stale or malformed webhooks are refused; unknown payments are recorded, not applied', async () => {
    const { auth, txn } = await paid(31_000);
    const event = { id: `evt_${uniq()}`, type: 'payment.settled', created: Math.floor(Date.now() / 1000), data: { idempotencyKey: auth.id, status: 'settled' } };
    expect((await signedWebhook(event, { secret: 'x'.repeat(64) })).status).toBe(401);
    expect((await signedWebhook(event, { at: Math.floor(Date.now() / 1000) - 3600 })).status).toBe(401);
    expect((await fetch(`${server.baseUrl}/v1/webhooks/payments/sandbox`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(event) })).status).toBe(401);
    expect(await txnStatus(txn.id)).toBe('accepted');
    const unknown = await signedWebhook({ ...event, id: `evt_${uniq()}`, data: { idempotencyKey: 'auth_unknown', status: 'settled' } });
    expect(((await unknown.json()) as { outcome: string }).outcome).toBe('unknown_transaction');
  });
});

describe('returns and reversals', () => {
  it('a returned payment puts the invoice on hold; it is NOT eligible for another payment until reconciled and explicitly released', async () => {
    const { o, auth, txn } = await paid(32_000);
    await world.platform.sandboxAdvance(auth.id, 'settled');
    expect(await invoiceStatus(o.invoiceId!)).toBe('paid');
    await world.platform.sandboxAdvance(auth.id, 'returned');
    expect(await txnStatus(txn.id)).toBe('returned');
    expect(await invoiceStatus(o.invoiceId!)).toBe('payment_exception');
    const { alerts } = await world.admin.get<{ alerts: { category?: string; subjectId: string }[] }>('/v1/alerts');
    expect(alerts.some((a) => a.category === 'payment_exception' && a.subjectId === txn.id)).toBe(true);

    // No automatic retry: the invoice and the instruction capacity stay blocked.
    const retry = await purchase(agent, { ...o, amountCents: 32_000 });
    expect(retry.decision).toBe('DENY');
    expect(retry.reasonCodes).toEqual(expect.arrayContaining(['INVOICE_PAYMENT_EXCEPTION', 'INSTRUCTION_USES_EXHAUSTED']));
    expect((await apiError(executeFor(agent, auth))).code).toBe('AUTHORIZATION_ALREADY_USED');

    // Release requires an admin with a fresh login...
    const stale = new DevTokenService(loadConfig(process.env)).issue(`dev|${world.adminUserId}`, new Date(Date.now() - 10 * 60_000));
    const staleAdmin = new AgentTrustAdmin({ baseUrl: server.baseUrl, accessToken: stale.accessToken });
    expect((await apiError(staleAdmin.post(`/v1/transactions/${txn.id}/resolve`, { note: 'Supplier confirmed account closed' }))).code).toBe('REAUTHENTICATION_REQUIRED');
    expect((await apiError(world.approver.post(`/v1/transactions/${txn.id}/resolve`, { note: 'Supplier confirmed account closed' }))).code).toBe('ROLE_REQUIRED');
    const released = await world.admin.post<{ resolution: string }>(`/v1/transactions/${txn.id}/resolve`, { note: 'Supplier confirmed account closed; re-pay new verified account' });
    expect(released.resolution).toBe('released_for_reauthorization');
    expect(await invoiceStatus(o.invoiceId!)).toBe('open');

    // ...and then a NEW authorization is required (the old one stays consumed).
    const fresh = await purchase(agent, { ...o, amountCents: 32_000 });
    expect(fresh.decision).toBe('ALLOW');
    expect(fresh.id).not.toBe(auth.id);
  });

  it('release is refused when the provider disagrees (money may still be moving)', async () => {
    const { auth, txn } = await paid(33_000);
    await world.platform.sandboxAdvance(auth.id, 'reversed');
    expect(await txnStatus(txn.id)).toBe('reversed');
    await world.platform.sandboxAdvance(auth.id, 'settled', { deliverWebhook: false }); // provider now reports settled
    expect((await apiError(world.admin.post(`/v1/transactions/${txn.id}/resolve`, { note: 'trying to release a payment' }))).code).toBe('PROVIDER_DISAGREES');
  });

  it('a failure AFTER acceptance is held as an exception; a decline BEFORE acceptance is released automatically', async () => {
    const { o, auth, txn } = await paid(34_000);
    await world.platform.sandboxAdvance(auth.id, 'failed');
    expect(await txnStatus(txn.id)).toBe('failed');
    expect(await invoiceStatus(o.invoiceId!)).toBe('payment_exception');

    const o2 = await world.order(agent, 35_000);
    const auth2 = await purchase(agent, { ...o2, amountCents: 35_000 });
    await world.platform.sandboxFaults(['decline']);
    expect((await executeFor(agent, auth2)).status).toBe('failed');
    expect(await invoiceStatus(o2.invoiceId!)).toBe('open');
  });

  it('settled payments cannot be "resolved" away', async () => {
    const { auth, txn } = await paid(36_000);
    await world.platform.sandboxAdvance(auth.id, 'settled');
    expect((await apiError(world.admin.post(`/v1/transactions/${txn.id}/resolve`, { note: 'release a settled payment' }))).code).toBe('NOT_RESOLVABLE');
  });
});
