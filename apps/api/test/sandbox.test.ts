import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createApp } from '../src/app';
import { loadConfig } from '../src/config';
import { PrismaService } from '../src/common/prisma.service';
import { AgentTrust, AgentTrustAdmin, generateEd25519KeyPair } from '@agenttrust/sdk';
import { apiError, BANK_GOOD, last4, startServer, uniq, type TestServer } from './helpers';
import type { INestApplication } from '@nestjs/common';
import type { AddressInfo } from 'node:net';

/**
 * Self-service hosted sandbox: a developer with nothing but the base URL signs
 * up, gets persona tokens, and completes a real authorization + payment.
 */
let server: TestServer;

beforeAll(async () => {
  server = await startServer();
});
afterAll(async () => {
  await server.close();
});

async function call<T = any>(baseUrl: string, method: string, path: string, opts: { key?: string; body?: unknown; headers?: Record<string, string> } = {}) {
  const headers: Record<string, string> = { ...(opts.headers ?? {}) };
  if (opts.key) headers['x-agenttrust-sandbox-key'] = opts.key;
  if (opts.body !== undefined) headers['content-type'] = 'application/json';
  const res = await fetch(`${baseUrl}${path}`, { method, headers, body: opts.body === undefined ? undefined : JSON.stringify(opts.body) });
  const text = await res.text();
  return { status: res.status, body: (text ? JSON.parse(text) : undefined) as T };
}

async function signup(baseUrl = server.baseUrl) {
  const res = await call(baseUrl, 'POST', '/v1/sandbox/signup', { body: { organizationName: `Eval Co ${uniq()}`, email: `dev+${uniq()}@eval.test` } });
  expect(res.status).toBe(201);
  return res.body as { organizationId: string; sandboxKey: string; personas: Record<'admin' | 'verifier' | 'approver', { id: string; role: string }> };
}

async function persona(key: string, p: 'admin' | 'verifier' | 'approver') {
  const res = await call(server.baseUrl, 'POST', '/v1/sandbox/token', { key, body: { persona: p } });
  expect(res.status).toBe(201);
  return new AgentTrustAdmin({ baseUrl: server.baseUrl, accessToken: res.body.accessToken });
}

/** Everything a developer does in the quickstart, through public endpoints only. */
async function journey(key: string) {
  const admin = await persona(key, 'admin');
  const verifier = await persona(key, 'verifier');
  const approver = await persona(key, 'approver');

  const supplier = await admin.post<{ id: string }>('/v1/suppliers', { name: 'Northwind Industrial Supply', paymentDestination: BANK_GOOD });
  await verifier.post(`/v1/suppliers/${supplier.id}/verify-payment-destination`, {
    evidence: 'Sandbox: called supplier AP at the number on the master agreement; confirmed account.',
    confirmedLast4: last4(BANK_GOOD),
  });

  const keys = generateEd25519KeyPair();
  const users = await admin.get<{ users: { id: string; role: string; email: string }[] }>('/v1/users');
  const owner = users.users.find((u) => u.role === 'admin' && !u.email.startsWith('verifier+'))!;
  const reg = await admin.post<{ agent: { id: string }; credential: { id: string } }>('/v1/agents', { name: 'Procurement agent', ownerUserId: owner.id, publicKeyPem: keys.publicKeyPem });
  await approver.post('/v1/delegations', {
    agentId: reg.agent.id, actions: ['purchase'], currency: 'USD', maxTransactionCents: 100_000, monthlyLimitCents: 500_000,
    expiresAt: new Date(Date.now() + 7 * 86_400_000).toISOString(),
  });
  const po = await admin.post<{ id: string }>('/v1/purchase-orders', { supplierId: supplier.id, externalReference: `PO-${uniq()}`, approvedAmountCents: 48_000, currency: 'USD' });
  const lines = [{ lineNumber: 1, sku: 'DRL-100', description: 'Cordless drill', quantity: '4', unitPriceCents: 12_000 }];
  const instruction = await admin.post<{ id: string }>('/v1/purchase-instructions', {
    agentId: reg.agent.id, supplierId: supplier.id, purchaseOrderId: po.id, fulfillmentType: 'physical_goods', currency: 'USD',
    lines, maxUses: 1, expiresAt: new Date(Date.now() + 7 * 86_400_000).toISOString(),
  });
  await approver.post(`/v1/purchase-instructions/${instruction.id}/approve`, {});
  const invoice = await admin.post<{ id: string }>('/v1/invoices', {
    supplierId: supplier.id, purchaseOrderId: po.id, purchaseInstructionId: instruction.id, invoiceNumber: `INV-${uniq()}`, amountCents: 48_000, currency: 'USD',
    lines: lines.map((l) => ({ ...l, instructionLineNumber: l.lineNumber })),
  });

  const agent = new AgentTrust({ baseUrl: server.baseUrl, credentialId: reg.credential.id, privateKeyPem: keys.privateKeyPem });
  const auth = await agent.authorizations.create({
    idempotencyKey: `buy-${uniq()}`, action: 'purchase', supplierId: supplier.id, payee: BANK_GOOD, amountCents: 48_000, currency: 'USD',
    purchaseOrderId: po.id, invoiceId: invoice.id, purchaseInstructionId: instruction.id,
  });
  const tx = auth.token
    ? await agent.transactions.execute({ token: auth.token, expected: { supplierId: supplier.id, amountCents: 48_000, currency: 'USD', purchaseOrderId: po.id, invoiceId: invoice.id } })
    : null;
  return { admin, auth, tx, invoiceId: invoice.id };
}

describe('self-service hosted sandbox', () => {
  it('signup → persona tokens → ALLOW → execute → settle via signed webhook → invoice paid; progress is measured', async () => {
    const acct = await signup();
    expect(acct.sandboxKey).toMatch(/^atsk_sbx_[a-f0-9]{48}$/);
    expect(acct.personas.verifier.role).toBe('admin');
    expect(acct.personas.approver.role).toBe('approver');

    const { admin, auth, tx, invoiceId } = await journey(acct.sandboxKey);
    expect(auth.decision).toBe('ALLOW');
    expect(tx!.status).toBe('accepted');

    const settled = await call(server.baseUrl, 'POST', `/v1/sandbox/transactions/${tx!.id}/advance`, { key: acct.sandboxKey, body: { status: 'settled' } });
    expect(settled.status).toBe(201);
    expect(settled.body.transactionStatus).toBe('settled');
    const invoice = await admin.get<{ status: string }>(`/v1/invoices/${invoiceId}`);
    expect(invoice.status).toBe('paid');

    const progress = await call(server.baseUrl, 'GET', '/v1/sandbox/progress', { key: acct.sandboxKey });
    expect(progress.status).toBe(200);
    expect(progress.body.completed).toBe(true);
    for (const step of ['agentRegistered', 'instructionApproved', 'firstAuthorization', 'firstAllow', 'firstExecution', 'firstSettledPayment']) {
      expect(progress.body.steps[step], step).not.toBeNull();
    }
    expect(progress.body.minutesToFirstSettledPayment).toBeGreaterThanOrEqual(0);
  });

  it('the sandbox key is stored only as a keyed hash and never written to the audit log', async () => {
    const acct = await signup();
    const prisma = server.app.get(PrismaService);
    const row = await prisma.sandboxAccount.findUniqueOrThrow({ where: { organizationId: acct.organizationId } });
    expect(row.keyHash).not.toContain(acct.sandboxKey);
    expect(acct.sandboxKey.startsWith(row.keyPrefix)).toBe(true);
    const events = await prisma.auditEvent.findMany({ where: { organizationId: acct.organizationId } });
    expect(events.map((e) => e.eventType)).toEqual(expect.arrayContaining(['organization.created', 'user.created', 'sandbox.account_created']));
    expect(JSON.stringify(events)).not.toContain(acct.sandboxKey);
  });

  it('separation of duties is not relaxed: the admin who entered bank details cannot also verify them', async () => {
    const acct = await signup();
    const admin = await persona(acct.sandboxKey, 'admin');
    const s = await admin.post<{ id: string }>('/v1/suppliers', { name: 'Self-verified Co', paymentDestination: BANK_GOOD });
    const err = await apiError(admin.post(`/v1/suppliers/${s.id}/verify-payment-destination`, {
      evidence: 'Called supplier AP at the number on the signed master agreement; confirmed account.',
      confirmedLast4: last4(BANK_GOOD),
    }));
    expect(err.status).toBe(403);
  });

  it('tenant isolation: one sandbox key cannot touch another sandbox’s payments', async () => {
    const a = await signup();
    const b = await signup();
    const { tx } = await journey(a.sandboxKey);
    const cross = await call(server.baseUrl, 'POST', `/v1/sandbox/transactions/${tx!.id}/advance`, { key: b.sandboxKey, body: { status: 'settled' } });
    expect(cross.status).toBe(404);
    // B's persona tokens are B's users, and cannot read A's transaction either.
    const bAdmin = await persona(b.sandboxKey, 'admin');
    await expect(bAdmin.get(`/v1/transactions/${tx!.id}`)).rejects.toMatchObject({ status: 404 });
  });

  it('missing, malformed, unknown and expired keys are refused', async () => {
    expect((await call(server.baseUrl, 'POST', '/v1/sandbox/token', { body: { persona: 'admin' } })).status).toBe(401);
    expect((await call(server.baseUrl, 'POST', '/v1/sandbox/token', { key: 'atsk_sbx_nothex', body: { persona: 'admin' } })).status).toBe(401);
    expect((await call(server.baseUrl, 'POST', '/v1/sandbox/token', { key: `atsk_sbx_${'0'.repeat(48)}`, body: { persona: 'admin' } })).status).toBe(401);
    expect((await call(server.baseUrl, 'POST', '/v1/sandbox/token', { key: (await signup()).sandboxKey, body: { persona: 'root' } })).status).toBe(400);

    const acct = await signup();
    await server.app.get(PrismaService).sandboxAccount.update({ where: { organizationId: acct.organizationId }, data: { expiresAt: new Date(Date.now() - 1000) } });
    const expired = await call(server.baseUrl, 'POST', '/v1/sandbox/token', { key: acct.sandboxKey, body: { persona: 'admin' } });
    expect(expired.status).toBe(403);
    expect(expired.body.error.code).toBe('SANDBOX_EXPIRED');
  });

  it('operator metrics need the bootstrap token and report time-to-first-settled-payment', async () => {
    expect((await call(server.baseUrl, 'GET', '/v1/sandbox/metrics')).status).toBe(401);
    const res = await call(server.baseUrl, 'GET', '/v1/sandbox/metrics', { headers: { 'x-agenttrust-bootstrap-token': process.env.AGENTTRUST_BOOTSTRAP_TOKEN! } });
    expect(res.status).toBe(200);
    expect(res.body.completedFirstSettledPayment).toBeGreaterThanOrEqual(1);
    expect(JSON.stringify(res.body)).not.toMatch(/atsk_sbx_[a-f0-9]{48}/);
  });

  it('signup rejects unknown fields (no privilege smuggling)', async () => {
    const res = await call(server.baseUrl, 'POST', '/v1/sandbox/signup', { body: { organizationName: 'X', email: 'x@eval.test', spendingAuthorityCents: 1e12 } });
    expect(res.status).toBe(400);
  });
});

describe('sandbox configuration guards', () => {
  async function boot(overrides: Record<string, string>): Promise<{ app: INestApplication; baseUrl: string }> {
    const app = await createApp(loadConfig({ ...process.env, ...overrides }), { logger: false });
    await app.listen(0, '127.0.0.1');
    return { app, baseUrl: `http://127.0.0.1:${(app.getHttpServer().address() as AddressInfo).port}` };
  }

  it('signup is a 404 when the feature is disabled', async () => {
    const s = await boot({ AGENTTRUST_SANDBOX_SIGNUP: 'false' });
    try {
      expect((await call(s.baseUrl, 'POST', '/v1/sandbox/signup', { body: { organizationName: 'X', email: 'x@eval.test' } })).status).toBe(404);
    } finally {
      await s.app.close();
    }
  });

  it('the platform-wide daily cap returns 503 SANDBOX_CAPACITY', async () => {
    const recent = await server.app.get(PrismaService).sandboxAccount.count({ where: { createdAt: { gte: new Date(Date.now() - 86_400_000) } } });
    const s = await boot({ AGENTTRUST_SANDBOX_MAX_SIGNUPS_PER_DAY: String(recent + 1) });
    try {
      await signup(s.baseUrl);
      const over = await call(s.baseUrl, 'POST', '/v1/sandbox/signup', { body: { organizationName: 'Y', email: 'y@eval.test' } });
      expect(over.status).toBe(503);
      expect(over.body.error.code).toBe('SANDBOX_CAPACITY');
    } finally {
      await s.app.close();
    }
  });

  it('config refuses sandbox signup in production, without dev auth, or without a webhook secret', () => {
    expect(() => loadConfig({ ...process.env, AGENTTRUST_SANDBOX_SIGNUP: 'true', NODE_ENV: 'production', AGENTTRUST_DEV_AUTH: 'false' })).toThrow(/production/);
    expect(() => loadConfig({ ...process.env, AGENTTRUST_SANDBOX_SIGNUP: 'true', AGENTTRUST_DEV_AUTH: 'false' })).toThrow(/DEV_AUTH/);
    expect(() => loadConfig({ ...process.env, AGENTTRUST_SANDBOX_SIGNUP: 'true', AGENTTRUST_SANDBOX_WEBHOOK_SECRET: undefined })).toThrow(/WEBHOOK_SECRET/);
  });
});
