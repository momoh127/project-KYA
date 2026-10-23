/**
 * Security invariants: tenant isolation, forged identity, replay, privilege
 * escalation, request smuggling, idempotency, dual control, append-only audit.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { PrismaClient } from '@prisma/client';
import { generateEd25519KeyPair, signRequest } from '@agenttrust/identity';
import { AgentTrust } from '@agenttrust/sdk';
import { apiError, BANK_ATTACKER, BANK_GOOD, createWorld, executeFor, purchase, startServer, uniq, type Agent, type TestServer, type World } from './helpers';

let server: TestServer;
let acme: World;
let globex: World;
let acmeAgent: Agent;
let globexAgent: Agent;
const prisma = new PrismaClient();

beforeAll(async () => {
  server = await startServer();
  acme = await createWorld(server.baseUrl, 'Acme Manufacturing');
  globex = await createWorld(server.baseUrl, 'Globex Corp');
  acmeAgent = await acme.createAgent('Acme Agent', { maxTransactionCents: 500_000, monthlyLimitCents: 2_000_000 });
  globexAgent = await globex.createAgent('Globex Agent', { maxTransactionCents: 500_000, monthlyLimitCents: 2_000_000 });
});
afterAll(async () => {
  await prisma.$disconnect();
  await server?.close();
});

describe('tenant isolation', () => {
  it('humans cannot read another organization\'s records (404, not 403)', async () => {
    for (const path of [`/v1/organizations/${acme.orgId}`, `/v1/agents/${acmeAgent.id}`, `/v1/suppliers/${acme.supplierId}`]) {
      expect((await apiError(globex.admin.get(path))).status).toBe(404);
    }
  });

  it('an agent cannot use another organization\'s supplier, PO or invoice', async () => {
    const { poId, invoiceId } = await acme.poAndInvoice(50_000);
    const r = await purchase(globexAgent, { supplierId: acme.supplierId, amountCents: 50_000, poId, invoiceId });
    expect(r.decision).not.toBe('ALLOW');
    expect(r.reasonCodes).toEqual(expect.arrayContaining(['SUPPLIER_UNKNOWN']));
    expect(r.decision).toBe('DENY'); // PO/invoice ids resolve to "not found" in Globex's scope
    expect(r.reasonCodes).toEqual(expect.arrayContaining(['PO_NOT_FOUND', 'INVOICE_NOT_FOUND']));
  });

  it('an agent cannot execute another agent\'s authorization', async () => {
    const { poId, invoiceId } = await acme.poAndInvoice(50_000);
    const auth = await purchase(acmeAgent, { supplierId: acme.supplierId, amountCents: 50_000, poId, invoiceId });
    expect(auth.decision).toBe('ALLOW');
    expect((await apiError(executeFor(globexAgent, auth))).code).toBe('TOKEN_NOT_ISSUED_TO_CALLER');
    const sibling = await acme.createAgent('Acme Sibling', { maxTransactionCents: 500_000, monthlyLimitCents: 2_000_000 });
    expect((await apiError(executeFor(sibling, auth))).code).toBe('TOKEN_NOT_ISSUED_TO_CALLER');
    expect((await apiError(globexAgent.client.authorizations.get(auth.id))).status).toBe(404);
  });

  it('request bodies cannot smuggle in organization or approval fields', async () => {
    const err = await apiError(
      acmeAgent.client.authorizations.create({
        idempotencyKey: `smuggle-${uniq()}`, action: 'purchase', supplierId: acme.supplierId, payee: BANK_GOOD,
        amountCents: 50_000, currency: 'USD',
        ...({ organizationId: globex.orgId, approved: true } as object),
      }),
    );
    expect(err.status).toBe(400);
  });
});

describe('agent identity', () => {
  it('rejects requests signed with the wrong key (forged identity)', async () => {
    const impostor = new AgentTrust({ baseUrl: server.baseUrl, credentialId: acmeAgent.credentialId, privateKeyPem: generateEd25519KeyPair().privateKeyPem });
    const err = await apiError(purchase({ ...acmeAgent, client: impostor }, { supplierId: acme.supplierId, amountCents: 50_000 }));
    expect(err.status).toBe(401);
  });

  it('rejects a replayed signed request', async () => {
    const body = JSON.stringify({ idempotencyKey: `replay-${uniq()}`, action: 'purchase', supplierId: acme.supplierId, payee: BANK_GOOD, amountCents: 1_000, currency: 'USD' });
    const headers = { ...signRequest({ credentialId: acmeAgent.credentialId, privateKeyPem: acmeAgent.privateKeyPem, method: 'POST', path: '/v1/authorizations', body }), 'content-type': 'application/json' };
    const first = await fetch(`${server.baseUrl}/v1/authorizations`, { method: 'POST', headers, body });
    expect(first.status).toBe(201);
    const second = await fetch(`${server.baseUrl}/v1/authorizations`, { method: 'POST', headers, body });
    expect(second.status).toBe(401);
    expect(((await second.json()) as { error: { message: string } }).error.message).toMatch(/Replayed/);
  });

  it('rejects a signed request whose body was modified in transit', async () => {
    const body = JSON.stringify({ idempotencyKey: `mitm-${uniq()}`, action: 'purchase', supplierId: acme.supplierId, payee: BANK_GOOD, amountCents: 1_000, currency: 'USD' });
    const headers = { ...signRequest({ credentialId: acmeAgent.credentialId, privateKeyPem: acmeAgent.privateKeyPem, method: 'POST', path: '/v1/authorizations', body }), 'content-type': 'application/json' };
    const res = await fetch(`${server.baseUrl}/v1/authorizations`, { method: 'POST', headers, body: body.replace('1000', '9000') });
    expect(res.status).toBe(401);
  });

  it('agents cannot call any human/governance endpoint', async () => {
    for (const path of ['/v1/delegations', '/v1/suppliers', '/v1/policies', '/v1/agents']) {
      const body = '{}';
      const headers = { ...signRequest({ credentialId: acmeAgent.credentialId, privateKeyPem: acmeAgent.privateKeyPem, method: 'POST', path, body }), 'content-type': 'application/json' };
      const res = await fetch(`${server.baseUrl}${path}`, { method: 'POST', headers, body });
      expect(res.status).toBe(401);
    }
  });
});

describe('privilege escalation', () => {
  it('enforces roles', async () => {
    expect((await apiError(acme.approver.post('/v1/agents', {}))).code).toBe('ROLE_REQUIRED');
    expect((await apiError(acme.member.post('/v1/delegations', {}))).code).toBe('ROLE_REQUIRED');
    expect((await apiError(acme.member.post(`/v1/authorizations/auth_${'0'.repeat(32)}/approve`, {}))).code).toBe('ROLE_REQUIRED');
  });

  it('a person cannot delegate or approve more than their own authority', async () => {
    const err = await apiError(acme.approver.post('/v1/delegations', {
      agentId: acmeAgent.id, actions: ['purchase'], currency: 'USD', maxTransactionCents: 5_000_000, monthlyLimitCents: 5_000_000,
      expiresAt: new Date(Date.now() + 86_400_000).toISOString(),
    }));
    expect(err.code).toBe('INSUFFICIENT_AUTHORITY');
    expect((await apiError(acme.approver.post('/v1/purchase-orders', {
      supplierId: acme.supplierId, externalReference: `PO-${uniq()}`, approvedAmountCents: 5_000_000, currency: 'USD',
    }))).code).toBe('INSUFFICIENT_AUTHORITY');
  });

  it('unauthenticated requests are rejected', async () => {
    for (const path of ['/v1/agents', '/v1/suppliers', '/v1/audit/events']) {
      expect((await fetch(`${server.baseUrl}${path}`)).status).toBe(401);
    }
    const bad = await fetch(`${server.baseUrl}/v1/agents`, { headers: { authorization: 'Bearer forged.token.value' } });
    expect(bad.status).toBe(401);
  });
});

describe('payee protection (dual control)', () => {
  it('the admin who changes bank details cannot also verify them', async () => {
    const s = await acme.admin.post<{ id: string }>('/v1/suppliers', { name: 'Dual Control Co', paymentDestination: BANK_GOOD, verificationStatus: 'verified' });
    const changed = await acme.admin.patch<{ verificationStatus: string }>(`/v1/suppliers/${s.id}`, { paymentDestination: BANK_ATTACKER });
    expect(changed.verificationStatus).toBe('pending');
    expect((await apiError(acme.admin.patch(`/v1/suppliers/${s.id}`, { verificationStatus: 'verified' }))).code).toBe('DUAL_CONTROL_REQUIRED');
    expect((await apiError(acme.admin.patch(`/v1/suppliers/${s.id}`, { paymentDestination: BANK_GOOD, verificationStatus: 'verified' }))).code).toBe('DUAL_CONTROL_REQUIRED');
    const verified = await acme.admin2.patch<{ verificationStatus: string }>(`/v1/suppliers/${s.id}`, { verificationStatus: 'verified' });
    expect(verified.verificationStatus).toBe('verified');
  });

  it('purchases from a supplier pending re-verification go to REVIEW, not ALLOW', async () => {
    const s = await acme.admin.post<{ id: string }>('/v1/suppliers', { name: 'Pending Co', paymentDestination: BANK_GOOD, verificationStatus: 'pending' });
    const { poId, invoiceId } = await acme.poAndInvoice(10_000, s.id);
    const r = await purchase(acmeAgent, { supplierId: s.id, amountCents: 10_000, poId, invoiceId });
    expect(r.decision).toBe('REVIEW');
    expect(r.approvable).toBe(false);
  });
});

describe('idempotency and duplicates', () => {
  it('same key + same transaction returns the same authorization; a different transaction conflicts', async () => {
    const { poId, invoiceId } = await acme.poAndInvoice(20_000);
    const key = `idem-${uniq()}`;
    const a = await purchase(acmeAgent, { supplierId: acme.supplierId, amountCents: 20_000, poId, invoiceId, key });
    const b = await purchase(acmeAgent, { supplierId: acme.supplierId, amountCents: 20_000, poId, invoiceId, key });
    expect(b.id).toBe(a.id);
    const c = await apiError(purchase(acmeAgent, { supplierId: acme.supplierId, amountCents: 19_999, poId, invoiceId, key }));
    expect(c.code).toBe('IDEMPOTENCY_CONFLICT');
  });

  it('the same invoice cannot be held by two live authorizations', async () => {
    const { poId, invoiceId } = await acme.poAndInvoice(20_000);
    const first = await purchase(acmeAgent, { supplierId: acme.supplierId, amountCents: 20_000, poId, invoiceId });
    expect(first.decision).toBe('ALLOW');
    const second = await purchase(acmeAgent, { supplierId: acme.supplierId, amountCents: 20_000, poId, invoiceId });
    expect(second.decision).toBe('DENY');
    expect(second.reasonCodes).toContain('INVOICE_IN_FLIGHT');
  });

  it('a duplicate supplier invoice number cannot be recorded twice', async () => {
    const number = `INV-${uniq()}`;
    await acme.admin.post('/v1/invoices', { supplierId: acme.supplierId, invoiceNumber: number, amountCents: 1_000, currency: 'USD' });
    expect((await apiError(acme.admin.post('/v1/invoices', { supplierId: acme.supplierId, invoiceNumber: number, amountCents: 1_000, currency: 'USD' }))).code).toBe('DUPLICATE_INVOICE');
  });
});

describe('input validation and delegation scope', () => {
  it('rejects invalid amounts and payees', async () => {
    for (const amountCents of [10.5, -100, 0]) {
      expect((await apiError(purchase(acmeAgent, { supplierId: acme.supplierId, amountCents }))).status).toBe(400);
    }
    const badPayee = await apiError(purchase(acmeAgent, { supplierId: acme.supplierId, amountCents: 100, payee: { type: 'us_ach', routingNumber: '12', accountNumber: '1' } }));
    expect(badPayee.status).toBe(400);
  });

  it('an agent without a delegation is denied', async () => {
    const orphan = await acme.createAgent('No Delegation', null);
    const r = await purchase(orphan, { supplierId: acme.supplierId, amountCents: 1_000 });
    expect(r.decision).toBe('DENY');
    expect(r.reasonCodes).toContain('DELEGATION_MISSING');
  });

  it('a revoked delegation stops spending immediately, including already-issued authorizations', async () => {
    const a = await acme.createAgent('Revocable', { maxTransactionCents: 100_000, monthlyLimitCents: 100_000 });
    const { poId, invoiceId } = await acme.poAndInvoice(10_000);
    const auth = await purchase(a, { supplierId: acme.supplierId, amountCents: 10_000, poId, invoiceId });
    expect(auth.decision).toBe('ALLOW');
    const delegation = await prisma.delegation.findFirstOrThrow({ where: { agentId: a.id } });
    await acme.approver.post(`/v1/delegations/${delegation.id}/revoke`, {});
    expect((await apiError(executeFor(a, auth))).code).toBe('DELEGATION_NO_LONGER_VALID');
  });

  it('supplier-scoped delegations deny other suppliers', async () => {
    const other = await acme.admin.post<{ id: string }>('/v1/suppliers', { name: 'Not Allowed Inc', paymentDestination: BANK_ATTACKER, verificationStatus: 'verified' });
    const scoped = await acme.createAgent('Scoped', { maxTransactionCents: 100_000, monthlyLimitCents: 100_000, approvedSupplierIds: [acme.supplierId] });
    const { poId, invoiceId } = await acme.poAndInvoice(10_000, other.id);
    const r = await purchase(scoped, { supplierId: other.id, payee: BANK_ATTACKER, amountCents: 10_000, poId, invoiceId });
    expect(r.decision).toBe('DENY');
    expect(r.reasonCodes).toContain('SUPPLIER_NOT_DELEGATED');
  });
});

describe('audit evidence', () => {
  it('the database refuses to update or delete audit events', async () => {
    const evt = await prisma.auditEvent.findFirstOrThrow({ where: { organizationId: acme.orgId } });
    await expect(prisma.$executeRawUnsafe(`UPDATE "AuditEvent" SET "eventType" = 'tampered' WHERE id = $1`, evt.id)).rejects.toThrow(/append-only/);
    await expect(prisma.$executeRawUnsafe(`DELETE FROM "AuditEvent" WHERE id = $1`, evt.id)).rejects.toThrow(/append-only/);
  });

  it('each organization\'s chain verifies independently', async () => {
    for (const w of [acme, globex]) {
      const r = await w.admin.get<{ valid: boolean; problems: unknown[] }>('/v1/audit/verify');
      expect(r.problems).toEqual([]);
      expect(r.valid).toBe(true);
    }
  });

  it('only admins can verify; approvers can read events; members cannot', async () => {
    expect((await apiError(acme.approver.get('/v1/audit/verify'))).code).toBe('ROLE_REQUIRED');
    const { events } = await acme.approver.get<{ events: { organizationId: string }[] }>('/v1/audit/events?limit=5');
    expect(events.every((e) => e.organizationId === acme.orgId)).toBe(true);
    expect((await apiError(acme.member.get('/v1/audit/events'))).code).toBe('ROLE_REQUIRED');
  });
});
