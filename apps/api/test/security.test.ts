/**
 * Security invariants: tenant isolation, workload/session identity, replay,
 * DoS-resistant security responses, privilege escalation, request smuggling,
 * idempotency, high-risk supplier changes, append-only audit.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { PrismaClient } from '@prisma/client';
import { generateEd25519KeyPair, signRequest } from '@agenttrust/identity';
import { AgentTrust, AgentTrustAdmin } from '@agenttrust/sdk';
import { DevTokenService } from '../src/auth/human-token';
import { loadConfig } from '../src/config';
import { apiError, BANK_ATTACKER, BANK_GOOD, BANK_OTHER_SUPPLIER, createWorld, executeFor, purchase, startServer, uniq, type Agent, type TestServer, type World } from './helpers';

let server: TestServer;
let acme: World;
let globex: World;
let acmeAgent: Agent;
let globexAgent: Agent;
const prisma = new PrismaClient();

/** Mints a session the raw way, returning its id and private key, for hand-built requests. */
async function rawSession(agent: Agent) {
  const keys = generateEd25519KeyPair();
  const body = JSON.stringify({ publicKeyPem: keys.publicKeyPem, ttlSeconds: 900 });
  const headers = { ...signRequest({ credentialId: agent.credentialId, privateKeyPem: agent.privateKeyPem, method: 'POST', path: '/v1/agent-sessions', body }), 'content-type': 'application/json' };
  const res = await fetch(`${server.baseUrl}/v1/agent-sessions`, { method: 'POST', headers, body });
  expect(res.status).toBe(201);
  const { sessionId } = (await res.json()) as { sessionId: string };
  return { sessionId, privateKeyPem: keys.privateKeyPem };
}

function signedFetch(keyId: string, privateKeyPem: string, method: 'GET' | 'POST', path: string, payload?: unknown) {
  const body = payload === undefined ? '' : JSON.stringify(payload);
  const headers: Record<string, string> = signRequest({ credentialId: keyId, privateKeyPem, method, path, body });
  if (body) headers['content-type'] = 'application/json';
  return fetch(`${server.baseUrl}${path}`, { method, headers, body: body || undefined });
}

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
    expect(r.decision).toBe('DENY');
    expect(r.reasonCodes).toEqual(expect.arrayContaining(['SUPPLIER_UNKNOWN', 'PO_NOT_FOUND', 'INVOICE_NOT_FOUND']));
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

describe('agent identity: workload credentials and short-lived sessions', () => {
  it('the long-lived workload credential cannot authorize or pay; it can only mint sessions', async () => {
    const res = await signedFetch(acmeAgent.credentialId, acmeAgent.privateKeyPem, 'POST', '/v1/authorizations', {
      idempotencyKey: `wl-${uniq()}`, action: 'purchase', supplierId: acme.supplierId, payee: BANK_GOOD, amountCents: 1_000, currency: 'USD',
    });
    expect(res.status).toBe(403);
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe('SESSION_REQUIRED');
  });

  it('a session key cannot mint further sessions', async () => {
    const s = await rawSession(acmeAgent);
    const res = await signedFetch(s.sessionId, s.privateKeyPem, 'POST', '/v1/agent-sessions', { publicKeyPem: generateEd25519KeyPair().publicKeyPem });
    expect(res.status).toBe(403);
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe('WORKLOAD_CREDENTIAL_REQUIRED');
  });

  it('expired sessions are rejected (a stolen session key is useful for minutes, not forever)', async () => {
    const s = await rawSession(acmeAgent);
    expect((await signedFetch(s.sessionId, s.privateKeyPem, 'GET', `/v1/authorizations/auth_${'0'.repeat(32)}`)).status).toBe(404);
    await prisma.agentSession.update({ where: { id: s.sessionId }, data: { expiresAt: new Date(Date.now() - 1000) } });
    expect((await signedFetch(s.sessionId, s.privateKeyPem, 'GET', `/v1/authorizations/auth_${'0'.repeat(32)}`)).status).toBe(401);
  });

  it('rejects requests signed with the wrong key (forged identity)', async () => {
    const impostor = new AgentTrust({ baseUrl: server.baseUrl, credentialId: acmeAgent.credentialId, privateKeyPem: generateEd25519KeyPair().privateKeyPem });
    expect((await apiError(impostor.sessions.current())).status).toBe(401);
  });

  it('rejects a replayed signed request', async () => {
    const s = await rawSession(acmeAgent);
    const body = JSON.stringify({ idempotencyKey: `replay-${uniq()}`, action: 'purchase', supplierId: acme.supplierId, payee: BANK_GOOD, amountCents: 1_000, currency: 'USD' });
    const headers = { ...signRequest({ credentialId: s.sessionId, privateKeyPem: s.privateKeyPem, method: 'POST', path: '/v1/authorizations', body }), 'content-type': 'application/json' };
    expect((await fetch(`${server.baseUrl}/v1/authorizations`, { method: 'POST', headers, body })).status).toBe(201);
    const second = await fetch(`${server.baseUrl}/v1/authorizations`, { method: 'POST', headers, body });
    expect(second.status).toBe(401);
    expect(((await second.json()) as { error: { message: string } }).error.message).toMatch(/Replayed/);
  });

  it('rejects a signed request whose body was modified in transit', async () => {
    const s = await rawSession(acmeAgent);
    const body = JSON.stringify({ idempotencyKey: `mitm-${uniq()}`, action: 'purchase', supplierId: acme.supplierId, payee: BANK_GOOD, amountCents: 1_000, currency: 'USD' });
    const headers = { ...signRequest({ credentialId: s.sessionId, privateKeyPem: s.privateKeyPem, method: 'POST', path: '/v1/authorizations', body }), 'content-type': 'application/json' };
    const res = await fetch(`${server.baseUrl}/v1/authorizations`, { method: 'POST', headers, body: body.replace('1000', '9000') });
    expect(res.status).toBe(401);
  });

  it('agents cannot call any human/governance endpoint', async () => {
    const s = await rawSession(acmeAgent);
    for (const path of ['/v1/delegations', '/v1/suppliers', '/v1/policies', '/v1/agents']) {
      expect((await signedFetch(s.sessionId, s.privateKeyPem, 'POST', path, {})).status).toBe(401);
    }
  });
});

describe('security responses are graded (no denial-of-service by outsiders)', () => {
  it('an outsider spamming invalid signatures cannot suspend the agent; it raises an alert and flags the credential', async () => {
    const victim = await acme.createAgent('Victim Agent', { maxTransactionCents: 100_000, monthlyLimitCents: 100_000 });
    const attackerKey = generateEd25519KeyPair().privateKeyPem;
    for (let i = 0; i < 12; i++) {
      expect((await signedFetch(victim.credentialId, attackerKey, 'POST', '/v1/agent-sessions', { publicKeyPem: generateEd25519KeyPair().publicKeyPem })).status).toBe(401);
    }
    expect((await acme.admin.get<{ status: string }>(`/v1/agents/${victim.id}`)).status).toBe('active');
    const cred = await prisma.agentCredential.findUniqueOrThrow({ where: { id: victim.credentialId } });
    expect(cred.flaggedAt).not.toBeNull();
    const { alerts } = await acme.admin.get<{ alerts: { category?: string; subjectId: string }[] }>('/v1/alerts');
    expect(alerts.some((a) => a.category === 'auth_failures' && a.subjectId === victim.id)).toBe(true);

    // The legitimate agent keeps working.
    const { poId, invoiceId } = await acme.poAndInvoice(10_000);
    expect((await purchase(victim, { supplierId: acme.supplierId, amountCents: 10_000, poId, invoiceId })).decision).toBe('ALLOW');
  });

  it('repeated business-policy denials raise an alert but never suspend', async () => {
    const busy = await acme.createAgent('Busy Agent', { maxTransactionCents: 10_000, monthlyLimitCents: 10_000 });
    for (let i = 0; i < 10; i++) {
      const r = await purchase(busy, { supplierId: acme.supplierId, amountCents: 50_000 });
      expect(r.decision).toBe('DENY');
    }
    expect((await acme.admin.get<{ status: string }>(`/v1/agents/${busy.id}`)).status).toBe('active');
    const { alerts } = await acme.admin.get<{ alerts: { category?: string; subjectId: string }[] }>('/v1/alerts');
    expect(alerts.some((a) => a.category === 'repeated_denials' && a.subjectId === busy.id)).toBe(true);
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
    for (const path of ['/v1/agents', '/v1/suppliers', '/v1/audit/events', '/v1/alerts']) {
      expect((await fetch(`${server.baseUrl}${path}`)).status).toBe(401);
    }
    const bad = await fetch(`${server.baseUrl}/v1/agents`, { headers: { authorization: 'Bearer forged.token.value' } });
    expect(bad.status).toBe(401);
  });
});

describe('supplier records are high-risk', () => {
  const evidence = 'Called supplier AP at the number on the signed master agreement; confirmed account.';

  it('new bank details are always pending until a DIFFERENT admin verifies them with evidence', async () => {
    const s = await acme.admin.post<{ id: string; verificationStatus: string; version: number }>('/v1/suppliers', { name: `Onboarding ${uniq()}`, paymentDestination: BANK_OTHER_SUPPLIER });
    expect(s.verificationStatus).toBe('pending');

    // Same person cannot verify their own entry, even at onboarding.
    expect((await apiError(acme.admin.post(`/v1/suppliers/${s.id}/verify-payment-destination`, { evidence, confirmedLast4: '1111' }))).code).toBe('DUAL_CONTROL_REQUIRED');
    // Verifier must confirm the right account and record real evidence.
    expect((await apiError(acme.admin2.post(`/v1/suppliers/${s.id}/verify-payment-destination`, { evidence, confirmedLast4: '9999' }))).code).toBe('VERIFICATION_MISMATCH');
    expect((await apiError(acme.admin2.post(`/v1/suppliers/${s.id}/verify-payment-destination`, { evidence: 'ok', confirmedLast4: '1111' }))).status).toBe(400);

    const verified = await acme.admin2.post<{ verificationStatus: string; version: number }>(`/v1/suppliers/${s.id}/verify-payment-destination`, { evidence, confirmedLast4: '1111' });
    expect(verified).toMatchObject({ verificationStatus: 'verified', version: 2 });
    // verificationStatus can no longer be set via PATCH at all.
    expect((await apiError(acme.admin.patch(`/v1/suppliers/${s.id}`, { verificationStatus: 'verified' }))).status).toBe(400);
  });

  it('changing bank details requires step-up authentication', async () => {
    const stale = new DevTokenService(loadConfig(process.env)).issue(`dev|${acme.adminUserId}`, new Date(Date.now() - 10 * 60_000));
    const staleAdmin = new AgentTrustAdmin({ baseUrl: server.baseUrl, accessToken: stale.accessToken });
    // Ordinary reads still work with the older login...
    await staleAdmin.get(`/v1/suppliers/${acme.supplierId}`);
    // ...but bank-detail changes and verifications demand a fresh one.
    expect((await apiError(staleAdmin.patch(`/v1/suppliers/${acme.supplierId}`, { paymentDestination: BANK_ATTACKER }))).code).toBe('REAUTHENTICATION_REQUIRED');
    expect((await apiError(staleAdmin.post('/v1/suppliers', { name: 'x', paymentDestination: BANK_ATTACKER }))).code).toBe('REAUTHENTICATION_REQUIRED');
  });

  it('every change creates a new immutable version', async () => {
    const id = await acme.verifiedSupplier(`Versioned ${uniq()}`, BANK_OTHER_SUPPLIER);
    await acme.admin.patch(`/v1/suppliers/${id}`, { paymentDestination: BANK_ATTACKER });
    await acme.admin.patch(`/v1/suppliers/${id}`, { status: 'blocked' });
    const { versions } = await acme.admin.get<{ versions: { version: number; changeType: string; snapshot: { paymentDestinationLast4: string; verificationStatus: string } }[] }>(`/v1/suppliers/${id}/versions`);
    expect(versions.map((v) => `${v.version}:${v.changeType}`)).toEqual([
      '1:created', '2:payment_destination_verified', '3:payment_destination_changed', '4:status_blocked',
    ]);
    expect(versions[1]!.snapshot.paymentDestinationLast4).toBe('1111');
    expect(versions[2]!.snapshot).toMatchObject({ paymentDestinationLast4: '0011', verificationStatus: 'pending' });
  });

  it('a pending supplier gets REVIEW that cannot be click-approved', async () => {
    const s = await acme.admin.post<{ id: string }>('/v1/suppliers', { name: `Pending ${uniq()}`, paymentDestination: BANK_GOOD });
    const { poId, invoiceId } = await acme.poAndInvoice(10_000, s.id);
    const r = await purchase(acmeAgent, { supplierId: s.id, amountCents: 10_000, poId, invoiceId });
    expect(r.decision).toBe('REVIEW');
    expect(r.approvable).toBe(false);
  });

  it('any supplier record change (even a rename) invalidates live authorizations', async () => {
    const id = await acme.verifiedSupplier(`Rename ${uniq()}`, BANK_OTHER_SUPPLIER);
    const { poId, invoiceId } = await acme.poAndInvoice(10_000, id);
    const auth = await purchase(acmeAgent, { supplierId: id, payee: BANK_OTHER_SUPPLIER, amountCents: 10_000, poId, invoiceId });
    expect(auth.decision).toBe('ALLOW');
    await acme.admin.patch(`/v1/suppliers/${id}`, { name: 'Renamed Supplier LLC' });
    expect((await apiError(executeFor(acmeAgent, auth))).code).toBe('AUTHORIZATION_INVALIDATED');
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
    expect((await apiError(executeFor(a, auth))).code).toBe('AUTHORIZATION_INVALIDATED');
  });

  it('supplier-scoped delegations deny other suppliers', async () => {
    const otherId = await acme.verifiedSupplier(`Not Allowed ${uniq()}`, BANK_ATTACKER);
    const scoped = await acme.createAgent('Scoped', { maxTransactionCents: 100_000, monthlyLimitCents: 100_000, approvedSupplierIds: [acme.supplierId] });
    const { poId, invoiceId } = await acme.poAndInvoice(10_000, otherId);
    const r = await purchase(scoped, { supplierId: otherId, payee: BANK_ATTACKER, amountCents: 10_000, poId, invoiceId });
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
