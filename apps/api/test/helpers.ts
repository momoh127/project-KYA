import 'reflect-metadata';
import type { INestApplication } from '@nestjs/common';
import type { AddressInfo } from 'node:net';
import { randomBytes } from 'node:crypto';
import {
  AgentTrust,
  AgentTrustAdmin,
  AgentTrustError,
  AgentTrustPlatform,
  generateEd25519KeyPair,
  type AuthorizationResponse,
  type PaymentDestination,
} from '@agenttrust/sdk';
import { signRequest } from '@agenttrust/identity';
import { createApp } from '../src/app';
import { loadConfig } from '../src/config';

export const BANK_GOOD: PaymentDestination = { type: 'us_ach', routingNumber: '021000021', accountNumber: '4000123456' };
export const BANK_ATTACKER: PaymentDestination = { type: 'us_ach', routingNumber: '026009593', accountNumber: '9999000011' };
export const BANK_OTHER_SUPPLIER: PaymentDestination = { type: 'us_ach', routingNumber: '011000015', accountNumber: '5550001111' };

export interface TestServer {
  app: INestApplication;
  baseUrl: string;
  close: () => Promise<void>;
}

export async function startServer(): Promise<TestServer> {
  if (!process.env.DATABASE_URL?.includes('agenttrust_test')) {
    throw new Error('Refusing to run integration tests against a non-test database');
  }
  const app = await createApp(loadConfig(process.env), { logger: false });
  await app.listen(0, '127.0.0.1');
  const { port } = app.getHttpServer().address() as AddressInfo;
  return { app, baseUrl: `http://127.0.0.1:${port}`, close: () => app.close() };
}

export const uniq = () => randomBytes(4).toString('hex');

export interface Agent {
  id: string;
  credentialId: string;
  privateKeyPem: string;
  client: AgentTrust;
}

/** A fresh, fully isolated organization with people, a verified supplier and helpers. */
export async function createWorld(baseUrl: string, name = 'Acme Manufacturing') {
  const platform = new AgentTrustPlatform({ baseUrl, bootstrapToken: process.env.AGENTTRUST_BOOTSTRAP_TOKEN! });
  const tag = uniq();
  const created = await platform.createOrganization<{ organization: { id: string }; admin: { id: string } }>({
    name,
    admin: { email: `sarah+${tag}@acme.test`, spendingAuthorityCents: 10_000_000 },
  });
  const orgId = created.organization.id;
  const loginAs = async (userId: string) => new AgentTrustAdmin({ baseUrl, accessToken: (await platform.devToken(userId)).accessToken });

  const admin = await loginAs(created.admin.id);
  const admin2User = await admin.post<{ id: string }>('/v1/users', { email: `omar+${tag}@acme.test`, role: 'admin', spendingAuthorityCents: 10_000_000 });
  const approverUser = await admin.post<{ id: string }>('/v1/users', { email: `priya+${tag}@acme.test`, role: 'approver', spendingAuthorityCents: 1_000_000 });
  const memberUser = await admin.post<{ id: string }>('/v1/users', { email: `max+${tag}@acme.test`, role: 'member', spendingAuthorityCents: 0 });
  const admin2 = await loginAs(admin2User.id);
  const approver = await loginAs(approverUser.id);
  const member = await loginAs(memberUser.id);

  const supplierId = await verifiedSupplier(admin, admin2, 'Precision Tools Co', BANK_GOOD);

  const world = {
    platform,
    orgId,
    adminUserId: created.admin.id,
    admin2UserId: admin2User.id,
    approverUserId: approverUser.id,
    admin,
    admin2,
    approver,
    member,
    supplierId,
    loginAs,

    /** Supplier onboarded by admin, verified by a second admin (dual control). */
    verifiedSupplier: (name: string, bank: PaymentDestination) => verifiedSupplier(admin, admin2, name, bank),

    async createAgent(
      agentName: string,
      delegation: { maxTransactionCents: number; monthlyLimitCents: number; approvedSupplierIds?: string[] | null } | null,
    ): Promise<Agent> {
      const keys = generateEd25519KeyPair();
      const reg = await admin.post<{ agent: { id: string }; credential: { id: string } }>('/v1/agents', {
        name: agentName,
        ownerUserId: created.admin.id,
        publicKeyPem: keys.publicKeyPem,
      });
      if (delegation) {
        await approver.post('/v1/delegations', {
          agentId: reg.agent.id,
          actions: ['purchase'],
          currency: 'USD',
          expiresAt: new Date(Date.now() + 30 * 86_400_000).toISOString(),
          ...delegation,
        });
      }
      return {
        id: reg.agent.id,
        credentialId: reg.credential.id,
        privateKeyPem: keys.privateKeyPem,
        client: new AgentTrust({ baseUrl, credentialId: reg.credential.id, privateKeyPem: keys.privateKeyPem }),
      };
    },

    /**
     * The trusted business setup for one purchase: an approved PO, a purchase
     * instruction assigned to `agent` (requested by an admin, independently
     * approved by the approver), and a matching invoice with trusted lines.
     */
    async order(agent: Agent | string, amountCents: number, o: OrderOptions = {}) {
      const agentId = typeof agent === 'string' ? agent : agent.id;
      const forSupplier = o.supplierId ?? supplierId;
      const sku = `SKU-${uniq()}`;
      const lines = o.lines ?? [{ lineNumber: 1, sku, description: 'Tooling item', quantity: '1', unitPriceCents: amountCents }];
      const po = await admin.post<{ id: string }>('/v1/purchase-orders', {
        supplierId: forSupplier, externalReference: `PO-${uniq()}`, approvedAmountCents: o.poAmountCents ?? amountCents * (o.maxUses ?? 1), currency: 'USD',
      });
      const instruction = await admin.post<{ id: string; version: number }>('/v1/purchase-instructions', {
        agentId, supplierId: forSupplier, purchaseOrderId: po.id, fulfillmentType: o.fulfillmentType ?? 'physical_goods', currency: 'USD',
        lines, maxUses: o.maxUses ?? 1, expiresAt: new Date(Date.now() + 7 * 86_400_000).toISOString(),
      });
      if (o.approve !== false) await (o.approver ?? approver).post(`/v1/purchase-instructions/${instruction.id}/approve`, {});
      let invoiceId: string | undefined;
      if (o.invoice !== false) {
        const invLines = o.invoiceLines ?? lines.map((l) => ({ lineNumber: l.lineNumber, instructionLineNumber: l.lineNumber, sku: l.sku, description: l.description, quantity: l.quantity, unitPriceCents: l.unitPriceCents }));
        const inv = await admin.post<{ id: string }>('/v1/invoices', {
          supplierId: forSupplier, purchaseOrderId: po.id, purchaseInstructionId: instruction.id, invoiceNumber: `INV-${uniq()}`,
          amountCents: o.invoiceAmountCents ?? amountCents, currency: 'USD', lines: invLines,
        });
        invoiceId = inv.id;
      }
      return { supplierId: forSupplier, poId: po.id, invoiceId, instructionId: instruction.id, sku };
    },
  };
  return world;
}

export type World = Awaited<ReturnType<typeof createWorld>>;

export interface OrderOptions {
  supplierId?: string;
  fulfillmentType?: 'physical_goods' | 'services' | 'subscription' | 'digital_goods';
  maxUses?: number;
  poAmountCents?: number;
  lines?: { lineNumber: number; sku?: string; description: string; quantity: string; unitPriceCents: number }[];
  invoice?: boolean;
  invoiceAmountCents?: number;
  invoiceLines?: { lineNumber: number; instructionLineNumber?: number; sku?: string; description: string; quantity: string; unitPriceCents: number }[];
  approve?: boolean;
  approver?: AgentTrustAdmin;
}

export function last4(bank: PaymentDestination): string {
  return bank.type === 'us_ach' ? bank.accountNumber.slice(-4) : bank.iban.slice(-4);
}

export async function verifiedSupplier(enteredBy: AgentTrustAdmin, verifiedBy: AgentTrustAdmin, name: string, bank: PaymentDestination): Promise<string> {
  const s = await enteredBy.post<{ id: string }>('/v1/suppliers', { name, paymentDestination: bank });
  await verifiedBy.post(`/v1/suppliers/${s.id}/verify-payment-destination`, {
    evidence: 'Called supplier AP at the number on the signed master agreement; confirmed account.',
    confirmedLast4: last4(bank),
  });
  return s.id;
}

export function purchase(
  agent: Agent,
  p: {
    supplierId?: string; payee?: PaymentDestination; amountCents: number; poId?: string; invoiceId?: string; instructionId?: string;
    lines?: { instructionLineNumber: number; sku?: string; quantity: string; unitPriceCents: number }[]; key?: string; currency?: string;
  },
) {
  return agent.client.authorizations.create({
    idempotencyKey: p.key ?? `purchase-${uniq()}`,
    action: 'purchase',
    supplierId: p.supplierId,
    payee: p.payee ?? BANK_GOOD,
    amountCents: p.amountCents,
    currency: p.currency ?? 'USD',
    purchaseOrderId: p.poId,
    invoiceId: p.invoiceId,
    purchaseInstructionId: p.instructionId,
    lines: p.lines,
  });
}

export function executeFor(agent: Agent, auth: AuthorizationResponse, overrides: { token?: string; amountCents?: number } = {}) {
  return agent.client.transactions.execute({
    token: overrides.token ?? auth.token ?? '',
    expected: {
      supplierId: auth.supplierId,
      amountCents: overrides.amountCents ?? auth.amountCents,
      currency: auth.currency,
      purchaseOrderId: auth.purchaseOrderId,
      invoiceId: auth.invoiceId,
    },
  });
}

/** Resolves to the AgentTrustError thrown by `p` (fails the test if it succeeds). */
export async function apiError(p: Promise<unknown>): Promise<AgentTrustError> {
  try {
    await p;
  } catch (e) {
    if (e instanceof AgentTrustError) return e;
    throw e;
  }
  throw new Error('expected request to fail, but it succeeded');
}

/** Mints a session the raw way (for hand-built signed requests). */
export async function rawSession(baseUrl: string, agent: Agent) {
  const keys = generateEd25519KeyPair();
  const body = JSON.stringify({ publicKeyPem: keys.publicKeyPem, ttlSeconds: 900 });
  const headers = { ...signRequest({ credentialId: agent.credentialId, privateKeyPem: agent.privateKeyPem, method: 'POST', path: '/v1/agent-sessions', body }), 'content-type': 'application/json' };
  const res = await fetch(`${baseUrl}/v1/agent-sessions`, { method: 'POST', headers, body });
  if (res.status !== 201) throw new Error(`session creation failed: ${res.status}`);
  const { sessionId } = (await res.json()) as { sessionId: string };
  return { sessionId, privateKeyPem: keys.privateKeyPem };
}

export function signedFetch(baseUrl: string, keyId: string, privateKeyPem: string, method: 'GET' | 'POST' | 'PUT', path: string, payload?: unknown) {
  const body = payload === undefined ? '' : JSON.stringify(payload);
  const headers: Record<string, string> = signRequest({ credentialId: keyId, privateKeyPem, method, path, body });
  if (body) headers['content-type'] = 'application/json';
  return fetch(`${baseUrl}${path}`, { method, headers, body: body || undefined });
}

/** Creates a new active policy version with `patch` applied to the current rules. */
export async function patchPolicy(w: World, patch: (rules: Record<string, any>) => Record<string, any>) {
  const { policies } = await w.admin.get<{ policies: { id: string; status: string; rules: Record<string, any> }[] }>('/v1/policies');
  const active = policies.find((p) => p.status === 'active')!;
  await w.admin.put(`/v1/policies/${active.id}`, { rules: patch(structuredClone(active.rules)) });
}
