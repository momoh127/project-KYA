import { generateEd25519KeyPair } from '@agenttrust/identity';
import { AgentTrustAdmin } from './admin';
import { AgentTrust } from './client';
import { send, type FetchFn } from './http';
import type { PaymentDestination, TransactionResponse } from './types';

export type SandboxPersona = 'admin' | 'verifier' | 'approver';

export interface SandboxSignupResponse {
  environment: 'sandbox';
  organizationId: string;
  organizationName: string;
  /** Shown once. Store it like a password. */
  sandboxKey: string;
  expiresAt: string;
  personas: Record<SandboxPersona, { id: string; email: string; role: 'admin' | 'approver' }>;
  policy: { id: string; version: number };
  notice: string;
}

export interface SandboxProgress {
  organizationId: string;
  keyPrefix: string;
  steps: Record<string, { at: string; minutesFromSignup: number | null } | null>;
  minutesToFirstSettledPayment: number | null;
  completed: boolean;
}

/** Sandbox-only bank details for the example supplier (not a real account). */
export const SANDBOX_SUPPLIER_BANK: PaymentDestination = { type: 'us_ach', routingNumber: '021000021', accountNumber: '4000123456' };

/**
 * Hosted-sandbox helper. A sandbox organization comes with three personas so
 * one developer can exercise dual control alone:
 *   - `admin`    : you. Registers agents, enters suppliers, POs, instructions, invoices.
 *   - `verifier` : a second administrator. Verifies supplier bank details you entered.
 *   - `approver` : approves purchase instructions and grants delegations.
 * Sandbox only: no real money moves and persona logins are development tokens.
 */
export class AgentTrustSandbox {
  private readonly fetchFn: FetchFn;
  private readonly cache = new Map<SandboxPersona, { token: string; expiresAt: number }>();

  constructor(private readonly opts: { baseUrl: string; sandboxKey: string; fetch?: FetchFn }) {
    this.fetchFn = opts.fetch ?? fetch;
  }

  /** Creates a new sandbox organization. Keep `account.sandboxKey`; it is not shown again. */
  static async signup(opts: { baseUrl: string; organizationName: string; email: string; fetch?: FetchFn }) {
    const fetchFn = opts.fetch ?? fetch;
    const account = await send<SandboxSignupResponse>(fetchFn, `${opts.baseUrl}/v1/sandbox/signup`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ organizationName: opts.organizationName, email: opts.email }),
    });
    return { account, sandbox: new AgentTrustSandbox({ baseUrl: opts.baseUrl, sandboxKey: account.sandboxKey, fetch: fetchFn }) };
  }

  get baseUrl() {
    return this.opts.baseUrl;
  }

  private call<T>(method: 'GET' | 'POST', path: string, payload?: unknown) {
    const headers: Record<string, string> = { 'x-agenttrust-sandbox-key': this.opts.sandboxKey };
    if (payload !== undefined) headers['content-type'] = 'application/json';
    return send<T>(this.fetchFn, `${this.opts.baseUrl}${path}`, { method, headers, body: payload === undefined ? undefined : JSON.stringify(payload) });
  }

  /** A short-lived access token for one persona (cached; refreshed 5 minutes before expiry). */
  async token(persona: SandboxPersona): Promise<string> {
    const hit = this.cache.get(persona);
    if (hit && hit.expiresAt - Date.now() > 300_000) return hit.token;
    const res = await this.call<{ accessToken: string; expiresAt: string }>('POST', '/v1/sandbox/token', { persona });
    this.cache.set(persona, { token: res.accessToken, expiresAt: Date.parse(res.expiresAt) });
    return res.accessToken;
  }

  /** An admin/approver client acting as `persona`, with automatic token refresh. */
  as(persona: SandboxPersona): AgentTrustAdmin {
    return new AgentTrustAdmin({ baseUrl: this.opts.baseUrl, accessToken: () => this.token(persona), fetch: this.fetchFn });
  }

  /**
   * Plays the payment provider for one of YOUR sandbox payments. The change is
   * delivered as a signed provider webhook, so finality rules apply: only
   * `settled` marks the invoice paid; `returned`/`reversed` never auto-repay.
   */
  advancePayment(transactionId: string, status: 'processing' | 'settled' | 'failed' | 'returned' | 'reversed', opts: { duplicateDelivery?: boolean } = {}) {
    return this.call<{ transactionId: string; providerStatus: string; transactionStatus: TransactionResponse['status'] }>(
      'POST',
      `/v1/sandbox/transactions/${encodeURIComponent(transactionId)}/advance`,
      { status, duplicateDelivery: opts.duplicateDelivery ?? false },
    );
  }

  /** How far this sandbox got through the integration, with minutes from signup. */
  progress() {
    return this.call<SandboxProgress>('GET', '/v1/sandbox/progress');
  }

  /**
   * Creates a supplier with verified bank details the way a real business
   * would: entered by `admin`, verified out of band by `verifier` (dual control).
   */
  async createVerifiedSupplier(name = 'Northwind Industrial Supply', bank: PaymentDestination = SANDBOX_SUPPLIER_BANK) {
    const supplier = await this.as('admin').suppliers.create({ name, paymentDestination: bank });
    const last4 = bank.type === 'us_ach' ? bank.accountNumber.slice(-4) : bank.iban.slice(-4);
    await this.as('verifier').suppliers.verifyPaymentDestination(supplier.id, {
      evidence: 'Sandbox: called supplier AP at the number on the signed master agreement; confirmed account.',
      confirmedLast4: last4,
    });
    return { supplierId: supplier.id, bank };
  }

  /**
   * Registers an agent and returns a ready AgentTrust client for it.
   * DEVELOPMENT ONLY key handling: the private key is generated in this
   * process. In production, generate it in the agent's key holder (sidecar,
   * KMS) and register only the public key.
   */
  async registerAgent(name = 'Procurement agent') {
    const admin = this.as('admin');
    const { users } = await admin.users.list();
    const owner = users.find((u) => u.role === 'admin' && !u.email.startsWith('verifier+')) ?? users[0]!;
    const keys = generateEd25519KeyPair();
    const reg = await admin.agents.register({ name, ownerUserId: owner.id, publicKeyPem: keys.publicKeyPem });
    return {
      agentId: reg.agent.id,
      credentialId: reg.credential.id,
      privateKeyPem: keys.privateKeyPem,
      client: new AgentTrust({ baseUrl: this.opts.baseUrl, credentialId: reg.credential.id, privateKeyPem: keys.privateKeyPem, fetch: this.fetchFn }),
    };
  }
}
