import { generateKeyPairSync, type KeyObject } from 'node:crypto';
import { ed25519Sign, parseEd25519PrivateKey, signRequest, signRequestWith, type SignFn } from '@agenttrust/identity';
import type {
  ApiErrorBody,
  AuthorizationResponse,
  CreateAuthorizationInput,
  ExecuteTransactionInput,
  PurchaseInstruction,
  TransactionResponse,
} from './types';

export type { SignFn };

/**
 * DEVELOPMENT ONLY: signs with a workload key held in this process. In
 * production, pass a SignFn that calls a sidecar, OS keystore or KMS/HSM, so
 * the long-lived key is never in memory that the LLM/tool layer can reach.
 */
export function localSigner(privateKeyPem: string): SignFn {
  const key = parseEd25519PrivateKey(privateKeyPem);
  return (data: Buffer) => ed25519Sign(key, data);
}

export class AgentTrustError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly details?: unknown,
  ) {
    super(message);
    this.name = 'AgentTrustError';
  }
}

type FetchFn = typeof fetch;

async function send<T>(fetchFn: FetchFn, url: string, init: RequestInit): Promise<T> {
  const res = await fetchFn(url, init);
  const text = await res.text();
  const body = text ? JSON.parse(text) : undefined;
  if (!res.ok) {
    const err = (body as ApiErrorBody | undefined)?.error;
    throw new AgentTrustError(res.status, err?.code ?? 'HTTP_ERROR', err?.message ?? res.statusText, err?.details);
  }
  return body as T;
}

export interface AgentClientOptions {
  baseUrl: string;
  /** Workload credential id (`akc_…`). */
  credentialId: string;
  /**
   * Signs with the long-lived WORKLOAD key. That key can only mint short-lived
   * sessions. Keep it outside the LLM-accessible environment (sidecar / KMS).
   */
  workloadSigner?: SignFn;
  /** Convenience for local development; equivalent to `workloadSigner: localSigner(pem)`. */
  privateKeyPem?: string;
  /** Session lifetime requested from the server (60–3600 s, default 900). */
  sessionTtlSeconds?: number;
  fetch?: FetchFn;
}

interface Session {
  id: string;
  key: KeyObject;
  expiresAt: number;
}

/**
 * Client used by an AI agent's runtime (NOT by the LLM itself: expose only
 * high-level tools such as "request purchase authorization" to the model).
 *
 * Every API call is signed with a short-lived SESSION key (in-memory, never
 * exported) that is minted by the workload credential and rotated before it
 * expires. The agent never holds payment credentials: the only way to pay is
 * `transactions.execute`, which the AgentTrust gateway enforces.
 */
export class AgentTrust {
  private readonly fetchFn: FetchFn;
  private readonly workloadSigner: SignFn;
  private session: Session | null = null;
  private sessionPromise: Promise<Session> | null = null;

  constructor(private readonly opts: AgentClientOptions) {
    this.fetchFn = opts.fetch ?? fetch;
    const signer = opts.workloadSigner ?? (opts.privateKeyPem ? localSigner(opts.privateKeyPem) : null);
    if (!signer) throw new Error('AgentTrust: provide workloadSigner (or privateKeyPem for local development)');
    this.workloadSigner = signer;
  }

  private async ensureSession(): Promise<Session> {
    if (this.session && this.session.expiresAt - Date.now() > 60_000) return this.session;
    this.sessionPromise ??= this.createSession().finally(() => {
      this.sessionPromise = null;
    });
    return this.sessionPromise;
  }

  private async createSession(): Promise<Session> {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const path = '/v1/agent-sessions';
    const body = JSON.stringify({
      publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
      ttlSeconds: this.opts.sessionTtlSeconds ?? 900,
    });
    const headers = await signRequestWith({ credentialId: this.opts.credentialId, sign: this.workloadSigner, method: 'POST', path, body });
    const res = await send<{ sessionId: string; expiresAt: string }>(this.fetchFn, `${this.opts.baseUrl}${path}`, {
      method: 'POST',
      headers: { ...headers, 'content-type': 'application/json' },
      body,
    });
    this.session = { id: res.sessionId, key: privateKey, expiresAt: Date.parse(res.expiresAt) };
    return this.session;
  }

  private async request<T>(method: 'GET' | 'POST', path: string, payload?: unknown): Promise<T> {
    const session = await this.ensureSession();
    const body = payload === undefined ? '' : JSON.stringify(payload);
    const headers: Record<string, string> = signRequest({ credentialId: session.id, privateKeyPem: session.key, method, path, body });
    if (body) headers['content-type'] = 'application/json';
    return send<T>(this.fetchFn, `${this.opts.baseUrl}${path}`, { method, headers, body: body || undefined });
  }

  readonly sessions = {
    /** Current session id (creates one if needed). */
    current: async () => (await this.ensureSession()).id,
    /** Force a fresh session key now (e.g. after suspected exposure). */
    rotate: async () => {
      this.session = null;
      return (await this.ensureSession()).id;
    },
  };

  /** Read-only view of the approved purchase instructions assigned to this agent. */
  readonly instructions = {
    list: () => this.request<{ instructions: PurchaseInstruction[] }>('GET', '/v1/agent/purchase-instructions'),
    get: (id: string) => this.request<PurchaseInstruction>('GET', `/v1/agent/purchase-instructions/${encodeURIComponent(id)}`),
  };

  readonly authorizations = {
    create: (input: CreateAuthorizationInput) =>
      this.request<AuthorizationResponse>('POST', '/v1/authorizations', input),
    get: (id: string) => this.request<AuthorizationResponse>('GET', `/v1/authorizations/${encodeURIComponent(id)}`),
  };

  readonly transactions = {
    /** Executes through the enforcing gateway. There is no other payment path. */
    execute: (input: ExecuteTransactionInput) =>
      this.request<TransactionResponse>('POST', '/v1/transactions/execute', input),
    get: (id: string) => this.request<TransactionResponse>('GET', `/v1/transactions/${encodeURIComponent(id)}`),
  };
}

export interface AdminClientOptions {
  baseUrl: string;
  /** Human access token from the identity provider (dev: /v1/dev/token). */
  accessToken: string;
  fetch?: FetchFn;
}

/** Client for human administrators / approvers (dashboard, back-office scripts). */
export class AgentTrustAdmin {
  private readonly fetchFn: FetchFn;

  constructor(private readonly opts: AdminClientOptions) {
    this.fetchFn = opts.fetch ?? fetch;
  }

  request<T>(method: 'GET' | 'POST' | 'PUT' | 'PATCH', path: string, payload?: unknown): Promise<T> {
    const headers: Record<string, string> = { authorization: `Bearer ${this.opts.accessToken}` };
    if (payload !== undefined) headers['content-type'] = 'application/json';
    return send<T>(this.fetchFn, `${this.opts.baseUrl}${path}`, {
      method,
      headers,
      body: payload === undefined ? undefined : JSON.stringify(payload),
    });
  }

  get = <T>(path: string) => this.request<T>('GET', path);
  post = <T>(path: string, payload: unknown = {}) => this.request<T>('POST', path, payload);
  put = <T>(path: string, payload: unknown) => this.request<T>('PUT', path, payload);
  patch = <T>(path: string, payload: unknown) => this.request<T>('PATCH', path, payload);
}

/** Platform-operator helpers (organization bootstrap + development login). */
export class AgentTrustPlatform {
  private readonly fetchFn: FetchFn;

  constructor(private readonly opts: { baseUrl: string; bootstrapToken: string; fetch?: FetchFn }) {
    this.fetchFn = opts.fetch ?? fetch;
  }

  private post<T>(path: string, payload: unknown): Promise<T> {
    return send<T>(this.fetchFn, `${this.opts.baseUrl}${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-agenttrust-bootstrap-token': this.opts.bootstrapToken },
      body: JSON.stringify(payload),
    });
  }

  createOrganization<T = unknown>(input: { name: string; admin: { email: string; spendingAuthorityCents: number } }) {
    return this.post<T>('/v1/organizations', input);
  }

  /** Development only. The server refuses this in production. */
  devToken(userId: string) {
    return this.post<{ accessToken: string; expiresAt: string }>('/v1/dev/token', { userId });
  }

  /** Development only: queue sandbox payment-provider faults (FIFO). */
  sandboxFaults(faults: string[]) {
    return this.post<{ queued: string[] }>('/v1/dev/sandbox/faults', { faults });
  }

  /** Development only: move a sandbox payment along the provider lifecycle (optionally delivering a signed webhook). */
  sandboxAdvance(idempotencyKey: string, status: 'accepted' | 'processing' | 'settled' | 'failed' | 'returned' | 'reversed', opts: { deliverWebhook?: boolean; duplicateDelivery?: boolean } = {}) {
    return this.post<{ providerStatus: string; deliveries: { outcome: string; duplicate: boolean; transactionStatus?: string }[] }>(
      `/v1/dev/sandbox/payments/${encodeURIComponent(idempotencyKey)}/advance`,
      { status, deliverWebhook: opts.deliverWebhook ?? true, duplicateDelivery: opts.duplicateDelivery ?? false },
    );
  }

  /** Development only: the sandbox provider's own ledger for an idempotency key. */
  async sandboxLedger(idempotencyKey: string) {
    return send<{ payments: { idempotencyKey: string; status: string; amountCents: number; providerReference: string }[] }>(
      this.fetchFn,
      `${this.opts.baseUrl}/v1/dev/sandbox/payments/${encodeURIComponent(idempotencyKey)}`,
      { headers: { 'x-agenttrust-bootstrap-token': this.opts.bootstrapToken } },
    );
  }
}
