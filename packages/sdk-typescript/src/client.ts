import { signRequest } from '@agenttrust/identity';
import type {
  ApiErrorBody,
  AuthorizationResponse,
  CreateAuthorizationInput,
  ExecuteTransactionInput,
  TransactionResponse,
} from './types';

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
  credentialId: string;
  /** Agent private key. Keep it in the agent runtime / secret store, never in an LLM prompt. */
  privateKeyPem: string;
  fetch?: FetchFn;
}

/**
 * Client used by an AI agent's runtime. Every call is signed with the agent's
 * Ed25519 key. The agent never holds payment credentials: the only way to pay
 * is `transactions.execute`, which the AgentTrust gateway enforces.
 */
export class AgentTrust {
  private readonly fetchFn: FetchFn;

  constructor(private readonly opts: AgentClientOptions) {
    this.fetchFn = opts.fetch ?? fetch;
  }

  private request<T>(method: 'GET' | 'POST', path: string, payload?: unknown): Promise<T> {
    const body = payload === undefined ? '' : JSON.stringify(payload);
    const headers: Record<string, string> = signRequest({
      credentialId: this.opts.credentialId,
      privateKeyPem: this.opts.privateKeyPem,
      method,
      path,
      body,
    });
    if (body) headers['content-type'] = 'application/json';
    return send<T>(this.fetchFn, `${this.opts.baseUrl}${path}`, { method, headers, body: body || undefined });
  }

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
}
