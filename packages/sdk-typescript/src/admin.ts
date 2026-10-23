import type { AuthorizationResponse, PaymentDestination, PurchaseInstruction, TransactionResponse } from './types';
import { send, type FetchFn } from './http';

/** A static token, or a function returning a current one (called per request; cache inside it). */
export type AccessTokenSource = string | (() => string | Promise<string>);

export interface AdminClientOptions {
  baseUrl: string;
  /** Human access token from the identity provider (sandbox: `AgentTrustSandbox.as(persona)`). */
  accessToken: AccessTokenSource;
  fetch?: FetchFn;
}

type Json = Record<string, unknown>;
type WithRest<T> = T & Json;

export interface User { id: string; organizationId: string; email: string; role: 'admin' | 'approver' | 'member'; status: string; spendingAuthorityCents: number; createdAt: string }
export interface AgentRecord { id: string; organizationId: string; ownerUserId: string; name: string; status: 'active' | 'suspended' | 'revoked'; createdAt: string }
export interface RegisterAgentInput { name: string; ownerUserId: string; /** Ed25519 SPKI PEM. The private key never leaves the agent's key holder. */ publicKeyPem: string; description?: string; credentialExpiresAt?: string }
export interface CreateDelegationInput {
  agentId: string;
  actions: ['purchase'];
  maxTransactionCents: number;
  monthlyLimitCents: number;
  currency: string;
  /** null/omitted = any verified supplier; array = only these suppliers. */
  approvedSupplierIds?: string[] | null;
  validFrom?: string;
  expiresAt: string;
}
export interface CreateSupplierInput { name: string; legalName?: string; externalReference?: string; paymentDestination?: PaymentDestination }
export interface Supplier {
  id: string;
  organizationId: string;
  name: string;
  legalName: string | null;
  externalReference: string | null;
  version: number;
  verificationStatus: string;
  /** recorded → reviewed → account_verified → ownership_verified */
  assuranceLevel: 'recorded' | 'reviewed' | 'account_verified' | 'ownership_verified';
  status: 'active' | 'blocked';
  paymentDestination: { type: PaymentDestination['type']; last4: string } | null;
  verifiedAt: string | null;
  createdAt: string;
}
export interface VerifyPaymentDestinationInput {
  /** How ownership was confirmed out of band (min 20 chars), e.g. "Called AP at the number on the signed contract". */
  evidence: string;
  /** Must equal the last 4 characters of the account on record. */
  confirmedLast4: string;
}
export interface CreatePurchaseOrderInput { supplierId: string; externalReference: string; approvedAmountCents: number; currency: string }
export interface InstructionLineInput { lineNumber: number; sku?: string; description: string; unit?: string; /** Exact decimal string, up to 3 places: "4", "2.5". */ quantity: string; unitPriceCents: number }
export interface CreateInstructionInput {
  agentId: string;
  supplierId: string;
  purchaseOrderId?: string;
  fulfillmentType: 'physical_goods' | 'services' | 'subscription' | 'digital_goods';
  currency: string;
  lines: InstructionLineInput[];
  /** Defaults to the lines total; may be lower, never higher. */
  maxAmountCents?: number;
  maxUses?: number;
  validFrom?: string;
  expiresAt: string;
  description?: string;
}
export interface InvoiceLineInput { lineNumber: number; instructionLineNumber?: number; sku?: string; description: string; quantity: string; unitPriceCents: number }
export interface CreateInvoiceInput {
  supplierId: string;
  purchaseOrderId?: string;
  purchaseInstructionId?: string;
  invoiceNumber: string;
  amountCents: number;
  currency: string;
  documentHash?: string;
  /** Trusted line items (from AP / ERP), summing exactly to amountCents. */
  lines?: InvoiceLineInput[];
}
export interface CreateReceiptInput {
  purchaseInstructionId: string;
  type: 'goods_received' | 'service_completed' | 'subscription_activated' | 'digital_delivered';
  lines?: { instructionLineNumber: number; quantity: string }[];
  [k: string]: unknown;
}

/**
 * Client for human administrators and approvers (back-office scripts, your
 * own admin UI, ERP glue). Agents must never hold these credentials.
 */
export class AgentTrustAdmin {
  private readonly fetchFn: FetchFn;

  constructor(private readonly opts: AdminClientOptions) {
    this.fetchFn = opts.fetch ?? fetch;
  }

  private async token(): Promise<string> {
    return typeof this.opts.accessToken === 'string' ? this.opts.accessToken : this.opts.accessToken();
  }

  async request<T>(method: 'GET' | 'POST' | 'PUT' | 'PATCH', path: string, payload?: unknown): Promise<T> {
    const headers: Record<string, string> = { authorization: `Bearer ${await this.token()}` };
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

  readonly users = {
    list: () => this.get<{ users: User[] }>('/v1/users'),
    create: (input: { email: string; role: User['role']; spendingAuthorityCents?: number }) => this.post<User>('/v1/users', input),
  };

  readonly agents = {
    /** Registers an agent with its workload PUBLIC key. Returns the credential id the agent runtime signs with. */
    register: (input: RegisterAgentInput) =>
      this.post<{ agent: AgentRecord; credential: { id: string; expiresAt: string | null } }>('/v1/agents', input),
    list: () => this.get<{ agents: AgentRecord[] }>('/v1/agents'),
    get: (id: string) => this.get<WithRest<AgentRecord>>(`/v1/agents/${enc(id)}`),
    /** Kill switch: a revoked agent can never transact again. */
    revoke: (id: string, reason?: string) => this.post<WithRest<AgentRecord>>(`/v1/agents/${enc(id)}/revoke`, reason ? { reason } : {}),
    reactivate: (id: string, reason?: string) => this.post<WithRest<AgentRecord>>(`/v1/agents/${enc(id)}/reactivate`, reason ? { reason } : {}),
  };

  /** What an agent may spend at most (a ceiling). It never authorizes a specific purchase by itself. */
  readonly delegations = {
    create: (input: CreateDelegationInput) => this.post<WithRest<{ id: string }>>('/v1/delegations', input),
    get: (id: string) => this.get<WithRest<{ id: string }>>(`/v1/delegations/${enc(id)}`),
    revoke: (id: string) => this.post<WithRest<{ id: string }>>(`/v1/delegations/${enc(id)}/revoke`, {}),
  };

  readonly suppliers = {
    create: (input: CreateSupplierInput) => this.post<WithRest<Supplier>>('/v1/suppliers', input),
    list: () => this.get<{ suppliers: WithRest<Supplier>[] }>('/v1/suppliers'),
    get: (id: string) => this.get<WithRest<Supplier>>(`/v1/suppliers/${enc(id)}`),
    update: (id: string, input: Partial<CreateSupplierInput> & { status?: 'active' | 'blocked' }) => this.patch<WithRest<Supplier>>(`/v1/suppliers/${enc(id)}`, input),
    /**
     * Dual control: must be called by a DIFFERENT administrator than the one
     * who entered the bank details (the server refuses self-verification).
     */
    verifyPaymentDestination: (id: string, input: VerifyPaymentDestinationInput) =>
      this.post<WithRest<Supplier>>(`/v1/suppliers/${enc(id)}/verify-payment-destination`, input),
    /** Runs the account-ownership provider check (sandbox provider in v0.4). */
    accountVerification: (id: string, paymentDestination: PaymentDestination) =>
      this.post<Json>(`/v1/suppliers/${enc(id)}/account-verification`, { paymentDestination }),
  };

  readonly purchaseOrders = {
    create: (input: CreatePurchaseOrderInput) => this.post<WithRest<{ id: string; status: string }>>('/v1/purchase-orders', input),
    get: (id: string) => this.get<WithRest<{ id: string; status: string }>>(`/v1/purchase-orders/${enc(id)}`),
  };

  readonly invoices = {
    create: (input: CreateInvoiceInput) => this.post<WithRest<{ id: string; status: string }>>('/v1/invoices', input),
    get: (id: string) => this.get<WithRest<{ id: string; status: string }>>(`/v1/invoices/${enc(id)}`),
  };

  /**
   * Purchase instructions: the independently approved "what the business
   * actually wants bought". Humans create and approve; agents can only read
   * the ones assigned to them. Approval should come from a different person
   * than the requester.
   */
  readonly instructions = {
    create: (input: CreateInstructionInput) => this.post<PurchaseInstruction>('/v1/purchase-instructions', input),
    update: (id: string, input: CreateInstructionInput) => this.put<PurchaseInstruction>(`/v1/purchase-instructions/${enc(id)}`, input),
    approve: (id: string, comment?: string) => this.post<PurchaseInstruction>(`/v1/purchase-instructions/${enc(id)}/approve`, comment ? { comment } : {}),
    reject: (id: string, reason: string) => this.post<PurchaseInstruction>(`/v1/purchase-instructions/${enc(id)}/reject`, { reason }),
    revoke: (id: string, reason: string) => this.post<PurchaseInstruction>(`/v1/purchase-instructions/${enc(id)}/revoke`, { reason }),
    list: (q: { agentId?: string; status?: PurchaseInstruction['status'] } = {}) =>
      this.get<{ instructions: PurchaseInstruction[] }>(`/v1/purchase-instructions${query(q)}`),
    get: (id: string) => this.get<PurchaseInstruction>(`/v1/purchase-instructions/${enc(id)}`),
    versions: (id: string) => this.get<Json>(`/v1/purchase-instructions/${enc(id)}/versions`),
  };

  /** Goods received / service completed confirmations (three-way matching). */
  readonly receipts = {
    create: (input: CreateReceiptInput) => this.post<WithRest<{ id: string }>>('/v1/receipts', input),
    void: (id: string, reason: string) => this.post<WithRest<{ id: string }>>(`/v1/receipts/${enc(id)}/void`, { reason }),
  };

  /** Review queue: REVIEW decisions wait here for a human. */
  readonly authorizations = {
    list: (q: { status?: AuthorizationResponse['status'] } = {}) => this.get<{ authorizations: AuthorizationResponse[] }>(`/v1/authorizations${query(q)}`),
    get: (id: string) => this.get<AuthorizationResponse>(`/v1/authorizations/${enc(id)}`),
    approve: (id: string, comment?: string) => this.post<AuthorizationResponse>(`/v1/authorizations/${enc(id)}/approve`, comment ? { comment } : {}),
    deny: (id: string, comment?: string) => this.post<AuthorizationResponse>(`/v1/authorizations/${enc(id)}/deny`, comment ? { comment } : {}),
  };

  readonly transactions = {
    get: (id: string) => this.get<TransactionResponse>(`/v1/transactions/${enc(id)}`),
    reconcile: (id: string) => this.post<TransactionResponse>(`/v1/transactions/${enc(id)}/reconcile`, {}),
    resolve: (id: string, note: string) => this.post<TransactionResponse>(`/v1/transactions/${enc(id)}/resolve`, { note }),
  };

  readonly policies = {
    list: () => this.get<{ policies: WithRest<{ id: string; version: number; status: string; rules: Json }>[] }>('/v1/policies'),
    /** Creates a new active policy version (the previous version is retained). */
    update: (id: string, rules: Json) => this.put<WithRest<{ id: string; version: number }>>(`/v1/policies/${enc(id)}`, { rules }),
  };

  readonly audit = {
    /** Recomputes the organization's audit hash chain and signatures. */
    verify: () => this.get<WithRest<{ valid: boolean }>>('/v1/audit/verify'),
    events: () => this.get<Json>('/v1/audit/events'),
    anchors: () => this.get<Json>('/v1/audit/anchors'),
    anchorNow: () => this.post<Json>('/v1/audit/anchors', {}),
  };
}

function enc(id: string) {
  return encodeURIComponent(id);
}

function query(q: Record<string, string | undefined>) {
  const entries = Object.entries(q).filter((e): e is [string, string] => e[1] !== undefined);
  return entries.length ? `?${new URLSearchParams(entries).toString()}` : '';
}
