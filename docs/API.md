# API (v1)

Base URL (local): `http://localhost:4000`. All bodies are JSON. Unknown fields are rejected (400).
Errors: `{ "error": { "code": "...", "message": "...", "details": ... } }`. Treat any non-2xx as **not authorized**.

## Authentication

| Caller | How |
|---|---|
| Human | `Authorization: Bearer <token>` from the identity provider (dev: `POST /v1/dev/token`). Sensitive actions require a recent login (step-up). |
| Agent workload | Ed25519-signed headers with the **workload credential** (`akc_…`). Allowed only on `POST /v1/agent-sessions`. |
| Agent session | Ed25519-signed headers with a **session key** (`ags_…`). Required for authorizations and payments. |
| Platform operator | `x-agenttrust-bootstrap-token` |

Signed headers: `x-agenttrust-credential` (key id), `x-agenttrust-timestamp`, `x-agenttrust-nonce`,
`x-agenttrust-signature` over `AGENTTRUST-ED25519-V1\nMETHOD\npath\ntimestamp\nnonce\nsha256(body)`.
The SDK handles sessions automatically.

## Endpoints

| Method & path | Caller | Purpose |
|---|---|---|
| `GET /v1/health` | public | Liveness |
| `POST /v1/organizations` | platform | Create org + first admin + policy v1 + audit chain |
| `GET /v1/organizations/:id` | human | Own organization only |
| `POST /v1/dev/token` | platform (dev only) | Issue a dev human token |
| `POST /v1/users` / `GET /v1/users` | admin | Users with role + spending authority |
| `POST /v1/agents` | admin | Register agent + workload public key |
| `GET /v1/agents`, `GET /v1/agents/:id` | human | Registry |
| `POST /v1/agents/:id/revoke` | admin | Permanent kill switch (revokes sessions, invalidates live authorizations) |
| `POST /v1/agents/:id/reactivate` | admin | Lift a suspension |
| `POST /v1/agent-sessions` | **agent workload** | Mint a session `{ publicKeyPem, ttlSeconds? }` → `{ sessionId, expiresAt }` |
| `GET /v1/alerts` | admin, approver | Security alerts and auto-suspensions |
| `POST /v1/delegations` | admin, approver | Grant bounded authority (≤ own authority); supersedes previous |
| `GET /v1/delegations/:id`, `POST /v1/delegations/:id/revoke` | human / admin, approver | Revoke invalidates live authorizations |
| `GET /v1/policies`, `POST /v1/policies`, `PUT /v1/policies/:id` | human / admin | Immutable versions; a new version invalidates live authorizations |
| `POST /v1/suppliers` | admin (step-up if bank details) | Always `pending` when bank details are provided |
| `PATCH /v1/suppliers/:id` | admin (step-up for bank changes) | `name`, `status`, `paymentDestination`; new version; invalidates live authorizations |
| `POST /v1/suppliers/:id/verify-payment-destination` | **different** admin, step-up | `{ evidence, confirmedLast4 }` |
| `GET /v1/suppliers[/:id]`, `GET /v1/suppliers/:id/versions` | human / admin, approver | Records + immutable history |
| `POST /v1/purchase-orders`, `GET /v1/purchase-orders/:id` | admin, approver / human | |
| `POST /v1/invoices`, `GET /v1/invoices/:id` | human | Duplicate invoice numbers rejected |
| `POST /v1/authorizations` | **agent session** | Request authorization → ALLOW / REVIEW / DENY |
| `GET /v1/authorizations` | human | Queue / history (`?status=pending_review`) |
| `GET /v1/authorizations/:id` | human or owning agent | Agent receives the token once allowed |
| `POST /v1/authorizations/:id/approve` / `deny` | admin, approver (fresh login) | Approve re-evaluates every rule |
| `POST /v1/transactions/execute` | **agent session** | Enforcing gateway. **200** = final (`succeeded`/`failed`); **202** = not yet known |
| `GET /v1/transactions/:id` | human or owning agent | Humans also get `providerAttempts` |
| `POST /v1/transactions/:id/reconcile` | admin | Reconcile with the provider (query first, never blind re-pay) |
| `GET /v1/audit/events[/:id]` | admin, approver | Evidence |
| `GET /v1/audit/verify` | admin | Verify the whole chain |
| `POST /v1/dev/sandbox/faults` | platform (dev only) | Queue provider faults: `decline`, `timeout_before_processing`, `timeout_after_processing`, `crash_after_processing`, `status_unavailable` |
| `GET /v1/dev/sandbox/payments/:idempotencyKey` | platform (dev only) | Sandbox provider ledger |

## Example (agent)

```ts
import { AgentTrust } from '@agenttrust/sdk';

const agenttrust = new AgentTrust({
  baseUrl,
  credentialId,                 // workload credential id
  workloadSigner: kmsSigner,    // signs in a sidecar/KMS; dev: localSigner(pem)
});

const auth = await agenttrust.authorizations.create({
  idempotencyKey: 'purchase-inv-900',
  action: 'purchase',
  supplierId: 'sup_…',
  payee: { type: 'us_ach', routingNumber: '021000021', accountNumber: '4000123456' },
  amountCents: 480000,
  currency: 'USD',
  purchaseOrderId: 'po_…',
  invoiceId: 'inv_…',
});

if (auth.decision === 'ALLOW') {
  const txn = await agenttrust.transactions.execute({
    token: auth.token!,
    expected: { supplierId: auth.supplierId, amountCents: auth.amountCents, currency: auth.currency,
                purchaseOrderId: auth.purchaseOrderId, invoiceId: auth.invoiceId },
  });
  // txn.status === 'unknown' → NOT a failure. Retry the same call (it reconciles) or poll.
}
```

## Gateway rejection codes

| Code | Category |
|---|---|
| `TOKEN_BAD_SIGNATURE`, `TOKEN_UNSUPPORTED_ALGORITHM`, `TOKEN_UNKNOWN_KEY`, `TOKEN_NOT_ISSUED_TO_CALLER`, `TRANSACTION_MISMATCH` | **security violation** (counts toward suspension) |
| `TOKEN_MALFORMED`, `TOKEN_EXPIRED`, `TOKEN_SUPERSEDED`, `AUTHORIZATION_NOT_FOUND`, `AUTHORIZATION_NOT_ALLOWED`, `AUTHORIZATION_EXPIRED`, `AUTHORIZATION_INVALIDATED`, `AUTHORIZATION_ALREADY_USED` (409), `AGENT_NOT_ACTIVE`, `DELEGATION_CHANGED`, `DELEGATION_NO_LONGER_VALID`, `POLICY_CHANGED`, `SUPPLIER_NOT_VERIFIED`, `SUPPLIER_RECORD_CHANGED`, `PAYEE_CHANGED`, `AUTHORIZATION_BINDING_CHANGED`, `INVOICE_NOT_PAYABLE` | operational (alerts only) |

Decision reason codes are defined in [`packages/shared/src/decision.ts`](../packages/shared/src/decision.ts).
