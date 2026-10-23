# API (v1)

Base URL (local): `http://localhost:4000`. All bodies are JSON. Unknown fields are rejected (400).
Errors: `{ "error": { "code": "...", "message": "...", "details": ... } }`. Treat any non-2xx as **not authorized**.

## Authentication

| Caller | How |
|---|---|
| Human | `Authorization: Bearer <token>` from the identity provider (dev: `POST /v1/dev/token`) |
| Agent | Ed25519-signed request headers (use `@agenttrust/sdk`): `x-agenttrust-credential`, `x-agenttrust-timestamp`, `x-agenttrust-nonce`, `x-agenttrust-signature`. Signature covers `AGENTTRUST-ED25519-V1\nMETHOD\npath\ntimestamp\nnonce\nsha256(body)`. |
| Platform operator | `x-agenttrust-bootstrap-token` |

## Endpoints

| Method & path | Caller | Purpose |
|---|---|---|
| `GET /v1/health` | public | Liveness |
| `POST /v1/organizations` | platform | Create org + first admin + policy v1 + audit chain |
| `GET /v1/organizations/:id` | human | Own organization only |
| `POST /v1/dev/token` | platform (dev only) | Issue a dev human token |
| `POST /v1/users` / `GET /v1/users` | admin | Invite users with role + spending authority |
| `POST /v1/agents` | admin | Register agent with its Ed25519 public key |
| `GET /v1/agents`, `GET /v1/agents/:id` | human | Registry |
| `POST /v1/agents/:id/revoke` | admin | Permanent kill switch |
| `POST /v1/agents/:id/reactivate` | admin | Lift a suspension |
| `POST /v1/delegations` | admin, approver | Grant bounded authority (≤ own authority); supersedes previous |
| `GET /v1/delegations/:id`, `POST /v1/delegations/:id/revoke` | human / admin, approver | |
| `GET /v1/policies`, `POST /v1/policies`, `PUT /v1/policies/:id` | human / admin | Immutable versions |
| `POST /v1/suppliers`, `GET /v1/suppliers[/:id]`, `PATCH /v1/suppliers/:id` | admin / human | Bank changes require dual-control re-verification |
| `POST /v1/purchase-orders`, `GET /v1/purchase-orders/:id` | admin, approver / human | |
| `POST /v1/invoices`, `GET /v1/invoices/:id` | human | Duplicate invoice numbers rejected |
| `POST /v1/authorizations` | **agent** | Request authorization → ALLOW / REVIEW / DENY |
| `GET /v1/authorizations` | human | Queue / history (`?status=pending_review`) |
| `GET /v1/authorizations/:id` | human or owning agent | Agent receives token once approved |
| `POST /v1/authorizations/:id/approve` | admin, approver (fresh login) | Re-evaluates with approval |
| `POST /v1/authorizations/:id/deny` | admin, approver (fresh login) | |
| `POST /v1/transactions/execute` | **agent** | Enforcing gateway |
| `GET /v1/transactions/:id` | human or owning agent | |
| `GET /v1/audit/events`, `GET /v1/audit/events/:id` | admin, approver | Evidence |
| `GET /v1/audit/verify` | admin | Verify the whole chain |

## Example: request an authorization (agent)

```ts
import { AgentTrust } from '@agenttrust/sdk';

const agenttrust = new AgentTrust({ baseUrl, credentialId, privateKeyPem });

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
  await agenttrust.transactions.execute({
    token: auth.token!,
    expected: { supplierId: auth.supplierId, amountCents: auth.amountCents, currency: auth.currency,
                purchaseOrderId: auth.purchaseOrderId, invoiceId: auth.invoiceId },
  });
}
```

Response (abridged):

```json
{
  "id": "auth_…",
  "decision": "ALLOW",
  "status": "allowed",
  "reasonCodes": ["AGENT_ACTIVE", "DELEGATION_VALID", "SUPPLIER_APPROVED", "PAYEE_VERIFIED",
                  "AMOUNT_WITHIN_LIMIT", "BUDGET_AVAILABLE", "PO_MATCHED", "INVOICE_MATCHED", "APPROVAL_NOT_REQUIRED"],
  "checks": [{ "code": "PAYEE_VERIFIED", "outcome": "pass", "message": "Payment destination matches the verified supplier record." }],
  "policyVersion": 1,
  "transactionFingerprint": "tx_…",
  "expiresAt": "2026-10-22T23:00:00.000Z",
  "token": "eyJhbGciOiJFZERTQSIs…"
}
```

## Gateway rejection codes

`TOKEN_MALFORMED`, `TOKEN_BAD_SIGNATURE`, `TOKEN_UNKNOWN_KEY`, `TOKEN_UNSUPPORTED_ALGORITHM`, `TOKEN_EXPIRED`,
`TOKEN_NOT_ISSUED_TO_CALLER`, `TRANSACTION_MISMATCH`, `AUTHORIZATION_NOT_FOUND`, `AUTHORIZATION_NOT_ALLOWED`,
`AUTHORIZATION_EXPIRED`, `AUTHORIZATION_ALREADY_USED` (409), `AGENT_NOT_ACTIVE`, `DELEGATION_NO_LONGER_VALID`,
`SUPPLIER_NOT_VERIFIED`, `PAYEE_CHANGED`, `INVOICE_NOT_PAYABLE`.

Reason codes for decisions are defined in [`packages/shared/src/decision.ts`](../packages/shared/src/decision.ts).
