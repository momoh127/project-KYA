# @agenttrust/sdk (TypeScript / Node ≥ 18.17)

AgentTrust checks that an AI agent's payment matches what the business actually approved (the supplier, line items,
amount, PO/invoice, a verified payee, and policy) before the payment can execute.

> Sandbox only. No real money moves. Not production-ready, certified, or audited.

```bash
npm install ./agenttrust-sdk-0.4.0.tgz      # or the URL your sandbox serves under /downloads
```

```ts
import { AgentTrustSandbox, SANDBOX_SUPPLIER_BANK } from '@agenttrust/sdk';

const { sandbox, account } = await AgentTrustSandbox.signup({ baseUrl, organizationName: 'Acme', email: 'you@acme.com' });
// Save account.sandboxKey. It is shown only once.
const { supplierId } = await sandbox.createVerifiedSupplier();      // entered by admin, verified by a 2nd admin
const agent = await sandbox.registerAgent();                         // agent.client is what your agent runtime uses
// ...the approver grants a delegation and approves a purchase instruction (see the Quickstart)
const auth = await agent.client.authorizations.create({ /* … */ }); // ALLOW | REVIEW | DENY
if (auth.decision === 'ALLOW') await agent.client.transactions.execute({ token: auth.token!, expected: { /* … */ } });
```

Three clients:

| Client | Used by | Auth |
|---|---|---|
| `AgentTrust` | the agent **runtime** (never the LLM itself) | Ed25519 workload key → short-lived session keys, every request signed |
| `AgentTrustAdmin` | humans / back office: suppliers, POs, instructions, approvals | bearer token from your identity provider (sandbox: persona tokens) |
| `AgentTrustSandbox` | evaluation only: signup, personas, simulated provider settlement | sandbox key |

Every non-2xx response throws `AgentTrustError` (`status`, `code`, `message`). Treat any error as **not authorized**.

Full docs: the sandbox's `/docs` (Quickstart, Integration Guide, API reference).
