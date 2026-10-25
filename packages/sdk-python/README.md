# agenttrust (Python ≥ 3.9)

AgentTrust checks that an AI agent's payment matches what the business actually approved (the supplier, line items,
amount, PO/invoice, a verified payee, and policy) before the payment can execute.

> Sandbox only. No real money moves. Not production-ready, certified, or audited.

```bash
pip install https://<your-sandbox>/downloads/agenttrust-0.4.0-py3-none-any.whl
```

The only dependency is `cryptography` (for Ed25519). HTTP uses the standard library.

```python
from agenttrust import AgentTrustSandbox, SANDBOX_SUPPLIER_BANK

sandbox, account = AgentTrustSandbox.signup(BASE_URL, "Acme", "you@acme.com")   # save account["sandboxKey"]
supplier_id = sandbox.create_verified_supplier()["supplierId"]                   # admin enters, verifier verifies
agent = sandbox.register_agent()                                                 # agent["client"] runs in your agent runtime
# ... the approver grants a delegation and approves a purchase instruction (see the Quickstart)
auth = agent["client"].authorizations.create({...})                              # decision: ALLOW | REVIEW | DENY
if auth["decision"] == "ALLOW":
    agent["client"].transactions.execute(auth["token"], {...expected...})
```

Clients:

| Client | Used by | Auth |
|---|---|---|
| `AgentTrust` | the agent **runtime** (never the LLM itself) | Ed25519 workload key → short-lived session keys; every request signed |
| `AgentTrustAdmin` | humans / back office | bearer token (sandbox: `sandbox.as_persona("admin")`) |
| `AgentTrustSandbox` | evaluation only | sandbox key |

**Conventions.** Requests and responses are plain dicts that use the API reference's field names (camelCase), so
the API docs apply word for word. Every failure (HTTP error, network error, unreadable response) raises
`AgentTrustError`. Treat any exception as **not authorized** and never pay on an error.

**Keys in production.** Pass `workload_signer=` (a callable `bytes -> 64-byte signature`) backed by a sidecar or KMS,
so the long-lived key never lives in the process the LLM's tools can reach. `private_key_pem=` is for development.

Request signing (`AGENTTRUST-ED25519-V1`) is checked against the same committed test vectors as the TypeScript
reference implementation.
