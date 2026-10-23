# Security

## Scope of the guarantee

AgentTrust prevents unauthorized AI-agent payments **that go through its enforcing gateway**. It can't control
payment credentials or tools a customer gives an agent outside AgentTrust. Route all agent payment capability
through the gateway (or a future AgentTrust-issued single-use instrument).

## Security invariants (and where they are enforced)

| Invariant | Enforcement |
|---|---|
| Never trust an agent's self-reported identity | `AuthGuard`: Ed25519 signature against a registered workload key or a live session key |
| Long-lived agent secrets can't transact | Workload credentials may only call `POST /v1/agent-sessions`; everything else needs a session (`SESSION_REQUIRED`) |
| Stolen session keys expire quickly | Sessions default to 15 min (max 1 h), never outlive the workload credential, and are revoked on suspension/revocation |
| Never trust an agent's claim that a human approved | Approval only via human-only routes; engine reads approval state from the DB |
| Agent can't modify its permissions / raise limits | Delegation, policy and supplier routes are `@Human(...)` |
| Agent can't approve its own transaction | Approval routes are human-only and require fresh authentication |
| Approval can't override hard denials | Approval re-runs every rule; only approval-threshold / missing-PO checks are approvable |
| Sensitive record changes are high-risk | Bank changes need step-up auth; verification needs a *different* admin + step-up + last-4 + evidence; records are versioned |
| Authorization can't be reused or outlive its authority | Token binds the complete instruction incl. supplier/policy/delegation versions; single-use; invalidated on changes |
| No double payment on crash/timeout | Payment state machine; provider idempotency key; reconcile before retry; `processing` invoices |
| Concurrent transactions can't overspend | Agent row lock + reservations in one DB transaction |
| No payment credentials or signing secrets reach the LLM | Provider credentials live only in the gateway; the workload key belongs in a sidecar/KMS via `SignFn`; session keys are non-exported in-memory objects in the runtime, not in prompts |
| LLM output is never final authority | Deterministic `evaluatePurchase` |
| Security responses can't be weaponized | Only authenticated violations suspend; outsider-triggerable signals alert only |
| Fail closed | Missing policy/rules → DENY; errors → no authorization; unknown access rule → 403 |
| No cross-organization access | All queries scoped by org from credentials; 404 for foreign ids |

## Integrating an agent safely

1. Keep the **workload private key out of the agent/LLM process**. Provide the SDK a `workloadSigner` that calls a
   sidecar, OS keystore or KMS/HSM. `localSigner(pem)` is for development only.
2. Expose only **high-level tools** to the model (e.g. "request purchase authorization", "pay authorized
   invoice"). Never expose raw tokens, keys or the SDK object to the model.
3. Give the agent **no other payment credential**.
4. Treat `202` / `unknown` execution results as **pending**. Retry the same execute call or poll; never request a
   new authorization to "try again".

*Production target:* a `WorkloadIdentityVerifier` that accepts SPIFFE JWT-SVIDs or cloud workload-identity OIDC
tokens to mint sessions, removing the long-lived agent secret entirely.

## Graded security responses

| Signal | Example | Response |
|---|---|---|
| Authenticated security violation | Tampered/forged token, another agent's token, parameter mismatch at the gateway | `security.violation` audit event; suspend agent + revoke sessions at threshold (default 3 / 10 min) |
| Unauthenticated failure | Bad signature, replayed nonce, expired key | `SecuritySignal`; alert + flag credential at threshold (default 10 / h); **never suspend** |
| Fraud-signal denial | `PAYEE_MISMATCH`, blocked or non-delegated supplier | Alert (once per window); **never suspend** |
| Business-policy denial | Budget, amount, missing PO | Alert at threshold (default 10 / h); **never suspend** |

Alerts are signed audit events, listed at `GET /v1/alerts`.

## Cryptography

Only standard algorithms through Node's `crypto` module. No custom primitives.

| Use | Algorithm |
|---|---|
| Agent request signatures (workload + session) | Ed25519 over `scheme, method, path, timestamp, nonce, sha256(body)` |
| Authorization tokens | Compact JWS, `alg: EdDSA`, algorithm pinned |
| Authorization fingerprint | SHA-256 over canonical JSON of the complete payment instruction (v2) |
| Audit events | SHA-256 hash chain + Ed25519 signature per event |
| Payee fingerprints | HMAC-SHA256 with a server-side pepper. Proves *sameness*, not *ownership* (ownership = separate verification) |
| Dev human tokens | HMAC-SHA256 JWT (development only; disabled in production by config) |

## Data handling

- Raw bank account numbers are **not stored**: only HMAC fingerprint, type and last 4 digits.
- No card numbers, no customer funds, no money transmission. The sandbox adapter moves no money.
- Secrets live in `.env` locally (gitignored, generated by `pnpm setup:env`). Production uses a secret manager and
  KMS-backed signing.

## Known gaps before any production use

See [THREAT_MODEL.md § Residual risks](THREAT_MODEL.md#residual-risks-unresolved-documented).

**This MVP is not production-certified, compliant, or independently audited.**

## Reporting

Report suspected vulnerabilities privately to the maintainers; do not open public issues.

## v0.3 invariants

| Invariant | Enforcement |
|---|---|
| Valid credentials alone never authorize a payment | Approved, current purchase instruction required; missing → non-approvable REVIEW / DENY |
| Agents can't create, modify, approve or reassign instructions | No agent-writable routes; agents read only their own approved instructions |
| A sync is not an approval | `instructions:attest_approval` scope required for ERP-reported approvals |
| Exact money and quantity arithmetic | Integer cents, integer milli-quantities, exact totals or rejection; DB CHECK constraints; no currency conversion |
| Acceptance ≠ payment | Invoice paid only on `settled`; transition table blocks backwards moves |
| Returned/reversed payments are not auto-repayable | `payment_exception` hold; explicit release after provider re-confirmation; new authorization required |
| Collusion-resistant payee assurance | Provider-backed `ownership_verified` required above policy thresholds |
| History rewrite is detectable | Merkle anchors in write-once storage + independent verifier |
