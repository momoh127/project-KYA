# ADR-0003: Hardening identity, trusted records, binding, payment execution and security responses

- **Status:** Accepted (supersedes parts of ADR-0002)
- **Date:** 2026-10-22

## Context

An architecture review of MVP v0.1 identified six weaknesses that separate a convincing prototype from
infrastructure that could eventually be trusted with enterprise money:

1. A long-lived agent private key sat in the agent runtime. A compromised runtime yields a key that is valid
   forever. And a signature proves *possession of a credential*, not *human intent*.
2. Human-maintained records (supplier bank details) were trusted, but a compromised employee account could
   change them and make a malicious payment pass every check.
3. The authorization fingerprint did not bind the complete payment instruction (rail, provider destination,
   record/policy/delegation versions).
4. Atomic consumption alone does not prevent double payment when the gateway crashes after the provider
   accepted a payment.
5. REVIEW must never become a way around DENY.
6. Auto-suspending an agent after N denials lets outsiders deliberately knock a legitimate agent offline.

## Decisions

### 1. Workload credentials + short-lived sessions
- The registered key becomes a **workload credential** that can do exactly one thing: mint **sessions**
  (`POST /v1/agent-sessions`), each bound to a fresh ephemeral key, default 15 min, max 1 h, never outliving
  the credential.
- Only **session keys** can request authorizations or execute payments; workload keys get `SESSION_REQUIRED`.
- The SDK takes a `workloadSigner` callback so the workload key can live in a sidecar, OS keystore or
  KMS/HSM outside the LLM-accessible environment. The session key is a non-exported in-memory `KeyObject`.
- Suspension/revocation revokes all sessions immediately.
- Every request is signed over method, path, timestamp, nonce and body hash (unchanged), so a request is
  bound to the authenticated workload session and its exact payload.
- **Explicit non-goal:** cryptography proves which credential signed, not what the human intended. Human intent
  is established by delegations, POs, invoices and approvals, which are human-only records.
- *Production next step:* a `WorkloadIdentityVerifier` accepting SPIFFE JWT-SVIDs or cloud workload-identity
  OIDC tokens to mint sessions, so no long-lived agent secret needs to exist at all.

### 2. Supplier records are high-risk
- New or changed bank details are always `pending`. Only a **different** administrator can verify them, via a
  dedicated endpoint that requires **step-up authentication** (login ≤ 5 min), the **last 4 digits** of the
  account, and written **out-of-band evidence** (no single-admin onboarding exception any more).
- Bank-detail changes require step-up authentication.
- Every change creates an immutable `SupplierVersion` and bumps `Supplier.version`.
- Every change **invalidates live authorizations** for that supplier (status `invalidated`, holds released).
- Documented: an HMAC fingerprint proves *sameness* of an account, not *ownership*. Ownership verification is a
  separate (currently human, later provider-backed) process.

### 3. Complete payment-instruction binding
- New `authorizationFingerprint` (v2, canonical JSON → SHA-256) over: organization, agent, action, supplier,
  **supplier version**, **payment rail**, **provider destination id**, payee fingerprint, amount, currency, PO,
  invoice, **policy id + version**, **delegation id** (delegations are immutable grants, so id = version).
- The token signs every one of these fields. The gateway **rebuilds the instruction from current records** and
  rejects with a specific reason (`POLICY_CHANGED`, `DELEGATION_CHANGED`, `SUPPLIER_RECORD_CHANGED`,
  `PAYEE_CHANGED`, `AUTHORIZATION_BINDING_CHANGED`).
- Policy version changes, delegation supersession/revocation and agent revocation proactively invalidate live
  authorizations.

### 4. Payment state machine with reconciliation
- Transaction states: `executing → succeeded | failed | unknown`, and `unknown → (reconcile) → succeeded |
  failed | reconciliation_required`. Invoice gains `processing`. **A timeout is never treated as failure.**
- Every provider call carries the same idempotency key (= authorization id); adapters must support lookup by key.
- Attempt counter is persisted **before** each provider call; every call is logged in `TransactionAttempt`.
- Retrying `execute` with a consumed authorization whose transaction is non-final **reconciles** (status query
  first; resend with the same key only if the provider has no record; escalate to `reconciliation_required`
  + alert after 3 attempts). Final transactions return `AUTHORIZATION_ALREADY_USED`.
- A lease prevents concurrent reconcilers; outcomes apply exactly once (conditional updates).
- Background reconciler + manual `POST /v1/transactions/:id/reconcile`.
- The sandbox provider keeps its own ledger table (survives gateway crashes) and supports fault injection:
  `decline`, `timeout_before_processing`, `timeout_after_processing`, `crash_after_processing`,
  `status_unavailable`.

### 5. REVIEW cannot bypass DENY (confirmed + tested)
- Approval re-evaluates **all** rules against current facts with only "approvable" checks (approval threshold,
  missing PO) resolvable by a human. Supplier/payee checks are never approvable; any DENY stays DENY.
- Records changing during review invalidate the review (e.g. delegation revoked → `invalidated`); conditions
  that lapse without an event (delegation expiry) are caught by re-evaluation → `DENY`.

### 6. Graded security responses (replaces the circuit breaker)

| Signal | Who can cause it | Response |
|---|---|---|
| Authenticated security violation (forged/tampered token, another agent's token, parameter tampering) | only the agent's own session-key holder | audit `security.violation`; **suspend** at threshold (default 3 / 10 min) |
| Unauthenticated failure (bad signature, replayed nonce, expired key) | anyone who knows a key id | `SecuritySignal` (not in audit chain); **alert + flag credential**; never suspend |
| Fraud-signal denial (payee mismatch, blocked supplier) | outsiders via scam invoices | **alert**; never suspend |
| Business-policy denial (budget, amount, missing PO) | normal operation | alert at threshold; never suspend |

## Consequences
- Integrators must keep the workload key outside the model's reach and use the SDK's session handling.
- Any supplier/policy/delegation change kills outstanding authorizations (10-minute TTL keeps the cost low).
- Execute can return **202** with `unknown`; clients must not treat that as failure.
- Positioning is corrected (see README): AgentTrust prevents unauthorized payments **through the enforcing
  gateway**. It cannot stop an agent that was separately given unrestricted payment credentials.
