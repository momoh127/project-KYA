# Threat Model (MVP v0.2)

Method: assets → actors → attacks → mitigations → residual risk. Every mitigation marked "Tested" has an automated
test in `apps/api/test/` or `packages/*/test/`.

**Enforcement boundary:** all guarantees apply to payments executed through the AgentTrust gateway. An agent that
holds any *other* payment credential or tool is outside this model (see R0).

## Assets

1. Customer funds (moved by payment providers on our authorization)
2. Supplier master data, especially bank details and their verification
3. Delegations, policies and budgets (the "business authority")
4. Agent workload credentials and session keys
5. Platform signing key (authorizations + audit) and payee-fingerprint pepper
6. Audit evidence
7. Tenant data confidentiality

## Actors

| Actor | Capability assumed |
|---|---|
| **Compromised / prompt-injected agent runtime** | Can read anything in the agent process, including its session key; sends arbitrary requests; believes malicious documents |
| **External fraudster** | Sends fake invoices / "bank changed" emails; knows public identifiers (e.g. a credential id) |
| **Malicious tenant** | Valid credentials in *their* organization; probes others |
| **Compromised employee account** | One human account (any role) in the customer organization, possibly with a fresh login |
| **Network attacker** | Can observe/replay/modify traffic where TLS is absent or terminated |
| **Platform insider / DB attacker** | Direct database access (partially out of scope) |

## Attacks and mitigations

| # | Attack | Mitigation | Status |
|---|---|---|---|
| T1 | Agent pays a fraudster's account (BEC, prompt injection) | Payee fingerprint must match verified supplier record; gateway re-checks and pays the verified counterparty only | Tested |
| T2 | Agent pays more than approved | Delegation limit, PO remaining, exact invoice amount, monthly budget | Tested |
| T3 | Same invoice paid twice | Invoice status incl. `processing`; one live hold per invoice (partial unique index); row locks; unique invoice numbers | Tested |
| T4 | Concurrent requests overspend budget | Agent row lock + reservations in the same transaction | Tested |
| T5 | Agent bypasses AgentTrust | Agent holds no payment credentials; gateway is the only payment path **we provide** | By construction (see R0) |
| T6 | Forged / edited authorization | EdDSA over all fields; algorithm pinned; gateway compares expected params and rebuilt instruction | Tested |
| T7 | Authorization replay | Atomic single-use consumption; unique `Transaction.authorizationId` | Tested |
| T8 | Using another agent's authorization | Token `agt`/`org` must equal caller | Tested |
| T9 | Stolen agent key used indefinitely | Workload key can only mint sessions; session keys expire (15 min default) and die on suspension/revocation; workload key held outside the LLM via `SignFn` | Tested (sessions) / Design (key custody) |
| T10 | Request replay / tampering in transit | Signed timestamp (±5 min), single-use nonce, body hash in signature | Tested |
| T11 | Agent grants itself authority / approves itself | Governance and approval routes are human-only | Tested |
| T12 | Human delegates/approves beyond their authority | `spendingAuthorityCents` checks | Tested |
| T13 | Compromised employee swaps a supplier's bank account | Step-up auth for changes; change → `pending`; verification by a **different** admin with step-up, last-4 confirmation and evidence; versioned records; live authorizations invalidated; gateway rejects old supplier versions | Tested |
| T14 | Authorization outlives the authority behind it | Binding includes policy version, delegation, supplier version, rail, destination; proactive invalidation + gateway re-verification | Tested |
| T15 | Gateway crash / provider timeout leads to double payment | State machine; idempotency key on every provider call; reconcile (status query) before any retry; `processing` invoice blocks re-authorization; escalation to `reconciliation_required` | Tested (sandbox fault injection) |
| T16 | Human approval used to bypass a hard denial | Approval re-evaluates all rules; only approval-threshold / missing-PO checks are approvable; records changing during review invalidate it | Tested |
| T17 | Outsider knocks a legitimate agent offline (DoS via security response) | Only authenticated violations (forged/tampered/misused tokens) suspend; bad signatures and scam-invoice denials alert only | Tested |
| T18 | Cross-tenant access / field smuggling | Org from credentials; 404 for foreign ids; strict schemas | Tested |
| T19 | Rewriting audit history | Hash chain + platform signature + DB trigger blocks UPDATE/DELETE | Tested (partial; see R3) |
| T20 | LLM decides a financial outcome | Engine is deterministic code | By construction |

## Residual risks (unresolved, documented)

| # | Risk | Plan |
|---|---|---|
| R0 | **Out-of-band payment paths:** if a customer gives an agent another card/bank/API credential, AgentTrust can't prevent its use | Deployment guidance; future single-use virtual-card adapter so the only usable instrument is AgentTrust-issued |
| R1 | Platform signing key and pepper are environment variables in dev | KMS/HSM-backed `Signer`; secret manager; key rotation by `kid` |
| R2 | Human auth is a dev HMAC issuer; step-up uses token `auth_time` | OIDC provider with MFA and real step-up (`max_age`/`acr`) |
| R3 | DB superuser can disable triggers and rewrite a chain (with key access) | Anchor chain heads to S3 Object Lock / external timestamping |
| R4 | Bank-account **ownership** is verified by a human with recorded evidence, not by a bank-data provider | Integrate account-ownership verification (Nacha-style validation, Trustpair/Eftsure-like providers) |
| R5 | Workload credential is still a registered key; custody depends on the integrator using a sidecar/KMS `SignFn` | `WorkloadIdentityVerifier` for SPIFFE JWT-SVID / cloud workload-identity OIDC so no long-lived agent secret exists |
| R6 | A compromised runtime can misuse its *current* session within policy limits for ≤ 15 min | Inherent: policy limits, budgets and payee checks bound the damage; shorter TTLs for high-risk agents |
| R7 | No Postgres row-level security (isolation enforced in app code) | RLS policies keyed by `organizationId` |
| R8 | Sandbox provider only; real adapters must meet the idempotency + status-lookup contract | Stripe / Modern Treasury adapters + contract tests |
| R9 | Rate limiting is per-process memory; `SecuritySignal` / nonce tables grow | Redis limits; TTL cleanup jobs |
| R10 | Webhook signing not implemented (no webhooks yet) | Signed webhooks with timestamp + id dedupe |
