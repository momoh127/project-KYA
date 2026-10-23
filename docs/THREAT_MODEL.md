# Threat Model (MVP v0.1)

Method: assets → actors → attacks → mitigations → residual risk. Every mitigation listed as "tested" has an
automated test in `apps/api/test/` or `packages/*/test/`.

## Assets

1. Customer funds (moved by payment providers on our authorization)
2. Supplier master data, especially verified bank details
3. Delegations, policies and budgets (the "business authority")
4. Platform signing key (authorizations + audit signatures) and payee-fingerprint pepper
5. Audit evidence
6. Tenant data confidentiality

## Actors

| Actor | Capability assumed |
|---|---|
| **Compromised / prompt-injected agent** | Holds its own valid signing key; sends arbitrary requests; believes malicious documents |
| **External fraudster** | Sends fake invoices / "bank changed" emails; may impersonate suppliers |
| **Malicious tenant** | Has valid credentials in *their* organization; probes other tenants |
| **Malicious or compromised insider** | One human account in the customer organization (any role) |
| **Network attacker** | Can observe/replay/modify traffic where TLS is absent or terminated |
| **Platform insider / DB attacker** | Direct database access (partially out of scope; see residual risks) |

## Attacks and mitigations

| # | Attack | Mitigation | Status |
|---|---|---|---|
| T1 | Agent pays a fraudster's bank account (BEC, prompt injection) | Payee fingerprint must match verified supplier record (engine) + gateway re-check + gateway pays verified counterparty only | Tested |
| T2 | Agent pays more than approved | Delegation limit, PO remaining, exact invoice amount, monthly budget | Tested |
| T3 | Agent pays an invoice twice | Invoice status, live-hold uniqueness (partial unique index), invoice row lock, atomic paid transition, unique invoice numbers | Tested |
| T4 | Concurrent requests overspend budget | Agent row lock + reservations counted in same transaction | Tested |
| T5 | Agent bypasses AgentTrust and pays directly | Agent holds no payment credentials; gateway is the only payment path | By construction |
| T6 | Agent forges / edits an authorization | EdDSA signature over all fields; `alg` pinned; gateway compares expected params and stored intent | Tested |
| T7 | Agent replays an authorization | Atomic single-use consumption; unique `Transaction.authorizationId` | Tested |
| T8 | Agent uses another agent's authorization | Token `agt`/`org` must equal caller; row lookup scoped by org | Tested |
| T9 | Agent impersonates another agent | Ed25519 signature per request against the registered public key | Tested |
| T10 | Request replay / tampering in transit | Signed timestamp (±5 min), single-use nonce, body hash in signature | Tested |
| T11 | Agent grants itself authority / approves itself | Governance and approval routes are human-only; agent credentials cannot authenticate there | Tested |
| T12 | Human delegates/approves beyond their authority | `spendingAuthorityCents` checks on delegation, PO creation, approval | Tested |
| T13 | Insider swaps a supplier's bank account | Bank change → `pending`; verifier must differ from changer (dual control); old authorizations stay bound to old account | Tested |
| T14 | Cross-tenant data access | Every query scoped by org from credentials; 404 for foreign ids | Tested |
| T15 | Field smuggling (`organizationId`, `approved`) | Strict Zod schemas reject unknown fields | Tested |
| T16 | Approval reused after transaction changes | Intent is immutable per authorization; approval bound to fingerprint; any change = new authorization | By construction |
| T17 | Rewriting audit history | Hash chain + platform signature + DB trigger blocks UPDATE/DELETE | Tested (partial; see R3) |
| T18 | Compromised agent keeps probing | Circuit breaker auto-suspends; revocation kill switch re-checked at execution | Tested |
| T19 | Dependency/DB failure leads to approval | Errors never yield authorizations; gateway requires committed state | By construction |
| T20 | LLM decides financial outcome | Engine is deterministic code; no model in the decision path | By construction |

## Residual risks (unresolved, documented)

| # | Risk | Plan |
|---|---|---|
| R1 | Platform signing key and pepper are environment variables in dev | KMS/HSM-backed `Signer`; pepper in secret manager; key rotation with `kid` |
| R2 | Human auth is a dev HMAC issuer | Integrate OIDC provider (JWKS verification, MFA, `auth_time` for fresh-auth) |
| R3 | DB superuser can disable triggers and rewrite a whole chain (with key access) | Anchor chain heads to S3 Object Lock / external timestamping; separate audit DB role |
| R4 | Admin may create a supplier directly as `verified` (onboarding exception) | Integrate bank-account ownership verification (e.g. Trustpair/Eftsure-style providers, Nacha account validation) and require dual control at onboarding |
| R5 | No Postgres row-level security (isolation enforced in app code) | Add RLS policies keyed by `organizationId` as defense in depth |
| R6 | Payment provider adapter is a sandbox; reconciliation job for `pending` transactions not built | Build provider adapters + reconciler |
| R7 | Rate limiting is per-process memory | Redis-backed limits per credential/org |
| R8 | Nonce table grows unbounded | TTL cleanup job (nonces older than skew window) |
| R9 | Single platform signing key for all tenants | Per-tenant keys; key-id rotation |
| R10 | Webhook signing / replay not implemented (no webhooks yet) | Signed webhooks with timestamp + id dedupe |
