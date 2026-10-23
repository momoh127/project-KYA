# ADR-0004: Purchase-intent verification, payment finality, assurance, anchoring (v0.3)

- **Status:** Accepted
- **Date:** 2026-10-22

## Context

After v0.2, a compromised agent with a **valid** session could still make purchases that were within its spending
authority but never requested by the business (e.g. drawing an unrelated amount on a valid PO). Payment
"success" also conflated provider acceptance with settlement. Supplier verification relied on two internal people.
The audit log could be rewritten by an insider holding both database superuser rights and the platform key.

## Decisions

### 1. Independently approved purchase instructions (T21): the product's centerpiece
- A **purchase instruction** defines *what* may be bought, from *whom*, by *which agent*, how much, how many times,
  until when, with exact line items (integer milli-quantities, integer cents, exact totals, no rounding).
- Trusted sources only: humans in AgentTrust (requester ≠ approver, approver authority ≥ amount, fresh login) or ERP
  integrations (source system, external id/version, sync timestamp retained). Agents can only *read* their own
  approved instructions.
- An ERP sync **never** implies approval unless the integration holds `instructions:attest_approval` and the ERP
  reports an approval with approver and time. Stale syncs are rejected. Material changes bump the version, require
  re-approval and invalidate outstanding authorizations.
- The engine requires the payment to match: approved, valid, assigned agent, supplier, PO, currency (never
  converted), remaining uses/amount, and approved lines (item, unit price, remaining quantity, exact totals).
  Trusted invoice lines take precedence over agent-supplied lines. Missing instruction → REVIEW that cannot be
  click-approved (or DENY). Invoice required by default.
- Authorizations bind the instruction id, **version** and the hash of the exact paid lines. The gateway re-verifies them.

### 2. Configurable three-way match
PO → receipt → invoice per fulfillment type: goods receipt, service completion, subscription activation / human
approval, digital delivery. Only humans or ERP integrations with `receipts:confirm` record receipts. Missing or short
receipt → REVIEW or DENY by policy, never ALLOW. Voiding a receipt invalidates dependent authorizations.

### 3. Payment lifecycle and finality (T22)
`requested → accepted → processing → settled → (returned | reversed)`, `failed`, `unknown`,
`reconciliation_required`. Only `settled` pays an invoice. A transition table ignores stale, out-of-order and
post-terminal observations. Webhooks are HMAC-signed with a 5-minute window and deduplicated on (provider, event id).
A conflicting payload under a seen id is rejected and alerted. Failure after acceptance, returns and reversals put
the invoice in `payment_exception` and keep capacity consumed. An admin with a fresh login releases only after the
gateway re-confirms the provider state; then a **new** authorization is required.

### 4. Valid-session abuse checks
Deterministic thresholds (authorizations/hour, share of monthly limit/hour, purchases per supplier/day, recently
changed payee) → approvable REVIEW or temporary DENY, plus an alert. Never suspension, never AI scoring.

### 5. Supplier assurance levels
`recorded → reviewed → account_verified → ownership_verified`. The top two come from an
`AccountVerificationProvider` (independent third party), defeating two colluding admins for payments above a
policy threshold. A positive ownership mismatch never raises assurance and raises a fraud alert.

### 6. External audit anchoring
Signed Merkle roots of audit batches, linked anchor-to-anchor, written to write-once storage outside the database. A
standalone verifier (`agenttrust-verify`) reads anchors directly from storage. Local O_EXCL/0444 adapter now. S3
Object Lock (compliance mode, separate account/role) is the documented production target and is **not implemented**.

### 7. Lock-order correction
Every transaction takes the `AuditChainHead` lock last. Paths that change records authorizations depend on lock live
authorization rows first. Global order: `Authorization → Agent → PurchaseInstruction → PurchaseOrder → Invoice →
AuditChainHead`.

## Consequences
- Every payment now requires business setup (instruction, usually invoice). This is the point: valid credentials alone
  never suffice.
- Execute returns 202 for accepted payments. Clients must treat only `settled` as paid.
- Shared capacity (POs) is protected by locks on the shared record. Agent budgets remain per agent. A future shared
  departmental budget needs its own locked ledger (tested pattern: `apps/api/test/concurrency.test.ts`).
