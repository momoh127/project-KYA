# Roadmap

## Done

**MVP v0.1:** deterministic policy engine; signed agent requests; transaction-bound single-use authorizations;
enforcing gateway; approvals; race-free budgets; duplicate protection; signed hash-chained audit; SDK; demo.

**v0.2 hardening** ([ADR-0003](adr/0003-hardening.md)):
- Workload credentials that can only mint short-lived session keys; `SignFn` so keys can live in a sidecar/KMS
- High-risk supplier records: step-up auth, dual-control verification with evidence (incl. onboarding), versions,
  invalidation of live authorizations
- Complete payment-instruction binding (rail, destination, supplier/policy/delegation versions)
- Payment state machine with provider idempotency, reconciliation, background reconciler, fault-injected sandbox
- Approval re-evaluation proven against revoked/expired delegations
- Graded, DoS-resistant security responses + alerts
- 90 automated tests; 15-scenario live demo

**v0.3: purchase-intent verification** ([ADR-0004](adr/0004-purchase-intent-and-finality.md)):
- Independently approved purchase instructions (human + ERP), line-item matching, configurable three-way match (T21)
- Payment lifecycle and finality, signed/deduplicated webhooks, returns/reversals held for explicit release (T22)
- Deterministic valid-session abuse checks
- Supplier assurance levels + account-verification provider interface
- External audit anchoring (Merkle, write-once storage, independent verifier)
- Cross-agent concurrency tests; branching workflow (main = production)
- 153 automated tests; 17-scenario live demo

**v0.4: developer experience** (goal: external developer ≤ 30 min to a settled sandbox payment, measured):
- Hosted sandbox: self-service signup (admin/verifier/approver personas), org-scoped provider simulation,
  time-to-first-payment funnel metrics; Docker image + Render blueprint; portal at `/docs`, SDK downloads
- TypeScript SDK (typed admin + sandbox clients, zero-dependency release bundle) and Python SDK (`agenttrust`),
  sharing committed signing test vectors
- OpenAPI 3.1 reference with a drift test; Quickstart; Integration Guide; evaluation protocol; runnable examples in CI
- 90-second terminal demo video + voice-over; GitHub rulesets versioned (enforcement deferred: plan limitation)
- 59 unit + 126 integration + 13 Python tests; both quickstarts run live in CI

## Next

Decided by design-partner evidence, not by us. Candidates, in the order we expect to need them:

| Signal from design partners | Then build |
|---|---|
| "We own the payment call" (expected to be common) | **Pattern B:** verify-and-consume API for the customer's payment service + outcome reporting |
| "Our approvals live in NetSuite / Coupa / Slack" | First real instruction source connector (ERP sync exists; add one concrete integration) |
| "We'd go live on rail X" | First real payment adapter behind `PaymentAdapter` (no real money until the production items below exist) |
| Integration takes > 30 min | Fix the top confusion point after every evaluation session |

Before any real money (unchanged from v0.3):

| Priority | Item | Why |
|---|---|---|
| P0 | OIDC human auth with MFA and real step-up (`max_age` / `acr`) | Replace dev issuer |
| P0 | KMS-backed platform `Signer`, key rotation | Key custody |
| P0 | `WorkloadIdentityVerifier` (SPIFFE JWT-SVID, AWS/GCP/Azure workload identity) | Remove long-lived agent secrets |
| P0 | Dashboard: instruction approvals, review queue, alerts, supplier verification, payment exceptions, audit/anchors | Finance/compliance users |
| P0 | S3 Object Lock anchor adapter (separate account) | Close R3 |
| P0 | Real account-verification provider | Close R4 |
| P1 | **MCP server** exposing only high-level tools to models | Drop-in for agent frameworks without exposing keys |
| P1 | Real payment adapters meeting the idempotency + status-lookup contract (Stripe incl. single-use Issuing cards, Modern Treasury) | Enforcement on real rails; closes R0 for card spend |
| P1 | Bank-account ownership verification provider | Close R4 |
| P1 | Signed webhooks for decisions, alerts, reconciliation | Integrations |
| P1 | RFC 9421 HTTP Message Signatures | Interop with Web Bot Auth / card-network agent protocols |
| P2 | ERP sync (NetSuite, SAP, Coupa) | Real workflows |
| P2 | Postgres RLS, audit anchoring to S3 Object Lock, Redis rate limits, TTL cleanup jobs | Defense in depth |
| P2 | KYA-manifest import (open-kya) | Interoperability |
| P3 | Cross-customer fraud signals (with explicit data rights) | Network effects |

## Explicitly not building (yet)

Government ID scanning, proprietary KYC, blockchain identity, crypto wallets, payment processing / money
transmission, general AI security, universal agent reputation scores, proprietary models, ERP replacement,
autonomous AI fraud decisioning.
