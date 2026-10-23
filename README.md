# AgentTrust

**The authorization layer for AI agents that spend money.**

*AgentTrust prevents unauthorized AI-agent payments through enforceable transaction controls, verified business
authority, and auditable execution.*

AI agents are starting to buy supplies and pay invoices. AgentTrust checks every payment an agent proposes
against independently established business authority: verified suppliers and bank accounts, approved purchase
orders, invoices, budgets and human delegations. The payment gateway then **enforces** the decision, so the agent
can't pay the wrong supplier, the wrong amount, the same invoice twice, or anything a human didn't authorize, even if
the agent itself is fooled or prompt-injected.

```
AI agent runtime ──session-signed request──▶ AgentTrust API ──▶ deterministic policy engine ──▶ ALLOW / REVIEW / DENY
   │  (workload key in sidecar/KMS mints 15-min session keys)                                     │
   │◀────────── single-use authorization bound to the COMPLETE payment instruction ───────────────┘
   └──execute──▶ AgentTrust payment gateway (sole holder of payment credentials)
                   └─ re-verifies current records → provider (idempotency key) → reconcile on uncertainty
```

> [!IMPORTANT]
> **The enforcement boundary.** AgentTrust prevents unauthorized spending *only for payments that go through its
> enforcing gateway*. If an agent is separately given unrestricted access to another bank account, card, API key
> or payment tool, AgentTrust can't stop it from using that other path. Deployments must route agent payment
> capability exclusively through AgentTrust.

> [!WARNING]
> This is an MVP running against a **sandbox** payment provider. It is not production-certified, compliant, or
> independently audited. Known gaps are in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md#residual-risks-unresolved-documented).

## What it checks

| Category | Checks |
|---|---|
| **Payee** | Supplier is known, active and verified; payment destination matches the verified, versioned supplier record; bank changes need step-up auth + a second admin with recorded evidence |
| **Amount** | Within the agent's per-purchase limit, the monthly budget (race-free), the PO's remaining amount, and the exact invoice amount |
| **Approval** | Valid human delegation; human approval above a threshold, which re-evaluates every rule and can never override a DENY; no duplicate / in-flight invoices; agent active |

## How it stays trustworthy

- **Short-lived agent credentials:** a workload key (kept outside the LLM's reach) can only mint 15-minute session keys.
- **Complete binding:** each authorization signs rail, provider destination, amount, currency, PO, invoice, and the exact
  supplier-record, policy and delegation versions. Any change makes it invalid.
- **No double payments:** a payment state machine (`executing → succeeded | failed | unknown → reconciled`) with
  provider idempotency keys. A timeout is never treated as failure; the gateway reconciles before any retry.
- **Graded security responses:** forged or tampered authorizations (which only the key holder can produce) suspend an agent.
  Outsider-triggerable signals (bad signatures, scam invoices) raise alerts but never suspend.
- **Evidence:** every decision is a signed, hash-chained, append-only audit event.

## Quick start

Prerequisites: Node 20+, pnpm 9, PostgreSQL 14+ binaries (`brew install postgresql@14`) **or** Docker.

```bash
pnpm install
pnpm setup:env          # writes .env with fresh development secrets (never commit it)
pnpm db:start           # project-local Postgres on :54329  (or: docker compose up -d)
pnpm db:migrate
pnpm --filter @agenttrust/api run db:migrate:test
pnpm build
pnpm dev:api            # API on http://localhost:4000
pnpm demo               # in another terminal: the 15-scenario procurement-agent demo
```

## Tests

```bash
pnpm test               # unit tests + API integration/security tests (needs Postgres)
```

- **38 unit tests:** policy engine, canonical hashing, payee fingerprints, request signing, complete-binding tokens, audit chain
- **52 integration tests** against a real server + database: every demo scenario plus tenant isolation, workload/session
  identity, replay, DoS-resistant security responses, privilege escalation, step-up auth, supplier versioning, dual
  control, idempotency, provider timeouts/declines/crashes, and append-only audit

## Demo scenarios (`pnpm demo`)

| # | The agent tries… | Result |
|---|---|---|
| 1 | \$500 to an approved supplier | ALLOW → paid |
| 2 | \$5,000 against a \$500 approval | DENY |
| 3 | \$500 to an unknown supplier | REVIEW (cannot be click-approved) |
| 4 | Paying with no / forged authorization | Blocked at gateway |
| 5 | Paying an already-paid invoice | DENY |
| 6 | Scam email: "our bank account changed" | DENY (payee mismatch) |
| 7 | Using a \$500 authorization for \$5,000 | Blocked |
| 8 | Re-using an authorization | Blocked |
| 9 | \$3,000 purchase → human approves → pays | REVIEW → paid |
| 10 | 5 simultaneous purchases vs \$1,200 budget | exactly 2 allowed |
| 11 | Scam-invoice spam, then forged tokens | alert only, then suspended |
| 12 | Supplier bank details changed **after** authorization | Blocked (authorization invalidated) |
| 13 | Provider pays, then the gateway crashes; agent retries | Reconciled: **exactly one** payment |
| 14 | Human approves after the delegation was revoked | Denied |
| 15 | Revoked agent with a valid authorization | Blocked |

## Repository layout

```
apps/
  api/                      NestJS API + enforcing payment gateway + reconciler (Prisma/PostgreSQL)
  demo-procurement-agent/   Narrated demo with a deliberately gullible agent
packages/
  shared/                   Canonical JSON, money, payee + transaction + authorization fingerprints, reason codes
  policy-engine/            Pure deterministic ALLOW/REVIEW/DENY engine
  identity/                 Ed25519 keys, request signing (incl. external SignFn), Signer abstraction
  authorization/            Signed authorization tokens binding the complete payment instruction
  audit/                    Hash-chained, signed audit events + verifier
  sdk-typescript/           Agent (sessions) / admin / platform clients
docs/                       Architecture, threat model, security, API, database, ADRs
```

## Documentation

[Architecture](docs/ARCHITECTURE.md) · [Threat model](docs/THREAT_MODEL.md) · [Security](docs/SECURITY.md) ·
[API](docs/API.md) · [Database](docs/DATABASE.md) · [Deployment](docs/DEPLOYMENT.md) · [Roadmap](docs/ROADMAP.md) ·
[Decisions](docs/adr/) · [Third-party notice](docs/THIRD_PARTY.md)

## License

Proprietary. See [LICENSE](LICENSE).
