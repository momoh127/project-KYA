# AgentTrust

**The authorization layer for AI agents that spend money.**
*Give AI agents permission to act, without giving up control.*

AI agents are starting to buy supplies and pay invoices. AgentTrust makes sure an agent can't pay the wrong
supplier, the wrong amount, the same invoice twice, or anything a human didn't authorize, **even if the agent
is fooled, prompt-injected or fully compromised.**

```
AI agent ──signed request──▶ AgentTrust API ──▶ deterministic policy engine ──▶ ALLOW / REVIEW / DENY
   │                                                                                │
   │◀──────────── single-use authorization, bound to the exact transaction ─────────┘
   │
   └──execute──▶ AgentTrust payment gateway (the ONLY holder of payment credentials) ──▶ payment provider
```

The agent never holds a card or bank login. It can only *ask*. Every request is checked against records that
humans control (verified suppliers and bank accounts, purchase orders, invoices, budgets, delegations), and the
gateway refuses to pay without a valid, unused authorization for *exactly* that payment.

> [!WARNING]
> This is an MVP running against a **sandbox** payment adapter. It is not production-certified, compliant, or
> independently audited. See [docs/SECURITY.md](docs/SECURITY.md) for known gaps.

## What it checks

| Category | Checks |
|---|---|
| **Payee** | Supplier is known, approved and verified; payment destination matches the verified bank record; bank changes need dual control |
| **Amount** | Within the agent's per-purchase limit, the monthly budget (race-free), the PO's remaining amount, and the exact invoice amount |
| **Approval** | Valid human delegation; human approval above a threshold; no duplicate/in-flight invoices; agent active |

## Quick start

Prerequisites: Node 20+, pnpm 9, PostgreSQL 14+ binaries (`brew install postgresql@14`) **or** Docker.

```bash
pnpm install
pnpm setup:env          # writes .env with fresh development secrets (never commit it)
pnpm db:start           # project-local Postgres on :54329  (or: docker compose up -d)
pnpm db:migrate         # apply schema to the dev database
pnpm --filter @agenttrust/api run db:migrate:test   # and to the test database
pnpm build
pnpm dev:api            # API on http://localhost:4000
pnpm demo               # in another terminal: the 12-scenario procurement-agent demo
```

## Tests

```bash
pnpm test               # unit tests (pure packages) + API integration/security tests (needs Postgres)
```

- **38 unit tests:** policy engine, canonical hashing, payee fingerprints, request signing, token tampering, audit chain tampering
- **37 integration tests** against a real server + database: all 12 demo scenarios plus tenant isolation, forged
  identity, replay, privilege escalation, request smuggling, idempotency, dual control, append-only audit

## The demo scenarios

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
| 11 | Hijacked agent keeps retrying | auto-suspended |
| 12 | Revoked agent with a valid authorization | Blocked |

## Repository layout

```
apps/
  api/                      NestJS API + enforcing payment gateway (Prisma/PostgreSQL)
  demo-procurement-agent/   Narrated demo with a deliberately gullible agent
packages/
  shared/                   Canonical JSON, money, fingerprints, reason codes
  policy-engine/            Pure deterministic ALLOW/REVIEW/DENY engine
  identity/                 Ed25519 keys, agent request signing, Signer abstraction
  authorization/            Transaction-bound signed authorization tokens (EdDSA JWS)
  audit/                    Hash-chained, signed audit events + verifier
  sdk-typescript/           Agent / admin / platform clients
docs/                       Architecture, threat model, security, API, database, ADRs
```

## Documentation

[Architecture](docs/ARCHITECTURE.md) · [Threat model](docs/THREAT_MODEL.md) · [Security](docs/SECURITY.md) ·
[API](docs/API.md) · [Database](docs/DATABASE.md) · [Deployment](docs/DEPLOYMENT.md) · [Roadmap](docs/ROADMAP.md) ·
[Decisions](docs/adr/) · [Third-party notice](docs/THIRD_PARTY.md)

## License

Proprietary. See [LICENSE](LICENSE).
