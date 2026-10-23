# AgentTrust

**AgentTrust ensures AI purchasing and invoice-paying agents can execute only transactions that match independently
approved business instructions, verified payees, and enforced spending limits.**

Most agent-identity systems answer *"who is this agent and what may it spend?"*. AgentTrust answers a narrower,
more valuable question: **does this exact payment correspond to a legitimate, independently approved business
obligation?**

```
Humans / ERP ──approve──▶ Purchase instruction (agent, supplier, items, qty, price, uses, expiry)  ◀─ agents can only READ
                                   │
AI agent (valid session) ──request──▶ deterministic policy engine ──▶ ALLOW / REVIEW / DENY
                                   │   (instruction · lines · PO · invoice · receipt · payee assurance · budget · velocity)
                                   ▼
             single-use authorization bound to the complete payment instruction (incl. instruction version + lines)
                                   │
AgentTrust gateway (sole holder of payment credentials) ──▶ provider: accepted → processing → settled (only now "paid")
```

> [!IMPORTANT]
> **Definition of done (v0.3):** even when an attacker controls an agent's *valid* session, the agent cannot execute a
> payment unless it matches an independently approved, currently valid business instruction and all applicable
> financial controls. **This guarantee applies only to payment paths enforced by AgentTrust.** If an agent is
> separately given another card, bank login or payment API, AgentTrust can't stop it from using that path.

> [!WARNING]
> MVP running against **sandbox** payment and account-verification providers. Not production-certified, compliant,
> or independently audited. Known gaps: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md#residual-risks-unresolved-documented).

## What it verifies

| Layer | Checks |
|---|---|
| **Business intent** | Approved purchase instruction assigned to this agent; supplier, PO, currency match; remaining uses and amount; approved line items (item, unit price, remaining quantity, exact totals); optional three-way match (receipt / service completion / activation) |
| **Payee** | Verified, versioned supplier record; payment destination matches; assurance level (`recorded → reviewed → account_verified → ownership_verified`) sufficient for the amount |
| **Amount** | Per-purchase limit, monthly budget, PO remaining, exact invoice amount; no currency conversion |
| **Approval** | Valid human delegation; human approval above threshold (re-evaluates everything, never overrides DENY) |
| **Behaviour** | Deterministic velocity / budget-depletion / supplier-frequency / recently-changed-payee checks → human review |
| **Execution** | Single-use token bound to the complete instruction; gateway re-verifies current records; idempotent provider calls; settlement-based finality; reconciliation before any retry |
| **Evidence** | Signed hash-chained audit, DB append-only, Merkle-anchored to write-once storage, independent verifier |

## Quick start

Prerequisites: Node 20+, pnpm 9, PostgreSQL 14+ binaries (`brew install postgresql@14`) **or** Docker.

```bash
pnpm install
pnpm hooks:install      # blocks direct pushes to main
pnpm setup:env          # writes .env with fresh development secrets (never commit it)
pnpm db:start           # project-local Postgres on :54329  (or: docker compose up -d)
pnpm db:migrate && pnpm --filter @agenttrust/api run db:migrate:test
pnpm build
pnpm dev:api            # API on http://localhost:4000
pnpm demo               # 17-scenario procurement-agent demo
```

Verify an audit export independently:

```bash
curl -H "authorization: Bearer $TOKEN" localhost:4000/v1/audit/export > export.json
node packages/audit/dist/cli.js --export export.json --anchors apps/api/.local/anchors
```

## Tests

`pnpm typecheck && pnpm test`: **56 unit + 97 integration tests** (real server + PostgreSQL). Suites: scenarios,
security, purchase instructions (adversarial), payments lifecycle, valid-session risk, supplier assurance, audit
anchoring (incl. a full-history-rewrite attack), cross-agent concurrency. Key controls were mutation-checked: breaking
them makes tests fail.

## Demo (`pnpm demo`, 17/17)

1 approved purchase (accepted → settled → paid) · 2 over-approval DENY · 3 unknown supplier REVIEW · 4 forged token blocked ·
5 duplicate invoice DENY · 6 scam bank account DENY · 7 tampered amount blocked · 8 replay never pays twice ·
9 review → approve → pay · 10 concurrent overspend blocked · 11 graded security response · 12 bank changed after
authorization blocked · 13 crash + retry → one payment · 14 approve after revocation denied · **15 valid session,
unapproved intent blocked** · **16 returned payment not auto-repaid** · 17 revoked agent blocked.

## Repository layout

```
apps/api                    NestJS API, gateway, reconciler, anchoring (Prisma/PostgreSQL)
apps/demo-procurement-agent Narrated demo with a deliberately gullible agent
packages/shared             Canonical JSON, money + exact quantities, fingerprints, reason codes
packages/policy-engine      Pure deterministic decision engine
packages/identity           Ed25519 keys, request signing, external SignFn
packages/authorization      Signed tokens binding the complete payment instruction
packages/audit              Hash chain, Merkle anchoring, independent verifier CLI
packages/sdk-typescript     Agent (sessions) / admin / platform clients
docs/                       Architecture, threat model, security, API, database, branching, ADRs
```

## Workflow

`main` is production; features land on `develop` via `feature/*` branches; releases go through `release/*`.
See [docs/BRANCHING.md](docs/BRANCHING.md).

## Documentation

[Architecture](docs/ARCHITECTURE.md) · [Threat model](docs/THREAT_MODEL.md) · [Security](docs/SECURITY.md) ·
[API](docs/API.md) · [Database](docs/DATABASE.md) · [Deployment](docs/DEPLOYMENT.md) · [Roadmap](docs/ROADMAP.md) ·
[Branching](docs/BRANCHING.md) · [Decisions](docs/adr/) · [Third-party notice](docs/THIRD_PARTY.md)

## License

Proprietary. See [LICENSE](LICENSE).
