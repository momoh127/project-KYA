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
> or independently audited. The hosted sandbox uses development persona logins and moves no real money. Known gaps:
> [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md#residual-risks-unresolved-documented).

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

## Developer experience (v0.4)

Goal: an external developer completes a sandbox authorization integration in **under 30 minutes** without our help,
and we can **measure** it.

| | |
|---|---|
| **Quickstart** | [docs/developer/QUICKSTART.md](docs/developer/QUICKSTART.md): signup → settled sandbox payment → blocked attacks |
| **Integration Guide** | [docs/developer/INTEGRATION_GUIDE.md](docs/developer/INTEGRATION_GUIDE.md): trust boundaries, instruction sources (human/ERP), enforcement patterns, finality, errors, keys |
| **API reference** | [docs/developer/openapi.yaml](docs/developer/openapi.yaml) (OpenAPI 3.1; a test keeps it in sync with the running app) |
| **TypeScript SDK** | `packages/sdk-typescript`: agent / admin / sandbox clients; zero-dependency release tarball (`pnpm --filter @agenttrust/sdk pack:release`) |
| **Python SDK** | `packages/sdk-python` (`agenttrust`): same surface; stdlib HTTP + `cryptography`; byte-compatible signing via shared test vectors |
| **Hosted sandbox** | Self-service signup with admin/verifier/approver personas; portal at `/docs`, SDK downloads at `/downloads`; [Render blueprint](render.yaml) + [Dockerfile](Dockerfile); see [docs/HOSTED_SANDBOX.md](docs/HOSTED_SANDBOX.md) |
| **Measurement** | `GET /v1/sandbox/metrics` (operator): minutes from signup to first settled payment, per sandbox; [evaluation protocol](docs/developer/EVALUATION_PROTOCOL.md) |
| **Demo video** | `vhs demo/video/agenttrust-90s.tape` (≈ 77 s, six beats) + [voice-over script](demo/video/VOICEOVER.md) |
| **Examples** | [`examples/quickstart-typescript`](examples/quickstart-typescript/quickstart.ts), [`examples/quickstart-python`](examples/quickstart-python/quickstart.py), both run in CI |

## Quick start (run it locally)

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

`pnpm typecheck && pnpm test`: **59 unit + 126 integration tests** (real server + PostgreSQL). Suites: scenarios,
security, purchase instructions (adversarial), payments lifecycle, valid-session risk, supplier assurance, audit
anchoring (incl. a full-history-rewrite attack), cross-agent concurrency, self-service sandbox (incl. tenant
isolation), TypeScript SDK, OpenAPI drift, hosted-sandbox portal. Key controls were mutation-checked: breaking them
makes tests fail.

`pnpm build && pnpm test:live`: **13 Python SDK tests** (cross-language signing vectors + live) and both quickstart
examples against a real API process. CI runs all of it and builds the Docker image.

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
packages/sdk-typescript     Agent (sessions) / admin / sandbox / platform clients; standalone release bundle
packages/sdk-python         Python SDK (agenttrust)
examples/                   Runnable quickstarts (TypeScript, Python)
demo/video/                 90-second terminal demo (VHS tape) + voice-over
docs/developer/             Quickstart, Integration Guide, OpenAPI reference, evaluation protocol
docs/                       Architecture, threat model, security, API, database, branching, hosted sandbox, ADRs
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
