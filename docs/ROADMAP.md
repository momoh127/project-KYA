# Roadmap

## Done (MVP v0.1)

- Deterministic policy engine (payee, amount, approval, PO, invoice, budget, delegation)
- Agent identity via Ed25519 signed requests with replay protection
- Transaction-bound, single-use, signed authorizations
- Enforcing payment gateway with live re-checks and two-phase execution (sandbox adapter)
- Human approvals with re-evaluation; dual-control supplier bank changes
- Race-free budgets (row locks + reservations); duplicate-invoice protection
- Signed hash-chained audit with DB-enforced append-only + verifier
- Rogue-agent circuit breaker and revocation kill switch
- TypeScript SDK, 12-scenario demo, 75 automated tests

## Next

| Priority | Item | Why |
|---|---|---|
| P0 | OIDC human auth + MFA | Replace dev issuer |
| P0 | KMS-backed `Signer`, key rotation | Key custody |
| P0 | Dashboard (Next.js): overview, agents, approvals queue, suppliers, transactions, audit | Finance/compliance users |
| P1 | **MCP server** exposing `request_authorization` / `execute_payment` tools | Drop-in for agent frameworks |
| P1 | Real payment adapters: Stripe (incl. single-use Issuing cards), Modern Treasury | Enforcement on real rails |
| P1 | Bank-account ownership verification integration at onboarding | Close R4 |
| P1 | Webhooks (signed) for decisions and approvals | Integrations |
| P1 | RFC 9421 HTTP Message Signatures for agent requests | Interop with Web Bot Auth / card-network agent protocols |
| P2 | ERP sync (NetSuite, SAP, Coupa) for suppliers/POs/invoices | Real workflows |
| P2 | Postgres RLS, audit anchoring to S3 Object Lock | Defense in depth |
| P2 | KYA-manifest import (open-kya) for agent onboarding | Interoperability |
| P3 | Cross-customer fraud signals (with explicit data rights) | Network effects |

## Explicitly not building (yet)

Government ID scanning, proprietary KYC, blockchain identity, crypto wallets, payment processing / money
transmission, general AI security, universal agent reputation scores, proprietary models, ERP replacement,
autonomous AI fraud decisioning.
