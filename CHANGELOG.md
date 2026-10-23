# Changelog

All notable changes. Versions follow the tags on `main`. Sandbox software: no release here is production-ready,
compliant, or independently audited.

## [Unreleased] — v0.4 Developer Experience

Goal: an external developer completes a sandbox authorization integration in under 30 minutes without our help.

### Changed
- Repository governance: server-side GitHub rulesets for `main` and `develop` versioned in `.github/rulesets/`, with
  `scripts/apply-rulesets.sh`. Not yet enforced (private repo on GitHub Free; deferred by decision). The local
  pre-push hook now blocks direct pushes to `develop` as well as `main`; changes land through pull requests.

## [0.3.0] — 2026-10-22

Purchase-intent verification: an agent's payment must match an independently approved business instruction.

- Purchase instructions (human-created or ERP-synced), agent assignment, line-item matching, invoice required by
  default, expiry, usage limits, configurable three-way matching (receipt / service completion / alternative approval).
- Payment lifecycle: accepted, processing, settled, failed, returned, reversed, unknown; only `settled` pays an
  invoice; webhook de-duplication; reconciliation.
- Deterministic valid-session abuse checks (velocity, budget consumption, supplier frequency, recently changed payee).
- Supplier assurance levels and an account-verification provider interface.
- External audit anchoring: signed batches, Merkle roots, write-once storage adapter, independent verifier.
- Concurrency: shared purchase-order capacity is never overspent by racing agents.
- Process note: M1–M4 were committed directly to `main` before the branching policy existed (see `docs/BRANCHING.md`).

## [0.2.0]

Hardened authorization gateway: workload credentials and short-lived sessions, request signing, binding of
authorizations to the full payment instruction, supplier dual control, idempotent execution, audit hash chain.
