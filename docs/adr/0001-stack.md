# ADR-0001: Stack and repository structure

- **Status:** Accepted
- **Date:** 2026-10-22

## Context

AgentTrust is financial authorization infrastructure built by a very small team. We need strong typing for
money and security logic, a single language across API/SDK/demo, real transactional guarantees, and fast tests.

## Decision

- **TypeScript (strict) monorepo with pnpm workspaces.** Pure logic (policy engine, crypto, audit) lives in
  small framework-free packages with unit tests; the API composes them.
- **NestJS** for the API: structured modules, guards and DI suited to an enterprise API.
- **PostgreSQL + Prisma.** PostgreSQL provides row locks, partial unique indexes, CHECK constraints and
  triggers, all of which we use for correctness. Prisma gives typed queries; locking uses raw SQL.
- **Vitest** for unit and integration tests; integration tests run a real server against a real database.
- **Deferred:** Redis, SQS, S3, KMS and Terraform are behind interfaces or documented targets until needed.

## Consequences

- Budget correctness depends on PostgreSQL (by design; no eventually consistent caches in the money path).
- NestJS needs decorator metadata, so API tests compile via SWC.
