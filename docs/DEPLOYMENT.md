# Deployment

## Local (supported today)

See the [README quick start](../README.md#quick-start). Two database options:

- `pnpm db:start`: project-local PostgreSQL cluster in `.local/pg`, port 54329 (needs Postgres binaries).
- `docker compose up -d`: PostgreSQL 16 on port 54329 with `agenttrust` and `agenttrust_test` databases.

Environment variables are documented in [`.env.example`](../.env.example). The API refuses to start with
missing or weak secrets, and refuses dev login when `NODE_ENV=production`.

## Production (not yet built; target design)

| Concern | Target |
|---|---|
| Compute | Containerized API on AWS ECS Fargate (or EKS) behind an ALB with TLS 1.2+ |
| Database | Amazon RDS PostgreSQL, Multi-AZ, encrypted, PITR backups; separate least-privilege roles for app vs migrations vs audit reader |
| Keys | AWS KMS asymmetric Ed25519/ECDSA key behind the `Signer` interface; pepper in Secrets Manager |
| Human identity | OIDC provider (Auth0/Okta/WorkOS/Clerk) with MFA; JWKS verification |
| Audit anchoring | Periodic chain-head export to S3 with Object Lock (compliance mode) |
| Rate limiting | Redis (ElastiCache) per credential / org |
| Async work | SQS for webhooks, reconciliation of `pending` transactions, nonce cleanup |
| Observability | OpenTelemetry traces/metrics/logs; alerts on circuit-breaker trips and gateway rejections |
| IaC | Terraform under `infrastructure/terraform` |

A production launch also requires legal, security (independent pen test), privacy and contractual review.
