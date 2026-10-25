# Hosted sandbox (Render)

A public evaluation sandbox: the API with self-service signup, the developer portal at `/docs`, and SDK downloads at
`/downloads`. **Sandbox only:** simulated payment provider, development persona logins, no real money.

## What gets deployed

| Piece | Source |
|---|---|
| Container | [`Dockerfile`](../Dockerfile): builds the monorepo, generates Prisma for Linux, builds the TS SDK tarball and Python wheel/sdist |
| Entrypoint | [`scripts/docker-entrypoint.sh`](../scripts/docker-entrypoint.sh): `prisma migrate deploy`, then start |
| Infrastructure | [`render.yaml`](../render.yaml): one web service (Docker, `starter`) and one Postgres (`basic-256mb`), deploying from **`main`** |

Deploying from `main` means the sandbox only ever runs **released, tested** code (release branch → PR → tag).

## One-time setup (≈ 15 minutes, needs your Render account)

1. Render dashboard → **New → Blueprint** → connect GitHub → choose `momoh127/project-KYA`. Render reads
   `render.yaml`. Grant access to the private repo when asked.
2. Approve the plan: web `starter` plus Postgres `basic-256mb`. Render shows the current prices before you confirm.
   The free web plan sleeps and adds a ~1 minute cold start, which spoils a timed evaluation. Free Postgres expires
   after 30 days.
3. Render generates the secrets marked `generateValue` (signing seed, pepper, bootstrap token, dev-auth secret,
   webhook secret). **Don't** copy them anywhere else. The bootstrap token is the operator credential for
   `/v1/sandbox/metrics`. Read it from the dashboard when you need it.
4. After the first deploy, set `AGENTTRUST_PUBLIC_URL` to the service URL (e.g. `https://agenttrust-sandbox.onrender.com`)
   or your custom domain, then redeploy. The docs use it in install commands and the OpenAPI `servers` entry.
5. Check it:
   ```bash
   curl -s $URL/v1/health                       # {"status":"ok"}
   open $URL/docs                               # portal, SDK links
   AGENTTRUST_BASE_URL=$URL npx tsx examples/quickstart-typescript/quickstart.ts
   ```

## Operating it

- **Measure time-to-integration:**
  `curl -s -H "x-agenttrust-bootstrap-token: $TOKEN" $URL/v1/sandbox/metrics`
  (see [EVALUATION_PROTOCOL.md](developer/EVALUATION_PROTOCOL.md)).
- **Abuse limits:** 20 signups per client IP per hour (`AGENTTRUST_TRUST_PROXY=1` makes that the real client IP
  behind Render's proxy), 100 sandboxes per 24 hours platform-wide, and sandboxes expire after 30 days.
- **Rotating secrets:** changing `AGENTTRUST_SIGNING_KEY_SEED` changes the platform signing key. Existing audit
  signatures then verify only against the old key, so treat it as a reset. Changing the pepper makes stored payee
  fingerprints unmatchable (suppliers would need re-entry). Both are fine for a sandbox and both are reasons
  production uses a KMS.
- **Anchors:** audit anchors go to the container's local disk, which Render doesn't persist across deploys. That's
  acceptable for the sandbox; the production design is S3 Object Lock (not implemented).

## What this is not

Not production: there's no identity provider (persona logins are development tokens), no real payment adapter, no
KMS, no persistent immutable audit storage, and no independent security test. `NODE_ENV=sandbox` keeps the
production guards that refuse development login and signup when `NODE_ENV=production`.
