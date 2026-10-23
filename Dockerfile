# AgentTrust hosted sandbox image (API + developer portal + SDK downloads).
# Sandbox only: the payment adapter is the simulated provider; no real money moves.
FROM node:20-bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl ca-certificates python3 python3-venv \
 && rm -rf /var/lib/apt/lists/*
RUN corepack enable

WORKDIR /app
COPY . .

# Install, build (includes `prisma generate` for this platform), then build the
# downloadable SDK artifacts served at /downloads.
RUN pnpm install --frozen-lockfile \
 && pnpm build \
 && pnpm --filter @agenttrust/sdk run pack:release \
 && python3 -m venv /tmp/pybuild \
 && /tmp/pybuild/bin/pip install --no-cache-dir "build>=1.2" "hatchling>=1.25" \
 && cd packages/sdk-python && /tmp/pybuild/bin/python -m build --no-isolation --outdir /app/dist-sdk . \
 && rm -rf /tmp/pybuild /root/.cache /root/.local/share/pnpm/store

ENV NODE_ENV=sandbox \
    AGENTTRUST_PUBLIC_DOCS=true \
    AGENTTRUST_DOCS_DIR=/app/docs/developer \
    AGENTTRUST_DOWNLOADS_DIR=/app/dist-sdk \
    AGENTTRUST_ANCHOR_DIR=/app/apps/api/.local/anchors

# Local write-once anchor storage is ephemeral in a container (sandbox stand-in for S3 Object Lock).
RUN mkdir -p /app/apps/api/.local/anchors && chown -R node:node /app/apps/api/.local
USER node
EXPOSE 4000
CMD ["sh", "/app/scripts/docker-entrypoint.sh"]
