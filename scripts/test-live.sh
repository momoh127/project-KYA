#!/usr/bin/env bash
# Live checks against a real API process on the TEST database: the Python SDK
# suite (offline signing vectors + live tests), then both quickstart examples.
# Needs Postgres, `pnpm build`, and Python with `cryptography` + `pytest`.
#
#   PYTHON=python3 scripts/test-live.sh
set -euo pipefail
cd "$(dirname "$0")/.."

PY="${PYTHON:-.local/pyenv/bin/python}"
# Make a relative interpreter path absolute (we cd into the package later).
if [[ "$PY" == */* && "$PY" != /* ]]; then PY="$PWD/$PY"; fi
PORT="${AGENTTRUST_PY_TEST_PORT:-4555}"

set -a
# shellcheck disable=SC1091
. ./.env
set +a
if [[ "${TEST_DATABASE_URL:-}" != *agenttrust_test* ]]; then
  echo "Refusing to run: TEST_DATABASE_URL must point at the agenttrust_test database" >&2
  exit 1
fi
export DATABASE_URL="$TEST_DATABASE_URL" PORT NODE_ENV=test \
  AGENTTRUST_RECONCILE_INTERVAL_MS=0 AGENTTRUST_ANCHOR_INTERVAL_MS=0 \
  AGENTTRUST_ANCHOR_DIR=.local/anchors-pytest AGENTTRUST_SANDBOX_SIGNUP=true

mkdir -p .local
node apps/api/dist/main.js > .local/pytest-api.log 2>&1 &
API_PID=$!
trap 'kill "$API_PID" 2>/dev/null || true' EXIT

for _ in $(seq 1 100); do
  if curl -sf "http://127.0.0.1:$PORT/v1/health" >/dev/null; then break; fi
  sleep 0.1
done
curl -sf "http://127.0.0.1:$PORT/v1/health" >/dev/null || { echo "API did not start:"; cat .local/pytest-api.log; exit 1; }

cd packages/sdk-python
AGENTTRUST_BASE_URL="http://127.0.0.1:$PORT" "$PY" -m pytest -q "$@"
cd ../..

# The quickstarts are documentation: they must actually run.
echo "--- examples/quickstart-python"
AGENTTRUST_BASE_URL="http://127.0.0.1:$PORT" PYTHONPATH=packages/sdk-python/src "$PY" examples/quickstart-python/quickstart.py
echo "--- examples/quickstart-typescript"
AGENTTRUST_BASE_URL="http://127.0.0.1:$PORT" pnpm --silent --filter @agenttrust/example-quickstart start
