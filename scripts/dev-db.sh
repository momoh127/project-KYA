#!/usr/bin/env bash
# Project-local PostgreSQL for development. Data lives in .local/pg (gitignored).
# Uses port 54329 so it never collides with a system Postgres.
# Alternative: `docker compose up -d postgres` (see docker-compose.yml).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DATA="$ROOT/.local/pg"
PORT="${AGENTTRUST_PG_PORT:-54329}"
LOG="$ROOT/.local/pg.log"

case "${1:-start}" in
  start)
    mkdir -p "$ROOT/.local"
    if [ ! -f "$DATA/PG_VERSION" ]; then
      echo "Initializing local Postgres cluster in $DATA"
      initdb -D "$DATA" -U agenttrust --auth=trust --encoding=UTF8 >/dev/null
    fi
    if pg_ctl -D "$DATA" status >/dev/null 2>&1; then
      echo "Postgres already running on port $PORT"
    else
      pg_ctl -D "$DATA" -l "$LOG" -o "-p $PORT -k /tmp -c listen_addresses=localhost" -w start >/dev/null
      echo "Postgres started on port $PORT"
    fi
    for db in agenttrust agenttrust_test; do
      psql -h localhost -p "$PORT" -U agenttrust -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='$db'" | grep -q 1 \
        || createdb -h localhost -p "$PORT" -U agenttrust "$db"
    done
    ;;
  stop)
    pg_ctl -D "$DATA" -w stop >/dev/null && echo "Postgres stopped"
    ;;
  *)
    echo "usage: $0 start|stop" >&2
    exit 1
    ;;
esac
