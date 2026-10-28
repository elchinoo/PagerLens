#!/usr/bin/env bash
# Throwaway local stack for recording (docs/VIDEO-SCRIPT.md section 1): a private Postgres cluster with pgvector (fresh every
# start), the DEMO STAND-IN model (scripts/fake_llm.py), `pagerlens migrate`, `seed` and `serve`. Loopback only, no Docker.
#
#   WORK=<dir> BASE_PORT=41400 docs/video/stack.sh start|stop
#
# Needs a Postgres install with the vector and pg_trgm extensions (initdb/pg_ctl/psql on PATH or in PG_BIN) and the project's
# .venv (pip install -e ".[dev]"). State (pids, ports, logs) lives under $WORK/stack. Only PIDs this script started are killed.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
PL="$(cd "$HERE/../.." && pwd)"
WORK="${WORK:-$HERE/out/work}"
BASE_PORT="${BASE_PORT:-41400}"
PG_PORT=$((BASE_PORT + 1)); LLM_PORT=$((BASE_PORT + 2)); APP_PORT=$((BASE_PORT + 3))
S="$WORK/stack"
if [ -n "${PG_BIN:-}" ]; then PATH="$PG_BIN:$PATH"; fi
export PATH
mkdir -p "$S"

case "${1:-}" in
start)
  "$0" stop >/dev/null 2>&1 || true
  command -v initdb >/dev/null || { echo "initdb not found: set PG_BIN to a Postgres bin directory"; exit 1; }
  rm -rf "$S/pgdata"; mkdir -p "$S/pgdata"
  initdb -D "$S/pgdata" -U postgres --auth=trust -E UTF8 >"$S/initdb.log" 2>&1
  pg_ctl -D "$S/pgdata" -l "$S/pg.log" -w -o "-p $PG_PORT -c listen_addresses=127.0.0.1 -c unix_socket_directories='' -c shared_preload_libraries=pg_stat_statements" start >/dev/null
  psql -h 127.0.0.1 -p "$PG_PORT" -U postgres -d postgres -q -c "CREATE DATABASE pagerlens ENCODING 'UTF8' TEMPLATE template0"
  psql -h 127.0.0.1 -p "$PG_PORT" -U postgres -d pagerlens -q -c "CREATE EXTENSION vector" -c "CREATE EXTENSION pg_trgm" -c "CREATE EXTENSION pg_stat_statements"
  # Local stand-in for what AgentPG provides: the group role a1p_readonly (SELECT on every new table by default) and a login user
  # in it, which is what `agentpg db-users create --permission read` makes. `pagerlens migrate` then hardens it (hardening.py).
  psql -h 127.0.0.1 -p "$PG_PORT" -U postgres -d pagerlens -q -c "CREATE ROLE a1p_readonly NOLOGIN" \
    -c "CREATE ROLE pl_reader LOGIN IN ROLE a1p_readonly" -c "GRANT USAGE ON SCHEMA public TO a1p_readonly" \
    -c "ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public GRANT SELECT ON TABLES TO a1p_readonly"
  nohup "$PL/.venv/bin/python" "$PL/scripts/fake_llm.py" --port "$LLM_PORT" >"$S/fake-llm.log" 2>&1 &
  echo $! >"$S/llm.pid"
  E=(env -i PATH=/usr/bin:/bin HOME="$S" TMPDIR="$S" LANG=en_US.UTF-8 PYTHONUNBUFFERED=1 HOST=127.0.0.1 PORT="$APP_PORT"
     DATABASE_URL="postgresql://postgres@127.0.0.1:$PG_PORT/pagerlens"
     LLM_BASE_URL="http://127.0.0.1:$LLM_PORT/v1" LLM_API_KEY=demo LLM_CHAT_MODEL=demo-chat EMBEDDING_MODEL=demo-embed)
  "${E[@]}" "$PL/.venv/bin/pagerlens" migrate >"$S/migrate.log" 2>&1
  "${E[@]}" "$PL/.venv/bin/pagerlens" seed >"$S/seed.log" 2>&1
  nohup "${E[@]}" "$PL/.venv/bin/pagerlens" serve >"$S/app.log" 2>&1 &
  echo $! >"$S/app.pid"
  for _ in $(seq 60); do curl -sf "http://127.0.0.1:$APP_PORT/readyz" >/dev/null && break; sleep 0.5; done
  curl -sf "http://127.0.0.1:$APP_PORT/readyz" >/dev/null || { echo "app did not become ready; see $S/app.log"; exit 1; }
  echo "http://127.0.0.1:$APP_PORT"
  ;;
stop)
  for n in app llm; do
    if [ -f "$S/$n.pid" ]; then kill "$(cat "$S/$n.pid")" 2>/dev/null || true; rm -f "$S/$n.pid"; fi
  done
  if [ -d "$S/pgdata" ]; then pg_ctl -D "$S/pgdata" -m fast stop >/dev/null 2>&1 || true; fi
  ;;
*) echo "usage: $0 start|stop" >&2; exit 2;;
esac
