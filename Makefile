.PHONY: up down migrate seed test test-db serve lint
up:        ; docker compose up -d db
down:      ; docker compose down
migrate:   ; .venv/bin/pagerlens migrate
seed:      ; .venv/bin/pagerlens seed
serve:     ; .venv/bin/pagerlens serve
lint:      ; .venv/bin/ruff check src tests
test:      ; .venv/bin/pytest -q
# Needs POSTGRES_PASSWORD exported (set -a; . ./.env; set +a). Uses a throwaway database named pagerlens_test on the compose Postgres (dropped and recreated).
test-db:   ; docker compose exec -T db psql -U pagerlens -c "DROP DATABASE IF EXISTS pagerlens_test" -c "CREATE DATABASE pagerlens_test" && \
	TEST_DATABASE_URL=postgresql://pagerlens:$$POSTGRES_PASSWORD@127.0.0.1:5433/pagerlens_test .venv/bin/pytest -q
