"""Tiny plain-SQL migration runner (just Postgres: no ORM, no proprietary tooling)."""
from pathlib import Path

from .config import get_settings
from .db import connect

MIGRATIONS = Path(__file__).resolve().parent / "migrations"


def run() -> list[str]:
    dim = get_settings().embedding_dim
    applied: list[str] = []
    with connect() as conn:
        conn.execute("CREATE EXTENSION IF NOT EXISTS vector")
        conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations (name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())"
        )
        done = {r["name"] for r in conn.execute("SELECT name FROM schema_migrations")}
        for path in sorted(MIGRATIONS.glob("*.sql")):
            if path.name in done:
                continue
            sql = path.read_text().replace("{{EMBEDDING_DIM}}", str(dim))
            conn.execute(sql)
            conn.execute("INSERT INTO schema_migrations (name) VALUES (%s)", (path.name,))
            applied.append(path.name)
        conn.commit()
    return applied
