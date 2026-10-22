"""Tiny plain-SQL migration runner (just Postgres: no ORM, no proprietary tooling)."""
from pathlib import Path

from .config import get_settings

MIGRATIONS = Path(__file__).resolve().parent / "migrations"


def run() -> list[str]:
    """Apply the SQL migrations. The shared tables (settings, sessions, API tokens, OIDC state) come from the kit."""
    from apgkit import migrate as kit_migrate
    from apgkit.auth.schema import SQL as AUTH_SQL

    from .core import db

    applied = kit_migrate.run(db, MIGRATIONS, extensions=("vector",), replacements={"{{EMBEDDING_DIM}}": str(get_settings().embedding_dim)})
    with db.connect() as conn:      # after the app's own migrations: it upgrades tables they created (sessions) and adds the OIDC state
        conn.execute(AUTH_SQL)
        conn.commit()
    return applied
