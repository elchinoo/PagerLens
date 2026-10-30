import os
from dataclasses import dataclass

from apgkit.config import read_secret


@dataclass(frozen=True)
class Settings:
    database_url: str
    api_key: str
    llm_base_url: str
    llm_api_key: str
    embedding_model: str
    llm_chat_model: str
    embedding_dim: int
    allow_anonymous: bool
    send_dimensions: bool


def bind_host() -> str:
    """The address the server binds to: PAGERLENS_HOST, else HOST, else all interfaces (public, as far as the kit is concerned)."""
    return os.environ.get("PAGERLENS_HOST") or os.environ.get("HOST") or "0.0.0.0"  # noqa: S104 - a default, not a bind in this module


def _api_key() -> str:
    return read_secret("PAGERLENS_API_KEY", "/etc/pagerlens/api_key")


def get_settings() -> Settings:
    return Settings(
        # First match wins. An empty DSN makes libpq fall back to the standard PG* variables
        # (PGHOST, PGUSER, PGPASSWORD, PGDATABASE...), which linked sandboxes also provide.
        database_url=os.environ.get("DATABASE_URL")
        or os.environ.get("DB_EXTERNAL_DSN")
        or os.environ.get("PSQL_CONNECTION_STRING")
        or "",
        api_key=_api_key(),
        llm_base_url=os.environ.get("LLM_BASE_URL", "").rstrip("/"),
        llm_api_key=read_secret("LLM_API_KEY", "/etc/pagerlens/llm_api_key"),
        embedding_model=os.environ.get("EMBEDDING_MODEL", "text-embedding-3-small"),
        llm_chat_model=os.environ.get("LLM_CHAT_MODEL", ""),
        embedding_dim=int(os.environ.get("EMBEDDING_DIM", "768")),
        allow_anonymous=os.environ.get("PAGERLENS_ALLOW_ANONYMOUS", "").lower() in {"1", "true", "yes"},
        # Some providers reject an unknown `dimensions` field; set EMBEDDING_SEND_DIMENSIONS=false for them.
        send_dimensions=os.environ.get("EMBEDDING_SEND_DIMENSIONS", "true").lower() not in {"0", "false", "no"},
    )
