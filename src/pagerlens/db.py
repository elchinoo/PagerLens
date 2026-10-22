"""Connections. The implementation (retries for a database that is scaled to zero, the pgvector adapter) lives in agentpg-kit."""
import psycopg

from .core import db as _db


def connect(retries: int = 5, delay: float = 1.0) -> psycopg.Connection:
    return _db.connect(retries, delay)


def connect_vector() -> psycopg.Connection:
    """Connection with the pgvector adapters; requires the extension to exist (run migrations first)."""
    return _db.connect()
