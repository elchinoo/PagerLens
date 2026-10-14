"""Credentials: admin password, web sessions and API tokens. Only hashes are ever stored.

* First run: a one-time *setup code* is printed to the server log (readable only by whoever operates the
  server). Presenting it in the browser lets the first person set the admin password.
* Browser: password login creates a server-side session; the browser holds an HttpOnly cookie.
* Clients (REST, MCP): API tokens created in the UI, shown once, revocable, `read` or `full` scope.
* Optional static key: PAGERLENS_API_KEY (env or file) still works as a full-access credential for automation.
"""
import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from . import passwords, vault
from . import settings_store as store
from .config import get_settings

SESSION_HOURS = 12
TOKEN_PREFIX = "pl_"
_K_ADMIN = "admin_password_hash"
_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no look-alike characters  # pragma: allowlist secret
_setup_code: str | None = None


@dataclass(frozen=True)
class Principal:
    kind: str   # "session" | "token" | "static" | "anonymous"
    scope: str  # "full" | "read"
    ident: int | None = None


def sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


# ---- setup ------------------------------------------------------------------------------------
def setup_code() -> str:
    """The in-memory one-time code. It changes on every process start while setup is pending."""
    global _setup_code
    if _setup_code is None:
        raw = "".join(secrets.choice(_ALPHABET) for _ in range(12))
        _setup_code = f"{raw[:4]}-{raw[4:8]}-{raw[8:]}"
    return _setup_code


def admin_configured(conn) -> bool:
    return store.get(conn, _K_ADMIN) is not None


def static_key_configured() -> bool:
    return bool(get_settings().api_key)


def needs_setup(conn) -> bool:
    return not admin_configured(conn) and not static_key_configured()


def complete_setup(conn, code: str, password: str) -> None:
    global _setup_code
    if admin_configured(conn):
        raise PermissionError("setup is already complete")
    if not hmac.compare_digest(code.strip().upper().encode(), setup_code().encode()):
        raise PermissionError("invalid setup code")
    set_admin_password(conn, password)
    _setup_code = None


def set_admin_password(conn, password: str) -> None:
    """Create or replace the admin password (hash) and make sure the vault is initialised and unlocked."""
    passwords.check_strength(password)
    store.put(conn, _K_ADMIN, passwords.hash_password(password))
    if vault.is_initialized(conn):
        vault.change_password(conn, password)
    else:
        vault.initialize(conn, password)
    conn.commit()


def login_password(conn, password: str) -> bool:
    stored = store.get(conn, _K_ADMIN)
    if stored is None or not passwords.verify_password(password, stored):
        return False
    vault.unlock_with_password(conn, password)
    conn.commit()
    return True


def change_password(conn, current: str, new: str) -> None:
    stored = store.get(conn, _K_ADMIN)
    if stored is None or not passwords.verify_password(current, stored):
        raise PermissionError("current password is incorrect")
    if not vault.is_unlocked():
        vault.unlock_with_password(conn, current)
    set_admin_password(conn, new)


def reset_admin(conn) -> None:
    """Operator recovery: forget the admin password, vault and every stored provider key."""
    store.delete(conn, _K_ADMIN)
    vault.reset(conn)
    conn.execute("UPDATE llm_account SET api_key_enc = NULL, api_key_last4 = NULL")
    conn.execute("DELETE FROM web_session")
    conn.commit()


# ---- sessions ---------------------------------------------------------------------------------
def create_session(conn) -> str:
    raw = secrets.token_urlsafe(32)
    now = datetime.now(UTC)
    conn.execute("DELETE FROM web_session WHERE expires_at < %s", (now,))
    conn.execute("INSERT INTO web_session (token_hash, expires_at) VALUES (%s, %s)",
                 (sha256(raw), now + timedelta(hours=SESSION_HOURS)))
    conn.commit()
    return raw


def session_valid(conn, raw: str | None) -> bool:
    if not raw:
        return False
    row = conn.execute("SELECT 1 FROM web_session WHERE token_hash=%s AND expires_at > now()",
                       (sha256(raw),)).fetchone()
    return row is not None


def delete_session(conn, raw: str | None) -> None:
    if raw:
        conn.execute("DELETE FROM web_session WHERE token_hash=%s", (sha256(raw),))
        conn.commit()


# ---- API tokens -------------------------------------------------------------------------------
def create_token(conn, name: str, scope: str) -> tuple[int, str]:
    if scope not in {"read", "ingest", "full"}:
        raise ValueError("scope must be 'read', 'ingest' or 'full'")
    raw = TOKEN_PREFIX + secrets.token_urlsafe(32)
    row = conn.execute(
        "INSERT INTO api_token (name, token_hash, prefix, scope) VALUES (%s,%s,%s,%s) RETURNING id",
        (name, sha256(raw), raw[:8], scope),
    ).fetchone()
    conn.commit()
    return row["id"], raw


def list_tokens(conn) -> list[dict]:
    return conn.execute(
        "SELECT id, name, prefix, scope, created_at, last_used_at, revoked_at FROM api_token ORDER BY id DESC"
    ).fetchall()


def revoke_token(conn, token_id: int) -> bool:
    row = conn.execute("UPDATE api_token SET revoked_at = now() WHERE id=%s AND revoked_at IS NULL RETURNING id",
                       (token_id,)).fetchone()
    conn.commit()
    return row is not None


def token_principal(conn, raw: str) -> Principal | None:
    if not raw.startswith(TOKEN_PREFIX):
        return None
    row = conn.execute(
        "UPDATE api_token SET last_used_at = now() WHERE token_hash=%s AND revoked_at IS NULL RETURNING id, scope",
        (sha256(raw),),
    ).fetchone()
    conn.commit()
    return Principal("token", row["scope"], row["id"]) if row else None


def static_key_matches(raw: str) -> bool:
    key = get_settings().api_key
    return bool(key) and hmac.compare_digest(raw.encode(), key.encode())
