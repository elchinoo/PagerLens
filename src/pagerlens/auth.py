"""Credentials. The implementation lives in agentpg-kit (`apgkit.auth`); this module keeps the old function names for the few
callers that still use them (setup, password change, sessions) and exposes this app's pieces from `core`."""
from apgkit.ids import sha256  # noqa: F401

from . import core

local = core.local


def admin_configured(conn) -> bool:
    return local.admin_configured(conn)


def static_key_configured() -> bool:
    return local.static_key_configured()


def needs_setup(conn) -> bool:
    return local.needs_setup(conn)


def setup_code() -> str:
    return local.setup_code()


def complete_setup(conn, code: str, password: str) -> None:
    local.complete_setup(conn, code, password)


def set_admin_password(conn, password: str) -> None:
    local.set_admin_password(conn, password)


def login_password(conn, password: str) -> bool:
    return local.login_password(conn, password)


def change_password(conn, current: str, new: str) -> None:
    local.change_password(conn, current, new)


def reset_admin(conn) -> None:
    local.reset_admin(conn)
