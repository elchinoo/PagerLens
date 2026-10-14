"""Envelope encryption for provider API keys stored in the database.

A random 32-byte *data key* encrypts every stored provider key (Fernet: AES-128-CBC + HMAC-SHA256). The data key
is never stored in the clear. It is stored *wrapped* (encrypted) under:

  * a key derived from the admin password with scrypt, and optionally
  * a key derived from a platform-managed secret (PAGERLENS_ENCRYPTION_KEY or /etc/pagerlens/encryption_key).

Consequences, by design:
  * The database alone is useless to an attacker: it holds only ciphertext and wrapped keys.
  * After a restart the vault is LOCKED until the admin signs in, unless a platform secret is configured,
    in which case it unlocks itself at startup.
  * The unwrapped data key lives only in this process's memory.
"""
import base64
import hashlib
import secrets
import threading

from cryptography.fernet import Fernet, InvalidToken

from . import settings_store as store
from .config import read_secret

_K_SALT, _K_PW, _K_ENV_SALT, _K_ENV = "vault_salt", "vault_wrap_pw", "vault_env_salt", "vault_wrap_env"
_lock = threading.Lock()
_data_key: bytes | None = None


class VaultError(RuntimeError):
    """A failure whose message is safe to show to users."""


class VaultLocked(VaultError):
    pass


def _kdf(secret: str, salt: bytes) -> Fernet:
    raw = hashlib.scrypt(secret.encode(), salt=salt, n=2**15, r=8, p=1, maxmem=128 * 1024 * 1024, dklen=32)
    return Fernet(base64.urlsafe_b64encode(raw))


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _env_secret() -> str:
    return read_secret("PAGERLENS_ENCRYPTION_KEY", "/etc/pagerlens/encryption_key")


def _wrap(conn, secret: str, salt_key: str, wrap_key: str, data_key: bytes) -> None:
    salt = secrets.token_bytes(16)
    store.put(conn, salt_key, _b64(salt))
    store.put(conn, wrap_key, _kdf(secret, salt).encrypt(data_key).decode())


def _unwrap(conn, secret: str, salt_key: str, wrap_key: str) -> bytes | None:
    salt, wrapped = store.get(conn, salt_key), store.get(conn, wrap_key)
    if not salt or not wrapped:
        return None
    try:
        return _kdf(secret, base64.b64decode(salt)).decrypt(wrapped.encode())
    except InvalidToken:
        return None


def is_initialized(conn) -> bool:
    return store.get(conn, _K_PW) is not None


def is_unlocked() -> bool:
    return _data_key is not None


def lock() -> None:
    global _data_key
    with _lock:
        _data_key = None


def status(conn) -> dict:
    return {
        "initialized": is_initialized(conn),
        "unlocked": is_unlocked(),
        "auto_unlock": bool(_env_secret()) and store.get(conn, _K_ENV) is not None,
    }


def initialize(conn, password: str) -> None:
    """Create the data key, wrapped under the password (and the platform secret, if configured). Unlocks."""
    global _data_key
    data_key = secrets.token_bytes(32)
    _wrap(conn, password, _K_SALT, _K_PW, data_key)
    env = _env_secret()
    if env:
        _wrap(conn, env, _K_ENV_SALT, _K_ENV, data_key)
    with _lock:
        _data_key = data_key


def unlock_with_password(conn, password: str) -> bool:
    global _data_key
    key = _unwrap(conn, password, _K_SALT, _K_PW)
    if key is None:
        return False
    with _lock:
        _data_key = key
    env = _env_secret()
    if env and store.get(conn, _K_ENV) is None:  # a platform secret was added later: wrap for auto-unlock
        _wrap(conn, env, _K_ENV_SALT, _K_ENV, key)
    return True


def try_unlock_with_platform_secret(conn) -> bool:
    global _data_key
    env = _env_secret()
    if not env:
        return False
    key = _unwrap(conn, env, _K_ENV_SALT, _K_ENV)
    if key is None:
        return False
    with _lock:
        _data_key = key
    return True


def change_password(conn, new_password: str) -> None:
    """Re-wrap the data key under a new password. Requires the vault to be unlocked."""
    if _data_key is None:
        raise VaultLocked("unlock the vault first")
    _wrap(conn, new_password, _K_SALT, _K_PW, _data_key)


def reset(conn) -> None:
    """Forget the data key and all wraps. Anything encrypted with it becomes unreadable (callers must delete it)."""
    lock()
    store.delete(conn, _K_SALT, _K_PW, _K_ENV_SALT, _K_ENV)


def _fernet() -> Fernet:
    if _data_key is None:
        raise VaultLocked("Provider keys are locked. Sign in with your admin password to unlock them.")
    return Fernet(base64.urlsafe_b64encode(_data_key))


def encrypt(plaintext: str) -> str:
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt(token: str) -> str:
    try:
        return _fernet().decrypt(token.encode()).decode()
    except InvalidToken as exc:
        raise VaultError("A stored provider key could not be decrypted. Re-enter the key.") from exc
