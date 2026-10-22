"""Envelope encryption for stored provider keys. The implementation lives in agentpg-kit; this module keeps the old function API
(`vault.encrypt(...)`) bound to this app's single vault."""
from apgkit.vault import VaultError, VaultLocked  # noqa: F401

from .core import vault as _v

is_initialized = _v.is_initialized
is_unlocked = _v.is_unlocked
lock = _v.lock
status = _v.status
initialize = _v.initialize
unlock_with_password = _v.unlock_with_password
try_unlock_with_platform_secret = _v.try_unlock_with_platform_secret
change_password = _v.change_password
reset = _v.reset
encrypt = _v.encrypt
decrypt = _v.decrypt
