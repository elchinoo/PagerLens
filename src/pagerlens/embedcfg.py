"""Which embedding provider is active: a stored account (chosen in the UI) or the environment.

The key is decrypted only at the moment of use, so a locked vault (after a restart) does not break startup;
it just means external embeddings are unavailable until the admin signs in.
"""
from dataclasses import dataclass

from . import settings_store as store
from . import vault
from .config import get_settings

SETTING = "embedding_account_id"


@dataclass(frozen=True)
class EmbeddingConfig:
    base_url: str            # empty => the offline demo embedder
    model: str
    dim: int
    send_dimensions: bool
    trusted: bool            # True only for operator-set environment config (skips the URL guard)
    account_id: int | None   # None => environment
    key_plain: str = ""
    key_enc: str | None = None

    @property
    def semantic(self) -> bool:
        return bool(self.base_url)

    @property
    def label(self) -> str:
        return self.model if self.base_url else "builtin-hash"

    def api_key(self) -> str:
        return vault.decrypt(self.key_enc) if self.key_enc else self.key_plain


def from_env() -> EmbeddingConfig:
    s = get_settings()
    return EmbeddingConfig(base_url=s.llm_base_url, model=s.embedding_model, dim=s.embedding_dim,
                           send_dimensions=s.send_dimensions, trusted=True, account_id=None, key_plain=s.llm_api_key)


_active: EmbeddingConfig | None = None
_loaded = False


def current() -> EmbeddingConfig:
    return _active or from_env()


def set_active(cfg: EmbeddingConfig | None) -> None:
    global _active, _loaded
    _active, _loaded = cfg, True


def reset() -> None:
    """Forget the cached choice (used by tests and after a database reset)."""
    global _active, _loaded
    _active, _loaded = None, False


def ensure_loaded(conn) -> None:
    """Load the stored choice once per process. Tolerates a database that has not been migrated yet."""
    global _loaded
    if _loaded:
        return
    from .accounts import embedding_config_for  # local import: accounts imports this module

    try:
        pointer = store.get(conn, SETTING)
        cfg = embedding_config_for(conn, int(pointer)) if pointer else None
    except Exception:  # noqa: BLE001 - missing tables on a fresh database, or a deleted account
        conn.rollback()
        cfg = None
    set_active(cfg)
