"""Provider accounts (OpenAI-compatible endpoints). Keys are encrypted at rest and never returned."""
from dataclasses import dataclass

from . import embedcfg, vault
from . import settings_store as store
from .config import get_settings
from .netguard import check_url

DEFAULT_DIM = 768

# Starting points for the UI. Model names change often: they are hints, not defaults we promise.
PRESETS = [
    {"id": "openai", "name": "OpenAI", "base_url": "https://api.openai.com/v1",
     "chat_model": "", "embedding_model": "text-embedding-3-small", "embedding_dim": 768,
     "note": "Embeddings support a custom output size, so 768 works."},
    {"id": "openrouter", "name": "OpenRouter", "base_url": "https://openrouter.ai/api/v1",
     "chat_model": "", "embedding_model": "openai/text-embedding-3-small", "embedding_dim": 768,
     "note": "One key for many models. Chat models are named like openai/gpt-4o-mini; see openrouter.ai/models."},
    {"id": "glm", "name": "GLM (Zhipu)", "base_url": "https://open.bigmodel.cn/api/paas/v4",
     "chat_model": "", "embedding_model": "embedding-3", "embedding_dim": 1024,
     "note": "Note the /v4 path. embedding-3 accepts a custom size. Check the provider docs for chat model names."},
    {"id": "kimi", "name": "Kimi (Moonshot)", "base_url": "https://api.moonshot.ai/v1",
     "chat_model": "", "embedding_model": "", "embedding_dim": None,
     "note": "Documented for chat only; use another account for embeddings."},
    {"id": "anthropic", "name": "Anthropic (Claude)", "base_url": "https://api.anthropic.com/v1",
     "chat_model": "", "embedding_model": "", "embedding_dim": None,
     "note": "Uses Anthropic's OpenAI-compatibility endpoint, which they describe as not for production. "
             "Chat only: Anthropic has no embedding model."},
    {"id": "custom", "name": "Custom (OpenAI-compatible)", "base_url": "",
     "chat_model": "", "embedding_model": "", "embedding_dim": None,
     "note": "Any server that implements /chat/completions and/or /embeddings."},
]
PROVIDER_IDS = {p["id"] for p in PRESETS}


class AccountError(ValueError):
    pass


@dataclass(frozen=True)
class ChatConfig:
    base_url: str
    model: str
    trusted: bool
    label: str
    key_plain: str = ""
    key_enc: str | None = None

    def api_key(self) -> str:
        return vault.decrypt(self.key_enc) if self.key_enc else self.key_plain


_PUBLIC = ("id, name, provider, base_url, (api_key_enc IS NOT NULL) AS has_key, api_key_last4, chat_model, "
           "embedding_model, embedding_dim, created_at, updated_at")


def env_account() -> dict | None:
    """The operator-set environment configuration, shown read-only in the UI."""
    s = get_settings()
    if not s.llm_base_url:
        return None
    return {"id": "env", "name": "Environment (server settings)", "provider": "env", "base_url": s.llm_base_url,
            "has_key": bool(s.llm_api_key), "api_key_last4": None, "chat_model": s.llm_chat_model or None,
            "embedding_model": s.embedding_model, "embedding_dim": s.embedding_dim, "read_only": True}


def list_accounts(conn) -> list[dict]:
    return conn.execute(f"SELECT {_PUBLIC} FROM llm_account ORDER BY name").fetchall()


def get_account(conn, account_id: int) -> dict:
    row = conn.execute(f"SELECT {_PUBLIC} FROM llm_account WHERE id=%s", (account_id,)).fetchone()
    if not row:
        raise AccountError("account not found")
    return row


def _require_vault(conn) -> None:
    if not vault.is_initialized(conn):
        raise AccountError("set an admin password first (Settings > Security): provider keys are stored encrypted "
                           "under it")


def _clean(value: str | None) -> str | None:
    value = (value or "").strip()
    return value or None


def create(conn, *, name: str, provider: str, base_url: str, api_key: str | None, chat_model: str | None,
           embedding_model: str | None, embedding_dim: int | None) -> int:
    name = name.strip()
    if provider not in PROVIDER_IDS:
        raise AccountError("unknown provider")
    base_url = check_url(base_url)
    enc = last4 = None
    if _clean(api_key):
        _require_vault(conn)
        key = api_key.strip()
        enc, last4 = vault.encrypt(key), key[-4:]
    exists = conn.execute("SELECT 1 FROM llm_account WHERE lower(name)=lower(%s)", (name,)).fetchone()
    if exists:
        raise AccountError("an account with that name already exists")
    row = conn.execute(
        "INSERT INTO llm_account (name, provider, base_url, api_key_enc, api_key_last4, chat_model, embedding_model, "
        "embedding_dim) VALUES (%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id",
        (name, provider, base_url, enc, last4, _clean(chat_model), _clean(embedding_model), embedding_dim),
    ).fetchone()
    conn.commit()
    return row["id"]


def update(conn, account_id: int, *, name: str, provider: str, base_url: str, api_key: str | None,
           clear_key: bool, chat_model: str | None, embedding_model: str | None, embedding_dim: int | None) -> None:
    get_account(conn, account_id)
    if provider not in PROVIDER_IDS:
        raise AccountError("unknown provider")
    name, base_url = name.strip(), check_url(base_url)
    clash = conn.execute("SELECT 1 FROM llm_account WHERE lower(name)=lower(%s) AND id<>%s", (name, account_id)).fetchone()
    if clash:
        raise AccountError("an account with that name already exists")
    sets = ["name=%s", "provider=%s", "base_url=%s", "chat_model=%s", "embedding_model=%s", "embedding_dim=%s",
            "updated_at=now()"]
    args: list = [name, provider, base_url, _clean(chat_model), _clean(embedding_model), embedding_dim]
    if _clean(api_key):
        _require_vault(conn)
        key = api_key.strip()
        sets += ["api_key_enc=%s", "api_key_last4=%s"]
        args += [vault.encrypt(key), key[-4:]]
    elif clear_key:
        sets += ["api_key_enc=NULL", "api_key_last4=NULL"]
    conn.execute(f"UPDATE llm_account SET {', '.join(sets)} WHERE id=%s", (*args, account_id))
    conn.commit()
    if embedcfg.current().account_id == account_id:  # the active embedder changed: reload it
        embedcfg.reset()
        embedcfg.ensure_loaded(conn)


def delete(conn, account_id: int) -> None:
    get_account(conn, account_id)
    if embedcfg.current().account_id == account_id:
        raise AccountError("this account is used for embeddings; switch embeddings to another account first")
    conn.execute("DELETE FROM llm_account WHERE id=%s", (account_id,))
    conn.commit()


def _raw(conn, account_id: int) -> dict:
    row = conn.execute("SELECT * FROM llm_account WHERE id=%s", (account_id,)).fetchone()
    if not row:
        raise AccountError("account not found")
    return row


def embedding_config_for(conn, account_id: int) -> embedcfg.EmbeddingConfig:
    row = _raw(conn, account_id)
    if not row["embedding_model"]:
        raise AccountError("this account has no embedding model configured")
    s = get_settings()
    return embedcfg.EmbeddingConfig(
        base_url=row["base_url"], model=row["embedding_model"], dim=row["embedding_dim"] or DEFAULT_DIM,
        send_dimensions=s.send_dimensions, trusted=False, account_id=account_id, key_enc=row["api_key_enc"])


def chat_config_for(conn, ref: int | str) -> ChatConfig:
    if ref == "env":
        s = get_settings()
        if not s.llm_base_url or not s.llm_chat_model:
            raise AccountError("the environment configuration has no chat model (set LLM_CHAT_MODEL)")
        return ChatConfig(base_url=s.llm_base_url, model=s.llm_chat_model, trusted=True,
                          label="Environment", key_plain=s.llm_api_key)
    row = _raw(conn, int(ref))
    if not row["chat_model"]:
        raise AccountError("this account has no chat model configured")
    return ChatConfig(base_url=row["base_url"], model=row["chat_model"], trusted=False, label=row["name"],
                      key_enc=row["api_key_enc"])


def active_embedding_ref(conn) -> int | str | None:
    pointer = store.get(conn, embedcfg.SETTING)
    return int(pointer) if pointer else ("env" if env_account() else None)
