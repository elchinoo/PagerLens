"""One chat-completions call through any OpenAI-compatible endpoint (used by the LLM investigator and the UI test)."""
from . import vault
from .accounts import ChatConfig
from .llm_http import LLMError, error_detail, post_json


def chat(cfg: ChatConfig, messages: list[dict], max_tokens: int = 700, tools: list[dict] | None = None) -> dict:
    """Returns {"text", "tool_calls", "usage"}. Errors are LLMError with a message that never contains the key."""
    if not cfg.model:
        raise LLMError("this account has no chat model set; add one under Settings")
    try:
        key = cfg.api_key()
    except vault.VaultLocked:
        raise
    except vault.VaultError as exc:
        raise LLMError(str(exc)) from exc
    body: dict = {"model": cfg.model, "messages": messages, "max_tokens": max_tokens, "temperature": 0.1}
    if tools:
        body["tools"] = tools
    resp = post_json(cfg.base_url, "/chat/completions", key, body, trusted=cfg.trusted)
    if resp.status_code >= 400:
        raise LLMError(f"chat endpoint returned HTTP {resp.status_code}: {error_detail(resp, key)}")
    try:
        data = resp.json()
        msg = data["choices"][0]["message"]
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        raise LLMError("unexpected response from the chat endpoint (no choices[0].message)") from exc
    return {"text": (msg.get("content") or "").strip(), "tool_calls": msg.get("tool_calls") or [],
            "usage": data.get("usage") or {}, "message": msg, "response": data}
