"""One chat-completions call through any OpenAI-compatible endpoint (used by the LLM investigator and the UI test)."""
from . import vault
from .accounts import ChatConfig
from .llm_http import LLMError, error_detail, post_json

# Some gateways/providers answer 400 to `tool_choice`. The first time that happens (and the same request then works without it) we
# stop sending it for the life of this process instead of failing or retrying every question.
_tool_choice_rejected = False


def tool_choice_supported() -> bool:
    return not _tool_choice_rejected


def reset_tool_choice() -> None:
    """Forget that the provider rejected tool_choice (tests)."""
    global _tool_choice_rejected
    _tool_choice_rejected = False


def chat(cfg: ChatConfig, messages: list[dict], max_tokens: int = 700, tools: list[dict] | None = None,
         tool_choice: str | None = None) -> dict:
    """Returns {"text", "tool_calls", "usage", "tool_choice_sent"}. `tool_choice` ("required") is only sent with tools, and dropped
    for good if the endpoint rejects it with a 400. Errors are LLMError with a message that never contains the key."""
    global _tool_choice_rejected
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
    sent = False
    if tools and tool_choice and not _tool_choice_rejected:
        body["tool_choice"] = tool_choice
        sent = True
    resp = post_json(cfg.base_url, "/chat/completions", key, body, trusted=cfg.trusted)
    if sent and resp.status_code == 400:
        retry_body = {k: v for k, v in body.items() if k != "tool_choice"}
        retry = post_json(cfg.base_url, "/chat/completions", key, retry_body, trusted=cfg.trusted)
        if retry.status_code < 400:
            _tool_choice_rejected = True          # it was tool_choice: do not send it again from this process
            sent = False
        resp = retry
    if resp.status_code >= 400:
        raise LLMError(f"chat endpoint returned HTTP {resp.status_code}: {error_detail(resp, key)}")
    try:
        data = resp.json()
        msg = data["choices"][0]["message"]
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        raise LLMError("unexpected response from the chat endpoint (no choices[0].message)") from exc
    return {"text": (msg.get("content") or "").strip(), "tool_calls": msg.get("tool_calls") or [],
            "usage": data.get("usage") or {}, "tool_choice_sent": sent, "message": msg, "response": data}
