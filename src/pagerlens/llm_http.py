"""The outbound LLM client now lives in agentpg-kit; this module keeps the old import path."""
from apgkit.llm import MAX_RESPONSE_BYTES, LLMError, redact  # noqa: F401

from .core import llm as _llm


def post_json(base_url: str, path: str, api_key: str, body: dict, *, trusted: bool, retries: int = 3):
    return _llm.post_json(base_url, path, api_key, body, trusted=trusted, retries=retries)


def error_detail(resp, api_key: str) -> str:
    return redact(resp.text[:300], api_key)
