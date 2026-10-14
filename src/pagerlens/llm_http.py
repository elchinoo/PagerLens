"""One HTTP path for every outbound call to an OpenAI-compatible provider.

Retries transient failures, never follows redirects, bounds the response, and redacts the API key from every
message it raises.
"""
import time

import httpx

from .netguard import UnsafeURL, check_url

_RETRY_STATUS = {408, 409, 429, 500, 502, 503, 504}
MAX_RESPONSE_BYTES = 8 * 1024 * 1024


class LLMError(RuntimeError):
    """A failure whose message is safe to show to users: it never contains the API key."""


def _client() -> httpx.Client:  # indirection so tests can inject a mock transport
    return httpx.Client(timeout=60, follow_redirects=False)


def redact(text: str, api_key: str) -> str:
    return text.replace(api_key, "***") if api_key else text


def post_json(base_url: str, path: str, api_key: str, body: dict, *, trusted: bool,
              retries: int = 3) -> httpx.Response:
    """POST {base_url}{path}. `trusted` is True for operator-set environment config; user-entered accounts are
    checked by the URL guard on every call."""
    if not trusted:
        try:
            base_url = check_url(base_url)
        except UnsafeURL as exc:
            raise LLMError(f"provider URL rejected: {exc}") from exc
    url = f"{base_url.rstrip('/')}{path}"
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    with _client() as client:
        for attempt in range(retries + 1):
            try:
                resp = client.post(url, headers=headers, json=body)
            except httpx.TransportError as exc:
                if attempt == retries:
                    raise LLMError(f"could not reach the provider: {type(exc).__name__}") from exc
            else:
                if resp.is_redirect:
                    raise LLMError("the provider URL redirected; use the final URL directly")
                if len(resp.content) > MAX_RESPONSE_BYTES:
                    raise LLMError("provider response too large")
                if resp.status_code not in _RETRY_STATUS or attempt == retries:
                    return resp
            time.sleep(min(2**attempt, 8))
    raise AssertionError("unreachable")


def error_detail(resp: httpx.Response, api_key: str) -> str:
    return redact(resp.text[:300], api_key)
