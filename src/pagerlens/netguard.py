"""Guard for user-supplied provider URLs (the server makes outbound requests to them).

Blocks loopback, private, link-local (cloud metadata), reserved and carrier-grade-NAT addresses, URLs with
embedded credentials, and plain http to non-local hosts. Operators can allow private/loopback targets
(for example a local Ollama) with PAGERLENS_ALLOW_PRIVATE_LLM_URLS=true; link-local is always blocked.

Limitation: the hostname is resolved here and again by the HTTP client, so a hostile DNS server could in
principle answer differently the second time. Redirects are never followed, which closes the common route.
"""
import ipaddress
import os
import socket
from urllib.parse import urlsplit


class UnsafeURL(ValueError):
    pass


def _allow_private() -> bool:
    return os.environ.get("PAGERLENS_ALLOW_PRIVATE_LLM_URLS", "").lower() in {"1", "true", "yes"}


def check_url(url: str) -> str:
    """Validate and normalise a provider base URL (no trailing slash). Raises UnsafeURL."""
    url = (url or "").strip()
    if not url or len(url) > 300:
        raise UnsafeURL("base URL is required (max 300 characters)")
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise UnsafeURL("base URL must start with https:// (or http:// for an allowed local server)")
    if parts.username or parts.password:
        raise UnsafeURL("credentials must not be embedded in the URL; use the API key field")
    if parts.query or parts.fragment:
        raise UnsafeURL("base URL must not contain a query string or fragment")
    try:
        infos = socket.getaddrinfo(parts.hostname, parts.port or (443 if parts.scheme == "https" else 80),
                                   type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise UnsafeURL(f"cannot resolve host {parts.hostname!r}") from exc
    allow = _allow_private()
    local = False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        if ip.is_link_local:
            raise UnsafeURL("link-local addresses (including cloud metadata services) are not allowed")
        if not ip.is_global:
            if not allow:
                raise UnsafeURL(
                    "that address is private or local; set PAGERLENS_ALLOW_PRIVATE_LLM_URLS=true on the server "
                    "to allow a local model server"
                )
            local = True
    if parts.scheme == "http" and not local:
        raise UnsafeURL("plain http is only allowed for local servers; use https://")
    return url.rstrip("/")
