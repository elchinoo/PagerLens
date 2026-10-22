"""The outbound-URL guard now lives in agentpg-kit; this module keeps the old import path and this app's environment switch."""
import socket  # noqa: F401  (tests patch netguard.socket.getaddrinfo)

from apgkit.netguard import UnsafeURL

from .core import netguard as _guard


def check_url(url: str) -> str:
    return _guard.check(url)


__all__ = ["UnsafeURL", "check_url"]
