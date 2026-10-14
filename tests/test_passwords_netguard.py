import socket

import pytest

from pagerlens import netguard, passwords
from pagerlens.netguard import UnsafeURL


def test_password_roundtrip_and_salting():
    h1, h2 = passwords.hash_password("correct horse battery"), passwords.hash_password("correct horse battery")
    assert h1 != h2 and h1.startswith("scrypt$")  # random salt each time
    assert passwords.verify_password("correct horse battery", h1)
    assert not passwords.verify_password("correct horse batterY", h1)
    assert not passwords.verify_password("x", "garbage") and not passwords.verify_password("x", "bcrypt$1$2")


def test_password_strength():
    with pytest.raises(ValueError):
        passwords.check_strength("short")
    with pytest.raises(ValueError):
        passwords.check_strength("x" * 257)
    passwords.check_strength("a-long-enough-pass")


def _resolve(monkeypatch, *ips):
    def fake(host, port, **kw):
        return [(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port)) for ip in ips]

    monkeypatch.setattr(netguard.socket, "getaddrinfo", fake)


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.1.2.3", "192.168.0.5", "172.16.0.1", "100.64.0.1", "::1", "fd00::1",
                                "0.0.0.0", "::ffff:127.0.0.1"])
def test_private_and_local_targets_blocked_by_default(monkeypatch, ip):
    monkeypatch.delenv("PAGERLENS_ALLOW_PRIVATE_LLM_URLS", raising=False)
    _resolve(monkeypatch, ip)
    with pytest.raises(UnsafeURL):
        netguard.check_url("https://example.test/v1")


@pytest.mark.parametrize("ip", ["169.254.169.254", "fe80::1"])
def test_metadata_and_link_local_always_blocked(monkeypatch, ip):
    monkeypatch.setenv("PAGERLENS_ALLOW_PRIVATE_LLM_URLS", "true")
    _resolve(monkeypatch, ip)
    with pytest.raises(UnsafeURL, match="link-local"):
        netguard.check_url("https://example.test/v1")


def test_any_private_answer_blocks_mixed_dns(monkeypatch):
    monkeypatch.delenv("PAGERLENS_ALLOW_PRIVATE_LLM_URLS", raising=False)
    _resolve(monkeypatch, "93.184.216.34", "10.0.0.1")
    with pytest.raises(UnsafeURL):
        netguard.check_url("https://example.test/v1")


def test_public_https_is_allowed_and_normalised(monkeypatch):
    _resolve(monkeypatch, "93.184.216.34")
    assert netguard.check_url(" https://api.example.test/v1/ ") == "https://api.example.test/v1"


def test_plain_http_only_for_allowed_local(monkeypatch):
    _resolve(monkeypatch, "93.184.216.34")
    with pytest.raises(UnsafeURL, match="https"):
        netguard.check_url("http://api.example.test/v1")
    monkeypatch.setenv("PAGERLENS_ALLOW_PRIVATE_LLM_URLS", "true")
    _resolve(monkeypatch, "127.0.0.1")
    assert netguard.check_url("http://localhost:11434/v1") == "http://localhost:11434/v1"


@pytest.mark.parametrize("url", ["", "ftp://x/v1", "https://user:pw@example.test/v1", "https://example.test/v1?x=1",  # pragma: allowlist secret
                                 "https://example.test/v1#f", "https:///v1", "x" * 301])
def test_malformed_urls_rejected(monkeypatch, url):
    _resolve(monkeypatch, "93.184.216.34")
    with pytest.raises(UnsafeURL):
        netguard.check_url(url)


def test_unresolvable_host_rejected(monkeypatch):
    def boom(*a, **k):
        raise socket.gaierror("nope")

    monkeypatch.setattr(netguard.socket, "getaddrinfo", boom)
    with pytest.raises(UnsafeURL, match="resolve"):
        netguard.check_url("https://nope.invalid/v1")
