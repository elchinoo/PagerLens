"""Provider accounts, embeddings switching and Ask, against a disposable Postgres and a mock provider."""
import json
import os
import socket

import httpx
import pytest

if not os.environ.get("TEST_DATABASE_URL"):
    pytest.skip("set TEST_DATABASE_URL to run DB tests", allow_module_level=True)

from pagerlens import api, auth, llm_http, migrate, netguard, vault  # noqa: E402
from pagerlens.db import connect  # noqa: E402
from pagerlens.embeddings import hash_embed  # noqa: E402

H = {"X-PagerLens-CSRF": "1"}
PASSWORD = "correct-horse-battery"  # pragma: allowlist secret
PROVIDER_KEY = "sk-" + "live" * 6  # fake placeholder  # pragma: allowlist secret
CALLS: list[dict] = []


def provider(request: httpx.Request) -> httpx.Response:
    """A fake OpenAI-compatible provider."""
    body = json.loads(request.content)
    CALLS.append({"path": request.url.path, "auth": request.headers.get("authorization"), "body": body})
    if request.headers.get("authorization") != f"Bearer {PROVIDER_KEY}":
        return httpx.Response(401, text=f"bad key {request.headers.get('authorization')}")  # echoes the key back
    if request.url.path.endswith("/embeddings"):
        dim = body.get("dimensions", 16)
        data = [{"index": i, "embedding": hash_embed(t, dim)} for i, t in enumerate(body["input"])]
        return httpx.Response(200, json={"data": data})
    if request.url.path.endswith("/chat/completions"):
        reply = "Customers are notified within 72 hours [1]." if "breach" in body["messages"][-1]["content"] else "No idea."
        return httpx.Response(200, json={"choices": [{"message": {"content": reply}}], "usage": {"total_tokens": 42}})
    return httpx.Response(404)


@pytest.fixture(autouse=True)
def _env(monkeypatch, client):
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    for v in ("PAGERLENS_API_KEY", "PAGERLENS_ALLOW_ANONYMOUS", "PAGERLENS_ENCRYPTION_KEY", "LLM_BASE_URL"):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setenv("PAGERLENS_API_KEY_FILE", "/nonexistent/key")
    monkeypatch.setenv("PAGERLENS_ENCRYPTION_KEY_FILE", "/nonexistent/key")
    monkeypatch.setenv("LLM_API_KEY_FILE", "/nonexistent/key")
    monkeypatch.setenv("EMBEDDING_DIM", "768")
    monkeypatch.setattr(llm_http, "_client", lambda: httpx.Client(transport=httpx.MockTransport(provider)))
    monkeypatch.setattr(llm_http.time, "sleep", lambda _: None)

    def fake_dns(host, port, **kw):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

    monkeypatch.setattr(netguard.socket, "getaddrinfo", fake_dns)
    api._failures.clear()
    auth._setup_code = None
    CALLS.clear()
    client.cookies.clear()
    with connect() as c:
        c.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public")
        c.commit()
    migrate.run()


@pytest.fixture
def admin(client):
    with connect() as c:
        auth.set_admin_password(c, PASSWORD)
    assert client.post("/api/login", json={"password": PASSWORD}, headers=H).status_code == 200
    return client


def new_account(client, **over):
    body = {"name": "openai-main", "provider": "openai", "base_url": "https://llm.example/v1", "api_key": PROVIDER_KEY,
            "chat_model": "chat-1", "embedding_model": "emb-1", "embedding_dim": 32} | over
    return client.post("/api/accounts", json=body, headers=H)


# ---- storage and secrecy ----------------------------------------------------------------------
def test_keys_are_encrypted_and_never_returned(admin):
    r = new_account(admin)
    assert r.status_code == 200
    acct = r.json()
    assert acct["has_key"] is True and acct["api_key_last4"] == PROVIDER_KEY[-4:] and "api_key" not in acct
    assert PROVIDER_KEY not in json.dumps(admin.get("/api/accounts").json())
    with connect() as c:
        row = c.execute("SELECT * FROM llm_account").fetchone()
    assert PROVIDER_KEY not in json.dumps({k: str(v) for k, v in row.items()})  # only ciphertext in the database
    assert row["api_key_enc"] and row["api_key_enc"] != PROVIDER_KEY


def test_validation_and_duplicates(admin):
    assert new_account(admin, base_url="https://user:pw@llm.example/v1").status_code == 422  # pragma: allowlist secret
    assert new_account(admin, base_url="ftp://llm.example/v1").status_code == 422
    assert new_account(admin, provider="nope").status_code == 422
    assert new_account(admin).status_code == 200
    dup = new_account(admin, name="OPENAI-MAIN")
    assert dup.status_code == 422 and "already exists" in dup.json()["detail"]


def test_private_urls_blocked(admin, monkeypatch):
    monkeypatch.setattr(netguard.socket, "getaddrinfo",
                        lambda h, p, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", p))])
    r = new_account(admin, base_url="https://metadata.example/v1")
    assert r.status_code == 422 and "link-local" in r.json()["detail"]


def test_storing_a_key_requires_an_admin_password(client, monkeypatch):
    monkeypatch.setenv("PAGERLENS_API_KEY", "static-automation-key")  # pragma: allowlist secret
    client.post("/api/login", json={"api_key": "static-automation-key"}, headers=H)  # pragma: allowlist secret
    r = new_account(client)
    assert r.status_code == 422 and "admin password" in r.json()["detail"]
    assert new_account(client, api_key=None).status_code == 200  # keyless endpoints (e.g. local servers) are fine


def test_locked_vault_blocks_key_use_but_not_listing(admin):
    acct = new_account(admin).json()
    vault.lock()  # simulate a restart
    assert admin.get("/api/accounts").status_code == 200
    r = admin.post(f"/api/accounts/{acct['id']}/test", json={"target": "chat"}, headers=H)
    assert r.status_code == 423 and "unlock" in r.json()["detail"].lower()
    assert new_account(admin, name="second").status_code == 423  # cannot encrypt a new key either
    admin.post("/api/vault/unlock", json={"password": PASSWORD}, headers=H)
    assert admin.post(f"/api/accounts/{acct['id']}/test", json={"target": "chat"}, headers=H).status_code == 200


def test_update_keeps_the_key_unless_replaced(admin):
    acct = new_account(admin).json()
    body = {"name": "renamed", "provider": "openai", "base_url": "https://llm.example/v1", "chat_model": "chat-2"}
    assert admin.put(f"/api/accounts/{acct['id']}", json=body, headers=H).json()["has_key"] is True
    assert admin.post(f"/api/accounts/{acct['id']}/test", json={"target": "chat"}, headers=H).status_code == 200
    assert admin.put(f"/api/accounts/{acct['id']}", json=body | {"clear_key": True}, headers=H).json()["has_key"] is False


def test_read_only_tokens_cannot_touch_accounts(admin):
    tok = admin.post("/api/tokens", json={"name": "m", "scope": "read"}, headers=H).json()["token"]
    admin.cookies.clear()
    ro = {"Authorization": f"Bearer {tok}"}
    assert admin.get("/api/accounts", headers=ro).status_code == 403
    assert admin.post("/api/simulator/baseline", headers=ro).status_code == 403


# ---- provider calls ---------------------------------------------------------------------------
def test_connection_test_reports_success_and_safe_errors(admin):
    good = new_account(admin).json()["id"]
    r = admin.post(f"/api/accounts/{good}/test", json={"target": "embeddings"}, headers=H).json()
    assert r["ok"] and r["dimensions"] == 32
    assert admin.post(f"/api/accounts/{good}/test", json={"target": "chat"}, headers=H).json()["reply"] == "No idea."

    bad = new_account(admin, name="wrongkey", api_key="sk-" + "nope" * 6).json()["id"]  # pragma: allowlist secret
    r = admin.post(f"/api/accounts/{bad}/test", json={"target": "chat"}, headers=H)
    assert r.status_code == 502 and "401" in r.json()["detail"]
    assert "nope" * 6 not in r.text  # the provider echoed the key; it must be redacted


def test_redirects_are_refused(admin, monkeypatch):
    monkeypatch.setattr(llm_http, "_client", lambda: httpx.Client(
        transport=httpx.MockTransport(lambda r: httpx.Response(302, headers={"location": "http://169.254.169.254/"}))))
    acct = new_account(admin).json()["id"]
    r = admin.post(f"/api/accounts/{acct}/test", json={"target": "chat"}, headers=H)
    assert r.status_code == 502 and "redirect" in r.json()["detail"]


# ---- switching embeddings ---------------------------------------------------------------------
