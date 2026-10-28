"""Retrieval honours the embedding account an administrator activated, and falls back to the environment otherwise."""
import json
import os
import socket

import apgkit.llm as apgkit_llm
import httpx
import pytest

if not os.environ.get("TEST_DATABASE_URL"):
    pytest.skip("set TEST_DATABASE_URL to run DB tests", allow_module_level=True)

from pagerlens import auth, cli, core, embedcfg, migrate, netguard, retrieval, simulator, vault  # noqa: E402
from pagerlens.db import connect, connect_vector  # noqa: E402
from pagerlens.embeddings import hash_embed  # noqa: E402

H = {"X-PagerLens-CSRF": "1"}
PASSWORD = "correct-horse-battery"  # pragma: allowlist secret
PROVIDER_KEY = "sk-" + "demo" * 6  # fake placeholder  # pragma: allowlist secret
CALLS: list[dict] = []


def provider(request: httpx.Request) -> httpx.Response:
    """A fake OpenAI-compatible embeddings provider that records what it was asked."""
    body = json.loads(request.content)
    CALLS.append({"path": request.url.path, "auth": request.headers.get("authorization"), "body": body})
    if request.headers.get("authorization") != f"Bearer {PROVIDER_KEY}":
        return httpx.Response(401, text="bad key")
    if request.url.path.endswith("/embeddings"):
        dim = body.get("dimensions", 16)
        return httpx.Response(200, json={"data": [{"index": i, "embedding": hash_embed(t, dim)}
                                                   for i, t in enumerate(body["input"])]})
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
    monkeypatch.setattr(core.llm, "_http", lambda: httpx.Client(transport=httpx.MockTransport(provider)))
    monkeypatch.setattr(apgkit_llm.time, "sleep", lambda _: None)
    monkeypatch.setattr(netguard.socket, "getaddrinfo",
                        lambda host, port, **kw: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))])
    core.auth.limiter.clear()
    core.local._setup_code = None
    CALLS.clear()
    client.cookies.clear()
    with connect() as c:
        c.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public")
        c.commit()
    migrate.run()
    with connect_vector() as c:
        simulator.seed_runbooks(c)   # no provider yet: stored without vectors, which is fine for these tests
        c.commit()
    migrate._job.update(state="idle", done=0, total=0, message="")
    CALLS.clear()


@pytest.fixture
def admin(client):
    with connect() as c:
        auth.set_admin_password(c, PASSWORD)
    assert client.post("/api/login", json={"password": PASSWORD}, headers=H).status_code == 200
    return client


def new_account(client, **over):
    body = {"name": "emb", "provider": "custom", "base_url": "https://llm.example/v1", "api_key": PROVIDER_KEY,
            "chat_model": "chat-1", "embedding_model": "emb-1", "embedding_dim": 768} | over
    r = client.post("/api/accounts", json=body, headers=H)
    assert r.status_code == 200, r.text
    return r.json()["id"]


def activate(client, ref):
    return client.put("/api/embeddings/active", json={"account": str(ref)}, headers=H)


def embedding_requests():
    return [c for c in CALLS if c["path"].endswith("/embeddings")]


def test_without_a_choice_retrieval_uses_the_environment_embedder(admin):
    new_account(admin)                                 # exists, but is not activated
    with connect_vector() as c:
        assert retrieval.search_runbooks(c, "database connection pool saturation")
    assert embedding_requests() == []


def test_retrieval_embeds_with_the_activated_account(admin):
    acct = new_account(admin, embedding_model="emb-account")
    r = activate(admin, acct)
    assert r.status_code == 200 and r.json()["active_embedding"] == str(acct)
    assert admin.get("/api/accounts").json()["active_embedding"] == acct
    CALLS.clear()
    with connect_vector() as c:
        rows = retrieval.search_runbooks(c, "database connection pool saturation")
        assert rows
        assert retrieval.similar_incidents(c, "checkout errors after deploy") == []   # nothing resolved yet, but no error
    sent = embedding_requests()
    assert sent and all(s["body"]["model"] == "emb-account" and s["auth"] == f"Bearer {PROVIDER_KEY}" for s in sent)


def test_the_choice_survives_a_restart_and_can_be_switched_back_to_the_environment(admin):
    acct = new_account(admin)
    assert activate(admin, acct).status_code == 200
    embedcfg.reset()                                    # a new process: the pointer is read from the database
    with connect_vector() as c:
        assert embedcfg.resolve(c).account_id == acct
    assert activate(admin, "env").status_code == 200
    CALLS.clear()
    with connect_vector() as c:
        assert embedcfg.resolve(c).account_id is None
        retrieval.search_runbooks(c, "sudden traffic spike")
    assert embedding_requests() == []


def test_a_size_that_does_not_fit_the_columns_means_text_search_until_reembedded(admin, caplog):
    acct = new_account(admin, embedding_dim=32)
    assert activate(admin, acct).json()["mismatch"] is True
    with connect_vector() as c:
        assert migrate.column_dim(c, "runbook") == 768
        rows = retrieval.search_runbooks(c, "database connection pool saturation")
        assert rows and "pool" in rows[0]["title"].lower()          # full-text only, no exception
    assert any("does not match" in r.getMessage() for r in caplog.records)
    assert admin.post("/api/embeddings/reembed", headers=H).json() == {"started": True}
    migrate.wait_background()
    with connect_vector() as c:
        assert migrate.column_dim(c, "runbook") == migrate.column_dim(c, "incident") == 32
        assert c.execute("SELECT count(*) AS n FROM runbook WHERE embedding IS NULL").fetchone()["n"] == 0
    CALLS.clear()
    with connect_vector() as c:
        assert retrieval.search_runbooks(c, "database connection pool saturation")
    assert embedding_requests()                                        # now the vector path is used


def test_an_account_that_fails_its_probe_is_not_activated(admin):
    acct = new_account(admin)
    r = admin.put(f"/api/accounts/{acct}", json={"name": "emb", "provider": "custom", "base_url": "https://llm.example/v1",
                                                   "api_key": "wrong-key", "embedding_model": "emb-1",
                                                   "embedding_dim": 768}, headers=H)
    assert r.status_code == 200
    assert activate(admin, acct).status_code == 502
    assert admin.get("/api/accounts").json()["active_embedding"] in (None, "env")
    assert activate(admin, 999999).status_code == 422                  # unknown account
    chat_only = new_account(admin, name="chat-only", embedding_model=None, embedding_dim=None)
    assert activate(admin, chat_only).status_code == 422               # no embedding model configured


def test_startup_with_a_locked_vault_changes_nothing_for_an_account_embedder(admin, capsys):
    acct = new_account(admin, embedding_dim=32)
    assert activate(admin, acct).status_code == 200
    vault.lock()                                                       # what a restart does until the admin signs in
    with connect_vector() as c:
        r = migrate.reconcile_embedding_dim(c)
        assert r["skipped"] and not r["changed"]
        assert migrate.column_dim(c, "runbook") == 768
        assert retrieval.search_runbooks(c, "memory leak")             # text search, no exception
    assert cli.main(["reembed"]) == 1
    assert "reembed skipped" in capsys.readouterr().err
