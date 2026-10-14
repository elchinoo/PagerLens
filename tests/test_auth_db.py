"""Vault, setup, login, sessions and API tokens against a disposable Postgres (TEST_DATABASE_URL)."""
import os

import pytest

if not os.environ.get("TEST_DATABASE_URL"):
    pytest.skip("set TEST_DATABASE_URL to run DB tests", allow_module_level=True)

from pagerlens import api, auth, migrate, vault  # noqa: E402
from pagerlens.db import connect  # noqa: E402

H = {"X-PagerLens-CSRF": "1"}
PASSWORD = "correct-horse-battery"  # pragma: allowlist secret


@pytest.fixture(autouse=True)
def _db(monkeypatch, client):
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    for v in ("PAGERLENS_API_KEY", "PAGERLENS_ALLOW_ANONYMOUS", "PAGERLENS_ENCRYPTION_KEY"):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setenv("PAGERLENS_API_KEY_FILE", "/nonexistent/key")
    monkeypatch.setenv("PAGERLENS_ENCRYPTION_KEY_FILE", "/nonexistent/key")
    api._failures.clear()
    api._announced = False
    auth._setup_code = None
    vault.lock()
    client.cookies.clear()
    with connect() as c:
        c.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public")
        c.commit()
    migrate.run()


# ---- vault ------------------------------------------------------------------------------------
def test_vault_lifecycle():
    with connect() as c:
        assert vault.status(c) == {"initialized": False, "unlocked": False, "auto_unlock": False}
        vault.initialize(c, PASSWORD)
        c.commit()
        token = vault.encrypt("sk-secret-value")
        assert "sk-secret" not in token and vault.decrypt(token) == "sk-secret-value"
        vault.lock()
        with pytest.raises(vault.VaultLocked):
            vault.decrypt(token)
        assert vault.unlock_with_password(c, "wrong-password-here") is False and not vault.is_unlocked()
        assert vault.unlock_with_password(c, PASSWORD) and vault.decrypt(token) == "sk-secret-value"
        vault.change_password(c, "another-long-password")
        c.commit()
        vault.lock()
        assert not vault.unlock_with_password(c, PASSWORD)  # old password no longer works
        assert vault.unlock_with_password(c, "another-long-password") and vault.decrypt(token) == "sk-secret-value"


def test_platform_secret_enables_unattended_unlock(monkeypatch):
    monkeypatch.setenv("PAGERLENS_ENCRYPTION_KEY", "platform-managed-secret")  # pragma: allowlist secret
    with connect() as c:
        vault.initialize(c, PASSWORD)
        c.commit()
        token = vault.encrypt("abc")
        vault.lock()
        assert vault.try_unlock_with_platform_secret(c) and vault.decrypt(token) == "abc"
        assert vault.status(c)["auto_unlock"] is True
        vault.lock()
        monkeypatch.setenv("PAGERLENS_ENCRYPTION_KEY", "a-different-secret")  # pragma: allowlist secret
        assert vault.try_unlock_with_platform_secret(c) is False  # wrong secret never unlocks


def test_platform_secret_added_later_is_wrapped_on_next_password_unlock(monkeypatch):
    with connect() as c:
        vault.initialize(c, PASSWORD)
        c.commit()
        vault.lock()
        monkeypatch.setenv("PAGERLENS_ENCRYPTION_KEY", "added-later-secret")  # pragma: allowlist secret
        assert not vault.try_unlock_with_platform_secret(c)
        assert vault.unlock_with_password(c, PASSWORD)
        c.commit()
        vault.lock()
        assert vault.try_unlock_with_platform_secret(c)


def test_database_holds_no_plaintext_secret():
    with connect() as c:
        vault.initialize(c, PASSWORD)
        c.commit()
        rows = c.execute("SELECT key, value FROM app_setting").fetchall()
    blob = " ".join(f"{r['key']} {r['value']}" for r in rows)
    assert PASSWORD not in blob


# ---- setup, login, sessions ---------------------------------------------------------------------
def test_first_run_setup_flow(client):
    s = client.get("/api/session").json()
    assert s["state"] == "setup_required"
    assert client.get("/api/incidents").status_code == 401  # nothing works before setup

    code = auth.setup_code()
    assert client.post("/api/setup", json={"code": "WRONG-CODE-0000", "password": PASSWORD}, headers=H).status_code == 403
    assert client.post("/api/setup", json={"code": code, "password": "short"}, headers=H).status_code == 422  # pragma: allowlist secret

    r = client.post("/api/setup", json={"code": code, "password": PASSWORD}, headers=H)
    assert r.status_code == 200
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie and "pl_session" in cookie
    assert client.get("/api/session").json()["state"] == "logged_in"
    assert client.get("/api/stats").status_code == 200

    # setup cannot be repeated, even with a valid code
    client.cookies.clear()
    assert client.post("/api/setup", json={"code": code, "password": "another-long-pass"}, headers=H).status_code == 403  # pragma: allowlist secret
    assert client.get("/api/session").json()["state"] == "logged_out"


def test_login_logout_and_wrong_password(client):
    with connect() as c:
        auth.set_admin_password(c, PASSWORD)
    assert client.post("/api/login", json={"password": "wrong-password-xx"}, headers=H).status_code == 401  # pragma: allowlist secret
    assert client.post("/api/login", json={"password": PASSWORD}, headers=H).status_code == 200
    assert client.get("/api/session").json()["state"] == "logged_in"
    assert client.post("/api/logout", headers=H).status_code == 200
    assert client.get("/api/session").json()["state"] == "logged_out"
    assert client.get("/api/stats").status_code == 401


def test_login_rate_limit(client):
    with connect() as c:
        auth.set_admin_password(c, PASSWORD)
    codes = [client.post("/api/login", json={"password": "nope-nope-nope-1"}, headers=H).status_code for _ in range(12)]  # pragma: allowlist secret
    assert codes[:10] == [401] * 10 and codes[10:] == [429, 429]
    assert client.post("/api/login", json={"password": PASSWORD}, headers=H).status_code == 429


def test_restart_locks_vault_until_password(client):
    with connect() as c:
        auth.set_admin_password(c, PASSWORD)
    client.post("/api/login", json={"password": PASSWORD}, headers=H)
    assert client.get("/api/session").json()["vault"]["unlocked"] is True
    vault.lock()  # simulates a process restart: the session cookie survives, the in-memory key does not
    s = client.get("/api/session").json()
    assert s["state"] == "logged_in" and s["vault"] == {"initialized": True, "unlocked": False, "auto_unlock": False}
    assert client.post("/api/vault/unlock", json={"password": "wrong-password-xx"}, headers=H).status_code == 403  # pragma: allowlist secret
    assert client.get("/api/session").json()["state"] == "logged_in"  # a wrong password must not end the session
    assert client.post("/api/vault/unlock", json={"password": PASSWORD}, headers=H).status_code == 200
    assert client.get("/api/session").json()["vault"]["unlocked"] is True


def test_password_change_signs_everyone_out(client):
    with connect() as c:
        auth.set_admin_password(c, PASSWORD)
    client.post("/api/login", json={"password": PASSWORD}, headers=H)
    assert client.post("/api/admin-password", json={"current": "bad-current-pass", "new": "brand-new-password"}, headers=H).status_code == 403
    assert client.post("/api/admin-password", json={"current": PASSWORD, "new": "brand-new-password"}, headers=H).status_code == 200
    assert client.get("/api/session").json()["state"] == "logged_out"
    assert client.post("/api/login", json={"password": PASSWORD}, headers=H).status_code == 401
    assert client.post("/api/login", json={"password": "brand-new-password"}, headers=H).status_code == 200  # pragma: allowlist secret


def test_reset_admin_recovery(client):
    with connect() as c:
        auth.set_admin_password(c, PASSWORD)
        auth.reset_admin(c)
    assert client.get("/api/session").json()["state"] == "setup_required"


# ---- API tokens -------------------------------------------------------------------------------
def test_token_lifecycle_and_scopes(client):
    with connect() as c:
        auth.set_admin_password(c, PASSWORD)
    client.post("/api/login", json={"password": PASSWORD}, headers=H)
    ro = client.post("/api/tokens", json={"name": "mcp", "scope": "read"}, headers=H).json()
    full = client.post("/api/tokens", json={"name": "ci", "scope": "full"}, headers=H).json()
    assert ro["token"].startswith("pl_") and len(ro["token"]) > 30
    listed = client.get("/api/tokens").json()
    assert {t["name"] for t in listed} == {"mcp", "ci"} and all("token" not in t and "token_hash" not in t for t in listed)

    with connect() as c:  # only the hash is stored
        stored = c.execute("SELECT token_hash, prefix FROM api_token WHERE id=%s", (ro["id"],)).fetchone()
    assert ro["token"] not in stored["token_hash"] and stored["token_hash"] == auth.sha256(ro["token"])

    client.cookies.clear()
    bearer = lambda t: {"Authorization": f"Bearer {t['token']}"}  # noqa: E731
    assert client.get("/api/incidents", headers=bearer(ro)).status_code == 200
    assert client.post("/api/simulator/baseline", headers=bearer(ro)).status_code == 403  # read-only cannot write
    assert client.get("/api/tokens", headers=bearer(ro)).status_code == 403
    assert client.post("/api/simulator/baseline", headers=bearer(full)).status_code == 200

    client.cookies.clear()
    client.post("/api/login", json={"password": PASSWORD}, headers=H)
    assert client.delete(f"/api/tokens/{ro['id']}", headers=H).status_code == 200
    assert client.delete(f"/api/tokens/{ro['id']}", headers=H).status_code == 404
    client.cookies.clear()
    assert client.get("/api/incidents", headers=bearer(ro)).status_code == 401  # revoked


def test_mcp_ignores_cookies_and_accepts_tokens(client):
    with connect() as c:
        auth.set_admin_password(c, PASSWORD)
    client.post("/api/login", json={"password": PASSWORD}, headers=H)
    assert client.post("/mcp/", json={}).status_code == 401  # a browser session is not an MCP credential
    tok = client.post("/api/tokens", json={"name": "m", "scope": "read"}, headers=H).json()["token"]
    client.cookies.clear()
    r = client.post("/mcp/", json={}, headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code != 401


def test_mcp_bare_path_does_not_redirect(client):
    with connect() as c:
        auth.set_admin_password(c, PASSWORD)
    client.post("/api/login", json={"password": PASSWORD}, headers=H)
    tok = client.post("/api/tokens", json={"name": "bare", "scope": "read"}, headers=H).json()["token"]
    client.cookies.clear()
    assert client.post("/mcp", json={}, follow_redirects=False).status_code == 401
    r = client.post("/mcp", json={}, headers={"Authorization": f"Bearer {tok}"}, follow_redirects=False)
    assert r.status_code not in (301, 302, 307, 308, 401)
