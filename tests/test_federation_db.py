"""PagerLens federated: people and services authenticate with the ecosystem identity provider, and roles decide what they may do."""
import os
import time
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

if not os.environ.get("TEST_DATABASE_URL"):
    pytest.skip("set TEST_DATABASE_URL to run DB tests", allow_module_level=True)

from apgkit.auth import Federation, RelyingParty, TokenVerifier  # noqa: E402
from joserfc import jwt  # noqa: E402
from joserfc.jwk import RSAKey  # noqa: E402

from pagerlens import api, core, mcp_server, migrate, vault  # noqa: E402
from pagerlens.db import connect  # noqa: E402

ISS, AUD = "https://id.example.org", "pagerlens"
KEY = RSAKey.generate_key(2048, {"kid": "k1", "use": "sig", "alg": "RS256"})
CSRF = {"X-PagerLens-CSRF": "1"}
OTLP = {"Content-Type": "application/json"}


class Provider:
    def __init__(self):
        self.nonce = None
        self.id_claims = {"sub": "usr_1", "name": "Ada", "email": "ada@example.org", "roles": ["pagerlens:responder"]}

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/.well-known/openid-configuration":
            return httpx.Response(200, json={"issuer": ISS, "jwks_uri": f"{ISS}/jwks", "authorization_endpoint": f"{ISS}/oauth/authorize",
                                             "token_endpoint": f"{ISS}/oauth/token", "end_session_endpoint": f"{ISS}/oauth/logout"})
        if path == "/jwks":
            return httpx.Response(200, json={"keys": [KEY.as_dict(private=False)]})
        if path == "/oauth/token":
            claims = {"iss": ISS, "aud": AUD, "exp": int(time.time()) + 300, "nonce": self.nonce, **self.id_claims}
            return httpx.Response(200, json={"id_token": jwt.encode({"alg": "RS256", "kid": "k1"}, claims, KEY), "access_token": "x"})
        return httpx.Response(404)

    def http(self):
        return lambda: httpx.Client(transport=httpx.MockTransport(self.handler), follow_redirects=False)


def access(**claims) -> dict:
    base = {"iss": ISS, "aud": AUD, "sub": "usr_1", "exp": int(time.time()) + 600, "sub_type": "user"}
    base.update(claims)
    return {"Authorization": "Bearer " + jwt.encode({"alg": "RS256", "kid": "k1", "typ": "at+jwt"}, base, KEY)}


def service(scope: str, sub: str = "svc") -> dict:
    return access(sub=sub, sub_type="service", scope=scope, client_id=sub)


ADMIN, RESPONDER, VIEWER, STRANGER = (access(sub="u_admin", roles=["pagerlens:admin"]), access(sub="u_resp", roles=["pagerlens:responder"]),
                                      access(sub="u_view", roles=["pagerlens:viewer"]), access(sub="u_x", roles=["otherapp:admin"]))


@pytest.fixture(autouse=True)
def _federated(monkeypatch, client):
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    for v in ("PAGERLENS_API_KEY", "PAGERLENS_ALLOW_ANONYMOUS", "PAGERLENS_ENCRYPTION_KEY", "LLM_BASE_URL"):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setenv("PAGERLENS_API_KEY_FILE", "/nonexistent/key")
    monkeypatch.setenv("PAGERLENS_ENCRYPTION_KEY_FILE", "/nonexistent/key")
    core.auth.limiter.clear()
    core.local._setup_code = None
    api._announced = False
    api._auto_unlock_tried = False
    vault.lock()
    client.cookies.clear()
    with connect() as c:
        c.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public")
        c.commit()
    migrate.run()
    provider = Provider()
    verifier = TokenVerifier(ISS, AUD, http=provider.http())
    monkeypatch.setattr(core.auth, "verifier", verifier)
    monkeypatch.setattr(api, "fed", Federation(ISS, AUD, verifier, RelyingParty(ISS, AUD, None, http=provider.http()), True))
    client.provider = provider
    yield


def incident(client) -> int:
    r = client.post("/api/simulator/trigger", headers=ADMIN, json={"scenario": "bad_deploy"})
    assert r.status_code == 200, r.text
    return r.json()["incident_id"]


def test_roles_decide_what_a_person_may_do(client):
    iid = incident(client)
    for who in (RESPONDER, VIEWER, ADMIN):
        assert client.get("/api/dashboard", headers=who).status_code == 200
        assert client.get(f"/api/incidents/{iid}", headers=who).status_code == 200
        assert client.get("/api/runbooks", headers=who).status_code == 200
    assert client.get("/api/incidents", headers=STRANGER).status_code == 403                          # signed in, but no role in this app
    assert client.get("/api/dashboard", headers=STRANGER).status_code == 403
    # viewers read; they investigate and resolve nothing
    assert client.post(f"/api/incidents/{iid}/investigate", headers=VIEWER, json={"mode": "rules"}).status_code == 403
    assert client.post(f"/api/incidents/{iid}/notes", headers=VIEWER, json={"body": "x"}).status_code == 403
    assert client.post(f"/api/incidents/{iid}/resolve", headers=VIEWER, json={"category": "bad_deploy"}).status_code == 403
    assert client.get("/api/chat-accounts", headers=VIEWER).status_code == 403
    # responders do all of that, but administer and break nothing
    assert client.get("/api/chat-accounts", headers=RESPONDER).json() == {"accounts": []}
    assert client.post(f"/api/incidents/{iid}/investigate", headers=RESPONDER, json={"mode": "rules"}).status_code == 200
    assert client.post(f"/api/incidents/{iid}/notes", headers=RESPONDER, json={"body": "paged infra"}).status_code == 200
    for method, path in (("get", "/api/accounts"), ("get", "/api/tokens"), ("post", "/api/simulator/baseline"), ("post", "/api/simulator/trigger"),
                         ("post", "/api/ingest/logs"), ("get", "/metrics")):
        assert getattr(client, method)(path, headers=RESPONDER).status_code == 403, path
    assert client.get("/api/accounts", headers=ADMIN).status_code == 200
    assert client.post(f"/api/incidents/{iid}/resolve", headers=RESPONDER, json={"category": "bad_deploy", "note": "rolled back"}).status_code == 200


def test_notes_carry_the_name_of_the_signed_in_person(client):
    iid = incident(client)
    who = access(sub="u_resp", name="Ada Lovelace", roles=["pagerlens:responder"])
    assert client.post(f"/api/incidents/{iid}/notes", headers=who, json={"body": "looking"}).status_code == 200
    assert client.post(f"/api/incidents/{iid}/notes", headers=ADMIN, json={"body": "also"}).status_code == 200
    authors = {n["body"]: n["author"] for n in client.get(f"/api/incidents/{iid}", headers=who).json()["notes"]}
    assert authors == {"looking": "Ada Lovelace", "also": "u_admin"}


def test_service_scopes_are_exactly_what_they_say(client):
    iid = incident(client)
    ingest, read, scrape = service("pagerlens.ingest", "citypulse"), service("pagerlens.read", "kb-bot"), service("pagerlens.metrics", "prom")
    push = {"service": "web", "points": [{"name": "up", "value": 1}]}
    assert client.post("/api/ingest/metrics", headers=ingest, json=push).status_code == 200
    assert client.post("/api/ingest/alerts", headers=ingest, json={"service": "web", "name": "Down"}).status_code == 200
    assert client.post("/v1/logs", headers={**ingest, **OTLP}, content=b"{}").status_code != 403
    assert client.get("/api/dashboard", headers=ingest).status_code == 403                             # ingest reads nothing
    assert client.get(f"/api/incidents/{iid}", headers=ingest).status_code == 403
    assert client.get("/metrics", headers=ingest).status_code == 403
    assert client.post("/mcp", headers={"Accept": "application/json, text/event-stream", **ingest}, json={}).status_code == 403
    assert client.get("/api/dashboard", headers=read).status_code == 200
    assert client.get(f"/api/incidents/{iid}", headers=read).status_code == 200
    assert client.post("/api/ingest/metrics", headers=read, json=push).status_code == 403
    assert client.post(f"/api/incidents/{iid}/investigate", headers=read, json={}).status_code == 403
    assert client.get("/metrics", headers=scrape).status_code == 200 and b"pagerlens_open_incidents" in client.get("/metrics", headers=scrape).content
    assert client.get("/api/dashboard", headers=scrape).status_code == 403
    assert client.post("/api/ingest/metrics", headers=scrape, json=push).status_code == 403
    assert client.post("/mcp", headers={"Accept": "application/json, text/event-stream", **scrape}, json={}).status_code == 403
    assert client.get("/api/dashboard", headers=service("trustdesk.requests.write")).status_code == 403     # a scope of another app is no scope here


def test_local_token_scopes_keep_exactly_the_access_they_had(client):
    iid = incident(client)
    toks = {s: {"Authorization": "Bearer " + client.post("/api/tokens", headers=ADMIN, json={"name": s, "scope": s}).json()["token"]}
            for s in ("read", "ingest", "metrics", "full")}
    push = {"service": "web", "points": [{"name": "up", "value": 1}]}
    # an ingest-only token ingests, and does nothing else
    assert client.post("/api/ingest/metrics", headers=toks["ingest"], json=push).status_code == 200
    for method, path in (("get", "/api/dashboard"), ("get", "/api/incidents"), ("get", f"/api/incidents/{iid}"), ("get", "/metrics"), ("get", "/api/tokens"),
                         ("get", "/api/providers"), ("get", "/api/runbooks")):
        assert getattr(client, method)(path, headers=toks["ingest"]).status_code == 403, path
    assert client.post("/mcp", headers={"Accept": "application/json, text/event-stream", **toks["ingest"]}, json={}).status_code == 403
    # a metrics token scrapes, and does nothing else
    assert client.get("/metrics", headers=toks["metrics"]).status_code == 200
    assert client.get("/api/incidents", headers=toks["metrics"]).status_code == 403
    assert client.post("/api/ingest/metrics", headers=toks["metrics"], json=push).status_code == 403
    assert client.post("/mcp", headers={"Accept": "application/json, text/event-stream", **toks["metrics"]}, json={}).status_code == 403
    # a read token reads (incidents, dashboard, runbooks, presets, MCP) and writes nothing
    for path in ("/api/dashboard", "/api/incidents", f"/api/incidents/{iid}", "/api/runbooks", "/api/providers", "/api/simulator/scenarios", "/api/stats"):
        assert client.get(path, headers=toks["read"]).status_code == 200, path
    assert client.post("/mcp", headers={"Accept": "application/json, text/event-stream", **toks["read"]}, json={}).status_code != 403
    assert client.post("/api/ingest/metrics", headers=toks["read"], json=push).status_code == 403
    assert client.post("/api/simulator/baseline", headers=toks["read"]).status_code == 403
    assert client.get("/api/tokens", headers=toks["read"]).status_code == 403
    assert client.get("/metrics", headers=toks["read"]).status_code == 403
    # a full token does everything
    assert client.get("/api/tokens", headers=toks["full"]).status_code == 200
    assert client.post(f"/api/incidents/{iid}/investigate", headers=toks["full"], json={"mode": "rules"}).status_code == 200
    # tokens only exist with scopes this app knows
    assert client.post("/api/tokens", headers=ADMIN, json={"name": "x", "scope": "pagerlens.ingest"}).status_code == 422


def test_tokens_for_another_app_or_with_a_bad_signature_are_refused(client):
    assert client.get("/api/incidents", headers=access(aud="some-other-app", roles=["pagerlens:admin"])).status_code == 401
    assert client.get("/api/incidents", headers=access(exp=int(time.time()) - 3600, roles=["pagerlens:admin"])).status_code == 401
    assert client.get("/api/incidents", headers=access(iss="https://evil.example.org", roles=["pagerlens:admin"])).status_code == 401
    other = RSAKey.generate_key(2048, {"kid": "k1", "use": "sig", "alg": "RS256"})
    forged = {"Authorization": "Bearer " + jwt.encode({"alg": "RS256", "kid": "k1"}, {"iss": ISS, "aud": AUD, "sub": "x", "exp": int(time.time()) + 60,
                                                                                    "roles": ["pagerlens:admin"]}, other)}
    assert client.get("/api/incidents", headers=forged).status_code == 401
    assert client.post("/api/ingest/metrics", headers=forged, json={"service": "web", "points": []}).status_code == 401


def test_mcp_needs_the_mcp_permission_and_writes_need_their_own(client):
    h = {"Accept": "application/json, text/event-stream"}
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    for who in (VIEWER, RESPONDER, ADMIN):
        assert client.post("/mcp", headers={**h, **who}, json=body).status_code != 403
    assert client.post("/mcp", headers={**h, **STRANGER}, json=body).status_code == 403
    ctx = lambda who: SimpleNamespace(headers={k.lower(): v for k, v in who.items()})  # noqa: E731
    mcp_server._require(ctx(RESPONDER), "incidents:investigate")
    mcp_server._require(ctx(RESPONDER), "incidents:write")
    mcp_server._require(ctx(ADMIN), "incidents:write")
    for who in (VIEWER, STRANGER, service("pagerlens.read")):
        for perm in ("incidents:investigate", "incidents:write"):
            with pytest.raises(mcp_server.NeedsPermission):
                mcp_server._require(ctx(who), perm)


def test_single_sign_on_login_creates_a_role_bound_session(client):
    r = client.get("/auth/login", params={"next": "/#incidents"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith(f"{ISS}/oauth/authorize?")
    q = parse_qs(urlsplit(r.headers["location"]).query)
    assert q["code_challenge_method"] == ["S256"] and q["redirect_uri"] == ["http://testserver/auth/callback"] and q["client_id"] == [AUD]
    client.provider.nonce = q["nonce"][0]
    cb = client.get("/auth/callback", params={"code": "c", "state": q["state"][0]}, follow_redirects=False)
    assert cb.status_code == 303 and cb.headers["location"] == "/#incidents" and "pl_session" in cb.cookies
    s = client.get("/api/session").json()
    assert s["state"] == "logged_in" and s["user"]["name"] == "Ada" and s["user"]["roles"] == ["pagerlens:responder"] and s["user"]["source"] == "oidc"
    assert "incidents:investigate" in s["user"]["permissions"] and "settings:manage" not in s["user"]["permissions"]
    assert s["sso"]["login_url"] == "/auth/login" and s["sso"]["issuer"] == ISS
    assert client.get("/api/incidents").status_code == 200
    assert client.get("/api/accounts").status_code == 403                                           # a responder is not an administrator
    assert client.post("/api/simulator/baseline", headers=CSRF).status_code == 403
    assert client.post("/mcp", headers={"Accept": "application/json, text/event-stream"}, json={}).status_code == 401   # MCP never takes cookies
    out = client.post("/api/logout", headers=CSRF).json()
    assert out["logout_url"].startswith(f"{ISS}/oauth/logout?") and "id_token_hint=" in out["logout_url"]
    assert client.get("/api/incidents").status_code == 401


def test_sso_is_not_a_setup_flow_and_hides_the_password_login_only_on_request(client, monkeypatch):
    s = client.get("/api/session").json()
    assert s["state"] == "logged_out" and s["sso"]["issuer"] == ISS                                    # no setup code is asked for with SSO on
    monkeypatch.setattr(api, "fed", Federation(ISS, AUD, core.auth.verifier, None, False))
    assert client.get("/api/session").json()["state"] == "logged_out"


def test_sso_refuses_people_without_a_role_here_and_replayed_or_foreign_logins(client):
    client.provider.id_claims = {"sub": "usr_9", "name": "Nobody", "roles": ["otherapp:admin"]}
    r = client.get("/auth/login", follow_redirects=False)
    q = parse_qs(urlsplit(r.headers["location"]).query)
    client.provider.nonce = q["nonce"][0]
    cb = client.get("/auth/callback", params={"code": "c", "state": q["state"][0]}, follow_redirects=False)
    assert cb.headers["location"].startswith("/?sso_error=") and "pl_session" not in cb.cookies
    assert client.get("/api/incidents").status_code == 401
    again = client.get("/auth/callback", params={"code": "c", "state": q["state"][0]}, follow_redirects=False)
    assert again.headers["location"].startswith("/?sso_error=")                                      # the state was single-use
    assert client.get("/auth/callback", params={"error": "access_denied"}, follow_redirects=False).headers["location"].startswith("/?sso_error=")


def test_a_federated_session_ends_when_sessions_are_cleared(client):
    r = client.get("/auth/login", follow_redirects=False)
    q = parse_qs(urlsplit(r.headers["location"]).query)
    client.provider.nonce = q["nonce"][0]
    client.get("/auth/callback", params={"code": "c", "state": q["state"][0]}, follow_redirects=False)
    assert client.get("/api/incidents").status_code == 200
    with connect() as c:
        c.execute("DELETE FROM web_session")
        c.commit()
    assert client.get("/api/incidents").status_code == 401


def test_sso_endpoints_are_404_when_federation_is_off(client, monkeypatch):
    monkeypatch.setattr(api, "fed", Federation("", AUD, None, None, True))
    assert client.get("/auth/login", follow_redirects=False).status_code == 404
    assert client.get("/auth/callback", follow_redirects=False).status_code == 404
    assert client.get("/api/session").json()["sso"] is None


def test_with_sso_only_the_vault_is_created_from_the_platform_secret(monkeypatch):
    monkeypatch.setenv("PAGERLENS_ENCRYPTION_KEY", "platform-managed-secret")  # pragma: allowlist secret
    with connect() as c:
        assert not vault.is_initialized(c)
    api._startup_tasks()
    assert vault.is_unlocked()
    token = vault.encrypt("sk-secret-value")
    vault.lock()
    with connect() as c:
        assert vault.is_initialized(c) and vault.try_unlock_with_platform_secret(c)
    assert vault.decrypt(token) == "sk-secret-value"


def test_a_callback_from_a_browser_that_did_not_start_the_login_is_refused(client):
    r = client.get("/auth/login", follow_redirects=False)
    assert "apg_oidc_bind" in r.headers.get("set-cookie", "")
    q = parse_qs(urlsplit(r.headers["location"]).query)
    client.provider.nonce = q["nonce"][0]
    client.cookies.clear()                                                                            # another browser: no binding cookie
    cb = client.get("/auth/callback", params={"code": "c", "state": q["state"][0]}, follow_redirects=False)
    assert cb.headers["location"].startswith("/?sso_error=") and "pl_session" not in cb.cookies
    assert client.get("/api/incidents").status_code == 401


def test_a_callback_with_the_wrong_binding_cookie_is_refused_and_the_state_is_burnt(client):
    r = client.get("/auth/login", follow_redirects=False)
    q = parse_qs(urlsplit(r.headers["location"]).query)
    client.provider.nonce = q["nonce"][0]
    client.cookies.clear()
    client.cookies.set("apg_oidc_bind", "not-the-binding")
    cb = client.get("/auth/callback", params={"code": "c", "state": q["state"][0]}, follow_redirects=False)
    assert cb.headers["location"].startswith("/?sso_error=") and "pl_session" not in cb.cookies
    assert client.get("/api/incidents").status_code == 401


def test_the_binding_cookie_is_cleared_after_a_successful_callback(client):
    r = client.get("/auth/login", follow_redirects=False)
    q = parse_qs(urlsplit(r.headers["location"]).query)
    client.provider.nonce = q["nonce"][0]
    cb = client.get("/auth/callback", params={"code": "c", "state": q["state"][0]}, follow_redirects=False)
    assert cb.status_code == 303 and any("apg_oidc_bind" in v for v in cb.headers.get_list("set-cookie"))
    assert "apg_oidc_bind" not in client.cookies
