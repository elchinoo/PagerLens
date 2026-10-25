import contextlib
import sys
import time
from pathlib import Path

import psycopg
from apgkit.auth.rp import safe_return_to
from apgkit.config import env_bool
from apgkit.guard import SecurityGuard
from apgkit.web import is_https, mount_kit_static, public_url
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import (
    __version__,
    accounts,
    core,
    dashboard,
    embedcfg,
    housekeeping,
    incidents,
    ingest,
    investigator,
    metrics,
    migrate,
    otlp,
    simulator,
    vault,
)
from . import chat as chatter
from .core import COOKIE, CSRF_HEADER, auth, fed, local
from .db import connect, connect_vector
from .embeddings import embed as embed_texts
from .llm_http import LLMError, empty_answer_error
from .mcp_server import mcp
from .netguard import UnsafeURL
from .tools import ToolError

STATIC = Path(__file__).resolve().parent / "static"
MAX_BODY = 2 * 1024 * 1024

mcp_app = mcp.streamable_http_app(streamable_http_path="/", host="0.0.0.0")


_announced = False
_auto_unlock_tried = False


def _announce_setup_code() -> None:
    """Print the one-time setup code to the server log (once per process)."""
    global _announced
    if not _announced:
        _announced = True
        print("\n=== PagerLens first-run setup ===\n"
              f"Open the app in your browser and enter this one-time code to create the admin password:\n"
              f"    {local.setup_code()}\n"
              "(It changes every time the server restarts until setup is complete.)\n", file=sys.stderr, flush=True)


def _startup_tasks() -> None:
    """Best effort: unlock the vault with a platform secret and announce the setup code. Never blocks startup."""
    global _auto_unlock_tried
    try:
        with connect(retries=1) as conn:
            _auto_unlock_tried = True
            if fed.enabled and not vault.is_initialized(conn):
                core.vault.initialize_with_platform_secret(conn)   # single sign-on only: no admin password to wrap the key with
                conn.commit()
            vault.try_unlock_with_platform_secret(conn)
            if local.needs_setup(conn) and not fed.enabled:
                _announce_setup_code()
    except Exception:  # noqa: BLE001 - database may be asleep; it is retried on the first request
        pass


@contextlib.asynccontextmanager
async def lifespan(_: FastAPI):
    _startup_tasks()
    housekeeping.start_background()
    try:
        async with mcp_app.router.lifespan_context(mcp_app):
            yield
    finally:
        housekeeping.stop_background()


# --- authentication ---------------------------------------------------------------------------------------
# Fail closed: with no credential configured every protected route is denied (and the setup flow is offered), unless
# the operator explicitly sets PAGERLENS_ALLOW_ANONYMOUS=true. The mechanics (local admin, API tokens, federated JWTs,
# sessions, rate limiting) are agentpg-kit's `Authenticator`; here we only name the permission each route needs.

def authenticate(request: Request, *, allow_cookie: bool = True):
    return auth.authenticate(request, allow_cookie=allow_cookie)


def require(permission: str):
    """Dependency: the caller must hold `permission` (see core.PERMISSIONS). Holders of `*` (an admin, a full token, the static
    key) pass everything; a read token holds the read permissions, an ingest token only `ingest:write`, and so on."""
    return auth.require(permission)


def _client(request: Request) -> str:
    return auth.client(request)


def _db_unavailable() -> HTTPException:
    return auth.db_unavailable()


class McpGuard:
    """MCP never accepts browser cookies; the credential must carry `mcp:use` (a read or full token, or a federated user or
    service allowed to). Telemetry-only (ingest, metrics) credentials are refused. The tools that change state check their own
    permission again (see mcp_server)."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not scope["path"].startswith("/mcp"):
            return await self.app(scope, receive, send)
        if scope["path"] == "/mcp":
            # Serve the bare path directly: the mount would answer with a redirect, and behind a TLS-terminating proxy that
            # redirect can point at http://, where clients (rightly) drop the Authorization header.
            scope["path"] = scope["raw_path"] = "/mcp/"
        request = Request(scope, receive)
        try:
            principal = auth.authenticate(request, allow_cookie=False)
        except HTTPException as exc:
            return await JSONResponse({"error": exc.detail}, status_code=exc.status_code)(scope, receive, send)
        if principal is None:
            return await JSONResponse({"error": "authentication required"}, status_code=401)(scope, receive, send)
        if not principal.can("mcp:use"):
            return await JSONResponse({"error": "this credential cannot use MCP"}, status_code=403)(scope, receive, send)
        await self.app(scope, receive, send)


# Interactive API docs load scripts from a CDN and expose the schema; keep them off.
app = FastAPI(title="PagerLens", version=__version__, lifespan=lifespan,
              docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(McpGuard)
app.add_middleware(SecurityGuard, csrf_header=CSRF_HEADER, csrf_prefixes=("/api/",), body_prefixes=("/api/", "/v1/"), max_body=MAX_BODY,
                   observe=core.metrics.observe)
app.mount("/mcp", mcp_app)
app.mount("/static", StaticFiles(directory=STATIC), name="static")
mount_kit_static(app)



@contextlib.contextmanager
def _translate():
    """Map domain failures to honest HTTP statuses without leaking internals or secrets."""
    try:
        yield
    except vault.VaultLocked as exc:
        raise HTTPException(423, str(exc)) from exc  # 423 Locked: sign in / unlock to continue
    except vault.VaultError as exc:
        raise HTTPException(409, str(exc)) from exc
    except incidents.NotFound as exc:
        raise HTTPException(404, str(exc)) from exc
    except (accounts.AccountError, UnsafeURL, ingest.IngestError, ToolError, ValueError) as exc:
        raise HTTPException(422, str(exc)) from exc
    except LLMError as exc:
        raise HTTPException(502, str(exc)) from exc


@app.get("/healthz")
def healthz():
    return {"status": "ok", "version": __version__}


@app.get("/readyz")
def readyz():
    try:
        with connect(retries=1) as conn:
            conn.execute("SELECT 1")
        return {"status": "ready"}
    except Exception:  # noqa: BLE001 - database may be waking; never echo connection details
        return JSONResponse({"status": "waking-database"}, status_code=503)


# --- session, setup, login, tokens ----------------------------------------------------------

class SetupBody(BaseModel):
    code: str = Field(max_length=64)
    password: str = Field(max_length=256)


class LoginBody(BaseModel):
    password: str | None = Field(default=None, max_length=256)
    api_key: str | None = Field(default=None, max_length=512)


class UnlockBody(BaseModel):
    password: str = Field(max_length=256)


class PasswordBody(BaseModel):
    current: str | None = Field(default=None, max_length=256)
    new: str = Field(max_length=256)


class TokenBody(BaseModel):
    name: str = Field(min_length=1, max_length=60)
    scope: str = Field(pattern="^(read|ingest|metrics|full)$")


def _start_session(conn, request: Request, response: Response, **who) -> None:
    raw = local.create_session(conn, **who)
    response.set_cookie(COOKIE, raw, httponly=True, samesite="strict" if not who else "lax", secure=is_https(request),
                        max_age=12 * 3600, path="/")


def _guard_attempts(request: Request) -> str:
    client = auth.client(request)
    if auth.limiter.limited(client):
        raise HTTPException(429, "too many failed attempts; wait a minute")
    return client


@app.get("/api/session")
def session_state(request: Request):
    """Public: tells the UI which screen to show. Reveals no secrets."""
    global _auto_unlock_tried
    principal = None
    try:
        principal = authenticate(request)
        with connect(retries=1) as conn:
            if not _auto_unlock_tried:
                _auto_unlock_tried = True
                vault.try_unlock_with_platform_secret(conn)
            setup = local.needs_setup(conn) and not env_bool("PAGERLENS_ALLOW_ANONYMOUS") and not fed.enabled
            v = vault.status(conn)
            has_password = local.admin_configured(conn)
    except HTTPException:
        raise
    except (psycopg.Error, RuntimeError) as exc:
        raise _db_unavailable() from exc
    if setup:
        _announce_setup_code()
    state = "setup_required" if setup else "logged_in" if principal else "logged_out"
    out = {"state": state, "vault": v, "has_admin_password": has_password,
           "password_login": has_password and (fed.local_login or not fed.enabled), "key_login": local.static_key_configured() and (fed.local_login or not fed.enabled),
           "sso": {"issuer": fed.issuer, "login_url": "/auth/login"} if fed.enabled else None}
    if principal:
        out["user"] = {"name": principal.name, "email": principal.email, "source": principal.source, "roles": sorted(principal.roles),
                       "permissions": ["*"] if "*" in principal.permissions else sorted(principal.permissions)}
    return out


# ---- federated sign-in (only when PAGERLENS_OIDC_ISSUER is set) ----------------------------------------------
@app.get("/auth/login")
def sso_login(request: Request, next: str | None = None):
    if not fed.enabled:
        raise HTTPException(404, "single sign-on is not configured")
    try:
        with connect(retries=1) as conn:
            url = fed.rp.begin(conn, public_url(request, core.public_url_env) + "/auth/callback", next)
    except psycopg.Error as exc:
        raise _db_unavailable() from exc
    except Exception:  # noqa: BLE001 - the identity provider may be unreachable
        return RedirectResponse("/?sso_error=the identity provider is unavailable", status_code=303)
    return RedirectResponse(url, status_code=303)


@app.get("/auth/callback")
def sso_callback(request: Request, code: str = "", state: str = "", error: str = ""):
    if not fed.enabled:
        raise HTTPException(404, "single sign-on is not configured")
    if error or not code or not state:
        return RedirectResponse("/?sso_error=the sign-in was cancelled or failed", status_code=303)
    from apgkit.auth import TokenError
    try:
        with connect(retries=1) as conn:
            claims, back, id_token = fed.rp.finish(conn, public_url(request, core.public_url_env) + "/auth/callback", code, state)
            roles = [r for r in claims.get("roles", []) if isinstance(r, str)]
            resp = RedirectResponse(safe_return_to(back), status_code=303)
            if not core.APP_AUTH.permissions_for(roles=roles):
                return RedirectResponse("/?sso_error=your account has no role in PagerLens; ask an administrator", status_code=303)
            _start_session(conn, request, resp, subject=str(claims["sub"]), name=str(claims.get("name") or ""), email=str(claims.get("email") or ""),
                           roles=roles, source="oidc", id_token_hint=id_token)
            return resp
    except TokenError as exc:
        return RedirectResponse("/?sso_error=" + str(exc)[:120], status_code=303)


@app.post("/api/setup")
def setup(body: SetupBody, request: Request, response: Response):
    client = _guard_attempts(request)
    try:
        with connect(retries=1) as conn:
            try:
                local.complete_setup(conn, body.code, body.password)
            except PermissionError as exc:
                auth.limiter.record(client)
                raise HTTPException(403, str(exc)) from exc
            except ValueError as exc:
                raise HTTPException(422, str(exc)) from exc
            _start_session(conn, request, response)
    except (psycopg.Error, RuntimeError) as exc:
        raise _db_unavailable() from exc
    return {"ok": True}


@app.post("/api/login")
def login(body: LoginBody, request: Request, response: Response):
    client = _guard_attempts(request)
    try:
        with connect(retries=1) as conn:
            ok = False
            if body.password is not None:
                ok = local.login_password(conn, body.password)
            elif body.api_key is not None and local.static_key_matches(body.api_key):
                ok = True
                vault.try_unlock_with_platform_secret(conn)
            if not ok:
                auth.limiter.record(client)
                raise HTTPException(401, "invalid credentials")
            _start_session(conn, request, response)
    except (psycopg.Error, RuntimeError) as exc:
        raise _db_unavailable() from exc
    return {"ok": True}


@app.post("/api/logout")
def logout(request: Request, response: Response):
    out: dict = {"ok": True}
    try:
        with connect(retries=1) as conn:
            row = local.delete_session(conn, request.cookies.get(COOKIE))
        if row and row["source"] == "oidc" and fed.enabled:
            with contextlib.suppress(Exception):
                out["logout_url"] = fed.rp.logout_url(row["id_token_hint"], public_url(request, core.public_url_env) + "/")
    except (psycopg.Error, RuntimeError):
        pass  # the cookie is cleared regardless; the session row expires on its own
    response.delete_cookie(COOKIE, path="/")
    return out


@app.post("/api/vault/unlock", dependencies=[Depends(require("settings:manage"))])
def unlock_vault(body: UnlockBody, request: Request):
    client = _guard_attempts(request)
    with connect() as conn:
        if not vault.is_initialized(conn):
            raise HTTPException(409, "no provider keys are stored yet; set an admin password first")
        if not vault.unlock_with_password(conn, body.password):
            auth.limiter.record(client)
            raise HTTPException(403, "wrong password")  # 403, not 401: the session itself is still valid
        conn.commit()
    return {"ok": True}


@app.post("/api/admin-password", dependencies=[Depends(require("settings:manage"))])
def admin_password(body: PasswordBody, request: Request):
    """Set the admin password (first time, when signed in with a static key) or change it."""
    client = _guard_attempts(request)
    with connect() as conn:
        try:
            if local.admin_configured(conn):
                if body.current is None:
                    raise HTTPException(422, "current password is required")
                local.change_password(conn, body.current, body.new)
            else:
                local.set_admin_password(conn, body.new)
        except PermissionError as exc:
            auth.limiter.record(client)
            raise HTTPException(403, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        conn.execute("DELETE FROM web_session")  # sign every browser out after a password change
        conn.commit()
    return {"ok": True, "signed_out_everywhere": True}


@app.get("/api/tokens", dependencies=[Depends(require("settings:manage"))])
def list_tokens():
    with connect() as conn:
        return local.list_tokens(conn)


@app.post("/api/tokens", dependencies=[Depends(require("settings:manage"))])
def create_token(body: TokenBody):
    """The token value is returned exactly once; only its hash is stored."""
    with connect() as conn:
        token_id, raw = local.create_token(conn, body.name.strip(), body.scope)
    return {"id": token_id, "token": raw, "scope": body.scope, "name": body.name.strip()}


@app.delete("/api/tokens/{token_id}", dependencies=[Depends(require("settings:manage"))])
def revoke_token(token_id: int):
    with connect() as conn:
        if not local.revoke_token(conn, token_id):
            raise HTTPException(404, "token not found or already revoked")
    return {"revoked": token_id}


# --- provider accounts, embeddings, ask ------------------------------------------------------------

class AccountBody(BaseModel):
    name: str = Field(min_length=1, max_length=60)
    provider: str = Field(default="custom", max_length=20)
    base_url: str = Field(max_length=300)
    api_key: str | None = Field(default=None, max_length=512)
    clear_key: bool = False
    chat_model: str | None = Field(default=None, max_length=120)
    embedding_model: str | None = Field(default=None, max_length=120)
    embedding_dim: int | None = Field(default=None, ge=8, le=2000)


class TestBody(BaseModel):
    target: str = Field(pattern="^(chat|embeddings)$")


def _ref(value: str) -> int | str:
    return value if value == "env" else int(value)


@app.get("/api/providers", dependencies=[Depends(require("dashboard:read"))])
def providers():
    """A static list of presets (no secrets): any read credential may fetch it, as before."""
    return accounts.PRESETS


@app.get("/api/chat-accounts", dependencies=[Depends(require("incidents:investigate"))])
def chat_accounts():
    """The accounts an investigation can use, without the settings the administrator manages: just id, name and model."""
    with connect() as conn:
        found = [*accounts.list_accounts(conn), *([accounts.env_account()] if accounts.env_account() else [])]
    return {"accounts": [{"id": a["id"], "name": a["name"], "chat_model": a["chat_model"]} for a in found if a["chat_model"]]}


@app.get("/api/accounts", dependencies=[Depends(require("settings:manage"))])
def list_accounts():
    with connect() as conn:
        embedcfg.ensure_loaded(conn)
        return {"accounts": accounts.list_accounts(conn), "env": accounts.env_account(),
                "vault": vault.status(conn), "active_embedding": accounts.active_embedding_ref(conn)}


@app.post("/api/accounts", dependencies=[Depends(require("settings:manage"))])
def create_account(body: AccountBody):
    with _translate(), connect() as conn:
        new_id = accounts.create(conn, name=body.name, provider=body.provider, base_url=body.base_url,
                                 api_key=body.api_key, chat_model=body.chat_model,
                                 embedding_model=body.embedding_model, embedding_dim=body.embedding_dim)
        return accounts.get_account(conn, new_id)


@app.put("/api/accounts/{account_id}", dependencies=[Depends(require("settings:manage"))])
def update_account(account_id: int, body: AccountBody):
    with _translate(), connect() as conn:
        accounts.update(conn, account_id, name=body.name, provider=body.provider, base_url=body.base_url,
                        api_key=body.api_key, clear_key=body.clear_key, chat_model=body.chat_model,
                        embedding_model=body.embedding_model, embedding_dim=body.embedding_dim)
        return accounts.get_account(conn, account_id)


@app.delete("/api/accounts/{account_id}", dependencies=[Depends(require("settings:manage"))])
def delete_account(account_id: int):
    with _translate(), connect() as conn:
        embedcfg.ensure_loaded(conn)
        accounts.delete(conn, account_id)
    return {"deleted": account_id}


@app.post("/api/accounts/{account}/test", dependencies=[Depends(require("settings:manage"))])
def test_account(account: str, body: TestBody):
    """Make one tiny real call to the provider so mistakes (URL, key, model name) show up immediately."""
    if account != "env" and not account.isdigit():
        raise HTTPException(422, "invalid account")
    started = time.monotonic()
    with _translate(), connect() as conn:
        if body.target == "chat":
            reply = chatter.chat(accounts.chat_config_for(conn, _ref(account)),
                               [{"role": "user", "content": "Reply with the single word OK. Keep any reasoning very short."}], max_tokens=64)
            if not reply["text"]:
                raise empty_answer_error(reply.get("response"), 64)
            detail = {"reply": reply["text"][:60]}
        else:
            cfg = (embedcfg.from_env() if account == "env" else accounts.embedding_config_for(conn, int(account)))
            vec = embed_texts(["connection test"], cfg)[0]
            detail = {"dimensions": len(vec), "model": cfg.model}
    return {"ok": True, "ms": int((time.monotonic() - started) * 1000), **detail}



@app.get("/api/embeddings/status", dependencies=[Depends(require("settings:manage"))])
def embeddings_status():
    """Configured vs stored vector size, rows still lacking a vector and the background job: 'needs re-embedding' lives here."""
    with connect_vector() as conn:
        return migrate.embedding_status(conn)


@app.post("/api/embeddings/reembed", dependencies=[Depends(require("settings:manage"))])
def reembed_embeddings():
    """Resize the vector columns to EMBEDDING_DIM if needed and re-embed every incident and runbook in the background."""
    with connect_vector() as conn:
        st = migrate.embedding_status(conn)
    if not st["indexable"]:
        raise HTTPException(422, f"{st['configured']['dimension']} dimensions cannot be indexed (limit {migrate.MAX_HNSW_DIM})")
    if not migrate.start_reembed_job():
        raise HTTPException(409, "a re-embedding job is already running")
    return {"started": True}


# --- ingest: write-only for 'ingest' tokens -------------------------------------------------------

class LogsBody(BaseModel):
    service: str = Field(max_length=63)
    events: list[dict] = Field(max_length=ingest.MAX_BATCH)


class MetricsBody(BaseModel):
    service: str = Field(max_length=63)
    points: list[dict] = Field(max_length=ingest.MAX_BATCH)


class DeployBody(BaseModel):
    service: str = Field(max_length=63)
    version: str = Field(max_length=80)
    git_sha: str | None = Field(default=None, max_length=64)
    author: str | None = Field(default=None, max_length=80)
    summary: str | None = Field(default=None, max_length=300)
    ts: str | float | None = None


class ServiceBody(BaseModel):
    name: str = Field(max_length=63)
    owner: str | None = Field(default=None, max_length=80)
    tier: str | None = Field(default=None, max_length=40)
    description: str | None = Field(default=None, max_length=300)
    depends_on: list[str] | None = Field(default=None, max_length=20)


class AlertBody(BaseModel):
    service: str = Field(max_length=63)
    name: str = Field(min_length=1, max_length=200)
    summary: str | None = Field(default=None, max_length=500)
    severity: str = Field(default="sev3", max_length=10)
    labels: dict | None = None
    source: str = Field(default="webhook", max_length=40)
    investigate: bool = False


@app.post("/api/ingest/logs", dependencies=[Depends(require("ingest:write"))])
def ingest_logs(body: LogsBody):
    with _translate(), connect() as conn:
        n = ingest.ingest_logs(conn, body.service, body.events)
        conn.commit()
    metrics.INGESTED.labels("logs").inc(n)
    return {"accepted": n}


@app.post("/api/ingest/metrics", dependencies=[Depends(require("ingest:write"))])
def ingest_metrics(body: MetricsBody):
    with _translate(), connect() as conn:
        n = ingest.ingest_metrics(conn, body.service, body.points)
        conn.commit()
    metrics.INGESTED.labels("metrics").inc(n)
    return {"accepted": n}


@app.post("/api/ingest/deploys", dependencies=[Depends(require("ingest:write"))])
def ingest_deploy(body: DeployBody):
    with _translate(), connect() as conn:
        deploy_id = ingest.ingest_deploy(conn, body.service, body.model_dump())
        conn.commit()
    return {"id": deploy_id}


@app.post("/api/ingest/services", dependencies=[Depends(require("ingest:write"))])
def ingest_service(body: ServiceBody):
    with _translate(), connect() as conn:
        sid = ingest.upsert_service(conn, body.name, owner=body.owner, tier=body.tier, description=body.description,
                                    depends_on=body.depends_on)
        conn.commit()
    return {"id": sid}


@app.post("/api/ingest/alerts", dependencies=[Depends(require("ingest:write"))])
def ingest_alert(body: AlertBody):
    """Generic alert webhook: opens or joins an incident. An ingest token cannot start an investigation."""
    with _translate(), connect_vector() as conn:
        result = ingest.raise_alert(conn, body.service, body.name, summary=body.summary, severity=body.severity,
                                    labels=body.labels, source=body.source)
        conn.commit()
    return result


# --- incidents, investigation, learning ---------------------------------------------------------

class InvestigateBody(BaseModel):
    mode: str = Field(default="rules", pattern="^(rules|llm|hybrid)$")
    use_memory: bool = True
    account: str | None = Field(default=None, pattern=r"^(env|\d{1,12})$")


class ResolveBody(BaseModel):
    category: str = Field(max_length=40)
    note: str | None = Field(default=None, max_length=1000)


class NoteBody(BaseModel):
    body: str = Field(min_length=1, max_length=4000)


# --- OTLP/HTTP receiver and Prometheus metrics ---------------------------------------------------------------

async def _read_capped(request: Request) -> bytes:
    data = bytearray()
    async for chunk in request.stream():
        data += chunk
        if len(data) > MAX_BODY:
            raise HTTPException(413, "request body too large (2 MB limit)")
    return bytes(data)


async def _otlp(request: Request, kind: str):
    raw = await _read_capped(request)
    protobuf = "protobuf" in request.headers.get("content-type", "").lower()
    try:
        data = otlp.decode(raw, request.headers.get("content-type", ""), request.headers.get("content-encoding", "").lower(),
                           otlp.REQUESTS[kind])
        if kind == "traces":
            count = sum(len(ss.get("spans") or []) for rs in data.get("resourceSpans") or [] for ss in rs.get("scopeSpans") or [])
            accepted, rejected, note = 0, count, "traces are acknowledged but not stored in this version"
        else:
            with connect() as conn:
                accepted, rejected = (otlp.store_logs if kind == "logs" else otlp.store_metrics)(conn, data)
                conn.commit()
            note = "some items were not stored (missing service.name, bad metric name or type)"
    except otlp.OtlpError as exc:
        raise HTTPException(400, str(exc)) from exc
    except (ingest.IngestError, psycopg.Error, RuntimeError) as exc:
        if isinstance(exc, ingest.IngestError):
            raise HTTPException(400, str(exc)) from exc
        raise _db_unavailable() from exc
    if kind != "traces":
        metrics.INGESTED.labels(f"otlp_{kind}").inc(accepted)
    body, ctype = otlp.ack(kind, rejected, note, protobuf)
    return Response(body, media_type=ctype)


@app.post("/v1/logs", dependencies=[Depends(require("ingest:write"))])
async def otlp_logs(request: Request):
    return await _otlp(request, "logs")


@app.post("/v1/metrics", dependencies=[Depends(require("ingest:write"))])
async def otlp_metrics(request: Request):
    return await _otlp(request, "metrics")


@app.post("/v1/traces", dependencies=[Depends(require("ingest:write"))])
async def otlp_traces(request: Request):
    return await _otlp(request, "traces")


@app.get("/metrics", dependencies=[Depends(require("metrics:scrape"))])
def prometheus_metrics():
    body, ctype = metrics.render()
    return Response(body, media_type=ctype)


@app.get("/api/fleet", dependencies=[Depends(require("dashboard:read"))])
def get_fleet():
    with connect() as conn:
        return {"services": incidents.fleet(conn)}


@app.get("/api/dashboard", dependencies=[Depends(require("dashboard:read"))])
def get_dashboard():
    """Every monitored service with its verdict and sparklines (see dashboard.py)."""
    with _translate(), connect() as conn:
        return dashboard.overview(conn, housekeeping.settings(conn)["stale_after_minutes"])


@app.get("/api/services/{name}", dependencies=[Depends(require("dashboard:read"))])
def get_service(name: str, minutes: int = Query(60, ge=5, le=1440)):
    if not ingest.NAME.match(name):
        raise HTTPException(404, "no such service")
    with _translate(), connect() as conn:
        detail = dashboard.service_detail(conn, name, minutes, housekeeping.settings(conn)["stale_after_minutes"])
    if detail is None:
        raise HTTPException(404, "no such service")
    return detail


class RetireBody(BaseModel):
    confirm: str = Field(max_length=63)


@app.post("/api/services/{name}/retire")
def retire_service(name: str, body: RetireBody, principal=Depends(require("services:retire"))):
    """Delete a service with its metric points, log events, deploys and dependency edges; resolve its open incidents as
    `service retired` without teaching the memory. `confirm` must repeat the service name. Telemetry sent later for the
    same name creates the service again."""
    if not ingest.NAME.match(name):
        raise HTTPException(404, "no such service")
    if body.confirm != name:
        raise HTTPException(422, "confirm must be the exact name of the service")
    actor = principal.actor if principal.source == "oidc" else "operator"
    with _translate(), connect() as conn:
        result = housekeeping.retire_service(conn, name, actor=actor)
        conn.commit()
    return result


class HousekeepingBody(BaseModel):
    auto_resolve_minutes: int | None = None
    stale_after_minutes: int | None = None


@app.get("/api/settings/housekeeping", dependencies=[Depends(require("settings:manage"))])
def get_housekeeping():
    with connect() as conn:
        return {**housekeeping.settings(conn), "limits": housekeeping.LIMITS, "min_stale": housekeeping.MIN_STALE}


@app.put("/api/settings/housekeeping", dependencies=[Depends(require("settings:manage"))])
def put_housekeeping(body: HousekeepingBody):
    with _translate(), connect() as conn:
        saved = housekeeping.save_settings(conn, body.model_dump())
        conn.commit()
    return saved


@app.get("/api/incidents", dependencies=[Depends(require("incidents:read"))])
def list_incidents(status: str | None = Query(None, pattern="^(open|investigating|resolved)$"),
                   service: str | None = Query(None, max_length=63), limit: int = Query(50, ge=1, le=200)):
    with connect() as conn:
        return {"incidents": incidents.list_incidents(conn, status=status, limit=limit, service=service),
                "total": incidents.count_incidents(conn, status=status, service=service)}


class BulkResolveBody(BaseModel):
    reason: str = Field(min_length=1, max_length=500)
    confirm: bool = False
    ids: list[int] | None = Field(default=None, max_length=housekeeping.MAX_BULK)
    status: str | None = Field(default=None, pattern="^(open|investigating)$")
    service: str | None = Field(default=None, max_length=63)
    all_matching: bool = False


@app.post("/api/incidents/bulk-resolve")
def bulk_resolve_incidents(body: BulkResolveBody, principal=Depends(require("incidents:write"))):
    """Resolve the selected incidents (`ids`), or every unresolved one matching `status`/`service` (`all_matching: true`),
    with a reason and no cause, so the memory learns nothing. Refused unless `confirm` is true."""
    if not body.confirm:
        raise HTTPException(422, "confirm must be true: bulk resolution closes every matching incident")
    if body.ids is None and not body.all_matching:
        raise HTTPException(422, "send the ids to resolve, or all_matching: true with an optional status and service filter")
    if body.ids is not None and (body.all_matching or body.status or body.service):
        raise HTTPException(422, "send either ids or a filter, not both")
    actor = principal.actor if principal.source == "oidc" else "operator"
    with _translate(), connect() as conn:
        result = housekeeping.bulk_resolve(conn, body.reason, ids=body.ids, actor=actor,
                                           match=None if body.ids is not None else {"status": body.status, "service": body.service})
        conn.commit()
    return result


@app.get("/api/incidents/{incident_id}", dependencies=[Depends(require("incidents:read"))])
def get_incident(incident_id: int):
    with _translate(), connect() as conn:
        return incidents.get_incident(conn, incident_id)


@app.post("/api/incidents/{incident_id}/investigate", dependencies=[Depends(require("incidents:investigate"))])
def investigate(incident_id: int, body: InvestigateBody):
    """rules: deterministic. llm: a model drives the read-only tools. hybrid: both, reconciled. The AI modes use
    one of your chat accounts and spend its credit; the key is checked before anything runs (423 if locked)."""
    with _translate(), connect_vector() as conn:
        cfg = None
        if body.mode != "rules":
            if not body.account:
                raise HTTPException(422, "choose a chat account for the AI modes")
            cfg = accounts.chat_config_for(conn, _ref(body.account))
            cfg.api_key()  # raises VaultLocked now rather than after a run has started
        try:
            run_id = investigator.investigate(conn, incident_id, mode=body.mode, use_memory=body.use_memory,
                                              account=body.account, chat_cfg=cfg)
        except Exception:
            metrics.INVESTIGATIONS.labels(body.mode, "failed").inc()
            raise
        metrics.INVESTIGATIONS.labels(body.mode, "done").inc()
        return {"run_id": run_id, **incidents.get_incident(conn, incident_id)}


@app.get("/api/incidents/{incident_id}/telemetry", dependencies=[Depends(require("incidents:read"))])
def incident_telemetry(incident_id: int, minutes: int = Query(90, ge=10, le=240)):
    with _translate(), connect() as conn:
        return incidents.telemetry(conn, incident_id, minutes)


@app.get("/api/runs/{run_id}", dependencies=[Depends(require("incidents:read"))])
def get_run(run_id: int):
    with _translate(), connect() as conn:
        return incidents.get_run(conn, run_id)


@app.get("/api/observations/{obs_id}", dependencies=[Depends(require("incidents:read"))])
def get_observation(obs_id: int):
    with _translate(), connect() as conn:
        return incidents.get_observation(conn, obs_id)


@app.post("/api/incidents/{incident_id}/resolve", dependencies=[Depends(require("incidents:write"))])
def resolve_incident(incident_id: int, body: ResolveBody):
    with _translate(), connect_vector() as conn:
        incidents.resolve(conn, incident_id, body.category, body.note)
        conn.commit()
        return {"resolved": incident_id, "truth": incidents.reveal_truth(conn, incident_id)}


@app.post("/api/incidents/{incident_id}/notes")
def add_note(incident_id: int, body: NoteBody, principal=Depends(require("incidents:write"))):
    author = principal.actor if principal.source == "oidc" else "operator"      # a signed-in person's notes carry their name
    with _translate(), connect() as conn:
        note_id = incidents.add_note(conn, incident_id, body.body, author=author)
        conn.commit()
    return {"id": note_id}


@app.get("/api/incidents/{incident_id}/truth", dependencies=[Depends(require("incidents:read"))])
def incident_truth(incident_id: int):
    """Only simulated incidents have a known answer; real ones return null."""
    with connect() as conn:
        return {"truth": incidents.reveal_truth(conn, incident_id)}


@app.get("/api/runbooks", dependencies=[Depends(require("runbooks:read"))])
def list_runbooks():
    with connect() as conn:
        return {"runbooks": conn.execute("SELECT id, title, category, service, body FROM runbook ORDER BY id").fetchall()}


# --- simulator --------------------------------------------------------------------------------------

class SimBody(BaseModel):
    scenario: str = Field(max_length=40)


@app.get("/api/simulator/scenarios", dependencies=[Depends(require("incidents:read"))])
def sim_scenarios():
    return {"scenarios": simulator.catalog(), "categories": investigator.CATEGORIES}


@app.post("/api/simulator/trigger", dependencies=[Depends(require("simulator:run"))])
def sim_trigger(body: SimBody):
    """Regenerate the demo telemetry with a failure overlaid and fire its alert. Replaces existing telemetry."""
    with _translate(), connect_vector() as conn:
        result = simulator.trigger(conn, body.scenario)
        conn.commit()
    return result


@app.post("/api/simulator/baseline", dependencies=[Depends(require("simulator:run"))])
def sim_baseline():
    with _translate(), connect_vector() as conn:
        simulator.baseline(conn)
        conn.commit()
    return {"ok": True}


@app.get("/api/stats", dependencies=[Depends(require("dashboard:read"))])
def stats():
    with connect() as conn:
        return conn.execute(
            "SELECT (SELECT count(*) FROM service) AS services, (SELECT count(*) FROM incident) AS incidents, "
            "(SELECT count(*) FROM incident WHERE status <> 'resolved') AS open_incidents, "
            "(SELECT count(*) FROM log_event) AS logs, (SELECT count(*) FROM runbook) AS runbooks").fetchone()


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")
