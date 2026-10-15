import contextlib
import sys
import time
from pathlib import Path

import psycopg
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.middleware.base import BaseHTTPMiddleware

from . import (
    __version__,
    accounts,
    auth,
    embedcfg,
    incidents,
    ingest,
    investigator,
    metrics,
    otlp,
    simulator,
    vault,
)
from . import chat as chatter
from .auth import Principal
from .config import get_settings
from .db import connect, connect_vector
from .embeddings import embed as embed_texts
from .llm_http import LLMError
from .mcp_server import mcp
from .netguard import UnsafeURL
from .tools import ToolError

STATIC = Path(__file__).resolve().parent / "static"
MAX_BODY = 2 * 1024 * 1024

mcp_app = mcp.streamable_http_app(streamable_http_path="/", host="0.0.0.0")


COOKIE = "pl_session"
CSRF_HEADER = "x-pagerlens-csrf"
_announced = False
_auto_unlock_tried = False


def _announce_setup_code() -> None:
    """Print the one-time setup code to the server log (once per process)."""
    global _announced
    if not _announced:
        _announced = True
        print("\n=== PagerLens first-run setup ===\n"
              f"Open the app in your browser and enter this one-time code to create the admin password:\n"
              f"    {auth.setup_code()}\n"
              "(It changes every time the server restarts until setup is complete.)\n", file=sys.stderr, flush=True)


def _startup_tasks() -> None:
    """Best effort: unlock the vault with a platform secret and announce the setup code. Never blocks startup."""
    global _auto_unlock_tried
    try:
        with connect(retries=1) as conn:
            _auto_unlock_tried = True
            vault.try_unlock_with_platform_secret(conn)
            if auth.needs_setup(conn):
                _announce_setup_code()
    except Exception:  # noqa: BLE001 - database may be asleep; it is retried on the first request
        pass


@contextlib.asynccontextmanager
async def lifespan(_: FastAPI):
    _startup_tasks()
    async with mcp_app.router.lifespan_context(mcp_app):
        yield


# --- authentication -------------------------------------------------------------------------
# Fail closed: with no credential configured every protected route is denied (and the setup flow is offered),
# unless the operator explicitly sets PAGERLENS_ALLOW_ANONYMOUS=true.

_FAIL_WINDOW, _FAIL_LIMIT = 60.0, 10
_failures: dict[str, list[float]] = {}


def _client(request: Request) -> str:
    return request.client.host if request.client else "?"


def _rate_limited(client: str) -> bool:
    now = time.monotonic()
    recent = [t for t in _failures.get(client, []) if now - t < _FAIL_WINDOW]
    _failures[client] = recent
    return len(recent) >= _FAIL_LIMIT


def _record_failure(client: str) -> None:
    _failures.setdefault(client, []).append(time.monotonic())
    if len(_failures) > 10_000:  # bound memory under address churn
        _failures.clear()


def _bearer(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    return header[7:].strip() if header[:7].lower() == "bearer " else None


def _declared_length(request: Request) -> int:
    value = request.headers.get("content-length", "")
    return int(value) if value.isdigit() else 0


def _is_https(request: Request) -> bool:
    return request.url.scheme == "https" or request.headers.get("x-forwarded-proto", "").lower() == "https"


def _db_unavailable() -> HTTPException:
    return HTTPException(503, "database unavailable; it may be waking up, retry in a few seconds")


def authenticate(request: Request, *, allow_cookie: bool = True) -> Principal | None:
    """Return the caller's Principal, or None if no credential was presented. Raises 401/429 for bad credentials."""
    if get_settings().allow_anonymous:
        return Principal("anonymous", "full")
    client = _client(request)
    if _rate_limited(client):
        raise HTTPException(429, "too many failed attempts; wait a minute")
    raw = _bearer(request)
    if raw is not None:
        if auth.static_key_matches(raw):
            return Principal("static", "full")
        if raw.startswith(auth.TOKEN_PREFIX):
            try:
                with connect(retries=1) as conn:
                    principal = auth.token_principal(conn, raw)
            except (psycopg.Error, RuntimeError) as exc:
                raise _db_unavailable() from exc
            if principal:
                return principal
        _record_failure(client)
        raise HTTPException(401, "invalid credentials")
    cookie = request.cookies.get(COOKIE) if allow_cookie else None
    if cookie:
        try:
            with connect(retries=1) as conn:
                ok = auth.session_valid(conn, cookie)
        except (psycopg.Error, RuntimeError) as exc:
            raise _db_unavailable() from exc
        if ok:
            return Principal("session", "full")
    return None


def require(scope: str = "read"):
    """Dependency: the caller must hold `scope`. 'full' (admin session or full token) satisfies everything;
    'read' tokens can only read; 'ingest' tokens can only push telemetry."""

    def dep(request: Request) -> Principal:
        principal = authenticate(request)
        if principal is None:
            raise HTTPException(401, "authentication required")
        if principal.scope != "full" and principal.scope != scope:
            raise HTTPException(403, f"this token cannot do that (it is a '{principal.scope}' token)")
        return principal

    return dep


class Guard(BaseHTTPMiddleware):
    """MCP bearer auth (route dependencies don't apply to mounts), CSRF check, and security headers."""

    async def dispatch(self, request, call_next):
        started = time.perf_counter()
        status = 500
        try:
            resp = await self._dispatch(request, call_next)
            status = resp.status_code
            return resp
        finally:
            route = request.scope.get("route")
            label = getattr(route, "path", None) or ("/mcp" if request.url.path.startswith("/mcp") else "other")
            if label != "/metrics":
                metrics.observe(request.method, label, status, started)

    async def _dispatch(self, request, call_next):
        path = request.url.path
        if path == "/mcp":
            # Serve the bare path directly: the mount would answer with a redirect, and behind a TLS-terminating
            # proxy that redirect can point at http://, where clients (rightly) drop the Authorization header.
            request.scope["path"] = request.scope["raw_path"] = "/mcp/"
            path = "/mcp/"
        if path.startswith("/mcp"):
            try:
                principal = authenticate(request, allow_cookie=False)  # MCP never accepts cookies
            except HTTPException as exc:
                return JSONResponse({"error": exc.detail}, status_code=exc.status_code)
            if principal is None:
                return JSONResponse({"error": "authentication required"}, status_code=401)
            if principal.scope in ("ingest", "metrics"):  # telemetry-only tokens never read incident data
                return JSONResponse({"error": f"{principal.scope} tokens cannot use MCP"}, status_code=403)
            request.scope["pagerlens_scope"] = principal.scope  # lets MCP tools gate state-changing calls
        elif path.startswith(("/api/", "/v1/")) and _declared_length(request) > MAX_BODY:
            return JSONResponse({"detail": "request body too large (2 MB limit)"}, status_code=413)
        elif (path.startswith("/api/") and request.method not in {"GET", "HEAD", "OPTIONS"}
              and _bearer(request) is None and not request.headers.get(CSRF_HEADER)):
            # Cookie-authenticated (browser) writes must carry a custom header, which cross-site pages can't set.
            return JSONResponse({"detail": "missing CSRF header"}, status_code=403)
        resp = await call_next(request)
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Cache-Control"] = resp.headers.get("Cache-Control", "no-store")
        resp.headers["Content-Security-Policy"] = (
            "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; "
            "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
        )
        return resp


# Interactive API docs load scripts from a CDN and expose the schema; keep them off.
app = FastAPI(title="PagerLens", version=__version__, lifespan=lifespan,
              docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(Guard)
app.mount("/mcp", mcp_app)
app.mount("/static", StaticFiles(directory=STATIC), name="static")



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


def _start_session(conn, request: Request, response: Response) -> None:
    raw = auth.create_session(conn)
    response.set_cookie(COOKIE, raw, httponly=True, samesite="strict", secure=_is_https(request),
                        max_age=auth.SESSION_HOURS * 3600, path="/")


def _guard_attempts(request: Request) -> str:
    client = _client(request)
    if _rate_limited(client):
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
            setup = auth.needs_setup(conn) and not get_settings().allow_anonymous
            v = vault.status(conn)
            has_password = auth.admin_configured(conn)
    except HTTPException:
        raise
    except (psycopg.Error, RuntimeError) as exc:
        raise _db_unavailable() from exc
    if setup:
        _announce_setup_code()
    state = "setup_required" if setup else "logged_in" if principal else "logged_out"
    return {"state": state, "vault": v, "has_admin_password": has_password,
            "password_login": has_password, "key_login": auth.static_key_configured()}


@app.post("/api/setup")
def setup(body: SetupBody, request: Request, response: Response):
    client = _guard_attempts(request)
    try:
        with connect(retries=1) as conn:
            try:
                auth.complete_setup(conn, body.code, body.password)
            except PermissionError as exc:
                _record_failure(client)
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
                ok = auth.login_password(conn, body.password)
            elif body.api_key is not None and auth.static_key_matches(body.api_key):
                ok = True
                vault.try_unlock_with_platform_secret(conn)
            if not ok:
                _record_failure(client)
                raise HTTPException(401, "invalid credentials")
            _start_session(conn, request, response)
    except (psycopg.Error, RuntimeError) as exc:
        raise _db_unavailable() from exc
    return {"ok": True}


@app.post("/api/logout")
def logout(request: Request, response: Response):
    try:
        with connect(retries=1) as conn:
            auth.delete_session(conn, request.cookies.get(COOKIE))
    except (psycopg.Error, RuntimeError):
        pass  # the cookie is cleared regardless; the session row expires on its own
    response.delete_cookie(COOKIE, path="/")
    return {"ok": True}


@app.post("/api/vault/unlock", dependencies=[Depends(require("full"))])
def unlock_vault(body: UnlockBody, request: Request):
    client = _guard_attempts(request)
    with connect() as conn:
        if not vault.is_initialized(conn):
            raise HTTPException(409, "no provider keys are stored yet; set an admin password first")
        if not vault.unlock_with_password(conn, body.password):
            _record_failure(client)
            raise HTTPException(403, "wrong password")  # 403, not 401: the session itself is still valid
        conn.commit()
    return {"ok": True}


@app.post("/api/admin-password", dependencies=[Depends(require("full"))])
def admin_password(body: PasswordBody, request: Request):
    """Set the admin password (first time, when signed in with a static key) or change it."""
    client = _guard_attempts(request)
    with connect() as conn:
        try:
            if auth.admin_configured(conn):
                if body.current is None:
                    raise HTTPException(422, "current password is required")
                auth.change_password(conn, body.current, body.new)
            else:
                auth.set_admin_password(conn, body.new)
        except PermissionError as exc:
            _record_failure(client)
            raise HTTPException(403, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        conn.execute("DELETE FROM web_session")  # sign every browser out after a password change
        conn.commit()
    return {"ok": True, "signed_out_everywhere": True}


@app.get("/api/tokens", dependencies=[Depends(require("full"))])
def list_tokens():
    with connect() as conn:
        return auth.list_tokens(conn)


@app.post("/api/tokens", dependencies=[Depends(require("full"))])
def create_token(body: TokenBody):
    """The token value is returned exactly once; only its hash is stored."""
    with connect() as conn:
        token_id, raw = auth.create_token(conn, body.name.strip(), body.scope)
    return {"id": token_id, "token": raw, "scope": body.scope, "name": body.name.strip()}


@app.delete("/api/tokens/{token_id}", dependencies=[Depends(require("full"))])
def revoke_token(token_id: int):
    with connect() as conn:
        if not auth.revoke_token(conn, token_id):
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


@app.get("/api/providers", dependencies=[Depends(require("read"))])
def providers():
    return accounts.PRESETS


@app.get("/api/accounts", dependencies=[Depends(require("full"))])
def list_accounts():
    with connect() as conn:
        embedcfg.ensure_loaded(conn)
        return {"accounts": accounts.list_accounts(conn), "env": accounts.env_account(),
                "vault": vault.status(conn), "active_embedding": accounts.active_embedding_ref(conn)}


@app.post("/api/accounts", dependencies=[Depends(require("full"))])
def create_account(body: AccountBody):
    with _translate(), connect() as conn:
        new_id = accounts.create(conn, name=body.name, provider=body.provider, base_url=body.base_url,
                                 api_key=body.api_key, chat_model=body.chat_model,
                                 embedding_model=body.embedding_model, embedding_dim=body.embedding_dim)
        return accounts.get_account(conn, new_id)


@app.put("/api/accounts/{account_id}", dependencies=[Depends(require("full"))])
def update_account(account_id: int, body: AccountBody):
    with _translate(), connect() as conn:
        accounts.update(conn, account_id, name=body.name, provider=body.provider, base_url=body.base_url,
                        api_key=body.api_key, clear_key=body.clear_key, chat_model=body.chat_model,
                        embedding_model=body.embedding_model, embedding_dim=body.embedding_dim)
        return accounts.get_account(conn, account_id)


@app.delete("/api/accounts/{account_id}", dependencies=[Depends(require("full"))])
def delete_account(account_id: int):
    with _translate(), connect() as conn:
        embedcfg.ensure_loaded(conn)
        accounts.delete(conn, account_id)
    return {"deleted": account_id}


@app.post("/api/accounts/{account}/test", dependencies=[Depends(require("full"))])
def test_account(account: str, body: TestBody):
    """Make one tiny real call to the provider so mistakes (URL, key, model name) show up immediately."""
    if account != "env" and not account.isdigit():
        raise HTTPException(422, "invalid account")
    started = time.monotonic()
    with _translate(), connect() as conn:
        if body.target == "chat":
            reply = chatter.chat(accounts.chat_config_for(conn, _ref(account)),
                               [{"role": "user", "content": "Reply with the single word OK."}], max_tokens=8)
            detail = {"reply": reply["text"][:60]}
        else:
            cfg = (embedcfg.from_env() if account == "env" else accounts.embedding_config_for(conn, int(account)))
            vec = embed_texts(["connection test"], cfg)[0]
            detail = {"dimensions": len(vec), "model": cfg.model}
    return {"ok": True, "ms": int((time.monotonic() - started) * 1000), **detail}



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


@app.post("/api/ingest/logs", dependencies=[Depends(require("ingest"))])
def ingest_logs(body: LogsBody):
    with _translate(), connect() as conn:
        n = ingest.ingest_logs(conn, body.service, body.events)
        conn.commit()
    metrics.INGESTED.labels("logs").inc(n)
    return {"accepted": n}


@app.post("/api/ingest/metrics", dependencies=[Depends(require("ingest"))])
def ingest_metrics(body: MetricsBody):
    with _translate(), connect() as conn:
        n = ingest.ingest_metrics(conn, body.service, body.points)
        conn.commit()
    metrics.INGESTED.labels("metrics").inc(n)
    return {"accepted": n}


@app.post("/api/ingest/deploys", dependencies=[Depends(require("ingest"))])
def ingest_deploy(body: DeployBody):
    with _translate(), connect() as conn:
        deploy_id = ingest.ingest_deploy(conn, body.service, body.model_dump())
        conn.commit()
    return {"id": deploy_id}


@app.post("/api/ingest/services", dependencies=[Depends(require("ingest"))])
def ingest_service(body: ServiceBody):
    with _translate(), connect() as conn:
        sid = ingest.upsert_service(conn, body.name, owner=body.owner, tier=body.tier, description=body.description,
                                    depends_on=body.depends_on)
        conn.commit()
    return {"id": sid}


@app.post("/api/ingest/alerts", dependencies=[Depends(require("ingest"))])
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


@app.post("/v1/logs", dependencies=[Depends(require("ingest"))])
async def otlp_logs(request: Request):
    return await _otlp(request, "logs")


@app.post("/v1/metrics", dependencies=[Depends(require("ingest"))])
async def otlp_metrics(request: Request):
    return await _otlp(request, "metrics")


@app.post("/v1/traces", dependencies=[Depends(require("ingest"))])
async def otlp_traces(request: Request):
    return await _otlp(request, "traces")


@app.get("/metrics", dependencies=[Depends(require("metrics"))])
def prometheus_metrics():
    body, ctype = metrics.render()
    return Response(body, media_type=ctype)


@app.get("/api/fleet", dependencies=[Depends(require("read"))])
def get_fleet():
    with connect() as conn:
        return {"services": incidents.fleet(conn)}


@app.get("/api/incidents", dependencies=[Depends(require("read"))])
def list_incidents(status: str | None = Query(None, pattern="^(open|investigating|resolved)$"),
                   limit: int = Query(50, ge=1, le=200)):
    with connect() as conn:
        return {"incidents": incidents.list_incidents(conn, status=status, limit=limit)}


@app.get("/api/incidents/{incident_id}", dependencies=[Depends(require("read"))])
def get_incident(incident_id: int):
    with _translate(), connect() as conn:
        return incidents.get_incident(conn, incident_id)


@app.post("/api/incidents/{incident_id}/investigate", dependencies=[Depends(require("full"))])
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


@app.get("/api/incidents/{incident_id}/telemetry", dependencies=[Depends(require("read"))])
def incident_telemetry(incident_id: int, minutes: int = Query(90, ge=10, le=240)):
    with _translate(), connect() as conn:
        return incidents.telemetry(conn, incident_id, minutes)


@app.get("/api/runs/{run_id}", dependencies=[Depends(require("read"))])
def get_run(run_id: int):
    with _translate(), connect() as conn:
        return incidents.get_run(conn, run_id)


@app.get("/api/observations/{obs_id}", dependencies=[Depends(require("read"))])
def get_observation(obs_id: int):
    with _translate(), connect() as conn:
        return incidents.get_observation(conn, obs_id)


@app.post("/api/incidents/{incident_id}/resolve", dependencies=[Depends(require("full"))])
def resolve_incident(incident_id: int, body: ResolveBody):
    with _translate(), connect_vector() as conn:
        incidents.resolve(conn, incident_id, body.category, body.note)
        conn.commit()
        return {"resolved": incident_id, "truth": incidents.reveal_truth(conn, incident_id)}


@app.post("/api/incidents/{incident_id}/notes", dependencies=[Depends(require("full"))])
def add_note(incident_id: int, body: NoteBody):
    with _translate(), connect() as conn:
        note_id = incidents.add_note(conn, incident_id, body.body)
        conn.commit()
    return {"id": note_id}


@app.get("/api/incidents/{incident_id}/truth", dependencies=[Depends(require("read"))])
def incident_truth(incident_id: int):
    """Only simulated incidents have a known answer; real ones return null."""
    with connect() as conn:
        return {"truth": incidents.reveal_truth(conn, incident_id)}


@app.get("/api/runbooks", dependencies=[Depends(require("read"))])
def list_runbooks():
    with connect() as conn:
        return {"runbooks": conn.execute("SELECT id, title, category, service, body FROM runbook ORDER BY id").fetchall()}


# --- simulator --------------------------------------------------------------------------------------

class SimBody(BaseModel):
    scenario: str = Field(max_length=40)


@app.get("/api/simulator/scenarios", dependencies=[Depends(require("read"))])
def sim_scenarios():
    return {"scenarios": simulator.catalog(), "categories": investigator.CATEGORIES}


@app.post("/api/simulator/trigger", dependencies=[Depends(require("full"))])
def sim_trigger(body: SimBody):
    """Regenerate the demo telemetry with a failure overlaid and fire its alert. Replaces existing telemetry."""
    with _translate(), connect_vector() as conn:
        result = simulator.trigger(conn, body.scenario)
        conn.commit()
    return result


@app.post("/api/simulator/baseline", dependencies=[Depends(require("full"))])
def sim_baseline():
    with _translate(), connect_vector() as conn:
        simulator.baseline(conn)
        conn.commit()
    return {"ok": True}


@app.get("/api/stats", dependencies=[Depends(require("read"))])
def stats():
    with connect() as conn:
        return conn.execute(
            "SELECT (SELECT count(*) FROM service) AS services, (SELECT count(*) FROM incident) AS incidents, "
            "(SELECT count(*) FROM incident WHERE status <> 'resolved') AS open_incidents, "
            "(SELECT count(*) FROM log_event) AS logs, (SELECT count(*) FROM runbook) AS runbooks").fetchone()


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")
