"""Live updates: tcn row-change notifications, the one LISTEN connection, and the server-sent-events endpoint (a real LISTEN, no mocks)."""
import asyncio
import json
import os
import threading
import time

import pytest

if not os.environ.get("TEST_DATABASE_URL"):
    pytest.skip("set TEST_DATABASE_URL to run DB tests", allow_module_level=True)

import psycopg  # noqa: E402
from apgkit.config import database_url  # noqa: E402

from pagerlens import api, auth, core, live, migrate, simulator, vault  # noqa: E402
from pagerlens.db import connect  # noqa: E402

H = {"X-PagerLens-CSRF": "1"}
PASSWORD = "correct-horse-battery"  # pragma: allowlist secret


def _tcn_available() -> bool:
    try:
        with psycopg.connect(os.environ["TEST_DATABASE_URL"], autocommit=True) as c:
            return bool(c.execute("SELECT 1 FROM pg_available_extensions WHERE name='tcn'").fetchone())
    except psycopg.Error:
        return False


pytestmark = pytest.mark.skipif(not _tcn_available(), reason="the tcn contrib extension is not installed in this Postgres")


@pytest.fixture(autouse=True)
def _db(monkeypatch, client):
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    for v in ("PAGERLENS_API_KEY", "PAGERLENS_ALLOW_ANONYMOUS", "PAGERLENS_ENCRYPTION_KEY"):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setenv("PAGERLENS_API_KEY_FILE", "/nonexistent/key")
    monkeypatch.setenv("PAGERLENS_ENCRYPTION_KEY_FILE", "/nonexistent/key")
    core.auth.limiter.clear()
    core.local._setup_code = None
    vault.lock()
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


def token(admin, scope):
    return {"Authorization": "Bearer " + admin.post("/api/tokens", json={"name": scope, "scope": scope}, headers=H).json()["token"]}


def open_incident() -> int:
    with connect() as c:
        simulator.seed_fleet(c)
        sid = c.execute("SELECT id FROM service WHERE name='checkout-api'").fetchone()["id"]
        iid = c.execute("INSERT INTO incident (service_id, service_name, title, fingerprint, symptom) VALUES (%s,'checkout-api',"
                        "'secret title jane@example.com','fp','sym') RETURNING id", (sid,)).fetchone()["id"]
        c.commit()
    return iid


def test_triggers_exist_and_notify_with_table_operation_and_key_only():
    with connect() as c:
        assert live.available(c)
    with psycopg.connect(os.environ["TEST_DATABASE_URL"], autocommit=True) as listener:
        listener.execute(f"LISTEN {live.CHANNEL}")
        iid = open_incident()
        with connect() as c:
            c.execute("UPDATE incident SET status='investigating' WHERE id=%s", (iid,))
            c.execute("INSERT INTO alert (incident_id, source, name) VALUES (%s,'t','a')", (iid,))
            c.commit()
        got = [n.payload for n in listener.notifies(timeout=3, stop_after=3)]
    parsed = [live.parse(p) for p in got]
    assert {"table": "incident", "op": "insert", "id": iid} in parsed and {"table": "incident", "op": "update", "id": iid} in parsed
    assert any(p and p["table"] == "alert" and p["op"] == "insert" for p in parsed)
    assert not any("secret" in p or "jane@" in p for p in got)          # a change carries no row content


def test_the_migration_is_guarded_when_tcn_is_unavailable():
    sql = live.TCN_SQL.read_text().replace("EXISTS tcn;", "EXISTS tcn_is_not_installed;")
    with connect() as c:
        c.execute("DROP EXTENSION tcn CASCADE")           # removes the triggers as well
        c.commit()
        assert not live.available(c)
        c.execute(sql)                                    # must not raise: the extension cannot be created
        c.commit()
        assert not live.available(c)
        assert live.install(c) is True                    # the real file, run on the next start, restores them
        assert live.available(c)


def test_parse_ignores_what_it_does_not_understand():
    assert live.parse('"incident",U,"id"=\'7\'') == {"table": "incident", "op": "update", "id": 7}
    assert live.parse("garbage") is None and live.parse('"incident",X,"id"=\'7\'') is None


def test_hub_fans_a_real_notification_out_and_closes_when_idle(monkeypatch):
    monkeypatch.setattr(live, "IDLE_CLOSE", 1.5)

    async def scenario():
        hub = live.Hub(database_url)
        a, b = hub.subscribe(), hub.subscribe()
        assert await asyncio.to_thread(hub.listening.wait, 10)
        iid = await asyncio.to_thread(open_incident)
        for sub in (a, b):                                # one connection, every stream gets it
            ev = await asyncio.wait_for(sub.queue.get(), 10)
            assert ev == {"table": "incident", "op": "insert", "id": iid}
        hub.unsubscribe(a)
        hub.unsubscribe(b)
        deadline = time.monotonic() + 8
        while hub._thread is not None and time.monotonic() < deadline:     # idle: the connection goes away
            await asyncio.sleep(0.2)
        assert hub._thread is None and not hub.listening.is_set()
        c = hub.subscribe()                               # and a new subscriber starts it again
        assert await asyncio.to_thread(hub.listening.wait, 10)
        hub.unsubscribe(c)
        hub.stop()

    asyncio.run(scenario())


def test_the_events_endpoint_needs_the_incident_read_permission(admin):
    ingest = token(admin, "ingest")
    admin.cookies.clear()
    assert admin.get("/api/events").status_code == 401
    assert admin.get("/api/events", headers=ingest).status_code == 403


@pytest.fixture
def server():
    """The real app on a real port: Starlette's TestClient buffers a response until it ends, which an event stream never does."""
    import uvicorn

    srv = uvicorn.Server(uvicorn.Config(api.app, host="127.0.0.1", port=42411, log_level="warning", lifespan="off"))
    t = threading.Thread(target=srv.run, daemon=True)
    t.start()
    deadline = time.monotonic() + 10
    while not srv.started and time.monotonic() < deadline:
        time.sleep(0.05)
    assert srv.started
    yield "http://127.0.0.1:42411"
    srv.should_exit = True
    t.join(10)


def read_events(response, want: int) -> list[tuple[str, dict]]:
    out: list[tuple[str, dict]] = []
    name = ""
    for line in response.iter_lines():
        if line.startswith("event:"):
            name = line.split(":", 1)[1].strip()
        elif line.startswith("data:") and name:
            out.append((name, json.loads(line.split(":", 1)[1])))
            if len(out) >= want:
                break
    return out


def test_the_events_endpoint_streams_a_change_over_a_real_listen(admin, server):
    import httpx

    read = token(admin, "read")
    result: dict = {"events": []}

    def reader():
        try:
            with httpx.stream("GET", server + "/api/events", headers=read, timeout=20) as r:
                result["status"], result["headers"] = r.status_code, r.headers
                for ev in read_events(r, 2):
                    result["events"].append(ev)
        except Exception as exc:  # noqa: BLE001 - reported by the assertions below
            result["error"] = repr(exc)

    t = threading.Thread(target=reader, daemon=True)
    t.start()
    assert api.hub.listening.wait(10) or "error" in result       # the one LISTEN connection is up once a browser subscribed
    iid = open_incident()
    t.join(15)
    assert not t.is_alive(), "the stream did not deliver the change"
    assert "error" not in result, result
    assert result["status"] == 200 and result["headers"]["content-type"].startswith("text/event-stream")
    assert result["headers"]["cache-control"] == "no-store"
    assert result["events"] == [("hello", {"live": True}), ("change", {"table": "incident", "op": "insert", "id": iid})]


def test_without_tcn_the_stream_says_so_and_ends(admin):
    with connect() as c:
        c.execute("DROP EXTENSION tcn CASCADE")
        c.commit()
    with admin.stream("GET", "/api/events") as r:
        assert r.status_code == 200
        body = "".join(r.iter_text())
    assert "event: hello" in body and '"live": false' in body and "event: change" not in body
    # ~2 KB of comment padding comes first, before `retry:`, so a buffering proxy flushes the first frame
    assert body.startswith(live.PADDING) and body.index("retry:") >= 2048 and body.index("retry:") < body.index("event: hello")
