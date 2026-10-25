"""Retire a service, resolve in bulk, auto-resolve recovered incidents and the stale marker, against a disposable Postgres."""
import os
from datetime import UTC, datetime, timedelta

import pytest

if not os.environ.get("TEST_DATABASE_URL"):
    pytest.skip("set TEST_DATABASE_URL to run DB tests", allow_module_level=True)

from pagerlens import auth, core, housekeeping, incidents, ingest, migrate, retrieval, vault  # noqa: E402
from pagerlens.db import connect, connect_vector  # noqa: E402

H = {"X-PagerLens-CSRF": "1"}
PASSWORD = "correct-horse-battery"  # pragma: allowlist secret


@pytest.fixture(autouse=True)
def _db(monkeypatch, client):
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    for v in ("PAGERLENS_API_KEY", "PAGERLENS_ALLOW_ANONYMOUS", "PAGERLENS_ENCRYPTION_KEY", "LLM_BASE_URL"):
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
def learned(monkeypatch):
    """Calls of the memory-writing function: housekeeping must never make one."""
    calls = []
    monkeypatch.setattr(retrieval, "remember_incident", lambda *a, **k: calls.append(a))
    return calls


def token(client, scope):
    with connect() as c:
        if not auth.admin_configured(c):
            auth.set_admin_password(c, PASSWORD)
    client.post("/api/login", json={"password": PASSWORD}, headers=H)
    tok = client.post("/api/tokens", json={"name": scope, "scope": scope}, headers=H).json()["token"]
    client.cookies.clear()
    return {"Authorization": f"Bearer {tok}"}


def feed(service, metrics, minutes=30, ago=0, **svc):
    """metrics: name -> value (constant) or a list, one per minute, ending `ago` minutes ago."""
    now = datetime.now(UTC).replace(second=0, microsecond=0)
    with connect_vector() as conn:
        ingest.upsert_service(conn, service, **svc)
        for name, v in metrics.items():
            vals = v if isinstance(v, list) else [v] * minutes
            pts = [{"name": name, "value": x, "ts": (now - timedelta(minutes=ago + len(vals) - 1 - i)).isoformat()} for i, x in enumerate(vals)]
            ingest.ingest_metrics(conn, service, pts)
        conn.commit()


def alert(service, name="HighErrorRate", minutes_ago=0):
    with connect_vector() as conn:
        out = ingest.raise_alert(conn, service, name, summary=f"{name} fired", severity="sev2", source="test",
                                 fired_at=datetime.now(UTC) - timedelta(minutes=minutes_ago))
        conn.commit()
    return out["incident_id"]


def row(incident_id):
    with connect() as c:
        return c.execute("SELECT status, root_cause_category, root_cause_note, resolved_at, service_id, service_name FROM incident WHERE id=%s",
                         (incident_id,)).fetchone()


# --- retire ---------------------------------------------------------------------------------------------------------

def seed_retirable():
    feed("citypulse-fleet-default", {"up": 1, "fleet_health_pct": 60}, ago=4000, depends_on=["gateway"])
    feed("gateway", {"up": 1}, depends_on=["citypulse-fleet-default"])
    feed("other-api", {"up": 1})
    with connect_vector() as conn:
        ingest.ingest_deploy(conn, "citypulse-fleet-default", {"version": "1.0", "ts": datetime.now(UTC).isoformat()})
        ingest.ingest_logs(conn, "citypulse-fleet-default", [{"level": "error", "message": "sensor offline"}])
        conn.commit()
    return alert("citypulse-fleet-default", "SensorFleetDegraded")


def test_retire_removes_the_service_and_its_data_and_closes_incidents_without_learning(client, learned):
    open_id = seed_retirable()
    with connect() as c:                                   # a person's note on it stays, and the service still goes
        incidents.add_note(c, open_id, "looking into it")
        c.commit()
    full = token(client, "full")
    r = client.post("/api/services/citypulse-fleet-default/retire", json={"confirm": "citypulse-fleet-default"}, headers=full)
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["incidents_resolved"] == [open_id] and out["deploys"] == 1 and out["log_events"] == 1
    assert out["metric_points"] == 60 and out["dependency_edges"] == 1
    with connect() as c:
        assert c.execute("SELECT count(*) AS n FROM service WHERE name='citypulse-fleet-default'").fetchone()["n"] == 0
        assert c.execute("SELECT depends_on FROM service WHERE name='gateway'").fetchone()["depends_on"] == []   # the edge to it is gone
        assert c.execute("SELECT count(*) AS n FROM metric_point").fetchone()["n"] == 60                  # only gateway and other-api remain
        assert c.execute("SELECT count(*) AS n FROM deploy").fetchone()["n"] == 0
        assert c.execute("SELECT count(*) AS n FROM log_event").fetchone()["n"] == 0
    inc = row(open_id)
    assert inc["status"] == "resolved" and inc["root_cause_note"] == "service retired" and inc["resolved_at"]
    assert inc["root_cause_category"] is None and inc["service_id"] is None and inc["service_name"] == "citypulse-fleet-default"
    assert learned == []                                   # no confirmed cause, nothing embedded
    with connect_vector() as c:
        assert retrieval.similar_incidents(c, "SensorFleetDegraded 5xx", min_similarity=-1) == []
    shown = client.get(f"/api/incidents/{open_id}", headers=full).json()      # history survives under the old name
    assert shown["service"] == "citypulse-fleet-default" and shown["status"] == "resolved"
    assert [s["name"] for s in client.get("/api/dashboard", headers=full).json()["services"]] == ["gateway", "other-api"]
    assert client.get("/api/services/citypulse-fleet-default", headers=full).status_code == 404
    # telemetry for the same name later simply recreates it, empty
    feed("citypulse-fleet-default", {"up": 1})
    assert client.get("/api/services/citypulse-fleet-default", headers=full).json()["status"] == "healthy"


def test_retire_is_guarded(client):
    seed_retirable()
    full, read, ing = token(client, "full"), token(client, "read"), token(client, "ingest")
    url = "/api/services/other-api/retire"
    assert client.post(url, json={"confirm": "other-api"}, headers=H).status_code == 401
    assert client.post(url, json={"confirm": "other-api"}, headers=read).status_code == 403          # reading is not retiring
    assert client.post(url, json={"confirm": "other-api"}, headers=ing).status_code == 403
    assert client.post(url, json={}, headers=full).status_code == 422
    assert client.post(url, json={"confirm": "other"}, headers=full).status_code == 422               # the name must be typed exactly
    assert client.post(url, json={"confirm": "OTHER-API"}, headers=full).status_code == 422
    assert client.post("/api/services/ghost/retire", json={"confirm": "ghost"}, headers=full).status_code == 404
    assert client.post("/api/services/Bad%20Name/retire", json={"confirm": "Bad Name"}, headers=full).status_code == 404
    client.post("/api/login", json={"password": PASSWORD}, headers=H)                                  # a browser session needs the CSRF header
    assert client.post(url, json={"confirm": "other-api"}).status_code == 403
    with connect() as c:
        assert c.execute("SELECT count(*) AS n FROM service").fetchone()["n"] == 3


# --- bulk resolve ---------------------------------------------------------------------------------------------------

def storm():
    for s in ("alpha", "beta"):
        feed(s, {"up": 1})
    return [alert("alpha", n) for n in ("DiskFull", "CertificateExpired", "QueueBacklog")] + [alert("beta", "CacheMissStorm")]


def test_bulk_resolve_by_filter_and_by_selection(client, learned):
    ids = storm()
    full, read = token(client, "full"), token(client, "read")
    body = {"reason": "alert storm", "all_matching": True, "service": "alpha", "confirm": True}
    assert client.post("/api/incidents/bulk-resolve", json=body, headers=read).status_code == 403
    assert client.post("/api/incidents/bulk-resolve", json={**body, "confirm": False}, headers=full).status_code == 422
    no_confirm = {k: v for k, v in body.items() if k != "confirm"}
    assert client.post("/api/incidents/bulk-resolve", json=no_confirm, headers=full).status_code == 422
    assert client.post("/api/incidents/bulk-resolve", json={**body, "reason": ""}, headers=full).status_code == 422
    assert client.post("/api/incidents/bulk-resolve", json={"reason": "x", "confirm": True}, headers=full).status_code == 422   # neither ids nor a filter
    assert client.post("/api/incidents/bulk-resolve", json={**body, "ids": [ids[0]]}, headers=full).status_code == 422          # both
    assert client.post("/api/incidents/bulk-resolve", json={**body, "status": "resolved"}, headers=full).status_code == 422
    assert all(row(i)["status"] == "open" for i in ids)                         # every refusal left everything open
    r = client.post("/api/incidents/bulk-resolve", json=body, headers=full).json()
    assert r["resolved"] == 3 and sorted(r["ids"]) == sorted(ids[:3])
    for i in ids[:3]:
        inc = row(i)
        assert inc["status"] == "resolved" and inc["root_cause_category"] is None and inc["root_cause_note"] == "bulk resolved: alert storm"
        notes = client.get(f"/api/incidents/{i}", headers=full).json()["notes"]
        assert notes[0]["body"] == "resolved in bulk by operator: alert storm"       # the audit record, like a resolve leaves one
    assert row(ids[3])["status"] == "open"
    assert client.post("/api/incidents/bulk-resolve", json=body, headers=full).json()["resolved"] == 0   # nothing left to match
    sel = client.post("/api/incidents/bulk-resolve", json={"reason": "picked", "ids": [ids[3], ids[0]], "confirm": True}, headers=full).json()
    assert sel["resolved"] == 1 and sel["ids"] == [ids[3]]                       # an already resolved one is not touched again
    assert learned == []
    listed = client.get("/api/incidents?service=alpha&status=resolved", headers=full).json()
    assert listed["total"] == 3 and {i["service"] for i in listed["incidents"]} == {"alpha"}


def test_bulk_resolve_with_an_empty_filter_closes_everything_unresolved(client):
    ids = storm()
    full = token(client, "full")
    r = client.post("/api/incidents/bulk-resolve", json={"reason": "reset", "all_matching": True, "confirm": True}, headers=full).json()
    assert r["resolved"] == len(ids)


# --- auto-resolve ---------------------------------------------------------------------------------------------------

def run_pass(now=None, **setting):
    with connect() as c:
        if setting:
            housekeeping.save_settings(c, setting)
        out = housekeeping.auto_resolve_pass(c, now)
        c.commit()
    return out


def test_auto_resolve_closes_a_recovered_incident_without_learning(client, learned):
    feed("checkout-api", {"up": 1, "error_rate": 0.3}, minutes=60)
    iid = alert("checkout-api", minutes_ago=45)
    assert run_pass() == [iid]
    inc = row(iid)
    assert inc["status"] == "resolved" and inc["root_cause_note"] == "auto-resolved: recovered" and inc["root_cause_category"] is None
    assert learned == []
    assert run_pass() == []                                                       # idempotent


def test_auto_resolve_waits_for_a_quiet_alert_and_a_healthy_service(client):
    feed("checkout-api", {"up": 1, "error_rate": 0.3}, minutes=60)
    fresh = alert("checkout-api", "Fresh", minutes_ago=10)                         # the alert fired 10 minutes ago: not quiet yet
    assert run_pass() == [] and row(fresh)["status"] == "open"
    feed("slow-api", {"up": 1, "error_rate": [0.3] * 30 + [8.0] * 2 + [0.3] * 28}, minutes=60)     # a breach 28 minutes ago, inside the 30 minute window
    breach = alert("slow-api", minutes_ago=50)
    assert run_pass() == [] and row(breach)["status"] == "open"
    feed("gone-api", {"up": 1}, minutes=60, ago=20)                                # silent for the last 20 minutes
    gone = alert("gone-api", minutes_ago=90)
    assert run_pass() == [] and row(gone)["status"] == "open"
    nodata = alert("never-reported", minutes_ago=90)
    assert run_pass() == [] and row(nodata)["status"] == "open"
    feed("late-api", {"up": 1}, minutes=3)                                         # healthy for 2 minutes only
    late = alert("late-api", minutes_ago=90)
    assert run_pass() == [] and row(late)["status"] == "open"


def test_auto_resolve_never_touches_work_in_progress(client):
    feed("checkout-api", {"up": 1}, minutes=60)
    noted, investigated, investigating, refired, plain = (alert("checkout-api", n, minutes_ago=45) for n in ("DiskFull", "CertificateExpired", "QueueBacklog", "CacheMissStorm", "ReplicaLag"))
    with connect() as c:
        incidents.add_note(c, noted, "I am on it")
        c.execute("INSERT INTO run (incident_id, mode, status) VALUES (%s, 'rules', 'done')", (investigated,))
        c.execute("UPDATE incident SET status='investigating' WHERE id=%s", (investigating,))
        c.execute("INSERT INTO alert (service_id, incident_id, source, name, severity) SELECT service_id, %s, 'test', 'again', 'sev2' "
                  "FROM incident WHERE id=%s", (refired, refired))                 # fired again just now
        c.commit()
    assert run_pass() == [plain]
    assert [row(i)["status"] for i in (noted, investigated, investigating, refired)] == ["open", "open", "investigating", "open"]


def test_auto_resolve_is_off_at_zero_and_follows_the_setting(client):
    feed("checkout-api", {"up": 1}, minutes=90)
    iid = alert("checkout-api", minutes_ago=80)
    assert run_pass(auto_resolve_minutes=0) == [] and row(iid)["status"] == "open"
    assert run_pass(auto_resolve_minutes=120) == []                                # needs two hours of calm; only 90 minutes of data
    assert run_pass(auto_resolve_minutes=60) == [iid]


def test_injected_clock_decides(client):
    feed("checkout-api", {"up": 1}, minutes=60)
    iid = alert("checkout-api", minutes_ago=35)
    assert run_pass(now=datetime.now(UTC) - timedelta(minutes=20)) == []           # twenty minutes earlier the alert was only 15 minutes old
    assert run_pass() == [iid]


# --- stale marker and settings --------------------------------------------------------------------------------------

def test_a_stale_service_is_marked_and_leaves_the_degraded_count(client):
    feed("live-api", {"up": 1, "error_rate": 0.2})
    feed("sick-api", {"up": 1, "error_rate": 9.0})
    feed("citypulse-fleet-default", {"up": 1, "fleet_health_pct": 50}, minutes=10, ago=3 * 24 * 60 - 20)
    alert("citypulse-fleet-default", "SensorFleetDegraded", minutes_ago=3 * 24 * 60)
    h = token(client, "read")
    d = client.get("/api/dashboard", headers=h).json()
    by = {s["name"]: s for s in d["services"]}
    assert by["citypulse-fleet-default"]["stale"] and by["citypulse-fleet-default"]["status"] == "stale"
    assert by["citypulse-fleet-default"]["reasons"][0].startswith("no data for ") and by["citypulse-fleet-default"]["open_incidents"] == 1
    assert not by["live-api"]["stale"] and not by["sick-api"]["stale"] and by["sick-api"]["status"] == "degraded"
    assert d["summary"]["degraded"] == 1 and d["summary"]["stale"] == 1
    detail = client.get("/api/services/citypulse-fleet-default", headers=h).json()
    assert detail["stale"] is True
    full = token(client, "full")
    assert client.put("/api/settings/housekeeping", json={"stale_after_minutes": 0}, headers=full).json()["stale_after_minutes"] == 0
    d = client.get("/api/dashboard", headers=h).json()
    assert d["summary"]["degraded"] == 2 and not any(s["stale"] for s in d["services"])      # marker off: back to the old verdict


def test_the_two_settings_api(client):
    full, read = token(client, "full"), token(client, "read")
    got = client.get("/api/settings/housekeeping", headers=full).json()
    assert (got["auto_resolve_minutes"], got["stale_after_minutes"]) == (30, 60)               # the defaults
    assert client.get("/api/settings/housekeeping", headers=read).status_code == 403
    assert client.put("/api/settings/housekeeping", json={"auto_resolve_minutes": 5}, headers=read).status_code == 403
    assert client.put("/api/settings/housekeeping", json={"auto_resolve_minutes": 5}, headers=full).json() == {"auto_resolve_minutes": 5, "stale_after_minutes": 60}
    assert client.put("/api/settings/housekeeping", json={"stale_after_minutes": 2}, headers=full).status_code == 422
    assert client.put("/api/settings/housekeeping", json={"auto_resolve_minutes": -3}, headers=full).status_code == 422
    assert client.put("/api/settings/housekeeping", json={"auto_resolve_minutes": "soon"}, headers=full).status_code == 422
    assert client.get("/api/settings/housekeeping", headers=full).json()["auto_resolve_minutes"] == 5
