"""The dashboard endpoints against a disposable Postgres."""
import os
from datetime import UTC, datetime, timedelta

import pytest

if not os.environ.get("TEST_DATABASE_URL"):
    pytest.skip("set TEST_DATABASE_URL to run DB tests", allow_module_level=True)

from pagerlens import auth, core, ingest, migrate, vault  # noqa: E402
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


def token(client, scope):
    with connect() as c:
        if not auth.admin_configured(c):
            auth.set_admin_password(c, PASSWORD)
    client.post("/api/login", json={"password": PASSWORD}, headers=H)
    tok = client.post("/api/tokens", json={"name": scope, "scope": scope}, headers=H).json()["token"]
    client.cookies.clear()
    return {"Authorization": f"Bearer {tok}"}


def feed(service, metrics, minutes=30, ago=0, **svc):
    """metrics: name -> value (constant) or a list of values, one per minute, ending `ago` minutes ago."""
    now = datetime.now(UTC).replace(second=0, microsecond=0)
    with connect_vector() as conn:
        ingest.upsert_service(conn, service, **svc)
        for name, v in metrics.items():
            vals = v if isinstance(v, list) else [v] * minutes
            pts = [{"name": name, "value": x, "ts": (now - timedelta(minutes=ago + len(vals) - 1 - i)).isoformat()} for i, x in enumerate(vals)]
            ingest.ingest_metrics(conn, service, pts)
        conn.commit()


def test_the_dashboard_lists_every_service_with_a_verdict_worst_first(client):
    feed("calm-api", {"up": 1, "error_rate": 0.3, "request_rate": 120, "latency_p95_ms": 80})
    feed("sick-api", {"up": 1, "error_rate": [0.5] * 20 + [9.0] * 10, "request_rate": 100})
    feed("dead-api", {"up": [1] * 25 + [0] * 5})
    feed("quiet-api", {"up": 1, "error_rate": 0.1}, ago=30)
    with connect_vector() as conn:
        ingest.upsert_service(conn, "new-api")
        conn.commit()
    h = token(client, "read")
    d = client.get("/api/dashboard", headers=h).json()
    by = {s["name"]: s for s in d["services"]}
    assert {n: s["status"] for n, s in by.items()} == {"calm-api": "healthy", "sick-api": "degraded", "dead-api": "down",
                                                      "quiet-api": "stale", "new-api": "unknown"}
    assert [s["name"] for s in d["services"]][:2] == ["dead-api", "sick-api"]                  # down first, then degraded
    assert d["summary"] == {"down": 1, "degraded": 1, "stale": 1, "unknown": 1, "healthy": 1, "services": 5, "open_incidents": 0}
    assert set(by["calm-api"]["sparks"]) == {"request_rate", "error_rate", "latency_p95_ms"}   # three headline series
    assert 1 < len(by["calm-api"]["sparks"]["error_rate"]) <= 120 and by["calm-api"]["latest"]["request_rate"] == 120
    assert "error rate 9.0%" in by["sick-api"]["reasons"]


def test_open_incidents_show_on_the_card_and_in_the_summary(client):
    feed("checkout-api", {"up": 1, "error_rate": 0.2})
    with connect_vector() as conn:
        ingest.raise_alert(conn, "checkout-api", "HighErrorRate", summary="5xx", severity="sev1", source="test")
        conn.commit()
    d = client.get("/api/dashboard", headers=token(client, "read")).json()
    card = d["services"][0]
    assert card["status"] == "degraded" and card["open_incidents"] == 1 and card["worst_severity"] == "sev1"
    assert d["summary"]["open_incidents"] == 1 and "open incident: HighErrorRate" in card["reasons"][0]


def test_a_service_page_has_every_metric_incidents_deploys_signatures_and_neighbours(client):
    feed("citypulse-ingest", {"up": 1, "ingest_rate": 90}, owner="city-platform", tier="critical", description="the gateway")
    feed("citypulse-fleet", {"fleet_health_pct": [99] * 20 + [55] * 10, "offline_pct": 0, "worst_district_pct": 90}, depends_on=["citypulse-ingest"])
    now = datetime.now(UTC)
    with connect_vector() as conn:
        ingest.ingest_deploy(conn, "citypulse-fleet", {"version": "1.4.0", "author": "ci", "summary": "new rules", "deployed_at": (now - timedelta(minutes=12)).isoformat()})
        ingest.ingest_logs(conn, "citypulse-fleet", [{"ts": (now - timedelta(minutes=m)).isoformat(), "level": "error", "message": f"sensor batch rejected for user{m}@example.com"} for m in range(1, 5)])
        ingest.raise_alert(conn, "citypulse-fleet", "SensorFleetDegraded", summary="fleet down", severity="sev2", source="test")
        conn.commit()
    h = token(client, "read")
    d = client.get("/api/services/citypulse-fleet?minutes=60", headers=h).json()
    assert d["name"] == "citypulse-fleet" and d["status"] == "degraded" and d["minutes"] == 60
    assert d["data_since"] is not None
    assert set(d["metrics"]) == {"fleet_health_pct", "offline_pct", "worst_district_pct"}
    fh = d["metrics"]["fleet_health_pct"]
    assert fh["latest"] == 55 and fh["min"] == 55 and fh["max"] == 99 and 2 <= len(fh["points"]) <= 120
    assert d["incidents"][0]["title"] == "SensorFleetDegraded" and d["deploys"][0]["version"] == "1.4.0"
    assert d["signatures"][0]["n"] == 4 and "@example.com" not in d["signatures"][0]["signature"]       # scrubbed at ingest
    assert d["log_counts"] == {"errors": 4, "total": 4}
    assert [(n["name"], n["relation"], n["status"]) for n in d["neighbours"]] == [("citypulse-ingest", "depends on", "healthy")]
    up = client.get("/api/services/citypulse-ingest", headers=h).json()
    assert [(n["name"], n["relation"]) for n in up["neighbours"]] == [("citypulse-fleet", "used by")]
    assert up["owner"] == "city-platform" and up["tier"] == "critical"


def test_bad_requests_and_scopes(client):
    feed("a-service", {"up": 1})
    rd, ing = token(client, "read"), token(client, "ingest")
    assert client.get("/api/services/ghost", headers=rd).status_code == 404
    assert client.get("/api/services/Not%20A%20Name", headers=rd).status_code == 404
    assert client.get("/api/services/a-service?minutes=2", headers=rd).status_code == 422
    assert client.get("/api/services/a-service?minutes=99999", headers=rd).status_code == 422
    assert client.get("/api/services/a-service?minutes=1440", headers=rd).status_code == 200
    assert client.get("/api/dashboard").status_code == 401
    assert client.get("/api/dashboard", headers=ing).status_code == 403                  # ingest tokens read nothing
    assert client.get("/api/services/a-service", headers=ing).status_code == 403
