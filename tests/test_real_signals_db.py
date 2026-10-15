"""Failures reported by the agent (probes, scrapes, sandbox status) rather than by the simulator."""
import os
from datetime import UTC, datetime, timedelta

import pytest

if not os.environ.get("TEST_DATABASE_URL"):
    pytest.skip("set TEST_DATABASE_URL to run DB tests", allow_module_level=True)

from pagerlens import ingest, investigator, migrate, simulator, vault  # noqa: E402
from pagerlens.db import connect, connect_vector  # noqa: E402


@pytest.fixture(autouse=True)
def _db(monkeypatch, client):
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    vault.lock()
    with connect() as c:
        c.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public")
        c.commit()
    migrate.run()


def scenario(metrics, logs, alert="ServiceDown"):
    """metrics: name -> (value before, value during the last 12 minutes). Returns the investigation's hypotheses."""
    now = datetime.now(UTC).replace(second=0, microsecond=0)
    with connect_vector() as conn:
        simulator.seed_runbooks(conn)
        ingest.upsert_service(conn, "app-x")
        for name, (before, during) in metrics.items():
            pts = [{"name": name, "value": during if i >= 78 else before, "ts": (now - timedelta(minutes=90 - i)).isoformat()}
                   for i in range(91)]
            ingest.ingest_metrics(conn, "app-x", pts)
        ingest.ingest_logs(conn, "app-x", [{"ts": (now - timedelta(minutes=m)).isoformat(), "level": "error", "message": msg}
                                           for m in range(1, 11) for msg in logs])
        info = ingest.raise_alert(conn, "app-x", alert, summary="agent alert", source="pagerlens-agent", fired_at=now)
        conn.commit()
        run_id = investigator.investigate(conn, info["incident_id"], use_memory=False)
        hyps = conn.execute("SELECT category, score FROM hypothesis WHERE run_id=%s ORDER BY rank", (run_id,)).fetchall()
        report = conn.execute("SELECT markdown FROM report WHERE run_id=%s", (run_id,)).fetchone()["markdown"]
    return hyps, report


def test_a_refused_connection_is_service_down_and_gets_a_relevant_runbook():
    hyps, report = scenario({"up": (1, 0), "error_rate": (0, 100)}, ["health probe failed: connection error: ConnectError"])
    assert hyps[0]["category"] == "service_down" and hyps[0]["score"] > 0.8
    assert "Service stopped answering health checks" in report          # not the certificate or rollback runbooks
    assert "connections are refused or unreachable" in report


def test_a_paused_sandbox_is_named_as_such_and_outranks_a_generic_outage():
    hyps, report = scenario({"up": (1, 0), "sandbox_running": (1, 0)},
                            ["health probe failed: HTTP 503 (expected 200)", "sandbox is paused (the platform may have auto-paused it)"],
                            alert="SandboxNotRunning")
    assert [h["category"] for h in hyps][:2] == ["sandbox_paused", "service_down"]
    assert "agentpg sandbox resume" in report


def test_a_database_outage_behind_a_healthy_service_is_not_called_service_down():
    hyps, _ = scenario({"up": (1, 1), "db_up": (1, 0)}, ["metrics scrape failed: ReadTimeout"], alert="DatabaseDown")
    assert hyps[0]["category"] == "database_unreachable"
    assert "service_down" not in [h["category"] for h in hyps]


def test_a_healthy_service_raises_none_of_the_new_hypotheses():
    hyps, _ = scenario({"up": (1, 1), "sandbox_running": (1, 1), "db_up": (1, 1)}, ["unrelated warning"], alert="Noise")
    assert not {"service_down", "sandbox_paused", "database_unreachable"} & {h["category"] for h in hyps}


def test_a_newly_monitored_service_with_three_minutes_of_history_is_still_diagnosed():
    """The first real incident arrives minutes after the agent starts: there is no baseline window yet."""
    now = datetime.now(UTC).replace(second=0, microsecond=0)
    with connect_vector() as conn:
        simulator.seed_runbooks(conn)
        ingest.upsert_service(conn, "fresh-app")
        ingest.ingest_metrics(conn, "fresh-app", [{"name": "up", "value": 0.0, "ts": (now - timedelta(minutes=m)).isoformat()} for m in range(0, 3)])
        ingest.ingest_logs(conn, "fresh-app", [{"ts": (now - timedelta(minutes=m)).isoformat(), "level": "error",
                                                "message": "health probe failed: connection error: ConnectError"} for m in range(0, 3)])
        info = ingest.raise_alert(conn, "fresh-app", "ServiceDown", summary="3 failed checks", source="pagerlens-agent", fired_at=now)
        conn.commit()
        run_id = investigator.investigate(conn, info["incident_id"], use_memory=False)
        top = conn.execute("SELECT category, explanation FROM hypothesis WHERE run_id=%s ORDER BY rank LIMIT 1", (run_id,)).fetchone()
    assert top["category"] == "service_down" and "no earlier history" in top["explanation"]


def test_an_outage_seconds_old_is_not_averaged_away_by_earlier_healthy_checks():
    now = datetime.now(UTC).replace(second=0, microsecond=0)
    with connect_vector() as conn:
        simulator.seed_runbooks(conn)
        ingest.upsert_service(conn, "just-failed")
        pts = [{"name": "up", "value": 0.0 if i >= 88 else 1.0, "ts": (now - timedelta(minutes=90 - i)).isoformat()} for i in range(91)]
        ingest.ingest_metrics(conn, "just-failed", pts)
        ingest.ingest_logs(conn, "just-failed", [{"ts": (now - timedelta(minutes=m)).isoformat(), "level": "error",
                                                  "message": "health probe failed: HTTP 503 (expected 200)"} for m in (0, 1, 2)])
        info = ingest.raise_alert(conn, "just-failed", "ServiceDown", summary="x", source="pagerlens-agent", fired_at=now)
        conn.commit()
        run_id = investigator.investigate(conn, info["incident_id"], use_memory=False)
        top = conn.execute("SELECT category FROM hypothesis WHERE run_id=%s ORDER BY rank LIMIT 1", (run_id,)).fetchone()
    assert top["category"] == "service_down"
