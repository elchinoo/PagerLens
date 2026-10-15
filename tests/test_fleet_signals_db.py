"""Sensor-fleet failures as CityPulse reports them: an ingest tier and a fleet service that depends on it."""
import os
from datetime import UTC, datetime, timedelta

import pytest

if not os.environ.get("TEST_DATABASE_URL"):
    pytest.skip("set TEST_DATABASE_URL to run DB tests", allow_module_level=True)

from pagerlens import ingest, investigator, migrate, simulator, vault  # noqa: E402
from pagerlens.db import connect, connect_vector  # noqa: E402

CAT = {"ingest_overload", "sensor_fleet_outage", "data_quality"}


@pytest.fixture(autouse=True)
def _db(monkeypatch, client):
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    vault.lock()
    with connect() as c:
        c.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public")
        c.commit()
    migrate.run()


def run(ingest_metrics, fleet_metrics, minutes=91, bad_from=78):
    """Each metric is (value before, value during). Series start `minutes` ago; the bad value starts at index bad_from."""
    now = datetime.now(UTC).replace(second=0, microsecond=0)
    with connect_vector() as conn:
        simulator.seed_runbooks(conn)
        ingest.upsert_service(conn, "city-ingest")
        ingest.upsert_service(conn, "city-fleet", depends_on=["city-ingest"])
        for svc, metrics in (("city-ingest", ingest_metrics), ("city-fleet", fleet_metrics)):
            for name, (before, during) in metrics.items():
                pts = [{"name": name, "value": during if i >= bad_from else before,
                        "ts": (now - timedelta(minutes=minutes - 1 - i)).isoformat()} for i in range(minutes)]
                ingest.ingest_metrics(conn, svc, pts)
        info = ingest.raise_alert(conn, "city-fleet", "SensorFleetDegraded", summary="fleet degraded", source="citypulse", fired_at=now)
        conn.commit()
        run_id = investigator.investigate(conn, info["incident_id"], use_memory=False)
        hyps = conn.execute("SELECT category, score, explanation FROM hypothesis WHERE run_id=%s ORDER BY rank", (run_id,)).fetchall()
        report = conn.execute("SELECT markdown FROM report WHERE run_id=%s", (run_id,)).fetchone()["markdown"]
    return hyps, report


HEALTHY_INGEST = {"up": (1, 1), "overloaded_pct": (0, 0), "reject_pct": (0, 0), "latency_p95_ms": (50, 55), "ingest_rate": (100, 100)}
HEALTHY_FLEET = {"fleet_health_pct": (99, 99), "offline_pct": (0, 0), "stale_pct": (0, 0), "fault_pct": (0, 0),
                 "stuck_pct": (0, 0), "worst_district_pct": (98, 98)}


def test_a_flood_that_saturates_the_gateway_is_ingest_overload():
    hyps, report = run({**HEALTHY_INGEST, "overloaded_pct": (0, 60), "latency_p95_ms": (50, 3000), "ingest_rate": (100, 600)},
                       {**HEALTHY_FLEET, "fleet_health_pct": (99, 55), "stale_pct": (0, 40)})
    assert hyps[0]["category"] == "ingest_overload" and hyps[0]["score"] > 0.8
    assert "delayed behind the overload" in hyps[0]["explanation"] and "flooding" in hyps[0]["explanation"]
    assert "Collection tier overloaded" in report
    assert "sensor_fleet_outage" not in [h["category"] for h in hyps]       # stale-only is not an outage


def test_a_slow_gateway_that_never_says_429_is_still_ingest_overload():
    """Seen live: a single sender is throttled by latency, so batches are never refused, yet every sensor goes stale."""
    hyps, _ = run({**HEALTHY_INGEST, "latency_p95_ms": (50, 2500), "reject_pct": (0, 16)},
                  {**HEALTHY_FLEET, "fleet_health_pct": (99, 60), "stale_pct": (0, 40)})
    assert hyps[0]["category"] == "ingest_overload"
    assert "too slowly to keep up" in hyps[0]["explanation"]
    assert hyps[0]["score"] > [h for h in hyps if h["category"] == "data_quality"][0]["score"]


def test_one_dark_district_is_a_regional_sensor_outage_not_an_overload():
    hyps, report = run(HEALTHY_INGEST, {**HEALTHY_FLEET, "fleet_health_pct": (99, 91), "offline_pct": (0, 9), "worst_district_pct": (98, 4)})
    assert hyps[0]["category"] == "sensor_fleet_outage"
    assert "regional" in hyps[0]["explanation"]
    assert "Sensors stopped reporting" in report
    assert not {"ingest_overload"} & {h["category"] for h in hyps}


def test_rejected_out_of_range_and_frozen_readings_are_data_quality():
    hyps, report = run({**HEALTHY_INGEST, "reject_pct": (0, 15)}, {**HEALTHY_FLEET, "fault_pct": (0, 6), "stuck_pct": (0, 9), "fleet_health_pct": (99, 85)})
    assert hyps[0]["category"] == "data_quality"
    assert "rejected as malformed" in hyps[0]["explanation"] and "frozen" in hyps[0]["explanation"]
    assert "Sensors sending bad data" in report


def test_a_full_burst_names_the_overload_first_and_keeps_the_other_causes():
    hyps, _ = run({**HEALTHY_INGEST, "overloaded_pct": (0, 45), "reject_pct": (0, 12), "latency_p95_ms": (50, 2500), "ingest_rate": (100, 700)},
                  {**HEALTHY_FLEET, "fleet_health_pct": (99, 20), "stale_pct": (0, 50), "offline_pct": (0, 12), "fault_pct": (0, 4),
                   "stuck_pct": (0, 5), "worst_district_pct": (98, 3)})
    cats = [h["category"] for h in hyps]
    assert cats[0] == "ingest_overload" and {"data_quality", "sensor_fleet_outage"} <= set(cats)
    by = {h["category"]: h for h in hyps}
    assert "may be effect, not cause" in by["sensor_fleet_outage"]["explanation"] or by["sensor_fleet_outage"]["score"] < by["ingest_overload"]["score"]


def test_a_healthy_city_raises_none_of_the_fleet_hypotheses():
    hyps, _ = run(HEALTHY_INGEST, HEALTHY_FLEET)
    assert not CAT & {h["category"] for h in hyps}


def test_a_city_monitored_for_only_three_minutes_is_still_diagnosed():
    """The first incident can arrive right after CityPulse starts reporting: no baseline window exists."""
    hyps, _ = run({**HEALTHY_INGEST, "overloaded_pct": (0, 70)}, {**HEALTHY_FLEET, "fleet_health_pct": (10, 10), "stale_pct": (80, 80)},
                  minutes=3, bad_from=0)
    assert hyps[0]["category"] == "ingest_overload"


def test_a_slow_gateway_is_diagnosed_even_with_no_baseline_for_its_latency():
    hyps, _ = run({**HEALTHY_INGEST, "latency_p95_ms": (2500, 2500)}, {**HEALTHY_FLEET, "fleet_health_pct": (60, 60), "stale_pct": (40, 40)},
                  minutes=6, bad_from=0)
    assert hyps[0]["category"] == "ingest_overload"
