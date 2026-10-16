"""The dashboard's verdict logic (no database needed)."""
from datetime import UTC, datetime, timedelta

from pagerlens.dashboard import judge

NOW = datetime(2026, 10, 16, 12, 0, tzinfo=UTC)
FRESH, OLD = NOW - timedelta(seconds=20), NOW - timedelta(minutes=9)


def m(**kv):
    return {k: (v, FRESH) for k, v in kv.items()}


def inc(title="HighErrorRate", sev="sev2"):
    return {"title": title, "severity": sev}


def test_a_quiet_service_is_healthy_and_a_new_one_is_unknown():
    assert judge(m(up=1, error_rate=0.4, cpu_pct=30), [], NOW) == ("healthy", [])
    assert judge({}, [], NOW) == ("unknown", ["has not reported yet"])


def test_a_failing_probe_or_a_stopped_sandbox_is_down_and_beats_everything_else():
    status, why = judge(m(up=0, error_rate=50), [inc()], NOW)
    assert status == "down" and why == ["health checks are failing"]
    assert judge(m(up=0, sandbox_running=0), [], NOW)[1] == ["health checks are failing", "the platform reports the sandbox is not running"]


def test_thresholds_make_a_service_degraded_with_a_reason_each():
    status, why = judge(m(up=1, error_rate=8.2, mem_pct=95, db_up=0), [], NOW)
    assert status == "degraded"
    assert "error rate 8.2%" in why and "memory 95%" in why and "its database is unreachable" in why
    assert judge(m(fleet_health_pct=60, offline_pct=12), [], NOW)[1] == ["fleet health 60%", "12% of sensors offline"]
    assert judge(m(fleet_health_pct=99, offline_pct=0), [], NOW)[0] == "healthy"


def test_an_open_incident_degrades_a_service_that_looks_fine_and_names_the_worst_one():
    status, why = judge(m(up=1, error_rate=0.2), [inc("Minor", "sev4"), inc("Checkout down", "sev1")], NOW)
    assert status == "degraded" and why == ["open incident: Checkout down (+1 more)"]
    assert judge({}, [inc()], NOW)[0] == "degraded"                                  # an incident with no telemetry at all


def test_silence_is_stale_but_a_fault_in_old_data_is_not_trusted():
    stale = {"up": (1, OLD), "error_rate": (90.0, OLD)}
    assert judge(stale, [], NOW) == ("stale", ["no data for 9 min"])               # an old reading must not raise a threshold alarm
    assert judge({"up": (0, OLD)}, [], NOW)[0] == "stale"                            # nor call a silent service down
    assert judge(stale, [inc()], NOW)[0] == "degraded"
