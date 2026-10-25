"""The rules behind retire, stale and auto-resolve, without a database: the clock is an argument."""
from datetime import UTC, datetime, timedelta

import pytest

from pagerlens import dashboard, housekeeping

NOW = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)


def pts(name, value, minutes_ago):
    return [(name, value, NOW - timedelta(minutes=m)) for m in minutes_ago]


def test_a_service_is_stale_only_after_the_configured_silence():
    assert dashboard.is_stale(NOW - timedelta(minutes=61), NOW, 60)
    assert not dashboard.is_stale(NOW - timedelta(minutes=59), NOW, 60)
    assert not dashboard.is_stale(NOW - timedelta(days=3), NOW, 0)          # 0 turns the marker off
    assert not dashboard.is_stale(NOW - timedelta(days=3), NOW, None)
    assert not dashboard.is_stale(None, NOW, 60)                            # never reported: unknown, not stale


def test_recovered_means_healthy_and_reporting_throughout_the_window():
    ok = pts("up", 1, range(0, 31)) + pts("error_rate", 0.4, range(0, 31))
    assert housekeeping.healthy_throughout(ok, NOW, 30)[0]
    assert not housekeeping.healthy_throughout([], NOW, 30)[0]
    bad = pts("up", 1, range(0, 31)) + pts("error_rate", 7.0, [12])                       # one breach inside the window
    assert "error_rate" in housekeeping.healthy_throughout(bad, NOW, 30)[1]
    assert not housekeeping.healthy_throughout(pts("up", 1, range(0, 31)) + pts("db_up", 0, [3]), NOW, 30)[0]
    assert not housekeeping.healthy_throughout(pts("fleet_health_pct", 70, [1]), NOW, 30)[0]   # the "<" thresholds too
    assert housekeeping.healthy_throughout(pts("unlisted_metric", 1e9, range(0, 31)), NOW, 30)[0]


def test_a_service_that_only_just_came_back_has_not_recovered():
    just_back = pts("up", 1, range(0, 3))                      # healthy for 2 minutes of a 30 minute window
    assert not housekeeping.healthy_throughout(just_back, NOW, 30)[0]
    gap = pts("up", 1, [*range(0, 10), *range(20, 31)])         # silent from 10 to 20 minutes ago
    assert not housekeeping.healthy_throughout(gap, NOW, 30)[0]
    silent_now = pts("up", 1, range(10, 31))                    # nothing in the last ten minutes
    assert not housekeeping.healthy_throughout(silent_now, NOW, 30)[0]


def test_a_person_s_work_is_never_overridden():
    base = {"status": "open", "notes": 0, "runs": 0}
    assert housekeeping.blocked(base) is None
    assert housekeeping.blocked({**base, "status": "investigating"})
    assert housekeeping.blocked({**base, "notes": 1})
    assert housekeeping.blocked({**base, "runs": 1})


def test_the_alert_must_have_been_quiet_for_the_whole_period():
    detected = NOW - timedelta(hours=5)
    assert housekeeping.quiet(NOW - timedelta(minutes=31), detected, NOW, 30)
    assert not housekeeping.quiet(NOW - timedelta(minutes=29), detected, NOW, 30)
    assert housekeeping.quiet(None, detected, NOW, 30)                      # no alert row: counts from detection
    assert not housekeeping.quiet(None, NOW - timedelta(minutes=5), NOW, 30)


def test_settings_are_validated():
    assert housekeeping.check_settings({"auto_resolve_minutes": 0, "stale_after_minutes": 0}) == {"auto_resolve_minutes": 0, "stale_after_minutes": 0}
    assert housekeeping.check_settings({"stale_after_minutes": 5}) == {"stale_after_minutes": 5}
    for bad in ({"auto_resolve_minutes": -1}, {"auto_resolve_minutes": 99999}, {"stale_after_minutes": 3}, {"stale_after_minutes": "60"},
                {"stale_after_minutes": True}, {"stale_after_minutes": 1.5}, {"nope": 1}):
        with pytest.raises(ValueError):
            housekeeping.check_settings(bad)
