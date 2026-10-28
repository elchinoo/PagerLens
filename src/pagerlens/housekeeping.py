"""Keeping the dashboard honest: retire a service, resolve incidents in bulk, resolve recovered incidents by themselves.

None of these paths teaches the memory. An incident only becomes recallable when a person confirms a cause (`incidents.resolve`
sets `root_cause_category` and embeds it); everything here resolves with a note and no category, so nothing is learned from it.

Two settings, stored like the other instance settings (app_setting), changed in Settings or through the API:
  auto_resolve_minutes  0 = off (default 30): how long an alert must have stayed quiet and the service healthy
  stale_after_minutes   0 = off (default 60): no data for this long marks a service stale
"""
import contextlib
import logging
import os
import threading
from datetime import UTC, datetime, timedelta

from . import dashboard, ingest
from . import settings_store as store
from .incidents import NotFound

log = logging.getLogger("pagerlens.housekeeping")

DEFAULTS = {"auto_resolve_minutes": 30, "stale_after_minutes": 60}
LIMITS = {"auto_resolve_minutes": (0, 1440), "stale_after_minutes": (0, 43200)}
MIN_STALE = 5          # below the dashboard's own "no data" threshold a service would be stale while still counted as down
PASS_EVERY = 60        # seconds between background passes
MAX_BULK = 5000
HEALTH_FLAGS = ("up", "db_up", "sandbox_running")       # 1 = fine, 0 = not
_LOCK = 7204119        # advisory lock key: one replica runs a pass at a time


def _now() -> datetime:
    return datetime.now(UTC)


# --- settings ----------------------------------------------------------------------------------------------------------

def settings(conn) -> dict[str, int]:
    out = dict(DEFAULTS)
    for key in DEFAULTS:
        raw = store.get(conn, key)
        with contextlib.suppress(TypeError, ValueError):
            out[key] = int(raw)
    return out


def check_settings(values: dict) -> dict[str, int]:
    out: dict[str, int] = {}
    for key, value in values.items():
        if key not in DEFAULTS:
            raise ValueError(f"unknown setting {key!r}")
        lo, hi = LIMITS[key]
        if not isinstance(value, int) or isinstance(value, bool) or not lo <= value <= hi:
            raise ValueError(f"{key} must be a whole number of minutes between {lo} and {hi} (0 turns it off)")
        if key == "stale_after_minutes" and 0 < value < MIN_STALE:
            raise ValueError(f"stale_after_minutes must be 0 (off) or at least {MIN_STALE}")
        out[key] = value
    return out


def save_settings(conn, values: dict) -> dict[str, int]:
    for key, value in check_settings({k: v for k, v in values.items() if v is not None}).items():
        store.put(conn, key, str(value))
    return settings(conn)


# --- rules (pure: no database, the clock is an argument) ----------------------------------------------------------------

def unhealthy(name: str, value: float) -> bool:
    """One data point against the same limits the dashboard uses to call a service degraded or down."""
    if name in HEALTH_FLAGS:
        return value <= 0.5
    for metric, op, limit, _ in dashboard.THRESHOLDS:
        if metric == name:
            return value >= limit if op == ">=" else value < limit
    return False


def healthy_throughout(points: list[tuple[str, float, datetime]], now: datetime, minutes: int) -> tuple[bool, str]:
    """True when the service reported without a gap longer than the dashboard's 'no data' limit across the whole window
    [now - minutes, now] and not one point in it was over a limit. `points` are (metric, value, ts) inside the window."""
    if not points:
        return False, "no data in the window"
    start = now - timedelta(minutes=minutes)
    for name, value, ts in points:
        if unhealthy(name, value):
            return False, f"{name} was {value:g} at {ts:%H:%M}"
    stamps = sorted({ts for _, _, ts in points})
    gaps = [stamps[0] - start, *(b - a for a, b in zip(stamps, stamps[1:], strict=False)), now - stamps[-1]]
    if max(gaps) > dashboard.STALE_AFTER:
        return False, "the service did not report continuously during the window"
    return True, "healthy throughout"


def blocked(incident: dict) -> str | None:
    """Why a person's work must not be overridden (None: nobody has touched it). `incident` carries status, notes, runs."""
    if incident["status"] != "open":
        return f"status is {incident['status']}"
    if incident["notes"]:
        return "has a note"
    if incident["runs"]:
        return "has an investigation"
    return None


def quiet(last_alert: datetime | None, detected_at: datetime, now: datetime, minutes: int) -> bool:
    """The alert condition has not re-fired for `minutes` (an incident without an alert counts from its detection)."""
    return now - (last_alert or detected_at) >= timedelta(minutes=minutes)


# --- the background pass -----------------------------------------------------------------------------------------------

def auto_resolve_pass(conn, now: datetime | None = None) -> list[int]:
    """Resolve open incidents whose alert went quiet and whose service has been healthy for auto_resolve_minutes.
    Returns the ids resolved. Safe to run from several replicas at once (advisory lock) and re-checks every condition in the
    UPDATE itself, so a note or an investigation added a moment ago is never overridden."""
    minutes = settings(conn)["auto_resolve_minutes"]
    if not minutes:
        return []
    if not conn.execute("SELECT pg_try_advisory_xact_lock(%s) AS ok", (_LOCK,)).fetchone()["ok"]:
        return []
    now = now or _now()
    since = now - timedelta(minutes=minutes)
    candidates = conn.execute(
        "SELECT i.id, i.service_id, i.detected_at, i.status, "
        "(SELECT max(a.fired_at) FROM alert a WHERE a.incident_id = i.id) AS last_alert, "
        "(SELECT count(*) FROM incident_note n WHERE n.incident_id = i.id) AS notes, "
        "(SELECT count(*) FROM run r WHERE r.incident_id = i.id) AS runs "
        "FROM incident i WHERE i.status = 'open' AND i.service_id IS NOT NULL AND i.detected_at <= %s ORDER BY i.id", (since,)).fetchall()
    verdicts: dict[int, bool] = {}
    resolved: list[int] = []
    for inc in candidates:
        if blocked(inc) or not quiet(inc["last_alert"], inc["detected_at"], now, minutes):
            continue
        sid = inc["service_id"]
        if sid not in verdicts:
            pts = conn.execute("SELECT name, value, ts FROM metric_point WHERE service_id=%s AND ts >= %s AND ts <= %s",
                               (sid, since, now)).fetchall()
            verdicts[sid] = healthy_throughout([(p["name"], p["value"], p["ts"]) for p in pts], now, minutes)[0]
        if not verdicts[sid]:
            continue
        row = conn.execute(
            "UPDATE incident SET status='resolved', resolved_at=%s, root_cause_note='auto-resolved: recovered' "
            "WHERE id=%s AND status='open' AND NOT EXISTS (SELECT 1 FROM incident_note WHERE incident_id=incident.id) "
            "AND NOT EXISTS (SELECT 1 FROM run WHERE incident_id=incident.id) "
            "AND NOT EXISTS (SELECT 1 FROM alert WHERE incident_id=incident.id AND fired_at > %s) RETURNING id",
            (now, inc["id"], since)).fetchone()
        if row:
            resolved.append(row["id"])
    return resolved


def tuning_scan_minutes() -> float:
    try:
        return max(0.0, float(os.environ.get("PAGERLENS_TUNING_SCAN_MINUTES", "60")))
    except ValueError:
        return 60.0


_stop = threading.Event()
_thread: threading.Thread | None = None


def _loop() -> None:
    from .db import connect

    while not _stop.wait(PASS_EVERY):
        try:
            with connect(retries=1) as conn:
                done = auto_resolve_pass(conn)
                conn.commit()
            if done:
                log.info("auto-resolved %d recovered incident(s): %s", len(done), ", ".join(f"#{i}" for i in done))
        except Exception as exc:  # noqa: BLE001 - the database may be asleep or mid-migration; try again next minute
            log.warning("housekeeping pass failed: %s", str(exc)[:200])
        try:    # the tuning job: new PROPOSALS only (it changes nothing); PAGERLENS_TUNING_SCAN_MINUTES=0 turns it off
            from . import tuning

            with connect(retries=1) as conn:
                found = tuning.scan_if_due(conn, tuning_scan_minutes())
            if found and found["created"]:
                log.info("tuning scan: %d new proposal(s)", len(found["created"]))
        except Exception as exc:  # noqa: BLE001
            log.warning("tuning scan failed: %s", str(exc)[:200])


def start_background() -> bool:
    """One daemon thread per process; PAGERLENS_HOUSEKEEPING=false turns it off (the auto_resolve_minutes setting is the runtime switch)."""
    from apgkit.config import env_bool

    global _thread
    if not env_bool("PAGERLENS_HOUSEKEEPING", True) or (_thread and _thread.is_alive()):
        return False
    _stop.clear()
    _thread = threading.Thread(target=_loop, daemon=True, name="pagerlens-housekeeping")
    _thread.start()
    return True


def stop_background() -> None:
    _stop.set()


# --- retire a service --------------------------------------------------------------------------------------------------

def _note(conn, ids: list[int], author: str, body: str) -> None:
    if ids:
        conn.execute("INSERT INTO incident_note (incident_id, author, body) SELECT unnest(%s::bigint[]), %s, %s",
                     (ids, author[:40], body[:4000]))


def retire_service(conn, name: str, *, actor: str = "operator", now: datetime | None = None) -> dict:
    """Remove a service from the dashboard together with its metric points, log events, deploys and dependency edges.
    Its open incidents are resolved as `service retired` (no cause, nothing embedded) and kept as history under the service's
    name. Telemetry that arrives later for the same name simply creates the service again."""
    name = ingest.check_name(name)
    row = conn.execute("SELECT id FROM service WHERE name=%s FOR UPDATE", (name,)).fetchone()
    if not row:
        raise NotFound("no such service")
    sid, now = row["id"], now or _now()
    conn.execute("UPDATE incident SET service_name=%s WHERE service_id=%s", (name, sid))
    closed = [r["id"] for r in conn.execute(
        "UPDATE incident SET status='resolved', resolved_at=%s, root_cause_note='service retired' "
        "WHERE service_id=%s AND status <> 'resolved' RETURNING id", (now, sid)).fetchall()]
    _note(conn, closed, actor, f"service {name} was retired by {actor}")
    counts = {}
    for table in ("metric_point", "log_event", "deploy"):
        counts[table] = conn.execute(f"DELETE FROM {table} WHERE service_id=%s", (sid,)).rowcount  # noqa: S608 - fixed names
    edges = conn.execute("UPDATE service SET depends_on = array_remove(depends_on, %s) WHERE %s = ANY(depends_on)",
                         (name, name)).rowcount
    store.delete(conn, f"otlp_version:{name}")
    conn.execute("DELETE FROM service WHERE id=%s", (sid,))
    return {"retired": name, "incidents_resolved": closed, "metric_points": counts["metric_point"],
            "log_events": counts["log_event"], "deploys": counts["deploy"], "dependency_edges": edges}


# --- resolve many incidents ---------------------------------------------------------------------------------------------

def bulk_resolve(conn, reason: str, *, ids: list[int] | None = None, match: dict | None = None,
                 actor: str = "operator", now: datetime | None = None) -> dict:
    """Resolve the given incidents (`ids`), or every unresolved incident matching `match` ({status?, service?}: an empty
    dict matches them all), with a reason and no cause: nothing is embedded or remembered. Each incident gets a note saying
    who did it. Already resolved incidents are left alone."""
    reason = (reason or "").strip()
    if not reason:
        raise ValueError("a reason is required")
    if (ids is None) == (match is None):
        raise ValueError("choose either the selected incidents or a filter, not both and not neither")
    status, service = (match or {}).get("status"), (match or {}).get("service")
    if status not in (None, "open", "investigating"):
        raise ValueError("a filter can only match open or investigating incidents")
    now = now or _now()
    note = f"bulk resolved: {reason}"[:1000]
    found = [r["id"] for r in conn.execute(
        "UPDATE incident SET status='resolved', resolved_at=%s, root_cause_note=%s WHERE status <> 'resolved' "
        "AND (%s::bigint[] IS NULL OR id = ANY(%s)) AND (%s::text IS NULL OR status = %s) "
        "AND (%s::text IS NULL OR COALESCE((SELECT name FROM service s WHERE s.id = incident.service_id), service_name) = %s) "
        "RETURNING id", (now, note, ids, ids, status, status, service, service)).fetchall()]
    if len(found) > MAX_BULK:
        raise ValueError(f"that would resolve {len(found)} incidents; narrow the filter (limit {MAX_BULK})")
    _note(conn, found, actor, f"resolved in bulk by {actor}: {reason}")
    return {"resolved": len(found), "ids": found[:200]}
