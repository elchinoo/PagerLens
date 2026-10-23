"""Telemetry ingest: services, deploys, logs, metrics and alerts. Everything is validated, bounded and scrubbed."""
import hashlib
import json
import re
from datetime import UTC, datetime, timedelta

from . import retrieval
from .scrub import normalise_level, scrub, scrub_value, signature

MAX_BATCH = 1000
NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")
METRIC_NAME = re.compile(r"^[a-z][a-z0-9_]{0,48}$")
SEVERITIES = {"sev1", "sev2", "sev3", "sev4"}
_MAX_AGE, _MAX_FUTURE = timedelta(days=14), timedelta(minutes=5)


class IngestError(ValueError):
    pass


def _now() -> datetime:
    return datetime.now(UTC)


def parse_ts(value, *, default: datetime | None = None) -> datetime:
    if value is None:
        if default is None:
            raise IngestError("timestamp is required")
        return default
    try:
        ts = datetime.fromtimestamp(float(value), UTC) if isinstance(value, (int, float)) else \
            datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (ValueError, OverflowError, OSError) as exc:
        raise IngestError(f"invalid timestamp: {str(value)[:40]!r}") from exc
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=UTC)
    now = _now()
    if ts < now - _MAX_AGE or ts > now + _MAX_FUTURE:
        raise IngestError("timestamp outside the accepted window (14 days back, 5 minutes ahead)")
    return ts


def check_name(name: str) -> str:
    name = (name or "").strip().lower()
    if not NAME.match(name):
        raise IngestError("service name must be lowercase letters, digits, '.', '_' or '-' (max 63 chars)")
    return name


def upsert_service(conn, name: str, *, owner=None, tier=None, description=None, depends_on=None) -> int:
    name = check_name(name)
    deps = [check_name(d) for d in (depends_on or [])][:20]
    row = conn.execute(
        "INSERT INTO service (name, owner, tier, description, depends_on) VALUES (%s,%s,%s,%s,%s) "
        "ON CONFLICT (name) DO UPDATE SET owner=COALESCE(EXCLUDED.owner, service.owner), "
        "tier=COALESCE(EXCLUDED.tier, service.tier), description=COALESCE(EXCLUDED.description, service.description), "
        "depends_on=CASE WHEN %s THEN EXCLUDED.depends_on ELSE service.depends_on END RETURNING id",
        (name, _clip(owner, 80), _clip(tier, 40), _clip(description, 300), deps, depends_on is not None),
    ).fetchone()
    return row["id"]


def _clip(value, n: int):
    return None if value is None else str(value)[:n]


def service_id(conn, name: str, *, create: bool = True) -> int:
    name = check_name(name)
    row = conn.execute("SELECT id FROM service WHERE name=%s", (name,)).fetchone()
    if row:
        return row["id"]
    if not create:
        raise IngestError(f"unknown service {name!r}")
    return upsert_service(conn, name)


def ingest_logs(conn, service: str, events: list[dict]) -> int:
    if not isinstance(events, list) or not events or len(events) > MAX_BATCH:
        raise IngestError(f"send between 1 and {MAX_BATCH} log events per request")
    sid = service_id(conn, service)
    now = _now()
    rows = []
    for ev in events:
        if not isinstance(ev, dict) or not isinstance(ev.get("message"), str):
            raise IngestError("each log event needs a string 'message'")
        msg = scrub(ev["message"])
        rows.append((sid, parse_ts(ev.get("ts"), default=now), normalise_level(str(ev.get("level", "info"))), msg,
                     json.dumps(scrub_value(ev.get("fields") or {})), signature(msg)))
    with conn.cursor() as cur:
        cur.executemany("INSERT INTO log_event (service_id, ts, level, message, fields, signature) "
                        "VALUES (%s,%s,%s,%s,%s::jsonb,%s)", rows)
    return len(rows)


def ingest_metrics(conn, service: str, points: list[dict]) -> int:
    if not isinstance(points, list) or not points or len(points) > MAX_BATCH:
        raise IngestError(f"send between 1 and {MAX_BATCH} metric points per request")
    sid = service_id(conn, service)
    now = _now()
    rows = []
    for p in points:
        name = str(p.get("name", "")) if isinstance(p, dict) else ""
        if not METRIC_NAME.match(name):
            raise IngestError("metric 'name' must be snake_case (letters, digits, underscore)")
        try:
            value = float(p["value"])
        except (KeyError, TypeError, ValueError) as exc:
            raise IngestError("each metric point needs a numeric 'value'") from exc
        if value != value or abs(value) > 1e15:
            raise IngestError("metric value out of range")
        rows.append((sid, name, parse_ts(p.get("ts"), default=now), value))
    with conn.cursor() as cur:
        cur.executemany("INSERT INTO metric_point (service_id, name, ts, value) VALUES (%s,%s,%s,%s) "
                        "ON CONFLICT (service_id, name, ts) DO UPDATE SET value=EXCLUDED.value", rows)
    return len(rows)


def ingest_deploy(conn, service: str, d: dict) -> int:
    sid = service_id(conn, service)
    version = _clip(d.get("version"), 80)
    if not version:
        raise IngestError("a deploy needs a 'version'")
    row = conn.execute(
        "INSERT INTO deploy (service_id, version, git_sha, author, summary, deployed_at) VALUES (%s,%s,%s,%s,%s,%s) "
        "RETURNING id",
        (sid, version, _clip(d.get("git_sha"), 64), _clip(d.get("author"), 80),
         scrub(str(d.get("summary", ""))[:300]) or None, parse_ts(d.get("ts"), default=_now())),
    ).fetchone()
    return row["id"]


def _fingerprint(service: str, name: str) -> str:
    return hashlib.sha256(f"{service}|{signature(name)}".encode()).hexdigest()[:16]


def raise_alert(conn, service: str, name: str, *, summary: str | None = None, severity: str = "sev3",
                labels: dict | None = None, source: str = "webhook", fired_at: datetime | None = None) -> dict:
    """Record an alert and attach it to an open incident, or open a new one (triage + dedupe)."""
    sid = service_id(conn, service)
    name = scrub(name)[:200]
    severity = severity if severity in SEVERITIES else "sev3"
    summary = scrub(summary or name)[:500]
    fired = fired_at or _now()
    fp = _fingerprint(service, name)
    vec = retrieval.query_vector(conn, f"{service}: {name}. {summary}", "incident")   # None: dedupe by fingerprint only
    similar = "OR (embedding IS NOT NULL AND 1 - (embedding <=> %s) > 0.9)" if vec is not None else ""
    existing = conn.execute(
        "SELECT id FROM incident WHERE service_id=%s AND status <> 'resolved' AND detected_at > now() - interval '3 hours' "
        f"AND (fingerprint=%s {similar}) "  # noqa: S608 - fixed fragment
        "ORDER BY detected_at DESC LIMIT 1", (sid, fp, *([vec] if vec is not None else []))).fetchone()
    if existing:
        incident_id, created = existing["id"], False
    else:
        incident_id = conn.execute(
            "INSERT INTO incident (service_id, title, severity, fingerprint, symptom, detected_at, embedding) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING id",
            (sid, name, severity, fp, summary, fired, vec)).fetchone()["id"]
        created = True
    alert_id = conn.execute(
        "INSERT INTO alert (service_id, incident_id, source, name, severity, summary, labels, fired_at) "
        "VALUES (%s,%s,%s,%s,%s,%s,%s::jsonb,%s) RETURNING id",
        (sid, incident_id, source[:40], name, severity, summary, json.dumps(scrub_value(labels or {})), fired),
    ).fetchone()["id"]
    return {"alert_id": alert_id, "incident_id": incident_id, "new_incident": created}
