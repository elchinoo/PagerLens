"""The dashboard: one verdict per monitored service, and a deep view of a single service.

A service's status is derived from what it reports, never configured:
  down      the latest health probe failed (`up` = 0) or the platform says the sandbox is not running
  degraded  an open incident, or a signal over its threshold (errors, memory, CPU, a refused database, sensor-fleet shares)
  stale     it has reported before but nothing arrived for 5 minutes
  unknown   it has never reported
  healthy   none of the above
"""
from datetime import UTC, datetime, timedelta

STALE_AFTER = timedelta(minutes=5)
STATUS_RANK = {"down": 0, "degraded": 1, "stale": 2, "unknown": 3, "healthy": 4}
SEVERITY_RANK = {"sev1": 0, "sev2": 1, "sev3": 2, "sev4": 3}
# Shown on a card, in this order of preference (the first three the service actually reports).
CARD_METRICS = ("request_rate", "error_rate", "latency_p95_ms", "fleet_health_pct", "ingest_rate", "overloaded_pct",
                "cpu_pct", "mem_pct", "offline_pct", "reject_pct", "db_connections")
# (metric, comparison, threshold, wording)
THRESHOLDS = (
    ("error_rate", ">=", 5.0, "error rate {v:.1f}%"),
    ("mem_pct", ">=", 90.0, "memory {v:.0f}%"),
    ("cpu_pct", ">=", 90.0, "CPU {v:.0f}%"),
    ("fleet_health_pct", "<", 85.0, "fleet health {v:.0f}%"),
    ("overloaded_pct", ">=", 5.0, "{v:.0f}% of batches refused as overloaded"),
    ("offline_pct", ">=", 5.0, "{v:.0f}% of sensors offline"),
    ("fault_pct", ">=", 3.0, "{v:.0f}% of sensors faulty"),
    ("reject_pct", ">=", 5.0, "{v:.0f}% of readings rejected"),
)


def _now() -> datetime:
    return datetime.now(UTC)


def judge(latest: dict[str, tuple[float, datetime]], incidents: list[dict], now: datetime | None = None) -> tuple[str, list[str]]:
    """(status, reasons) from the newest value of each metric and the open incidents."""
    now = now or _now()
    reasons: list[str] = []
    if not latest:
        return ("degraded", [f"open incident: {incidents[0]['title']}"]) if incidents else ("unknown", ["has not reported yet"])
    newest = max(ts for _, ts in latest.values())
    fresh = now - newest <= STALE_AFTER
    down: list[str] = []
    if fresh:
        if "up" in latest and latest["up"][0] <= 0.5:
            down.append("health checks are failing")
        if "sandbox_running" in latest and latest["sandbox_running"][0] <= 0.5:
            down.append("the platform reports the sandbox is not running")
    if down:
        return "down", down
    if fresh:
        if "db_up" in latest and latest["db_up"][0] <= 0.5:
            reasons.append("its database is unreachable")
        for name, op, limit, text in THRESHOLDS:
            if name in latest:
                v = latest[name][0]
                if (v >= limit) if op == ">=" else (v < limit):
                    reasons.append(text.format(v=v))
    if incidents:
        worst = min(incidents, key=lambda i: SEVERITY_RANK.get(i["severity"], 9))
        more = f" (+{len(incidents) - 1} more)" if len(incidents) > 1 else ""
        reasons.append(f"open incident: {worst['title']}{more}")
    if reasons:
        return "degraded", reasons
    if not fresh:
        mins = int((now - newest).total_seconds() // 60)
        return "stale", [f"no data for {mins} min"]
    return "healthy", []


def _latest(conn) -> dict[int, dict[str, tuple[float, datetime]]]:
    out: dict[int, dict[str, tuple[float, datetime]]] = {}
    for r in conn.execute("SELECT DISTINCT ON (service_id, name) service_id, name, value, ts FROM metric_point "
                          "ORDER BY service_id, name, ts DESC"):
        out.setdefault(r["service_id"], {})[r["name"]] = (r["value"], r["ts"])
    return out


def _open_incidents(conn) -> dict[int, list[dict]]:
    out: dict[int, list[dict]] = {}
    for r in conn.execute("SELECT id, service_id, title, severity, status, detected_at FROM incident "
                          "WHERE status <> 'resolved' ORDER BY detected_at DESC"):
        out.setdefault(r["service_id"], []).append(r)
    return out


def _bucket_seconds(minutes: int) -> int:
    return max(10, minutes * 60 // 120)


def series(conn, service_id: int, names: list[str], minutes: int) -> dict[str, list[list]]:
    """Per metric, at most ~120 points (averaged in time buckets) covering the last `minutes`."""
    if not names:
        return {}
    out: dict[str, list[list]] = {n: [] for n in names}
    rows = conn.execute(
        "SELECT name, date_bin(make_interval(secs => %s), ts, TIMESTAMPTZ '2000-01-01') AS b, avg(value) AS v "
        "FROM metric_point WHERE service_id=%s AND name = ANY(%s) AND ts > now() - make_interval(mins => %s) "
        "GROUP BY 1, 2 ORDER BY 2", (_bucket_seconds(minutes), service_id, names, minutes)).fetchall()
    for r in rows:
        out[r["name"]].append([r["b"].isoformat(), round(r["v"], 4)])
    return out


def overview(conn) -> dict:
    """Every monitored service with its verdict, headline numbers and sparklines, worst first."""
    now = _now()
    services = conn.execute("SELECT id, name, owner, tier, description, depends_on FROM service ORDER BY name").fetchall()
    latest, incidents = _latest(conn), _open_incidents(conn)
    cards = []
    for s in services:
        mine, inc = latest.get(s["id"], {}), incidents.get(s["id"], [])
        status, reasons = judge(mine, inc, now)
        names = [m for m in CARD_METRICS if m in mine][:3]
        cards.append({
            "name": s["name"], "owner": s["owner"], "tier": s["tier"], "description": s["description"],
            "depends_on": s["depends_on"], "status": status, "reasons": reasons,
            "open_incidents": len(inc), "worst_severity": min((i["severity"] for i in inc), key=lambda x: SEVERITY_RANK.get(x, 9), default=None),
            "last_seen": max((ts for _, ts in mine.values()), default=None),
            "latest": {n: v for n, (v, _) in mine.items()},
            "sparks": series(conn, s["id"], names, 60),
        })
    cards.sort(key=lambda c: (STATUS_RANK[c["status"]], SEVERITY_RANK.get(c["worst_severity"] or "sev4", 9), c["name"]))
    counts = {k: sum(1 for c in cards if c["status"] == k) for k in STATUS_RANK}
    return {"summary": {**counts, "services": len(cards), "open_incidents": sum(c["open_incidents"] for c in cards)}, "services": cards}


def service_detail(conn, name: str, minutes: int) -> dict | None:
    """Everything about one service: verdict, every metric as a series, incidents, deploys, error signatures, neighbours."""
    s = conn.execute("SELECT id, name, owner, tier, description, depends_on, created_at FROM service WHERE name=%s", (name,)).fetchone()
    if not s:
        return None
    now = _now()
    latest_all, incidents_all = _latest(conn), _open_incidents(conn)
    mine = latest_all.get(s["id"], {})
    status, reasons = judge(mine, incidents_all.get(s["id"], []), now)
    names = sorted(mine, key=lambda m: (m not in CARD_METRICS, CARD_METRICS.index(m) if m in CARD_METRICS else 0, m))[:24]
    data = series(conn, s["id"], names, minutes)
    metrics = {n: {"points": data[n], "latest": mine[n][0], "latest_ts": mine[n][1],
                   "min": min((p[1] for p in data[n]), default=None), "max": max((p[1] for p in data[n]), default=None)}
               for n in names}
    window = timedelta(minutes=minutes)
    incidents = conn.execute(
        "SELECT id, title, severity, status, detected_at, resolved_at, root_cause_category FROM incident "
        "WHERE service_id=%s AND (status <> 'resolved' OR detected_at > %s) ORDER BY detected_at DESC LIMIT 25",
        (s["id"], now - max(window, timedelta(days=7)))).fetchall()
    deploys = conn.execute("SELECT version, author, summary, deployed_at FROM deploy WHERE service_id=%s "
                           "ORDER BY deployed_at DESC LIMIT 10", (s["id"],)).fetchall()
    signatures = conn.execute(
        "SELECT signature, count(*) AS n, max(ts) AS last_seen, (array_agg(level ORDER BY ts DESC))[1] AS level "
        "FROM log_event WHERE service_id=%s AND level IN ('warn','error','fatal') AND ts > now() - make_interval(mins => %s) "
        "GROUP BY signature ORDER BY n DESC LIMIT 8", (s["id"], min(max(minutes, 30), 1440))).fetchall()
    logs = conn.execute("SELECT count(*) FILTER (WHERE level IN ('error','fatal')) AS errors, count(*) AS total "
                        "FROM log_event WHERE service_id=%s AND ts > now() - make_interval(mins => %s)", (s["id"], minutes)).fetchone()
    since = conn.execute("SELECT min(ts) AS t FROM metric_point WHERE service_id=%s", (s["id"],)).fetchone()["t"]
    names_to_id = {r["name"]: r["id"] for r in conn.execute("SELECT id, name FROM service")}

    def neighbour(n: str, relation: str) -> dict:
        sid = names_to_id.get(n)
        st, why = judge(latest_all.get(sid, {}), incidents_all.get(sid, []), now) if sid else ("unknown", ["not monitored yet"])
        return {"name": n, "relation": relation, "status": st, "reasons": why}

    depends = [neighbour(n, "depends on") for n in s["depends_on"]]
    used_by = [neighbour(r["name"], "used by") for r in conn.execute(
        "SELECT name FROM service WHERE %s = ANY(depends_on) ORDER BY name", (name,))]
    return {"name": s["name"], "owner": s["owner"], "tier": s["tier"], "description": s["description"], "created_at": s["created_at"],
            "status": status, "reasons": reasons, "minutes": minutes, "data_since": since, "bucket_seconds": _bucket_seconds(minutes),
            "metrics": metrics, "incidents": incidents, "deploys": deploys, "signatures": signatures,
            "log_counts": {"errors": logs["errors"], "total": logs["total"]}, "neighbours": depends + used_by}
