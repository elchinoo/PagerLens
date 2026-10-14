"""Read-only investigation tools. They only SELECT, cap their output, and mark log text as untrusted data.

Each tool takes a Ctx (database connection + the incident being investigated) and returns a ToolResult.
The registry at the bottom also carries JSON schemas so the same tools can be offered to an LLM.
"""
import statistics
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from . import retrieval

BASE_FROM, BASE_TO = timedelta(minutes=85), timedelta(minutes=35)   # baseline window, before the anchor
CUR_FROM = timedelta(minutes=10)                                       # "now" window
METRICS = ("error_rate", "latency_p95_ms", "request_rate", "cpu_pct", "mem_pct", "db_connections")
MAX_ROWS = 10


@dataclass
class Ctx:
    conn: object
    incident_id: int
    service: str
    anchor: datetime           # when the incident was detected; every window is relative to it
    symptom: str = ""


@dataclass
class ToolResult:
    summary: str
    data: dict = field(default_factory=dict)
    rows: int = 0


class ToolError(ValueError):
    pass


def _service(ctx: Ctx, name: str) -> dict:
    row = ctx.conn.execute("SELECT id, name, owner, tier, description, depends_on FROM service WHERE name=%s",
                           (name,)).fetchone()
    if not row:
        raise ToolError(f"unknown service {name!r}")
    return row


def service_overview(ctx: Ctx, service: str) -> ToolResult:
    s = _service(ctx, service)
    dependents = [r["name"] for r in ctx.conn.execute(
        "SELECT name FROM service WHERE %s = ANY(depends_on) ORDER BY name", (service,))]
    data = {"service": s["name"], "owner": s["owner"], "tier": s["tier"], "description": s["description"],
            "depends_on": s["depends_on"], "dependents": dependents}
    return ToolResult(f"{service}: depends on {', '.join(s['depends_on']) or 'nothing'}; "
                      f"used by {', '.join(dependents) or 'nobody'}", data, 1)


def recent_deploys(ctx: Ctx, service: str, since_minutes: int = 180) -> ToolResult:
    s = _service(ctx, service)
    since_minutes = max(5, min(int(since_minutes), 1440))
    rows = ctx.conn.execute(
        "SELECT version, git_sha, author, summary, deployed_at FROM deploy WHERE service_id=%s "
        "AND deployed_at BETWEEN %s AND %s ORDER BY deployed_at DESC LIMIT %s",
        (s["id"], ctx.anchor - timedelta(minutes=since_minutes), ctx.anchor, MAX_ROWS)).fetchall()
    last = ctx.conn.execute(
        "SELECT version, deployed_at FROM deploy WHERE service_id=%s AND deployed_at <= %s ORDER BY deployed_at DESC LIMIT 1",
        (s["id"], ctx.anchor)).fetchone()
    deploys = [{**r, "deployed_at": r["deployed_at"].isoformat(),
                "minutes_before_alert": round((ctx.anchor - r["deployed_at"]).total_seconds() / 60, 1)} for r in rows]
    age = f"; last deploy {last['version']} was {_ago(ctx.anchor - last['deployed_at'])} ago" if last else ""
    return ToolResult(f"{service}: {len(deploys)} deploy(s) in the last {since_minutes} min{age}",
                      {"service": service, "deploys": deploys,
                       "last_deploy": {"version": last["version"], "age_minutes": round((ctx.anchor - last["deployed_at"]).total_seconds() / 60)}
                       if last else None, "untrusted_fields": ["summary"]}, len(deploys))


def _ago(delta: timedelta) -> str:
    mins = delta.total_seconds() / 60
    return f"{mins:.0f} min" if mins < 120 else f"{mins / 60:.0f} h" if mins < 2880 else f"{mins / 1440:.0f} d"


def _series(ctx: Ctx, service_id: int, metric: str, start: datetime, end: datetime) -> list[tuple[datetime, float]]:
    return [(r["ts"], r["value"]) for r in ctx.conn.execute(
        "SELECT ts, value FROM metric_point WHERE service_id=%s AND name=%s AND ts BETWEEN %s AND %s ORDER BY ts",
        (service_id, metric, start, end))]


def _compare(ctx: Ctx, service_id: int, metric: str) -> dict | None:
    base = [v for _, v in _series(ctx, service_id, metric, ctx.anchor - BASE_FROM, ctx.anchor - BASE_TO)]
    cur_series = _series(ctx, service_id, metric, ctx.anchor - CUR_FROM, ctx.anchor)
    if len(base) < 5 or len(cur_series) < 3:
        return None
    cur = [v for _, v in cur_series]
    b_mean, b_std = statistics.fmean(base), statistics.pstdev(base)
    c_mean = statistics.fmean(cur)
    z = (c_mean - b_mean) / max(b_std, 0.03 * abs(b_mean), 1e-6)
    xs = list(range(len(cur)))
    x_mean = statistics.fmean(xs)
    denom = sum((x - x_mean) ** 2 for x in xs) or 1.0
    slope = sum((x - x_mean) * (y - c_mean) for x, y in zip(xs, cur, strict=True)) / denom
    # onset: first of three consecutive anomalous points in the hour before the anchor
    threshold = max(4 * max(b_std, 0.03 * abs(b_mean)), 1e-6)
    window = _series(ctx, service_id, metric, ctx.anchor - timedelta(minutes=60), ctx.anchor)
    flags = [abs(v - b_mean) >= threshold for _, v in window]
    onset = next((window[i][0] for i in range(len(window) - 2) if all(flags[i:i + 3])), None)
    return {"baseline_mean": round(b_mean, 2), "current_mean": round(c_mean, 2), "current_max": round(max(cur), 2),
            "ratio": round(c_mean / b_mean, 2) if b_mean else None, "z": round(z, 1),
            "slope_per_min": round(slope, 3), "onset": onset.isoformat() if onset else None}


def metrics_overview(ctx: Ctx, service: str) -> ToolResult:
    s = _service(ctx, service)
    out, notable = {}, []
    for metric in METRICS:
        c = _compare(ctx, s["id"], metric)
        if c:
            out[metric] = c
            if abs(c["z"]) >= 4:
                notable.append(f"{metric} {c['baseline_mean']} -> {c['current_mean']} (x{c['ratio']})")
    cap = _compare(ctx, s["id"], "db_connections_max")
    if cap and "db_connections" in out:
        out["db_connections"]["pool_max"] = cap["current_mean"]
    onsets = sorted(c["onset"] for c in out.values() if c["onset"])
    return ToolResult(f"{service}: " + ("; ".join(notable) if notable else "no metric deviates from its baseline"),
                      {"service": service, "metrics": out, "first_anomaly": onsets[0] if onsets else None}, len(out))


def error_signatures(ctx: Ctx, service: str, minutes: int = 30) -> ToolResult:
    s = _service(ctx, service)
    minutes = max(5, min(int(minutes), 240))
    rows = ctx.conn.execute(
        """
        SELECT signature, count(*) AS n, min(ts) AS first_seen, max(ts) AS last_seen,
               (array_agg(message ORDER BY ts DESC))[1] AS sample,
               (SELECT count(*) FROM log_event p WHERE p.service_id = %(sid)s AND p.signature = l.signature
                  AND p.ts BETWEEN %(base_from)s AND %(base_to)s) AS before_window
        FROM log_event l
        WHERE service_id = %(sid)s AND level IN ('warn','error','fatal') AND ts BETWEEN %(start)s AND %(end)s
        GROUP BY signature ORDER BY n DESC LIMIT %(lim)s
        """,
        {"sid": s["id"], "start": ctx.anchor - timedelta(minutes=minutes), "end": ctx.anchor,
         "base_from": ctx.anchor - BASE_FROM, "base_to": ctx.anchor - BASE_TO, "lim": 8}).fetchall()
    sigs = [{"signature": r["signature"], "count": r["n"], "first_seen": r["first_seen"].isoformat(),
             "last_seen": r["last_seen"].isoformat(), "new": r["before_window"] == 0, "sample": r["sample"][:300]}
            for r in rows]
    text = "; ".join(f"{x['count']}x '{x['signature'][:70]}'" for x in sigs[:3]) or "no warnings or errors"
    return ToolResult(f"{service}: {text}", {"service": service, "signatures": sigs,
                                             "untrusted_fields": ["signature", "sample"]}, len(sigs))


def log_sample(ctx: Ctx, service: str, signature: str, n: int = 3) -> ToolResult:
    s = _service(ctx, service)
    n = max(1, min(int(n), MAX_ROWS))
    rows = ctx.conn.execute(
        "SELECT ts, level, message, fields FROM log_event WHERE service_id=%s AND signature=%s AND ts <= %s "
        "ORDER BY ts DESC LIMIT %s", (s["id"], signature[:200], ctx.anchor, n)).fetchall()
    lines = [{"ts": r["ts"].isoformat(), "level": r["level"], "message": r["message"], "fields": r["fields"]} for r in rows]
    return ToolResult(f"{service}: {len(lines)} sample line(s) for that signature",
                      {"service": service, "lines": lines, "untrusted_fields": ["message", "fields"]}, len(lines))


def find_similar_incidents(ctx: Ctx, text: str = "") -> ToolResult:
    query = text or f"{ctx.service}: {ctx.symptom}"
    rows = retrieval.similar_incidents(ctx.conn, query, exclude_id=ctx.incident_id, limit=5)
    items = [{"incident_id": r["id"], "service": r["service"], "title": r["title"],
              "root_cause_category": r["root_cause_category"], "root_cause_note": r["root_cause_note"],
              "similarity": round(float(r["similarity"]), 3)} for r in rows]
    return ToolResult(f"{len(items)} similar resolved incident(s)" +
                      (f"; closest was a {items[0]['root_cause_category']} ({items[0]['similarity']})" if items else ""),
                      {"incidents": items, "untrusted_fields": ["title", "root_cause_note"]}, len(items))


def find_runbooks(ctx: Ctx, query: str = "", category: str | None = None) -> ToolResult:
    rows = retrieval.search_runbooks(ctx.conn, query or f"{ctx.service} {ctx.symptom}", category=category, limit=3)
    items = [{"runbook_id": r["id"], "title": r["title"], "category": r["category"], "body": r["body"]} for r in rows]
    return ToolResult(f"{len(items)} runbook(s): " + ", ".join(i["title"] for i in items), {"runbooks": items}, len(items))


# name -> (function, JSON schema for an LLM). Every tool is read-only.
REGISTRY = {
    "service_overview": (service_overview, {"description": "Owner, dependencies and dependents of a service.",
                                            "properties": {"service": {"type": "string"}}, "required": ["service"]}),
    "recent_deploys": (recent_deploys, {"description": "Deploys of a service shortly before the alert.",
                                        "properties": {"service": {"type": "string"}, "since_minutes": {"type": "integer"}},
                                        "required": ["service"]}),
    "metrics_overview": (metrics_overview, {"description": "Compare current metrics to the baseline for a service.",
                                            "properties": {"service": {"type": "string"}}, "required": ["service"]}),
    "error_signatures": (error_signatures, {"description": "Most frequent warning/error log signatures, with first seen times.",
                                            "properties": {"service": {"type": "string"}, "minutes": {"type": "integer"}},
                                            "required": ["service"]}),
    "log_sample": (log_sample, {"description": "A few example log lines for one error signature.",
                                "properties": {"service": {"type": "string"}, "signature": {"type": "string"},
                                               "n": {"type": "integer"}}, "required": ["service", "signature"]}),
    "find_similar_incidents": (find_similar_incidents, {"description": "Past resolved incidents that look similar.",
                                                        "properties": {"text": {"type": "string"}}, "required": []}),
    "find_runbooks": (find_runbooks, {"description": "Runbooks relevant to the symptom.",
                                      "properties": {"query": {"type": "string"}, "category": {"type": "string"}},
                                      "required": []}),
}


def openai_tool_specs() -> list[dict]:
    return [{"type": "function", "function": {"name": n, "description": s["description"],
                                              "parameters": {"type": "object", "properties": s["properties"],
                                                             "required": s["required"]}}}
            for n, (_, s) in REGISTRY.items()]


def make_ctx(conn, incident_id: int) -> Ctx:
    row = conn.execute("SELECT i.id, i.symptom, i.detected_at, s.name FROM incident i JOIN service s ON s.id=i.service_id "
                       "WHERE i.id=%s", (incident_id,)).fetchone()
    if not row:
        raise ToolError("incident not found")
    return Ctx(conn, row["id"], row["name"], row["detected_at"], row["symptom"])
