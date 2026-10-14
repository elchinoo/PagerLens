"""Incident reads and human actions, shared by the REST API and the MCP server."""
from . import investigator, retrieval


class NotFound(LookupError):
    pass


def list_incidents(conn, *, status: str | None = None, limit: int = 50) -> list[dict]:
    return conn.execute(
        "SELECT i.id, i.title, i.status, i.severity, s.name AS service, i.detected_at, i.resolved_at, "
        "i.root_cause_category, (SELECT count(*) FROM alert a WHERE a.incident_id = i.id) AS alerts, "
        "(SELECT h.title FROM hypothesis h WHERE h.incident_id = i.id ORDER BY h.run_id DESC, h.rank LIMIT 1) AS top_hypothesis "
        "FROM incident i JOIN service s ON s.id = i.service_id WHERE (%s::text IS NULL OR i.status = %s) "
        "ORDER BY i.detected_at DESC LIMIT %s", (status, status, max(1, min(limit, 200)))).fetchall()


def get_incident(conn, incident_id: int) -> dict:
    inc = conn.execute(
        "SELECT i.id, i.title, i.status, i.severity, s.name AS service, i.symptom, i.detected_at, i.resolved_at, "
        "i.root_cause_category, i.root_cause_note FROM incident i JOIN service s ON s.id = i.service_id WHERE i.id=%s",
        (incident_id,)).fetchone()
    if not inc:
        raise NotFound("incident not found")
    inc["alerts"] = conn.execute("SELECT id, source, name, severity, summary, fired_at FROM alert WHERE incident_id=%s "
                                 "ORDER BY fired_at", (incident_id,)).fetchall()
    inc["notes"] = conn.execute("SELECT id, author, body, created_at FROM incident_note WHERE incident_id=%s ORDER BY id",
                                (incident_id,)).fetchall()
    inc["runs"] = conn.execute("SELECT id, mode, status, use_memory, error, warning, usage, started_at, finished_at FROM run "
                               "WHERE incident_id=%s ORDER BY id DESC", (incident_id,)).fetchall()
    latest = inc["runs"][0]["id"] if inc["runs"] else None
    inc["hypotheses"] = _hypotheses(conn, latest) if latest else []
    rep = conn.execute("SELECT markdown, created_at FROM report WHERE incident_id=%s ORDER BY id DESC LIMIT 1",
                       (incident_id,)).fetchone()
    inc["report"] = rep
    return inc


def _hypotheses(conn, run_id: int) -> list[dict]:
    hyps = conn.execute("SELECT id, category, title, explanation, score, rank, suspect, source, rules_score, llm_score, grounded "
                        "FROM hypothesis WHERE run_id=%s "
                        "ORDER BY rank", (run_id,)).fetchall()
    for h in hyps:
        h["evidence"] = conn.execute(
            "SELECT e.stance, e.note, e.observation_id, o.source FROM hypothesis_evidence e "
            "JOIN observation o ON o.id = e.observation_id WHERE e.hypothesis_id=%s ORDER BY e.id", (h["id"],)).fetchall()
    return hyps


def get_run(conn, run_id: int) -> dict:
    run = conn.execute("SELECT id, incident_id, mode, status, use_memory, error, warning, budget, usage, started_at, finished_at "
                       "FROM run WHERE id=%s", (run_id,)).fetchone()
    if not run:
        raise NotFound("run not found")
    run["steps"] = conn.execute("SELECT id, ord, kind, tool, args, summary, row_count, ms FROM run_step WHERE run_id=%s "
                                "ORDER BY ord", (run_id,)).fetchall()
    return run


def get_observation(conn, obs_id: int) -> dict:
    row = conn.execute("SELECT id, incident_id, run_id, source, kind, summary, payload, digest, created_at "
                       "FROM observation WHERE id=%s", (obs_id,)).fetchone()
    if not row:
        raise NotFound("observation not found")
    return row


def add_note(conn, incident_id: int, body: str, author: str = "operator") -> int:
    if not conn.execute("SELECT 1 FROM incident WHERE id=%s", (incident_id,)).fetchone():
        raise NotFound("incident not found")
    return conn.execute("INSERT INTO incident_note (incident_id, author, body) VALUES (%s,%s,%s) RETURNING id",
                        (incident_id, author[:40], body.strip()[:4000])).fetchone()["id"]


def resolve(conn, incident_id: int, category: str, note: str | None = None) -> None:
    """Humans mark the real cause. The incident then becomes recallable memory for future investigations."""
    if category not in investigator.CATEGORIES or category == "unknown":
        raise ValueError(f"category must be one of: {', '.join(c for c in investigator.CATEGORIES if c != 'unknown')}")
    row = conn.execute("UPDATE incident SET status='resolved', resolved_at=now(), root_cause_category=%s, root_cause_note=%s "
                       "WHERE id=%s RETURNING id", (category, (note or "")[:1000] or None, incident_id)).fetchone()
    if not row:
        raise NotFound("incident not found")
    sigs = conn.execute(
        "SELECT o.payload FROM observation o WHERE o.incident_id=%s AND o.source='error_signatures' ORDER BY o.id DESC LIMIT 3",
        (incident_id,)).fetchall()
    signatures = [s["signature"] for r in sigs for s in r["payload"].get("signatures", [])[:2]]
    retrieval.remember_incident(conn, incident_id, signatures)


def reveal_truth(conn, incident_id: int) -> dict | None:
    """Ground truth of a SIMULATED incident (for the learning UI). Real incidents have none."""
    return conn.execute("SELECT scenario, category FROM sim_truth WHERE incident_id=%s", (incident_id,)).fetchone()


def fleet(conn) -> list[dict]:
    rows = conn.execute("SELECT id, name, owner, tier, description, depends_on FROM service ORDER BY name").fetchall()
    for r in rows:
        r["last_deploy"] = conn.execute("SELECT version, deployed_at FROM deploy WHERE service_id=%s "
                                        "ORDER BY deployed_at DESC LIMIT 1", (r["id"],)).fetchone()
        r["open_incidents"] = conn.execute("SELECT count(*) AS n FROM incident WHERE service_id=%s AND status <> 'resolved'",
                                           (r["id"],)).fetchone()["n"]
        latest = {m["name"]: m["value"] for m in conn.execute(
            "SELECT DISTINCT ON (name) name, value FROM metric_point WHERE service_id=%s ORDER BY name, ts DESC", (r["id"],))}
        r["latest"] = latest
    return rows


CHART_METRICS = ("error_rate", "latency_p95_ms", "request_rate", "cpu_pct", "mem_pct", "db_connections")


def telemetry(conn, incident_id: int, minutes: int = 90) -> dict:
    """Metric series and deploys for the incident's service and its dependencies, ending just after detection."""
    from datetime import timedelta

    inc = conn.execute("SELECT i.detected_at, s.name, s.depends_on FROM incident i JOIN service s ON s.id=i.service_id "
                       "WHERE i.id=%s", (incident_id,)).fetchone()
    if not inc:
        raise NotFound("incident not found")
    start, end = inc["detected_at"] - timedelta(minutes=max(10, min(minutes, 240))), inc["detected_at"] + timedelta(minutes=2)
    out: dict = {"anchor": inc["detected_at"], "services": {}}
    for name in [inc["name"], *inc["depends_on"]]:
        svc = conn.execute("SELECT id FROM service WHERE name=%s", (name,)).fetchone()
        if not svc:
            continue
        series = {m: [[r["ts"], r["value"]] for r in conn.execute(
            "SELECT ts, value FROM metric_point WHERE service_id=%s AND name=%s AND ts BETWEEN %s AND %s ORDER BY ts",
            (svc["id"], m, start, end))] for m in CHART_METRICS}
        deploys = conn.execute("SELECT version, author, summary, deployed_at FROM deploy WHERE service_id=%s "
                               "AND deployed_at BETWEEN %s AND %s ORDER BY deployed_at", (svc["id"], start, end)).fetchall()
        out["services"][name] = {"metrics": {k: v for k, v in series.items() if v}, "deploys": deploys}
    return out
