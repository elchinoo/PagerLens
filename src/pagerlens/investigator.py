"""The investigation loop (rules mode): bounded, read-only, evidence-linked and fully recorded.

Collect evidence with the read-only tools -> propose hypotheses, each tied to observations that support or refute
it -> run refuting checks -> apply the memory prior from similar resolved incidents -> write a report.
Nothing here changes any monitored system; the only writes are PagerLens' own run/evidence/report tables.
"""
import hashlib
import json
import re
import time
from datetime import datetime, timedelta

from . import retrieval, tools
from .tools import Ctx, ToolError

MAX_TOOL_CALLS = 30
CATEGORIES = {
    "bad_deploy": "A recent deploy introduced the failure",
    "db_saturation": "Database connection pool or database saturation",
    "resource_exhaustion": "A service is running out of memory or other resources",
    "dependency_outage": "A dependency the service relies on is failing",
    "traffic_spike": "Traffic surged beyond capacity",
    "expired_certificate": "A TLS certificate expired or is invalid",
    "unknown": "Not enough evidence",
}
_POOL = re.compile(r"pool|too many connections|timeout acquiring connection|connection.*exhaust", re.I)
_OOM = re.compile(r"OutOfMemory|OOMKilled|heap space|out of memory", re.I)
_CERT = re.compile(r"x509|certificate (has )?expired|certificate verify|tls handshake|ssl.*(expired|verify)", re.I)
_QUEUE = re.compile(r"queue depth|backlog|rate limit", re.I)
_TIMEOUT = re.compile(r"timeout|timed out|unavailable|connection refused|upstream", re.I)


class Budget:
    def __init__(self, max_calls: int | None = None):
        self.max_calls, self.calls, self.ms = max_calls or MAX_TOOL_CALLS, 0, 0

    def spend(self) -> None:
        if self.calls >= self.max_calls:
            raise ToolError(f"tool-call budget of {self.max_calls} exhausted")
        self.calls += 1


class Recorder:
    """Writes every step and observation as it happens, so a run can be replayed and audited."""

    def __init__(self, conn, run_id: int, incident_id: int):
        self.conn, self.run_id, self.incident_id, self.ord = conn, run_id, incident_id, 0

    def step(self, kind: str, tool: str | None, args: dict, summary: str, rows: int | None, ms: int | None) -> int:
        self.ord += 1
        return self.conn.execute(
            "INSERT INTO run_step (run_id, ord, kind, tool, args, summary, row_count, ms) VALUES (%s,%s,%s,%s,%s::jsonb,%s,%s,%s) "
            "RETURNING id", (self.run_id, self.ord, kind, tool, json.dumps(args), summary[:500], rows, ms)).fetchone()["id"]

    def observe(self, step_id: int | None, source: str, kind: str, summary: str, payload: dict) -> int:
        body = json.dumps(payload, default=str, sort_keys=True)
        return self.conn.execute(
            "INSERT INTO observation (incident_id, run_id, step_id, source, kind, summary, payload, digest) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s::jsonb,%s) RETURNING id",
            (self.incident_id, self.run_id, step_id, source, kind, summary[:500], body,
             hashlib.sha256(body.encode()).hexdigest()[:16])).fetchone()["id"]


def call_tool(ctx: Ctx, rec: Recorder, budget: Budget, name: str, **args) -> tuple[tools.ToolResult, int]:
    """Run one registered read-only tool, recording the step and its observation."""
    if name not in tools.REGISTRY:
        raise ToolError(f"unknown tool {name!r}")
    budget.spend()
    started = time.monotonic()
    result = tools.REGISTRY[name][0](ctx, **args)
    ms = int((time.monotonic() - started) * 1000)
    budget.ms += ms
    step_id = rec.step("tool", name, args, result.summary, result.rows, ms)
    obs_id = rec.observe(step_id, name, name, result.summary, result.data)
    return result, obs_id


def _dt(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


class Hyp:
    def __init__(self, category: str, suspect: str, title: str):
        self.category, self.suspect, self.title = category, suspect, title
        self.score = 0.0
        self.evidence: list[tuple[int, str, str]] = []
        self.notes: list[str] = []

    def support(self, obs: int, weight: float, note: str) -> None:
        self.score += weight
        self.evidence.append((obs, "supports", note))
        self.notes.append(note)

    def refute(self, obs: int, weight: float, note: str) -> None:
        self.score -= weight
        self.evidence.append((obs, "refutes", note))


def _hypotheses(S: str, targets: list[str], M: dict, SIG: dict, DEP: dict, onset: datetime | None) -> list[Hyp]:
    out: list[Hyp] = []

    def metric(svc, name):
        return (M.get(svc) or ({}, 0))[0].get("metrics", {}).get(name)

    def sigs(svc):
        return (SIG.get(svc) or ({}, 0))[0].get("signatures", [])

    # --- bad deploy: a deploy on the service or something it depends on, just before the onset -------------------
    for svc in targets:
        data, obs = DEP[svc]
        near = [d for d in data["deploys"] if onset and timedelta(minutes=-3) <= onset - _dt(d["deployed_at"]) <= timedelta(minutes=15)]
        if not near:
            continue
        d = near[0]
        h = Hyp("bad_deploy", svc, f"Release {d['version']} of {svc} introduced the failure")
        h.support(obs, 0.55, f"{svc} {d['version']} was deployed {d['minutes_before_alert']:.0f} min before the alert, "
                              f"shortly before the first anomaly" + (f" ({d['summary']})" if d.get("summary") else ""))
        top = next((s for s in sigs(svc) if s["new"]), None)
        s_obs = SIG[svc][1]
        if top and _dt(top["first_seen"]) >= _dt(d["deployed_at"]) - timedelta(minutes=1):
            h.support(s_obs, 0.25, f"the new error '{top['signature'][:80]}' first appeared after the deploy")
        elif top:
            h.refute(s_obs, 0.4, f"'{top['signature'][:80]}' was already being logged before the deploy")
        out.append(h)

    # --- database saturation ---------------------------------------------------------------------------------------------
    for svc in targets:
        db = metric(svc, "db_connections")
        if not db or not db.get("pool_max"):
            continue
        used = db["current_mean"] / db["pool_max"]
        pool_sig = next((s for s in sigs(svc) if _POOL.search(s["signature"])), None)
        if used >= 0.85 or pool_sig:
            h = Hyp("db_saturation", svc, f"{svc} exhausted its database connection pool")
            m_obs = M[svc][1]
            if used >= 0.85:
                h.support(m_obs, 0.45, f"{svc} is using {used:.0%} of its pool ({db['current_mean']:.0f}/{db['pool_max']:.0f}); "
                                       f"baseline was {db['baseline_mean']:.0f}")
            if pool_sig:
                h.support(SIG[svc][1], 0.3, f"{pool_sig['count']} log errors match pool exhaustion: '{pool_sig['signature'][:80]}'")
            lat = metric(svc, "latency_p95_ms")
            if lat and lat["z"] >= 4:
                h.support(m_obs, 0.1, f"p95 latency rose from {lat['baseline_mean']:.0f} to {lat['current_mean']:.0f} ms")
            out.append(h)

    # --- resource exhaustion (memory) --------------------------------------------------------------------------------
    for svc in targets:
        mem = metric(svc, "mem_pct")
        oom = next((s for s in sigs(svc) if _OOM.search(s["signature"])), None)
        if (mem and mem["current_mean"] >= 85 and mem["slope_per_min"] > 0.3) or oom:
            h = Hyp("resource_exhaustion", svc, f"{svc} is running out of memory")
            if mem and mem["current_mean"] >= 85:
                h.support(M[svc][1], 0.45, f"memory is at {mem['current_mean']:.0f}% (baseline {mem['baseline_mean']:.0f}%) "
                                           f"and rising {mem['slope_per_min']:.1f} points/min")
            if oom:
                h.support(SIG[svc][1], 0.3, f"{oom['count']} log lines show memory exhaustion: '{oom['signature'][:80]}'")
            req = metric(svc, "request_rate")
            if req and req["ratio"] and req["ratio"] >= 3:
                h.refute(M[svc][1], 0.25, f"request rate is x{req['ratio']}: the memory growth may simply be load")
            elif req:
                h.support(M[svc][1], 0.1, "request rate is normal, so the growth is not explained by load")
            out.append(h)

    # --- dependency outage: the service is a victim, the cause is something it calls ----------------------------------
    for dep in [t for t in targets if t != S]:
        err, lat = metric(dep, "error_rate"), metric(dep, "latency_p95_ms")
        sick = (err and err["z"] >= 4 and err["current_mean"] > 2) or (lat and lat["z"] >= 4 and lat["ratio"] and lat["ratio"] >= 4)
        if not sick:
            continue
        h = Hyp("dependency_outage", dep, f"{dep} is failing and {S} is a downstream victim")
        bits = []
        if err and err["z"] >= 4:
            bits.append(f"error rate {err['baseline_mean']:.1f}% -> {err['current_mean']:.1f}%")
        if lat and lat["z"] >= 4:
            bits.append(f"p95 latency {lat['baseline_mean']:.0f} -> {lat['current_mean']:.0f} ms")
        h.support(M[dep][1], 0.5, f"{dep} itself is unhealthy: " + ", ".join(bits))
        mention = next((s for s in sigs(S) if dep in s["signature"] and _TIMEOUT.search(s["signature"])), None)
        if mention:
            h.support(SIG[S][1], 0.2, f"{S} logs blame {dep}: '{mention['signature'][:80]}'")
        own = next((s for s in sigs(dep) if _TIMEOUT.search(s["signature"])), None)
        if own:
            h.support(SIG[dep][1], 0.15, f"{dep} logs show upstream failures: '{own['signature'][:80]}'")
        if DEP[dep][0]["deploys"]:
            h.refute(DEP[dep][1], 0.1, f"{dep} was also deployed recently, so the cause may be that release")
        out.append(h)

    # --- traffic spike -------------------------------------------------------------------------------------------------------
    for svc in targets:
        req = metric(svc, "request_rate")
        if req and req["ratio"] and req["ratio"] >= 3 and req["z"] >= 4:
            h = Hyp("traffic_spike", svc, f"Traffic to {svc} surged beyond capacity")
            h.support(M[svc][1], 0.55, f"request rate on {svc} is x{req['ratio']} its baseline ({req['baseline_mean']:.0f} -> {req['current_mean']:.0f} rps)")
            cpu = metric(svc, "cpu_pct")
            if cpu and cpu["z"] >= 4:
                h.support(M[svc][1], 0.15, f"CPU rose from {cpu['baseline_mean']:.0f}% to {cpu['current_mean']:.0f}%")
            q = next((s for s in sigs(svc) if _QUEUE.search(s["signature"])), None)
            if q:
                h.support(SIG[svc][1], 0.1, f"queueing warnings: '{q['signature'][:80]}'")
            out.append(h)

    # --- expired certificate -------------------------------------------------------------------------------------------
    for svc in targets:
        cert = next((s for s in sigs(svc) if _CERT.search(s["signature"])), None)
        if not cert:
            continue
        h = Hyp("expired_certificate", svc, f"{svc} cannot establish TLS: a certificate has expired or is invalid")
        h.support(SIG[svc][1], 0.6, f"{cert['count']} log lines report a certificate problem: '{cert['signature'][:90]}'")
        err = metric(svc, "error_rate")
        if err and err["z"] >= 4:
            h.support(M[svc][1], 0.1, f"error rate stepped from {err['baseline_mean']:.1f}% to {err['current_mean']:.1f}%")
        for dep in targets:
            req = metric(dep, "request_rate")
            if dep != svc and req and req["ratio"] is not None and req["ratio"] <= 0.3:
                h.support(M[dep][1], 0.15, f"{dep} is healthy but its request rate fell {1 - req['ratio']:.0%}: clients cannot reach it")
        if DEP[svc][0]["deploys"] and onset and any(
                timedelta(minutes=-3) <= onset - _dt(d["deployed_at"]) <= timedelta(minutes=15) for d in DEP[svc][0]["deploys"]):
            h.refute(DEP[svc][1], 0.2, "a deploy happened right before the onset, so the release is also a suspect")
        out.append(h)
    return out


def _timeline(S, targets, DEP, SIG, onset, anchor) -> list[dict]:
    events = []
    for svc in targets:
        for d in DEP[svc][0]["deploys"]:
            events.append({"ts": d["deployed_at"], "text": f"deploy {svc} {d['version']}" + (f" by {d['author']}" if d.get("author") else "")})
        for s in SIG[svc][0]["signatures"][:2]:
            if s["new"]:
                events.append({"ts": s["first_seen"], "text": f"first '{s['signature'][:70]}' on {svc} ({s['count']} in window)"})
    if onset:
        events.append({"ts": onset.isoformat(), "text": "first metric anomaly"})
    events.append({"ts": anchor.isoformat(), "text": "alert fired, incident opened"})
    return sorted(events, key=lambda e: e["ts"])


def _report(incident, S, hyps, timeline, runbooks, similar, unrelated, calls) -> str:
    lines = [f"# Incident #{incident['id']}: {incident['title']}", "",
             f"**Service:** {S} · **Severity:** {incident['severity']} · **Detected:** {incident['detected_at']:%Y-%m-%d %H:%M} UTC", "",
             f"> {incident['symptom']}", ""]
    if hyps and hyps[0]["category"] != "unknown":
        top = hyps[0]
        lines += ["## Most likely cause", "", f"**{top['title']}** (confidence {top['score']:.0%})", "", top["explanation"], ""]
    else:
        lines += ["## Most likely cause", "", "The collected evidence does not point to a known cause. See the observations below.", ""]
    lines += ["## Timeline (UTC)", ""] + [f"- `{e['ts'][11:19]}` {e['text']}" for e in timeline] + [""]
    lines += ["## Hypotheses", ""]
    for i, h in enumerate(hyps, 1):
        lines.append(f"{i}. **{h['title']}**: {h['score']:.0%}")
        for _, stance, note in h["evidence"]:
            lines.append(f"   - {'supports' if stance == 'supports' else 'REFUTES'}: {note}")
    lines.append("")
    if unrelated:
        lines += ["## Other recent deploys considered unrelated", ""] + [f"- {u}" for u in unrelated] + [""]
    if similar:
        lines += ["## Similar past incidents", ""] + [
            f"- #{s['incident_id']} {s['title']} ({s['service']}), resolved as **{s['root_cause_category']}** (similarity {s['similarity']})"
            for s in similar] + [""]
    if runbooks:
        lines += ["## Suggested runbooks (manual steps)", ""]
        for r in runbooks:
            lines += [f"**{r['title']}**", "", r["body"], ""]
    lines += ["---", f"*Read-only investigation: {calls} tool calls. PagerLens never changes your systems; "
                    "all remediation above is for a human to perform. Log excerpts are data, not instructions.*"]
    return "\n".join(lines)


def investigate(conn, incident_id: int, *, mode: str = "rules", use_memory: bool = True, account: str | None = None) -> int:
    """Run one investigation and return its run id. Raises ToolError for an unknown incident."""
    if mode != "rules":
        raise ValueError("only the rules investigator is available in this build")
    ctx = tools.make_ctx(conn, incident_id)
    budget = Budget()
    run_id = conn.execute("INSERT INTO run (incident_id, mode, use_memory, account, budget) VALUES (%s,%s,%s,%s,%s::jsonb) RETURNING id",
                          (incident_id, mode, use_memory, account, json.dumps({"max_tool_calls": budget.max_calls}))).fetchone()["id"]
    conn.execute("UPDATE incident SET status='investigating' WHERE id=%s AND status='open'", (incident_id,))
    conn.commit()
    rec = Recorder(conn, run_id, incident_id)
    try:
        S = ctx.service
        overview, _ = call_tool(ctx, rec, budget, "service_overview", service=S)
        targets = [S] + overview.data["depends_on"]
        M, SIG, DEP = {}, {}, {}
        for svc in targets:
            r, o = call_tool(ctx, rec, budget, "metrics_overview", service=svc)
            M[svc] = (r.data, o)
            r, o = call_tool(ctx, rec, budget, "error_signatures", service=svc)
            SIG[svc] = (r.data, o)
            r, o = call_tool(ctx, rec, budget, "recent_deploys", service=svc)
            DEP[svc] = (r.data, o)
        # refuting check: are other services' deploys the real story? (read-only, bounded)
        unrelated = []
        for other in [r["name"] for r in conn.execute("SELECT name FROM service ORDER BY name")]:
            if other in targets or len(unrelated) >= 5:
                continue
            r, _ = call_tool(ctx, rec, budget, "recent_deploys", service=other, since_minutes=60)
            unrelated += [f"{other} {d['version']} ({d['minutes_before_alert']:.0f} min before the alert): not a dependency of {S}"
                          for d in r.data["deploys"]]
        anomalies = sorted(_dt(d["first_anomaly"]) for d, _ in M.values() if d.get("first_anomaly"))
        onset = anomalies[0] if anomalies else None
        hyps = _hypotheses(S, targets, M, SIG, DEP, onset)

        similar: list[dict] = []
        if use_memory:
            top_sigs = [s["signature"] for svc in targets for s in SIG[svc][0]["signatures"][:2]]
            r, sim_obs = call_tool(ctx, rec, budget, "find_similar_incidents",
                                   text=f"{S}: {ctx.symptom} | " + " | ".join(top_sigs[:6]))
            similar = r.data["incidents"]
            for h in hyps:
                match = [s for s in similar if s["root_cause_category"] == h.category and s["similarity"] >= 0.3]
                if match:
                    best = max(s["similarity"] for s in match)
                    h.support(sim_obs, min(0.2, 0.25 * best),
                              f"{len(match)} similar past incident(s) were resolved as {h.category} (best similarity {best:.2f})")

        for h in hyps:
            h.score = max(0.01, min(0.99, h.score))
        hyps.sort(key=lambda h: h.score, reverse=True)
        if not hyps:
            h = Hyp("unknown", S, "No known failure pattern matches the evidence")
            h.score = 0.05
            _, o = SIG[S]
            h.evidence.append((o, "supports", "no deploy, resource, dependency, traffic or certificate pattern was found"))
            h.notes.append("The checks did not match a known pattern; review the error signatures and metrics manually.")
            hyps = [h]
        rbs, _ = call_tool(ctx, rec, budget, "find_runbooks", query=f"{hyps[0].title} {S}",
                           category=hyps[0].category if hyps[0].category != "unknown" else None)
        stored = []
        for rank, h in enumerate(hyps, 1):
            explanation = "; ".join(h.notes) if h.notes else h.title
            hid = conn.execute(
                "INSERT INTO hypothesis (incident_id, run_id, category, title, explanation, score, rank, suspect) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id",
                (incident_id, run_id, h.category, h.title, explanation, h.score, rank, h.suspect)).fetchone()["id"]
            for obs_id, stance, note in h.evidence:
                conn.execute("INSERT INTO hypothesis_evidence (hypothesis_id, observation_id, stance, note) VALUES (%s,%s,%s,%s)",
                             (hid, obs_id, stance, note))
            stored.append({"category": h.category, "title": h.title, "score": h.score, "explanation": explanation,
                           "evidence": h.evidence})
        rec.step("hypotheses", None, {}, f"{len(stored)} hypothesis(es); top: {stored[0]['title']}", len(stored), None)
        incident = conn.execute("SELECT id, title, severity, symptom, detected_at FROM incident WHERE id=%s", (incident_id,)).fetchone()
        md = _report(incident, S, stored, _timeline(S, targets, DEP, SIG, onset, ctx.anchor), rbs.data["runbooks"][:2],
                     similar[:3], unrelated, budget.calls)
        conn.execute("INSERT INTO report (incident_id, run_id, markdown) VALUES (%s,%s,%s)", (incident_id, run_id, md))
        rec.step("report", None, {}, "report written", None, None)
        retrieval.remember_incident(conn, incident_id, [s["signature"] for svc in targets for s in SIG[svc][0]["signatures"][:3]])
        conn.execute("UPDATE run SET status='done', finished_at=now(), usage=%s::jsonb WHERE id=%s",
                     (json.dumps({"tool_calls": budget.calls, "tool_ms": budget.ms}), run_id))
        conn.commit()
    except Exception as exc:
        conn.rollback()
        conn.execute("UPDATE run SET status='failed', finished_at=now(), error=%s WHERE id=%s", (str(exc)[:300], run_id))
        conn.commit()
        raise
    return run_id
