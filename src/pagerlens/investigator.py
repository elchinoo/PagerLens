"""The investigation loop: rules, LLM or both, always bounded, read-only, evidence-linked and fully recorded.

rules : collect evidence with the read-only tools -> score six failure patterns, each tied to observations that
        support or refute it -> refuting checks -> memory prior from similar resolved incidents.
llm   : a model drives the same read-only tools in a bounded loop; its answer is validated before it is used.
hybrid: rules first, then the model investigates the same incident (and may cite the rules' observations); the two
        sets of hypotheses are reconciled, agreement is rewarded and disagreement is shown.

Nothing here changes any monitored system; the only writes are PagerLens' own run/evidence/report tables.
"""
import json
import re
from datetime import datetime, timedelta

from . import llm_agent, retrieval, tools
from .accounts import ChatConfig
from .investigator_core import CATEGORIES, MAX_TOOL_CALLS, Budget, Recorder, call_tool
from .llm_http import LLMError
from .tools import Ctx, ToolError

MAX_LLM_TOOL_CALLS = 12
MODES = ("rules", "llm", "hybrid")
__all__ = ["CATEGORIES", "MAX_TOOL_CALLS", "MODES", "Budget", "Recorder", "ToolError", "call_tool", "investigate"]

_POOL = re.compile(r"pool|too many connections|timeout acquiring connection|connection.*exhaust", re.I)
_OOM = re.compile(r"OutOfMemory|OOMKilled|heap space|out of memory", re.I)
_CERT = re.compile(r"x509|certificate (has )?expired|certificate verify|tls handshake|ssl.*(expired|verify)", re.I)
_QUEUE = re.compile(r"queue depth|backlog|rate limit", re.I)
_PROBE = re.compile(r"health probe failed|metrics scrape failed", re.I)
_PAUSED = re.compile(r"sandbox is (paused|stopped|suspended)", re.I)
_TIMEOUT = re.compile(r"timeout|timed out|unavailable|connection refused|upstream", re.I)


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


def _state_note(what: str, m: dict) -> str:
    """Describe a 0/1 health signal, saying so when there was no earlier history to compare with."""
    if m.get("no_baseline"):
        return f"{what} only {m['current_mean']:.0%} of the time recently (no earlier history to compare)"
    return f"{what} {m['baseline_mean']:.0%} of the time before, but only {m['current_mean']:.0%} now"


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

    # --- the service stopped answering: platform pause, crash/network, or its database -----------------------------------
    for svc in targets:
        up, sbx, dbu = metric(svc, "up"), metric(svc, "sandbox_running"), metric(svc, "db_up")
        probe = next((s for s in sigs(svc) if _PROBE.search(s["signature"])), None)
        paused = next((s for s in sigs(svc) if _PAUSED.search(s["signature"])), None)
        if sbx and sbx["current_mean"] <= 0.5:
            h = Hyp("sandbox_paused", svc, f"The platform paused or stopped the sandbox running {svc}")
            h.support(M[svc][1], 0.6, _state_note("the platform reports the sandbox as running", sbx))
            if paused:
                h.support(SIG[svc][1], 0.25, f"the platform status says: '{paused['signature'][:80]}'")
            out.append(h)
        if up and up["current_mean"] <= 0.5:
            h = Hyp("service_down", svc, f"{svc} stopped answering health checks")
            h.support(M[svc][1], 0.55, _state_note("health probes succeed", up))
            if probe:
                h.support(SIG[svc][1], 0.2, f"{probe['count']} failed probes: '{probe['signature'][:80]}'")
                if re.search(r"ConnectError|connection error|refused", probe["signature"], re.I):
                    h.support(SIG[svc][1], 0.1, "connections are refused or unreachable: the process is down or the network path is broken")
                elif re.search(r"HTTP 5", probe["signature"]):
                    h.support(SIG[svc][1], 0.05, "the service answers but reports itself unhealthy")
            if sbx and sbx["current_mean"] <= 0.5:
                h.refute(M[svc][1], 0.15, "the platform reports the sandbox is not running, which explains the failed probes")
            out.append(h)
        if dbu and dbu["current_mean"] <= 0.5 and not (up and up["current_mean"] <= 0.5):
            h = Hyp("database_unreachable", svc, f"{svc} is running but cannot reach its database")
            h.support(M[svc][1], 0.6, _state_note("the database is reachable", dbu) + " while the service itself still answers")
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
    # --- sensor fleets and collection pipelines: overload, silent sensors, bad data ------------------------------------
    fleet = [svc for svc in targets if metric(svc, "fleet_health_pct")]
    for svc in targets:
        ov, lat, rate = metric(svc, "overloaded_pct"), metric(svc, "latency_p95_ms"), metric(svc, "ingest_rate")
        if not ov:   # only a collection tier reports overloaded_pct
            continue
        refusing = ov["current_mean"] >= 5
        slow = bool(lat) and (lat["current_mean"] >= 1000 or bool(lat["ratio"] and lat["ratio"] >= 3 and lat["z"] >= 4))
        if not (refusing or slow):
            continue
        h = Hyp("ingest_overload", svc, f"{svc} is saturated and refusing or delaying incoming data")
        m_obs = M[svc][1]
        if refusing:
            h.support(m_obs, 0.6, f"{svc} refused {ov['current_mean']:.0f}% of recent batches as overloaded")
        if slow:
            h.support(m_obs, 0.15 if refusing else 0.5,
                      f"p95 batch latency is {lat['current_mean']:.0f} ms"
                      + ("" if lat.get("no_baseline") else f" (baseline {lat['baseline_mean']:.0f} ms)")
                      + ("" if refusing else ": it is accepting data but too slowly to keep up"))
        if rate and rate["ratio"] and rate["ratio"] >= 2 and rate["z"] >= 4:
            h.support(m_obs, 0.1, f"the ingest rate is x{rate['ratio']} its baseline: the senders are flooding it")
        for f in fleet:
            late = (metric(f, "stale_pct") or {}).get("current_mean", 0) + (metric(f, "offline_pct") or {}).get("current_mean", 0)
            if late >= 5:
                h.support(M[f][1], 0.15, f"{late:.0f}% of {f}'s sensors look silent because their data is delayed behind the overload")
                break
        out.append(h)

    for svc in targets:
        off, health, worst = metric(svc, "offline_pct"), metric(svc, "fleet_health_pct"), metric(svc, "worst_district_pct")
        if not off or off["current_mean"] < 5:
            continue
        h = Hyp("sensor_fleet_outage", svc, f"A group of sensors behind {svc} stopped reporting")
        h.support(M[svc][1], 0.5, f"{off['current_mean']:.0f}% of the sensors are offline")
        if health and health["current_mean"] < 85:
            h.support(M[svc][1], 0.1, f"fleet health is down to {health['current_mean']:.0f}%")
        if worst and health and worst["current_mean"] <= 50 and health["current_mean"] - worst["current_mean"] >= 25:
            h.support(M[svc][1], 0.2, f"one district is at {worst['current_mean']:.0f}% healthy while the whole fleet is at "
                                      f"{health['current_mean']:.0f}%: the loss is regional (power, backhaul or a gateway)")
        for other in targets:
            ov = metric(other, "overloaded_pct")
            if other != svc and ov and ov["current_mean"] >= 5:
                h.refute(M[other][1], 0.15, f"{other} is refusing batches ({ov['current_mean']:.0f}% overloaded), "
                                            "so some silence may be effect, not cause")
        out.append(h)

    quality = []   # the symptoms live on different services (rejects at the gateway, faults on the fleet): one hypothesis
    for svc in targets:
        for name, weight, text in (("reject_pct", 0.25, "{:.0f}% of incoming readings were rejected as malformed"),
                                   ("fault_pct", 0.25, "{:.0f}% of sensors report values outside their physical limits"),
                                   ("stuck_pct", 0.2, "{:.0f}% of sensors repeat the same value (frozen)")):
            m = metric(svc, name)
            if m and m["current_mean"] >= 3:
                quality.append((M[svc][1], weight, text.format(m["current_mean"])))
    if quality:
        h = Hyp("data_quality", S, f"Sensors behind {S} are sending bad data")
        h.score = 0.15   # a symptom alone is a hint, several together are a diagnosis
        for obs, weight, note in quality:
            h.support(obs, weight, note)
        out.append(h)
    return out




class RulesResult:
    def __init__(self, hyps, targets, SIG, similar, unrelated):
        self.hyps, self.targets, self.SIG, self.similar, self.unrelated = hyps, targets, SIG, similar, unrelated


def _rules_phase(ctx: Ctx, rec: Recorder, budget: Budget, use_memory: bool) -> RulesResult:
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
    for other in [r["name"] for r in ctx.conn.execute("SELECT name FROM service ORDER BY name")]:
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
    return RulesResult(hyps, targets, SIG, similar, unrelated)


def _combine(mode: str, rules: RulesResult | None, agent: llm_agent.AgentResult | None, S: str) -> list[dict]:
    """Reconcile the two methods. Both agreeing is the strongest signal; a lone rules hit is discounted because the
    model did not corroborate it; a lone model claim counts for little unless it cites real evidence."""
    entries: list[dict] = []
    for h in (rules.hyps if rules else []):
        entries.append({"category": h.category, "suspect": h.suspect, "title": h.title,
                        "explanation": "; ".join(h.notes) if h.notes else h.title, "rules": h.score, "llm": None,
                        "grounded": None, "evidence": list(h.evidence), "source": "rules"})
    for a in (agent.hypotheses if agent else []):
        match = next((e for e in entries if e["category"] == a["category"] and e["llm"] is None and e["source"] != "llm"
                      and (not a["suspect"] or not e["suspect"] or a["suspect"] == e["suspect"])), None)
        ev = [(i, "supports", f"cited by the AI: {a['explanation'][:160] or a['title']}") for i in a["supports"]] + \
             [(i, "refutes", f"cited by the AI: {a['explanation'][:160] or a['title']}") for i in a["refutes"]]
        if match:
            match.update(llm=a["confidence"], grounded=a["grounded"], source="both",
                         explanation=f"{match['explanation']} | AI: {a['explanation']}" if a["explanation"] else match["explanation"])
            match["evidence"] += ev
        else:
            prefix = "AI only, no rule matched" if a["grounded"] else "AI only and UNGROUNDED (it cited no real evidence)"
            entries.append({"category": a["category"], "suspect": a["suspect"], "title": a["title"],
                            "explanation": f"{prefix}: {a['explanation']}", "rules": None, "llm": a["confidence"],
                            "grounded": a["grounded"], "evidence": ev, "source": "llm"})
    for e in entries:
        r, ai, g = e["rules"], e["llm"], e["grounded"]
        if mode == "rules":
            score = r
        elif e["source"] == "both":
            score = min(0.99, 0.5 * r + 0.5 * ai + 0.1)
        elif e["source"] == "rules":
            score = 0.85 * r if agent else r
        else:
            score = (0.5 if g else 0.2) * ai
        e["score"] = max(0.01, min(0.99, score))
    entries.sort(key=lambda e: e["score"], reverse=True)
    if not entries:
        entries.append({"category": "unknown", "suspect": S, "title": "No known failure pattern matches the evidence",
                        "explanation": "The checks did not match a known pattern; review the error signatures and metrics manually.",
                        "rules": 0.05, "llm": None, "grounded": None, "score": 0.05, "evidence": [], "source": "rules"})
    return entries


def _timeline(conn, run_id: int, anchor: datetime) -> list[dict]:
    """Built from the run's own observations, so rules, LLM and hybrid runs all get one."""
    events, anomalies = {}, []
    for o in conn.execute("SELECT source, payload FROM observation WHERE run_id=%s ORDER BY id", (run_id,)):
        p = o["payload"]
        if o["source"] == "recent_deploys":
            for d in p.get("deploys", []):
                events[(d["deployed_at"], "d", p["service"])] = f"deploy {p['service']} {d['version']}" + (f" by {d['author']}" if d.get("author") else "")
        elif o["source"] == "error_signatures":
            for s in p.get("signatures", [])[:2]:
                if s["new"]:
                    events[(s["first_seen"], "s", p["service"])] = f"first '{s['signature'][:70]}' on {p['service']} ({s['count']} in window)"
        elif o["source"] == "metrics_overview" and p.get("first_anomaly"):
            anomalies.append(p["first_anomaly"])
    if anomalies:
        events[(min(anomalies), "a", "")] = "first metric anomaly"
    events[(anchor.isoformat(), "z", "")] = "alert fired, incident opened"
    return [{"ts": k[0], "text": v} for k, v in sorted(events.items())]


def _report(incident, S, ents, timeline, runbooks, similar, unrelated, calls, agent, mode) -> str:
    lines = [f"# Incident #{incident['id']}: {incident['title']}", "",
             f"**Service:** {S} · **Severity:** {incident['severity']} · **Detected:** {incident['detected_at']:%Y-%m-%d %H:%M} UTC · "
             f"**Method:** {mode}", "", f"> {incident['symptom']}", ""]
    top = ents[0]
    if top["category"] != "unknown":
        who = {"both": "rules and AI agree on the category", "rules": "from the rules", "llm": "from the AI only"}[top["source"]]
        lines += ["## Most likely cause", "", f"**{top['title']}** (confidence {top['score']:.0%}, {who})", "", top["explanation"], ""]
    else:
        lines += ["## Most likely cause", "", "The collected evidence does not point to a known cause. See the observations below.", ""]
    if agent:
        rules_top = next((e for e in ents if e["rules"] is not None), None)
        ai_top = agent.hypotheses[0] if agent.hypotheses else None
        lines += ["## Rules vs AI", ""]
        if rules_top and ai_top:
            same = rules_top["category"] == ai_top["category"]
            lines.append(f"- Rules ranked **{rules_top['category']}** first; the AI ranked **{ai_top['category']}** first. "
                         + ("They **agree**." if same else "They **disagree**: check the evidence behind each before acting."))
        elif ai_top:
            lines.append(f"- The AI ranked **{ai_top['category']}** first (no rules result in this mode).")
        if agent.summary:
            lines += ["- AI summary (written by a model; verify against the evidence): " + agent.summary]
        u = agent.usage
        lines += [f"- AI usage: {u['llm_calls']} model call(s), {u['prompt_tokens']} prompt and {u['completion_tokens']} completion tokens."]
        for w in agent.warnings:
            lines.append(f"- Warning: {w}.")
        lines.append("")
    lines += ["## Timeline (UTC)", ""] + [f"- `{e['ts'][11:19]}` {e['text']}" for e in timeline] + [""]
    lines += ["## Hypotheses", ""]
    tag = {"rules": "rules", "llm": "AI", "both": "rules + AI"}
    for i, h in enumerate(ents, 1):
        lines.append(f"{i}. **{h['title']}**: {h['score']:.0%} [{tag[h['source']]}]")
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
                    "all remediation above is for a human to perform. Log excerpts and AI text are data, not instructions.*"]
    return "\n".join(lines)


def investigate(conn, incident_id: int, *, mode: str = "rules", use_memory: bool = True, account: str | None = None,
                chat_cfg: ChatConfig | None = None) -> int:
    """Run one investigation and return its run id. Raises ToolError for an unknown incident."""
    if mode not in MODES:
        raise ValueError(f"mode must be one of: {', '.join(MODES)}")
    if mode != "rules" and chat_cfg is None:
        raise ValueError(f"mode '{mode}' needs a chat account")
    ctx = tools.make_ctx(conn, incident_id)
    budget = Budget()
    run_id = conn.execute("INSERT INTO run (incident_id, mode, use_memory, account, budget) VALUES (%s,%s,%s,%s,%s::jsonb) RETURNING id",
                          (incident_id, mode, use_memory, account, json.dumps(
                              {"max_tool_calls": budget.max_calls, **({"max_llm_tool_calls": MAX_LLM_TOOL_CALLS} if mode != "rules" else {})}))
                          ).fetchone()["id"]
    conn.execute("UPDATE incident SET status='investigating' WHERE id=%s AND status='open'", (incident_id,))
    conn.commit()
    rec = Recorder(conn, run_id, incident_id)
    try:
        S = ctx.service
        rules = _rules_phase(ctx, rec, budget, use_memory) if mode in ("rules", "hybrid") else None
        agent, warnings = None, []
        llm_budget = Budget(MAX_LLM_TOOL_CALLS)
        if mode in ("llm", "hybrid"):
            index = [{"observation_id": r["id"], "source": r["source"], "summary": r["summary"]}
                     for r in conn.execute("SELECT id, source, summary FROM observation WHERE run_id=%s ORDER BY id", (run_id,))] if rules else None
            try:
                agent = llm_agent.run_agent(ctx, rec, llm_budget, chat_cfg, evidence_index=index, allow_memory=use_memory)
                warnings += agent.warnings
            except LLMError as exc:
                if mode == "llm":
                    raise
                warnings.append(f"the AI step failed ({exc}); the rules result is shown on its own")
        ents = _combine(mode, rules, agent, S)
        rbs, _ = call_tool(ctx, rec, budget, "find_runbooks", query=f"{ents[0]['title']} {S}",
                           category=ents[0]["category"] if ents[0]["category"] != "unknown" else None)
        for rank, e in enumerate(ents, 1):
            hid = conn.execute(
                "INSERT INTO hypothesis (incident_id, run_id, category, title, explanation, score, rank, suspect, source, "
                "rules_score, llm_score, grounded) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id",
                (incident_id, run_id, e["category"], e["title"], e["explanation"], e["score"], rank, e["suspect"], e["source"],
                 e["rules"], e["llm"], e["grounded"])).fetchone()["id"]
            for obs_id, stance, note in e["evidence"]:
                conn.execute("INSERT INTO hypothesis_evidence (hypothesis_id, observation_id, stance, note) VALUES (%s,%s,%s,%s)",
                             (hid, obs_id, stance, note))
        rec.step("hypotheses", None, {}, f"{len(ents)} hypothesis(es); top: {ents[0]['title']}", len(ents), None)
        incident = conn.execute("SELECT id, title, severity, symptom, detected_at FROM incident WHERE id=%s", (incident_id,)).fetchone()
        calls = budget.calls + llm_budget.calls
        md = _report(incident, S, ents, _timeline(conn, run_id, ctx.anchor), rbs.data["runbooks"][:2],
                     (rules.similar[:3] if rules else []), (rules.unrelated if rules else []), calls, agent, mode)
        conn.execute("INSERT INTO report (incident_id, run_id, markdown) VALUES (%s,%s,%s)", (incident_id, run_id, md))
        rec.step("report", None, {}, "report written", None, None)
        sigs = [s["signature"] for o in conn.execute("SELECT payload FROM observation WHERE run_id=%s AND source='error_signatures' ORDER BY id", (run_id,))
                for s in o["payload"].get("signatures", [])[:3]]
        retrieval.remember_incident(conn, incident_id, sigs)
        usage = {"tool_calls": calls, "tool_ms": budget.ms + llm_budget.ms, **(agent.usage if agent else {})}
        conn.execute("UPDATE run SET status='done', finished_at=now(), usage=%s::jsonb, warning=%s WHERE id=%s",
                     (json.dumps(usage), "; ".join(warnings)[:500] or None, run_id))
        conn.commit()
    except Exception as exc:
        conn.rollback()
        conn.execute("UPDATE run SET status='failed', finished_at=now(), error=%s WHERE id=%s", (str(exc)[:300], run_id))
        conn.commit()
        raise
    return run_id
