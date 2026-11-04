"""AIDB mode, runtime side (opt-in; plain Postgres stays the default and keeps working).

Two independent switches, both off by default:

* `PAGERLENS_RETRIEVAL_BACKEND=app|aidb` (agentpg-kit `apgkit.retrieval.select`): where runbook search and incident recall come from.
  `app` is the existing code (pgvector in this process's tables, our embeddings). `aidb` reads AIDB knowledge bases that live pipelines
  keep current over the runbook and resolved-incident text. Asking for `aidb` where it cannot work falls back to `app` loudly (an ERROR
  line, and /readyz says so); a failure at query time falls back for that call.
* the investigator method `aidb` / `aidb_hybrid`: an AIDB agent with custom SQL tools over read-only evidence views (aidb_views.py), run
  under a purpose bound to a role that holds SELECT on those views and nothing else.

What stays in the application whichever way a switch is set: row MACs on runbooks (a hit is only a key; the row is read back and verified
here), the citation check (an evidence id the agent cites must exist in the views for this incident's window or it is dropped), fencing
and scrubbing of everything shown, the bounded budget and the human decisions.

Verification: the operator's `pagerlens aidb-setup` seals every authority-bearing definition under the vault data key. `verify_cached`
compares them with the catalog; a definition changed behind the app's back is reported (/readyz, `pagerlens aidb-status`, a counter and
a security log line). The agent refuses to run while any definition fails verification, and the AIDB retrieval backend is not used while a
pipeline or model fails verification (it falls back to `app`). Like the row MACs, this is enforced only while the vault is unlocked.
"""
import logging
import os
import re
import threading
import time
from datetime import datetime, timedelta

import psycopg
from apgkit import aidb, retrieval

from . import aidb_setup, aidb_views, core, rowmac
from .investigator_core import CATEGORIES, Recorder
from .llm_agent import FENCE_CLOSE, FENCE_OPEN, MAX_HYPOTHESES, AgentResult, _ids, _parse_final
from .scrub import scrub

log = logging.getLogger("pagerlens.aidb")
sec = logging.getLogger("pagerlens.security")

PREFIX = "PAGERLENS"
KB = {"runbook": "public.pipeline_pl_runbook", "incident": "public.pipeline_pl_incident"}
RECHECK_SECONDS = 60          # a fallback is retried after this long (AIDB may have been set up meanwhile)
VERIFY_SECONDS = 300
CONVERSE_TIMEOUT = 150.0
MAX_CITATIONS = 40
WINDOW_BEFORE, WINDOW_AFTER = timedelta(hours=6), timedelta(minutes=30)
# bge-small cosine similarities of unrelated short texts sit around 0.5; the app's thresholds (0.2 minimum, 0.3 for the memory prior) were
# set for a different embedding model. Similarities from the AIDB knowledge base are rescaled so that SIM_FLOOR maps to 0 and 1 to 1.
SIM_FLOOR = 0.5            # PAGERLENS_AIDB_SIM_FLOOR overrides it


class AidbModeError(RuntimeError):
    """The AIDB agent cannot be used or failed (the AIDB counterpart of llm_http.LLMError). Never carries a secret."""


class _App:
    """The `app` backend: the retrieval code in retrieval.py itself. A sentinel for `retrieval.select`, which only needs `.name`."""
    name = "app"

    def retrieve(self, *_a, **_k):  # pragma: no cover - never called: callers branch on the name
        raise NotImplementedError


APP = _App()
_lock = threading.Lock()
_retrievers: dict[str, tuple[object, float]] = {}
_verify: dict = {"at": 0.0, "checked": False, "drift": [], "reason": "not checked yet"}


def reset() -> None:
    """Forget every cached decision (tests, and after `aidb-setup` in the same process)."""
    with _lock:
        _retrievers.clear()
        _verify.update(at=0.0, checked=False, drift=[], reason="not checked yet")


def requested_backend() -> str:
    return retrieval.requested_backend(PREFIX)


# ---------------------------------------------------------------------------------------------------------------------
# Verification of sealed definitions
# ---------------------------------------------------------------------------------------------------------------------
RETRIEVAL_KINDS = ("pipeline", "model", "credential")


def _extra_drift(conn) -> list[aidb.Drift]:
    """The evidence views and pl_fence, which the kit's seal does not cover: modified or missing since the operator sealed them."""
    out: list[aidb.Drift] = []
    if not aidb.seal_table_exists(conn):          # nothing was ever sealed: the views that exist are unsealed (no DDL, no error)
        for name in (*aidb_views.VIEW_NAMES, aidb_setup.GOVERNANCE_VIEW):
            if aidb_views.current_definition(conn, name) is not None:
                out.append(aidb.Drift("pl_view", name, "unsealed"))
        if aidb_views.function_definition(conn, "pl_fence") is not None:
            out.append(aidb.Drift("pl_function", "pl_fence", "unsealed"))
        return out
    for r in conn.execute("SELECT kind, name, mac FROM apgkit_aidb_seal WHERE kind = ANY(%s) ORDER BY kind, name",
                          (list(aidb_setup.SEAL_KINDS_EXTRA),)).fetchall():
        fields = (aidb_views.current_definition(conn, r["name"]) if r["kind"] == "pl_view"
                  else aidb_views.function_definition(conn, r["name"]))
        if fields is None:
            out.append(aidb.Drift(r["kind"], r["name"], "missing"))
        elif not core.vault.check_row_mac(aidb.SEAL_TABLE, r["mac"], *fields):
            out.append(aidb.Drift(r["kind"], r["name"], "modified"))
    return out


def verify_now(conn) -> dict:
    """Compare every sealed AIDB definition with the catalog. While the vault is locked nothing can be checked (`checked: False`)."""
    if not core.vault.is_unlocked():
        res = {"at": time.monotonic(), "checked": False, "drift": [], "reason": "the vault is locked, so seals cannot be verified"}
    else:
        try:
            drift = [*aidb.verify(conn, core.vault, expect=aidb_setup.expected_seals()), *_extra_drift(conn)]
            conn.commit()
            res = {"at": time.monotonic(), "checked": True, "drift": [{"kind": d.kind, "name": d.name, "problem": d.problem} for d in drift],
                   "reason": ""}
        except Exception as exc:  # noqa: BLE001 - AIDB absent, role without access: the check could not run
            conn.rollback()
            res = {"at": time.monotonic(), "checked": False, "drift": [], "reason": f"could not verify: {type(exc).__name__}"}
    with _lock:
        before = {(d["kind"], d["name"]) for d in _verify["drift"]}
        _verify.update(res)
    for d in res["drift"]:
        if (d["kind"], d["name"]) not in before:
            rowmac.tampered.labels(f"aidb_{d['kind']}").inc()
            sec.warning("AIDB definition refused, %s: %s %s (changed outside the app; inspect it, then re-run `pagerlens aidb-setup`)",
                        d["problem"], d["kind"], d["name"])
    return dict(res)


def verify_cached(conn, max_age: float = VERIFY_SECONDS) -> dict:
    with _lock:
        age = time.monotonic() - _verify["at"]
        if _verify["at"] and age < max_age and not (not _verify["checked"] and core.vault.is_unlocked()):
            return dict(_verify)
    return verify_now(conn)


def tampered(conn, kinds: tuple[str, ...] | None = None) -> list[dict]:
    drift = verify_cached(conn)["drift"]
    return [d for d in drift if kinds is None or d["kind"] in kinds]


# ---------------------------------------------------------------------------------------------------------------------
# Retrieval backend
# ---------------------------------------------------------------------------------------------------------------------
def _select(kind: str):
    from .db import connect

    return retrieval.select(PREFIX, app=APP, aidb=retrieval.AidbRetrieval(KB[kind]), connect=lambda: connect(retries=1))


def retriever(kind: str, conn=None):
    """The backend for `kind` ('runbook' | 'incident'): `APP` or an AidbRetrieval. The choice is made lazily and cached; a fallback is
    re-examined every RECHECK_SECONDS so an app started before `aidb-setup` picks AIDB up without a restart."""
    if requested_backend() == "app":
        return APP
    with _lock:
        hit = _retrievers.get(kind)
    if hit and hit[0] is not APP:
        bad = _retrieval_drift(conn)            # an AIDB choice is kept, but a pipeline that stops verifying ends it (checked at most every VERIFY_SECONDS)
        if not bad:
            return hit[0]
        _use_app(kind, bad)
        return APP
    if hit and time.monotonic() - hit[1] < RECHECK_SECONDS:
        return hit[0]
    r = _select(kind)
    if r is not APP:
        bad = _retrieval_drift(conn)
        if bad:
            _use_app(kind, bad)
            return APP
    with _lock:
        _retrievers[kind] = (r, time.monotonic())
    return r


def _retrieval_drift(conn) -> list[dict]:
    if conn is None:
        return []
    try:
        return tampered(conn, RETRIEVAL_KINDS)
    except Exception:  # noqa: BLE001 - the check itself failing is not evidence of tampering
        return []


def _use_app(kind: str, bad: list[dict]) -> None:
    log.error("RETRIEVAL BACKEND FALLBACK: %s_RETRIEVAL_BACKEND=aidb but %s failed verification (%s); using the app backend",
              PREFIX, ", ".join(f"{d['kind']} {d['name']}" for d in bad[:3]), bad[0]["problem"])
    with _lock:
        _retrievers[kind] = (APP, time.monotonic())


def _norm_similarity(distance: float | None) -> float | None:
    if distance is None:
        return None
    try:
        floor = min(0.95, max(0.0, float(os.environ.get("PAGERLENS_AIDB_SIM_FLOOR", SIM_FLOOR))))
    except ValueError:
        floor = SIM_FLOOR
    cos = 1.0 - float(distance)
    return round(max(0.0, (cos - floor) / (1.0 - floor)), 4)


def _fallback(kind: str, exc: Exception) -> None:
    log.error("RETRIEVAL BACKEND FALLBACK: AIDB %s retrieval failed at query time (%s: %s); this call uses the app backend",
              kind, type(exc).__name__, str(exc).splitlines()[0][:160] if str(exc) else "")
    with _lock:
        _retrievers[kind] = (APP, time.monotonic())          # re-examined after RECHECK_SECONDS


def search_runbooks(conn, query: str, *, category: str | None, service: str | None, limit: int) -> list[dict] | None:
    """Runbook hits from the AIDB knowledge base, or None when the app backend should answer. A hit is only a key: the runbook row is read
    back and its MAC verified here, exactly as for the app backend, and the `service` filter is applied to the row."""
    r = retriever("runbook", conn)
    if r is APP:
        return None
    try:
        with conn.transaction():
            hits = r.retrieve(conn, query[:300], limit * 5 if rowmac.enforced() else max(limit * 2, 6),
                              filters={"category": category} if category else None, hybrid=True)
            ids = [int(h.key) for h in hits]
            rows = {x["id"]: x for x in conn.execute(
                "SELECT id, title, category, service, body, mac FROM runbook WHERE id = ANY(%s)", (ids,)).fetchall()} if ids else {}
    except Exception as exc:  # noqa: BLE001 - AIDB must never make runbook search fail
        _fallback("runbook", exc)
        return None
    out = []
    for h in hits:
        row = rows.get(int(h.key))
        if row is None or not rowmac.verify("runbook", row) or (service and row["service"] not in (None, service)):
            continue
        out.append({**rowmac.without_mac(row), "score": h.score})
    return out[:limit]


def similar_incidents(conn, text: str, *, exclude_id: int | None, limit: int, min_similarity: float) -> list[dict] | None:
    """Resolved incidents recalled from the AIDB knowledge base over the incident memory, or None for the app backend. Similarity is the
    knowledge base's cosine similarity rescaled (see SIM_FLOOR) so the app's thresholds keep their meaning."""
    r = retriever("incident", conn)
    if r is APP:
        return None
    try:
        with conn.transaction():
            hits = r.retrieve(conn, text[:1000], limit + 4, hybrid=False)
            sims = {int(h.key): _norm_similarity(h.distance) for h in hits}
            ids = [i for i in sims if i != exclude_id and sims[i] is not None and sims[i] >= min_similarity]
            rows = {x["id"]: x for x in conn.execute(
                "SELECT i.id, i.title, i.symptom, i.root_cause_category, i.root_cause_note, COALESCE(s.name, i.service_name) AS service, "
                "i.resolved_at FROM incident i LEFT JOIN service s ON s.id = i.service_id "
                "WHERE i.id = ANY(%s) AND i.status = 'resolved' AND i.root_cause_category IS NOT NULL", (ids,)).fetchall()} if ids else {}
    except Exception as exc:  # noqa: BLE001
        _fallback("incident", exc)
        return None
    ordered = sorted((i for i in ids if i in rows), key=lambda i: -sims[i])
    return [{**rows[i], "similarity": sims[i]} for i in ordered][:limit]


# ---------------------------------------------------------------------------------------------------------------------
# The AIDB agent
# ---------------------------------------------------------------------------------------------------------------------
def agent_ready(conn) -> None:
    """Raise AidbModeError (a message safe to show) unless the agent exists, is usable by this role and every definition verifies."""
    st = aidb.detect(conn)
    if not st.available:
        raise AidbModeError(f"AIDB is not available here: {st.reason}")
    if not conn.execute("SELECT 1 FROM aidb.agents WHERE name = %s", (aidb_setup.AGENT,)).fetchone():
        raise AidbModeError("the AIDB agent is not set up: an operator runs `pagerlens aidb-setup`")
    bad = tampered(conn)
    if bad:
        raise AidbModeError("AIDB definitions failed verification, the agent is refused: "
                            + ", ".join(f"{d['kind']} {d['name']} ({d['problem']})" for d in bad[:4]))


_EVIDENCE = {
    "deploy": ("pl_ev_deploys", "deployed_at", "deploy"),
    "alert": ("pl_ev_alerts", "fired_at", "alert"),
    "log": ("pl_ev_logs", "ts", "log"),
    "metric": ("pl_ev_metrics", "bucket", "metric"),
}
_ID = re.compile(r"^(?:(deploy|alert|log):\d{1,12}|metric:[a-z0-9][a-z0-9._-]{0,62}:[a-z_0-9]{1,40}:\d{1,12}|service:[a-z0-9][a-z0-9._-]{0,62}|"
                 r"incident:\d{1,12}|obs:\d{1,12})$")


def _json_row(row: dict) -> dict:
    return {k: (v.isoformat() if isinstance(v, datetime) else float(v) if hasattr(v, "as_tuple") else v) for k, v in row.items()}


def verify_citations(conn, rec: Recorder, anchor: datetime, incident_id: int, raw: list) -> tuple[dict[str, int], int]:
    """Check evidence ids the agent cited. A citation counts only if the id exists in the evidence views, inside this incident's window,
    or is an observation of this incident (`obs:<id>`, rules evidence in the hybrid method). Each verified id becomes (or is) an
    observation of the run, so hypotheses cite stored rows exactly as for the other methods. Returns ({evidence id: observation id}, dropped)."""
    ok: dict[str, int] = {}
    dropped = 0
    lo, hi = anchor - WINDOW_BEFORE, anchor + WINDOW_AFTER
    for ident in list(dict.fromkeys(str(x).strip() for x in raw if isinstance(x, (str, int))))[:MAX_CITATIONS]:
        if not _ID.match(ident):
            dropped += 1
            continue
        kind, _, rest = ident.partition(":")
        if kind == "obs":
            if conn.execute("SELECT 1 FROM observation WHERE id = %s AND incident_id = %s", (int(rest), incident_id)).fetchone():
                ok[ident] = int(rest)
            else:
                dropped += 1
            continue
        if kind == "incident":
            row = conn.execute("SELECT * FROM pl_ev_incidents WHERE evidence_id = %s AND incident_id = %s", (ident, incident_id)).fetchone()
        elif kind == "service":
            row = conn.execute("SELECT * FROM pl_ev_services WHERE evidence_id = %s", (ident,)).fetchone()
        else:
            view, col, _ = _EVIDENCE[kind]
            row = conn.execute(f"SELECT * FROM {view} WHERE evidence_id = %s AND {col} BETWEEN %s AND %s",       # noqa: S608 - fixed names
                               (ident, lo, hi)).fetchone()
        if row is None:
            dropped += 1
            continue
        step = rec.step("evidence", None, {"evidence_id": ident}, f"verified {ident} in the evidence views", 1, None)
        ok[ident] = rec.observe(step, "aidb_evidence", kind, f"{ident}: verified row from the evidence views (cited by the AIDB agent)",
                                {"evidence_id": ident, "row": _json_row(row), "untrusted_fields": ["message", "summary", "title", "symptom", "name", "signature"]})
    return ok, dropped


def _strs(values) -> list[str]:
    return [str(x).strip() for x in (values if isinstance(values, list) else []) if isinstance(x, (str, int))]


def _brief(ctx, evidence_index: list[dict] | None) -> str:
    text = (f"Incident #{ctx.incident_id}\nAlerting service: {ctx.service}\nAnchor (detected_at, pass it as `anchor`): {ctx.anchor.isoformat()}\n"
            f"Symptom (from the alert): {FENCE_OPEN}{scrub(ctx.symptom).replace(FENCE_CLOSE, '[removed]')[:600]}{FENCE_CLOSE}\n"
            "Use at most 12 tool calls.")
    if evidence_index:
        lines = "\n".join(f"obs:{e['observation_id']} [{e['source']}] {scrub(e['summary'])[:160]}" for e in evidence_index[:40])
        text += ("\n\nEvidence already collected by the rules investigator (you may cite these ids as shown):\n"
                 f"{FENCE_OPEN}\n{lines.replace(FENCE_CLOSE, '[removed]')}\n{FENCE_CLOSE}")
    return text


def _governance_view_exists(conn) -> bool:
    return bool(conn.execute("SELECT to_regclass(%s) IS NOT NULL AS ok", (f"public.{aidb_setup.GOVERNANCE_VIEW}",)).fetchone()["ok"])


def _denials_since(conn, started: datetime) -> int | None:
    try:
        with conn.transaction():
            if not _governance_view_exists(conn):
                return None
            return conn.execute(f"SELECT count(*) AS n FROM {aidb_setup.GOVERNANCE_VIEW} WHERE decision_status = 'denied' "      # noqa: S608
                                "AND agent_name = %s AND recorded_at >= %s", (aidb_setup.AGENT, started)).fetchone()["n"]
    except Exception:  # noqa: BLE001 - not readable by this role: unknown, not zero
        return None


def run_agent(ctx, rec: Recorder, *, evidence_index: list[dict] | None = None) -> AgentResult:
    """One AIDB agent conversation for the incident in `ctx`. Raises AidbModeError when it cannot run or returns nothing usable. The
    agent runs on its own connection (AIDB commits the conversation); the app's connection only verifies and records."""
    from .db import connect

    agent_ready(ctx.conn)
    result = AgentResult()
    started = datetime.now().astimezone()
    t0 = time.monotonic()
    with connect(retries=1) as aconn:
        reply = aidb.converse(aconn, aidb_setup.AGENT, _brief(ctx, evidence_index), timeout=CONVERSE_TIMEOUT)
        final_text, conversation = reply.message or "", reply.conversation_id
        if reply.ok:
            try:
                final = _parse_final(final_text)
            except ValueError:
                again = aidb.converse(aconn, aidb_setup.AGENT, "That was not valid JSON in the required shape. Reply with ONLY the JSON object.",
                                      conversation_id=conversation, timeout=CONVERSE_TIMEOUT)
                try:
                    final = _parse_final(again.message or "")
                except ValueError:
                    final = None
        else:
            final = None
    ms = int((time.monotonic() - t0) * 1000)
    rec.step("aidb_agent", None, {"agent": aidb_setup.AGENT, "purpose": aidb_setup.PURPOSE, "conversation_id": conversation},
             scrub(final_text)[:300] or (reply.error or "no reply")[:300], None, ms)
    result.usage["llm_calls"] = 1
    if reply.timed_out:
        raise AidbModeError("the AIDB agent timed out")
    if not reply.ok:
        raise AidbModeError(f"the AIDB agent failed: {scrub(str(reply.error))[:200]}")
    if final is None:
        raise AidbModeError("the AIDB agent did not return a usable answer (invalid JSON twice)")
    services = {r["name"] for r in ctx.conn.execute("SELECT name FROM service")}
    cited: dict[str, int] = {}
    invalid = 0
    hyps = []
    for h in final["hypotheses"][:MAX_HYPOTHESES]:
        if not isinstance(h, dict):
            continue
        sup, ref = _strs(h.get("supports")), _strs(h.get("refutes"))
        ok, dropped = verify_citations(ctx.conn, rec, ctx.anchor, ctx.incident_id, [x for x in dict.fromkeys([*sup, *ref]) if x not in cited])
        cited.update(ok)
        invalid += dropped
        supports = _ids([cited[x] for x in sup if x in cited], set(cited.values()))
        refutes = _ids([cited[x] for x in ref if x in cited], set(cited.values()))
        category = h.get("category") if h.get("category") in CATEGORIES else "unknown"
        try:
            confidence = max(0.0, min(1.0, float(h.get("confidence", 0.0))))
        except (TypeError, ValueError):
            confidence = 0.0
        hyps.append({"category": category, "suspect": h.get("suspect") if h.get("suspect") in services else None, "confidence": confidence,
                     "title": scrub(str(h.get("title") or CATEGORIES[category]))[:200], "explanation": scrub(str(h.get("explanation") or ""))[:800],
                     "supports": supports, "refutes": refutes, "grounded": bool(supports), "cited_invalid": 0})
    result.hypotheses = hyps
    result.summary = scrub(str(final.get("summary") or ""))[:600]
    if invalid:
        result.warnings.append(f"the AIDB agent cited {invalid} evidence id(s) that do not exist in this incident's window; those citations were dropped")
    if not hyps:
        result.warnings.append("the AIDB agent returned no hypotheses")
    denied = _denials_since(ctx.conn, started)
    if denied:
        result.warnings.append(f"{denied} tool call(s) of the AIDB agent were denied by its purpose (see the governance panel)")
    return result


# ---------------------------------------------------------------------------------------------------------------------
# Health, status and the governance panel
# ---------------------------------------------------------------------------------------------------------------------
def health(conn) -> dict:
    """What /readyz reports about AIDB. Never raises and never makes the app unready: AIDB is optional."""
    want = requested_backend()
    out: dict = {"requested_backend": want, "state": "off"}
    try:
        st = aidb.detect(conn)
        conn.commit()
        out["available"] = st.available
        if not st.available:
            out["reason"] = "aidb is not installed or not usable by this role" if want == "aidb" else ""
            if want == "aidb":
                out["state"] = "unavailable"
            return {k: v for k, v in out.items() if v != ""}
        agent = conn.execute("SELECT 1 FROM aidb.agents WHERE name = %s", (aidb_setup.AGENT,)).fetchone() is not None
        kbs = [k for k, kb in KB.items() if aidb.kb_exists(conn, kb)]
        conn.commit()
        out.update(version=st.version, agent=agent, knowledge_bases=kbs)
        if not agent and not kbs:
            out["state"] = "not-set-up"
            return out
        v = verify_cached(conn)
        out["verified"] = v["checked"]
        if not aidb.seal_table_exists(conn):
            conn.commit()
            out["state"] = "unsealed"          # AIDB objects without any seal: refused, but the app stays ready
            out["verify_note"] = "the seal table does not exist: an operator runs `pagerlens aidb-setup`"
        elif v["drift"]:
            out["state"] = "tampered"
            out["tampered"] = [f"{d['kind']} {d['name']}: {d['problem']}" for d in v["drift"][:10]]
        else:
            out["state"] = "ready" if v["checked"] else "unverified"
            if not v["checked"]:
                out["verify_note"] = v["reason"]
        if want == "aidb":
            out["retrieval"] = {k: retriever(k, conn).name for k in KB}
    except Exception as exc:  # noqa: BLE001
        try:
            conn.rollback()
        except Exception:  # noqa: BLE001, S110
            pass
        out["state"] = "error"
        out["error"] = type(exc).__name__
    return out


def governance(conn, *, window: str = "24 hours") -> dict:
    """The small governance panel: what the agent may touch, what verification says, and the tool calls its purpose denied."""
    out: dict = {"agent": aidb_setup.AGENT, "purpose": aidb_setup.PURPOSE, "role": aidb.purpose_role_name(aidb_setup.PURPOSE),
                 "window": window, "grants": [], "denials": [], "allowed": None, "telemetry": {}, "verification": {}}
    st = aidb.detect(conn)
    conn.commit()
    if not st.available:
        out["state"] = "unavailable"
        out["reason"] = st.reason
        return out
    out["state"] = "ready"
    out["telemetry"] = {"otel_client": st.otel_client, "can_read": st.can_read_telemetry}
    out["grants"] = [f"{p} on {s}.{r}" for s, r, p in aidb.role_grants(conn, out["role"])]
    v = verify_cached(conn)
    out["verification"] = {"checked": v["checked"], "drift": v["drift"], "reason": v["reason"]}
    # The source is the narrow view `aidb-setup` creates (no SQL text, only this app's agents and purpose). The kit's `aidb.decisions`
    # reads aidb_otel.traces itself and is used only by a role that was given that access some other way.
    try:
        with conn.transaction():
            if _governance_view_exists(conn):
                out["source"] = aidb_setup.GOVERNANCE_VIEW
                rows = conn.execute(f"SELECT recorded_at, decision_id, agent_name, agent_role, interaction_point, denial_reason, denial_class "   # noqa: S608
                                    f"FROM {aidb_setup.GOVERNANCE_VIEW} WHERE decision_status = 'denied' AND recorded_at > now() - %s::interval "
                                    "ORDER BY id DESC LIMIT 50", (window,)).fetchall()
                out["denials"] = [{"at": r["recorded_at"].isoformat(), "agent": r["agent_name"], "role": r["agent_role"], "reason": r["denial_reason"],
                                   "class": r["denial_class"], "where": r["interaction_point"], "decision_id": r["decision_id"]} for r in rows]
                out["allowed"] = conn.execute(f"SELECT count(*) AS n FROM {aidb_setup.GOVERNANCE_VIEW} WHERE decision_status = 'allowed' "        # noqa: S608
                                              "AND recorded_at > now() - %s::interval", (window,)).fetchone()["n"]
            elif st.can_read_telemetry:
                out["source"] = "apgkit.aidb.decisions"
                out["denials"] = [{"at": d["recorded_at"].isoformat(), "agent": d["agent"], "role": d["role"], "reason": d["reason"],
                                   "decision_id": d["decision_id"]} for d in aidb.decisions(conn, status="denied", since=window, limit=50)]
            else:
                out["denials_error"] = f"the view {aidb_setup.GOVERNANCE_VIEW} does not exist (an operator runs `pagerlens aidb-setup`)"
    except psycopg.Error as exc:
        out["denials_error"] = type(exc).__name__
    return out


def status(conn) -> dict:
    """Everything `pagerlens aidb-status` prints: the kit's report plus verification and the backend in effect."""
    rep = aidb.status(conn)
    v = verify_cached(conn, max_age=0)
    rep["verification"] = {"checked": v["checked"], "drift": v["drift"], "reason": v["reason"]}
    rep["requested_backend"] = requested_backend()
    if rep["aidb"]["available"]:
        if not rep["aidb"].get("can_read_telemetry"):          # the runtime role never reads aidb_otel.traces: count from the narrow view
            try:
                with conn.transaction():
                    if _governance_view_exists(conn):
                        rep["denials"] = {"window": "24 hours", "source": aidb_setup.GOVERNANCE_VIEW, "count": conn.execute(
                            f"SELECT count(*) AS n FROM {aidb_setup.GOVERNANCE_VIEW} WHERE decision_status = 'denied' "      # noqa: S608
                            "AND recorded_at > now() - interval '24 hours'").fetchone()["n"]}
            except psycopg.Error:
                pass
        rep["retrieval"] = {k: retriever(k, conn).name for k in KB} if rep["requested_backend"] == "aidb" else {k: "app" for k in KB}
    return rep


__all__ = ["APP", "AidbModeError", "agent_ready", "governance", "health", "reset", "retriever", "run_agent", "search_runbooks",
           "similar_incidents", "status", "verify_cached", "verify_now"]
