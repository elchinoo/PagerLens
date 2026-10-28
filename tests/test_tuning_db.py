"""Propose-and-approve tuning against a disposable Postgres: proposals from the kit's insights and the slow-query findings, approval,
the apply switch (off by default), the allow-list at apply time, EXPLAIN-based before and after, one at a time, timeouts and audit."""
import json
import os

import pytest

if not os.environ.get("TEST_DATABASE_URL"):
    pytest.skip("set TEST_DATABASE_URL to run DB tests", allow_module_level=True)

from pagerlens import auth, core, migrate, simulator, tuning, vault  # noqa: E402
from pagerlens.db import connect, connect_vector  # noqa: E402

H = {"X-PagerLens-CSRF": "1"}
PASSWORD = "correct-horse-battery"  # pragma: allowlist secret
DEMO_QUERY = "SELECT * FROM public.tuning_demo WHERE k = $1"


@pytest.fixture(autouse=True)
def _db(monkeypatch, client):
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    for v in ("PAGERLENS_API_KEY", "PAGERLENS_ALLOW_ANONYMOUS", "PAGERLENS_ENCRYPTION_KEY", "PAGERLENS_ALLOW_TUNING_APPLY",
              "LLM_BASE_URL", "PAGERLENS_TUNING_LOCK_TIMEOUT_SECONDS"):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setenv("PAGERLENS_API_KEY_FILE", "/nonexistent/key")
    monkeypatch.setenv("PAGERLENS_ENCRYPTION_KEY_FILE", "/nonexistent/key")
    monkeypatch.setenv("LLM_API_KEY_FILE", "/nonexistent/key")
    core.auth.limiter.clear()
    core.local._setup_code = None
    vault.lock()
    client.cookies.clear()
    with connect() as c:
        c.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public")
        c.commit()
    migrate.run()


@pytest.fixture
def admin(client):
    with connect() as c:
        auth.set_admin_password(c, PASSWORD)
    assert client.post("/api/login", json={"password": PASSWORD}, headers=H).status_code == 200
    return client


def token(admin, scope):
    return {"Authorization": "Bearer " + admin.post("/api/tokens", json={"name": scope, "scope": scope}, headers=H).json()["token"]}


@pytest.fixture
def demo_table():
    """A table big enough that the planner prefers an index once one exists on k (30 000 rows, 300 distinct values)."""
    with connect() as c:
        c.execute("CREATE TABLE public.tuning_demo (id serial PRIMARY KEY, k text NOT NULL, j int NOT NULL)")
        c.execute("INSERT INTO public.tuning_demo (k, j) SELECT 'key' || (g % 300), g % 10 FROM generate_series(1, 30000) g")
        c.execute("ANALYZE public.tuning_demo")
        c.commit()


def propose(statement, *, applicable=True, target="self", query=DEMO_QUERY, status="proposed", source="advisor"):
    with connect() as c:
        pid = c.execute(
            "INSERT INTO tuning_proposal (source, target, statement, applicable, rationale, estimated_benefit, motivating_queryid, "
            "motivating_query, status) VALUES (%s,%s,%s,%s,'because','faster','42',%s,%s) RETURNING id",
            (source, target, statement, applicable, query, status)).fetchone()["id"]
        c.commit()
    return pid


def row(pid):
    with connect() as c:
        return tuning.get(c, pid)


def actions(pid):
    return [(a["action"], a["actor"]) for a in row(pid)["audit"]]


def approve(admin, pid, note="looks right"):
    r = admin.post(f"/api/tuning/{pid}/decide", json={"decision": "approve", "note": note}, headers=H)
    assert r.status_code == 200, r.text
    return r.json()


def index_exists(name):
    with connect() as c:
        return c.execute("SELECT to_regclass(%s) IS NOT NULL AS ok", (f"public.{name}",)).fetchone()["ok"]


INSIGHTS = {
    "top_queries": {"available": True, "queries": [{"queryid": "111", "query": "SELECT * FROM incident WHERE status = $1", "mean_ms": 5.0}]},
    "advisor": {"available": True, "suggestions": [
        {"schema": "public", "table": "incident", "column": "status", "operator": "=", "occurrences": 40, "executions": 900,
         "rows_filtered": 90000, "filtered_per_execution": 100.0},
        {"schema": "public", "table": "incident", "column": "severity", "operator": "=", "occurrences": 4, "executions": 90,
         "rows_filtered": 900, "filtered_per_execution": 10.0}]},
    "tuner": {"available": True, "recommendations": [{"setting": "shared_buffers", "value": "186 MB", "raw": "x"}]},
}


# ---- scanning and proposals -----------------------------------------------------------------------------

def test_scan_records_proposals_once_and_audits(admin):
    with connect() as c:
        first = tuning.scan(c, "operator", insights=INSIGHTS)
        second = tuning.scan(c, "operator", insights=INSIGHTS)
    assert len(first["created"]) == 4 and first["skipped"] == 0           # two indexes, one statistics, one tuner advice
    assert second["created"] == [] and second["skipped"] == 4
    listing = admin.get("/api/tuning").json()
    assert listing["apply_enabled"] is False and len(listing["proposals"]) == 4
    by_source = {}
    for p in listing["proposals"]:
        by_source.setdefault(p["source"], []).append(p)
    assert len(by_source["advisor"]) == 3 and all(p["applicable"] and p["status"] == "proposed" for p in by_source["advisor"])
    assert by_source["tuner"][0]["applicable"] is False and by_source["tuner"][0]["target"] == "self"
    one = admin.get(f"/api/tuning/{first['created'][0]}").json()
    assert [a["action"] for a in one["audit"]] == ["created"] and one["audit"][0]["actor"] == "operator"


def test_a_rejected_proposal_is_not_proposed_again(admin):
    with connect() as c:
        pid = tuning.scan(c, "x", insights=INSIGHTS)["created"][0]
    assert admin.post(f"/api/tuning/{pid}/decide", json={"decision": "reject", "note": "no thanks"}, headers=H).status_code == 200
    with connect() as c:
        again = tuning.scan(c, "x", insights=INSIGHTS)
    assert again["created"] == [] and again["skipped"] == 4


def test_scan_on_plain_postgres_says_what_is_missing_and_does_not_fail(admin):
    r = admin.post("/api/tuning/scan", headers=H)
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["created"] == [] and any("query_advisor is not available" in n for n in out["notes"])
    assert any("edb_pg_tuner is not available" in n for n in out["notes"])


def test_slow_query_findings_of_a_monitored_app_become_advice_only(admin):
    with connect_vector() as conn:
        info = simulator.trigger(conn, "slow_query")
        conn.commit()
    r = admin.post("/api/tuning/scan", headers=H)
    assert r.status_code == 200, r.text
    props = admin.get("/api/tuning").json()["proposals"]
    slow = [p for p in props if p["source"] == "slow_query"]
    assert len(slow) == 1 and slow[0]["target"] == "inventory-api" and slow[0]["applicable"] is False
    assert "6823950417" in slow[0]["statement"] and "never changes a monitored system" in slow[0]["rationale"]
    assert info["service"] == "inventory-api"
    pid = slow[0]["id"]
    approve(admin, pid)                                                      # a person may acknowledge it ...
    r = admin.post(f"/api/tuning/{pid}/apply", headers=H)                    # ... but PagerLens will not run it, even with apply on
    assert r.status_code in (403, 409)


def test_advice_is_refused_even_when_apply_is_on(admin, monkeypatch):
    monkeypatch.setenv("PAGERLENS_ALLOW_TUNING_APPLY", "true")
    pid = propose("Review query 6823950417 in inventory-api's database", applicable=False, target="inventory-api", source="slow_query")
    approve(admin, pid)
    r = admin.post(f"/api/tuning/{pid}/apply", headers=H)
    assert r.status_code == 409 and "advice only" in r.json()["detail"]
    assert row(pid)["status"] == "approved" and ("apply_refused", "operator") in actions(pid)


# ---- permissions ----------------------------------------------------------------------------------------

def test_every_tuning_route_is_administrators_only(admin):
    pid = propose("CREATE INDEX ON public.incident (status)")
    read, ingest, full = token(admin, "read"), token(admin, "ingest"), token(admin, "full")
    admin.cookies.clear()
    routes = [("get", "/api/tuning", None), ("get", f"/api/tuning/{pid}", None), ("post", "/api/tuning/scan", {}),
              ("post", f"/api/tuning/{pid}/decide", {"decision": "approve"}), ("post", f"/api/tuning/{pid}/apply", {})]
    for method, path, body in routes:
        kw = {"json": body} if body is not None else {}
        assert getattr(admin, method)(path, headers=H, **kw).status_code == 401, path
        for who in (read, ingest):
            assert getattr(admin, method)(path, headers={**who, **H}, **kw).status_code == 403, (path, "non-admin")
    assert admin.get("/api/tuning", headers=full).status_code == 200


def test_the_database_tab_style_permission_exists_and_only_admin_holds_it():
    assert "tuning:manage" in core.PERMISSIONS
    assert not any("tuning:manage" in p for p in core.ROLE_PERMISSIONS.values() if p != core.ALL)
    assert not any("tuning:manage" in p for p in core.SCOPE_PERMISSIONS.values() if p != core.ALL)


# ---- decisions ------------------------------------------------------------------------------------------

def test_approve_and_reject_record_who_when_and_why(admin):
    a, b = propose("CREATE INDEX ON public.incident (status)"), propose("CREATE INDEX ON public.incident (severity)")
    done = approve(admin, a, "fine with me")
    assert done["status"] == "approved" and done["decided_by"] == "operator" and done["decided_at"] and done["decision_note"] == "fine with me"
    r = admin.post(f"/api/tuning/{b}/decide", json={"decision": "reject", "note": "mail jane@example.com says no"}, headers=H)
    assert r.json()["status"] == "rejected" and "jane@example.com" not in r.json()["decision_note"]
    assert [x[0] for x in actions(a)] == ["approved"] and [x[0] for x in actions(b)] == ["rejected"]
    again = admin.post(f"/api/tuning/{a}/decide", json={"decision": "reject"}, headers=H)
    assert again.status_code == 409 and "approved" in again.json()["detail"]                 # decided once
    assert admin.post("/api/tuning/99999/decide", json={"decision": "approve"}, headers=H).status_code == 404
    assert admin.post(f"/api/tuning/{a}/decide", json={"decision": "maybe"}, headers=H).status_code == 422
    assert admin.get("/api/tuning/99999").status_code == 404


# ---- apply: off by default -----------------------------------------------------------------------------

def test_apply_is_disabled_by_default_and_changes_nothing(admin, demo_table):
    pid = propose("CREATE INDEX CONCURRENTLY IF NOT EXISTS pl_ix_demo_k ON public.tuning_demo (k)")
    approve(admin, pid)
    r = admin.post(f"/api/tuning/{pid}/apply", headers=H)
    assert r.status_code == 403 and "PAGERLENS_ALLOW_TUNING_APPLY" in r.json()["detail"]
    p = row(pid)
    assert p["status"] == "approved" and p["applied_at"] is None and p["before_timing"] is None
    assert not index_exists("pl_ix_demo_k")
    assert actions(pid) == [("approved", "operator"), ("apply_refused", "operator")]
    for v in ("false", "0", ""):
        os.environ["PAGERLENS_ALLOW_TUNING_APPLY"] = v
        try:
            assert admin.post(f"/api/tuning/{pid}/apply", headers=H).status_code == 403
        finally:
            del os.environ["PAGERLENS_ALLOW_TUNING_APPLY"]


def test_only_an_approved_proposal_can_be_applied(admin, monkeypatch):
    monkeypatch.setenv("PAGERLENS_ALLOW_TUNING_APPLY", "true")
    pid = propose("CREATE INDEX ON public.incident (status)")
    r = admin.post(f"/api/tuning/{pid}/apply", headers=H)
    assert r.status_code == 409 and "approved" in r.json()["detail"] and row(pid)["status"] == "proposed"
    rej = propose("CREATE INDEX ON public.incident (severity)", status="rejected")
    assert admin.post(f"/api/tuning/{rej}/apply", headers=H).status_code == 409
    assert admin.post("/api/tuning/99999/apply", headers=H).status_code == 404


# ---- apply: on -----------------------------------------------------------------------------------------

def test_apply_creates_the_index_and_records_an_explain_based_before_and_after(admin, demo_table, monkeypatch):
    monkeypatch.setenv("PAGERLENS_ALLOW_TUNING_APPLY", "true")
    pid = propose("CREATE INDEX CONCURRENTLY IF NOT EXISTS pl_ix_demo_k ON public.tuning_demo (k)")
    approve(admin, pid)
    r = admin.post(f"/api/tuning/{pid}/apply", headers=H)
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["status"] == "applied" and out["applied_by"] == "operator" and out["applied_at"] and out["error"] is None
    assert index_exists("pl_ix_demo_k")
    before, after = out["before_timing"], out["after_timing"]
    assert before["available"] and after["available"] and "estimated cost units, not measured time" in before["method"]
    assert any("Seq Scan" in s for s in before["scans"]) and any("pl_ix_demo_k" in s for s in after["scans"])
    assert after["total_cost"] < before["total_cost"] / 2                      # the plan is far cheaper with the index
    assert [a["action"] for a in out["audit"]] == ["approved", "apply_started", "applied"]
    assert [a["actor"] for a in out["audit"]] == ["operator"] * 3
    with connect() as c:    # nothing was left invalid
        assert c.execute("SELECT indisvalid FROM pg_index WHERE indexrelid = 'public.pl_ix_demo_k'::regclass").fetchone()["indisvalid"]
    assert admin.post(f"/api/tuning/{pid}/apply", headers=H).status_code == 409           # applied once


def test_apply_without_a_known_query_still_applies_and_says_why_there_is_no_before_after(admin, demo_table, monkeypatch):
    monkeypatch.setenv("PAGERLENS_ALLOW_TUNING_APPLY", "true")
    pid = propose("CREATE INDEX IF NOT EXISTS pl_ix_demo_j ON public.tuning_demo (j)", query=None)
    approve(admin, pid)
    out = admin.post(f"/api/tuning/{pid}/apply", headers=H).json()
    assert out["status"] == "applied" and out["before_timing"]["available"] is False and "no motivating statement" in out["before_timing"]["reason"]
    assert index_exists("pl_ix_demo_j")


def test_a_cut_or_unexplainable_query_is_reported_not_fatal(admin, demo_table, monkeypatch):
    monkeypatch.setenv("PAGERLENS_ALLOW_TUNING_APPLY", "true")
    for n, query in enumerate(("SELECT * FROM public.tuning_demo WHERE k = $1 AND (j = ", "DELETE FROM public.tuning_demo", "SELECT 1; DROP TABLE x")):
        pid = propose(f"CREATE INDEX IF NOT EXISTS pl_ix_demo_{n} ON public.tuning_demo (k)", query=query)
        approve(admin, pid)
        out = admin.post(f"/api/tuning/{pid}/apply", headers=H).json()
        assert out["status"] == "applied" and out["before_timing"]["available"] is False and out["before_timing"]["reason"]
    with connect() as c:
        assert c.execute("SELECT count(*) AS n FROM public.tuning_demo").fetchone()["n"] == 30000      # the DELETE was never run


def test_create_statistics_is_applied_and_analyzed(admin, demo_table, monkeypatch):
    monkeypatch.setenv("PAGERLENS_ALLOW_TUNING_APPLY", "true")
    pid = propose("CREATE STATISTICS IF NOT EXISTS pl_st_demo (dependencies) ON k, j FROM public.tuning_demo", query=None)
    approve(admin, pid)
    out = admin.post(f"/api/tuning/{pid}/apply", headers=H).json()
    assert out["status"] == "applied"
    with connect() as c:
        built = c.execute("SELECT d.stxddependencies IS NOT NULL AS built FROM pg_statistic_ext s "
                          "JOIN pg_statistic_ext_data d ON d.stxoid = s.oid WHERE s.stxname = 'pl_st_demo'").fetchone()
    assert built and built["built"]


# ---- apply: the allow-list holds at apply time, whatever is stored --------------------------------------

@pytest.mark.parametrize("statement", [
    "DROP TABLE public.incident", "CREATE INDEX i ON public.incident (status); DROP TABLE public.incident",
    "CREATE INDEX i ON other_schema.t (c)", "CREATE INDEX i ON public.incident (status) -- x", "ALTER SYSTEM SET fsync = off",
    "CREATE INDEX i ON public.incident (status) WHERE true", "CREATE UNIQUE INDEX i ON public.incident (status)",
])
def test_a_tampered_row_is_refused_by_the_allow_list_when_applying(admin, monkeypatch, statement):
    monkeypatch.setenv("PAGERLENS_ALLOW_TUNING_APPLY", "true")
    pid = propose(statement, applicable=True)                    # as if someone edited the row in the database
    approve(admin, pid)
    r = admin.post(f"/api/tuning/{pid}/apply", headers=H)
    assert r.status_code == 422 and "refused by the allow-list" in r.json()["detail"]
    p = row(pid)
    assert p["status"] == "failed" and "allow-list" in p["error"] and ("failed", "operator") in actions(pid)
    with connect() as c:
        assert c.execute("SELECT to_regclass('public.incident') IS NOT NULL AS ok").fetchone()["ok"]
        assert c.execute("SELECT count(*) AS n FROM pg_indexes WHERE indexname = 'i'").fetchone()["n"] == 0


def test_a_missing_table_or_column_is_refused_before_anything_runs(admin, monkeypatch):
    monkeypatch.setenv("PAGERLENS_ALLOW_TUNING_APPLY", "true")
    for stmt in ("CREATE INDEX IF NOT EXISTS pl_x ON public.no_such_table (c)", "CREATE INDEX IF NOT EXISTS pl_y ON public.incident (no_such_column)",
                 "CREATE INDEX IF NOT EXISTS pl_z ON public.pg_class (relname)"):
        pid = propose(stmt)
        approve(admin, pid)
        r = admin.post(f"/api/tuning/{pid}/apply", headers=H)
        assert r.status_code == 422, (stmt, r.text)
        assert row(pid)["status"] == "failed"


def test_a_database_error_is_recorded_on_the_proposal(admin, demo_table, monkeypatch):
    monkeypatch.setenv("PAGERLENS_ALLOW_TUNING_APPLY", "true")
    pid = propose("CREATE INDEX tuning_demo ON public.tuning_demo (k)")           # the name is taken by the table itself
    approve(admin, pid)
    r = admin.post(f"/api/tuning/{pid}/apply", headers=H)
    assert r.status_code == 200
    p = r.json()
    assert p["status"] == "failed" and "already exists" in p["error"] and p["applied_at"] is None
    assert [a["action"] for a in p["audit"]] == ["approved", "apply_started", "failed"]


def test_a_lock_that_cannot_be_had_times_out_instead_of_hanging(admin, demo_table, monkeypatch):
    monkeypatch.setenv("PAGERLENS_ALLOW_TUNING_APPLY", "true")
    monkeypatch.setenv("PAGERLENS_TUNING_LOCK_TIMEOUT_SECONDS", "1")
    pid = propose("CREATE INDEX IF NOT EXISTS pl_ix_locked ON public.tuning_demo (k)", query=None)
    approve(admin, pid)
    blocker = connect()
    try:
        blocker.execute("LOCK TABLE public.tuning_demo IN ACCESS EXCLUSIVE MODE")      # someone else holds the table
        out = admin.post(f"/api/tuning/{pid}/apply", headers=H).json()
    finally:
        blocker.rollback()
        blocker.close()
    assert out["status"] == "failed" and "lock timeout" in out["error"].lower()
    assert not index_exists("pl_ix_locked")


def test_a_statement_that_runs_too_long_is_cancelled_by_the_statement_timeout(admin, demo_table, monkeypatch):
    from psycopg import sql

    monkeypatch.setenv("PAGERLENS_ALLOW_TUNING_APPLY", "true")
    monkeypatch.setenv("PAGERLENS_TUNING_STATEMENT_TIMEOUT_SECONDS", "1")
    # stand in for a build that takes too long: whatever is executed here runs under the timeout the apply session sets
    monkeypatch.setattr(tuning.Parsed, "composed", lambda self: sql.SQL("SELECT pg_sleep(30)"))
    pid = propose("CREATE INDEX IF NOT EXISTS pl_ix_timeout ON public.tuning_demo (k)", query=None)
    approve(admin, pid)
    out = admin.post(f"/api/tuning/{pid}/apply", headers=H).json()
    assert out["status"] == "failed" and "statement timeout" in out["error"].lower()
    assert [a["action"] for a in out["audit"]] == ["approved", "apply_started", "failed"]


def test_one_apply_at_a_time(admin, demo_table, monkeypatch):
    monkeypatch.setenv("PAGERLENS_ALLOW_TUNING_APPLY", "true")
    pid = propose("CREATE INDEX IF NOT EXISTS pl_ix_busy ON public.tuning_demo (k)")
    approve(admin, pid)
    other = connect()
    try:
        assert other.execute("SELECT pg_try_advisory_lock(%s) AS ok", (tuning.LOCK_KEY,)).fetchone()["ok"]
        r = admin.post(f"/api/tuning/{pid}/apply", headers=H)
    finally:
        other.execute("SELECT pg_advisory_unlock(%s)", (tuning.LOCK_KEY,))
        other.close()
    assert r.status_code == 409 and "another change is being applied" in r.json()["detail"]
    assert row(pid)["status"] == "approved" and not index_exists("pl_ix_busy")
    assert admin.post(f"/api/tuning/{pid}/apply", headers=H).status_code == 200            # and it works once the lock is free


def test_apply_only_ever_connects_to_the_configured_database(admin, demo_table, monkeypatch):
    """There is no way to name another database: the statement grammar has no database part and apply() takes only the id and the actor."""
    import inspect

    assert list(inspect.signature(tuning.apply).parameters) == ["proposal_id", "actor"]
    for text in ("CREATE INDEX i ON otherdb.public.t (c)", "CREATE INDEX i ON public.t (c) \\c otherdb"):
        assert tuning.is_applicable(text) is False
    monkeypatch.setenv("PAGERLENS_ALLOW_TUNING_APPLY", "true")
    pid = propose("CREATE INDEX IF NOT EXISTS pl_ix_here ON public.tuning_demo (k)", query=None)
    approve(admin, pid)
    assert admin.post(f"/api/tuning/{pid}/apply", headers=H).json()["status"] == "applied"
    with connect() as c:
        assert c.execute("SELECT current_database() AS d").fetchone()["d"] == os.environ["TEST_DATABASE_URL"].rsplit("/", 1)[1]
        assert c.execute("SELECT to_regclass('public.pl_ix_here') IS NOT NULL AS ok").fetchone()["ok"]


# ---- the job -------------------------------------------------------------------------------------------

def test_the_scheduled_scan_is_off_at_zero_and_runs_once_per_interval(admin):
    with connect() as c:
        assert tuning.scan_if_due(c, 0) is None
        first = tuning.scan_if_due(c, 60)
        assert first is not None and "created" in first
        assert tuning.scan_if_due(c, 60) is None                  # not due yet
        c.rollback()
    with connect() as c:
        assert [a["actor"] for a in c.execute("SELECT actor FROM tuning_audit WHERE action='scan'").fetchall()] == ["scheduled job"]


def test_proposals_are_json_clean_for_the_ui(admin):
    pid = propose("CREATE INDEX ON public.incident (status)")
    approve(admin, pid)
    body = admin.get("/api/tuning").json()
    json.dumps(body)
    assert body["proposals"][0]["id"] == pid and "note" in body and body["statement_timeout_seconds"] == 60
