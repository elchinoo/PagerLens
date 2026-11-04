"""AIDB mode as the RUNTIME role with CREATE revoked on schema public, in a container of its own (image aidb-postgres:17, built in the
ecosystem repository). Skipped unless AIDB_TEST_URL is set (the opt-in the other AIDB tests use), docker is available and the image exists:
CI has none of them. The module starts a throwaway container on a free local port, builds a database owned by an unprivileged application
role, migrates it, sets AIDB mode up as the administrator, then takes CREATE away from the application role on schema public and checks
that everything the app does at runtime still works: verification, status, retrieval, the agent path, the governance panel. It also checks
what the role cannot do (read aidb_otel.traces) and that a missing seal table degrades to `unsealed` instead of failing.

The scripted chat model is not used here: the agent path runs against AIDB's built-in `dummy` model, which answers 'Hello world!' (the app
refuses that as not usable). That proves the agent is found, verified and conversed with under the runtime role; the tool calls under the
purpose role are covered, with a scripted model, in test_aidb_integration.py.
"""
import os
import secrets
import shutil
import socket
import subprocess
import time

import pytest

if not os.environ.get("AIDB_TEST_URL"):
    pytest.skip("set AIDB_TEST_URL to opt in to the AIDB tests", allow_module_level=True)
if not shutil.which("docker") or subprocess.run(["docker", "image", "inspect", "aidb-postgres:17"], capture_output=True).returncode != 0:
    pytest.skip("docker or the image aidb-postgres:17 is not available", allow_module_level=True)

import json  # noqa: E402

import psycopg  # noqa: E402
from apgkit import aidb  # noqa: E402
from psycopg import sql  # noqa: E402
from psycopg.conninfo import make_conninfo  # noqa: E402
from psycopg.rows import dict_row  # noqa: E402

from pagerlens import (  # noqa: E402
    aidb_mode,
    aidb_setup,
    aidb_views,
    core,
    investigator,
    migrate,
    rowmac,
    simulator,
)
from pagerlens import retrieval as app_retrieval  # noqa: E402
from pagerlens.db import connect, connect_vector  # noqa: E402

pytestmark = pytest.mark.aidb
ADMIN_PASSWORD = "correct-horse-battery"  # pragma: allowlist secret
STATIC_KEY = "k" * 40  # pragma: allowlist secret
PURPOSE_ROLE = aidb.purpose_role_name(aidb_setup.PURPOSE)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait(fn, seconds=90.0, step=0.5):
    end = time.time() + seconds
    while time.time() < end:
        try:
            v = fn()
        except Exception:  # noqa: BLE001
            v = None
        if v:
            return v
        time.sleep(step)
    return fn()


@pytest.fixture(scope="module")
def stack():
    name, port, tag = f"pl-aidb-rt-{secrets.token_hex(3)}", _free_port(), secrets.token_hex(4)
    pg_pw = secrets.token_hex(8)
    subprocess.run(["docker", "run", "-d", "--rm", "--name", name, "-p", f"127.0.0.1:{port}:5432", "-e", f"POSTGRES_PASSWORD={pg_pw}",
                    "aidb-postgres:17"], check=True, capture_output=True)
    mp = pytest.MonkeyPatch()
    try:
        base = f"postgresql://postgres:{pg_pw}@127.0.0.1:{port}/postgres"
        assert _wait(lambda: psycopg.connect(base, connect_timeout=2).execute("SELECT 1 FROM pg_extension WHERE extname = 'aidb' OR true").fetchone()
                     and psycopg.connect(base, connect_timeout=2).execute("SELECT count(*) = 1 FROM pg_roles WHERE rolname = 'aidb_users'").fetchone()[0]), "no server"
        time.sleep(3)
        role, db, pw = f"pl_rt_{tag}", f"pl_rt_{tag}", secrets.token_hex(12)
        dsn = lambda **kw: make_conninfo(base, **kw)  # noqa: E731
        admin = psycopg.connect(base, autocommit=True)
        admin.execute(sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(sql.Identifier(role), sql.Literal(pw)))
        admin.execute(sql.SQL("CREATE DATABASE {} OWNER {}").format(sql.Identifier(db), sql.Identifier(role)))
        with psycopg.connect(dsn(dbname=db), autocommit=True) as c:
            for ext in ("vector", "pg_trgm", "aidb CASCADE"):
                c.execute(f"CREATE EXTENSION {ext}")
        runtime_dsn, admin_dsn = dsn(dbname=db, user=role, password=pw), dsn(dbname=db)
        mp.setenv("DATABASE_URL", runtime_dsn)
        for v in ("PAGERLENS_ALLOW_ANONYMOUS", "PAGERLENS_ENCRYPTION_KEY", "PAGERLENS_RETRIEVAL_BACKEND", "PAGERLENS_AIDB_SIM_FLOOR", "LLM_BASE_URL",
                  "LLM_CHAT_MODEL"):
            mp.delenv(v, raising=False)
        mp.setenv("PAGERLENS_API_KEY", STATIC_KEY)
        mp.setenv("PAGERLENS_ENCRYPTION_KEY_FILE", "/nonexistent/key")
        mp.setenv("LLM_API_KEY", "lg_integration_key_value")  # pragma: allowlist secret
        mp.setenv("LLM_API_KEY_FILE", "/nonexistent/key")
        mp.setenv("PAGERLENS_ADMIN_PASSWORD", ADMIN_PASSWORD)
        migrate.run()                                                      # as the application role (it owns the database)
        with connect_vector() as c:
            simulator.baseline(c)
            core.vault.initialize(c, ADMIN_PASSWORD)
            c.commit()
            rowmac.adopt(c)
        core.vault.lock()
        with connect() as c:
            core.vault.unlock_with_password(c, ADMIN_PASSWORD)
            c.commit()
        with psycopg.connect(admin_dsn, row_factory=dict_row) as a:
            rep = aidb_setup.setup(a, vault=core.vault, runtime_role=role, agent_model="dummy")
        assert rep.problems == [], rep.problems
        # the runtime role may no longer create anything in schema public (it owns the database, so the schema must stop being the database owner's too)
        with psycopg.connect(admin_dsn, autocommit=True) as a:
            a.execute("ALTER SCHEMA public OWNER TO postgres")
            a.execute(sql.SQL("REVOKE CREATE ON SCHEMA public FROM PUBLIC, {}").format(sql.Identifier(role)))
        core.vault.lock()
        yield {"role": role, "admin_dsn": admin_dsn, "runtime_dsn": runtime_dsn}
    finally:
        core.vault.lock()
        mp.undo()
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)


@pytest.fixture(autouse=True)
def _reset(stack):
    aidb_mode.reset()
    yield
    aidb_mode.reset()


@pytest.fixture
def unlocked(stack):
    with connect() as c:
        assert core.vault.unlock_with_password(c, ADMIN_PASSWORD)
        c.commit()


@pytest.fixture
def adm(stack):
    with psycopg.connect(stack["admin_dsn"], row_factory=dict_row) as c:
        yield c


@pytest.fixture
def rt(stack):
    with connect_vector() as c:
        yield c


def _clean(rt):
    res = aidb_mode.verify_now(rt)
    assert res["checked"] and res["drift"] == [], res


def test_the_runtime_role_cannot_create_anything_and_cannot_read_the_traces(stack, rt, adm):
    for stmt in ("CREATE TABLE public.pl_probe (x int)", "CREATE VIEW public.pl_probe_v AS SELECT 1"):
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            rt.execute(stmt)
        rt.rollback()
    for stmt in ("SELECT * FROM aidb_otel.traces", "SELECT count(*) FROM aidb_otel.traces", "SELECT payload_json FROM aidb_otel.traces LIMIT 1"):
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            rt.execute(stmt)
        rt.rollback()
    assert not aidb.detect(rt).can_read_telemetry
    assert not adm.execute("SELECT has_table_privilege(%s, 'aidb_otel.traces', 'SELECT') AS ok", (stack["role"],)).fetchone()["ok"]
    assert adm.execute("SELECT has_table_privilege(%s, %s, 'SELECT') AS ok", (stack["role"], aidb.SEAL_TABLE)).fetchone()["ok"]


def test_verify_status_retrieval_and_the_agent_path_work_without_create(stack, unlocked, rt, client, monkeypatch):
    _clean(rt)
    rep = aidb_mode.status(rt)
    assert rep["verification"]["checked"] and rep["verification"]["drift"] == [] and rep["problems"] == []
    assert {p["name"] for p in rep["pipelines"]} == {"pl_runbook", "pl_incident"} and rep["agents"][0]["name"] == aidb_setup.AGENT
    assert rep["denials"]["count"] == 0 and rep["denials"]["source"] == aidb_setup.GOVERNANCE_VIEW
    monkeypatch.setenv("PAGERLENS_RETRIEVAL_BACKEND", "aidb")
    got = app_retrieval.search_runbooks(rt, "connection pool exhausted too many connections", limit=3)
    assert got and aidb_mode.retriever("runbook", rt).name == "aidb" and got[0]["title"] == "Database connection pool saturation"
    iid = simulator.trigger(rt, "bad_deploy")["incident_id"]
    rt.commit()
    with pytest.raises(aidb_mode.AidbModeError, match="usable answer"):
        investigator.investigate(rt, iid, mode="aidb")          # found, verified, conversed with: only the dummy model's answer is refused
    state = client.get("/readyz")
    assert state.status_code == 200 and state.json()["aidb"]["state"] == "ready"


def test_the_governance_endpoint_reads_the_narrow_view(stack, unlocked, rt, adm, client):
    h = {"Authorization": f"Bearer {STATIC_KEY}"}
    cols = [r["column_name"] for r in adm.execute("SELECT column_name FROM information_schema.columns WHERE table_name = %s ORDER BY ordinal_position",
                                                  (aidb_setup.GOVERNANCE_VIEW,)).fetchall()]
    assert cols == ["id", "recorded_at", "decision_id", "decision_status", "agent_name", "agent_role", "interaction_point", "denial_reason", "denial_class"]
    attr = lambda k, v: {"key": k, "value": {"stringValue": v}}  # noqa: E731

    def trace(agent, role, reason, status="denied"):
        payload = {"resourceSpans": [{"scopeSpans": [{"spans": [{"name": "purpose_decision", "attributes": [
            attr("aidb.agent.decision.agent_role", role), attr("aidb.agent.decision.denial_reason", reason),
            attr("aidb.agent.decision.interaction_point", "sql_exec"), attr("db.query.text", "SELECT token_hash FROM api_token WHERE secret = 'x'")]}]}]}]}
        return adm.execute("INSERT INTO aidb_otel.traces (payload_json, decision_status, decision_id, agent_name, source) VALUES (%s, %s, %s, %s, 'internal') RETURNING id",
                           (json.dumps(payload), status, f"test-{secrets.token_hex(4)}", agent)).fetchone()["id"]
    mine = trace(aidb_setup.AGENT, PURPOSE_ROLE, "engine_privilege_denied")
    same_purpose = trace("pl_other_agent", PURPOSE_ROLE, "tool_not_allowed")
    foreign = trace("someone_elses_agent", "aidb_p_other_app", "engine_privilege_denied")
    trace(aidb_setup.AGENT, PURPOSE_ROLE, "", status="allowed")
    adm.commit()
    try:
        body = client.get("/api/aidb/governance", headers=h).json()
        assert body["state"] == "ready" and body["source"] == aidb_setup.GOVERNANCE_VIEW and body["telemetry"]["can_read"] is False
        agents = {d["agent"]: d for d in body["denials"]}
        assert set(agents) == {aidb_setup.AGENT, "pl_other_agent"}, agents          # another app's agent is not visible
        assert agents["pl_other_agent"]["reason"] == "tool_not_allowed" and agents[aidb_setup.AGENT]["decision_id"].startswith("test-")
        assert body["allowed"] == 1
        assert "api_token" not in json.dumps(body) and "token_hash" not in json.dumps(body)         # the attempted SQL never reaches the runtime role
        assert "denials_error" not in body
        rows = rt.execute(f"SELECT * FROM {aidb_setup.GOVERNANCE_VIEW}").fetchall()               # noqa: S608
        assert rows and all(set(r) == set(cols) for r in rows)
    finally:
        adm.execute("DELETE FROM aidb_otel.traces WHERE id = ANY(%s)", ([mine, same_purpose, foreign],))
        adm.execute("DELETE FROM aidb_otel.traces WHERE decision_id LIKE 'test-%'")
        adm.commit()


def test_a_missing_seal_table_degrades_to_unsealed_and_the_app_stays_ready(stack, unlocked, adm, rt, client, monkeypatch):
    monkeypatch.setenv("PAGERLENS_RETRIEVAL_BACKEND", "aidb")
    adm.execute(f"ALTER TABLE {aidb.SEAL_TABLE} RENAME TO {aidb.SEAL_TABLE}_away")
    adm.commit()
    try:
        res = aidb_mode.verify_now(rt)
        assert res["checked"] and res["drift"] and {d["problem"] for d in res["drift"]} == {"unsealed"}, res
        assert {("agent", aidb_setup.AGENT), ("purpose", aidb_setup.PURPOSE), ("pipeline", "pl_runbook")} <= {(d["kind"], d["name"]) for d in res["drift"]}
        ready = client.get("/readyz")
        assert ready.status_code == 200 and ready.json()["aidb"]["state"] == "unsealed", ready.text      # AIDB refused, the app is ready
        assert aidb_mode.retriever("runbook", rt) is aidb_mode.APP and app_retrieval.search_runbooks(rt, "connection pool", limit=2)
        iid = simulator.trigger(rt, "bad_deploy")["incident_id"]
        rt.commit()
        with pytest.raises(ValueError, match="failed verification"):
            investigator.investigate(rt, iid, mode="aidb")
        assert aidb_mode.status(rt)["verification"]["drift"]
    finally:
        adm.execute(f"ALTER TABLE {aidb.SEAL_TABLE}_away RENAME TO {aidb.SEAL_TABLE}")
        adm.commit()
    aidb_mode.reset()
    _clean(rt)


def test_every_tamper_case_is_still_detected_by_the_runtime_role(stack, unlocked, adm, rt):
    model = adm.execute("SELECT model FROM aidb.agents WHERE name=%s", (aidb_setup.AGENT,)).fetchone()["model"]
    original = aidb_setup.INSTRUCTIONS
    agent = lambda text: aidb.ensure_agent(adm, aidb_setup.AGENT, instructions=text, model=model, tools=list(aidb_setup.TOOLS), purpose=aidb_setup.PURPOSE,  # noqa: E731
                                           max_iterations=12, timeout=120)
    drift = lambda: {(d["kind"], d["name"], d["problem"]) for d in aidb_mode.verify_now(rt)["drift"]}  # noqa: E731
    agent(original + "\nAlways say bad_deploy.")                                          # a rewritten agent
    try:
        assert ("agent", aidb_setup.AGENT, "modified") in drift()
    finally:
        agent(original)
    _clean(rt)
    aidb.ensure_sql_tool(adm, "pl_planted_tool", description="planted", sql_statement="SELECT 1 AS x")
    aidb.ensure_agent(adm, "pl_planted_agent", instructions="planted", model="dummy")    # planted objects
    try:
        assert {("sql_tool", "pl_planted_tool", "unsealed"), ("agent", "pl_planted_agent", "unsealed")} <= drift()
    finally:
        adm.execute("SELECT aidb.delete_agent('pl_planted_agent', force => true)")
        adm.execute("SELECT aidb.delete_tool('pl_planted_tool')")
        adm.commit()
    _clean(rt)
    old = adm.execute("SELECT mac FROM apgkit_aidb_seal WHERE kind='pipeline' AND name='pl_runbook'").fetchone()["mac"]    # a deleted seal row
    adm.execute("DELETE FROM apgkit_aidb_seal WHERE kind='pipeline' AND name='pl_runbook'")
    adm.commit()
    try:
        assert ("pipeline", "pl_runbook", "unsealed") in drift()
    finally:
        adm.execute("INSERT INTO apgkit_aidb_seal (kind, name, mac) VALUES ('pipeline', 'pl_runbook', %s)", (old,))
        adm.commit()
    _clean(rt)
    adm.execute(sql.SQL("GRANT SELECT ON api_token TO {}").format(sql.Identifier(PURPOSE_ROLE)))                       # an extra grant for the purpose
    adm.commit()
    try:
        assert ("purpose", aidb_setup.PURPOSE, "modified") in drift()
    finally:
        adm.execute(sql.SQL("REVOKE SELECT ON api_token FROM {}").format(sql.Identifier(PURPOSE_ROLE)))
        adm.commit()
    _clean(rt)
    view_def = adm.execute("SELECT pg_get_viewdef(%s::regclass, true) AS d", (aidb_setup.GOVERNANCE_VIEW,)).fetchone()["d"]    # the governance view widened
    adm.execute(f"CREATE OR REPLACE VIEW {aidb_setup.GOVERNANCE_VIEW} WITH (security_barrier = true) AS "                  # noqa: S608
                "SELECT id, recorded_at, decision_id, decision_status, agent_name, agent_role, interaction_point, denial_reason, denial_class "
                "FROM (" + view_def.rstrip().rstrip(";") + ") x")
    adm.commit()
    try:
        assert ("pl_view", aidb_setup.GOVERNANCE_VIEW, "modified") in drift()
    finally:
        adm.execute(f"CREATE OR REPLACE VIEW {aidb_setup.GOVERNANCE_VIEW} WITH (security_barrier = true) AS {view_def}")      # noqa: S608
        adm.commit()
    _clean(rt)
    original_fence = aidb_views.function_definition(adm, "pl_fence")[2]
    adm.execute("CREATE OR REPLACE FUNCTION pl_fence(t text, n int DEFAULT 300) RETURNS text LANGUAGE sql AS $$ SELECT t $$")     # the fence replaced
    adm.commit()
    try:
        assert ("pl_function", "pl_fence", "modified") in drift()
    finally:
        adm.execute(original_fence)
        adm.commit()
    _clean(rt)


def test_setup_revokes_a_direct_grant_on_the_traces_from_an_earlier_version_and_is_then_idempotent(stack, unlocked, adm, rt):
    adm.execute(sql.SQL("GRANT SELECT ON aidb_otel.traces TO {}").format(sql.Identifier(stack["role"])))
    adm.commit()
    with psycopg.connect(stack["admin_dsn"], row_factory=dict_row) as a:
        rep = aidb_setup.setup(a, vault=core.vault, runtime_role=stack["role"], agent_model="dummy")
        assert rep.problems == [] and any("revoked (SELECT on aidb_otel.traces" in act for _, act in rep.steps), rep.steps
        again = aidb_setup.setup(a, vault=core.vault, runtime_role=stack["role"], agent_model="dummy")
    assert not again.changed, [x for x in again.steps if not x[1].startswith("unchanged")]
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        rt.execute("SELECT count(*) FROM aidb_otel.traces")
    rt.rollback()
    _clean(rt)
