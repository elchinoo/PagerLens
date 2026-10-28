"""Database insights (EDB extensions, degrading on plain Postgres) and read-only/AI hardening with real roles, against a disposable Postgres."""
import os

import pytest

if not os.environ.get("TEST_DATABASE_URL"):
    pytest.skip("set TEST_DATABASE_URL to run DB tests", allow_module_level=True)

import psycopg  # noqa: E402
from psycopg.conninfo import make_conninfo  # noqa: E402
from psycopg.rows import dict_row  # noqa: E402

from pagerlens import auth, core, hardening, migrate, simulator, vault  # noqa: E402
from pagerlens.db import connect  # noqa: E402

H = {"X-PagerLens-CSRF": "1"}
PASSWORD = "correct-horse-battery"  # pragma: allowlist secret
LOGIN = "pl_ro_login"
SECRET_TABLES = hardening.DENIED


@pytest.fixture(autouse=True)
def _db(monkeypatch, client):
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    for v in ("PAGERLENS_API_KEY", "PAGERLENS_ALLOW_ANONYMOUS", "PAGERLENS_ENCRYPTION_KEY"):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setenv("PAGERLENS_API_KEY_FILE", "/nonexistent/key")
    monkeypatch.setenv("PAGERLENS_ENCRYPTION_KEY_FILE", "/nonexistent/key")
    core.auth.limiter.clear()
    core.local._setup_code = None
    vault.lock()
    client.cookies.clear()
    _reset()
    migrate.run()


def _reset(drop_roles: bool = True):
    with connect() as c:
        c.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public")
        if drop_roles:
            c.execute(f"DROP ROLE IF EXISTS {LOGIN}")
            c.execute("DROP ROLE IF EXISTS a1p_readonly")
        c.commit()


@pytest.fixture
def admin(client):
    with connect() as c:
        auth.set_admin_password(c, PASSWORD)
    assert client.post("/api/login", json={"password": PASSWORD}, headers=H).status_code == 200
    return client


def token(admin, scope):
    return {"Authorization": "Bearer " + admin.post("/api/tokens", json={"name": scope, "scope": scope}, headers=H).json()["token"]}


# ---- database insights ---------------------------------------------------------------------------------

def test_insights_needs_the_admin_permission(admin):
    read, ingest = token(admin, "read"), token(admin, "ingest")
    admin.cookies.clear()
    assert admin.get("/api/insights").status_code == 401
    assert admin.get("/api/insights", headers=read).status_code == 403          # statement text reveals the workload
    assert admin.get("/api/insights", headers=ingest).status_code == 403
    assert admin.get("/api/insights", headers=token_full(admin)).status_code == 200


def token_full(admin):
    with connect() as c:
        auth.set_admin_password(c, PASSWORD)
    admin.post("/api/login", json={"password": PASSWORD}, headers=H)
    t = token(admin, "full")
    admin.cookies.clear()
    return t


def test_insights_degrade_on_plain_postgres_without_error(admin):
    r = admin.get("/api/insights?order=mean&limit=5")
    assert r.status_code == 200
    body = r.json()
    assert set(body) == {"sources", "top_queries", "tuner", "advisor"}
    for src in ("edb_stat_monitor", "edb_pg_tuner", "query_advisor"):          # the edb_* extensions are not on a plain Postgres
        assert body["sources"][src]["available"] is False
    for part in ("tuner", "advisor"):
        assert body[part]["available"] is False and body[part]["reason"]
    assert body["top_queries"]["available"] in (True, False)                    # pg_stat_statements may or may not be loaded
    assert admin.get("/api/insights?order=nonsense").status_code == 200        # an unknown order falls back instead of failing
    assert admin.get("/api/insights?limit=0").status_code == 422


def test_metrics_scrape_carries_the_insights_gauges_and_never_fails(admin):
    tok = token(admin, "metrics")
    admin.cookies.clear()
    r = admin.get("/metrics", headers=tok)
    assert r.status_code == 200
    assert 'db_insights_available{app="pagerlens"}' in r.text
    assert "db_up" in r.text and "pagerlens_open_incidents" in r.text


# ---- read-only / AI hardening ---------------------------------------------------------------------------------

@pytest.fixture
def roles():
    """AgentPG's group role, a login member of it, and the default privilege AgentPG sets (SELECT on every new table)."""
    with connect() as c:
        c.execute("CREATE ROLE a1p_readonly NOLOGIN")
        c.execute(f"CREATE ROLE {LOGIN} LOGIN PASSWORD 'ro-pw-test' IN ROLE a1p_readonly")
        c.commit()
    _reset(drop_roles=False)
    with connect() as c:
        c.execute("GRANT USAGE ON SCHEMA public TO a1p_readonly")
        c.execute("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO a1p_readonly")
        c.commit()
    migrate.run()                 # as the platform does: the tables exist, the role can read them all, and the hook runs
    yield
    _reset()


def ro():
    return psycopg.connect(make_conninfo(os.environ["TEST_DATABASE_URL"], user=LOGIN, password="ro-pw-test"), row_factory=dict_row, autocommit=True)


def test_without_the_read_only_role_hardening_skips_quietly(admin):
    with connect() as c:
        assert hardening.apply(c) == {"masked": {}, "denied": {}}
        views = c.execute("SELECT count(*) AS n FROM pg_views WHERE schemaname='public' AND viewname LIKE '%\\_masked'").fetchone()["n"]
    assert views == 0
    assert migrate.run() == []    # and a second migrate is a no-op


def test_secrets_are_not_readable_by_the_read_only_role_and_have_no_view(roles):
    with ro() as r:
        for table in SECRET_TABLES:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                r.execute(f"SELECT * FROM {table}")                                   # noqa: S608 - fixed names
            assert r.execute("SELECT to_regclass(%s) AS v", (f"{table}_masked",)).fetchone()["v"] is None
    with connect() as c:      # the application itself (the owner) still reads them
        for table in SECRET_TABLES:
            c.execute(f"SELECT count(*) FROM {table}")                                # noqa: S608


def test_personal_data_is_masked_and_telemetry_stays_readable(roles):
    secret_key = "sk-" + "A1b2C3d4E5f6G7h8I9j0"  # pragma: allowlist secret
    with connect() as c:
        simulator.baseline(c)
        sid = c.execute("SELECT id FROM service WHERE name='checkout-api'").fetchone()["id"]
        iid = c.execute("INSERT INTO incident (service_id, service_name, title, severity, fingerprint, symptom, root_cause_note) "
                        "VALUES (%s,'checkout-api','Login failed for jane.doe@example.com','sev2','fp','card for bob@example.org failed','called jane.doe@example.com') "
                        "RETURNING id", (sid,)).fetchone()["id"]
        c.execute("INSERT INTO incident_note (incident_id, author, body) VALUES (%s,'Jane Doe',%s)", (iid, f"token {secret_key} leaked, mail jane.doe@example.com"))
        c.execute("INSERT INTO alert (service_id, incident_id, source, name, summary, labels) VALUES (%s,%s,'webhook','Alert for x@y.io','mail x@y.io', %s::jsonb)",
                  (sid, iid, '{"user": "x@y.io", "region": "eu"}'))
        c.execute("INSERT INTO deploy (service_id, version, author, summary, deployed_at) VALUES (%s,'v9','Jane Doe','by jane.doe@example.com', now())", (sid,))
        c.commit()
    with ro() as r:
        for base in ("incident", "incident_note", "alert", "deploy", "service", "log_event"):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                r.execute(f"SELECT * FROM {base}")                                    # noqa: S608
        inc = r.execute("SELECT * FROM incident_masked WHERE id=%s", (iid,)).fetchone()
        assert "embedding" not in inc
        assert inc["severity"] == "sev2" and inc["service_name"] == "checkout-api" and inc["status"] == "open"     # operational: readable
        assert "example.com" not in inc["title"] + inc["symptom"] + inc["root_cause_note"] and "[EMAIL]" in inc["title"]
        note = r.execute("SELECT * FROM incident_note_masked").fetchone()
        assert note["author"] == "J***" and secret_key not in note["body"] and "jane.doe" not in note["body"] and "[REDACTED-KEY]" in note["body"]
        alert = r.execute("SELECT * FROM alert_masked").fetchone()
        assert "x@y.io" not in alert["name"] + alert["summary"] and alert["labels"] == {"user": "[EMAIL]", "region": "eu"}
        dep = r.execute("SELECT * FROM deploy_masked WHERE version='v9'").fetchone()
        assert dep["author"] == "J***" and "jane.doe" not in dep["summary"] and dep["version"] == "v9"
        assert r.execute("SELECT count(*) AS n FROM log_event_masked").fetchone()["n"] > 0
        assert r.execute("SELECT count(*) AS n FROM service_masked").fetchone()["n"] == 5
        # tables with no personal data stay directly readable, so an AI assistant can still investigate the telemetry
        assert r.execute("SELECT count(*) AS n FROM metric_point").fetchone()["n"] > 0
        assert r.execute("SELECT count(*) AS n FROM runbook").fetchone()["n"] > 0
        for ddl in ("DELETE FROM incident_masked", "UPDATE incident_masked SET severity='x'", "DROP TABLE metric_point"):
            with pytest.raises(psycopg.Error):
                r.execute(ddl)


def test_hardening_is_idempotent_and_survives_the_next_migration(roles):
    with connect() as c:
        first = hardening.apply(c)
        second = hardening.apply(c)
    assert first == second and all(v["applied"] for v in first["masked"].values()) and all(v["applied"] for v in first["denied"].values())
    # a table created later gets SELECT from the default privileges again; the next migrate/start puts the secrets back behind the wall
    with connect() as c:
        c.execute("GRANT SELECT ON api_token, app_setting TO a1p_readonly")
        c.commit()
    with ro() as r:
        assert r.execute("SELECT count(*) AS n FROM api_token").fetchone()["n"] == 0        # leaked by the re-grant
    migrate.run()
    with ro() as r, pytest.raises(psycopg.errors.InsufficientPrivilege):
        r.execute("SELECT * FROM api_token")


def test_simulator_answer_key_is_hidden_from_the_read_only_role(roles):
    with connect() as c:
        simulator.trigger(c, "bad_deploy")
        c.commit()
    with ro() as r, pytest.raises(psycopg.errors.InsufficientPrivilege):
        r.execute("SELECT scenario FROM sim_truth")


def test_tuning_proposals_are_masked_for_the_read_only_role(roles):
    with connect() as c:
        pid = c.execute("INSERT INTO tuning_proposal (source, statement, applicable, rationale, status, decided_by, decision_note) "
                        "VALUES ('advisor','CREATE INDEX ON public.incident (status)', true, 'seen for jane.doe@example.com', 'approved', 'Jane Doe', "
                        "'mail jane.doe@example.com') RETURNING id").fetchone()["id"]
        c.execute("INSERT INTO tuning_audit (proposal_id, action, actor, detail) VALUES (%s,'approved','Jane Doe','by jane.doe@example.com')", (pid,))
        c.commit()
    with ro() as r:
        for base in ("tuning_proposal", "tuning_audit"):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                r.execute(f"SELECT * FROM {base}")                                    # noqa: S608 - fixed names
        p = r.execute("SELECT * FROM tuning_proposal_masked WHERE id=%s", (pid,)).fetchone()
        assert p["decided_by"] == "J***" and "jane.doe" not in p["rationale"] + p["decision_note"] and p["status"] == "approved"
        assert p["statement"] == "CREATE INDEX ON public.incident (status)"
        a = r.execute("SELECT * FROM tuning_audit_masked WHERE proposal_id=%s", (pid,)).fetchone()
        assert a["actor"] == "J***" and "jane.doe" not in a["detail"] and a["action"] == "approved"
