"""The evidence views an AIDB agent may read (and nothing else).

The AIDB investigator runs its tools as a purpose role that holds SELECT on exactly these views and on no table: "PagerLens never
changes your systems" is then a grant boundary Postgres enforces, not a promise of the Python loop. A view runs with its owner's rights,
so the role needs nothing on the base tables, and the views choose what is exposed:

- the same masking the read-only role gets (`hardening.scrub_expr`: e-mail addresses, key-like strings and JWTs inside free text are
  redacted, author names become an initial);
- free text from monitored systems arrives already fenced as `<untrusted_data>` and truncated (`pl_fence`, migration 008);
- every row carries an `evidence_id` such as `deploy:12`. The app accepts a citation only if that id exists in these views for the
  incident's window (`aidb_mode.verify_citations`);
- nothing about secrets, sessions, tokens, provider accounts, the simulator's answer key, root causes of incidents, tuning, or the
  runbook and incident memory tables.

`install` creates or replaces them on every start (idempotent). `definition_fingerprint` is what the operator's seal covers.
"""
import logging

from .hardening import scrub_expr

log = logging.getLogger("pagerlens.aidb")


def _ft(column: str, n: int = 300) -> str:
    """Scrubbed, truncated, fenced free text."""
    return f"pl_fence({scrub_expr(column)}, {n})"


_SVC = "(SELECT s.name FROM service s WHERE s.id = {t}.service_id)"

# view name -> SQL body (without CREATE VIEW). Columns are the contract of the tools in aidb_setup.TOOLS.
VIEWS: dict[str, str] = {
    "pl_ev_services": f"""
        SELECT 'service:' || s.name AS evidence_id, s.name AS service, s.tier, s.depends_on,
               left(COALESCE(s.owner, ''), 80) AS owner, {_ft("description")} AS description
        FROM service s""",
    "pl_ev_incidents": f"""
        SELECT 'incident:' || i.id AS evidence_id, i.id AS incident_id, COALESCE({_SVC.format(t='i')}, i.service_name) AS service,
               i.severity, i.status, i.detected_at, {_ft("title", 200)} AS title, {_ft("symptom", 400)} AS symptom
        FROM incident i""",
    "pl_ev_deploys": f"""
        SELECT 'deploy:' || d.id AS evidence_id, {_SVC.format(t='d')} AS service, d.version, d.git_sha,
               left(COALESCE(d.author, ''), 1) AS author, {_ft("summary")} AS summary, d.deployed_at
        FROM deploy d""",
    "pl_ev_alerts": f"""
        SELECT 'alert:' || a.id AS evidence_id, {_SVC.format(t='a')} AS service, a.severity, a.source, a.incident_id,
               {_ft("name", 200)} AS name, {_ft("summary")} AS summary, a.fired_at
        FROM alert a""",
    "pl_ev_logs": f"""
        SELECT 'log:' || l.id AS evidence_id, l.id AS log_id, {_SVC.format(t='l')} AS service, l.ts, l.level, l.signature,
               {_ft("message")} AS message
        FROM log_event l""",
    # one row per service, metric and five-minute bucket: a series the model can read without thousands of points
    "pl_ev_metrics": """
        SELECT 'metric:' || s.name || ':' || m.name || ':' || extract(epoch FROM date_bin('5 minutes', m.ts, TIMESTAMPTZ 'epoch'))::bigint
                   AS evidence_id,
               s.name AS service, m.name AS metric, date_bin('5 minutes', m.ts, TIMESTAMPTZ 'epoch') AS bucket,
               round(avg(m.value)::numeric, 3) AS avg_value, round(max(m.value)::numeric, 3) AS max_value, count(*) AS samples
        FROM metric_point m JOIN service s ON s.id = m.service_id
        GROUP BY s.name, m.name, date_bin('5 minutes', m.ts, TIMESTAMPTZ 'epoch')""",
}
VIEW_NAMES = tuple(VIEWS)


def install(conn) -> dict[str, str]:
    """CREATE OR REPLACE every evidence view (and nothing else: no grants, no AIDB). Safe on plain Postgres; run after the migrations."""
    conn.commit()
    done = {}
    for name, body in VIEWS.items():
        conn.execute(f"CREATE OR REPLACE VIEW {name} AS {body}")           # noqa: S608 - developer-written SQL, no user input
        done[name] = "ok"
    conn.commit()
    return done


def current_definition(conn, name: str) -> list[str] | None:
    """What the catalog says about one evidence view right now: its SQL, owner and options. None if it does not exist."""
    r = conn.execute(
        "SELECT pg_get_viewdef(c.oid, true) AS body, pg_get_userbyid(c.relowner) AS owner, COALESCE(c.reloptions::text, '') AS options "
        "FROM pg_class c WHERE c.relname = %s AND c.relnamespace = 'public'::regnamespace AND c.relkind = 'v'", (name,)).fetchone()
    return None if r is None else ["pl_view", name, r["body"], r["owner"], r["options"]]


def function_definition(conn, name: str) -> list[str] | None:
    r = conn.execute("SELECT pg_get_functiondef(p.oid) AS body FROM pg_proc p WHERE p.proname = %s AND p.pronamespace = 'public'::regnamespace",
                     (name,)).fetchone()
    return None if r is None else ["pl_function", name, r["body"]]
