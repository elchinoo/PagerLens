"""The tuning allow-list parser and the proposal builder: pure functions, no database."""
import pytest

from pagerlens import tuning
from pagerlens.tuning import StatementRejected, parse_statement

ACCEPTED = {
    "CREATE INDEX CONCURRENTLY IF NOT EXISTS pl_ix_incident_status ON public.incident (status)":
        "CREATE INDEX CONCURRENTLY IF NOT EXISTS pl_ix_incident_status ON public.incident (status)",
    "create index on public.incident (status, severity desc);": "CREATE INDEX ON public.incident (status, severity DESC)",
    "CREATE INDEX idx ON public.alert USING btree (fired_at ASC)": "CREATE INDEX idx ON public.alert (fired_at)",
    "CREATE  INDEX\n  CONCURRENTLY idx\n ON public.alert\n(fired_at)": "CREATE INDEX CONCURRENTLY idx ON public.alert (fired_at)",
    "CREATE INDEX I ON PUBLIC.T (C)": "CREATE INDEX i ON public.t (c)",
    "CREATE STATISTICS s (dependencies, ndistinct) ON a, b FROM public.t":
        "CREATE STATISTICS s (dependencies, ndistinct) ON a, b FROM public.t",
    "CREATE STATISTICS IF NOT EXISTS s ON a, b, c FROM public.t;": "CREATE STATISTICS IF NOT EXISTS s ON a, b, c FROM public.t",
}


@pytest.mark.parametrize("text, canonical", ACCEPTED.items())
def test_accepted_statements_are_rebuilt_canonically(text, canonical):
    p = parse_statement(text)
    assert p.text() == canonical
    assert parse_statement(p.text()) == p                          # the canonical form parses back to the same thing


REJECTED = [
    # not a CREATE INDEX / CREATE STATISTICS at all
    "DROP INDEX public.incident_pkey", "DROP TABLE public.incident", "DROP TABLE public.incident CASCADE", "DELETE FROM public.incident",
    "TRUNCATE public.incident", "ALTER TABLE public.incident ADD COLUMN x int", "ALTER SYSTEM SET shared_buffers = '1GB'",
    "CREATE TABLE public.x (a int)", "CREATE EXTENSION dblink", "CREATE FUNCTION f() RETURNS int AS 'select 1' LANGUAGE sql",
    "CREATE ROLE evil SUPERUSER", "GRANT ALL ON public.incident TO PUBLIC", "COPY public.incident TO PROGRAM 'id'", "SELECT 1", "", "   ", ";",
    "REINDEX TABLE public.incident", "VACUUM FULL public.incident", "ANALYZE public.incident", "CREATE TRIGGER t BEFORE INSERT ON public.x EXECUTE FUNCTION f()",
    # more than one statement
    "CREATE INDEX i ON public.t (c); DROP TABLE public.t", "CREATE INDEX i ON public.t (c);;", "CREATE INDEX i ON public.t (c); SELECT 1",
    "CREATE INDEX i ON public.t (c)\n;DROP TABLE public.t", "DROP TABLE x; CREATE INDEX i ON public.t (c)", "CREATE INDEX i ON public.t (c) ; ;",
    "CREATE INDEX i ON public.t (c) DROP TABLE public.t", "CREATE INDEX i ON public.t (c)\nDROP TABLE public.t",
    # other schemas, no schema, other databases
    "CREATE INDEX i ON other.t (c)", "CREATE INDEX i ON t (c)", "CREATE INDEX i ON pg_catalog.pg_class (relname)",
    "CREATE INDEX i ON information_schema.tables (table_name)", "CREATE INDEX i ON otherdb.public.t (c)", "CREATE INDEX i ON public.t.c (c)",
    "CREATE INDEX i ON publicc.t (c)", "CREATE INDEX i ON public..t (c)", "CREATE INDEX public.i ON public.t (c)", "CREATE INDEX other.i ON public.t (c)",
    "CREATE STATISTICS s ON a, b FROM other.t", "CREATE STATISTICS s ON a, b FROM t", "CREATE STATISTICS other.s ON a, b FROM public.t",
    # comment tricks, quoting tricks, encodings
    "CREATE INDEX i ON public.t (c) -- comment", "CREATE INDEX i ON public.t (c) --", "-- x\nCREATE INDEX i ON public.t (c)",
    "/* x */ CREATE INDEX i ON public.t (c)", "CREATE INDEX i ON public.t (c) /* ; DROP TABLE x */", "CREATE INDEX i /* hi */ ON public.t (c)",
    "CREATE INDEX i ON public.t (c) /*", "CREATE INDEX i ON public.t (c) */", "CREATE/**/INDEX i ON public.t (c)", "CREATE INDEX i ON public.t (c)#",
    'CREATE INDEX "i" ON public.t (c)', 'CREATE INDEX i ON public."t" (c)', 'CREATE INDEX i ON "public".t (c)', 'CREATE INDEX i ON public.t ("c")',
    "CREATE INDEX i ON public.t (c) WHERE c = 'x'", "CREATE INDEX 'i' ON public.t (c)", "CREATE INDEX i ON public.t ($$c$$)",
    "CREATE INDEX i ON public.t (c\\)", "CREATE INDEX i ON public.t (c)\x00", "CREATE INDEX i ON public.t (c) DROP", "CREATE INDEX i ON public.t (c) ",
    "CREATE INDEX i ON public.t (ｃ)", "CREATE INDEX i ON public.t (c) ; DROP TABLE x", "CREATE INDEX i ON public.t (c)\u0000;DROP TABLE x",
    # clauses and shapes outside the grammar
    "CREATE UNIQUE INDEX i ON public.t (c)", "CREATE INDEX i ON ONLY public.t (c)", "CREATE INDEX i ON public.t ((lower(c)))", "CREATE INDEX i ON public.t (lower(c))",
    "CREATE INDEX i ON public.t (c) WHERE c > 1", "CREATE INDEX i ON public.t (c) INCLUDE (d)", "CREATE INDEX i ON public.t (c) WITH (fillfactor = 10)",
    "CREATE INDEX i ON public.t (c) TABLESPACE pg_global", "CREATE INDEX i ON public.t USING gin (c)", "CREATE INDEX i ON public.t USING hash (c)",
    "CREATE INDEX i ON public.t (c desc nulls first)", "CREATE INDEX i ON public.t (c COLLATE \"C\")", "CREATE INDEX i ON public.t (c, c2, c3, c4, c5)",
    "CREATE INDEX i ON public.t ()", "CREATE INDEX i ON public.t (c,)", "CREATE INDEX i ON public.t (c d)", "CREATE INDEX i ON public.t (c", "CREATE INDEX i ON public.t",
    "CREATE INDEX i public.t (c)", "CREATE INDEX CONCURRENTLY CONCURRENTLY i ON public.t (c)", "CREATE INDEX i ON public.t (c) CONCURRENTLY",
    "CREATE INDEX 1i ON public.t (c)", "CREATE INDEX i-1 ON public.t (c)", "CREATE INDEX " + "x" * 64 + " ON public.t (c)", "CREATE INDEX i ON public.t (" + "c" * 64 + ")",
    "CREATE STATISTICS s ON a FROM public.t", "CREATE STATISTICS s (foo) ON a, b FROM public.t", "CREATE STATISTICS s (mcv ON a, b FROM public.t",
    "CREATE STATISTICS s ON a, b FROM public.t; DROP TABLE public.t", "CREATE STATISTICS s ON (a + 1), b FROM public.t", "CREATE STATISTICS ON a, b FROM public.t",
    "CREATE STATISTICS s ON a, b, c, d, e, f, g, h, i FROM public.t", "CREATE STATISTICS s ON a, b FROM public.t WHERE a = 1",
    "CREATE INDEX i ON public.t (c) " + "x" * 700,
]


@pytest.mark.parametrize("text", REJECTED, ids=lambda t: repr(t)[:70])
def test_the_allow_list_rejects(text):
    with pytest.raises(StatementRejected):
        parse_statement(text)
    assert tuning.is_applicable(text) is False


def test_non_text_is_rejected():
    for bad in (None, 5, b"CREATE INDEX i ON public.t (c)", ["CREATE INDEX i ON public.t (c)"]):
        with pytest.raises(StatementRejected):
            parse_statement(bad)


def test_what_is_executed_is_rebuilt_from_the_parsed_pieces_with_quoted_identifiers():
    p = parse_statement("CREATE INDEX CONCURRENTLY IF NOT EXISTS select ON public.user (order DESC, group)")
    rendered = p.composed().as_string()
    assert rendered == 'CREATE INDEX CONCURRENTLY IF NOT EXISTS "select" ON "public"."user" ("order" DESC, "group")'
    stat = parse_statement("CREATE STATISTICS s (mcv) ON a, b FROM public.t").composed().as_string()
    assert stat == 'CREATE STATISTICS "s" (mcv) ON "a", "b" FROM "public"."t"'


# ---- the proposal builder -----------------------------------------------------------------------------------

OWN = {"incident": {"status", "severity", "service_id", "id"}, "alert": {"fired_at", "source"}}
PAYLOAD = {
    "top_queries": {"available": True, "queries": [
        {"queryid": "111", "query": "SELECT * FROM incident WHERE status = $1 AND severity = $2", "mean_ms": 5.0},
        {"queryid": "222", "query": "SELECT count(*) FROM alert", "mean_ms": 1.0}]},
    "advisor": {"available": True, "suggestions": [
        {"schema": "public", "table": "incident", "column": "status", "operator": "=", "occurrences": 40, "executions": 900,
         "rows_filtered": 90000, "filtered_per_execution": 100.0, "suggestion": "Consider an index on incident (status)"},
        {"schema": "public", "table": "incident", "column": "severity", "operator": "=", "occurrences": 10, "executions": 300,
         "rows_filtered": 3000, "filtered_per_execution": 10.0, "suggestion": "Consider an index on incident (severity)"},
        {"schema": "audit", "table": "incident", "column": "status", "operator": "=", "occurrences": 5, "executions": 5, "rows_filtered": 5},
        {"schema": "public", "table": "not_mine", "column": "x", "operator": "=", "occurrences": 5, "executions": 5, "rows_filtered": 5},
        {"schema": "public", "table": "incident", "column": "evil; DROP TABLE x", "operator": "=", "occurrences": 5, "executions": 5, "rows_filtered": 5}]},
    "tuner": {"available": True, "recommendations": [{"setting": "shared_buffers", "value": "186 MB", "raw": "shared_buffers = '186 MB'"},
                                                     {"setting": "", "value": None, "raw": "garbage"}]},
}


def test_builder_proposes_only_safe_statements_for_tables_pagerlens_owns():
    out = tuning.build_candidates(PAYLOAD, OWN, [])
    by_kind = {(c["source"], c["statement"].split()[0] + " " + c["statement"].split()[1]): c for c in out}
    index = [c for c in out if c["statement"].startswith("CREATE INDEX")]
    assert {c["statement"] for c in index} == {
        "CREATE INDEX CONCURRENTLY IF NOT EXISTS pl_ix_incident_status ON public.incident (status)",
        "CREATE INDEX CONCURRENTLY IF NOT EXISTS pl_ix_incident_severity ON public.incident (severity)"}
    assert all(c["applicable"] and c["target"] == "self" and c["source"] == "advisor" for c in index)
    status = next(c for c in index if "(status)" in c["statement"])
    assert status["motivating_queryid"] == "111" and "WHERE status = $1" in status["motivating_query"]
    assert "not a measured speed-up" in status["estimated_benefit"]
    stats = [c for c in out if c["statement"].startswith("CREATE STATISTICS")]
    assert len(stats) == 1 and stats[0]["applicable"] and "ON status, severity FROM public.incident" in stats[0]["statement"]
    tuner = [c for c in out if c["source"] == "tuner"]
    assert len(tuner) == 1 and tuner[0]["applicable"] is False and "shared_buffers" in tuner[0]["statement"]
    assert by_kind                                                       # nothing for the other schema, the unknown table or the hostile column
    assert not any("audit" in c["statement"] or "not_mine" in c["statement"] or "DROP" in c["statement"] for c in out)
    assert all(tuning.is_applicable(c["statement"]) == c["applicable"] for c in out)     # `applicable` is exactly what the parser says


def test_builder_never_proposes_for_a_monitored_app_beyond_advice():
    slow = [{"service": "inventory-api", "queryid": "6823950417", "baseline_ms": 12.0, "current_ms": 484.0, "ratio": 40.3}]
    out = tuning.build_candidates({"advisor": {"available": False, "reason": "x"}}, OWN, slow)
    assert len(out) == 1
    c = out[0]
    assert c["source"] == "slow_query" and c["target"] == "inventory-api" and c["applicable"] is False
    assert "never changes a monitored system" in c["rationale"] and "6823950417" in c["statement"]


def test_a_slow_query_of_pagerlens_itself_becomes_an_index_proposal_when_the_advisor_agrees():
    slow = [{"service": "pagerlens", "queryid": "111", "baseline_ms": 2.0, "current_ms": 90.0, "ratio": 45.0}]
    out = tuning.build_candidates(PAYLOAD, OWN, slow, self_name="pagerlens")
    mine = [c for c in out if c["source"] == "slow_query"]
    assert len(mine) == 1 and mine[0]["applicable"] and mine[0]["target"] == "self" and mine[0]["motivating_queryid"] == "111"
    assert mine[0]["statement"].startswith("CREATE INDEX CONCURRENTLY IF NOT EXISTS pl_ix_incident_")
    other = tuning.build_candidates(PAYLOAD, OWN, [{**slow[0], "service": "someone-else"}], self_name="pagerlens")
    assert [c for c in other if c["source"] == "slow_query"][0]["applicable"] is False


def test_long_names_are_shortened_deterministically():
    n = tuning._name("pl_ix", "t" * 40, ["c" * 30])
    assert len(n) <= 63 and n == tuning._name("pl_ix", "t" * 40, ["c" * 30]) and tuning._name("pl_ix", "a", ["b"]) == "pl_ix_a_b"
    assert tuning.is_applicable(f"CREATE INDEX {n} ON public.{'t' * 40} ({'c' * 30})")


def test_apply_is_off_by_default_and_the_timeouts_are_bounded(monkeypatch):
    monkeypatch.delenv("PAGERLENS_ALLOW_TUNING_APPLY", raising=False)
    assert tuning.apply_enabled() is False
    for v in ("false", "0", "no", "", "off"):
        monkeypatch.setenv("PAGERLENS_ALLOW_TUNING_APPLY", v)
        assert tuning.apply_enabled() is False
    monkeypatch.setenv("PAGERLENS_ALLOW_TUNING_APPLY", "true")
    assert tuning.apply_enabled() is True
    for raw, want in (("999999", 600), ("0", 1), ("x", 60), ("30", 30)):
        monkeypatch.setenv("PAGERLENS_TUNING_STATEMENT_TIMEOUT_SECONDS", raw)
        assert tuning.statement_timeout_seconds() == want
