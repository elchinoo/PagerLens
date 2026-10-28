"""Watching the fleet's databases: db_insights_* gauges -> telemetry -> a slow_query finding (agent unit tests; investigator against a Postgres)."""
import json
import os

import httpx
import pytest

from pagerlens import agent, ingest, slowquery

QID = "6823950417"


# ---- naming and the agent-side detector (no database) ----------------------------------------------

def test_metric_names_round_trip_and_hostile_labels_are_refused():
    assert slowquery.metric_name(QID) == f"slowq_{QID}" and slowquery.query_id(f"slowq_{QID}") == QID
    assert slowquery.metric_name("-4417203391") == "slowq_m4417203391" and slowquery.query_id("slowq_m4417203391") == "-4417203391"
    assert slowquery.metric_name("deadbeef01") == "slowq_deadbeef01"
    for bad in ("", "1; DROP TABLE x", "a b", "x" * 40, "../etc", "A\nB"):
        assert slowquery.metric_name(bad) is None or ingest.METRIC_NAME.match(slowquery.metric_name(bad))
    for ok in (QID, "-4417203391", "-9223372036854775808", "9223372036854775807"):
        assert ingest.METRIC_NAME.match(slowquery.metric_name(ok))               # accepted by ingest as a metric name


def test_a_long_query_id_is_shortened_in_alert_text_so_ingest_does_not_scrub_it_as_a_card():
    long_id = "9223372036854775807"
    assert slowquery.short_id(QID) == QID and slowquery.short_id(long_id) == "…" + long_id[-8:]
    assert "[CARD]" in ingest.scrub(f"query {long_id} slow") and "[CARD]" not in ingest.scrub(f"query {slowquery.short_id(long_id)} slow")


def test_watch_fires_once_on_a_sustained_rise_and_not_on_a_spike():
    w = slowquery.Watch()
    hits = [w.observe("1", v) for v in [12, 13, 11, 12, 12, 13, 12]]
    assert not any(hits)
    assert w.observe("1", 400) is None and w.observe("1", 12) is None              # a one-scrape spike does not fire
    w = slowquery.Watch()
    for v in [12, 13, 11, 12, 12, 13]:
        w.observe("1", v)
    out = [w.observe("1", v) for v in (480, 470, 490, 485)]
    assert out[0] is None and out[1] is None and out[2]["queryid"] == "1" and out[3] is None      # fires once, on the third slow scrape
    assert 11 <= out[2]["before_ms"] <= 13 and 470 <= out[2]["after_ms"] <= 490
    for v in (12, 12, 12, 12, 12):                                                  # recovery re-arms the alert
        w.observe("1", v)
    again = [w.observe("1", v) for v in (500, 500, 500)]
    assert again[2] is not None


def test_watch_ignores_statements_too_fast_to_matter():
    w = slowquery.Watch()
    for v in [1, 1, 1, 1, 1, 1]:
        w.observe("fast", v)
    assert not any(w.observe("fast", v) for v in (8, 8, 8))                          # x8 but under 20 ms


# ---- the agent turns the kit's gauge into telemetry and an alert ---------------------------------------

class World:
    """A fake monitored app exposing /metrics and a fake PagerLens recording what the agent pushed."""

    def __init__(self):
        self.mean = {QID: 0.012, "-4417203391": 0.004}
        self.sent = []

    def metrics_text(self):
        lines = ["# TYPE db_insights_available gauge", 'db_insights_available{app="shop"} 1',
                 "# TYPE db_insights_top_query_mean_seconds gauge"]
        lines += [f'db_insights_top_query_mean_seconds{{app="shop",queryid="{q}"}} {v}' for q, v in self.mean.items()]
        lines += ['db_insights_top_query_mean_seconds{app="shop",queryid="1; DROP TABLE x"} 9', "# TYPE db_up gauge", 'db_up{app="shop"} 1']
        return "\n".join(lines) + "\n"

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if request.url.host == "pl.example":
            self.sent.append((request.url.path, json.loads(request.content)))
            return httpx.Response(200, json={})
        return httpx.Response(200, text=self.metrics_text())

    def posted(self, path):
        return [b for p, b in self.sent if p == path]


def make_agent(world, monkeypatch):
    monkeypatch.setenv("PAGERLENS_TOKEN", "tok-" + "abc123456789")  # pragma: allowlist secret
    client = httpx.Client(transport=httpx.MockTransport(world), follow_redirects=False)
    cfg = agent.load_config({"pagerlens": {"url": "https://pl.example"}, "targets": [
        {"name": "shop", "scrape": [{"url": "https://shop.example/metrics"}]}]})
    return agent.Agent(cfg, client, agent.Pusher(cfg, client))


def test_agent_stores_each_statement_as_a_metric_and_opens_an_alert_on_a_sustained_rise(monkeypatch):
    w = World()
    a = make_agent(w, monkeypatch)
    for i in range(6):
        a.cycle(now=100 + 30 * i)
    pts = {p["name"]: p["value"] for b in w.posted("/api/ingest/metrics") for p in b["points"]}
    assert pts[f"slowq_{QID}"] == pytest.approx(12.0) and pts["slowq_m4417203391"] == pytest.approx(4.0)   # milliseconds
    assert not any("DROP" in name for b in w.posted("/api/ingest/metrics") for name in (p["name"] for p in b["points"]))
    assert not w.posted("/api/ingest/alerts")
    w.mean[QID] = 0.480
    for i in range(6, 10):
        a.cycle(now=100 + 30 * i)
    alerts = w.posted("/api/ingest/alerts")
    assert len(alerts) == 1                                                       # once, not on every scrape
    al = alerts[0]
    assert al["service"] == "shop" and al["name"] == "SlowQuery" and al["source"] == "pagerlens-agent"
    assert QID in al["summary"] and "12 ms" in al["summary"] and "480 ms" in al["summary"]


def test_agent_example_config_scrapes_the_fleet_and_still_loads():
    import pathlib

    import yaml
    path = pathlib.Path(__file__).resolve().parent.parent / "agent.example.yaml"
    raw = path.read_text()
    assert "db_insights_top_query_mean_seconds" in raw and "slowq_" in raw           # documented where people configure the agent
    agent.load_config(yaml.safe_load(raw))


# ---- the investigator (needs a Postgres) -------------------------------------------------------------

if os.environ.get("TEST_DATABASE_URL"):
    from pagerlens import core, incidents, investigator, migrate, simulator, vault
    from pagerlens.db import connect, connect_vector

    @pytest.fixture(autouse=True)
    def _db(monkeypatch, client):
        monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
        for v in ("PAGERLENS_API_KEY", "PAGERLENS_ALLOW_ANONYMOUS", "PAGERLENS_ENCRYPTION_KEY", "LLM_BASE_URL"):
            monkeypatch.delenv(v, raising=False)
        monkeypatch.setenv("PAGERLENS_API_KEY_FILE", "/nonexistent/key")
        monkeypatch.setenv("PAGERLENS_ENCRYPTION_KEY_FILE", "/nonexistent/key")
        core.auth.limiter.clear()
        core.local._setup_code = None
        vault.lock()
        client.cookies.clear()
        with connect() as c:
            c.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public")
            c.commit()
        migrate.run()

    def run_scenario(key, *, seed=7, memory=False):
        with connect_vector() as conn:
            info = simulator.trigger(conn, key, seed=seed)
            conn.commit()
            run_id = investigator.investigate(conn, info["incident_id"], use_memory=memory)
            hyps = incidents.get_run(conn, run_id)
            rows = conn.execute("SELECT h.id, h.category, h.suspect, h.score FROM hypothesis h WHERE run_id=%s ORDER BY rank", (run_id,)).fetchall()
            for r in rows:
                r["evidence"] = [e["note"] for e in conn.execute(
                    "SELECT note FROM hypothesis_evidence WHERE hypothesis_id=%s AND stance='supports'", (r["id"],))]
                r["refutes"] = [e["note"] for e in conn.execute(
                    "SELECT note FROM hypothesis_evidence WHERE hypothesis_id=%s AND stance='refutes'", (r["id"],))]
        return run_id, hyps, rows

    @pytest.mark.parametrize("seed", [7, 11])
    def test_a_slow_query_regression_is_the_top_finding_and_names_the_query(seed):
        _, run, hyps = run_scenario("slow_query", seed=seed)
        assert hyps[0]["category"] == "slow_query" and hyps[0]["suspect"] == "inventory-api"
        text = " ".join(hyps[0]["evidence"])
        import re
        m = re.search(rf"query {QID} on inventory-api: mean ([\d.]+) ms before, ([\d.]+) ms now", text)
        assert m and "Database insights" in text and f"queryid {QID}" in text
        assert 11 <= float(m.group(1)) <= 13 and 420 <= float(m.group(2)) <= 520        # before and after means
        assert "m4417203391" not in text and "4417203391" not in text               # the unchanged statement is not blamed
        assert "db_saturation" not in [h["category"] for h in hyps]                    # the pool is not full: no competing saturation story
        assert hyps[0]["score"] > 0.6
        assert {s["tool"] for s in run["steps"] if s["kind"] == "tool"} >= {"slow_queries"}

    def test_the_slow_query_scenario_belongs_to_the_scenario_set_and_runbooks():
        assert "slow_query" in simulator.SCENARIOS and simulator.SCENARIOS["slow_query"].category == "slow_query"
        assert "slow_query" in investigator.CATEGORIES
        assert any(rb[1] == "slow_query" for rb in simulator.RUNBOOKS)
        assert any(s["key"] == "slow_query" for s in simulator.catalog())
        with connect() as c:
            simulator.trigger(c, "slow_query")
            c.commit()
            names = {r["name"] for r in c.execute("SELECT DISTINCT name FROM metric_point WHERE name LIKE 'slowq\\_%%'")}
        assert names == {f"slowq_{QID}", "slowq_m4417203391"}                            # the regressed query and a steady one, both valid ingest names
        assert all(ingest.METRIC_NAME.match(n) for n in names)

    def test_other_scenarios_have_the_steady_statements_but_no_slow_query_finding():
        for key in ("bad_deploy", "db_pool_exhaustion"):
            _, _, hyps = run_scenario(key)
            assert "slow_query" not in [h["category"] for h in hyps], key
        with connect_vector() as conn:
            info = simulator.trigger(conn, "bad_deploy")
            conn.commit()
            ctx = investigator.tools.make_ctx(conn, info["incident_id"])
            res = investigator.tools.slow_queries(ctx, "inventory-api")
            assert res.data["queries"] == [] and res.data["tracked"] == 2 and "no statement got slower" in res.summary
            assert "no query statistics" in investigator.tools.slow_queries(ctx, "web-frontend").summary

    def test_a_short_spike_is_not_reported_as_a_regression():
        with connect_vector() as conn:
            info = simulator.trigger(conn, "slow_query")
            conn.commit()
            sid = conn.execute("SELECT id FROM service WHERE name='inventory-api'").fetchone()["id"]
            anchor = conn.execute("SELECT detected_at FROM incident WHERE id=%s", (info["incident_id"],)).fetchone()["detected_at"]
            conn.execute("UPDATE metric_point SET value = 12 WHERE service_id=%s AND name=%s AND ts > %s - interval '2 minutes'",
                         (sid, f"slowq_{QID}", anchor))      # the last samples are back to normal: it is no longer sustained
            ctx = investigator.tools.make_ctx(conn, info["incident_id"])
            assert investigator.tools.slow_queries(ctx, "inventory-api").data["queries"] == []
