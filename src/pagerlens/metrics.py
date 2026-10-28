"""Prometheus metrics for this app, using the same metric names every app in the family exposes
(http_requests_total, http_request_duration_seconds, db_up, app_info, process_*), so one agent preset reads them all."""
from prometheus_client import Counter
from prometheus_client.core import GaugeMetricFamily

from .core import metrics as _kit

APP = "pagerlens"
REGISTRY = _kit.registry          # the kit's registry already carries http_requests_total, http_request_duration_seconds, app_info, process_*
observe = _kit.observe
render = _kit.render
INGESTED = Counter("pagerlens_ingested_total", "Telemetry items accepted", ["kind"], registry=REGISTRY)
ASKED = Counter("pagerlens_ask_total", "Questions asked in Ask PagerLens", ["status"], registry=REGISTRY)
ASK_TURNS = Counter("pagerlens_ask_turns_total", "Ask turns by outcome: grounded, corrected (grounded after the corrective round), ungrounded",
                    ["outcome"], registry=REGISTRY)
for _outcome in ("grounded", "corrected", "ungrounded"):
    ASK_TURNS.labels(_outcome)
INVESTIGATIONS = Counter("pagerlens_investigations_total", "Investigations run", ["mode", "status"], registry=REGISTRY)


class DatabaseCollector:
    """Evaluated at scrape time: is the database reachable, and what is open."""

    def collect(self):
        from .db import connect

        up, open_incidents = 0, 0
        try:
            with connect(retries=1) as conn:
                open_incidents = conn.execute("SELECT count(*) AS n FROM incident WHERE status <> 'resolved'").fetchone()["n"]
            up = 1
        except Exception:  # noqa: BLE001 - a scrape must never fail because the database is down; that is the signal
            pass
        g = GaugeMetricFamily("db_up", "1 if the database answers", labels=["app"])
        g.add_metric([APP], up)
        yield g
        o = GaugeMetricFamily("pagerlens_open_incidents", "Incidents not yet resolved", labels=["app"])
        o.add_metric([APP], open_incidents)
        yield o


REGISTRY.register(DatabaseCollector())



# Query statistics of THIS app's database (EDB's edb_stat_monitor, else pg_stat_statements) as a few small gauges, so pagerlens-agent
# can feed them back as telemetry and a regression becomes a finding (see docs/GUIDE.md, "Watching the fleet's databases").
# Cached for 30 s; a scrape never fails: no statistics means db_insights_available 0.
def _connect():
    from .db import connect
    return connect(retries=1)


_kit.add_insights_collector(_connect, top=5, min_calls=5, ttl=30)
