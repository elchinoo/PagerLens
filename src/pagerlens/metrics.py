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

