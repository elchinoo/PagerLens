"""Prometheus metrics for this app, using the same metric names every app in the family exposes
(http_requests_total, http_request_duration_seconds, db_up, app_info, process_*), so one agent preset reads them all."""
import time

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)
from prometheus_client.core import GaugeMetricFamily
from prometheus_client.process_collector import ProcessCollector

from . import __version__

APP = "pagerlens"
REGISTRY = CollectorRegistry()
ProcessCollector(registry=REGISTRY)
REQUESTS = Counter("http_requests_total", "HTTP requests handled", ["app", "method", "route", "status"], registry=REGISTRY)
LATENCY = Histogram("http_request_duration_seconds", "HTTP request latency", ["app", "route"], registry=REGISTRY,
                    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10))
INFO = Gauge("app_info", "Build information", ["app", "version"], registry=REGISTRY)
INFO.labels(APP, __version__).set(1)
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


def observe(method: str, route: str, status: int, started: float) -> None:
    REQUESTS.labels(APP, method, route, str(status)).inc()
    LATENCY.labels(APP, route).observe(time.perf_counter() - started)


def render() -> tuple[bytes, str]:
    return generate_latest(REGISTRY), CONTENT_TYPE_LATEST
