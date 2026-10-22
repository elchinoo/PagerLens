"""OTLP/HTTP receiver and the Prometheus /metrics endpoint against a disposable Postgres."""
import gzip
import json
import os
import sys
import time

import pytest

if not os.environ.get("TEST_DATABASE_URL"):
    pytest.skip("set TEST_DATABASE_URL to run DB tests", allow_module_level=True)

from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import ExportLogsServiceRequest  # noqa: E402

from pagerlens import api, auth, core, migrate, otlp, vault  # noqa: E402
from pagerlens.db import connect  # noqa: E402

H = {"X-PagerLens-CSRF": "1"}
PASSWORD = "correct-horse-battery"  # pragma: allowlist secret
JSON_CT = {"Content-Type": "application/json"}


@pytest.fixture(autouse=True)
def _db(monkeypatch, client):
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    for v in ("PAGERLENS_API_KEY", "PAGERLENS_ALLOW_ANONYMOUS", "PAGERLENS_ENCRYPTION_KEY", "LLM_BASE_URL"):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setenv("PAGERLENS_API_KEY_FILE", "/nonexistent/key")
    monkeypatch.setenv("PAGERLENS_ENCRYPTION_KEY_FILE", "/nonexistent/key")
    core.auth.limiter.clear()
    core.local._setup_code = None
    otlp._prev.clear()
    vault.lock()
    client.cookies.clear()
    with connect() as c:
        c.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public")
        c.commit()
    migrate.run()


def token(client, scope):
    with connect() as c:
        if not auth.admin_configured(c):
            auth.set_admin_password(c, PASSWORD)
    client.post("/api/login", json={"password": PASSWORD}, headers=H)
    tok = client.post("/api/tokens", json={"name": scope, "scope": scope}, headers=H).json()["token"]
    client.cookies.clear()
    return {"Authorization": f"Bearer {tok}"}


def attrs(**kv):
    return [{"key": k, "value": {"stringValue": v}} for k, v in kv.items()]


def logs_body(service="otel-svc", version=None, records=None):
    res = attrs(**{"service.name": service, **({"service.version": version} if version else {})})
    return {"resourceLogs": [{"resource": {"attributes": res}, "scopeLogs": [{"logRecords": records or [
        {"timeUnixNano": str(int(time.time() * 1e9)), "severityText": "ERROR", "body": {"stringValue": "payment failed for jane@example.com"},
         "attributes": attrs(route="/pay")}]}]}]}


# ---- logs -----------------------------------------------------------------------------------------

def test_json_logs_are_stored_scrubbed_and_the_service_is_registered(client):
    h = token(client, "ingest")
    r = client.post("/v1/logs", headers=h | JSON_CT, content=json.dumps(logs_body()))
    assert r.status_code == 200 and r.json() == {}
    with connect() as c:
        row = c.execute("SELECT l.level, l.message, l.fields::text AS f, s.name FROM log_event l JOIN service s ON s.id=l.service_id").fetchone()
    assert row["name"] == "otel-svc" and row["level"] == "error"
    assert "jane@example.com" not in row["message"] and "[EMAIL]" in row["message"] and "/pay" in row["f"]


def test_protobuf_logs_gzip_and_severity_numbers(client):
    h = token(client, "ingest")
    req = ExportLogsServiceRequest()
    rl = req.resource_logs.add()
    kv = rl.resource.attributes.add()
    kv.key, kv.value.string_value = "service.name", "Proto-Svc:v1"
    for n, text in ((9, "info line"), (13, "warn line"), (17, "error line"), (21, "fatal line")):
        lr = rl.scope_logs.add().log_records.add()
        lr.time_unix_nano, lr.severity_number, lr.body.string_value = int(time.time() * 1e9), n, text
    r = client.post("/v1/logs", headers=h | {"Content-Type": "application/x-protobuf", "Content-Encoding": "gzip"},
                    content=gzip.compress(req.SerializeToString()))
    assert r.status_code == 200 and r.headers["content-type"].startswith("application/x-protobuf")
    with connect() as c:
        got = {x["message"]: x["level"] for x in c.execute("SELECT message, level FROM log_event")}
        name = c.execute("SELECT name FROM service").fetchone()["name"]
    assert got == {"info line": "info", "warn line": "warn", "error line": "error", "fatal line": "fatal"}
    assert name == "proto-svc"  # lowercased, ':v1' suffix dropped


def test_records_without_a_service_name_are_rejected_not_stored(client):
    h = token(client, "ingest")
    body = {"resourceLogs": [{"resource": {"attributes": []}, "scopeLogs": [{"logRecords": [{"body": {"stringValue": "x"}}]}]}]}
    r = client.post("/v1/logs", headers=h | JSON_CT, content=json.dumps(body))
    assert r.status_code == 200 and r.json()["partialSuccess"]["rejectedLogRecords"] == "1"
    with connect() as c:
        assert c.execute("SELECT count(*) AS n FROM log_event").fetchone()["n"] == 0


def test_hostile_or_malformed_bodies_get_clean_errors(client):
    h = token(client, "ingest")
    assert client.post("/v1/logs", headers=h | JSON_CT, content=b"{not json").status_code == 400
    assert client.post("/v1/logs", headers=h | {"Content-Type": "text/plain"}, content=b"x").status_code == 400
    assert client.post("/v1/logs", headers=h | {"Content-Type": "application/x-protobuf"}, content=b"\xff\xff\xff").status_code == 400
    assert client.post("/v1/logs", headers=h | JSON_CT | {"Content-Encoding": "gzip"}, content=b"nope").status_code == 400
    assert client.post("/v1/logs", headers=h | JSON_CT | {"Content-Encoding": "br"}, content=b"{}").status_code == 400
    bomb = gzip.compress(b"\0" * (otlp.MAX_DECOMPRESSED + 1024 * 1024))  # tiny on the wire, huge when inflated
    assert len(bomb) < 100_000
    r = client.post("/v1/logs", headers=h | JSON_CT | {"Content-Encoding": "gzip"}, content=bomb)
    assert r.status_code == 400 and "too large" in r.text
    big = b'{"pad":"' + b"a" * (api.MAX_BODY + 10) + b'"}'
    assert client.post("/v1/logs", headers=h | JSON_CT, content=big).status_code == 413


def test_version_change_becomes_a_deploy_but_first_sight_is_only_a_baseline(client):
    h = token(client, "ingest")
    for version in ("1.0.0", "1.0.0", "1.1.0", "1.1.0"):
        assert client.post("/v1/logs", headers=h | JSON_CT, content=json.dumps(logs_body(version=version))).status_code == 200
    with connect() as c:
        deploys = c.execute("SELECT version, author FROM deploy").fetchall()
    assert [(d["version"], d["author"]) for d in deploys] == [("1.1.0", "telemetry")]


def test_dependencies_can_be_declared_in_resource_attributes(client):
    h = token(client, "ingest")
    body = logs_body()
    body["resourceLogs"][0]["resource"]["attributes"] += attrs(**{"pagerlens.depends_on": "db-svc, cache-svc"})
    client.post("/v1/logs", headers=h | JSON_CT, content=json.dumps(body))
    with connect() as c:
        assert c.execute("SELECT depends_on FROM service WHERE name='otel-svc'").fetchone()["depends_on"] == ["db-svc", "cache-svc"]


# ---- metrics ----------------------------------------------------------------------------------------

def metric_body(metric, service="otel-svc"):
    return {"resourceMetrics": [{"resource": {"attributes": attrs(**{"service.name": service})},
                                 "scopeMetrics": [{"metrics": [metric]}]}]}


def test_gauge_counter_rate_and_histogram_p95(client):
    h = token(client, "ingest")
    now = int(time.time() * 1e9)
    post = lambda m: client.post("/v1/metrics", headers=h | JSON_CT, content=json.dumps(metric_body(m))).status_code  # noqa: E731
    assert post({"name": "cpu.pct", "gauge": {"dataPoints": [{"timeUnixNano": str(now), "asDouble": 42.5}]}}) == 200
    counter = lambda v, t: {"name": "http.requests", "sum": {"aggregationTemporality": 2, "isMonotonic": True,  # noqa: E731
                                                              "dataPoints": [{"timeUnixNano": str(t), "asInt": str(v)}]}}
    assert post(counter(100, now - 10_000_000_000)) == 200 and post(counter(160, now)) == 200
    hist = lambda counts, t: {"name": "latency.ms", "histogram": {"aggregationTemporality": 2, "dataPoints": [  # noqa: E731
        {"timeUnixNano": str(t), "explicitBounds": [10, 50, 100], "bucketCounts": [str(c) for c in counts]}]}}
    assert post(hist([0, 0, 0, 0], now - 5_000_000_000)) == 200 and post(hist([50, 40, 10, 0], now)) == 200
    with connect() as c:
        vals = {r["name"]: r["value"] for r in c.execute("SELECT name, value FROM metric_point")}
    assert vals["cpu_pct"] == 42.5
    assert vals["http_requests_rate"] == pytest.approx(6.0)             # 60 requests over 10 s
    assert 50 < vals["latency_ms_p95"] <= 100                           # 95th of 100 samples falls in the 50-100 bucket


def test_traces_are_acknowledged_but_not_stored(client):
    h = token(client, "ingest")
    body = {"resourceSpans": [{"scopeSpans": [{"spans": [{"name": "a"}, {"name": "b"}]}]}]}
    r = client.post("/v1/traces", headers=h | JSON_CT, content=json.dumps(body))
    assert r.status_code == 200 and r.json()["partialSuccess"]["rejectedSpans"] == "2"


# ---- scopes and /metrics -------------------------------------------------------------------------------

def test_otlp_needs_an_ingest_token(client):
    read, metrics_tok = token(client, "read"), token(client, "metrics")
    assert client.post("/v1/logs", headers=JSON_CT, content=b"{}").status_code == 401
    assert client.post("/v1/logs", headers=read | JSON_CT, content=b"{}").status_code == 403
    assert client.post("/v1/logs", headers=metrics_tok | JSON_CT, content=b"{}").status_code == 403


def test_metrics_endpoint_scope_content_and_low_cardinality(client):
    m, ing, read = token(client, "metrics"), token(client, "ingest"), token(client, "read")
    assert client.get("/metrics").status_code == 401
    assert client.get("/metrics", headers=ing).status_code == 403 and client.get("/metrics", headers=read).status_code == 403
    client.get("/api/incidents/424242", headers=read)   # a 404 on a templated route
    r = client.get("/metrics", headers=m)
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/plain")
    text = r.text
    assert 'db_up{app="pagerlens"} 1.0' in text and "app_info{" in text
    if sys.platform.startswith("linux"):  # the process collector reads /proc, so it exists in the (Linux) container only
        assert "process_resident_memory_bytes" in text
    assert 'route="/api/incidents/{incident_id}"' in text and "424242" not in text
    assert client.get("/api/incidents", headers=m).status_code == 403          # a metrics token reads nothing else
    assert client.post("/mcp", headers=m, json={}).status_code == 403
