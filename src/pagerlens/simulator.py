"""Self-contained 'shop' fleet that breaks on demand.

Five fictional services produce baseline telemetry; a scenario overlays a failure that started 20 minutes ago.
Everything goes through the same ingest functions a real integration would use (so PII scrubbing applies), and the
true cause is stored in `sim_truth`, which the investigator never reads. Data is deterministic for a given seed.
"""
import hashlib
import random
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from . import ingest

WINDOW_MIN = 90        # minutes of telemetry written
ONSET_MIN = 20         # the failure began this many minutes before 'now'
CHUNK = 900

# name: (owner, tier, description, depends_on, baseline)
FLEET: dict[str, dict] = {
    "web-frontend": dict(owner="storefront", tier="edge", description="Public web tier and API gateway",
                         depends_on=["checkout-api", "search-service"],
                         base=dict(request_rate=120, error_rate=0.2, latency_p95_ms=90, cpu_pct=30, mem_pct=45)),
    "checkout-api": dict(owner="payments", tier="critical", description="Cart, pricing and order placement",
                         depends_on=["payments-gateway", "inventory-api"],
                         base=dict(request_rate=40, error_rate=0.4, latency_p95_ms=180, cpu_pct=35, mem_pct=55,
                                   db_connections=8, db_connections_max=20)),
    "payments-gateway": dict(owner="payments", tier="critical", description="Talks to the external payment provider",
                             depends_on=[],
                             base=dict(request_rate=25, error_rate=0.3, latency_p95_ms=320, cpu_pct=25, mem_pct=50)),
    "inventory-api": dict(owner="fulfilment", tier="standard", description="Stock levels and reservations",
                          depends_on=[],
                          base=dict(request_rate=60, error_rate=0.3, latency_p95_ms=70, cpu_pct=28, mem_pct=48,
                                    db_connections=6, db_connections_max=20)),
    "search-service": dict(owner="discovery", tier="standard", description="Catalogue search",
                           depends_on=[],
                           base=dict(request_rate=80, error_rate=0.2, latency_p95_ms=110, cpu_pct=40, mem_pct=55)),
}

INFO_LINES = {
    "web-frontend": ["GET /products 200 in <ms>ms (user=jane.doe@example.com ip=203.0.113.<ip>)",
                     "GET /cart 200 in <ms>ms", "POST /session 201 (client_ip=198.51.100.<ip>)"],
    "checkout-api": ["order placed id=<id> total=<amt> items=<n>", "cart priced in <ms>ms",
                     "payment authorised via payments-gateway in <ms>ms"],
    "payments-gateway": ["authorised charge ref=<id> provider=acme-pay in <ms>ms",
                         "received webhook from provider event=charge.settled"],
    "inventory-api": ["reserved sku=<sku> qty=<n>", "stock lookup sku=<sku> in <ms>ms"],
    "search-service": ["query served terms=<n> hits=<n> in <ms>ms", "index refresh complete docs=<n>"],
}

OLD_DEPLOYS = [  # (service, days ago, version, summary)
    ("web-frontend", 2.3, "v5.8.1", "Update product card layout"),
    ("checkout-api", 1.6, "v2.13.4", "Fix rounding in tax calculation"),
    ("payments-gateway", 4.2, "v1.9.0", "Rotate provider client certificate"),
    ("inventory-api", 2.1, "v3.2.2", "Add index on stock(sku)"),
    ("search-service", 3.1, "v4.1.0", "Upgrade analyzer library"),
]


@dataclass
class Scenario:
    key: str
    title: str
    category: str
    service: str                 # where the alert fires
    alert_name: str
    alert_summary: str
    severity: str
    metrics: list[tuple[str, str, Callable[[float, float], float]]] = field(default_factory=list)  # svc, metric, f(base, m)
    errors: list[tuple[str, int, str, str]] = field(default_factory=list)   # svc, per-minute, level, message template
    deploys: list[tuple[str, float, str, str, str]] = field(default_factory=list)  # svc, minutes before alert, ver, author, summary
    blurb: str = ""


def _ramp(frm: float, to: float, over: float) -> Callable[[float, float], float]:
    return lambda base, m: frm + (to - frm) * min(max(m, 0) / over, 1.0)


def _mult(k: float, over: float = 1.0) -> Callable[[float, float], float]:
    return lambda base, m: base * (1 + (k - 1) * min(max(m, 0) / over, 1.0))


def _step(value: float) -> Callable[[float, float], float]:
    return lambda base, m: value


SCENARIOS: dict[str, Scenario] = {s.key: s for s in [
    Scenario(
        "bad_deploy", "Bad release breaks checkout", "bad_deploy", "checkout-api", "HighErrorRate",
        "checkout-api 5xx error rate above 5% for 5 minutes", "sev2",
        metrics=[("checkout-api", "error_rate", _step(18.0)), ("checkout-api", "latency_p95_ms", _mult(1.4)),
                 ("web-frontend", "error_rate", _ramp(0.2, 3.5, 2))],
        errors=[("checkout-api", 12, "error", "NullPointerException in PromoCalculator.apply (cart=<n>)"),
                ("web-frontend", 4, "warn", "checkout-api returned HTTP 500 for POST /checkout")],
        deploys=[("checkout-api", ONSET_MIN + 2, "v2.14.0", "dev-a", "Add promo code stacking; refactor PromoCalculator")],
        blurb="A release ships and errors start within minutes."),
    Scenario(
        "db_pool_exhaustion", "Inventory database pool exhausted", "db_saturation", "inventory-api",
        "HighLatencyP95", "inventory-api p95 latency above 1s for 5 minutes", "sev2",
        metrics=[("inventory-api", "db_connections", _ramp(6, 20, 3)), ("inventory-api", "latency_p95_ms", _ramp(70, 2400, 4)),
                 ("inventory-api", "error_rate", _ramp(0.3, 9, 4)), ("checkout-api", "error_rate", _ramp(0.4, 3, 4))],
        errors=[("inventory-api", 10, "error", "timeout acquiring connection from pool (max=20, waiting=<n>)"),
                ("inventory-api", 3, "warn", "slow query: SELECT qty FROM stock WHERE sku = $1 took <n>ms"),
                ("checkout-api", 6, "warn", "inventory-api request timed out after 2000ms")],
        blurb="No deploy; the connection pool saturates and queues build up."),
    Scenario(
        "memory_leak", "Search service slowly runs out of memory", "resource_exhaustion", "search-service",
        "MemoryHigh", "search-service memory above 90% and rising", "sev3",
        metrics=[("search-service", "mem_pct", _ramp(55, 98, 20)), ("search-service", "cpu_pct", _ramp(40, 78, 18)),
                 ("search-service", "latency_p95_ms", _ramp(110, 900, 20)), ("search-service", "error_rate", _ramp(0.2, 6, 20))],
        errors=[("search-service", 3, "warn", "GC overhead high: pause=<n>ms heap=<n>%"),
                ("search-service", 2, "error", "java.lang.OutOfMemoryError: Java heap space"),
                ("search-service", 1, "error", "container restarted: OOMKilled (exit code 137)")],
        blurb="Memory climbs steadily with no deploy; the container is OOM-killed."),
    Scenario(
        "dependency_outage", "Payment provider outage", "dependency_outage", "checkout-api", "PaymentFailures",
        "checkout-api payment authorisation failures above 10%", "sev1",
        metrics=[("payments-gateway", "error_rate", _ramp(0.3, 35, 2)), ("payments-gateway", "latency_p95_ms", _ramp(320, 5200, 2)),
                 ("checkout-api", "error_rate", _ramp(0.4, 12, 3))],
        errors=[("payments-gateway", 14, "error", "upstream provider timeout after 5000ms (provider=acme-pay)"),
                ("checkout-api", 10, "error", "payment authorisation failed: payments-gateway timeout")],
        deploys=[("web-frontend", ONSET_MIN + 35, "v5.8.2", "dev-c", "Copy changes on the home page")],
        blurb="The alert fires on checkout-api but the cause is a dependency. A harmless deploy is a red herring."),
    Scenario(
        "traffic_spike", "Flash-sale traffic spike", "traffic_spike", "web-frontend", "HighLatencyP95",
        "web-frontend p95 latency above 1s for 5 minutes", "sev2",
        metrics=[("web-frontend", "request_rate", _mult(6, 4)), ("web-frontend", "cpu_pct", _ramp(30, 92, 4)),
                 ("web-frontend", "latency_p95_ms", _ramp(90, 1400, 4)), ("web-frontend", "error_rate", _ramp(0.2, 6, 5)),
                 ("checkout-api", "request_rate", _mult(4, 4)), ("checkout-api", "cpu_pct", _ramp(35, 70, 5))],
        errors=[("web-frontend", 8, "warn", "request queue depth high (depth=<n>)"),
                ("web-frontend", 5, "error", "upstream connect timeout to checkout-api")],
        blurb="Request rate multiplies and the edge tier saturates."),
    Scenario(
        "cert_expiry", "Internal TLS certificate expired", "expired_certificate", "checkout-api", "HighErrorRate",
        "checkout-api 5xx error rate above 5% for 5 minutes", "sev2",
        metrics=[("checkout-api", "error_rate", _step(22.0)), ("inventory-api", "request_rate", _mult(0.1))],
        errors=[("checkout-api", 9, "error",
                 "x509: certificate has expired or is not yet valid (host=inventory-api.internal)")],
        deploys=[("search-service", ONSET_MIN + 8, "v4.1.1", "dev-b", "Tune analyzer cache size")],
        blurb="An abrupt step change with no deploy, load or resource change."),
    Scenario(
        "coincident_deploy", "Provider outage during an unrelated release", "dependency_outage", "checkout-api",
        "PaymentFailures", "checkout-api payment authorisation failures above 10%", "sev1",
        metrics=[("payments-gateway", "error_rate", _ramp(0.3, 35, 2)), ("payments-gateway", "latency_p95_ms", _ramp(320, 5200, 2)),
                 ("checkout-api", "error_rate", _ramp(0.4, 12, 3))],
        errors=[("payments-gateway", 14, "error", "upstream provider timeout after 5000ms (provider=acme-pay)"),
                ("checkout-api", 10, "error", "payment authorisation failed: payments-gateway timeout")],
        deploys=[("checkout-api", ONSET_MIN + 6, "v2.14.1", "dev-a", "Tweak cart summary wording")],
        blurb="A real dependency outage, but the alerting service also shipped a harmless release minutes earlier."),
    Scenario(
        "load_induced_oom", "Memory exhaustion caused by a traffic surge", "traffic_spike", "search-service",
        "MemoryHigh", "search-service memory above 90% and rising", "sev2",
        metrics=[("search-service", "request_rate", _mult(5, 4)), ("search-service", "mem_pct", _ramp(55, 97, 14)),
                 ("search-service", "cpu_pct", _ramp(40, 90, 10)), ("search-service", "latency_p95_ms", _ramp(110, 1500, 10)),
                 ("search-service", "error_rate", _ramp(0.2, 5, 12))],
        errors=[("search-service", 3, "warn", "GC overhead high: pause=<n>ms heap=<n>%"),
                ("search-service", 2, "error", "java.lang.OutOfMemoryError: Java heap space")],
        blurb="Memory alarms are the symptom; the cause is five times the normal request rate."),
    Scenario(
        "deploy_leak", "Release introduces a memory leak", "bad_deploy", "search-service", "MemoryHigh",
        "search-service memory above 90% and rising", "sev3",
        metrics=[("search-service", "mem_pct", _ramp(55, 98, 16)), ("search-service", "cpu_pct", _ramp(40, 70, 16)),
                 ("search-service", "latency_p95_ms", _ramp(110, 700, 16)), ("search-service", "error_rate", _ramp(0.2, 5, 16))],
        errors=[("search-service", 3, "warn", "GC overhead high: pause=<n>ms heap=<n>%"),
                ("search-service", 2, "error", "java.lang.OutOfMemoryError: Java heap space")],
        deploys=[("search-service", ONSET_MIN + 3, "v4.2.0", "dev-b", "Cache analyzer results in memory")],
        blurb="The same memory symptoms as a leak, but they began right after a release."),
]}

RUNBOOKS = [
    ("Roll back or fix forward after a bad release", "bad_deploy", None,
     "When errors begin right after a deploy: confirm the first error timestamp is after the deploy time, "
     "check the release notes and diff for the changed code path, then roll back to the previous version while the "
     "fix is prepared. Verify the error rate returns to baseline within 5 minutes. Keep the failing build for analysis."),
    ("Database connection pool saturation", "db_saturation", None,
     "Symptoms: 'timeout acquiring connection from pool', db_connections pinned at the pool maximum, rising latency. "
     "Find long-running or blocked queries (pg_stat_activity), look for missing indexes or a slow statement, check for "
     "connection leaks, then raise the pool size only after the cause is understood. Consider a pooler in front of Postgres."),
    ("Memory leak and OOM kills", "resource_exhaustion", None,
     "Symptoms: memory climbing steadily without a matching traffic increase, GC overhead warnings, OutOfMemoryError, "
     "OOMKilled restarts. Capture a heap profile before restarting if possible, restart or scale out to buy time, "
     "and review recent dependency or cache changes. Set a memory limit alert below the kill threshold."),
    ("Upstream dependency outage", "dependency_outage", None,
     "When the alerting service shows timeouts to a dependency, investigate the dependency first: its error rate, "
     "latency and its own logs. If the cause is an external provider, check their status page, enable degraded mode or "
     "queueing, and communicate impact. Do not roll back the caller; it is not the origin."),
    ("Sudden traffic spike", "traffic_spike", None,
     "Symptoms: request rate several times normal, CPU saturated, queue depth warnings. Confirm legitimate demand "
     "(campaign, sale) versus abuse, scale out the edge tier, enable rate limiting or a cache, and warn downstream "
     "services. Review autoscaling thresholds afterwards."),
    ("Expired or invalid TLS certificate", "expired_certificate", None,
     "Symptoms: 'x509: certificate has expired' or handshake failures, an abrupt step change in errors with no deploy "
     "and normal resource use. Identify the host in the message, renew and deploy the certificate, then restart "
     "clients that cache the old one. Add expiry alerts 30 days ahead."),
    ("Service stopped answering health checks", "service_down", None,
     "Symptoms: health probes fail with connection errors or timeouts, up drops to 0. Check whether the process or "
     "container is running and why it exited (logs, exit code, OOM kill), whether a recent deploy or config change "
     "preceded it, and whether the network path or DNS changed. Restart or roll back, then confirm probes recover."),
    ("Sandbox paused or stopped by the platform", "sandbox_paused", None,
     "Symptoms: every URL returns an empty 503 from the platform, the sandbox status is paused, and no application "
     "headers appear. Free-tier sandboxes auto-pause when idle and do not wake on a request. Resume it "
     "(for AgentPG: agentpg sandbox resume <sandbox-id>), then unlock stored provider keys in the app. Ask the "
     "platform whether auto-pause can be disabled on your plan."),
    ("Database unreachable while the service is up", "database_unreachable", None,
     "Symptoms: db_up is 0 and readiness fails (waking-database) while health checks still pass. The database may be "
     "scaled to zero, paused, or unreachable from the service. Check the instance status, credentials and network "
     "rules, wait for a waking database, and confirm connections recover."),
    ("Collection tier overloaded", "ingest_overload", None,
     "Symptoms: the ingest gateway answers 429 or times out, p95 batch latency climbs, senders buffer and their data "
     "arrives late so sensors look stale. Check for a flood (a misconfigured sender, a retry storm) versus a slow "
     "database, add gateway replicas or raise the write concurrency, ask noisy senders to back off, and confirm the "
     "senders' buffers drain. Watch the buffer size: when it is full, data is dropped."),
    ("Sensors stopped reporting", "sensor_fleet_outage", None,
     "Symptoms: a share of sensors is offline. If one district is dark while the rest is healthy, suspect shared "
     "infrastructure there: power, a backhaul link or a local gateway. If the loss is spread out, suspect the "
     "collection path or a credential that expired. Check the last-seen times, the local gateway and the senders' "
     "logs, restore the link, and confirm sensors report again."),
    ("Sensors sending bad data", "data_quality", None,
     "Symptoms: many readings rejected, values outside physical limits, or sensors repeating the same value. "
     "Identify which types and districts are affected, check for a firmware release, a calibration drift or a "
     "failing power supply, quarantine the affected sensors from downstream decisions, and roll back or recalibrate."),
]


def _fill(template: str, rng: random.Random) -> str:
    out = template
    for token, gen in (("<ms>", lambda: str(rng.randint(8, 400))), ("<ip>", lambda: str(rng.randint(2, 250))),
                       ("<id>", lambda: hashlib.sha1(str(rng.random()).encode()).hexdigest()[:10]),
                       ("<amt>", lambda: f"{rng.randint(5, 300)}.{rng.randint(0, 99):02d}"),
                       ("<n>", lambda: str(rng.randint(1, 99))), ("<sku>", lambda: f"SKU-{rng.randint(1000, 9999)}")):
        while token in out:
            out = out.replace(token, gen(), 1)
    return out


def _iso(ts: datetime) -> str:
    return ts.isoformat()


def reset_telemetry(conn) -> None:
    """Remove all telemetry (logs, metrics, deploys). Incidents, runs and reports are kept."""
    conn.execute("DELETE FROM log_event")
    conn.execute("DELETE FROM metric_point")
    conn.execute("DELETE FROM deploy")


def seed_fleet(conn) -> None:
    for name, d in FLEET.items():
        ingest.upsert_service(conn, name, owner=d["owner"], tier=d["tier"], description=d["description"],
                              depends_on=d["depends_on"])


def seed_runbooks(conn) -> int:
    from . import retrieval
    n = 0
    for title, category, service, body in RUNBOOKS:
        row = conn.execute("INSERT INTO runbook (title, category, service, body, embedding) VALUES (%s,%s,%s,%s,%s) "
                           "ON CONFLICT (title) DO NOTHING RETURNING id",
                           (title, category, service, body, retrieval.embed_one(f"{title}. {body}"))).fetchone()
        n += 1 if row else 0
    return n


def _batches(items: list, size: int = CHUNK):
    for i in range(0, len(items), size):
        yield items[i:i + size]


def generate(conn, scenario: Scenario | None, *, now: datetime | None = None, seed: int = 7) -> None:
    """Write WINDOW_MIN minutes of telemetry ending at `now`, with the scenario's failure overlaid."""
    now = (now or datetime.now(UTC)).replace(second=0, microsecond=0)
    start = now - timedelta(minutes=WINDOW_MIN)
    onset = now - timedelta(minutes=ONSET_MIN)
    rng = random.Random(seed)
    seed_fleet(conn)
    overlay = {(s, m): f for s, m, f in (scenario.metrics if scenario else [])}
    for name, d in FLEET.items():
        points, logs = [], []
        for i in range(WINDOW_MIN + 1):
            ts = start + timedelta(minutes=i)
            m = (ts - onset).total_seconds() / 60.0
            for metric, base in d["base"].items():
                value = base * (1 + rng.uniform(-0.03, 0.03)) if metric != "db_connections_max" else base
                f = overlay.get((name, metric))
                if f and m >= 0:
                    value = f(base, m) * (1 + rng.uniform(-0.02, 0.02)) if metric != "db_connections_max" else value
                if metric.endswith("_pct"):
                    value = min(value, 100.0)
                points.append({"name": metric, "value": round(value, 3), "ts": _iso(ts)})
            for _ in range(rng.randint(1, 2)):
                logs.append({"ts": _iso(ts + timedelta(seconds=rng.randint(0, 59))), "level": "info",
                             "message": _fill(rng.choice(INFO_LINES[name]), rng)})
        for batch in _batches(points):
            ingest.ingest_metrics(conn, name, batch)
        if scenario:
            for svc, per_min, level, template in scenario.errors:
                if svc != name:
                    continue
                for i in range(WINDOW_MIN + 1):
                    ts = start + timedelta(minutes=i)
                    m = (ts - onset).total_seconds() / 60.0
                    if m < 0:
                        continue
                    scale = min(1.0, 0.4 + m / 6.0)  # errors build up over the first minutes
                    for _ in range(max(1, round(per_min * scale * rng.uniform(0.7, 1.2)))):
                        logs.append({"ts": _iso(ts + timedelta(seconds=rng.randint(0, 59))), "level": level,
                                     "message": _fill(template, rng),
                                     "fields": {"request_id": _fill("<id>", rng)}})
        for batch in _batches(logs):
            ingest.ingest_logs(conn, name, batch)
    for svc, days, version, summary in OLD_DEPLOYS:
        ingest.ingest_deploy(conn, svc, {"version": version, "author": "release-bot", "summary": summary,
                                         "git_sha": hashlib.sha1(f"{svc}{version}".encode()).hexdigest()[:10],
                                         "ts": _iso(now - timedelta(days=days))})
    if scenario:
        for svc, mins_before_alert, version, author, summary in scenario.deploys:
            ingest.ingest_deploy(conn, svc, {"version": version, "author": author, "summary": summary,
                                             "git_sha": hashlib.sha1(f"{svc}{version}".encode()).hexdigest()[:10],
                                             "ts": _iso(now - timedelta(minutes=mins_before_alert))})


def trigger(conn, key: str, *, now: datetime | None = None, seed: int = 7) -> dict:
    """Reset telemetry, generate a fresh window with the scenario, and fire its alert (opening an incident)."""
    if key not in SCENARIOS:
        raise ValueError(f"unknown scenario {key!r}; choose one of {', '.join(SCENARIOS)}")
    sc = SCENARIOS[key]
    now = (now or datetime.now(UTC)).replace(second=0, microsecond=0)
    reset_telemetry(conn)
    seed_runbooks(conn)
    generate(conn, sc, now=now, seed=seed)
    alert = ingest.raise_alert(conn, sc.service, sc.alert_name, summary=sc.alert_summary, severity=sc.severity,
                               source="simulator", fired_at=now, labels={"scenario_hint": "hidden"})
    conn.execute("INSERT INTO sim_truth (incident_id, scenario, category) VALUES (%s,%s,%s) "
                 "ON CONFLICT (incident_id) DO NOTHING", (alert["incident_id"], sc.key, sc.category))
    return {**alert, "service": sc.service, "title": sc.title}


def baseline(conn, *, now: datetime | None = None, seed: int = 7) -> None:
    reset_telemetry(conn)
    seed_runbooks(conn)
    generate(conn, None, now=now, seed=seed)


def catalog() -> list[dict]:
    return [{"key": s.key, "title": s.title, "service": s.service, "blurb": s.blurb, "severity": s.severity}
            for s in SCENARIOS.values()]
