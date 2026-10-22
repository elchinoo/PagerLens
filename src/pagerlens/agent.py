"""pagerlens-agent: pull health and metrics from your services and push them to PagerLens.

For targets that cannot push their own telemetry (or that you want watched from outside): HTTP health probes,
Prometheus /metrics scraping, and, where this machine is logged in to AgentPG, sandbox status. Everything goes to the
ordinary ingest API with an ingest-only token, or, where the ecosystem identity provider is set up, with a token the agent
mints itself (scope `pagerlens.ingest`, see below). Secrets come from environment variables named in the config, never
from the file itself, and are never printed.

Pushing with the identity provider instead of a hand-copied token: set PAGERLENS_AGENT_OIDC_ISSUER,
PAGERLENS_AGENT_OIDC_CLIENT_ID and PAGERLENS_AGENT_OIDC_CLIENT_SECRET (or ..._SECRET_FILE) for a `service` client allowed the
scope `pagerlens.ingest`. A static token (token_env) still works and wins when both are set.

    pagerlens-agent run  config.yaml            # loop forever
    pagerlens-agent once config.yaml --dry-run  # one cycle, print what would be sent, send nothing
"""
import argparse
import os
import re
import subprocess
import sys
import time
from collections import deque
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import httpx
import yaml
from apgkit.auth import TokenError, TokenSource
from apgkit.config import read_secret
from prometheus_client.parser import text_string_to_metric_families

NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")
ENV = re.compile(r"^[A-Z_][A-Z0-9_]{0,63}$")
SANDBOX = re.compile(r"^sbx-[a-z0-9]{4,40}$")
MAX_BUFFER = 5000
WINDOW = 12  # probes kept per target for error_rate / latency_p95_ms


class ConfigError(ValueError):
    pass


@dataclass
class Target:
    name: str
    depends_on: list[str] = field(default_factory=list)
    owner: str | None = None
    tier: str | None = None
    description: str | None = None
    probes: list[dict] = field(default_factory=list)
    scrapes: list[dict] = field(default_factory=list)
    sandboxes: list[dict] = field(default_factory=list)
    alert_after: int = 3
    alert_name: str = "ServiceDown"
    alert_severity: str = "sev2"


@dataclass
class Config:
    url: str
    token_env: str
    interval: int
    targets: list[Target]


# ---- configuration --------------------------------------------------------------------------------

def _url(value, where: str) -> str:
    parts = urlsplit(str(value or ""))
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ConfigError(f"{where}: a full http(s) URL is required")
    if parts.username or parts.password:
        raise ConfigError(f"{where}: do not put credentials in the URL; use token_env")
    return str(value)


def _env_name(value, where: str) -> str | None:
    if value is None:
        return None
    if not ENV.match(str(value)):
        raise ConfigError(f"{where}: token_env must be the NAME of an environment variable (like MY_TOKEN), not the secret itself")
    return str(value)


def load_config(raw: dict) -> Config:
    if not isinstance(raw, dict):
        raise ConfigError("the config must be a YAML mapping")
    pl = raw.get("pagerlens") or {}
    url = _url(pl.get("url"), "pagerlens.url").rstrip("/")
    token_env = _env_name(pl.get("token_env", "PAGERLENS_TOKEN"), "pagerlens") or "PAGERLENS_TOKEN"
    interval = int(raw.get("interval_seconds", 30))
    if interval < 5:
        raise ConfigError("interval_seconds must be at least 5")
    targets = []
    for i, t in enumerate(raw.get("targets") or []):
        where = f"targets[{i}]"
        name = str(t.get("name", "")).lower()
        if not NAME.match(name):
            raise ConfigError(f"{where}: name must be lowercase letters, digits, '.', '_' or '-'")
        alert = t.get("alert") or {}
        tgt = Target(name=name, depends_on=[str(d) for d in t.get("depends_on", [])], owner=t.get("owner"), tier=t.get("tier"),
                     description=t.get("description"), alert_after=int(alert.get("after_failures", 3)),
                     alert_name=str(alert.get("name", "ServiceDown"))[:100], alert_severity=str(alert.get("severity", "sev2")))
        for d in tgt.depends_on:
            if not NAME.match(d):
                raise ConfigError(f"{where}: depends_on entry {d!r} is not a valid service name")
        for j, p in enumerate(t.get("probes") or []):
            if p.get("type", "http") != "http":
                raise ConfigError(f"{where}.probes[{j}]: only type 'http' exists")
            tgt.probes.append({"url": _url(p.get("url"), f"{where}.probes[{j}].url"), "expect": int(p.get("expect_status", 200)),
                               "timeout": float(p.get("timeout", 10)), "token_env": _env_name(p.get("token_env"), f"{where}.probes[{j}]")})
        for j, p in enumerate(t.get("scrape") or []):
            if p.get("type", "prometheus") != "prometheus" or p.get("preset", "http-standard") != "http-standard":
                raise ConfigError(f"{where}.scrape[{j}]: only type 'prometheus' with preset 'http-standard' exists")
            tgt.scrapes.append({"url": _url(p.get("url"), f"{where}.scrape[{j}].url"), "timeout": float(p.get("timeout", 10)),
                                "token_env": _env_name(p.get("token_env"), f"{where}.scrape[{j}]"),
                                "mem_limit_mb": float(p["mem_limit_mb"]) if p.get("mem_limit_mb") else None})
        for j, p in enumerate(t.get("agentpg") or []):
            if not SANDBOX.match(str(p.get("sandbox_id", ""))):
                raise ConfigError(f"{where}.agentpg[{j}]: sandbox_id must look like sbx-1234abcd")
            tgt.sandboxes.append({"sandbox_id": p["sandbox_id"], "command": str(p.get("command", "agentpg"))})
        if not (tgt.probes or tgt.scrapes or tgt.sandboxes):
            raise ConfigError(f"{where}: add at least one of probes, scrape or agentpg")
        targets.append(tgt)
    if not targets:
        raise ConfigError("no targets configured")
    return Config(url, token_env, interval, targets)


# ---- collection -----------------------------------------------------------------------------------

@dataclass
class Batch:
    metrics: list[dict] = field(default_factory=list)
    logs: list[dict] = field(default_factory=list)
    deploys: list[dict] = field(default_factory=list)
    alerts: list[dict] = field(default_factory=list)


def _p95(values: list[float]) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(0.95 * len(ordered)))]


def _bearer(token_env: str | None) -> dict:
    token = os.environ.get(token_env or "", "")
    return {"Authorization": f"Bearer {token}"} if token else {}


class ProbeState:
    def __init__(self):
        self.window: deque = deque(maxlen=WINDOW)
        self.failures = 0
        self.alerted = False


def run_probe(client: httpx.Client, target: Target, probe: dict, st: ProbeState, now: float, batch: Batch) -> None:
    started, ok, reason = time.perf_counter(), False, ""
    try:
        r = client.get(probe["url"], headers=_bearer(probe["token_env"]), timeout=probe["timeout"])
        ok = r.status_code == probe["expect"]
        reason = "" if ok else f"HTTP {r.status_code} (expected {probe['expect']})"
    except httpx.TimeoutException:
        reason = f"timeout after {probe['timeout']:g}s"
    except httpx.HTTPError as exc:
        reason = f"connection error: {type(exc).__name__}"
    ms = (time.perf_counter() - started) * 1000 if ok else probe["timeout"] * 1000
    st.window.append((ok, ms))
    batch.metrics += [{"name": "up", "value": 1.0 if ok else 0.0},
                      {"name": "error_rate", "value": 100.0 * sum(1 for o, _ in st.window if not o) / len(st.window)},
                      {"name": "latency_p95_ms", "value": _p95([m for _, m in st.window])}]
    if ok:
        st.failures, st.alerted = 0, False
        return
    st.failures += 1
    batch.logs.append({"level": "error", "message": f"health probe failed: {reason}", "fields": {"probe": "http"}})
    if st.failures >= target.alert_after and not st.alerted:
        st.alerted = True
        batch.alerts.append({"service": target.name, "name": target.alert_name, "severity": target.alert_severity, "source": "pagerlens-agent",
                             "summary": f"{target.name} failed {st.failures} health checks in a row (last: {reason})"})


class ScrapeState:
    def __init__(self):
        self.prev: dict | None = None
        self.version: str | None = None


def _hist_p95(prev: dict, cur: dict) -> float | None:
    """95th percentile (ms) of requests made between two scrapes, from cumulative bucket counts."""
    les = sorted(cur, key=lambda x: float("inf") if x == "+Inf" else float(x))
    deltas = [(le, cur[le] - prev.get(le, 0.0)) for le in les]
    total = deltas[-1][1] if deltas else 0
    if total <= 0 or any(d < 0 for _, d in deltas):
        return None
    target, last_bound, last_count = 0.95 * total, 0.0, 0.0
    for le, count in deltas:
        if count >= target:
            bound = float(le) if le != "+Inf" else last_bound
            span = max(count - last_count, 1e-9)
            return (last_bound + (bound - last_bound) * ((target - last_count) / span)) * 1000
        last_bound, last_count = float(le) if le != "+Inf" else last_bound, count
    return None


def run_scrape(client: httpx.Client, target: Target, sc: dict, st: ScrapeState, now: float, batch: Batch) -> None:
    try:
        r = client.get(sc["url"], headers=_bearer(sc["token_env"]), timeout=sc["timeout"])
        r.raise_for_status()
        families = list(text_string_to_metric_families(r.text))
    except (httpx.HTTPError, ValueError) as exc:
        batch.logs.append({"level": "error", "message": f"metrics scrape failed: {type(exc).__name__}", "fields": {"probe": "scrape"}})
        return
    cur = {"t": now, "total": 0.0, "errors": 0.0, "buckets": {}, "cpu": None}
    version = None
    for fam in families:
        for s in fam.samples:
            if s.name == "http_requests_total":
                cur["total"] += s.value
                if str(s.labels.get("status", "")).startswith("5"):
                    cur["errors"] += s.value
            elif s.name == "http_request_duration_seconds_bucket":
                cur["buckets"][s.labels["le"]] = cur["buckets"].get(s.labels["le"], 0.0) + s.value
            elif s.name == "db_up":
                batch.metrics.append({"name": "db_up", "value": s.value})
            elif s.name == "process_resident_memory_bytes":
                mb = s.value / 1048576
                batch.metrics.append({"name": "mem_rss_mb", "value": mb})
                if sc["mem_limit_mb"]:
                    batch.metrics.append({"name": "mem_pct", "value": min(100.0, 100 * mb / sc["mem_limit_mb"])})
            elif s.name == "process_cpu_seconds_total":
                cur["cpu"] = s.value
            elif s.name == "app_info":
                version = s.labels.get("version")
    prev = st.prev
    if prev and now > prev["t"]:
        dt, dtotal, derr = now - prev["t"], cur["total"] - prev["total"], cur["errors"] - prev["errors"]
        if dtotal >= 0 and derr >= 0:
            batch.metrics.append({"name": "request_rate", "value": dtotal / dt})
            batch.metrics.append({"name": "error_rate", "value": 100.0 * derr / dtotal if dtotal else 0.0})
            if (p := _hist_p95(prev["buckets"], cur["buckets"])) is not None:
                batch.metrics.append({"name": "latency_p95_ms", "value": p})
        if cur["cpu"] is not None and prev["cpu"] is not None and cur["cpu"] >= prev["cpu"]:
            batch.metrics.append({"name": "cpu_pct", "value": min(100.0, 100 * (cur["cpu"] - prev["cpu"]) / dt)})
    st.prev = cur
    if version:
        if st.version and version != st.version:   # the first sighting is only a baseline
            batch.deploys.append({"version": version, "author": "pagerlens-agent", "summary": "detected: app_info version changed"})
        st.version = version


def run_sandbox_status(target: Target, sb: dict, batch: Batch, runner=subprocess.run) -> None:
    """Experimental: needs the agentpg CLI logged in on this machine. Parses `agentpg sandbox status <id>`."""
    try:
        out = runner([sb["command"], "sandbox", "status", sb["sandbox_id"]], capture_output=True, text=True, timeout=30, check=False).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        batch.logs.append({"level": "error", "message": f"agentpg status failed: {type(exc).__name__}", "fields": {"probe": "agentpg"}})
        return
    status = re.search(r"^Status:\s+(\w+)", out, re.M)
    mem = re.search(r"Memory:\s+([\d.]+)%", out)
    running = bool(status and status.group(1).lower() == "running")
    batch.metrics.append({"name": "sandbox_running", "value": 1.0 if running else 0.0})
    if mem:
        batch.metrics.append({"name": "mem_pct", "value": float(mem.group(1))})
    if status and not running:
        batch.logs.append({"level": "error", "message": f"sandbox is {status.group(1)} (the platform may have auto-paused it)", "fields": {"probe": "agentpg"}})
        batch.alerts.append({"service": target.name, "name": "SandboxNotRunning", "severity": "sev3", "source": "pagerlens-agent",
                             "summary": f"{target.name}: sandbox {sb['sandbox_id']} is {status.group(1)}"})


# ---- delivery -------------------------------------------------------------------------------------

def token_source_from_env() -> TokenSource | None:
    """A client_credentials token source when PAGERLENS_AGENT_OIDC_ISSUER / _CLIENT_ID / _CLIENT_SECRET are all set."""
    issuer = os.environ.get("PAGERLENS_AGENT_OIDC_ISSUER", "").strip()
    client_id = os.environ.get("PAGERLENS_AGENT_OIDC_CLIENT_ID", "").strip()
    if not (issuer and client_id and read_secret("PAGERLENS_AGENT_OIDC_CLIENT_SECRET")):
        return None
    return TokenSource(issuer, client_id, lambda: read_secret("PAGERLENS_AGENT_OIDC_CLIENT_SECRET"), scope="pagerlens.ingest")


class Pusher:
    def __init__(self, cfg: Config, client: httpx.Client, dry_run: bool = False, source: TokenSource | None = None):
        self.cfg, self.client, self.dry = cfg, client, dry_run
        self.pending: deque = deque(maxlen=MAX_BUFFER)
        static = os.environ.get(cfg.token_env, "")
        self.source = None if static else source
        self.headers = {"Authorization": f"Bearer {static}"}

    def _headers(self) -> dict:
        """The static token if one is set, else a (cached, refreshed) token from the identity provider."""
        return self.source.headers() if self.source else self.headers

    def queue(self, path: str, body: dict) -> None:
        self.pending.append((path, body))

    def flush(self) -> int:
        sent = 0
        while self.pending:
            path, body = self.pending[0]
            if self.dry:
                print(f"[dry-run] POST {path} {str(body)[:200]}")
            else:
                try:
                    r = self.client.post(self.cfg.url + path, headers=self._headers(), json=body, timeout=15)
                except TokenError as exc:
                    print(f"could not get a token from the identity provider ({exc}); will retry", file=sys.stderr)
                    break
                except httpx.HTTPError as exc:
                    print(f"push failed ({type(exc).__name__}); will retry", file=sys.stderr)
                    break
                if r.status_code in (401, 403):
                    raise SystemExit("PagerLens rejected the token (401/403): check PAGERLENS_TOKEN (an 'ingest' token) or the service client's 'pagerlens.ingest' scope")
                if r.status_code >= 500 or r.status_code == 429:
                    print(f"push got HTTP {r.status_code}; will retry", file=sys.stderr)
                    break
                if r.status_code >= 400:
                    print(f"dropped one item: HTTP {r.status_code} {r.text[:120]}", file=sys.stderr)
            self.pending.popleft()
            sent += 1
        return sent


class Agent:
    def __init__(self, cfg: Config, client: httpx.Client, pusher: Pusher):
        self.cfg, self.client, self.pusher = cfg, client, pusher
        self.state = {t.name: {"probes": [ProbeState() for _ in t.probes], "scrapes": [ScrapeState() for _ in t.scrapes]} for t in cfg.targets}
        self.registered = False

    def register(self) -> None:
        for t in self.cfg.targets:
            self.pusher.queue("/api/ingest/services", {"name": t.name, "depends_on": t.depends_on, "owner": t.owner, "tier": t.tier,
                                                       "description": t.description})
        self.registered = True

    def cycle(self, now: float | None = None) -> None:
        now = now if now is not None else time.time()
        if not self.registered:
            self.register()
        for t in self.cfg.targets:
            batch = Batch()
            for p, st in zip(t.probes, self.state[t.name]["probes"], strict=True):
                run_probe(self.client, t, p, st, now, batch)
            for sc, st in zip(t.scrapes, self.state[t.name]["scrapes"], strict=True):
                run_scrape(self.client, t, sc, st, now, batch)
            for sb in t.sandboxes:
                run_sandbox_status(t, sb, batch)
            if batch.metrics:
                self.pusher.queue("/api/ingest/metrics", {"service": t.name, "points": batch.metrics})
            if batch.logs:
                self.pusher.queue("/api/ingest/logs", {"service": t.name, "events": batch.logs})
            for d in batch.deploys:
                self.pusher.queue("/api/ingest/deploys", {"service": t.name, **d})
            for a in batch.alerts:
                self.pusher.queue("/api/ingest/alerts", a)
        self.pusher.flush()


def _client() -> httpx.Client:  # indirection so tests can inject a mock transport
    return httpx.Client(follow_redirects=False)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="pagerlens-agent", description=__doc__.split("\n\n")[0])
    ap.add_argument("command", choices=["run", "once"])
    ap.add_argument("config")
    ap.add_argument("--dry-run", action="store_true", help="print what would be sent and send nothing (no token needed)")
    args = ap.parse_args(argv)
    try:
        with open(args.config) as fh:
            cfg = load_config(yaml.safe_load(fh))
    except (OSError, yaml.YAMLError, ConfigError, ValueError, TypeError) as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2
    source = token_source_from_env()
    if not args.dry_run and not os.environ.get(cfg.token_env) and source is None:
        print(f"set the environment variable {cfg.token_env} to an ingest-scope PagerLens token "
              "(or the PAGERLENS_AGENT_OIDC_* variables to get one from the identity provider)", file=sys.stderr)
        return 2
    with _client() as client:
        agent = Agent(cfg, client, Pusher(cfg, client, dry_run=args.dry_run, source=source))
        if args.command == "once":
            agent.cycle()
            return 0
        print(f"pagerlens-agent watching {len(cfg.targets)} target(s) every {cfg.interval}s, sending to {cfg.url}", flush=True)
        try:
            while True:
                started = time.monotonic()
                agent.cycle()
                time.sleep(max(0.0, cfg.interval - (time.monotonic() - started)))
        except KeyboardInterrupt:
            return 0


if __name__ == "__main__":
    raise SystemExit(main())
