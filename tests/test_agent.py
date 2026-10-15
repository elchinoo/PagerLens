import json
import subprocess

import httpx
import pytest

from pagerlens import agent

SECRET = "tok-" + "s3cr3t-value-123"  # pragma: allowlist secret


def cfg_dict(**target):
    t = {"name": "web", "probes": [{"url": "https://web.example/healthz"}]} | target
    return {"pagerlens": {"url": "https://pl.example"}, "interval_seconds": 10, "targets": [t]}


def make_agent(handler, monkeypatch, cfg=None, dry=False):
    monkeypatch.setenv("PAGERLENS_TOKEN", SECRET)
    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    config = agent.load_config(cfg or cfg_dict())
    return agent.Agent(config, client, agent.Pusher(config, client, dry_run=dry)), config


class World:
    """A fake monitored service plus a fake PagerLens, recording what the agent sent."""

    def __init__(self):
        self.target_status, self.target_body, self.sent = 200, "", []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if request.url.host == "pl.example":
            self.sent.append((request.url.path, json.loads(request.content), request.headers.get("authorization")))
            return httpx.Response(200, json={})
        if self.target_status == "timeout":
            raise httpx.ReadTimeout("slow", request=request)
        return httpx.Response(self.target_status, text=self.target_body)

    def posted(self, path):
        return [b for p, b, _ in self.sent if p == path]


# ---- configuration -------------------------------------------------------------------------------

@pytest.mark.parametrize("mutate,message", [
    (lambda c: c["pagerlens"].update(url="https://user:pw@pl.example"), "credentials"),
    (lambda c: c["pagerlens"].update(url="ftp://x"), r"http\(s\)"),
    (lambda c: c["pagerlens"].update(token_env="sk-abcdef123456"), "NAME of an environment variable"),
    (lambda c: c.update(interval_seconds=1), "at least 5"),
    (lambda c: c["targets"][0].update(name="Bad Name"), "name must be"),
    (lambda c: c["targets"][0].update(probes=[{"url": "https://u:p@x/"}]), "credentials"),
    (lambda c: c["targets"][0].update(probes=[], agentpg=[{"sandbox_id": "sbx-1; rm -rf /"}]), "sbx-"),
    (lambda c: c["targets"][0].update(probes=[]), "at least one"),
    (lambda c: c["targets"][0].update(depends_on=["Not Valid"]), "valid service name"),
    (lambda c: c.update(targets=[]), "no targets"),
])
def test_bad_configuration_is_refused_with_a_clear_message(mutate, message):
    c = cfg_dict()
    mutate(c)
    with pytest.raises(agent.ConfigError, match=message):
        agent.load_config(c)


# ---- probes and alerts -----------------------------------------------------------------------------

def test_healthy_probe_reports_up_and_zero_errors(monkeypatch):
    w = World()
    a, _ = make_agent(w, monkeypatch)
    a.cycle(now=100)
    m = {p["name"]: p["value"] for p in w.posted("/api/ingest/metrics")[0]["points"]}
    assert m["up"] == 1.0 and m["error_rate"] == 0.0 and m["latency_p95_ms"] >= 0
    assert not w.posted("/api/ingest/alerts") and not w.posted("/api/ingest/logs")
    assert w.posted("/api/ingest/services")[0]["name"] == "web"


def test_outage_logs_each_failure_and_alerts_once_then_again_after_recovery(monkeypatch):
    w = World()
    a, _ = make_agent(w, monkeypatch)
    w.target_status = 503
    for i in range(5):
        a.cycle(now=100 + i)
    alerts = w.posted("/api/ingest/alerts")
    assert len(alerts) == 1 and alerts[0]["name"] == "ServiceDown" and "HTTP 503" in alerts[0]["summary"]
    assert alerts[0]["service"] == "web" and alerts[0]["source"] == "pagerlens-agent"
    logs = [e for b in w.posted("/api/ingest/logs") for e in b["events"]]
    assert len(logs) == 5 and all(e["level"] == "error" and "HTTP 503" in e["message"] for e in logs)
    last = w.posted("/api/ingest/metrics")[-1]["points"]
    assert {p["name"]: p["value"] for p in last}["error_rate"] == 100.0
    w.target_status = 200
    a.cycle(now=200)
    w.target_status = "timeout"
    for i in range(3):
        a.cycle(now=300 + i)
    assert len(w.posted("/api/ingest/alerts")) == 2
    assert any("timeout after" in e["message"] for b in w.posted("/api/ingest/logs") for e in b["events"])


def test_redirects_are_not_followed(monkeypatch):
    w = World()
    a, _ = make_agent(w, monkeypatch)
    w.target_status = 302
    a.cycle(now=1)
    assert "HTTP 302" in w.posted("/api/ingest/logs")[0]["events"][0]["message"]


def test_target_token_is_sent_to_the_target_only_and_never_leaks(monkeypatch, capsys):
    seen = []

    def handler(request):
        seen.append((request.url.host, request.headers.get("authorization")))
        return httpx.Response(200, json={}) if request.url.host == "pl.example" else httpx.Response(503)

    monkeypatch.setenv("TARGET_TOKEN", SECRET + "-target")
    cfg = cfg_dict(probes=[{"url": "https://web.example/healthz", "token_env": "TARGET_TOKEN"}])
    a, _ = make_agent(handler, monkeypatch, cfg)
    for i in range(3):
        a.cycle(now=i)
    web = {auth for host, auth in seen if host == "web.example"}
    pl = {auth for host, auth in seen if host == "pl.example"}
    assert web == {f"Bearer {SECRET}-target"} and pl == {f"Bearer {SECRET}"}   # each host only ever sees its own token
    out = capsys.readouterr()
    assert SECRET not in out.out + out.err


# ---- Prometheus scraping ------------------------------------------------------------------------------

def prom(total_ok, total_err, buckets, version="1.0", cpu=1.0):
    b = "\n".join(f'http_request_duration_seconds_bucket{{app="x",route="/a",le="{le}"}} {n}' for le, n in buckets)
    return f"""# TYPE http_requests_total counter
http_requests_total{{app="x",method="GET",route="/a",status="200"}} {total_ok}
http_requests_total{{app="x",method="GET",route="/a",status="500"}} {total_err}
{b}
db_up{{app="x"}} 1
process_resident_memory_bytes 104857600
process_cpu_seconds_total {cpu}
app_info{{app="x",version="{version}"}} 1
"""


def test_scrape_derives_rate_error_rate_latency_cpu_and_deploys(monkeypatch):
    w = World()
    cfg = cfg_dict(probes=[], scrape=[{"url": "https://web.example/metrics", "mem_limit_mb": 200}])
    a, _ = make_agent(w, monkeypatch, cfg)
    w.target_body = prom(100, 0, [("0.1", 0), ("0.5", 0), ("+Inf", 0)])
    a.cycle(now=0)                                          # baseline: only gauges, no rates yet
    first = {p["name"]: p["value"] for p in w.posted("/api/ingest/metrics")[0]["points"]}
    assert first["db_up"] == 1 and first["mem_rss_mb"] == pytest.approx(100) and first["mem_pct"] == pytest.approx(50)
    assert "request_rate" not in first and not w.posted("/api/ingest/deploys")
    w.target_body = prom(150, 10, [("0.1", 30), ("0.5", 57), ("+Inf", 60)], cpu=6.0)
    a.cycle(now=10)
    second = {p["name"]: p["value"] for p in w.posted("/api/ingest/metrics")[1]["points"]}
    assert second["request_rate"] == pytest.approx(6.0)                     # 60 requests in 10 s
    assert second["error_rate"] == pytest.approx(100 * 10 / 60)
    assert 100 < second["latency_p95_ms"] <= 500                              # 95th of 60 falls in the 0.1-0.5 s bucket
    assert second["cpu_pct"] == pytest.approx(50.0)                           # 5 CPU-seconds over 10 s
    w.target_body = prom(160, 10, [("0.1", 40), ("0.5", 67), ("+Inf", 70)], version="1.1")
    a.cycle(now=20)
    assert [d["version"] for d in w.posted("/api/ingest/deploys")] == ["1.1"]  # version CHANGE, never the first sighting


def test_counter_resets_are_skipped_and_scrape_failures_are_logged(monkeypatch):
    w = World()
    cfg = cfg_dict(probes=[], scrape=[{"url": "https://web.example/metrics"}])
    a, _ = make_agent(w, monkeypatch, cfg)
    w.target_body = prom(1000, 0, [("+Inf", 1000)])
    a.cycle(now=0)
    w.target_body = prom(5, 0, [("+Inf", 5)])               # the app restarted
    a.cycle(now=10)
    assert "request_rate" not in {p["name"] for b in w.posted("/api/ingest/metrics")[1:] for p in b["points"]}
    w.target_status = 500
    a.cycle(now=20)
    assert any("scrape failed" in e["message"] for b in w.posted("/api/ingest/logs") for e in b["events"])


# ---- AgentPG sandbox status (experimental) ---------------------------------------------------------------

RUNNING = """ID:         sbx-52b5354c28c6
Name:       trustdesk
Status:     running
Auto-pause: true

Metrics (current):
  Memory:       17.3%
"""


def run_status(output):
    t = agent.Target(name="trustdesk")
    batch = agent.Batch()
    agent.run_sandbox_status(t, {"sandbox_id": "sbx-52b5354c28c6", "command": "agentpg"}, batch,
                             runner=lambda *a, **k: subprocess.CompletedProcess(a, 0, stdout=output))
    return batch


def test_sandbox_status_is_parsed_and_a_pause_raises_an_alert():
    ok = run_status(RUNNING)
    assert {m["name"]: m["value"] for m in ok.metrics} == {"sandbox_running": 1.0, "mem_pct": 17.3} and not ok.alerts
    paused = run_status(RUNNING.replace("running", "paused"))
    assert paused.metrics[0]["value"] == 0.0
    assert paused.alerts[0]["name"] == "SandboxNotRunning" and "auto-paused" in paused.logs[0]["message"]


# ---- delivery ---------------------------------------------------------------------------------------------

def test_rejected_token_stops_the_agent_without_printing_it(monkeypatch, capsys):
    a, _ = make_agent(lambda r: httpx.Response(401) if r.url.host == "pl.example" else httpx.Response(200), monkeypatch)
    with pytest.raises(SystemExit) as exc:
        a.cycle(now=1)
    assert SECRET not in str(exc.value) and "401/403" in str(exc.value)


def test_server_errors_are_retried_not_lost(monkeypatch):
    state = {"down": True, "got": []}

    def handler(request):
        if request.url.host == "pl.example":
            if state["down"]:
                return httpx.Response(503)
            state["got"].append(request.url.path)
            return httpx.Response(200, json={})
        return httpx.Response(200)

    a, _ = make_agent(handler, monkeypatch)
    a.cycle(now=1)
    assert state["got"] == [] and len(a.pusher.pending) >= 2
    state["down"] = False
    a.cycle(now=11)
    assert "/api/ingest/services" in state["got"] and "/api/ingest/metrics" in state["got"] and not a.pusher.pending


def test_dry_run_sends_nothing(monkeypatch, capsys):
    w = World()
    a, _ = make_agent(w, monkeypatch, dry=True)
    a.cycle(now=1)
    assert w.sent == [] and "[dry-run] POST /api/ingest/metrics" in capsys.readouterr().out


def test_main_validates_config_and_requires_a_token(tmp_path, monkeypatch, capsys):
    path = tmp_path / "a.yaml"
    path.write_text("pagerlens: {url: 'https://pl.example'}\ntargets: [{name: web, probes: [{url: 'https://web.example/'}]}]\n")
    monkeypatch.delenv("PAGERLENS_TOKEN", raising=False)
    assert agent.main(["once", str(path)]) == 2 and "PAGERLENS_TOKEN" in capsys.readouterr().err
    path.write_text("targets: []\n")
    assert agent.main(["once", str(path), "--dry-run"]) == 2 and "config error" in capsys.readouterr().err
