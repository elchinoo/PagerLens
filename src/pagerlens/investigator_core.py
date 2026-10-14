"""Shared plumbing for every investigator: categories, the tool-call budget, the step recorder and the tool runner."""
import hashlib
import json
import time

from . import tools
from .tools import Ctx, ToolError

MAX_TOOL_CALLS = 30
CATEGORIES = {
    "bad_deploy": "A recent deploy introduced the failure",
    "db_saturation": "Database connection pool or database saturation",
    "resource_exhaustion": "A service is running out of memory or other resources",
    "dependency_outage": "A dependency the service relies on is failing",
    "traffic_spike": "Traffic surged beyond capacity",
    "expired_certificate": "A TLS certificate expired or is invalid",
    "unknown": "Not enough evidence",
}


class Budget:
    def __init__(self, max_calls: int | None = None):
        self.max_calls, self.calls, self.ms = max_calls or MAX_TOOL_CALLS, 0, 0

    def spend(self) -> None:
        if self.calls >= self.max_calls:
            raise ToolError(f"tool-call budget of {self.max_calls} exhausted")
        self.calls += 1


class Recorder:
    """Writes every step and observation as it happens, so a run can be replayed and audited."""

    def __init__(self, conn, run_id: int, incident_id: int):
        self.conn, self.run_id, self.incident_id, self.ord = conn, run_id, incident_id, 0

    def step(self, kind: str, tool: str | None, args: dict, summary: str, rows: int | None, ms: int | None) -> int:
        self.ord += 1
        return self.conn.execute(
            "INSERT INTO run_step (run_id, ord, kind, tool, args, summary, row_count, ms) VALUES (%s,%s,%s,%s,%s::jsonb,%s,%s,%s) "
            "RETURNING id", (self.run_id, self.ord, kind, tool, json.dumps(args), summary[:500], rows, ms)).fetchone()["id"]

    def observe(self, step_id: int | None, source: str, kind: str, summary: str, payload: dict) -> int:
        body = json.dumps(payload, default=str, sort_keys=True)
        return self.conn.execute(
            "INSERT INTO observation (incident_id, run_id, step_id, source, kind, summary, payload, digest) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s::jsonb,%s) RETURNING id",
            (self.incident_id, self.run_id, step_id, source, kind, summary[:500], body,
             hashlib.sha256(body.encode()).hexdigest()[:16])).fetchone()["id"]


def call_tool(ctx: Ctx, rec: Recorder, budget: Budget, name: str, **args) -> tuple[tools.ToolResult, int]:
    """Run one registered read-only tool, recording the step and its observation."""
    if name not in tools.REGISTRY:
        raise ToolError(f"unknown tool {name!r}")
    budget.spend()
    started = time.monotonic()
    result = tools.REGISTRY[name][0](ctx, **args)
    ms = int((time.monotonic() - started) * 1000)
    budget.ms += ms
    step_id = rec.step("tool", name, args, result.summary, result.rows, ms)
    obs_id = rec.observe(step_id, name, name, result.summary, result.data)
    return result, obs_id
