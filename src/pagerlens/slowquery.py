"""Watching the fleet's databases: the agentpg-kit `db_insights_top_query_mean_seconds{queryid}` gauge as PagerLens telemetry.

Every app built on agentpg-kit can export, at `/metrics`, the mean time of its slowest SQL statements (from EDB's `edb_stat_monitor`,
else `pg_stat_statements`). `pagerlens-agent` scrapes that gauge and pushes each statement as an ordinary metric point named
`slowq_<queryid>` (value: mean milliseconds) for the service that owns the database. The investigator then compares each such
series with its own baseline (`tools.slow_queries`) and can name a regression: the query id, and its mean before and after.

A metric name cannot hold a minus sign, so a negative query id (Postgres query ids are signed 64-bit numbers) is written with a
leading `m`: `slowq_m6823950417` is query id `-6823950417`.
"""
import re
from collections import deque

PREFIX = "slowq_"
SOURCE_METRIC = "db_insights_top_query_mean_seconds"
_ID = re.compile(r"^-?[0-9a-z]{1,30}$")


def metric_name(queryid: str) -> str | None:
    """`slowq_<id>` for a query id, or None if it is not a plain id (so a hostile label can never become a metric name)."""
    q = str(queryid).strip().lower()
    if not _ID.match(q):
        return None
    return PREFIX + ("m" + q[1:] if q.startswith("-") else q)


def query_id(name: str) -> str:
    """The query id behind a `slowq_` metric name."""
    rest = name[len(PREFIX):]
    return "-" + rest[1:] if re.fullmatch(r"m[0-9]+", rest) else rest


def short_id(queryid: str) -> str:
    """A query id as shown in alert text. Ingest scrubs 13 or more digits in a row as a possible card number, so a long id is
    shortened to its last 8 characters; the investigator's evidence (not scrubbed) and the metric names carry the full id."""
    return queryid if len(queryid) <= 12 else "\u2026" + queryid[-8:]


class Watch:
    """Agent-side detector: a statement whose mean stays at least `factor` times its earlier median for `sustain` scrapes in a row.

    Needs `history` earlier scrapes first, never fires twice for the same statement until it has recovered, and ignores statements
    that are too fast to matter (`min_ms`). This is what opens the incident the investigator then explains."""

    def __init__(self, *, factor: float = 3.0, sustain: int = 3, history: int = 6, min_ms: float = 20.0, keep: int = 40):
        self.factor, self.sustain, self.history, self.min_ms, self.keep = factor, sustain, history, min_ms, keep
        self.series: dict[str, deque] = {}
        self.fired: set[str] = set()

    def observe(self, queryid: str, mean_ms: float) -> dict | None:
        s = self.series.setdefault(queryid, deque(maxlen=self.keep))
        s.append(mean_ms)
        if len(s) < self.history + self.sustain:
            return None
        vals = list(s)
        earlier, recent = sorted(vals[:-self.sustain]), vals[-self.sustain:]
        median = earlier[len(earlier) // 2]
        slow = all(v >= self.factor * max(median, 1e-6) and v >= self.min_ms for v in recent)
        if not slow:
            if queryid in self.fired and all(v < 1.5 * max(median, 1e-6) for v in recent):
                self.fired.discard(queryid)          # recovered: a later regression may alert again
            return None
        if queryid in self.fired:
            return None
        self.fired.add(queryid)
        return {"queryid": queryid, "before_ms": median, "after_ms": sum(recent) / len(recent)}
