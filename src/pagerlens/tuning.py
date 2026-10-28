"""Propose-and-approve tuning: the safe form of "proactive performance tuning".

PagerLens looks at what EDB's extensions know about ITS OWN database (the kit's `insights_payload`: top statements, `edb_pg_tuner`,
`query_advisor`) and at the `slow_query` findings of the fleet, and writes PROPOSALS. A person approves or rejects each one. Applying
is a separate, admin-only act that is OFF unless `PAGERLENS_ALLOW_TUNING_APPLY=true`, and even then it runs only a statement that
passes the strict allow-list parser below, one at a time, with a statement timeout, against PagerLens' own database. It records an
EXPLAIN-based before/after for the query that motivated the change.

What this module never does: touch another database, run anything the parser does not recognise, or change a monitored system. For
a monitored app a slow-query finding only becomes written advice (`applicable = false`, `target` = that service).
"""
import hashlib
import json
import logging
import os
import re
import time
from dataclasses import dataclass

from apgkit import insights as kit_insights
from apgkit.config import env_bool
from psycopg import sql

from . import settings_store as store
from . import tools
from .scrub import scrub

log = logging.getLogger("pagerlens.tuning")

LOCK_KEY = 7204119                 # advisory lock: one apply at a time across replicas
SCAN_LOCK_KEY = 7204120
LAST_SCAN = "tuning_last_scan"
MAX_STATEMENT = 600
MAX_INDEX_COLUMNS = 4
MAX_STAT_COLUMNS = 8
STAT_KINDS = ("ndistinct", "dependencies", "mcv")
SOURCES = ("advisor", "tuner", "slow_query")


class TuningError(ValueError):
    """A request that cannot be honoured (wrong state, unknown proposal): shown to the caller as is."""


class StatementRejected(TuningError):
    """The statement is not on the allow-list."""


class ApplyDisabled(TuningError):
    pass


class Busy(TuningError):
    pass


def apply_enabled() -> bool:
    return env_bool("PAGERLENS_ALLOW_TUNING_APPLY", False)


def statement_timeout_seconds() -> int:
    try:
        return max(1, min(int(os.environ.get("PAGERLENS_TUNING_STATEMENT_TIMEOUT_SECONDS", "60")), 600))
    except ValueError:
        return 60


def lock_timeout_seconds() -> int:
    try:
        return max(1, min(int(os.environ.get("PAGERLENS_TUNING_LOCK_TIMEOUT_SECONDS", "5")), 60))
    except ValueError:
        return 5


def self_service() -> str:
    return os.environ.get("PAGERLENS_SELF_SERVICE", "pagerlens")


# --- the allow-list parser ---------------------------------------------------------------------------------------------
# Not a regex over the raw text: the text is cut into tokens first, any character outside a tiny alphabet is refused (no quotes,
# no comment markers, no backslash, no dollar quoting, no second statement), and the token sequence must match one of two grammars:
#
#   CREATE INDEX [CONCURRENTLY] [IF NOT EXISTS] [name] ON public.<table> [USING btree] (<col> [ASC|DESC], ...)
#   CREATE STATISTICS [IF NOT EXISTS] <name> [(<kind>, ...)] ON <col>, <col>, ... FROM public.<table>
#
# Identifiers are lower-case words (what an unquoted PostgreSQL identifier folds to); everything that gets executed is rebuilt from the
# parsed pieces with proper identifier quoting, never the submitted text.

_ALPHABET = re.compile(r"[A-Za-z0-9_(),. \t\r\n]*")
_TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|[(),.]")
_IDENT = re.compile(r"[a-z_][a-z0-9_]{0,62}")


@dataclass(frozen=True)
class Parsed:
    kind: str                                  # "index" | "statistics"
    table: str
    columns: tuple[str, ...]
    name: str | None = None
    concurrently: bool = False
    if_not_exists: bool = False
    descending: tuple[bool, ...] = ()
    stat_kinds: tuple[str, ...] = ()

    def text(self) -> str:
        """The canonical, human-readable statement (every identifier here passed the identifier check)."""
        if self.kind == "index":
            cols = ", ".join(c + (" DESC" if d else "") for c, d in zip(self.columns, self.descending, strict=True))
            return ("CREATE INDEX" + (" CONCURRENTLY" if self.concurrently else "") + (" IF NOT EXISTS" if self.if_not_exists else "")
                    + (f" {self.name}" if self.name else "") + f" ON public.{self.table} ({cols})")
        kinds = f" ({', '.join(self.stat_kinds)})" if self.stat_kinds else ""
        return ("CREATE STATISTICS" + (" IF NOT EXISTS" if self.if_not_exists else "") + f" {self.name}{kinds}"
                + f" ON {', '.join(self.columns)} FROM public.{self.table}")

    def composed(self) -> sql.Composed:
        """What is actually executed: rebuilt with quoted identifiers from the parsed pieces."""
        ident, table = sql.Identifier, sql.Identifier("public", self.table)
        if self.kind == "index":
            cols = sql.SQL(", ").join(sql.Composed([ident(c), sql.SQL(" DESC" if d else "")])
                                      for c, d in zip(self.columns, self.descending, strict=True))
            return sql.SQL("CREATE INDEX {conc}{ine}{name}ON {table} ({cols})").format(
                conc=sql.SQL("CONCURRENTLY " if self.concurrently else ""), ine=sql.SQL("IF NOT EXISTS " if self.if_not_exists else ""),
                name=sql.Composed([ident(self.name), sql.SQL(" ")]) if self.name else sql.SQL(""), table=table, cols=cols)
        return sql.SQL("CREATE STATISTICS {ine}{name}{kinds} ON {cols} FROM {table}").format(
            ine=sql.SQL("IF NOT EXISTS " if self.if_not_exists else ""), name=ident(self.name),
            kinds=sql.SQL(f" ({', '.join(self.stat_kinds)})" if self.stat_kinds else ""),
            cols=sql.SQL(", ").join(ident(c) for c in self.columns), table=table)


class _Tokens:
    def __init__(self, items: list[str]):
        self.items, self.i = items, 0

    def peek(self, k: int = 0) -> str | None:
        return self.items[self.i + k].lower() if self.i + k < len(self.items) else None

    def take(self) -> str:
        if self.i >= len(self.items):
            raise StatementRejected("the statement ends too early")
        self.i += 1
        return self.items[self.i - 1].lower()

    def expect(self, *words: str) -> str:
        got = self.take()
        if got not in words:
            raise StatementRejected(f"expected {' or '.join(w.upper() for w in words)}, found {got!r}")
        return got

    def accept(self, *words: str) -> bool:
        """Consume the word sequence if it is next (all of it or nothing)."""
        if [self.peek(k) for k in range(len(words))] == list(words):
            self.i += len(words)
            return True
        return False

    def ident(self, what: str) -> str:
        got = self.take()
        if not _IDENT.fullmatch(got):
            raise StatementRejected(f"{what} must be a plain lower-case name, found {got!r}")
        return got

    def done(self) -> None:
        if self.i != len(self.items):
            raise StatementRejected(f"unexpected text after the statement: {self.items[self.i]!r}")


def _tokenize(text: str) -> _Tokens:
    if not isinstance(text, str) or not text.strip(" \t\r\n"):
        raise StatementRejected("the statement is empty")
    body = text.strip(" \t\r\n")
    if body.endswith(";"):
        body = body[:-1].rstrip(" \t\r\n")                 # one trailing semicolon is tolerated, a second or a middle one is not
    if len(body) > MAX_STATEMENT:
        raise StatementRejected("the statement is too long")
    if not _ALPHABET.fullmatch(body):
        raise StatementRejected("only letters, digits, underscores, commas, dots and parentheses are allowed "
                                "(no quotes, comments, semicolons or other statements)")
    items, pos = [], 0
    while pos < len(body):
        if body[pos].isspace():
            pos += 1
            continue
        m = _TOKEN.match(body, pos)
        if not m:
            raise StatementRejected(f"cannot read the statement near {body[pos:pos + 12]!r}")
        items.append(m.group())
        pos = m.end()
    return _Tokens(items)


def _public_table(t: _Tokens) -> str:
    if t.take() != "public" or t.take() != ".":
        raise StatementRejected("the table must be written public.<table>: other schemas are refused")
    return t.ident("the table")


def _columns_until(t: _Tokens, closer: str | None, limit: int, *, direction: bool) -> tuple[list[str], list[bool]]:
    cols, desc = [], []
    while True:
        cols.append(t.ident("a column"))
        desc.append(False)
        if direction and t.peek() in ("asc", "desc"):
            desc[-1] = t.take() == "desc"
        if len(cols) > limit:
            raise StatementRejected(f"at most {limit} columns")
        if t.peek() == ",":
            t.take()
            continue
        break
    if closer:
        t.expect(closer)
    return cols, desc


def parse_statement(text: str) -> Parsed:
    """Return the parsed statement or raise StatementRejected. This is the only gate between a stored proposal and the database."""
    t = _tokenize(text)
    t.expect("create")
    first = t.take()
    if first == "index":
        concurrently = t.accept("concurrently")
        if_not_exists = t.accept("if", "not", "exists")
        name = None if t.peek() == "on" else t.ident("the index name")
        t.expect("on")
        table = _public_table(t)
        if t.accept("using"):
            t.expect("btree")
        t.expect("(")
        cols, desc = _columns_until(t, ")", MAX_INDEX_COLUMNS, direction=True)
        t.done()
        return Parsed("index", table, tuple(cols), name, concurrently, if_not_exists, tuple(desc))
    if first == "statistics":
        if_not_exists = t.accept("if", "not", "exists")
        name = t.ident("the statistics name")
        kinds: list[str] = []
        if t.peek() == "(":
            t.take()
            while True:
                kinds.append(t.expect(*STAT_KINDS))
                if t.peek() == ",":
                    t.take()
                    continue
                break
            t.expect(")")
        t.expect("on")
        cols, _ = _columns_until(t, None, MAX_STAT_COLUMNS, direction=False)
        if len(cols) < 2:
            raise StatementRejected("CREATE STATISTICS needs at least two columns")
        t.expect("from")
        table = _public_table(t)
        t.done()
        return Parsed("statistics", table, tuple(cols), name, False, if_not_exists, (), tuple(kinds))
    raise StatementRejected("only CREATE INDEX and CREATE STATISTICS are allowed")


def is_applicable(text: str) -> bool:
    try:
        parse_statement(text)
        return True
    except StatementRejected:
        return False


# --- proposals ---------------------------------------------------------------------------------------------------------

def _name(prefix: str, table: str, cols: list[str]) -> str:
    raw = f"{prefix}_{table}_{'_'.join(cols)}"
    if len(raw) <= 63:
        return raw
    return raw[:54] + "_" + hashlib.sha1(raw.encode()).hexdigest()[:8]


def _own_tables(conn) -> dict[str, set[str]]:
    """Ordinary tables of PagerLens' own `public` schema and their columns (what a proposal may name)."""
    out: dict[str, set[str]] = {}
    for r in conn.execute(
            "SELECT c.relname AS t, a.attname AS c FROM pg_class c JOIN pg_attribute a ON a.attrelid = c.oid "
            "WHERE c.relnamespace = 'public'::regnamespace AND c.relkind IN ('r','p') AND a.attnum > 0 AND NOT a.attisdropped"):
        out.setdefault(r["t"], set()).add(r["c"])
    return out


def _matching_query(top: list[dict], table: str, column: str) -> dict | None:
    for q in top:
        text = (q.get("query") or "").lower()
        if re.search(rf"\b{re.escape(table)}\b", text) and re.search(rf"\b{re.escape(column)}\b", text):
            return q
    return None


def _proposal(source, statement, rationale, benefit, *, target="self", query=None, applicable=None) -> dict:
    return {"source": source, "target": target, "statement": statement,
            "applicable": is_applicable(statement) if applicable is None else applicable, "rationale": rationale,
            "estimated_benefit": benefit, "motivating_queryid": (query or {}).get("queryid"),
            "motivating_query": (query or {}).get("query")}


def build_candidates(payload: dict, own: dict[str, set[str]], slow: list[dict], *, self_name: str = "pagerlens") -> list[dict]:
    """Pure function: proposals from the kit's insights payload, the tables PagerLens owns and the fleet's slow-query findings.
    `slow` is a list of {service, queryid, baseline_ms, current_ms, ratio}."""
    out: list[dict] = []
    top = ((payload.get("top_queries") or {}).get("queries") or []) if (payload.get("top_queries") or {}).get("available") else []
    adv = payload.get("advisor") or {}
    suggestions = []
    if adv.get("available"):
        for s in adv.get("suggestions") or []:
            table, col = s.get("table"), s.get("column")
            if (s.get("schema") or "public") == "public" and table in own and col in own[table] and (s.get("operator") or "") != "":
                suggestions.append(s)
    seen_idx = set()
    for s in suggestions:
        table, col = s["table"], s["column"]
        if (table, col) in seen_idx:
            continue
        seen_idx.add((table, col))
        stmt = f"CREATE INDEX CONCURRENTLY IF NOT EXISTS {_name('pl_ix', table, [col])} ON public.{table} ({col})"
        q = _matching_query(top, table, col)
        out.append(_proposal(
            "advisor", stmt,
            f"query_advisor saw {s.get('occurrences', '?')} filter(s) on public.{table}.{col} (operator {s.get('operator')}) over "
            f"{s.get('executions', '?')} execution(s): the condition read rows and then threw {s.get('rows_filtered', '?')} of them away.",
            f"about {s.get('filtered_per_execution', '?')} row(s) read and discarded per execution; an observed hint that an index "
            "could help, not a measured speed-up", query=q))
    by_table: dict[str, list[str]] = {}
    for s in suggestions:
        by_table.setdefault(s["table"], [])
        if s["column"] not in by_table[s["table"]]:
            by_table[s["table"]].append(s["column"])
    for table, cols in by_table.items():
        if len(cols) >= 2:
            use = cols[:3]
            stmt = f"CREATE STATISTICS IF NOT EXISTS {_name('pl_st', table, use)} (dependencies) ON {', '.join(use)} FROM public.{table}"
            out.append(_proposal(
                "advisor", stmt, f"queries filter public.{table} on {', '.join(use)} together; extended statistics let the planner "
                "see that those columns are correlated.", "better row estimates for multi-column filters (PagerLens runs ANALYZE "
                "on that one table after creating it)"))
    tun = payload.get("tuner") or {}
    if tun.get("available"):
        for r in (tun.get("recommendations") or [])[:10]:
            if r.get("setting") and r.get("value") is not None:
                stmt = f"ALTER SYSTEM SET {r['setting']} = '{r['value']}'"
                out.append(_proposal("tuner", stmt, f"edb_pg_tuner recommends {r['setting']} = {r['value']}.",
                                     "a server setting: PagerLens never changes it, a person does through the platform",
                                     applicable=False))
    for f in slow:
        svc, qid = f["service"], f["queryid"]
        summary = f"query {qid} in {svc}: mean {f['baseline_ms']:g} ms before, {f['current_ms']:g} ms now (x{f['ratio']:g})"
        mine = next((q for q in top if str(q.get("queryid")) == str(qid)), None)
        if svc == self_name and mine:
            tables = [t for t in own if re.search(rf"\b{re.escape(t)}\b", (mine.get("query") or "").lower())]
            hit = next((s for s in suggestions if s["table"] in tables
                        and re.search(rf"\b{re.escape(s['column'])}\b", (mine.get("query") or "").lower())), None)
            if hit:
                stmt = (f"CREATE INDEX CONCURRENTLY IF NOT EXISTS {_name('pl_ix', hit['table'], [hit['column']])} "
                        f"ON public.{hit['table']} ({hit['column']})")
                out.append(_proposal("slow_query", stmt, f"{summary}. The advisor saw filters on public.{hit['table']}.{hit['column']} "
                                     "that this statement uses.", "should bring the statement back toward its earlier mean "
                                     "(check the before/after plan after applying)", query=mine))
                continue
        out.append(_proposal(
            "slow_query", f"Review query {qid} in {svc}'s database ({f['baseline_ms']:g} -> {f['current_ms']:g} ms)",
            f"{summary}. PagerLens never changes a monitored system: this is advice for the people who own {svc}"
            + ("" if mine else f" (the statement text is not in PagerLens: open {svc}'s own Database tab and find query id {qid})") + ".",
            "restore the earlier mean time; look at the plan and at that app's own advisor suggestions",
            target=svc, query=mine, applicable=False))
    return out


def _slow_findings(conn) -> list[dict]:
    """The investigator's `slow_queries` tool over every service that reports `slowq_*` series, as of its newest data."""
    found: list[dict] = []
    services = conn.execute(
        "SELECT s.id, s.name FROM service s WHERE EXISTS (SELECT 1 FROM metric_point m WHERE m.service_id = s.id "
        "AND starts_with(m.name, 'slowq_') AND m.ts > now() - interval '7 days') ORDER BY s.name").fetchall()
    for s in services:
        anchor = conn.execute("SELECT max(ts) AS t FROM metric_point WHERE service_id=%s", (s["id"],)).fetchone()["t"]
        if anchor is None:
            continue
        res = tools.slow_queries(tools.Ctx(conn, 0, s["name"], anchor), s["name"])
        found += [{"service": s["name"], **q} for q in res.data["queries"]]
    return found


def _audit(conn, proposal_id: int | None, action: str, actor: str, detail: str = "") -> None:
    conn.execute("INSERT INTO tuning_audit (proposal_id, action, actor, detail) VALUES (%s,%s,%s,%s)",
                 (proposal_id, action, actor[:60], scrub(detail)[:500]))


def scan(conn, actor: str = "system", *, insights: dict | None = None) -> dict:
    """Look for improvements and record new proposals. Idempotent: a statement that is already proposed, approved, applied or
    rejected is not proposed again. `insights` is for tests; normally it is read from this database through the kit."""
    payload = insights if insights is not None else kit_insights.insights_payload(conn, "total", 50)
    candidates = build_candidates(payload, _own_tables(conn), _slow_findings(conn), self_name=self_service())
    created, skipped = [], 0
    for c in candidates:
        if conn.execute("SELECT 1 FROM tuning_proposal WHERE statement=%s AND status IN ('proposed','approved','rejected','applied')",
                        (c["statement"],)).fetchone():
            skipped += 1
            continue
        row = conn.execute(
            "INSERT INTO tuning_proposal (source, target, statement, applicable, rationale, estimated_benefit, motivating_queryid, "
            "motivating_query) VALUES (%(source)s, %(target)s, %(statement)s, %(applicable)s, %(rationale)s, %(estimated_benefit)s, "
            "%(motivating_queryid)s, %(motivating_query)s) ON CONFLICT DO NOTHING RETURNING id",
            {**c, "rationale": scrub(c["rationale"]), "motivating_query": scrub(c["motivating_query"]) if c["motivating_query"] else None}
        ).fetchone()
        if row:
            created.append(row["id"])
            _audit(conn, row["id"], "created", actor, f"{c['source']} / {c['target']}")
        else:
            skipped += 1
    notes = []
    if not (payload.get("advisor") or {}).get("available"):
        notes.append("query_advisor is not available on this database: " + str((payload.get("advisor") or {}).get("reason", "unknown")))
    if not (payload.get("tuner") or {}).get("available"):
        notes.append("edb_pg_tuner is not available on this database: " + str((payload.get("tuner") or {}).get("reason", "unknown")))
    _audit(conn, None, "scan", actor, f"{len(created)} new, {skipped} already known")
    store.put(conn, LAST_SCAN, str(time.time()))
    conn.commit()
    return {"created": created, "skipped": skipped, "notes": notes}


def scan_if_due(conn, every_minutes: float) -> dict | None:
    """The background job's entry point: scan when the last scan is older than `every_minutes` (0 = never), one replica at a time."""
    if every_minutes <= 0:
        return None
    if not conn.execute("SELECT pg_try_advisory_xact_lock(%s) AS ok", (SCAN_LOCK_KEY,)).fetchone()["ok"]:
        return None
    last = store.get(conn, LAST_SCAN)
    if last and time.time() - float(last) < every_minutes * 60:
        conn.rollback()
        return None
    return scan(conn, "scheduled job")


def list_proposals(conn, status: str | None = None, limit: int = 200) -> list[dict]:
    return conn.execute(
        "SELECT * FROM tuning_proposal WHERE (%s::text IS NULL OR status = %s) ORDER BY id DESC LIMIT %s",
        (status, status, max(1, min(limit, 500)))).fetchall()


def get(conn, proposal_id: int) -> dict:
    row = conn.execute("SELECT * FROM tuning_proposal WHERE id=%s", (proposal_id,)).fetchone()
    if not row:
        raise TuningError("proposal not found")
    row["audit"] = conn.execute("SELECT id, action, actor, detail, at FROM tuning_audit WHERE proposal_id=%s ORDER BY id",
                                (proposal_id,)).fetchall()
    return row


def decide(conn, proposal_id: int, decision: str, note: str | None, actor: str) -> dict:
    if decision not in ("approve", "reject"):
        raise TuningError("decision must be approve or reject")
    status = "approved" if decision == "approve" else "rejected"
    row = conn.execute(
        "UPDATE tuning_proposal SET status=%s, decided_by=%s, decided_at=now(), decision_note=%s "
        "WHERE id=%s AND status='proposed' RETURNING id", (status, actor[:60], scrub(note or "")[:500] or None, proposal_id)).fetchone()
    if not row:
        exists = conn.execute("SELECT status FROM tuning_proposal WHERE id=%s", (proposal_id,)).fetchone()
        raise TuningError("proposal not found" if not exists else f"only a proposed change can be decided (this one is {exists['status']})")
    _audit(conn, proposal_id, status, actor, note or "")
    conn.commit()
    return get(conn, proposal_id)


# --- EXPLAIN-based before/after ----------------------------------------------------------------------------------------

def _scan_nodes(plan: dict, out: list[str]) -> None:
    node = plan.get("Node Type", "")
    if "Scan" in node:
        label = node + (f" on {plan['Relation Name']}" if plan.get("Relation Name") else "")
        out.append(label + (f" using {plan['Index Name']}" if plan.get("Index Name") else ""))
    for child in plan.get("Plans") or []:
        _scan_nodes(child, out)


def explain_cost(conn, query: str | None) -> dict:
    """Estimated plan of a normalised SELECT (`$1` placeholders are fine: a generic plan). Estimated cost units, NOT milliseconds,
    and nothing is executed (no ANALYZE), inside a read-only transaction. Honest about when it cannot be done."""
    when = {"method": "EXPLAIN (GENERIC_PLAN, FORMAT JSON): estimated cost units, not measured time", "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    text = (query or "").strip().rstrip(";").strip()
    if not text:
        return {**when, "available": False, "reason": "no motivating statement is known for this proposal"}
    if not re.match(r"select\b", text, re.I) or ";" in text:
        return {**when, "available": False, "reason": "only a single SELECT is explained"}
    options = "GENERIC_PLAN, FORMAT JSON" if re.search(r"\$\d", text) else "FORMAT JSON"
    try:
        with conn.transaction():
            conn.execute("SET TRANSACTION READ ONLY")
            conn.execute("SET LOCAL statement_timeout = '5s'")
            row = conn.execute(f"EXPLAIN ({options}) {text}").fetchone()   # noqa: S608 - one SELECT, read-only transaction, no ANALYZE
    except Exception as exc:  # noqa: BLE001 - a cut statement, a missing table: report why, never fail the apply because of it
        return {**when, "available": False, "reason": scrub(str(exc).strip().splitlines()[0] if str(exc).strip() else type(exc).__name__)[:200]}
    data = row["QUERY PLAN"]
    data = json.loads(data) if isinstance(data, str) else data
    plan = data[0]["Plan"]
    scans: list[str] = []
    _scan_nodes(plan, scans)
    return {**when, "available": True, "total_cost": plan["Total Cost"], "plan_rows": plan["Plan Rows"], "scans": scans[:6]}


# --- apply -------------------------------------------------------------------------------------------------------------

def _check_target(conn, p: Parsed) -> None:
    own = _own_tables(conn)
    if p.table not in own:
        raise StatementRejected(f"public.{p.table} is not a table of this database")
    missing = [c for c in p.columns if c not in own[p.table]]
    if missing:
        raise StatementRejected(f"public.{p.table} has no column {', '.join(missing)}")


def apply(proposal_id: int, actor: str) -> dict:
    """Apply one approved proposal to PagerLens' own database. Raises ApplyDisabled (off by default), TuningError (wrong state),
    StatementRejected (not on the allow-list; the proposal is marked failed) or Busy (another apply is running)."""
    from .db import connect

    conn = connect(retries=1)
    conn.autocommit = True                     # CREATE INDEX CONCURRENTLY cannot run inside a transaction block
    try:
        if not apply_enabled():
            _audit(conn, proposal_id, "apply_refused", actor, "PAGERLENS_ALLOW_TUNING_APPLY is not true")
            raise ApplyDisabled("applying changes is switched off on this server (set PAGERLENS_ALLOW_TUNING_APPLY=true to allow it)")
        if not conn.execute("SELECT pg_try_advisory_lock(%s) AS ok", (LOCK_KEY,)).fetchone()["ok"]:
            raise Busy("another change is being applied right now; try again in a moment")
        try:
            return _apply_locked(conn, proposal_id, actor)
        finally:
            conn.execute("SELECT pg_advisory_unlock(%s)", (LOCK_KEY,))
    finally:
        conn.close()


def _fail(conn, proposal_id: int, actor: str, message: str, before: dict | None = None) -> None:
    conn.execute("UPDATE tuning_proposal SET status='failed', error=%s, before_timing=COALESCE(%s::jsonb, before_timing) WHERE id=%s",
                 (scrub(message)[:500], json.dumps(before) if before else None, proposal_id))
    _audit(conn, proposal_id, "failed", actor, message)


def _apply_locked(conn, proposal_id: int, actor: str) -> dict:
    row = conn.execute("SELECT * FROM tuning_proposal WHERE id=%s", (proposal_id,)).fetchone()
    if not row:
        raise TuningError("proposal not found")
    if row["status"] != "approved":
        _audit(conn, proposal_id, "apply_refused", actor, f"status is {row['status']}")
        raise TuningError(f"only an approved change can be applied (this one is {row['status']})")
    if row["target"] != "self" or not row["applicable"]:
        _audit(conn, proposal_id, "apply_refused", actor, "advice only: PagerLens does not run it")
        raise TuningError("this is advice only: PagerLens never changes a monitored system or a server setting; a person does it")
    try:
        parsed = parse_statement(row["statement"])
        _check_target(conn, parsed)
    except StatementRejected as exc:
        _fail(conn, proposal_id, actor, f"refused by the allow-list: {exc}")
        raise
    _audit(conn, proposal_id, "apply_started", actor, parsed.text())
    before = explain_cost(conn, row["motivating_query"])
    conn.execute("UPDATE tuning_proposal SET before_timing=%s::jsonb WHERE id=%s", (json.dumps(before), proposal_id))
    conn.execute(sql.SQL("SET statement_timeout = {}").format(sql.Literal(f"{statement_timeout_seconds()}s")))
    conn.execute(sql.SQL("SET lock_timeout = {}").format(sql.Literal(f"{lock_timeout_seconds()}s")))
    try:
        conn.execute(parsed.composed())
        if parsed.kind == "statistics":      # the definition only takes effect at the next ANALYZE; built from the validated table name
            conn.execute(sql.SQL("ANALYZE {}").format(sql.Identifier("public", parsed.table)))
    except Exception as exc:  # noqa: BLE001 - recorded on the proposal, not hidden
        hint = (" A failed concurrent build can leave an INVALID index with this name; drop it by hand before retrying."
                if parsed.kind == "index" and parsed.concurrently else "")
        _fail(conn, proposal_id, actor, f"{type(exc).__name__}: {str(exc).strip().splitlines()[0] if str(exc).strip() else ''}.{hint}", before)
        return get(conn, proposal_id)
    finally:
        conn.execute("RESET statement_timeout")
        conn.execute("RESET lock_timeout")
    after = explain_cost(conn, row["motivating_query"])
    conn.execute("UPDATE tuning_proposal SET status='applied', applied_by=%s, applied_at=now(), after_timing=%s::jsonb, error=NULL "
                 "WHERE id=%s", (actor[:60], json.dumps(after), proposal_id))
    _audit(conn, proposal_id, "applied", actor, parsed.text())
    return get(conn, proposal_id)
