"""Live updates: Postgres row-change notifications (`tcn`) to the browser as server-sent events.

`migrations/005_tcn.sql` puts `triggered_change_notification('pl_changes')` triggers on `incident` and `alert`. ONE background
connection per process LISTENs on that channel and fans each notification out to every open `GET /api/events` stream. The payload
Postgres sends is `"incident",I,"id"='42'` (table, operation, primary key): no row content ever travels, the page re-reads what it
shows through the normal, permission-checked API. The connection is opened when the first browser subscribes and closed 30 seconds
after the last one leaves, so an idle app does not keep a database that scales to zero awake. If tcn is missing nothing is sent and
the pages keep their timer-based refresh.
"""
import asyncio
import contextlib
import logging
import re
import threading
import time
from pathlib import Path

import psycopg

log = logging.getLogger("pagerlens.live")

CHANNEL = "pl_changes"
IDLE_CLOSE = 30.0
TCN_SQL = Path(__file__).resolve().parent / "migrations" / "005_tcn.sql"
_PAYLOAD = re.compile(r'^"(?P<table>[a-z_]+)",(?P<op>[IUD]),"(?P<key>[a-z_]+)"=\'(?P<id>[^\']*)\'')
OPS = {"I": "insert", "U": "update", "D": "delete"}


def install(conn: psycopg.Connection) -> bool:
    """After-migrate hook: (re)apply the guarded tcn migration, so a database that gained the extension later gets the triggers on the
    next start. Returns whether the triggers exist."""
    if available(conn):
        return True                          # nothing to do (and no lock taken on the tables)
    conn.execute(TCN_SQL.read_text())
    conn.commit()
    return available(conn)


def available(conn: psycopg.Connection) -> bool:
    row = conn.execute("SELECT count(*) AS n FROM pg_trigger WHERE tgname IN ('incident_tcn', 'alert_tcn') AND NOT tgisinternal").fetchone()
    conn.rollback()
    return row["n"] == 2


def parse(payload: str) -> dict | None:
    m = _PAYLOAD.match(payload)
    if not m:
        return None
    return {"table": m["table"], "op": OPS[m["op"]], "id": int(m["id"]) if m["id"].isdigit() else m["id"]}


class Subscription:
    """One open event stream: an asyncio queue filled from the listener thread."""

    def __init__(self, loop: asyncio.AbstractEventLoop):
        self.loop, self.queue = loop, asyncio.Queue(maxsize=200)

    def push(self, event: dict) -> None:
        def put() -> None:
            with contextlib.suppress(asyncio.QueueFull):     # a stalled browser loses events; it also refreshes on its own
                self.queue.put_nowait(event)
        with contextlib.suppress(RuntimeError):              # the loop is closed: the stream is already gone
            self.loop.call_soon_threadsafe(put)


class Hub:
    def __init__(self, url):
        self._url = url
        self._subs: set[Subscription] = set()
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self.listening = threading.Event()       # set while the LISTEN connection is up (tests wait on it)

    def subscribe(self) -> Subscription:
        sub = Subscription(asyncio.get_running_loop())
        with self._lock:
            self._subs.add(sub)
            if self._thread is None or not self._thread.is_alive():
                self._stop.clear()
                self._thread = threading.Thread(target=self._run, daemon=True, name="pagerlens-listen")
                self._thread.start()
        return sub

    def unsubscribe(self, sub: Subscription) -> None:
        with self._lock:
            self._subs.discard(sub)

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        t = self._thread
        if t is not None:
            t.join(timeout)
        self._thread = None

    @property
    def subscribers(self) -> int:
        return len(self._subs)

    def _dispatch(self, payload: str) -> None:
        event = parse(payload)
        if event is None:
            return
        with self._lock:
            subs = list(self._subs)
        for s in subs:
            s.push(event)

    def _run(self) -> None:
        backoff, idle_since = 1.0, None
        while not self._stop.is_set():
            try:
                with psycopg.connect(self._url(), autocommit=True, connect_timeout=10) as conn:
                    conn.execute(f"LISTEN {CHANNEL}")
                    self.listening.set()
                    backoff = 1.0
                    while not self._stop.is_set():
                        for n in conn.notifies(timeout=1.0):
                            self._dispatch(n.payload)
                        with self._lock:
                            idle_since = (idle_since or time.monotonic()) if not self._subs else None
                            if idle_since and time.monotonic() - idle_since >= IDLE_CLOSE and not self._subs:
                                self._thread = None      # decided under the lock, so a new subscriber starts a fresh thread
                                return
            except Exception as exc:  # noqa: BLE001 - the database restarted, scaled to zero or is unreachable: retry quietly
                log.warning("live-update listener lost its connection (%s: %s); retrying in %.0f s", type(exc).__name__,
                            str(exc).strip().splitlines()[0][:120] if str(exc).strip() else "", backoff)
                self.listening.clear()
                if self._stop.wait(backoff):
                    return
                backoff = min(backoff * 2, 30.0)
            finally:
                self.listening.clear()
