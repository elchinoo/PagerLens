"""Tiny plain-SQL migration runner (just Postgres: no ORM, no proprietary tooling)."""
import json
import logging
import threading
import time
from pathlib import Path

from pgvector import Vector

from .config import get_settings

MIGRATIONS = Path(__file__).resolve().parent / "migrations"


def run() -> list[str]:
    """Apply the SQL migrations. The shared tables (settings, sessions, API tokens, OIDC state) come from the kit."""
    from apgkit import migrate as kit_migrate
    from apgkit.auth.schema import SQL as AUTH_SQL

    from .core import db

    applied = kit_migrate.run(db, MIGRATIONS, extensions=("vector",), replacements={"{{EMBEDDING_DIM}}": str(get_settings().embedding_dim)})
    with db.connect() as conn:      # after the app's own migrations: it upgrades tables they created (sessions) and adds the OIDC state
        conn.execute(AUTH_SQL)
        conn.commit()
    return applied


# --- embedding dimension reconciliation ------------------------------------------------------------------
# The vector columns get their size once, from EMBEDDING_DIM at first migration. If the configured size later changes
# (a new model, a fleet-wide env change) the stored vectors cannot be converted: they are derived data, so the columns are
# resized (USING NULL) and the vectors recomputed from the source text. Nothing here may stop the web app from starting.
log = logging.getLogger("pagerlens.embeddings")

MAX_HNSW_DIM = 2000          # pgvector's limit for HNSW/IVFFlat indexes on the `vector` type
DEFER_ABOVE = 5000           # more rows than this: change the columns at startup, re-embed in the background
BATCH = 64
SETTING = "embedding_index"  # app_setting: {"model", "dim", "complete"}, what the vectors in the database were made with
INDEXES = {"runbook": "runbook_embedding", "incident": "incident_embedding"}
_RESIZE_LOCK = 7204117       # advisory lock keys: one replica alters, one replica re-embeds
_EMBED_LOCK = 7204118

_job: dict = {"state": "idle", "done": 0, "total": 0, "message": "", "started_at": None}
_thread: threading.Thread | None = None
_job_lock = threading.Lock()


def job_status() -> dict:
    return dict(_job)


def wait_background(timeout: float = 30.0) -> None:
    t = _thread
    if t is not None:
        t.join(timeout)


def column_dim(conn, table: str = "runbook") -> int | None:
    """Vector dimension of <table>.embedding, or None if the table does not exist yet."""
    row = conn.execute(
        "SELECT a.atttypmod AS dim FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid "
        "WHERE c.relname = %s AND a.attname = 'embedding' AND c.relnamespace = 'public'::regnamespace "
        "AND NOT a.attisdropped", (table,)).fetchone()
    return row["dim"] if row else None


def _counts(conn, force: bool) -> dict[str, int]:
    where = "" if force else " WHERE embedding IS NULL"
    return {t: conn.execute(f"SELECT count(*) AS n FROM {t}{where}").fetchone()["n"]  # noqa: S608 - fixed table names
            for t in INDEXES}


def _incident_text(row: dict, signatures: list[str]) -> str:
    """The text an incident was embedded from: its alert (title + symptom), or once investigated or resolved its symptom
    plus the stored error signatures (retrieval.remember_incident). Signatures are read back from the observations."""
    if signatures:
        return f"{row['service']}: {row['symptom']} | " + " | ".join(signatures[:6])
    return f"{row['service']}: {row['title']}. {row['symptom']}"


def _batch(conn, table: str, last: int, force: bool) -> tuple[list[int], list[str]]:
    if table == "runbook":
        flt = "" if force else "AND embedding IS NULL"
        rows = conn.execute(f"SELECT id, title, body FROM runbook WHERE id > %s {flt} ORDER BY id LIMIT %s",  # noqa: S608
                            (last, BATCH)).fetchall()
        return [r["id"] for r in rows], [f"{r['title']}. {r['body']}"[:4000] for r in rows]
    flt = "" if force else "AND i.embedding IS NULL"
    rows = conn.execute(
        "SELECT i.id, i.title, i.symptom, COALESCE(s.name, i.service_name) AS service FROM incident i LEFT JOIN service s ON s.id = i.service_id "
        f"WHERE i.id > %s {flt} ORDER BY i.id LIMIT %s", (last, BATCH)).fetchall()  # noqa: S608
    sigs: dict[int, list[str]] = {r["id"]: [] for r in rows}
    seen: dict[int, int] = {}
    for o in conn.execute("SELECT incident_id, payload FROM observation WHERE incident_id = ANY(%s) AND source = 'error_signatures' "
                          "ORDER BY id DESC", ([r["id"] for r in rows],)):
        if seen.get(o["incident_id"], 0) < 3:   # the last three observations, two signatures each, as when resolving
            seen[o["incident_id"]] = seen.get(o["incident_id"], 0) + 1
            sigs[o["incident_id"]] += [s["signature"] for s in o["payload"].get("signatures", [])[:2]]
    return [r["id"] for r in rows], [_incident_text(r, sigs[r["id"]])[:4000] for r in rows]


def _embed_rows(conn, cfg, *, force: bool, progress=None) -> dict:
    """Embed the rows that lack a vector (or all, with `force`), committing per batch. Stops at the first provider
    failure with ONE log line; the rows stay NULL and are retried on the next start."""
    from . import retrieval
    from .embeddings import EmbeddingError

    out: dict = {"embedded": {t: 0 for t in INDEXES}, "failed": None, "skipped": None}
    if not conn.execute("SELECT pg_try_advisory_lock(%s) AS ok", (_EMBED_LOCK,)).fetchone()["ok"]:
        out["skipped"] = "another process is already re-embedding"
        return out
    try:
        for table in INDEXES:
            dim, last = column_dim(conn, table), 0
            while True:
                ids, texts = _batch(conn, table, last, force)
                if not ids:
                    break
                try:
                    vecs = retrieval.embed(texts, cfg)
                    if len(vecs) != len(ids) or any(len(v) != dim for v in vecs):
                        raise EmbeddingError(f"the provider returned vectors of {len(vecs[0]) if vecs else 0} dimensions "
                                             f"but {table}.embedding has {dim}")
                except Exception as exc:  # noqa: BLE001 - provider down, locked vault, network, wrong size: leave NULL
                    conn.rollback()
                    out["failed"] = retrieval.describe(exc)
                    log.warning("re-embedding stopped (%s); the remaining embeddings stay empty and are retried on the next "
                                "start or by `pagerlens reembed`", out["failed"])
                    return out
                with conn.cursor() as cur:
                    cur.executemany(f"UPDATE {table} SET embedding = %s WHERE id = %s",  # noqa: S608 - fixed table names
                                    [(Vector(v), i) for i, v in zip(ids, vecs, strict=True)])
                conn.commit()
                last = ids[-1]
                out["embedded"][table] += len(ids)
                if progress:
                    progress(sum(out["embedded"].values()))
    finally:
        conn.execute("SELECT pg_advisory_unlock(%s)", (_EMBED_LOCK,))
        conn.commit()
    return out


def _record(conn, cfg, complete: bool) -> None:
    from . import settings_store as store

    value = json.dumps({"model": cfg.label, "dim": cfg.dim, "complete": complete})
    if store.get(conn, SETTING) != value:
        store.put(conn, SETTING, value)
    conn.commit()


def reconcile_embedding_dim(conn, cfg=None, *, defer_above: int | None = DEFER_ABOVE, force: bool = False,
                            strict: bool = False) -> dict:
    """Make incident.embedding and runbook.embedding match the configured embedding size, and fill in missing vectors.

    * Sizes differ: in ONE transaction drop the HNSW indexes, `ALTER COLUMN ... TYPE vector(N) USING NULL`, recreate the
      indexes. Sizes above the HNSW limit (2000) are refused and nothing changes.
    * Then every row without a vector (all rows with `force`) is embedded from its source text, in batches. A provider
      failure leaves the rest NULL (one log line) to be retried on the next start. Above `defer_above` rows the
      embedding runs in a background thread instead (`None` = never defer).
    * `strict` (the CLI): probe the provider before altering anything and raise if it fails.
    Never raises on provider problems unless `strict`. Returns a summary dict."""
    from . import embedcfg, retrieval

    cfg = cfg or embedcfg.from_env()
    res: dict = {"dimension": cfg.dim, "previous": {}, "changed": False, "refused": None, "deferred": False,
                 "embedded": {t: 0 for t in INDEXES}, "failed": None, "skipped": None}
    dims = {t: column_dim(conn, t) for t in INDEXES}
    conn.rollback()
    if None in dims.values():
        res["refused"] = "tables not found; run migrations first"
        return res
    if any(d != cfg.dim for d in dims.values()):
        if cfg.dim > MAX_HNSW_DIM or cfg.dim < 1:
            res["refused"] = (f"{cfg.dim} dimensions cannot be indexed (pgvector allows 1 to {MAX_HNSW_DIM}); the "
                              f"columns stay at {dims['incident']} dimensions. Set EMBEDDING_DIM to a supported size "
                              "(most providers let you request fewer dimensions).")
            log.warning("embedding resize refused: %s", res["refused"])
            return res
        if strict:
            retrieval.embed(["connection test"], cfg)   # fail fast, before anything is altered
        conn.execute("SELECT pg_advisory_xact_lock(%s)", (_RESIZE_LOCK,))   # replicas: the second finds nothing to do
        for t in INDEXES:
            have = column_dim(conn, t)
            if have == cfg.dim:
                continue
            res["previous"][t] = have
            conn.execute(f"DROP INDEX IF EXISTS {INDEXES[t]}")
            conn.execute(f"ALTER TABLE {t} ALTER COLUMN embedding TYPE vector({int(cfg.dim)}) USING NULL")  # noqa: S608
            conn.execute(f"CREATE INDEX {INDEXES[t]} ON {t} USING hnsw (embedding vector_cosine_ops)")  # noqa: S608
        conn.commit()
        res["changed"] = bool(res["previous"])
        if res["changed"]:
            log.warning("embedding columns resized %s -> %d dimensions; stored vectors were derived data and are "
                        "being recomputed", ", ".join(f"{t} {d}" for t, d in res["previous"].items()), cfg.dim)
    todo = _counts(conn, force)
    conn.rollback()
    total = sum(todo.values())
    if total == 0:
        _record(conn, cfg, True)
        return res
    if defer_above is not None and total > defer_above:
        res["deferred"] = True
        _record(conn, cfg, False)
        log.warning("%d rows need embeddings (more than %d): re-embedding continues in the background; retrieval uses "
                    "text search meanwhile", total, defer_above)
        start_background(cfg, force=force, total=total)
        return res
    r = _embed_rows(conn, cfg, force=force)
    res.update(embedded=r["embedded"], failed=r["failed"], skipped=r["skipped"])
    if r["skipped"]:
        log.info("%s", r["skipped"])
    else:
        _record(conn, cfg, r["failed"] is None)
    return res


def _spawn(work, total: int = 0) -> bool:
    """Run work(conn) -> result dict in a daemon thread with its own connection and job state. False if one is running."""
    global _thread
    with _job_lock:
        if _job["state"] == "running":
            return False
        _job.update(state="running", done=0, total=total, message="starting", started_at=time.time())

    def run() -> None:
        from .db import connect_vector

        try:
            with connect_vector() as conn:
                r = work(conn)
            problem = r.get("refused") or r.get("failed")
            _job.update(state="error" if problem else "done", message=f"stopped: {problem}" if problem
                        else (r.get("skipped") or "finished"))
        except Exception as exc:  # noqa: BLE001 - a background job must never take the server down
            log.warning("background re-embedding failed: %s: %s", type(exc).__name__, str(exc)[:200])
            _job.update(state="error", message=f"{type(exc).__name__}: {str(exc)[:200]}")

    _thread = threading.Thread(target=run, daemon=True, name="pagerlens-reembed")
    _thread.start()
    return True


def start_background(cfg, *, force: bool = False, total: int = 0) -> bool:
    """Embed the rows lacking a vector in the background (the deferred part of a large reconciliation)."""
    def work(conn) -> dict:
        r = _embed_rows(conn, cfg, force=force, progress=lambda n: _job.update(done=n, message="re-embedding"))
        if not r["skipped"]:
            _record(conn, cfg, r["failed"] is None)
        return r

    return _spawn(work, total)


def start_reembed_job(cfg=None, *, force: bool = True) -> bool:
    """The admin action: resize if needed, then re-embed everything (or just the missing vectors), in the background."""
    return _spawn(lambda conn: reconcile_embedding_dim(conn, cfg, defer_above=None, force=force))


def embedding_status(conn, cfg=None) -> dict:
    """Where the vectors stand: the configured size, each column's size, rows still lacking a vector, any running job."""
    from . import embedcfg
    from . import settings_store as store

    cfg = cfg or embedcfg.from_env()
    cols = {t: column_dim(conn, t) for t in INDEXES}
    missing = _counts(conn, False) if None not in cols.values() else {}
    try:
        recorded = json.loads(store.get(conn, SETTING) or "null")
    except ValueError:
        recorded = None
    conn.rollback()
    mismatch = any(d is not None and d != cfg.dim for d in cols.values())
    return {"configured": {"model": cfg.label, "dimension": cfg.dim}, "columns": cols, "recorded": recorded,
            "mismatch": mismatch, "missing": missing, "needs_reembedding": mismatch or any(missing.values()),
            "indexable": cfg.dim <= MAX_HNSW_DIM, "job": job_status()}
