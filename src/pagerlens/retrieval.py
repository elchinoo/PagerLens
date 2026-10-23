"""Retrieval over pgvector: runbooks (hybrid vector + full-text, reciprocal rank fusion) and resolved incidents.

Embeddings use the environment-configured provider when one is set (LLM_BASE_URL, EMBEDDING_MODEL, EMBEDDING_DIM,
whose size the vector columns follow: `migrate.reconcile_embedding_dim` converts them at startup when EMBEDDING_DIM
changes). Otherwise a built-in offline hasher is used: lexical, not semantic, but enough to demo recall without any account.

Retrieval never fails because of embeddings: when the provider is down, or its vectors do not fit the column yet (a
reconciliation is pending), runbook search falls back to full-text only and incident recall returns nothing.
"""
import logging

from pgvector import Vector

from . import embedcfg
from .embeddings import embed

RRF_K = 60
log = logging.getLogger("pagerlens.embeddings")


def embed_one(text: str) -> Vector:
    return Vector(embed([text[:4000]], embedcfg.from_env())[0])


def describe(exc: Exception) -> str:
    return f"{type(exc).__name__}: {exc}"[:200]


def query_vector(conn, text: str, table: str) -> Vector | None:
    """Embedding of `text` that fits `table`.embedding, or None (logged once, as one line) when it cannot be had:
    the provider failed, or its size differs from the column's (until the reconciler has converted the column)."""
    from .migrate import column_dim

    try:
        vec = embed_one(text)
    except Exception as exc:  # noqa: BLE001 - EmbeddingError, locked vault, network: all mean 'no vector', never a 500
        log.warning("embedding unavailable (%s); using text search only", describe(exc))
        return None
    have = column_dim(conn, table)
    if have is not None and len(vec.to_list()) != have:
        log.warning("embedding size %d does not match %s.embedding (%d): text search only until `pagerlens reembed` "
                    "or a restart reconciles it", len(vec.to_list()), table, have)
        return None
    return vec


def search_runbooks(conn, query: str, *, category: str | None = None, service: str | None = None,
                    limit: int = 3) -> list[dict]:
    vec = query_vector(conn, query, "runbook")
    vec_cte = ("""SELECT id, row_number() OVER (ORDER BY embedding <=> %(vec)s) AS r FROM runbook
            WHERE (%(cat)s::text IS NULL OR category = %(cat)s) AND embedding IS NOT NULL
            ORDER BY embedding <=> %(vec)s LIMIT 20""" if vec is not None else
               "SELECT NULL::bigint AS id, NULL::bigint AS r WHERE false")
    params = {"q": query[:300], "cat": category, "svc": service, "k": RRF_K, "n": limit}
    if vec is not None:
        params["vec"] = vec
    return conn.execute(
        f"""
        WITH vec AS (
            {vec_cte}),
        lex AS (
            SELECT id, row_number() OVER (ORDER BY ts_rank(tsv, q) DESC) AS r
            FROM runbook, websearch_to_tsquery('english', %(q)s) q
            WHERE tsv @@ q AND (%(cat)s::text IS NULL OR category = %(cat)s)
            ORDER BY ts_rank(tsv, q) DESC LIMIT 20),
        fused AS (
            SELECT COALESCE(vec.id, lex.id) AS id,
                   COALESCE(1.0 / (%(k)s + vec.r), 0) + COALESCE(1.0 / (%(k)s + lex.r), 0) AS score
            FROM vec FULL OUTER JOIN lex ON vec.id = lex.id)
        SELECT r.id, r.title, r.category, r.service, r.body, f.score
        FROM fused f JOIN runbook r ON r.id = f.id
        WHERE (%(svc)s::text IS NULL OR r.service IS NULL OR r.service = %(svc)s)
        ORDER BY f.score DESC LIMIT %(n)s
        """,
        params,
    ).fetchall()


def similar_incidents(conn, text: str, *, exclude_id: int | None = None, limit: int = 5,
                      min_similarity: float = 0.2) -> list[dict]:
    """Resolved incidents whose symptom/signatures look like `text` (the learning loop's memory)."""
    vec = query_vector(conn, text, "incident")
    if vec is None:
        return []
    return conn.execute(
        """
        SELECT i.id, i.title, i.symptom, i.root_cause_category, i.root_cause_note, s.name AS service,
               i.resolved_at, 1 - (i.embedding <=> %(vec)s) AS similarity
        FROM incident i JOIN service s ON s.id = i.service_id
        WHERE i.status = 'resolved' AND i.root_cause_category IS NOT NULL AND i.embedding IS NOT NULL
          AND (%(ex)s::bigint IS NULL OR i.id <> %(ex)s)
          AND 1 - (i.embedding <=> %(vec)s) >= %(min)s
        ORDER BY i.embedding <=> %(vec)s LIMIT %(n)s
        """,
        {"vec": vec, "ex": exclude_id, "n": limit, "min": min_similarity},
    ).fetchall()


def remember_incident(conn, incident_id: int, signatures: list[str]) -> None:
    """Re-embed an incident with its error signatures so future recall matches on what the logs said."""
    row = conn.execute("SELECT i.symptom, s.name FROM incident i JOIN service s ON s.id=i.service_id WHERE i.id=%s",
                       (incident_id,)).fetchone()
    if row:
        text = f"{row['name']}: {row['symptom']} | " + " | ".join(signatures[:6])
        vec = query_vector(conn, text, "incident")
        if vec is not None:  # otherwise keep whatever is stored: the reconciler fills it in later
            conn.execute("UPDATE incident SET embedding=%s WHERE id=%s", (vec, incident_id))
